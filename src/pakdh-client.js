/*
 * PAK allows two parties to authenticate themselves
 * while performing the Diffie-Hellman exchange.
 *
 * See http://tools.ietf.org/html/rfc5683
 */
PAKDHClient = function (password, group) {
  
  // Verify presence of password.
  if (!password) throw 'Missing password.';

  // Store password.
  this.password = password;
  
  // Retrieve initialization values.
  var group = group || 1024;
  var initVal = this.initVals[group];
  
  // Set N and g from initialization values.
  this.N = new BigInteger(initVal.N, 16);
  this.g = new BigInteger(initVal.g, 16);
  
  // Convenience big integer objects for 1 and 2.
  this.one = new BigInteger("1", 16);
  this.two = new BigInteger("2", 16);
  
};

/*
 * Implementation of an PAK-DH client conforming
 * to the protocol described in RFC 5683.
 */
PAKDHClient.prototype = {

  // Generates Ra, A's random secret exponent.
  generategRa: function () {
    
    return this.modPow(this.random());  
    
  },
  
  // Generates Rb, B's random secret exponent.
  generategRb: function () {
    
    return this.modPow(this.random());
    
  },
  
  // Calculates g ^ x mod N
  modPow: function(x) {
    
    if (!x) throw 'Missing parameter.';
    
    return this.g.modPow(x, this.N);
    
  },
  
  // X = H1(A|B|PW)*(g^Ra)
  calculateX: function (A, B, gRa) {
    
    if (!A || !B || !gRa)
      throw 'Missing parameters.';
    
    var str = A + B + this.password;
    
    return this.H1(str).multiply(gRa);
    
  },
  
  // Xab = Q / H1(A|B|PW)
  calculateXab: function (A, B, Q) {
    
    if (!A || !B || !Q)
      throw 'Missing parameter(s).';
      
    if (Q.toString() == '0')
      throw 'X should not be equal to 0.'

    var str = A + B + this.password;
    
    return Q.divide(this.H1(str));
    
  },
  
  // Y = H2(A|B|PW)*(g^Rb)
  calculateY: function (A, B, gRb) {
    
    if (!A || !B || !gRb)
      throw 'Missing parameter(s).';
    
    var str = A + B + this.password;
    var Y = this.H2(str).multiply(gRb);
    
    if (Y.toString() == '0')
      throw 'Y should not be equal to 0.'

    return Y;
    
  },
  
  // Yba = Y / H2(A|B|PW)
  calculateYba: function (A, B, Y) {
    
    if (!A || !B || !Y)
      throw 'Missing parameter(s).';
    
    //var Y = this.calculateY(A, B, gRb);
    var str = A + B + this.password;
    
    return Y.divide(this.H2(str));
  
  },
  
  // S1 = H3(A|B|PW|Xab|g^Rb|(Xab)^Rb)
  calculateS1: function (A, B, gRa, gRb) {
    
    if (!A || !B || !gRa || !gRb)
      throw 'Missing parameter(s).';
    
    var AB = this.modPow(gRa.multiply(gRb));
    
    return this.H3(
        this.password +
        gRa.toString(16) +
        gRb.toString(16) +
        AB.toString(16));
    
  },
  
  // S2 = H4(A|B|PW|g^Ra|Yba|(Yba)^Ra)
  calculateS2: function (A, B, gRa, gRb) {
    
    if (!A || !B || !gRa || !gRb)
      throw 'Missing parameter(s).'
      
    var AB = this.modPow(gRa.multiply(gRb));
    
    return this.H4( A + B + 
        this.password +
        gRa.toString(16) +
        gRb.toString(16) + 
        AB.toString(16));
    
  },
  
  
  // K = H5(A|B|PW|g^Ra|Yba|(Yba)^Ra)
  calculateK: function (A, B, gRa, gRb) {
    
    if (!A || !B || !gRa || !gRb)
      throw 'Missing parameter(s).'
    
    var AB = this.modPow(gRa.multiply(gRb));
    
    return this.H5(A + B +
        this.password +
        gRa.toString(16) +
        gRb.toString(16) +
        AB.toString(16));
    
  },
  
  /*
   * Helper functions for random number
   * generation and format conversion.
   */
  
  // Generate a 384-bit random exponent.
  random: function() {
    
    var words = sjcl.random.randomWords(12,0);
    var hex = sjcl.codec.hex.fromBits(words);
    
    if (hex.length * 4 != 384)
      throw 'Invalid random exponent size.';
    
    return new BigInteger(hex, 16);

  },
  
  /*
   * Hashing and random functions.
   *
   * See Bellare, M. and P. Rogaway, "Random
   * Oracles are Practical: A Paradigm for 
   * Designing Efficient Protocols", 1998.
   */
  
  H1: function (string) {
    
    return this.HA(string, 1);
  
  },
  
  H2: function (string) {
    
    return this.HA(string, 2);
    
  },
  
  // SHA-1(t|1|z) mod 2^128 |...|
  // SHA-1(t|9|z) mod 2^128
  HA: function (string, type) {
    
    var hash = '';
    
    for (var i = 1; i < 10; i++) {
      
      var tmp = sjcl.hash.sha256.hash(
        type.toString() + i.toString() + string);
      
      var lsB = this.lsb128(tmp);
      
      hash += sjcl.codec.hex.fromBits(lsB);
      
    }
    
    // Verify hash is 1152 bits.
    if (hash.length * 4 != 1152)
      throw 'Invalid hash size.';
    
    return new BigInteger(hash, 16);
    
  },
  
  H3: function (string) {
    return this.HB(string, 3);
  },
  
  H4: function (string) {
    return this.HB(string, 4);
  },
  
  H5: function (string) {
    return this.HB(string, 5);
  },
  
  // SHA-1(t|len(z)|z|z) mod 2^128
  HB: function (string, type) {
    
    var type = type.toString();
    var len = string.length.toString();
    
    var tmp = sjcl.hash.sha256.hash(
        type + len + string + string);
    
    var lsB = this.lsb128(tmp);
    
    return new BigInteger(lsB, 256);
    
  },
  
  // Return the 128 least significant bits of a
  // SHA-256 hash represented as an array of 8
  // 32-bit integers (i.e. the 4 left elements).
  lsb128: function (tmp) {
    return tmp.splice(tmp.length / 2, tmp.length);
  },
  
  /*
   * Initialization values for g and p used in this protocol.
   *
   * For the moment, only a 1024-bit official value is publisherd;
   * however, a larger prime (e.g., 2048 bits long, or even larger) 
   * will definitely provide better protection.
   *
   * See TIA, "Over-the-Air Service Provisioning of Mobile 
   * Stations in Spread Spectrum Systems", TIA-683-D, 2006.
   */
  initVals: {
    
    1024: {
            
      N: 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08' +
         '8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B' +
         '302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9' +
         'A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6' +
         '49286651ECE65381FFFFFFFFFFFFFFFF',
      g: '13'

    }
    
  }
  
};