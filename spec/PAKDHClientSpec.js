describe("PAKDHClient", function() {

  var password = 'password123';

  var pakdh = new PAKDHClient(password);

  var rand = pakdh.random();
  
  // If short exponents are used for Diffie-Hellman parameters
  // Ra and Rb, then they should have a minimum size of 384 bits.
  it ("should generate a random 384-bit exponent", function () {

    expect(rand.toString(16).length * 4).toEqual(384);

  });
  
  var HA = pakdh.HA("test", 1);
  
  // The independent, random functions H1 and H2 should each output
  // 1152 bits, assuming prime p is 1024 bits and session keys 128 bits.
  it ("should output a 1152-bit long random hash", function () {

    expect(HA.toString(16).length * 4).toEqual(1152);

  });

  var gRa = pakdh.generategRa();

  var X = pakdh.calculateX('A', 'B', gRa);
  
  var Xab = pakdh.calculateXab('A', 'B', X);
  
  it ("should be able to recover the value of g^Ra", function () {

    expect(Xab.toString(16)).toEqual(gRa.toString(16));

  });
  
  var gRb = pakdh.generategRb();
  
  var S1 = pakdh.calculateS1('A', 'B', Xab, gRb);
  var Y = pakdh.calculateY('A', 'B', gRb);
  
  var Yba = pakdh.calculateYba('A', 'B', Y);

  it ("should be able to recover the value of g^Rb", function () {

    expect(Yba.toString(16)).toEqual(gRb.toString(16));

  });

  var S1p = pakdh.calculateS1('A', 'B', gRa, Yba);

  console.log(S1p.toString(16));
  
  it ("S1 should match", function () {

    expect(S1p.toString(16)).toEqual(S1.toString(16));

  });

  var S2 = pakdh.calculateS2('A', 'B', gRa, Yba);
  var S2p = pakdh.calculateS2('A', 'B', Xab, gRb);

  it ("S2 should match", function () {

    expect(S2.toString(16)).toEqual(S2p.toString(16));

  });
  
  var Ka = pakdh.calculateK('A', 'B', gRa, Yba);

  var Kb = pakdh.calculateK('A', 'B', Xab, gRb);

  it ("K should match", function () {

    expect(Ka.toString(16)).toEqual(Kb.toString(16));

  });  
  
});