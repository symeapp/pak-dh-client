### Password-Authenticated Diffie-Hellman Key Exchange  (RFC 5683)

_**Warning:** This is an alpha release and is not intended for production use. Peer review is appreciated._

This library implements a Javascript client for password-authenticated key exchange, as described in [RFC 5683](http://tools.ietf.org/html/rfc5683). It is released under the MPL.

### Usage

```javascript

var idA = 'A', idB = 'B', password = 'password';

var pakdh = new PAKDHClient(password);

// 1. A calculates X.

var gRa = pakdh.generategRa();
var X = pakdh.calculateX(idA, idB, gRa);

// 2. A sends X to B.

// 3. B calculates Y and S1.

var gRb = pakdh.generategRb();
var Xab = pakdh.calculateXab(idA, idB, X);
var S1 = pakdh.calculateS1(idA, idB, Xab, gRb);
var Y = pakdh.calculateY(idA, idB, gRb);

// 4. A sends S1 and Y to B.

// 5. B calculates S1' and verifies.

var Y = pakdh.calculateY(idA, idB, gRb);
var Yba = pakdh.calculateYba(idA, idB, Y);
var S1p = pakdh.calculateS1(idA, idB, gRa, Yba);

if (S1p.toString(16) != S1.toString())
  throw "Error - S1 doesn't match.";

// 6. B calculates Kb and S2.
var Kb = pakdh.calculateK(idA, idB, Xab, gRb);
var S2 = pakdh.calculateS2(idA, idB, gRa, Yba);

// 7. B sends S2 to A.

// 8. A calculates S2' and verifies.
var S2p = pakdh.calculateS2(idA, idB, gRa, Yba);

if (S2p.toString(16) != S2.toString())
  throw "Error - S2 doesn't match.";

// 9. A calculates Ka.
var Ka = pakdh.calculateK(idA, idB, gRa, Yba);

// 10. A and B can now communicate using K.
```

### Further Reading

- [RFC 5683 - Password-Authenticated Diffie-Hellman Key Exchange](http://tools.ietf.org/html/rfc5683)

### License

This library is released under the MPL.
