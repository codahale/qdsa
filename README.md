# qDSA

A pure-Rust implementation of [qDSA](https://joostrenes.nl/publications/qdsa-eprint.pdf) (aka Quotient DSA) over
Curve25519.
Includes X25519 key agreement, Elligator2 encoding and decoding, and a designated-verifier adaptation of qDSA.

* qDSA/SHAKE128 compatibility tested with the [reference C version](https://joostrenes.nl/software/cref-g1.tar.gz) by
  Joost Renes.
* X25519 compatibility tested with [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748) and
  [Project Wycheproof](https://github.com/google/wycheproof).
* Elligator2 compatibility tested with [Monocypher](https://monocypher.org) 3.1.3.

## License

Copyright © 2022 Coda Hale

Distributed under the BSD 3-Clause License.
