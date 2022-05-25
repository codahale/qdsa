# qDSA

A pure-Rust implementation of [qDSA](https://joostrenes.nl/publications/qdsa-eprint.pdf) (aka Quotient DSA) over
Curve25519.
Includes X25519 key agreement, Elligator2 encoding and decoding, and a designated-verifier adaptation of qDSA.
Tested for compatibility with the the [reference C version](https://joostrenes.nl/software/cref-g1.tar.gz) by
Joost Renes.
Portions of the Curve25519 and scalar arithmetic were adapted from
[curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek).

## License

Copyright © 2022 Coda Hale

Distributed under the BSD 3-Clause License.
