# qDSA

A pure-Rust implementation of [qDSA](https://joostrenes.nl/publications/qdsa-eprint.pdf) (aka Quotient DSA) over
Curve25519, plus X25519 key agreement.

Ported from the [reference C version](https://joostrenes.nl/software/cref-g1.tar.gz) by Joost Renes, with the main
exception of replacing the Keccak-based hash with SHA3.

## License

Copyright © 2022 Coda Hale

Distributed under the Apache License 2.0 or MIT License.
