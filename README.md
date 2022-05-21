# qDSA

A pure-Rust implementation of [qDSA](https://joostrenes.nl/publications/qdsa-eprint.pdf) (aka Quotient DSA) over
Curve25519, plus X25519 key agreement.

Ported from the [reference C version](https://joostrenes.nl/software/cref-g1.tar.gz) by Joost Renes, with the main
exception of making the hash function generic.

## TODO

- [ ] unify keygen API
- [ ] expand sign to allow hedging, external challenge scalars

## License

Copyright © 2022 Coda Hale

Distributed under the Apache License 2.0 or MIT License.
