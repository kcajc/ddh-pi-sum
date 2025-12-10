# DDH-based Private Intersection-Sum Protocol

A Rust implementation of the DDH-based Private Intersection-Sum protocol described in [On Deploying Secure Computing: Private Intersection-Sum-with-Cardinality](https://eprint.iacr.org/2019/723.pdf).

## Stack
* PSI: `ristretto255` with hash to curve.
* AHE: Paillier cryptosystem for additive homomorphic aggregation.

## Usage
```bash
cargo run
```
