# DDH-based Private Intersection-Sum Protocol

A toy implementation of the DDH-based protocol described in [On Deploying Secure Computing: Private Intersection-Sum-with-Cardinality](https://eprint.iacr.org/2019/723.pdf).

Started this as a course project, but they want Python code, finished it as I procrastinate reading papers.

## Stack
* PSI: `ristretto255` for the DDH-based OPRF.
* AHE: Paillier cryptosystem for additive homomorphic aggregation.

## Usage
```bash
cargo run
```
