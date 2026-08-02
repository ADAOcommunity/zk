# Aiken ZKP Standards Library

A standards-compliant Zero-Knowledge Proof (ZKP) library for Cardano smart contracts, implemented in Aiken. This library enables efficient on-chain verification while maintaining robust security guarantees.

## Project Overview

The Aiken ZKP Standards Library takes a pragmatic approach to implementing zero-knowledge proof systems on Cardano. We distinguish between committed features (current targets) and aspirational features (planned for future development).

This implementation is designed for Plutus v3, leveraging its built-in BLS12-381 curve functions to ensure efficient and secure verification of ZKPs. It emphasizes clarity and maintainability, making it suitable for educational/demonstrative purposes without sacrificing security.

### Implemented

All three verifiers are functional, unit-tested, and build cleanly (`aiken check` / `aiken build`, 37/37 tests passing as of this writing). Each is **verification-only**: proof generation, circuit compilation, and (for Groth16/PLONK) trusted setup are assumed to happen off-chain, using external tooling this library does not provide. Full architecture, security arguments, and known limitations for each are written up in [`zkp/docs/`](./zkp/docs).

#### Groth16

- Generic Groth16 proof verifier ([`zkp/lib/groth`](./zkp/lib/groth)) on native BLS12-381 pairing builtins
- Tested against externally-generated proof/verification-key fixtures, both accepting valid proofs and rejecting tampered ones
- [Implementation report](./zkp/docs/groth16-implementation-report.md)

#### Plonk

- Generic Plonk proof verifier ([`zkp/lib/plonk`](./zkp/lib/plonk)) with a batched KZG opening and a Keccak-256 Fiat–Shamir transcript matching the SnarkJS convention
- Tested against an externally-generated proof/verification-key fixture, including rejection of tampered proofs and mismatched public inputs
- [Implementation report](./zkp/docs/plonk-implementation-report.md)

#### Bullet Proofs

- Generic Bulletproofs range-proof verifier _and_ reference prover ([`zkp/lib/bullet`](./zkp/lib/bullet)) — the only one of the three with no trusted setup, so this library owns both sides and tests them together with no external fixtures needed
- [Implementation report](./zkp/docs/bulletproofs-implementation-report.md)

Currently, the Groth16 module includes:

- [x] Generic Groth16 proof verifier system
- [x] Onchain verification tests

Wishlist:

- [ ] Integration examples with circom and SnarkJS
- [ ] Integration into a merkelized validator

### Plonk

Status: Optimizing

The Plonk implementation is loosely based on perturbing's [plutus-plonk](https://github.com/perturbing/plutus-plonk-example), with several optimizations and restructuring done around point compression to improve performance and clarity.

The Plonk module currently includes:

- [x] Generic Plonk proof verifier system
- [x] Onchain verification tests

Wishlist:

- [ ] Optimize further to fit within Plutus resource limits
- [ ] Integration examples with circom and SnarkJS
- [ ] Integration into a merkelized validator

### Bulletproofs

Status: Early Development

The Bulletproofs implementation is in the early stages, with a focus on building out the necessary field arithmetic and point operations required for Bulletproofs.

### Helper Functions

- Affine point operations - conversion to/from native types
- Field arithmetic utilities

## Aspirational ZKP Systems

- **Marlin**: Preprocessing zkSNARKs with Universal and Updatable SRS
- **Plonky2**: Advanced recursive proof composition

## Implementation

- Leverages PlutusV3's BLS12-381 curve builtin functions
- Focuses on efficient verification
- Maintains strong security guarantees
- See the per-protocol implementation reports in [`zkp/docs/`](./zkp/docs) for details

## Getting Started

### Prerequisites

- Aiken development environment
- Familiarity with ZKP systems
- Understanding of Cardano smart contracts

## Contributing

We welcome contributions! Please see our [Contributing Guide](./CONTRIBUTING.md) for:

- Development guidelines
- Submission process
- Testing requirements

### Prerequisites

- Aiken development environment
- Familiarity with ZKP systems
- Understanding of Cardano smart contracts
