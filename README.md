# Aiken ZKP Standards Library

A standards-compliant Zero-Knowledge Proof (ZKP) library for Cardano smart contracts, implemented in Aiken. This library enables efficient on-chain verification while maintaining robust security guarantees.

## Project Overview

The Aiken ZKP Standards Library takes a pragmatic approach to implementing zero-knowledge proof systems on Cardano. We distinguish between committed features (ready for production) and aspirational features (planned for future development).

## Features

### Features Currently Under Development

#### Groth16
- Generic Groth16 proof verifier system
- Example circuits and R1CS constraint sets
- Comprehensive test suite

#### Plonk
- Generic Plonk proof verifier system
- circom and SnarkJS integration
- Complete verification examples

#### Bullet Proofs
- Generic Bullet Proof verifier system
- Example circuits and implementations
- Extensive testing suite

### Aspirational Features

- **Marlin**: Preprocessing zkSNARKs with Universal and Updatable SRS
- **Plonky2**: Advanced recursive proof composition

## Implementation

### On-Chain
- Leverages PlutusV3's BLS12-381 curve builtin functions
- Focuses on efficient verification
- Maintains strong security guarantees

### Off-Chain
- Examples using circom
- Integration with SnarkJS
- User-customizable proof generation

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