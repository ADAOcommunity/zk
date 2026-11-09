# zkp

Aiken package containing this project's three zero-knowledge proof verifiers, targeting Plutus V3 on Cardano. See the repository root [README](../README.md) and [specification.md](../specification.md) for project-level scope and status.

## Layout

```
lib/
  groth/    Groth16 verifier
  plonk/    PLONK verifier
  bullet/   Bulletproofs range-proof verifier and reference prover
  common/   Shared field/point scaffolding (legacy; superseded by native BLS12-381
            builtins inside groth/plonk/bullet — see docs/ for details)
  tests/    Test suites for groth and plonk (bullet's tests live alongside bullet.ak)
docs/
  step-by-step.md                       Protocol-level walkthrough of all three systems
  groth16-implementation-report.md      Architecture, design decisions, security argument
  plonk-implementation-report.md          "
  bulletproofs-implementation-report.md   "
```

## Working with this package

```sh
aiken check   # run the test suite
aiken build   # compile and generate plutus.json
aiken fmt     # format .ak source
```

Each implementation report in `docs/` documents what's actually built, how it departs from a naive port of the underlying protocol, and its known limitations — read those before integrating one of these verifiers into a validator.
