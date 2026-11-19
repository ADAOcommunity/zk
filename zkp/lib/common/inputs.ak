//// Checks on values a verifier takes from outside the script: the public
//// inputs of the Groth16 and PLONK verifiers, and the scalars in PLONK and
//// Bulletproofs proofs.

use aiken/crypto/bitwise.{State}
use aiken/crypto/bls12_381/scalar.{Scalar, field_prime}

/// True when `inputs` has exactly `expected` entries and each one lies in
/// `[0, r)`, where `r` is the BLS12-381 scalar field order.
///
/// Both verifiers reduce public inputs mod `r`, so without the range check
/// `x` and `x + r` verify with the same proof, and a validator that also reads
/// the input as a plain `Int` sees a value the proof didn't bind. Without the
/// count check, inputs the circuit has no slot for are never constrained.
pub fn check_public_inputs(inputs: List<Int>, expected: Int) -> Bool {
  when inputs is {
    [] -> expected == 0
    [x, ..rest] -> and {
        expected > 0,
        x >= 0,
        x < field_prime,
        check_public_inputs(rest, expected - 1),
      }
  }
}

/// `x` as a scalar. Fails unless `x` lies in `[0, r)`.
///
/// `scalar.from_int` reduces mod `r`, so without the check `x`, `x + r` and
/// `x - r` would decode to the same scalar, and one proof would have many
/// encodings that all verify. The proof decoders that use this fail rather
/// than return `None`, since they also decompress points with a builtin that
/// fails on a bad one.
pub fn scalar_in_field(x: Int) -> State<Scalar> {
  if x < 0 || x >= field_prime {
    fail @"scalar must be in [0, r)"
  } else {
    scalar.from_int(x)
  }
}
