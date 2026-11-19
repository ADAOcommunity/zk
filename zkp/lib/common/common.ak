//// Constants and small helpers shared by the verifiers.
////
//// `blst_affine` uses the two BLS12-381 constants to check and compress
//// affine points. The PLONK transcript uses `concat_and_keccak_256`, and the
//// PLONK verifier uses `scalar_sum` and `g1_sum`. Group operations and
//// pairings use the native BLS12-381 builtins in `aiken/crypto/bls12_381`;
//// the package has none of its own.

use aiken/collection/list
use aiken/crypto
use aiken/crypto/bitwise.{State}
use aiken/crypto/bls12_381/g1
use aiken/crypto/bls12_381/scalar.{Scalar}
use aiken/primitive/bytearray

/// BLS12-381 base field prime p
pub const bls12_381_base_prime: Int =
  4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787

/// (p-1)/2 for BLS12-381 field modulus, used to determine y-coordinate sort bit.
pub const bls12_381_half_prime: Int =
  2001204777610833696708894912867952078278441409969503942666029068062015825245418932221343814564507832018947136279893

/// Keccak-256 of the inputs joined in order.
pub fn concat_and_keccak_256(inputs: List<ByteArray>) -> ByteArray {
  let concatenated =
    list.foldl(inputs, #"", fn(x, acc) { bytearray.concat(acc, x) })
  crypto.keccak_256(concatenated)
}

/// Sum of the scalars mod r; zero for an empty list.
pub fn scalar_sum(scalars: List<State<Scalar>>) -> State<Scalar> {
  list.foldl(scalars, scalar.from_int(0), fn(acc, x) { scalar.add(acc, x) })
}

/// Sum of the points; the point at infinity for an empty list.
pub fn g1_sum(points: List<G1Element>) -> G1Element {
  list.foldl(points, g1.zero, g1.add)
}
