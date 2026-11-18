//// Property-based tests for the Bulletproofs range-proof verifier, at
//// n = 8 (values in [0, 256)). See `tests/groth_props` for what the `prop_*`
//// and `known_issue_*` prefixes mean.

use aiken/collection/list
use aiken/crypto
use aiken/crypto/bls12_381/scalar.{field_prime}
use aiken/fuzz
use aiken/primitive/bytearray
use bullet/bullet.{
  BulletproofProof, BulletproofVerificationKey, ProofBlinding, commit_value,
  generate_proof, setup, verify,
}
use tests/groth_props.{nonzero_scalar}

const n: Int = 8

/// A constant, so `setup` runs once at compile time rather than in every case.
const vk: BulletproofVerificationKey = setup(n)

/// An in-range value, a commitment blinding, and a prover seed.
fn statement() -> Fuzzer<(Int, Int, ByteArray)> {
  fuzz.tuple3(
    fuzz.int_between(0, 255),
    nonzero_scalar(),
    fuzz.bytearray_between(0, 32),
  )
}

/// Blinding factors derived from `seed`. Test-only: anyone who knows the seed
/// can read the committed value back from the proof's `l_vec`.
fn seeded_blinding(seed: ByteArray) -> ProofBlinding {
  let draw =
    fn(tag) {
      scalar.from_bytes(crypto.blake2b_256(bytearray.concat(seed, tag)))
    }
  let draw_vec =
    fn(tag) {
      list.map(
        list.range(0, n - 1),
        fn(i) {
          draw(bytearray.concat(tag, bytearray.from_int_big_endian(i, 4)))
        },
      )
    }
  ProofBlinding {
    alpha: draw("alpha"),
    rho: draw("rho"),
    tau1: draw("tau1"),
    tau2: draw("tau2"),
    s_l: draw_vec("s_l"),
    s_r: draw_vec("s_r"),
  }
}

/// The key, a proof for `value`, and the matching commitment.
fn prove(
  value: Int,
  gamma: Int,
  seed: ByteArray,
) -> (BulletproofVerificationKey, BulletproofProof, G1Element) {
  let g = scalar.from_int(gamma)
  (
    vk,
    generate_proof(vk, value, g, seeded_blinding(seed)),
    commit_value(vk, value, g),
  )
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

/// Every value in [0, 2^n) can be proven, with any blinding and seed.
test prop_bullet_valid_proof_verifies((value, gamma, seed) via statement()) {
  let (vk, proof, commitment) = prove(value, gamma, seed)
  verify(vk, commitment, proof)
}

/// A proof for one value doesn't verify against a commitment to another value
/// (mod r) with the same blinding.
test prop_bullet_rejects_other_value(
  ((value, gamma, seed), delta) via fuzz.tuple(statement(), nonzero_scalar()),
) {
  let (vk, proof, _) = prove(value, gamma, seed)
  let other =
    commit_value(vk, ( value + delta ) % field_prime, scalar.from_int(gamma))
  !verify(vk, other, proof)
}

/// Changing `tau_x`, `mu` or the first entry of `l_vec` or `r_vec` breaks the
/// proof.
test prop_bullet_rejects_tampered_proof(
  ((value, gamma, seed), which, delta) via fuzz.tuple3(
    statement(),
    fuzz.int_between(0, 3),
    nonzero_scalar(),
  ),
) {
  let (vk, proof, commitment) = prove(value, gamma, seed)
  let d = scalar.from_int(delta)
  let bump_head =
    fn(xs) {
      when xs is {
        [x, ..rest] -> [scalar.add(x, d), ..rest]
        [] -> fail @"empty vector"
      }
    }
  let tampered =
    when which is {
      0 -> BulletproofProof { ..proof, tau_x: scalar.add(proof.tau_x, d) }
      1 -> BulletproofProof { ..proof, mu: scalar.add(proof.mu, d) }
      2 -> BulletproofProof { ..proof, l_vec: bump_head(proof.l_vec) }
      _ -> BulletproofProof { ..proof, r_vec: bump_head(proof.r_vec) }
    }
  !verify(vk, commitment, tampered)
}

/// ADAOcommunity/zk#16: `commit_value` fails for `value + k * r` (with
/// negative k, a negative amount), where it used to return the same point as
/// for `value`.
test prop_bullet_commit_value_rejects_out_of_field(
  ((value, gamma, _), k) via fuzz.tuple(
    statement(),
    fuzz.either(fuzz.int_between(-1000, -1), fuzz.int_between(1, 1000)),
  ),
) fail {
  let g = scalar.from_int(gamma)
  commit_value(vk, value + k * field_prime, g) == commit_value(vk, value, g)
}
