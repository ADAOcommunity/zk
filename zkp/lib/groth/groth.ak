use aiken/builtin.{
  bls12_381_final_verify, bls12_381_g1_add, bls12_381_g1_scalar_mul,
  bls12_381_g1_uncompress, bls12_381_g2_uncompress, bls12_381_miller_loop,
  bls12_381_mul_miller_loop_result
}
use aiken/collection/list

pub type CompressedProof {
  a: ByteArray,
  b: ByteArray,
  c: ByteArray,
}

pub type CompressedVK {
  alpha: ByteArray,
  beta: ByteArray,
  gamma: ByteArray,
  delta: ByteArray,
  ic0: ByteArray,
  ic1: ByteArray,
}

pub type Proof {
  a: G1Element,
  b: G2Element,
  c: G1Element,
}

pub type VerifierKey {
  alpha: G1Element,
  beta: G2Element,
  gamma: G2Element,
  delta: G2Element,
  ic0: G1Element,
  ic1: G1Element,
}

pub fn uncompress_proof(c: CompressedProof) -> Proof {
  Proof {
    a: bls12_381_g1_uncompress(c.a),
    b: bls12_381_g2_uncompress(c.b),
    c: bls12_381_g1_uncompress(c.c),
  }
}

pub fn uncompress_vk(c: CompressedVK) -> VerifierKey {
  VerifierKey {
    alpha: bls12_381_g1_uncompress(c.alpha),
    beta: bls12_381_g2_uncompress(c.beta),
    gamma: bls12_381_g2_uncompress(c.gamma),
    delta: bls12_381_g2_uncompress(c.delta),
    ic0: bls12_381_g1_uncompress(c.ic0),
    ic1: bls12_381_g1_uncompress(c.ic1),
  }
}

pub fn verify_compressed(
  vk: CompressedVK,
  proof: CompressedProof,
  input: List<Int>
){
  let vk = uncompress_vk(vk)
  let proof = uncompress_proof(proof)
  verify(vk, proof, input)
}

pub fn pairing_check(
  a: G1Element,
  b: G2Element,
  c: G1Element,
  delta: G2Element,
  alpha: G1Element,
  beta: G2Element,
  k: G1Element,
  gamma: G2Element
) -> Bool {
  // e(A,B) = e(α,β) ∙ e(C,δ) ∙ e(K,γ)
  // e: miller loop
  // ∙: mul miller loop
  // =: final verify

  // Pair Components w/ Miller Loop
  let ab = bls12_381_miller_loop(a, b)
  let alphabeta = bls12_381_miller_loop(alpha, beta)

  let kgamma = bls12_381_miller_loop(k, gamma)
  let cdelta = bls12_381_miller_loop(c, delta)

  // Combine Miller Loop Results
  let mlr1 = bls12_381_mul_miller_loop_result(alphabeta, kgamma)
  let mlr2 = bls12_381_mul_miller_loop_result(mlr1, cdelta)

  // Final Equality Check
  bls12_381_final_verify(ab, mlr2)
}

// Main verification function
pub fn verify(vk: VerifierKey, proof: Proof, input: List<Int>) -> Bool {

  // Construct K
  let k1 = when list.head(input) is {
    Some(x) -> bls12_381_g1_scalar_mul(x, vk.ic0)
    None -> vk.ic0 // or handle error appropriately
  }
  let k2 = when list.tail(input) is {
    Some(tail) -> when list.head(tail) is {
      Some(x) -> bls12_381_g1_scalar_mul(x, vk.ic1)
      None -> vk.ic1 // handle empty tail
    }
    None -> vk.ic1 // handle empty input
  }
  let k = bls12_381_g1_add(k1, k2)

  // Pairing check
  pairing_check(
    proof.a,
    proof.b,
    proof.c,
    vk.delta,
    vk.alpha,
    vk.beta,
    k,
    vk.gamma
  )
}

// Emulate verification
// pub fn emulate() -> Bool {
//   let vk = verifier_key()
//   let proof = proof()
//   let input = input()
//   verify(vk, proof, input)
// }

// // Hardcoded input values
// pub fn input() -> List<Int> {
//   list.range(1, 104)
// }

// pub fn verifier_key() -> VerifierKey {
//   TODO
// }

// fn proof() -> Proof {
//   Proof {
//     a: bls12_381_g1_uncompress(#"8bc8cc3f11483138cc55d5f0389e67231f9e8465e5cb4a5a668e6e298d5c4febb2a18e86881c84dd03c5d33db65af272"),
//     b: bls12_381_g2_uncompress(#"a8e6ba4dbce6aa84de8ca1cd39d42353fcac89fe8cb800e728ada3ca4ae3b07baa68f76b9e4fa73eebf78cc609fa85d6166a3b69cd08cc59f2ff36e52dfdf231540a4212fdd4a142504c76066bddea342dd0183b2b11ed62cfc1497189a4db52"),
//     c: bls12_381_g1_uncompress(#"8e02a87c519c3145f984d25fdf769f74fbc36626c385d4554fb4bc1d7a12cbf669d40f257023b8b3c9a31e631aa8f981"),
//     }
// }