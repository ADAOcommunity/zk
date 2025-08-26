use aiken/builtin.{
  bls12_381_final_verify, bls12_381_g1_add, bls12_381_g1_scalar_mul,
  bls12_381_g1_uncompress, bls12_381_g2_uncompress, bls12_381_miller_loop,
  bls12_381_mul_miller_loop_result,
}

pub type G1Point =
  ByteArray

pub type G2Point =
  ByteArray

pub type Field =
  Int

pub type GrothVerificationKey {
  n_public: Int,
  vk_alpha_g1: G1Point,
  vk_beta_g2: G2Point,
  vk_gamma_g2: G2Point,
  vk_delta_g2: G2Point,
  vk_ic: List<G1Point>,
}

pub type PreparedGrothVerificationKey {
  vk: GrothVerificationKey,
  vk_alpha_beta: G1Point,
  vk_neg_gamma_g2: G2Point,
  vk_delta_neg_g2: G2Point,
}

pub type GrothProof {
  pi_a: G1Point,
  pi_b: G2Point,
  pi_c: G1Point,
}

pub type GrothError {
  InvalidProofFormat
  InvalidVerificationKey
  PairingCheckFailed
  InvalidPublicInput
}

pub fn pairing(g1: G1Point, g2: G2Point) {
  bls12_381_miller_loop(
    bls12_381_g1_uncompress(g1),
    bls12_381_g2_uncompress(g2),
  )
}

// anticipates prepared verification key and inputs
pub fn verify_prepared(
  prepared_vk: PreparedGrothVerificationKey,
  proof: GrothProof,
  prepared_inputs: List<Field>
) -> Bool {
  // Compute Linear Combination

  // Run the pairing check
  let pairing_result = pairing(proof.pi_a, prepared_vk.vk_neg_gamma_g2) *
                       pairing(prepared_vk.vk_alpha_beta, proof.pi_b) *
                       pairing(prepared_vk.vk_delta_neg_g2, proof.pi_c)

  pairing_result == pairing(
    prepared_vk.vk_alpha_g1
    prepared_vk.vk_beta_g2
  )
}