use aiken/builtin
use aiken/bytearray
use aiken/crypto
use common/common

// Groth16 specific types
pub type GrothVerificationKey {
  n_public: Int,
  vk_alpha_g1: common.G1Point,
  vk_beta_g2: common.G2Point,
  vk_gamma_g2: common.G2Point,
  vk_delta_g2: common.G2Point,
  vk_ic: List<common.G1Point>,
}

pub type GrothProof {
  pi_a: common.G1Point,
  pi_b: common.G2Point,
  pi_c: common.G1Point,
}

pub type GrothError {
  InvalidProofFormat
  InvalidVerificationKey
  PairingCheckFailed
  InvalidPublicInput
}

// Main verification function
pub fn verify(
  vk: GrothVerificationKey,
  proof: GrothProof,
  public_inputs: List<common.Field>,
) -> Result<Bool, GrothError> {
  // Verify sizes match
  verify_sizes(vk, public_inputs)?
  
  // Verify proof elements are valid
  verify_proof_elements(proof)?
  
  // Prepare inputs (negate first element)
  let prepared_inputs = prepare_inputs(public_inputs)
  
  // Compute the linear combination of inputs with IC
  let vk_x = compute_linear_combination(vk.vk_ic, prepared_inputs)?

  // Perform pairing checks
  let e_ab = pairing(proof.pi_a, proof.pi_b)
  let e_alpha_beta = pairing(vk.vk_alpha_g1, vk.vk_beta_g2)
  let e_vk_gamma = pairing(vk_x, vk.vk_gamma_g2)
  let e_c_delta = pairing(proof.pi_c, vk.vk_delta_g2)

  // Final verification
  let mlr1 = builtin.bls12_381_mul_miller_loop_result(e_alpha_beta, e_vk_gamma)
  let mlr2 = builtin.bls12_381_mul_miller_loop_result(mlr1, e_c_delta)
  
  Ok(builtin.bls12_381_final_verify(e_ab, mlr2))
}

// Helper function for pairing computation
fn pairing(g1: common.G1Point, g2: common.G2Point) -> builtin.MillerLoopResult {
  builtin.bls12_381_miller_loop(
    builtin.bls12_381_g1_uncompress(g1),
    builtin.bls12_381_g2_uncompress(g2),
  )
}

// Helper function to compute linear combination
fn compute_linear_combination(
  ic: List<common.G1Point>,
  inputs: List<common.Field>,
) -> Result<common.G1Point, GrothError> {
  when ic is {
    [] -> Error(InvalidVerificationKey)
    [vk_0, ..rest] -> {
      let init = builtin.bls12_381_g1_uncompress(vk_0)
      Ok(combine_inputs(rest, inputs, init))
    }
  }
}

fn combine_inputs(
  ic: List<common.G1Point>,
  inputs: List<common.Field>,
  acc: common.G1Point,
) -> common.G1Point {
  when (ic, inputs) is {
    ([], _) | (_, []) -> acc
    ([vk_i, ..rest_ic], [input, ..rest_inputs]) -> {
      let term = builtin.bls12_381_g1_scalar_mul(
        input,
        builtin.bls12_381_g1_uncompress(vk_i),
      )
      let new_acc = builtin.bls12_381_g1_add(acc, term)
      combine_inputs(rest_ic, rest_inputs, new_acc)
    }
  }
}

// Helper function to negate a field element
fn negate_field(x: common.Field) -> common.Field {
  // In BLS12-381, negation is done by subtracting from the modulus
  // This is handled by the builtin function
  builtin.bls12_381_scalar_negate(x)
}

// Helper function to verify the proof size matches expected public input size
fn verify_sizes(
  vk: GrothVerificationKey,
  public_inputs: List<common.Field>,
) -> Result<Void, GrothError> {
  if builtin.length(public_inputs) != vk.n_public {
    Error(InvalidPublicInput)
  } else {
    Ok(void)
  }
}

// Helper function to prepare public inputs for verification
fn prepare_inputs(
  inputs: List<common.Field>,
) -> List<common.Field> {
  // The first element should be negated as per the protocol
  when inputs is {
    [] -> []
    [first, ..rest] -> [negate_field(first), ..rest]
  }
}

// Helper function to verify proof elements are valid curve points
fn verify_proof_elements(proof: GrothProof) -> Result<Void, GrothError> {
  let valid_a = builtin.bls12_381_g1_validate(proof.pi_a)
  let valid_b = builtin.bls12_381_g2_validate(proof.pi_b)
  let valid_c = builtin.bls12_381_g1_validate(proof.pi_c)

  if valid_a && valid_b && valid_c {
    Ok(void)
  } else {
    Error(InvalidProofFormat)
  }
}
