use aiken/builtin
use aiken/collection/list
use aiken/crypto/bls12_381/g1
use aiken/crypto/bls12_381/g2
use aiken/crypto/bls12_381/scalar
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

pub type G1PointOrGrothError {
  PGP(common.G1Point)
  PGG(GrothError)
}

pub type BoolOrGrothError {
  BGB(Bool)
  BGG(GrothError)
}

// Main verification function
pub fn verify(
  vk: GrothVerificationKey,
  proof: GrothProof,
  public_inputs: List<common.Field>,
) -> BoolOrGrothError {
  // Verify sizes match
  expect
    when verify_sizes(vk, public_inputs) is {
      Some(err) -> {
        trace BGG(err)
        fail
      }
      None -> True
    }
  // Verify proof elements are valid
  expect
    when verify_proof_elements(proof) is {
      Some(err) -> {
        trace BGG(err)
        fail
      }
      None -> True
    }
  // Prepare inputs (negate first element)
  let prepared_inputs = prepare_inputs(public_inputs)
  // Compute the linear combination of inputs with IC
  when compute_linear_combination(vk.vk_ic, prepared_inputs) is {
    PGG(err) -> BGG(err)
    PGP(vk_x) -> {
      // Perform pairing checks
      let e_ab = pairing(proof.pi_a, proof.pi_b)
      let e_alpha_beta = pairing(vk.vk_alpha_g1, vk.vk_beta_g2)
      let e_vk_gamma = pairing(vk_x, vk.vk_gamma_g2)
      let e_c_delta = pairing(proof.pi_c, vk.vk_delta_g2)

      // Final verification
      let mlr1 =
        builtin.bls12_381_mul_miller_loop_result(e_alpha_beta, e_vk_gamma)
      let mlr2 = builtin.bls12_381_mul_miller_loop_result(mlr1, e_c_delta)
      if builtin.bls12_381_final_verify(e_ab, mlr2) {
        BGB(True)
      } else {
        BGG(PairingCheckFailed)
      }
    }
  }
}

// Helper function for pairing computation
// Optimized to use the standard library's BLS12-381 implementation more efficiently
fn pairing(g1: common.G1Point, g2: common.G2Point) {
  // Convert G1Point to ByteArray
  let g1_bytes = common.serialize_g1_point(g1)
  // Convert G2Point to ByteArray
  let g2_bytes = common.serialize_g2_point(g2)
  // Use the standard library's decompress functions directly
  let g1_element = g1.decompress(g1_bytes)
  let g2_element = g2.decompress(g2_bytes)
  // Perform the pairing
  builtin.bls12_381_miller_loop(g1_element, g2_element)
}

// Helper function to compute linear combination
fn compute_linear_combination(
  ic: List<common.G1Point>,
  inputs: List<common.Field>,
) -> G1PointOrGrothError {
  when ic is {
    [] -> PGG(InvalidVerificationKey)
    [vk_0, ..rest] -> {
      // Convert the first IC element to a G1 element
      let vk_0_bytes = common.serialize_g1_point(vk_0)
      let init_element = g1.decompress(vk_0_bytes)
      // Combine the rest of the inputs
      let result = combine_inputs(rest, inputs, init_element)
      // Convert back to our G1Point representation
      let result_bytes = g1.compress(result)
      when common.g1_decompress(result_bytes) is {
        Some(point) -> PGP(point)
        None -> PGG(InvalidVerificationKey)
      }
    }
  }
}

// Optimized function to combine inputs using the standard library's BLS12-381 implementation
fn combine_inputs(ic: List<common.G1Point>, inputs: List<common.Field>, acc) {
  when (ic, inputs) is {
    ([], _) | (_, []) -> acc
    ([vk_i, ..rest_ic], [input, ..rest_inputs]) -> {
      // Convert the IC element to a G1 element
      let vk_i_bytes = common.serialize_g1_point(vk_i)
      let vk_i_element = g1.decompress(vk_i_bytes)
      // Convert Field to Scalar for g1.scale
      let scalar_input =
        when scalar.new(input) is {
          Some(s) -> s
          None -> scalar.zero
        }
      // Multiply by the input and add to accumulator
      let term = g1.scale(vk_i_element, scalar_input)
      let new_acc = g1.add(acc, term)
      // Continue with the rest of the inputs
      combine_inputs(rest_ic, rest_inputs, new_acc)
    }
  }
}

// Helper function to negate a field element
fn negate_field(x: common.Field) -> common.Field {
  if x == 0 {
    x
  } else {
    common.bls12_381_prime - x
  }
}

// Helper function to verify the proof size matches expected public input size
fn verify_sizes(
  vk: GrothVerificationKey,
  public_inputs: List<common.Field>,
) -> Option<GrothError> {
  if list.length(public_inputs) != vk.n_public {
    Some(InvalidPublicInput)
  } else {
    None
  }
}

// Helper function to prepare public inputs for verification
fn prepare_inputs(inputs: List<common.Field>) -> List<common.Field> {
  // The first element should be negated as per the protocol
  when inputs is {
    [] -> []
    [first, ..rest] -> [negate_field(first), ..rest]
  }
}

// Helper function to verify proof elements are valid curve points
fn verify_proof_elements(proof: GrothProof) -> Option<GrothError> {
  // Convert G1 points to ByteArray
  let pi_a_bytes = common.serialize_g1_point(proof.pi_a)
  let pi_c_bytes = common.serialize_g1_point(proof.pi_c)
  // Convert G2 point to ByteArray
  let pi_b_bytes = common.serialize_g2_point(proof.pi_b)
  // Validate the points
  let valid_a =
    when common.g1_decompress(pi_a_bytes) is {
      Some(_) -> True
      None -> False
    }
  let valid_b =
    when common.g2_decompress(pi_b_bytes) is {
      Some(_) -> True
      None -> False
    }
  let valid_c =
    when common.g1_decompress(pi_c_bytes) is {
      Some(_) -> True
      None -> False
    }

  if valid_a && valid_b && valid_c {
    None
  } else {
    Some(InvalidProofFormat)
  }
}
