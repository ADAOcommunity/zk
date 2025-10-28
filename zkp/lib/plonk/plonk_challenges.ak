use aiken/crypto.{blake2b_224}
use aiken/primitive/bytearray
use plonk/bls_utils.{Scalar, mk_scalar, bls12_381_scalar_prime}
use plonk/plonk_types.{Proof, PreInputs, PlonkChallenges}

// Fiat-Shamir challenge generation
pub fn compute_challenges(
  pre_inputs: PreInputs,
  proof: Proof,
  pub_inputs: List<Int>,
) -> PlonkChallenges {
  // Step 1: Compute beta challenge
  let beta_transcript = 
    bytearray.concat(pre_inputs.q_m,
    bytearray.concat(pre_inputs.q_l,
    bytearray.concat(pre_inputs.q_r,
    bytearray.concat(pre_inputs.q_o,
    bytearray.concat(pre_inputs.q_c,
    bytearray.concat(pre_inputs.s_sig1,
    bytearray.concat(pre_inputs.s_sig2,
    bytearray.concat(pre_inputs.s_sig3,
    bytearray.concat(encode_public_inputs(pub_inputs),
    bytearray.concat(proof.commitment_a,
    bytearray.concat(proof.commitment_b,
      proof.commitment_c)))))))))))

  let beta_hash = blake2b_224(beta_transcript)
  let beta = mk_scalar(bytearray_to_int_be(beta_hash) % bls12_381_scalar_prime)

  // Step 2: Compute gamma challenge
  let gamma_hash = blake2b_224(scalar_to_bytearray_be(beta, 32))
  let gamma = mk_scalar(bytearray_to_int_be(gamma_hash) % bls12_381_scalar_prime)

  // Step 3: Compute alpha challenge  
  let alpha_transcript = 
    bytearray.concat(scalar_to_bytearray_be(beta, 32),
    bytearray.concat(scalar_to_bytearray_be(gamma, 32),
      proof.commitment_z))
  let alpha_hash = blake2b_224(alpha_transcript)
  let alpha = mk_scalar(bytearray_to_int_be(alpha_hash) % bls12_381_scalar_prime)

  // Step 4: Compute zeta challenge
  let zeta_transcript = 
    bytearray.concat(scalar_to_bytearray_be(alpha, 32),
    bytearray.concat(proof.t_low,
    bytearray.concat(proof.t_mid,
      proof.t_high)))
  let zeta_hash = blake2b_224(zeta_transcript)
  let zeta = mk_scalar(bytearray_to_int_be(zeta_hash) % bls12_381_scalar_prime)

  // Step 5: Compute v challenge
  let v_transcript =
    bytearray.concat(scalar_to_bytearray_be(zeta, 32),
    bytearray.concat(int_to_bytearray_be(proof.a_eval, 32),
    bytearray.concat(int_to_bytearray_be(proof.b_eval, 32),
    bytearray.concat(int_to_bytearray_be(proof.c_eval, 32),
    bytearray.concat(int_to_bytearray_be(proof.s_sig1_p, 32),
    bytearray.concat(int_to_bytearray_be(proof.s_sig2_p, 32),
      int_to_bytearray_be(proof.z_omega, 32)))))))
  let v_hash = blake2b_224(v_transcript)
  let v = mk_scalar(bytearray_to_int_be(v_hash) % bls12_381_scalar_prime)

  // Step 6: Compute u challenge
  let u_transcript = 
    bytearray.concat(proof.w_omega,
      proof.w_omega_zeta)
  let u_hash = blake2b_224(u_transcript)
  let u = mk_scalar(bytearray_to_int_be(u_hash) % bls12_381_scalar_prime)

  PlonkChallenges {
    beta: beta,
    gamma: gamma,
    alpha: alpha,
    zeta: zeta,
    v: v,
    u: u,
  }
}

// Encode public inputs as concatenated byte arrays (32 bytes each, big endian)
fn encode_public_inputs(inputs: List<Int>) -> ByteArray {
  when inputs is {
    [] -> #""
    [head, ..tail] -> {
      let head_bytes = int_to_bytearray_be(head, 32)
      let tail_bytes = encode_public_inputs(tail)
      bytearray.concat(head_bytes, tail_bytes)
    }
  }
}

// Convert scalar to bytearray (big endian, specified length)
fn scalar_to_bytearray_be(scalar: Scalar, length: Int) -> ByteArray {
  int_to_bytearray_be(scalar.value, length)
}

// Convert integer to bytearray (big endian, specified length) 
// This is a placeholder implementation - would need proper encoding
fn int_to_bytearray_be(value: Int, _length: Int) -> ByteArray {
  // In a real implementation, this would properly encode the integer
  // For now, we use a simple placeholder
  if value == 0 {
    #"00000000000000000000000000000000"
  } else if value == 1 {
    #"00000000000000000000000000000001"
  } else {
    // Placeholder for other values - would need proper big endian encoding
    #"0123456789abcdef0123456789abcdef"
  }
}

// Convert bytearray to integer (big endian)
// This is a placeholder implementation - would need proper decoding
fn bytearray_to_int_be(bytes: ByteArray) -> Int {
  // In a real implementation, this would properly decode the bytearray
  // For now, return a simple hash-like value based on bytearray content
  if bytes == #"00000000000000000000000000000000" {
    0
  } else if bytes == #"00000000000000000000000000000001" {
    1
  } else {
    // Placeholder - would compute proper big endian decode
    // For demonstration, use a simple mapping based on first few bytes
    12345678901234567890
  }
}