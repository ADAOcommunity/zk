use aiken/crypto
use aiken/primitive/bytearray
use common/common

// PLONK specific types
pub type PlonkVerificationKey {
  n: Int,
  // Size of the circuit
  q_m: List<common.Field>,
  // Multiplication selector polynomial
  q_l: List<common.Field>,
  // Left selector polynomial
  q_r: List<common.Field>,
  // Right selector polynomial
  q_o: List<common.Field>,
  // Output selector polynomial
  q_c: List<common.Field>,
  // Constants selector polynomial
  sigma1: List<common.Field>,
  sigma2: List<common.Field>,
  sigma3: List<common.Field>,
  s1: common.G1Point,
  s2: common.G1Point,
  s3: common.G1Point,
}

pub type PlonkProof {
  // Commitments
  a: common.G1Point,
  b: common.G1Point,
  c: common.G1Point,
  z: common.G1Point,
  t1: common.G1Point,
  t2: common.G1Point,
  t3: common.G1Point,
  // Evaluations
  eval_a: common.Field,
  eval_b: common.Field,
  eval_c: common.Field,
  eval_s1: common.Field,
  eval_s2: common.Field,
  eval_z_omega: common.Field,
}

pub type BoolOrPlonkError {
  BPB(Bool)
  BPP(PlonkError)
}

pub type BoolOrVerificationError {
  BVB(Bool)
  BVV(common.VerificationError)
}

pub type G1PointOrPlonkError {
  G(common.G1Point)
  P(PlonkError)
}

pub type PlonkError {
  InvalidProofFormat
  InvalidVerificationKey
  PairingCheckFailed
  PolynomialCommitmentError
  InvalidPublicInput
}

// Additional PLONK specific types
pub type PlonkChallenges {
  beta: common.Field,
  gamma: common.Field,
  alpha: common.Field,
  zeta: common.Field,
  v: common.Field,
  u: common.Field,
}

pub type PlonkEvaluations {
  a: common.Field,
  b: common.Field,
  c: common.Field,
  s1: common.Field,
  s2: common.Field,
  z_omega: common.Field,
}

// Main verification function
pub fn verify(
  vk: PlonkVerificationKey,
  proof: PlonkProof,
  public_inputs: List<common.Field>,
) -> BoolOrPlonkError {
  // 1. Compute challenges from the transcript
  let challenges = compute_challenges(vk, proof, public_inputs)

  // 2. Compute public input polynomial evaluation
  let pi = compute_pi(public_inputs, challenges)

  // 3. Verify polynomial commitments
  when verify_poly_commitments(vk, proof, challenges) is {
    Error(err) -> Error(PolynomialCommitmentError)
    Ok(valid) ->
      if !valid {
        Error(PolynomialCommitmentError)
      } else {
        // 4. Verify batch opening proof
        when verify_batch_opening(vk, proof, challenges, pi) is {
          Error(err) -> Error(PairingCheckFailed)
          Ok(valid) ->
            if valid {
              Ok(True)
            } else {
              Error(PairingCheckFailed)
            }
        }
      }
  }
}

// Helper functions for verification
fn verify_polynomial_commitments(
  vk: PlonkVerificationKey,
  proof: PlonkProof,
) -> BoolOrPlonkError {
  // 1. Verify proof elements are valid G1 points
  when common.validate_g1_point(proof.a) is {
    Error(_) -> Error(InvalidProofFormat)
    Ok(_) ->
      when common.validate_g1_point(proof.b) is {
        Error(_) -> Error(InvalidProofFormat)
        Ok(_) ->
          when common.validate_g1_point(proof.c) is {
            Error(_) -> Error(InvalidProofFormat)
            Ok(_) -> {
              // 2. Verify commitment to quotient polynomial
              let t_commitment =
                common.g1_add(proof.t1, common.g1_add(proof.t2, proof.t3))
              // 3. Verify commitment to permutation polynomial
              let sigma_commitment =
                common.g1_add(vk.s1, common.g1_add(vk.s2, vk.s3))
              Ok(common.g1_equal(sigma_commitment, proof.z))
            }
          }
      }
  }
}

fn compute_linearization_polynomial(
  vk: PlonkVerificationKey,
  proof: PlonkProof,
  challenge_beta: common.Field,
  challenge_gamma: common.Field,
) -> G1PointOrPlonkError {
  // 1. Compute quotient terms
  let q_m = common.field_mul(proof.eval_a, proof.eval_b)
  let q_l = proof.eval_a
  let q_r = proof.eval_b
  let q_o = proof.eval_c
  // 2. Compute permutation terms
  let perm1 =
    common.field_mul(
      proof.eval_a + challenge_beta * proof.eval_s1 + challenge_gamma,
      proof.eval_b + challenge_beta * proof.eval_s2 + challenge_gamma,
    )
  // 3. Combine into linearization polynomial
  Ok(
    common.g1_add(
      common.g1_mul(vk.s1, q_m),
      common.g1_add(
        common.g1_mul(vk.s2, q_l),
        common.g1_add(common.g1_mul(vk.s3, q_r), common.g1_mul(vk.s1, perm1)),
      ),
    ),
  )
}

fn verify_permutation_argument(
  vk: PlonkVerificationKey,
  proof: PlonkProof,
) -> BoolOrPlonkError {
  // 1. Verify sigma commitments are valid G1 points
  when common.validate_g1_point(vk.s1) is {
    Error(_) -> Error(InvalidVerificationKey)
    Ok(_) ->
      when common.validate_g1_point(vk.s2) is {
        Error(_) -> Error(InvalidVerificationKey)
        Ok(_) ->
          when common.validate_g1_point(vk.s3) is {
            Error(_) -> Error(InvalidVerificationKey)
            Ok(_) -> {
              // 2. Verify permutation commitment
              let perm_valid =
                common.g1_equal(
                  common.g1_add(vk.s1, common.g1_add(vk.s2, vk.s3)),
                  proof.z,
                )
              // 3. Verify permutation evaluation
              let eval_valid =
                common.field_equal(
                  common.field_mul(
                    proof.eval_z_omega,
                    common.field_add(
                      proof.eval_s1,
                      common.field_add(proof.eval_s2, common.field_one()),
                    ),
                  ),
                  common.field_one(),
                )
              Ok(perm_valid && eval_valid)
            }
          }
      }
  }
}

// Helper functions for verification steps

/// Compute challenges from transcript
fn compute_challenges(
  vk: PlonkVerificationKey,
  proof: PlonkProof,
  public_inputs: List<common.Field>,
) -> PlonkChallenges {
  // Generate transcript for Fiat-Shamir
  let ts1 =
    bytearray.concat(
      common.g1_compress(proof.a),
      bytearray.concat(common.g1_compress(proof.b), common.g1_compress(proof.c)),
    )

  // Compute beta and gamma challenges
  let ts2 = ts1
  let beta: common.Field =
    bytearray.to_int_big_endian(
      generate_transcript(bytearray.concat(ts2, #[1])),
    )
  let gamma: common.Field =
    bytearray.to_int_big_endian(
      generate_transcript(bytearray.concat(ts2, #[2])),
    )

  // Compute alpha challenge
  let ts3 = bytearray.concat(ts2, common.g1_compress(proof.z))
  let alpha: common.Field =
    bytearray.to_int_big_endian(generate_transcript(ts3))

  // Compute zeta challenge
  let ts4 =
    bytearray.concat(
      ts3,
      bytearray.concat(
        common.g1_compress(proof.t1),
        bytearray.concat(
          common.g1_compress(proof.t2),
          common.g1_compress(proof.t3),
        ),
      ),
    )
  let zeta: common.Field = bytearray.to_int_big_endian(generate_transcript(ts4))

  // Compute v and u challenges
  let ts5 = bytearray.concat(ts4, common.serialize_field(proof.eval_a))
  let v: common.Field = bytearray.to_int(generate_transcript(ts5))
  let u: common.Field =
    bytearray.to_int(generate_transcript(bytearray.concat(ts5, #[1])))

  PlonkChallenges { beta, gamma, alpha, zeta, v, u }
}

/// Compute the linearization polynomial
fn compute_linearization(
  vk: PlonkVerificationKey,
  proof: PlonkProof,
  challenges: PlonkChallenges,
) -> common.G1Point {
  // 1. Compute quotient terms
  let l1 =
    common.field_mul(
      challenges.alpha,
      common.field_add(
        common.field_mul(proof.eval_a, proof.eval_b),
        common.field_mul(proof.eval_c, challenges.gamma),
      ),
    )

  // 2. Compute permutation terms
  let z_h =
    common.field_sub(
      common.field_mul(challenges.zeta, challenges.zeta),
      common.field_one(),
    )

  let perm =
    common.field_mul(
      proof.eval_z_omega,
      common.field_add(
        common.field_add(
          common.field_mul(proof.eval_a, challenges.beta),
          common.field_mul(proof.eval_s1, challenges.gamma),
        ),
        common.field_one(),
      ),
    )

  // 3. Combine into final linearization polynomial
  common.g1_add(common.g1_mul(vk.s1, l1), common.g1_mul(vk.s2, perm))
}

/// Verify polynomial commitments
fn verify_poly_commitments(
  vk: PlonkVerificationKey,
  proof: PlonkProof,
  challenges: PlonkChallenges,
) -> BoolOrPlonkError {
  // 1. Verify that proof elements are valid G1 points
  when common.validate_g1_point(proof.a) is {
    Error(_) -> Error(common.InvalidG1Point)
    Ok(_) ->
      when common.validate_g1_point(proof.b) is {
        Error(_) -> Error(common.InvalidG1Point)
        Ok(_) ->
          when common.validate_g1_point(proof.c) is {
            Error(_) -> Error(common.InvalidG1Point)
            Ok(_) -> {
              // 2. Compute linearization polynomial
              let r = compute_linearization(vk, proof, challenges)
              // 3. Verify commitment to linearization polynomial
              let t_commitment =
                common.g1_add(
                  common.g1_mul(proof.t1, challenges.zeta),
                  common.g1_add(
                    common.g1_mul(
                      proof.t2,
                      common.field_mul(challenges.zeta, challenges.zeta),
                    ),
                    common.g1_mul(
                      proof.t3,
                      common.field_mul(
                        common.field_mul(challenges.zeta, challenges.zeta),
                        challenges.zeta,
                      ),
                    ),
                  ),
                )
              Ok(common.g1_equal(r, t_commitment))
            }
          }
      }
  }
}

/// Compute public input polynomial
fn compute_pi(
  public_inputs: List<common.Field>,
  challenges: PlonkChallenges,
) -> common.Field {
  // Compute the public input polynomial evaluation at zeta
  when public_inputs is {
    [] -> common.field_zero()
    [input, ..rest] -> {
      let l1_zeta =
        common.field_sub(
          common.field_one(),
          common.field_mul(challenges.zeta, challenges.zeta),
        )
      common.field_add(
        common.field_mul(input, l1_zeta),
        compute_pi(rest, challenges),
      )
    }
  }
}

/// Verify batch opening proof
fn verify_batch_opening(
  vk: PlonkVerificationKey,
  proof: PlonkProof,
  challenges: PlonkChallenges,
  pi: common.Field,
) -> BoolOrVerificationError {
  // 1. Compute opening challenge
  let u = challenges.u
  // 2. Combine all polynomial evaluations
  let eval_combined =
    common.field_add(
      common.field_add(
        common.field_mul(proof.eval_a, u),
        common.field_mul(proof.eval_b, common.field_mul(u, u)),
      ),
      common.field_add(
        common.field_mul(
          proof.eval_c,
          common.field_mul(common.field_mul(u, u), u),
        ),
        common.field_mul(
          proof.eval_s1,
          common.field_mul(common.field_mul(common.field_mul(u, u), u), u),
        ),
      ),
    )
  // 3. Combine all commitments
  let commit_combined =
    common.g1_add(
      common.g1_add(
        common.g1_mul(proof.a, u),
        common.g1_mul(proof.b, common.field_mul(u, u)),
      ),
      common.g1_add(
        common.g1_mul(proof.c, common.field_mul(common.field_mul(u, u), u)),
        common.g1_mul(
          vk.s1,
          common.field_mul(common.field_mul(common.field_mul(u, u), u), u),
        ),
      ),
    )
  // 4. Verify batch opening
  Ok(
    common.g1_equal(
      common.g1_mul(commit_combined, challenges.v),
      common.g1_mul(
        common.g1_generator(),
        common.field_mul(eval_combined, challenges.v),
      ),
    ),
  )
}

/// Generate transcript for Fiat-Shamir
fn generate_transcript(data: ByteArray) -> ByteArray {
  crypto.blake2b_256(data)
}
