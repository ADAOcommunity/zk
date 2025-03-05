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
  BatchOpeningFailed
  InvalidProofElements
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
  // 1. Compute challenges from transcript
  let challenges = compute_challenges(vk, proof, public_inputs)

  // 2. Compute public input polynomial evaluation
  let pi = compute_pi(public_inputs, challenges)

  // 3. Verify polynomial commitments
  when verify_poly_commitments(vk, proof, challenges) is {
    BPP(_err) -> BPP(PolynomialCommitmentError)
    BPB(valid) ->
      if !valid {
        BPP(PolynomialCommitmentError)
      } else {
        // 4. Verify batch opening proof
        when verify_batch_opening(vk, proof, challenges, pi) is {
          BPP(_err) -> BPP(PairingCheckFailed)
          BPB(valid) ->
            if valid {
              BPB(True)
            } else {
              BPP(PairingCheckFailed)
            }
        }
      }
  }
}

// Helper functions for verification
fn verify_polynomial_commitments(
  _vk: PlonkVerificationKey,
  proof: PlonkProof,
) -> BoolOrPlonkError {
  // Verify that the polynomial commitments are valid
  when validate_proof_elements(proof) is {
    BVV(_) -> BPP(InvalidProofElements)
    BVB(valid) ->
      if valid {
        BPB(True)
      } else {
        BPP(InvalidProofElements)
      }
  }
}

fn compute_linearization_polynomial(
  _vk: PlonkVerificationKey,
  proof: PlonkProof,
  _challenge_beta: common.Field,
  _challenge_gamma: common.Field,
) -> G1PointOrPlonkError {
  // Extract the commitments from the proof
  let a_commitment = proof.a
  // Compute the linearization polynomial
  // This is a placeholder implementation
  G(a_commitment)
}

fn verify_permutation_argument(
  _vk: PlonkVerificationKey,
  _proof: PlonkProof,
) -> BoolOrPlonkError {
  // Verify the permutation argument
  // This is a placeholder implementation
  BPB(True)
}

// Helper functions for verification steps

/// Compute challenges from transcript
fn compute_challenges(
  _vk: PlonkVerificationKey,
  proof: PlonkProof,
  _public_inputs: List<common.Field>,
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
  let v: common.Field = bytearray.to_int_big_endian(generate_transcript(ts5))
  let u: common.Field =
    bytearray.to_int_big_endian(
      generate_transcript(bytearray.concat(ts5, #[1])),
    )

  PlonkChallenges { beta, gamma, alpha, zeta, v, u }
}

/// Compute the linearization polynomial
fn compute_linearization(
  _vk: PlonkVerificationKey,
  proof: PlonkProof,
  challenges: PlonkChallenges,
) -> common.G1Point {
  // 1. Compute quotient terms
  let _l1 =
    common.field_mul(
      challenges.alpha,
      common.field_add(
        common.field_mul(proof.eval_a, proof.eval_b),
        common.field_mul(proof.eval_c, challenges.gamma),
      ),
    )

  // 2. Compute permutation terms
  // Compute z_h = zeta^2 - 1 (not used in this implementation yet)
  let _z_h =
    common.field_sub(
      common.field_mul(challenges.zeta, challenges.zeta),
      common.field_one(),
    )

  let _perm =
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
  // This is a placeholder implementation
  proof.a
}

/// Verify polynomial commitments
fn verify_poly_commitments(
  _vk: PlonkVerificationKey,
  proof: PlonkProof,
  _challenges: PlonkChallenges,
) -> BoolOrPlonkError {
  // Verify that the polynomial commitments are valid
  when validate_proof_elements(proof) is {
    BVV(_) -> BPP(InvalidProofElements)
    BVB(valid) ->
      if valid {
        BPB(True)
      } else {
        BPP(InvalidProofElements)
      }
  }
}

/// Compute public input polynomial
fn compute_pi(
  public_inputs: List<common.Field>,
  challenges: PlonkChallenges,
) -> common.Field {
  when public_inputs is {
    [] -> 0
    [input, ..rest] -> {
      let pi = common.field_mul(input, challenges.zeta)
      when rest is {
        [] -> pi
        [input2, ..rest2] -> {
          let pi2 =
            common.field_mul(
              input2,
              common.field_mul(challenges.zeta, challenges.zeta),
            )
          when rest2 is {
            [] -> common.field_add(pi, pi2)
            [input3, ..] -> {
              let pi3 =
                common.field_mul(
                  input3,
                  common.field_mul(
                    common.field_mul(challenges.zeta, challenges.zeta),
                    challenges.zeta,
                  ),
                )
              common.field_add(common.field_add(pi, pi2), pi3)
            }
          }
        }
      }
    }
  }
}

/// Verify batch opening proof
fn verify_batch_opening(
  vk: PlonkVerificationKey,
  proof: PlonkProof,
  challenges: PlonkChallenges,
  _pi: common.Field,
) -> BoolOrPlonkError {
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
  BPB(
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

// Helper function to validate proof elements
fn validate_proof_elements(proof: PlonkProof) -> BoolOrVerificationError {
  // Validate that all proof elements are valid G1 points
  when common.validate_g1_point(proof.a) is {
    common.Error(_) -> BVV(common.InvalidG1Point)
    common.Ok(_) ->
      when common.validate_g1_point(proof.b) is {
        common.Error(_) -> BVV(common.InvalidG1Point)
        common.Ok(_) ->
          when common.validate_g1_point(proof.c) is {
            common.Error(_) -> BVV(common.InvalidG1Point)
            common.Ok(_) ->
              when common.validate_g1_point(proof.z) is {
                common.Error(_) -> BVV(common.InvalidG1Point)
                common.Ok(_) ->
                  when common.validate_g1_point(proof.t1) is {
                    common.Error(_) -> BVV(common.InvalidG1Point)
                    common.Ok(_) ->
                      when common.validate_g1_point(proof.t2) is {
                        common.Error(_) -> BVV(common.InvalidG1Point)
                        common.Ok(_) ->
                          when common.validate_g1_point(proof.t3) is {
                            common.Error(_) -> BVV(common.InvalidG1Point)
                            common.Ok(_) -> BVB(True)
                          }
                      }
                  }
              }
          }
      }
  }
}
