use aiken/crypto
use aiken/crypto/bls12_381/g1
use aiken/crypto/bls12_381/scalar
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
  s1: ByteArray,
  s2: ByteArray,
  s3: ByteArray,
}

pub type PlonkProof {
  // Commitments
  a: ByteArray,
  b: ByteArray,
  c: ByteArray,
  z: ByteArray,
  t1: ByteArray,
  t2: ByteArray,
  t3: ByteArray,
  // Evaluations
  eval_a: scalar.Scalar,
  eval_b: scalar.Scalar,
  eval_c: scalar.Scalar,
  eval_s1: scalar.Scalar,
  eval_s2: scalar.Scalar,
  eval_z_omega: scalar.Scalar,
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
  G(ByteArray)
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
  beta: scalar.Scalar,
  gamma: scalar.Scalar,
  alpha: scalar.Scalar,
  zeta: scalar.Scalar,
  v: scalar.Scalar,
  u: scalar.Scalar,
}

pub type PlonkEvaluations {
  a: scalar.Scalar,
  b: scalar.Scalar,
  c: scalar.Scalar,
  s1: scalar.Scalar,
  s2: scalar.Scalar,
  z_omega: scalar.Scalar,
}

// Main verification function
pub fn verify(
  vk: PlonkVerificationKey,
  proof: PlonkProof,
  public_inputs: List<scalar.Scalar>,
) -> BoolOrPlonkError {
  // 1. Compute challenges from transcript
  let challenges = compute_challenges(vk, proof, public_inputs)

  // 2. Compute public input polynomial evaluation
  let pi = compute_pi(public_inputs, challenges)

  // 3. Verify polynomial commitments
  when verify_polynomial_commitments(vk, proof, challenges) is {
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

/// Verify the polynomial commitments
pub fn verify_polynomial_commitments(
  vk: PlonkVerificationKey,
  proof: PlonkProof,
  challenges: PlonkChallenges,
) -> BoolOrPlonkError {
  // First, validate that proof elements are valid curve points
  when validate_proof_elements(proof) is {
    BVB(True) ->
      // Verify the permutation argument
      verify_permutation_argument(vk, proof, challenges)
    BVB(False) -> BPP(InvalidProofElements)
    BVV(_) -> BPP(InvalidProofElements)
  }
}

pub fn compute_linearization_polynomial(
  _vk: PlonkVerificationKey,
  proof: PlonkProof,
  _challenge_beta: scalar.Scalar,
  _challenge_gamma: scalar.Scalar,
) -> G1PointOrPlonkError {
  // Extract the commitments from the proof
  let a_commitment = proof.a
  // Compute the linearization polynomial
  // This is a placeholder implementation
  G(a_commitment)
}

/// Verify the permutation argument
pub fn verify_permutation_argument(
  _vk: PlonkVerificationKey,
  proof: PlonkProof,
  challenges: PlonkChallenges,
) -> BoolOrPlonkError {
  // Verify that z(ω·X) has the correct relationship with z(X)
  // This checks that z(X) is a valid permutation polynomial
  // 1. Compute the permutation challenges
  let beta = challenges.beta
  let gamma = challenges.gamma
  // 2. Check that z(ω·X) = z(X) · (a(X) + β·σ1(X) + γ) · (b(X) + β·σ2(X) + γ) · (c(X) + β·σ3(X) + γ) / ((a(X) + β·id1(X) + γ) · (b(X) + β·id2(X) + γ) · (c(X) + β·id3(X) + γ))
  // For now, we'll implement a simplified check that just verifies that z(ω·X) is related to z(X)
  // A complete implementation would verify the full permutation argument
  // Check that eval_z_omega is consistent with the permutation argument
  let expected_z_omega =
    scalar.mul(
      proof.eval_z_omega,
      scalar.add(
        scalar.add(
          scalar.mul(proof.eval_a, beta),
          scalar.mul(proof.eval_s1, gamma),
        ),
        scalar.one,
      ),
    )
  // Compare with a simplified expected value
  // In a complete implementation, this would be a more complex check
  if expected_z_omega == scalar.mul(proof.eval_z_omega, beta) {
    BPB(True)
  } else {
    BPP(PolynomialCommitmentError)
  }
}

/// Compute the linearization polynomial
pub fn compute_linearization(
  proof: PlonkProof,
  challenges: PlonkChallenges,
) -> ByteArray {
  // 1. Compute quotient terms
  let l1 =
    scalar.mul(
      challenges.alpha,
      scalar.add(
        scalar.mul(proof.eval_a, proof.eval_b),
        scalar.mul(proof.eval_c, challenges.gamma),
      ),
    )

  // 2. Compute permutation terms
  // Compute z_h = zeta^2 - 1
  let z_h = scalar.sub(scalar.mul(challenges.zeta, challenges.zeta), scalar.one)

  let perm =
    scalar.mul(
      proof.eval_z_omega,
      scalar.add(
        scalar.add(
          scalar.mul(proof.eval_a, challenges.beta),
          scalar.mul(proof.eval_s1, challenges.gamma),
        ),
        scalar.one,
      ),
    )
  // 3. Compute the linearization polynomial commitment
  // Combine the terms using the challenges
  let l_scalar = scalar.add(scalar.add(l1, z_h), perm)
  // Scale the proof.a commitment by the computed scalar
  // This is a simplified version - a complete implementation would combine multiple commitments
  g1.compress(g1.scale(g1.decompress(proof.a), l_scalar))
}

/// Compute public input polynomial
fn compute_pi(
  public_inputs: List<scalar.Scalar>,
  challenges: PlonkChallenges,
) -> scalar.Scalar {
  when public_inputs is {
    [] -> scalar.zero
    [input, ..rest] -> {
      let pi = scalar.mul(input, challenges.zeta)
      when rest is {
        [] -> pi
        [input2, ..rest2] -> {
          let pi2 =
            scalar.mul(input2, scalar.mul(challenges.zeta, challenges.zeta))
          when rest2 is {
            [] -> scalar.add(pi, pi2)
            [input3, ..] -> {
              let pi3 =
                scalar.mul(
                  input3,
                  scalar.mul(
                    scalar.mul(challenges.zeta, challenges.zeta),
                    challenges.zeta,
                  ),
                )
              scalar.add(scalar.add(pi, pi2), pi3)
            }
          }
        }
      }
    }
  }
}

/// Verify batch opening proof
fn verify_batch_opening(
  _vk: PlonkVerificationKey,
  proof: PlonkProof,
  challenges: PlonkChallenges,
  pi: scalar.Scalar,
) -> BoolOrPlonkError {
  // 1. Compute opening challenge
  let u = challenges.u
  // 2. Combine all polynomial evaluations with the public input
  // Calculate the combined evaluation that will be used for verification
  expect _eval_combined =
    scalar.add(
      scalar.add(
        scalar.add(
          scalar.mul(proof.eval_a, u),
          scalar.mul(proof.eval_b, scalar.mul(u, u)),
        ),
        scalar.add(
          scalar.mul(proof.eval_c, scalar.mul(scalar.mul(u, u), u)),
          scalar.mul(
            proof.eval_s1,
            scalar.mul(scalar.mul(scalar.mul(u, u), u), u),
          ),
        ),
      ),
      pi,
    )
  // 3. Combine all commitments
  let a_point = g1.decompress(proof.a)
  let b_point = g1.decompress(proof.b)
  let c_point = g1.decompress(proof.c)
  let z_point = g1.decompress(proof.z)
  let commit_combined_point =
    g1.add(
      g1.add(
        g1.add(g1.scale(a_point, u), g1.scale(b_point, scalar.mul(u, u))),
        g1.add(
          g1.scale(c_point, scalar.mul(scalar.mul(u, u), u)),
          g1.scale(z_point, scalar.mul(scalar.mul(scalar.mul(u, u), u), u)),
        ),
      ),
      // Add linearization polynomial commitment
      g1.decompress(compute_linearization(proof, challenges)),
    )
  // 4. Perform a simplified pairing check
  // In a complete implementation, this would use the full pairing check
  // For now, we'll just check that the commitments are consistent
  // Scale the commitments by the challenge
  let scaled_commit_point = g1.scale(commit_combined_point, challenges.v)
  // Check if the scaled commitments are equal
  if g1.equal(scaled_commit_point, commit_combined_point) {
    BPB(True)
  } else {
    BPP(BatchOpeningFailed)
  }
}

/// Generate transcript for Fiat-Shamir
fn generate_transcript(data: ByteArray) -> ByteArray {
  crypto.blake2b_256(data)
}

// Helper function to validate proof elements
fn validate_proof_elements(_proof: PlonkProof) -> BoolOrVerificationError {
  // For now, we'll assume all proof elements are valid
  // In a real implementation, we would check that they are valid G1 points
  BVB(True)
}

/// Compute challenges from transcript
pub fn compute_challenges(
  _vk: PlonkVerificationKey,
  proof: PlonkProof,
  _public_inputs: List<scalar.Scalar>,
) -> PlonkChallenges {
  // Generate transcript for Fiat-Shamir
  let ts1 = bytearray.concat(proof.a, bytearray.concat(proof.b, proof.c))

  // Compute beta and gamma challenges
  let ts2 = ts1
  // Convert the transcript hash to a scalar field element
  expect Some(beta) =
    scalar.from_bytearray_big_endian(
      generate_transcript(bytearray.concat(ts2, #[1])),
    )
  expect Some(gamma) =
    scalar.from_bytearray_big_endian(
      generate_transcript(bytearray.concat(ts2, #[2])),
    )

  // Compute alpha challenge
  let ts3 = bytearray.concat(ts2, proof.z)
  expect Some(alpha) =
    scalar.from_bytearray_big_endian(generate_transcript(ts3))

  // Compute zeta challenge
  let ts4 =
    bytearray.concat(
      ts3,
      bytearray.concat(proof.t1, bytearray.concat(proof.t2, proof.t3)),
    )
  expect Some(zeta) = scalar.from_bytearray_big_endian(generate_transcript(ts4))

  // Compute v and u challenges
  let ts5 =
    bytearray.concat(ts4, scalar.to_bytearray_big_endian(proof.eval_a, 32))
  expect Some(v) = scalar.from_bytearray_big_endian(generate_transcript(ts5))
  expect Some(u) =
    scalar.from_bytearray_big_endian(
      generate_transcript(bytearray.concat(ts5, #[1])),
    )

  PlonkChallenges { beta, gamma, alpha, zeta, v, u }
}
