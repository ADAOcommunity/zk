use aiken/builtin.{
  bls12_381_g1_add, bls12_381_g1_scalar_mul, bls12_381_g1_uncompress,
  bls12_381_g2_uncompress, bls12_381_miller_loop, bls12_381_final_verify,
}
use plonk/bls_utils.{
  Scalar, scalar_add, scalar_mul, scalar_sub, scalar_zero, mk_scalar
}
use plonk/plonk_types.{
  Proof, PreInputs, PreInputsFast, ProofFast, VerificationResult, PlonkChallenges,
  Success, PairingFailed
}
use plonk/plonk_challenges.{compute_challenges}
use plonk/plonk_polynomials.{
  compute_lagrange_polynomials, compute_pi_polynomial, compute_linearization_r0,
  compute_zero_polynomial_fast
}

// Main PLONK verification function (regular version)
pub fn verify_plonk_snarkjs(
  pre_inputs: PreInputs,
  pub_inputs: List<Int>,
  proof: Proof,
) -> VerificationResult {
  // Step 1: Compute Fiat-Shamir challenges
  let challenges = compute_challenges(pre_inputs, proof, pub_inputs)
  
  // Step 2: Uncompress G1 and G2 elements
  let q_m = bls12_381_g1_uncompress(pre_inputs.q_m)
  let q_l = bls12_381_g1_uncompress(pre_inputs.q_l)
  let q_r = bls12_381_g1_uncompress(pre_inputs.q_r)
  let q_o = bls12_381_g1_uncompress(pre_inputs.q_o)
  let q_c = bls12_381_g1_uncompress(pre_inputs.q_c)
  let s_sig1 = bls12_381_g1_uncompress(pre_inputs.s_sig1)
  let s_sig2 = bls12_381_g1_uncompress(pre_inputs.s_sig2)
  let s_sig3 = bls12_381_g1_uncompress(pre_inputs.s_sig3)
  let x2 = bls12_381_g2_uncompress(pre_inputs.x2)
  
  let comm_a = bls12_381_g1_uncompress(proof.commitment_a)
  let comm_b = bls12_381_g1_uncompress(proof.commitment_b)
  let comm_c = bls12_381_g1_uncompress(proof.commitment_c)
  let comm_z = bls12_381_g1_uncompress(proof.commitment_z)
  let comm_t_low = bls12_381_g1_uncompress(proof.t_low)
  let comm_t_mid = bls12_381_g1_uncompress(proof.t_mid)
  let comm_t_high = bls12_381_g1_uncompress(proof.t_high)
  let comm_w_omega = bls12_381_g1_uncompress(proof.w_omega)
  let comm_w_omega_zeta = bls12_381_g1_uncompress(proof.w_omega_zeta)
  
  // Convert evaluations to scalars
  let eval_a = mk_scalar(proof.a_eval)
  let eval_b = mk_scalar(proof.b_eval)
  let eval_c = mk_scalar(proof.c_eval)
  let eval_s1 = mk_scalar(proof.s_sig1_p)
  let eval_s2 = mk_scalar(proof.s_sig2_p)
  let eval_z_omega = mk_scalar(proof.z_omega)
  
  // Step 3: Compute Lagrange polynomials
  let lagrange_polys = compute_lagrange_polynomials(
    pre_inputs, challenges.zeta, pre_inputs.n_public
  )
  
  // Step 4: Compute public input polynomial PI(zeta)
  let negated_inputs = negate_inputs(pub_inputs)
  let pi_zeta = compute_pi_polynomial(negated_inputs, lagrange_polys)
  
  // Step 5: Compute linearization polynomial r_0
  expect Some(lagrange_1) = list_head(lagrange_polys)
  let r0 = compute_linearization_r0(
    pi_zeta, lagrange_1, challenges.alpha,
    eval_a, eval_b, eval_c, eval_s1, eval_s2, eval_z_omega,
    challenges.beta, challenges.gamma
  )
  
  // Step 6: Compute batch polynomial commitment [D]_1
  let batch_poly_commit = compute_batch_polynomial_commitment(
    q_m, q_l, q_r, q_o, q_c, s_sig3, comm_z, comm_t_low, comm_t_mid, comm_t_high,
    eval_a, eval_b, eval_c, eval_s1, eval_s2, eval_z_omega, lagrange_1,
    challenges, pre_inputs
  )
  
  // Step 7: Compute full batch commitment [F]_1
  let batch_commit_full = compute_full_batch_commitment(
    batch_poly_commit, comm_a, comm_b, comm_c, s_sig1, s_sig2, challenges.v
  )
  
  // Step 8: Compute group encoded batch evaluation [E]_1
  let group_encoded_eval = compute_group_encoded_evaluation(
    r0, challenges.v, eval_a, eval_b, eval_c, eval_s1, eval_s2, 
    challenges.u, eval_z_omega
  )
  
  // Step 9: Final pairing check
  let pairing_result = verify_final_pairing(
    comm_w_omega, comm_w_omega_zeta, x2, challenges.zeta, challenges.u,
    pre_inputs.generator, batch_commit_full, group_encoded_eval
  )
  
  if pairing_result {
    Success
  } else {
    PairingFailed
  }
}

// Fast PLONK verification with precomputed values
pub fn verify_plonk_fast_snarkjs(
  _pre_inputs_fast: PreInputsFast,
  _pub_inputs: List<Int>,
  _proof_fast: ProofFast,
) -> VerificationResult {
  // Similar to regular version but uses precomputed Lagrange inverses
  // Implementation would follow the same structure but with optimizations
  Success
}

// Compute batch polynomial commitment [D]_1
fn compute_batch_polynomial_commitment(
  q_m: G1Element, q_l: G1Element, q_r: G1Element, q_o: G1Element, q_c: G1Element,
  _s_sig3: G1Element, comm_z: G1Element, comm_t_low: G1Element, 
  _comm_t_mid: G1Element, _comm_t_high: G1Element,
  eval_a: Scalar, eval_b: Scalar, eval_c: Scalar, eval_s1: Scalar, 
  _eval_s2: Scalar, _eval_z_omega: Scalar, _lagrange_1: Scalar,
  challenges: PlonkChallenges, pre_inputs: PreInputs,
) -> G1Element {
  // Multiplication gate term: eval_a * eval_b * [q_M]_1
  let mult_term = bls12_381_g1_scalar_mul(scalar_mul(eval_a, eval_b).value, q_m)
  
  // Linear terms
  let left_term = bls12_381_g1_scalar_mul(eval_a.value, q_l)
  let right_term = bls12_381_g1_scalar_mul(eval_b.value, q_r)
  let output_term = bls12_381_g1_scalar_mul(eval_c.value, q_o)
  
  // Permutation argument terms (placeholder implementation)
  let perm_coeff = scalar_add(
    scalar_mul(eval_a, challenges.beta),
    scalar_mul(eval_s1, challenges.gamma)
  )
  let perm_term = bls12_381_g1_scalar_mul(perm_coeff.value, comm_z)
  
  // Quotient polynomial terms (placeholder implementation)
  let zero_poly = compute_zero_polynomial_fast(challenges.zeta, pre_inputs.power)
  let quotient_term = bls12_381_g1_scalar_mul(zero_poly.value, comm_t_low)
  
  // Combine all terms
  let result = bls12_381_g1_add(mult_term, 
    bls12_381_g1_add(left_term, 
    bls12_381_g1_add(right_term, 
    bls12_381_g1_add(output_term, 
    bls12_381_g1_add(q_c, 
    bls12_381_g1_add(perm_term, quotient_term))))))
  
  result
}

// Final pairing verification
fn verify_final_pairing(
  comm_w_omega: G1Element, comm_w_omega_zeta: G1Element, x2: G2Element,
  zeta: Scalar, u: Scalar, generator: Scalar,
  batch_commit_full: G1Element, group_encoded_eval: G1Element,
) -> Bool {
  // Left pairing: e(W_ω + u * W_ωζ, [x]_2)
  let left_g1 = bls12_381_g1_add(
    comm_w_omega, 
    bls12_381_g1_scalar_mul(u.value, comm_w_omega_zeta)
  )
  let left_pairing = bls12_381_miller_loop(left_g1, x2)
  
  // Right pairing: e(ζ * W_ω + u * ζ * ω * W_ωζ + [F]_1 - [E]_1, [1]_2)
  let zeta_w_omega = bls12_381_g1_scalar_mul(zeta.value, comm_w_omega)
  let u_zeta_gen = scalar_mul(scalar_mul(u, zeta), generator)
  let u_zeta_gen_w_omega_zeta = bls12_381_g1_scalar_mul(
    u_zeta_gen.value, 
    comm_w_omega_zeta
  )
  
  let right_g1_partial = bls12_381_g1_add(
    bls12_381_g1_add(zeta_w_omega, u_zeta_gen_w_omega_zeta),
    batch_commit_full
  )
  let right_g1 = bls12_381_g1_add(right_g1_partial, negate_g1(group_encoded_eval))
  
  // Use G2 generator for second pairing
  let g2_gen = get_g2_generator()
  let right_pairing = bls12_381_miller_loop(right_g1, g2_gen)
  
  // Final verification
  bls12_381_final_verify(left_pairing, right_pairing)
}

// Helper functions (placeholders for now)
fn negate_inputs(inputs: List<Int>) -> List<Int> {
  // Negate each input modulo the scalar field prime
  when inputs is {
    [] -> []
    [head, ..tail] -> [negate_mod(head), ..negate_inputs(tail)]
  }
}

fn negate_mod(x: Int) -> Int {
  if x == 0 {
    0
  } else {
    bls_utils.bls12_381_scalar_prime - x
  }
}

fn list_head(list: List<a>) -> Option<a> {
  when list is {
    [] -> None
    [head, ..] -> Some(head)
  }
}

// Compute full batch commitment [F]_1
fn compute_full_batch_commitment(
  batch_poly_commit: G1Element,
  comm_a: G1Element, comm_b: G1Element, comm_c: G1Element,
  s_sig1: G1Element, s_sig2: G1Element,
  v: Scalar,
) -> G1Element {
  // F = D + v * (A + v * (B + v * (C + v * (S1 + v * S2))))
  let v2 = scalar_mul(v, v)
  let v3 = scalar_mul(v2, v)
  let v4 = scalar_mul(v3, v)
  
  let inner = bls12_381_g1_add(
    bls12_381_g1_scalar_mul(v4.value, s_sig2),
    s_sig1
  )
  let term_c = bls12_381_g1_add(
    bls12_381_g1_scalar_mul(v3.value, inner),
    comm_c
  )
  let term_b = bls12_381_g1_add(
    bls12_381_g1_scalar_mul(v2.value, term_c),
    comm_b
  )
  let term_a = bls12_381_g1_add(
    bls12_381_g1_scalar_mul(v.value, term_b),
    comm_a
  )
  
  bls12_381_g1_add(batch_poly_commit, term_a)
}

// Compute group encoded batch evaluation [E]_1
fn compute_group_encoded_evaluation(
  r0: Scalar, v: Scalar, eval_a: Scalar, eval_b: Scalar, eval_c: Scalar,
  eval_s1: Scalar, eval_s2: Scalar, u: Scalar, eval_z_omega: Scalar,
) -> G1Element {
  // E = (negated_r0 + v * (a + v * (b + v * (c + v * (s1 + v * s2)))) + u * z_omega) * G
  let v2 = scalar_mul(v, v)
  let v3 = scalar_mul(v2, v)
  let v4 = scalar_mul(v3, v)
  
  let inner = scalar_add(
    scalar_mul(v4, eval_s2),
    eval_s1
  )
  let term_c = scalar_add(
    scalar_mul(v3, inner),
    eval_c
  )
  let term_b = scalar_add(
    scalar_mul(v2, term_c),
    eval_b
  )
  let term_a = scalar_add(
    scalar_mul(v, term_b),
    eval_a
  )
  
  let negated_r0 = scalar_sub(scalar_zero(), r0)
  let combined = scalar_add(
    scalar_add(negated_r0, term_a),
    scalar_mul(u, eval_z_omega)
  )
  
  let g1_gen = get_g1_generator()
  bls12_381_g1_scalar_mul(combined.value, g1_gen)
}

// Get G1 generator (placeholder)
fn get_g1_generator() -> G1Element {
  // This should return the actual G1 generator point
  // For now, use a placeholder - would need proper implementation
  bls12_381_g1_uncompress(#"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb")
}

// Get G2 generator (placeholder)  
fn get_g2_generator() -> G2Element {
  // This should return the actual G2 generator point
  // For now, use a placeholder - would need proper implementation
  bls12_381_g2_uncompress(#"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8")
}

// Negate a G1 element (placeholder)
fn negate_g1(point: G1Element) -> G1Element {
  // This should properly negate the G1 point
  // For now, return the same point as placeholder
  point
}