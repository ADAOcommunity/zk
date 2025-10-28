use plonk/bls_utils.{Scalar}

// PLONK Proof type - contains commitments and evaluations
pub type Proof {
  // Commitments (serialized G1 elements as ByteArrays)
  commitment_a: ByteArray,
  commitment_b: ByteArray, 
  commitment_c: ByteArray,
  commitment_z: ByteArray,
  t_low: ByteArray,
  t_mid: ByteArray,
  t_high: ByteArray,
  w_omega: ByteArray,
  w_omega_zeta: ByteArray,
  // Field element evaluations
  a_eval: Int,
  b_eval: Int,
  c_eval: Int,
  s_sig1_p: Int,
  s_sig2_p: Int,
  z_omega: Int,
}

// PLONK verification inputs
pub type PreInputs {
  n_public: Int,             // Number of public inputs
  power: Int,                // Power such that 2^power >= number of constraints
  k1: Scalar,               // First field element for disjoint left coset of H
  k2: Scalar,               // Second field element for disjoint left coset of H
  q_m: ByteArray,           // Committed multiplication gates polynomial
  q_l: ByteArray,           // Committed left inputs polynomial
  q_r: ByteArray,           // Committed right inputs polynomial
  q_o: ByteArray,           // Committed outputs polynomial
  q_c: ByteArray,           // Committed constants polynomial
  s_sig1: ByteArray,        // Committed first wire permutation polynomial
  s_sig2: ByteArray,        // Committed second wire permutation polynomial
  s_sig3: ByteArray,        // Committed third wire permutation polynomial
  x2: ByteArray,            // First order SRS over G2 (g^x where x is toxic waste)
  generator: Scalar,        // Generator of subgroup H
}

// Fast/optimized proof type with precomputed values
pub type ProofFast {
  // Same commitments as regular Proof
  commitment_a: ByteArray,
  commitment_b: ByteArray,
  commitment_c: ByteArray,
  commitment_z: ByteArray,
  t_low: ByteArray,
  t_mid: ByteArray,
  t_high: ByteArray,
  w_omega: ByteArray,
  w_omega_zeta: ByteArray,
  // Field element evaluations
  a_eval: Int,
  b_eval: Int,
  c_eval: Int,
  s_sig1_p: Int,
  s_sig2_p: Int,
  z_omega: Int,
  // Precomputed Lagrange polynomial inverses
  lagrange_inverses: List<Int>,
}

// Fast/optimized verification inputs with precomputed generators
pub type PreInputsFast {
  n: Int,                   // Number of constraints (upper bound)
  power: Int,               // n = 2^power
  k1: Scalar,               // First field element for disjoint left coset of H
  k2: Scalar,               // Second field element for disjoint left coset of H
  q_m: ByteArray,           // Committed multiplication gates polynomial
  q_l: ByteArray,           // Committed left inputs polynomial
  q_r: ByteArray,           // Committed right inputs polynomial
  q_o: ByteArray,           // Committed outputs polynomial
  q_c: ByteArray,           // Committed constants polynomial
  s_sig1: ByteArray,        // Committed first wire permutation polynomial
  s_sig2: ByteArray,        // Committed second wire permutation polynomial
  s_sig3: ByteArray,        // Committed third wire permutation polynomial
  x2: ByteArray,            // First order SRS over G2
  generators: List<Scalar>, // Powers of generator: [g, g^2, ..., g^{n_public}]
}

// Challenge values computed during Fiat-Shamir
pub type PlonkChallenges {
  beta: Scalar,
  gamma: Scalar,
  alpha: Scalar,
  zeta: Scalar,
  v: Scalar,
  u: Scalar,
}

// Result type for verification
pub type VerificationResult {
  Success
  InvalidProof
  InvalidInput
  PairingFailed
}

// Convert regular inputs to fast inputs
pub fn convert_to_fast_pre_inputs(pre_inputs: PreInputs) -> PreInputsFast {
  let n = pow_2(pre_inputs.power)
  let generators = generate_powers(pre_inputs.generator, pre_inputs.n_public)
  
  PreInputsFast {
    n: n,
    power: pre_inputs.power,
    k1: pre_inputs.k1,
    k2: pre_inputs.k2,
    q_m: pre_inputs.q_m,
    q_l: pre_inputs.q_l,
    q_r: pre_inputs.q_r,
    q_o: pre_inputs.q_o,
    q_c: pre_inputs.q_c,
    s_sig1: pre_inputs.s_sig1,
    s_sig2: pre_inputs.s_sig2,
    s_sig3: pre_inputs.s_sig3,
    x2: pre_inputs.x2,
    generators: generators,
  }
}

// Helper function to compute 2^n
fn pow_2(n: Int) -> Int {
  if n == 0 {
    1
  } else if n == 1 {
    2
  } else {
    2 * pow_2(n - 1)
  }
}

// Helper function to generate powers of a scalar [g^0, g^1, ..., g^n]
fn generate_powers(gen: Scalar, n: Int) -> List<Scalar> {
  generate_powers_helper(gen, n, bls_utils.scalar_one(), [])
}

fn generate_powers_helper(gen: Scalar, n: Int, current: Scalar, acc: List<Scalar>) -> List<Scalar> {
  if n < 0 {
    acc
  } else {
    let new_acc = [current, ..acc]
    let next = bls_utils.scalar_mul(current, gen)
    generate_powers_helper(gen, n - 1, next, new_acc)
  }
}

// Convert regular proof to fast proof with precomputed lagrange inverses
pub fn convert_to_fast_proof(
  pre_inputs_fast: PreInputsFast,
  pub_inputs: List<Int>,
  proof: Proof,
) -> ProofFast {
  // Compute Lagrange polynomial inverses
  let lagrange_invs = compute_lagrange_inverses(pre_inputs_fast, pub_inputs, proof)
  
  ProofFast {
    commitment_a: proof.commitment_a,
    commitment_b: proof.commitment_b,
    commitment_c: proof.commitment_c,
    commitment_z: proof.commitment_z,
    t_low: proof.t_low,
    t_mid: proof.t_mid,
    t_high: proof.t_high,
    w_omega: proof.w_omega,
    w_omega_zeta: proof.w_omega_zeta,
    a_eval: proof.a_eval,
    b_eval: proof.b_eval,
    c_eval: proof.c_eval,
    s_sig1_p: proof.s_sig1_p,
    s_sig2_p: proof.s_sig2_p,
    z_omega: proof.z_omega,
    lagrange_inverses: lagrange_invs,
  }
}

// Compute Lagrange polynomial inverses (placeholder implementation)
fn compute_lagrange_inverses(
  _pre_inputs_fast: PreInputsFast,
  _pub_inputs: List<Int>,
  _proof: Proof,
) -> List<Int> {
  // This would compute the actual Lagrange polynomial inverses
  // For now, return empty list as placeholder
  []
}