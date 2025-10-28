// PLONK Zero-Knowledge Proof Verifier in Aiken
// Translated from Haskell implementation

use plonk/plonk_verifier.{verify_plonk_snarkjs, verify_plonk_fast_snarkjs}
use plonk/plonk_types.{
  Proof, PreInputs, PreInputsFast, ProofFast, VerificationResult, Success
}
use plonk/bls_utils.{mk_scalar}

/// Main PLONK verification function (standard version)
/// Verifies a PLONK proof using the SnarkJS format
pub fn verify(
  pre_inputs: PreInputs,
  pub_inputs: List<Int>, 
  proof: Proof,
) -> VerificationResult {
  verify_plonk_snarkjs(pre_inputs, pub_inputs, proof)
}

/// Fast PLONK verification with precomputed values
/// Uses optimized computation with precomputed Lagrange polynomial inverses
pub fn verify_fast(
  pre_inputs_fast: PreInputsFast,
  pub_inputs: List<Int>,
  proof_fast: ProofFast,
) -> VerificationResult {
  verify_plonk_fast_snarkjs(pre_inputs_fast, pub_inputs, proof_fast)
}

/// Verify a PLONK proof with public inputs
/// This is the main entry point for verification
pub fn verify_plonk_proof(
  verification_key: PreInputs,
  public_inputs: List<Int>,
  proof: Proof,
) -> Bool {
  when verify(verification_key, public_inputs, proof) is {
    Success -> True
    _ -> False
  }
}

/// Example usage with hardcoded values
pub fn example_verification() -> Bool {
  // This would use actual proof data in practice
  let example_pre_inputs = create_example_pre_inputs()
  let example_proof = create_example_proof() 
  let example_inputs = [1, 2, 3, 42]
  
  verify_plonk_proof(example_pre_inputs, example_inputs, example_proof)
}

// Helper functions for example data
fn create_example_pre_inputs() -> PreInputs {
  PreInputs {
    n_public: 4,
    power: 8,
    k1: mk_scalar(1),
    k2: mk_scalar(2),
    q_m: #"0123456789abcdef",
    q_l: #"0123456789abcdef", 
    q_r: #"0123456789abcdef",
    q_o: #"0123456789abcdef",
    q_c: #"0123456789abcdef",
    s_sig1: #"0123456789abcdef",
    s_sig2: #"0123456789abcdef",
    s_sig3: #"0123456789abcdef",
    x2: #"0123456789abcdef",
    generator: mk_scalar(5),
  }
}

fn create_example_proof() -> Proof {
  Proof {
    commitment_a: #"0123456789abcdef",
    commitment_b: #"0123456789abcdef",
    commitment_c: #"0123456789abcdef", 
    commitment_z: #"0123456789abcdef",
    t_low: #"0123456789abcdef",
    t_mid: #"0123456789abcdef",
    t_high: #"0123456789abcdef",
    w_omega: #"0123456789abcdef",
    w_omega_zeta: #"0123456789abcdef",
    a_eval: 12345,
    b_eval: 23456,
    c_eval: 34567,
    s_sig1_p: 45678,
    s_sig2_p: 56789,
    z_omega: 67890,
  }
}
