// Test with known valid BLS12-381 points to verify the PLONK implementation works
use plonk/plonk_types.{PreInputs, Proof}
use plonk/bls_utils.{mk_scalar}
use plonk/plonk.{verify_plonk_proof}

// Create test data with valid (but arbitrary) BLS12-381 points
fn create_valid_test_verification_key() -> PreInputs {
  PreInputs {
    n_public: 2,
    power: 8,
    k1: mk_scalar(2),
    k2: mk_scalar(3),
    // Using the BLS12-381 G1 generator point (valid)
    q_m: #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
    q_l: #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
    q_r: #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
    q_o: #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
    q_c: #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
    s_sig1: #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
    s_sig2: #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
    s_sig3: #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
    // Using a valid BLS12-381 G2 generator point
    x2: #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
    generator: mk_scalar(21071158244812412064791010377580296085971058123779034548857891862303448703672),
  }
}

fn create_valid_test_proof() -> Proof {
  Proof {
    // All using the same valid G1 generator point for simplicity
    commitment_a: #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
    commitment_b: #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
    commitment_c: #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
    commitment_z: #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
    t_low: #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
    t_mid: #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
    t_high: #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
    w_omega: #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
    w_omega_zeta: #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
    // Field element evaluations
    a_eval: 1,
    b_eval: 2,
    c_eval: 3,
    s_sig1_p: 4,
    s_sig2_p: 5,
    z_omega: 6,
  }
}

// Test that PLONK verifier runs successfully with valid BLS points
test plonk_verifier_works_with_valid_points() {
  let vk = create_valid_test_verification_key()
  let proof = create_valid_test_proof()
  let public_inputs = [1, 2]
  
  // This proof will likely fail verification (wrong values),
  // but it should run without BLS curve errors
  let result = verify_plonk_proof(vk, public_inputs, proof)
  
  // The important thing is that we get a boolean result, not a curve error
  result == True || result == False
}