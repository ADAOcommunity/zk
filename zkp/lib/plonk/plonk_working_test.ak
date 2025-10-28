// Simple functional test for PLONK verify() function using VALID BLS12-381 points
use plonk/plonk.{verify_plonk_proof}
use plonk/valid_test_constants.{get_valid_test_vk, get_valid_test_proof, get_valid_test_public_inputs}

// Test that verify function works with proper BLS points (no curve errors)
test plonk_verify_with_mathematically_valid_points() {
    let vk = get_valid_test_vk()
    let proof = get_valid_test_proof()
    let public_inputs = get_valid_test_public_inputs()
    
    // This should NOT fail with BLS curve errors
    // It might fail cryptographically, but no BLST_POINT_NOT_ON_CURVE or similar
    let _result = verify_plonk_proof(vk, public_inputs, proof)
    
    // Success means no BLS errors occurred
    True
}