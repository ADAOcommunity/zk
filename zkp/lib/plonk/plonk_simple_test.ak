// Simple functional test for PLONK verify() function
use plonk/plonk_types.{PreInputs, Proof}
use plonk/bls_utils.{mk_scalar}
use plonk/plonk.{verify_plonk_proof}
use common/common.{g1_compress, g2_compress, g1_generator, g2_generator, Point, G2Point}
use plonk/test_constants.{test_vk, test_public_inputs, test_proof}
// Test that verify function works with proper BLS points
test plonk_verify_with_real_bls_points() {
  verify_plonk_proof(test_vk, test_public_inputs, test_proof)
}