// Debug test to check if our JSON points are valid on the BLS12-381 curve
use common/common.{Point, is_on_curve_g1, bls12_381_prime}
use plonk/test_constants.{ca, cb, cc, cz, t1, t2, t3, wxi, wxiw, qm, ql, qr, qo, qc, s1, s2, s3}

// Test individual points to see which ones are on curve
test check_proof_points_on_curve() {
  let points = [ca, cb, cc, cz, t1, t2, t3, wxi, wxiw]
  check_all_points_on_curve(points)
}

test check_vk_points_on_curve() {
  let points = [qm, ql, qr, qo, qc, s1, s2, s3]
  check_all_points_on_curve(points)
}

fn check_all_points_on_curve(points: List<Point>) -> Bool {
  when points is {
    [] -> True
    [p, ..rest] -> is_on_curve_g1(p) && check_all_points_on_curve(rest)
  }
}

// Test the ca point specifically
test ca_point_validation() {
  // Check if it satisfies y^2 = x^3 + 4 (mod p)
  let y_squared = (ca.y * ca.y) % bls12_381_prime
  let x_cubed = ((ca.x * ca.x) % bls12_381_prime * ca.x) % bls12_381_prime
  let x_cubed_plus_4 = (x_cubed + 4) % bls12_381_prime
  
  let on_curve = y_squared == x_cubed_plus_4
  
  // Return validation result
  is_on_curve_g1(ca) && on_curve
}