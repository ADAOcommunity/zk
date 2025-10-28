use plonk/bls_utils.{
  Scalar, scalar_add, scalar_sub, scalar_mul, scalar_div, scalar_one, 
  scalar_zero, scalar_power_of_two_exp, mk_scalar
}
use plonk/plonk_types.{PreInputs, PreInputsFast}

// Compute Lagrange polynomial evaluations
pub fn compute_lagrange_polynomials(
  pre_inputs: PreInputs,
  zeta: Scalar,
  n_public: Int,
) -> List<Scalar> {
  let n = pow_2(pre_inputs.power)
  let zero_poly = compute_zero_polynomial(zeta, n)
  
  compute_lagrange_helper(pre_inputs.generator, zeta, zero_poly, n_public, n, [])
}

// Compute fast Lagrange polynomials using precomputed generators and inverses
pub fn compute_lagrange_polynomials_fast(
  pre_inputs_fast: PreInputsFast,
  zeta: Scalar,
  lagrange_inverses: List<Int>,
) -> List<Scalar> {
  let zero_poly = compute_zero_polynomial_fast(zeta, pre_inputs_fast.power)
  
  compute_lagrange_fast_helper(
    pre_inputs_fast.generators,
    lagrange_inverses, 
    zero_poly,
    []
  )
}

// Compute zero polynomial Z_H(zeta) = zeta^n - 1
pub fn compute_zero_polynomial(zeta: Scalar, n: Int) -> Scalar {
  let zeta_n = scalar_pow(zeta, n)
  scalar_sub(zeta_n, scalar_one())
}

// Fast zero polynomial computation using power of 2 exponentiation  
pub fn compute_zero_polynomial_fast(zeta: Scalar, power: Int) -> Scalar {
  let zeta_n = scalar_power_of_two_exp(zeta, power)
  scalar_sub(zeta_n, scalar_one())
}

// Compute public input polynomial PI(zeta)
pub fn compute_pi_polynomial(
  pub_inputs: List<Int>,
  lagrange_polys: List<Scalar>,
) -> Scalar {
  compute_pi_helper(pub_inputs, lagrange_polys, scalar_zero())
}

// Compute linearization polynomial r_0
pub fn compute_linearization_r0(
  pi_zeta: Scalar,
  lagrange_poly_1: Scalar,
  alpha: Scalar,
  eval_a: Scalar,
  eval_b: Scalar,
  eval_c: Scalar,
  eval_s1: Scalar,
  eval_s2: Scalar,
  eval_z_omega: Scalar,
  beta: Scalar,
  gamma: Scalar,
) -> Scalar {
  let alpha_squared = scalar_mul(alpha, alpha)
  let lagrange_term = scalar_mul(lagrange_poly_1, alpha_squared)
  
  let perm_term_1 = scalar_add(eval_a, scalar_add(scalar_mul(beta, eval_s1), gamma))
  let perm_term_2 = scalar_add(eval_b, scalar_add(scalar_mul(beta, eval_s2), gamma))
  let perm_term_3 = scalar_add(eval_c, gamma)
  
  let perm_product = scalar_mul(
    scalar_mul(perm_term_1, perm_term_2),
    scalar_mul(perm_term_3, eval_z_omega)
  )
  let perm_term = scalar_mul(alpha, perm_product)
  
  scalar_sub(
    scalar_sub(pi_zeta, lagrange_term),
    perm_term
  )
}

// Helper function to compute Lagrange polynomials iteratively
fn compute_lagrange_helper(
  generator: Scalar,
  zeta: Scalar,
  zero_poly: Scalar,
  n_public: Int,
  n: Int,
  acc: List<Scalar>,
) -> List<Scalar> {
  if n_public < 0 {
    acc
  } else {
    let gen_i = scalar_pow(generator, n_public)
    let numerator = scalar_mul(gen_i, zero_poly)
    let denominator = scalar_mul(
      mk_scalar(n),
      scalar_sub(zeta, gen_i)
    )
    let lagrange_i = scalar_div(numerator, denominator)
    
    compute_lagrange_helper(
      generator, zeta, zero_poly, n_public - 1, n,
      [lagrange_i, ..acc]
    )
  }
}

// Helper for fast Lagrange computation with precomputed values
fn compute_lagrange_fast_helper(
  generators: List<Scalar>,
  inverses: List<Int>,
  zero_poly: Scalar,
  acc: List<Scalar>,
) -> List<Scalar> {
  when generators is {
    [] -> acc
    [gen_head, ..gen_tail] -> {
      when inverses is {
        [] -> acc
        [inv_head, ..inv_tail] -> {
          let numerator = scalar_mul(gen_head, zero_poly)
          let lagrange_i = scalar_mul(numerator, mk_scalar(inv_head))
          
          compute_lagrange_fast_helper(
            gen_tail, inv_tail, zero_poly,
            [lagrange_i, ..acc]
          )
        }
      }
    }
  }
}

// Helper to compute PI(zeta) = sum(w_i * L_i(zeta))
fn compute_pi_helper(
  pub_inputs: List<Int>,
  lagrange_polys: List<Scalar>,
  acc: Scalar,
) -> Scalar {
  when pub_inputs is {
    [] -> acc
    [input_head, ..input_tail] -> {
      when lagrange_polys is {
        [] -> acc
        [lagrange_head, ..lagrange_tail] -> {
          let term = scalar_mul(mk_scalar(input_head), lagrange_head)
          let new_acc = scalar_add(acc, term)
          
          compute_pi_helper(input_tail, lagrange_tail, new_acc)
        }
      }
    }
  }
}

// Simple exponentiation (not optimized)
fn scalar_pow(base: Scalar, exp: Int) -> Scalar {
  if exp == 0 {
    scalar_one()
  } else if exp == 1 {
    base
  } else if exp % 2 == 0 {
    let half_pow = scalar_pow(base, exp / 2)
    scalar_mul(half_pow, half_pow)
  } else {
    let half_pow = scalar_pow(base, (exp - 1) / 2)
    scalar_mul(base, scalar_mul(half_pow, half_pow))
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