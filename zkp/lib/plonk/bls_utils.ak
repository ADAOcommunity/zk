// BLS12-381 utilities for PLONK verifier

// BLS12-381 field constants
pub const bls12_381_scalar_prime: Int =
  52435875175126190479447740508185965837690552500527637822603658699938581184513

pub const bls12_381_base_prime: Int =
  4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787

// Scalar field element type
pub type Scalar {
  value: Int,
}

// Base field element type  
pub type Fp {
  value: Int,
}

// Fp2 field element type (complex extension)
pub type Fp2 {
  c0: Fp,
  c1: Fp,
}

// Create a scalar field element with validation
pub fn mk_scalar(n: Int) -> Scalar {
  if n >= 0 && n < bls12_381_scalar_prime {
    Scalar { value: n }
  } else {
    fail @"Invalid scalar: must be in range [0, p)"
  }
}

// Create a base field element with validation
pub fn mk_fp(n: Int) -> Fp {
  if n >= 0 && n < bls12_381_base_prime {
    Fp { value: n }
  } else {
    fail @"Invalid Fp: must be in range [0, p)"
  }
}

// Scalar arithmetic operations
pub fn scalar_add(a: Scalar, b: Scalar) -> Scalar {
  let sum = a.value + b.value
  Scalar { value: sum % bls12_381_scalar_prime }
}

pub fn scalar_sub(a: Scalar, b: Scalar) -> Scalar {
  let diff = a.value - b.value
  Scalar { value: (diff + bls12_381_scalar_prime) % bls12_381_scalar_prime }
}

pub fn scalar_mul(a: Scalar, b: Scalar) -> Scalar {
  let prod = a.value * b.value
  Scalar { value: prod % bls12_381_scalar_prime }
}

pub fn scalar_negate(a: Scalar) -> Scalar {
  if a.value == 0 {
    Scalar { value: 0 }
  } else {
    Scalar { value: bls12_381_scalar_prime - a.value }
  }
}

// Scalar constants
pub fn scalar_zero() -> Scalar {
  Scalar { value: 0 }
}

pub fn scalar_one() -> Scalar {
  Scalar { value: 1 }
}

// Modular exponentiation for scalars
pub fn scalar_pow_mod(base: Scalar, exp: Int) -> Scalar {
  if exp < 0 {
    fail @"Negative exponent not supported"
  } else if exp == 0 {
    scalar_one()
  } else if exp == 1 {
    base
  } else if exp % 2 == 0 {
    let half_pow = scalar_pow_mod(base, exp / 2)
    scalar_mul(half_pow, half_pow)
  } else {
    let half_pow = scalar_pow_mod(base, (exp - 1) / 2)
    scalar_mul(base, scalar_mul(half_pow, half_pow))
  }
}

// Extended Euclidean algorithm for modular inverse
fn extended_gcd(a: Int, b: Int) -> (Int, Int, Int) {
  if a == 0 {
    (b, 0, 1)
  } else {
    let (gcd, x1, y1) = extended_gcd(b % a, a)
    let x = y1 - b / a * x1
    (gcd, x, x1)
  }
}

// Modular multiplicative inverse
pub fn scalar_inverse(a: Scalar) -> Scalar {
  if a.value == 0 {
    fail @"Cannot invert zero"
  } else {
    let (gcd, x, _) = extended_gcd(a.value, bls12_381_scalar_prime)
    if gcd == 1 {
      let inv = (x + bls12_381_scalar_prime) % bls12_381_scalar_prime
      Scalar { value: inv }
    } else {
      fail @"No multiplicative inverse exists"
    }
  }
}

pub fn scalar_div(a: Scalar, b: Scalar) -> Scalar {
  scalar_mul(a, scalar_inverse(b))
}

// Power of two exponentiation (optimized for 2^k)
pub fn scalar_power_of_two_exp(base: Scalar, k: Int) -> Scalar {
  if k < 0 {
    fail @"Negative power not supported"
  } else if k == 0 {
    base
  } else {
    let squared = scalar_mul(base, base)
    scalar_power_of_two_exp(squared, k - 1)
  }
}

// Fp arithmetic operations
pub fn fp_add(a: Fp, b: Fp) -> Fp {
  let sum = a.value + b.value
  Fp { value: sum % bls12_381_base_prime }
}

pub fn fp_sub(a: Fp, b: Fp) -> Fp {
  let diff = a.value - b.value
  Fp { value: (diff + bls12_381_base_prime) % bls12_381_base_prime }
}

pub fn fp_mul(a: Fp, b: Fp) -> Fp {
  let prod = a.value * b.value
  Fp { value: prod % bls12_381_base_prime }
}

pub fn fp_negate(a: Fp) -> Fp {
  if a.value == 0 {
    Fp { value: 0 }
  } else {
    Fp { value: bls12_381_base_prime - a.value }
  }
}

// Fp constants
pub fn fp_zero() -> Fp {
  Fp { value: 0 }
}

pub fn fp_one() -> Fp {
  Fp { value: 1 }
}

// Fp2 arithmetic (complex field extension)
pub fn fp2_add(a: Fp2, b: Fp2) -> Fp2 {
  Fp2 {
    c0: fp_add(a.c0, b.c0),
    c1: fp_add(a.c1, b.c1),
  }
}

pub fn fp2_sub(a: Fp2, b: Fp2) -> Fp2 {
  Fp2 {
    c0: fp_sub(a.c0, b.c0),
    c1: fp_sub(a.c1, b.c1),
  }
}

pub fn fp2_mul(a: Fp2, b: Fp2) -> Fp2 {
  // Complex multiplication: (a0 + a1*i) * (b0 + b1*i) = (a0*b0 - a1*b1) + (a0*b1 + a1*b0)*i
  let c0 = fp_sub(fp_mul(a.c0, b.c0), fp_mul(a.c1, b.c1))
  let c1 = fp_add(fp_mul(a.c0, b.c1), fp_mul(a.c1, b.c0))
  Fp2 { c0, c1 }
}

pub fn fp2_zero() -> Fp2 {
  Fp2 { c0: fp_zero(), c1: fp_zero() }
}

pub fn fp2_one() -> Fp2 {
  Fp2 { c0: fp_one(), c1: fp_zero() }
}

// Utility function to convert integers to byte arrays (big endian)
pub fn int_to_bytearray_be(_value: Int, _length: Int) -> ByteArray {
  // This is a placeholder - Aiken doesn't have direct integer to bytearray conversion
  // In practice, this would need to be implemented using builtin functions
  #""
}

// Utility function to convert byte arrays to integers (big endian)  
pub fn bytearray_to_int_be(_bytes: ByteArray) -> Int {
  // This is a placeholder - Aiken doesn't have direct bytearray to integer conversion
  // In practice, this would need to be implemented using builtin functions
  0
}