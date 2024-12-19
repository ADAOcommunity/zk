use aiken/crypto

// Constants for BLS12-381
pub const bls12_381_prime = 52435875175126190479447740508185965837690552500527637822603658699938581184513

// Additional curve constants
pub const bls12_381_r = 52435875175126190479447740508185965837690552500527637822603658699938581184513
pub const bls12_381_h = 1

// Common types for ZKP systems
pub type Field = Int

pub type Point {
  x: Field,
  y: Field,
  z: Field,
}

pub type G1Point = Point

pub type G2Point {
  x: (Field, Field),
  y: (Field, Field),
  z: (Field, Field),
}

pub type VerificationKey {
  alpha_g1: G1Point,
  beta_g2: G2Point,
  gamma_g2: G2Point,
  delta_g2: G2Point,
  ic: List<G1Point>,
}

pub type Proof {
  a: G1Point,
  b: G2Point,
  c: G1Point,
}

pub type VerificationError {
  InvalidProof
  InvalidPublicInputs
  InvalidVerifyingKey
  PairingCheckFailed
  InvalidCurvePoint
  InvalidFieldElement
}

// Common utility functions for field operations
pub fn mod_add(a: Field, b: Field) -> Field {
  (a + b) % bls12_381_prime
}

pub fn mod_sub(a: Field, b: Field) -> Field {
  let result = (a - b) % bls12_381_prime
  if result < 0 {
    result + bls12_381_prime
  } else {
    result
  }
}

pub fn mod_mul(a: Field, b: Field) -> Field {
  (a * b) % bls12_381_prime
}

pub fn mod_neg(a: Field) -> Field {
  if a == 0 {
    0
  } else {
    bls12_381_prime - a
  }
}

// Field operations (keeping existing ones and adding more)
pub fn mod_inv(a: Field, p: Field) -> Option<Field> {
  if a == 0 {
    None
  } else {
    // Extended Euclidean Algorithm for modular inverse
    let (last_r, last_s) = extended_gcd(a, p)
    if last_r == 1 {
      let result = last_s % p
      Some(if result < 0 { result + p } else { result })
    } else {
      None
    }
  }
}

fn extended_gcd(a: Int, b: Int) -> (Int, Int) {
  if b == 0 {
    (a, 1)
  } else {
    let q = a / b
    let r = a % b
    let (last_r, last_s) = extended_gcd(b, r)
    (last_r, last_s - q * last_s)
  }
}

pub fn mod_sqrt(a: Field) -> Option<Field> {
  // Tonelli-Shanks algorithm for p ≡ 3 (mod 4)
  // For BLS12-381, we can use the simpler case since p ≡ 3 (mod 4)
  if a == 0 {
    Some(0)
  } else {
    // For p ≡ 3 (mod 4), sqrt(a) = a^((p+1)/4) if a is a quadratic residue
    let exp = (bls12_381_prime + 1) / 4
    let sqrt = mod_pow(a, exp)
    
    // Verify the result
    if mod_mul(sqrt, sqrt) == a {
      Some(sqrt)
    } else {
      None
    }
  }
}

fn mod_pow(base: Field, exp: Field) -> Field {
  if exp == 0 {
    1
  } else {
    mod_pow_loop(base, exp, 1)
  }
}

fn mod_pow_loop(b, e, result) {
  if e > 0 {
    when e % 2 is {
      1 -> let result = mod_mul(result, b)
    }
    mod_pow_loop(
      mod_mul(b, b),
      e / 2,
      result
    )
  }
  else {
    result
  }
}

// Point operations (expanding on existing ones)
pub fn g1_generator() -> G1Point {
  // BLS12-381 G1 generator coordinates
  G1Point {
    x: 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507,
    y: 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569,
    z: 1,
  }
}

pub fn g2_generator() -> G2Point {
  // BLS12-381 G2 generator coordinates
  G2Point {
    x: (
      352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160,
      3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758,
    ),
    y: (
      1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905,
      927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582,
    ),
    z: (1, 0),
  }
}

pub fn is_infinity(p: G1Point) -> Bool {
  p.z == 0
}

pub fn g1_compress(p: G1Point) -> ByteArray {
  if is_infinity(p) {
    // Special encoding for point at infinity
    crypto.blake2b_256(#"00")
  } else {
    // Convert to affine coordinates first
    let z_inv = mod_inv(p.z, bls12_381_prime)
    when z_inv is {
      Some(z_inv_val) -> {
        let x_affine = mod_mul(p.x, z_inv_val)
        let y_affine = mod_mul(p.y, z_inv_val)
        // Compress point by keeping x coordinate and y's sign
        let compressed = serialize_field(x_affine)
        // Add a bit for y's sign (we'll use the last byte)
        let is_y_negative = y_affine > (bls12_381_prime / 2)
        if is_y_negative {
          bytearray.concat(compressed, #"01")
        } else {
          bytearray.concat(compressed, #"00")
        }
      }
      None -> crypto.blake2b_256(#"00")
    }
  }
}

pub fn g1_decompress(bytes: ByteArray) -> Option<G1Point> {
  if bytearray.length(bytes) != 33 {
    None
  } else {
    let x_bytes = bytearray.slice(bytes, 0, 32)
    let flag_byte = bytearray.slice(bytes, 32, 1)
    
    when deserialize_field(x_bytes) is {
      Some(x) -> {
        // Compute y^2 = x^3 + 4
        let x_squared = mod_mul(x, x)
        let x_cubed = mod_mul(x_squared, x)
        let y_squared = mod_add(x_cubed, 4)
        
        when mod_sqrt(y_squared) is {
          Some(y) -> {
            let is_negative = bytearray.to_list(flag_byte)[0] == 1
            let final_y = if is_negative && y > (bls12_381_prime / 2) || 
                            !is_negative && y <= (bls12_381_prime / 2) {
              y
            } else {
              mod_neg(y)
            }
            Some(G1Point { x: x, y: final_y, z: 1 })
          }
          None -> None
        }
      }
      None -> None
    }
  }
}

pub fn g2_compress(p: G2Point) -> ByteArray {
  if is_infinity_g2(p) {
    // Special encoding for point at infinity
    crypto.blake2b_256(#"00")
  } else {
    // Convert to affine coordinates first
    let (z1, z2) = p.z
    let z_inv = mod_inv(z1, bls12_381_prime)
    
    when z_inv is {
      Some(z_inv_val) -> {
        let z_inv_squared = fp2_square((z_inv_val, z2))
        let (x_affine_1, x_affine_2) = fp2_mul(p.x, z_inv_squared)
        let (y_affine_1, y_affine_2) = fp2_mul(p.y, z_inv_squared)
        
        // Compress point by keeping x-coordinate and y's sign
        let x1_bytes = serialize_field(x_affine_1)
        let x2_bytes = serialize_field(x_affine_2)
        
        // Add a bit for y's sign
        let is_y_negative = y_affine_1 > (bls12_381_prime / 2)
        let flag_byte = if is_y_negative { #"01" } else { #"00" }
        
        bytearray.concat(
          bytearray.concat(x1_bytes, x2_bytes),
          flag_byte
        )
      }
      None -> crypto.blake2b_256(#"00")
    }
  }
}

pub fn g2_decompress(bytes: ByteArray) -> Option<G2Point> {
  if bytearray.length(bytes) != 65 {
    None
  } else {
    let x1_bytes = bytearray.slice(bytes, 0, 32)
    let x2_bytes = bytearray.slice(bytes, 32, 32)
    let flag_byte = bytearray.slice(bytes, 64, 1)
    
    when (deserialize_field(x1_bytes), deserialize_field(x2_bytes)) is {
      (Some(x1), Some(x2)) -> {
        // Compute y^2 = x^3 + 4(1 + i)
        let x = (x1, x2)
        let x_squared = fp2_square(x)
        let x_cubed = fp2_mul(x_squared, x)
        let b2 = (4, 4) // 4(1 + i)
        let y_squared = fp2_add(x_cubed, b2)
        
        // Try to find y in Fp2
        when fp2_sqrt(y_squared) is {
          Some((y1, y2)) -> {
            let is_negative = bytearray.to_list(flag_byte)[0] == 1
            let final_y = if is_negative {
              fp2_neg((y1, y2))
            } else {
              (y1, y2)
            }
            Some(G2Point { x: x, y: final_y, z: (1, 0) })
          }
          None -> None
        }
      }
      _ -> None
    }
  }
}

fn fp2_sqrt(a: (Field, Field)) -> Option<(Field, Field)> {
  // Simplified implementation for square root in Fp2
  // This is a placeholder - real implementation needs more complex math
  when (mod_sqrt(a.1st), mod_sqrt(a.2nd)) is {
    (Some(r1), Some(r2)) -> Some((r1, r2))
    _ -> None
  }
}

fn fp2_neg(a: (Field, Field)) -> (Field, Field) {
  (mod_neg(a.1st), mod_neg(a.2nd))
}

pub fn miller_loop(p1: G1Point, p2: G2Point) -> ByteArray {
  // Simplified Miller loop implementation
  // This is a placeholder - real implementation needs proper line evaluation and Fp12 arithmetic
  if !is_on_curve_g1(p1) || !is_on_curve_g2(p2) {
    #"000000000000000000000000000000000000000000000000000000000000000000"
  } else {
    // Combine point coordinates to create a unique representation
    let p1_bytes = g1_compress(p1)
    let p2_bytes = g2_compress(p2)
    crypto.blake2b_256(bytearray.concat(p1_bytes, p2_bytes))
  }
}

pub fn final_exponentiation(ml_result: ByteArray) -> ByteArray {
  // Simplified final exponentiation
  // This is a placeholder - real implementation needs proper Fp12 arithmetic
  if ml_result == #"000000000000000000000000000000000000000000000000000000000000000000" {
    #"010000000000000000000000000000000000000000000000000000000000000000"
  } else {
    ml_result
  }
}

pub fn serialize_vkey(vk: VerificationKey) -> ByteArray {
  // Serialize all components of the verification key
  let alpha_g1_bytes = g1_compress(vk.alpha_g1)
  let beta_g2_bytes = g2_compress(vk.beta_g2)
  let gamma_g2_bytes = g2_compress(vk.gamma_g2)
  let delta_g2_bytes = g2_compress(vk.delta_g2)
  
  // Serialize IC points
  let ic_bytes = #""
  for point in vk.ic {
    let ic_bytes = bytearray.concat(ic_bytes, g1_compress(point))
  }
  
  // Combine all parts
  bytearray.concat(
    bytearray.concat(
      bytearray.concat(
        bytearray.concat(
          alpha_g1_bytes,
          beta_g2_bytes
        ),
        gamma_g2_bytes
      ),
      delta_g2_bytes
    ),
    ic_bytes
  )
}

pub fn deserialize_vkey(bytes: ByteArray) -> Option<VerificationKey> {
  // Minimum length check (without IC points)
  let min_length = 33 + (3 * 65) // 1 G1 point + 3 G2 points
  if bytearray.length(bytes) < min_length {
    None
  } else {
    // Deserialize fixed components
    let alpha_g1_bytes = bytearray.slice(bytes, 0, 33)
    let beta_g2_bytes = bytearray.slice(bytes, 33, 65)
    let gamma_g2_bytes = bytearray.slice(bytes, 98, 65)
    let delta_g2_bytes = bytearray.slice(bytes, 163, 65)
    
    when (
      g1_decompress(alpha_g1_bytes),
      g2_decompress(beta_g2_bytes),
      g2_decompress(gamma_g2_bytes),
      g2_decompress(delta_g2_bytes)
    ) is {
      (Some(alpha_g1), Some(beta_g2), Some(gamma_g2), Some(delta_g2)) -> {
        // Deserialize IC points
        let remaining_bytes = bytearray.slice(bytes, 228, bytearray.length(bytes) - 228)
        let num_ic_points = bytearray.length(remaining_bytes) / 33
        
        let ic = []
        let i = 0
        
        while i < num_ic_points {
          let point_bytes = bytearray.slice(remaining_bytes, i * 33, 33)
          when g1_decompress(point_bytes) is {
            Some(point) -> {
              list.push(ic, point)
              let i = i + 1
            }
            None -> {
              return None
            }
          }
        }
        
        Some(
          VerificationKey {
            alpha_g1: alpha_g1,
            beta_g2: beta_g2,
            gamma_g2: gamma_g2,
            delta_g2: delta_g2,
            ic: list.reverse(ic),
          }
        )
      }
      _ -> None
    }
  }
}

// Serialization functions
pub fn serialize_field(f: Field) -> ByteArray {
  // Serialize a field element to a 32-byte array
  // This is a simplified implementation - you might want to add more error checking
  serialize_loop([], f, 0)
}

pub fn serialize_loop(bytes, value, i) {
  if i < 32 {
    serialize_loop(list.push(bytes, value % 256), value / 256, i + 1)
  } else
  {
    bytes
  }
}

pub fn deserialize_field(bytes: ByteArray) -> Option<Field> {
  let byte_list = bytearray.to_list(bytes)
  if bytearray.length(bytes) != 32 {
    None
  } else {
    let result = list.foldl(byte_list, 0, fn(result, byte) {((result * 256 + byte) % bls12_381_prime)})
    if result < bls12_381_prime {
      Some(result)
    } else {
      None
    }
  }
}

// Hashing utilities
pub fn hash_to_field(data: ByteArray) -> Field {
  // Hash the input data and reduce it modulo the field characteristic
  let hash = crypto.blake2b_256(data)
  let bytes = bytearray.to_list(hash)
  
  list.foldl(byte_list, 0, fn(result, byte) {((result * 256 + byte) % bls12_381_prime)})
}

pub fn hash_to_curve(data: ByteArray) -> G1Point {
  // Simplified SWU map-to-curve implementation
  let u = hash_to_field(data)
  let u_squared = mod_mul(u, u)
  let u_squared_plus_1 = mod_add(u_squared, 1)
  
  // Calculate x = -(u^2) / (u^2 + 1) if u^2 ≠ -1
  when mod_inv(u_squared_plus_1, bls12_381_prime) is {
    Some(inv) -> {
      let x = mod_mul(mod_neg(u_squared), inv)
      
      // Calculate y^2 = x^3 + 4
      let x_squared = mod_mul(x, x)
      let x_cubed = mod_mul(x_squared, x)
      let y_squared = mod_add(x_cubed, 4)
      
      // Try to find y
      when mod_sqrt(y_squared) is {
        Some(y) -> {
          // Ensure y has the same sign as u
          let final_y = if (y > (bls12_381_prime / 2)) == (u > (bls12_381_prime / 2)) {
            y
          } else {
            mod_neg(y)
          }
          G1Point { x: x, y: final_y, z: 1 }
        }
        None -> g1_generator() // Fallback to generator if sqrt fails
      }
    }
    None -> g1_generator() // Fallback to generator if inverse doesn't exist
  }
}

pub fn g1_add(p1: G1Point, p2: G1Point) -> G1Point {
  if is_infinity(p1) {
    p2
  } else if is_infinity(p2) {
    p1
  } else {
    // Projective coordinate addition formulas
    let x1 = p1.x
    let y1 = p1.y
    let z1 = p1.z
    let x2 = p2.x
    let y2 = p2.y
    let z2 = p2.z

    let u1 = mod_mul(y2, z1)
    let u2 = mod_mul(y1, z2)
    let v1 = mod_mul(x2, z1)
    let v2 = mod_mul(x1, z2)

    if v1 == v2 {
      if u1 != u2 {
        // Return point at infinity
        G1Point { x: 0, y: 1, z: 0 }
      } else {
        // Point doubling
        g1_double(p1)
      }
    } else {
      let u = mod_sub(u1, u2)
      let v = mod_sub(v1, v2)
      let v_squared = mod_mul(v, v)
      let v_cubed = mod_mul(v_squared, v)
      let w = mod_mul(z1, z2)
      
      let x3 = mod_sub(
        mod_mul(u, u),
        mod_add(mod_mul(v_squared, mod_add(v2, v1)), v_cubed)
      )
      let y3 = mod_sub(
        mod_mul(u, mod_sub(mod_mul(v, v2), x3)),
        mod_mul(v_cubed, u2)
      )
      let z3 = mod_mul(v_cubed, w)

      G1Point { x: x3, y: y3, z: z3 }
    }
  }
}

fn g1_double(p: G1Point) -> G1Point {
  if is_infinity(p) {
    p
  } else {
    let x = p.x
    let y = p.y
    let z = p.z

    let a = mod_mul(x, x)
    let b = mod_mul(y, y)
    let c = mod_mul(b, b)

    let d = mod_mul(2, mod_mul(x, mod_add(x, x)))
    let e = mod_mul(3, a)
    let f = mod_mul(e, e)

    let x3 = mod_sub(f, mod_mul(2, d))
    let y3 = mod_sub(mod_mul(e, mod_sub(d, x3)), mod_mul(8, c))
    let z3 = mod_mul(2, mod_mul(y, z))

    G1Point { x: x3, y: y3, z: z3 }
  }
}

pub fn g1_mul(p: G1Point, scalar: Field) -> G1Point {
  if scalar == 0 || is_infinity(p) {
    // Return point at infinity
    G1Point { x: 0, y: 1, z: 0 }
  } else {
    // Double-and-add algorithm
    let result = G1Point { x: 0, y: 1, z: 0 }
    let temp = p
    let n = scalar

    while n > 0 {
      if n % 2 == 1 {
        result = g1_add(result, temp)
      }
      temp = g1_double(temp)
      n = n / 2
    }

    result
  }
}

pub fn is_on_curve_g1(p: G1Point) -> Bool {
  if is_infinity(p) {
    True
  } else {
    // Convert to affine coordinates
    let z_inv = mod_inv(p.z, bls12_381_prime)
    when z_inv is {
      Some(z_inv_val) -> {
        let z_inv_squared = mod_mul(z_inv_val, z_inv_val)
        let z_inv_cubed = mod_mul(z_inv_squared, z_inv_val)
        
        let x_affine = mod_mul(p.x, z_inv_squared)
        let y_affine = mod_mul(p.y, z_inv_cubed)
        
        // Check y^2 = x^3 + 4
        let y_squared = mod_mul(y_affine, y_affine)
        let x_cubed = mod_mul(mod_mul(x_affine, x_affine), x_affine)
        let rhs = mod_add(x_cubed, 4)
        
        y_squared == rhs
      }
      None -> False
    }
  }
}

pub fn is_in_g1_subgroup(p: G1Point) -> Bool {
  if !is_on_curve_g1(p) {
    False
  } else {
    // Check that the point has the right order
    let scalar_mult = g1_mul(p, bls12_381_r)
    is_infinity(scalar_mult)
  }
}

pub fn g2_add(p1: G2Point, p2: G2Point) -> G2Point {
  if is_infinity_g2(p1) {
    p2
  } else if is_infinity_g2(p2) {
    p1
  } else {
    // Similar to g1_add but with extension field arithmetic
    let (x1_1, x1_2) = p1.x
    let (y1_1, y1_2) = p1.y
    let (z1_1, z1_2) = p1.z
    let (x2_1, x2_2) = p2.x
    let (y2_1, y2_2) = p2.y
    let (z2_1, z2_2) = p2.z

    let (u1_1, u1_2) = fp2_mul((y2_1, y2_2), (z1_1, z1_2))
    let (u2_1, u2_2) = fp2_mul((y1_1, y1_2), (z2_1, z2_2))
    let (v1_1, v1_2) = fp2_mul((x2_1, x2_2), (z1_1, z1_2))
    let (v2_1, v2_2) = fp2_mul((x1_1, x1_2), (z2_1, z2_2))

    if fp2_eq((v1_1, v1_2), (v2_1, v2_2)) {
      if !fp2_eq((u1_1, u1_2), (u2_1, u2_2)) {
        // Return point at infinity
        G2Point { x: (0, 0), y: (1, 0), z: (0, 0) }
      } else {
        // Point doubling
        g2_double(p1)
      }
    } else {
      let (u_1, u_2) = fp2_sub((u1_1, u1_2), (u2_1, u2_2))
      let (v_1, v_2) = fp2_sub((v1_1, v1_2), (v2_1, v2_2))
      let (v_squared_1, v_squared_2) = fp2_square((v_1, v_2))
      let (v_cubed_1, v_cubed_2) = fp2_mul((v_1, v_2), (v_squared_1, v_squared_2))
      let (w_1, w_2) = fp2_mul((z1_1, z1_2), (z2_1, z2_2))

      let (temp1_1, temp1_2) = fp2_add((v2_1, v2_2), (v1_1, v1_2))
      let (temp2_1, temp2_2) = fp2_mul((v_squared_1, v_squared_2), (temp1_1, temp1_2))
      let (temp3_1, temp3_2) = fp2_add((temp2_1, temp2_2), (v_cubed_1, v_cubed_2))
      
      let (x3_1, x3_2) = fp2_sub(
        fp2_square((u_1, u_2)),
        (temp3_1, temp3_2)
      )

      let (y3_1, y3_2) = fp2_sub(
        fp2_mul((u_1, u_2), fp2_sub((v_1, v_2), (x3_1, x3_2))),
        fp2_mul((v_cubed_1, v_cubed_2), (u2_1, u2_2))
      )

      let (z3_1, z3_2) = fp2_mul((v_cubed_1, v_cubed_2), (w_1, w_2))

      G2Point { x: (x3_1, x3_2), y: (y3_1, y3_2), z: (z3_1, z3_2) }
    }
  }
}

fn g2_double(p: G2Point) -> G2Point {
  if is_infinity_g2(p) {
    p
  } else {
    let (x_1, x_2) = p.x
    let (y_1, y_2) = p.y
    let (z_1, z_2) = p.z

    let (a_1, a_2) = fp2_square((x_1, x_2))
    let (b_1, b_2) = fp2_square((y_1, y_2))
    let (c_1, c_2) = fp2_square((b_1, b_2))

    let (temp1_1, temp1_2) = fp2_add((x_1, x_2), (x_1, x_2))
    let (d_1, d_2) = fp2_mul((temp1_1, temp1_2), (x_1, x_2))
    let (d_1, d_2) = fp2_add((d_1, d_2), (d_1, d_2))

    let (e_1, e_2) = fp2_mul((3, 0), (a_1, a_2))
    let (f_1, f_2) = fp2_square((e_1, e_2))

    let (x3_1, x3_2) = fp2_sub((f_1, f_2), fp2_add((d_1, d_2), (d_1, d_2)))
    
    let (y3_1, y3_2) = fp2_sub(
      fp2_mul((e_1, e_2), fp2_sub((d_1, d_2), (x3_1, x3_2))),
      fp2_mul((8, 0), (c_1, c_2))
    )

    let (z3_1, z3_2) = fp2_mul((2, 0), fp2_mul((y_1, y_2), (z_1, z_2)))

    G2Point { x: (x3_1, x3_2), y: (y3_1, y3_2), z: (z3_1, z3_2) }
  }
}

pub fn g2_mul(p: G2Point, scalar: Field) -> G2Point {
  if scalar == 0 || is_infinity_g2(p) {
    // Return point at infinity
    G2Point { x: (0, 0), y: (1, 0), z: (0, 0) }
  } else {
    // Double-and-add algorithm for G2
    let result = G2Point { x: (0, 0), y: (1, 0), z: (0, 0) }
    let temp = p
    let n = scalar

    while n > 0 {
      if n % 2 == 1 {
        result = g2_add(result, temp)
      }
      temp = g2_double(temp)
      n = n / 2
    }

    result
  }
}

fn is_infinity_g2(p: G2Point) -> Bool {
  let (z1, z2) = p.z
  z1 == 0 && z2 == 0
}

// Extension field arithmetic helpers
fn fp2_add(a: (Field, Field), b: (Field, Field)) -> (Field, Field) {
  (mod_add(a.0, b.0), mod_add(a.1, b.1))
}

fn fp2_sub(a: (Field, Field), b: (Field, Field)) -> (Field, Field) {
  (mod_sub(a.0, b.0), mod_sub(a.1, b.1))
}

fn fp2_mul(a: (Field, Field), b: (Field, Field)) -> (Field, Field) {
  let a0b0 = mod_mul(a.0, b.0)
  let a1b1 = mod_mul(a.1, b.1)
  let a0b1_plus_a1b0 = mod_mul(mod_add(a.0, a.1), mod_add(b.0, b.1))
  
  (
    mod_sub(a0b0, a1b1),
    mod_sub(a0b1_plus_a1b0, mod_add(a0b0, a1b1))
  )
}

fn fp2_square(a: (Field, Field)) -> (Field, Field) {
  fp2_mul(a, a)
}

fn fp2_eq(a: (Field, Field), b: (Field, Field)) -> Bool {
  a.0 == b.0 && a.1 == b.1
}

pub fn is_on_curve_g2(p: G2Point) -> Bool {
  if is_infinity_g2(p) {
    True
  } else {
    // Convert to affine coordinates
    let (z1, z2) = p.z
    let z_inv = mod_inv(z1, bls12_381_prime)
    
    when z_inv is {
      Some(z_inv_val) -> {
        let z_inv_squared = fp2_square((z_inv_val, z2))
        let z_inv_cubed = fp2_mul((z_inv_val, z2), z_inv_squared)
        
        let (x_affine_1, x_affine_2) = fp2_mul(p.x, z_inv_squared)
        let (y_affine_1, y_affine_2) = fp2_mul(p.y, z_inv_cubed)
        
        // Check y^2 = x^3 + 4(1 + i)
        let y_squared = fp2_square((y_affine_1, y_affine_2))
        let x_cubed = fp2_mul(fp2_square((x_affine_1, x_affine_2)), (x_affine_1, x_affine_2))
        let b2 = (4, 4) // 4(1 + i) is the B coefficient for G2
        let rhs = fp2_add(x_cubed, b2)
        
        fp2_eq(y_squared, rhs)
      }
      None -> False
    }
  }
}

pub fn is_in_g2_subgroup(p: G2Point) -> Bool {
  if !is_on_curve_g2(p) {
    False
  } else {
    // Check that the point has the right order
    let scalar_mult = g2_mul(p, bls12_381_r)
    is_infinity_g2(scalar_mult)
  }
}

pub fn pairing_check(g1_points: List<G1Point>, g2_points: List<G2Point>) -> Bool {
  if list.length(g1_points) != list.length(g2_points) {
    False
  } else {
    // Compute \prod e(P_i, Q_i) = 1
    let pairs = list.zip(g1_points, g2_points)
    let acc = #"010000000000000000000000000000000000000000000000000000000000000000"
    
    for (p1, p2) in pairs {
      let ml = miller_loop(p1, p2)
      acc = combine_miller_loop_results(acc, ml)
    }
    
    let final_result = final_exponentiation(acc)
    is_one(final_result)
  }
}

fn combine_miller_loop_results(a: ByteArray, b: ByteArray) -> ByteArray {
  // TODO: Implement proper Fp12 multiplication
  crypto.blake2b_256(bytearray.concat(a, b))
}

fn is_one(bytes: ByteArray) -> Bool {
  bytes == #"010000000000000000000000000000000000000000000000000000000000000000"
}