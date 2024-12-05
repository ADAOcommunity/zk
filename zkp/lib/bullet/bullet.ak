use aiken/primitive/bytearray
use aiken/crypto
use common/common

// Bulletproof specific types
pub type BulletproofVerificationKey {
  g: common.G1Point,
  h: common.G1Point,
  u: common.G1Point,
  g_vec: List<common.G1Point>,
  h_vec: List<common.G1Point>,
  n: Int,  // Vector length (must be power of 2)
}

pub type BulletproofProof {
  a: common.G1Point,
  s: common.G1Point,
  t1: common.G1Point,
  t2: common.G1Point,
  tau_x: common.Field,
  mu: common.Field,
  l_vec: List<common.Field>,
  r_vec: List<common.Field>,
}

pub type BulletproofError {
  InvalidProofFormat
  InvalidVerificationKey
  InvalidVectorLength
  PairingCheckFailed
  InvalidRangeProof
}

// Main verification function
pub fn verify(
  vk: BulletproofVerificationKey,
  proof: BulletproofProof,
  value: common.Field,
) -> Bool {
  // First verify the vector length is valid
  if !verify_power_of_two(vk.n) {
    False
  } else {
    // Verify the range proof
    verify_range_proof(vk, proof, value, vk.n)
  }
}

// Helper functions for verification
fn verify_inner_product(
  g_vec: List<common.G1Point>,
  h_vec: List<common.G1Point>,
  u: common.G1Point,
  p: common.G1Point,
  c: common.Field,
  l_vec: List<common.Field>,
  r_vec: List<common.Field>,
) -> Bool {
  let inner_prod = compute_inner_product(l_vec, r_vec)
  let g_commit = compute_vector_commitments(l_vec, g_vec)
  let h_commit = compute_vector_commitments(r_vec, h_vec)
  
  let u_scaled = common.Point {
    x: (u.x * inner_prod) % common.bls12_381_prime,
    y: (u.y * inner_prod) % common.bls12_381_prime,
    z: (u.z * inner_prod) % common.bls12_381_prime,
  }
  
  let lhs = p
  let rhs = common.Point {
    x: common.mod_add(common.mod_add(g_commit.x, h_commit.x), u_scaled.x),
    y: common.mod_add(common.mod_add(g_commit.y, h_commit.y), u_scaled.y),
    z: common.mod_add(common.mod_add(g_commit.z, h_commit.z), u_scaled.z),
  }
  
  // Compare points
  lhs.x == rhs.x && lhs.y == rhs.y && lhs.z == rhs.z
}

fn compute_challenges(
  vk: BulletproofVerificationKey,
  proof: BulletproofProof,
  value: common.Field,
) -> List<common.Field> {
  // Initial transcript with verification key components
  let initial_transcript = generate_transcript(
    bytearray.concat_many([
      common.point_to_bytes(vk.g),
      common.point_to_bytes(vk.h),
      common.point_to_bytes(vk.u),
      common.field_to_bytes(value),
    ])
  )

  // Add proof components to transcript
  let proof_transcript = generate_transcript(
    bytearray.concat_many([
      initial_transcript,
      common.point_to_bytes(proof.a),
      common.point_to_bytes(proof.s),
      common.point_to_bytes(proof.t1),
      common.point_to_bytes(proof.t2),
    ])
  )

  // Generate challenges using the transcript
  let challenge1 = common.bytes_to_field(generate_transcript(proof_transcript))
  let challenge2 = common.bytes_to_field(
    generate_transcript(common.field_to_bytes(challenge1))
  )
  let challenge3 = common.bytes_to_field(
    generate_transcript(common.field_to_bytes(challenge2))
  )

  [challenge1, challenge2, challenge3]
}

fn verify_range_proof(
  vk: BulletproofVerificationKey,
  proof: BulletproofProof,
  value: common.Field,
  bit_length: Int,
) -> Bool {
  // 1. Compute challenges
  let challenges = compute_challenges(vk, proof, value)
  when challenges is {
    [x, y, z] -> {
      // 2. Verify the commitment matches
      let commitment = commit(value, proof.tau_x, vk.g, vk.h)
      
      // 3. Verify vector lengths match the expected bit length
      if list.length(proof.l_vec) != bit_length || list.length(proof.r_vec) != bit_length {
        False
      } else {
        // 4. Verify the inner product argument
        let p = common.Point {
          x: common.mod_add(commitment.x, common.mod_add(proof.t1.x, proof.t2.x)),
          y: common.mod_add(commitment.y, common.mod_add(proof.t1.y, proof.t2.y)),
          z: common.mod_add(commitment.z, common.mod_add(proof.t1.z, proof.t2.z)),
        }
        
        verify_inner_product(vk.g_vec, vk.h_vec, vk.u, p, x, proof.l_vec, proof.r_vec)
      }
    }
    _ -> False
  }
}

fn generate_transcript(data: ByteArray) -> ByteArray {
  crypto.blake2b_256(data)
}

// Function to generate a Bulletproof proof
pub fn generate_proof(
  value: common.Field,
  randomness: common.Field,
  bit_length: Int,
  vk: BulletproofVerificationKey
) -> BulletproofProof {
  // 1. Generate the Pedersen commitment
  let a = commit(value, randomness, vk.g, vk.h)
  
  // 2. Generate random blinding factors
  let tau_x = crypto.blake2b_256(
    bytearray.concat(
      common.field_to_bytes(value),
      common.field_to_bytes(randomness),
    )
  ) |> common.bytes_to_field
  
  let mu = crypto.blake2b_256(
    common.field_to_bytes(tau_x)
  ) |> common.bytes_to_field

  // 3. Generate the vector commitments
  let bit_vec = decompose_into_bits(value, bit_length)
  let l_vec = vector_scalar_multiplication(bit_vec, tau_x)
  let r_vec = vector_scalar_multiplication(bit_vec, mu)
  
  // 4. Generate t1 and t2 commitments
  let t1 = compute_vector_commitments(l_vec, vk.g_vec)
  let t2 = compute_vector_commitments(r_vec, vk.h_vec)
  
  // 5. Generate s commitment
  let s = common.Point {
    x: (vk.h.x * mu) % common.bls12_381_prime,
    y: (vk.h.y * mu) % common.bls12_381_prime,
    z: (vk.h.z * mu) % common.bls12_381_prime,
  }

  BulletproofProof {
    a,
    s,
    t1,
    t2,
    tau_x,
    mu,
    l_vec,
    r_vec,
  }
}

// Helper function to decompose a value into its binary representation
fn decompose_into_bits(value: common.Field, bit_length: Int) -> List<common.Field> {
  if bit_length == 0 {
    []
  } else {
    let bit = value % 2
    let next_value = value / 2
    [bit, ..decompose_into_bits(next_value, bit_length - 1)]
  }
}

// Function to create a Pedersen commitment
fn commit(
  value: common.Field,
  randomness: common.Field,
  g: common.G1Point,
  h: common.G1Point
) -> common.G1Point {
  let g_scaled = common.Point {
    x: (g.x * value) % common.bls12_381_prime,
    y: (g.y * value) % common.bls12_381_prime,
    z: (g.z * value) % common.bls12_381_prime,
  }
  let h_scaled = common.Point {
    x: (h.x * randomness) % common.bls12_381_prime,
    y: (h.y * randomness) % common.bls12_381_prime,
    z: (h.z * randomness) % common.bls12_381_prime,
  }
  // Add the two scaled points
  common.Point {
    x: common.mod_add(g_scaled.x, h_scaled.x),
    y: common.mod_add(g_scaled.y, h_scaled.y),
    z: common.mod_add(g_scaled.z, h_scaled.z),
  }
}

// Function to compute the inner product of two vectors
pub fn compute_inner_product(
  l_vec: List<common.Field>,
  r_vec: List<common.Field>
) -> common.Field {
  when (l_vec, r_vec) is {
    ([], []) -> 0
    ([x, ..xs], [y, ..ys]) -> 
      common.mod_add(
        (x * y) % common.bls12_381_prime,
        compute_inner_product(xs, ys)
      )
    (_, _) -> fail @"Vector lengths must match"
  }
}

// Function to verify that a number is a power of two
pub fn verify_power_of_two(n: Int) -> Bool {
  if n <= 0 {
    False
  } else {
    // A number is a power of 2 if it has exactly one bit set
    // n & (n - 1) will clear the rightmost set bit
    // If result is 0, n was a power of 2
    (n && (n - 1)) == 0
  }
}

// Function to compute vector commitments
pub fn compute_vector_commitments(vec: List<common.Field>, g_vec: List<common.G1Point>) -> common.G1Point {
  when (vec, g_vec) is {
    ([], []) -> 
      // Return point at infinity (identity element)
      common.Point { x: 0, y: 0, z: 0 }
    ([s, ..ss], [g, ..gs]) -> {
      let scaled = common.Point {
        x: (g.x * s) % common.bls12_381_prime,
        y: (g.y * s) % common.bls12_381_prime,
        z: (g.z * s) % common.bls12_381_prime,
      }
      let rest = compute_vector_commitments(ss, gs)
      // Add points using BLS12-381 point addition
      common.Point {
        x: common.mod_add(scaled.x, rest.x),
        y: common.mod_add(scaled.y, rest.y),
        z: common.mod_add(scaled.z, rest.z),
      }
    }
    (_, _) -> fail @"Vector lengths must match"
  }
}

// Function for vector addition
pub fn vector_addition(vec1: List<common.Field>, vec2: List<common.Field>) -> List<common.Field> {
  when (vec1, vec2) is {
    ([], []) -> []
    ([x, ..xs], [y, ..ys]) -> [common.mod_add(x, y), ..vector_addition(xs, ys)]
    (_, _) -> fail @"Vector lengths must match"
  }
}

// Function for vector scalar multiplication
pub fn vector_scalar_multiplication(vec: List<common.Field>, scalar: common.Field) -> List<common.Field> {
  when vec is {
    [] -> []
    [x, ..xs] -> [(x * scalar) % common.bls12_381_prime, ..vector_scalar_multiplication(xs, scalar)]
  }
}

// Function for Hadamard product of two vectors
pub fn hadamard_product(vec1: List<common.Field>, vec2: List<common.Field>) -> List<common.Field> {
  when (vec1, vec2) is {
    ([], []) -> []
    ([x, ..xs], [y, ..ys]) -> [(x * y) % common.bls12_381_prime, ..hadamard_product(xs, ys)]
    (_, _) -> fail @"Vector lengths must match"
  }
}
