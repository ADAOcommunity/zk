use aiken/primitive/bytearray
use common/common.{bls12_381_base_prime, bls12_381_half_prime}

/// Affine representation of a point on the BLS12-381 G1 curve
pub type G1Affine {
  /// Point at infinity
  G1Infinity
  /// Finite point with x and y coordinates
  G1Point { x: ByteArray, y: ByteArray }
}

/// Affine representation of a point on the BLS12-381 G2 curve
pub type G2Affine {
  /// Point at infinity
  G2Infinity
  /// Finite point with x and y coordinates (each coordinate is 2 field elements)
  G2Point { x: (ByteArray, ByteArray), y: (ByteArray, ByteArray) }
}

/// Compress a G1 affine point to 48 bytes using BLS12-381 standard.
///
/// Fails unless `g1_affine_valid(point)`. Compression keeps only which side of
/// (p - 1) / 2 `y` is on, so without that check any `y` on the same side would
/// give the same bytes, and many different `G1Affine` values would decode to
/// one point.
pub fn g1_affine_compress(point: G1Affine) -> ByteArray {
  when point is {
    G1Infinity -> {
      // BLS12-381 infinity encoding: compression bit (0x80) + infinity bit (0x40) = 0xc0
      let infinity_byte = #"c0"
      let zeros = bytearray.from_int_big_endian(0, 47)
      // 47 bytes of zeros
      bytearray.concat(infinity_byte, zeros)
    }
    G1Point { x, y } -> {
      let y_int = bytearray.to_int_big_endian(y)
      expect g1_coordinates_valid(x, bytearray.to_int_big_endian(x), y, y_int)
      // Manual BLS12-381 G1 compression. x is below p, so its top three bits
      // are clear and free for the flags.
      // Set compression bit (0x80) and determine y-coordinate lexicographic ordering
      let first_x_byte = bytearray.take(x, 1)
      let rest_x = bytearray.drop(x, 1)
      // Check if y > (p-1)/2 to determine which of the two possible y values this is.
      // The sort bit (0x20) indicates the "lexicographically larger" y-coordinate.
      let y_is_larger = y_int > bls12_381_half_prime
      // Set the compression bit (0x80) and y-coordinate bit if needed
      let compressed_first_byte =
        if y_is_larger {
          // 0x80 | 0x20 = 0xa0: compression + sort bit
          bytearray.or_bytes(first_x_byte, #"a0", False)
        } else {
          // 0x80 only: compression bit, no sort bit
          bytearray.or_bytes(first_x_byte, #"80", False)
        }
      bytearray.concat(compressed_first_byte, rest_x)
    }
  }
}

/// Compress a G2 affine point to 96 bytes using BLS12-381 standard
pub fn g2_affine_compress(point: G2Affine) -> ByteArray {
  when point is {
    G2Infinity -> {
      // BLS12-381 G2 infinity encoding: compression bit (0x80) + infinity bit (0x40) = 0xc0
      let infinity_byte = #"c0"
      let zeros = bytearray.from_int_big_endian(0, 95)
      // 95 bytes of zeros
      bytearray.concat(infinity_byte, zeros)
    }
    G2Point { x: (x0, x1), y: (y0, y1) } -> {
      // Manual BLS12-381 G2 compression
      // G2 uses Fp2 elements: each coordinate is (c0, c1) representing c0 + c1*u
      // where x0=c0 (real), x1=c1 (imaginary) per snarkjs convention.
      //
      // BLST serialization format: [c1_with_flags | c0] (imaginary first, real second)
      // So we put x1 first (with flags), then x0.
      let first_x1_byte = bytearray.take(x1, 1)
      let rest_x1 = bytearray.drop(x1, 1)
      // Determine y sort bit using Fp2 lexicographic ordering:
      // Compare c1 (imaginary) of y first. If c1 is zero, compare c0 (real).
      let y1_int = bytearray.to_int_big_endian(y1)
      let y0_int = bytearray.to_int_big_endian(y0)
      let y_is_larger =
        if y1_int == 0 {
          y0_int > bls12_381_half_prime
        } else {
          y1_int > bls12_381_half_prime
        }
      // Set compression and y-ordering bits
      let compressed_first_byte =
        if y_is_larger {
          // 0x80 | 0x20 = 0xa0: compression + sort bit
          bytearray.or_bytes(first_x1_byte, #"a0", False)
        } else {
          // 0x80 only: compression bit, no sort bit
          bytearray.or_bytes(first_x1_byte, #"80", False)
        }
      // Return compressed form: [c1_with_flags | c0] (96 bytes total)
      bytearray.concat(bytearray.concat(compressed_first_byte, rest_x1), x0)
    }
  }
}

/// True when `point` is the point at infinity, or each coordinate is exactly
/// 48 bytes and below p, and y^2 = x^3 + 4. These are the points
/// `g1_affine_compress` accepts, and each one has exactly one `G1Affine` value.
/// Membership of the G1 subgroup isn't checked here; `g1.decompress` checks it
/// when the compressed bytes are used.
pub fn g1_affine_valid(point: G1Affine) -> Bool {
  when point is {
    G1Infinity -> True
    G1Point { x, y } ->
      g1_coordinates_valid(
        x,
        bytearray.to_int_big_endian(x),
        y,
        bytearray.to_int_big_endian(y),
      )
  }
}

/// True when the point satisfies the BLS12-381 G1 curve equation
/// y^2 = x^3 + 4 mod p. Coordinates aren't required to be below p or 48 bytes
/// long; `g1_affine_valid` checks that too.
pub fn g1_on_curve(point: G1Affine) -> Bool {
  when point is {
    G1Infinity -> True
    G1Point { x, y } ->
      on_g1_curve(
        bytearray.to_int_big_endian(x),
        bytearray.to_int_big_endian(y),
      )
  }
}

fn g1_coordinates_valid(
  x: ByteArray,
  x_int: Int,
  y: ByteArray,
  y_int: Int,
) -> Bool {
  and {
    canonical_field_element(x, x_int),
    canonical_field_element(y, y_int),
    on_g1_curve(x_int, y_int),
  }
}

/// True when `bytes`, which encodes `value`, is exactly 48 bytes and `value`
/// is below p, so no other byte string encodes the same field element.
fn canonical_field_element(bytes: ByteArray, value: Int) -> Bool {
  bytearray.length(bytes) == 48 && value < bls12_381_base_prime
}

fn on_g1_curve(x: Int, y: Int) -> Bool {
  y * y % bls12_381_base_prime == ( x * x * x + 4 ) % bls12_381_base_prime
}
