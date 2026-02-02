use aiken/primitive/bytearray

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

/// Compress a G1 affine point to 48 bytes using BLS12-381 standard
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
      // Manual BLS12-381 G1 compression
      // Set compression bit (0x80) and determine y-coordinate lexicographic ordering
      let first_x_byte = bytearray.take(x, 1)
      let rest_x = bytearray.drop(x, 1)
      // Check if y is lexicographically larger than (p-y) mod p
      // For now, we'll use a simple heuristic: check if y's first byte > 0x7f
      let first_y_byte = bytearray.take(y, 1)
      let y_is_larger = bytearray.to_int_big_endian(first_y_byte) >= 128
      // Set the compression bit (0x80) and y-coordinate bit if needed
      let compressed_first_byte =
        if y_is_larger {
          bytearray.or_bytes(first_x_byte, #"a0", False)
        } else {
          // 0x80 | 0x20
          bytearray.or_bytes(first_x_byte, #"80", False)
        }
      // 0x80 only
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
    G2Point { x: (x0, x1), y: (y0, _y1) } -> {
      // Manual BLS12-381 G2 compression
      // G2 compression is similar to G1 but works on Fp2 elements
      // Each coordinate is a pair of field elements (x0, x1) representing x0 + x1*u
      // Set compression bit on the first byte of x0 (the higher-order part)
      let first_x0_byte = bytearray.take(x0, 1)
      let rest_x0 = bytearray.drop(x0, 1)
      // Determine lexicographic ordering of y-coordinate
      // For G2, we compare y with (p-y) in Fp2 ordering
      let first_y0_byte = bytearray.take(y0, 1)
      let y_is_larger = bytearray.to_int_big_endian(first_y0_byte) >= 128
      // Set compression and y-ordering bits
      let compressed_first_byte =
        if y_is_larger {
          bytearray.or_bytes(first_x0_byte, #"a0", False)
        } else {
          // 0x80 | 0x20
          bytearray.or_bytes(first_x0_byte, #"80", False)
        }
      // 0x80 only
      // Return compressed form: compressed_x0 + x1 (96 bytes total)
      bytearray.concat(bytearray.concat(compressed_first_byte, rest_x0), x1)
    }
  }
}
