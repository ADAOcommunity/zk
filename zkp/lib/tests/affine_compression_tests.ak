use aiken/primitive/bytearray
use common/blst_affine.{
  G1Infinity, G1Point, G2Infinity, G2Point, g1_affine_compress,
  g2_affine_compress,
}
use tests/test_utils.{int_to_field_bytes}

const g1_a =
  G1Point {
    x: int_to_field_bytes(
      1449497163185511255960735085284916465289671960584516882188976107972557459282929317206787632956592412629479052789269,
    ),
    y: int_to_field_bytes(
      3989435130608907884226398003251903810202294754002824591270717519803551766794598638405495657602973072105705998377235,
    ),
  }

const g1_b =
  G1Point {
    x: int_to_field_bytes(
      1736517976604336165319190912612272873938577839112916200234711436320455450585513057542289433496238251851408450867401,
    ),
    y: int_to_field_bytes(
      3933887163973139524131102938351008807575633708420235139733365238460765495095075881949112452329274308243204895789594,
    ),
  }

const g2_a =
  G2Point {
    x: (
      int_to_field_bytes(
        3704008370612030042639225780688100652501841279134321941704739881999208925475933291394297428500078646993316240973153,
      ),
      int_to_field_bytes(
        1810906233092108589178121796443607027092699677349013567194850167065200892154306562227413644705236351395811153581123,
      ),
    ),
    y: (
      int_to_field_bytes(
        1037602692507020953234459923280188933700635788749088578899524073006036329531065870292398532987175917561104371064333,
      ),
      int_to_field_bytes(
        539240156603698219404689729686562881306656606356852620033422782463096424705762574130046909186283630196554411802829,
      ),
    ),
  }

// Test G1 compression format
test test_g1_compression_format() {
  let point = g1_a
  let compressed = g1_affine_compress(point)
  // Verify compressed format: should be 48 bytes with compression bit set
  let compressed_length = bytearray.length(compressed)
  let first_byte = bytearray.to_int_big_endian(bytearray.take(compressed, 1))
  let has_compression_bit = first_byte >= 128
  // Check if bit 7 is set (0x80)
  compressed_length == 48 && has_compression_bit
}

test test_g1_infinity_compression() {
  let compressed = g1_affine_compress(G1Infinity)
  let first_byte = bytearray.to_int_big_endian(bytearray.take(compressed, 1))
  let length = bytearray.length(compressed)
  // Should have compression bit (0x80) + infinity bit (0x40) = 0xc0 = 192
  let is_infinity_encoding = first_byte == 192
  let correct_length = length == 48
  is_infinity_encoding && correct_length
}

test test_g1_different_points_different_compression() {
  let compressed1 = g1_affine_compress(g1_a)
  let compressed2 = g1_affine_compress(g1_b)
  // Different points should compress to different values
  compressed1 != compressed2
}

test test_g2_compression_format() {
  expect G2Point { x: x2, y: y2 } = g2_a
  let compressed = g2_affine_compress(G2Point(x2, y2))
  let compressed_length = bytearray.length(compressed)
  let first_byte = bytearray.to_int_big_endian(bytearray.take(compressed, 1))
  let has_compression_bit = first_byte >= 128
  // G2 compressed should be 96 bytes with compression bit set
  compressed_length == 96 && has_compression_bit
}

test test_g2_infinity_compression() {
  let compressed = g2_affine_compress(G2Infinity)
  let first_byte = bytearray.to_int_big_endian(bytearray.take(compressed, 1))
  let length = bytearray.length(compressed)
  // Should have compression + infinity bits
  let is_infinity_encoding = first_byte == 192
  // 0xc0
  let correct_length = length == 96
  is_infinity_encoding && correct_length
}

test test_g2_infinity_debug() {
  let compressed = g2_affine_compress(G2Infinity)
  let first_byte = bytearray.to_int_big_endian(bytearray.take(compressed, 1))
  // Check just the first byte
  first_byte == 192
}

test test_g2_infinity_length() {
  let compressed = g2_affine_compress(G2Infinity)
  let length = bytearray.length(compressed)
  // Check only the length  
  length == 96
}

// Test that y-coordinate ordering bit is being set correctly
test test_y_ordering_bit() {
  expect G1Point { y, .. } = g1_a
  let compressed = g1_affine_compress(g1_a)
  let first_byte = bytearray.to_int_big_endian(bytearray.take(compressed, 1))
  // Extract y-ordering bit (bit 5, value 32)
  let y_bit_set = first_byte % 64 >= 32
  // Check if bit 5 is set
  // This should match our y_is_larger logic from the compression
  let first_y_byte = bytearray.take(y, 1)
  let expected_y_larger = bytearray.to_int_big_endian(first_y_byte) >= 128
  y_bit_set == expected_y_larger
}
