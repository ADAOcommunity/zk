//// Tests for `common/inputs`, the public-input check both verifiers share.

use aiken/collection/list
use aiken/crypto/bls12_381/scalar.{field_prime}
use aiken/fuzz
use common/inputs.{check_public_inputs}

/// A uniformly random value in `[0, r)`.
fn in_field() -> Fuzzer<Int> {
  fuzz.int_between(0, field_prime - 1)
}

/// A list length to compare against, including one below zero.
fn some_count() -> Fuzzer<Int> {
  fuzz.int_between(-1, 9)
}

/// Any list of in-range values passes for its own length, and fails for every
/// other length.
test prop_check_public_inputs_count(
  (xs, other) via fuzz.tuple(fuzz.list_between(in_field(), 0, 8), some_count()),
) {
  let n = list.length(xs)
  and {
    check_public_inputs(xs, n),
    check_public_inputs(xs, other) == ( other == n ),
  }
}

test check_public_inputs_empty() {
  and {
    check_public_inputs([], 0),
    !check_public_inputs([], 1),
    !check_public_inputs([0], 0),
  }
}
