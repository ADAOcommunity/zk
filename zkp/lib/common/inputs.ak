//// Checks on public inputs, shared by the Groth16 and PLONK verifiers.

/// True when `inputs` has exactly `expected` entries.
///
/// Without this check, inputs the circuit has no slot for are never
/// constrained, and a validator that reads inputs by position could be given a
/// value the proof doesn't bind.
pub fn check_public_inputs(inputs: List<Int>, expected: Int) -> Bool {
  when inputs is {
    [] -> expected == 0
    [_, ..rest] -> and {
        expected > 0,
        check_public_inputs(rest, expected - 1),
      }
  }
}
