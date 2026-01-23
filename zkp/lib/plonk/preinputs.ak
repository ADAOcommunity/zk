use aiken/collection/list
use aiken/crypto/bitwise.{State}
use aiken/crypto/bls12_381/scalar.{Scalar, scale}

pub type PlonkPreInputs {
  power: Int,
  k1: State<Scalar>,
  k2: State<Scalar>,
  q_m: ByteArray,
  q_l: ByteArray,
  q_r: ByteArray,
  q_o: ByteArray,
  q_c: ByteArray,
  s_sig1: ByteArray,
  s_sig2: ByteArray,
  s_sig3: ByteArray,
  x2: ByteArray,
}

pub type PreparedPlonkPreInputs {
  n: Int,
  generators: List<State<Scalar>>,
  inputs: PlonkPreInputs,
}

pub fn plonk_prepare_preinputs(
  inputs: PlonkPreInputs,
  generator: State<Scalar>,
  n_public: Int,
) -> PreparedPlonkPreInputs {
  PreparedPlonkPreInputs {
    n: scalar.to_int(scale(scalar.from_int(2), inputs.power)),
    generators: list.map(list.range(0, n_public), fn(n) { scale(generator, n) }),
    inputs,
  }
}
