use aiken/builtin.{blake2b_224}
use aiken/collection/list
use aiken/crypto/bitwise.{State}
use aiken/crypto/bls12_381/scalar.{Scalar}
use aiken/primitive/bytearray
use common/common.{concat_and_blake2b_224, scalar_rt_bs}
use plonk/preinputs.{PreparedPlonkPreInputs}

pub type PlonkProof {
  commitment_a: ByteArray,
  commitment_b: ByteArray,
  commitment_c: ByteArray,
  commitment_z: ByteArray,
  t_low: ByteArray,
  t_mid: ByteArray,
  t_high: ByteArray,
  w_omega: ByteArray,
  w_omega_zeta: ByteArray,
  a_eval: Int,
  b_eval: Int,
  c_eval: Int,
  s_sig1_p: Int,
  s_sig2_p: Int,
  z_omega: Int,
}

pub type PreparedPlonkProof {
  proof: PlonkProof,
  lagrange_inverses: List<State<Scalar>>,
}

pub fn plonk_prepare_proof(
  preinputs: PreparedPlonkPreInputs,
  pub_inputs: List<Int>,
  proof: PlonkProof,
) -> PreparedPlonkProof {
  let beta_inputs =
    [
      preinputs.inputs.q_m,
      preinputs.inputs.q_l,
      preinputs.inputs.q_r,
      preinputs.inputs.q_o,
      preinputs.inputs.q_c,
      preinputs.inputs.s_sig1,
      preinputs.inputs.s_sig2,
      preinputs.inputs.s_sig3,
      list.foldl(
        pub_inputs,
        #"",
        fn(a, b) { bytearray.concat(b, bytearray.from_int_big_endian(a, 32)) },
      ),
      proof.commitment_a,
      proof.commitment_b,
      proof.commitment_c,
    ]
  let beta = scalar_rt_bs(concat_and_blake2b_224(beta_inputs))
  let gamma = scalar_rt_bs(blake2b_224(beta))
  let alpha =
    scalar_rt_bs(concat_and_blake2b_224([beta, gamma, proof.commitment_z]))
  let zeta =
    scalar.from_bytes(
      concat_and_blake2b_224([alpha, proof.t_low, proof.t_mid, proof.t_high]),
    )
  let lagrange_inverses =
    list.map(
      preinputs.generators,
      fn(x) {
        scalar.neg(
          scalar.mul(scalar.from_int(preinputs.n), scalar.sub(zeta, x)),
        )
      },
    )

  PreparedPlonkProof { proof, lagrange_inverses }
}
