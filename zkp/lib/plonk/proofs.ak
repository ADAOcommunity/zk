use aiken/builtin.{blake2b_224}
use aiken/collection/list
use aiken/crypto/bitwise.{State}
use aiken/crypto/bls12_381/scalar.{Scalar}
use aiken/crypto/bls12_381/g1
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
  commitment_a: G1Element,
  commitment_b: G1Element,
  commitment_c: G1Element,
  commitment_z: G1Element,
  t_low: G1Element,
  t_mid: G1Element,
  t_high: G1Element,
  w_omega: G1Element,
  w_omega_zeta: G1Element,
  a_eval: State<Scalar>,
  b_eval: State<Scalar>,
  c_eval: State<Scalar>,
  s_sig1_p: State<Scalar>,
  s_sig2_p: State<Scalar>,
  z_omega: State<Scalar>,
  lagrange_inverses: List<State<Scalar>>,
}

pub fn plonk_prepare_proof(
  preinputs: PreparedPlonkPreInputs,
  pub_inputs: List<Int>,
  proof: PlonkProof,
) -> PreparedPlonkProof {
  let beta_inputs =
    [
      g1.compress(preinputs.q_m),
      g1.compress(preinputs.q_l),
      g1.compress(preinputs.q_r),
      g1.compress(preinputs.q_o),
      g1.compress(preinputs.q_c),
      g1.compress(preinputs.s_sig1),
      g1.compress(preinputs.s_sig2),
      g1.compress(preinputs.s_sig3),
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

  // uncompress the proof commitments
  expect commitment_a: G1Element = g1.decompress(proof.commitment_a)
  expect commitment_b: G1Element = g1.decompress(proof.commitment_b)
  expect commitment_c: G1Element = g1.decompress(proof.commitment_c)
  expect commitment_z: G1Element = g1.decompress(proof.commitment_z)
  expect t_low: G1Element = g1.decompress(proof.t_low)
  expect t_mid: G1Element = g1.decompress(proof.t_mid)
  expect t_high: G1Element = g1.decompress(proof.t_high)
  expect w_omega: G1Element = g1.decompress(proof.w_omega)
  expect w_omega_zeta: G1Element = g1.decompress(proof.w_omega_zeta)

  // convert polynomial evaluations
  let a_eval: State<Scalar> = scalar.from_int(proof.a_eval)
  let b_eval: State<Scalar> = scalar.from_int(proof.b_eval)
  let c_eval: State<Scalar> = scalar.from_int(proof.c_eval)
  let s_sig1_p: State<Scalar> = scalar.from_int(proof.s_sig1_p)
  let s_sig2_p: State<Scalar> = scalar.from_int(proof.s_sig2_p)
  let z_omega: State<Scalar> = scalar.from_int(proof.z_omega)

  PreparedPlonkProof { 
    commitment_a,
    commitment_b,
    commitment_c,
    commitment_z,
    t_low,
    t_mid,
    t_high,
    w_omega,
    w_omega_zeta,
    a_eval,
    b_eval,
    c_eval,
    s_sig1_p,
    s_sig2_p,
    z_omega,
    lagrange_inverses }
}