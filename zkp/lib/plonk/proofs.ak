use aiken/builtin.{keccak_256}
use aiken/collection/list
use aiken/crypto/bitwise.{State}
use aiken/crypto/bls12_381/g1
use aiken/crypto/bls12_381/scalar.{Scalar, field_prime}
use common/common.{concat_and_keccak_256}
use common/inputs.{scalar_in_field}
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

/// Decode a proof and compute its Lagrange inverses for `verify_plonk`. Fails
/// unless every point is a valid compressed G1 point in the prime-order
/// subgroup (`g1.decompress` checks this) and every evaluation lies in
/// `[0, r)`. The evaluations are hashed into the transcript only after they
/// are reduced mod `r`, so without the range check `x` and `x + r` would
/// verify alike, and one proof would have many encodings.
pub fn plonk_prepare_proof(
  preinputs: PreparedPlonkPreInputs,
  pub_inputs: List<Int>,
  proof: PlonkProof,
) -> PreparedPlonkProof {
  let pub_input_bytes =
    list.map(pub_inputs, fn(x) { scalar.to_bytes(scalar.from_int(x)) })
  let beta_inputs =
    list.concat(
      [
        g1.compress(preinputs.q_m),
        g1.compress(preinputs.q_l),
        g1.compress(preinputs.q_r),
        g1.compress(preinputs.q_o),
        g1.compress(preinputs.q_c),
        g1.compress(preinputs.s_sig1),
        g1.compress(preinputs.s_sig2),
        g1.compress(preinputs.s_sig3),
      ],
      list.concat(
        pub_input_bytes,
        [proof.commitment_a, proof.commitment_b, proof.commitment_c],
      ),
    )
  let beta: State<Scalar> =
    scalar.from_bytes(concat_and_keccak_256(beta_inputs))
  let gamma: State<Scalar> =
    scalar.from_bytes(keccak_256(scalar.to_bytes(beta)))
  let alpha: State<Scalar> =
    scalar.from_bytes(
      concat_and_keccak_256(
        [scalar.to_bytes(beta), scalar.to_bytes(gamma), proof.commitment_z],
      ),
    )
  let zeta: State<Scalar> =
    scalar.from_bytes(
      concat_and_keccak_256(
        [scalar.to_bytes(alpha), proof.t_low, proof.t_mid, proof.t_high],
      ),
    )
  let lagrange_inverses =
    list.map(
      preinputs.generators,
      fn(x) {
        let denom =
          scalar.mul(scalar.from_int(preinputs.n), scalar.sub(zeta, x))
        scalar.scale(denom, field_prime - 2)
      },
    )

  // uncompress the proof commitments
  let commitment_a = g1.decompress(proof.commitment_a)
  let commitment_b = g1.decompress(proof.commitment_b)
  let commitment_c = g1.decompress(proof.commitment_c)
  let commitment_z = g1.decompress(proof.commitment_z)
  let t_low = g1.decompress(proof.t_low)
  let t_mid = g1.decompress(proof.t_mid)
  let t_high = g1.decompress(proof.t_high)
  let w_omega = g1.decompress(proof.w_omega)
  let w_omega_zeta = g1.decompress(proof.w_omega_zeta)

  // convert polynomial evaluations, failing unless each is in [0, r)
  let a_eval: State<Scalar> = scalar_in_field(proof.a_eval)
  let b_eval: State<Scalar> = scalar_in_field(proof.b_eval)
  let c_eval: State<Scalar> = scalar_in_field(proof.c_eval)
  let s_sig1_p: State<Scalar> = scalar_in_field(proof.s_sig1_p)
  let s_sig2_p: State<Scalar> = scalar_in_field(proof.s_sig2_p)
  let z_omega: State<Scalar> = scalar_in_field(proof.z_omega)

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
    lagrange_inverses,
  }
}
