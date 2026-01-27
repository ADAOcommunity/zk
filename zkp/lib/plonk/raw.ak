// use plonk/preinputs.{PlonkPreInputs}
use common/common.{G1Point, G2Point}

pub type PlonkVerificationKey {
  n_public: Int,
  power: Int,
  k1: Int,
  k2: Int,
  q_m: G1Point,
  q_l: G1Point,
  q_r: G1Point,
  q_o: G1Point,
  q_c: G1Point,
  s_sig1: G1Point,
  s_sig2: G1Point,
  s_sig3: G1Point,
  x2: G2Point,
  w: Int,
}

pub type RawPlonkProof {
  commitment_a: G1Point,
  commitment_b: G1Point,
  commitment_c: G1Point,
  commitment_z: G1Point,
  t_low: G1Point,
  t_mid: G1Point,
  t_high: G1Point,
  w_omega: G1Point,
  w_omega_zeta: G1Point,
  a_eval: Int,
  b_eval: Int,
  c_eval: Int,
  s_sig1_p: Int,
  s_sig2_p: Int,
  z_omega: Int,
}
// pub fn vkey_to_preinputs(vkey: PlonkVerificationKey) -> PlonkPreInputs {
//     // PlonkPreInputs {
//     //     n_public: vkey.n_public,
//     //     power: vkey.power,
//     //     k1: vkey.k1,
//     //     k2: vkey.k2,
//     //     q_m: vkey.q_m,
//     //     q_l: vkey.q_l,
//     //     q_r: vkey.q_r,
//     //     q_o: vkey.q_o,
//     //     q_c: vkey.q_c,
//     //     s_sig1: vkey.s_sig1,
//     //     s_sig2: vkey.s_sig2,
//     //     s_sig3: vkey.s_sig3,
//     //     x2: vkey.x2,
//     //     w: vkey.w,
//     // }
//     TODO
// }
