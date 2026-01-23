use aiken/builtin.{blake2b_224}
use aiken/collection/list
use aiken/crypto/bitwise.{State}
use aiken/crypto/bls12_381/g1
use aiken/crypto/bls12_381/g2
use aiken/crypto/bls12_381/pairing.{final_exponentiation, miller_loop}
use aiken/crypto/bls12_381/scalar.{Scalar, scale2}
use aiken/primitive/bytearray
use common/common.{bls12_381_prime, concat_and_blake2b_224, g1_sum, scalar_sum}
use plonk/preinputs.{PlonkPreInputs, PreparedPlonkPreInputs}
use plonk/proofs.{PlonkProof, PreparedPlonkProof}

pub fn verify_plonk(
  preinputs: PreparedPlonkPreInputs,
  pub_inputs: List<Int>,
  preproof: PreparedPlonkProof,
) -> Bool {
  let proof: PlonkProof = preproof.proof
  let inputs: PlonkPreInputs = preinputs.inputs

  // uncompress the inputs
  let q_m: G1Element = g1.decompress(inputs.q_m)
  let q_l: G1Element = g1.decompress(inputs.q_l)
  let q_r: G1Element = g1.decompress(inputs.q_r)
  let q_o: G1Element = g1.decompress(inputs.q_o)
  let q_c: G1Element = g1.decompress(inputs.q_c)
  let s_sig1: G1Element = g1.decompress(inputs.s_sig1)
  let s_sig2: G1Element = g1.decompress(inputs.s_sig2)
  let s_sig3: G1Element = g1.decompress(inputs.s_sig3)
  let x2: G2Element = g2.decompress(inputs.x2)

  // uncompress the proof commitments
  let comm_a: G1Element = g1.decompress(proof.commitment_a)
  let comm_b: G1Element = g1.decompress(proof.commitment_b)
  let comm_c: G1Element = g1.decompress(proof.commitment_c)
  let comm_z: G1Element = g1.decompress(proof.commitment_z)
  let comm_t_low: G1Element = g1.decompress(proof.t_low)
  let comm_t_mid: G1Element = g1.decompress(proof.t_mid)
  let comm_t_high: G1Element = g1.decompress(proof.t_high)
  let comm_w_omega: G1Element = g1.decompress(proof.w_omega)
  let comm_w_omega_zeta: G1Element = g1.decompress(proof.w_omega_zeta)

  // clamp scalars
  let a_eval: State<Scalar> = scalar.from_int(proof.a_eval)
  let b_eval: State<Scalar> = scalar.from_int(proof.b_eval)
  let c_eval: State<Scalar> = scalar.from_int(proof.c_eval)
  let s1: State<Scalar> = scalar.from_int(proof.s_sig1_p)
  let s2: State<Scalar> = scalar.from_int(proof.s_sig2_p)
  let z_omega: State<Scalar> = scalar.from_int(proof.z_omega)

  let w_all: List<State<Scalar>> =
    list.map(pub_inputs, fn(x) { scalar.neg(scalar.from_int(x)) })

  expect Some(gen_tail) = list.tail(preinputs.generators)
  expect Some(gen_2nd) = list.head(gen_tail)

  let scalar1: State<Scalar> = scalar.from_int(1)

  // I guess we don't need to decompress the generators? The aiken documentation is not clear on this.
  // let g1_generator = g1.decompress(g1.generator)
  // let g2_generator = g2.decompress(g2.generator)
  let beta_bs: ByteArray =
    concat_and_blake2b_224(
      [
        inputs.q_m,
        inputs.q_l,
        inputs.q_r,
        inputs.q_o,
        inputs.q_c,
        inputs.s_sig1,
        inputs.s_sig2,
        inputs.s_sig3,
        list.foldl(
          pub_inputs,
          #"",
          fn(a, b) { bytearray.concat(b, bytearray.from_int_big_endian(a, 32)) },
        ),
        proof.commitment_a,
        proof.commitment_b,
        proof.commitment_c,
      ],
    )
  let beta: State<Scalar> = scalar.from_bytes(beta_bs)
  let gamma_bs: ByteArray = blake2b_224(scalar.to_bytes(beta))
  let gamma: State<Scalar> = scalar.from_bytes(gamma_bs)

  let alpha_bs: ByteArray =
    concat_and_blake2b_224(
      [scalar.to_bytes(beta), scalar.to_bytes(gamma), proof.commitment_z],
    )
  let alpha: State<Scalar> = scalar.from_bytes(alpha_bs)

  let zeta_bs: ByteArray =
    concat_and_blake2b_224(
      [scalar.to_bytes(alpha), proof.t_low, proof.t_mid, proof.t_high],
    )
  let zeta: State<Scalar> = scalar.from_bytes(zeta_bs)

  let v_bs: ByteArray =
    concat_and_blake2b_224(
      [
        scalar.to_bytes(zeta),
        scalar.to_bytes(a_eval),
        scalar.to_bytes(b_eval),
        scalar.to_bytes(c_eval),
        scalar.to_bytes(s1),
        scalar.to_bytes(s2),
        scalar.to_bytes(z_omega),
      ],
    )
  let v: State<Scalar> = scalar.from_bytes(v_bs)
  let u_bs: ByteArray =
    concat_and_blake2b_224([proof.w_omega, proof.w_omega_zeta])
  let u: State<Scalar> = scalar.from_bytes(u_bs)

  let pow2_zeta_p: State<Scalar> = scale2(zeta, bls12_381_prime)
  let pow2_zeta_p_minus_1: State<Scalar> = scalar.sub(pow2_zeta_p, scalar1)

  // calculate lagrange polynomials
  let langrange_polys: List<State<Scalar>> =
    list.map2(
      preinputs.generators,
      preproof.lagrange_inverses,
      fn(x, y) { scalar.mul(scalar.mul(x, pow2_zeta_p_minus_1), y) },
    )
  expect Some(lagrange_poly_head) = list.head(langrange_polys)

  let pi_zeta: State<Scalar> =
    scalar_sum(
      list.map2(w_all, langrange_polys, fn(w, lag) { scalar.mul(w, lag) }),
    )

  let alpha_sq = scalar.mul(alpha, alpha)
  let alpha_z_omega = scalar.mul(alpha, z_omega)
  let beta_zeta = scalar.mul(beta, zeta)
  let a_gamma = scalar.add(a_eval, gamma)
  let b_gamma = scalar.add(b_eval, gamma)
  let c_gamma = scalar.add(c_eval, gamma)

  let beta_s1 = scalar.mul(beta, s1)
  let beta_s2 = scalar.mul(beta, s2)
  let r0 =
    scalar.sub(
      scalar.sub(pi_zeta, scalar.mul(lagrange_poly_head, alpha_sq)),
      scalar.mul(
        alpha_z_omega,
        scalar.mul(
          scalar.add(a_gamma, beta_s1),
          scalar.mul(scalar.add(b_gamma, beta_s2), c_gamma),
        ),
      ),
    )

  // batch polynomial commitments
  let bpc_g1 =
    g1_sum(
      [
        g1.scale(q_m, scalar.mul(a_eval, b_eval)),
        g1.scale(q_l, a_eval),
        g1.scale(q_r, b_eval),
        g1.scale(q_o, c_eval),
        q_c,
        g1.scale(
          comm_z,
          {
            // product: (a_gamma + beta_zeta) * (b_gamma + beta_zeta * k1) * (c_gamma + beta_zeta * k2) * alpha
            let product =
              scalar.add(a_gamma, beta_zeta)
                |> scalar.mul(
                    scalar.add(b_gamma, scalar.mul(beta_zeta, inputs.k1)),
                  )
                |> scalar.mul(
                    scalar.add(c_gamma, scalar.mul(beta_zeta, inputs.k2)),
                  )
                |> scalar.mul(alpha)
            scalar.add(
              scalar.add(product, scalar.mul(lagrange_poly_head, alpha_sq)),
              u,
            )
          },
        ),
        g1.scale(
          s_sig3,
          scalar.neg(
            scalar.mul(
              scalar.mul(
                scalar.add(a_gamma, beta_s1),
                scalar.add(b_gamma, beta_s2),
              ),
              scalar.mul(alpha_z_omega, beta),
            ),
          ),
        ),
        g1.scale(
          g1.add(
            comm_t_low,
            g1.add(
              g1.scale(comm_t_mid, pow2_zeta_p),
              g1.scale(comm_t_high, scale2(pow2_zeta_p, 1)),
            ),
          ),
          scalar.neg(pow2_zeta_p_minus_1),
        ),
      ],
    )

  let bpc_full =
    g1.add(
      bpc_g1,
      {
        // nested commitments: comm_a + v * (comm_b + v * (comm_c + v * (s_sig1 + v * s_sig2)))
        let nested_comms =
          g1.add(s_sig1, g1.scale(s_sig2, v))
            |> g1.scale(v)
            |> g1.add(comm_c, _)
            |> g1.scale(v)
            |> g1.add(comm_b, _)
            |> g1.scale(v)
            |> g1.add(comm_a, _)

        g1.scale(nested_comms, v)
      },
    )

  let group_encoded_batch_eval =
    g1.scale(
      g1.generator,
      {
        // nested evaluation: a_eval + v * (b_eval + v * (c_eval + v * (s1 + v * s2)))
        let nested_eval =
          scalar.add(s1, scalar.mul(v, s2))
            |> scalar.mul(v, _)
            |> scalar.add(c_eval, _)
            |> scalar.mul(v, _)
            |> scalar.add(b_eval, _)
            |> scalar.mul(v, _)
            |> scalar.add(a_eval, _)
        // final expression: -r0 + v * nested_eval + u * z_omega
        scalar.add(
          scalar.add(scalar.neg(r0), scalar.mul(v, nested_eval)),
          scalar.mul(u, z_omega),
        )
      },
    )

  //  bls12_381_millerLoop (commWOmega + scale u commWOmegaZeta) x2)
  let miller_loop_1 =
    miller_loop(g1.add(comm_w_omega, g1.scale(comm_w_omega_zeta, u)), x2)

  //  (bls12_381_millerLoop (scale zeta commWOmega + scale (u * zeta * head (tail gens)) commWOmegaZeta + batchPolyCommitFull - groupEncodedBatchEval) bls12_381_G2_generator)
  let miller_loop_2 =
    miller_loop(
      g1.add(
        g1.add(
          g1.scale(comm_w_omega, zeta),
          g1.scale(comm_w_omega_zeta, scalar.mul(u, scalar.mul(zeta, gen_2nd))),
        ),
        g1.sub(bpc_full, group_encoded_batch_eval),
      ),
      g2.generator,
    )

  // bls12_381_finalVerify
  let final_verification = final_exponentiation(miller_loop_1, miller_loop_2)

  // and (zipWith (\x y -> x * Scalar n * (zeta - y) == one) lagsInv gens)
  let lagrange_check =
    scalar_sum(
      list.map2(
        preproof.lagrange_inverses,
        preinputs.generators,
        fn(x, y) {
          scalar.mul(
            x,
            scalar.mul(scalar.from_int(preinputs.n), scalar.sub(zeta, y)),
          )
        },
      ),
    ) == scalar.from_int(1)
  final_verification && lagrange_check
}
