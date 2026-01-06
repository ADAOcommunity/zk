use aiken/builtin.{
  bls12_381_final_verify, bls12_381_g1_add, bls12_381_g1_neg,
  bls12_381_g1_scalar_mul, bls12_381_g1_uncompress, bls12_381_g2_uncompress,
  bls12_381_miller_loop,
}
use aiken/collection/list
use aiken/crypto
use aiken/crypto/bls12_381/g1
use aiken/crypto/bls12_381/g2
use aiken/crypto/bls12_381/scalar
use aiken/math
use aiken/primitive/bytearray

// Proof is a type that wraps all necessary elements needed for a proof.
// Note that the G1 elements are compressed as byte arrays.
// The field elements are represented as integers and must be checked to be in the field.
pub type Proof {
  commitmentA: ByteArray,
  commitmentB: ByteArray,
  commitmentC: ByteArray,
  commitmentZ: ByteArray,
  tLow: ByteArray,
  tMid: ByteArray,
  tHigh: ByteArray,
  wOmega: ByteArray,
  wOmegaZeta: ByteArray,
  aEval: Int,
  bEval: Int,
  cEval: Int,
  sSig1P: Int,
  sSig2P: Int,
  zOmega: Int,
}

// PreInputs are the minimal values that parametrize a plonk verifier.
// These values are known before proof generation.
pub type PreInputs {
  nPublic: Int,
  power: Int,
  k1: scalar.Scalar,
  k2: scalar.Scalar,
  qM: ByteArray,
  qL: ByteArray,
  qR: ByteArray,
  qO: ByteArray,
  qC: ByteArray,
  sSig1: ByteArray,
  sSig2: ByteArray,
  sSig3: ByteArray,
  x2: ByteArray,
  generator: scalar.Scalar,
}

// PreInputsFast are the optimized minimal values that parametrize a plonk verifier.
// These values are known before proof generation.
pub type PreInputsFast {
  n: Int,
  power: Int,
  k1: scalar.Scalar,
  k2: scalar.Scalar,
  qM: ByteArray,
  qL: ByteArray,
  qR: ByteArray,
  qO: ByteArray,
  qC: ByteArray,
  sSig1: ByteArray,
  sSig2: ByteArray,
  sSig3: ByteArray,
  x2: ByteArray,
  generators: List<scalar.Scalar>,
}

// ProofFast is a proof with precomputed lagrange inverses to save on-chain work.
pub type ProofFast {
  commitmentA: ByteArray,
  commitmentB: ByteArray,
  commitmentC: ByteArray,
  commitmentZ: ByteArray,
  tLow: ByteArray,
  tMid: ByteArray,
  tHigh: ByteArray,
  wOmega: ByteArray,
  wOmegaZeta: ByteArray,
  aEval: Int,
  bEval: Int,
  cEval: Int,
  sSig1P: Int,
  sSig2P: Int,
  zOmega: Int,
  lagrangeInverses: List<Int>,
}

// The prime order of the generator in the field. So, g^order = id.
pub const bls12_381_scalar_prime = scalar.field_prime

// The prime of the base field. So for a g on the curve, its x and y coordinates are elements of the base field.
pub const bls12_381_base_prime =
  4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787

fn concat_all(chunks: List<ByteArray>) -> ByteArray {
  list.foldl(chunks, #"", fn(chunk, acc) { bytearray.concat(acc, chunk) })
}

fn int_to_bytes32(value: Int) -> ByteArray {
  bytearray.from_int_big_endian(value, 32)
}

fn scalar_to_bytes32(value: scalar.Scalar) -> ByteArray {
  scalar.to_bytearray_big_endian(value, 32)
}

fn scalar_from_input(value: Int) -> scalar.Scalar {
  expect Some(s) = scalar.new(value)
  s
}

fn scalar_from_hash(bytes: ByteArray) -> scalar.Scalar {
  let reduced = bytearray.to_int_big_endian(bytes) % scalar.field_prime
  expect Some(s) = scalar.new(reduced)
  s
}

fn s_add(left: scalar.Scalar, right: scalar.Scalar) -> scalar.Scalar {
  scalar.add(left, right)
}

fn s_sub(left: scalar.Scalar, right: scalar.Scalar) -> scalar.Scalar {
  scalar.sub(left, right)
}

fn s_mul(left: scalar.Scalar, right: scalar.Scalar) -> scalar.Scalar {
  scalar.mul(left, right)
}

fn s_neg(value: scalar.Scalar) -> scalar.Scalar {
  scalar.neg(value)
}

fn s_pow(base: scalar.Scalar, exp: Int) -> scalar.Scalar {
  scalar.scale(base, exp)
}

fn s_pow2(base: scalar.Scalar, exp: Int) -> scalar.Scalar {
  scalar.scale2(base, exp)
}

fn s_sum(values: List<scalar.Scalar>) -> scalar.Scalar {
  list.foldl(values, scalar.zero, fn(value, acc) { s_add(acc, value) })
}

fn g1_add(left: G1Element, right: G1Element) -> G1Element {
  bls12_381_g1_add(left, right)
}

fn g1_sub(left: G1Element, right: G1Element) -> G1Element {
  bls12_381_g1_add(left, bls12_381_g1_neg(right))
}

fn g1_scale(point: G1Element, factor: scalar.Scalar) -> G1Element {
  bls12_381_g1_scalar_mul(scalar.to_int(factor), point)
}

pub fn convertToFastPreInputs(pre_inputs: PreInputs) -> PreInputsFast {
  let n = math.pow2(pre_inputs.power)
  let generators =
    list.map(list.range(0, pre_inputs.nPublic), fn(i) {
      s_pow(pre_inputs.generator, i)
    })

  PreInputsFast {
    n,
    power: pre_inputs.power,
    k1: pre_inputs.k1,
    k2: pre_inputs.k2,
    qM: pre_inputs.qM,
    qL: pre_inputs.qL,
    qR: pre_inputs.qR,
    qO: pre_inputs.qO,
    qC: pre_inputs.qC,
    sSig1: pre_inputs.sSig1,
    sSig2: pre_inputs.sSig2,
    sSig3: pre_inputs.sSig3,
    x2: pre_inputs.x2,
    generators,
  }
}

pub fn convertToFastProof(
  pre_inputs_fast: PreInputsFast,
  pub_inputs: List<Int>,
  proof: Proof,
) -> ProofFast {
  let pub_inputs_bytes = list.map(pub_inputs, fn(value) { int_to_bytes32(value) })
  let beta =
    crypto.blake2b_224(
      concat_all(
        list.concat(
          list.concat(
            [
              pre_inputs_fast.qM,
              pre_inputs_fast.qL,
              pre_inputs_fast.qR,
              pre_inputs_fast.qO,
              pre_inputs_fast.qC,
              pre_inputs_fast.sSig1,
              pre_inputs_fast.sSig2,
              pre_inputs_fast.sSig3,
            ],
            pub_inputs_bytes,
          ),
          [proof.commitmentA, proof.commitmentB, proof.commitmentC],
        ),
      ),
    )
      |> scalar_from_hash

  let gamma =
    crypto.blake2b_224(scalar_to_bytes32(beta))
      |> scalar_from_hash

  let alpha =
    crypto.blake2b_224(
      concat_all(
        [scalar_to_bytes32(beta), scalar_to_bytes32(gamma), proof.commitmentZ],
      ),
    )
      |> scalar_from_hash

  let zeta =
    crypto.blake2b_224(
      concat_all([scalar_to_bytes32(alpha), proof.tLow, proof.tMid, proof.tHigh]),
    )
      |> scalar_from_hash

  let n_scalar = scalar_from_input(pre_inputs_fast.n)
  let lagrange_inverses =
    list.map(pre_inputs_fast.generators, fn(gen_i) {
      let denom = s_mul(n_scalar, s_sub(zeta, gen_i))
      expect Some(inv) = scalar.recip(denom)
      scalar.to_int(inv)
    })

  ProofFast {
    commitmentA: proof.commitmentA,
    commitmentB: proof.commitmentB,
    commitmentC: proof.commitmentC,
    commitmentZ: proof.commitmentZ,
    tLow: proof.tLow,
    tMid: proof.tMid,
    tHigh: proof.tHigh,
    wOmega: proof.wOmega,
    wOmegaZeta: proof.wOmegaZeta,
    aEval: proof.aEval,
    bEval: proof.bEval,
    cEval: proof.cEval,
    sSig1P: proof.sSig1P,
    sSig2P: proof.sSig2P,
    zOmega: proof.zOmega,
    lagrangeInverses: lagrange_inverses,
  }
}

pub fn verifyPlonkSnarkjs(
  pre_inputs: PreInputs,
  pub_inputs: List<Int>,
  proof: Proof,
) -> Bool {
  let qM = bls12_381_g1_uncompress(pre_inputs.qM)
  let qL = bls12_381_g1_uncompress(pre_inputs.qL)
  let qR = bls12_381_g1_uncompress(pre_inputs.qR)
  let qO = bls12_381_g1_uncompress(pre_inputs.qO)
  let qC = bls12_381_g1_uncompress(pre_inputs.qC)
  let sSig1 = bls12_381_g1_uncompress(pre_inputs.sSig1)
  let sSig2 = bls12_381_g1_uncompress(pre_inputs.sSig2)
  let sSig3 = bls12_381_g1_uncompress(pre_inputs.sSig3)
  let x2 = bls12_381_g2_uncompress(pre_inputs.x2)

  let commA = bls12_381_g1_uncompress(proof.commitmentA)
  let commB = bls12_381_g1_uncompress(proof.commitmentB)
  let commC = bls12_381_g1_uncompress(proof.commitmentC)
  let commZ = bls12_381_g1_uncompress(proof.commitmentZ)
  let commTLow = bls12_381_g1_uncompress(proof.tLow)
  let commTMid = bls12_381_g1_uncompress(proof.tMid)
  let commTHigh = bls12_381_g1_uncompress(proof.tHigh)
  let commWOmega = bls12_381_g1_uncompress(proof.wOmega)
  let commWOmegaZeta = bls12_381_g1_uncompress(proof.wOmegaZeta)

  let evalA = scalar_from_input(proof.aEval)
  let evalB = scalar_from_input(proof.bEval)
  let evalC = scalar_from_input(proof.cEval)
  let evalS1 = scalar_from_input(proof.sSig1P)
  let evalS2 = scalar_from_input(proof.sSig2P)
  let evalZOmega = scalar_from_input(proof.zOmega)

  let neg_pub_inputs =
    list.map(pub_inputs, fn(value) { s_neg(scalar_from_input(value)) })
  expect [w1, ..wxs] = neg_pub_inputs

  let g1_generator = g1.generator
  let g2_generator = g2.generator

  let n = math.pow2(pre_inputs.power)
  let pub_inputs_bytes = list.map(pub_inputs, fn(value) { int_to_bytes32(value) })
  let beta =
    crypto.blake2b_224(
      concat_all(
        list.concat(
          list.concat(
            [
              pre_inputs.qM,
              pre_inputs.qL,
              pre_inputs.qR,
              pre_inputs.qO,
              pre_inputs.qC,
              pre_inputs.sSig1,
              pre_inputs.sSig2,
              pre_inputs.sSig3,
            ],
            pub_inputs_bytes,
          ),
          [proof.commitmentA, proof.commitmentB, proof.commitmentC],
        ),
      ),
    )
      |> scalar_from_hash

  let gamma =
    crypto.blake2b_224(scalar_to_bytes32(beta))
      |> scalar_from_hash

  let alpha =
    crypto.blake2b_224(
      concat_all(
        [scalar_to_bytes32(beta), scalar_to_bytes32(gamma), proof.commitmentZ],
      ),
    )
      |> scalar_from_hash

  let zeta =
    crypto.blake2b_224(
      concat_all([scalar_to_bytes32(alpha), proof.tLow, proof.tMid, proof.tHigh]),
    )
      |> scalar_from_hash

  let v =
    crypto.blake2b_224(
      concat_all(
        [
          scalar_to_bytes32(zeta),
          int_to_bytes32(proof.aEval),
          int_to_bytes32(proof.bEval),
          int_to_bytes32(proof.cEval),
          int_to_bytes32(proof.sSig1P),
          int_to_bytes32(proof.sSig2P),
          int_to_bytes32(proof.zOmega),
        ],
      ),
    )
      |> scalar_from_hash

  let u =
    crypto.blake2b_224(concat_all([proof.wOmega, proof.wOmegaZeta]))
      |> scalar_from_hash

  // Z_H(zeta) = zeta^n - 1
  let zero_poly = s_sub(s_pow(zeta, n), scalar.one)

  // L_1(zeta) and higher-order L_i.
  let n_scalar = scalar_from_input(n)
  let generators =
    list.map(list.range(0, pre_inputs.nPublic), fn(i) {
      s_pow(pre_inputs.generator, i)
    })
  let lagranges =
    list.map(generators, fn(gen_i) {
      let denom = s_mul(n_scalar, s_sub(zeta, gen_i))
      expect Some(inv) = scalar.recip(denom)
      s_mul(s_mul(gen_i, zero_poly), inv)
    })
  expect [lagrange1, ..lagrange_xs] = lagranges

  // PI(zeta)
  let pi_zeta =
    s_add(s_mul(w1, lagrange1), s_sum(list.map2(wxs, lagrange_xs, s_mul)))

  let alpha_square = s_mul(alpha, alpha)
  let evalA_s1 = s_add(evalA, s_add(s_mul(beta, evalS1), gamma))
  let evalB_s2 = s_add(evalB, s_add(s_mul(beta, evalS2), gamma))
  let evalC_gamma = s_add(evalC, gamma)
  let term1 = s_mul(lagrange1, alpha_square)
  let term2 =
    s_mul(
      s_mul(s_mul(s_mul(alpha, evalA_s1), evalB_s2), evalC_gamma),
      evalZOmega,
    )
  let r0 = s_sub(pi_zeta, s_add(term1, term2))

  let evalA_beta_zeta_gamma = s_add(evalA, s_add(s_mul(beta, zeta), gamma))
  let evalB_beta_k1_zeta_gamma =
    s_add(evalB, s_add(s_mul(beta, s_mul(pre_inputs.k1, zeta)), gamma))
  let evalC_beta_k2_zeta_gamma =
    s_add(evalC, s_add(s_mul(beta, s_mul(pre_inputs.k2, zeta)), gamma))
  let commZ_scalar =
    s_add(
      s_add(
        s_mul(
          s_mul(
            s_mul(evalA_beta_zeta_gamma, evalB_beta_k1_zeta_gamma),
            evalC_beta_k2_zeta_gamma,
          ),
          alpha,
        ),
        term1,
      ),
      u,
    )

  let evalA_beta_s1_gamma = s_add(evalA, s_add(s_mul(beta, evalS1), gamma))
  let evalB_beta_s2_gamma = s_add(evalB, s_add(s_mul(beta, evalS2), gamma))
  let sSig3_scalar =
    s_mul(
      s_mul(evalA_beta_s1_gamma, evalB_beta_s2_gamma),
      s_mul(alpha, s_mul(beta, evalZOmega)),
    )

  let pow_zeta_n = s_pow(zeta, n)
  let pow_zeta_2n = s_pow(zeta, 2 * n)
  let t_poly =
    g1_add(
      commTLow,
      g1_add(g1_scale(commTMid, pow_zeta_n), g1_scale(commTHigh, pow_zeta_2n)),
    )

  let batch_poly_commit_g1 =
    g1_sub(
      g1_sub(
        g1_add(
          g1_add(
            g1_add(
              g1_add(
                g1_add(g1_scale(qM, s_mul(evalA, evalB)), g1_scale(qL, evalA)),
                g1_scale(qR, evalB),
              ),
              g1_scale(qO, evalC),
            ),
            qC,
          ),
          g1_scale(commZ, commZ_scalar),
        ),
        g1_scale(sSig3, sSig3_scalar),
      ),
      g1_scale(t_poly, zero_poly),
    )

  let inner =
    g1_add(sSig1, g1_scale(sSig2, v))
      |> fn(x) { g1_add(commC, g1_scale(x, v)) }
      |> fn(x) { g1_add(commB, g1_scale(x, v)) }
      |> fn(x) { g1_add(commA, g1_scale(x, v)) }
  let batch_poly_commit_full =
    g1_add(batch_poly_commit_g1, g1_scale(inner, v))

  let evals =
    s_add(
      evalA,
      s_mul(
        v,
        s_add(
          evalB,
          s_mul(
            v,
            s_add(evalC, s_mul(v, s_add(evalS1, s_mul(v, evalS2)))),
          ),
        ),
      ),
    )
  let group_encoded_batch_eval =
    g1_scale(
      g1_generator,
      s_add(s_add(s_neg(r0), s_mul(v, evals)), s_mul(u, evalZOmega)),
    )

  let lhs =
    bls12_381_miller_loop(
      g1_add(commWOmega, g1_scale(commWOmegaZeta, u)),
      x2,
    )
  let rhs_g1 =
    g1_sub(
      g1_add(
        g1_add(
          g1_scale(commWOmega, zeta),
          g1_scale(commWOmegaZeta, s_mul(s_mul(u, zeta), pre_inputs.generator)),
        ),
        batch_poly_commit_full,
      ),
      group_encoded_batch_eval,
    )
  let rhs = bls12_381_miller_loop(rhs_g1, g2_generator)

  bls12_381_final_verify(lhs, rhs)
}

pub fn verifyPlonkFastSnarkjs(
  pre_inputs_fast: PreInputsFast,
  pub_inputs: List<Int>,
  proof: ProofFast,
) -> Bool {
  let qM = bls12_381_g1_uncompress(pre_inputs_fast.qM)
  let qL = bls12_381_g1_uncompress(pre_inputs_fast.qL)
  let qR = bls12_381_g1_uncompress(pre_inputs_fast.qR)
  let qO = bls12_381_g1_uncompress(pre_inputs_fast.qO)
  let qC = bls12_381_g1_uncompress(pre_inputs_fast.qC)
  let sSig1 = bls12_381_g1_uncompress(pre_inputs_fast.sSig1)
  let sSig2 = bls12_381_g1_uncompress(pre_inputs_fast.sSig2)
  let sSig3 = bls12_381_g1_uncompress(pre_inputs_fast.sSig3)
  let x2 = bls12_381_g2_uncompress(pre_inputs_fast.x2)

  let commA = bls12_381_g1_uncompress(proof.commitmentA)
  let commB = bls12_381_g1_uncompress(proof.commitmentB)
  let commC = bls12_381_g1_uncompress(proof.commitmentC)
  let commZ = bls12_381_g1_uncompress(proof.commitmentZ)
  let commTLow = bls12_381_g1_uncompress(proof.tLow)
  let commTMid = bls12_381_g1_uncompress(proof.tMid)
  let commTHigh = bls12_381_g1_uncompress(proof.tHigh)
  let commWOmega = bls12_381_g1_uncompress(proof.wOmega)
  let commWOmegaZeta = bls12_381_g1_uncompress(proof.wOmegaZeta)

  let evalA = scalar_from_input(proof.aEval)
  let evalB = scalar_from_input(proof.bEval)
  let evalC = scalar_from_input(proof.cEval)
  let evalS1 = scalar_from_input(proof.sSig1P)
  let evalS2 = scalar_from_input(proof.sSig2P)
  let evalZOmega = scalar_from_input(proof.zOmega)

  let neg_pub_inputs =
    list.map(pub_inputs, fn(value) { s_neg(scalar_from_input(value)) })
  expect [w1, ..wxs] = neg_pub_inputs

  let lags_inv = list.map(proof.lagrangeInverses, scalar_from_input)
  let g1_generator = g1.generator
  let g2_generator = g2.generator

  let pub_inputs_bytes = list.map(pub_inputs, fn(value) { int_to_bytes32(value) })
  let beta =
    crypto.blake2b_224(
      concat_all(
        list.concat(
          list.concat(
            [
              pre_inputs_fast.qM,
              pre_inputs_fast.qL,
              pre_inputs_fast.qR,
              pre_inputs_fast.qO,
              pre_inputs_fast.qC,
              pre_inputs_fast.sSig1,
              pre_inputs_fast.sSig2,
              pre_inputs_fast.sSig3,
            ],
            pub_inputs_bytes,
          ),
          [proof.commitmentA, proof.commitmentB, proof.commitmentC],
        ),
      ),
    )
      |> scalar_from_hash

  let gamma =
    crypto.blake2b_224(scalar_to_bytes32(beta))
      |> scalar_from_hash

  let alpha =
    crypto.blake2b_224(
      concat_all(
        [scalar_to_bytes32(beta), scalar_to_bytes32(gamma), proof.commitmentZ],
      ),
    )
      |> scalar_from_hash

  let zeta =
    crypto.blake2b_224(
      concat_all([scalar_to_bytes32(alpha), proof.tLow, proof.tMid, proof.tHigh]),
    )
      |> scalar_from_hash

  let v =
    crypto.blake2b_224(
      concat_all(
        [
          scalar_to_bytes32(zeta),
          int_to_bytes32(proof.aEval),
          int_to_bytes32(proof.bEval),
          int_to_bytes32(proof.cEval),
          int_to_bytes32(proof.sSig1P),
          int_to_bytes32(proof.sSig2P),
          int_to_bytes32(proof.zOmega),
        ],
      ),
    )
      |> scalar_from_hash

  let u =
    crypto.blake2b_224(concat_all([proof.wOmega, proof.wOmegaZeta]))
      |> scalar_from_hash

  let pow_zeta_2p = s_pow2(zeta, pre_inputs_fast.power)
  let pow_zeta_2p_min_one = s_sub(pow_zeta_2p, scalar.one)
  let lagranges =
    list.map2(
      pre_inputs_fast.generators,
      lags_inv,
      fn(gen_i, inv_i) { s_mul(s_mul(gen_i, pow_zeta_2p_min_one), inv_i) },
    )
  expect [lagrange1, ..lagrange_xs] = lagranges

  let pi_zeta =
    s_add(s_mul(w1, lagrange1), s_sum(list.map2(wxs, lagrange_xs, s_mul)))

  let alpha_square = s_mul(alpha, alpha)
  let alpha_eval_zomega = s_mul(alpha, evalZOmega)
  let beta_zeta = s_mul(beta, zeta)
  let evalA_plus_gamma = s_add(evalA, gamma)
  let evalB_plus_gamma = s_add(evalB, gamma)
  let evalC_plus_gamma = s_add(evalC, gamma)
  let beta_eval_s1 = s_mul(beta, evalS1)
  let beta_eval_s2 = s_mul(beta, evalS2)
  let r0 =
    s_sub(
      pi_zeta,
      s_add(
        s_mul(lagrange1, alpha_square),
        s_mul(
          s_mul(
            s_mul(alpha_eval_zomega, s_add(evalA_plus_gamma, beta_eval_s1)),
            s_add(evalB_plus_gamma, beta_eval_s2),
          ),
          evalC_plus_gamma,
        ),
      ),
    )

  let evalA_beta_zeta = s_add(evalA_plus_gamma, beta_zeta)
  let evalB_beta_zeta = s_add(evalB_plus_gamma, s_mul(beta_zeta, pre_inputs_fast.k1))
  let evalC_beta_zeta = s_add(evalC_plus_gamma, s_mul(beta_zeta, pre_inputs_fast.k2))
  let commZ_scalar =
    s_add(
      s_add(
        s_mul(
          s_mul(s_mul(evalA_beta_zeta, evalB_beta_zeta), evalC_beta_zeta),
          alpha,
        ),
        s_mul(lagrange1, alpha_square),
      ),
      u,
    )

  let sSig3_scalar =
    s_mul(
      s_mul(
        s_add(evalA_plus_gamma, beta_eval_s1),
        s_add(evalB_plus_gamma, beta_eval_s2),
      ),
      s_mul(alpha_eval_zomega, beta),
    )

  let pow_zeta_2p_squared = s_pow2(pow_zeta_2p, 1)
  let t_poly =
    g1_add(
      commTLow,
      g1_add(
        g1_scale(commTMid, pow_zeta_2p),
        g1_scale(commTHigh, pow_zeta_2p_squared),
      ),
    )

  let batch_poly_commit_g1 =
    g1_sub(
      g1_sub(
        g1_add(
          g1_add(
            g1_add(
              g1_add(
                g1_add(g1_scale(qM, s_mul(evalA, evalB)), g1_scale(qL, evalA)),
                g1_scale(qR, evalB),
              ),
              g1_scale(qO, evalC),
            ),
            qC,
          ),
          g1_scale(commZ, commZ_scalar),
        ),
        g1_scale(sSig3, sSig3_scalar),
      ),
      g1_scale(t_poly, pow_zeta_2p_min_one),
    )

  let inner =
    g1_add(sSig1, g1_scale(sSig2, v))
      |> fn(x) { g1_add(commC, g1_scale(x, v)) }
      |> fn(x) { g1_add(commB, g1_scale(x, v)) }
      |> fn(x) { g1_add(commA, g1_scale(x, v)) }
  let batch_poly_commit_full =
    g1_add(batch_poly_commit_g1, g1_scale(inner, v))

  let evals =
    s_add(
      evalA,
      s_mul(
        v,
        s_add(
          evalB,
          s_mul(
            v,
            s_add(evalC, s_mul(v, s_add(evalS1, s_mul(v, evalS2)))),
          ),
        ),
      ),
    )
  let group_encoded_batch_eval =
    g1_scale(
      g1_generator,
      s_add(s_add(s_neg(r0), s_mul(v, evals)), s_mul(u, evalZOmega)),
    )

  expect [_, gen1, .._] = pre_inputs_fast.generators
  let lhs =
    bls12_381_miller_loop(
      g1_add(commWOmega, g1_scale(commWOmegaZeta, u)),
      x2,
    )
  let rhs_g1 =
    g1_sub(
      g1_add(
        g1_add(
          g1_scale(commWOmega, zeta),
          g1_scale(commWOmegaZeta, s_mul(s_mul(u, zeta), gen1)),
        ),
        batch_poly_commit_full,
      ),
      group_encoded_batch_eval,
    )
  let rhs = bls12_381_miller_loop(rhs_g1, g2_generator)

  let n_scalar = scalar_from_input(pre_inputs_fast.n)
  let lags_ok =
    list.all(
      list.map2(lags_inv, pre_inputs_fast.generators, fn(inv_i, gen_i) {
        s_mul(s_mul(inv_i, n_scalar), s_sub(zeta, gen_i)) == scalar.one
      }),
      fn(x) { x },
    )

  bls12_381_final_verify(lhs, rhs) && lags_ok
}

fn example_pre_inputs() -> PreInputs {
  expect Some(k1) = scalar.new(2)
  expect Some(k2) = scalar.new(3)
  expect Some(generator) = scalar.new(
    21071158244812412064791010377580296085971058123779034548857891862303448703672,
  )

  PreInputs {
    nPublic: 2,
    power: 8,
    k1,
    k2,
    qM: #"89a6764312cef0ff651afad2da581333695a28db3ae2abbc18e7ccb5d50cdc1fd9c9096f38282b14d4a9c5d0904c2993",
    qL: #"98be2173a45a15c6a84fde90abd06b9b4ce4f93db354f7a54a7c8842810300bf273a442ac3e6090e440df9c45d799b13",
    qR: #"b2d382cdade15aa27faff93adfeb428953d4df062c4a15055be5c7b64afee80b29535d488890afb84dad1727f5815bee",
    qO: #"854a79bca15dc9f845d483fff3889cc4ca7a00a90660fb4aaca738f357bdabfe084967e0dfe1e0fd66a4d5d7b2d620fb",
    qC: #"c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    sSig1: #"8e470c78bd9b285477e87de3418c4c08fa25d6c1f134d15c417ef55f470274fa79939917dd1fee69605bb4f7dfafa4d2",
    sSig2: #"b2245ee73cc1104a2447172562ee592321ec15e6cfe1d094f1ef66cc31dc346306dd85b0d737a6921ce087e59923e544",
    sSig3: #"a72c1c722a5921919ddc2be8e6972d0b7c5ff64076500b75c549aa2a847e8cbe728b5f8244e660c4ba80dcbb0d93f46b",
    x2: #"b27815a4ca62c956a4cdee684958e42b45a20c9f538234be871e0d817c233cbc8344152fadbcabfcc34f46f81f7ed76b08ff6cd05f4535e3605782b57d141be5ff213f4372f6cdfde28ea33cdf1e91d1e2c679c18c55b8fddca8c1eb81e8a3b9",
    generator,
  }
}

fn example_proof() -> Proof {
  Proof {
    commitmentA: #"8298d4f6329a61d954cbd1b0e4503867777e55810cf0a353cfeb86adc0ec3e452b1047e2b895619d92c8458b5387e356",
    commitmentB: #"a96ae61226d3e8df66902e2792ac576219b540061bd89a2d5921f4ef507920bff41848aa6c71d9a404622485d78bc615",
    commitmentC: #"ab484a616de907b3c099d4fe602887427cbbfcfbd8486a340719d7ab915dae387da19f3801016f1b2fb93b5736dd50c9",
    commitmentZ: #"9810bfe38fbcb6b3a5a5a1896beda96cc7c52798bde71b0a6824117cb04b7a1a53cbaebd94dcccc0ae9db9d8e7905d61",
    tLow: #"86bdcf0f38a2670e5fe6488a22affb8ba488c77dcc49e1052c4be52a9396277f932904898f58aa63854605e789fc9e0d",
    tMid: #"8afe9f5a450b12760950acff40c27f6cdb08fac71dc4a92c5fb9ef21f88cacbbc039a2281a6842f2e57e72caa3a66da2",
    tHigh: #"aebd2f5ab258439b5bb090a857f9d1f998d0c737aab95fa361ffdd70156a8bac6bd4b0726780a407a6ee18bed6092393",
    wOmega: #"8ea8bf8bece2be28541ba2d42830f28ec55b62c8de80b03a85578037f497fbed2a686ab54e973cb87c7ee93c983ffc3a",
    wOmegaZeta: #"a916d57b24a502308f9f4bdb6cf11402685641352a71f0ba01daa1bd519294ab5fce4f6b9f503fd12aa89224a635b0d9",
    aEval:
      18376945509548979154234285967502303667654384864417109878730063780807771386804,
    bEval:
      48091350738882108076678452440283491448151427314124311219043220475171874763276,
    cEval:
      19995498867920222404318895039685100281891200599706204591987499224278246956716,
    sSig1P:
      22639172691520838707669313728412965432032750722138107727665998164239763135904,
    sSig2P:
      38226063540390035205748121923613940584145755981537302966237851066336751425207,
    zOmega:
      46342921279167233860927215620995843068292504644614777821809165775517811410811,
  }
}

fn example_public_inputs() -> List<Int> {
  [
    8301577178634781303874616783681599046073052196886694608055856488206182952326,
    5,
  ]
}

test verify_plonk_snarkjs_pass() {
  verifyPlonkSnarkjs(example_pre_inputs(), example_public_inputs(), example_proof())
}

test verify_plonk_snarkjs_fail() fail {
  let proof = example_proof()
  let bad_proof =
    Proof {
      commitmentA: proof.commitmentA,
      commitmentB: proof.commitmentB,
      commitmentC: proof.commitmentC,
      commitmentZ: proof.commitmentZ,
      tLow: proof.tLow,
      tMid: proof.tMid,
      tHigh: proof.tHigh,
      wOmega: proof.wOmega,
      wOmegaZeta: proof.wOmegaZeta,
      aEval: proof.aEval + 1,
      bEval: proof.bEval,
      cEval: proof.cEval,
      sSig1P: proof.sSig1P,
      sSig2P: proof.sSig2P,
      zOmega: proof.zOmega,
    }

  verifyPlonkSnarkjs(example_pre_inputs(), example_public_inputs(), bad_proof)
}

test verify_plonk_fast_snarkjs_pass() {
  let pre_inputs = example_pre_inputs()
  let pre_inputs_fast = convertToFastPreInputs(pre_inputs)
  let proof_fast =
    convertToFastProof(pre_inputs_fast, example_public_inputs(), example_proof())

  verifyPlonkFastSnarkjs(pre_inputs_fast, example_public_inputs(), proof_fast)
}

test verify_plonk_fast_snarkjs_fail() fail {
  let pre_inputs = example_pre_inputs()
  let pre_inputs_fast = convertToFastPreInputs(pre_inputs)
  let proof_fast =
    convertToFastProof(pre_inputs_fast, example_public_inputs(), example_proof())
  let bad_proof_fast =
    ProofFast {
      commitmentA: proof_fast.commitmentA,
      commitmentB: proof_fast.commitmentB,
      commitmentC: proof_fast.commitmentC,
      commitmentZ: proof_fast.commitmentZ,
      tLow: proof_fast.tLow,
      tMid: proof_fast.tMid,
      tHigh: proof_fast.tHigh,
      wOmega: proof_fast.wOmega,
      wOmegaZeta: proof_fast.wOmegaZeta,
      aEval: proof_fast.aEval + 1,
      bEval: proof_fast.bEval,
      cEval: proof_fast.cEval,
      sSig1P: proof_fast.sSig1P,
      sSig2P: proof_fast.sSig2P,
      zOmega: proof_fast.zOmega,
      lagrangeInverses: proof_fast.lagrangeInverses,
    }

  verifyPlonkFastSnarkjs(pre_inputs_fast, example_public_inputs(), bad_proof_fast)
}
