use aiken/builtin.{
  bls12_381_final_verify, bls12_381_g1_add, bls12_381_g1_scalar_mul,
  bls12_381_g1_uncompress, bls12_381_g2_uncompress, bls12_381_miller_loop,
  bls12_381_mul_miller_loop_result
}
use aiken/collection/list

pub type CompressedProof {
  a: ByteArray,
  b: ByteArray,
  c: ByteArray,
}

pub type CompressedVK {
  alpha: ByteArray,
  beta: ByteArray,
  gamma: ByteArray,
  delta: ByteArray,
  vkIC: List<ByteArray>,
}

pub type Proof {
  a: G1Element,
  b: G2Element,
  c: G1Element,
}

pub type VerifierKey {
  alpha: G1Element,
  beta: G2Element,
  gamma: G2Element,
  delta: G2Element,
  vkIC: List<G1Element>,
}

pub fn uncompress_proof(c: CompressedProof) -> Proof {
  Proof {
    a: bls12_381_g1_uncompress(c.a),
    b: bls12_381_g2_uncompress(c.b),
    c: bls12_381_g1_uncompress(c.c),
  }
}

pub fn uncompress_vk(c: CompressedVK) -> VerifierKey {
  VerifierKey {
    alpha: bls12_381_g1_uncompress(c.alpha),
    beta: bls12_381_g2_uncompress(c.beta),
    gamma: bls12_381_g2_uncompress(c.gamma),
    delta: bls12_381_g2_uncompress(c.delta),
    vkIC: list.map(c.vkIC, fn(c_ic) { bls12_381_g1_uncompress(c_ic)}),
  }
}

pub fn verify_compressed(
  vk: CompressedVK,
  proof: CompressedProof,
  inputs: List<Int>
){
  let vk = uncompress_vk(vk)
  let proof = uncompress_proof(proof)
  verify(vk, proof, inputs)
}

pub fn pairing_check(
  a: G1Element,
  b: G2Element,
  c: G1Element,
  delta: G2Element,
  alpha: G1Element,
  beta: G2Element,
  k: G1Element,
  gamma: G2Element
) -> Bool {
  // e(A,B) = e(α,β) ∙ e(C,δ) ∙ e(K,γ)
  // e: miller loop
  // ∙: mul miller loop
  // =: final verify

  // Pair Components w/ Miller Loop
  let ab = bls12_381_miller_loop(a, b)
  let alphabeta = bls12_381_miller_loop(alpha, beta)

  let kgamma = bls12_381_miller_loop(k, gamma)
  let cdelta = bls12_381_miller_loop(c, delta)

  // Combine Miller Loop Results
  let mlr1 = bls12_381_mul_miller_loop_result(alphabeta, kgamma)
  let mlr2 = bls12_381_mul_miller_loop_result(mlr1, cdelta)

  // Final Equality Check
  bls12_381_final_verify(ab, mlr2)
}

// Main verification function
pub fn verify(vk: VerifierKey, proof: Proof, inputs: List<Int>) -> Bool {

  let k = when vk.vkIC is {
    [] -> fail @"empty vkIC?"
    [head, ..tail] -> derive(tail, inputs, head)
  }

  // Pairing check
  pairing_check(
    proof.a,
    proof.b,
    proof.c,
    vk.delta,
    vk.alpha,
    vk.beta,
    k,
    vk.gamma
  )
}

pub fn derive(
  vk_ic: List<G1Element>,
  public: List<Int>,
  result: G1Element,
) -> G1Element {
  when vk_ic is {
    [] -> result
    [i, ..vk_ic] ->
      when public is {
        [] -> fail
        [scalar, ..public] ->
          derive(
            vk_ic,
            public,
            bls12_381_g1_add(
              result,
              bls12_381_g1_scalar_mul(scalar, i),
            ),
          )
      }
  }
}

test groth_verify_pass_1() {
  //  Template of VK
  let vk: CompressedVK =
    CompressedVK {
      alpha: #"8e3d9e248feda194cb6fa0a3b64fd2a380cb5e94836bf8148bf97ebcbb5819d9a78f63102f0293c104bcbb2f810d8eb4",
      beta: #"8cd68a7186a908212680a0234d8210c20328f8fb3ce1d69c9aec9330a5802d6cfaf6d7cf3176133221c19188590cb4141874ea7bbfcb9872931e115d882c46b90c3dcbcee10062d1c9b9b0a691d7bec7d2735f06495c7f71dea210e55b2782df",
      gamma: #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      delta: #"938231fcec443fbdeb1079ff126b8f69bd8579ffe82d39923214d4345395beee60200288fa20c97ae50f3212131b6f8802af2f9f515c65af6a9a6c294c738590104376a0af44731d6699db6a286608774243f7d1dddc4605eb340e65e15060a5",
      vkIC: [
        #"b5813c90d3455acb8608fdf66e8601f24ef048f3fdf9384862d77c72cb5cddfde2b307976b1b0319c42ba985f94be60a",
        #"a41a0e6370c054be0f9acce08e97f6d5702d9daa9e9a934e8a377f553593baa1c58062adc73d63558653422d54d6f50c",
        #"8e02a87c519c3145f984d25fdf769f74fbc36626c385d4554fb4bc1d7a12cbf669d40f257023b8b3c9a31e631aa8f981",
      ],
    }

  //  Template of Proof
  let pk: CompressedProof =
    CompressedProof {
      a: #"8b84d092731c653b1accdda79c51e3f5d289bed7311189d927deadef0470e437e6d1d400634726512a79a015867424e3",
      b: #"92cb1c125816e4b522c7f430a5d74a61116b6189de7b2341f040194c02f10d9ef0cf081f4029444a65ea74e69d98b1cf08d3864087d5d2dee2ed6ab102f9b78e65d341f0824341a9fc25d0ea9dacccc5d355b4eddb0057949370a19c47135b0e",
      c: #"a4ef633c858a3ff194db50eacdf715f7296fb3d1202c54b543284e9656b69aa90f33ac0e2572d3ab847b88268dcd1f7e",
    }
  // Template of public values
  let public_values: List<Int> =
    [561, 3]

  verify_compressed(vk, pk, public_values)
}

test groth_verify_fail_1() fail {
  //  Template of VK
  let vk: CompressedVK =
    CompressedVK {
      alpha: #"8e3d9e248feda194cb6fa0a3b64fd2a380cb5e94836bf8148bf97ebcbb5819d9a78f63102f0293c104bcbb2f810d8eb4",
      beta: #"8cd68a7186a908212680a0234d8210c20328f8fb3ce1d69c9aec9330a5802d6cfaf6d7cf3176133221c19188590cb4141874ea7bbfcb9872931e115d882c46b90c3dcbcee10062d1c9b9b0a691d7bec7d2735f06495c7f71dea210e55b2782df",
      gamma: #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      delta: #"938231fcec443fbdeb1079ff126b8f69bd8579ffe82d39923214d4345395beee60200288fa20c97ae50f3212131b6f8802af2f9f515c65af6a9a6c294c738590104376a0af44731d6699db6a286608774243f7d1dddc4605eb340e65e15060a5",
      vkIC: [
        #"b5813c90d3455acb8608fdf66e8601f24ef048f3fdf9384862d77c72cb5cddfde2b307976b1b0319c42ba985f94be60a",
        #"a41a0e6370c054be0f9acce08e97f6d5702d9daa9e9a934e8a377f553593baa1c58062adc73d63558653422d54d6f50c",
        #"8e02a87c519c3145f984d25fdf769f74fbc36626c385d4554fb4bc1d7a12cbf669d40f257023b8b3c9a31e631aa8f981",
      ],
    }

  //  Template of Proof
  let pk: CompressedProof =
    CompressedProof {
      a: #"a4ef633c858a3ff194db50eacdf715f7296fb3d1202c54b543284e9656b69aa90f33ac0e2572d3ab847b88268dcd1f7e",
      b: #"92cb1c125816e4b522c7f430a5d74a61116b6189de7b2341f040194c02f10d9ef0cf081f4029444a65ea74e69d98b1cf08d3864087d5d2dee2ed6ab102f9b78e65d341f0824341a9fc25d0ea9dacccc5d355b4eddb0057949370a19c47135b0e",
      c: #"8b84d092731c653b1accdda79c51e3f5d289bed7311189d927deadef0470e437e6d1d400634726512a79a015867424e3",
    }
  // Template of public values
  let public_values: List<Int> =
    [561, 3]

  verify_compressed(vk, pk, public_values)
}

test groth_verify_pass_2() {
  //  Template of VK
  let vk: CompressedVK =
    CompressedVK {
      alpha: #"8e3d9e248feda194cb6fa0a3b64fd2a380cb5e94836bf8148bf97ebcbb5819d9a78f63102f0293c104bcbb2f810d8eb4",
      beta: #"8cd68a7186a908212680a0234d8210c20328f8fb3ce1d69c9aec9330a5802d6cfaf6d7cf3176133221c19188590cb4141874ea7bbfcb9872931e115d882c46b90c3dcbcee10062d1c9b9b0a691d7bec7d2735f06495c7f71dea210e55b2782df",
      gamma: #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      delta: #"938231fcec443fbdeb1079ff126b8f69bd8579ffe82d39923214d4345395beee60200288fa20c97ae50f3212131b6f8802af2f9f515c65af6a9a6c294c738590104376a0af44731d6699db6a286608774243f7d1dddc4605eb340e65e15060a5",
      vkIC: [
        #"b5813c90d3455acb8608fdf66e8601f24ef048f3fdf9384862d77c72cb5cddfde2b307976b1b0319c42ba985f94be60a",
        #"a41a0e6370c054be0f9acce08e97f6d5702d9daa9e9a934e8a377f553593baa1c58062adc73d63558653422d54d6f50c",
        #"8e02a87c519c3145f984d25fdf769f74fbc36626c385d4554fb4bc1d7a12cbf669d40f257023b8b3c9a31e631aa8f981",
      ],
    }

  //  Template of Proof
  let pk: CompressedProof =
    CompressedProof {
      a: #"98ca847cc04a6f67ac85a628521450323d7aa5335d4c2c48e9780b659cf7ea8ece2d0b305c9ff9dcfb3e548d61bbaebe",
      b: #"a8e6ba4dbce6aa84de8ca1cd39d42353fcac89fe8cb800e728ada3ca4ae3b07baa68f76b9e4fa73eebf78cc609fa85d6166a3b69cd08cc59f2ff36e52dfdf231540a4212fdd4a142504c76066bddea342dd0183b2b11ed62cfc1497189a4db52",
      c: #"8bc8cc3f11483138cc55d5f0389e67231f9e8465e5cb4a5a668e6e298d5c4febb2a18e86881c84dd03c5d33db65af272",
    }
  // Template of public values
  let public_values: List<Int> =
    [8827, 7]

  verify_compressed(vk, pk, public_values)
}