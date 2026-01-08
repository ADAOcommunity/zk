use aiken/collection/list
use aiken/crypto
use aiken/crypto/bls12_381/g1
use aiken/crypto/bls12_381/scalar
use aiken/primitive/bytearray

pub type BulletproofVerificationKey {
  n: Int,
  g: ByteArray,
  h: ByteArray,
  u: ByteArray,
  g_vec: List<ByteArray>,
  h_vec: List<ByteArray>,
}

pub type BulletproofProof {
  a: ByteArray,
  s: ByteArray,
  t1: ByteArray,
  t2: ByteArray,
  tau_x: Int,
  mu: Int,
  t_hat: Int,
  l_vec: List<ByteArray>,
  r_vec: List<ByteArray>,
  a_eval: Int,
  b_eval: Int,
}

pub fn verify(
  vk: BulletproofVerificationKey,
  commitment: ByteArray,
  proof: BulletproofProof,
) -> Bool {
  if !is_power_of_two(vk.n) {
    False
  } else if list.length(vk.g_vec) != vk.n || list.length(vk.h_vec) != vk.n {
    False
  } else {
    let rounds = log2_unchecked(vk.n)
    if list.length(proof.l_vec) != rounds || list.length(proof.r_vec) != rounds {
      False
    } else {
      when (
        scalar.new(proof.tau_x),
        scalar.new(proof.mu),
        scalar.new(proof.t_hat),
        scalar.new(proof.a_eval),
        scalar.new(proof.b_eval),
      ) is {
        (
          Some(tau_x),
          Some(mu),
          Some(t_hat),
          Some(a_eval),
          Some(b_eval),
        ) ->
          verify_with_scalars(
            vk,
            commitment,
            proof,
            tau_x,
            mu,
            t_hat,
            a_eval,
            b_eval,
          )
        _ -> False
      }
    }
  }
}

fn verify_with_scalars(
  vk: BulletproofVerificationKey,
  commitment: ByteArray,
  proof: BulletproofProof,
  tau_x: scalar.Scalar,
  mu: scalar.Scalar,
  t_hat: scalar.Scalar,
  a_eval: scalar.Scalar,
  b_eval: scalar.Scalar,
) -> Bool {
  let g = g1.decompress(vk.g)
  let h = g1.decompress(vk.h)
  let u = g1.decompress(vk.u)
  let g_vec = decompress_points(vk.g_vec)
  let h_vec = decompress_points(vk.h_vec)
  let v = g1.decompress(commitment)
  let a = g1.decompress(proof.a)
  let s = g1.decompress(proof.s)
  let t1 = g1.decompress(proof.t1)
  let t2 = g1.decompress(proof.t2)

  let y = hash_to_scalar([commitment, proof.a, proof.s])
  let z = hash_to_scalar([scalar_to_bytes32(y)])
  let x = hash_to_scalar([scalar_to_bytes32(z), proof.t1, proof.t2])

  when scalar.recip(y) is {
    None -> False
    Some(y_inv) -> {
      let y_pows = build_pows(y, vk.n)
      let y_inv_pows = build_pows(y_inv, vk.n)
      let two = scalar_from_int(2)
      let pow2 = build_pows(two, vk.n)

      let z2 = scalar.mul(z, z)
      let z3 = scalar.mul(z2, z)
      let x2 = scalar.mul(x, x)

      let sum_y = scalar_sum(y_pows)
      let sum_pow2 = scalar_sum(pow2)
      let delta =
        scalar.sub(
          scalar.mul(scalar.sub(z, z2), sum_y),
          scalar.mul(z3, sum_pow2),
        )

      let lhs = g1.add(g1.scale(g, t_hat), g1.scale(h, tau_x))
      let rhs =
        g1.add(
          g1.add(
            g1.add(g1.scale(v, z2), g1.scale(g, delta)),
            g1.scale(t1, x),
          ),
          g1.scale(t2, x2),
        )

      if !g1.equal(lhs, rhs) {
        False
      } else {
        let h_prime =
          list.map2(h_vec, y_inv_pows, fn(h_i, y_inv_i) {
            g1.scale(h_i, y_inv_i)
          })

        let neg_z = scalar.neg(z)
        let g_z = list.map(g_vec, fn(g_i) { g1.scale(g_i, neg_z) })
        let z_y = list.map(y_pows, fn(y_i) { scalar.mul(z, y_i) })
        let z2_pow2 = list.map(pow2, fn(p2) { scalar.mul(z2, p2) })
        let h_coeff = list.map2(z_y, z2_pow2, scalar.add)
        let h_z =
          list.map2(h_prime, h_coeff, fn(h_i, coeff) {
            g1.scale(h_i, coeff)
          })

        let p0 = g1.add(a, g1.scale(s, x))
        let p1 = g1.add(p0, sum_points(g_z))
        let p2 = g1.add(p1, sum_points(h_z))
        let p3 = g1.add(p2, g1.scale(u, t_hat))
        let p = g1.add(p3, g1.scale(h, scalar.neg(mu)))

        verify_inner_product(
          g_vec,
          h_prime,
          u,
          p,
          proof.l_vec,
          proof.r_vec,
          a_eval,
          b_eval,
        )
      }
    }
  }
}

fn verify_inner_product(
  g_vec: List<G1Element>,
  h_vec: List<G1Element>,
  u: G1Element,
  p: G1Element,
  l_bytes: List<ByteArray>,
  r_bytes: List<ByteArray>,
  a_eval: scalar.Scalar,
  b_eval: scalar.Scalar,
) -> Bool {
  let l_points = decompress_points(l_bytes)
  let r_points = decompress_points(r_bytes)

  when fold_inner_rounds(g_vec, h_vec, p, l_points, r_points, l_bytes, r_bytes) is {
    None -> False
    Some((g_final, h_final, p_final)) ->
      when (g_final, h_final) is {
        ([g0], [h0]) -> {
          let ab = scalar.mul(a_eval, b_eval)
          let rhs =
            g1.add(
              g1.scale(g0, a_eval),
              g1.add(g1.scale(h0, b_eval), g1.scale(u, ab)),
            )
          g1.equal(p_final, rhs)
        }
        _ -> False
      }
  }
}

fn fold_inner_rounds(
  g_vec: List<G1Element>,
  h_vec: List<G1Element>,
  p: G1Element,
  l_points: List<G1Element>,
  r_points: List<G1Element>,
  l_bytes: List<ByteArray>,
  r_bytes: List<ByteArray>,
) -> Option<(List<G1Element>, List<G1Element>, G1Element)> {
  when (l_points, r_points, l_bytes, r_bytes) is {
    ([], [], [], []) -> Some((g_vec, h_vec, p))
    ([l, ..ls], [r, ..rs], [l_b, ..lbs], [r_b, ..rbs]) -> {
      let x = hash_to_scalar([l_b, r_b])
      when scalar.recip(x) is {
        None -> None
        Some(x_inv) -> {
          let x2 = scalar.mul(x, x)
          let x_inv2 = scalar.mul(x_inv, x_inv)
          let p_next =
            g1.add(p, g1.add(g1.scale(l, x2), g1.scale(r, x_inv2)))

          let len = list.length(g_vec)
          let half = len / 2
          if len <= 1 || half * 2 != len {
            None
          } else {
            let (g_l, g_r) = list.span(g_vec, half)
            let (h_l, h_r) = list.span(h_vec, half)
            if list.length(g_l) != list.length(g_r) ||
              list.length(h_l) != list.length(h_r)
            {
              None
            } else {
              let g_next =
                list.map2(g_l, g_r, fn(gl, gr) {
                  g1.add(g1.scale(gl, x_inv), g1.scale(gr, x))
                })
              let h_next =
                list.map2(h_l, h_r, fn(hl, hr) {
                  g1.add(g1.scale(hl, x), g1.scale(hr, x_inv))
                })
              fold_inner_rounds(g_next, h_next, p_next, ls, rs, lbs, rbs)
            }
          }
        }
      }
    }
    _ -> None
  }
}

fn concat_all(chunks: List<ByteArray>) -> ByteArray {
  list.foldl(chunks, #"", fn(chunk, acc) { bytearray.concat(acc, chunk) })
}

fn scalar_from_hash(bytes: ByteArray) -> scalar.Scalar {
  let reduced = bytearray.to_int_big_endian(bytes) % scalar.field_prime
  expect Some(s) = scalar.new(reduced)
  s
}

fn hash_to_scalar(chunks: List<ByteArray>) -> scalar.Scalar {
  scalar_from_hash(crypto.blake2b_256(concat_all(chunks)))
}

fn scalar_from_int(value: Int) -> scalar.Scalar {
  expect Some(s) = scalar.new(value)
  s
}

fn scalar_to_bytes32(value: scalar.Scalar) -> ByteArray {
  scalar.to_bytearray_big_endian(value, 32)
}

fn scalar_sum(values: List<scalar.Scalar>) -> scalar.Scalar {
  list.foldl(values, scalar.zero, fn(value, acc) { scalar.add(acc, value) })
}

fn build_pows(base: scalar.Scalar, count: Int) -> List<scalar.Scalar> {
  build_pows_loop(base, count, scalar.one)
}

fn build_pows_loop(
  base: scalar.Scalar,
  count: Int,
  acc: scalar.Scalar,
) -> List<scalar.Scalar> {
  if count <= 0 {
    []
  } else {
    [acc, ..build_pows_loop(base, count - 1, scalar.mul(acc, base))]
  }
}

fn sum_points(points: List<G1Element>) -> G1Element {
  list.foldl(points, g1.zero, fn(point, acc) { g1.add(acc, point) })
}

fn decompress_points(points: List<ByteArray>) -> List<G1Element> {
  list.map(points, fn(bytes) { g1.decompress(bytes) })
}

fn is_power_of_two(n: Int) -> Bool {
  if n <= 0 {
    False
  } else {
    is_power_of_two_loop(n)
  }
}

fn is_power_of_two_loop(n: Int) -> Bool {
  if n == 1 {
    True
  } else if n % 2 != 0 {
    False
  } else {
    is_power_of_two_loop(n / 2)
  }
}

fn log2_unchecked(n: Int) -> Int {
  if n <= 1 {
    0
  } else {
    1 + log2_unchecked(n / 2)
  }
}

fn example_vk() -> BulletproofVerificationKey {
  BulletproofVerificationKey {
    n: 8,
    g: #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
    h: #"ae6fc86ed4ced6110e1864a7548c3fac3e745503d393aa0b7c81d374c0cd1a562599bf051855efcd9c24ab160eba3bd8",
    u: #"96a97eda9b5a0ffc42737da84fa0450e04c0df92ca6a1b7479ec65069e45dfb2757f2786cddfdf983fc5ea2af5369edb",
    g_vec: [
      #"87b7d78947b4e4f84afea63796cbc638f9881558de4df81a7db55ae495c7c66940da0b9bd3bca0142976c16da8fe33c1",
      #"afd4f772bf0dd51640e960a8c9807ad757e189451c5112628dfcd7050995bb329c7de349c72112f709e58bdffe91a319",
      #"a1cb67512e3b86784ca533be682c4870d7ba1a9388169109bee49ebded440ddd8b53cf0f36ee4bf2b3407edeb460352e",
      #"ab6b09686fa506449f85f788f4a3c7cc922539c95350e383d35d3cb21048d258b429ac9a58c106061244da86804c0ffa",
      #"b3884968addc082d844a15bcc3f0940db66cf8296598cdcd50d848e90fbefd4413d24321c1c03955af712de8bd354d78",
      #"884799bf65e26e6fc3ae7d265e54b22b11a3d6a58fad95f0ff16f6e5148a0dabccc6856358f854024b73b3f102543f68",
      #"ac0a10e75485af12d248bae20a9b579cfa431df15bf251563d7dfe5bdff392af54406a504b13aef1f2a4db87bd4b91ee",
      #"83b0e17b41cfd35a4c9e142ffcdcf2ae265676c0cff3a8c3941fe7a84df7c41c650e02fa421795f090362a449a00ca16",
    ],
    h_vec: [
      #"a12edf2114aaab2e19aa3b9dafaf0b747d79c8e5670c9a792a5d07cbe5541c63036c25d975b115b67085fc93f9c7d4dd",
      #"823bf5e7765a203bd63ee9b9f71d8918fe5a9b0f971e20a7663bfeb5485bf449d5037ca0291572fa55b60667061b6ead",
      #"a38378e403dfcf7c0b52ffb2d1e532eac0c7cca8fb674b7580a5ea0336893fe8bcef989c9fd7f01614eb026fff2bb39b",
      #"977e735fad75a56083d0c40e7461b57dce1ba4cae5ea0216a12970440e6c447ecbaafaea0f4b621e6873ebb903e222e6",
      #"b10e0ec8b187e3e60137dcfeabb6348e1b57f44dddf5bb731cb650fcd20a695559271191471d6b6599f3d9ed9593aebd",
      #"b5beb394c8599dbdc73661bf6ed979ce97ebf66113f3705f0931e2e50d1e7381c127330cc2072ffeb36a78e5a337011c",
      #"907f98ad91643bcc0834fac286bbbba87641d56b693f06783bc7c8c56d7ed4868a4b51f82938f4f52fd7772102d1af67",
      #"93377ad6bf499566e1f81472e26b40b247b153b519b49d9a19d1aa672a9458e09e5fb19bd915bef39064d28b703024e9",
    ],
  }
}

fn example_commitment() -> ByteArray {
  #"88194b090d4df42c0c37c9f1379a05091e0c16eebf2b2bc1408fc57afb03aedf2f2695df9bfb2296e6db14d1ce95c4ea"
}

fn example_proof() -> BulletproofProof {
  BulletproofProof {
    a: #"933ec459db23e4ff6d59dd22534b5bf01b578b61dbc682c6cf06629edd77f75965e6534373c341c795e9e7e611ec3669",
    s: #"b06503746c611733485ced0a9487fe82da4ac4f6416c2d44c695bed2ae9dff6e5217c39ca12e3a913f6fc8181c0b7ba2",
    t1: #"aef4e04a43ba463b8086397a3084cc3ad7c2f2ec4543614802f5691530e42244c5f9a4deb74ed0b150e7b3b4bba427f2",
    t2: #"a8c0cdee49d3e733a226b7c0fe45d97d06344063d2de759a41ece31166889e0c214a16d010f288e197842fa50c90d93f",
    tau_x:
      47391452572029312100729586948019820109056884332188082782777998681278291690308,
    mu:
      42436237380226425661787152880702382935550206602423835603638030116664895862021,
    t_hat:
      47492977255941204010696170884933052481703132331628544488796995946967039103600,
    l_vec: [
      #"847b9603faf728e5c221172faa8db80e8d532aabb7621ee0b077be57d33d4322c200009f9df21375e6488bb06dab1b4b",
      #"b36f399fc6ae310deae6175afe35f913bab5a8cecaf93dc6bc1547fb775de6ba115907e9078a76521339443040ff2854",
      #"a4ce288ce0abd8eedba91ba7f8358a76df6a304741b79608678c081eeb09b4d2e98c34355d1627880ec17d8132b0f855",
    ],
    r_vec: [
      #"865e8eeb7ebc826f22bf0f33452b21e9e30c2b2eb8f61b298cd762305c362bd30025a3df7a2d8100b599571d6d082cda",
      #"a42618f243bc6541e9517f4167cb06d8c40fbff3616cdd76f51a6bc8bc95a2051f6f1ec11459223d4fe45455813515e6",
      #"b65069da21a2964a323c274baf9f3893b6d898e8b18c769da52ecd09dc1c223e3e851912f254a8d503ff382ebdc1e558",
    ],
    a_eval:
      25539554453696753687903061771910794431948400070689649663774001912761335621489,
    b_eval:
      10649768096521911548697966917415860732428226723091357902726347505394279427746,
  }
}

test verify_bulletproof_pass() {
  verify(example_vk(), example_commitment(), example_proof())
}

test verify_bulletproof_fail() fail {
  let proof = example_proof()
  let bad_proof =
    BulletproofProof {
      a: proof.a,
      s: proof.s,
      t1: proof.t1,
      t2: proof.t2,
      tau_x: proof.tau_x,
      mu: proof.mu,
      t_hat: proof.t_hat + 1,
      l_vec: proof.l_vec,
      r_vec: proof.r_vec,
      a_eval: proof.a_eval,
      b_eval: proof.b_eval,
    }

  verify(example_vk(), example_commitment(), bad_proof)
}
