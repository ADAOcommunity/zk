const ff = require("ffjavascript");
const blake = require("blakejs");

const DOMAIN = "bulletproof-test-v1";

function blake2b256(data) {
  return Buffer.from(blake.blake2b(data, null, 32));
}

function concatBuffers(buffers) {
  return Buffer.concat(buffers);
}

function bigIntToBytes32(value) {
  let hex = value.toString(16);
  if (hex.length % 2 === 1) hex = "0" + hex;
  const buf = Buffer.from(hex, "hex");
  if (buf.length > 32) throw new Error("bigInt too large");
  return Buffer.concat([Buffer.alloc(32 - buf.length, 0), buf]);
}

function modPow(base, exp, mod) {
  let result = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

async function main() {
  const curve = await ff.getCurveFromName("bls12381");
  const r = BigInt(curve.r);

  const mod = (x) => ((x % r) + r) % r;
  const add = (a, b) => mod(a + b);
  const sub = (a, b) => mod(a - b);
  const mul = (a, b) => mod(a * b);
  const inv = (a) => modPow(a, r - 2n, r);

  const hashToScalar = (buf) => {
    const digest = blake2b256(buf);
    return mod(BigInt("0x" + digest.toString("hex")));
  };

  const randScalar = (label) => {
    let s = hashToScalar(Buffer.from(`${DOMAIN}:${label}`));
    if (s === 0n) s = 1n;
    return s;
  };

  const randVector = (label, n) => {
    const out = [];
    for (let i = 0; i < n; i += 1) {
      out.push(randScalar(`${label}:${i}`));
    }
    return out;
  };

  const g1Add = (a, b) => curve.G1.add(a, b);
  const g1Mul = (p, s) => curve.G1.timesScalar(p, s);

  const g1Zero = curve.G1.zero;
  const g1Gen = curve.G1.g;

  const g1Compress = (p) => {
    const buf = Buffer.alloc(48);
    curve.G1.toRprCompressed(buf, 0, p);
    const isInf = (buf[0] & 0x40) !== 0;
    const isSign = (buf[0] & 0x80) !== 0;
    buf[0] &= 0x1f;
    buf[0] |= 0x80;
    if (isInf) buf[0] |= 0x40;
    if (isSign) buf[0] |= 0x20;
    return buf;
  };

  const vectorAdd = (a, b) => a.map((x, i) => add(x, b[i]));
  const vectorSub = (a, b) => a.map((x, i) => sub(x, b[i]));
  const vectorScalarMul = (a, s) => a.map((x) => mul(x, s));
  const vectorHadamard = (a, b) => a.map((x, i) => mul(x, b[i]));
  const innerProduct = (a, b) => a.reduce((acc, x, i) => add(acc, mul(x, b[i])), 0n);

  const vectorCommit = (scalars, points) => {
    let acc = g1Zero;
    for (let i = 0; i < scalars.length; i += 1) {
      acc = g1Add(acc, g1Mul(points[i], scalars[i]));
    }
    return acc;
  };

  const split = (arr) => {
    const mid = arr.length / 2;
    return [arr.slice(0, mid), arr.slice(mid)];
  };

  const innerProductProve = (a, b, gVec, hVec, u) => {
    const Ls = [];
    const Rs = [];
    let aVec = a;
    let bVec = b;
    let g = gVec;
    let h = hVec;

    while (aVec.length > 1) {
      const [aL, aR] = split(aVec);
      const [bL, bR] = split(bVec);
      const [gL, gR] = split(g);
      const [hL, hR] = split(h);

      const cL = innerProduct(aL, bR);
      const cR = innerProduct(aR, bL);

      const L = g1Add(g1Add(vectorCommit(aL, gR), vectorCommit(bR, hL)), g1Mul(u, cL));
      const R = g1Add(g1Add(vectorCommit(aR, gL), vectorCommit(bL, hR)), g1Mul(u, cR));

      Ls.push(L);
      Rs.push(R);

      const x = hashToScalar(concatBuffers([g1Compress(L), g1Compress(R)]));
      const xInv = inv(x);

      aVec = aL.map((ai, i) => add(mul(ai, x), mul(aR[i], xInv)));
      bVec = bL.map((bi, i) => add(mul(bi, xInv), mul(bR[i], x)));

      g = gL.map((gi, i) => g1Add(g1Mul(gi, xInv), g1Mul(gR[i], x)));
      h = hL.map((hi, i) => g1Add(g1Mul(hi, x), g1Mul(hR[i], xInv)));
    }

    return { Ls, Rs, a: aVec[0], b: bVec[0] };
  };

  const n = 8;
  const value = 13n;

  const g = g1Gen;
  const h = g1Mul(g1Gen, randScalar("h"));
  const u = g1Mul(g1Gen, randScalar("u"));

  const gVec = Array.from({ length: n }, (_, i) => g1Mul(g1Gen, randScalar(`g:${i}`)));
  const hVec = Array.from({ length: n }, (_, i) => g1Mul(g1Gen, randScalar(`h:${i}`)));

  const gamma = randScalar("gamma");
  const V = g1Add(g1Mul(g, value), g1Mul(h, gamma));

  const aL = Array.from({ length: n }, (_, i) => (value >> BigInt(i)) & 1n);
  const aR = aL.map((bit) => sub(bit, 1n));
  const alpha = randScalar("alpha");
  const A = g1Add(g1Add(vectorCommit(aL, gVec), vectorCommit(aR, hVec)), g1Mul(h, alpha));

  const sL = randVector("sL", n);
  const sR = randVector("sR", n);
  const rho = randScalar("rho");
  const S = g1Add(g1Add(vectorCommit(sL, gVec), vectorCommit(sR, hVec)), g1Mul(h, rho));

  const y = hashToScalar(concatBuffers([g1Compress(V), g1Compress(A), g1Compress(S)]));
  const z = hashToScalar(bigIntToBytes32(y));

  const yPows = [];
  const yInvPows = [];
  let yPow = 1n;
  let yInvPow = 1n;
  const yInv = inv(y);
  for (let i = 0; i < n; i += 1) {
    yPows.push(yPow);
    yInvPows.push(yInvPow);
    yPow = mul(yPow, y);
    yInvPow = mul(yInvPow, yInv);
  }

  const pow2 = [];
  let pow = 1n;
  for (let i = 0; i < n; i += 1) {
    pow2.push(pow);
    pow = mul(pow, 2n);
  }

  const ones = Array.from({ length: n }, () => 1n);
  const zOnes = vectorScalarMul(ones, z);
  const z2 = mul(z, z);
  const z3 = mul(z2, z);

  const l0 = vectorSub(aL, zOnes);
  const l1 = sL;

  const aRPlusZ = vectorAdd(aR, zOnes);
  const r0 = vectorAdd(vectorHadamard(yPows, aRPlusZ), vectorScalarMul(pow2, z2));
  const r1 = vectorHadamard(yPows, sR);

  const t1 = add(innerProduct(l0, r1), innerProduct(l1, r0));
  const t2 = innerProduct(l1, r1);

  const tau1 = randScalar("tau1");
  const tau2 = randScalar("tau2");

  const T1 = g1Add(g1Mul(g, t1), g1Mul(h, tau1));
  const T2 = g1Add(g1Mul(g, t2), g1Mul(h, tau2));

  const x = hashToScalar(concatBuffers([bigIntToBytes32(z), g1Compress(T1), g1Compress(T2)]));
  const x2 = mul(x, x);

  const l = vectorAdd(l0, vectorScalarMul(l1, x));
  const rVec = vectorAdd(r0, vectorScalarMul(r1, x));
  const tHat = innerProduct(l, rVec);
  const tauX = add(add(mul(tau2, x2), mul(tau1, x)), mul(z2, gamma));
  const mu = add(alpha, mul(rho, x));

  const hPrime = hVec.map((hi, i) => g1Mul(hi, yInvPows[i]));

  const gZ = gVec.map((gi) => g1Mul(gi, sub(0n, z)));
  const hCoeff = hPrime.map((_, i) => add(mul(z, yPows[i]), mul(z2, pow2[i])));
  const hZ = hPrime.map((hi, i) => g1Mul(hi, hCoeff[i]));

  let P = A;
  P = g1Add(P, g1Mul(S, x));
  gZ.forEach((pt) => {
    P = g1Add(P, pt);
  });
  hZ.forEach((pt) => {
    P = g1Add(P, pt);
  });
  P = g1Add(P, g1Mul(u, tHat));
  P = g1Add(P, g1Mul(h, sub(0n, mu)));

  const ipProof = innerProductProve(l, rVec, gVec, hPrime, u);

  const out = {
    vk: {
      n,
      g: g1Compress(g).toString("hex"),
      h: g1Compress(h).toString("hex"),
      u: g1Compress(u).toString("hex"),
      g_vec: gVec.map((pt) => g1Compress(pt).toString("hex")),
      h_vec: hVec.map((pt) => g1Compress(pt).toString("hex")),
    },
    commitment: g1Compress(V).toString("hex"),
    proof: {
      a: g1Compress(A).toString("hex"),
      s: g1Compress(S).toString("hex"),
      t1: g1Compress(T1).toString("hex"),
      t2: g1Compress(T2).toString("hex"),
      tau_x: tauX.toString(10),
      mu: mu.toString(10),
      t_hat: tHat.toString(10),
      l_vec: ipProof.Ls.map((pt) => g1Compress(pt).toString("hex")),
      r_vec: ipProof.Rs.map((pt) => g1Compress(pt).toString("hex")),
      a_eval: ipProof.a.toString(10),
      b_eval: ipProof.b.toString(10),
    },
  };

  console.log(JSON.stringify(out, null, 2));

  curve.terminate();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
