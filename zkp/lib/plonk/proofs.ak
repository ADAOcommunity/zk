use aiken/builtin.{blake2b_224}
use common/common.{Field, bls12_381_prime, make_scalar, mod_inv}
use aiken/collection/list
use aiken/primitive/bytearray
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
    a_eval: Field,
    b_eval: Field,
    c_eval: Field,
    s_sig1_p: Field,
    s_sig2_p: Field,
    z_omega: Field,
}

pub type PreparedPlonkProof {
    proof: PlonkProof,
    lagrange_inverses: List<Field>,
}

pub fn plonk_prepare_proof(preinputs: PreparedPlonkPreInputs, pub_inputs: List<Int>, proof: PlonkProof) -> PreparedPlonkProof {
    let beta_inputs = [
        preinputs.inputs.q_m,
        preinputs.inputs.q_l,
        preinputs.inputs.q_r,
        preinputs.inputs.q_o,
        preinputs.inputs.q_c,
        preinputs.inputs.s_sig1,
        preinputs.inputs.s_sig2,
        preinputs.inputs.s_sig3,
        list.foldl(pub_inputs, #"", fn(a, b) { bytearray.concat(b, bytearray.from_int_big_endian(a, 32)) }),
        proof.commitment_a,
        proof.commitment_b,
        proof.commitment_c
    ]
    let beta_bs = blake2b_224(
        list.foldl(beta_inputs, #"", bytearray.concat)
    )
    let beta = make_scalar(bytearray.to_int_big_endian(beta_bs) % bls12_381_prime)
    let gamma_bs = blake2b_224(bytearray.from_int_big_endian(beta, 32))
    let gamma = make_scalar(bytearray.to_int_big_endian(gamma_bs) % bls12_381_prime)
    let alpha_bs = blake2b_224(list.foldl([
        bytearray.from_int_big_endian(beta, 32),
        bytearray.from_int_big_endian(gamma, 32),
        proof.commitment_z
    ], #"", bytearray.concat))
    let alpha = make_scalar(bytearray.to_int_big_endian(alpha_bs) % bls12_381_prime)
    let zeta_bs = blake2b_224(list.foldl([
            bytearray.from_int_big_endian(alpha, 32),
            proof.t_low,
            proof.t_mid,
            proof.t_high
    ], #"", bytearray.concat))
    let zeta = make_scalar(bytearray.to_int_big_endian(zeta_bs) % bls12_381_prime)
    let lagrange_inverses = list.map(preinputs.generators, fn(x) { 
        let nzx = make_scalar(preinputs.n) * (zeta - x)
        expect Some(inv) = mod_inv(nzx, bls12_381_prime)
        inv
    })

    PreparedPlonkProof {
        proof,
        lagrange_inverses,
    }
}