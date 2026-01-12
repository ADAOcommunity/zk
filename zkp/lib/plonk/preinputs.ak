use aiken/builtin
use aiken/collection/list
use common/common.{Field, mod_pow}

pub type PlonkPreInputs {
    n_public: Int,
    power: Int,
    k1: Field,
    k2: Field,
    q_m: ByteArray,
    q_l: ByteArray,
    q_r: ByteArray,
    q_o: ByteArray,
    q_c: ByteArray,
    s_sig1: ByteArray,
    s_sig2: ByteArray,
    s_sig3: ByteArray,
    x2: ByteArray,
    generator: Field,
}

pub type PlonkPreInputsFast {
    n: Int,
    power: Int,
    k1: Field,
    k2: Field,
    q_m: ByteArray,
    q_l: ByteArray,
    q_r: ByteArray,
    q_o: ByteArray,
    q_c: ByteArray,
    s_sig1: ByteArray,
    s_sig2: ByteArray,
    s_sig3: ByteArray,
    x2: ByteArray,
    generators: List<Field>,
}

pub fn convert_to_fast_pre_inputs(pre_inputs: PlonkPreInputs) -> PlonkPreInputsFast {
    let ppif = PlonkPreInputsFast {
        n: mod_pow(2, pre_inputs.power),
        power: pre_inputs.power,
        k1: pre_inputs.k1,
        k2: pre_inputs.k2,
        q_m: pre_inputs.q_m,
        q_l: pre_inputs.q_l,
        q_r: pre_inputs.q_r,
        q_o: pre_inputs.q_o,
        q_c: pre_inputs.q_c,
        s_sig1: pre_inputs.s_sig1,
        s_sig2: pre_inputs.s_sig2,
        s_sig3: pre_inputs.s_sig3,
        x2: pre_inputs.x2,
        generators: list.map(list.range(0, pre_inputs.n_public), fn(n) { mod_pow(pre_inputs.generator, n) }),
    }
    ppif
}