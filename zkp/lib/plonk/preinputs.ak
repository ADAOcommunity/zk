use aiken/collection/list
use common/common.{Field, mod_pow}

pub type PlonkPreInputs {
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
}

pub type PreparedPlonkPreInputs {
    n: Int,
    generators: List<Field>,
    inputs: PlonkPreInputs,
}

pub fn plonk_prepare_preinputs(inputs: PlonkPreInputs, generator: Field, n_public: Int) -> PreparedPlonkPreInputs {
    PreparedPlonkPreInputs {
        n: mod_pow(2, inputs.power),
        generators: list.map(list.range(0, n_public), fn(n) { mod_pow(generator, n) }),
        inputs: inputs,
    }
}