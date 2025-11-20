use ark_bn254::Fr as Scalar;
use soroban_env_host::{
    testutils::crypto::{
        from_hex, scalar_vec_to_vecobj, vec_of_vec_to_vecobj, vecobj_to_scalar_vec,
    },
    Env, Host, HostError, Symbol, U32Val,
};
use std::str::FromStr;

// Import the parameter data for Poseidon t=3 (circomlib compatibility)
mod data {
    pub mod poseidon {
        include!("data/poseidon/poseidon_instance_bn254_t_3.rs");
    }
}

// ============================================================================
// Circomlib Poseidon Test Suite
// Tests from: https://github.com/iden3/circomlib/blob/master/test/poseidoncircuit.js
// ============================================================================

// Helper function to implement circomlib's Poseidon hash
// This is NOT a sponge - it runs one permutation with state = [0, inputs...]
fn poseidon_circomlib(host: &Host, inputs: Vec<Scalar>) -> Result<Scalar, HostError> {
    // Load BN254 t=3 parameters
    let params_data = data::poseidon::RC3.clone();
    let mds_data = data::poseidon::MDS3.clone();

    // Create state: [0, input[0], input[1], ...]
    let mut state = vec![Scalar::from(0)];
    state.extend(inputs);

    // Convert to host format
    let input_vecobj = scalar_vec_to_vecobj(host, state)?;
    let mds_vecobj = vec_of_vec_to_vecobj(host, &mds_data)?;
    let rc_vecobj = vec_of_vec_to_vecobj(host, &params_data)?;

    let field_symbol = Symbol::try_from_small_str("BN254")?;
    let t = (data::poseidon::POSEIDON_BN254_T3_T) as u32;
    let d = (data::poseidon::POSEIDON_BN254_T3_D) as u32;
    let rounds_f = (data::poseidon::POSEIDON_BN254_T3_ROUNDS_F) as u32;
    let rounds_p = (data::poseidon::POSEIDON_BN254_T3_ROUNDS_P) as u32;

    // Run permutation
    let result = host.poseidon_permutation(
        input_vecobj,
        field_symbol,
        U32Val::from(t),
        U32Val::from(d),
        U32Val::from(rounds_f),
        U32Val::from(rounds_p),
        mds_vecobj,
        rc_vecobj,
    )?;

    // Return first element
    let result_vec: Vec<Scalar> = vecobj_to_scalar_vec(host, result)?;
    Ok(result_vec[0])
}

// Test case from circomlib: hash([1, 2]) with t=3
// Source: circomlib/test/poseidoncircuit.js line 47
#[test]
fn test_poseidon_circomlib_t3_case1() -> Result<(), HostError> {
    let host = Host::test_host();
    host.enable_debug()?;

    let inputs = vec![Scalar::from(1), Scalar::from(2)];

    let result = poseidon_circomlib(&host, inputs)?;

    // Expected from circomlib test
    let expected =
        Scalar::from_str("7853200120776062878684798364095072458815029376092732009249414926327459813530").unwrap();

    assert_eq!(result, expected, "Poseidon hash([1, 2]) mismatch");

    Ok(())
}

// Test case from circomlib: hash([3, 4]) with t=3
// Source: circomlib/test/poseidoncircuit.js line 57
#[test]
fn test_poseidon_circomlib_t3_case2() -> Result<(), HostError> {
    let host = Host::test_host();
    host.enable_debug()?;

    let inputs = vec![Scalar::from(3), Scalar::from(4)];

    let result = poseidon_circomlib(&host, inputs)?;

    // Expected from circomlib test
    let expected =
        Scalar::from_str("14763215145315200506921711489642608356394854266165572616578112107564877678998").unwrap();

    assert_eq!(result, expected, "Poseidon hash([3, 4]) mismatch");

    Ok(())
}

// Note: Tests for t=6 (5 inputs) are skipped because parameters are not available
// To add these tests, generate parameters for t=6 using circomlib's parameter generation
// and add them to tests/data/poseidon/poseidon_instance_bn254_t_6.rs
//
// Skipped tests from circomlib:
// - test_poseidon_circomlib_t6_case1: hash([1, 2, 0, 0, 0])
// - test_poseidon_circomlib_t6_case2: hash([3, 4, 5, 10, 23])

// Note: PoseidonEx tests are also skipped as they require different parameter sets
// and support for variable output lengths (multiple outputs from final state)
// Skipped test from circomlib:
// - test_poseidon_ex_16_inputs: 16 inputs with initialState=17, 17 outputs
