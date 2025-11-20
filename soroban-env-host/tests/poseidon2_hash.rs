use ark_bn254::Fr as Scalar;
use soroban_env_host::{
    testutils::crypto::{
        from_hex, scalar_vec_to_vecobj, vec_of_vec_to_vecobj, vecobj_to_scalar_vec,
    },
    Env, Host, HostError, Symbol, U32Val,
};



// Import the parameter data
mod data {
    pub mod poseidon {
        include!("data/poseidon/poseidon2_instance_bn254_t_4.rs");
    }
}

// Poseidon2 sponge implementation for testing
// Based on: https://github.com/AztecProtocol/aztec-packages/blob/next/barretenberg/cpp/src/barretenberg/crypto/poseidon2/sponge/sponge.hpp
mod sponge {
    use super::*;

    const RATE: usize = 3;
    const CAPACITY: usize = 1;
    const T: usize = RATE + CAPACITY; // 4

    #[derive(Debug, Clone, Copy, PartialEq)]
    enum SpongeMode {
        Absorb,
        Squeeze,
    }

    pub struct Poseidon2Sponge {
        state: Vec<Scalar>,
        cache: Vec<Scalar>,
        cache_size: usize,
        mode: SpongeMode,
    }

    impl Poseidon2Sponge {
        pub fn new(domain_iv: Scalar) -> Self {
            let mut state = vec![Scalar::from(0); RATE];
            state.push(domain_iv);

            Self {
                state,
                cache: vec![Scalar::from(0); RATE],
                cache_size: 0,
                mode: SpongeMode::Absorb,
            }
        }

        fn perform_duplex(&mut self, host: &Host) -> Result<Vec<Scalar>, HostError> {
            // Zero-pad the cache
            for i in self.cache_size..RATE {
                self.cache[i] = Scalar::from(0);
            }

            // Add the cache into sponge state (field addition)
            for i in 0..RATE {
                self.state[i] += self.cache[i];
            }

            // Apply permutation
            self.state = self.permute(host)?;

            // Return rate number of field elements from the sponge state
            Ok(self.state[0..RATE].to_vec())
        }

        fn permute(&self, host: &Host) -> Result<Vec<Scalar>, HostError> {
            // Call the host's poseidon2_permutation function
            let input_vecobj = scalar_vec_to_vecobj(host, self.state.clone())?;
            let mat_diag_vecobj = scalar_vec_to_vecobj(
                host,
                data::poseidon::POSEIDON2_BN254_T4_MAT_DIAG.clone(),
            )?;
            let rc_vecobj =
                vec_of_vec_to_vecobj(host, &data::poseidon::POSEIDON2_BN254_T4_PARAMS)?;

            let field_symbol = Symbol::try_from_small_str("BN254")?;

            let result = host.poseidon2_permutation(
                input_vecobj,
                field_symbol,
                U32Val::from(T as u32),
                U32Val::from(5u32),  // d
                U32Val::from(8u32),  // rounds_f
                U32Val::from(56u32), // rounds_p
                mat_diag_vecobj,
                rc_vecobj,
            )?;

            vecobj_to_scalar_vec(host, result)
        }

        pub fn absorb(&mut self, input: Scalar, host: &Host) -> Result<(), HostError> {
            if self.mode == SpongeMode::Squeeze {
                // Reset cache and switch to absorb mode
                self.cache_size = 0;
                self.mode = SpongeMode::Absorb;
            }

            if self.cache_size == RATE {
                // Cache is full, perform duplex
                self.cache = self.perform_duplex(host)?;
                // Store input as first element 
                self.cache[0] = input;
                self.cache_size = 1;
            } else {
                // Add to cache
                self.cache[self.cache_size] = input;
                self.cache_size += 1;
            }

            Ok(())
        }

        pub fn squeeze(&mut self, host: &Host) -> Result<Scalar, HostError> {
            if self.mode == SpongeMode::Absorb {
                // Perform duplex and switch to squeeze mode
                self.cache = self.perform_duplex(host)?;
                self.cache_size = RATE;
                self.mode = SpongeMode::Squeeze;
            }

            if self.cache_size == 0 {
                // Refill cache
                self.cache = self.perform_duplex(host)?;
                self.cache_size = RATE;
            }

            // Return first cached element
            let output = self.cache[0];

            // Shift remaining elements forward
            for i in 1..self.cache_size {
                self.cache[i - 1] = self.cache[i];
            }
            self.cache_size -= 1;

            Ok(output)
        }
    }

    pub fn poseidon2_hash(host: &Host, input: Vec<Scalar>) -> Result<Scalar, HostError> {
        let input_len = input.len() as u128;
        let output_len = 1u128;

        // Compute IV: (input_length << 64) + output_length - 1
        // This computes 2^64 * input_len + output_len - 1
        let iv_value = (input_len << 64) + output_len - 1;
        let iv = Scalar::from(iv_value);

        let mut sponge = Poseidon2Sponge::new(iv);

        // Absorb all inputs
        for elem in input {
            sponge.absorb(elem, host)?;
        }

        // Squeeze one output
        sponge.squeeze(host)
    }
}

#[test]
fn test_poseidon2_basic_functionality() -> Result<(), HostError> {
    let host = Host::test_host();

    // Test with the provided input/output vectors
    let input: Vec<Scalar> = vec![
        from_hex("0x0000000000000000000000000000000000000000000000000000000000000000"),
        from_hex("0x0000000000000000000000000000000000000000000000000000000000000001"),
        from_hex("0x0000000000000000000000000000000000000000000000000000000000000002"),
        from_hex("0x0000000000000000000000000000000000000000000000000000000000000003"),
    ];

    let expected_output: Vec<Scalar> = vec![
        from_hex("0x01bd538c2ee014ed5141b29e9ae240bf8db3fe5b9a38629a9647cf8d76c01737"),
        from_hex("0x239b62e7db98aa3a2a8f6a0d2fa1709e7a35959aa6c7034814d9daa90cbac662"),
        from_hex("0x04cbb44c61d928ed06808456bf758cbf0c18d1e15a7b6dbc8245fa7515d5e3cb"),
        from_hex("0x2e11c5cff2a22c64d01304b778d78f6998eff1ab73163a35603f54794c30847a"),
    ];

    // Convert inputs to host expected format
    let input_vecobj = scalar_vec_to_vecobj(&host, input)?;
    let mat_internal_diag_m_1_vecobj =
        scalar_vec_to_vecobj(&host, data::poseidon::POSEIDON2_BN254_T4_MAT_DIAG.clone())?;
    let rc_vecobj = vec_of_vec_to_vecobj(&host, &data::poseidon::POSEIDON2_BN254_T4_PARAMS)?;

    // Call the host function
    let field_symbol = Symbol::try_from_small_str("BN254")?;
    let result = host.poseidon2_permutation(
        input_vecobj,
        field_symbol,
        U32Val::from(4u32),  // t (state size)
        U32Val::from(5u32),  // d (sbox degree)
        U32Val::from(8u32),  // rounds_f (full rounds)
        U32Val::from(56u32), // rounds_p (partial rounds)
        mat_internal_diag_m_1_vecobj,
        rc_vecobj,
    )?;

    // Convert result back to scalar vector
    let result_scalars: Vec<Scalar> = vecobj_to_scalar_vec(&host, result)?;
    assert_eq!(result_scalars, expected_output);
    Ok(())
}

// Barretenberg test case: https://github.com/AztecProtocol/aztec-packages/blob/b95e36c6c1a5a84ba488c720189102ecbb052d2c/barretenberg/cpp/src/barretenberg/crypto/poseidon2/poseidon2_permutation.test.cpp#L44
#[test]
fn test_poseidon2_barretenberg_permutation_consistency() -> Result<(), HostError> {
    let host = Host::test_host();

    // Input
    let input: Vec<Scalar> = vec![
        from_hex("0x9a807b615c4d3e2fa0b1c2d3e4f56789fedcba9876543210abcdef0123456789"),
        from_hex("0x9a807b615c4d3e2fa0b1c2d3e4f56789fedcba9876543210abcdef0123456789"),
        from_hex("0x9a807b615c4d3e2fa0b1c2d3e4f56789fedcba9876543210abcdef0123456789"),
        from_hex("0x9a807b615c4d3e2fa0b1c2d3e4f56789fedcba9876543210abcdef0123456789"),
    ];

    // Expected output (using the actual output from the working implementation)
    let expected_output: Vec<Scalar> = vec![
        from_hex("0x2bf1eaf87f7d27e8dc4056e9af975985bccc89077a21891d6c7b6ccce0631f95"),
        from_hex("0x0c01fa1b8d0748becafbe452c0cb0231c38224ea824554c9362518eebdd5701f"),
        from_hex("0x018555a8eb50cf07f64b019ebaf3af3c925c93e631f3ecd455db07bbb52bbdd3"),
        from_hex("0x0cbea457c91c22c6c31fd89afd2541efc2edf31736b9f721e823b2165c90fd41"),
    ];
    let input_vecobj = scalar_vec_to_vecobj(&host, input.clone())?;
    let mat_diag_vecobj =
        scalar_vec_to_vecobj(&host, data::poseidon::POSEIDON2_BN254_T4_MAT_DIAG.clone())?;
    let rc_vecobj = vec_of_vec_to_vecobj(&host, &data::poseidon::POSEIDON2_BN254_T4_PARAMS)?;

    let field_symbol = Symbol::try_from_small_str("BN254")?;

    let result = host.poseidon2_permutation(
        input_vecobj,
        field_symbol,
        U32Val::from(4u32),  // t (state size)
        U32Val::from(5u32),  // d (sbox degree)
        U32Val::from(8u32),  // rounds_f (full rounds)
        U32Val::from(56u32), // rounds_p (partial rounds)
        mat_diag_vecobj,
        rc_vecobj,
    )?;

    let result_scalar_vec: Vec<Scalar> = vecobj_to_scalar_vec(&host, result)?;
    assert_eq!(
        result_scalar_vec, expected_output,
        "Poseidon2 hash result mismatch"
    );

    Ok(())
}

// https://github.com/AztecProtocol/aztec-packages/blob/b95e36c6c1a5a84ba488c720189102ecbb052d2c/barretenberg/cpp/src/barretenberg/crypto/poseidon2/poseidon2.test.cpp#L34
#[test]
fn test_poseidon2_hash_consistency_check() -> Result<(), HostError> {
    let host = Host::test_host();
    host.enable_debug()?;

    // Input - 4 identical field elements
    let input: Vec<Scalar> = vec![
        from_hex("0x9a807b615c4d3e2fa0b1c2d3e4f56789fedcba9876543210abcdef0123456789"),
        from_hex("0x9a807b615c4d3e2fa0b1c2d3e4f56789fedcba9876543210abcdef0123456789"),
        from_hex("0x9a807b615c4d3e2fa0b1c2d3e4f56789fedcba9876543210abcdef0123456789"),
        from_hex("0x9a807b615c4d3e2fa0b1c2d3e4f56789fedcba9876543210abcdef0123456789"),
    ];

    // Expected output from Aztec's implementation
    let expected_output: Scalar =
        from_hex("0x2f43a0f83b51a6f5fc839dea0ecec74947637802a579fa9841930a25a0bcec11");

    // Use the sponge implementation to hash the input
    let result = sponge::poseidon2_hash(&host, input)?;

    assert_eq!(result, expected_output, "Poseidon2 hash result mismatch");

    Ok(())
}
