use crate::{
    budget::AsBudget,
    host_object::HostVec,
    xdr::{ContractCostType, ScBytes, ScErrorCode, ScErrorType},
    Bool, BytesObject, Env, Host, HostError, TryFromVal, U256Object, U256Small, U256Val, Val,
    VecObject, U256,
};
use ark_bn254::{
    g1::Config as G1Config, g2::Config as G2Config, Bn254, Fq, Fq12, Fq2, Fr, G1Affine,
    G1Projective, G2Affine, G2Projective,
};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    scalar_mul::variable_base::VariableBaseMSM,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig, CurveGroup,
};
use ark_ff::{Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use std::cmp::Ordering;
use std::ops::{Add, Mul};

pub(crate) const FP_SERIALIZED_SIZE: usize = 32;
pub(crate) const FP2_SERIALIZED_SIZE: usize = FP_SERIALIZED_SIZE * 2;
#[allow(dead_code)]
pub(crate) const FP12_SERIALIZED_SIZE: usize = FP_SERIALIZED_SIZE * 12;
pub(crate) const G1_SERIALIZED_SIZE: usize = FP_SERIALIZED_SIZE * 2;
pub(crate) const G2_SERIALIZED_SIZE: usize = FP2_SERIALIZED_SIZE * 2;
pub(crate) const FR_SERIALIZED_SIZE: usize = 32;

#[inline(always)]
#[allow(dead_code)]
fn units_of_fp<const EXPECTED_SIZE: usize>() -> u64 {
    EXPECTED_SIZE.div_ceil(FP_SERIALIZED_SIZE) as u64
}

impl Host {
    // This is the internal routine performing deserialization on various
    // element types, which can be conceptually decomposed into units of Fp
    // (the base field element), and will be charged accordingly.
    // Validation of the deserialized entity must be performed outside of this
    // function, to keep budget charging isolated.
    pub(crate) fn bn254_deserialize_uncompressed_no_validate<
        const EXPECTED_SIZE: usize,
        T: CanonicalDeserialize,
    >(
        &self,
        slice: &[u8],
        tag: &str,
    ) -> Result<T, HostError> {
        if EXPECTED_SIZE == 0 || slice.len() != EXPECTED_SIZE {
            return Err(self.err(
                ScErrorType::Crypto,
                ScErrorCode::InvalidInput,
                format!("bn254 {tag}: invalid input length to deserialize").as_str(),
                &[
                    Val::from_u32(slice.len() as u32).into(),
                    Val::from_u32(EXPECTED_SIZE as u32).into(),
                ],
            ));
        }

        self.as_budget().bulk_charge(
            ContractCostType::Bn254DecodeFp,
            units_of_fp::<EXPECTED_SIZE>(),
            None,
        )?;

        // validation turned off here to isolate the cost of serialization.
        // proper validation has to be performed outside of this function
        T::deserialize_with_mode(slice, Compress::Yes, Validate::No).map_err(|_e| {
            self.err(
                ScErrorType::Crypto,
                ScErrorCode::InvalidInput,
                format!("bn254: unable to deserialize {tag}").as_str(),
                &[],
            )
        })
    }

    // This is the internal routine performing serialization on various
    // element types, which can be conceptually decomposed into units of Fp
    // (the base field element), and will be charged accordingly.
    pub(crate) fn bn254_serialize_uncompressed_into_slice<
        const EXPECTED_SIZE: usize,
        T: CanonicalSerialize,
    >(
        &self,
        element: &T,
        buf: &mut [u8],
        tag: &str,
    ) -> Result<(), HostError> {
        if EXPECTED_SIZE == 0 || buf.len() != EXPECTED_SIZE {
            return Err(self.err(
                ScErrorType::Crypto,
                ScErrorCode::InvalidInput,
                format!("bn254 {tag}: invalid buffer length to serialize into").as_str(),
                &[
                    Val::from_u32(buf.len() as u32).into(),
                    Val::from_u32(EXPECTED_SIZE as u32).into(),
                ],
            ));
        }

        self.as_budget().bulk_charge(
            ContractCostType::Bn254EncodeFp,
            units_of_fp::<EXPECTED_SIZE>(),
            None,
        )?;
        element.serialize_uncompressed(buf).map_err(|_e| {
            self.err(
                ScErrorType::Crypto,
                ScErrorCode::InternalError,
                format!("bn254: unable to serialize {tag}").as_str(),
                &[],
            )
        })?;
        Ok(())
    }

    fn bn254_validate_point_encoding<const EXPECTED_SIZE: usize>(
        &self,
        bytes: &[u8],
        tag: &str,
    ) -> Result<(), HostError> {
        // validate input bytes length
        if EXPECTED_SIZE == 0 || bytes.len() != EXPECTED_SIZE {
            return Err(self.err(
                ScErrorType::Crypto,
                ScErrorCode::InvalidInput,
                format!("bn254 {tag}: invalid input length to deserialize").as_str(),
                &[
                    Val::from_u32(bytes.len() as u32).into(),
                    Val::from_u32(EXPECTED_SIZE as u32).into(),
                ],
            ));
        }
        // TODO: BN254 might use different encoding standards than BLS12-381
        // For now, skip validation to see if serialization/deserialization works
        // Will investigate BN254 encoding standards separately

        // TODO: Should we allow compressed encoding? We don't for bls12-381.
        Ok(())
    }

    pub(crate) fn bn254_check_point_is_on_curve<P: SWCurveConfig>(
        &self,
        pt: &Affine<P>,
    ) -> Result<bool, HostError> {
        // TODO: Add proper cost type once BN254 cost types are added to XDR
        // self.charge_budget(cost_type, None)?;
        Ok(pt.is_on_curve())
    }

    pub(crate) fn bn254_check_point_is_in_subgroup<P: SWCurveConfig>(
        &self,
        pt: &Affine<P>,
    ) -> Result<bool, HostError> {
        // TODO: Add proper cost type once BN254 cost types are added to XDR
        // self.charge_budget(cost_type, None)?;
        Ok(pt.is_in_correct_subgroup_assuming_on_curve())
    }

    pub(crate) fn bn254_affine_deserialize<const EXPECTED_SIZE: usize, P: SWCurveConfig>(
        &self,
        bo: BytesObject,
        subgroup_check: bool,
        tag: &str,
    ) -> Result<Affine<P>, HostError> {
        let pt: Affine<P> = self.visit_obj(bo, |bytes: &ScBytes| {
            self.bn254_validate_point_encoding::<EXPECTED_SIZE>(&bytes, tag)?;
            // `CanonicalDeserialize` of `Affine<P>` calls into
            // `P::deserialize_with_mode`, where `P` is `arc_bn254::{g1,g2}::Config`, the
            // core logic is in `arc_bn254::curves::util::read_{g1,g2}_uncompressed`.
            //
            // The `arc_bn254` lib already expects the input to be serialized in
            // big-endian order (aligning with the common standard and contrary
            // to ark::serialize's convention),
            //
            // i.e. `input = be_bytes(X) || be_bytes(Y)` and the
            // most-significant three bits of X are flags:
            //
            // `bits(Affine) = [compression_flag, infinity_flag, sort_flag, ..remaining X_bits.., ..Y_bits..]`
            //
            // For `G1Affine`, each coordinate is an `Fq` that is 32 bytes.
            //
            // For `G2Affine`, each coordinate is an `Fq2` which contains two `Fq`,
            // i.e. `(c1: Fq, c0: Fq)` see `field_element_deserialize` for more details.
            //
            // Internally when deserializing `Fq`, the flag bits are masked off
            // to get `X: Fq`. The Y however, does not have the top bits masked off
            // so it is possible for Y to exceed 254 bits. Internally `Fq` deserialization
            // makes sure any value >= prime modulus results in an error.
            self.bn254_deserialize_uncompressed_no_validate::<EXPECTED_SIZE, _>(
                bytes.as_slice(),
                tag,
            )
        })?;
        if !self.bn254_check_point_is_on_curve(&pt)? {
            return Err(self.err(
                ScErrorType::Crypto,
                ScErrorCode::InvalidInput,
                format!("bn254 {}: point not on curve", tag).as_str(),
                &[],
            ));
        }
        if subgroup_check && !self.bn254_check_point_is_in_subgroup(&pt)? {
            return Err(self.err(
                ScErrorType::Crypto,
                ScErrorCode::InvalidInput,
                format!("bn254 {}: point not in the correct subgroup", tag).as_str(),
                &[],
            ));
        }
        Ok(pt)
    }

    pub(crate) fn bn254_g1_affine_deserialize_from_bytesobj(
        &self,
        bo: BytesObject,
        subgroup_check: bool,
    ) -> Result<G1Affine, HostError> {
        self.bn254_affine_deserialize::<G1_SERIALIZED_SIZE, G1Config>(bo, subgroup_check, "G1")
    }

    pub(crate) fn bn254_g2_affine_deserialize_from_bytesobj(
        &self,
        bo: BytesObject,
        subgroup_check: bool,
    ) -> Result<G2Affine, HostError> {
        self.bn254_affine_deserialize::<G2_SERIALIZED_SIZE, G2Config>(bo, subgroup_check, "G2")
    }

    pub(crate) fn bn254_g1_projective_into_affine(
        &self,
        g1: G1Projective,
    ) -> Result<G1Affine, HostError> {
        self.charge_budget(ContractCostType::Bn254G1ProjectiveToAffine, None)?;
        Ok(g1.into_affine())
    }

    pub(crate) fn bn254_g1_affine_serialize_uncompressed(
        &self,
        g1: &G1Affine,
    ) -> Result<BytesObject, HostError> {
        let mut buf = [0; G1_SERIALIZED_SIZE];

        //TODO: Add comments about serialization format
        self.bn254_serialize_uncompressed_into_slice::<G1_SERIALIZED_SIZE, _>(g1, &mut buf, "G1")?;
        self.add_host_object(self.scbytes_from_slice(&buf)?)
    }

    pub(crate) fn bn254_g1_projective_serialize_uncompressed(
        &self,
        g1: G1Projective,
    ) -> Result<BytesObject, HostError> {
        let g1_affine = self.bn254_g1_projective_into_affine(g1)?;
        self.bn254_g1_affine_serialize_uncompressed(&g1_affine)
    }

    pub(crate) fn bn254_g2_projective_into_affine(
        &self,
        g2: G2Projective,
    ) -> Result<G2Affine, HostError> {
        // TODO: Add proper cost type once BN254 cost types are added to XDR
        // self.charge_budget(ContractCostType::Bn254G2ProjectiveToAffine, None)?;
        Ok(g2.into_affine())
    }

    pub(crate) fn bn254_g2_affine_serialize_uncompressed(
        &self,
        g2: &G2Affine,
    ) -> Result<BytesObject, HostError> {
        let mut buf = [0; G2_SERIALIZED_SIZE];
        // `CanonicalSerialization of Affine<P>` where `P` is `ark_bn254::curves::g2::Config`,
        // calls into `P::serialize_with_mode`.
        //
        // The output is in the following format:
        // `be_bytes(X_c1) || be_bytes(X_c0) || be_bytes(Y_c1) || be_bytes(Y_c0)`
        //
        // The most significant three bits of `X_c1` encodes the flags, i.e.
        // `bits(X_c1) = [compression_flag, infinity_flag, sort_flag, bit_3, .. bit_255]`
        //
        // This aligns with the standard serialization format
        self.bn254_serialize_uncompressed_into_slice::<G2_SERIALIZED_SIZE, _>(g2, &mut buf, "G2")?;
        self.add_host_object(self.scbytes_from_slice(&buf)?)
    }

    pub(crate) fn bn254_g2_projective_serialize_uncompressed(
        &self,
        g2: G2Projective,
    ) -> Result<BytesObject, HostError> {
        let g2_affine = self.bn254_g2_projective_into_affine(g2)?;
        self.bn254_g2_affine_serialize_uncompressed(&g2_affine)
    }

    pub(crate) fn bn254_fr_from_u256val(&self, sv: U256Val) -> Result<Fr, HostError> {
        self.charge_budget(ContractCostType::Bn254FrFromU256, None)?;
        let fr = if let Ok(small) = U256Small::try_from(sv) {
            Fr::from_le_bytes_mod_order(&u64::from(small).to_le_bytes())
        } else {
            let obj: U256Object = sv.try_into()?;
            self.visit_obj(obj, |u: &U256| {
                Ok(Fr::from_le_bytes_mod_order(&u.to_le_bytes()))
            })?
        };
        Ok(fr)
    }

    #[allow(dead_code)]
    pub(crate) fn bn254_field_element_deserialize<
        const EXPECTED_SIZE: usize,
        T: CanonicalDeserialize,
    >(
        &self,
        bo: BytesObject,
        tag: &str,
    ) -> Result<T, HostError> {
        self.visit_obj(bo, |bytes: &ScBytes| {
            if bytes.len() != EXPECTED_SIZE {
                return Err(self.err(
                    ScErrorType::Crypto,
                    ScErrorCode::InvalidInput,
                    format!(
                        "bn254 field element {}: invalid input length to deserialize",
                        tag
                    )
                    .as_str(),
                    &[
                        Val::from_u32(bytes.len() as u32).into(),
                        Val::from_u32(EXPECTED_SIZE as u32).into(),
                    ],
                ));
            }
            // TODO: Add proper cost type once BN254 cost types are added to XDR
            // self.charge_budget(ContractCostType::MemCpy, Some(EXPECTED_SIZE as u64))?;
            let mut buf = [0u8; EXPECTED_SIZE];
            buf.copy_from_slice(bytes);
            buf.reverse();

            // The field element here an either be a Fq<P, N=4> (base field
            // element) or QuadExtField<P> (quadratic extension)
            //
            // - `CanonicalDeserialize for Fq<P, N>` assumes input bytes in
            // little-endian order, with the highest (right-most) bits being
            // empty flags. This is reverse of our rule, which assumes
            // big-endian order with the highest (left-most) bits for flags.
            //
            // - `CanonicalDeserialize for QuadExtField<P>` reads the first
            // chunk, deserialize it into `Fq` as `c0`. Then repeat for `c1`. The
            // deserialization for `Fq` follows same rules as above, where the
            // bytes are expected in little-endian, with the highest bits being
            // empty flags. There is no check involved. This is entirely
            // reversed from our input format: `be_bytes(c1) || be_bytes(c0)` from
            // the standard serialization format
            //
            // In either case, we just need to reverse the input bytes before
            // passing them in. There is no other check for `Fq` besides the
            // length check, internally it makes sure `Fq` is valid integer
            // modulo `q` (the prime modulus)
            self.bn254_deserialize_uncompressed_no_validate::<EXPECTED_SIZE, _>(&buf, tag)
        })
    }

    #[allow(dead_code)]
    pub(crate) fn bn254_fp_deserialize_from_bytesobj(
        &self,
        bo: BytesObject,
    ) -> Result<Fq, HostError> {
        self.bn254_field_element_deserialize::<FP_SERIALIZED_SIZE, Fq>(bo, "Fp")
    }

    #[allow(dead_code)]
    pub(crate) fn bn254_fp2_deserialize_from_bytesobj(
        &self,
        bo: BytesObject,
    ) -> Result<Fq2, HostError> {
        self.bn254_field_element_deserialize::<FP2_SERIALIZED_SIZE, Fq2>(bo, "Fp2")
    }

    pub(crate) fn bn254_fr_vec_from_vecobj(&self, vs: VecObject) -> Result<Vec<Fr>, HostError> {
        let len: u32 = self.vec_len(vs)?.into();
        let mut scalars: Vec<Fr> = vec![];
        self.charge_budget(
            ContractCostType::MemAlloc,
            Some(len as u64 * FR_SERIALIZED_SIZE as u64),
        )?;
        scalars.reserve(len as usize);
        let _ = self.visit_obj(vs, |vs: &HostVec| {
            for s in vs.iter() {
                let ss = self.bn254_fr_from_u256val(U256Val::try_from_val(self, s)?)?;
                scalars.push(ss);
            }
            Ok(())
        })?;
        Ok(scalars)
    }

    pub(crate) fn bn254_g1_add_internal(
        &self,
        p0: G1Affine,
        p1: G1Affine,
    ) -> Result<G1Projective, HostError> {
        // TODO: Add proper cost type once BN254 cost types are added to XDR
        // self.charge_budget(ContractCostType::Bn254G1Add, None)?;
        Ok(p0.add(p1))
    }

    pub(crate) fn bn254_g1_mul_internal(
        &self,
        p0: G1Affine,
        scalar: Fr,
    ) -> Result<G1Projective, HostError> {
        // TODO: Add proper cost type once BN254 cost types are added to XDR
        // self.charge_budget(ContractCostType::Bn254G1Mul, None)?;
        Ok(p0.mul(scalar))
    }

    pub(crate) fn bn254_affine_vec_from_vecobj<const EXPECTED_SIZE: usize, P: SWCurveConfig>(
        &self,
        vp: VecObject,
        subgroup_check: bool,
        tag: &str,
    ) -> Result<Vec<Affine<P>>, HostError> {
        let len: u32 = self.vec_len(vp)?.into();
        self.charge_budget(
            ContractCostType::MemAlloc,
            Some(len as u64 * EXPECTED_SIZE as u64),
        )?;
        let mut points: Vec<Affine<P>> = Vec::with_capacity(len as usize);
        let _ = self.visit_obj(vp, |vp: &HostVec| {
            for p in vp.iter() {
                let pp = self.bn254_affine_deserialize::<EXPECTED_SIZE, P>(
                    BytesObject::try_from_val(self, p)?,
                    subgroup_check,
                    tag,
                )?;
                points.push(pp);
            }
            Ok(())
        })?;
        Ok(points)
    }

    pub(crate) fn bn254_checked_g1_vec_from_vecobj(
        &self,
        vp: VecObject,
    ) -> Result<Vec<G1Affine>, HostError> {
        self.bn254_affine_vec_from_vecobj::<G1_SERIALIZED_SIZE, G1Config>(vp, true, "G1")
    }

    pub(crate) fn bn254_checked_g2_vec_from_vecobj(
        &self,
        vp: VecObject,
    ) -> Result<Vec<G2Affine>, HostError> {
        self.bn254_affine_vec_from_vecobj::<G2_SERIALIZED_SIZE, G2Config>(vp, true, "G2")
    }

    pub(crate) fn bn254_g2_add_internal(
        &self,
        p0: G2Affine,
        p1: G2Affine,
    ) -> Result<G2Projective, HostError> {
        // TODO: Add proper cost type once BN254 cost types are added to XDR
        // self.charge_budget(ContractCostType::Bn254G2Add, None)?;
        Ok(p0.add(p1))
    }

    pub(crate) fn bn254_g2_mul_internal(
        &self,
        p0: G2Affine,
        scalar: Fr,
    ) -> Result<G2Projective, HostError> {
        // TODO: Add proper cost type once BN254 cost types are added to XDR
        // self.charge_budget(ContractCostType::Bn254G2Mul, None)?;
        Ok(p0.mul(scalar))
    }

    pub(crate) fn bn254_msm_internal<P: SWCurveConfig>(
        &self,
        points: &[Affine<P>],
        scalars: &[<P as CurveConfig>::ScalarField],
        tag: &str,
    ) -> Result<Projective<P>, HostError> {
        // TODO: Add proper cost type once BN254 cost types are added to XDR
        // self.charge_budget(*ty, Some(points.len() as u64))?;
        if points.len() != scalars.len() || points.len() == 0 {
            return Err(self.err(
                ScErrorType::Crypto,
                ScErrorCode::InvalidInput,
                format!(
                    "{tag} msm: invalid input vector lengths ({}, {})",
                    points.len(),
                    scalars.len()
                )
                .as_str(),
                &[],
            ));
        }
        // The actual logic happens inside msm_bigint_wnaf (ark_ec/variable_base/mod.rs)
        // under branch negation is cheap.
        // the unchecked version just skips the length equal check
        Ok(Projective::<P>::msm_unchecked(points, scalars))
    }

    pub(crate) fn bn254_pairing_internal(
        &self,
        vp1: &Vec<G1Affine>,
        vp2: &Vec<G2Affine>,
    ) -> Result<PairingOutput<Bn254>, HostError> {
        // TODO: Add proper cost type once BN254 cost types are added to XDR
        // self.charge_budget(ContractCostType::Bn254Pairing, Some(vp1.len() as u64))?;
        // check length requirements
        if vp1.len() != vp2.len() || vp1.len() == 0 {
            return Err(self.err(
                ScErrorType::Crypto,
                ScErrorCode::InvalidInput,
                format!(
                    "pairing: invalid input vector lengths ({}, {})",
                    vp1.len(),
                    vp2.len()
                )
                .as_str(),
                &[],
            ));
        }

        // This calls into `Bn254<Config>::multi_miller_loop`, which just calls
        // `ark_ec::models::bn::BnConfig::multi_miller_loop` with specific
        // parameters defined in `ark_bn254::curves`.
        //
        // Panic analysis:
        //
        // The following potential panic conditions could exist:
        // 1. if two input vector lengths are not equal. There is a `zip_eq`
        // which panics if the length of the two vectors are not equal. This is
        // weeded out up front.
        //
        // 2. `coeffs.next().unwrap()`. This occurs when the algorithm Loops
        // over pairs of `(a: G1Affine, b: G2Affine)`, converting them into
        // `Vec<(G1Prepared, G2Preared::EllCoeff<Config>)>`, the latter contains
        // three elements of Fq2. For each pair, the coeffs.next() can at most
        // be called twice, when the bit being looped over in `Config::X` is
        // set. So this panic cannot happen.
        //
        // 3. if any of the G1Affine point is infinity. The ell() function which
        // calls p.xy().unwrap(), which is when the point is infinity. This
        // condition also cannot happen because when the pairs are generated,
        // any pair containing a zero point is filtered.
        //
        // The above analysis is best effort to weed out panics from the source,
        // however the algorithm is quite involved. So we cannot be 100% certain
        // every panic condition has been excluded.
        let mlo = Bn254::multi_miller_loop(vp1, vp2);
        // final_exponentiation returning None means the `mlo.0.is_zero()`
        Bn254::final_exponentiation(mlo).ok_or_else(|| {
            self.err(
                ScErrorType::Crypto,
                ScErrorCode::InvalidInput,
                "final_exponentiation has failed, most likely multi_miller_loop produced infinity",
                &[],
            )
        })
    }

    pub(crate) fn bn254_check_pairing_output(
        &self,
        output: &PairingOutput<Bn254>,
    ) -> Result<Bool, HostError> {
        self.charge_budget(ContractCostType::MemCmp, Some(FP12_SERIALIZED_SIZE as u64))?;
        match output.0.cmp(&Fq12::ONE) {
            Ordering::Equal => Ok(true.into()),
            _ => Ok(false.into()),
        }
    }
}
