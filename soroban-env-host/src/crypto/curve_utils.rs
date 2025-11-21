use crate::{Host, HostError, Val, xdr::{ScErrorType, ScErrorCode, ContractCostType}};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

impl Host {
    pub(crate) fn field_element_deserialize<const EXPECTED_SIZE: usize, T: CanonicalDeserialize>(
        &self,
        input: &[u8],
        tag: &str,
    ) -> Result<T, HostError> {
        if EXPECTED_SIZE == 0 || input.len() != EXPECTED_SIZE {
            return Err(self.err(
                ScErrorType::Crypto,
                ScErrorCode::InvalidInput,
                format!(
                    "field element {}: invalid input length to deserialize",
                    tag
                )
                .as_str(),
                &[
                    Val::from_u32(input.len() as u32).into(),
                    Val::from_u32(EXPECTED_SIZE as u32).into(),
                ],
            ));
        }
        self.charge_budget(ContractCostType::MemCpy, Some(EXPECTED_SIZE as u64))?;
        let mut buf = [0u8; EXPECTED_SIZE];
        buf.copy_from_slice(input);
        buf.reverse();

        // The field element here an either be a Fp<P, N=6> (base field
        // element) or QuadExtField<P> (quadratic extension)
        //
        // - `CanonicalDeserialize for Fp<P, N>` assumes input bytes in
        // little-endian order, with the highest (right-most) bits being
        // empty flags. This is reverse of our rule, which assumes
        // big-endian order with the highest (left-most) bits for flags.
        //
        // - `CanonicalDeserialize for QuadExtField<P>` reads the first
        // chunk, deserialize it into `Fp` as `c0`. Then repeat for `c1`. The
        // deserialization for `Fp` follows same rules as above, where the
        // bytes are expected in little-endian, with the highest bits being
        // empty flags. There is no check involved. This is entirely
        // reversed from our input format: `be_bytes(c1) || be_bytes(c0)` from
        // [standard](https://github.com/zcash/librustzcash/blob/6e0364cd42a2b3d2b958a54771ef51a8db79dd29/pairing/src/bls12_381/README.md#serialization)
        //
        // In either case, we just need to reverse the input bytes before
        // passing them in. There is no other check for `Fp` besides the
        // length check, internally it makes sure `Fp` is valid integer
        // modulo `q` (the prime modulus)
        self.deserialize_uncompressed_no_validate::<EXPECTED_SIZE, _>(&buf, tag)
    }

    pub(crate) fn field_element_serialize<const EXPECTED_SIZE: usize, T: CanonicalSerialize>(
        &self,
        elem: T,
        buf: &mut [u8],
        tag: &str,
    ) -> Result<(), HostError> {
        if EXPECTED_SIZE == 0 || buf.len() != EXPECTED_SIZE {
            return Err(self.err(
                ScErrorType::Crypto,
                ScErrorCode::InvalidInput,
                format!("field element {tag}: invalid buffer length to serialize into").as_str(),
                &[
                    Val::from_u32(buf.len() as u32).into(),
                    Val::from_u32(EXPECTED_SIZE as u32).into(),
                ],
            ));
        }

        // TODO: handle metering

        elem.serialize_uncompressed(&mut *buf).map_err(|_e| {
            self.err(
                ScErrorType::Crypto,
                ScErrorCode::InternalError,
                format!("field element {tag}: unable to serialize").as_str(),
                &[],
            )
        })?;

        // the reverse here works for the same reason explained above
        buf.reverse();
        Ok(())
    }
}