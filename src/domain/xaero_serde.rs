use rkyv::{Archive, Deserialize, Serialize};

// Better approach for zero-copy
#[derive(Debug, Clone, Archive, Serialize, Deserialize, PartialEq, Eq)]
#[rkyv(derive(Debug))]
#[repr(C)]
pub struct XaeroIdFr {
    pub bytes: [u8; 32],
}

impl XaeroIdFr {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl From<ark_bn254::Fr> for XaeroIdFr {
    fn from(fr: ark_bn254::Fr) -> Self {
        use ark_ff::{BigInteger, PrimeField};

        let bigint = fr.into_bigint();
        let le_bytes = bigint.to_bytes_le();

        let mut bytes = [0u8; 32];
        let copy_len = le_bytes.len().min(32);
        bytes[..copy_len].copy_from_slice(&le_bytes[..copy_len]);

        XaeroIdFr { bytes }
    }
}

impl From<XaeroIdFr> for ark_bn254::Fr {
    fn from(xaero_fr: XaeroIdFr) -> Self {
        use ark_ff::PrimeField;
        ark_bn254::Fr::from_le_bytes_mod_order(&xaero_fr.bytes)
    }
}

// Zero-copy access from archived version
impl ArchivedXaeroIdFr {
    pub fn as_fr(&self) -> ark_bn254::Fr {
        use ark_ff::PrimeField;
        ark_bn254::Fr::from_le_bytes_mod_order(&self.bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}
use ark_bn254::Fr;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Valid,
};

impl CanonicalSerialize for XaeroIdFr {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.bytes.serialize_with_mode(writer, compress)
    }

    fn compressed_size(&self) -> usize {
        self.bytes.compressed_size()
    }

    fn uncompressed_size(&self) -> usize {
        self.bytes.uncompressed_size()
    }

    fn serialize_compressed<W: std::io::Write>(
        &self,
        writer: W,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.bytes.serialize_compressed(writer)
    }

    fn serialize_uncompressed<W: std::io::Write>(
        &self,
        writer: W,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.bytes.serialize_uncompressed(writer)
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.bytes.serialized_size(compress)
    }
}

impl Valid for XaeroIdFr {
    fn check(&self) -> Result<(), SerializationError> {
        self.bytes.check()
    }
}

impl CanonicalDeserialize for XaeroIdFr {
    fn deserialize_with_mode<R: std::io::Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let fr = Fr::deserialize_with_mode(reader, compress, validate)?;
        Ok(XaeroIdFr::from(fr))
    }

    fn deserialize_compressed<R: std::io::Read>(
        reader: R,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let fr = Fr::deserialize_compressed(reader)?;
        Ok(XaeroIdFr::from(fr))
    }

    fn deserialize_uncompressed<R: std::io::Read>(
        reader: R,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let fr = Fr::deserialize_uncompressed(reader)?;
        Ok(XaeroIdFr::from(fr))
    }

    fn deserialize_compressed_unchecked<R: std::io::Read>(
        reader: R,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let fr = Fr::deserialize_compressed_unchecked(reader)?;
        Ok(XaeroIdFr::from(fr))
    }

    fn deserialize_uncompressed_unchecked<R: std::io::Read>(
        reader: R,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let fr = Fr::deserialize_uncompressed_unchecked(reader)?;
        Ok(XaeroIdFr::from(fr))
    }
}

#[cfg(test)]
mod tests {
    use ark_std::{test_rng, UniformRand};
    use rkyv::rancor::Failure;

    use super::*;

    #[test]
    fn test_compilation() {
        let mut rng = test_rng();
        let fr = ark_bn254::Fr::rand(&mut rng);
        let xaero_fr = XaeroIdFr::from(fr);
        let restored_fr = ark_bn254::Fr::from(xaero_fr);
        assert_eq!(fr, restored_fr);
    }

    #[test]
    fn test_rkyv_serialization() {
        let mut rng = test_rng();
        let fr = ark_bn254::Fr::rand(&mut rng);
        let xaero_fr = XaeroIdFr::from(fr);

        // Serialize with rkyv
        let bytes = rkyv::to_bytes::<Failure>(&xaero_fr).expect("failed_to_unravel");

        // Zero-copy access
        let archived =
            rkyv::access::<ArchivedXaeroIdFr, Failure>(&bytes).expect("failed_to_unravel");
        let restored_fr = archived.as_fr();

        assert_eq!(fr, restored_fr);
    }
}
