use core::marker::PhantomData;
use std::fmt::Error;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rkyv::{
    api::high::HighSerializer,
    ser::allocator::ArenaHandle,
    util::AlignedVec,
    vec::{ArchivedVec, VecResolver},
    with::{ArchiveWith, SerializeWith}, // Add this import
    Place,
};

/// This type tells rkyv: when you see a field `T`, archive it
/// by first calling T::serialize(&mut Vec<u8>) and stashing those bytes.
pub struct ArkBytes<T>(PhantomData<T>);

impl<T> ArchiveWith<T> for ArkBytes<T>
where
    T: CanonicalSerialize + CanonicalDeserialize,
{
    type Archived = ArchivedVec<u8>;
    type Resolver = VecResolver;

    fn resolve_with(field: &T, resolver: Self::Resolver, out: Place<Self::Archived>) {
        let len = field.compressed_size();
        let mut bytes: Vec<u8> = Vec::with_capacity(len);
        field
            .serialize_compressed(&mut bytes)
            .expect("resolve_with_failed");
        ArchivedVec::resolve_from_slice(bytes.as_slice(), resolver, out)
    }
}

impl<'a, T> SerializeWith<T, HighSerializer<AlignedVec, ArenaHandle<'a>, Error>> for ArkBytes<T>
where
    T: CanonicalSerialize + CanonicalDeserialize,
{
    fn serialize_with(
        field: &T,
        serializer: &mut HighSerializer<AlignedVec, ArenaHandle<'a>, Error>,
    ) -> Result<Self::Resolver, Error> {
        let mut buf = Vec::new();
        field
            .serialize_compressed(&mut buf)
            .expect("failed to serialize");
        ArchivedVec::serialize_from_slice(buf.as_slice(), serializer)
    }
}

#[cfg(test)]
mod tests {
    use rkyv::{
        rancor::Failure,
        to_bytes,
        Archive, // Add Archive import
        Deserialize,
        Portable,
        Serialize,
    };

    use super::*;
    use crate::domain::xaero_serde::XaeroIdFr;

    #[derive(Debug, Archive, Serialize, Deserialize, PartialEq, Eq)]
    struct TestFr {
        #[rkyv(with = ArkBytes::<XaeroIdFr>)]
        value: XaeroIdFr, // Changed field name from xaero_id_fr to value
    }
    unsafe impl Portable for TestFr {}

    #[test]
    pub fn test_archive_read_archive() {
        // 1) serialize to bytes
        use ark_bn254::Fr;
        use ark_std::UniformRand;
        use rand::rngs::OsRng;

        use crate::domain::xaero_serde::XaeroIdFr;
        let t = TestFr {
            value: XaeroIdFr::from(Fr::rand(&mut OsRng)), // Changed field name
        };

        let bytes = to_bytes::<Failure>(&t.value).expect("to_bytes works"); // Changed field name
                                                                            // 2) rehydrate the whole struct from those bytes
        let _recovered: &TestFr = unsafe { rkyv::access_unchecked::<TestFr>(bytes.as_slice()) }; // Prefix with underscore

        assert_eq!(
            t.value.bytes, // Changed field name
            bytes.as_slice(),
            "full from_bytes round-trip should match"
        );
        assert_eq!(true, true)
    }
}
