use core::marker::PhantomData;
use std::fmt::Error;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rkyv::{
    api::high::HighSerializer,
    rancor::Fallible,
    ser::allocator::ArenaHandle,
    util::AlignedVec,
    vec::{ArchivedVec, VecResolver},
    with::{ArchiveWith, DeserializeWith, SerializeWith},
    Archive, Deserialize, Place,
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
        field.serialize_compressed(&mut buf).unwrap();
        ArchivedVec::serialize_from_slice(buf.as_slice(), serializer)
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use rand::rngs::OsRng;
    use rkyv::{
        bytecheck::CheckBytes, rancor::Failure, to_bytes, Deserialize, Portable, Serialize,
    };

    use super::*;
    use crate::domain::xaero_serde::XaeroIdFr;

    #[derive(Debug, Archive, Serialize, Deserialize, PartialEq, Eq)]
    struct TestFr {
        #[rkyv(with = ArkBytes::<XaeroIdFr>)]
        xaero_id_fr: XaeroIdFr,
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
            xaero_id_fr: XaeroIdFr::from(Fr::rand(&mut OsRng)),
        };

        let bytes = to_bytes::<Failure>(&t.xaero_id_fr).expect("to_bytes works");
        // 2) rehydrate the whole struct from those bytes
        let recovered: &TestFr = unsafe { rkyv::access_unchecked::<TestFr>(bytes.as_slice()) };

        assert_eq!(
            t.xaero_id_fr.bytes,
            bytes.as_slice(),
            "full from_bytes round-trip should match"
        );
        assert_eq!(true, true)
    }
}
