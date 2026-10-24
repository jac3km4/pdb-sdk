use pdb_sdk::{Publics, StrBuf, StreamIndex, Strings, SymbolMap};

#[test]
fn stream_types_are_nameable_from_the_crate_root() {
    // Inferred return types alone would not catch accidentally private reexports.
    fn assert_public_type<T>() {
        let _ = std::mem::size_of::<T>();
    }

    assert_public_type::<Strings>();
    assert_public_type::<Publics>();
    assert_public_type::<SymbolMap>();
    assert_public_type::<StreamIndex>();
    assert_public_type::<StrBuf>();
}
