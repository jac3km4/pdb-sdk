//! Offline compatibility tests. Expectations are extracted by LLVM, not pdb-sdk.
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use pdb_sdk::codeview::symbols::SymbolRecord;
use pdb_sdk::codeview::types::{IdRecord, TypeRecord};
use pdb_sdk::{IdIndex, Integer, PdbFile, TypeIndex};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: u32,
    fixtures: Vec<Fixture>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    id: String,
    file: String,
    sha256: String,
    source: String,
    source_sha256: String,
    license: String,
    compiler: String,
    linker: String,
    compile_args: Vec<String>,
    link_args: Vec<String>,
    reference_tool: String,
    reference_args: Vec<String>,
    machine: String,
    type_kinds: BTreeMap<String, usize>,
    id_kinds: BTreeMap<String, usize>,
    public_names: Vec<String>,
    module_count: usize,
    struct_anchor: StructAnchor,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StructAnchor {
    name: String,
    size: i128,
    members: BTreeMap<String, i128>,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus")
}

fn manifest() -> Result<Manifest> {
    let manifest: Manifest = serde_json::from_slice(&fs::read(root().join("manifest.json"))?)?;
    ensure!(manifest.schema == 1, "unsupported corpus schema");
    ensure!(!manifest.fixtures.is_empty(), "empty corpus");
    Ok(manifest)
}

fn local_file(name: &str) -> Result<PathBuf> {
    ensure!(
        !name.is_empty()
            && Path::new(name)
                .components()
                .all(|part| matches!(part, Component::Normal(_))),
        "fixture paths must remain inside the corpus: {name}"
    );
    Ok(root().join(name))
}

fn verified_bytes(name: &str, expected: &str) -> Result<Vec<u8>> {
    let bytes =
        fs::read(local_file(name)?).with_context(|| format!("missing corpus file {name}"))?;
    let actual = format!("{:x}", Sha256::digest(&bytes));
    ensure!(
        actual == expected,
        "SHA-256 mismatch for {name}: expected {expected}, got {actual}"
    );
    Ok(bytes)
}

#[test]
fn corpus_integrity_and_provenance() -> Result<()> {
    let manifest = manifest()?;
    let mut ids = BTreeSet::new();
    let mut files = BTreeSet::new();
    for fixture in &manifest.fixtures {
        ensure!(ids.insert(&fixture.id), "duplicate ID {}", fixture.id);
        ensure!(files.insert(fixture.file.clone()), "duplicate fixture file");
        verified_bytes(&fixture.file, &fixture.sha256)?;
        verified_bytes(&fixture.source, &fixture.source_sha256)?;
        for value in [
            &fixture.license,
            &fixture.compiler,
            &fixture.linker,
            &fixture.reference_tool,
        ] {
            ensure!(
                !value.trim().is_empty(),
                "{}: missing provenance",
                fixture.id
            );
        }
        ensure!(
            !fixture.compile_args.is_empty()
                && !fixture.link_args.is_empty()
                && !fixture.reference_args.is_empty()
        );
        ensure!(
            !fixture.type_kinds.is_empty()
                && !fixture.id_kinds.is_empty()
                && !fixture.public_names.is_empty()
        );
    }
    let actual = fs::read_dir(root())?
        .map(|entry| Ok(entry?.path()))
        .collect::<io::Result<Vec<_>>>()?
        .into_iter()
        .filter(|path| path.extension().is_some_and(|extension| extension == "pdb"))
        .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
        .collect::<BTreeSet<_>>();
    ensure!(
        actual == files,
        "every corpus PDB must be registered in manifest.json"
    );
    Ok(())
}

#[test]
fn truncated_and_wrong_format_containers_are_rejected() -> Result<()> {
    for fixture in manifest()?.fixtures {
        let bytes = verified_bytes(&fixture.file, &fixture.sha256)?;
        for length in [0, 1, 31, 32, 55, 56, bytes.len() / 2, bytes.len() - 1] {
            ensure!(
                PdbFile::open(Cursor::new(&bytes[..length])).is_err(),
                "{}: accepted truncated container of {length} bytes",
                fixture.id
            );
        }
        let mut wrong_magic = bytes;
        wrong_magic[0] ^= 0xff;
        ensure!(
            PdbFile::open(Cursor::new(wrong_magic)).is_err(),
            "{}: accepted invalid magic",
            fixture.id
        );
    }
    // Portable PDB metadata starts with BSJB, not the native MSF signature.
    ensure!(PdbFile::open(Cursor::new(b"BSJB".as_slice())).is_err());
    Ok(())
}

struct ReadMeter<R> {
    inner: R,
    bytes_read: usize,
}
impl<R: Read> Read for ReadMeter<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buffer)?;
        self.bytes_read += count;
        Ok(count)
    }
}
impl<R: Seek> Seek for ReadMeter<R> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.inner.seek(position)
    }
}

#[test]
fn opening_reads_metadata_not_the_entire_file() -> Result<()> {
    for fixture in manifest()?.fixtures {
        let bytes = verified_bytes(&fixture.file, &fixture.sha256)?;
        let mut meter = ReadMeter {
            inner: Cursor::new(&bytes),
            bytes_read: 0,
        };
        let pdb = PdbFile::open(&mut meter)?;
        drop(pdb);
        ensure!(
            meter.bytes_read < bytes.len() / 4,
            "{}: opening read {} of {} bytes",
            fixture.id,
            meter.bytes_read,
            bytes.len()
        );
    }
    Ok(())
}

fn type_kind(record: &TypeRecord) -> &'static str {
    match record {
        TypeRecord::ArgList { .. } => "LF_ARGLIST",
        TypeRecord::Array { .. } => "LF_ARRAY",
        TypeRecord::Enum(_) => "LF_ENUM",
        TypeRecord::FieldList { .. } => "LF_FIELDLIST",
        TypeRecord::Modifier { .. } => "LF_MODIFIER",
        TypeRecord::Pointer { .. } => "LF_POINTER",
        TypeRecord::Procedure { .. } => "LF_PROCEDURE",
        TypeRecord::Struct(_) => "LF_STRUCTURE",
        TypeRecord::Union(_) => "LF_UNION",
        TypeRecord::Class(_) => "LF_CLASS",
        TypeRecord::Interface(_) => "LF_INTERFACE",
        TypeRecord::Class2(_) => "LF_CLASS2",
        TypeRecord::Struct2(_) => "LF_STRUCTURE2",
        TypeRecord::Interface2(_) => "LF_INTERFACE2",
        TypeRecord::MemberFunction { .. } => "LF_MFUNCTION",
        TypeRecord::Label(_) => "LF_LABEL",
        TypeRecord::TypeServer2 { .. } => "LF_TYPESERVER2",
        TypeRecord::VFTable { .. } => "LF_VFTABLE",
        TypeRecord::VfTableShape(_) => "LF_VTSHAPE",
        TypeRecord::BitField { .. } => "LF_BITFIELD",
        TypeRecord::BaseClass(_) => "LF_BCLASS",
        TypeRecord::BaseInterface(_) => "LF_BINTERFACE",
        TypeRecord::VirtualBaseClass(_) => "LF_VBCLASS",
        TypeRecord::IndirectVirtualBaseClass(_) => "LF_IVBCLASS",
        TypeRecord::VFPtr { .. } => "LF_VFUNCTAB",
        TypeRecord::StaticDataMember { .. } => "LF_STMEMBER",
        TypeRecord::OverloadedMethod { .. } => "LF_METHOD",
        TypeRecord::DataMember { .. } => "LF_MEMBER",
        TypeRecord::NestedType { .. } => "LF_NESTTYPE",
        TypeRecord::OneMethod { .. } => "LF_ONEMETHOD",
        TypeRecord::Enumerator { .. } => "LF_ENUMERATE",
        TypeRecord::ListContinuation(_) => "LF_INDEX",
        TypeRecord::MethodList { .. } => "LF_METHODLIST",
    }
}

fn id_kind(record: &IdRecord) -> &'static str {
    match record {
        IdRecord::FuncId { .. } => "LF_FUNC_ID",
        IdRecord::MemberFuncId { .. } => "LF_MFUNC_ID",
        IdRecord::BuildInfo { .. } => "LF_BUILDINFO",
        IdRecord::StringList { .. } => "LF_SUBSTR_LIST",
        IdRecord::StringId { .. } => "LF_STRING_ID",
        IdRecord::UdtSourceLine { .. } => "LF_UDT_SRC_LINE",
        IdRecord::UdtModSourceLine { .. } => "LF_UDT_MOD_SRC_LINE",
    }
}

fn integer(value: &Integer) -> i128 {
    match *value {
        Integer::I16(value) => value.into(),
        Integer::I32(value) => value.into(),
        Integer::I64(value) => value.into(),
        Integer::U8(value) => value.into(),
        Integer::U16(value) => value.into(),
        Integer::U32(value) => value.into(),
        Integer::U64(value) => value.into(),
    }
}

/// Short reads are legal even for files. Test the same semantics without assuming
/// the underlying reader fills buffers or that streams are read in a fixed order.
struct ShortReader<R>(R);
impl<R: Read> Read for ShortReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let length = buffer.len().min(7);
        self.0.read(&mut buffer[..length])
    }
}
impl<R: Seek> Seek for ShortReader<R> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.0.seek(position)
    }
}

fn walk<R: Read + Seek>(reader: R, fixture: &Fixture, reverse: bool) -> Result<()> {
    let mut pdb = PdbFile::open(reader).context("open")?;
    // Deliberately interleave getters that share the underlying seekable reader.
    let ipi = pdb.get_ipi().context("IPI")?;
    let dbi = pdb.get_dbi().context("DBI")?;
    let tpi = pdb.get_tpi().context("TPI")?;
    let info = pdb.get_info().context("Info")?;
    ensure!(
        format!("{:?}", dbi.header().machine_type) == fixture.machine,
        "machine type"
    );
    ensure!(
        dbi.header().age == info.header().age,
        "DBI/Info age mismatch"
    );
    pdb.get_strings(&info).context("/names")?;
    pdb.get_globals(&dbi).context("globals")?;
    let publics = pdb.get_publics(&dbi).context("publics")?;
    ensure!(
        publics.address_map().len() == fixture.public_names.len(),
        "public address count"
    );
    let symbols = pdb.get_symbols(&dbi).context("symbols")?;
    let public_names = symbols
        .records()
        .iter()
        .filter_map(|record| match record {
            SymbolRecord::Public32(public) => Some(public.name.as_ref()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    ensure!(
        public_names == fixture.public_names.iter().map(String::as_str).collect(),
        "public names: {public_names:?}"
    );
    let sections = pdb.get_section_headers(&dbi).context("sections")?;
    ensure!(!sections.headers().is_empty(), "missing image sections");

    let mut kinds = BTreeMap::new();
    let first = u32::from(tpi.header().type_index_begin);
    ensure!(u32::from(tpi.header().type_index_end) - first == tpi.records().len() as u32);
    for (offset, record) in tpi.records().iter().enumerate() {
        *kinds.entry(type_kind(record).to_owned()).or_insert(0) += 1;
        ensure!(std::ptr::eq(
            tpi.record(
                TypeIndex::try_from(first + offset as u32)
                    .map_err(|_| anyhow::anyhow!("zero type index"))?
            )
            .unwrap(),
            record
        ));
    }
    ensure!(kinds == fixture.type_kinds, "TPI kinds: {kinds:?}");
    let mut kinds = BTreeMap::new();
    let first = u32::from(ipi.header().type_index_begin);
    for (offset, record) in ipi.records().iter().enumerate() {
        *kinds.entry(id_kind(record).to_owned()).or_insert(0) += 1;
        ensure!(std::ptr::eq(
            ipi.record(
                IdIndex::try_from(first + offset as u32)
                    .map_err(|_| anyhow::anyhow!("zero ID index"))?
            )
            .unwrap(),
            record
        ));
    }
    ensure!(kinds == fixture.id_kinds, "IPI kinds: {kinds:?}");

    // Source-level anchors complement LLVM's record-kind counts. In particular,
    // forward declarations alone must not satisfy these checks.
    let sample = tpi
        .records()
        .iter()
        .find_map(|record| match record {
            TypeRecord::Struct(record)
                if record.name.as_ref() == fixture.struct_anchor.name
                    && !record.properties.is_forward_ref() =>
            {
                Some(record)
            }
            _ => None,
        })
        .with_context(|| format!("complete {} struct", fixture.struct_anchor.name))?;
    ensure!(usize::from(sample.member_count) == fixture.struct_anchor.members.len());
    ensure!(
        integer(&sample.size) == fixture.struct_anchor.size,
        "struct size"
    );
    let fields = tpi
        .record(sample.field_list.context("Sample field list index")?)
        .context("Sample field list")?;
    let TypeRecord::FieldList { fields } = fields else {
        bail!("Sample does not reference a field list")
    };
    let members = fields
        .iter()
        .map(|field| match field {
            TypeRecord::DataMember { name, offset, .. } => {
                Ok((name.as_ref().to_owned(), integer(offset)))
            }
            other => bail!("unexpected struct member {other:?}"),
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    ensure!(
        members == fixture.struct_anchor.members,
        "struct members: {members:?}"
    );
    let hash = pdb.get_tpi_hash(&tpi).context("TPI hash")?;
    ensure!(
        hash.get_index(&fixture.struct_anchor.name)
            .and_then(|index| tpi.record(index))
            .is_some(),
        "Sample hash lookup"
    );
    pdb.get_tpi_hash(&ipi).context("IPI hash")?;
    // DBI slots 0 and 9 are FPO and NewFPO; absent slots must report absence,
    // not be silently swallowed along with malformed present streams.
    let present = |slot| {
        dbi.dbg_streams()
            .get(slot)
            .is_some_and(|index| u16::from(*index) != u16::MAX)
    };
    if present(0) {
        pdb.get_fpo(&dbi).context("FPO")?;
    } else {
        ensure!(matches!(
            pdb.get_fpo(&dbi),
            Err(pdb_sdk::result::Error::StreamNotFound(_))
        ));
    }
    if present(9) {
        pdb.get_frame_data(&dbi).context("frame data")?;
    } else {
        ensure!(matches!(
            pdb.get_frame_data(&dbi),
            Err(pdb_sdk::result::Error::StreamNotFound(_))
        ));
    }

    ensure!(dbi.modules().len() == fixture.module_count, "module count");
    let modules: Vec<_> = if reverse {
        dbi.modules().iter().rev().collect()
    } else {
        dbi.modules().iter().collect()
    };
    let mut symbol_count = 0;
    let mut subsection_count = 0;
    for module in modules {
        let decoded = pdb
            .get_module(module)
            .with_context(|| format!("module {:?}", module.module_name))?;
        symbol_count += decoded.symbols().len();
        for entry in decoded.c13_records() {
            entry
                .decoded()
                .with_context(|| format!("C13 {:?}", entry.record_type))?;
            subsection_count += 1;
        }
    }
    ensure!(
        symbol_count > 0 && subsection_count > 0,
        "module traversal must exercise symbols and C13"
    );
    // Re-read after visiting every module: no stale stream position may leak.
    ensure!(pdb.get_tpi()?.records().len() == tpi.records().len());
    ensure!(pdb.get_symbols(&dbi)?.records().len() == symbols.records().len());
    ensure!(pdb.get_info()?.header().age == info.header().age);
    Ok(())
}

#[test]
fn external_producer_compatibility() -> Result<()> {
    let mut failures = Vec::new();
    for fixture in manifest()?.fixtures {
        let result = (|| {
            let bytes = verified_bytes(&fixture.file, &fixture.sha256)?;
            walk(Cursor::new(&bytes), &fixture, false)?;
            walk(ShortReader(Cursor::new(&bytes)), &fixture, true)
        })();
        if let Err(error) = result {
            failures.push(format!("{}: {error:#}", fixture.id));
        }
    }
    ensure!(
        failures.is_empty(),
        "corpus failures:\n{}",
        failures.join("\n")
    );
    Ok(())
}
