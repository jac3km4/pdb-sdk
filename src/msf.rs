//! MSF 7.0 block layout and logical stream I/O.
//!
//! Stream bytes may cross noncontiguous blocks; positions are logical byte
//! offsets, independent of physical file offsets and final-block padding.
//! See LLVM's [MSF guide](https://llvm.org/docs/PDB/MsfFile.html).

use std::fmt;
use std::io::{self, Read};

use declio::{Decode, Encode, EncodedSize, magic_bytes};

use crate::result::Result;
use crate::{BufMsfStream, constants};

pub(crate) const DEFAULT_BLOCK_SIZE: u32 = 4096;
pub(crate) const EMPTY_BLOCK: &[u8] = &[0; DEFAULT_BLOCK_SIZE as usize];
pub(crate) const FULL_BLOCK: &[u8] = &[0xff; DEFAULT_BLOCK_SIZE as usize];

magic_bytes! {
    #[derive(Debug)]
    pub(crate) MsfHeader(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0");
}

#[derive(Debug, Encode, Decode)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub(crate) struct SuperBlock {
    pub magic: MsfHeader,
    pub block_size: u32,
    pub free_block_map_block: u32,
    pub num_blocks: u32,
    pub num_dir_bytes: u32,
    pub unknown: u32,
    pub block_map_addr: BlockIndex,
}

impl SuperBlock {
    /// Gets the absolute byte offset of the block map.
    pub fn block_map_offset(&self) -> u64 {
        self.block_map_addr.to_file_pos(self.block_size)
    }

    pub fn validate(&self, file_len: u64) -> Result<()> {
        let invalid = |message| io::Error::new(io::ErrorKind::InvalidData, message);
        if !matches!(
            self.block_size,
            512 | 1024 | 2048 | 4096 | 8192 | 16384 | 32768
        ) {
            return Err(invalid("unsupported MSF block size").into());
        }
        if u64::from(self.num_blocks) * u64::from(self.block_size) > file_len {
            return Err(invalid("MSF file is shorter than its declared block count").into());
        }
        if !matches!(self.free_block_map_block, 1 | 2)
            || self.free_block_map_block >= self.num_blocks
            || self.block_map_addr.0 >= self.num_blocks
        {
            return Err(invalid("invalid MSF metadata block reference").into());
        }
        if self.num_dir_bytes < 4
            || u64::from(self.block_map_blocks()) * 4 > u64::from(self.block_size)
        {
            return Err(invalid("invalid MSF directory size").into());
        }
        Ok(())
    }

    /// Returns the number of directory blocks listed in the block-map block.
    pub fn block_map_blocks(&self) -> u32 {
        self.num_dir_bytes.div_ceil(self.block_size)
    }
}

#[derive(Debug, Default)]
pub(crate) struct MsfStreamLayout {
    pub blocks: Vec<BlockIndex>,
    pub byte_size: u32,
}

impl MsfStreamLayout {
    /// Creates a new MSF stream layout.
    pub fn new(blocks: Vec<BlockIndex>, byte_size: u32) -> Self {
        Self { blocks, byte_size }
    }
}

/// A logical view bounded by the directory's stream size, excluding block padding.
#[derive(Debug)]
pub(crate) struct MsfStream<'a, R> {
    layout: &'a MsfStreamLayout,
    inner: R,
    position: u64,
    block_size: u32,
}

impl<'a, R> MsfStream<'a, R> {
    /// Creates a new reader for an MSF stream given its layout and block size.
    pub fn new(inner: R, layout: &'a MsfStreamLayout, block_size: u32) -> Self {
        Self {
            inner,
            layout,
            position: 0,
            block_size,
        }
    }

    /// Returns the length of the stream in bytes.
    pub fn length(&self) -> u32 {
        self.layout.byte_size
    }

    /// Returns whether the stream has reached the end of file.
    pub fn is_eof(&self) -> bool {
        self.position >= u64::from(self.layout.byte_size)
    }
}

impl<'a, R> io::Read for MsfStream<'a, R>
where
    R: io::Read + io::Seek,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.is_eof() {
            return Ok(0);
        }
        let block_size = u64::from(self.block_size);
        if block_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "zero MSF block size",
            ));
        }
        let cur = self.position / block_size;
        let offset = self.position % block_size;
        let block = self.layout.blocks.get(cur as usize).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing MSF stream block")
        })?;
        self.inner.seek(io::SeekFrom::Start(
            block.to_file_pos(self.block_size) + offset,
        ))?;
        let rem_stream = u64::from(self.layout.byte_size) - self.position;
        let len = rem_stream.min(block_size - offset).min(buf.len() as u64) as usize;
        let read = self.inner.read(&mut buf[..len])?;
        self.position += read as u64;
        Ok(read)
    }
}

impl<'a, R> io::Seek for MsfStream<'a, R>
where
    R: io::Seek,
{
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let target = match pos {
            io::SeekFrom::Start(pos) => Some(pos),
            io::SeekFrom::End(offset) => {
                u64::from(self.layout.byte_size).checked_add_signed(offset)
            }
            io::SeekFrom::Current(offset) => self.position.checked_add_signed(offset),
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid MSF seek target"))?;
        if self.block_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "zero MSF block size",
            ));
        }
        if target < u64::from(self.layout.byte_size) {
            let cur = (target / u64::from(self.block_size)) as usize;
            let block = self.layout.blocks.get(cur).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing MSF stream block")
            })?;
            let offset = target % u64::from(self.block_size);
            self.inner.seek(io::SeekFrom::Start(
                block.to_file_pos(self.block_size) + offset,
            ))?;
        }
        self.position = target;
        Ok(target)
    }
}

pub(crate) type DefaultMsfStreamWriter<'a, S> = MsfStreamWriter<'a, S, DEFAULT_BLOCK_SIZE>;

pub(crate) struct MsfStreamWriter<'a, S, const BLOCK_SIZE: u32> {
    sink: &'a mut S,
    blocks: Vec<BlockIndex>,
    position: u32,
}

impl<'a, S, const BLOCK_SIZE: u32> MsfStreamWriter<'a, S, BLOCK_SIZE> {
    /// Creates a new MSF stream writer.
    pub fn new(sink: &'a mut S) -> io::Result<Self> {
        let res = Self {
            sink,
            blocks: vec![],
            position: 0,
        };
        Ok(res)
    }

    /// Gets the current byte position within the stream.
    pub fn position(&self) -> u32 {
        self.position
    }

    fn advance_block(&mut self) -> io::Result<()>
    where
        S: io::Write + io::Seek,
    {
        let position = self.sink.stream_position()?;
        let block_index = position as u32 / BLOCK_SIZE;
        let cur_block = if block_index % BLOCK_SIZE == 1 {
            // skip two FPM blocks
            self.sink.write_all(FULL_BLOCK)?;
            self.sink.write_all(FULL_BLOCK)?;
            BlockIndex(block_index + 2)
        } else {
            BlockIndex(block_index)
        };
        self.blocks.push(cur_block);
        Ok(())
    }

    /// Finishes writing the stream, padding the final block to block boundaries, and returns the layout.
    pub fn finish(self) -> io::Result<MsfStreamLayout>
    where
        S: io::Write + io::Seek,
    {
        let rem = (BLOCK_SIZE - self.position % BLOCK_SIZE) % BLOCK_SIZE;
        self.sink.write_all(&EMPTY_BLOCK[..rem as usize])?;

        Ok(MsfStreamLayout::new(self.blocks, self.position))
    }
}

impl<'a, W, const BLOCK_SIZE: u32> io::Write for MsfStreamWriter<'a, W, BLOCK_SIZE>
where
    W: io::Write + io::Seek,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let index_in_block = self.position % BLOCK_SIZE;
        if index_in_block == 0 && !buf.is_empty() {
            self.advance_block()?;
        }

        let rem = BLOCK_SIZE - self.position % BLOCK_SIZE;
        let len = rem.min(buf.len() as u32);

        let read = self.sink.write(&buf[..len as usize])?;
        self.position += read as u32;
        Ok(read)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sink.flush()
    }
}

#[derive(Debug)]
pub(crate) struct FreeBlockMap(#[allow(unused)] Vec<u8>);

impl FreeBlockMap {
    /// Calculates the stream layout for the Free Block Map.
    pub fn layout(main: &SuperBlock) -> MsfStreamLayout {
        let intervals = main.num_blocks.div_ceil(8 * main.block_size);
        let byte_size = main.num_blocks.div_ceil(8);
        let mut blocks = Vec::with_capacity(intervals as usize);
        let mut fpm_block = main.free_block_map_block;
        for _ in 0..intervals {
            blocks.push(BlockIndex(fpm_block));
            fpm_block += main.block_size;
        }
        MsfStreamLayout { blocks, byte_size }
    }

    /// Writes the free block map to the sink.
    pub fn write<S>(main: &SuperBlock, sink: &mut S) -> Result<()>
    where
        S: io::Write + io::Seek,
    {
        // assumes every block in the file is used and unset each bit accordingly
        let layout = Self::layout(main);
        let mut bit = 0;
        for block in layout.blocks {
            sink.seek(io::SeekFrom::Start(block.to_file_pos(main.block_size)))?;
            let available = (main.num_blocks - bit).min(main.block_size * 8);
            for _ in 0..available / 8 {
                sink.write_all(&[0x00])?;
                bit += 8;
            }

            if !available.is_multiple_of(8) {
                let mut byte = 0;
                for i in 0..available % 8 {
                    byte |= 1 << i;
                }
                sink.write_all(&[!byte])?;
                break;
            }
        }
        Ok(())
    }

    #[allow(unused)]
    /// Reads the free block map from the MSF stream.
    pub fn read<R>(mut inner: BufMsfStream<'_, R>) -> Result<FreeBlockMap>
    where
        R: io::Read + io::Seek,
    {
        let mut buf = Vec::with_capacity(inner.get_ref().length() as usize);
        inner.read_to_end(&mut buf)?;
        Ok(FreeBlockMap(buf))
    }
}

#[derive(Debug, Clone, Copy, Encode, Decode)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub(crate) struct BlockIndex(pub u32);

impl BlockIndex {
    #[inline]
    fn to_file_pos(self, block_size: u32) -> u64 {
        self.0 as u64 * block_size as u64
    }
}

#[derive(Clone, Copy, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
/// A 16-bit MSF stream reference used by PDB records.
///
/// `0xffff` denotes an absent stream in fields that permit it. This is a stream
/// number, not a block number or a byte offset.
pub struct StreamIndex(pub(crate) u16);

impl fmt::Debug for StreamIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<StreamIndex> for u16 {
    fn from(idx: StreamIndex) -> Self {
        idx.0
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

    use super::{
        BlockIndex, DEFAULT_BLOCK_SIZE, DefaultMsfStreamWriter, MsfStream, MsfStreamLayout,
    };

    struct LimitedReader {
        inner: Cursor<Vec<u8>>,
        max_read: usize,
        fail_next_seek: bool,
    }

    impl Read for LimitedReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let len = buf.len().min(self.max_read);
            self.inner.read(&mut buf[..len])
        }
    }

    impl Seek for LimitedReader {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            let position = self.inner.seek(pos)?;
            if std::mem::take(&mut self.fail_next_seek) {
                return Err(io::Error::other("injected seek failure"));
            }
            Ok(position)
        }
    }

    fn patterned_bytes(len: usize) -> Vec<u8> {
        (0..len).map(|index| (index % 251) as u8).collect()
    }

    fn fragmented_bytes(payload: &[u8], block_size: usize) -> (Vec<u8>, MsfStreamLayout) {
        let blocks: Vec<_> = [7, 2, 9, 4]
            .into_iter()
            .take(payload.len().div_ceil(block_size))
            .map(BlockIndex)
            .collect();
        // Poison gaps and padding so a physical overread cannot match the payload.
        let mut bytes = vec![0xa5; 10 * block_size];
        for (chunk, block) in payload.chunks(block_size).zip(&blocks) {
            let start = block.0 as usize * block_size;
            bytes[start..start + chunk.len()].copy_from_slice(chunk);
        }
        (bytes, MsfStreamLayout::new(blocks, payload.len() as u32))
    }

    #[test]
    fn discontiguous_stream_matches_cursor_model() {
        for block_size in [512, 1024, 2048, 4096, 8192, 16384, 32768] {
            let bs = block_size as usize;
            for len in [0, 1, bs - 1, bs, bs + 1, 2 * bs, 3 * bs + 17] {
                let expected = patterned_bytes(len);
                let (physical, layout) = fragmented_bytes(&expected, bs);
                for max_read in [usize::MAX, 1, 7, bs - 1] {
                    let inner = LimitedReader {
                        inner: Cursor::new(physical.clone()),
                        max_read,
                        fail_next_seek: false,
                    };
                    let mut stream = MsfStream::new(inner, &layout, block_size);
                    let mut model = Cursor::new(expected.as_slice());
                    for start in [0, bs - 1, bs, len, len + 3] {
                        let context =
                            format!("block={bs}, len={len}, max_read={max_read}, start={start}");
                        stream.seek(SeekFrom::Start(start as u64)).unwrap();
                        model.set_position(start as u64);
                        assert_eq!(stream.read(&mut []).unwrap(), 0);
                        let mut actual = vec![0xcc; bs + 3];
                        let count = stream.read(&mut actual).unwrap();
                        let available = len.saturating_sub(start).min(actual.len());
                        assert!(count <= available, "{context}");
                        assert_eq!(count == 0, available == 0, "{context}");
                        // Short reads are legal; compare exactly the returned prefix.
                        let mut wanted = vec![0xcc; actual.len()];
                        model.read_exact(&mut wanted[..count]).unwrap();
                        assert_eq!(actual, wanted, "{context}");
                        assert_eq!(
                            stream.stream_position().unwrap(),
                            model.position(),
                            "{context}"
                        );
                        assert_eq!(stream.is_eof(), model.position() >= len as u64, "{context}");

                        let mut actual = Vec::new();
                        let mut wanted = Vec::new();
                        assert_eq!(
                            stream.read_to_end(&mut actual).unwrap(),
                            model.read_to_end(&mut wanted).unwrap(),
                            "{context}"
                        );
                        assert_eq!(actual, wanted, "{context}");
                        assert_eq!(
                            stream.stream_position().unwrap(),
                            model.position(),
                            "{context}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn seeks_match_cursor_and_preserve_position_on_error() {
        let (bytes, layout) = fragmented_bytes(b"abcdef", 4);
        let mut stream = MsfStream::new(Cursor::new(bytes), &layout, 4);
        let mut model = Cursor::new(b"abcdef");
        for target in [
            SeekFrom::End(-3),
            SeekFrom::Current(-1),
            SeekFrom::End(3),
            SeekFrom::End(-7),
            SeekFrom::Current(i64::MIN),
            SeekFrom::Start(u64::MAX),
            SeekFrom::Current(1),
            SeekFrom::Current(i64::MIN),
            SeekFrom::Current(i64::MAX),
            SeekFrom::Start(0),
        ] {
            assert_eq!(
                stream.seek(target).map_err(|e| e.kind()),
                model.seek(target).map_err(|e| e.kind()),
                "{target:?}"
            );
            assert_eq!(
                stream.stream_position().unwrap(),
                model.position(),
                "{target:?}"
            );
        }
    }

    #[test]
    fn failed_underlying_seek_preserves_logical_position() {
        let layout = MsfStreamLayout::new(vec![BlockIndex(3), BlockIndex(1)], 7);
        let inner = LimitedReader {
            inner: Cursor::new(b"----efg-----abcd".to_vec()),
            max_read: 2,
            fail_next_seek: false,
        };
        let mut stream = MsfStream::new(inner, &layout, 4);
        stream.seek(SeekFrom::Start(2)).unwrap();
        stream.inner.fail_next_seek = true;
        assert_eq!(
            stream.seek(SeekFrom::Start(5)).unwrap_err().kind(),
            io::ErrorKind::Other
        );
        assert_eq!(stream.position, 2);
        let mut bytes = [0; 3];
        stream.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"cde");
        assert_eq!(stream.position, 5);

        stream.inner.fail_next_seek = true;
        assert!(stream.read(&mut bytes).is_err());
        assert_eq!(stream.position, 5);
        stream.read_exact(&mut bytes[..2]).unwrap();
        assert_eq!(&bytes[..2], b"fg");
        assert_eq!(stream.position, 7);
    }

    fn write_in_chunks(
        payload: &[u8],
        chunk_size: usize,
        start_block: usize,
    ) -> (Vec<u8>, MsfStreamLayout) {
        let bs = DEFAULT_BLOCK_SIZE as usize;
        let mut sink = Cursor::new(vec![0xa5; start_block * bs]);
        sink.set_position((start_block * bs) as u64);
        let mut writer = DefaultMsfStreamWriter::new(&mut sink).unwrap();
        assert_eq!(writer.write(&[]).unwrap(), 0);
        let mut written = 0;
        for chunk in payload.chunks(chunk_size) {
            writer.write_all(chunk).unwrap();
            written += chunk.len();
            assert_eq!(writer.position() as usize, written);
            assert_eq!(writer.write(&[]).unwrap(), 0);
        }
        writer.flush().unwrap();
        let layout = writer.finish().unwrap();
        assert_eq!(sink.position(), sink.get_ref().len() as u64);
        (sink.into_inner(), layout)
    }

    #[test]
    fn writer_chunking_is_equivalent_and_reads_back() {
        let bs = DEFAULT_BLOCK_SIZE as usize;
        // The second start crosses an FPM pair without a multi-megabyte payload.
        for start_block in [3, bs] {
            for len in [0, 1, bs - 1, bs, bs + 1, 3 * bs + 17] {
                let payload = patterned_bytes(len);
                let (baseline, _) = write_in_chunks(&payload, usize::MAX, start_block);
                for chunk_size in [1, 7, bs - 1, bs, bs + 1] {
                    let (bytes, layout) = write_in_chunks(&payload, chunk_size, start_block);
                    assert_eq!(bytes, baseline, "len={len}, chunk_size={chunk_size}");

                    assert_eq!(layout.byte_size as usize, len);
                    assert_eq!(layout.blocks.len(), len.div_ceil(bs));

                    let skipped = if start_block == bs && len > bs { 2 } else { 0 };
                    assert_eq!(bytes.len(), (start_block + len.div_ceil(bs) + skipped) * bs);
                    assert!(bytes[..start_block * bs].iter().all(|&byte| byte == 0xa5));
                    if skipped != 0 {
                        assert!(
                            bytes[(bs + 1) * bs..(bs + 3) * bs]
                                .iter()
                                .all(|&byte| byte == 0xff)
                        );
                    }
                    if !len.is_multiple_of(bs) {
                        let padding = bs - len % bs;
                        assert!(bytes[bytes.len() - padding..].iter().all(|&byte| byte == 0));
                    }
                    let mut reader =
                        MsfStream::new(Cursor::new(bytes), &layout, DEFAULT_BLOCK_SIZE);
                    let mut decoded = Vec::new();
                    reader.read_to_end(&mut decoded).unwrap();
                    assert_eq!(decoded, payload);
                    assert_eq!(reader.stream_position().unwrap(), len as u64);
                }
            }
        }
    }

    #[test]
    fn reads_discontiguous_blocks_and_checks_seek_positions() {
        let layout = MsfStreamLayout::new(vec![BlockIndex(1), BlockIndex(3)], 6);
        let mut bytes = vec![0; 16];
        bytes[4..8].copy_from_slice(b"abcd");
        bytes[12..16].copy_from_slice(b"efgh");
        let mut stream = MsfStream::new(Cursor::new(bytes), &layout, 4);
        let mut decoded = Vec::new();
        stream.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, b"abcdef");
        assert_eq!(stream.stream_position().unwrap(), 6);
        assert_eq!(stream.seek(SeekFrom::End(-3)).unwrap(), 3);
        let mut pair = [0; 2];
        stream.read_exact(&mut pair).unwrap();
        assert_eq!(&pair, b"de");
        assert_eq!(stream.stream_position().unwrap(), 5);
        assert!(stream.seek(SeekFrom::Current(-6)).is_err());
        assert_eq!(stream.stream_position().unwrap(), 5);
        assert_eq!(stream.seek(SeekFrom::Start(u64::MAX)).unwrap(), u64::MAX);
        assert_eq!(stream.read(&mut pair).unwrap(), 0);
        assert!(stream.seek(SeekFrom::Current(1)).is_err());
        assert_eq!(stream.stream_position().unwrap(), u64::MAX);
    }

    #[test]
    fn missing_block_returns_error_and_empty_read_is_noop() {
        let layout = MsfStreamLayout::new(vec![], 1);
        let mut stream = MsfStream::new(Cursor::new(vec![]), &layout, 512);
        assert_eq!(stream.read(&mut []).unwrap(), 0);
        assert_eq!(
            stream.read(&mut [0]).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert!(stream.seek(SeekFrom::Start(0)).is_err());
    }

    #[test]
    fn writer_finish_only_pads_partial_blocks() {
        for size in [0, 1, 4095, 4096, 4097] {
            let mut sink = Cursor::new(vec![0; 3 * 4096]);
            sink.set_position(3 * 4096);
            let mut writer = DefaultMsfStreamWriter::new(&mut sink).unwrap();
            writer.write_all(&vec![0x42; size]).unwrap();
            let layout = writer.finish().unwrap();
            assert_eq!(layout.byte_size as usize, size);
            assert_eq!(layout.blocks.len(), size.div_ceil(4096));
            assert_eq!(
                sink.stream_position().unwrap(),
                ((3 + size.div_ceil(4096)) * 4096) as u64
            );
            assert!(
                sink.get_ref()[3 * 4096..3 * 4096 + size]
                    .iter()
                    .all(|&byte| byte == 0x42)
            );
            assert!(
                sink.get_ref()[3 * 4096 + size..]
                    .iter()
                    .all(|&byte| byte == 0)
            );
        }
    }

    #[test]
    fn seek_on_empty_stream_does_not_panic() {
        let layout = MsfStreamLayout::new(Vec::new(), 0);
        let mut inner = Cursor::new(Vec::<u8>::new());
        let mut stream = MsfStream::new(&mut inner, &layout, 512);

        assert_eq!(stream.seek(SeekFrom::Start(0)).unwrap(), 0);
        let mut buf = [0u8; 4];
        assert_eq!(stream.read(&mut buf).unwrap(), 0);
    }
}
