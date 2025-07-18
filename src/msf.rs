use std::io::{self, Read};

use declio::{magic_bytes, Decode, Encode, EncodedSize};

use crate::result::Result;
use crate::utils::div_ceil;
use crate::{constants, BufMsfStream};

pub(crate) const DEFAULT_BLOCK_SIZE: u32 = 4096;
pub(crate) const EMPTY_BLOCK: &[u8] = &[0; DEFAULT_BLOCK_SIZE as usize];

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
    pub fn block_map_offset(&self) -> u32 {
        self.block_map_addr.0 * self.block_size
    }

    pub fn block_map_blocks(&self) -> u32 {
        div_ceil(self.num_dir_bytes, self.block_size)
    }
}

#[derive(Debug, Default)]
pub(crate) struct MsfStreamLayout {
    pub blocks: Vec<BlockIndex>,
    pub byte_size: u32,
}

impl MsfStreamLayout {
    pub fn new(blocks: Vec<BlockIndex>, byte_size: u32) -> Self {
        Self { blocks, byte_size }
    }
}

#[derive(Debug)]
pub(crate) struct MsfStream<'a, R> {
    layout: &'a MsfStreamLayout,
    inner: R,
    position: u32,
    block_size: u32,
}

impl<'a, R> MsfStream<'a, R> {
    pub fn new(inner: R, layout: &'a MsfStreamLayout, block_size: u32) -> Self {
        Self {
            inner,
            layout,
            position: 0,
            block_size,
        }
    }

    pub fn length(&self) -> u32 {
        self.layout.byte_size
    }

    pub fn is_eof(&self) -> bool {
        self.layout.byte_size == self.position
    }
}

impl<'a, R> io::Read for MsfStream<'a, R>
where
    R: io::Read + io::Seek,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let cur = self.position / self.block_size;
        let rem_block = self.block_size - self.position % self.block_size;
        let rem_stream = self.layout.byte_size - self.position;
        if rem_stream == 0 {
            return Ok(0);
        };
        if rem_block == self.block_size {
            let file_pos = self.layout.blocks[cur as usize];
            self.inner
                .seek(io::SeekFrom::Start(file_pos.to_file_pos(self.block_size)))?;
        }
        let len = rem_stream.min(rem_block).min(buf.len() as u32);
        let read = self.inner.read(&mut buf[..len as usize])?;
        self.position += read as u32;
        Ok(read)
    }
}

impl<'a, R> io::Seek for MsfStream<'a, R>
where
    R: io::Seek,
{
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        match pos {
            io::SeekFrom::Start(pos) => {
                self.position = pos as u32;
            }
            io::SeekFrom::End(offset) => {
                self.position = (self.layout.byte_size as i64 + offset) as u32;
            }
            io::SeekFrom::Current(offset) => {
                self.position = (self.position as i64 + offset) as u32;
            }
        }
        let cur = self.position / self.block_size;
        let file_pos = self.layout.blocks[cur as usize];
        let offset: u64 = (self.position % self.block_size).into();
        self.inner.seek(io::SeekFrom::Start(
            file_pos.to_file_pos(self.block_size) + offset,
        ))?;
        Ok(self.position.into())
    }
}

pub(crate) type DefaultMsfStreamWriter<'a, S> = MsfStreamWriter<'a, S, DEFAULT_BLOCK_SIZE>;

pub(crate) struct MsfStreamWriter<'a, S, const BLOCK_SIZE: u32> {
    sink: &'a mut S,
    blocks: Vec<BlockIndex>,
    position: u32,
}

impl<'a, S, const BLOCK_SIZE: u32> MsfStreamWriter<'a, S, BLOCK_SIZE> {
    pub fn new(sink: &'a mut S) -> io::Result<Self> {
        let res = Self {
            sink,
            blocks: vec![],
            position: 0,
        };
        Ok(res)
    }

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
            self.sink.write_all(EMPTY_BLOCK)?;
            self.sink.write_all(EMPTY_BLOCK)?;
            BlockIndex(block_index + 2)
        } else {
            BlockIndex(block_index)
        };
        self.blocks.push(cur_block);
        Ok(())
    }

    pub fn finish(self) -> io::Result<MsfStreamLayout>
    where
        S: io::Write + io::Seek,
    {
        let rem = BLOCK_SIZE - self.position % BLOCK_SIZE;
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
    pub fn layout(main: &SuperBlock) -> MsfStreamLayout {
        let intervals = div_ceil(main.num_blocks, 8 * main.block_size);
        let byte_size = div_ceil(main.num_blocks, 8);
        let mut blocks = Vec::with_capacity(intervals as usize);
        let mut fpm_block = main.free_block_map_block;
        for _ in 0..intervals {
            blocks.push(BlockIndex(fpm_block));
            fpm_block += main.block_size;
        }
        MsfStreamLayout { blocks, byte_size }
    }

    pub fn write<S>(main: &SuperBlock, sink: &mut S) -> Result<()>
    where
        S: io::Write + io::Seek,
    {
        let layout = Self::layout(main);
        let mut bit = 0;
        for block in layout.blocks {
            sink.seek(io::SeekFrom::Start(block.to_file_pos(main.block_size)))?;
            let available = (main.num_blocks - bit).min(main.block_size * 8);
            for _ in 0..available / 8 {
                sink.write_all(&[0xFF])?;
                bit += 8;
            }

            if available % 8 != 0 {
                let mut byte = 0;
                for i in 0..available % 8 {
                    byte |= 1 << i;
                }
                sink.write_all(&[byte])?;
                break;
            }
        }
        Ok(())
    }

    #[allow(unused)]
    pub fn read<R>(mut inner: BufMsfStream<R>) -> Result<FreeBlockMap>
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

#[derive(Debug, Clone, Copy, Encode, Decode, EncodedSize)]
#[declio(ctx_is = "constants::ENDIANESS")]
pub struct StreamIndex(pub(crate) u16);

impl From<StreamIndex> for u16 {
    fn from(idx: StreamIndex) -> Self {
        idx.0
    }
}
