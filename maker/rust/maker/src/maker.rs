use std::collections::HashMap;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::sync::Arc;

use bytes::{BufMut, BytesMut};
use itertools::Itertools;
use num_traits::Zero;
use tracing::{debug, info, trace};

use crate::error::{MakerError, Result};
use crate::header::{IPAddrExt, IndexPolicy, IpVersion, VECTOR_INDEX_ROWS};
use crate::segment::Segment;
use crate::{
    HEADER_INFO_LENGTH, Header, VECTOR_INDEX_COLS, VECTOR_INDEX_LENGTH, VECTOR_INDEX_SIZE,
};

pub struct Maker {
    ip_version: IpVersion,
    dst_file: File,
    region_pool: HashMap<Arc<String>, u32>,
    vector_index: [[[u8; VECTOR_INDEX_SIZE]; VECTOR_INDEX_ROWS]; VECTOR_INDEX_COLS],
    segments: Vec<Segment>,
}

impl Maker {
    pub fn new(
        ip_version: IpVersion,
        index_policy: IndexPolicy,
        src_filepath: &str,
        end_filepath: &str,
        filter_fields: Vec<usize>,
    ) -> Result<Self> {
        let src_file = File::open(src_filepath)?;
        info!(src_filepath, "Opened src file");

        let mut dst_file = File::create(end_filepath)?;
        dst_file.seek(SeekFrom::Start(0))?;
        let buf = Header::encode_bytes(index_policy, ip_version);
        debug!(?buf, "Encoding header");
        dst_file.write_all(buf.as_ref())?;

        let segments = Segment::from_file(&src_file, ip_version, &filter_fields)?;
        if segments.is_empty() {
            return Err(MakerError::EmptySegments);
        }

        Ok(Self {
            ip_version,
            dst_file,
            region_pool: HashMap::new(),
            vector_index: [[[0; VECTOR_INDEX_SIZE]; VECTOR_INDEX_ROWS]; VECTOR_INDEX_COLS],
            segments,
        })
    }

    fn load_region_pool(&mut self) -> Result<()> {
        self.dst_file.seek(SeekFrom::Start(
            (HEADER_INFO_LENGTH + VECTOR_INDEX_LENGTH) as u64,
        ))?;
        for region in self.segments.iter().map(|s| s.region.clone()).unique() {
            let current = self.dst_file.stream_position()?;
            self.dst_file.write_all(region.as_bytes())?;
            self.region_pool.insert(region, u32::try_from(current)?);
        }
        Ok(())
    }

    fn set_vector_index(&mut self, ip: &[u8], ptr: u32) -> Result<()> {
        let (l0, l1) = (ip[0] as usize, ip[1] as usize);

        let block = &mut self.vector_index[l0][l1];

        let value = u32::from_le_bytes(block[0..4].try_into()?);
        if value.is_zero() {
            block[0..4].copy_from_slice(&ptr.to_le_bytes());
        }
        let end_value = ptr + self.ip_version.segment_index_size() as u32;
        block[4..].copy_from_slice(&end_value.to_le_bytes());
        Ok(())
    }

    pub fn start(&mut self) -> Result<()> {
        self.load_region_pool()?;

        let start_index_ptr = u32::try_from(self.dst_file.stream_position()?)?;
        let mut end_index_ptr = 0;

        let mut count = 0;
        let segments = std::mem::take(&mut self.segments);
        for segment in segments {
            let region_ptr = *self
                .region_pool
                .get(&segment.region)
                .ok_or(MakerError::RegionNotFound)?;
            let region_len = u16::try_from(segment.region.len())?;

            trace!(?segment, "before segment split");
            for seg in segment.split()? {
                let pos = u32::try_from(self.dst_file.stream_position()?)?;
                end_index_ptr = pos;
                self.set_vector_index(&seg.start_ip.ipaddr_bytes(), pos)?;

                let mut index_buf = BytesMut::with_capacity(self.ip_version.segment_index_size());
                index_buf.put_slice(&seg.start_ip.encode_ipaddr_bytes());
                index_buf.put_slice(&seg.end_ip.encode_ipaddr_bytes());
                index_buf.put_u16_le(region_len);
                index_buf.put_u32_le(region_ptr);
                trace!(?index_buf, ?seg, "Finished split segment");
                self.dst_file.write_all(index_buf.as_ref())?;

                count += 1;
            }
        }

        self.dst_file
            .seek(SeekFrom::Start(HEADER_INFO_LENGTH as u64))?;
        self.dst_file
            .write_all(self.vector_index.as_flattened().as_flattened())?;

        let mut index_buf = BytesMut::new();
        index_buf.put_u32_le(start_index_ptr);
        index_buf.put_u32_le(end_index_ptr);
        self.dst_file.seek(SeekFrom::Start(8))?;
        self.dst_file.write_all(index_buf.as_ref())?;

        info!(
            start_index_ptr,
            end_index_ptr,
            region_pool_len = self.region_pool.len(),
            count,
            "Write done"
        );

        Ok(())
    }
}
