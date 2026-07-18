//! SCSI CDB 실행과 Storage backend 경계.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use bytes::Bytes;

pub const STATUS_GOOD: u8 = 0x00;
pub const STATUS_CHECK_CONDITION: u8 = 0x02;
pub const DEFAULT_MAX_SCSI_TRANSFER_LENGTH: usize = 16 * 1024 * 1024;

const SENSE_NO_SENSE: u8 = 0x00;
const SENSE_ILLEGAL_REQUEST: u8 = 0x05;
const SENSE_DATA_PROTECT: u8 = 0x07;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StorageError {
    #[error("block range is outside the backend")]
    OutOfRange,
    #[error("I/O length is not aligned to the backend block size")]
    Misaligned,
    #[error("backend is read-only")]
    ReadOnly,
    #[error(transparent)]
    Io(#[from] StorageIoError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("storage {operation} failed with {kind:?} (OS error {raw_os_error:?})")]
pub struct StorageIoError {
    operation: StorageIoOperation,
    kind: std::io::ErrorKind,
    raw_os_error: Option<i32>,
}

impl StorageIoError {
    pub fn operation(self) -> StorageIoOperation {
        self.operation
    }

    pub fn kind(self) -> std::io::ErrorKind {
        self.kind
    }

    pub fn raw_os_error(self) -> Option<i32> {
        self.raw_os_error
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StorageIoOperation {
    #[error("open")]
    Open,
    #[error("metadata")]
    Metadata,
    #[error("resize")]
    Resize,
    #[error("seek")]
    Seek,
    #[error("read")]
    Read,
    #[error("write")]
    Write,
    #[error("flush")]
    Flush,
    #[error("sync")]
    Sync,
    #[error("device-control")]
    DeviceControl,
}

pub(crate) fn storage_io_error(
    operation: StorageIoOperation,
    error: std::io::Error,
) -> StorageError {
    StorageIoError {
        operation,
        kind: error.kind(),
        raw_os_error: error.raw_os_error(),
    }
    .into()
}

/// block 단위 Storage backend. 구현은 요청 buffer를 정확히 모두 처리해야 한다.
pub trait StorageBackend: Send {
    fn block_size(&self) -> u32;
    fn block_count(&self) -> u64;
    fn read_only(&self) -> bool;
    fn read_blocks(&mut self, lba: u64, output: &mut [u8]) -> Result<(), StorageError>;
    fn write_blocks(&mut self, lba: u64, input: &[u8]) -> Result<(), StorageError>;
    fn flush(&mut self) -> Result<(), StorageError>;
}

#[derive(Debug, Clone)]
pub struct MemoryBackend {
    block_size: u32,
    data: Vec<u8>,
    read_only: bool,
}

impl MemoryBackend {
    pub fn new(block_size: u32, block_count: u64) -> Result<Self, StorageError> {
        let length = storage_length_usize(block_size, block_count)?;
        Ok(Self {
            block_size,
            data: vec![0; length],
            read_only: false,
        })
    }

    pub fn set_read_only(&mut self, value: bool) {
        self.read_only = value;
    }
}

impl StorageBackend for MemoryBackend {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn block_count(&self) -> u64 {
        (self.data.len() as u64) / u64::from(self.block_size)
    }

    fn read_only(&self) -> bool {
        self.read_only
    }

    fn read_blocks(&mut self, lba: u64, output: &mut [u8]) -> Result<(), StorageError> {
        let range = byte_range(lba, output.len(), self.block_size, self.data.len())?;
        output.copy_from_slice(&self.data[range]);
        Ok(())
    }

    fn write_blocks(&mut self, lba: u64, input: &[u8]) -> Result<(), StorageError> {
        if self.read_only {
            return Err(StorageError::ReadOnly);
        }
        let range = byte_range(lba, input.len(), self.block_size, self.data.len())?;
        self.data[range].copy_from_slice(input);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), StorageError> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct FileBackend {
    file: File,
    block_size: u32,
    block_count: u64,
    read_only: bool,
    durable_flush: bool,
}

impl FileBackend {
    pub fn open_read_write(path: impl AsRef<Path>, block_size: u32) -> Result<Self, StorageError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|error| storage_io_error(StorageIoOperation::Open, error))?;
        Self::from_file(file, block_size, false)
    }

    pub fn open_read_only(path: impl AsRef<Path>, block_size: u32) -> Result<Self, StorageError> {
        let file = OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|error| storage_io_error(StorageIoOperation::Open, error))?;
        Self::from_file(file, block_size, true)
    }

    pub fn create_sparse(
        path: impl AsRef<Path>,
        block_size: u32,
        block_count: u64,
    ) -> Result<Self, StorageError> {
        let length = storage_length(block_size, block_count)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| storage_io_error(StorageIoOperation::Open, error))?;
        file.set_len(length)
            .map_err(|error| storage_io_error(StorageIoOperation::Resize, error))?;
        Self::from_file(file, block_size, false)
    }

    pub fn from_file(file: File, block_size: u32, read_only: bool) -> Result<Self, StorageError> {
        validate_block_geometry(block_size, 1)?;
        let length = file
            .metadata()
            .map_err(|error| storage_io_error(StorageIoOperation::Metadata, error))?
            .len();
        if length == 0 {
            return Err(StorageError::OutOfRange);
        }
        if length % u64::from(block_size) != 0 {
            return Err(StorageError::Misaligned);
        }
        Ok(Self {
            file,
            block_size,
            block_count: length / u64::from(block_size),
            read_only,
            durable_flush: true,
        })
    }

    pub fn set_durable_flush(&mut self, value: bool) {
        self.durable_flush = value;
    }

    pub fn durable_flush(&self) -> bool {
        self.durable_flush
    }
}

impl StorageBackend for FileBackend {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn block_count(&self) -> u64 {
        self.block_count
    }

    fn read_only(&self) -> bool {
        self.read_only
    }

    fn read_blocks(&mut self, lba: u64, output: &mut [u8]) -> Result<(), StorageError> {
        let offset = block_io_offset(lba, output.len(), self.block_size, self.block_count)?;
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|error| storage_io_error(StorageIoOperation::Seek, error))?;
        self.file
            .read_exact(output)
            .map_err(|error| storage_io_error(StorageIoOperation::Read, error))?;
        Ok(())
    }

    fn write_blocks(&mut self, lba: u64, input: &[u8]) -> Result<(), StorageError> {
        if self.read_only {
            return Err(StorageError::ReadOnly);
        }
        let offset = block_io_offset(lba, input.len(), self.block_size, self.block_count)?;
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|error| storage_io_error(StorageIoOperation::Seek, error))?;
        self.file
            .write_all(input)
            .map_err(|error| storage_io_error(StorageIoOperation::Write, error))?;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), StorageError> {
        self.file
            .flush()
            .map_err(|error| storage_io_error(StorageIoOperation::Flush, error))?;
        if self.durable_flush {
            self.file
                .sync_all()
                .map_err(|error| storage_io_error(StorageIoOperation::Sync, error))?;
        }
        Ok(())
    }
}

fn validate_block_geometry(block_size: u32, block_count: u64) -> Result<(), StorageError> {
    if block_size == 0 || block_count == 0 {
        return Err(StorageError::OutOfRange);
    }
    Ok(())
}

fn storage_length(block_size: u32, block_count: u64) -> Result<u64, StorageError> {
    validate_block_geometry(block_size, block_count)?;
    u64::from(block_size)
        .checked_mul(block_count)
        .ok_or(StorageError::OutOfRange)
}

fn storage_length_usize(block_size: u32, block_count: u64) -> Result<usize, StorageError> {
    storage_length(block_size, block_count)
        .and_then(|value| usize::try_from(value).map_err(|_| StorageError::OutOfRange))
}

pub(crate) fn block_io_offset(
    lba: u64,
    length: usize,
    block_size: u32,
    block_count: u64,
) -> Result<u64, StorageError> {
    validate_block_geometry(block_size, block_count)?;
    if !length.is_multiple_of(block_size as usize) {
        return Err(StorageError::Misaligned);
    }
    let transfer_blocks =
        u64::try_from(length / block_size as usize).map_err(|_| StorageError::OutOfRange)?;
    let end_lba = lba
        .checked_add(transfer_blocks)
        .ok_or(StorageError::OutOfRange)?;
    if end_lba > block_count {
        return Err(StorageError::OutOfRange);
    }
    lba.checked_mul(u64::from(block_size))
        .ok_or(StorageError::OutOfRange)
}

fn byte_range(
    lba: u64,
    length: usize,
    block_size: u32,
    capacity: usize,
) -> Result<std::ops::Range<usize>, StorageError> {
    if !length.is_multiple_of(block_size as usize) {
        return Err(StorageError::Misaligned);
    }
    let start = lba
        .checked_mul(u64::from(block_size))
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(StorageError::OutOfRange)?;
    let end = start.checked_add(length).ok_or(StorageError::OutOfRange)?;
    if end > capacity {
        return Err(StorageError::OutOfRange);
    }
    Ok(start..end)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScsiExecution {
    pub status: u8,
    pub data: Bytes,
    pub sense: Bytes,
}

impl ScsiExecution {
    fn good(data: Vec<u8>) -> Self {
        Self {
            status: STATUS_GOOD,
            data: Bytes::from(data),
            sense: Bytes::new(),
        }
    }
}

struct Lun {
    backend: Box<dyn StorageBackend>,
    last_sense: Bytes,
}

impl std::fmt::Debug for Lun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lun")
            .field("block_size", &self.backend.block_size())
            .field("block_count", &self.backend.block_count())
            .field("read_only", &self.backend.read_only())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct ScsiTarget {
    luns: BTreeMap<u64, Lun>,
    max_transfer_length: usize,
}

impl Default for ScsiTarget {
    fn default() -> Self {
        Self {
            luns: BTreeMap::new(),
            max_transfer_length: DEFAULT_MAX_SCSI_TRANSFER_LENGTH,
        }
    }
}

impl ScsiTarget {
    pub fn add_lun(
        &mut self,
        lun: u64,
        backend: impl StorageBackend + 'static,
    ) -> Option<Box<dyn StorageBackend>> {
        self.luns
            .insert(
                lun,
                Lun {
                    backend: Box::new(backend),
                    last_sense: Bytes::new(),
                },
            )
            .map(|old| old.backend)
    }

    pub fn remove_lun(&mut self, lun: u64) -> Option<Box<dyn StorageBackend>> {
        self.luns.remove(&lun).map(|old| old.backend)
    }

    pub fn set_max_transfer_length(&mut self, value: usize) -> Result<(), StorageError> {
        if value == 0 {
            return Err(StorageError::OutOfRange);
        }
        self.max_transfer_length = value;
        Ok(())
    }

    pub fn max_transfer_length(&self) -> usize {
        self.max_transfer_length
    }

    pub fn execute(&mut self, lun: u64, cdb: &[u8; 16], data_out: &[u8]) -> ScsiExecution {
        if cdb[0] == 0xa0 {
            return self.report_luns(cdb);
        }
        let Some(device) = self.luns.get_mut(&lun) else {
            return check_condition(SENSE_ILLEGAL_REQUEST, 0x25, 0x00);
        };
        let result = execute_lun(device, cdb, data_out, self.max_transfer_length);
        if result.status == STATUS_CHECK_CONDITION {
            device.last_sense = result.sense.clone();
        }
        result
    }

    fn report_luns(&self, cdb: &[u8; 16]) -> ScsiExecution {
        if cdb[2] > 2 {
            return check_condition(SENSE_ILLEGAL_REQUEST, 0x24, 0x00);
        }
        let allocation = be_u32(cdb, 6) as usize;
        let list_length = self.luns.len().saturating_mul(8);
        let mut output = vec![0; 8 + list_length];
        output[..4].copy_from_slice(&(list_length as u32).to_be_bytes());
        for (slot, lun) in output[8..].chunks_exact_mut(8).zip(self.luns.keys()) {
            slot.copy_from_slice(&lun.to_be_bytes());
        }
        output.truncate(output.len().min(allocation));
        ScsiExecution::good(output)
    }
}

fn execute_lun(
    device: &mut Lun,
    cdb: &[u8; 16],
    data_out: &[u8],
    max_transfer_length: usize,
) -> ScsiExecution {
    match cdb[0] {
        0x00 => ScsiExecution::good(Vec::new()),
        0x03 => request_sense(device, cdb),
        0x12 => inquiry(cdb),
        0x1a => mode_sense(device, cdb, false),
        0x25 => read_capacity_10(device),
        0x28 => read_blocks(
            device,
            be_u32(cdb, 2) as u64,
            be_u16(cdb, 7) as u32,
            max_transfer_length,
        ),
        0x2a => write_blocks(
            device,
            be_u32(cdb, 2) as u64,
            be_u16(cdb, 7) as u32,
            data_out,
            max_transfer_length,
        ),
        0x35 => flush(device),
        0x5a => mode_sense(device, cdb, true),
        0x88 => read_blocks(device, be_u64(cdb, 2), be_u32(cdb, 10), max_transfer_length),
        0x8a => write_blocks(
            device,
            be_u64(cdb, 2),
            be_u32(cdb, 10),
            data_out,
            max_transfer_length,
        ),
        0x91 => flush(device),
        0x9e if cdb[1] & 0x1f == 0x10 => read_capacity_16(device, cdb),
        0xa8 => read_blocks(
            device,
            be_u32(cdb, 2) as u64,
            be_u32(cdb, 6),
            max_transfer_length,
        ),
        0xaa => write_blocks(
            device,
            be_u32(cdb, 2) as u64,
            be_u32(cdb, 6),
            data_out,
            max_transfer_length,
        ),
        _ => check_condition(SENSE_ILLEGAL_REQUEST, 0x20, 0x00),
    }
}

fn request_sense(device: &mut Lun, cdb: &[u8; 16]) -> ScsiExecution {
    let allocation = cdb[4] as usize;
    let mut sense = if device.last_sense.is_empty() {
        fixed_sense(SENSE_NO_SENSE, 0x00, 0x00).to_vec()
    } else {
        std::mem::take(&mut device.last_sense).to_vec()
    };
    sense.truncate(allocation.min(sense.len()));
    ScsiExecution::good(sense)
}

fn inquiry(cdb: &[u8; 16]) -> ScsiExecution {
    let evpd = cdb[1] & 1 != 0;
    let page = cdb[2];
    let allocation = be_u16(cdb, 3) as usize;
    let mut output = if !evpd && page == 0 {
        let mut value = vec![0; 36];
        value[2] = 0x06;
        value[3] = 0x02;
        value[4] = 31;
        value[7] = 0x02;
        value[8..16].copy_from_slice(b"RUSTISCS");
        value[16..32].copy_from_slice(b"VIRTUAL DISK    ");
        value[32..36].copy_from_slice(b"0001");
        value
    } else if evpd {
        let Some(value) = inquiry_vpd(page) else {
            return check_condition(SENSE_ILLEGAL_REQUEST, 0x24, 0x00);
        };
        value
    } else {
        return check_condition(SENSE_ILLEGAL_REQUEST, 0x24, 0x00);
    };
    output.truncate(allocation.min(output.len()));
    ScsiExecution::good(output)
}

fn inquiry_vpd(page: u8) -> Option<Vec<u8>> {
    let payload: Vec<u8> = match page {
        0x00 => vec![0x00, 0x80, 0x83],
        0x80 => b"RUSTISCSI0000001".to_vec(),
        0x83 => {
            let identifier = b"iqn.2024-01.rs.iscsi:lun";
            let mut descriptor = vec![0x02, 0x08, 0x00, identifier.len() as u8];
            descriptor.extend_from_slice(identifier);
            descriptor
        }
        _ => return None,
    };
    let mut output = vec![0, page, 0, payload.len() as u8];
    output.extend_from_slice(&payload);
    Some(output)
}

fn read_capacity_10(device: &Lun) -> ScsiExecution {
    let last = device
        .backend
        .block_count()
        .saturating_sub(1)
        .min(u32::MAX as u64) as u32;
    let mut output = Vec::with_capacity(8);
    output.extend_from_slice(&last.to_be_bytes());
    output.extend_from_slice(&device.backend.block_size().to_be_bytes());
    ScsiExecution::good(output)
}

fn read_capacity_16(device: &Lun, cdb: &[u8; 16]) -> ScsiExecution {
    let allocation = be_u32(cdb, 10) as usize;
    let mut output = vec![0; 32];
    output[..8].copy_from_slice(&device.backend.block_count().saturating_sub(1).to_be_bytes());
    output[8..12].copy_from_slice(&device.backend.block_size().to_be_bytes());
    output.truncate(allocation.min(output.len()));
    ScsiExecution::good(output)
}

fn mode_sense(device: &Lun, cdb: &[u8; 16], ten_byte: bool) -> ScsiExecution {
    let page_code = cdb[2] & 0x3f;
    if !matches!(page_code, 0x08 | 0x3f) {
        return check_condition(SENSE_ILLEGAL_REQUEST, 0x24, 0x00);
    }
    let allocation = if ten_byte {
        be_u16(cdb, 7) as usize
    } else {
        cdb[4] as usize
    };
    let header = if ten_byte { 8 } else { 4 };
    let mut output = vec![0; header];
    output[if ten_byte { 3 } else { 2 }] = if device.backend.read_only() { 0x80 } else { 0 };
    output.extend_from_slice(&[
        0x08, 0x12, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    if ten_byte {
        let length = (output.len() - 2) as u16;
        output[..2].copy_from_slice(&length.to_be_bytes());
    } else {
        output[0] = (output.len() - 1) as u8;
    }
    output.truncate(allocation.min(output.len()));
    ScsiExecution::good(output)
}

fn read_blocks(
    device: &mut Lun,
    lba: u64,
    blocks: u32,
    max_transfer_length: usize,
) -> ScsiExecution {
    let Some(length) = validated_transfer(device, lba, blocks, max_transfer_length) else {
        return check_condition(SENSE_ILLEGAL_REQUEST, 0x21, 0x00);
    };
    let mut output = vec![0; length];
    match device.backend.read_blocks(lba, &mut output) {
        Ok(()) => ScsiExecution::good(output),
        Err(error) => storage_error(error),
    }
}

fn write_blocks(
    device: &mut Lun,
    lba: u64,
    blocks: u32,
    input: &[u8],
    max_transfer_length: usize,
) -> ScsiExecution {
    let Some(length) = validated_transfer(device, lba, blocks, max_transfer_length) else {
        return check_condition(SENSE_ILLEGAL_REQUEST, 0x21, 0x00);
    };
    if input.len() != length {
        return check_condition(SENSE_ILLEGAL_REQUEST, 0x1a, 0x00);
    }
    match device.backend.write_blocks(lba, input) {
        Ok(()) => ScsiExecution::good(Vec::new()),
        Err(error) => storage_error(error),
    }
}

fn flush(device: &mut Lun) -> ScsiExecution {
    match device.backend.flush() {
        Ok(()) => ScsiExecution::good(Vec::new()),
        Err(error) => storage_error(error),
    }
}

fn transfer_length(block_size: u32, blocks: u32) -> Option<usize> {
    u64::from(block_size)
        .checked_mul(u64::from(blocks))
        .and_then(|value| usize::try_from(value).ok())
}

fn validated_transfer(
    device: &Lun,
    lba: u64,
    blocks: u32,
    max_transfer_length: usize,
) -> Option<usize> {
    let end_lba = lba.checked_add(u64::from(blocks))?;
    if end_lba > device.backend.block_count() {
        return None;
    }
    let length = transfer_length(device.backend.block_size(), blocks)?;
    (length <= max_transfer_length).then_some(length)
}

fn storage_error(error: StorageError) -> ScsiExecution {
    match error {
        StorageError::OutOfRange => check_condition(SENSE_ILLEGAL_REQUEST, 0x21, 0x00),
        StorageError::Misaligned => check_condition(SENSE_ILLEGAL_REQUEST, 0x1a, 0x00),
        StorageError::ReadOnly => check_condition(SENSE_DATA_PROTECT, 0x27, 0x00),
        StorageError::Io(_) => check_condition(0x03, 0x11, 0x00),
    }
}

fn check_condition(key: u8, asc: u8, ascq: u8) -> ScsiExecution {
    ScsiExecution {
        status: STATUS_CHECK_CONDITION,
        data: Bytes::new(),
        sense: fixed_sense(key, asc, ascq),
    }
}

fn fixed_sense(key: u8, asc: u8, ascq: u8) -> Bytes {
    let mut value = [0; 18];
    value[0] = 0x70;
    value[2] = key;
    value[7] = 10;
    value[12] = asc;
    value[13] = ascq;
    Bytes::copy_from_slice(&value)
}

fn be_u16(value: &[u8; 16], offset: usize) -> u16 {
    u16::from_be_bytes([value[offset], value[offset + 1]])
}

fn be_u32(value: &[u8; 16], offset: usize) -> u32 {
    u32::from_be_bytes([
        value[offset],
        value[offset + 1],
        value[offset + 2],
        value[offset + 3],
    ])
}

fn be_u64(value: &[u8; 16], offset: usize) -> u64 {
    u64::from_be_bytes([
        value[offset],
        value[offset + 1],
        value[offset + 2],
        value[offset + 3],
        value[offset + 4],
        value[offset + 5],
        value[offset + 6],
        value[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn target() -> ScsiTarget {
        let mut target = ScsiTarget::default();
        target.add_lun(0, MemoryBackend::new(512, 32).unwrap());
        target
    }

    #[test]
    fn inquiry_capacity_modes_and_report_luns_have_fixed_fields() {
        let mut target = target();
        let mut inquiry = [0; 16];
        inquiry[0] = 0x12;
        inquiry[4] = 36;
        let result = target.execute(0, &inquiry, &[]);
        assert_eq!(result.status, STATUS_GOOD);
        assert_eq!(&result.data[8..16], b"RUSTISCS");

        let mut capacity = [0; 16];
        capacity[0] = 0x25;
        assert_eq!(
            target.execute(0, &capacity, &[]).data.as_ref(),
            &[0, 0, 0, 31, 0, 0, 2, 0]
        );

        let mut mode = [0; 16];
        mode[0] = 0x1a;
        mode[2] = 0x3f;
        mode[4] = 64;
        assert_eq!(target.execute(0, &mode, &[]).data[4], 0x08);

        let mut report = [0; 16];
        report[0] = 0xa0;
        report[9] = 16;
        assert_eq!(target.execute(99, &report, &[]).data.len(), 16);
    }

    #[test]
    fn read_write_and_flush_share_a_bounded_backend() {
        let mut target = target();
        let mut write = [0; 16];
        write[0] = 0x2a;
        write[5] = 2;
        write[8] = 1;
        let payload = vec![0x5a; 512];
        assert_eq!(target.execute(0, &write, &payload).status, STATUS_GOOD);

        let mut read = write;
        read[0] = 0x28;
        assert_eq!(target.execute(0, &read, &[]).data.as_ref(), payload);

        let mut flush = [0; 16];
        flush[0] = 0x35;
        assert_eq!(target.execute(0, &flush, &[]).status, STATUS_GOOD);
    }

    #[test]
    fn twelve_and_sixteen_byte_io_and_capacity_sixteen_are_supported() {
        let payload = vec![0xa5; 512];
        for (write_opcode, read_opcode, transfer_offset) in
            [(0xaa, 0xa8, 6usize), (0x8a, 0x88, 10usize)]
        {
            let mut target = target();
            let mut write = [0; 16];
            write[0] = write_opcode;
            write[transfer_offset + 3] = 1;
            assert_eq!(target.execute(0, &write, &payload).status, STATUS_GOOD);
            write[0] = read_opcode;
            assert_eq!(target.execute(0, &write, &[]).data.as_ref(), payload);
        }

        let mut target = target();
        let mut capacity = [0; 16];
        capacity[0] = 0x9e;
        capacity[1] = 0x10;
        capacity[13] = 32;
        let result = target.execute(0, &capacity, &[]);
        assert_eq!(result.data.len(), 32);
        assert_eq!(&result.data[..12], &[0, 0, 0, 0, 0, 0, 0, 31, 0, 0, 2, 0]);
    }

    #[test]
    fn transfer_limit_is_checked_before_read_allocation() {
        let mut target = target();
        target.set_max_transfer_length(512).unwrap();
        let mut read = [0; 16];
        read[0] = 0x28;
        read[8] = 2;
        let result = target.execute(0, &read, &[]);
        assert_eq!(
            (result.status, result.sense[12]),
            (STATUS_CHECK_CONDITION, 0x21)
        );
    }

    #[test]
    fn invalid_cdb_lun_range_and_read_only_write_return_sense() {
        let mut target = target();
        let result = target.execute(0, &[0xff; 16], &[]);
        assert_eq!(
            (result.status, result.sense[2], result.sense[12]),
            (2, 5, 0x20)
        );

        let mut read = [0; 16];
        read[0] = 0x28;
        read[5] = 32;
        read[8] = 1;
        assert_eq!(target.execute(0, &read, &[]).sense[12], 0x21);
        assert_eq!(target.execute(9, &read, &[]).sense[12], 0x25);

        let mut backend = MemoryBackend::new(512, 1).unwrap();
        backend.set_read_only(true);
        target.add_lun(1, backend);
        let mut write = [0; 16];
        write[0] = 0x2a;
        write[8] = 1;
        let result = target.execute(1, &write, &[0; 512]);
        assert_eq!((result.sense[2], result.sense[12]), (7, 0x27));
    }

    #[test]
    fn request_sense_reports_and_then_clears_last_error() {
        let mut target = target();
        let _ = target.execute(0, &[0xff; 16], &[]);
        let mut request = [0; 16];
        request[0] = 0x03;
        request[4] = 18;
        let first = target.execute(0, &request, &[]);
        let second = target.execute(0, &request, &[]);
        assert_eq!((first.data[2], first.data[12]), (5, 0x20));
        assert_eq!(second.data[2], SENSE_NO_SENSE);
    }

    #[test]
    fn memory_backend_rejects_unaligned_and_out_of_range_io() {
        let mut backend = MemoryBackend::new(512, 1).unwrap();
        let mut unaligned = [0; 511];
        assert_eq!(
            backend.read_blocks(0, &mut unaligned),
            Err(StorageError::Misaligned)
        );
        assert_eq!(
            backend.write_blocks(1, &[0; 512]),
            Err(StorageError::OutOfRange)
        );
    }

    #[test]
    fn file_backend_uses_file_size_and_persists_blocks() {
        let path = temp_image_path("rw");
        {
            let mut backend = FileBackend::create_sparse(&path, 512, 2).unwrap();
            backend.set_durable_flush(false);
            assert_eq!(backend.block_count(), 2);
            backend.write_blocks(1, &[0x6d; 512]).unwrap();
            backend.flush().unwrap();
        }
        {
            let mut target = ScsiTarget::default();
            target.add_lun(0, FileBackend::open_read_write(&path, 512).unwrap());
            let mut capacity = [0; 16];
            capacity[0] = 0x25;
            assert_eq!(
                target.execute(0, &capacity, &[]).data.as_ref(),
                &[0, 0, 0, 1, 0, 0, 2, 0]
            );

            let mut read = [0; 16];
            read[0] = 0x28;
            read[5] = 1;
            read[8] = 1;
            assert_eq!(target.execute(0, &read, &[]).data.as_ref(), &[0x6d; 512]);
        }
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn file_backend_rejects_unaligned_images_and_read_only_writes() {
        let unaligned = temp_image_path("unaligned");
        fs::write(&unaligned, [0; 513]).unwrap();
        assert_eq!(
            FileBackend::open_read_write(&unaligned, 512).unwrap_err(),
            StorageError::Misaligned
        );
        fs::remove_file(unaligned).unwrap();

        let path = temp_image_path("ro");
        FileBackend::create_sparse(&path, 512, 1).unwrap();
        let mut target = ScsiTarget::default();
        target.add_lun(0, FileBackend::open_read_only(&path, 512).unwrap());
        let mut write = [0; 16];
        write[0] = 0x2a;
        write[8] = 1;
        let result = target.execute(0, &write, &[0; 512]);
        assert_eq!((result.sense[2], result.sense[12]), (7, 0x27));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn sparse_creation_never_truncates_an_existing_file_and_keeps_io_context() {
        let path = temp_image_path("existing");
        fs::write(&path, b"keep-this-data").unwrap();

        let error = FileBackend::create_sparse(&path, 512, 1).unwrap_err();
        let StorageError::Io(error) = error else {
            panic!("expected contextual I/O error");
        };
        assert_eq!(error.operation(), StorageIoOperation::Open);
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).unwrap(), b"keep-this-data");

        fs::remove_file(path).unwrap();
    }

    fn temp_image_path(label: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "iscsi-target-server-{label}-{}-{unique}.img",
            std::process::id()
        ))
    }
}
