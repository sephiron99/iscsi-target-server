//! SCSI CDB 실행과 Storage backend 경계.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use bytes::Bytes;

pub const STATUS_GOOD: u8 = 0x00;
pub const STATUS_CHECK_CONDITION: u8 = 0x02;
pub const DEFAULT_MAX_SCSI_TRANSFER_LENGTH: usize = 16 * 1024 * 1024;

/// 설정할 수 있는 가장 큰 LUN 번호. single level LUN의 flat space addressing이 14 bit이다
/// (SAM-5 §4.7.7.3).
pub const MAX_LUN: u64 = 0x3fff;

/// peripheral device addressing으로 표현하는 LUN 번호의 상한 (SAM-5 §4.7.7.2).
const MAX_PERIPHERAL_LUN: u64 = 0xff;
const LUN_ADDRESS_METHOD_MASK: u64 = 0xc0;
const LUN_ADDRESS_METHOD_PERIPHERAL: u64 = 0x00;
const LUN_ADDRESS_METHOD_FLAT: u64 = 0x40;

/// LUN 번호를 iSCSI BHS와 REPORT LUNS가 쓰는 8-byte LUN 값으로 바꾼다.
///
/// SAM-5 §4.7.5의 single level LUN 구조를 따른다. 8 byte 중 앞 2 byte만 쓰고 나머지는
/// 0이다. 255 이하는 bus identifier 0의 peripheral device addressing, 그보다 큰 번호는
/// flat space addressing으로 인코딩한다. 그래서 LUN 0은 값 0이지만 LUN 1은
/// `0x0001_0000_0000_0000`이다.
pub fn encode_lun(lun: u64) -> Option<u64> {
    let address = if lun <= MAX_PERIPHERAL_LUN {
        lun
    } else if lun <= MAX_LUN {
        (LUN_ADDRESS_METHOD_FLAT << 8) | lun
    } else {
        return None;
    };
    Some(address << 48)
}

/// Initiator가 보낸 8-byte LUN 값을 LUN 번호로 바꾼다.
///
/// peripheral device addressing(bus identifier 0)과 flat space addressing만 받는다.
/// 둘째 level 이하가 0이 아니거나 다른 addressing method를 쓴 값은 이 Target에 없는
/// logical unit이므로 `None`을 반환한다.
pub fn decode_lun(wire: u64) -> Option<u64> {
    if wire & 0x0000_ffff_ffff_ffff != 0 {
        return None;
    }
    let first = wire >> 56;
    let second = (wire >> 48) & 0xff;
    match first & LUN_ADDRESS_METHOD_MASK {
        LUN_ADDRESS_METHOD_PERIPHERAL if first == 0 => Some(second),
        LUN_ADDRESS_METHOD_FLAT => Some(((first & !LUN_ADDRESS_METHOD_MASK) << 8) | second),
        _ => None,
    }
}

/// [`MAX_LUN`]을 넘어 SAM LUN으로 표현할 수 없는 LUN 번호.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("LUN {0} is outside the supported range 0..={MAX_LUN}")]
pub struct InvalidLun(pub u64);

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

    pub fn create_fixed(
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
        // read-only backend에는 내보낼 data가 없다. Windows의 FlushFileBuffers는 write
        // 접근이 없는 handle에서 ERROR_ACCESS_DENIED로 실패하므로 호출하지 않는다.
        if self.read_only {
            return Ok(());
        }
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
    /// LUN 번호를 key로 한다. wire의 8-byte LUN 값은 [`decode_lun`]으로 바꿔 찾는다.
    luns: BTreeMap<u64, Lun>,
    max_transfer_length: usize,
    /// logical unit의 장치 식별자를 다른 Target과 구분하는 값. 보통 Target의 iSCSI name이다.
    identity_namespace: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SharedScsiTarget {
    inner: Arc<Mutex<ScsiTarget>>,
}

impl SharedScsiTarget {
    pub fn new(target: ScsiTarget) -> Self {
        Self {
            inner: Arc::new(Mutex::new(target)),
        }
    }

    pub fn add_lun(
        &self,
        lun: u64,
        backend: impl StorageBackend + 'static,
    ) -> Result<(), SharedScsiTargetError> {
        self.add_boxed_lun(lun, Box::new(backend))
    }

    pub fn add_boxed_lun(
        &self,
        lun: u64,
        backend: Box<dyn StorageBackend>,
    ) -> Result<(), SharedScsiTargetError> {
        let mut target = self.lock()?;
        if target.luns.contains_key(&lun) {
            return Err(SharedScsiTargetError::DuplicateLun(lun));
        }
        target.add_boxed_lun(lun, backend)?;
        Ok(())
    }

    pub fn remove_lun(&self, lun: u64) -> Result<bool, SharedScsiTargetError> {
        Ok(self.lock()?.remove_lun(lun).is_some())
    }

    pub fn lun_info(&self) -> Result<Vec<LunInfo>, SharedScsiTargetError> {
        Ok(self.lock()?.lun_info())
    }

    pub fn max_transfer_length(&self) -> Result<usize, SharedScsiTargetError> {
        Ok(self.lock()?.max_transfer_length())
    }

    pub fn execute(
        &self,
        lun: u64,
        cdb: &[u8; 16],
        data_out: &[u8],
    ) -> Result<ScsiExecution, SharedScsiTargetError> {
        Ok(self.lock()?.execute(lun, cdb, data_out))
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, ScsiTarget>, SharedScsiTargetError> {
        self.inner
            .lock()
            .map_err(|_| SharedScsiTargetError::Poisoned)
    }
}

impl Default for SharedScsiTarget {
    fn default() -> Self {
        Self::new(ScsiTarget::default())
    }
}

impl From<ScsiTarget> for SharedScsiTarget {
    fn from(target: ScsiTarget) -> Self {
        Self::new(target)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SharedScsiTargetError {
    #[error("shared SCSI Target state is poisoned")]
    Poisoned,
    #[error("shared SCSI Target already contains LUN {0}")]
    DuplicateLun(u64),
    #[error(transparent)]
    InvalidLun(#[from] InvalidLun),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LunInfo {
    pub lun: u64,
    pub block_size: u32,
    pub block_count: u64,
    pub read_only: bool,
}

impl Default for ScsiTarget {
    fn default() -> Self {
        Self {
            luns: BTreeMap::new(),
            max_transfer_length: DEFAULT_MAX_SCSI_TRANSFER_LENGTH,
            identity_namespace: Vec::new(),
        }
    }
}

impl ScsiTarget {
    /// logical unit의 장치 식별자(VPD 0x80, 0x83)를 다른 Target과 구분하는 값을 정한다.
    ///
    /// 식별자는 이 값과 LUN 번호에서 만든다. 같은 Initiator가 여러 Target에 연결해도
    /// 서로 다른 disk로 보이도록 Target마다 고유한 값, 보통 iSCSI name을 준다.
    pub fn set_identity_namespace(&mut self, namespace: impl AsRef<[u8]>) {
        self.identity_namespace = namespace.as_ref().to_vec();
    }

    /// `lun`은 LUN 번호이다. 같은 번호가 이미 있으면 교체하고 이전 backend를 반환한다.
    pub fn add_lun(
        &mut self,
        lun: u64,
        backend: impl StorageBackend + 'static,
    ) -> Result<Option<Box<dyn StorageBackend>>, InvalidLun> {
        self.add_boxed_lun(lun, Box::new(backend))
    }

    pub fn add_boxed_lun(
        &mut self,
        lun: u64,
        backend: Box<dyn StorageBackend>,
    ) -> Result<Option<Box<dyn StorageBackend>>, InvalidLun> {
        if lun > MAX_LUN {
            return Err(InvalidLun(lun));
        }
        Ok(self
            .luns
            .insert(
                lun,
                Lun {
                    backend,
                    last_sense: Bytes::new(),
                },
            )
            .map(|old| old.backend))
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

    pub fn lun_info(&self) -> Vec<LunInfo> {
        self.luns
            .iter()
            .map(|(lun, device)| LunInfo {
                lun: *lun,
                block_size: device.backend.block_size(),
                block_count: device.backend.block_count(),
                read_only: device.backend.read_only(),
            })
            .collect()
    }

    /// `lun`은 iSCSI BHS의 8-byte LUN 값이다. LUN 번호가 아니다.
    pub fn execute(&mut self, lun: u64, cdb: &[u8; 16], data_out: &[u8]) -> ScsiExecution {
        let result = self.execute_command(lun, cdb, data_out);
        log_command(lun, cdb, &result);
        result
    }

    fn execute_command(&mut self, lun: u64, cdb: &[u8; 16], data_out: &[u8]) -> ScsiExecution {
        if cdb[0] == 0xa0 {
            return self.report_luns(cdb);
        }
        let Some((number, device)) =
            decode_lun(lun).and_then(|number| Some((number, self.luns.get_mut(&number)?)))
        else {
            let result = execute_unsupported_lun(cdb);
            if result.status == STATUS_CHECK_CONDITION {
                log_check_condition(lun, cdb, &result.sense);
            }
            return result;
        };
        let identity = DeviceIdentity::new(&self.identity_namespace, number);
        let result = execute_lun(device, identity, cdb, data_out, self.max_transfer_length);
        if result.status == STATUS_CHECK_CONDITION {
            log_check_condition(lun, cdb, &result.sense);
            device.last_sense = result.sense.clone();
        }
        result
    }

    /// REPORT LUNS (SPC-4 §6.33). 어느 LUN으로 보내도 같은 목록을 돌려준다.
    fn report_luns(&self, cdb: &[u8; 16]) -> ScsiExecution {
        let luns: Vec<u64> = match cdb[2] {
            // 0x00: 접근 가능한 logical unit, 0x02: 전체. 이 Target에서는 둘이 같다.
            0x00 | 0x02 => self.luns.keys().copied().filter_map(encode_lun).collect(),
            // 0x01: well known logical unit만. 이 Target에는 없다.
            0x01 => Vec::new(),
            _ => return check_condition(SENSE_ILLEGAL_REQUEST, 0x24, 0x00),
        };
        let allocation = be_u32(cdb, 6) as usize;
        let list_length = luns.len().saturating_mul(8);
        let mut output = Vec::with_capacity(8 + list_length);
        output.extend_from_slice(&(list_length as u32).to_be_bytes());
        output.extend_from_slice(&[0; 4]);
        for lun in luns {
            output.extend_from_slice(&lun.to_be_bytes());
        }
        output.truncate(output.len().min(allocation));
        ScsiExecution::good(output)
    }
}

/// 이 Target에 없는 logical unit으로 온 명령을 처리한다.
///
/// INQUIRY와 REQUEST SENSE는 logical unit이 없어도 GOOD으로 답해야 Initiator가 LUN 탐색을
/// 이어 갈 수 있다. 예를 들어 LUN 0을 설정하지 않은 Target에서 Initiator는 LUN 0에
/// INQUIRY를 먼저 보낸다.
fn execute_unsupported_lun(cdb: &[u8; 16]) -> ScsiExecution {
    match cdb[0] {
        // SPC-4 §6.4.2: peripheral qualifier 011b, device type 1Fh로 "지원할 수 없는
        // logical unit"임을 standard INQUIRY data에 담아 돌려준다.
        0x12 if cdb[1] & 1 == 0 && cdb[2] == 0 => {
            let mut output = standard_inquiry_data(0x7f);
            output.truncate(be_u16(cdb, 3) as usize);
            ScsiExecution::good(output)
        }
        // SPC-4 §6.39: sense data를 parameter data로 돌려주고 status는 GOOD이다.
        0x03 => {
            let mut sense = fixed_sense(SENSE_ILLEGAL_REQUEST, 0x25, 0x00).to_vec();
            sense.truncate(cdb[4] as usize);
            ScsiExecution::good(sense)
        }
        _ => check_condition(SENSE_ILLEGAL_REQUEST, 0x25, 0x00),
    }
}

/// logical unit 하나의 장치 식별자.
///
/// Target의 identity namespace와 LUN 번호의 FNV-1a 64-bit hash이다. 같은 Target의 서로
/// 다른 LUN은 항상 다른 값을 갖고, namespace가 다른 Target끼리는 사실상 겹치지 않는다.
/// Initiator는 이 값으로 disk를 구분하므로, 여러 LUN이 같은 값을 내면 한 disk의 중복
/// 경로로 오인될 수 있다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeviceIdentity(u64);

impl DeviceIdentity {
    fn new(namespace: &[u8], lun: u64) -> Self {
        const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
        const PRIME: u64 = 0x0000_0100_0000_01b3;
        // namespace와 LUN 번호 사이의 0은 둘의 경계를 고정한다.
        let hash = namespace
            .iter()
            .copied()
            .chain([0])
            .chain(lun.to_be_bytes())
            .fold(OFFSET_BASIS, |hash, byte| {
                (hash ^ u64::from(byte)).wrapping_mul(PRIME)
            });
        Self(hash)
    }

    /// VPD 0x80의 product serial number. 16자리 대문자 hexadecimal이다.
    fn serial_number(self) -> [u8; 16] {
        const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
        let mut serial = [0; 16];
        for (index, digit) in serial.iter_mut().enumerate() {
            *digit = DIGITS[((self.0 >> (60 - 4 * index)) & 0xf) as usize];
        }
        serial
    }

    /// NAA Locally Assigned designator (SPC-4 §7.8.6.6.5). 첫 nibble이 3h이고 나머지
    /// 60 bit가 이 Target이 정한 값이다. IEEE company ID가 없으므로 이 형식을 쓴다.
    fn naa_locally_assigned(self) -> [u8; 8] {
        ((self.0 & 0x0fff_ffff_ffff_ffff) | 0x3000_0000_0000_0000).to_be_bytes()
    }
}

fn execute_lun(
    device: &mut Lun,
    identity: DeviceIdentity,
    cdb: &[u8; 16],
    data_out: &[u8],
    max_transfer_length: usize,
) -> ScsiExecution {
    match cdb[0] {
        0x00 => ScsiExecution::good(Vec::new()),
        0x03 => request_sense(device, cdb),
        0x12 => inquiry(cdb, identity),
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

const INQUIRY_VENDOR: &[u8; 8] = b"RUSTISCS";

/// standard INQUIRY data (SPC-4 §6.4.2). `peripheral`은 byte 0의 peripheral qualifier와
/// device type이다.
fn standard_inquiry_data(peripheral: u8) -> Vec<u8> {
    let mut value = vec![0; 36];
    value[0] = peripheral;
    value[2] = 0x06;
    value[3] = 0x02;
    value[4] = 31;
    value[7] = 0x02;
    value[8..16].copy_from_slice(INQUIRY_VENDOR);
    value[16..32].copy_from_slice(b"VIRTUAL DISK    ");
    value[32..36].copy_from_slice(b"0001");
    value
}

fn inquiry(cdb: &[u8; 16], identity: DeviceIdentity) -> ScsiExecution {
    let evpd = cdb[1] & 1 != 0;
    let page = cdb[2];
    let allocation = be_u16(cdb, 3) as usize;
    let mut output = if !evpd && page == 0 {
        standard_inquiry_data(0x00)
    } else if evpd {
        let Some(value) = inquiry_vpd(page, identity) else {
            return check_condition(SENSE_ILLEGAL_REQUEST, 0x24, 0x00);
        };
        value
    } else {
        return check_condition(SENSE_ILLEGAL_REQUEST, 0x24, 0x00);
    };
    output.truncate(allocation.min(output.len()));
    ScsiExecution::good(output)
}

fn inquiry_vpd(page: u8, identity: DeviceIdentity) -> Option<Vec<u8>> {
    let payload: Vec<u8> = match page {
        0x00 => vec![0x00, 0x80, 0x83],
        0x80 => identity.serial_number().to_vec(),
        // Device Identification (SPC-4 §7.8.6). 두 designator 모두 logical unit에 대한
        // 것이다 (association 00b).
        0x83 => {
            // NAA designator: code set 1h(binary), designator type 3h.
            let mut descriptors = vec![0x01, 0x03, 0x00, 8];
            descriptors.extend_from_slice(&identity.naa_locally_assigned());
            // T10 vendor ID designator: code set 2h(ASCII), designator type 1h.
            // vendor ID 8 byte 뒤에 vendor가 정한 식별자가 온다.
            let serial = identity.serial_number();
            descriptors.extend_from_slice(&[
                0x02,
                0x01,
                0x00,
                (INQUIRY_VENDOR.len() + serial.len()) as u8,
            ]);
            descriptors.extend_from_slice(INQUIRY_VENDOR);
            descriptors.extend_from_slice(&serial);
            descriptors
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
        StorageError::Io(error) => {
            log_storage_io_error(&error);
            check_condition(0x03, 0x11, 0x00)
        }
    }
}

// 로그에는 LUN, opcode, 대상 LBA 또는 page code, sense와 backend 오류 요약만 남긴다.
// data payload는 어떤 레벨에서도 기록하지 않는다.

/// 로그에 쓸 LUN 표기. LUN 번호로 풀리면 그 번호, 아니면 8-byte 값 그대로이다.
#[cfg(feature = "tracing")]
fn lun_label(wire: u64) -> String {
    match decode_lun(wire) {
        Some(number) => number.to_string(),
        None => format!("{wire:#018x}"),
    }
}

fn log_command(lun: u64, cdb: &[u8; 16], result: &ScsiExecution) {
    #[cfg(feature = "tracing")]
    tracing::trace!(
        lun = lun_label(lun),
        opcode = format_args!("{:#04x}", cdb[0]),
        lba = cdb_lba(cdb),
        page = cdb_page_code(cdb).map(|page| format!("{page:#04x}")),
        status = format_args!("{:#04x}", result.status),
        data_in_length = result.data.len(),
        "SCSI 명령을 실행했다"
    );
    #[cfg(not(feature = "tracing"))]
    let _ = (lun, cdb, result);
}

fn log_check_condition(lun: u64, cdb: &[u8; 16], sense: &[u8]) {
    // read-only LUN에 대한 write는 Initiator 쪽에서 조용히 실패할 수 있으므로 기본 로그
    // 레벨에서도 보이게 한다.
    #[cfg(feature = "tracing")]
    if sense.get(2).copied().unwrap_or(0) & 0x0f == SENSE_DATA_PROTECT {
        tracing::warn!(
            lun = lun_label(lun),
            opcode = format_args!("{:#04x}", cdb[0]),
            lba = cdb_lba(cdb),
            "read-only LUN에 대한 write 요청을 거부했다"
        );
        return;
    }
    #[cfg(feature = "tracing")]
    tracing::debug!(
        lun = lun_label(lun),
        opcode = format_args!("{:#04x}", cdb[0]),
        lba = cdb_lba(cdb),
        page = cdb_page_code(cdb).map(|page| format!("{page:#04x}")),
        sense_key = format_args!("{:#04x}", sense.get(2).copied().unwrap_or(0) & 0x0f),
        asc = format_args!("{:#04x}", sense.get(12).copied().unwrap_or(0)),
        ascq = format_args!("{:#04x}", sense.get(13).copied().unwrap_or(0)),
        "SCSI 명령이 CHECK CONDITION으로 끝났다"
    );
    #[cfg(not(feature = "tracing"))]
    let _ = (lun, cdb, sense);
}

/// READ/WRITE (10/12/16) CDB의 시작 LBA.
#[cfg(feature = "tracing")]
fn cdb_lba(cdb: &[u8; 16]) -> Option<u64> {
    match cdb[0] {
        0x28 | 0x2a | 0xa8 | 0xaa => Some(u64::from(be_u32(cdb, 2))),
        0x88 | 0x8a => Some(be_u64(cdb, 2)),
        _ => None,
    }
}

/// INQUIRY와 MODE SENSE (6/10) CDB의 page code.
#[cfg(feature = "tracing")]
fn cdb_page_code(cdb: &[u8; 16]) -> Option<u8> {
    match cdb[0] {
        0x12 => Some(cdb[2]),
        0x1a | 0x5a => Some(cdb[2] & 0x3f),
        _ => None,
    }
}

fn log_storage_io_error(error: &StorageIoError) {
    #[cfg(feature = "tracing")]
    tracing::warn!(%error, "Storage backend I/O 오류를 MEDIUM ERROR로 보고한다");
    #[cfg(not(feature = "tracing"))]
    let _ = error;
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
        target
            .add_lun(0, MemoryBackend::new(512, 32).unwrap())
            .unwrap();
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
        target.add_lun(1, backend).unwrap();
        let mut write = [0; 16];
        write[0] = 0x2a;
        write[8] = 1;
        let result = target.execute(wire_lun(1), &write, &[0; 512]);
        assert_eq!((result.sense[2], result.sense[12]), (7, 0x27));
    }

    fn wire_lun(number: u64) -> u64 {
        encode_lun(number).unwrap()
    }

    fn command(opcode: u8) -> [u8; 16] {
        let mut cdb = [0; 16];
        cdb[0] = opcode;
        cdb
    }

    #[test]
    fn lun_numbers_use_sam_single_level_wire_encoding() {
        // SAM-5 §4.7.7.2: peripheral device addressing, bus identifier 0.
        assert_eq!(encode_lun(0), Some(0));
        assert_eq!(encode_lun(1), Some(0x0001_0000_0000_0000));
        assert_eq!(encode_lun(255), Some(0x00ff_0000_0000_0000));
        // SAM-5 §4.7.7.3: flat space addressing, method 01b와 14-bit LUN.
        assert_eq!(encode_lun(256), Some(0x4100_0000_0000_0000));
        assert_eq!(encode_lun(300), Some(0x412c_0000_0000_0000));
        assert_eq!(encode_lun(MAX_LUN), Some(0x7fff_0000_0000_0000));
        assert_eq!(encode_lun(MAX_LUN + 1), None);
        assert_eq!(encode_lun(u64::MAX), None);

        for number in [0, 1, 2, 255, 256, 300, MAX_LUN] {
            assert_eq!(decode_lun(wire_lun(number)), Some(number));
        }
        // flat space addressing은 작은 번호에도 쓸 수 있다.
        assert_eq!(decode_lun(0x4005_0000_0000_0000), Some(5));
    }

    #[test]
    fn wire_values_outside_the_supported_addressing_are_not_luns() {
        // LUN 번호를 인코딩하지 않고 그대로 넣은 값. 둘째 level 이하가 0이 아니다.
        assert_eq!(decode_lun(1), None);
        assert_eq!(decode_lun(0x0001_0000_0000_0001), None);
        assert_eq!(decode_lun(0x0001_0001_0000_0000), None);
        // peripheral device addressing의 bus identifier가 0이 아니다.
        assert_eq!(decode_lun(0x0100_0000_0000_0000), None);
        assert_eq!(decode_lun(0x3f05_0000_0000_0000), None);
        // logical unit addressing(10b)과 extended addressing(11b, well known LUN 포함).
        assert_eq!(decode_lun(0x8001_0000_0000_0000), None);
        assert_eq!(decode_lun(0xc101_0000_0000_0000), None);
        assert_eq!(decode_lun(u64::MAX), None);
    }

    #[test]
    fn lun_numbers_beyond_the_encodable_range_are_rejected() {
        let mut target = ScsiTarget::default();
        assert!(target
            .add_lun(MAX_LUN, MemoryBackend::new(512, 1).unwrap())
            .unwrap()
            .is_none());
        assert_eq!(
            target
                .add_lun(MAX_LUN + 1, MemoryBackend::new(512, 1).unwrap())
                .err(),
            Some(InvalidLun(MAX_LUN + 1))
        );
        assert_eq!(target.lun_info().len(), 1);

        let shared = SharedScsiTarget::default();
        assert_eq!(
            shared.add_lun(MAX_LUN + 1, MemoryBackend::new(512, 1).unwrap()),
            Err(SharedScsiTargetError::InvalidLun(InvalidLun(MAX_LUN + 1)))
        );
        assert!(shared.lun_info().unwrap().is_empty());
    }

    fn multi_lun_target() -> ScsiTarget {
        let mut target = ScsiTarget::default();
        target.set_identity_namespace("iqn.2026-10.local.test:disk");
        for (lun, blocks) in [(300, 4), (0, 1), (2, 3)] {
            target
                .add_lun(lun, MemoryBackend::new(512, blocks).unwrap())
                .unwrap();
        }
        target
    }

    #[test]
    fn report_luns_lists_wire_encoded_luns_in_ascending_order() {
        let mut target = multi_lun_target();
        let mut report = command(0xa0);
        report[6..10].copy_from_slice(&64u32.to_be_bytes());
        let expected: &[u8] = &[
            0, 0, 0, 24, 0, 0, 0, 0, // LUN list length, reserved
            0x00, 0x00, 0, 0, 0, 0, 0, 0, // LUN 0
            0x00, 0x02, 0, 0, 0, 0, 0, 0, // LUN 2
            0x41, 0x2c, 0, 0, 0, 0, 0, 0, // LUN 300
        ];
        // 어느 LUN으로 보내도, 없는 LUN으로 보내도 같은 목록이다.
        for lun in [0, wire_lun(2), wire_lun(9), 0xc101_0000_0000_0000] {
            let result = target.execute(lun, &report, &[]);
            assert_eq!(result.status, STATUS_GOOD);
            assert_eq!(result.data.as_ref(), expected);
        }

        // SELECT REPORT 02h도 같은 목록이고 01h(well known LUN)는 빈 목록이다.
        report[2] = 0x02;
        assert_eq!(target.execute(0, &report, &[]).data.as_ref(), expected);
        report[2] = 0x01;
        assert_eq!(
            target.execute(0, &report, &[]).data.as_ref(),
            &[0, 0, 0, 0, 0, 0, 0, 0]
        );
        report[2] = 0x03;
        let result = target.execute(0, &report, &[]);
        assert_eq!((result.status, result.sense[12]), (2, 0x24));

        // allocation length가 작으면 잘라 보내되 LUN list length는 전체 길이를 알린다.
        report[2] = 0x00;
        report[6..10].copy_from_slice(&16u32.to_be_bytes());
        assert_eq!(
            target.execute(0, &report, &[]).data.as_ref(),
            &expected[..16]
        );
    }

    #[test]
    fn commands_reach_the_logical_unit_named_by_the_wire_lun() {
        let mut target = multi_lun_target();
        let capacity = command(0x25);
        for (number, last_lba) in [(0, 0), (2, 2), (300, 3)] {
            assert_eq!(
                target
                    .execute(wire_lun(number), &capacity, &[])
                    .data
                    .as_ref(),
                &[0, 0, 0, last_lba, 0, 0, 2, 0],
                "LUN {number}"
            );
        }

        // 한 LUN에 쓴 data는 그 LUN에서만 읽힌다.
        let mut write = command(0x2a);
        write[8] = 1;
        assert_eq!(
            target.execute(wire_lun(2), &write, &[0x5a; 512]).status,
            STATUS_GOOD
        );
        let mut read = command(0x28);
        read[8] = 1;
        assert_eq!(
            target.execute(wire_lun(2), &read, &[]).data.as_ref(),
            &[0x5a; 512]
        );
        assert_eq!(target.execute(0, &read, &[]).data.as_ref(), &[0; 512]);

        // 인코딩하지 않은 번호와 설정하지 않은 LUN은 logical unit이 아니다.
        for lun in [2, wire_lun(1), wire_lun(299)] {
            let result = target.execute(lun, &capacity, &[]);
            assert_eq!(
                (result.status, result.sense[2], result.sense[12]),
                (2, 5, 0x25),
                "wire LUN {lun:#018x}"
            );
        }
    }

    #[test]
    fn unsupported_lun_answers_inquiry_and_request_sense_with_good_status() {
        // LUN 0이 없는 Target: Initiator는 그래도 LUN 0부터 탐색한다.
        let mut target = ScsiTarget::default();
        target
            .add_lun(2, MemoryBackend::new(512, 1).unwrap())
            .unwrap();

        let mut inquiry = command(0x12);
        inquiry[4] = 96;
        let result = target.execute(0, &inquiry, &[]);
        assert_eq!(result.status, STATUS_GOOD);
        assert_eq!(result.data.len(), 36);
        // peripheral qualifier 011b, device type 1Fh.
        assert_eq!(result.data[0], 0x7f);
        assert_eq!(result.data[4], 31);
        assert_eq!(&result.data[8..16], b"RUSTISCS");
        assert_eq!(target.execute(wire_lun(2), &inquiry, &[]).data[0], 0x00);

        inquiry[4] = 5;
        assert_eq!(
            target.execute(0, &inquiry, &[]).data.as_ref(),
            &[0x7f, 0, 6, 2, 31]
        );

        // VPD page는 logical unit이 있어야 답할 수 있다.
        inquiry[1] = 1;
        inquiry[2] = 0x83;
        inquiry[4] = 96;
        let result = target.execute(0, &inquiry, &[]);
        assert_eq!(
            (result.status, result.sense[2], result.sense[12]),
            (2, 5, 0x25)
        );

        let mut request_sense = command(0x03);
        request_sense[4] = 18;
        let result = target.execute(0, &request_sense, &[]);
        assert_eq!(result.status, STATUS_GOOD);
        assert_eq!(
            (
                result.data[0],
                result.data[2],
                result.data[12],
                result.data[13]
            ),
            (0x70, 5, 0x25, 0x00)
        );

        let result = target.execute(0, &command(0x00), &[]);
        assert_eq!(
            (result.status, result.sense[2], result.sense[12]),
            (2, 5, 0x25)
        );
    }

    #[test]
    fn each_logical_unit_reports_its_own_device_identity() {
        // 기대값은 Python으로 따로 계산한 FNV-1a 64(namespace, 0x00, LUN 번호 8 byte)이다.
        let mut target = multi_lun_target();
        let mut serial = command(0x12);
        serial[1] = 1;
        serial[2] = 0x80;
        serial[4] = 96;
        let expected = [
            (0, &b"0CCD5F7D53575CE3"[..]),
            (2, b"0CCD617D53576049"),
            (300, b"0CCA0D7D53549BB6"),
        ];
        for (number, expected) in expected {
            let result = target.execute(wire_lun(number), &serial, &[]);
            assert_eq!(result.status, STATUS_GOOD);
            assert_eq!(&result.data[..4], &[0, 0x80, 0, 16]);
            assert_eq!(&result.data[4..], expected, "LUN {number}");
        }

        let mut identification = command(0x12);
        identification[1] = 1;
        identification[2] = 0x83;
        identification[4] = 96;
        let mut page = vec![0, 0x83, 0, 40];
        // NAA Locally Assigned: 첫 nibble 3h와 hash의 하위 60 bit.
        page.extend([0x01, 0x03, 0x00, 8]);
        page.extend([0x3c, 0xcd, 0x5f, 0x7d, 0x53, 0x57, 0x5c, 0xe3]);
        // T10 vendor ID: vendor 8 byte와 serial number.
        page.extend([0x02, 0x01, 0x00, 24]);
        page.extend(b"RUSTISCS0CCD5F7D53575CE3");
        assert_eq!(
            target.execute(0, &identification, &[]).data.as_ref(),
            page.as_slice()
        );
        let other = target.execute(wire_lun(2), &identification, &[]);
        assert_eq!(
            &other.data[8..16],
            &[0x3c, 0xcd, 0x61, 0x7d, 0x53, 0x57, 0x60, 0x49]
        );

        // namespace가 다른 Target의 같은 LUN 번호는 다른 장치이다.
        let mut unnamed = ScsiTarget::default();
        unnamed
            .add_lun(0, MemoryBackend::new(512, 1).unwrap())
            .unwrap();
        assert_eq!(
            &unnamed.execute(0, &serial, &[]).data[4..],
            b"E604823A249029BF"
        );
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
            let mut backend = FileBackend::create_fixed(&path, 512, 2).unwrap();
            backend.set_durable_flush(false);
            assert_eq!(backend.block_count(), 2);
            backend.write_blocks(1, &[0x6d; 512]).unwrap();
            backend.flush().unwrap();
        }
        {
            let mut target = ScsiTarget::default();
            target
                .add_lun(0, FileBackend::open_read_write(&path, 512).unwrap())
                .unwrap();
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
        FileBackend::create_fixed(&path, 512, 1).unwrap();
        let mut target = ScsiTarget::default();
        target
            .add_lun(0, FileBackend::open_read_only(&path, 512).unwrap())
            .unwrap();
        let mut write = [0; 16];
        write[0] = 0x2a;
        write[8] = 1;
        let result = target.execute(0, &write, &[0; 512]);
        assert_eq!((result.sense[2], result.sense[12]), (7, 0x27));

        // Windows의 FlushFileBuffers는 write 접근이 없는 handle에서 거부된다. read-only
        // LUN의 SYNCHRONIZE CACHE는 내보낼 data가 없으므로 backend를 건드리지 않고 성공한다.
        for opcode in [0x35, 0x91] {
            let mut synchronize = [0; 16];
            synchronize[0] = opcode;
            assert_eq!(target.execute(0, &synchronize, &[]).status, STATUS_GOOD);
        }
        drop(target);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn fixed_creation_never_truncates_an_existing_file_and_keeps_io_context() {
        let path = temp_image_path("existing");
        fs::write(&path, b"keep-this-data").unwrap();

        let error = FileBackend::create_fixed(&path, 512, 1).unwrap_err();
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
