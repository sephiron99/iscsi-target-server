//! Windows physical disk 및 volume Storage backend.
//!
//! Win32 handle과 `DeviceIoControl` 사용은 이 모듈 안에만 격리한다. 상위 계층은
//! [`StorageBackend`]만 사용하며 장치 경로나 Win32 타입을 알 필요가 없다.
//!
//! serve할 disk를 고르는 화면을 위해 [`physical_disks`]가 이 PC의 physical disk를
//! 열거한다.

use std::ffi::{OsString, c_void};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::OsStringExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    BusType1394, BusTypeAta, BusTypeAtapi, BusTypeFibre, BusTypeFileBackedVirtual, BusTypeMmc,
    BusTypeNvme, BusTypeRAID, BusTypeSas, BusTypeSata, BusTypeScsi, BusTypeSd, BusTypeSpaces,
    BusTypeUfs, BusTypeUsb, BusTypeVirtual, BusTypeiScsi, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Ioctl::{
    DISK_ATTRIBUTE_OFFLINE, DISK_EXTENT, DISK_GEOMETRY, DISK_GEOMETRY_EX, FSCTL_DISMOUNT_VOLUME,
    FSCTL_LOCK_VOLUME, GET_DISK_ATTRIBUTES, GET_LENGTH_INFORMATION, IOCTL_DISK_GET_DISK_ATTRIBUTES,
    IOCTL_DISK_GET_DRIVE_GEOMETRY, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, IOCTL_DISK_GET_LENGTH_INFO,
    IOCTL_DISK_SET_DISK_ATTRIBUTES, IOCTL_STORAGE_QUERY_PROPERTY, PropertyStandardQuery,
    SET_DISK_ATTRIBUTES, STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR, STORAGE_DEVICE_DESCRIPTOR,
    STORAGE_PROPERTY_QUERY, StorageAccessAlignmentProperty, StorageDeviceProperty,
    VOLUME_DISK_EXTENTS,
};

use crate::scsi_target::{
    StorageBackend, StorageError, StorageIoOperation, block_io_offset, storage_io_error,
};

/// raw device를 열 때 허용할 접근 방식.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsStorageAccess {
    /// 장치를 공유 읽기로 열며 모든 write 요청을 거부한다.
    ReadOnly,
    /// 장치를 배타적으로 열고 write 요청을 허용한다.
    ReadWrite,
}

impl WindowsStorageAccess {
    fn read_only(self) -> bool {
        matches!(self, Self::ReadOnly)
    }
}

/// 열려는 raw device 종류. `ReadWrite`에서 volume 잠금 범위를 결정한다.
enum WindowsDeviceKind {
    Volume,
    PhysicalDrive { device_number: u32 },
}

/// Windows physical disk 또는 volume handle을 감싼 block backend.
///
/// `ReadWrite` volume은 handle 수명 동안 `FSCTL_LOCK_VOLUME`을 획득하고 dismount한다.
///
/// physical disk는 접근 방식과 무관하게 serve 전에 경고를 남기고 disk를 offline으로
/// 바꾼다. host가 같은 disk의 volume을 mount한 채로 Initiator에 내주면 양쪽 filesystem이
/// 서로 모르는 변경을 하게 되고, 같은 PC의 Initiator는 disk signature 충돌을 만나기
/// 때문이다. offline 전환은 재부팅 후 유지되지 않게 요청하며, 이 backend가 offline으로
/// 바꾼 disk는 drop할 때 다시 online으로 되돌린다. 이미 offline이던 disk는 그대로 둔다.
///
/// offline 전환에 실패한 disk는 경고 후 이전 방식으로
/// 동작한다: `ReadWrite`이면 그 위의 mounted volume을 전부 lock/dismount하고 잠금
/// handle을 backend 수명 동안 유지한다 — Windows가 mounted volume extent에 대한 physical
/// disk 직접 write를 차단하기 때문이다. `ReadOnly`이면 volume을 건드리지 않는다.
///
/// 모든 경우에 보통 관리자 권한이 필요하다.
#[derive(Debug)]
pub struct WindowsStorageBackend {
    file: File,
    block_size: u32,
    block_count: u64,
    read_only: bool,
    durable_flush: bool,
    /// physical disk를 `ReadWrite`로 여는 동안 잠근 volume handle들.
    /// 잠금은 handle이 닫힐 때 해제되므로 backend 수명 동안 보관만 한다.
    _volume_locks: Vec<File>,
    /// 이 backend가 offline으로 바꾼 physical disk. drop하면 online으로 되돌린다.
    _offline: Option<DiskOfflineGuard>,
    /// physical disk를 host로부터 어떻게 보호하고 있는지. volume이면 `None`이다.
    disk_protection: Option<DiskProtection>,
}

/// serve하는 physical disk를 host의 접근으로부터 보호하는 방식.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskProtection {
    /// 이 backend가 disk를 offline으로 바꿨고 닫을 때 되돌린다.
    TakenOffline,
    /// 열기 전부터 offline이었다. 그대로 두고 닫을 때도 건드리지 않는다.
    AlreadyOffline,
    /// offline으로 바꾸지 못해 disk 위의 mounted volume을 lock/dismount했다.
    VolumeLock,
    /// offline으로 바꾸지 못했고 read-only라 volume도 건드리지 않았다. 보호가 없다.
    None,
}

impl std::fmt::Display for DiskProtection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::TakenOffline => "offline",
            Self::AlreadyOffline => "already-offline",
            Self::VolumeLock => "volume-lock",
            Self::None => "online",
        })
    }
}

impl WindowsStorageBackend {
    /// `\\.\PhysicalDriveN` 장치를 연다.
    pub fn open_physical_drive(
        device_number: u32,
        access: WindowsStorageAccess,
    ) -> Result<Self, StorageError> {
        let path = PathBuf::from(format!(r"\\.\PhysicalDrive{device_number}"));
        Self::open(
            path,
            access,
            WindowsDeviceKind::PhysicalDrive { device_number },
        )
    }

    /// drive letter에 대응하는 `\\.\X:` volume을 연다.
    pub fn open_volume(
        drive_letter: char,
        access: WindowsStorageAccess,
    ) -> Result<Self, StorageError> {
        if !drive_letter.is_ascii_alphabetic() {
            return Err(StorageError::OutOfRange);
        }
        let drive_letter = drive_letter.to_ascii_uppercase();
        let path = PathBuf::from(format!(r"\\.\{drive_letter}:"));
        Self::open(path, access, WindowsDeviceKind::Volume)
    }

    pub fn set_durable_flush(&mut self, value: bool) {
        self.durable_flush = value;
    }

    pub fn durable_flush(&self) -> bool {
        self.durable_flush
    }

    /// physical disk를 host로부터 어떻게 보호하고 있는지. volume이면 `None`이다.
    pub fn disk_protection(&self) -> Option<DiskProtection> {
        self.disk_protection
    }

    fn open(
        path: PathBuf,
        access: WindowsStorageAccess,
        kind: WindowsDeviceKind,
    ) -> Result<Self, StorageError> {
        let read_only = access.read_only();
        let share_mode = if read_only {
            FILE_SHARE_READ | FILE_SHARE_WRITE
        } else {
            0
        };
        let file = OpenOptions::new()
            .read(true)
            .write(!read_only)
            .share_mode(share_mode)
            .open(&path)
            .map_err(|error| storage_io_error(StorageIoOperation::Open, error))?;

        let (offline, already_offline) = match kind {
            WindowsDeviceKind::Volume => (None, false),
            WindowsDeviceKind::PhysicalDrive { device_number } => {
                take_disk_offline(&path, &file, read_only, device_number)
            }
        };
        let disk_protection = match kind {
            WindowsDeviceKind::Volume => None,
            WindowsDeviceKind::PhysicalDrive { .. } => Some(if offline.is_some() {
                DiskProtection::TakenOffline
            } else if already_offline {
                DiskProtection::AlreadyOffline
            } else if read_only {
                DiskProtection::None
            } else {
                DiskProtection::VolumeLock
            }),
        };

        let volume_locks = if read_only {
            Vec::new()
        } else {
            match kind {
                WindowsDeviceKind::Volume => {
                    device_io_control_no_buffers(&file, FSCTL_LOCK_VOLUME)?;
                    device_io_control_no_buffers(&file, FSCTL_DISMOUNT_VOLUME)?;
                    Vec::new()
                }
                // offline disk에는 mounted volume이 없으므로 잠글 대상도 없다.
                WindowsDeviceKind::PhysicalDrive { .. } if offline.is_some() => Vec::new(),
                WindowsDeviceKind::PhysicalDrive { device_number } => {
                    lock_mounted_volumes_on_disk(device_number)?
                }
            }
        };

        let length = query_device_length(&file)?;
        let block_size = query_logical_sector_size(&file)?;
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
            _volume_locks: volume_locks,
            _offline: offline,
            disk_protection,
        })
    }
}

impl StorageBackend for WindowsStorageBackend {
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
            .map_err(|error| storage_io_error(StorageIoOperation::Read, error))
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
            .map_err(|error| storage_io_error(StorageIoOperation::Write, error))
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

fn query_device_length(file: &File) -> Result<u64, StorageError> {
    let info: GET_LENGTH_INFORMATION = device_io_control_output(file, IOCTL_DISK_GET_LENGTH_INFO)?;
    u64::try_from(info.Length).map_err(|_| StorageError::OutOfRange)
}

/// logical sector 크기를 조회한다.
///
/// `StorageAccessAlignmentProperty`는 USB mass-storage bridge 다수가 구현하지 않아
/// `ERROR_INVALID_FUNCTION` 등으로 실패하므로, 그 경우 모든 disk 장치가 지원하는
/// `IOCTL_DISK_GET_DRIVE_GEOMETRY`의 `BytesPerSector`로 fallback한다.
fn query_logical_sector_size(file: &File) -> Result<u32, StorageError> {
    if let Ok(descriptor) = query_access_alignment(file)
        && descriptor.BytesPerLogicalSector != 0
    {
        return Ok(descriptor.BytesPerLogicalSector);
    }
    let geometry: DISK_GEOMETRY = device_io_control_output(file, IOCTL_DISK_GET_DRIVE_GEOMETRY)?;
    if geometry.BytesPerSector == 0 {
        return Err(StorageError::OutOfRange);
    }
    Ok(geometry.BytesPerSector)
}

fn query_access_alignment(
    file: &File,
) -> Result<STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR, StorageError> {
    let query = STORAGE_PROPERTY_QUERY {
        PropertyId: StorageAccessAlignmentProperty,
        QueryType: PropertyStandardQuery,
        AdditionalParameters: [0],
    };
    device_io_control(file, IOCTL_STORAGE_QUERY_PROPERTY, &query)
}

/// offline으로 바꾼 physical disk를 drop 시점에 online으로 되돌리는 guard.
///
/// `control`은 `IOCTL_DISK_SET_DISK_ATTRIBUTES`가 요구하는 read/write 접근을 가진
/// handle이다. data handle과 별도로 소유하므로 field drop 순서에 의존하지 않는다.
#[derive(Debug)]
struct DiskOfflineGuard {
    control: File,
    device_number: u32,
}

impl Drop for DiskOfflineGuard {
    fn drop(&mut self) {
        match set_disk_offline(&self.control, false) {
            Ok(()) => log_disk_restored_online(self.device_number),
            Err(error) => log_disk_online_restore_failed(self.device_number, &error),
        }
    }
}

/// physical disk를 경고 후 offline으로 바꾸고, 바꿨다면 복원 guard를 반환한다.
///
/// offline 전환은 serve의 전제 조건이 아니라 보호 조치이므로 실패해도 open을
/// 중단하지 않는다. 이미 offline이거나 전환할 수 없으면 guard 없이 반환하고 호출자가
/// volume lock 방식으로 계속한다. 두 번째 값은 disk가 이미 offline이었는지 여부다.
fn take_disk_offline(
    path: &Path,
    data: &File,
    read_only: bool,
    device_number: u32,
) -> (Option<DiskOfflineGuard>, bool) {
    // `ReadOnly` data handle에는 write 접근이 없어 attribute를 바꿀 수 없으므로 제어용
    // handle을 따로 연다. `ReadWrite` data handle은 배타적으로 열려 있어 두 번째 open이
    // 불가능하므로 같은 접근 권한을 가진 handle을 복제한다.
    let control = if read_only {
        OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(path)
    } else {
        data.try_clone()
    };
    let control = match control {
        Ok(control) => control,
        Err(error) => {
            let error = storage_io_error(StorageIoOperation::Open, error);
            log_disk_offline_unavailable(device_number, &error);
            return (None, false);
        }
    };

    match query_disk_offline(&control) {
        Ok(true) => {
            log_disk_already_offline(device_number);
            return (None, true);
        }
        Ok(false) => {}
        Err(error) => {
            log_disk_offline_unavailable(device_number, &error);
            return (None, false);
        }
    }

    log_disk_going_offline(device_number);
    match set_disk_offline(&control, true) {
        Ok(()) => (
            Some(DiskOfflineGuard {
                control,
                device_number,
            }),
            false,
        ),
        Err(error) => {
            log_disk_offline_unavailable(device_number, &error);
            (None, false)
        }
    }
}

fn query_disk_offline(disk: &File) -> Result<bool, StorageError> {
    let attributes: GET_DISK_ATTRIBUTES =
        device_io_control_output(disk, IOCTL_DISK_GET_DISK_ATTRIBUTES)?;
    Ok(attributes.Attributes & DISK_ATTRIBUTE_OFFLINE != 0)
}

fn set_disk_offline(disk: &File, offline: bool) -> Result<(), StorageError> {
    let request = disk_offline_request(offline)?;
    device_io_control_input(disk, IOCTL_DISK_SET_DISK_ATTRIBUTES, &request)
}

/// offline attribute 하나만 바꾸는 요청. `Persist`를 끄므로 server가 비정상 종료해
/// 복원하지 못해도 재부팅하면 disk가 원래 상태로 돌아온다.
fn disk_offline_request(offline: bool) -> Result<SET_DISK_ATTRIBUTES, StorageError> {
    Ok(SET_DISK_ATTRIBUTES {
        Version: u32::try_from(size_of::<SET_DISK_ATTRIBUTES>())
            .map_err(|_| StorageError::OutOfRange)?,
        Persist: false,
        Attributes: if offline { DISK_ATTRIBUTE_OFFLINE } else { 0 },
        AttributesMask: DISK_ATTRIBUTE_OFFLINE,
        ..SET_DISK_ATTRIBUTES::default()
    })
}

fn log_disk_going_offline(device_number: u32) {
    tracing::warn!(
        device_number,
        "taking the physical disk offline; its volumes are unavailable on this PC while it is served, and it is brought back online on exit"
    );
}

fn log_disk_already_offline(device_number: u32) {
    tracing::info!(
        device_number,
        "the physical disk is already offline; leaving it as it is, also on exit"
    );
}

fn log_disk_offline_unavailable(device_number: u32, error: &StorageError) {
    tracing::warn!(
        device_number,
        %error,
        "could not take the physical disk offline; serving it while online, so do not use its volumes on this PC"
    );
}

fn log_disk_restored_online(device_number: u32) {
    tracing::info!(device_number, "physical disk brought back online");
}

fn log_disk_online_restore_failed(device_number: u32, error: &StorageError) {
    tracing::warn!(
        device_number,
        %error,
        "could not bring the physical disk back online; restore it with Disk Management or a reboot"
    );
}

/// 대상 physical disk 위의 mounted volume을 모두 lock/dismount하고 handle을 반환한다.
///
/// Windows는 mounted volume extent에 대한 physical disk 직접 write를 차단하므로
/// read-write serve 전에 이 잠금이 필요하다. 대상 disk 소속으로 판정된 volume을
/// 잠글 수 없으면 전체를 실패로 처리한다. 열 수 없어 소속을 판정할 수 없는 volume은
/// 건너뛴다 (예: 접근이 제한된 시스템 volume — 대상 disk 소속이면 이후 write가
/// 거부되어 오류로 드러난다).
fn lock_mounted_volumes_on_disk(device_number: u32) -> Result<Vec<File>, StorageError> {
    let share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE;
    let mut locks = Vec::new();
    for path in mounted_volume_device_paths()? {
        let volume = match OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(share_mode)
            .open(&path)
        {
            Ok(volume) => volume,
            Err(error) => {
                // write 접근이 거부된 volume이라도 대상 disk 소속이면 잠글 수
                // 없으므로 실패해야 한다. read 접근으로 소속만 판정한다.
                let Ok(probe) = OpenOptions::new()
                    .read(true)
                    .share_mode(share_mode)
                    .open(&path)
                else {
                    continue;
                };
                if volume_spans_disk(&probe, device_number) {
                    return Err(storage_io_error(StorageIoOperation::Open, error));
                }
                continue;
            }
        };
        if !volume_spans_disk(&volume, device_number) {
            continue;
        }
        device_io_control_no_buffers(&volume, FSCTL_LOCK_VOLUME)?;
        device_io_control_no_buffers(&volume, FSCTL_DISMOUNT_VOLUME)?;
        locks.push(volume);
    }
    Ok(locks)
}

/// extents를 조회할 수 없는 volume(예: disk 기반이 아닌 장치)은 소속이 아닌 것으로 본다.
fn volume_spans_disk(volume: &File, device_number: u32) -> bool {
    query_volume_disk_numbers(volume)
        .map(|numbers| numbers.contains(&device_number))
        .unwrap_or(false)
}

/// 시스템의 mounted volume 장치 경로(`\\?\Volume{...}`) 목록을 반환한다.
fn mounted_volume_device_paths() -> Result<Vec<PathBuf>, StorageError> {
    struct FindVolumeGuard(HANDLE);
    impl Drop for FindVolumeGuard {
        fn drop(&mut self) {
            // SAFETY: handle은 FindFirstVolumeW가 반환한 유효한 열거 handle이다.
            unsafe { FindVolumeClose(self.0) };
        }
    }

    let mut name = [0u16; 260];
    // SAFETY: name은 선언한 길이만큼 유효한 wide 문자 buffer다.
    let handle = unsafe { FindFirstVolumeW(name.as_mut_ptr(), name.len() as u32) };
    if handle == INVALID_HANDLE_VALUE {
        return Err(storage_io_error(
            StorageIoOperation::Open,
            std::io::Error::last_os_error(),
        ));
    }
    let guard = FindVolumeGuard(handle);
    let mut paths = Vec::new();
    loop {
        if let Some(path) = volume_device_path(&name) {
            paths.push(path);
        }
        // SAFETY: handle은 guard가 소유한 유효한 열거 handle이고 name은 유효한 buffer다.
        let more = unsafe { FindNextVolumeW(guard.0, name.as_mut_ptr(), name.len() as u32) };
        if more == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                break;
            }
            return Err(storage_io_error(StorageIoOperation::Open, error));
        }
    }
    Ok(paths)
}

/// `FindFirstVolumeW`가 돌려주는 `\\?\Volume{...}\` 이름을 CreateFile로 열 수 있는
/// 장치 경로로 바꾼다. 끝의 `\`를 제거하지 않으면 volume 장치가 아니라 filesystem
/// root directory가 열린다.
fn volume_device_path(name: &[u16]) -> Option<PathBuf> {
    let length = name.iter().position(|&unit| unit == 0)?;
    let mut name = &name[..length];
    if let [rest @ .., last] = name
        && *last == u16::from(b'\\')
    {
        name = rest;
    }
    if name.is_empty() {
        return None;
    }
    Some(PathBuf::from(OsString::from_wide(name)))
}

/// 하나의 volume이 걸쳐 있는 physical disk 번호 목록.
const MAX_VOLUME_DISK_EXTENTS: usize = 16;

#[repr(C)]
struct VolumeDiskExtentsBuffer {
    info: VOLUME_DISK_EXTENTS,
    /// `info.Extents[0]` 뒤에 이어지는 추가 extent 저장 공간.
    extra: [DISK_EXTENT; MAX_VOLUME_DISK_EXTENTS - 1],
}

fn query_volume_disk_numbers(volume: &File) -> Result<Vec<u32>, StorageError> {
    let mut buffer = VolumeDiskExtentsBuffer {
        info: VOLUME_DISK_EXTENTS::default(),
        extra: [DISK_EXTENT::default(); MAX_VOLUME_DISK_EXTENTS - 1],
    };
    let buffer_size = u32::try_from(size_of::<VolumeDiskExtentsBuffer>())
        .map_err(|_| StorageError::OutOfRange)?;
    let mut returned = 0;
    // SAFETY: output buffer는 선언한 크기만큼 유효하고 호출이 끝날 때까지 살아 있다.
    // handle은 열린 `File` 소유이고 동기 호출이므로 OVERLAPPED는 null이다.
    let succeeded = unsafe {
        DeviceIoControl(
            volume.as_raw_handle(),
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            null(),
            0,
            &mut buffer as *mut VolumeDiskExtentsBuffer as *mut c_void,
            buffer_size,
            &mut returned,
            null_mut(),
        )
    };
    if succeeded == 0 {
        return Err(storage_io_error(
            StorageIoOperation::DeviceControl,
            std::io::Error::last_os_error(),
        ));
    }
    disk_numbers_from_extents(&buffer.info, &buffer.extra, returned as usize)
}

fn disk_numbers_from_extents(
    info: &VOLUME_DISK_EXTENTS,
    extra: &[DISK_EXTENT],
    returned: usize,
) -> Result<Vec<u32>, StorageError> {
    let count = info.NumberOfDiskExtents as usize;
    if count == 0 || count > extra.len() + 1 {
        return Err(storage_io_error(
            StorageIoOperation::DeviceControl,
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unexpected volume disk extent count",
            ),
        ));
    }
    let required = offset_of!(VOLUME_DISK_EXTENTS, Extents) + count * size_of::<DISK_EXTENT>();
    if returned < required {
        return Err(storage_io_error(
            StorageIoOperation::DeviceControl,
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated volume disk extents",
            ),
        ));
    }
    let mut numbers = Vec::with_capacity(count);
    numbers.push(info.Extents[0].DiskNumber);
    for extent in &extra[..count - 1] {
        numbers.push(extent.DiskNumber);
    }
    Ok(numbers)
}

fn device_io_control_no_buffers(file: &File, code: u32) -> Result<(), StorageError> {
    let mut returned = 0;
    // SAFETY: handle은 호출 동안 열린 `File`에서 얻었고, 동기 호출이므로 OVERLAPPED는
    // null이다. 이 control code들은 input/output buffer를 요구하지 않는다.
    let succeeded = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            null(),
            0,
            null_mut(),
            0,
            &mut returned,
            null_mut(),
        )
    };
    if succeeded == 0 {
        return Err(storage_io_error(
            StorageIoOperation::DeviceControl,
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn device_io_control_input<I>(file: &File, code: u32, input: &I) -> Result<(), StorageError> {
    let input_size = u32::try_from(size_of::<I>()).map_err(|_| StorageError::OutOfRange)?;
    let mut returned = 0;
    // SAFETY: input은 전달한 크기만큼 유효하며 호출이 끝날 때까지 살아 있다. handle은
    // 열린 `File` 소유이고 동기 호출이므로 OVERLAPPED는 null이다. 이 control code는
    // output buffer를 요구하지 않는다.
    let succeeded = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            input as *const I as *const c_void,
            input_size,
            null_mut(),
            0,
            &mut returned,
            null_mut(),
        )
    };
    if succeeded == 0 {
        return Err(storage_io_error(
            StorageIoOperation::DeviceControl,
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn device_io_control_output<T: Default>(file: &File, code: u32) -> Result<T, StorageError> {
    let input = ();
    device_io_control(file, code, &input)
}

fn device_io_control<I, O: Default>(file: &File, code: u32, input: &I) -> Result<O, StorageError> {
    let input_size = u32::try_from(size_of::<I>()).map_err(|_| StorageError::OutOfRange)?;
    let output_size = u32::try_from(size_of::<O>()).map_err(|_| StorageError::OutOfRange)?;
    let mut output = O::default();
    let mut returned = 0;
    // SAFETY: input/output은 각각 전달한 크기만큼 유효하며 호출이 끝날 때까지 살아 있다.
    // handle은 열린 `File` 소유이고 동기 호출이므로 OVERLAPPED는 null이다.
    let succeeded = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            input as *const I as *const c_void,
            input_size,
            &mut output as *mut O as *mut c_void,
            output_size,
            &mut returned,
            null_mut(),
        )
    };
    if succeeded == 0 {
        return Err(storage_io_error(
            StorageIoOperation::DeviceControl,
            std::io::Error::last_os_error(),
        ));
    }
    if returned < output_size {
        return Err(storage_io_error(
            StorageIoOperation::DeviceControl,
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "DeviceIoControl returned a truncated result",
            ),
        ));
    }
    Ok(output)
}

/// [`physical_disks`]가 살펴보는 disk 번호의 상한(미포함).
///
/// Windows는 disk 번호를 0부터 붙이고 빈 번호를 다시 쓴다. 번호가 연속이라는 보장은
/// 없어서 중간에 없는 번호가 나와도 멈추지 않고 이 범위를 끝까지 본다.
pub const PHYSICAL_DISK_SCAN_LIMIT: u32 = 128;

/// disk가 연결된 방식.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskBusType {
    Usb,
    Sata,
    Ata,
    Atapi,
    Nvme,
    Scsi,
    Sas,
    Raid,
    Iscsi,
    Sd,
    Mmc,
    Ufs,
    Fibre,
    Ieee1394,
    /// Hyper-V 등의 가상 disk.
    Virtual,
    /// VHD처럼 파일을 disk로 붙인 것.
    FileBackedVirtual,
    /// Storage Spaces.
    Spaces,
    /// Windows가 알려 주지 않았거나 위에 없는 종류. 값은 `STORAGE_BUS_TYPE` 그대로다.
    Other(i32),
}

impl DiskBusType {
    // Win32 상수 이름은 Rust의 상수 표기와 달라서 pattern에 쓰면 lint에 걸린다.
    #[allow(non_upper_case_globals)]
    fn from_raw(value: i32) -> Self {
        match value {
            BusTypeUsb => Self::Usb,
            BusTypeSata => Self::Sata,
            BusTypeAta => Self::Ata,
            BusTypeAtapi => Self::Atapi,
            BusTypeNvme => Self::Nvme,
            BusTypeScsi => Self::Scsi,
            BusTypeSas => Self::Sas,
            BusTypeRAID => Self::Raid,
            BusTypeiScsi => Self::Iscsi,
            BusTypeSd => Self::Sd,
            BusTypeMmc => Self::Mmc,
            BusTypeUfs => Self::Ufs,
            BusTypeFibre => Self::Fibre,
            BusType1394 => Self::Ieee1394,
            BusTypeVirtual => Self::Virtual,
            BusTypeFileBackedVirtual => Self::FileBackedVirtual,
            BusTypeSpaces => Self::Spaces,
            other => Self::Other(other),
        }
    }
}

impl std::fmt::Display for DiskBusType {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Usb => "USB",
            Self::Sata => "SATA",
            Self::Ata => "ATA",
            Self::Atapi => "ATAPI",
            Self::Nvme => "NVMe",
            Self::Scsi => "SCSI",
            Self::Sas => "SAS",
            Self::Raid => "RAID",
            Self::Iscsi => "iSCSI",
            Self::Sd => "SD",
            Self::Mmc => "MMC",
            Self::Ufs => "UFS",
            Self::Fibre => "Fibre Channel",
            Self::Ieee1394 => "IEEE 1394",
            Self::Virtual => "Virtual",
            Self::FileBackedVirtual => "Virtual (file)",
            Self::Spaces => "Storage Spaces",
            Self::Other(_) => "Unknown",
        };
        formatter.write_str(name)
    }
}

/// physical disk 하나를 사람이 알아볼 수 있게 하는 정보.
///
/// 문자열은 장치가 스스로 알려 준 것이라 비어 있거나 부정확할 수 있다. 특히 USB
/// 장치의 serial number는 bridge chip이 지어낸 값인 경우가 있다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalDiskInfo {
    /// `\\.\PhysicalDriveN`의 N. 설정의 `device-number`에 쓰는 값이다.
    pub device_number: u32,
    pub vendor: String,
    pub product: String,
    pub serial_number: String,
    pub bus_type: DiskBusType,
    /// 매체를 뺄 수 있는 장치인지. USB memory는 `true`, USB 외장 HDD는 보통 `false`다.
    pub removable: bool,
    /// byte 단위 용량. card reader에 card가 없는 경우처럼 알 수 없으면 `None`이다.
    pub size_bytes: Option<u64>,
}

impl PhysicalDiskInfo {
    /// 제조사와 제품 이름을 이어 붙인 설명. 예: `SanDisk Ultra USB 3.0`.
    pub fn description(&self) -> String {
        match (self.vendor.is_empty(), self.product.is_empty()) {
            (true, _) => self.product.clone(),
            (false, true) => self.vendor.clone(),
            (false, false) => format!("{} {}", self.vendor, self.product),
        }
    }
}

/// 이 PC의 physical disk를 번호 순서로 열거한다.
///
/// disk를 읽거나 쓰지 않고 장치 정보만 묻기 때문에 관리자 권한이 필요 없고, 다른
/// 프로그램이 쓰고 있는 disk도 나온다. 정보를 물을 수 없는 disk는 목록에서 빠진다.
pub fn physical_disks() -> Vec<PhysicalDiskInfo> {
    (0..PHYSICAL_DISK_SCAN_LIMIT)
        .filter_map(physical_disk)
        .collect()
}

/// 번호 하나의 physical disk 정보. 그런 disk가 없거나 정보를 물을 수 없으면 `None`이다.
///
/// 다른 handle이 disk를 배타적으로 열고 있으면 물을 수 없으므로, serve하려는 disk의
/// 정보는 backend를 열기 전에 물어야 한다.
pub fn physical_disk(device_number: u32) -> Option<PhysicalDiskInfo> {
    // 접근 권한 0으로 열면 disk의 내용에는 손댈 수 없고 장치 정보만 물을 수 있다.
    let disk = OpenOptions::new()
        .access_mode(0)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(format!(r"\\.\PhysicalDrive{device_number}"))
        .ok()?;

    let query = STORAGE_PROPERTY_QUERY {
        PropertyId: StorageDeviceProperty,
        QueryType: PropertyStandardQuery,
        ..STORAGE_PROPERTY_QUERY::default()
    };
    let mut descriptor = [0u8; DEVICE_DESCRIPTOR_BUFFER_LENGTH];
    let parsed =
        device_io_control_bytes(&disk, IOCTL_STORAGE_QUERY_PROPERTY, &query, &mut descriptor)
            .ok()
            .and_then(|returned| parse_device_descriptor(&descriptor[..returned]));
    let Some(descriptor) = parsed else {
        tracing::debug!(
            device_number,
            "physical disk did not report a device descriptor"
        );
        return None;
    };

    let mut geometry = [0u8; DISK_GEOMETRY_BUFFER_LENGTH];
    let size_bytes =
        device_io_control_bytes(&disk, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, &(), &mut geometry)
            .ok()
            .and_then(|returned| parse_disk_size(&geometry[..returned]));

    Some(PhysicalDiskInfo {
        device_number,
        vendor: descriptor.vendor,
        product: descriptor.product,
        serial_number: descriptor.serial_number,
        bus_type: descriptor.bus_type,
        removable: descriptor.removable,
        size_bytes,
    })
}

/// `STORAGE_DEVICE_DESCRIPTOR`와 그 뒤의 문자열을 받을 buffer 크기.
const DEVICE_DESCRIPTOR_BUFFER_LENGTH: usize = 1024;
/// `DISK_GEOMETRY_EX`와 그 뒤의 partition/detection 정보를 받을 buffer 크기.
const DISK_GEOMETRY_BUFFER_LENGTH: usize = 256;

#[derive(Debug, PartialEq, Eq)]
struct DeviceDescriptor {
    vendor: String,
    product: String,
    serial_number: String,
    bus_type: DiskBusType,
    removable: bool,
}

/// `IOCTL_STORAGE_QUERY_PROPERTY`가 돌려준 `STORAGE_DEVICE_DESCRIPTOR`를 해석한다.
///
/// 내용은 장치가 채운 것이므로 믿지 않는다. 구조체로 바꿔 읽지 않고 byte에서 field를
/// 하나씩 꺼내며, 문자열 offset이 받은 범위를 벗어나면 그 문자열은 없는 것으로 본다.
fn parse_device_descriptor(bytes: &[u8]) -> Option<DeviceDescriptor> {
    if bytes.len() < offset_of!(STORAGE_DEVICE_DESCRIPTOR, RawDeviceProperties) {
        return None;
    }
    // `Size`는 문자열을 포함한 전체 길이다. buffer가 작았다면 받은 만큼만 본다.
    let size = read_u32(bytes, offset_of!(STORAGE_DEVICE_DESCRIPTOR, Size))? as usize;
    let bytes = &bytes[..size.min(bytes.len())];
    let string = |field_offset: usize| {
        read_u32(bytes, field_offset)
            .map(|offset| descriptor_string(bytes, offset as usize))
            .unwrap_or_default()
    };
    Some(DeviceDescriptor {
        vendor: string(offset_of!(STORAGE_DEVICE_DESCRIPTOR, VendorIdOffset)),
        product: string(offset_of!(STORAGE_DEVICE_DESCRIPTOR, ProductIdOffset)),
        serial_number: string(offset_of!(STORAGE_DEVICE_DESCRIPTOR, SerialNumberOffset)),
        bus_type: DiskBusType::from_raw(read_u32(
            bytes,
            offset_of!(STORAGE_DEVICE_DESCRIPTOR, BusType),
        )? as i32),
        removable: *bytes.get(offset_of!(STORAGE_DEVICE_DESCRIPTOR, RemovableMedia))? != 0,
    })
}

/// descriptor 안의 `offset`에서 시작하는 NUL 종료 ASCII 문자열. offset 0은 "없음"이다.
///
/// 장치는 고정 폭 field를 공백으로 채우므로 앞뒤 공백을 떼고, 화면과 로그에 그대로
/// 나가도 되도록 출력 가능한 ASCII가 아닌 byte는 버린다.
fn descriptor_string(bytes: &[u8], offset: usize) -> String {
    if offset == 0 {
        return String::new();
    }
    let Some(tail) = bytes.get(offset..) else {
        return String::new();
    };
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(tail.len());
    tail[..end]
        .iter()
        .filter(|byte| byte.is_ascii_graphic() || **byte == b' ')
        .map(|byte| char::from(*byte))
        .collect::<String>()
        .trim()
        .to_owned()
}

/// `IOCTL_DISK_GET_DRIVE_GEOMETRY_EX` 결과에서 `DiskSize`를 꺼낸다.
fn parse_disk_size(bytes: &[u8]) -> Option<u64> {
    let offset = offset_of!(DISK_GEOMETRY_EX, DiskSize);
    let size = i64::from_le_bytes(bytes.get(offset..offset + 8)?.try_into().ok()?);
    u64::try_from(size).ok().filter(|size| *size != 0)
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let field = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(field.try_into().ok()?))
}

/// 길이가 정해지지 않은 결과를 byte buffer로 받고, 채워진 byte 수를 돌려준다.
fn device_io_control_bytes<I>(
    file: &File,
    code: u32,
    input: &I,
    output: &mut [u8],
) -> Result<usize, StorageError> {
    let input_size = u32::try_from(size_of::<I>()).map_err(|_| StorageError::OutOfRange)?;
    let output_size = u32::try_from(output.len()).map_err(|_| StorageError::OutOfRange)?;
    let mut returned = 0;
    // SAFETY: input/output은 각각 전달한 크기만큼 유효하며 호출이 끝날 때까지 살아 있다.
    // output은 byte 배열이라 어떤 bit pattern이 쓰여도 유효하다. handle은 열린 `File`
    // 소유이고 동기 호출이므로 OVERLAPPED는 null이다.
    let succeeded = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            input as *const I as *const c_void,
            input_size,
            output.as_mut_ptr() as *mut c_void,
            output_size,
            &mut returned,
            null_mut(),
        )
    };
    if succeeded == 0 {
        return Err(storage_io_error(
            StorageIoOperation::DeviceControl,
            std::io::Error::last_os_error(),
        ));
    }
    // driver가 buffer보다 큰 값을 보고해도 buffer 밖을 읽지 않는다.
    Ok((returned as usize).min(output.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_mode_reports_read_only_state() {
        assert!(WindowsStorageAccess::ReadOnly.read_only());
        assert!(!WindowsStorageAccess::ReadWrite.read_only());
    }

    #[test]
    fn invalid_volume_letter_is_rejected_before_device_access() {
        assert_eq!(
            WindowsStorageBackend::open_volume('1', WindowsStorageAccess::ReadOnly).unwrap_err(),
            StorageError::OutOfRange
        );
    }

    #[test]
    fn volume_name_is_converted_to_openable_device_path() {
        let wide: Vec<u16> = r"\\?\Volume{a0b1}\"
            .encode_utf16()
            .chain([0, 0x7777])
            .collect();
        assert_eq!(
            volume_device_path(&wide),
            Some(PathBuf::from(r"\\?\Volume{a0b1}"))
        );
    }

    #[test]
    fn volume_name_without_terminator_or_content_is_rejected() {
        let unterminated: Vec<u16> = r"\\?\Volume{a0b1}\".encode_utf16().collect();
        assert_eq!(volume_device_path(&unterminated), None);
        assert_eq!(volume_device_path(&[u16::from(b'\\'), 0]), None);
        assert_eq!(volume_device_path(&[0]), None);
    }

    #[test]
    fn disk_offline_request_changes_only_the_offline_attribute_without_persisting() {
        let offline = disk_offline_request(true).unwrap();
        assert_eq!(offline.Version, 40);
        assert!(!offline.Persist);
        assert_eq!(offline.Attributes, 1);
        assert_eq!(offline.AttributesMask, 1);

        let online = disk_offline_request(false).unwrap();
        assert_eq!(online.Version, 40);
        assert!(!online.Persist);
        assert_eq!(online.Attributes, 0);
        assert_eq!(online.AttributesMask, 1);
    }

    #[test]
    fn missing_physical_drive_fails_at_open_before_any_offline_change() {
        let error =
            WindowsStorageBackend::open_physical_drive(u32::MAX, WindowsStorageAccess::ReadOnly)
                .unwrap_err();
        assert!(matches!(error, StorageError::Io(_)));
    }

    fn extents_with_count(count: u32) -> VOLUME_DISK_EXTENTS {
        VOLUME_DISK_EXTENTS {
            NumberOfDiskExtents: count,
            ..VOLUME_DISK_EXTENTS::default()
        }
    }

    #[test]
    fn extent_disk_numbers_are_read_from_contiguous_extents() {
        let info = VOLUME_DISK_EXTENTS {
            NumberOfDiskExtents: 2,
            Extents: [DISK_EXTENT {
                DiskNumber: 3,
                ..DISK_EXTENT::default()
            }],
        };
        let mut extra = [DISK_EXTENT::default(); MAX_VOLUME_DISK_EXTENTS - 1];
        extra[0].DiskNumber = 7;
        let returned = offset_of!(VOLUME_DISK_EXTENTS, Extents) + 2 * size_of::<DISK_EXTENT>();
        assert_eq!(
            disk_numbers_from_extents(&info, &extra, returned).unwrap(),
            vec![3, 7]
        );
    }

    #[test]
    fn truncated_or_invalid_extent_counts_are_rejected() {
        let extra = [DISK_EXTENT::default(); MAX_VOLUME_DISK_EXTENTS - 1];
        assert!(disk_numbers_from_extents(&extents_with_count(0), &extra, 4096).is_err());
        assert!(disk_numbers_from_extents(&extents_with_count(1), &extra, 8).is_err());

        let overflowing = u32::try_from(MAX_VOLUME_DISK_EXTENTS).unwrap() + 1;
        assert!(disk_numbers_from_extents(&extents_with_count(overflowing), &extra, 4096).is_err());
    }

    /// 문서의 `STORAGE_DEVICE_DESCRIPTOR` 배치를 손으로 적은 descriptor.
    ///
    /// offset 0 Version, 4 Size, 8 DeviceType, 9 DeviceTypeModifier, 10 RemovableMedia,
    /// 11 CommandQueueing, 12 VendorIdOffset, 16 ProductIdOffset, 20 ProductRevisionOffset,
    /// 24 SerialNumberOffset, 28 BusType, 32 RawPropertiesLength, 36부터 문자열.
    fn usb_descriptor() -> Vec<u8> {
        let mut bytes = vec![0u8; 36];
        bytes[0..4].copy_from_slice(&40u32.to_le_bytes());
        bytes[10] = 1;
        bytes[12..16].copy_from_slice(&36u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&45u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&62u32.to_le_bytes());
        bytes[24..28].copy_from_slice(&67u32.to_le_bytes());
        bytes[28..32].copy_from_slice(&7u32.to_le_bytes());
        bytes.extend_from_slice(b"SanDisk \0");
        bytes.extend_from_slice(b"Ultra USB 3.0   \0");
        bytes.extend_from_slice(b"1.00\0");
        bytes.extend_from_slice(b"  4C530001230506117341\0");
        let size = bytes.len() as u32;
        bytes[4..8].copy_from_slice(&size.to_le_bytes());
        bytes
    }

    #[test]
    fn device_descriptor_strings_are_read_at_their_offsets_and_trimmed() {
        let descriptor = parse_device_descriptor(&usb_descriptor()).unwrap();
        assert_eq!(
            descriptor,
            DeviceDescriptor {
                vendor: "SanDisk".to_owned(),
                product: "Ultra USB 3.0".to_owned(),
                serial_number: "4C530001230506117341".to_owned(),
                bus_type: DiskBusType::Usb,
                removable: true,
            }
        );
    }

    #[test]
    fn device_descriptor_tolerates_missing_and_invalid_strings() {
        // offset 0은 "없음"이고, 범위를 벗어난 offset과 NUL이 없는 문자열도 받아 낸다.
        let mut bytes = usb_descriptor();
        bytes[12..16].copy_from_slice(&0u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes[10] = 0;
        bytes[28..32].copy_from_slice(&17u32.to_le_bytes());
        let last = bytes.len() - 1;
        bytes[last] = b'Z';
        let descriptor = parse_device_descriptor(&bytes).unwrap();
        assert_eq!(descriptor.vendor, "");
        assert_eq!(descriptor.product, "");
        assert_eq!(descriptor.serial_number, "4C530001230506117341Z");
        assert_eq!(descriptor.bus_type, DiskBusType::Nvme);
        assert!(!descriptor.removable);

        // 출력할 수 없는 byte는 버린다.
        let mut bytes = usb_descriptor();
        bytes[36] = 0x07;
        bytes[37] = 0xff;
        assert_eq!(parse_device_descriptor(&bytes).unwrap().vendor, "nDisk");
    }

    #[test]
    fn device_descriptor_is_bounded_by_its_size_field_and_the_bytes_received() {
        let full = usb_descriptor();

        // `Size`가 문자열 앞에서 끝나면 문자열은 없는 것이다.
        let mut bytes = full.clone();
        bytes[4..8].copy_from_slice(&36u32.to_le_bytes());
        let descriptor = parse_device_descriptor(&bytes).unwrap();
        assert_eq!(descriptor.vendor, "");
        assert_eq!(descriptor.serial_number, "");
        assert_eq!(descriptor.bus_type, DiskBusType::Usb);

        // 받은 byte가 `Size`보다 적으면 받은 만큼만 본다.
        let descriptor = parse_device_descriptor(&full[..40]).unwrap();
        assert_eq!(descriptor.vendor, "SanD");
        assert_eq!(descriptor.product, "");

        // 고정 부분이 잘렸으면 해석하지 않는다. 어떤 길이에서도 panic하지 않는다.
        for length in 0..full.len() {
            let parsed = parse_device_descriptor(&full[..length]);
            assert_eq!(parsed.is_some(), length >= 36, "length {length}");
        }
    }

    #[test]
    fn disk_size_is_read_after_the_24_byte_geometry() {
        let mut bytes = vec![0u8; 32];
        bytes[24..32].copy_from_slice(&31_914_983_424u64.to_le_bytes());
        assert_eq!(parse_disk_size(&bytes), Some(31_914_983_424));
        assert_eq!(parse_disk_size(&bytes[..31]), None);

        // 0과 음수는 알 수 없는 크기로 본다.
        assert_eq!(parse_disk_size(&[0u8; 32]), None);
        bytes[24..32].copy_from_slice(&(-1i64).to_le_bytes());
        assert_eq!(parse_disk_size(&bytes), None);
    }

    #[test]
    fn bus_types_map_from_the_documented_values() {
        assert_eq!(DiskBusType::from_raw(1), DiskBusType::Scsi);
        assert_eq!(DiskBusType::from_raw(7), DiskBusType::Usb);
        assert_eq!(DiskBusType::from_raw(11), DiskBusType::Sata);
        assert_eq!(DiskBusType::from_raw(17), DiskBusType::Nvme);
        assert_eq!(DiskBusType::from_raw(0), DiskBusType::Other(0));
        assert_eq!(DiskBusType::from_raw(-5), DiskBusType::Other(-5));
        assert_eq!(DiskBusType::Usb.to_string(), "USB");
        assert_eq!(DiskBusType::Other(99).to_string(), "Unknown");
    }

    #[test]
    fn description_joins_vendor_and_product_that_are_present() {
        let mut disk = PhysicalDiskInfo {
            device_number: 2,
            vendor: "SanDisk".to_owned(),
            product: "Ultra".to_owned(),
            serial_number: String::new(),
            bus_type: DiskBusType::Usb,
            removable: true,
            size_bytes: None,
        };
        assert_eq!(disk.description(), "SanDisk Ultra");
        disk.vendor.clear();
        assert_eq!(disk.description(), "Ultra");
        disk.product.clear();
        assert_eq!(disk.description(), "");
        disk.vendor = "SanDisk".to_owned();
        assert_eq!(disk.description(), "SanDisk");
    }

    #[test]
    fn this_pc_reports_its_disks_in_ascending_order_without_elevation() {
        let disks = physical_disks();
        // test를 돌리는 PC에는 적어도 system disk가 있다.
        assert!(!disks.is_empty());
        assert!(
            disks
                .windows(2)
                .all(|pair| pair[0].device_number < pair[1].device_number)
        );
        for disk in &disks {
            println!(
                "disk {}: {:?} serial={:?} bus={} removable={} size={:?}",
                disk.device_number,
                disk.description(),
                disk.serial_number,
                disk.bus_type,
                disk.removable,
                disk.size_bytes
            );
        }
    }
}
