//! Windows physical disk 및 volume Storage backend.
//!
//! Win32 handle과 `DeviceIoControl` 사용은 이 모듈 안에만 격리한다. 상위 계층은
//! [`StorageBackend`]만 사용하며 장치 경로나 Win32 타입을 알 필요가 없다.

use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::PathBuf;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};
use windows_sys::Win32::System::Ioctl::{
    PropertyStandardQuery, StorageAccessAlignmentProperty, FSCTL_DISMOUNT_VOLUME,
    FSCTL_LOCK_VOLUME, GET_LENGTH_INFORMATION, IOCTL_DISK_GET_LENGTH_INFO,
    IOCTL_STORAGE_QUERY_PROPERTY, STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR, STORAGE_PROPERTY_QUERY,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

use crate::scsi_target::{
    block_io_offset, storage_io_error, StorageBackend, StorageError, StorageIoOperation,
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

/// Windows physical disk 또는 volume handle을 감싼 block backend.
///
/// `ReadWrite` physical disk는 Windows에서 장치가 offline/unmounted인 경우에만 사용해야
/// 한다. volume은 `ReadWrite`로 열 때 handle 수명 동안 `FSCTL_LOCK_VOLUME`을 획득하고
/// dismount한다. 두 경우 모두 보통 관리자 권한이 필요하다.
#[derive(Debug)]
pub struct WindowsStorageBackend {
    file: File,
    block_size: u32,
    block_count: u64,
    read_only: bool,
    durable_flush: bool,
}

impl WindowsStorageBackend {
    /// `\\.\PhysicalDriveN` 장치를 연다.
    pub fn open_physical_drive(
        device_number: u32,
        access: WindowsStorageAccess,
    ) -> Result<Self, StorageError> {
        let path = PathBuf::from(format!(r"\\.\PhysicalDrive{device_number}"));
        Self::open(path, access, false)
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
        Self::open(path, access, true)
    }

    pub fn set_durable_flush(&mut self, value: bool) {
        self.durable_flush = value;
    }

    pub fn durable_flush(&self) -> bool {
        self.durable_flush
    }

    fn open(
        path: PathBuf,
        access: WindowsStorageAccess,
        is_volume: bool,
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
            .open(path)
            .map_err(|error| storage_io_error(StorageIoOperation::Open, error))?;

        if is_volume && !read_only {
            device_io_control_no_buffers(&file, FSCTL_LOCK_VOLUME)?;
            device_io_control_no_buffers(&file, FSCTL_DISMOUNT_VOLUME)?;
        }

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

fn query_logical_sector_size(file: &File) -> Result<u32, StorageError> {
    let query = STORAGE_PROPERTY_QUERY {
        PropertyId: StorageAccessAlignmentProperty,
        QueryType: PropertyStandardQuery,
        AdditionalParameters: [0],
    };
    let descriptor: STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR =
        device_io_control(file, IOCTL_STORAGE_QUERY_PROPERTY, &query)?;
    if descriptor.BytesPerLogicalSector == 0 {
        return Err(StorageError::OutOfRange);
    }
    Ok(descriptor.BytesPerLogicalSector)
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
}
