//! disk 식별자를 가상화하는 Storage backend wrapper.
//!
//! physical disk를 같은 PC의 Initiator에 내주면 host는 원본 disk와 iSCSI disk 양쪽에서
//! 같은 식별자를 읽는다. Windows는 disk GUID가 겹치면 새 disk의 LBA 0에 써 본 뒤 기존
//! disk에서 그 변화가 보이는지로 같은 media인지 판정해 "Redundant Path"로 내리고,
//! partition GUID만 겹쳐도 "Collision"으로 offline 처리한다.
//!
//! 이 wrapper는 Initiator에게 보이는 식별자만 다른 값으로 바꾼다. 대상은 다음뿐이다.
//!
//! - LBA 0의 MBR disk signature (offset 440, 4 byte)
//! - GPT header의 DiskGUID (offset 56)
//! - GPT partition entry의 UniquePartitionGUID (entry offset 16)
//! - 위 변경에 따라 달라지는 PartitionEntryArrayCRC32와 HeaderCRC32
//!
//! partition의 위치, 종류와 filesystem 내용은 건드리지 않는다.
//!
//! GUID는 고정 mask와의 XOR로 바꾼다. XOR은 자기 자신의 역연산이므로 읽을 때와 쓸 때
//! 같은 변환을 적용하면 Initiator는 자신이 쓴 값을 그대로 다시 읽고, media에는 항상
//! 그 반대편 값이 기록된다. 원본 disk의 GUID는 serve 전후로 바뀌지 않는다.
//!
//! partition entry array의 CRC는 array 전체에 대한 값이라 header만으로는 바꿀 수 없다.
//! 그래서 header를 읽거나 쓸 때마다 media의 array를 읽어 양쪽 CRC를 계산한다.
//! Initiator가 array와 header를 어떤 순서로 쓰든 마지막 write가 끝나면 media의 GPT가
//! 유효해지도록 write 뒤에 header를 다시 맞춘다.

use crate::scsi_target::{StorageBackend, StorageError};

const MBR_SIGNATURE_OFFSET: usize = 440;
const MBR_BOOT_SIGNATURE_OFFSET: usize = 510;
const MBR_BOOT_SIGNATURE: [u8; 2] = [0x55, 0xaa];
const MBR_SIGNATURE_MASK: u32 = 0x5253_4953;

const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
const GPT_HEADER_SIZE_OFFSET: usize = 12;
const GPT_HEADER_CRC_OFFSET: usize = 16;
const GPT_MY_LBA_OFFSET: usize = 24;
const GPT_ALTERNATE_LBA_OFFSET: usize = 32;
const GPT_DISK_GUID_OFFSET: usize = 56;
const GPT_ENTRIES_LBA_OFFSET: usize = 72;
const GPT_ENTRY_COUNT_OFFSET: usize = 80;
const GPT_ENTRY_SIZE_OFFSET: usize = 84;
const GPT_ENTRIES_CRC_OFFSET: usize = 88;
const GPT_MIN_HEADER_SIZE: usize = 92;
const GPT_MIN_ENTRY_SIZE: usize = 128;
const GPT_ENTRY_UNIQUE_GUID_OFFSET: usize = 16;
const GPT_PRIMARY_HEADER_LBA: u64 = 1;
const GUID_LENGTH: usize = 16;
const GUID_MASK: [u8; GUID_LENGTH] = *b"RUSTISCSI-VDISK\x01";
/// header가 선언할 수 있는 partition entry array의 최대 크기. 표준 배치는 16 KiB이다.
/// media의 값은 신뢰할 수 없으므로 이 크기를 넘는 GPT는 가상화하지 않는다.
const MAX_ENTRY_ARRAY_LENGTH: usize = 1024 * 1024;

/// media에 기록된 원본 값과 Initiator에게 보여 줄 가상 값의 쌍.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Mapping<T> {
    original: T,
    presented: T,
}

/// MBR signature를 바꾸는 방향.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    /// media에서 읽은 data를 Initiator에게 내보낸다.
    ToInitiator,
    /// Initiator가 보낸 data를 media에 기록한다.
    ToMedia,
}

impl<T: Copy + PartialEq> Mapping<T> {
    fn translate(&self, value: T, direction: Direction) -> Option<T> {
        let (from, to) = match direction {
            Direction::ToInitiator => (self.original, self.presented),
            Direction::ToMedia => (self.presented, self.original),
        };
        (value == from).then_some(to)
    }
}

/// 유효성을 확인한 GPT header에서 가상화에 필요한 field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GptHeader {
    header_size: usize,
    alternate_lba: u64,
    entries: EntryArray,
    entries_crc: u32,
}

/// partition entry array의 위치와 형태.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EntryArray {
    lba: u64,
    length: usize,
    entry_size: usize,
    blocks: u64,
}

impl EntryArray {
    fn end_lba(&self) -> u64 {
        self.lba + self.blocks
    }

    fn overlaps(&self, other: &Self) -> bool {
        self.lba < other.end_lba() && other.lba < self.end_lba()
    }
}

/// MBR signature와 GPT의 disk/partition GUID를 가상 값으로 바꿔 보여 주는 backend wrapper.
pub struct VirtualDiskIdentity {
    inner: Box<dyn StorageBackend>,
    block_size: usize,
    block_count: u64,
    mbr_signature: Option<Mapping<u32>>,
    /// GPT header가 있을 수 있는 LBA. 중복이 없다.
    header_lbas: Vec<u64>,
    /// media의 유효한 header가 가리키는 entry array. 서로 겹치지 않는다.
    entry_arrays: Vec<EntryArray>,
}

impl std::fmt::Debug for VirtualDiskIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtualDiskIdentity")
            .field("mbr_signature", &self.mbr_signature.is_some())
            .field("header_lbas", &self.header_lbas)
            .field("entry_arrays", &self.entry_arrays)
            .finish()
    }
}

impl VirtualDiskIdentity {
    /// `inner`의 현재 MBR signature와 GPT 배치를 읽어 가상화를 준비한다.
    pub fn new(mut inner: Box<dyn StorageBackend>) -> Result<Self, StorageError> {
        let block_size =
            usize::try_from(inner.block_size()).map_err(|_| StorageError::OutOfRange)?;
        let block_count = inner.block_count();
        if block_size <= MBR_BOOT_SIGNATURE_OFFSET + 1 || block_count == 0 {
            return Err(StorageError::OutOfRange);
        }

        let mut sector = vec![0; block_size];
        inner.read_blocks(0, &mut sector)?;
        let mbr_signature = mbr_signature(&sector)
            .filter(|&signature| signature != 0)
            .map(|original| Mapping {
                original,
                presented: presented_mbr_signature(original),
            });

        let mut disk = Self {
            inner,
            block_size,
            block_count,
            mbr_signature,
            header_lbas: Vec::new(),
            entry_arrays: Vec::new(),
        };
        disk.refresh_layout()?;
        Ok(disk)
    }

    /// 지금 가상화하고 있는 식별자가 하나라도 있는지 여부.
    pub fn is_active(&self) -> bool {
        self.mbr_signature.is_some() || !self.entry_arrays.is_empty()
    }

    /// media의 header를 다시 읽어 header 후보 LBA와 entry array 목록을 갱신한다.
    fn refresh_layout(&mut self) -> Result<(), StorageError> {
        let mut header_lbas = Vec::new();
        let mut entry_arrays: Vec<EntryArray> = Vec::new();
        if self.block_count > GPT_PRIMARY_HEADER_LBA {
            // backup header는 보통 마지막 LBA에 있지만, 더 작은 disk에서 복제한 image는
            // primary header가 가리키는 다른 위치에 둔다.
            header_lbas.push(GPT_PRIMARY_HEADER_LBA);
            let last_lba = self.block_count - 1;
            if !header_lbas.contains(&last_lba) {
                header_lbas.push(last_lba);
            }
            if let Some(primary) = self.read_header(GPT_PRIMARY_HEADER_LBA)?
                && primary.alternate_lba < self.block_count
                && !header_lbas.contains(&primary.alternate_lba)
            {
                header_lbas.push(primary.alternate_lba);
            }
            for &lba in &header_lbas.clone() {
                if let Some(header) = self.read_header(lba)?
                    && !entry_arrays
                        .iter()
                        .any(|known| known.overlaps(&header.entries))
                {
                    entry_arrays.push(header.entries);
                }
            }
        }
        self.header_lbas = header_lbas;
        self.entry_arrays = entry_arrays;
        Ok(())
    }

    fn read_header(&mut self, lba: u64) -> Result<Option<GptHeader>, StorageError> {
        let mut sector = vec![0; self.block_size];
        self.inner.read_blocks(lba, &mut sector)?;
        Ok(parse_gpt_header(&sector, lba, self.block_count))
    }

    /// entry array가 차지하는 block 전체를 읽는다. array 자체는 앞쪽 `length` byte이다.
    fn read_entry_blocks(&mut self, array: &EntryArray) -> Result<Vec<u8>, StorageError> {
        let blocks = usize::try_from(array.blocks).map_err(|_| StorageError::OutOfRange)?;
        let length = blocks
            .checked_mul(self.block_size)
            .ok_or(StorageError::OutOfRange)?;
        let mut data = vec![0; length];
        self.inner.read_blocks(array.lba, &mut data)?;
        Ok(data)
    }

    /// `[lba, lba + blocks)`가 식별자를 담을 수 있는 sector와 겹치는지 여부.
    fn touches_identity(&self, lba: u64, blocks: u64) -> bool {
        let end = lba.saturating_add(blocks);
        let covers = |target: u64| lba <= target && target < end;
        (self.mbr_signature.is_some() && covers(0))
            || self.header_lbas.iter().any(|&header| covers(header))
            || self
                .entry_arrays
                .iter()
                .any(|array| lba < array.end_lba() && array.lba < end)
    }

    /// `lba`에서 시작하는 buffer 안에서 `target` sector가 차지하는 byte 범위.
    fn sector_range(&self, lba: u64, length: usize, target: u64) -> Option<std::ops::Range<usize>> {
        let index = usize::try_from(target.checked_sub(lba)?).ok()?;
        let start = index.checked_mul(self.block_size)?;
        let end = start.checked_add(self.block_size)?;
        (end <= length).then_some(start..end)
    }

    fn translate_mbr(&self, lba: u64, data: &mut [u8], direction: Direction) {
        let Some(mapping) = &self.mbr_signature else {
            return;
        };
        let Some(range) = self.sector_range(lba, data.len(), 0) else {
            return;
        };
        let sector = &mut data[range];
        if let Some(translated) =
            mbr_signature(sector).and_then(|value| mapping.translate(value, direction))
        {
            sector[MBR_SIGNATURE_OFFSET..MBR_SIGNATURE_OFFSET + 4]
                .copy_from_slice(&translated.to_le_bytes());
        }
    }

    /// `lba`에서 시작하는 buffer와 `array`가 겹치는 부분의 partition GUID를 바꾼다.
    fn translate_entries(&self, lba: u64, data: &mut [u8], array: &EntryArray) {
        let buffer_blocks = (data.len() / self.block_size) as u64;
        let start_lba = lba.max(array.lba);
        let end_lba = lba.saturating_add(buffer_blocks).min(array.end_lba());
        if start_lba >= end_lba {
            return;
        }
        // block 크기는 entry 크기의 배수이므로 block 경계는 항상 entry 경계이다.
        let array_offset = (start_lba - array.lba) as usize * self.block_size;
        if array_offset >= array.length {
            return;
        }
        let buffer_offset = (start_lba - lba) as usize * self.block_size;
        let overlap =
            ((end_lba - start_lba) as usize * self.block_size).min(array.length - array_offset);
        translate_entry_array(
            &mut data[buffer_offset..buffer_offset + overlap],
            array.entry_size,
        );
    }

    /// media에서 읽은 header sector를 Initiator에게 보여 줄 형태로 바꾼다.
    fn present_header(&mut self, lba: u64, sector: &mut [u8]) -> Result<(), StorageError> {
        let Some(header) = parse_gpt_header(sector, lba, self.block_count) else {
            return Ok(());
        };
        let mut entries = self.read_entry_blocks(&header.entries)?;
        let entries = &mut entries[..header.entries.length];
        let media_crc = crc32(entries);
        // media의 array와 맞지 않는 CRC는 Initiator가 header를 먼저 쓰고 array를 아직 쓰지
        // 않은 상태이다. 그 값은 Initiator가 쓴 그대로이므로 바꾸지 않는다.
        let entries_crc = if header.entries_crc == media_crc {
            translate_entry_array(entries, header.entries.entry_size);
            crc32(entries)
        } else {
            header.entries_crc
        };
        translate_guid(&mut sector[GPT_DISK_GUID_OFFSET..GPT_DISK_GUID_OFFSET + GUID_LENGTH]);
        store_header_crcs(sector, header.header_size, entries_crc);
        Ok(())
    }

    /// Initiator가 방금 쓴 header의 PartitionEntryArrayCRC32를 media의 array에 맞춘다.
    ///
    /// `header.entries_crc`는 Initiator가 보는 array에 대한 값이다. media에는 partition
    /// GUID가 바뀐 array가 있으므로 그 array의 CRC로 고쳐 써야 media의 GPT가 유효하다.
    fn settle_written_header(&mut self, lba: u64, header: &GptHeader) -> Result<(), StorageError> {
        let mut blocks = self.read_entry_blocks(&header.entries)?;
        let entries = &mut blocks[..header.entries.length];
        let media_crc = crc32(entries);
        translate_entry_array(entries, header.entries.entry_size);
        let other_crc = crc32(entries);

        let entries_crc = if header.entries_crc == other_crc {
            // 일반적인 경우: array가 이미 바뀐 GUID로 media에 기록되어 있다.
            media_crc
        } else if header.entries_crc == media_crc {
            // array가 어디인지 알기 전에 기록되어 Initiator의 GUID가 그대로 media에 있다.
            // Initiator가 같은 값을 다시 읽도록 media의 array를 바꿔 기록한다.
            self.inner.write_blocks(header.entries.lba, &blocks)?;
            other_crc
        } else {
            // array가 아직 기록되지 않았다. array write 뒤에 `settle_pending_headers`가 맞춘다.
            return Ok(());
        };
        self.rewrite_entries_crc(lba, header.header_size, entries_crc)
    }

    /// array write 뒤, 먼저 기록되어 CRC가 아직 Initiator 기준인 header를 media 기준으로 고친다.
    fn settle_pending_headers(&mut self) -> Result<(), StorageError> {
        for lba in self.header_lbas.clone() {
            let Some(header) = self.read_header(lba)? else {
                continue;
            };
            let mut blocks = self.read_entry_blocks(&header.entries)?;
            let entries = &mut blocks[..header.entries.length];
            let media_crc = crc32(entries);
            if header.entries_crc == media_crc {
                continue;
            }
            translate_entry_array(entries, header.entries.entry_size);
            if header.entries_crc == crc32(entries) {
                self.rewrite_entries_crc(lba, header.header_size, media_crc)?;
            }
        }
        Ok(())
    }

    fn rewrite_entries_crc(
        &mut self,
        lba: u64,
        header_size: usize,
        entries_crc: u32,
    ) -> Result<(), StorageError> {
        let mut sector = vec![0; self.block_size];
        self.inner.read_blocks(lba, &mut sector)?;
        store_header_crcs(&mut sector, header_size, entries_crc);
        self.inner.write_blocks(lba, &sector)
    }
}

impl StorageBackend for VirtualDiskIdentity {
    fn block_size(&self) -> u32 {
        self.inner.block_size()
    }

    fn block_count(&self) -> u64 {
        self.inner.block_count()
    }

    fn read_only(&self) -> bool {
        self.inner.read_only()
    }

    fn read_blocks(&mut self, lba: u64, output: &mut [u8]) -> Result<(), StorageError> {
        self.inner.read_blocks(lba, output)?;
        let blocks = (output.len() / self.block_size) as u64;
        if !self.touches_identity(lba, blocks) {
            return Ok(());
        }

        self.translate_mbr(lba, output, Direction::ToInitiator);
        for array in self.entry_arrays.clone() {
            self.translate_entries(lba, output, &array);
        }
        for header_lba in self.header_lbas.clone() {
            if let Some(range) = self.sector_range(lba, output.len(), header_lba) {
                self.present_header(header_lba, &mut output[range])?;
            }
        }
        Ok(())
    }

    fn write_blocks(&mut self, lba: u64, input: &[u8]) -> Result<(), StorageError> {
        let blocks = (input.len() / self.block_size) as u64;
        if self.inner.read_only()
            || !input.len().is_multiple_of(self.block_size)
            || !self.touches_identity(lba, blocks)
        {
            return self.inner.write_blocks(lba, input);
        }

        let mut data = input.to_vec();
        self.translate_mbr(lba, &mut data, Direction::ToMedia);

        // 이 write에 들어 있는 header. Initiator가 보는 형태이며 CRC까지 유효한 것만 다룬다.
        let mut written_headers = Vec::new();
        for header_lba in self.header_lbas.clone() {
            if let Some(range) = self.sector_range(lba, data.len(), header_lba)
                && let Some(header) = parse_gpt_header(&data[range], header_lba, self.block_count)
            {
                written_headers.push((header_lba, header));
            }
        }

        // 같은 entry를 두 번 바꾸면 원래 값으로 돌아가므로 겹치는 array는 한 번만 다룬다.
        // 이 write의 header가 가리키는 배치가 이전에 알던 배치보다 우선한다.
        let mut arrays: Vec<EntryArray> = Vec::new();
        for array in written_headers
            .iter()
            .map(|(_, header)| header.entries)
            .chain(self.entry_arrays.iter().copied())
        {
            if !arrays.iter().any(|chosen| chosen.overlaps(&array)) {
                arrays.push(array);
            }
        }
        for array in &arrays {
            self.translate_entries(lba, &mut data, array);
        }

        for (header_lba, header) in &written_headers {
            if let Some(range) = self.sector_range(lba, data.len(), *header_lba) {
                let sector = &mut data[range];
                translate_guid(
                    &mut sector[GPT_DISK_GUID_OFFSET..GPT_DISK_GUID_OFFSET + GUID_LENGTH],
                );
                store_header_crcs(sector, header.header_size, header.entries_crc);
            }
        }

        self.inner.write_blocks(lba, &data)?;
        if written_headers.is_empty() {
            self.settle_pending_headers()?;
        } else {
            for (header_lba, header) in &written_headers {
                self.settle_written_header(*header_lba, header)?;
            }
        }
        self.refresh_layout()
    }

    fn flush(&mut self) -> Result<(), StorageError> {
        self.inner.flush()
    }
}

/// 유효한 boot signature가 있는 sector의 MBR disk signature.
fn mbr_signature(sector: &[u8]) -> Option<u32> {
    if sector.get(MBR_BOOT_SIGNATURE_OFFSET..MBR_BOOT_SIGNATURE_OFFSET + 2)?
        != MBR_BOOT_SIGNATURE.as_slice()
    {
        return None;
    }
    read_u32_le(sector, MBR_SIGNATURE_OFFSET)
}

/// 0은 "signature 없음"을 뜻하므로 가상 값으로 쓰지 않는다.
fn presented_mbr_signature(original: u32) -> u32 {
    match original ^ MBR_SIGNATURE_MASK {
        0 => !original,
        presented => presented,
    }
}

fn translate_guid(guid: &mut [u8]) {
    for (byte, mask) in guid.iter_mut().zip(GUID_MASK) {
        *byte ^= mask;
    }
}

/// 사용 중인 entry의 UniquePartitionGUID를 바꾼다. PartitionTypeGUID가 0인 entry는 빈
/// 자리이므로 건드리지 않는다.
fn translate_entry_array(entries: &mut [u8], entry_size: usize) {
    for entry in entries.chunks_exact_mut(entry_size) {
        if entry[..GUID_LENGTH].iter().any(|&byte| byte != 0) {
            translate_guid(
                &mut entry
                    [GPT_ENTRY_UNIQUE_GUID_OFFSET..GPT_ENTRY_UNIQUE_GUID_OFFSET + GUID_LENGTH],
            );
        }
    }
}

/// `sector`가 `lba`에 놓인 유효한 GPT header이면 필요한 field를 반환한다.
///
/// media와 Initiator 양쪽에서 온 byte를 다루므로 CRC, 자기 위치와 entry array의 범위를
/// 모두 확인한다. 하나라도 맞지 않으면 GPT header로 보지 않는다.
fn parse_gpt_header(sector: &[u8], lba: u64, block_count: u64) -> Option<GptHeader> {
    if sector.get(..GPT_SIGNATURE.len())? != GPT_SIGNATURE.as_slice() {
        return None;
    }
    let header_size = read_u32_le(sector, GPT_HEADER_SIZE_OFFSET)? as usize;
    if !(GPT_MIN_HEADER_SIZE..=sector.len()).contains(&header_size) {
        return None;
    }
    if gpt_header_crc(&sector[..header_size]) != read_u32_le(sector, GPT_HEADER_CRC_OFFSET)? {
        return None;
    }
    if read_u64_le(sector, GPT_MY_LBA_OFFSET)? != lba {
        return None;
    }

    let entry_size = read_u32_le(sector, GPT_ENTRY_SIZE_OFFSET)? as usize;
    let entry_count = read_u32_le(sector, GPT_ENTRY_COUNT_OFFSET)? as usize;
    if entry_size < GPT_MIN_ENTRY_SIZE
        || entry_count == 0
        || !sector.len().is_multiple_of(entry_size)
    {
        return None;
    }
    let length = entry_size.checked_mul(entry_count)?;
    if length > MAX_ENTRY_ARRAY_LENGTH {
        return None;
    }
    let blocks = length.div_ceil(sector.len()) as u64;
    let entries_lba = read_u64_le(sector, GPT_ENTRIES_LBA_OFFSET)?;
    if entries_lba.checked_add(blocks)? > block_count {
        return None;
    }

    Some(GptHeader {
        header_size,
        alternate_lba: read_u64_le(sector, GPT_ALTERNATE_LBA_OFFSET)?,
        entries: EntryArray {
            lba: entries_lba,
            length,
            entry_size,
            blocks,
        },
        entries_crc: read_u32_le(sector, GPT_ENTRIES_CRC_OFFSET)?,
    })
}

/// PartitionEntryArrayCRC32를 기록하고 그에 맞춰 HeaderCRC32를 다시 계산한다.
fn store_header_crcs(sector: &mut [u8], header_size: usize, entries_crc: u32) {
    sector[GPT_ENTRIES_CRC_OFFSET..GPT_ENTRIES_CRC_OFFSET + 4]
        .copy_from_slice(&entries_crc.to_le_bytes());
    let crc = gpt_header_crc(&sector[..header_size]);
    sector[GPT_HEADER_CRC_OFFSET..GPT_HEADER_CRC_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
}

/// HeaderCRC32 field를 0으로 놓고 계산한 header CRC (UEFI 2.10 §5.3.2).
fn gpt_header_crc(header: &[u8]) -> u32 {
    let mut crc = Crc32::new();
    crc.update(&header[..GPT_HEADER_CRC_OFFSET]);
    crc.update(&[0; 4]);
    crc.update(&header[GPT_HEADER_CRC_OFFSET + 4..]);
    crc.finish()
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = Crc32::new();
    crc.update(data);
    crc.finish()
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64_le(data: &[u8], offset: usize) -> Option<u64> {
    let mut bytes = [0; 8];
    bytes.copy_from_slice(data.get(offset..offset.checked_add(8)?)?);
    Some(u64::from_le_bytes(bytes))
}

/// GPT가 쓰는 CRC-32 (IEEE 802.3, reflected polynomial 0xEDB88320).
///
/// iSCSI digest의 CRC32C와 polynomial이 달라 `crc32c` 의존성을 쓸 수 없다. GPT header와
/// entry array는 드물게, 한 번에 수십 KiB만 다루므로 table 없는 bitwise 구현으로 충분하다.
struct Crc32(u32);

impl Crc32 {
    fn new() -> Self {
        Self(!0)
    }

    fn update(&mut self, data: &[u8]) {
        for &byte in data {
            self.0 ^= u32::from(byte);
            for _ in 0..8 {
                self.0 = if self.0 & 1 != 0 {
                    (self.0 >> 1) ^ 0xedb8_8320
                } else {
                    self.0 >> 1
                };
            }
        }
    }

    fn finish(self) -> u32 {
        !self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scsi_target::MemoryBackend;

    const BLOCK: usize = 512;
    const BLOCKS: u64 = 2048;
    const LAST: u64 = BLOCKS - 1;
    const ENTRY_BLOCKS: usize = 32;
    const PRIMARY_ENTRIES: u64 = 2;
    const BACKUP_ENTRIES: u64 = LAST - ENTRY_BLOCKS as u64;

    // 아래 GUID와 CRC는 이 구현이 아닌 Python(`zlib.crc32`, byte XOR)으로 따로 계산했다.
    const TYPE_GUID: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    const MEDIA_DISK: [u8; 16] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf,
    ];
    const SHOWN_DISK: [u8; 16] = [
        0xf2, 0xf4, 0xf1, 0xf7, 0xed, 0xf6, 0xe5, 0xf4, 0xe1, 0x84, 0xfc, 0xef, 0xe5, 0xfe, 0xe5,
        0xae,
    ];
    const MEDIA_PARTITIONS: [[u8; 16]; 2] = [
        [
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
            0x3e, 0x3f,
        ],
        [
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d,
            0x5e, 0x5f,
        ],
    ];
    const SHOWN_PARTITIONS: [[u8; 16]; 2] = [
        [
            0x62, 0x64, 0x61, 0x67, 0x7d, 0x66, 0x75, 0x64, 0x71, 0x14, 0x6c, 0x7f, 0x75, 0x6e,
            0x75, 0x3e,
        ],
        [
            0x02, 0x04, 0x01, 0x07, 0x1d, 0x06, 0x15, 0x04, 0x11, 0x74, 0x0c, 0x1f, 0x15, 0x0e,
            0x15, 0x5e,
        ],
    ];
    const MEDIA_ARRAY_CRC: u32 = 0x51da_8910;
    const SHOWN_ARRAY_CRC: u32 = 0x0f16_6c21;
    const MEDIA_PRIMARY_CRC: u32 = 0xb426_eae7;
    const SHOWN_PRIMARY_CRC: u32 = 0x3584_a308;
    const MEDIA_BACKUP_CRC: u32 = 0x0754_c4ec;
    const SHOWN_BACKUP_CRC: u32 = 0x86f6_8d03;
    const MEDIA_SIGNATURE: u32 = 0x1234_5678;
    const SHOWN_SIGNATURE: u32 = 0x1234_5678 ^ 0x5253_4953;

    /// 이 모듈의 bitwise 구현과 다른 방식(table)으로 계산하는 검증용 CRC-32.
    fn reference_crc32(data: &[u8]) -> u32 {
        let mut table = [0u32; 256];
        for (index, slot) in table.iter_mut().enumerate() {
            let mut value = index as u32;
            for _ in 0..8 {
                value = if value & 1 != 0 {
                    0xedb8_8320 ^ (value >> 1)
                } else {
                    value >> 1
                };
            }
            *slot = value;
        }
        !data.iter().fold(!0u32, |crc, &byte| {
            table[((crc ^ u32::from(byte)) & 0xff) as usize] ^ (crc >> 8)
        })
    }

    fn entry(unique: [u8; 16], first: u64, last: u64) -> Vec<u8> {
        let mut entry = vec![0; 128];
        entry[..16].copy_from_slice(&TYPE_GUID);
        entry[16..32].copy_from_slice(&unique);
        entry[32..40].copy_from_slice(&first.to_le_bytes());
        entry[40..48].copy_from_slice(&last.to_le_bytes());
        entry
    }

    fn entry_array(partitions: &[[u8; 16]]) -> Vec<u8> {
        let ranges = [(34, 1000), (1001, 2014), (100, 200), (300, 400)];
        let mut array = Vec::new();
        for (unique, (first, last)) in partitions.iter().zip(ranges) {
            array.extend(entry(*unique, first, last));
        }
        array.resize(ENTRY_BLOCKS * BLOCK, 0);
        array
    }

    fn header(
        guid: [u8; 16],
        my_lba: u64,
        alternate_lba: u64,
        entries_lba: u64,
        entries_crc: u32,
        header_crc: u32,
    ) -> Vec<u8> {
        let mut sector = vec![0; BLOCK];
        sector[..8].copy_from_slice(b"EFI PART");
        sector[8..12].copy_from_slice(&[0, 0, 1, 0]);
        sector[12..16].copy_from_slice(&92u32.to_le_bytes());
        sector[16..20].copy_from_slice(&header_crc.to_le_bytes());
        sector[24..32].copy_from_slice(&my_lba.to_le_bytes());
        sector[32..40].copy_from_slice(&alternate_lba.to_le_bytes());
        sector[40..48].copy_from_slice(&34u64.to_le_bytes());
        sector[48..56].copy_from_slice(&2014u64.to_le_bytes());
        sector[56..72].copy_from_slice(&guid);
        sector[72..80].copy_from_slice(&entries_lba.to_le_bytes());
        sector[80..84].copy_from_slice(&128u32.to_le_bytes());
        sector[84..88].copy_from_slice(&128u32.to_le_bytes());
        sector[88..92].copy_from_slice(&entries_crc.to_le_bytes());
        sector
    }

    /// 검증용 CRC로 양쪽 CRC를 채운 header. 고정 fixture가 없는 배치에 쓴다.
    fn sealed_header(
        guid: [u8; 16],
        my_lba: u64,
        alternate_lba: u64,
        entries_lba: u64,
        array: &[u8],
    ) -> Vec<u8> {
        let mut sector = header(
            guid,
            my_lba,
            alternate_lba,
            entries_lba,
            reference_crc32(array),
            0,
        );
        let crc = reference_crc32(&sector[..92]);
        sector[16..20].copy_from_slice(&crc.to_le_bytes());
        sector
    }

    fn mbr(signature: u32) -> Vec<u8> {
        let mut sector = vec![0; BLOCK];
        sector[440..444].copy_from_slice(&signature.to_le_bytes());
        sector[510..512].copy_from_slice(&[0x55, 0xaa]);
        sector
    }

    fn media_primary() -> Vec<u8> {
        header(
            MEDIA_DISK,
            1,
            LAST,
            PRIMARY_ENTRIES,
            MEDIA_ARRAY_CRC,
            MEDIA_PRIMARY_CRC,
        )
    }

    fn media_backup() -> Vec<u8> {
        header(
            MEDIA_DISK,
            LAST,
            1,
            BACKUP_ENTRIES,
            MEDIA_ARRAY_CRC,
            MEDIA_BACKUP_CRC,
        )
    }

    fn shown_primary() -> Vec<u8> {
        header(
            SHOWN_DISK,
            1,
            LAST,
            PRIMARY_ENTRIES,
            SHOWN_ARRAY_CRC,
            SHOWN_PRIMARY_CRC,
        )
    }

    fn shown_backup() -> Vec<u8> {
        header(
            SHOWN_DISK,
            LAST,
            1,
            BACKUP_ENTRIES,
            SHOWN_ARRAY_CRC,
            SHOWN_BACKUP_CRC,
        )
    }

    fn gpt_disk() -> MemoryBackend {
        let mut backend = MemoryBackend::new(BLOCK as u32, BLOCKS).unwrap();
        backend.write_blocks(0, &mbr(MEDIA_SIGNATURE)).unwrap();
        backend.write_blocks(1, &media_primary()).unwrap();
        backend
            .write_blocks(PRIMARY_ENTRIES, &entry_array(&MEDIA_PARTITIONS))
            .unwrap();
        backend
            .write_blocks(BACKUP_ENTRIES, &entry_array(&MEDIA_PARTITIONS))
            .unwrap();
        backend.write_blocks(LAST, &media_backup()).unwrap();
        backend
    }

    fn read(backend: &mut dyn StorageBackend, lba: u64, blocks: usize) -> Vec<u8> {
        let mut output = vec![0; blocks * BLOCK];
        backend.read_blocks(lba, &mut output).unwrap();
        output
    }

    /// 전체가 유효한 GPT인지 검증용 CRC로 확인하고 (disk GUID, partition GUID들)을 반환한다.
    fn assert_valid_gpt(backend: &mut dyn StorageBackend) -> ([u8; 16], Vec<[u8; 16]>) {
        let mut identities = Vec::new();
        for (lba, entries_lba) in [(1, PRIMARY_ENTRIES), (LAST, BACKUP_ENTRIES)] {
            let sector = read(backend, lba, 1);
            let mut zeroed = sector[..92].to_vec();
            zeroed[16..20].fill(0);
            assert_eq!(
                reference_crc32(&zeroed),
                u32::from_le_bytes(sector[16..20].try_into().unwrap()),
                "header CRC at LBA {lba}"
            );
            let array = read(backend, entries_lba, ENTRY_BLOCKS);
            assert_eq!(
                reference_crc32(&array),
                u32::from_le_bytes(sector[88..92].try_into().unwrap()),
                "entry array CRC at LBA {lba}"
            );
            let partitions: Vec<[u8; 16]> = array
                .as_chunks::<128>()
                .0
                .iter()
                .filter(|entry| entry[..16].iter().any(|&byte| byte != 0))
                .map(|entry| entry[16..32].try_into().unwrap())
                .collect();
            identities.push((<[u8; 16]>::try_from(&sector[56..72]).unwrap(), partitions));
        }
        assert_eq!(identities[0], identities[1], "primary and backup agree");
        identities.swap_remove(0)
    }

    #[test]
    fn crc32_matches_the_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(reference_crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn reads_present_different_identifiers_with_valid_crcs() {
        let mut disk = VirtualDiskIdentity::new(Box::new(gpt_disk())).unwrap();
        assert!(disk.is_active());

        assert_eq!(read(&mut disk, 0, 1), mbr(SHOWN_SIGNATURE));
        assert_eq!(read(&mut disk, 1, 1), shown_primary());
        assert_eq!(read(&mut disk, LAST, 1), shown_backup());
        assert_eq!(
            read(&mut disk, PRIMARY_ENTRIES, ENTRY_BLOCKS),
            entry_array(&SHOWN_PARTITIONS)
        );
        assert_eq!(
            read(&mut disk, BACKUP_ENTRIES, ENTRY_BLOCKS),
            entry_array(&SHOWN_PARTITIONS)
        );
        assert_eq!(
            assert_valid_gpt(&mut disk),
            (SHOWN_DISK, SHOWN_PARTITIONS.to_vec())
        );
    }

    #[test]
    fn reads_spanning_several_structures_translate_each_part() {
        let mut disk = VirtualDiskIdentity::new(Box::new(gpt_disk())).unwrap();

        // Windows가 실제로 보내는 형태: LBA 0부터 16 sector를 한 번에 읽는다.
        let head = read(&mut disk, 0, 16);
        assert_eq!(head[..BLOCK], mbr(SHOWN_SIGNATURE)[..]);
        assert_eq!(head[BLOCK..2 * BLOCK], shown_primary()[..]);
        assert_eq!(
            head[2 * BLOCK..],
            entry_array(&SHOWN_PARTITIONS)[..14 * BLOCK]
        );

        // array 중간부터 그 뒤의 일반 data까지 걸친 read.
        disk.write_blocks(34, &[0x77; BLOCK]).unwrap();
        let tail = read(&mut disk, 33, 2);
        assert_eq!(tail[..BLOCK], entry_array(&SHOWN_PARTITIONS)[31 * BLOCK..]);
        assert_eq!(tail[BLOCK..], [0x77; BLOCK]);

        // array의 첫 sector만 읽어도 그 안의 entry가 바뀐다.
        assert_eq!(
            read(&mut disk, PRIMARY_ENTRIES, 1),
            entry_array(&SHOWN_PARTITIONS)[..BLOCK]
        );
    }

    #[test]
    fn writing_back_what_was_read_leaves_the_media_unchanged() {
        let mut disk = VirtualDiskIdentity::new(Box::new(gpt_disk())).unwrap();
        let mut untouched = gpt_disk();
        let everything = read(&mut disk, 0, BLOCKS as usize);

        disk.write_blocks(0, &everything[..34 * BLOCK]).unwrap();
        disk.write_blocks(
            BACKUP_ENTRIES,
            &everything[BACKUP_ENTRIES as usize * BLOCK..],
        )
        .unwrap();

        assert_eq!(read(&mut disk, 0, BLOCKS as usize), everything);
        let mut media = disk.inner;
        assert_eq!(
            read(media.as_mut(), 0, BLOCKS as usize),
            read(&mut untouched, 0, BLOCKS as usize)
        );
    }

    /// Initiator가 partition 하나를 추가하는 상황. 쓰는 순서와 무관하게 Initiator는 자신이
    /// 쓴 값을 다시 읽어야 하고 media에는 유효한 GPT가 남아야 한다.
    fn repartition(order: &[&str]) {
        let new_partition = [0xc3; 16];
        let mut shown = SHOWN_PARTITIONS.to_vec();
        shown.push(new_partition);
        let array = entry_array(&shown);
        let primary = sealed_header(SHOWN_DISK, 1, LAST, PRIMARY_ENTRIES, &array);
        let backup = sealed_header(SHOWN_DISK, LAST, 1, BACKUP_ENTRIES, &array);

        let mut disk = VirtualDiskIdentity::new(Box::new(gpt_disk())).unwrap();
        for &step in order {
            match step {
                "primary-array" => disk.write_blocks(PRIMARY_ENTRIES, &array).unwrap(),
                "primary-header" => disk.write_blocks(1, &primary).unwrap(),
                "backup-array" => disk.write_blocks(BACKUP_ENTRIES, &array).unwrap(),
                "backup-header" => disk.write_blocks(LAST, &backup).unwrap(),
                other => panic!("unknown step {other}"),
            }
        }

        assert_eq!(read(&mut disk, 1, 1), primary, "order {order:?}");
        assert_eq!(read(&mut disk, LAST, 1), backup, "order {order:?}");
        assert_eq!(read(&mut disk, PRIMARY_ENTRIES, ENTRY_BLOCKS), array);
        assert_eq!(read(&mut disk, BACKUP_ENTRIES, ENTRY_BLOCKS), array);

        let mut new_on_media = new_partition;
        translate_guid(&mut new_on_media);
        let mut expected = MEDIA_PARTITIONS.to_vec();
        expected.push(new_on_media);
        let mut media = disk.inner;
        assert_eq!(
            assert_valid_gpt(media.as_mut()),
            (MEDIA_DISK, expected),
            "order {order:?}"
        );
    }

    #[test]
    fn repartitioning_keeps_the_media_valid_for_every_write_order() {
        repartition(&[
            "primary-array",
            "primary-header",
            "backup-array",
            "backup-header",
        ]);
        repartition(&[
            "primary-header",
            "primary-array",
            "backup-header",
            "backup-array",
        ]);
        repartition(&[
            "backup-header",
            "backup-array",
            "primary-header",
            "primary-array",
        ]);
        repartition(&[
            "primary-array",
            "backup-array",
            "primary-header",
            "backup-header",
        ]);
        repartition(&[
            "primary-header",
            "backup-header",
            "primary-array",
            "backup-array",
        ]);
    }

    #[test]
    fn header_and_array_in_one_write_are_settled_together() {
        let new_partition = [0xc3; 16];
        let mut shown = SHOWN_PARTITIONS.to_vec();
        shown.push(new_partition);
        let array = entry_array(&shown);
        let mut front = sealed_header(SHOWN_DISK, 1, LAST, PRIMARY_ENTRIES, &array);
        front.extend(&array);
        let mut back = array.clone();
        back.extend(sealed_header(SHOWN_DISK, LAST, 1, BACKUP_ENTRIES, &array));

        let mut disk = VirtualDiskIdentity::new(Box::new(gpt_disk())).unwrap();
        disk.write_blocks(1, &front).unwrap();
        disk.write_blocks(BACKUP_ENTRIES, &back).unwrap();

        assert_eq!(read(&mut disk, 1, 1 + ENTRY_BLOCKS), front);
        assert_eq!(read(&mut disk, BACKUP_ENTRIES, ENTRY_BLOCKS + 1), back);
        let mut media = disk.inner;
        let (disk_guid, partitions) = assert_valid_gpt(media.as_mut());
        assert_eq!(disk_guid, MEDIA_DISK);
        assert_eq!(partitions[..2], MEDIA_PARTITIONS);
    }

    #[test]
    fn initializing_a_blank_disk_round_trips_in_either_write_order() {
        for array_first in [true, false] {
            let new_disk = [0x9d; 16];
            let shown = [[0x21; 16], [0x22; 16]];
            let array = entry_array(&shown);
            let primary = sealed_header(new_disk, 1, LAST, PRIMARY_ENTRIES, &array);
            let backup = sealed_header(new_disk, LAST, 1, BACKUP_ENTRIES, &array);

            let blank = MemoryBackend::new(BLOCK as u32, BLOCKS).unwrap();
            let mut disk = VirtualDiskIdentity::new(Box::new(blank)).unwrap();
            assert!(!disk.is_active());
            assert_eq!(read(&mut disk, 0, 4), vec![0; 4 * BLOCK]);

            // 처음 초기화할 때는 header가 없어 array의 위치를 미리 알 수 없다.
            if array_first {
                disk.write_blocks(PRIMARY_ENTRIES, &array).unwrap();
                disk.write_blocks(1, &primary).unwrap();
                disk.write_blocks(BACKUP_ENTRIES, &array).unwrap();
                disk.write_blocks(LAST, &backup).unwrap();
            } else {
                disk.write_blocks(1, &primary).unwrap();
                disk.write_blocks(PRIMARY_ENTRIES, &array).unwrap();
                disk.write_blocks(LAST, &backup).unwrap();
                disk.write_blocks(BACKUP_ENTRIES, &array).unwrap();
            }

            assert!(disk.is_active());
            assert_eq!(read(&mut disk, 1, 1), primary);
            assert_eq!(read(&mut disk, LAST, 1), backup);
            assert_eq!(read(&mut disk, PRIMARY_ENTRIES, ENTRY_BLOCKS), array);
            assert_eq!(read(&mut disk, BACKUP_ENTRIES, ENTRY_BLOCKS), array);
            assert_eq!(assert_valid_gpt(&mut disk), (new_disk, shown.to_vec()));

            let mut media = disk.inner;
            let (media_disk, media_partitions) = assert_valid_gpt(media.as_mut());
            assert_ne!(media_disk, new_disk);
            assert_ne!(media_partitions, shown.to_vec());
        }
    }

    #[test]
    fn invalid_headers_and_unrelated_sectors_pass_through_unchanged() {
        let mut disk = VirtualDiskIdentity::new(Box::new(gpt_disk())).unwrap();

        // 식별자 sector 밖의 I/O는 같은 byte pattern이 있어도 건드리지 않는다.
        let decoy = shown_primary();
        disk.write_blocks(100, &decoy).unwrap();
        assert_eq!(read(&mut disk, 100, 1), decoy);

        // boot signature가 없는 sector의 offset 440은 signature가 아니다.
        let mut not_mbr = mbr(SHOWN_SIGNATURE);
        not_mbr[510] = 0;
        disk.write_blocks(0, &not_mbr).unwrap();
        assert_eq!(read(&mut disk, 0, 1), not_mbr);

        // CRC가 맞지 않는 header는 GPT header로 보지 않고 그대로 기록한다.
        let mut corrupt = shown_primary();
        corrupt[16] ^= 0xff;
        disk.write_blocks(1, &corrupt).unwrap();
        assert_eq!(read(&mut disk, 1, 1), corrupt);
        let mut media = disk.inner;
        assert_eq!(read(media.as_mut(), 1, 1), corrupt);
    }

    #[test]
    fn headers_with_out_of_range_layouts_are_not_treated_as_gpt() {
        let array = entry_array(&MEDIA_PARTITIONS);
        // (field offset, field 폭, 값)
        let cases: [(usize, usize, u64); 3] = [
            (72, 8, BLOCKS - 1),  // entry array가 disk 끝을 넘는다
            (80, 4, 0x0100_0000), // entry 수가 상한을 넘는다
            (84, 4, 100),         // entry 크기가 block 크기를 나누지 못한다
        ];
        for (offset, width, value) in cases {
            let mut sector = sealed_header(MEDIA_DISK, 1, LAST, PRIMARY_ENTRIES, &array);
            sector[offset..offset + width].copy_from_slice(&value.to_le_bytes()[..width]);
            sector[16..20].fill(0);
            let crc = reference_crc32(&sector[..92]);
            sector[16..20].copy_from_slice(&crc.to_le_bytes());
            assert_eq!(
                parse_gpt_header(&sector, 1, BLOCKS),
                None,
                "offset {offset}"
            );

            let mut backend = MemoryBackend::new(BLOCK as u32, BLOCKS).unwrap();
            backend.write_blocks(1, &sector).unwrap();
            let mut disk = VirtualDiskIdentity::new(Box::new(backend)).unwrap();
            assert!(!disk.is_active());
            assert_eq!(read(&mut disk, 1, 1), sector);
        }

        // 자기 위치가 아닌 곳에 놓인 header도 GPT header가 아니다.
        let misplaced = sealed_header(MEDIA_DISK, 5, LAST, PRIMARY_ENTRIES, &array);
        assert_eq!(parse_gpt_header(&misplaced, 1, BLOCKS), None);
    }

    #[test]
    fn mbr_only_disk_maps_the_signature_and_zero_is_never_presented() {
        let mut backend = MemoryBackend::new(BLOCK as u32, BLOCKS).unwrap();
        backend.write_blocks(0, &mbr(MEDIA_SIGNATURE)).unwrap();
        let mut disk = VirtualDiskIdentity::new(Box::new(backend)).unwrap();
        assert_eq!(read(&mut disk, 0, 1), mbr(SHOWN_SIGNATURE));

        disk.write_blocks(0, &mbr(SHOWN_SIGNATURE)).unwrap();
        let mut media = disk.inner;
        assert_eq!(read(media.as_mut(), 0, 1), mbr(MEDIA_SIGNATURE));

        assert_eq!(
            presented_mbr_signature(MBR_SIGNATURE_MASK),
            !MBR_SIGNATURE_MASK
        );
    }

    #[test]
    fn backup_header_at_a_non_final_lba_is_also_translated() {
        // 더 작은 disk에서 복제한 image: backup header가 마지막 LBA가 아닌 곳에 있다.
        let alternate = 1000;
        let backup_entries = alternate - ENTRY_BLOCKS as u64;
        let array = entry_array(&MEDIA_PARTITIONS);
        let mut backend = MemoryBackend::new(BLOCK as u32, BLOCKS).unwrap();
        backend
            .write_blocks(
                1,
                &sealed_header(MEDIA_DISK, 1, alternate, PRIMARY_ENTRIES, &array),
            )
            .unwrap();
        backend.write_blocks(PRIMARY_ENTRIES, &array).unwrap();
        backend.write_blocks(backup_entries, &array).unwrap();
        backend
            .write_blocks(
                alternate,
                &sealed_header(MEDIA_DISK, alternate, 1, backup_entries, &array),
            )
            .unwrap();

        let mut disk = VirtualDiskIdentity::new(Box::new(backend)).unwrap();
        let shown = entry_array(&SHOWN_PARTITIONS);
        assert_eq!(
            read(&mut disk, alternate, 1),
            sealed_header(SHOWN_DISK, alternate, 1, backup_entries, &shown)
        );
        assert_eq!(read(&mut disk, backup_entries, ENTRY_BLOCKS), shown);
    }

    #[test]
    fn read_only_backend_rejects_writes_without_touching_the_layout() {
        let mut backend = gpt_disk();
        backend.set_read_only(true);
        let mut disk = VirtualDiskIdentity::new(Box::new(backend)).unwrap();
        assert_eq!(
            disk.write_blocks(1, &shown_primary()),
            Err(StorageError::ReadOnly)
        );
        assert_eq!(read(&mut disk, 1, 1), shown_primary());
    }
}
