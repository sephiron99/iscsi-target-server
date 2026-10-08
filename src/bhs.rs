// src/bhs.rs
//
// Bhs — 48바이트 Basic Header Segment의 저수준 래퍼
//
// 설계 의도:
// - [u8; 48] newtype에 big-endian word 접근자를 제공
// - 타입 PDU들이 이 위에서 named field로 파싱/직렬화
// - 와이어 포맷의 단일 진실 공급원(single source of truth)
//
// 왜 raw 배열을 들고 다니나?
// - iSCSI BHS는 항상 정확히 48바이트 (가변 없음)
// - 스택에 그대로 올라가므로 heap 할당 0
// - opcode-specific 영역을 각 PDU가 자기 방식으로 해석

use crate::opcode::Opcode;

pub const BHS_LEN: usize = 48;

#[derive(Clone)]
pub struct Bhs(pub [u8; BHS_LEN]);

impl Bhs {
    pub fn zeroed() -> Self {
        Bhs([0u8; BHS_LEN])
    }

    pub fn from_bytes(b: &[u8; BHS_LEN]) -> Self {
        Bhs(*b)
    }

    pub fn as_bytes(&self) -> &[u8; BHS_LEN] {
        &self.0
    }

    // ── Big-endian word 접근자 ──
    // iSCSI는 network byte order(big-endian)를 사용

    #[inline]
    pub fn get_u8(&self, i: usize) -> u8 {
        self.0[i]
    }

    #[inline]
    pub fn get_u16(&self, i: usize) -> u16 {
        u16::from_be_bytes([self.0[i], self.0[i + 1]])
    }

    /// 3바이트 big-endian (DataSegmentLength 전용)
    #[inline]
    pub fn get_u24(&self, i: usize) -> u32 {
        ((self.0[i] as u32) << 16) | ((self.0[i + 1] as u32) << 8) | (self.0[i + 2] as u32)
    }

    #[inline]
    pub fn get_u32(&self, i: usize) -> u32 {
        u32::from_be_bytes(self.0[i..i + 4].try_into().unwrap())
    }

    #[inline]
    pub fn get_u64(&self, i: usize) -> u64 {
        u64::from_be_bytes(self.0[i..i + 8].try_into().unwrap())
    }

    #[inline]
    pub fn set_u8(&mut self, i: usize, v: u8) {
        self.0[i] = v;
    }

    #[inline]
    pub fn set_u16(&mut self, i: usize, v: u16) {
        self.0[i..i + 2].copy_from_slice(&v.to_be_bytes());
    }

    #[inline]
    pub fn set_u24(&mut self, i: usize, v: u32) {
        self.0[i] = (v >> 16) as u8;
        self.0[i + 1] = (v >> 8) as u8;
        self.0[i + 2] = v as u8;
    }

    #[inline]
    pub fn set_u32(&mut self, i: usize, v: u32) {
        self.0[i..i + 4].copy_from_slice(&v.to_be_bytes());
    }

    #[inline]
    pub fn set_u64(&mut self, i: usize, v: u64) {
        self.0[i..i + 8].copy_from_slice(&v.to_be_bytes());
    }

    /// 6바이트 슬라이스 복사 (ISID 전용)
    #[inline]
    pub fn get_bytes6(&self, i: usize) -> [u8; 6] {
        self.0[i..i + 6].try_into().unwrap()
    }

    #[inline]
    pub fn set_bytes6(&mut self, i: usize, v: &[u8; 6]) {
        self.0[i..i + 6].copy_from_slice(v);
    }

    // ── 모든 PDU 공통 필드 (bytes 0-19) ──

    pub fn opcode_byte(&self) -> u8 {
        self.0[0]
    }

    pub fn is_immediate(&self) -> bool {
        self.0[0] & 0x40 != 0
    }

    /// opcode + I 플래그를 byte 0에 기록
    pub fn set_opcode(&mut self, op: Opcode, immediate: bool) {
        self.0[0] = op as u8 | if immediate { 0x40 } else { 0 };
    }

    pub fn flags(&self) -> u8 {
        self.0[1]
    }

    pub fn set_flags(&mut self, f: u8) {
        self.0[1] = f;
    }

    pub fn total_ahs_length(&self) -> u8 {
        self.0[4]
    }

    pub fn data_segment_length(&self) -> u32 {
        self.get_u24(5)
    }

    pub fn set_data_segment_length(&mut self, v: u32) {
        self.set_u24(5, v);
    }

    pub fn lun(&self) -> u64 {
        self.get_u64(8)
    }

    pub fn set_lun(&mut self, v: u64) {
        self.set_u64(8, v);
    }

    pub fn initiator_task_tag(&self) -> u32 {
        self.get_u32(16)
    }

    pub fn set_initiator_task_tag(&mut self, v: u32) {
        self.set_u32(16, v);
    }
}

impl std::fmt::Debug for Bhs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Bhs {{ opcode: 0x{:02x}, dsl: {}, itt: 0x{:08x} }}",
            self.opcode_byte(),
            self.data_segment_length(),
            self.initiator_task_tag()
        )
    }
}
