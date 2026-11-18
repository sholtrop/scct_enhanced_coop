#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

pub const TRACE_ALLOC_SIZE: usize = 0x40000;
pub const TRACE_CODE_LIMIT: usize = 0x0600;
pub const TRACE_HDR_OFF: usize = 0x0600;
pub const TRACE_HDR_SIZE: usize = 0x00A0;
pub const TRACE_RECORDS_OFF: usize = 0x06A0;
pub const TRACE_RECORD_SIZE: usize = 64;
pub const TRACE_MAX_RECORDS: usize = (TRACE_ALLOC_SIZE - TRACE_RECORDS_OFF) / TRACE_RECORD_SIZE;
pub const TRACE_MAGIC: u32 = 0x5452_4331; // "1CRT"

pub const TRACE_HDR_SEEN_STATUS6_OFF: usize = 0x58;
pub const TRACE_HDR_RESYNC_ENABLED_OFF: usize = 0x5C;
pub const TRACE_HDR_RESYNC_NEEDED_OFF: usize = 0x60;
pub const TRACE_HDR_RESYNC_HOLD_OFF: usize = 0x64;
pub const TRACE_HDR_RESYNC_PARKED_OFF: usize = 0x68;
pub const TRACE_HDR_RESYNC_STEP_OFF: usize = 0x6C;
pub const TRACE_HDR_RESYNC_SLOT_OFF: usize = 0x70;
pub const TRACE_HDR_RESYNC_COUNT_OFF: usize = 0x74;
pub const TRACE_HDR_RESYNC_TARGET_STEP_OFF: usize = 0x78;
pub const TRACE_HDR_RESYNC_TARGET_SLOT_OFF: usize = 0x7C;
pub const TRACE_HDR_LAST_CMP_STEP_OFF: usize = 0x80;
pub const TRACE_HDR_LAST_CMP_SLOT_OFF: usize = 0x84;
pub const TRACE_HDR_RESYNC_TARGET_TICK_STEP_OFF: usize = 0x88;
pub const TRACE_HDR_RESYNC_GRACE_UNTIL_STEP_OFF: usize = 0x8C;

pub const IAT_SLEEP_VA: u32 = 0x110B_72B8; // KERNEL32!Sleep
pub const IAT_GETTICKCOUNT_VA: u32 = 0x110B_7304; // KERNEL32!GetTickCount

// Game VAs referenced by trace stubs & hooks
pub const VA_GENGINE: u32 = 0x111F_5554;
pub const VA_SYNC_ENGINE: u32 = 0x111F_55A4;
pub const VA_WARMUP_FLAG: u32 = 0x111F_55E0;
pub const VA_WARMUP_COUNTER: u32 = 0x111F_55E4;
pub const VA_USER_CHECKSUM_0: u32 = 0x111F_5F14;
pub const VA_USER_CHECKSUM_1: u32 = 0x111F_5F18;
pub const VA_DESYNC_COUNT: u32 = crate::net::CAVE_DESYNC_COUNT_VA;

pub const HOOK_TRACE_RESET_VA: u32 = 0x1095_D150;
pub const HOOK_TRACE_RESET_ORIG: &[u8] = &[0x83, 0xEC, 0x08, 0x6A, 0x00]; // sub esp, 8; push 0
pub const HOOK_TRACE_RESET_RESUME_VA: u32 = 0x1095_D155;

pub const HOOK_TRACE_TICK_VA: u32 = 0x10A7_92A6;
pub const HOOK_TRACE_TICK_ORIG: &[u8] = &[0x8B, 0x87, 0x8C, 0x04, 0x00, 0x00]; // mov eax, [edi+0x48C]
pub const HOOK_TRACE_TICK_RESUME_VA: u32 = 0x10A7_92AC;

pub const HOOK_TRACE_SEND_VA: u32 = 0x1096_45D9;
pub const HOOK_TRACE_SEND_ORIG: &[u8] = &[0x68, 0x14, 0x5F, 0x1F, 0x11]; // push 0x111F5F14
pub const HOOK_TRACE_SEND_RESUME_VA: u32 = 0x1096_45DE;

pub const HOOK_TRACE_CMP_VA: u32 = 0x10DF_86BA;
pub const HOOK_TRACE_CMP_ORIG: &[u8] = &[0x3B, 0xC1, 0x8D, 0x4C, 0x24, 0x38]; // cmp eax, ecx; lea ecx, [esp+0x38]
pub const HOOK_TRACE_CMP_RESUME_VA: u32 = 0x10DF_86C0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum TraceKind {
    Reset = 1,
    Tick = 2,
    Send = 3,
    Cmp = 4,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceRecord {
    pub seq: u32,
    pub kind: u32,
    pub sync_step: i32,
    pub sync_status: u16,
    pub mismatch_count: u16,
    pub warmup_flag: u16,
    pub warmup_counter: u16,
    pub user_checksum_0: u32,
    pub user_checksum_1: u32,
    pub eng_bits: u32,
    pub level_pauser: u32,
    pub level_flags_4a4: u32,
    pub level_flags_5cc: u32,
    pub level_time_sec_bits: u32,
    pub arg_a: u32,
    pub arg_b: u32,
    pub arg_c: u32,
    pub rdtsc_lo: u32,
}

impl TraceRecord {
    pub fn from_words(w: &[u32; 16]) -> Self {
        Self {
            seq: w[15],
            kind: w[0],
            sync_step: w[1] as i32,
            sync_status: (w[2] & 0xFFFF) as u16,
            mismatch_count: ((w[2] >> 16) & 0xFFFF) as u16,
            warmup_flag: (w[3] & 0xFFFF) as u16,
            warmup_counter: ((w[3] >> 16) & 0xFFFF) as u16,
            user_checksum_0: w[4],
            user_checksum_1: w[5],
            eng_bits: w[6],
            level_pauser: w[7],
            level_flags_4a4: w[8],
            level_flags_5cc: w[9],
            level_time_sec_bits: w[10],
            arg_a: w[11],
            arg_b: w[12],
            arg_c: w[13],
            rdtsc_lo: w[14],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerRole {
    Host,
    Guest,
    LanOrDirect,
}

impl PeerRole {
    pub fn as_str(self) -> &'static str {
        match self {
            PeerRole::Host => "HOST",
            PeerRole::Guest => "GUEST",
            PeerRole::LanOrDirect => "LAN/DIRECT",
        }
    }

    pub fn file_tag(self) -> &'static str {
        match self {
            PeerRole::Host => "host",
            PeerRole::Guest => "guest",
            PeerRole::LanOrDirect => "lan",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SlotMismatchInfo {
    pub count: u32,
    pub first_step: i32,
    pub first_local: u32,
    pub first_remote: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceMismatchSummary {
    pub write_idx: u32,
    pub dropped_records: u32,
    pub total_mismatches: u32,
    pub slot_mask: u32,
    pub first_step: i32,
    pub first_slot: u32,
    pub first_local: u32,
    pub first_remote: u32,
    pub last_step: i32,
    pub last_slot: u32,
    pub last_local: u32,
    pub last_remote: u32,
    pub slot0: SlotMismatchInfo,
    pub slot5: SlotMismatchInfo,
    pub seen_status6: bool,
}

fn read_u32_le(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap())
}

fn read_i32_le(bytes: &[u8], off: usize) -> i32 {
    read_u32_le(bytes, off) as i32
}

impl TraceMismatchSummary {
    pub fn from_header_bytes(hdr: &[u8]) -> Option<Self> {
        if hdr.len() < 0x5C {
            return None;
        }
        if read_u32_le(hdr, 0x00) != TRACE_MAGIC {
            return None;
        }
        Some(Self {
            write_idx: read_u32_le(hdr, 0x04),
            dropped_records: read_u32_le(hdr, 0x08),
            total_mismatches: read_u32_le(hdr, 0x10),
            slot_mask: read_u32_le(hdr, 0x14),
            first_step: read_i32_le(hdr, 0x18),
            first_slot: read_u32_le(hdr, 0x1C),
            first_local: read_u32_le(hdr, 0x20),
            first_remote: read_u32_le(hdr, 0x24),
            last_step: read_i32_le(hdr, 0x28),
            last_slot: read_u32_le(hdr, 0x2C),
            last_local: read_u32_le(hdr, 0x30),
            last_remote: read_u32_le(hdr, 0x34),
            slot0: SlotMismatchInfo {
                count: read_u32_le(hdr, 0x38),
                first_step: read_i32_le(hdr, 0x3C),
                first_local: read_u32_le(hdr, 0x40),
                first_remote: read_u32_le(hdr, 0x44),
            },
            slot5: SlotMismatchInfo {
                count: read_u32_le(hdr, 0x48),
                first_step: read_i32_le(hdr, 0x4C),
                first_local: read_u32_le(hdr, 0x50),
                first_remote: read_u32_le(hdr, 0x54),
            },
            seen_status6: read_u32_le(hdr, TRACE_HDR_SEEN_STATUS6_OFF) != 0,
        })
    }

    pub fn has_slot5_mismatch(&self) -> bool {
        (self.slot_mask & (1 << 5)) != 0 || self.slot5.count > 0
    }

    pub fn mismatched_slots(&self) -> Vec<u32> {
        let mut slots = Vec::new();
        for bit in 0..32u32 {
            if (self.slot_mask & (1 << bit)) != 0 {
                slots.push(bit);
            }
        }
        if slots.is_empty() && self.total_mismatches > 0 && self.first_slot != 0xFFFF_FFFF {
            slots.push(self.first_slot);
        }
        slots
    }

    pub fn format_slot_list(&self) -> String {
        if self.total_mismatches == 0 {
            return "none recorded".to_string();
        }
        let slots = self.mismatched_slots();
        if slots.is_empty() {
            return format!("unknown (total_events={})", self.total_mismatches);
        }
        slots
            .into_iter()
            .map(|slot| match slot {
                0 if self.slot0.count > 0 => format!("slot=0 (x{})", self.slot0.count),
                5 if self.slot5.count > 0 => format!("slot=5 (x{})", self.slot5.count),
                other => format!("slot={}", other),
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn format_summary_lines(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "Mismatched Slots:       {} (total_cmp_mismatches={}, slot_mask=0x{:08X}, status6_seen={})",
            self.format_slot_list(),
            self.total_mismatches,
            self.slot_mask,
            self.seen_status6
        )];
        if self.total_mismatches == 0 {
            return lines;
        }
        lines.push(format!(
            "First Mismatch:         Step={} slot={} local=0x{:08X} remote=0x{:08X}",
            self.first_step, self.first_slot, self.first_local, self.first_remote
        ));
        if self.slot0.count > 0 {
            lines.push(format!(
                "Slot 0 First Mismatch:  Step={} count={} local=0x{:08X} remote=0x{:08X}",
                self.slot0.first_step,
                self.slot0.count,
                self.slot0.first_local,
                self.slot0.first_remote
            ));
        }
        if self.slot5.count > 0 {
            lines.push(format!(
                "Slot 5 First Mismatch:  Step={} count={} local=0x{:08X} remote=0x{:08X}",
                self.slot5.first_step,
                self.slot5.count,
                self.slot5.first_local,
                self.slot5.first_remote
            ));
        }
        if self.total_mismatches > 1 {
            lines.push(format!(
                "Last Mismatch:          Step={} slot={} local=0x{:08X} remote=0x{:08X}",
                self.last_step, self.last_slot, self.last_local, self.last_remote
            ));
        }
        lines
    }
}

pub struct TraceHookOffsets {
    pub stub_reset_va: u32,
    pub stub_tick_va: u32,
    pub stub_send_va: u32,
    pub stub_cmp_va: u32,
}

pub(crate) struct AsmBuilder {
    base_va: u32,
    limit: usize,
    buf: Vec<u8>,
    labels: HashMap<&'static str, usize>,
    fixups_rel32: Vec<(usize, &'static str)>,
    fixups_rel8: Vec<(usize, &'static str)>,
}

impl AsmBuilder {
    fn new(base_va: u32) -> Self {
        Self::with_limit(base_va, TRACE_CODE_LIMIT)
    }

    pub(crate) fn with_limit(base_va: u32, limit: usize) -> Self {
        Self {
            base_va,
            limit,
            buf: Vec::with_capacity(limit),
            labels: HashMap::new(),
            fixups_rel32: Vec::new(),
            fixups_rel8: Vec::new(),
        }
    }

    pub(crate) fn cur_va(&self) -> u32 {
        self.base_va + self.buf.len() as u32
    }

    pub(crate) fn label(&mut self, name: &'static str) {
        let prev = self.labels.insert(name, self.buf.len());
        assert!(prev.is_none(), "Duplicate asm label: {}", name);
    }

    pub(crate) fn emit(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    pub(crate) fn u8(&mut self, b: u8) {
        self.buf.push(b);
    }

    fn i8(&mut self, b: i8) {
        self.buf.push(b as u8);
    }

    pub(crate) fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub(crate) fn call_label(&mut self, name: &'static str) {
        self.u8(0xE8);
        self.fixups_rel32.push((self.buf.len(), name));
        self.u32(0);
    }

    pub(crate) fn jmp_label(&mut self, name: &'static str) {
        self.u8(0xE9);
        self.fixups_rel32.push((self.buf.len(), name));
        self.u32(0);
    }

    pub(crate) fn jcc_rel8(&mut self, opcode: u8, name: &'static str) {
        self.u8(opcode);
        self.fixups_rel8.push((self.buf.len(), name));
        self.u8(0);
    }

    pub(crate) fn jcc_rel32(&mut self, opcode2: u8, name: &'static str) {
        self.u8(0x0F);
        self.u8(opcode2);
        self.fixups_rel32.push((self.buf.len(), name));
        self.u32(0);
    }

    pub(crate) fn call_external(&mut self, target_va: u32) {
        let next_ip = self.cur_va() + 5;
        let rel = (target_va as i64 - next_ip as i64) as i32;
        self.u8(0xE8);
        self.u32(rel as u32);
    }

    pub(crate) fn jmp_external(&mut self, target_va: u32) {
        let next_ip = self.cur_va() + 5;
        let rel = (target_va as i64 - next_ip as i64) as i32;
        self.u8(0xE9);
        self.u32(rel as u32);
    }

    pub(crate) fn finish(mut self) -> Vec<u8> {
        for (off, name) in self.fixups_rel32 {
            let target = *self
                .labels
                .get(name)
                .unwrap_or_else(|| panic!("Missing rel32 label: {}", name));
            let rel = (target as i64 - (off as i64 + 4)) as i32;
            self.buf[off..off + 4].copy_from_slice(&rel.to_le_bytes());
        }
        for (off, name) in self.fixups_rel8 {
            let target = *self
                .labels
                .get(name)
                .unwrap_or_else(|| panic!("Missing rel8 label: {}", name));
            let rel = target as i64 - (off as i64 + 1);
            assert!(
                (-128..=127).contains(&rel),
                "rel8 jump out of range to {}: {}",
                name,
                rel
            );
            self.buf[off] = (rel as i8) as u8;
        }
        assert!(
            self.buf.len() <= self.limit,
            "Stub code ({} bytes) exceeded limit ({})",
            self.buf.len(),
            self.limit
        );
        self.buf
    }
}

/// Build the trace buffer contents (`[0..TRACE_CODE_LIMIT]` stubs + initialized header)
/// for injection at `base_va`.
#[allow(dead_code)]
pub fn build_trace_page(base_va: u32) -> (Vec<u8>, TraceHookOffsets) {
    build_trace_page_with_options(base_va, false)
}

/// Build the trace buffer contents (`[0..TRACE_CODE_LIMIT]` stubs + initialized header)
/// for injection at `base_va`, optionally enabling the Stage 1 resync mismatch trap.
pub fn build_trace_page_with_options(
    base_va: u32,
    resync_enabled: bool,
) -> (Vec<u8>, TraceHookOffsets) {
    let hdr_va = base_va + TRACE_HDR_OFF as u32;
    let hdr_write_idx = hdr_va + 0x04;
    let hdr_dropped = hdr_va + 0x08;
    let hdr_last_tick_key = hdr_va + 0x0C;
    let hdr_seen_status6 = hdr_va + TRACE_HDR_SEEN_STATUS6_OFF as u32;
    let hdr_resync_enabled = hdr_va + TRACE_HDR_RESYNC_ENABLED_OFF as u32;
    let hdr_resync_needed = hdr_va + TRACE_HDR_RESYNC_NEEDED_OFF as u32;
    let hdr_resync_hold = hdr_va + TRACE_HDR_RESYNC_HOLD_OFF as u32;
    let hdr_resync_parked = hdr_va + TRACE_HDR_RESYNC_PARKED_OFF as u32;
    let hdr_resync_step = hdr_va + TRACE_HDR_RESYNC_STEP_OFF as u32;
    let hdr_resync_slot = hdr_va + TRACE_HDR_RESYNC_SLOT_OFF as u32;
    let hdr_resync_target_step = hdr_va + TRACE_HDR_RESYNC_TARGET_STEP_OFF as u32;
    let hdr_resync_target_slot = hdr_va + TRACE_HDR_RESYNC_TARGET_SLOT_OFF as u32;
    let hdr_last_cmp_step = hdr_va + TRACE_HDR_LAST_CMP_STEP_OFF as u32;
    let hdr_last_cmp_slot = hdr_va + TRACE_HDR_LAST_CMP_SLOT_OFF as u32;
    let hdr_resync_target_tick_step = hdr_va + TRACE_HDR_RESYNC_TARGET_TICK_STEP_OFF as u32;
    let hdr_resync_grace_until_step = hdr_va + TRACE_HDR_RESYNC_GRACE_UNTIL_STEP_OFF as u32;
    let records_va = base_va + TRACE_RECORDS_OFF as u32;

    let mut a = AsmBuilder::new(base_va);

    // -------------------------------------------------------------------------
    // write_record(kind, ulevel, levelinfo, arg_a, arg_b, arg_c) [stdcall ret 0x18]
    // [ebp+0x08]=kind, [ebp+0x0C]=ulevel, [ebp+0x10]=levelinfo,
    // [ebp+0x14]=arg_a, [ebp+0x18]=arg_b, [ebp+0x1C]=arg_c
    // Locals:
    // [ebp-0x04]=ulevel, [ebp-0x08]=levelinfo, [ebp-0x0C]=sync_step,
    // [ebp-0x10]=status_and_mismatch, [ebp-0x14]=eng_bits
    // -------------------------------------------------------------------------
    a.label("write_record");
    a.emit(&[0x55, 0x89, 0xE5, 0x83, 0xEC, 0x14]); // push ebp; mov ebp,esp; sub esp,0x14
    a.emit(&[0x53, 0x56, 0x57]); // push ebx; push esi; push edi

    // Load SyncEngine -> sync_step (eax) & sync_status (edx)
    a.emit(&[0x8B, 0x0D]);
    a.u32(VA_SYNC_ENGINE); // mov ecx, [VA_SYNC_ENGINE]
    a.u8(0xB8);
    a.u32(0xFFFF_FFFF); // mov eax, -1
    a.emit(&[0x31, 0xD2]); // xor edx, edx
    a.emit(&[0x85, 0xC9]); // test ecx, ecx
    a.jcc_rel8(0x74, "wr_no_sync"); // jz wr_no_sync
    a.emit(&[0x8B, 0x41, 0x5C]); // mov eax, [ecx+0x5C]
    a.emit(&[0x0F, 0xB7, 0x51, 0x68]); // movzx edx, word ptr [ecx+0x68]
    a.emit(&[0x83, 0xFA, 0x06]); // cmp edx, 6
    a.jcc_rel8(0x75, "wr_not_s6");
    a.emit(&[0xC7, 0x05]);
    a.u32(hdr_seen_status6);
    a.u32(1); // mov dword ptr [hdr_seen_status6], 1
    a.label("wr_not_s6");
    a.label("wr_no_sync");
    a.emit(&[0x8B, 0x1D]);
    a.u32(VA_DESYNC_COUNT); // mov ebx, [VA_DESYNC_COUNT]
    a.emit(&[0xC1, 0xE3, 0x10]); // shl ebx, 16
    a.emit(&[0x09, 0xDA]); // or edx, ebx
    a.emit(&[0x89, 0x45]);
    a.i8(-0x0C); // mov [ebp-0x0C], eax (sync_step)
    a.emit(&[0x89, 0x55]);
    a.i8(-0x10); // mov [ebp-0x10], edx (status|mismatch)

    // Always inspect CMP events first so mismatches latch in the header even after buffer fills or step>60
    a.emit(&[0x8B, 0x4D, 0x08]); // mov ecx, [ebp+0x08] (kind)
    a.emit(&[0x83, 0xF9, 0x04]); // cmp ecx, 4 (CMP)
    a.jcc_rel32(0x85, "wr_filter_step"); // jne wr_filter_step

    // Track most recent CMP (step, slot) even when checksums match (used for aligned Host resync barrier)
    a.u8(0xA3);
    a.u32(hdr_last_cmp_step); // mov [hdr_last_cmp_step], eax (sync_step)
    a.emit(&[0x8B, 0x55, 0x1C]); // mov edx, [ebp+0x1C] (slot)
    a.emit(&[0x89, 0x15]);
    a.u32(hdr_last_cmp_slot); // mov [hdr_last_cmp_slot], edx

    a.emit(&[0x8B, 0x55, 0x14]); // mov edx, [ebp+0x14] (local)
    a.emit(&[0x8B, 0x7D, 0x18]); // mov edi, [ebp+0x18] (remote)
    a.emit(&[0x39, 0xFA]); // cmp edx, edi
    a.jcc_rel8(0x75, "wr_latch_cmp_mismatch");

    // Matching CMP: skip once past startup window (sync_step != -1 && sync_step > 60)
    a.emit(&[0x83, 0xF8, 0xFF]); // cmp eax, -1
    a.jcc_rel32(0x84, "wr_resolve_lvl");
    a.emit(&[0x83, 0xF8, 60]); // cmp eax, 60
    a.jcc_rel32(0x8F, "wr_ret"); // jg wr_ret
    a.jmp_label("wr_resolve_lvl");

    // Latch mismatched CMP directly in header [0x10..0x54] (eax=sync_step, edx=local, edi=remote)
    // Skip latching expected stale pipeline mismatches during post-resync grace window.
    a.label("wr_latch_cmp_mismatch");
    a.u8(0xBE);
    a.u32(hdr_va); // mov esi, hdr_va
    a.emit(&[0x83, 0xBE]);
    a.u32(TRACE_HDR_RESYNC_GRACE_UNTIL_STEP_OFF as u32);
    a.i8(-1); // cmp dword ptr [esi+TRACE_HDR_RESYNC_GRACE_UNTIL_STEP_OFF], -1
    a.jcc_rel8(0x74, "wr_do_latch");
    a.emit(&[0x83, 0xF8, 0xFF]); // cmp eax, -1
    a.jcc_rel8(0x74, "wr_do_latch");
    a.emit(&[0x3B, 0x86]);
    a.u32(TRACE_HDR_RESYNC_GRACE_UNTIL_STEP_OFF as u32); // cmp eax, [esi+grace_until]
    a.jcc_rel32(0x8E, "wr_resolve_lvl"); // jle wr_resolve_lvl
    a.label("wr_do_latch");
    a.emit(&[0xFF, 0x46, 0x10]); // inc dword ptr [esi+0x10] (mismatch_total)
    a.emit(&[0x8B, 0x4D, 0x1C]); // mov ecx, [ebp+0x1C] (slot)
    a.u8(0xBB);
    a.u32(1); // mov ebx, 1
    a.emit(&[0x80, 0xE1, 0x1F]); // and cl, 0x1F
    a.emit(&[0xD3, 0xE3]); // shl ebx, cl
    a.emit(&[0x09, 0x5E, 0x14]); // or [esi+0x14], ebx (mismatch_slot_mask)
    a.emit(&[0x8B, 0x4D, 0x1C]); // mov ecx, [ebp+0x1C] (reload slot)

    a.emit(&[0x89, 0x46, 0x28]); // mov [esi+0x28], eax (last_step)
    a.emit(&[0x89, 0x4E, 0x2C]); // mov [esi+0x2C], ecx (last_slot)
    a.emit(&[0x89, 0x56, 0x30]); // mov [esi+0x30], edx (last_local)
    a.emit(&[0x89, 0x7E, 0x34]); // mov [esi+0x34], edi (last_remote)

    a.emit(&[0x83, 0x7E, 0x1C, 0xFF]); // cmp dword ptr [esi+0x1C], -1
    a.jcc_rel8(0x75, "wr_chk_slot0");
    a.emit(&[0x89, 0x46, 0x18]); // mov [esi+0x18], eax (first_step)
    a.emit(&[0x89, 0x4E, 0x1C]); // mov [esi+0x1C], ecx (first_slot)
    a.emit(&[0x89, 0x56, 0x20]); // mov [esi+0x20], edx (first_local)
    a.emit(&[0x89, 0x7E, 0x24]); // mov [esi+0x24], edi (first_remote)

    a.label("wr_chk_slot0");
    a.emit(&[0x85, 0xC9]); // test ecx, ecx
    a.jcc_rel8(0x75, "wr_chk_slot5");
    a.emit(&[0x83, 0x7E, 0x38, 0x00]); // cmp dword ptr [esi+0x38], 0
    a.jcc_rel8(0x75, "wr_inc_slot0");
    a.emit(&[0x89, 0x46, 0x3C]); // mov [esi+0x3C], eax
    a.emit(&[0x89, 0x56, 0x40]); // mov [esi+0x40], edx
    a.emit(&[0x89, 0x7E, 0x44]); // mov [esi+0x44], edi
    a.label("wr_inc_slot0");
    a.emit(&[0xFF, 0x46, 0x38]); // inc dword ptr [esi+0x38]
    a.jmp_label("wr_resolve_lvl");

    a.label("wr_chk_slot5");
    a.emit(&[0x83, 0xF9, 0x05]); // cmp ecx, 5
    a.jcc_rel8(0x75, "wr_resolve_lvl");
    a.emit(&[0x83, 0x7E, 0x48, 0x00]); // cmp dword ptr [esi+0x48], 0
    a.jcc_rel8(0x75, "wr_inc_slot5");
    a.emit(&[0x89, 0x46, 0x4C]); // mov [esi+0x4C], eax
    a.emit(&[0x89, 0x56, 0x50]); // mov [esi+0x50], edx
    a.emit(&[0x89, 0x7E, 0x54]); // mov [esi+0x54], edi
    a.label("wr_inc_slot5");
    a.emit(&[0xFF, 0x46, 0x48]); // inc dword ptr [esi+0x48]
    a.jmp_label("wr_resolve_lvl");

    // Filter late ticks/sends once past startup window (eax=sync_step, ecx=kind)
    a.label("wr_filter_step");
    a.emit(&[0x83, 0xF8, 0xFF]); // cmp eax, -1
    a.jcc_rel8(0x74, "wr_resolve_lvl"); // je wr_resolve_lvl
    a.emit(&[0x83, 0xF9, 0x02]); // cmp ecx, 2 (TICK)
    a.jcc_rel8(0x75, "wr_chk_send");
    a.emit(&[0x83, 0xF8, 45]); // cmp eax, 45
    a.jcc_rel32(0x8F, "wr_ret"); // jg wr_ret
    a.jcc_rel8(0xEB, "wr_resolve_lvl");

    a.label("wr_chk_send");
    a.emit(&[0x83, 0xF9, 0x03]); // cmp ecx, 3 (SEND)
    a.jcc_rel8(0x75, "wr_resolve_lvl");
    a.emit(&[0x83, 0xF8, 60]); // cmp eax, 60
    a.jcc_rel32(0x8F, "wr_ret"); // jg wr_ret

    // Resolve ULevel -> [ebp-0x04]
    a.label("wr_resolve_lvl");
    a.emit(&[0x8B, 0x45, 0x0C]); // mov eax, [ebp+0x0C]
    a.emit(&[0x85, 0xC0]); // test eax, eax
    a.jcc_rel8(0x75, "wr_have_ulevel");
    a.emit(&[0x8B, 0x1D]);
    a.u32(VA_GENGINE); // mov ebx, [VA_GENGINE]
    a.emit(&[0x85, 0xDB]); // test ebx, ebx
    a.jcc_rel8(0x74, "wr_have_ulevel"); // eax=0
    a.emit(&[0x8B, 0x83]);
    a.u32(0x17C); // mov eax, [ebx+0x17C] (GLevel)
    a.emit(&[0x85, 0xC0]); // test eax, eax
    a.jcc_rel8(0x75, "wr_have_ulevel");
    a.emit(&[0x8B, 0x43, 0x44]); // mov eax, [ebx+0x44] (Client)
    a.emit(&[0x85, 0xC0]);
    a.jcc_rel8(0x74, "wr_no_vp");
    a.emit(&[0x8B, 0x40, 0x2C]); // mov eax, [eax+0x2C] (Viewports.Data)
    a.emit(&[0x85, 0xC0]);
    a.jcc_rel8(0x74, "wr_no_vp");
    a.emit(&[0x8B, 0x00]); // mov eax, [eax] (Viewports[0])
    a.emit(&[0x85, 0xC0]);
    a.jcc_rel8(0x74, "wr_no_vp");
    a.emit(&[0x8B, 0x40, 0x30]); // mov eax, [eax+0x30] (ViewActor)
    a.emit(&[0x85, 0xC0]);
    a.jcc_rel8(0x74, "wr_no_vp");
    a.emit(&[0x8B, 0x40, 0x7C]); // mov eax, [eax+0x7C] (XLevel)
    a.jcc_rel8(0xEB, "wr_have_ulevel");
    a.label("wr_no_vp");
    a.emit(&[0x31, 0xC0]); // xor eax, eax
    a.label("wr_have_ulevel");
    a.emit(&[0x89, 0x45]);
    a.i8(-0x04); // mov [ebp-0x04], eax (ULevel)

    // Resolve LevelInfo -> [ebp-0x08]
    a.emit(&[0x8B, 0x4D, 0x10]); // mov ecx, [ebp+0x10]
    a.emit(&[0x85, 0xC9]); // test ecx, ecx
    a.jcc_rel8(0x75, "wr_have_li");
    a.emit(&[0x85, 0xC0]); // test eax, eax (ULevel)
    a.jcc_rel8(0x74, "wr_have_li");
    a.emit(&[0x83, 0x78, 0x2C, 0x00]); // cmp dword ptr [eax+0x2C], 0
    a.jcc_rel8(0x7E, "wr_have_li"); // jle wr_have_li
    a.emit(&[0x8B, 0x40, 0x28]); // mov eax, [eax+0x28] (Actors.Data)
    a.emit(&[0x85, 0xC0]);
    a.jcc_rel8(0x74, "wr_have_li");
    a.emit(&[0x8B, 0x08]); // mov ecx, [eax] (LevelInfo0)
    a.label("wr_have_li");
    a.emit(&[0x89, 0x4D]);
    a.i8(-0x08); // mov [ebp-0x08], ecx (LevelInfo)

    // Build eng_bits in edx
    a.emit(&[0x31, 0xD2]); // xor edx, edx
    a.emit(&[0x8B, 0x1D]);
    a.u32(VA_GENGINE); // mov ebx, [VA_GENGINE]
    a.emit(&[0x85, 0xDB]);
    a.jcc_rel8(0x74, "wr_eng_done");
    a.emit(&[0x83, 0xBB]);
    a.u32(0xA8);
    a.u8(0x00); // cmp dword ptr [ebx+0xA8], 0
    a.jcc_rel8(0x74, "wr_no_a8");
    a.emit(&[0x80, 0xCA, 0x01]); // or dl, 1
    a.label("wr_no_a8");
    a.emit(&[0x83, 0xBB]);
    a.u32(0xA4);
    a.u8(0x00); // cmp dword ptr [ebx+0xA4], 0
    a.jcc_rel8(0x74, "wr_no_a4");
    a.emit(&[0x80, 0xCA, 0x02]); // or dl, 2
    a.label("wr_no_a4");
    a.emit(&[0x83, 0xBB]);
    a.u32(0xB8);
    a.u8(0x00); // cmp dword ptr [ebx+0xB8], 0
    a.jcc_rel8(0x74, "wr_eng_done");
    a.emit(&[0x80, 0xCA, 0x04]); // or dl, 4
    a.label("wr_eng_done");

    a.emit(&[0x8B, 0x45]);
    a.i8(-0x04); // mov eax, [ebp-0x04] (ULevel)
    a.emit(&[0x85, 0xC0]);
    a.jcc_rel8(0x74, "wr_no_ticked");
    a.emit(&[0xF6, 0x80]);
    a.u32(0x3A20);
    a.u8(0x01); // test byte ptr [eax+0x3A20], 1
    a.jcc_rel8(0x74, "wr_no_ticked");
    a.emit(&[0x80, 0xCA, 0x08]); // or dl, 8
    a.label("wr_no_ticked");

    a.emit(&[0x83, 0x7D, 0x08, 0x02]); // cmp dword ptr [ebp+0x08], 2 (TICK)
    a.jcc_rel8(0x75, "wr_save_bits");
    a.emit(&[0x8B, 0x45, 0x1C]); // mov eax, [ebp+0x1C] (arg_c = TickType)
    a.emit(&[0x83, 0xE0, 0x0F]); // and eax, 0x0F
    a.emit(&[0xC1, 0xE0, 0x04]); // shl eax, 4
    a.emit(&[0x09, 0xC2]); // or edx, eax
    a.label("wr_save_bits");
    a.emit(&[0x89, 0x55]);
    a.i8(-0x14); // mov [ebp-0x14], edx

    // Deduplicate idle SyncStep==0 && UserChecksum0==0 TICK frames
    a.emit(&[0x83, 0x7D, 0x08, 0x02]); // cmp dword ptr [ebp+0x08], 2
    a.jcc_rel8(0x75, "wr_alloc");
    a.emit(&[0x83, 0x7D]);
    a.i8(-0x0C);
    a.u8(0x00); // cmp dword ptr [ebp-0x0C], 0
    a.jcc_rel8(0x75, "wr_alloc");
    a.emit(&[0x83, 0x3D]);
    a.u32(VA_USER_CHECKSUM_0);
    a.u8(0x00); // cmp dword ptr [VA_USER_CHECKSUM_0], 0
    a.jcc_rel8(0x75, "wr_alloc");

    a.emit(&[0x89, 0xD0]); // mov eax, edx (eng_bits)
    a.emit(&[0x8B, 0x4D]);
    a.i8(-0x08); // mov ecx, [ebp-0x08] (LevelInfo)
    a.emit(&[0x85, 0xC9]);
    a.jcc_rel8(0x74, "wr_cmp_key");
    a.emit(&[0x83, 0xB9]);
    a.u32(0x48C);
    a.u8(0x00); // cmp dword ptr [ecx+0x48C], 0
    a.jcc_rel8(0x74, "wr_no_pauser_key");
    a.emit(&[0x0D]);
    a.u32(0x100); // or eax, 0x100
    a.label("wr_no_pauser_key");
    a.emit(&[0x0F, 0xB6, 0x99]);
    a.u32(0x4A4); // movzx ebx, byte ptr [ecx+0x4A4]
    a.emit(&[0xC1, 0xE3, 0x10]); // shl ebx, 16
    a.emit(&[0x09, 0xD8]); // or eax, ebx
    a.emit(&[0x0F, 0xB6, 0x99]);
    a.u32(0x5CC); // movzx ebx, byte ptr [ecx+0x5CC]
    a.emit(&[0xC1, 0xE3, 0x18]); // shl ebx, 24
    a.emit(&[0x09, 0xD8]); // or eax, ebx
    a.label("wr_cmp_key");
    a.emit(&[0x3B, 0x05]);
    a.u32(hdr_last_tick_key); // cmp eax, [hdr_last_tick_key]
    a.jcc_rel32(0x84, "wr_ret"); // je wr_ret
    a.emit(&[0xA3]);
    a.u32(hdr_last_tick_key); // mov [hdr_last_tick_key], eax

    // Atomically allocate slot
    a.label("wr_alloc");
    a.emit(&[0x81, 0x3D]);
    a.u32(hdr_write_idx);
    a.u32(TRACE_MAX_RECORDS as u32); // cmp dword ptr [hdr_write_idx], TRACE_MAX_RECORDS
    a.jcc_rel32(0x83, "wr_drop"); // jae wr_drop
    a.u8(0xB8);
    a.u32(1); // mov eax, 1
    a.emit(&[0xF0, 0x0F, 0xC1, 0x05]);
    a.u32(hdr_write_idx); // lock xadd [hdr_write_idx], eax
    a.emit(&[0x3D]);
    a.u32(TRACE_MAX_RECORDS as u32); // cmp eax, TRACE_MAX_RECORDS
    a.jcc_rel32(0x83, "wr_drop"); // jae wr_drop

    // esi = records_va + eax * 64, keep idx in ebx
    a.emit(&[0x89, 0xC3]); // mov ebx, eax
    a.emit(&[0x89, 0xC6]); // mov esi, eax
    a.emit(&[0xC1, 0xE6, 0x06]); // shl esi, 6
    a.emit(&[0x81, 0xC6]);
    a.u32(records_va); // add esi, records_va

    // Fill w[0..14]
    a.emit(&[0x8B, 0x4D, 0x08]);
    a.emit(&[0x89, 0x0E]); // [esi+0x00] = kind
    a.emit(&[0x8B, 0x4D]);
    a.i8(-0x0C);
    a.emit(&[0x89, 0x4E, 0x04]); // [esi+0x04] = sync_step
    a.emit(&[0x8B, 0x4D]);
    a.i8(-0x10);
    a.emit(&[0x89, 0x4E, 0x08]); // [esi+0x08] = sync_status | (mismatch_cnt << 16)

    // w[3] = (warmup_flag & 0xFFFF) | ((warmup_counter & 0xFFFF) << 16)
    a.emit(&[0x0F, 0xB7, 0x0D]);
    a.u32(VA_WARMUP_FLAG); // movzx ecx, word ptr [VA_WARMUP_FLAG]
    a.emit(&[0x0F, 0xB7, 0x15]);
    a.u32(VA_WARMUP_COUNTER); // movzx edx, word ptr [VA_WARMUP_COUNTER]
    a.emit(&[0xC1, 0xE2, 0x10]); // shl edx, 16
    a.emit(&[0x09, 0xD1]); // or ecx, edx
    a.emit(&[0x89, 0x4E, 0x0C]); // [esi+0x0C]

    a.emit(&[0xA1]);
    a.u32(VA_USER_CHECKSUM_0);
    a.emit(&[0x89, 0x46, 0x10]); // [esi+0x10] = UserChecksum0
    a.emit(&[0xA1]);
    a.u32(VA_USER_CHECKSUM_1);
    a.emit(&[0x89, 0x46, 0x14]); // [esi+0x14] = UserChecksum1
    a.emit(&[0x8B, 0x45]);
    a.i8(-0x14);
    a.emit(&[0x89, 0x46, 0x18]); // [esi+0x18] = eng_bits

    // LevelInfo fields
    a.emit(&[0x8B, 0x7D]);
    a.i8(-0x08); // mov edi, [ebp-0x08]
    a.emit(&[0x85, 0xFF]);
    a.jcc_rel8(0x74, "wr_zero_li");
    a.emit(&[0x8B, 0x87]);
    a.u32(0x48C);
    a.emit(&[0x89, 0x46, 0x1C]); // [esi+0x1C] = Pauser
    a.emit(&[0x8B, 0x87]);
    a.u32(0x4A4);
    a.emit(&[0x89, 0x46, 0x20]); // [esi+0x20] = Flags4A4
    a.emit(&[0x8B, 0x87]);
    a.u32(0x5CC);
    a.emit(&[0x89, 0x46, 0x24]); // [esi+0x24] = Flags5CC
    a.emit(&[0x8B, 0x87]);
    a.u32(0x430);
    a.emit(&[0x89, 0x46, 0x28]); // [esi+0x28] = TimeSeconds
    a.jcc_rel8(0xEB, "wr_args");

    a.label("wr_zero_li");
    a.emit(&[0x31, 0xC0]); // xor eax, eax
    a.emit(&[0x89, 0x46, 0x1C]);
    a.emit(&[0x89, 0x46, 0x20]);
    a.emit(&[0x89, 0x46, 0x24]);
    a.emit(&[0x89, 0x46, 0x28]);

    a.label("wr_args");
    a.emit(&[0x8B, 0x45, 0x14]);
    a.emit(&[0x89, 0x46, 0x2C]); // [esi+0x2C] = arg_a
    a.emit(&[0x8B, 0x45, 0x18]);
    a.emit(&[0x89, 0x46, 0x30]); // [esi+0x30] = arg_b
    a.emit(&[0x8B, 0x45, 0x1C]);
    a.emit(&[0x89, 0x46, 0x34]); // [esi+0x34] = arg_c
    a.emit(&[0x0F, 0x31]); // rdtsc (eax=lo, edx=hi)
    a.emit(&[0x89, 0x46, 0x38]); // [esi+0x38] = rdtsc_lo
    a.u8(0x43); // inc ebx (seq = idx + 1)
    a.emit(&[0x89, 0x5E, 0x3C]); // [esi+0x3C] = seq (commit last!)
    a.jcc_rel8(0xEB, "wr_ret");

    a.label("wr_drop");
    a.emit(&[0xFF, 0x05]);
    a.u32(hdr_dropped); // inc dword ptr [hdr_dropped]

    a.label("wr_ret");
    a.emit(&[0x5F, 0x5E, 0x5B]); // pop edi; pop esi; pop ebx
    a.emit(&[0x89, 0xEC, 0x5D]); // mov esp, ebp; pop ebp
    a.emit(&[0xC2, 0x18, 0x00]); // ret 0x18

    // -------------------------------------------------------------------------
    // Hook Stub 1: ResetChecksums (0x1095D150, orig: sub esp,8; push 0)
    // -------------------------------------------------------------------------
    let stub_reset_va = a.cur_va();
    a.emit(&[0x83, 0x3D]);
    a.u32(VA_SYNC_ENGINE);
    a.u8(0x00);
    a.jcc_rel8(0x75, "rst_log");
    a.emit(&[0x83, 0x3D]);
    a.u32(VA_USER_CHECKSUM_0);
    a.u8(0x00);
    a.jcc_rel8(0x74, "rst_done");
    a.label("rst_log");
    a.emit(&[0x9C, 0x60]); // pushfd; pushad
    a.emit(&[0x8B, 0x44, 0x24, 0x24]); // mov eax, [esp+0x24] (caller retaddr)
    a.emit(&[0x31, 0xD2]); // xor edx, edx
    a.emit(&[0x8B, 0x0D]);
    a.u32(VA_GENGINE);
    a.emit(&[0x85, 0xC9]);
    a.jcc_rel8(0x74, "rst_push");
    a.emit(&[0x8B, 0x91]);
    a.u32(0xA8); // mov edx, [ecx+0xA8]
    a.label("rst_push");
    a.emit(&[0x6A, 0x00]); // push 0 (arg_c)
    a.u8(0x52); // push edx (arg_b = GEngine+0xA8)
    a.u8(0x50); // push eax (arg_a = caller retaddr)
    a.emit(&[0x6A, 0x00]); // push 0 (levelinfo)
    a.emit(&[0x6A, 0x00]); // push 0 (ulevel)
    a.emit(&[0x6A, TraceKind::Reset as u8]); // push 1
    a.call_label("write_record");
    a.emit(&[0x61, 0x9D]); // popad; popfd
    a.label("rst_done");
    a.emit(HOOK_TRACE_RESET_ORIG);
    a.jmp_external(HOOK_TRACE_RESET_RESUME_VA);

    // -------------------------------------------------------------------------
    // Hook Stub 2: ULevel::Tick (0x10A792A6, orig: mov eax, [edi+0x48C])
    // -------------------------------------------------------------------------
    let stub_tick_va = a.cur_va();
    a.emit(&[0x83, 0x3D]);
    a.u32(VA_SYNC_ENGINE);
    a.u8(0x00);
    a.jcc_rel32(0x84, "tick_done");

    // Stage 1 Resync Barrier: arm hold when target_tick_step is reached, then spin in Sleep(1)
    // while hdr_resync_hold != 0 (with 4000 ms failsafe).
    a.emit(&[0x83, 0x3D]);
    a.u32(hdr_resync_target_tick_step);
    a.i8(-1); // cmp dword ptr [hdr_resync_target_tick_step], -1
    a.jcc_rel8(0x74, "tick_check_hold");
    a.u8(0x50); // push eax
    a.u8(0xA1);
    a.u32(VA_SYNC_ENGINE); // mov eax, [VA_SYNC_ENGINE]
    a.emit(&[0x8B, 0x40, 0x5C]); // mov eax, [eax+0x5C]
    a.emit(&[0x3B, 0x05]);
    a.u32(hdr_resync_target_tick_step); // cmp eax, [hdr_resync_target_tick_step]
    a.u8(0x58); // pop eax (preserves EFLAGS)
    a.jcc_rel8(0x7C, "tick_check_hold"); // jl tick_check_hold
    a.emit(&[0xC7, 0x05]);
    a.u32(hdr_resync_target_tick_step);
    a.u32(0xFFFF_FFFF);
    a.emit(&[0xC7, 0x05]);
    a.u32(hdr_resync_hold);
    a.u32(1);
    a.label("tick_check_hold");
    a.emit(&[0x83, 0x3D]);
    a.u32(hdr_resync_hold);
    a.u8(0x00);
    a.jcc_rel8(0x74, "tick_after_hold");
    a.emit(&[0x9C, 0x60]); // pushfd; pushad
    a.emit(&[0xC7, 0x05]);
    a.u32(hdr_resync_parked);
    a.u32(1); // mov dword ptr [hdr_resync_parked], 1
    a.emit(&[0xFF, 0x15]);
    a.u32(IAT_GETTICKCOUNT_VA); // call dword ptr [GetTickCount]
    a.emit(&[0x89, 0xC3]); // mov ebx, eax (barrier start tick)
    a.label("tick_hold_loop");
    a.emit(&[0x83, 0x3D]);
    a.u32(hdr_resync_hold);
    a.u8(0x00);
    a.jcc_rel8(0x74, "tick_hold_done");
    a.emit(&[0xFF, 0x15]);
    a.u32(IAT_GETTICKCOUNT_VA);
    a.emit(&[0x29, 0xD8]); // sub eax, ebx
    a.u8(0x3D);
    a.u32(4000); // cmp eax, 4000
    a.jcc_rel8(0x73, "tick_hold_timeout");
    a.emit(&[0x6A, 0x01, 0xFF, 0x15]);
    a.u32(IAT_SLEEP_VA); // push 1; call dword ptr [Sleep]
    a.jcc_rel8(0xEB, "tick_hold_loop");
    a.label("tick_hold_timeout");
    a.emit(&[0xC7, 0x05]);
    a.u32(hdr_resync_hold);
    a.u32(0); // mov dword ptr [hdr_resync_hold], 0
    a.label("tick_hold_done");
    a.emit(&[0xC7, 0x05]);
    a.u32(hdr_resync_parked);
    a.u32(0); // mov dword ptr [hdr_resync_parked], 0
    a.emit(&[0x61, 0x9D]); // popad; popfd
    a.label("tick_after_hold");

    a.emit(&[0x9C, 0x60]); // pushfd; pushad
    a.emit(&[0x8B, 0x44, 0x24, 0x60]); // mov eax, [esp+0x60] (DeltaSeconds before pushfd/pushad)
    a.u8(0x55); // push ebp (arg_c = TickType)
    a.emit(&[0xFF, 0xB6]);
    a.u32(0x3A20); // push dword ptr [esi+0x3A20] (arg_b = Ticked)
    a.u8(0x50); // push eax (arg_a = DeltaSeconds)
    a.u8(0x57); // push edi (levelinfo)
    a.u8(0x56); // push esi (ulevel)
    a.emit(&[0x6A, TraceKind::Tick as u8]); // push 2
    a.call_label("write_record");
    a.emit(&[0x61, 0x9D]); // popad; popfd
    a.label("tick_done");
    a.emit(HOOK_TRACE_TICK_ORIG);
    a.jmp_external(HOOK_TRACE_TICK_RESUME_VA);

    // -------------------------------------------------------------------------
    // Hook Stub 3: SyncStepWrapper commit (0x109645D9, orig: push 0x111F5F14)
    // -------------------------------------------------------------------------
    let stub_send_va = a.cur_va();
    a.emit(&[0x9C, 0x60]); // pushfd; pushad
    a.emit(&[0x31, 0xD2, 0x31, 0xDB, 0x31, 0xC9]); // xor edx,edx; xor ebx,ebx; xor ecx,ecx
    a.emit(&[0xA1]);
    a.u32(VA_GENGINE);
    a.emit(&[0x85, 0xC0]);
    a.jcc_rel8(0x74, "send_push");
    a.emit(&[0x8B, 0x90]);
    a.u32(0xA8); // edx = GEngine+0xA8
    a.emit(&[0x8B, 0x98]);
    a.u32(0xA4); // ebx = GEngine+0xA4
    a.emit(&[0x8B, 0x88]);
    a.u32(0xB8); // ecx = GEngine+0xB8
    a.label("send_push");
    a.u8(0x51); // push ecx (arg_c = +0xB8)
    a.u8(0x53); // push ebx (arg_b = +0xA4)
    a.u8(0x52); // push edx (arg_a = +0xA8)
    a.emit(&[0x6A, 0x00, 0x6A, 0x00]); // push 0; push 0
    a.emit(&[0x6A, TraceKind::Send as u8]); // push 3
    a.call_label("write_record");
    a.emit(&[0x61, 0x9D]); // popad; popfd
    a.emit(HOOK_TRACE_SEND_ORIG);
    a.jmp_external(HOOK_TRACE_SEND_RESUME_VA);

    // -------------------------------------------------------------------------
    // Hook Stub 4: CheckSimulationChecksum cmp (0x10DF86BA, orig: cmp eax,ecx; lea ecx,[esp+0x38])
    // At 0x10DF86BA: ecx = [esp+0x0C] (local station checksum), eax = [esp+0x38] (compared station checksum), esi = slot (0 or 5).
    // -------------------------------------------------------------------------
    let stub_cmp_va = a.cur_va();
    a.emit(&[0x9C, 0x60]); // pushfd; pushad
    a.u8(0x56); // push esi (arg_c = slot index 0 or 5)
    a.u8(0x50); // push eax (arg_b = remote/compared checksum)
    a.u8(0x51); // push ecx (arg_a = local checksum)
    a.emit(&[0x6A, 0x00, 0x6A, 0x00]); // push 0; push 0
    a.emit(&[0x6A, TraceKind::Cmp as u8]); // push 4
    a.call_label("write_record");
    a.emit(&[0x61, 0x9D]); // popad; popfd
    a.emit(&[0x3B, 0xC1]); // cmp eax, ecx
    a.jcc_rel32(0x84, "cmp_match_check_target");
    a.emit(&[0x83, 0x3D]);
    a.u32(hdr_resync_enabled);
    a.u8(0x00);
    a.jcc_rel32(0x84, "cmp_mismatch_orig");
    // Check post-resync grace window: suppress expected stale pipeline mismatches without trapping/holding.
    a.emit(&[0x83, 0x3D]);
    a.u32(hdr_resync_grace_until_step);
    a.i8(-1); // cmp dword ptr [hdr_resync_grace_until_step], -1
    a.jcc_rel8(0x74, "cmp_no_grace");
    a.u8(0x50); // push eax
    a.u8(0xA1);
    a.u32(hdr_last_cmp_step); // mov eax, [hdr_last_cmp_step]
    a.emit(&[0x83, 0xF8, 0xFF]); // cmp eax, -1
    a.jcc_rel8(0x74, "cmp_grace_pop");
    a.emit(&[0x3B, 0x05]);
    a.u32(hdr_resync_grace_until_step); // cmp eax, [hdr_resync_grace_until_step]
    a.jcc_rel8(0x7F, "cmp_grace_expire"); // jg cmp_grace_expire
    a.u8(0x58); // pop eax
    a.emit(&[0x3B, 0xC0]); // cmp eax, eax (ZF=1 -> suppress Status=6)
    a.jmp_label("cmp_finish");
    a.label("cmp_grace_expire");
    a.emit(&[0xC7, 0x05]);
    a.u32(hdr_resync_grace_until_step);
    a.u32(0xFFFF_FFFF);
    a.label("cmp_grace_pop");
    a.u8(0x58); // pop eax
    a.label("cmp_no_grace");

    a.emit(&[0xFF, 0x05]);
    a.u32(VA_DESYNC_COUNT); // inc dword ptr [VA_DESYNC_COUNT]
    a.emit(&[0x83, 0x3D]);
    a.u32(hdr_resync_needed);
    a.u8(0x00);
    a.jcc_rel8(0x75, "cmp_suppress"); // keep first latched step/slot while resync pending
    a.u8(0x50); // push eax
    a.u8(0xA1);
    a.u32(hdr_last_cmp_step); // mov eax, [hdr_last_cmp_step]
    a.u8(0xA3);
    a.u32(hdr_resync_step); // mov [hdr_resync_step], eax
    a.u8(0x58); // pop eax
    a.emit(&[0x89, 0x35]);
    a.u32(hdr_resync_slot); // mov [hdr_resync_slot], esi
    a.emit(&[0xC7, 0x05]);
    a.u32(hdr_resync_needed);
    a.u32(1); // mov dword ptr [hdr_resync_needed], 1
    a.label("cmp_suppress");
    a.emit(&[0x83, 0x3D]);
    a.u32(hdr_resync_target_tick_step);
    a.i8(-1); // if explicitly catching up to a target tick step, don't park early on mismatch
    a.jcc_rel8(0x75, "cmp_suppress_only");
    a.emit(&[0xC7, 0x05]);
    a.u32(hdr_resync_hold);
    a.u32(1); // mov dword ptr [hdr_resync_hold], 1
    a.label("cmp_suppress_only");
    a.emit(&[0xC7, 0x05]);
    a.u32(hdr_resync_target_step);
    a.u32(0xFFFF_FFFF); // clear any armed target step
    a.emit(&[0x3B, 0xC0]); // cmp eax, eax -> ZF=1 so setne bl yields 0 (suppresses Status=6)
    a.jcc_rel8(0xEB, "cmp_finish");

    a.label("cmp_match_check_target");
    a.emit(&[0x83, 0x3D]);
    a.u32(hdr_resync_target_step);
    a.i8(-1); // cmp dword ptr [hdr_resync_target_step], -1 (leaves ZF=1 when idle)
    a.jcc_rel8(0x74, "cmp_finish");
    a.u8(0x52); // push edx
    a.emit(&[0x8B, 0x15]);
    a.u32(hdr_last_cmp_step); // mov edx, [hdr_last_cmp_step]
    a.emit(&[0x3B, 0x15]);
    a.u32(hdr_resync_target_step); // cmp edx, [hdr_resync_target_step]
    a.jcc_rel8(0x7C, "cmp_target_pop"); // jl (not at target step yet)
    a.jcc_rel8(0x7F, "cmp_target_arm"); // jg (past target step)
    a.emit(&[0x83, 0xFE, 0x05]); // cmp esi, 5
    a.jcc_rel8(0x74, "cmp_target_arm");
    a.emit(&[0x3B, 0x35]);
    a.u32(hdr_resync_target_slot); // cmp esi, [hdr_resync_target_slot]
    a.jcc_rel8(0x75, "cmp_target_pop");
    a.label("cmp_target_arm");
    a.emit(&[0xC7, 0x05]);
    a.u32(hdr_resync_hold);
    a.u32(1); // mov dword ptr [hdr_resync_hold], 1
    a.emit(&[0xC7, 0x05]);
    a.u32(hdr_resync_target_step);
    a.u32(0xFFFF_FFFF);
    a.label("cmp_target_pop");
    a.u8(0x5A); // pop edx
    a.emit(&[0x3B, 0xC0]); // cmp eax, eax -> restore ZF=1 for setne bl
    a.jcc_rel8(0xEB, "cmp_finish");

    a.label("cmp_mismatch_orig");
    a.emit(&[0x3B, 0xC1]); // cmp eax, ecx -> ZF=0 for vanilla mismatch path
    a.label("cmp_finish");
    a.emit(&[0x8D, 0x4C, 0x24, 0x38]); // lea ecx, [esp+0x38] (EFLAGS preserved for setne bl)
    a.jmp_external(HOOK_TRACE_CMP_RESUME_VA);

    let code = a.finish();

    let mut page = vec![0u8; TRACE_ALLOC_SIZE];
    page[..code.len()].copy_from_slice(&code);
    page[TRACE_HDR_OFF..TRACE_HDR_OFF + 4].copy_from_slice(&TRACE_MAGIC.to_le_bytes());
    page[TRACE_HDR_OFF + TRACE_HDR_RESYNC_ENABLED_OFF..TRACE_HDR_OFF + TRACE_HDR_RESYNC_ENABLED_OFF + 4]
        .copy_from_slice(&u32::from(resync_enabled).to_le_bytes());
    let sentinel = 0xFFFF_FFFFu32.to_le_bytes();
    for off in [
        0x0Cusize,
        0x18,
        0x1C,
        0x28,
        0x2C,
        0x3C,
        0x4C,
        TRACE_HDR_RESYNC_STEP_OFF,
        TRACE_HDR_RESYNC_SLOT_OFF,
        TRACE_HDR_RESYNC_TARGET_STEP_OFF,
        TRACE_HDR_RESYNC_TARGET_SLOT_OFF,
        TRACE_HDR_LAST_CMP_STEP_OFF,
        TRACE_HDR_LAST_CMP_SLOT_OFF,
        TRACE_HDR_RESYNC_TARGET_TICK_STEP_OFF,
        TRACE_HDR_RESYNC_GRACE_UNTIL_STEP_OFF,
    ] {
        page[TRACE_HDR_OFF + off..TRACE_HDR_OFF + off + 4].copy_from_slice(&sentinel);
    }

    (
        page,
        TraceHookOffsets {
            stub_reset_va,
            stub_tick_va,
            stub_send_va,
            stub_cmp_va,
        },
    )
}

pub fn format_trace_lines(
    records: &[TraceRecord],
    prev_user0: &mut Option<u32>,
) -> Vec<String> {
    let mut lines = Vec::with_capacity(records.len());
    for rec in records {
        let kind_str = match rec.kind {
            1 => "RESET",
            2 => "TICK ",
            3 => "SEND ",
            4 => "CMP  ",
            _ => "???? ",
        };
        let delta_str = match *prev_user0 {
            Some(prev) => format!("{:+11}", (rec.user_checksum_0 as i32).wrapping_sub(prev as i32)),
            None => format!("{:>11}", "-"),
        };
        *prev_user0 = Some(rec.user_checksum_0);

        let a8 = rec.eng_bits & 1;
        let a4 = (rec.eng_bits >> 1) & 1;
        let b8 = (rec.eng_bits >> 2) & 1;
        let ticked = (rec.eng_bits >> 3) & 1;
        let ttype_bits = (rec.eng_bits >> 4) & 0xF;
        let tsec = f32::from_bits(rec.level_time_sec_bits);

        let detail = match rec.kind {
            1 => format!("caller=0x{:08X} a8=0x{:08X}", rec.arg_a, rec.arg_b),
            2 => format!(
                "dt={:.6} ticked={} ttype={}",
                f32::from_bits(rec.arg_a),
                rec.arg_b,
                rec.arg_c
            ),
            3 => format!(
                "a8=0x{:08X} a4=0x{:08X} b8=0x{:08X}",
                rec.arg_a, rec.arg_b, rec.arg_c
            ),
            4 => {
                let status_str = if rec.arg_a == rec.arg_b {
                    "MATCH"
                } else {
                    "MISMATCH!"
                };
                format!(
                    "slot={} local=0x{:08X} remote=0x{:08X} {}",
                    rec.arg_c, rec.arg_a, rec.arg_b, status_str
                )
            }
            _ => format!("a=0x{:08X} b=0x{:08X} c=0x{:08X}", rec.arg_a, rec.arg_b, rec.arg_c),
        };

        let ttype_col = if rec.kind == 2 {
            format!("{}", rec.arg_c)
        } else {
            let _ = ttype_bits;
            "-".to_string()
        };

        lines.push(format!(
            "{:>4}  {}  {:>4}  {:>2}/{:<2}  {}/{}  0x{:08X} ({:>11})  {}  0x{:08X}  {}/{}/{}   {}    {:<2}  0x{:08X}  0x{:08X}  0x{:08X}  {:>9.4}  {}",
            rec.seq,
            kind_str,
            rec.sync_step,
            rec.sync_status,
            rec.mismatch_count,
            rec.warmup_flag,
            rec.warmup_counter,
            rec.user_checksum_0,
            rec.user_checksum_0 as i32,
            delta_str,
            rec.user_checksum_1,
            a8,
            a4,
            b8,
            ticked,
            ttype_col,
            rec.level_pauser,
            rec.level_flags_4a4,
            rec.level_flags_5cc,
            tsec,
            detail,
        ));
    }
    lines
}

pub fn trace_header_lines(
    pid: u32,
    role: PeerRole,
    peer_ip: Option<Ipv4Addr>,
    bypass_active: bool,
) -> Vec<String> {
    let peer_str = peer_ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "none".to_string());
    vec![
        "================================================================================================================================================================".to_string(),
        format!(
            "SCCT CO-OP ENHANCER - STARTUP TICK & CHECKSUM TRACE (Role: {}, PID: {}, Peer: {}, BypassFlagActive: {})",
            role.as_str(),
            pid,
            peer_str,
            bypass_active
        ),
        "Columns: Seq | Event | Step | St/Mis | Wrm | UserChk0 (signed) | DeltaU0 | UserChk1 | Eng(a8/a4/b8) | Tkd | TType | Pauser | Flags4A4 | Flags5CC | TimeSec | Detail".to_string(),
        "----------------------------------------------------------------------------------------------------------------------------------------------------------------".to_string(),
    ]
}

#[cfg(windows)]
pub unsafe fn install_startup_trace(
    h_process: windows_sys::Win32::Foundation::HANDLE,
    write_fn: unsafe fn(windows_sys::Win32::Foundation::HANDLE, usize, &[u8], bool),
    resync_enabled: bool,
) -> usize {
    use windows_sys::Win32::System::Diagnostics::Debug::{FlushInstructionCache, ReadProcessMemory};
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx,
    };

    unsafe {
        let alloc = VirtualAllocEx(
            h_process,
            std::ptr::null(),
            TRACE_ALLOC_SIZE,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if alloc.is_null() {
            crate::scct_log!("  [TRACE] VirtualAllocEx failed; startup trace disabled");
            return 0;
        }
        let base_va = alloc as usize;
        if base_va > u32::MAX as usize {
            crate::scct_log!("  [TRACE] Allocation above 4GB (0x{:X}); startup trace disabled", base_va);
            return 0;
        }

        let (page, offs) = build_trace_page_with_options(base_va as u32, resync_enabled);
        write_fn(h_process, base_va, &page, false);

        let hooks = [
            (HOOK_TRACE_RESET_VA, HOOK_TRACE_RESET_ORIG, offs.stub_reset_va, "ResetChecksums"),
            (HOOK_TRACE_TICK_VA, HOOK_TRACE_TICK_ORIG, offs.stub_tick_va, "ULevel::Tick"),
            (HOOK_TRACE_SEND_VA, HOOK_TRACE_SEND_ORIG, offs.stub_send_va, "SyncStepCommit"),
            (HOOK_TRACE_CMP_VA, HOOK_TRACE_CMP_ORIG, offs.stub_cmp_va, "SimChecksumCmp"),
        ];

        let mut installed = 0usize;
        for (va, orig, stub_va, label) in hooks {
            let mut cur = [0u8; 8];
            let mut nread = 0usize;
            let ok = ReadProcessMemory(
                h_process,
                va as *const _,
                cur.as_mut_ptr() as *mut _,
                orig.len(),
                &mut nread,
            );
            if ok == 0 || nread != orig.len() || &cur[..orig.len()] != orig {
                crate::scct_log!(
                    "  [TRACE] Skipping hook {} @ 0x{:08X} (bytes mismatch: {:02X?})",
                    label,
                    va,
                    &cur[..orig.len()]
                );
                continue;
            }
            let jmp = crate::net::make_jmp(va, stub_va, orig.len());
            write_fn(h_process, va as usize, &jmp, true);
            installed += 1;
        }

        let _ = FlushInstructionCache(h_process, std::ptr::null(), 0);
        crate::scct_log!(
            "  [TRACE] Installed {}/{} startup trace hooks (buffer @ 0x{:08X})",
            installed,
            hooks.len(),
            base_va
        );
        if installed == 0 {
            0
        } else {
            base_va
        }
    }
}

pub fn session_file_path(game_root: &Path, stem: &str, ext: &str, suffix: Option<&str>) -> PathBuf {
    let sys_dir = crate::patcher::find_child_ci(game_root, "System");
    match suffix {
        Some(tag) => sys_dir.join(format!("{}_{}.{}", stem, tag, ext)),
        None => sys_dir.join(format!("{}.{}", stem, ext)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_trace_page_and_jumps() {
        let base = 0x0500_0000u32;
        let (page, offs) = build_trace_page(base);
        assert_eq!(page.len(), TRACE_ALLOC_SIZE);
        assert_eq!(TRACE_MAX_RECORDS, 4069);
        assert_eq!(
            u32::from_le_bytes(page[TRACE_HDR_OFF..TRACE_HDR_OFF + 4].try_into().unwrap()),
            TRACE_MAGIC
        );
        for off in [0x0Cusize, 0x18, 0x1C, 0x28, 0x2C, 0x3C, 0x4C] {
            assert_eq!(
                u32::from_le_bytes(
                    page[TRACE_HDR_OFF + off..TRACE_HDR_OFF + off + 4]
                        .try_into()
                        .unwrap()
                ),
                0xFFFF_FFFF
            );
        }

        assert!(offs.stub_reset_va >= base);
        assert!(offs.stub_tick_va > offs.stub_reset_va);
        assert!(offs.stub_send_va > offs.stub_tick_va);
        assert!(offs.stub_cmp_va > offs.stub_send_va);

        // Verify stub_cmp_va pushes esi (slot), eax (remote), ecx (local) -> arg_c, arg_b, arg_a
        let cmp_off = (offs.stub_cmp_va - base) as usize;
        assert_eq!(&page[cmp_off..cmp_off + 5], &[0x9C, 0x60, 0x56, 0x50, 0x51]);

        // Make sure hooks fit inside 1024-byte code area
        let code_end = offs.stub_cmp_va - base + 40;
        assert!((code_end as usize) < TRACE_CODE_LIMIT);

        // Verify jmp from each hook site reaches the generated stub cleanly
        let jmp_reset = crate::net::make_jmp(HOOK_TRACE_RESET_VA, offs.stub_reset_va, HOOK_TRACE_RESET_ORIG.len());
        assert_eq!(jmp_reset.len(), 5);
        assert_eq!(jmp_reset[0], 0xE9);

        let jmp_tick = crate::net::make_jmp(HOOK_TRACE_TICK_VA, offs.stub_tick_va, HOOK_TRACE_TICK_ORIG.len());
        assert_eq!(jmp_tick.len(), 6);
        assert_eq!(jmp_tick[5], 0x90);

        let summary = TraceMismatchSummary::from_header_bytes(&page[TRACE_HDR_OFF..TRACE_HDR_OFF + TRACE_HDR_SIZE]).unwrap();
        assert_eq!(summary.total_mismatches, 0);
        assert!(!summary.has_slot5_mismatch());
        assert_eq!(summary.format_slot_list(), "none recorded");
    }

    #[test]
    fn test_build_trace_page_with_resync_enabled() {
        let base = 0x0500_0000u32;
        let (page, offs) = build_trace_page_with_options(base, true);
        assert_eq!(
            read_u32_le(&page, TRACE_HDR_OFF + TRACE_HDR_RESYNC_ENABLED_OFF),
            1
        );
        assert_eq!(
            read_u32_le(&page, TRACE_HDR_OFF + TRACE_HDR_RESYNC_STEP_OFF),
            0xFFFF_FFFF
        );
        assert_eq!(
            read_u32_le(&page, TRACE_HDR_OFF + TRACE_HDR_RESYNC_SLOT_OFF),
            0xFFFF_FFFF
        );
        assert_eq!(
            read_u32_le(&page, TRACE_HDR_OFF + TRACE_HDR_RESYNC_TARGET_TICK_STEP_OFF),
            0xFFFF_FFFF
        );
        assert_eq!(
            read_u32_le(&page, TRACE_HDR_OFF + TRACE_HDR_RESYNC_GRACE_UNTIL_STEP_OFF),
            0xFFFF_FFFF
        );
        assert!((offs.stub_cmp_va - base) as usize + 128 <= TRACE_CODE_LIMIT);

        let (disabled_page, _) = build_trace_page(base);
        assert_eq!(
            read_u32_le(&disabled_page, TRACE_HDR_OFF + TRACE_HDR_RESYNC_ENABLED_OFF),
            0
        );
    }

    #[test]
    fn test_trace_mismatch_summary_parsing_and_formatting() {
        let mut hdr = vec![0u8; TRACE_HDR_SIZE];
        hdr[0..4].copy_from_slice(&TRACE_MAGIC.to_le_bytes());
        hdr[0x04..0x08].copy_from_slice(&56u32.to_le_bytes());
        hdr[0x08..0x0C].copy_from_slice(&2u32.to_le_bytes());
        hdr[0x10..0x14].copy_from_slice(&3u32.to_le_bytes()); // total_mismatches
        hdr[0x14..0x18].copy_from_slice(&((1u32 << 0) | (1u32 << 5)).to_le_bytes());
        hdr[0x18..0x1C].copy_from_slice(&7i32.to_le_bytes());
        hdr[0x1C..0x20].copy_from_slice(&0u32.to_le_bytes());
        hdr[0x20..0x24].copy_from_slice(&0x003A_C4ECu32.to_le_bytes());
        hdr[0x24..0x28].copy_from_slice(&0x003A_C230u32.to_le_bytes());
        hdr[0x28..0x2C].copy_from_slice(&7i32.to_le_bytes());
        hdr[0x2C..0x30].copy_from_slice(&5u32.to_le_bytes());
        hdr[0x30..0x34].copy_from_slice(&0x003A_C80Eu32.to_le_bytes());
        hdr[0x34..0x38].copy_from_slice(&0x003A_C552u32.to_le_bytes());
        hdr[0x38..0x3C].copy_from_slice(&1u32.to_le_bytes());
        hdr[0x3C..0x40].copy_from_slice(&7i32.to_le_bytes());
        hdr[0x40..0x44].copy_from_slice(&0x003A_C4ECu32.to_le_bytes());
        hdr[0x44..0x48].copy_from_slice(&0x003A_C230u32.to_le_bytes());
        hdr[0x48..0x4C].copy_from_slice(&2u32.to_le_bytes());
        hdr[0x4C..0x50].copy_from_slice(&7i32.to_le_bytes());
        hdr[0x50..0x54].copy_from_slice(&0x003A_C80Eu32.to_le_bytes());
        hdr[0x54..0x58].copy_from_slice(&0x003A_C552u32.to_le_bytes());
        hdr[0x58..0x5C].copy_from_slice(&1u32.to_le_bytes()); // seen_status6

        let summary = TraceMismatchSummary::from_header_bytes(&hdr).unwrap();
        assert_eq!(summary.mismatched_slots(), vec![0, 5]);
        assert!(summary.has_slot5_mismatch());
        assert!(summary.seen_status6);
        assert_eq!(summary.format_slot_list(), "slot=0 (x1), slot=5 (x2)");
        let lines = summary.format_summary_lines();
        assert!(lines.iter().any(|l| l.contains("Slot 0 First Mismatch:  Step=7 count=1 local=0x003AC4EC remote=0x003AC230")));
        assert!(lines.iter().any(|l| l.contains("Slot 5 First Mismatch:  Step=7 count=2 local=0x003AC80E remote=0x003AC552")));
    }

    #[test]
    fn test_trace_header_lines_includes_role_and_peer() {
        let lines = trace_header_lines(5272, PeerRole::Host, Some(Ipv4Addr::new(192, 168, 1, 50)), false);
        assert!(lines[1].contains("Role: HOST"));
        assert!(lines[1].contains("PID: 5272"));
        assert!(lines[1].contains("Peer: 192.168.1.50"));
        assert!(lines[1].contains("BypassFlagActive: false"));
    }

    #[test]
    fn test_session_file_path_suffix() {
        let root = Path::new("/tmp/scct");
        assert_eq!(
            session_file_path(root, "scct_startup_trace", "txt", None),
            PathBuf::from("/tmp/scct/System/scct_startup_trace.txt")
        );
        assert_eq!(
            session_file_path(root, "scct_startup_trace", "txt", Some("guest_pid32288")),
            PathBuf::from("/tmp/scct/System/scct_startup_trace_guest_pid32288.txt")
        );
    }

    #[test]
    fn test_format_trace_lines_delta_and_details() {
        let r1 = TraceRecord::from_words(&[
            2, 1, 0, 1 | (2 << 16), (-42920i32) as u32, 0, 0b1011, 0, 0x04, 0, 1.0f32.to_bits(),
            0.016f32.to_bits(), 1, 1, 100, 1,
        ]);
        let r2 = TraceRecord::from_words(&[
            4, 7, 6 | (1 << 16), 1, (-257520i32) as u32, 0, 0b0011, 0x1234, 0x00, 0x02,
            2.0f32.to_bits(), 0x1111_2222, 0x3333_4444, 5, 200, 2,
        ]);
        let mut prev = None;
        let lines = format_trace_lines(&[r1, r2], &mut prev);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("TICK "));
        assert!(lines[0].contains("ttype=1"));
        assert!(lines[1].contains("CMP  "));
        assert!(lines[1].contains("slot=5 local=0x11112222 remote=0x33334444 MISMATCH!"));
        assert!(lines[1].contains("-214600"));
        assert_eq!(prev, Some((-257520i32) as u32));
    }
}
