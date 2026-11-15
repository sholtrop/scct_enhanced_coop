use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub const TRACE_ALLOC_SIZE: usize = 0x10000;
pub const TRACE_CODE_LIMIT: usize = 0x0400;
pub const TRACE_HDR_OFF: usize = 0x0400;
pub const TRACE_RECORDS_OFF: usize = 0x0440;
pub const TRACE_RECORD_SIZE: usize = 64;
pub const TRACE_MAX_RECORDS: usize = 992;
pub const TRACE_MAGIC: u32 = 0x5452_4331; // "1CRT"

// Game VAs referenced by trace stubs & hooks
pub const VA_GENGINE: u32 = 0x111F_5554;
pub const VA_SYNC_ENGINE: u32 = 0x111F_55A4;
pub const VA_WARMUP_FLAG: u32 = 0x111F_55E0;
pub const VA_WARMUP_COUNTER: u32 = 0x111F_55E4;
pub const VA_USER_CHECKSUM_0: u32 = 0x111F_5F14;
pub const VA_USER_CHECKSUM_1: u32 = 0x111F_5F18;
pub const VA_DESYNC_COUNT: u32 = crate::net::CAVE_DESYNC_COUNT_VA;

#[cfg_attr(not(windows), allow(dead_code))]
pub const HOOK_TRACE_RESET_VA: u32 = 0x1095_D150;
pub const HOOK_TRACE_RESET_ORIG: &[u8] = &[0x83, 0xEC, 0x08, 0x6A, 0x00]; // sub esp, 8; push 0
pub const HOOK_TRACE_RESET_RESUME_VA: u32 = 0x1095_D155;

#[cfg_attr(not(windows), allow(dead_code))]
pub const HOOK_TRACE_TICK_VA: u32 = 0x10A7_92A6;
pub const HOOK_TRACE_TICK_ORIG: &[u8] = &[0x8B, 0x87, 0x8C, 0x04, 0x00, 0x00]; // mov eax, [edi+0x48C]
pub const HOOK_TRACE_TICK_RESUME_VA: u32 = 0x10A7_92AC;

#[cfg_attr(not(windows), allow(dead_code))]
pub const HOOK_TRACE_SEND_VA: u32 = 0x1096_45D9;
pub const HOOK_TRACE_SEND_ORIG: &[u8] = &[0x68, 0x14, 0x5F, 0x1F, 0x11]; // push 0x111F5F14
pub const HOOK_TRACE_SEND_RESUME_VA: u32 = 0x1096_45DE;

#[cfg_attr(not(windows), allow(dead_code))]
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

pub struct TraceHookOffsets {
    pub stub_reset_va: u32,
    pub stub_tick_va: u32,
    pub stub_send_va: u32,
    pub stub_cmp_va: u32,
}

struct AsmBuilder {
    base_va: u32,
    buf: Vec<u8>,
    labels: HashMap<&'static str, usize>,
    fixups_rel32: Vec<(usize, &'static str)>,
    fixups_rel8: Vec<(usize, &'static str)>,
}

impl AsmBuilder {
    fn new(base_va: u32) -> Self {
        Self {
            base_va,
            buf: Vec::with_capacity(TRACE_CODE_LIMIT),
            labels: HashMap::new(),
            fixups_rel32: Vec::new(),
            fixups_rel8: Vec::new(),
        }
    }

    fn cur_va(&self) -> u32 {
        self.base_va + self.buf.len() as u32
    }

    fn label(&mut self, name: &'static str) {
        let prev = self.labels.insert(name, self.buf.len());
        assert!(prev.is_none(), "Duplicate asm label: {}", name);
    }

    fn emit(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    fn u8(&mut self, b: u8) {
        self.buf.push(b);
    }

    fn i8(&mut self, b: i8) {
        self.buf.push(b as u8);
    }

    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn call_label(&mut self, name: &'static str) {
        self.u8(0xE8);
        self.fixups_rel32.push((self.buf.len(), name));
        self.u32(0);
    }

    fn jmp_label(&mut self, name: &'static str) {
        self.u8(0xE9);
        self.fixups_rel32.push((self.buf.len(), name));
        self.u32(0);
    }

    fn jcc_rel8(&mut self, opcode: u8, name: &'static str) {
        self.u8(opcode);
        self.fixups_rel8.push((self.buf.len(), name));
        self.u8(0);
    }

    fn jcc_rel32(&mut self, opcode2: u8, name: &'static str) {
        self.u8(0x0F);
        self.u8(opcode2);
        self.fixups_rel32.push((self.buf.len(), name));
        self.u32(0);
    }

    fn jmp_external(&mut self, target_va: u32) {
        let next_ip = self.cur_va() + 5;
        let rel = (target_va as i64 - next_ip as i64) as i32;
        self.u8(0xE9);
        self.u32(rel as u32);
    }

    fn finish(mut self) -> Vec<u8> {
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
            self.buf.len() <= TRACE_CODE_LIMIT,
            "Trace stub code ({} bytes) exceeded TRACE_CODE_LIMIT ({})",
            self.buf.len(),
            TRACE_CODE_LIMIT
        );
        self.buf
    }
}

/// Build the initial 64KB trace buffer contents (`[0..TRACE_CODE_LIMIT]` stubs + initialized header)
/// for injection at `base_va`.
pub fn build_trace_page(base_va: u32) -> (Vec<u8>, TraceHookOffsets) {
    let hdr_va = base_va + TRACE_HDR_OFF as u32;
    let hdr_write_idx = hdr_va + 0x04;
    let hdr_dropped = hdr_va + 0x08;
    let hdr_last_tick_key = hdr_va + 0x0C;
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
    a.label("wr_no_sync");
    a.emit(&[0x8B, 0x1D]);
    a.u32(VA_DESYNC_COUNT); // mov ebx, [VA_DESYNC_COUNT]
    a.emit(&[0xC1, 0xE3, 0x10]); // shl ebx, 16
    a.emit(&[0x09, 0xDA]); // or edx, ebx
    a.emit(&[0x89, 0x45]);
    a.i8(-0x0C); // mov [ebp-0x0C], eax (sync_step)
    a.emit(&[0x89, 0x55]);
    a.i8(-0x10); // mov [ebp-0x10], edx (status|mismatch)

    // Filter late ticks/sends/matching compares once past startup window
    a.emit(&[0x83, 0xF8, 0xFF]); // cmp eax, -1
    a.jcc_rel8(0x74, "wr_resolve_lvl"); // je wr_resolve_lvl
    a.emit(&[0x8B, 0x4D, 0x08]); // mov ecx, [ebp+0x08] (kind)
    a.emit(&[0x83, 0xF9, 0x02]); // cmp ecx, 2 (TICK)
    a.jcc_rel8(0x75, "wr_chk_send");
    a.emit(&[0x83, 0xF8, 45]); // cmp eax, 45
    a.jcc_rel32(0x8F, "wr_ret"); // jg wr_ret
    a.jmp_label("wr_resolve_lvl");

    a.label("wr_chk_send");
    a.emit(&[0x83, 0xF9, 0x03]); // cmp ecx, 3 (SEND)
    a.jcc_rel8(0x75, "wr_chk_cmp");
    a.emit(&[0x83, 0xF8, 60]); // cmp eax, 60
    a.jcc_rel32(0x8F, "wr_ret"); // jg wr_ret
    a.jmp_label("wr_resolve_lvl");

    a.label("wr_chk_cmp");
    a.emit(&[0x83, 0xF9, 0x04]); // cmp ecx, 4 (CMP)
    a.jcc_rel8(0x75, "wr_resolve_lvl");
    a.emit(&[0x83, 0xF8, 60]); // cmp eax, 60
    a.jcc_rel8(0x7E, "wr_resolve_lvl"); // jle wr_resolve_lvl
    a.emit(&[0x8B, 0x55, 0x14]); // mov edx, [ebp+0x14] (local)
    a.emit(&[0x3B, 0x55, 0x18]); // cmp edx, [ebp+0x18] (remote)
    a.jcc_rel32(0x84, "wr_ret"); // je wr_ret (skip late matching compares)

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
    a.jcc_rel8(0x74, "tick_done");
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
    // -------------------------------------------------------------------------
    let stub_cmp_va = a.cur_va();
    a.emit(&[0x9C, 0x60]); // pushfd; pushad
    a.u8(0x56); // push esi (arg_c = slot index 0 or 5)
    a.u8(0x51); // push ecx (arg_b = remote checksum)
    a.u8(0x50); // push eax (arg_a = local checksum)
    a.emit(&[0x6A, 0x00, 0x6A, 0x00]); // push 0; push 0
    a.emit(&[0x6A, TraceKind::Cmp as u8]); // push 4
    a.call_label("write_record");
    a.emit(&[0x61, 0x9D]); // popad; popfd
    a.emit(HOOK_TRACE_CMP_ORIG); // cmp eax, ecx; lea ecx, [esp+0x38] (EFLAGS preserved for setne bl)
    a.jmp_external(HOOK_TRACE_CMP_RESUME_VA);

    let code = a.finish();

    let mut page = vec![0u8; TRACE_ALLOC_SIZE];
    page[..code.len()].copy_from_slice(&code);
    page[TRACE_HDR_OFF..TRACE_HDR_OFF + 4].copy_from_slice(&TRACE_MAGIC.to_le_bytes());
    page[TRACE_HDR_OFF + 0x0C..TRACE_HDR_OFF + 0x10].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

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

        let a8 = (rec.eng_bits & 1) as u32;
        let a4 = ((rec.eng_bits >> 1) & 1) as u32;
        let b8 = ((rec.eng_bits >> 2) & 1) as u32;
        let ticked = ((rec.eng_bits >> 3) & 1) as u32;
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

pub fn trace_header_lines(pid: u32, bypass_active: bool) -> Vec<String> {
    vec![
        "================================================================================================================================================================".to_string(),
        format!(
            "SCCT CO-OP ENHANCER - STARTUP TICK & CHECKSUM TRACE (PID: {}, BypassFlagActive: {})",
            pid, bypass_active
        ),
        "Columns: Seq | Event | Step | St/Mis | Wrm | UserChk0 (signed) | DeltaU0 | UserChk1 | Eng(a8/a4/b8) | Tkd | TType | Pauser | Flags4A4 | Flags5CC | TimeSec | Detail".to_string(),
        "----------------------------------------------------------------------------------------------------------------------------------------------------------------".to_string(),
    ]
}

#[cfg(windows)]
pub unsafe fn install_startup_trace(
    h_process: windows_sys::Win32::Foundation::HANDLE,
    write_fn: unsafe fn(windows_sys::Win32::Foundation::HANDLE, usize, &[u8], bool),
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

        let (page, offs) = build_trace_page(base_va as u32);
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

pub fn trace_file_path(game_root: &Path) -> PathBuf {
    crate::patcher::find_child_ci(game_root, "System").join("scct_startup_trace.txt")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_trace_page_and_jumps() {
        let base = 0x0500_0000u32;
        let (page, offs) = build_trace_page(base);
        assert_eq!(page.len(), TRACE_ALLOC_SIZE);
        assert_eq!(
            u32::from_le_bytes(page[TRACE_HDR_OFF..TRACE_HDR_OFF + 4].try_into().unwrap()),
            TRACE_MAGIC
        );
        assert_eq!(
            u32::from_le_bytes(
                page[TRACE_HDR_OFF + 0x0C..TRACE_HDR_OFF + 0x10]
                    .try_into()
                    .unwrap()
            ),
            0xFFFF_FFFF
        );

        assert!(offs.stub_reset_va >= base);
        assert!(offs.stub_tick_va > offs.stub_reset_va);
        assert!(offs.stub_send_va > offs.stub_tick_va);
        assert!(offs.stub_cmp_va > offs.stub_send_va);

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
