#![cfg_attr(not(windows), allow(dead_code))]

use crate::launcher::{GameProcess, VA_GNAMES, VA_GNAMES_COUNT};
use crate::trace::{
    PeerRole, TRACE_HDR_OFF, TRACE_HDR_RESYNC_COUNT_OFF, TRACE_HDR_RESYNC_ENABLED_OFF,
    TRACE_HDR_RESYNC_GRACE_UNTIL_STEP_OFF, TRACE_HDR_RESYNC_HOLD_OFF, TRACE_HDR_RESYNC_NEEDED_OFF,
    TRACE_HDR_RESYNC_PARKED_OFF, TRACE_HDR_RESYNC_SLOT_OFF, TRACE_HDR_RESYNC_STEP_OFF,
    TRACE_HDR_RESYNC_TARGET_SLOT_OFF, TRACE_HDR_RESYNC_TARGET_STEP_OFF,
    TRACE_HDR_RESYNC_TARGET_TICK_STEP_OFF, VA_SYNC_ENGINE, VA_USER_CHECKSUM_0, VA_USER_CHECKSUM_1,
};
use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

pub const RESYNC_MAGIC: u32 = 0x5352_4353; // "SCRS"
pub const RESYNC_UDP_PORT_A: u16 = 9104;
pub const RESYNC_UDP_PORT_B: u16 = 9105;
pub const MAX_CHUNK_PAYLOAD: usize = 1024;
pub const RESYNC_PAWN_WIRE_SIZE: usize = 120;

pub const VA_LOCAL_SIM_STATION: usize = 0x1131_B3BC;
pub const SIM_STATION_SLOT5_OFF: usize = 0x04C;
pub const SIM_STATION_SLOT0_OFF: usize = 0x1A0;
pub const SIM_STATION_SLOT_BLOCK_LEN: usize = 0x154; // 340 bytes
pub const SIM_STATION_SLOTS_1_TO_4_OFFS: [usize; 4] = [0x2F4, 0x448, 0x59C, 0x6F0];
pub const SIM_STATION_CUMULATIVE_OFF: usize = 0xB0C;
pub const SYNC_ENGINE_CLOCK_OFFS: [usize; 2] = [0x54, 0x58];
pub const SYNC_ENGINE_WINDOW_OFFS: [usize; 5] = [0x60, 0x64, 0x7C, 0x80, 0x84];
pub const SYNC_ENGINE_SENT_STEP_OFF: usize = 0xA0;
pub const SYNC_ENGINE_RNG_OFF: usize = 0xB8;
pub const SYNC_ENGINE_RNG_LEN: usize = 2508; // mt[624] + mti (+0x9C0) + mag01[2] (+0x9C4)

const SNAPSHOT_FIXED_HDR_LEN: usize =
    4 + 4 + 4 + 4 + 16 + 8 + 20 + 4 + 8 + 4 + SIM_STATION_SLOT_BLOCK_LEN * 2 + SYNC_ENGINE_RNG_LEN + 4;
const RESYNC_GRACE_STEPS: i32 = 6;
const MAX_CONSECUTIVE_RESYNCS: u32 = 3;
const RESYNC_COOLDOWN_STEPS: i32 = 30;
const BARRIER_TIMEOUT_MS: u64 = 2500;
const RETRY_SEND_INTERVAL_MS: u64 = 100;
const PLAYER_DRIFT_SQ_THRESHOLD: f32 = 1.0;

#[derive(Clone, Debug, PartialEq)]
pub struct ResyncPawnState {
    pub actor_index: u16,
    pub is_player_pawn: u8,
    pub zone_number: u8,
    pub name_hash: u32,
    pub class_hash: u32,
    pub flags_28: u32,
    pub flags_2c: u32,
    pub location: [f32; 3],
    pub rotation: [i32; 3],
    pub velocity: [f32; 3],
    pub acceleration: [f32; 3],
    pub has_controller: u8,
    pub ctrl_location: [f32; 3],
    pub ctrl_rotation: [i32; 3],
    /// `[Pawn+0x934..+0x944]`: AI/Pawn RNG-seeded look/turn timers and rolled floats.
    pub pawn_rng_timers: [u32; 4],
    /// `[Pawn+0x744..+0x74C]`: Pawn AI/tick gate flags (applied only to AI pawns).
    pub pawn_tick_flags: [u32; 2],
}

impl ResyncPawnState {
    fn write_into(&self, out: &mut Vec<u8>) {
        let start = out.len();
        out.extend_from_slice(&self.actor_index.to_le_bytes());
        out.push(self.is_player_pawn);
        out.push(self.zone_number);
        out.extend_from_slice(&self.name_hash.to_le_bytes());
        out.extend_from_slice(&self.class_hash.to_le_bytes());
        out.extend_from_slice(&self.flags_28.to_le_bytes());
        out.extend_from_slice(&self.flags_2c.to_le_bytes());
        write_f32_3(out, self.location);
        write_i32_3(out, self.rotation);
        write_f32_3(out, self.velocity);
        write_f32_3(out, self.acceleration);
        out.extend_from_slice(&[self.has_controller, 0, 0, 0]);
        write_f32_3(out, self.ctrl_location);
        write_i32_3(out, self.ctrl_rotation);
        write_u32_slice(out, &self.pawn_rng_timers);
        write_u32_slice(out, &self.pawn_tick_flags);
        debug_assert_eq!(out.len() - start, RESYNC_PAWN_WIRE_SIZE);
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < RESYNC_PAWN_WIRE_SIZE {
            bail!("Truncated ResyncPawnState ({} bytes)", bytes.len());
        }
        Ok(Self {
            actor_index: u16::from_le_bytes([bytes[0], bytes[1]]),
            is_player_pawn: bytes[2],
            zone_number: bytes[3],
            name_hash: le_u32(bytes, 4),
            class_hash: le_u32(bytes, 8),
            flags_28: le_u32(bytes, 12),
            flags_2c: le_u32(bytes, 16),
            location: read_f32_3(bytes, 20),
            rotation: read_i32_3(bytes, 32),
            velocity: read_f32_3(bytes, 44),
            acceleration: read_f32_3(bytes, 56),
            has_controller: bytes[68],
            ctrl_location: read_f32_3(bytes, 72),
            ctrl_rotation: read_i32_3(bytes, 84),
            pawn_rng_timers: read_u32_array(bytes, 96),
            pawn_tick_flags: read_u32_array(bytes, 112),
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResyncSnapshot {
    pub step: i32,
    pub user_checksum_0: u32,
    pub user_checksum_1: u32,
    pub sim_station_cumulative: u32,
    pub sim_station_slots_1_4: [u32; 4],
    pub sync_engine_clock: [u32; 2],
    pub sync_engine_window_steps: [u32; 5],
    pub sync_engine_sent_step: u32,
    pub level_time_f64_bits: u64,
    pub level_info_time_bits: u32,
    pub sim_station_slot5_block: [u8; SIM_STATION_SLOT_BLOCK_LEN],
    pub sim_station_slot0_block: [u8; SIM_STATION_SLOT_BLOCK_LEN],
    pub rng_bytes: [u8; SYNC_ENGINE_RNG_LEN],
    pub pawns: Vec<ResyncPawnState>,
}

impl ResyncSnapshot {
    pub fn mti(&self) -> u32 {
        le_u32(&self.rng_bytes, 0x9C0)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(SNAPSHOT_FIXED_HDR_LEN + self.pawns.len() * RESYNC_PAWN_WIRE_SIZE);
        out.extend_from_slice(&self.step.to_le_bytes());
        out.extend_from_slice(&self.user_checksum_0.to_le_bytes());
        out.extend_from_slice(&self.user_checksum_1.to_le_bytes());
        out.extend_from_slice(&self.sim_station_cumulative.to_le_bytes());
        write_u32_slice(&mut out, &self.sim_station_slots_1_4);
        write_u32_slice(&mut out, &self.sync_engine_clock);
        write_u32_slice(&mut out, &self.sync_engine_window_steps);
        out.extend_from_slice(&self.sync_engine_sent_step.to_le_bytes());
        out.extend_from_slice(&self.level_time_f64_bits.to_le_bytes());
        out.extend_from_slice(&self.level_info_time_bits.to_le_bytes());
        out.extend_from_slice(&self.sim_station_slot5_block);
        out.extend_from_slice(&self.sim_station_slot0_block);
        out.extend_from_slice(&self.rng_bytes);
        out.extend_from_slice(&(self.pawns.len() as u32).to_le_bytes());
        for p in &self.pawns {
            p.write_into(&mut out);
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < SNAPSHOT_FIXED_HDR_LEN {
            bail!("ResyncSnapshot too short ({} bytes)", bytes.len());
        }
        let mut off = 0usize;
        let step = le_u32(bytes, off) as i32;
        off += 4;
        let user_checksum_0 = le_u32(bytes, off);
        off += 4;
        let user_checksum_1 = le_u32(bytes, off);
        off += 4;
        let sim_station_cumulative = le_u32(bytes, off);
        off += 4;

        let sim_station_slots_1_4: [u32; 4] = read_u32_array(bytes, off);
        off += 16;
        let sync_engine_clock: [u32; 2] = read_u32_array(bytes, off);
        off += 8;
        let sync_engine_window_steps: [u32; 5] = read_u32_array(bytes, off);
        off += 20;
        let sync_engine_sent_step = le_u32(bytes, off);
        off += 4;
        let level_time_f64_bits = le_u64(bytes, off);
        off += 8;
        let level_info_time_bits = le_u32(bytes, off);
        off += 4;

        let mut sim_station_slot5_block = [0u8; SIM_STATION_SLOT_BLOCK_LEN];
        sim_station_slot5_block.copy_from_slice(&bytes[off..off + SIM_STATION_SLOT_BLOCK_LEN]);
        off += SIM_STATION_SLOT_BLOCK_LEN;

        let mut sim_station_slot0_block = [0u8; SIM_STATION_SLOT_BLOCK_LEN];
        sim_station_slot0_block.copy_from_slice(&bytes[off..off + SIM_STATION_SLOT_BLOCK_LEN]);
        off += SIM_STATION_SLOT_BLOCK_LEN;

        let mut rng_bytes = [0u8; SYNC_ENGINE_RNG_LEN];
        rng_bytes.copy_from_slice(&bytes[off..off + SYNC_ENGINE_RNG_LEN]);
        off += SYNC_ENGINE_RNG_LEN;

        let pawn_count = le_u32(bytes, off) as usize;
        off += 4;
        if pawn_count > 16384 {
            bail!("Absurd ResyncSnapshot pawn count: {}", pawn_count);
        }
        let expected_len = off + pawn_count * RESYNC_PAWN_WIRE_SIZE;
        if bytes.len() != expected_len {
            bail!(
                "ResyncSnapshot size mismatch: expected {}, got {}",
                expected_len,
                bytes.len()
            );
        }

        let mut pawns = Vec::with_capacity(pawn_count);
        for _ in 0..pawn_count {
            pawns.push(ResyncPawnState::decode(&bytes[off..off + RESYNC_PAWN_WIRE_SIZE])?);
            off += RESYNC_PAWN_WIRE_SIZE;
        }

        Ok(Self {
            step,
            user_checksum_0,
            user_checksum_1,
            sim_station_cumulative,
            sim_station_slots_1_4,
            sync_engine_clock,
            sync_engine_window_steps,
            sync_engine_sent_step,
            level_time_f64_bits,
            level_info_time_bits,
            sim_station_slot5_block,
            sim_station_slot0_block,
            rng_bytes,
            pawns,
        })
    }
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResyncPacket {
    Request {
        step: i32,
        slot: u32,
    },
    Chunk {
        step: i32,
        total_len: u32,
        crc32: u32,
        chunk_idx: u16,
        chunk_count: u16,
        payload: Vec<u8>,
    },
    Ack {
        step: i32,
    },
}

impl ResyncPacket {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&RESYNC_MAGIC.to_le_bytes());
        match self {
            ResyncPacket::Request { step, slot } => {
                out.extend_from_slice(&[1, 0, 0, 0]);
                out.extend_from_slice(&step.to_le_bytes());
                out.extend_from_slice(&slot.to_le_bytes());
            }
            ResyncPacket::Chunk {
                step,
                total_len,
                crc32,
                chunk_idx,
                chunk_count,
                payload,
            } => {
                out.extend_from_slice(&[2, 0, 0, 0]);
                out.extend_from_slice(&step.to_le_bytes());
                out.extend_from_slice(&total_len.to_le_bytes());
                out.extend_from_slice(&crc32.to_le_bytes());
                out.extend_from_slice(&chunk_idx.to_le_bytes());
                out.extend_from_slice(&chunk_count.to_le_bytes());
                out.extend_from_slice(payload);
            }
            ResyncPacket::Ack { step } => {
                out.extend_from_slice(&[3, 0, 0, 0]);
                out.extend_from_slice(&step.to_le_bytes());
            }
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 12 {
            bail!("ResyncPacket too short ({} bytes)", bytes.len());
        }
        if le_u32(bytes, 0) != RESYNC_MAGIC {
            bail!("Bad ResyncPacket magic");
        }
        let kind = bytes[4];
        let step = le_u32(bytes, 8) as i32;
        match kind {
            1 => {
                if bytes.len() != 16 {
                    bail!("Bad Request len {}", bytes.len());
                }
                Ok(ResyncPacket::Request {
                    step,
                    slot: le_u32(bytes, 12),
                })
            }
            2 => {
                if bytes.len() < 24 {
                    bail!("Bad Chunk len {}", bytes.len());
                }
                let payload = bytes[24..].to_vec();
                if payload.len() > MAX_CHUNK_PAYLOAD {
                    bail!("Oversized chunk payload {}", payload.len());
                }
                let chunk_idx = u16::from_le_bytes([bytes[20], bytes[21]]);
                let chunk_count = u16::from_le_bytes([bytes[22], bytes[23]]);
                if chunk_count == 0 || chunk_idx >= chunk_count {
                    bail!("Invalid chunk index {}/{}", chunk_idx, chunk_count);
                }
                Ok(ResyncPacket::Chunk {
                    step,
                    total_len: le_u32(bytes, 12),
                    crc32: le_u32(bytes, 16),
                    chunk_idx,
                    chunk_count,
                    payload,
                })
            }
            3 => {
                if bytes.len() != 12 {
                    bail!("Bad Ack len {}", bytes.len());
                }
                Ok(ResyncPacket::Ack { step })
            }
            other => bail!("Unknown ResyncPacket kind {}", other),
        }
    }
}

pub fn encode_snapshot_chunks(snap: &ResyncSnapshot) -> Vec<Vec<u8>> {
    let raw = snap.to_bytes();
    let total_len = raw.len() as u32;
    let sum = crc32(&raw);
    let slices: Vec<&[u8]> = raw.chunks(MAX_CHUNK_PAYLOAD).collect();
    let chunk_count = slices.len().max(1) as u16;
    if slices.is_empty() {
        return vec![
            ResyncPacket::Chunk {
                step: snap.step,
                total_len,
                crc32: sum,
                chunk_idx: 0,
                chunk_count: 1,
                payload: Vec::new(),
            }
            .to_bytes(),
        ];
    }
    slices
        .into_iter()
        .enumerate()
        .map(|(idx, slice)| {
            ResyncPacket::Chunk {
                step: snap.step,
                total_len,
                crc32: sum,
                chunk_idx: idx as u16,
                chunk_count,
                payload: slice.to_vec(),
            }
            .to_bytes()
        })
        .collect()
}

#[derive(Default)]
pub struct ChunkAssembler {
    step: Option<i32>,
    total_len: usize,
    expected_crc: u32,
    chunks: Vec<Option<Vec<u8>>>,
    received: usize,
}

impl ChunkAssembler {
    pub fn reset(&mut self) {
        self.step = None;
        self.total_len = 0;
        self.expected_crc = 0;
        self.chunks.clear();
        self.received = 0;
    }

    pub fn progress(&self) -> (usize, usize) {
        (self.received, self.chunks.len())
    }

    pub fn push(&mut self, pkt: ResyncPacket) -> Result<Option<ResyncSnapshot>> {
        let ResyncPacket::Chunk {
            step,
            total_len,
            crc32: pkt_crc,
            chunk_idx,
            chunk_count,
            payload,
        } = pkt
        else {
            return Ok(None);
        };

        if chunk_count == 0 || chunk_idx >= chunk_count {
            bail!("Invalid chunk metadata {}/{}", chunk_idx, chunk_count);
        }

        let need_reset = self.step != Some(step)
            || self.total_len != total_len as usize
            || self.expected_crc != pkt_crc
            || self.chunks.len() != chunk_count as usize;

        if need_reset {
            self.step = Some(step);
            self.total_len = total_len as usize;
            self.expected_crc = pkt_crc;
            self.chunks = vec![None; chunk_count as usize];
            self.received = 0;
        }

        let idx = chunk_idx as usize;
        if self.chunks[idx].is_none() {
            self.chunks[idx] = Some(payload);
            self.received += 1;
        }

        if self.received < self.chunks.len() {
            return Ok(None);
        }

        let mut assembled = Vec::with_capacity(self.total_len);
        for part in self.chunks.iter().flatten() {
            assembled.extend_from_slice(part);
        }
        let expected_len = self.total_len;
        let expected_crc = self.expected_crc;
        self.reset();

        if assembled.len() != expected_len {
            bail!(
                "Reassembled snapshot length mismatch: expected {}, got {}",
                expected_len,
                assembled.len()
            );
        }
        let actual_crc = crc32(&assembled);
        if actual_crc != expected_crc {
            bail!(
                "Snapshot CRC32 mismatch: expected 0x{:08X}, got 0x{:08X}",
                expected_crc,
                actual_crc
            );
        }

        Ok(Some(ResyncSnapshot::from_bytes(&assembled)?))
    }
}

pub fn extract_host_snapshot(proc: &GameProcess) -> Result<ResyncSnapshot> {
    let sync_engine = proc.read_u32(VA_SYNC_ENGINE as usize).unwrap_or(0);
    if sync_engine == 0 {
        bail!("SyncEngine pointer is null");
    }
    let sync_base = sync_engine as usize;
    let step = proc
        .read_i32(sync_base + 0x5C)
        .context("Failed reading SyncEngine->Step")?;
    let sync_engine_clock: [u32; 2] = read_proc_u32_offs(proc, sync_base, SYNC_ENGINE_CLOCK_OFFS)
        .context("Failed reading SyncEngine clock")?;
    let sync_engine_window_steps: [u32; 5] =
        read_proc_u32_offs(proc, sync_base, SYNC_ENGINE_WINDOW_OFFS)
            .context("Failed reading SyncEngine window steps")?;
    let sync_engine_sent_step = proc
        .read_u32(sync_base + SYNC_ENGINE_SENT_STEP_OFF)
        .context("Failed reading SyncEngine->SentStep")?;

    let mut rng_bytes = [0u8; SYNC_ENGINE_RNG_LEN];
    if !proc.read_memory(sync_base + SYNC_ENGINE_RNG_OFF, &mut rng_bytes) {
        bail!("Failed reading MT19937 RNG state from SyncEngine");
    }

    let user_checksum_0 = proc
        .read_u32(VA_USER_CHECKSUM_0 as usize)
        .context("Failed reading UserChecksum0")?;
    let user_checksum_1 = proc
        .read_u32(VA_USER_CHECKSUM_1 as usize)
        .context("Failed reading UserChecksum1")?;

    let sim_station = proc.read_u32(VA_LOCAL_SIM_STATION).unwrap_or(0);
    if sim_station == 0 {
        bail!("Local SimStation pointer is null");
    }
    let sim_base = sim_station as usize;
    let sim_station_cumulative = proc
        .read_u32(sim_base + SIM_STATION_CUMULATIVE_OFF)
        .context("Failed reading SimStation cumulative checksum")?;
    let sim_station_slots_1_4: [u32; 4] =
        read_proc_u32_offs(proc, sim_base, SIM_STATION_SLOTS_1_TO_4_OFFS)
            .context("Failed reading SimStation slot checksum")?;
    let mut sim_station_slot5_block = [0u8; SIM_STATION_SLOT_BLOCK_LEN];
    if !proc.read_memory(
        sim_base + SIM_STATION_SLOT5_OFF,
        &mut sim_station_slot5_block,
    ) {
        bail!("Failed reading SimStation slot 5 block");
    }
    let mut sim_station_slot0_block = [0u8; SIM_STATION_SLOT_BLOCK_LEN];
    if !proc.read_memory(
        sim_base + SIM_STATION_SLOT0_OFF,
        &mut sim_station_slot0_block,
    ) {
        bail!("Failed reading SimStation slot 0 block");
    }

    let level_ptr = proc.resolve_level_ptr();
    if level_ptr == 0 {
        bail!("GLevel pointer is null");
    }
    let level_time_f64_bits = read_proc_u64(proc, level_ptr as usize + 0xC4)
        .context("Failed reading GLevel->TimeSeconds")?;
    let actor_ptrs = read_level_actor_ptrs(proc, level_ptr)?;
    let level_info_time_bits = actor_ptrs
        .first()
        .copied()
        .filter(|&ptr| ptr != 0)
        .and_then(|ptr| proc.read_u32(ptr as usize + 0x430))
        .unwrap_or(0);
    let mut fname_cache = FNameCache::new(proc);
    let mut pawns = Vec::new();

    for (idx, actor_ptr) in actor_ptrs.into_iter().enumerate() {
        if actor_ptr == 0 {
            continue;
        }
        let base = actor_ptr as usize;
        let flags_28 = proc.read_u32(base + 0x28).unwrap_or(0);
        let flags_2c = proc.read_u32(base + 0x2C).unwrap_or(0);
        if (flags_2c & 0x10) == 0 || (flags_28 & 0x04) != 0 {
            continue;
        }
        let (_, _, name_hash, class_hash) = fname_cache.actor_identity(proc, actor_ptr);
        let zone_number = proc.read_u8(base + 0xB4).unwrap_or(0);
        let location = read_proc_f32_3(proc, base + 0xE8).unwrap_or([0.0; 3]);
        let rotation = read_proc_i32_3(proc, base + 0xF4).unwrap_or([0; 3]);
        let velocity = read_proc_f32_3(proc, base + 0x100).unwrap_or([0.0; 3]);
        let acceleration = read_proc_f32_3(proc, base + 0x10C).unwrap_or([0.0; 3]);
        let pawn_rng_timers = read_proc_u32_array(proc, base + 0x934).unwrap_or([0; 4]);
        let pawn_tick_flags = read_proc_u32_array(proc, base + 0x744).unwrap_or([0; 2]);

        let ctrl_ptr = proc.read_u32(base + 0x2B4).unwrap_or(0);
        let (has_controller, ctrl_location, ctrl_rotation) = if ctrl_ptr != 0 {
            let cbase = ctrl_ptr as usize;
            (
                1u8,
                read_proc_f32_3(proc, cbase + 0xE8).unwrap_or([0.0; 3]),
                read_proc_i32_3(proc, cbase + 0xF4).unwrap_or([0; 3]),
            )
        } else {
            (0u8, [0.0; 3], [0; 3])
        };

        pawns.push(ResyncPawnState {
            actor_index: idx as u16,
            is_player_pawn: u8::from((flags_2c & 0x20) != 0),
            zone_number,
            name_hash,
            class_hash,
            flags_28,
            flags_2c,
            location,
            rotation,
            velocity,
            acceleration,
            has_controller,
            ctrl_location,
            ctrl_rotation,
            pawn_rng_timers,
            pawn_tick_flags,
        });
    }

    Ok(ResyncSnapshot {
        step,
        user_checksum_0,
        user_checksum_1,
        sim_station_cumulative,
        sim_station_slots_1_4,
        sync_engine_clock,
        sync_engine_window_steps,
        sync_engine_sent_step,
        level_time_f64_bits,
        level_info_time_bits,
        sim_station_slot5_block,
        sim_station_slot0_block,
        rng_bytes,
        pawns,
    })
}

pub fn apply_client_snapshot(proc: &GameProcess, snap: &ResyncSnapshot) -> Result<usize> {
    let sync_engine = proc.read_u32(VA_SYNC_ENGINE as usize).unwrap_or(0);
    if sync_engine == 0 {
        bail!("Client SyncEngine pointer is null");
    }
    let sim_station = proc.read_u32(VA_LOCAL_SIM_STATION).unwrap_or(0);
    if sim_station == 0 {
        bail!("Client SimStation pointer is null");
    }
    let level_ptr = proc.resolve_level_ptr();
    if level_ptr == 0 {
        bail!("Client GLevel pointer is null");
    }
    let actor_ptrs = read_level_actor_ptrs(proc, level_ptr)?;
    let mut fname_cache = FNameCache::new(proc);

    // Pass 1: Strict topology validation (resolved actor/class name hashes) before mutating memory.
    let mut validated = Vec::with_capacity(snap.pawns.len());
    for p in &snap.pawns {
        let idx = p.actor_index as usize;
        let Some(&actor_ptr) = actor_ptrs.get(idx) else {
            bail!(
                "Client Actors.Num ({}) <= host pawn actor_index {}",
                actor_ptrs.len(),
                idx
            );
        };
        if actor_ptr == 0 {
            bail!("Client actor[{}] is null", idx);
        }
        let (actor_name, class_name, name_hash, class_hash) =
            fname_cache.actor_identity(proc, actor_ptr);
        if (name_hash, class_hash) != (p.name_hash, p.class_hash) {
            bail!(
                "Actor topology mismatch at index {}: host=(0x{:08X}, 0x{:08X}) client=({}:0x{:08X}, {}:0x{:08X})",
                idx,
                p.name_hash,
                p.class_hash,
                actor_name,
                name_hash,
                class_name,
                class_hash
            );
        }
        validated.push((actor_ptr, p));
    }

    // Pass 2: Apply Pawn/Controller fields, level time, MT19937 RNG, SyncEngine, and SimStation baselines.
    let mut updated_pawns = 0usize;
    for (actor_ptr, p) in validated {
        let base = actor_ptr as usize;
        // Always sync deterministic RNG timers/rolls on all pawns (even non-drifted player pawns).
        let _ = write_proc_u32_array(proc, base + 0x934, &p.pawn_rng_timers);
        if p.is_player_pawn != 0 {
            let cur_loc = read_proc_f32_3(proc, base + 0xE8).unwrap_or(p.location);
            let dx = cur_loc[0] - p.location[0];
            let dy = cur_loc[1] - p.location[1];
            let dz = cur_loc[2] - p.location[2];
            if dx * dx + dy * dy + dz * dz <= PLAYER_DRIFT_SQ_THRESHOLD {
                continue;
            }
        }

        let _ = proc.write_u32(base + 0x28, p.flags_28);
        let _ = proc.write_u32(base + 0x2C, p.flags_2c);
        let _ = proc.write_memory(base + 0xB4, &[p.zone_number]);
        let _ = write_proc_f32_3(proc, base + 0xE8, p.location);
        let _ = write_proc_i32_3(proc, base + 0xF4, p.rotation);
        let _ = write_proc_f32_3(proc, base + 0x100, p.velocity);
        let _ = write_proc_f32_3(proc, base + 0x10C, p.acceleration);

        // Only push tick gate flags & controller transform for AI Pawns (PlayerControllers/Pawns hold local UI/camera state).
        if p.is_player_pawn == 0 {
            let _ = write_proc_u32_array(proc, base + 0x744, &p.pawn_tick_flags);
            if p.has_controller != 0 {
                let ctrl_ptr = proc.read_u32(base + 0x2B4).unwrap_or(0);
                if ctrl_ptr != 0 {
                    let cbase = ctrl_ptr as usize;
                    let _ = write_proc_f32_3(proc, cbase + 0xE8, p.ctrl_location);
                    let _ = write_proc_i32_3(proc, cbase + 0xF4, p.ctrl_rotation);
                }
            }
        }
        updated_pawns += 1;
    }

    let _ = write_proc_u64(proc, level_ptr as usize + 0xC4, snap.level_time_f64_bits);
    if let Some(&level_info_ptr) = actor_ptrs.first()
        && level_info_ptr != 0
    {
        let _ = proc.write_u32(level_info_ptr as usize + 0x430, snap.level_info_time_bits);
    }

    let sync_base = sync_engine as usize;
    if !proc.write_memory(sync_base + SYNC_ENGINE_RNG_OFF, &snap.rng_bytes) {
        bail!("Failed writing Client MT19937 RNG state");
    }
    write_proc_u32_offs(
        proc,
        sync_base,
        &SYNC_ENGINE_CLOCK_OFFS,
        &snap.sync_engine_clock,
    );
    write_proc_u32_offs(
        proc,
        sync_base,
        &SYNC_ENGINE_WINDOW_OFFS,
        &snap.sync_engine_window_steps,
    );
    let _ = proc.write_u32(
        sync_base + SYNC_ENGINE_SENT_STEP_OFF,
        snap.sync_engine_sent_step,
    );

    let _ = proc.write_u32(VA_USER_CHECKSUM_0 as usize, snap.user_checksum_0);
    let _ = proc.write_u32(VA_USER_CHECKSUM_1 as usize, snap.user_checksum_1);

    let sim_base = sim_station as usize;
    let _ = proc.write_memory(
        sim_base + SIM_STATION_SLOT5_OFF,
        &snap.sim_station_slot5_block,
    );
    let _ = proc.write_memory(
        sim_base + SIM_STATION_SLOT0_OFF,
        &snap.sim_station_slot0_block,
    );
    write_proc_u32_offs(
        proc,
        sim_base,
        &SIM_STATION_SLOTS_1_TO_4_OFFS,
        &snap.sim_station_slots_1_4,
    );
    let _ = proc.write_u32(
        sim_base + SIM_STATION_CUMULATIVE_OFF,
        snap.sim_station_cumulative,
    );

    Ok(updated_pawns)
}

#[derive(Debug)]
pub enum ResyncPollOutcome {
    None,
    Synced(String),
    Failed(String),
}

enum CoordState {
    Idle,
    WaitingPeerDiscovery {
        step: i32,
        slot: u32,
        started_at: Instant,
    },
    WaitingClientPark {
        trapped_step: i32,
        slot: u32,
        started_at: Instant,
    },
    WaitingHostBarrier {
        step: i32,
        slot: u32,
        armed_target: bool,
        started_at: Instant,
    },
    WaitingAck {
        step: i32,
        slot: u32,
        total_pawns: usize,
        mti: u32,
        chunks: Vec<Vec<u8>>,
        started_at: Instant,
        last_send: Instant,
    },
    WaitingChunks {
        step: i32,
        slot: u32,
        started_at: Instant,
        last_req: Instant,
    },
    ApplyingSnapshot {
        snap: Box<ResyncSnapshot>,
        slot: u32,
        started_at: Instant,
    },
}

pub struct ResyncCoordinator {
    socket: UdpSocket,
    local_port: u16,
    peer_role: PeerRole,
    known_is_host: Option<bool>,
    peer_ip: Option<Ipv4Addr>,
    peer_addr: Option<SocketAddr>,
    assembler: ChunkAssembler,
    state: CoordState,
    last_resync_step: Option<i32>,
    consecutive_resyncs: u32,
    last_acked_step: Option<i32>,
    pending_logs: Vec<String>,
}

impl ResyncCoordinator {
    pub fn new(
        peer_role: PeerRole,
        peer_ip: Option<Ipv4Addr>,
        local_bind_ip: Option<Ipv4Addr>,
    ) -> Result<Self> {
        let bind_ip = local_bind_ip.unwrap_or(Ipv4Addr::UNSPECIFIED);
        let socket = bind_resync_socket(bind_ip)?;
        let local_port = socket.local_addr().map(|a| a.port()).unwrap_or(0);
        let known_is_host = match peer_role {
            PeerRole::Host => Some(true),
            PeerRole::Guest => Some(false),
            PeerRole::LanOrDirect => None,
        };
        Ok(Self::with_socket(
            socket,
            local_port,
            peer_role,
            known_is_host,
            peer_ip,
            None,
        ))
    }

    fn with_socket(
        socket: UdpSocket,
        local_port: u16,
        peer_role: PeerRole,
        known_is_host: Option<bool>,
        peer_ip: Option<Ipv4Addr>,
        peer_addr: Option<SocketAddr>,
    ) -> Self {
        Self {
            socket,
            local_port,
            peer_role,
            known_is_host,
            peer_ip,
            peer_addr,
            assembler: ChunkAssembler::default(),
            state: CoordState::Idle,
            last_resync_step: None,
            consecutive_resyncs: 0,
            last_acked_step: None,
            pending_logs: Vec::new(),
        }
    }

    fn resolved_is_host(&mut self, proc: &GameProcess) -> Option<bool> {
        if let Some(h) = self.known_is_host {
            return Some(h);
        }
        if matches!(self.peer_role, PeerRole::LanOrDirect) {
            let mut octets = [0u8; 4];
            if proc.read_memory(crate::net::G_LAN_PEER_VA as usize, &mut octets)
                && octets != [0, 0, 0, 0]
            {
                let ip = Ipv4Addr::from(octets);
                if self.peer_ip.is_none() {
                    self.peer_ip = Some(ip);
                }
                self.known_is_host = Some(false);
                return Some(false);
            }
        }
        None
    }

    fn peer_targets(&self) -> Vec<SocketAddr> {
        if let Some(addr) = self.peer_addr {
            return vec![addr];
        }
        let Some(ip) = self.peer_ip else {
            return Vec::new();
        };
        if ip.is_loopback() {
            let other_port = if self.local_port == RESYNC_UDP_PORT_A {
                RESYNC_UDP_PORT_B
            } else {
                RESYNC_UDP_PORT_A
            };
            vec![SocketAddr::V4(SocketAddrV4::new(ip, other_port))]
        } else {
            vec![
                SocketAddr::V4(SocketAddrV4::new(ip, RESYNC_UDP_PORT_A)),
                SocketAddr::V4(SocketAddrV4::new(ip, RESYNC_UDP_PORT_B)),
            ]
        }
    }

    fn send_packet_bytes(&self, bytes: &[u8]) {
        for target in self.peer_targets() {
            let _ = self.socket.send_to(bytes, target);
        }
    }

    fn record_retry(&mut self, step: i32) -> Result<()> {
        let within_cooldown = self
            .last_resync_step
            .is_some_and(|prev| step <= prev.saturating_add(RESYNC_COOLDOWN_STEPS));
        if within_cooldown {
            self.consecutive_resyncs += 1;
        } else {
            self.consecutive_resyncs = 1;
        }
        self.last_resync_step = Some(step);
        if self.consecutive_resyncs > MAX_CONSECUTIVE_RESYNCS {
            bail!(
                "Aborted after {} consecutive resync retries within {} steps (step={})",
                self.consecutive_resyncs,
                RESYNC_COOLDOWN_STEPS,
                step
            );
        }
        Ok(())
    }

    fn recv_packets(&mut self) -> Vec<(SocketAddr, ResyncPacket)> {
        let mut out = Vec::new();
        let mut buf = [0u8; 2048];
        while let Ok((len, src)) = self.socket.recv_from(&mut buf) {
            if let Ok(pkt) = ResyncPacket::from_bytes(&buf[..len]) {
                self.peer_addr = Some(src);
                out.push((src, pkt));
            }
        }
        out
    }

    pub fn poll(&mut self, proc: &GameProcess) -> ResyncPollOutcome {
        let incoming = self.recv_packets();
        for (_, pkt) in &incoming {
            match pkt {
                ResyncPacket::Request { .. } if self.known_is_host.is_none() => {
                    self.known_is_host = Some(true);
                }
                ResyncPacket::Chunk { .. } if self.known_is_host.is_none() => {
                    self.known_is_host = Some(false);
                }
                _ => {}
            }
        }

        let trace_va = proc.trace_buf_va();
        if trace_va == 0 {
            return ResyncPollOutcome::None;
        }
        let hdr_va = trace_va + TRACE_HDR_OFF;

        // Handle incoming packets relevant to current state.
        for (src, pkt) in incoming {
            match pkt {
                ResyncPacket::Request { step, slot } => match &self.state {
                    CoordState::Idle => {
                        if let Err(e) = self.record_retry(step) {
                            return self.abort_resync(proc, e.to_string());
                        }
                        self.pending_logs.push(format!(
                            "[RESYNC] Host received Request(step={}, slot={}) from {}",
                            step, slot, src
                        ));
                        self.state = CoordState::WaitingHostBarrier {
                            step,
                            slot,
                            armed_target: false,
                            started_at: Instant::now(),
                        };
                    }
                    CoordState::WaitingPeerDiscovery { step: cur_step, .. } => {
                        if step != *cur_step
                            && let Err(e) = self.record_retry(step)
                        {
                            return self.abort_resync(proc, e.to_string());
                        }
                        self.pending_logs.push(format!(
                            "[RESYNC] Host received Request(step={}, slot={}) from {}",
                            step, slot, src
                        ));
                        self.state = CoordState::WaitingHostBarrier {
                            step,
                            slot,
                            armed_target: false,
                            started_at: Instant::now(),
                        };
                    }
                    CoordState::WaitingHostBarrier {
                        step: wait_step,
                        started_at,
                        ..
                    } if step > *wait_step => {
                        self.pending_logs.push(format!(
                            "[RESYNC] Host raising barrier step {} -> {} from Client Request (slot={})",
                            wait_step, step, slot
                        ));
                        self.state = CoordState::WaitingHostBarrier {
                            step,
                            slot,
                            armed_target: false,
                            started_at: *started_at,
                        };
                    }
                    CoordState::WaitingAck {
                        step: wait_step,
                        chunks,
                        ..
                    } => {
                        if step > *wait_step {
                            self.pending_logs.push(format!(
                                "[RESYNC] Host advancing from step={} to Client Request(step={}, slot={})",
                                wait_step, step, slot
                            ));
                            self.state = CoordState::WaitingHostBarrier {
                                step,
                                slot,
                                armed_target: false,
                                started_at: Instant::now(),
                            };
                        } else {
                            for c in chunks {
                                self.send_packet_bytes(c);
                            }
                        }
                    }
                    _ => {}
                },
                ResyncPacket::Chunk { step, .. } => {
                    if self.last_acked_step == Some(step) && matches!(self.state, CoordState::Idle)
                    {
                        self.send_packet_bytes(&ResyncPacket::Ack { step }.to_bytes());
                        continue;
                    }
                    if self.last_acked_step.is_some_and(|ack| step < ack) {
                        continue;
                    }
                    match &self.state {
                        CoordState::Idle => {
                            if read_sync_engine_step(proc).is_some_and(|c_step| step < c_step) {
                                continue;
                            }
                            if let Err(e) = self.record_retry(step) {
                                return self.abort_resync(proc, e.to_string());
                            }
                            let _ = proc.write_u32(hdr_va + TRACE_HDR_RESYNC_HOLD_OFF, 1);
                            self.state = CoordState::WaitingChunks {
                                step,
                                slot: 0,
                                started_at: Instant::now(),
                                last_req: Instant::now(),
                            };
                        }
                        CoordState::WaitingPeerDiscovery { step: cur_step, .. } => {
                            if step != *cur_step
                                && let Err(e) = self.record_retry(step)
                            {
                                return self.abort_resync(proc, e.to_string());
                            }
                            let _ = proc.write_u32(hdr_va + TRACE_HDR_RESYNC_HOLD_OFF, 1);
                            self.state = CoordState::WaitingChunks {
                                step,
                                slot: 0,
                                started_at: Instant::now(),
                                last_req: Instant::now(),
                            };
                        }
                        CoordState::WaitingClientPark { trapped_step, .. } => {
                            if *trapped_step >= 0 && step < *trapped_step {
                                continue;
                            }
                        }
                        CoordState::WaitingChunks { step: req_step, .. } => {
                            if *req_step >= 0 && step < *req_step {
                                continue;
                            }
                        }
                        CoordState::WaitingHostBarrier { .. }
                        | CoordState::WaitingAck { .. }
                        | CoordState::ApplyingSnapshot { .. } => {
                            continue;
                        }
                    }
                    let (slot_cur, started_cur) = match &self.state {
                        CoordState::WaitingChunks {
                            slot, started_at, ..
                        }
                        | CoordState::WaitingClientPark {
                            slot, started_at, ..
                        } => (*slot, *started_at),
                        _ => (0, Instant::now()),
                    };
                    match self.assembler.push(pkt) {
                        Ok(Some(snap)) => {
                            self.state = CoordState::ApplyingSnapshot {
                                snap: Box::new(snap),
                                slot: slot_cur,
                                started_at: started_cur,
                            };
                        }
                        Ok(None) => {}
                        Err(e) => {
                            self.pending_logs.push(format!(
                                "[RESYNC] Client chunk reassembly error (step={}): {:#}",
                                step, e
                            ));
                            if matches!(self.state, CoordState::WaitingChunks { .. }) {
                                let req = ResyncPacket::Request {
                                    step,
                                    slot: slot_cur,
                                }
                                .to_bytes();
                                self.send_packet_bytes(&req);
                            }
                        }
                    }
                }
                ResyncPacket::Ack { step } => {
                    if let CoordState::WaitingAck {
                        step: wait_step,
                        slot,
                        total_pawns,
                        mti,
                        ..
                    } = &self.state
                        && *wait_step == step
                    {
                        let slot = *slot;
                        let total_pawns = *total_pawns;
                        let mti = *mti;
                        let grace_until =
                            (step >= 0).then(|| step.saturating_add(RESYNC_GRACE_STEPS));
                        self.finish_success(proc, grace_until);
                        return ResyncPollOutcome::Synced(format!(
                            "[RESYNC] Step {} (slot={}): synced {} pawns (Host -> Client), MT19937 mti={}",
                            step, slot, total_pawns, mti
                        ));
                    }
                }
            }
        }

        // Check local mismatch trap when idle.
        if matches!(self.state, CoordState::Idle)
            && proc.read_u32(hdr_va + TRACE_HDR_RESYNC_NEEDED_OFF).unwrap_or(0) != 0
        {
            let step = proc
                .read_i32(hdr_va + TRACE_HDR_RESYNC_STEP_OFF)
                .unwrap_or(-1);
            let slot = proc
                .read_u32(hdr_va + TRACE_HDR_RESYNC_SLOT_OFF)
                .unwrap_or(0);
            if let Err(e) = self.record_retry(step) {
                return self.abort_resync(proc, e.to_string());
            }
            let _ = proc.write_u32(hdr_va + TRACE_HDR_RESYNC_HOLD_OFF, 1);
            match self.resolved_is_host(proc) {
                Some(true) => {
                    self.pending_logs.push(format!(
                        "[RESYNC] Host trapped mismatch at step={}, slot={} (targets={:?})",
                        step,
                        slot,
                        self.peer_targets()
                    ));
                    self.state = CoordState::WaitingHostBarrier {
                        step,
                        slot,
                        armed_target: false,
                        started_at: Instant::now(),
                    };
                }
                Some(false) => {
                    self.pending_logs.push(format!(
                        "[RESYNC] Client trapped mismatch at step={}, slot={} -> parking at tick barrier (targets={:?})",
                        step,
                        slot,
                        self.peer_targets()
                    ));
                    self.state = CoordState::WaitingClientPark {
                        trapped_step: step,
                        slot,
                        started_at: Instant::now(),
                    };
                }
                None => {
                    self.pending_logs.push(format!(
                        "[RESYNC] Trapped mismatch at step={}, slot={} (awaiting LAN peer role discovery)",
                        step, slot
                    ));
                    self.state = CoordState::WaitingPeerDiscovery {
                        step,
                        slot,
                        started_at: Instant::now(),
                    };
                }
            }
        }

        // Advance active state.
        let parked = proc.read_u32(hdr_va + TRACE_HDR_RESYNC_PARKED_OFF).unwrap_or(0) != 0;
        let state = std::mem::replace(&mut self.state, CoordState::Idle);
        match state {
            CoordState::Idle => ResyncPollOutcome::None,
            CoordState::WaitingPeerDiscovery {
                step,
                slot,
                started_at,
            } => {
                if started_at.elapsed() > Duration::from_millis(BARRIER_TIMEOUT_MS) {
                    return self.abort_resync(proc, "Timed out identifying LAN resync peer role".into());
                }
                match self.resolved_is_host(proc) {
                    Some(true) => {
                        self.state = CoordState::WaitingHostBarrier {
                            step,
                            slot,
                            armed_target: false,
                            started_at,
                        };
                    }
                    Some(false) => {
                        self.pending_logs.push(format!(
                            "[RESYNC] Client discovered Host {:?} -> parking at tick barrier (trapped_step={}, slot={})",
                            self.peer_targets(),
                            step,
                            slot
                        ));
                        self.state = CoordState::WaitingClientPark {
                            trapped_step: step,
                            slot,
                            started_at,
                        };
                    }
                    None => {
                        self.state = CoordState::WaitingPeerDiscovery {
                            step,
                            slot,
                            started_at,
                        };
                    }
                }
                ResyncPollOutcome::None
            }
            CoordState::WaitingClientPark {
                trapped_step,
                slot,
                started_at,
            } => {
                if started_at.elapsed() > Duration::from_millis(BARRIER_TIMEOUT_MS) {
                    return self.abort_resync(
                        proc,
                        format!(
                            "Client timed out waiting for tick barrier (trapped_step={}, slot={})",
                            trapped_step, slot
                        ),
                    );
                }
                let hold = proc
                    .read_u32(hdr_va + TRACE_HDR_RESYNC_HOLD_OFF)
                    .unwrap_or(0);
                let c_step = if parked && hold != 0 {
                    read_sync_engine_step(proc)
                } else {
                    None
                };
                let Some(c_step) = c_step else {
                    self.state = CoordState::WaitingClientPark {
                        trapped_step,
                        slot,
                        started_at,
                    };
                    return ResyncPollOutcome::None;
                };
                self.pending_logs.push(format!(
                    "[RESYNC] Client parked at step={} (trapped_step={}, slot={}) -> requesting snapshot from {:?}",
                    c_step,
                    trapped_step,
                    slot,
                    self.peer_targets()
                ));
                if matches!(self.assembler.step, Some(s) if s < c_step) {
                    self.assembler.reset();
                }
                self.send_packet_bytes(&ResyncPacket::Request { step: c_step, slot }.to_bytes());
                self.state = CoordState::WaitingChunks {
                    step: c_step,
                    slot,
                    started_at: Instant::now(),
                    last_req: Instant::now(),
                };
                ResyncPollOutcome::None
            }
            CoordState::WaitingHostBarrier {
                step,
                slot,
                mut armed_target,
                started_at,
            } => {
                if started_at.elapsed() > Duration::from_millis(BARRIER_TIMEOUT_MS) {
                    return self.abort_resync(
                        proc,
                        format!(
                            "Host timed out before sending snapshot (step={}, slot={}, parked={})",
                            step, slot, parked
                        ),
                    );
                }

                let hold = proc
                    .read_u32(hdr_va + TRACE_HDR_RESYNC_HOLD_OFF)
                    .unwrap_or(0);
                if !parked || hold == 0 {
                    if !armed_target {
                        let _ =
                            proc.write_u32(hdr_va + TRACE_HDR_RESYNC_TARGET_STEP_OFF, 0xFFFF_FFFF);
                        let _ =
                            proc.write_u32(hdr_va + TRACE_HDR_RESYNC_TARGET_SLOT_OFF, 0xFFFF_FFFF);
                        let cur_step = read_sync_engine_step(proc);
                        if step >= 0 && cur_step.is_some_and(|s| s < step) {
                            let _ = proc.write_u32(
                                hdr_va + TRACE_HDR_RESYNC_TARGET_TICK_STEP_OFF,
                                step as u32,
                            );
                        } else {
                            let _ = proc.write_u32(hdr_va + TRACE_HDR_RESYNC_HOLD_OFF, 1);
                        }
                        armed_target = true;
                    }
                    self.state = CoordState::WaitingHostBarrier {
                        step,
                        slot,
                        armed_target,
                        started_at,
                    };
                    return ResyncPollOutcome::None;
                }

                let Some(host_step) = read_sync_engine_step(proc) else {
                    self.state = CoordState::WaitingHostBarrier {
                        step,
                        slot,
                        armed_target,
                        started_at,
                    };
                    return ResyncPollOutcome::None;
                };
                if step >= 0 && host_step < step {
                    // Parked before target step: set TARGET_TICK_STEP before clearing HOLD.
                    let _ =
                        proc.write_u32(hdr_va + TRACE_HDR_RESYNC_TARGET_TICK_STEP_OFF, step as u32);
                    let _ = proc.write_u32(hdr_va + TRACE_HDR_RESYNC_HOLD_OFF, 0);
                    self.state = CoordState::WaitingHostBarrier {
                        step,
                        slot,
                        armed_target: true,
                        started_at,
                    };
                    return ResyncPollOutcome::None;
                }
                if self.peer_targets().is_empty() {
                    self.state = CoordState::WaitingHostBarrier {
                        step,
                        slot,
                        armed_target,
                        started_at,
                    };
                    return ResyncPollOutcome::None;
                }
                let _ =
                    proc.write_u32(hdr_va + TRACE_HDR_RESYNC_TARGET_TICK_STEP_OFF, 0xFFFF_FFFF);
                let _ = proc.write_u32(hdr_va + TRACE_HDR_RESYNC_TARGET_STEP_OFF, 0xFFFF_FFFF);
                let _ = proc.write_u32(hdr_va + TRACE_HDR_RESYNC_TARGET_SLOT_OFF, 0xFFFF_FFFF);
                let snap = match extract_host_snapshot(proc) {
                    Ok(s) => s,
                    Err(e) => {
                        return self.abort_resync(proc, format!("Host snapshot extract failed: {:#}", e));
                    }
                };
                let mti = snap.mti();
                let total_pawns = snap.pawns.len();
                let chunks = encode_snapshot_chunks(&snap);
                self.pending_logs.push(format!(
                    "[RESYNC] Host sending {} chunks ({} pawns, mti={}) for step={} to {:?}",
                    chunks.len(),
                    total_pawns,
                    mti,
                    snap.step,
                    self.peer_targets()
                ));
                for c in &chunks {
                    self.send_packet_bytes(c);
                }
                self.state = CoordState::WaitingAck {
                    step: snap.step,
                    slot,
                    total_pawns,
                    mti,
                    chunks,
                    started_at: Instant::now(),
                    last_send: Instant::now(),
                };
                ResyncPollOutcome::None
            }
            CoordState::WaitingAck {
                step,
                slot,
                total_pawns,
                mti,
                chunks,
                started_at,
                last_send,
            } => {
                if started_at.elapsed() > Duration::from_millis(BARRIER_TIMEOUT_MS) {
                    return self.abort_resync(
                        proc,
                        format!(
                            "Timed out waiting for Client RESYNC_ACK (step={}, sent {} chunks to {:?})",
                            step,
                            chunks.len(),
                            self.peer_targets()
                        ),
                    );
                }
                let next_last_send = if last_send.elapsed() >= Duration::from_millis(RETRY_SEND_INTERVAL_MS)
                {
                    for c in &chunks {
                        self.send_packet_bytes(c);
                    }
                    Instant::now()
                } else {
                    last_send
                };
                self.state = CoordState::WaitingAck {
                    step,
                    slot,
                    total_pawns,
                    mti,
                    chunks,
                    started_at,
                    last_send: next_last_send,
                };
                ResyncPollOutcome::None
            }
            CoordState::WaitingChunks {
                step,
                slot,
                started_at,
                last_req,
            } => {
                if started_at.elapsed() > Duration::from_millis(BARRIER_TIMEOUT_MS) {
                    let (rx, exp) = self.assembler.progress();
                    return self.abort_resync(
                        proc,
                        format!(
                            "Timed out waiting for Host snapshot chunks (step={}, received {}/{} chunks, targets={:?})",
                            step,
                            rx,
                            exp,
                            self.peer_targets()
                        ),
                    );
                }
                let next_last_req = if last_req.elapsed() >= Duration::from_millis(RETRY_SEND_INTERVAL_MS)
                {
                    self.send_packet_bytes(&ResyncPacket::Request { step, slot }.to_bytes());
                    Instant::now()
                } else {
                    last_req
                };
                self.state = CoordState::WaitingChunks {
                    step,
                    slot,
                    started_at,
                    last_req: next_last_req,
                };
                ResyncPollOutcome::None
            }
            CoordState::ApplyingSnapshot {
                snap,
                slot,
                started_at,
            } => {
                if started_at.elapsed() > Duration::from_millis(BARRIER_TIMEOUT_MS) {
                    return self.abort_resync(
                        proc,
                        format!(
                            "Client timed out waiting for tick barrier (snap.step={}, slot={}, parked={})",
                            snap.step, slot, parked
                        ),
                    );
                }
                let hold = proc
                    .read_u32(hdr_va + TRACE_HDR_RESYNC_HOLD_OFF)
                    .unwrap_or(0);
                if !parked || hold == 0 {
                    self.state = CoordState::ApplyingSnapshot {
                        snap,
                        slot,
                        started_at,
                    };
                    return ResyncPollOutcome::None;
                }
                let Some(c_step) = read_sync_engine_step(proc) else {
                    self.state = CoordState::ApplyingSnapshot {
                        snap,
                        slot,
                        started_at,
                    };
                    return ResyncPollOutcome::None;
                };
                if snap.step >= 0 && c_step < snap.step {
                    self.pending_logs.push(format!(
                        "[RESYNC] Client advancing parked barrier step={} -> snapshot step={}",
                        c_step, snap.step
                    ));
                    let _ = proc.write_u32(
                        hdr_va + TRACE_HDR_RESYNC_TARGET_TICK_STEP_OFF,
                        snap.step as u32,
                    );
                    let _ = proc.write_u32(hdr_va + TRACE_HDR_RESYNC_HOLD_OFF, 0);
                    self.state = CoordState::ApplyingSnapshot {
                        snap,
                        slot,
                        started_at,
                    };
                    return ResyncPollOutcome::None;
                }
                if snap.step >= 0 && c_step > snap.step {
                    self.pending_logs.push(format!(
                        "[RESYNC] Client parked at step={} > snapshot step={} -> re-requesting Host snapshot",
                        c_step, snap.step
                    ));
                    let _ =
                        proc.write_u32(hdr_va + TRACE_HDR_RESYNC_TARGET_TICK_STEP_OFF, 0xFFFF_FFFF);
                    let _ = proc.write_u32(hdr_va + TRACE_HDR_RESYNC_HOLD_OFF, 1);
                    self.assembler.reset();
                    self.send_packet_bytes(
                        &ResyncPacket::Request { step: c_step, slot }.to_bytes(),
                    );
                    self.state = CoordState::WaitingChunks {
                        step: c_step,
                        slot,
                        started_at: Instant::now(),
                        last_req: Instant::now(),
                    };
                    return ResyncPollOutcome::None;
                }
                match apply_client_snapshot(proc, &snap) {
                    Ok(updated_pawns) => {
                        let ack = ResyncPacket::Ack { step: snap.step }.to_bytes();
                        self.send_packet_bytes(&ack);
                        self.last_acked_step = Some(snap.step);
                        let grace_until = (snap.step >= 0)
                            .then(|| snap.step.saturating_add(RESYNC_GRACE_STEPS));
                        self.finish_success(proc, grace_until);
                        let mti = snap.mti();
                        let total_pawns = snap.pawns.len();
                        ResyncPollOutcome::Synced(format!(
                            "[RESYNC] Step {} (slot={}): synced {}/{} pawns, MT19937 mti={}",
                            snap.step, slot, updated_pawns, total_pawns, mti
                        ))
                    }
                    Err(e) => self.abort_resync(proc, format!("Client apply rejected: {:#}", e)),
                }
            }
        }
    }

    fn finish_success(&mut self, proc: &GameProcess, grace_until_step: Option<i32>) {
        let trace_va = proc.trace_buf_va();
        if trace_va != 0 {
            let hdr_va = trace_va + TRACE_HDR_OFF;
            let count = proc
                .read_u32(hdr_va + TRACE_HDR_RESYNC_COUNT_OFF)
                .unwrap_or(0);
            let _ = proc.write_u32(hdr_va + TRACE_HDR_RESYNC_COUNT_OFF, count.wrapping_add(1));
            let _ = proc.write_u32(hdr_va + TRACE_HDR_RESYNC_TARGET_STEP_OFF, 0xFFFF_FFFF);
            let _ = proc.write_u32(hdr_va + TRACE_HDR_RESYNC_TARGET_SLOT_OFF, 0xFFFF_FFFF);
            let _ = proc.write_u32(hdr_va + TRACE_HDR_RESYNC_TARGET_TICK_STEP_OFF, 0xFFFF_FFFF);
            if let Some(until_step) = grace_until_step {
                let _ = proc.write_u32(
                    hdr_va + TRACE_HDR_RESYNC_GRACE_UNTIL_STEP_OFF,
                    until_step as u32,
                );
            }
            let _ = proc.write_u32(hdr_va + TRACE_HDR_RESYNC_NEEDED_OFF, 0);
            let _ = proc.write_u32(hdr_va + TRACE_HDR_RESYNC_HOLD_OFF, 0);
        }
        self.assembler.reset();
        self.state = CoordState::Idle;
    }

    fn abort_resync(&mut self, proc: &GameProcess, reason: String) -> ResyncPollOutcome {
        let trace_va = proc.trace_buf_va();
        if trace_va != 0 {
            let hdr_va = trace_va + TRACE_HDR_OFF;
            let _ = proc.write_u32(hdr_va + TRACE_HDR_RESYNC_ENABLED_OFF, 0);
            let _ = proc.write_u32(hdr_va + TRACE_HDR_RESYNC_TARGET_STEP_OFF, 0xFFFF_FFFF);
            let _ = proc.write_u32(hdr_va + TRACE_HDR_RESYNC_TARGET_SLOT_OFF, 0xFFFF_FFFF);
            let _ = proc.write_u32(hdr_va + TRACE_HDR_RESYNC_TARGET_TICK_STEP_OFF, 0xFFFF_FFFF);
            let _ = proc.write_u32(hdr_va + TRACE_HDR_RESYNC_GRACE_UNTIL_STEP_OFF, 0xFFFF_FFFF);
            let _ = proc.write_u32(hdr_va + TRACE_HDR_RESYNC_NEEDED_OFF, 0);
            let _ = proc.write_u32(hdr_va + TRACE_HDR_RESYNC_HOLD_OFF, 0);
        }
        let _ = proc.write_memory(crate::net::CAVE_DESYNC_FLAG_VA as usize, &[1]);
        self.assembler.reset();
        self.state = CoordState::Idle;
        ResyncPollOutcome::Failed(reason)
    }
}

/// Polls the `ResyncCoordinator` attached to `proc`, appending any log lines to `out_logs`.
/// Returns `true` if Stage 1 resync aborted cleanly and normal desync dumping should trigger.
pub fn poll_resync(proc: &mut GameProcess, out_logs: &mut Vec<String>) -> bool {
    let Some(mut coord) = proc.resync_coord.take() else {
        return false;
    };
    let outcome = coord.poll(proc);
    out_logs.append(&mut coord.pending_logs);
    proc.resync_coord = Some(coord);
    match outcome {
        ResyncPollOutcome::None => false,
        ResyncPollOutcome::Synced(summary_line) => {
            out_logs.push(summary_line);
            false
        }
        ResyncPollOutcome::Failed(reason) => {
            proc.last_resync_error = Some(reason.clone());
            out_logs.push(format!("[RESYNC] Stage 1 aborted: {}", reason));
            true
        }
    }
}

fn bind_resync_socket(bind_ip: Ipv4Addr) -> Result<UdpSocket> {
    let mut last_err = None;
    for port in [RESYNC_UDP_PORT_A, RESYNC_UDP_PORT_B, 0] {
        match UdpSocket::bind(SocketAddrV4::new(bind_ip, port)) {
            Ok(sock) => {
                sock.set_nonblocking(true)
                    .context("Setting resync UDP socket non-blocking")?;
                return Ok(sock);
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap().into())
}

fn read_level_actor_ptrs(proc: &GameProcess, level_ptr: u32) -> Result<Vec<u32>> {
    let actors_data_ptr = proc.read_u32(level_ptr as usize + 0x28).unwrap_or(0);
    let raw_count = proc.read_i32(level_ptr as usize + 0x2C).unwrap_or(0);
    if actors_data_ptr == 0 || raw_count <= 0 {
        return Ok(Vec::new());
    }
    let count = raw_count.clamp(0, 16384) as usize;
    let mut raw = vec![0u8; count * 4];
    if proc.read_memory(actors_data_ptr as usize, &mut raw) {
        Ok(raw
            .as_chunks::<4>()
            .0
            .iter()
            .copied()
            .map(u32::from_le_bytes)
            .collect())
    } else {
        Ok((0..count)
            .map(|i| {
                proc.read_u32(actors_data_ptr as usize + i * 4)
                    .unwrap_or(0)
            })
            .collect())
    }
}

struct FNameCache {
    gnames_ptr: u32,
    gnames_count: u32,
    names: HashMap<u32, String>,
}

impl FNameCache {
    fn new(proc: &GameProcess) -> Self {
        Self {
            gnames_ptr: proc.read_u32(VA_GNAMES).unwrap_or(0),
            gnames_count: proc.read_u32(VA_GNAMES_COUNT).unwrap_or(0),
            names: HashMap::new(),
        }
    }

    fn resolve(&mut self, proc: &GameProcess, idx: u32) -> &str {
        self.names
            .entry(idx)
            .or_insert_with(|| proc.resolve_fname(self.gnames_ptr, self.gnames_count, idx))
            .as_str()
    }

    fn actor_identity(&mut self, proc: &GameProcess, actor_ptr: u32) -> (String, String, u32, u32) {
        let name_idx = proc.read_u32(actor_ptr as usize + 0x20).unwrap_or(0);
        let class_ptr = proc.read_u32(actor_ptr as usize + 0x24).unwrap_or(0);
        let class_name_idx = if class_ptr != 0 {
            proc.read_u32(class_ptr as usize + 0x20).unwrap_or(0)
        } else {
            0
        };
        let actor_name = self.resolve(proc, name_idx).to_string();
        let class_name = if class_ptr != 0 {
            self.resolve(proc, class_name_idx).to_string()
        } else {
            "None".to_string()
        };
        let name_hash = fnv1a_32(&actor_name);
        let class_hash = fnv1a_32(&class_name);
        (actor_name, class_name, name_hash, class_hash)
    }
}

fn fnv1a_32(s: &str) -> u32 {
    let mut h: u32 = 0x811C_9DC5;
    for b in s.as_bytes() {
        h ^= *b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

fn read_sync_engine_step(proc: &GameProcess) -> Option<i32> {
    let sync_engine = proc.read_u32(VA_SYNC_ENGINE as usize).unwrap_or(0);
    if sync_engine == 0 {
        return None;
    }
    proc.read_i32(sync_engine as usize + 0x5C)
}

fn read_proc_u64(proc: &GameProcess, addr: usize) -> Option<u64> {
    let mut buf = [0u8; 8];
    if !proc.read_memory(addr, &mut buf) {
        return None;
    }
    Some(u64::from_le_bytes(buf))
}

fn write_proc_u64(proc: &GameProcess, addr: usize, v: u64) -> bool {
    proc.write_memory(addr, &v.to_le_bytes())
}

fn read_proc_u32_array<const N: usize>(proc: &GameProcess, addr: usize) -> Option<[u32; N]> {
    let mut buf = vec![0u8; N * 4];
    if !proc.read_memory(addr, &mut buf) {
        return None;
    }
    Some(read_u32_array(&buf, 0))
}

fn read_proc_u32_offs<const N: usize>(
    proc: &GameProcess,
    base: usize,
    offs: [usize; N],
) -> Option<[u32; N]> {
    let mut out = [0u32; N];
    for (dst, off) in out.iter_mut().zip(offs) {
        *dst = proc.read_u32(base + off)?;
    }
    Some(out)
}

fn write_proc_u32_array(proc: &GameProcess, addr: usize, vals: &[u32]) -> bool {
    let mut buf = Vec::with_capacity(vals.len() * 4);
    write_u32_slice(&mut buf, vals);
    proc.write_memory(addr, &buf)
}

fn write_proc_u32_offs(proc: &GameProcess, base: usize, offs: &[usize], vals: &[u32]) {
    for (&off, &val) in offs.iter().zip(vals.iter()) {
        let _ = proc.write_u32(base + off, val);
    }
}

fn read_proc_f32_3(proc: &GameProcess, addr: usize) -> Option<[f32; 3]> {
    let mut buf = [0u8; 12];
    if !proc.read_memory(addr, &mut buf) {
        return None;
    }
    Some(read_f32_3(&buf, 0))
}

fn read_proc_i32_3(proc: &GameProcess, addr: usize) -> Option<[i32; 3]> {
    let mut buf = [0u8; 12];
    if !proc.read_memory(addr, &mut buf) {
        return None;
    }
    Some(read_i32_3(&buf, 0))
}

fn write_proc_f32_3(proc: &GameProcess, addr: usize, v: [f32; 3]) -> bool {
    let mut buf = Vec::with_capacity(12);
    write_f32_3(&mut buf, v);
    proc.write_memory(addr, &buf)
}

fn write_proc_i32_3(proc: &GameProcess, addr: usize, v: [i32; 3]) -> bool {
    let mut buf = Vec::with_capacity(12);
    write_i32_3(&mut buf, v);
    proc.write_memory(addr, &buf)
}

fn le_u32(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap())
}

fn le_u64(bytes: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap())
}

fn write_u32_slice(out: &mut Vec<u8>, vals: &[u32]) {
    for &v in vals {
        out.extend_from_slice(&v.to_le_bytes());
    }
}

fn read_u32_array<const N: usize>(bytes: &[u8], off: usize) -> [u32; N] {
    std::array::from_fn(|i| le_u32(bytes, off + i * 4))
}

fn write_f32_3(out: &mut Vec<u8>, v: [f32; 3]) {
    for f in v {
        out.extend_from_slice(&f.to_le_bytes());
    }
}

fn write_i32_3(out: &mut Vec<u8>, v: [i32; 3]) {
    for n in v {
        out.extend_from_slice(&n.to_le_bytes());
    }
}

fn read_f32_3(bytes: &[u8], off: usize) -> [f32; 3] {
    [
        f32::from_bits(le_u32(bytes, off)),
        f32::from_bits(le_u32(bytes, off + 4)),
        f32::from_bits(le_u32(bytes, off + 8)),
    ]
}

fn read_i32_3(bytes: &[u8], off: usize) -> [i32; 3] {
    [
        le_u32(bytes, off) as i32,
        le_u32(bytes, off + 4) as i32,
        le_u32(bytes, off + 8) as i32,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_snapshot() -> ResyncSnapshot {
        let mut rng_bytes = [0u8; SYNC_ENGINE_RNG_LEN];
        for (i, b) in rng_bytes.iter_mut().enumerate() {
            *b = ((i * 31 + 7) & 0xFF) as u8;
        }
        rng_bytes[0x9C0..0x9C4].copy_from_slice(&123u32.to_le_bytes());

        let pawns = (0..18u16)
            .map(|idx| ResyncPawnState {
                actor_index: idx * 3 + 5,
                is_player_pawn: u8::from(idx == 0),
                zone_number: 2,
                name_hash: fnv1a_32(&format!("ENorthKoreanSoldier{}", idx)),
                class_hash: fnv1a_32(if idx == 0 { "ESam" } else { "ENorthKoreanSoldier" }),
                flags_28: 0x0010_0001,
                flags_2c: if idx == 0 { 0x8000_0030 } else { 0x8200_0050 },
                location: [100.5 + idx as f32, -250.25, 42.0],
                rotation: [0, 16384 * idx as i32, -512],
                velocity: [1.5, -2.5, 0.0],
                acceleration: [0.0, 0.0, -9.8],
                has_controller: 1,
                ctrl_location: [100.5 + idx as f32, -250.25, 42.0],
                ctrl_rotation: [128, 16384 * idx as i32, 0],
                pawn_rng_timers: [0x4120_0000, 0x4130_0000, 0x3E80_0000, idx as u32],
                pawn_tick_flags: [0x0C00_0001, 0x0000_0002],
            })
            .collect();

        ResyncSnapshot {
            step: 421,
            user_checksum_0: 0xDEAD_BEEF,
            user_checksum_1: 0xCAFE_BABE,
            sim_station_cumulative: 0x1122_3344,
            sim_station_slots_1_4: [0x1111, 0x2222, 0x3333, 0x4444],
            sync_engine_clock: [0x1234_5678, 0x9ABC_DEF0],
            sync_engine_window_steps: [418, 419, 420, 421, 422],
            sync_engine_sent_step: 423,
            level_time_f64_bits: 123.456f64.to_bits(),
            level_info_time_bits: 123.456f32.to_bits(),
            sim_station_slot5_block: [0x5Au8; SIM_STATION_SLOT_BLOCK_LEN],
            sim_station_slot0_block: [0xA5u8; SIM_STATION_SLOT_BLOCK_LEN],
            rng_bytes,
            pawns,
        }
    }

    #[test]
    fn test_snapshot_roundtrip_and_chunk_reassembly() {
        assert_eq!(RESYNC_PAWN_WIRE_SIZE, 120);
        let snap = sample_snapshot();
        assert_eq!(snap.mti(), 123);

        let raw = snap.to_bytes();
        let expected_len = SNAPSHOT_FIXED_HDR_LEN + snap.pawns.len() * RESYNC_PAWN_WIRE_SIZE;
        assert_eq!(raw.len(), expected_len);
        assert_eq!(ResyncSnapshot::from_bytes(&raw).unwrap(), snap);

        let chunks = encode_snapshot_chunks(&snap);
        assert!(chunks.len() > 3);

        // Deliver chunks out of order plus one duplicate chunk.
        let mut asm = ChunkAssembler::default();
        for &idx in chunks.iter().rev().collect::<Vec<_>>().iter() {
            let pkt = ResyncPacket::from_bytes(idx).unwrap();
            if let Some(decoded) = asm.push(pkt).unwrap() {
                assert_eq!(decoded, snap);
                return;
            }
        }
        panic!("ChunkAssembler did not complete after receiving all chunks");
    }

    #[test]
    fn test_chunk_crc_mismatch_rejected() {
        let snap = sample_snapshot();
        let mut chunks = encode_snapshot_chunks(&snap);
        let mid = chunks.len() / 2;
        chunks[mid][24] ^= 0xFF;

        let mut asm = ChunkAssembler::default();
        let mut final_res = None;
        for bytes in chunks {
            let pkt = ResyncPacket::from_bytes(&bytes).unwrap();
            match asm.push(pkt) {
                Ok(Some(decoded)) => final_res = Some(Ok(decoded)),
                Ok(None) => {}
                Err(e) => final_res = Some(Err(e)),
            }
        }
        let err = final_res.unwrap().unwrap_err();
        assert!(err.to_string().contains("CRC32 mismatch"));
    }

    #[test]
    fn test_udp_loopback_request_chunks_ack() {
        let host_sock = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client_sock = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        host_sock.set_nonblocking(true).unwrap();
        client_sock.set_nonblocking(true).unwrap();
        let host_addr = host_sock.local_addr().unwrap();
        let client_addr = client_sock.local_addr().unwrap();

        let snap = sample_snapshot();
        let req_bytes = ResyncPacket::Request {
            step: snap.step,
            slot: 5,
        }
        .to_bytes();
        client_sock.send_to(&req_bytes, host_addr).unwrap();

        let mut buf = [0u8; 2048];
        let (n, src) = host_sock.recv_from(&mut buf).unwrap();
        assert_eq!(src, client_addr);
        assert_eq!(
            ResyncPacket::from_bytes(&buf[..n]).unwrap(),
            ResyncPacket::Request { step: 421, slot: 5 }
        );

        let chunks = encode_snapshot_chunks(&snap);
        for c in chunks {
            host_sock.send_to(&c, client_addr).unwrap();
        }

        let mut asm = ChunkAssembler::default();
        let mut decoded = None;
        while let Ok((len, _)) = client_sock.recv_from(&mut buf) {
            let pkt = ResyncPacket::from_bytes(&buf[..len]).unwrap();
            if let Some(s) = asm.push(pkt).unwrap() {
                decoded = Some(s);
                break;
            }
        }
        assert_eq!(decoded.unwrap(), snap);

        let ack_bytes = ResyncPacket::Ack { step: snap.step }.to_bytes();
        client_sock.send_to(&ack_bytes, host_addr).unwrap();
        let (n, _) = host_sock.recv_from(&mut buf).unwrap();
        assert_eq!(
            ResyncPacket::from_bytes(&buf[..n]).unwrap(),
            ResyncPacket::Ack { step: 421 }
        );
    }
}
