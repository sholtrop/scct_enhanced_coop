#[cfg(windows)]
use anyhow::bail;
use anyhow::Result;
#[cfg(not(windows))]
use anyhow::Context;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

pub const CAVE_DESYNC_FLAG_VA: usize = crate::net::CAVE_DESYNC_FLAG_VA as usize;
pub const CAVE_DESYNC_COUNT_VA: usize = crate::net::CAVE_DESYNC_COUNT_VA as usize;
pub const VA_GENGINE: usize = 0x111F5554;
pub const VA_SYNC_ENGINE: usize = 0x111F55A4;
pub const VA_USER_CHECKSUM_0: usize = 0x111F5F14;
pub const VA_WARMUP_FLAG: usize = 0x111F55E0;
pub const VA_GNAMES: usize = 0x1130DFC0;
pub const VA_GNAMES_COUNT: usize = 0x1130DFC4;

pub struct GameProcess {
    pub pid: u32,
    #[cfg(windows)]
    handle_val: usize,
    #[cfg(not(windows))]
    child: std::process::Child,
    trace_buf_va: usize,
    trace_flushed_seq: u32,
    trace_prev_u0: Option<u32>,
}

impl GameProcess {
    pub fn wait_for_exit(mut self) {
        #[cfg(windows)]
        {
            if self.handle_val != 0 {
                unsafe {
                    use windows_sys::Win32::System::Threading::{INFINITE, WaitForSingleObject};
                    WaitForSingleObject(
                        self.handle_val as windows_sys::Win32::Foundation::HANDLE,
                        INFINITE,
                    );
                    windows_sys::Win32::Foundation::CloseHandle(
                        self.handle_val as windows_sys::Win32::Foundation::HANDLE,
                    );
                }
                self.handle_val = 0;
            }
        }
        #[cfg(not(windows))]
        {
            let _ = self.child.wait();
        }
    }

    pub fn is_alive(&mut self) -> bool {
        #[cfg(windows)]
        {
            if self.handle_val == 0 {
                return false;
            }
            use windows_sys::Win32::Foundation::WAIT_TIMEOUT;
            use windows_sys::Win32::System::Threading::WaitForSingleObject;
            unsafe {
                WaitForSingleObject(self.handle_val as windows_sys::Win32::Foundation::HANDLE, 0)
                    == WAIT_TIMEOUT
            }
        }
        #[cfg(not(windows))]
        {
            match self.child.try_wait() {
                Ok(None) => true,
                _ => false,
            }
        }
    }

    pub fn read_memory(&self, addr: usize, out: &mut [u8]) -> bool {
        #[cfg(windows)]
        {
            if self.handle_val == 0 {
                return false;
            }
            use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
            let mut bytes_read: usize = 0;
            let res = unsafe {
                ReadProcessMemory(
                    self.handle_val as windows_sys::Win32::Foundation::HANDLE,
                    addr as *const _,
                    out.as_mut_ptr() as *mut _,
                    out.len(),
                    &mut bytes_read,
                )
            };
            res != 0 && bytes_read == out.len()
        }
        #[cfg(not(windows))]
        {
            use std::fs::File;
            use std::io::{Read, Seek, SeekFrom};
            let Ok(mut file) = File::open(format!("/proc/{}/mem", self.pid)) else {
                return false;
            };
            if file.seek(SeekFrom::Start(addr as u64)).is_err() {
                return false;
            }
            file.read_exact(out).is_ok()
        }
    }

    pub fn read_u8(&self, addr: usize) -> Option<u8> {
        let mut buf = [0u8; 1];
        if self.read_memory(addr, &mut buf) {
            Some(buf[0])
        } else {
            None
        }
    }

    pub fn read_u32(&self, addr: usize) -> Option<u32> {
        let mut buf = [0u8; 4];
        if self.read_memory(addr, &mut buf) {
            Some(u32::from_le_bytes(buf))
        } else {
            None
        }
    }

    pub fn read_i32(&self, addr: usize) -> Option<i32> {
        let mut buf = [0u8; 4];
        if self.read_memory(addr, &mut buf) {
            Some(i32::from_le_bytes(buf))
        } else {
            None
        }
    }

    pub fn read_f32(&self, addr: usize) -> Option<f32> {
        let mut buf = [0u8; 4];
        if self.read_memory(addr, &mut buf) {
            Some(f32::from_le_bytes(buf))
        } else {
            None
        }
    }

    pub fn read_u16(&self, addr: usize) -> Option<u16> {
        let mut buf = [0u8; 2];
        if self.read_memory(addr, &mut buf) {
            Some(u16::from_le_bytes(buf))
        } else {
            None
        }
    }

    #[allow(dead_code)]
    pub fn read_string(&self, addr: usize, max_len: usize) -> Option<String> {
        let mut buf = vec![0u8; max_len];
        if !self.read_memory(addr, &mut buf) {
            return None;
        }
        let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        Some(String::from_utf8_lossy(&buf[..len]).to_string())
    }

    /// Reads a null-terminated UTF-16LE string from target process memory.
    pub fn read_wstring(&self, addr: usize, max_chars: usize) -> Option<String> {
        if max_chars == 0 {
            return Some(String::new());
        }
        let mut buf = vec![0u8; max_chars * 2];
        if self.read_memory(addr, &mut buf) {
            let units: Vec<u16> = buf
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&u| u != 0)
                .collect();
            return Some(String::from_utf16_lossy(&units));
        }

        // Fallback near page boundaries: read 16-bit code units one at a time.
        let mut units = Vec::new();
        for i in 0..max_chars {
            let Some(ch) = self.read_u16(addr + i * 2) else {
                return if units.is_empty() {
                    None
                } else {
                    Some(String::from_utf16_lossy(&units))
                };
            };
            if ch == 0 {
                return Some(String::from_utf16_lossy(&units));
            }
            units.push(ch);
        }
        Some(String::from_utf16_lossy(&units))
    }

    /// Resolves a UE2 `FName` index via `GNames` (`FNameEntry::Name` UTF-16LE at `+0x0C`).
    pub fn resolve_fname(&self, gnames_ptr: u32, gnames_count: u32, name_idx: u32) -> String {
        if gnames_ptr != 0 && name_idx < gnames_count {
            let entry_ptr = self
                .read_u32(gnames_ptr as usize + (name_idx as usize) * 4)
                .unwrap_or(0);
            if entry_ptr != 0
                && let Some(name) = self.read_wstring(entry_ptr as usize + 0x0C, 64)
                && !name.is_empty()
            {
                return name;
            }
        }
        format!("Name_{}", name_idx)
    }

    fn read_actor_loc_rot(&self, ptr: u32) -> ((f32, f32, f32), (i32, i32, i32)) {
        if ptr == 0 {
            return ((0.0, 0.0, 0.0), (0, 0, 0));
        }
        let base = ptr as usize;
        let loc = (
            self.read_f32(base + 0xE8).unwrap_or(0.0),
            self.read_f32(base + 0xEC).unwrap_or(0.0),
            self.read_f32(base + 0xF0).unwrap_or(0.0),
        );
        let rot = (
            self.read_i32(base + 0xF4).unwrap_or(0),
            self.read_i32(base + 0xF8).unwrap_or(0),
            self.read_i32(base + 0xFC).unwrap_or(0),
        );
        (loc, rot)
    }

    pub fn is_desync_flagged(&self) -> bool {
        if self.read_u8(CAVE_DESYNC_FLAG_VA).unwrap_or(0) != 0 {
            return true;
        }
        let sync_engine_ptr = self.read_u32(VA_SYNC_ENGINE).unwrap_or(0);
        if sync_engine_ptr != 0 {
            let status = self.read_i32(sync_engine_ptr as usize + 0x68).unwrap_or(0);
            if status == 6 {
                return true;
            }
        }
        false
    }

    pub fn dump_desync_state(&self, game_root: &Path) -> Result<PathBuf> {
        let sys_dir = crate::patcher::find_child_ci(game_root, "System");
        let dump_path = sys_dir.join("scct_desync_dump.txt");

        let sync_engine_ptr = self.read_u32(VA_SYNC_ENGINE).unwrap_or(0);
        let step = if sync_engine_ptr != 0 {
            self.read_i32(sync_engine_ptr as usize + 0x5C).unwrap_or(-1)
        } else {
            -1
        };
        let status = if sync_engine_ptr != 0 {
            self.read_i32(sync_engine_ptr as usize + 0x68).unwrap_or(-1)
        } else {
            -1
        };
        let user_checksum = self.read_u32(VA_USER_CHECKSUM_0).unwrap_or(0);
        let warmup_flag = self.read_u32(VA_WARMUP_FLAG).unwrap_or(0);
        let mismatch_count = self.read_u32(CAVE_DESYNC_COUNT_VA).unwrap_or(0);

        let gnames_ptr = self.read_u32(VA_GNAMES).unwrap_or(0);
        let gnames_count = self.read_u32(VA_GNAMES_COUNT).unwrap_or(0);

        let gengine_ptr = self.read_u32(VA_GENGINE).unwrap_or(0);
        let glevel_direct = if gengine_ptr != 0 {
            self.read_u32(gengine_ptr as usize + 0x17C).unwrap_or(0)
        } else {
            0
        };
        let level_context = if gengine_ptr != 0 {
            self.read_u32(gengine_ptr as usize + 0x44).unwrap_or(0)
        } else {
            0
        };
        let viewport_ptr_ptr = if level_context != 0 {
            self.read_u32(level_context as usize + 0x2C).unwrap_or(0)
        } else {
            0
        };
        let viewport_ptr = if viewport_ptr_ptr != 0 {
            self.read_u32(viewport_ptr_ptr as usize).unwrap_or(0)
        } else {
            0
        };
        let view_actor = if viewport_ptr != 0 {
            self.read_u32(viewport_ptr as usize + 0x30).unwrap_or(0)
        } else {
            0
        };
        let viewport_actor_level = if view_actor != 0 {
            self.read_u32(view_actor as usize + 0x7C).unwrap_or(0)
        } else {
            0
        };
        let level_ptr = if glevel_direct != 0 {
            glevel_direct
        } else {
            viewport_actor_level
        };

        let mut pawn_lines = Vec::new();
        let mut actor_lines = Vec::new();
        let mut total_pawn_tick_delta: i32 = 0;

        if level_ptr != 0 {
            let actors_data_ptr = self.read_u32(level_ptr as usize + 0x28).unwrap_or(0);
            let raw_count = self.read_i32(level_ptr as usize + 0x2C).unwrap_or(0);
            let count = raw_count.clamp(0, 16384);

            for i in 0..count {
                let actor_ptr = if actors_data_ptr != 0 {
                    self.read_u32(actors_data_ptr as usize + (i as usize) * 4)
                        .unwrap_or(0)
                } else {
                    0
                };
                if actor_ptr == 0 {
                    continue;
                }

                let name_idx = self.read_u32(actor_ptr as usize + 0x20).unwrap_or(0);
                let actor_name = self.resolve_fname(gnames_ptr, gnames_count, name_idx);

                let class_ptr = self.read_u32(actor_ptr as usize + 0x24).unwrap_or(0);
                let class_name = if class_ptr != 0 {
                    let class_name_idx = self.read_u32(class_ptr as usize + 0x20).unwrap_or(0);
                    self.resolve_fname(gnames_ptr, gnames_count, class_name_idx)
                } else {
                    "None".to_string()
                };

                let flags_28 = self.read_u32(actor_ptr as usize + 0x28).unwrap_or(0);
                let flags_2c = self.read_u32(actor_ptr as usize + 0x2C).unwrap_or(0);
                let physics = self.read_u8(actor_ptr as usize + 0xB4).unwrap_or(0);

                let (loc, rot) = self.read_actor_loc_rot(actor_ptr);
                let vel_x = self.read_f32(actor_ptr as usize + 0x100).unwrap_or(0.0);
                let vel_y = self.read_f32(actor_ptr as usize + 0x104).unwrap_or(0.0);
                let vel_z = self.read_f32(actor_ptr as usize + 0x108).unwrap_or(0.0);

                if (flags_2c & 0x20) != 0 {
                    let ctrl_ptr = self.read_u32(actor_ptr as usize + 0x2B4).unwrap_or(0);
                    if (flags_28 & 0x04) == 0 && physics != 0 {
                        let pawn_loc_sum = (loc.2 as i32)
                            .wrapping_add(loc.1 as i32)
                            .wrapping_add(loc.0 as i32);
                        let pawn_rot_sum = rot.1.wrapping_add(rot.2).wrapping_add(rot.0);
                        let (ctrl_loc, ctrl_rot) = self.read_actor_loc_rot(ctrl_ptr);
                        let (ctrl_loc_sum, ctrl_rot_sum) = if ctrl_ptr != 0 {
                            (
                                (ctrl_loc.2 as i32)
                                    .wrapping_add(ctrl_loc.1 as i32)
                                    .wrapping_add(ctrl_loc.0 as i32),
                                ctrl_rot.1.wrapping_add(ctrl_rot.2).wrapping_add(ctrl_rot.0),
                            )
                        } else {
                            (0, 0)
                        };
                        let tick_delta = pawn_loc_sum
                            .wrapping_add(pawn_rot_sum)
                            .wrapping_add(ctrl_loc_sum)
                            .wrapping_add(ctrl_rot_sum);
                        total_pawn_tick_delta = total_pawn_tick_delta.wrapping_add(tick_delta);

                        let pawn_loc_str = format!("({:.2}, {:.2}, {:.2})", loc.0, loc.1, loc.2);
                        let pawn_rot_str = format!("({}, {}, {})", rot.0, rot.1, rot.2);
                        let ctrl_loc_str = if ctrl_ptr != 0 {
                            format!("({:.2}, {:.2}, {:.2})", ctrl_loc.0, ctrl_loc.1, ctrl_loc.2)
                        } else {
                            "NULL".to_string()
                        };
                        let ctrl_rot_str = if ctrl_ptr != 0 {
                            format!("({}, {}, {})", ctrl_rot.0, ctrl_rot.1, ctrl_rot.2)
                        } else {
                            "NULL".to_string()
                        };
                        pawn_lines.push(format!(
                            "[{:<4}] {:<24} {:<24} 0x{:08X} phys={:<3} {:<30} {:<24} 0x{:08X} {:<30} {:<24} {:>11} (0x{:08X})",
                            i,
                            actor_name,
                            class_name,
                            actor_ptr,
                            physics,
                            pawn_loc_str,
                            pawn_rot_str,
                            ctrl_ptr,
                            ctrl_loc_str,
                            ctrl_rot_str,
                            tick_delta,
                            tick_delta as u32
                        ));
                    }
                }

                let loc_str = format!("({:.2}, {:.2}, {:.2})", loc.0, loc.1, loc.2);
                let rot_str = format!("({}, {}, {})", rot.0, rot.1, rot.2);
                let vel_str = format!("({:.2}, {:.2}, {:.2})", vel_x, vel_y, vel_z);

                actor_lines.push(format!(
                    "[{:<4}] {:<24} {:<24} 0x{:08X} {:<30} {:<24} {:<30} 0x{:08X} 0x{:08X} {:<7}",
                    i, actor_name, class_name, actor_ptr, loc_str, rot_str, vel_str, flags_28, flags_2c, physics
                ));
            }
        } else {
            actor_lines.push("  [WARNING] GLevel was null or could not be read".to_string());
        }

        let mut lines = Vec::new();
        lines.push("================================================================================".to_string());
        lines.push("            SCCT CO-OP ENHANCER - DESYNC DIAGNOSTIC STATE DUMP                 ".to_string());
        lines.push("================================================================================".to_string());
        lines.push(format!("SyncEngine VA:          0x{:08X}", sync_engine_ptr));
        lines.push(format!("Simulation Step:        {}", step));
        lines.push(format!("Simulation Status:      {} (0x{:08X}) [MismatchCount: {}]", status, status, mismatch_count));
        lines.push(format!(
            "UserChecksum0:          0x{:08X} (ActivePawnTickDeltaSum: {} / 0x{:08X})",
            user_checksum, total_pawn_tick_delta, total_pawn_tick_delta as u32
        ));
        lines.push(format!("WarmupFlag (0x111F55E0): {}", warmup_flag));
        if gengine_ptr != 0 {
            let eng_a8 = self.read_u32(gengine_ptr as usize + 0xA8).unwrap_or(0);
            let eng_a4 = self.read_u32(gengine_ptr as usize + 0xA4).unwrap_or(0);
            let eng_b8 = self.read_u32(gengine_ptr as usize + 0xB8).unwrap_or(0);
            lines.push(format!(
                "GEngine VA:             0x{:08X} (+A8=0x{:08X}, +A4=0x{:08X}, +B8=0x{:08X})",
                gengine_ptr, eng_a8, eng_a4, eng_b8
            ));
        } else {
            lines.push(format!("GEngine VA:             0x{:08X}", gengine_ptr));
        }
        lines.push(format!("Viewport VA:            0x{:08X}", viewport_ptr));
        lines.push(format!(
            "GLevel VA:              0x{:08X} (direct=+0x17C: 0x{:08X}, fallback: 0x{:08X})",
            level_ptr, glevel_direct, viewport_actor_level
        ));
        if level_ptr != 0 {
            let ticked = self.read_u32(level_ptr as usize + 0x3A20).unwrap_or(0);
            let arr = self.read_u32(level_ptr as usize + 0x28).unwrap_or(0);
            let cnt = self.read_i32(level_ptr as usize + 0x2C).unwrap_or(0);
            if cnt > 0 && arr != 0 {
                let li = self.read_u32(arr as usize).unwrap_or(0);
                if li != 0 {
                    let pauser = self.read_u32(li as usize + 0x48C).unwrap_or(0);
                    let f4a4 = self.read_u32(li as usize + 0x4A4).unwrap_or(0);
                    let f5cc = self.read_u32(li as usize + 0x5CC).unwrap_or(0);
                    let tsec = f32::from_bits(self.read_u32(li as usize + 0x430).unwrap_or(0));
                    lines.push(format!(
                        "LevelInfo0/Tick State:  ULevel.Ticked={} | Pauser=0x{:08X} | Flags4A4=0x{:08X} | Flags5CC=0x{:08X} | TimeSec={:.4}",
                        ticked, pauser, f4a4, f5cc, tsec
                    ));
                }
            }
        }
        lines.push(format!("GNames VA:              0x{:08X} (Count: {})", gnames_ptr, gnames_count));
        lines.push("".to_string());
        lines.push("=== CHECKSUM-CONTRIBUTING PAWNS (bIsPawn && !bDeleteMe && Physics != 0) ===".to_string());
        lines.push(format!(
            "{:<6} {:<24} {:<24} {:<10} {:<8} {:<30} {:<24} {:<10} {:<30} {:<24} {}",
            "Index", "Actor Name", "Class", "Ptr", "Physics", "Location (X, Y, Z)", "Rotation (P, Y, R)", "Ctrl Ptr", "Ctrl Loc (X, Y, Z)", "Ctrl Rot (P, Y, R)", "TickDelta"
        ));
        lines.push("--------------------------------------------------------------------------------".to_string());
        if pawn_lines.is_empty() {
            lines.push("  (no active checksum-contributing pawns)".to_string());
        } else {
            lines.extend(pawn_lines);
        }
        lines.push("".to_string());
        lines.push("=== ALL LEVEL ACTORS ===".to_string());
        lines.push("--------------------------------------------------------------------------------".to_string());
        lines.push(format!(
            "{:<6} {:<24} {:<24} {:<10} {:<30} {:<24} {:<30} {:<10} {:<10} {:<7}",
            "Index", "Actor Name", "Class", "Ptr", "Location (X, Y, Z)", "Rotation (P, Y, R)", "Velocity (X, Y, Z)", "Flags28", "Flags2C", "Physics"
        ));
        lines.push("--------------------------------------------------------------------------------".to_string());
        lines.extend(actor_lines);

        lines.push("================================================================================".to_string());
        lines.push("Instructions: Both players should compare this file using a diff tool (e.g. diff,".to_string());
        lines.push("VS Code, Meld, WinMerge). Any actor with different Location, Rotation, Velocity,".to_string());
        lines.push("or Flags indicates where the simulation diverged between Host and Guest.".to_string());
        lines.push("================================================================================".to_string());

        let content = lines.join("\n");
        std::fs::write(&dump_path, content)?;

        Ok(dump_path)
    }

    pub fn poll_startup_trace(&mut self, game_root: &Path) -> Option<PathBuf> {
        if self.trace_buf_va == 0 {
            return None;
        }
        let mut hdr = [0u8; 16];
        if !self.read_memory(self.trace_buf_va + crate::trace::TRACE_HDR_OFF, &mut hdr) {
            return None;
        }
        let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        if magic != crate::trace::TRACE_MAGIC {
            return None;
        }
        let write_idx = u32::from_le_bytes(hdr[4..8].try_into().unwrap())
            .min(crate::trace::TRACE_MAX_RECORDS as u32);
        if write_idx <= self.trace_flushed_seq {
            return None;
        }

        let start = self.trace_flushed_seq;
        let to_read = (write_idx - start) as usize;
        let mut raw = vec![0u8; to_read * crate::trace::TRACE_RECORD_SIZE];
        let rec_va = self.trace_buf_va
            + crate::trace::TRACE_RECORDS_OFF
            + (start as usize) * crate::trace::TRACE_RECORD_SIZE;
        if !self.read_memory(rec_va, &mut raw) {
            return None;
        }

        let mut records = Vec::with_capacity(to_read);
        for chunk in raw.chunks_exact(crate::trace::TRACE_RECORD_SIZE) {
            let mut w = [0u32; 16];
            for (i, slot) in w.iter_mut().enumerate() {
                *slot = u32::from_le_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
            }
            if w[15] == 0 {
                break; // Still being committed
            }
            records.push(crate::trace::TraceRecord::from_words(&w));
        }
        if records.is_empty() {
            return None;
        }

        let trace_path = crate::trace::trace_file_path(game_root);
        let first_flush = self.trace_flushed_seq == 0;
        let lines = crate::trace::format_trace_lines(&records, &mut self.trace_prev_u0);
        self.trace_flushed_seq += records.len() as u32;

        if first_flush {
            let bypass_byte = self
                .read_u8(crate::net::HOOK_SITE_CHECK_SIM_CHECKSUM as usize)
                .unwrap_or(0);
            let mut all = crate::trace::trace_header_lines(self.pid, bypass_byte == 0xE9);
            all.extend(lines);
            let mut text = all.join("\n");
            text.push('\n');
            if std::fs::write(&trace_path, text).is_err() {
                return None;
            }
            return Some(trace_path);
        }

        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&trace_path)
        {
            for line in lines {
                let _ = writeln!(f, "{}", line);
            }
        }
        None
    }

    pub fn wait_for_exit_monitoring_desync(mut self, game_root: &Path) {
        let mut desync_dumped = false;
        let mut trace_notified = false;
        while self.is_alive() {
            if let Some(trace_path) = self.poll_startup_trace(game_root) {
                if !trace_notified {
                    trace_notified = true;
                    println!(
                        "  >>> [TRACE] Recording startup sync/tick trace to: {}",
                        trace_path.display()
                    );
                }
            }
            if !desync_dumped && self.is_desync_flagged() {
                desync_dumped = true;
                let _ = self.poll_startup_trace(game_root);
                match self.dump_desync_state(game_root) {
                    Ok(dump_path) => {
                        println!("\n  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                        println!("  >>> [DESYNC DETECTED] Simulation lockstep mismatch detected!");
                        println!("  >>> [DESYNC DUMP] Dumped actor states to: {}", dump_path.display());
                        println!("  >>> Compare this file with your co-op partner's dump file to find the desynced actor.");
                        println!("  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
                    }
                    Err(e) => {
                        eprintln!("  >>> [DESYNC ERROR] Failed to dump desync state: {:#}", e);
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let _ = self.poll_startup_trace(game_root);
        self.wait_for_exit();
    }
}

#[cfg(windows)]
impl Drop for GameProcess {
    fn drop(&mut self) {
        if self.handle_val != 0 {
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(
                    self.handle_val as windows_sys::Win32::Foundation::HANDLE,
                );
            }
            self.handle_val = 0;
        }
    }
}

#[cfg(windows)]
pub const CAVE_INHERITED_SOCK_9100: usize = 0x113303D0;
#[cfg(windows)]
pub const CAVE_INHERITED_SOCK_9103: usize = 0x113303D4;
#[cfg(windows)]
pub const CAVE_INHERITED_PRIMED_9100: usize = 0x113303D8;
#[cfg(windows)]
pub const CAVE_INHERITED_PRIMED_9103: usize = 0x113303DC;
#[cfg(windows)]
pub const CAVE_LAST_9103_KEEPALIVE_VA: usize = crate::net::G_LAST_9103_KEEPALIVE_VA as usize;
#[cfg(windows)]
pub const CAVE_LAST_9100_KEEPALIVE_VA: usize = crate::net::G_LAST_9100_KEEPALIVE_VA as usize;

#[cfg(windows)]
pub const CAVE_ONLINE_ENABLED_VA: usize = crate::net::CAVE_ONLINE_ENABLED_VA as usize;
#[cfg(windows)]
pub const CAVE_ONLINE_IP_VA: usize = crate::net::CAVE_ONLINE_IP_VA as usize;
#[cfg(windows)]
pub const CAVE_ONLINE_PORT_VA: usize = crate::net::CAVE_ONLINE_PORT_VA as usize;
#[cfg(windows)]
pub const JOIN_GAME_PORT_VA: usize = crate::net::JOIN_GAME_PORT_VA as usize;
#[cfg(windows)]
pub const CAVE_LAN_PEER_VA: usize = 0x113303A0;
#[cfg(windows)]
pub const CAVE_LOCAL_BIND_IP_VA: usize = crate::net::G_LOCAL_BIND_IP_VA as usize;

#[cfg(windows)]
unsafe fn write_proc_bytes(
    h_process: windows_sys::Win32::Foundation::HANDLE,
    addr: usize,
    bytes: &[u8],
    in_text: bool,
) {
    use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, VirtualProtectEx};

    unsafe {
        let mut old_prot: u32 = 0;
        let prot_changed = if in_text {
            VirtualProtectEx(
                h_process,
                addr as *const _,
                bytes.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old_prot,
            ) != 0
        } else {
            false
        };

        let mut written: usize = 0;
        WriteProcessMemory(
            h_process,
            addr as *mut _,
            bytes.as_ptr() as *const _,
            bytes.len(),
            &mut written,
        );

        if prot_changed {
            let mut dummy: u32 = 0;
            VirtualProtectEx(
                h_process,
                addr as *const _,
                bytes.len(),
                old_prot,
                &mut dummy,
            );
        }
    }
}

#[cfg(windows)]
pub fn launch_game(
    exe_path: &Path,
    game_dir: &Path,
    peer_ip: Option<Ipv4Addr>,
    peer_disco_port: u16,
    peer_game_port: u16,
    local_bind_ip: Option<Ipv4Addr>,
) -> Result<GameProcess> {
    use std::ffi::CString;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{CloseHandle, FALSE};
    use windows_sys::Win32::System::Threading::{
        CREATE_SUSPENDED, CreateProcessA, PROCESS_INFORMATION, ResumeThread, STARTUPINFOA,
    };

    let exe_str = CString::new(exe_path.to_string_lossy().as_bytes())?;
    let dir_str = CString::new(game_dir.to_string_lossy().as_bytes())?;

    let mut si: STARTUPINFOA = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // Spawn suspended process with bInheritHandles = FALSE
    let success = unsafe {
        CreateProcessA(
            exe_str.as_ptr() as *const u8,
            null_mut(),
            null_mut(),
            null_mut(),
            FALSE, // bInheritHandles = FALSE
            CREATE_SUSPENDED,
            null_mut(),
            dir_str.as_ptr() as *const u8,
            &si,
            &mut pi,
        )
    };

    if success == 0 {
        bail!(
            "CreateProcess failed to launch {}: error code {}",
            exe_path.display(),
            std::io::Error::last_os_error()
        );
    }

    let h_process = pi.hProcess;
    let h_thread = pi.hThread;
    let pid = pi.dwProcessId;

    let trace_buf_va = unsafe {
        let zero = 0u32.to_le_bytes();

        // 1. Explicitly zero out inherited socket, keepalive tick, and desync flag locations in .data
        write_proc_bytes(h_process, CAVE_INHERITED_SOCK_9100, &zero, false);
        write_proc_bytes(h_process, CAVE_INHERITED_SOCK_9103, &zero, false);
        write_proc_bytes(h_process, CAVE_INHERITED_PRIMED_9100, &zero, false);
        write_proc_bytes(h_process, CAVE_INHERITED_PRIMED_9103, &zero, false);
        write_proc_bytes(h_process, CAVE_LAST_9103_KEEPALIVE_VA, &zero, false);
        write_proc_bytes(h_process, CAVE_LAST_9100_KEEPALIVE_VA, &zero, false);
        write_proc_bytes(h_process, CAVE_DESYNC_FLAG_VA, &[0u8; 8], false);

        // 2. Configure ONLINE_CAVE, JOIN_GAME_PORT_VA, and CAVE_LAN_PEER_VA
        if let Some(ip) = peer_ip {
            let disco_port = if peer_disco_port == 0 {
                crate::net::DISCOVERY_PORT
            } else {
                peer_disco_port
            };
            let game_port = if peer_game_port == 0 {
                crate::net::GAME_PORT
            } else {
                peer_game_port
            };
            let ip_bytes = ip.octets();
            let disco_be = disco_port.to_be_bytes();
            let game_le = (game_port as u32).to_le_bytes();

            write_proc_bytes(h_process, CAVE_ONLINE_ENABLED_VA, &[1u8], true);
            write_proc_bytes(h_process, CAVE_ONLINE_IP_VA, &ip_bytes, true);
            write_proc_bytes(h_process, CAVE_ONLINE_PORT_VA, &disco_be, true);
            write_proc_bytes(h_process, JOIN_GAME_PORT_VA, &game_le, true);

            // Set CAVE_LAN_PEER_VA for route-matched NIC promotion in splintercell3.exe
            // If peer_ip is a private address, only set it if our local host shares the subnet.
            // Otherwise, keep it 0.0.0.0 so the probe defaults to 8.8.8.8 and selects the physical gateway.
            let oct = ip.octets();
            let is_private = oct[0] == 10
                || (oct[0] == 172 && (16..=31).contains(&oct[1]))
                || (oct[0] == 192 && oct[1] == 168);
            let is_local_routable = !is_private || crate::ip::find_matching_subnet_ip(ip).is_some();
            let probe_ip = if is_local_routable {
                ip_bytes
            } else {
                [0u8; 4]
            };

            write_proc_bytes(h_process, CAVE_LAN_PEER_VA, &probe_ip, false);
        } else {
            let zero_ip = [0u8; 4];
            let default_disco_be = crate::net::DISCOVERY_PORT.to_be_bytes();
            let default_game_le = (crate::net::GAME_PORT as u32).to_le_bytes();

            write_proc_bytes(h_process, CAVE_ONLINE_ENABLED_VA, &[0u8], true);
            write_proc_bytes(h_process, CAVE_ONLINE_IP_VA, &zero_ip, true);
            write_proc_bytes(h_process, CAVE_ONLINE_PORT_VA, &default_disco_be, true);
            write_proc_bytes(h_process, JOIN_GAME_PORT_VA, &default_game_le, true);
            write_proc_bytes(h_process, CAVE_LAN_PEER_VA, &zero_ip, false);
        }

        let bind_octets = local_bind_ip
            .filter(|ip| !ip.is_unspecified())
            .map(|ip| ip.octets())
            .unwrap_or([0u8; 4]);
        write_proc_bytes(h_process, CAVE_LOCAL_BIND_IP_VA, &bind_octets, false);

        let trace_buf_va = crate::trace::install_startup_trace(h_process, write_proc_bytes);

        // 3. Resume the game thread
        ResumeThread(h_thread);
        CloseHandle(h_thread);
        trace_buf_va
    };

    Ok(GameProcess {
        pid,
        handle_val: h_process as usize,
        trace_buf_va,
        trace_flushed_seq: 0,
        trace_prev_u0: None,
    })
}

#[cfg(not(windows))]
pub fn launch_game(
    exe_path: &Path,
    game_dir: &Path,
    _peer_ip: Option<Ipv4Addr>,
    _peer_disco_port: u16,
    _peer_game_port: u16,
    _local_bind_ip: Option<Ipv4Addr>,
) -> Result<GameProcess> {
    let child = std::process::Command::new(exe_path)
        .current_dir(game_dir)
        .spawn()
        .with_context(|| format!("Launching {}", exe_path.display()))?;

    Ok(GameProcess {
        pid: child.id(),
        child,
        trace_buf_va: 0,
        trace_flushed_seq: 0,
        trace_prev_u0: None,
    })
}
