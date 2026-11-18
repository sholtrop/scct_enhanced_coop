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

/// Decodes a NUL-terminated 8-bit ANSI (`FNameEntry::Name`) byte slice using SCCT's
/// `appFromAnsi` zero-extension mapping (stopping at the first NUL byte).
pub fn decode_ansi_cstr(bytes: &[u8]) -> String {
    bytes
        .iter()
        .copied()
        .take_while(|&b| b != 0)
        .map(char::from)
        .collect()
}

pub struct DesyncReport {
    pub dump_path: PathBuf,
    pub trace_path: Option<PathBuf>,
    pub mismatched_slots: String,
}

pub struct MonitorPollResult {
    pub trace_started: Option<PathBuf>,
    pub resync_logs: Vec<String>,
    pub desync: Option<Result<DesyncReport>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectPeerTarget {
    pub ip: Ipv4Addr,
    pub disco_port: u16,
    pub game_port: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaunchRuntimeOptions {
    pub auto_resync: bool,
    pub install_trace_hooks: bool,
    pub monitor_desync_dump: bool,
    pub inject_lan_net_globals: bool,
    pub inject_nat_direct_target: bool,
    pub enable_persistent_quicksave_load: bool,
}

impl Default for LaunchRuntimeOptions {
    fn default() -> Self {
        Self {
            auto_resync: false,
            install_trace_hooks: true,
            monitor_desync_dump: true,
            inject_lan_net_globals: true,
            inject_nat_direct_target: true,
            enable_persistent_quicksave_load: true,
        }
    }
}

pub struct GameProcess {
    pub pid: u32,
    pub peer_role: crate::trace::PeerRole,
    pub peer_ip: Option<Ipv4Addr>,
    #[cfg(windows)]
    handle_val: usize,
    #[cfg(not(windows))]
    child: std::process::Child,
    trace_buf_va: usize,
    trace_flushed_seq: u32,
    trace_prev_u0: Option<u32>,
    trace_last_mismatch_total: u32,
    trace_path: Option<PathBuf>,
    dump_path: Option<PathBuf>,
    trace_owner_marker: Option<PathBuf>,
    monitor_desync_dump: bool,
    pub(crate) resync_coord: Option<crate::resync::ResyncCoordinator>,
    resync_aborted: bool,
    pub(crate) last_resync_error: Option<String>,
}

fn is_pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return false;
            }
            let mut code: u32 = 0;
            let ok = GetExitCodeProcess(h, &mut code);
            let _ = CloseHandle(h);
            ok != 0 && code == STILL_ACTIVE as u32
        }
    }
    #[cfg(not(windows))]
    {
        Path::new(&format!("/proc/{}", pid)).exists()
    }
}

pub(crate) fn resolve_session_paths_with(
    game_root: &Path,
    role: crate::trace::PeerRole,
    pid: u32,
    pid_alive: impl Fn(u32) -> bool,
) -> (PathBuf, PathBuf, Option<PathBuf>) {
    const OWNER_PREFIX: &str = ".scct_trace_owner_";
    let sys_dir = crate::patcher::find_child_ci(game_root, "System");
    let mut conflict = false;

    if let Ok(entries) = std::fs::read_dir(&sys_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            let Some(rest) = name_str.strip_prefix(OWNER_PREFIX) else {
                continue;
            };
            let Ok(other_pid) = rest.parse::<u32>() else {
                continue;
            };
            if other_pid == pid {
                continue;
            }
            if pid_alive(other_pid) {
                conflict = true;
            } else {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    if conflict {
        let suffix = format!("{}_pid{}", role.file_tag(), pid);
        (
            crate::trace::session_file_path(game_root, "scct_startup_trace", "txt", Some(&suffix)),
            crate::trace::session_file_path(game_root, "scct_desync_dump", "txt", Some(&suffix)),
            None,
        )
    } else {
        let marker = sys_dir.join(format!("{}{}", OWNER_PREFIX, pid));
        let marker_opt = if std::fs::write(&marker, format!("{}\n", pid)).is_ok() {
            Some(marker)
        } else {
            None
        };
        (
            crate::trace::session_file_path(game_root, "scct_startup_trace", "txt", None),
            crate::trace::session_file_path(game_root, "scct_desync_dump", "txt", None),
            marker_opt,
        )
    }
}

impl Drop for GameProcess {
    fn drop(&mut self) {
        if let Some(marker) = self.trace_owner_marker.take() {
            let _ = std::fs::remove_file(marker);
        }
        #[cfg(windows)]
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
            matches!(self.child.try_wait(), Ok(None))
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

    pub fn write_memory(&self, addr: usize, data: &[u8]) -> bool {
        #[cfg(windows)]
        {
            if self.handle_val == 0 {
                return false;
            }
            use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
            let mut bytes_written: usize = 0;
            let res = unsafe {
                WriteProcessMemory(
                    self.handle_val as windows_sys::Win32::Foundation::HANDLE,
                    addr as *mut _,
                    data.as_ptr() as *const _,
                    data.len(),
                    &mut bytes_written,
                )
            };
            res != 0 && bytes_written == data.len()
        }
        #[cfg(not(windows))]
        {
            use std::fs::OpenOptions;
            use std::io::{Seek, SeekFrom, Write};
            let Ok(mut file) = OpenOptions::new()
                .write(true)
                .open(format!("/proc/{}/mem", self.pid))
            else {
                return false;
            };
            if file.seek(SeekFrom::Start(addr as u64)).is_err() {
                return false;
            }
            file.write_all(data).is_ok()
        }
    }

    pub fn write_u32(&self, addr: usize, val: u32) -> bool {
        self.write_memory(addr, &val.to_le_bytes())
    }

    pub fn trace_buf_va(&self) -> usize {
        self.trace_buf_va
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

    pub fn read_string(&self, addr: usize, max_len: usize) -> Option<String> {
        if max_len == 0 {
            return Some(String::new());
        }
        let mut buf = vec![0u8; max_len];
        if self.read_memory(addr, &mut buf) {
            return Some(decode_ansi_cstr(&buf));
        }

        // Fallback near page boundaries: read bytes one at a time.
        let mut bytes = Vec::new();
        for i in 0..max_len {
            let Some(b) = self.read_u8(addr + i) else {
                return if bytes.is_empty() {
                    None
                } else {
                    Some(decode_ansi_cstr(&bytes))
                };
            };
            if b == 0 {
                return Some(decode_ansi_cstr(&bytes));
            }
            bytes.push(b);
        }
        Some(decode_ansi_cstr(&bytes))
    }

    /// Reads a null-terminated UTF-16LE string from target process memory.
    #[allow(dead_code)]
    pub fn read_wstring(&self, addr: usize, max_chars: usize) -> Option<String> {
        if max_chars == 0 {
            return Some(String::new());
        }
        let mut buf = vec![0u8; max_chars * 2];
        if self.read_memory(addr, &mut buf) {
            let units: Vec<u16> = buf
                .as_chunks::<2>()
                .0
                .iter()
                .copied()
                .map(u16::from_le_bytes)
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

    /// Resolves a UE2 `FName` index via `GNames` (`FNameEntry::Name` ANSI string at `+0x0C`).
    pub fn resolve_fname(&self, gnames_ptr: u32, gnames_count: u32, name_idx: u32) -> String {
        if gnames_ptr != 0 && name_idx < gnames_count {
            let entry_ptr = self
                .read_u32(gnames_ptr as usize + (name_idx as usize) * 4)
                .unwrap_or(0);
            if entry_ptr != 0
                && let Some(name) = self.read_string(entry_ptr as usize + 0x0C, 64)
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

    fn ensure_session_paths(&mut self, game_root: &Path) -> (PathBuf, PathBuf) {
        if let (Some(trace_path), Some(dump_path)) = (&self.trace_path, &self.dump_path) {
            return (trace_path.clone(), dump_path.clone());
        }
        let (trace_path, dump_path, marker) =
            resolve_session_paths_with(game_root, self.peer_role, self.pid, is_pid_alive);
        self.trace_path = Some(trace_path.clone());
        self.dump_path = Some(dump_path.clone());
        self.trace_owner_marker = marker;
        (trace_path, dump_path)
    }

    pub fn trace_output_path(&self) -> Option<&Path> {
        self.trace_path.as_deref()
    }

    pub fn read_trace_mismatch_summary(&self) -> Option<crate::trace::TraceMismatchSummary> {
        if self.trace_buf_va == 0 {
            return None;
        }
        let mut hdr = [0u8; crate::trace::TRACE_HDR_SIZE];
        if !self.read_memory(self.trace_buf_va + crate::trace::TRACE_HDR_OFF, &mut hdr) {
            return None;
        }
        crate::trace::TraceMismatchSummary::from_header_bytes(&hdr)
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
        self.read_trace_mismatch_summary()
            .is_some_and(|s| s.seen_status6 || s.has_slot5_mismatch())
    }

    pub fn resolve_level_info(&self) -> (u32, u32, u32, u32, u32) {
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
        (
            level_ptr,
            gengine_ptr,
            glevel_direct,
            viewport_ptr,
            viewport_actor_level,
        )
    }

    pub fn resolve_level_ptr(&self) -> u32 {
        self.resolve_level_info().0
    }

    pub fn dump_desync_state(&mut self, game_root: &Path) -> Result<PathBuf> {
        let (trace_path, dump_path) = self.ensure_session_paths(game_root);
        let trace_summary = self.read_trace_mismatch_summary();
        let bypass_active = self
            .read_u8(crate::net::HOOK_SITE_CHECK_SIM_CHECKSUM as usize)
            .unwrap_or(0)
            == 0xE9;

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

        let (level_ptr, gengine_ptr, glevel_direct, viewport_ptr, viewport_actor_level) =
            self.resolve_level_info();

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

                if (flags_2c & 0x10) != 0 {
                    let ctrl_ptr = self.read_u32(actor_ptr as usize + 0x2B4).unwrap_or(0);
                    if (flags_28 & 0x04) == 0 && physics != 0 {
                        let pawn_loc_sum = (loc.2 as i32)
                            .wrapping_add(loc.1 as i32)
                            .wrapping_add(loc.0 as i32);
                        let pawn_rot_sum = rot.1.wrapping_add(rot.2).wrapping_add(rot.0);
                        let (ctrl_loc, ctrl_rot) = self.read_actor_loc_rot(ctrl_ptr);
                        let (ctrl_loc_sum, ctrl_rot_sum) =
                            if ctrl_ptr != 0 && (flags_2c & 0x20) != 0 {
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
        let peer_str = self
            .peer_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "none".to_string());
        lines.push("================================================================================".to_string());
        lines.push("            SCCT CO-OP ENHANCER - DESYNC DIAGNOSTIC STATE DUMP                 ".to_string());
        lines.push("================================================================================".to_string());
        lines.push(format!(
            "Peer Role / PID:        {} (PID: {}, Peer: {})",
            self.peer_role.as_str(),
            self.pid,
            peer_str
        ));
        lines.push(format!("BypassFlagActive:       {}", bypass_active));
        if let Some(ref err) = self.last_resync_error {
            lines.push(format!("Resync Abort Reason:    {}", err));
        }
        lines.push(format!("SyncEngine VA:          0x{:08X}", sync_engine_ptr));
        lines.push(format!("Simulation Step:        {}", step));
        lines.push(format!("Simulation Status:      {} (0x{:08X}) [MismatchCount: {}]", status, status, mismatch_count));
        if let Some(ref summary) = trace_summary {
            lines.extend(summary.format_summary_lines());
            lines.push(format!(
                "Startup Trace File:     {} (records={}, dropped={})",
                trace_path.display(),
                summary.write_idx,
                summary.dropped_records
            ));
        } else {
            lines.push("Mismatched Slots:       (startup trace header unavailable)".to_string());
            lines.push(format!("Startup Trace File:     {}", trace_path.display()));
        }
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
        lines.push("Instructions: Collect BOTH scct_desync_dump and scct_startup_trace from BOTH".to_string());
        lines.push("Host and Guest, then compare them (diff, VS Code, Meld, WinMerge).".to_string());
        lines.push("Mismatched Slots identifies whether slot=0 (UserChecksum0/pawn sim) and/or".to_string());
        lines.push("slot=5 (RNG/full sim) diverged; actor diffs pinpoint the desynced entity.".to_string());
        lines.push("================================================================================".to_string());

        let content = lines.join("\n");
        std::fs::write(&dump_path, content)?;

        Ok(dump_path)
    }

    pub fn poll_startup_trace(&mut self, game_root: &Path) -> Option<PathBuf> {
        let summary = self.read_trace_mismatch_summary()?;
        let write_idx = summary
            .write_idx
            .min(crate::trace::TRACE_MAX_RECORDS as u32);
        let has_new_records = write_idx > self.trace_flushed_seq;
        let mismatch_increased = summary.total_mismatches > self.trace_last_mismatch_total;
        if !has_new_records && !mismatch_increased {
            return None;
        }

        let mut records = Vec::new();
        if has_new_records {
            let start = self.trace_flushed_seq;
            let to_read = (write_idx - start) as usize;
            let mut raw = vec![0u8; to_read * crate::trace::TRACE_RECORD_SIZE];
            let rec_va = self.trace_buf_va
                + crate::trace::TRACE_RECORDS_OFF
                + (start as usize) * crate::trace::TRACE_RECORD_SIZE;
            if !self.read_memory(rec_va, &mut raw) {
                return None;
            }
            records.reserve(to_read);
            for chunk in raw.as_chunks::<{ crate::trace::TRACE_RECORD_SIZE }>().0 {
                let mut w = [0u32; 16];
                for (i, slot) in w.iter_mut().enumerate() {
                    *slot = u32::from_le_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
                }
                if w[15] == 0 {
                    break; // Still being committed
                }
                records.push(crate::trace::TraceRecord::from_words(&w));
            }
        }

        let first_flush = self.trace_flushed_seq == 0;
        if first_flush && records.is_empty() && !mismatch_increased {
            return None;
        }

        let (trace_path, _) = self.ensure_session_paths(game_root);
        let new_cmp_mismatches = records
            .iter()
            .filter(|r| r.kind == crate::trace::TraceKind::Cmp as u32 && r.arg_a != r.arg_b)
            .count() as u32;
        let mut lines = crate::trace::format_trace_lines(&records, &mut self.trace_prev_u0);

        let should_append_latch = (first_flush && summary.total_mismatches > 0 && new_cmp_mismatches < summary.total_mismatches)
            || (!first_flush
                && mismatch_increased
                && (summary.dropped_records > 0
                    || write_idx >= crate::trace::TRACE_MAX_RECORDS as u32
                    || new_cmp_mismatches == 0));
        if should_append_latch {
            for latch_line in summary.format_summary_lines() {
                lines.push(format!("# [MISMATCH LATCH] {}", latch_line));
            }
        }

        self.trace_flushed_seq += records.len() as u32;
        self.trace_last_mismatch_total = summary.total_mismatches;

        if first_flush {
            let bypass_byte = self
                .read_u8(crate::net::HOOK_SITE_CHECK_SIM_CHECKSUM as usize)
                .unwrap_or(0);
            let mut all = crate::trace::trace_header_lines(
                self.pid,
                self.peer_role,
                self.peer_ip,
                bypass_byte == 0xE9,
            );
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

    pub fn poll_monitor_once(
        &mut self,
        game_root: &Path,
        desync_dumped: &mut bool,
        trace_notified: &mut bool,
    ) -> MonitorPollResult {
        let mut res = MonitorPollResult {
            trace_started: None,
            resync_logs: Vec::new(),
            desync: None,
        };
        if self.resync_coord.is_some()
            && crate::resync::poll_resync(self, &mut res.resync_logs)
        {
            self.resync_aborted = true;
        }
        if let Some(trace_path) = self.poll_startup_trace(game_root)
            && !*trace_notified
        {
            *trace_notified = true;
            res.trace_started = Some(trace_path);
        }
        let resync_active = self.resync_coord.is_some() && !self.resync_aborted;
        if self.monitor_desync_dump && !*desync_dumped && !resync_active && self.is_desync_flagged()
        {
            *desync_dumped = true;
            let _ = self.poll_startup_trace(game_root);
            let mismatched_slots = self
                .read_trace_mismatch_summary()
                .map(|s| s.format_slot_list())
                .unwrap_or_else(|| "unknown".to_string());
            let trace_path = self.trace_output_path().map(Path::to_path_buf);
            res.desync = Some(self.dump_desync_state(game_root).map(|dump_path| DesyncReport {
                dump_path,
                trace_path,
                mismatched_slots,
            }));
        }
        res
    }

    pub fn wait_for_exit_monitoring_desync(mut self, game_root: &Path) {
        let mut desync_dumped = false;
        let mut trace_notified = false;
        loop {
            let alive = self.is_alive();
            let poll = self.poll_monitor_once(game_root, &mut desync_dumped, &mut trace_notified);
            if let Some(trace_path) = poll.trace_started {
                println!(
                    "  >>> [TRACE] Recording startup sync/tick trace ({}) to: {}",
                    self.peer_role.as_str(),
                    trace_path.display()
                );
            }
            for line in poll.resync_logs {
                println!("  {}", line);
            }
            if let Some(desync_res) = poll.desync {
                match desync_res {
                    Ok(report) => {
                        println!("\n  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                        println!("  >>> [DESYNC DETECTED] Simulation lockstep mismatch detected!");
                        println!("  >>> [MISMATCH SLOTS] {}", report.mismatched_slots);
                        println!("  >>> [DESYNC DUMP]   Actor state:  {}", report.dump_path.display());
                        if let Some(ref tp) = report.trace_path {
                            println!("  >>> [STARTUP TRACE] Sync trace:   {}", tp.display());
                        }
                        println!("  >>> Collect BOTH files above from BOTH Host and Guest to compare.");
                        println!("  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
                    }
                    Err(e) => {
                        eprintln!("  >>> [DESYNC ERROR] Failed to dump desync state: {:#}", e);
                    }
                }
            }
            if !alive {
                break;
            }
            let sleep_ms = if self.resync_coord.is_some() { 10 } else { 100 };
            std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
        }
        self.wait_for_exit();
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
    peer_role: crate::trace::PeerRole,
    direct_peer: Option<DirectPeerTarget>,
    local_bind_ip: Option<Ipv4Addr>,
    opts: LaunchRuntimeOptions,
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
    let peer_ip = direct_peer.map(|p| p.ip);

    let trace_buf_va = unsafe {
        let zero = 0u32.to_le_bytes();

        if opts.install_trace_hooks || opts.auto_resync || opts.monitor_desync_dump {
            write_proc_bytes(h_process, CAVE_DESYNC_FLAG_VA, &[0u8; 8], false);
        }

        // 1. Explicitly zero out inherited socket and keepalive tick locations in .data when LAN globals are enabled
        if opts.inject_lan_net_globals {
            write_proc_bytes(h_process, CAVE_INHERITED_SOCK_9100, &zero, false);
            write_proc_bytes(h_process, CAVE_INHERITED_SOCK_9103, &zero, false);
            write_proc_bytes(h_process, CAVE_INHERITED_PRIMED_9100, &zero, false);
            write_proc_bytes(h_process, CAVE_INHERITED_PRIMED_9103, &zero, false);
            write_proc_bytes(h_process, CAVE_LAST_9103_KEEPALIVE_VA, &zero, false);
            write_proc_bytes(h_process, CAVE_LAST_9100_KEEPALIVE_VA, &zero, false);
        }

        // 2. Configure ONLINE_CAVE, JOIN_GAME_PORT_VA, CAVE_LAN_PEER_VA, and CAVE_LOCAL_BIND_IP_VA
        if let Some(target) = direct_peer {
            if opts.inject_nat_direct_target {
                let disco_port = if target.disco_port == 0 {
                    crate::net::DISCOVERY_PORT
                } else {
                    target.disco_port
                };
                let game_port = if target.game_port == 0 {
                    crate::net::GAME_PORT
                } else {
                    target.game_port
                };
                let ip_bytes = target.ip.octets();
                let disco_be = disco_port.to_be_bytes();
                let game_le = (game_port as u32).to_le_bytes();

                write_proc_bytes(h_process, CAVE_ONLINE_ENABLED_VA, &[1u8], true);
                write_proc_bytes(h_process, CAVE_ONLINE_IP_VA, &ip_bytes, true);
                write_proc_bytes(h_process, CAVE_ONLINE_PORT_VA, &disco_be, true);
                write_proc_bytes(h_process, JOIN_GAME_PORT_VA, &game_le, true);
            }

            if opts.inject_lan_net_globals {
                let oct = target.ip.octets();
                let is_private = oct[0] == 10
                    || (oct[0] == 172 && (16..=31).contains(&oct[1]))
                    || (oct[0] == 192 && oct[1] == 168);
                let is_local_routable =
                    !is_private || crate::ip::find_matching_subnet_ip(target.ip).is_some();
                let probe_ip = if is_local_routable { oct } else { [0u8; 4] };
                write_proc_bytes(h_process, CAVE_LAN_PEER_VA, &probe_ip, false);
            }
        } else {
            let zero_ip = [0u8; 4];
            if opts.inject_nat_direct_target {
                let default_disco_be = crate::net::DISCOVERY_PORT.to_be_bytes();
                let default_game_le = (crate::net::GAME_PORT as u32).to_le_bytes();

                write_proc_bytes(h_process, CAVE_ONLINE_ENABLED_VA, &[0u8], true);
                write_proc_bytes(h_process, CAVE_ONLINE_IP_VA, &zero_ip, true);
                write_proc_bytes(h_process, CAVE_ONLINE_PORT_VA, &default_disco_be, true);
                write_proc_bytes(h_process, JOIN_GAME_PORT_VA, &default_game_le, true);
            }
            if opts.inject_lan_net_globals {
                write_proc_bytes(h_process, CAVE_LAN_PEER_VA, &zero_ip, false);
            }
        }

        if opts.inject_lan_net_globals {
            let bind_octets = local_bind_ip
                .filter(|ip| !ip.is_unspecified())
                .map(|ip| ip.octets())
                .unwrap_or([0u8; 4]);
            write_proc_bytes(h_process, CAVE_LOCAL_BIND_IP_VA, &bind_octets, false);
        }

        let trace_buf_va = if opts.install_trace_hooks || opts.auto_resync {
            crate::trace::install_startup_trace(h_process, write_proc_bytes, opts.auto_resync)
        } else {
            0
        };

        if opts.enable_persistent_quicksave_load {
            crate::quicksave_persistence::install_quicksave_persistence_hooks(
                h_process,
                write_proc_bytes,
            );
        }

        // 3. Resume the game thread
        ResumeThread(h_thread);
        CloseHandle(h_thread);
        trace_buf_va
    };

    let resync_coord = if opts.auto_resync {
        match crate::resync::ResyncCoordinator::new(peer_role, peer_ip, local_bind_ip) {
            Ok(coord) => Some(coord),
            Err(e) => {
                crate::scct_log!("  [RESYNC] Disabled (UDP socket init failed: {:#})", e);
                None
            }
        }
    } else {
        None
    };

    Ok(GameProcess {
        pid,
        peer_role,
        peer_ip,
        handle_val: h_process as usize,
        trace_buf_va,
        trace_flushed_seq: 0,
        trace_prev_u0: None,
        trace_last_mismatch_total: 0,
        trace_path: None,
        dump_path: None,
        trace_owner_marker: None,
        monitor_desync_dump: opts.monitor_desync_dump,
        resync_coord,
        resync_aborted: false,
        last_resync_error: None,
    })
}

#[cfg(not(windows))]
pub fn launch_game(
    exe_path: &Path,
    game_dir: &Path,
    peer_role: crate::trace::PeerRole,
    direct_peer: Option<DirectPeerTarget>,
    local_bind_ip: Option<Ipv4Addr>,
    opts: LaunchRuntimeOptions,
) -> Result<GameProcess> {
    let peer_ip = direct_peer.map(|p| p.ip);
    let child = std::process::Command::new(exe_path)
        .current_dir(game_dir)
        .spawn()
        .with_context(|| format!("Launching {}", exe_path.display()))?;

    let resync_coord = if opts.auto_resync {
        crate::resync::ResyncCoordinator::new(peer_role, peer_ip, local_bind_ip).ok()
    } else {
        None
    };

    Ok(GameProcess {
        pid: child.id(),
        peer_role,
        peer_ip,
        child,
        trace_buf_va: 0,
        trace_flushed_seq: 0,
        trace_prev_u0: None,
        trace_last_mismatch_total: 0,
        trace_path: None,
        dump_path: None,
        trace_owner_marker: None,
        monitor_desync_dump: opts.monitor_desync_dump,
        resync_coord,
        resync_aborted: false,
        last_resync_error: None,
    })
}

#[cfg(test)]
mod tests {
    use super::decode_ansi_cstr;

    #[test]
    fn decode_ansi_cstr_stops_at_single_nul_and_ignores_trailing_bytes() {
        assert_eq!(
            decode_ansi_cstr(b"EAIController0\x00\xc8\x97garbage"),
            "EAIController0"
        );
        assert_eq!(
            decode_ansi_cstr(b"BaseSoldier12\x00x\x1dC\x00h\x00e\x00m\x00i\x00c\x00a\x00l\x00F\x00l\x00a\x00r\x00e\x00"),
            "BaseSoldier12"
        );
        assert_eq!(decode_ansi_cstr(b"EHat6\x00J\x08\xb2\xe0"), "EHat6");
    }

    #[test]
    fn decode_ansi_cstr_handles_empty_unterminated_and_latin1() {
        assert_eq!(decode_ansi_cstr(b"\x00abc"), "");
        assert_eq!(decode_ansi_cstr(b""), "");
        assert_eq!(decode_ansi_cstr(b"ESam0"), "ESam0");
        assert_eq!(decode_ansi_cstr(b"Caf\xe9\x00"), "Café");
    }

    #[test]
    fn resolve_session_paths_separates_concurrent_peers_and_cleans_stale_markers() {
        let dir = std::env::temp_dir().join(format!("scct_session_paths_{}", std::process::id()));
        let sys_dir = dir.join("System");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&sys_dir).unwrap();

        // Stale marker (pid 999999 reported dead) is cleaned up and primary paths are used
        let stale = sys_dir.join(".scct_trace_owner_999999");
        std::fs::write(&stale, b"999999\n").unwrap();
        let (t1, d1, m1) =
            super::resolve_session_paths_with(&dir, crate::trace::PeerRole::Host, 1111, |_| false);
        assert!(!stale.exists());
        assert_eq!(t1, sys_dir.join("scct_startup_trace.txt"));
        assert_eq!(d1, sys_dir.join("scct_desync_dump.txt"));
        assert_eq!(m1, Some(sys_dir.join(".scct_trace_owner_1111")));

        // Second live peer (pid 1111 alive) receives role+pid suffixed paths so it won't overwrite P1
        let (t2, d2, m2) =
            super::resolve_session_paths_with(&dir, crate::trace::PeerRole::Guest, 2222, |p| p == 1111);
        assert_eq!(t2, sys_dir.join("scct_startup_trace_guest_pid2222.txt"));
        assert_eq!(d2, sys_dir.join("scct_desync_dump_guest_pid2222.txt"));
        assert_eq!(m2, None);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
