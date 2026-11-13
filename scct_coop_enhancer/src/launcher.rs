#[cfg(windows)]
use anyhow::bail;
use anyhow::Result;
#[cfg(not(windows))]
use anyhow::Context;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

pub const CAVE_DESYNC_FLAG_VA: usize = crate::net::CAVE_DESYNC_FLAG_VA as usize;
pub const VA_GENGINE: usize = 0x111F5554;
pub const VA_SYNC_ENGINE: usize = 0x111F55A4;
pub const VA_USER_CHECKSUM_0: usize = 0x111F5F14;
pub const VA_WARMUP_FLAG: usize = 0x111F55E0;
pub const VA_GNAMES: usize = 0x1130DFC0;
pub const VA_GNAMES_COUNT: usize = 0x1130DFBC;

pub struct GameProcess {
    pub pid: u32,
    #[cfg(windows)]
    handle_val: usize,
    #[cfg(not(windows))]
    child: std::process::Child,
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

    pub fn read_string(&self, addr: usize, max_len: usize) -> Option<String> {
        let mut buf = vec![0u8; max_len];
        if !self.read_memory(addr, &mut buf) {
            return None;
        }
        let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        Some(String::from_utf8_lossy(&buf[..len]).to_string())
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

        let gnames_ptr = self.read_u32(VA_GNAMES).unwrap_or(0);
        let gnames_count = self.read_u32(VA_GNAMES_COUNT).unwrap_or(0);

        let gengine_ptr = self.read_u32(VA_GENGINE).unwrap_or(0);
        let level_context = if gengine_ptr != 0 {
            self.read_u32(gengine_ptr as usize + 0x44).unwrap_or(0)
        } else {
            0
        };
        let level_ptr_ptr = if level_context != 0 {
            self.read_u32(level_context as usize + 0x2C).unwrap_or(0)
        } else {
            0
        };
        let level_ptr = if level_ptr_ptr != 0 {
            self.read_u32(level_ptr_ptr as usize).unwrap_or(0)
        } else {
            0
        };

        let mut lines = Vec::new();
        lines.push("================================================================================".to_string());
        lines.push("            SCCT CO-OP ENHANCER - DESYNC DIAGNOSTIC STATE DUMP                 ".to_string());
        lines.push("================================================================================".to_string());
        lines.push(format!("SyncEngine VA:          0x{:08X}", sync_engine_ptr));
        lines.push(format!("Simulation Step:        {}", step));
        lines.push(format!("Simulation Status:      {} (0x{:08X})", status, status));
        lines.push(format!("UserChecksum0:          0x{:08X}", user_checksum));
        lines.push(format!("WarmupFlag (0x111F55E0): {}", warmup_flag));
        lines.push(format!("GEngine VA:             0x{:08X}", gengine_ptr));
        lines.push(format!("LevelContext VA:        0x{:08X}", level_context));
        lines.push(format!("GLevel VA:              0x{:08X}", level_ptr));
        lines.push(format!("GNames VA:              0x{:08X} (Count: {})", gnames_ptr, gnames_count));
        lines.push("--------------------------------------------------------------------------------".to_string());
        lines.push(format!(
            "{:<6} {:<24} {:<10} {:<30} {:<24} {:<30} {:<10} {:<6}",
            "Index", "Actor Name", "Ptr", "Location (X, Y, Z)", "Rotation (P, Y, R)", "Velocity (X, Y, Z)", "Flags", "Ticked"
        ));
        lines.push("--------------------------------------------------------------------------------".to_string());

        if level_ptr != 0 {
            let actors_data_ptr = self.read_u32(level_ptr as usize + 0x11C).unwrap_or(0);
            let raw_count = self.read_i32(level_ptr as usize + 0x120).unwrap_or(0);
            let count = raw_count.clamp(0, 4096);

            for i in 0..count {
                let actor_ptr = if actors_data_ptr != 0 {
                    self.read_u32(actors_data_ptr as usize + (i as usize) * 4).unwrap_or(0)
                } else {
                    0
                };

                if actor_ptr == 0 {
                    continue;
                }

                let name_idx = self.read_u32(actor_ptr as usize + 0x20).unwrap_or(0);
                let name_num = self.read_i32(actor_ptr as usize + 0x24).unwrap_or(0);

                let base_name = if gnames_ptr != 0 && name_idx < gnames_count {
                    let entry_ptr = self.read_u32(gnames_ptr as usize + (name_idx as usize) * 4).unwrap_or(0);
                    if entry_ptr != 0 {
                        self.read_string(entry_ptr as usize + 0x0C, 64)
                            .unwrap_or_else(|| format!("Name_{}", name_idx))
                    } else {
                        format!("Name_{}", name_idx)
                    }
                } else {
                    format!("Name_{}", name_idx)
                };

                let actor_name = if name_num > 0 {
                    format!("{}_{}", base_name, name_num - 1)
                } else {
                    base_name
                };

                let loc_x = self.read_f32(actor_ptr as usize + 0xE8).unwrap_or(0.0);
                let loc_y = self.read_f32(actor_ptr as usize + 0xEC).unwrap_or(0.0);
                let loc_z = self.read_f32(actor_ptr as usize + 0xF0).unwrap_or(0.0);

                let rot_p = self.read_i32(actor_ptr as usize + 0xF4).unwrap_or(0);
                let rot_y = self.read_i32(actor_ptr as usize + 0xF8).unwrap_or(0);
                let rot_r = self.read_i32(actor_ptr as usize + 0xFC).unwrap_or(0);

                let vel_x = self.read_f32(actor_ptr as usize + 0x100).unwrap_or(0.0);
                let vel_y = self.read_f32(actor_ptr as usize + 0x104).unwrap_or(0.0);
                let vel_z = self.read_f32(actor_ptr as usize + 0x108).unwrap_or(0.0);

                let flags = self.read_u32(actor_ptr as usize + 0x28).unwrap_or(0);
                let ticked = self.read_u8(actor_ptr as usize + 0xB4).unwrap_or(0);

                let loc_str = format!("({:.2}, {:.2}, {:.2})", loc_x, loc_y, loc_z);
                let rot_str = format!("({}, {}, {})", rot_p, rot_y, rot_r);
                let vel_str = format!("({:.2}, {:.2}, {:.2})", vel_x, vel_y, vel_z);

                lines.push(format!(
                    "[{:<4}] {:<24} 0x{:08X} {:<30} {:<24} {:<30} 0x{:08X} {:<6}",
                    i, actor_name, actor_ptr, loc_str, rot_str, vel_str, flags, ticked
                ));
            }
        } else {
            lines.push("  [WARNING] GLevel was null or could not be read".to_string());
        }

        lines.push("================================================================================".to_string());
        lines.push("Instructions: Both players should compare this file using a diff tool (e.g. diff,".to_string());
        lines.push("VS Code, Meld, WinMerge). Any actor with different Location, Rotation, Velocity,".to_string());
        lines.push("or Flags indicates where the simulation diverged between Host and Guest.".to_string());
        lines.push("================================================================================".to_string());

        let content = lines.join("\n");
        std::fs::write(&dump_path, content)?;

        Ok(dump_path)
    }

    pub fn wait_for_exit_monitoring_desync(mut self, game_root: &Path) {
        let mut desync_dumped = false;
        while self.is_alive() {
            if !desync_dumped && self.is_desync_flagged() {
                desync_dumped = true;
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

    unsafe {
        let zero = 0u32.to_le_bytes();

        // 1. Explicitly zero out inherited socket, keepalive tick, and desync flag locations in .data
        write_proc_bytes(h_process, CAVE_INHERITED_SOCK_9100, &zero, false);
        write_proc_bytes(h_process, CAVE_INHERITED_SOCK_9103, &zero, false);
        write_proc_bytes(h_process, CAVE_INHERITED_PRIMED_9100, &zero, false);
        write_proc_bytes(h_process, CAVE_INHERITED_PRIMED_9103, &zero, false);
        write_proc_bytes(h_process, CAVE_LAST_9103_KEEPALIVE_VA, &zero, false);
        write_proc_bytes(h_process, CAVE_LAST_9100_KEEPALIVE_VA, &zero, false);
        write_proc_bytes(h_process, CAVE_DESYNC_FLAG_VA, &[0u8], false);

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

        // 3. Resume the game thread
        ResumeThread(h_thread);
        CloseHandle(h_thread);
    }

    Ok(GameProcess {
        pid,
        handle_val: h_process as usize,
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
    })
}
