#[cfg(windows)]
use anyhow::{Result, bail};
#[cfg(not(windows))]
use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use std::path::Path;

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

        // 1. Explicitly zero out inherited socket and keepalive tick locations in .data
        write_proc_bytes(h_process, CAVE_INHERITED_SOCK_9100, &zero, false);
        write_proc_bytes(h_process, CAVE_INHERITED_SOCK_9103, &zero, false);
        write_proc_bytes(h_process, CAVE_INHERITED_PRIMED_9100, &zero, false);
        write_proc_bytes(h_process, CAVE_INHERITED_PRIMED_9103, &zero, false);
        write_proc_bytes(h_process, CAVE_LAST_9103_KEEPALIVE_VA, &zero, false);
        write_proc_bytes(h_process, CAVE_LAST_9100_KEEPALIVE_VA, &zero, false);

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
