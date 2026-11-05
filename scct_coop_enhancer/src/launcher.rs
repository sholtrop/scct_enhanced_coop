#[cfg(windows)]
use anyhow::bail;
#[cfg(not(windows))]
use anyhow::Context;
use anyhow::Result;
use std::net::Ipv4Addr;
use std::path::Path;

pub const CAVE_INHERITED_SOCK_9100: usize = 0x113303D0;
pub const CAVE_INHERITED_SOCK_9103: usize = 0x113303D4;
pub const CAVE_INHERITED_PRIMED_9100: usize = 0x113303D8;
pub const CAVE_INHERITED_PRIMED_9103: usize = 0x113303DC;

pub const CAVE_ONLINE_ENABLED_VA: usize = 0x110B6760;
pub const CAVE_ONLINE_IP_VA: usize = 0x110B678B;

#[cfg(windows)]
pub fn launch_game(
    exe_path: &Path,
    game_dir: &Path,
    peer_ip: Option<Ipv4Addr>,
) -> Result<u32> {
    use std::ffi::CString;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{CloseHandle, FALSE};
    use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows_sys::Win32::System::Threading::{
        CreateProcessA, ResumeThread, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOA,
    };

    // Always update direct_ip.ini in System folder
    let sys_dir = crate::patcher::find_child_ci(game_dir, "System");
    let ini_path = sys_dir.join("direct_ip.ini");
    let _ = crate::net::save_direct_ip_ini(&ini_path, peer_ip);

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
        let mut written = 0;
        let zero: u32 = 0;

        // 1. Explicitly zero out inherited socket locations so cave hooks ALWAYS
        // use native Winsock socket() and bind() calls inside splintercell3.exe.
        WriteProcessMemory(
            h_process,
            CAVE_INHERITED_SOCK_9100 as *mut _,
            &zero as *const _ as *const _,
            4,
            &mut written,
        );
        WriteProcessMemory(
            h_process,
            CAVE_INHERITED_SOCK_9103 as *mut _,
            &zero as *const _ as *const _,
            4,
            &mut written,
        );
        WriteProcessMemory(
            h_process,
            CAVE_INHERITED_PRIMED_9100 as *mut _,
            &zero as *const _ as *const _,
            4,
            &mut written,
        );
        WriteProcessMemory(
            h_process,
            CAVE_INHERITED_PRIMED_9103 as *mut _,
            &zero as *const _ as *const _,
            4,
            &mut written,
        );

        // 2. Configure ONLINE_CAVE for direct IP replication if peer_ip is set
        if let Some(ip) = peer_ip {
            let enabled: u8 = 1;
            let ip_bytes = ip.octets();
            WriteProcessMemory(
                h_process,
                CAVE_ONLINE_ENABLED_VA as *mut _,
                &enabled as *const _ as *const _,
                1,
                &mut written,
            );
            WriteProcessMemory(
                h_process,
                CAVE_ONLINE_IP_VA as *mut _,
                ip_bytes.as_ptr() as *const _,
                4,
                &mut written,
            );
        } else {
            let disabled: u8 = 0;
            let zero_ip = [0u8; 4];
            WriteProcessMemory(
                h_process,
                CAVE_ONLINE_ENABLED_VA as *mut _,
                &disabled as *const _ as *const _,
                1,
                &mut written,
            );
            WriteProcessMemory(
                h_process,
                CAVE_ONLINE_IP_VA as *mut _,
                zero_ip.as_ptr() as *const _,
                4,
                &mut written,
            );
        }

        // 3. Resume the game thread
        ResumeThread(h_thread);
        CloseHandle(h_thread);
        CloseHandle(h_process);
    }

    Ok(pid)
}

#[cfg(not(windows))]
pub fn launch_game(
    exe_path: &Path,
    game_dir: &Path,
    peer_ip: Option<Ipv4Addr>,
) -> Result<u32> {
    let sys_dir = crate::patcher::find_child_ci(game_dir, "System");
    let ini_path = sys_dir.join("direct_ip.ini");
    let _ = crate::net::save_direct_ip_ini(&ini_path, peer_ip);

    let child = std::process::Command::new(exe_path)
        .current_dir(game_dir)
        .spawn()
        .with_context(|| format!("Launching {}", exe_path.display()))?;

    Ok(child.id())
}

#[allow(dead_code)]
pub fn launch_game_with_inherited_sockets(
    exe_path: &Path,
    game_dir: &Path,
    _sock_disco: &std::net::UdpSocket,
    _sock_game: &std::net::UdpSocket,
    peer_ip: Option<Ipv4Addr>,
) -> Result<u32> {
    launch_game(exe_path, game_dir, peer_ip)
}
