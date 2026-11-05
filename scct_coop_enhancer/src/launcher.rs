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
pub const CAVE_DIRECT_IP_U32: usize = 0x113303A4;
pub const CAVE_DIRECT_IP_ENABLED: usize = 0x113303A8;

#[cfg(windows)]
pub fn launch_game_with_inherited_sockets(
    exe_path: &Path,
    game_dir: &Path,
    sock_disco: &std::net::UdpSocket,
    sock_game: &std::net::UdpSocket,
    peer_ip: Option<Ipv4Addr>,
) -> Result<u32> {
    use std::ffi::CString;
    use std::os::windows::io::AsRawSocket;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation, TRUE};
    use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows_sys::Win32::System::Threading::{
        CreateProcessA, ResumeThread, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOA,
    };

    let raw_disco = sock_disco.as_raw_socket();
    let raw_game = sock_game.as_raw_socket();

    // 1. Mark socket handles as inheritable
    unsafe {
        SetHandleInformation(
            raw_disco as HANDLE,
            HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT,
        );
        SetHandleInformation(
            raw_game as HANDLE,
            HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT,
        );
    }

    let exe_str = CString::new(exe_path.to_string_lossy().as_bytes())?;
    let dir_str = CString::new(game_dir.to_string_lossy().as_bytes())?;

    let mut si: STARTUPINFOA = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // 2. Spawn suspended process with bInheritHandles = TRUE
    let success = unsafe {
        CreateProcessA(
            exe_str.as_ptr() as *const u8,
            null_mut(),
            null_mut(),
            null_mut(),
            TRUE, // bInheritHandles = TRUE
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

    // 3. Inject socket descriptors and primed flags into the game's .data cave
    let disco_u32 = raw_disco as u32;
    let game_u32 = raw_game as u32;
    let primed: u32 = 1;

    unsafe {
        let mut written = 0;
        WriteProcessMemory(
            h_process,
            CAVE_INHERITED_SOCK_9100 as *mut _,
            &disco_u32 as *const _ as *const _,
            4,
            &mut written,
        );
        WriteProcessMemory(
            h_process,
            CAVE_INHERITED_SOCK_9103 as *mut _,
            &game_u32 as *const _ as *const _,
            4,
            &mut written,
        );
        WriteProcessMemory(
            h_process,
            CAVE_INHERITED_PRIMED_9100 as *mut _,
            &primed as *const _ as *const _,
            4,
            &mut written,
        );
        WriteProcessMemory(
            h_process,
            CAVE_INHERITED_PRIMED_9103 as *mut _,
            &primed as *const _ as *const _,
            4,
            &mut written,
        );

        if let Some(ip) = peer_ip {
            let ip_u32 = u32::from_ne_bytes(ip.octets());
            let enabled: u32 = 1;
            WriteProcessMemory(
                h_process,
                CAVE_DIRECT_IP_U32 as *mut _,
                &ip_u32 as *const _ as *const _,
                4,
                &mut written,
            );
            WriteProcessMemory(
                h_process,
                CAVE_DIRECT_IP_ENABLED as *mut _,
                &enabled as *const _ as *const _,
                4,
                &mut written,
            );
        }

        // 4. Resume the game thread
        ResumeThread(h_thread);
        CloseHandle(h_thread);
        CloseHandle(h_process);
    }

    Ok(pid)
}

#[cfg(not(windows))]
pub fn launch_game_with_inherited_sockets(
    exe_path: &Path,
    game_dir: &Path,
    _sock_disco: &std::net::UdpSocket,
    _sock_game: &std::net::UdpSocket,
    peer_ip: Option<Ipv4Addr>,
) -> Result<u32> {
    // If peer_ip provided, save to direct_ip.ini
    if let Some(ip) = peer_ip {
        let sys_dir = crate::patcher::find_child_ci(game_dir, "System");
        let ini_path = sys_dir.join("direct_ip.ini");
        let _ = crate::net::save_direct_ip_ini(&ini_path, Some(ip));
    }

    let child = std::process::Command::new(exe_path)
        .current_dir(game_dir)
        .spawn()
        .with_context(|| format!("Launching {}", exe_path.display()))?;

    Ok(child.id())
}
