use anyhow::{Result, bail};
#[cfg(not(windows))]
use anyhow::Context;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

static SESSION_PATH_LOCK: Mutex<()> = Mutex::new(());

/// Built-in same-PC loopback pair addresses (`127.0.0.2` <-> `127.0.0.3`).
/// Note: `127.0.0.1` (`0x7F000001`) MUST NOT be used because SCCT's `Quazal::InterfaceTable::Build`
/// (`0x10DE5999`) and `GS_LanBroadcast` (`0x10EFBA39`) explicitly skip `127.0.0.1`, leaving an
/// instance bound to `127.0.0.1` with zero Quazal interfaces. Windows routes and binds all of
/// `127.0.0.0/8` natively, so `.2` and `.3` pass `InterfaceTable::Build` cleanly with zero adapters.
pub const LOOPBACK_PAIR_HOST_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
pub const LOOPBACK_PAIR_CLIENT_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);

/// Snapshot of a running `splintercell3.exe` process discovered for live attach / Nucleus Co-op.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunningGameInfo {
    pub pid: u32,
    pub exe_path: Option<PathBuf>,
    /// True if `BindIP.dll` / `BindIP64.dll` (ForceBindIP) is loaded in the process.
    pub has_forcebindip: bool,
    /// True if Nucleus Co-op / ProtoInput hook DLLs are loaded in the process.
    pub has_nucleus_hooks: bool,
    /// True if `splintercell3.exe` in memory contains our patched PE network caves.
    pub has_mod_net_caves: bool,
    /// Current `ONLINE_CAVE` target if enabled in process memory: `(ip, disco_port, game_port)`.
    pub online_target: Option<(Ipv4Addr, u16, u16)>,
    /// Current `G_LOCAL_BIND_IP_VA` in process memory (`None` when `0.0.0.0` / Auto).
    pub local_bind_ip: Option<Ipv4Addr>,
    /// True if startup trace hooks (`0x10A792A6`) are already installed.
    pub has_trace_hooks: bool,
    /// True if persistent quick-save hooks (`0x10B28732`) are already installed.
    pub has_quicksave_hooks: bool,
}

impl RunningGameInfo {
    pub fn summary_line(&self) -> String {
        let mut tags = Vec::new();
        if self.has_forcebindip {
            tags.push("ForceBindIP".to_string());
        }
        if self.has_nucleus_hooks {
            tags.push("Nucleus/ProtoInput".to_string());
        }
        if self.has_mod_net_caves {
            tags.push("ModCaves=OK".to_string());
        } else {
            tags.push("ModCaves=MISSING/OUTDATED".to_string());
        }
        match self.local_bind_ip {
            Some(ip) => tags.push(format!("bind={}", ip)),
            None => tags.push("bind=auto".to_string()),
        }
        if let Some((ip, dport, gport)) = self.online_target {
            tags.push(format!("peer={}:{}/{}", ip, dport, gport));
        } else {
            tags.push("peer=LAN".to_string());
        }
        if self.has_trace_hooks {
            tags.push("TraceHooked".to_string());
        }
        if self.has_quicksave_hooks {
            tags.push("QuickLoadHooked".to_string());
        }
        let path_part = self
            .exe_path
            .as_ref()
            .map(|p| format!(" [{}]", p.display()))
            .unwrap_or_default();
        format!("PID {} ({}){}", self.pid, tags.join(", "), path_part)
    }
}

/// Networking policy when attaching to multi-instance Nucleus Co-op `splintercell3.exe` processes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NucleusNetMode {
    /// Respect Nucleus Co-op's own networking (ForceBindIP / KM-TEST Loopback Adapters / IP Aliasing).
    /// Clears stale online Friend-Code targets and leaves `G_LOCAL_BIND_IP_VA = 0`.
    PreserveNucleusLan,
    /// Built-in same-PC loopback pairing (`127.0.0.2` <-> `127.0.0.3`) via `G_LOCAL_BIND_IP_VA` + `ONLINE_CAVE`.
    /// Requires no ForceBindIP and no virtual network adapters.
    BuiltInLoopbackPair,
    /// Explicit two-IP local pairing (`ip1` <-> `ip2`), e.g. two KM-TEST / Hyper-V / alias IPs.
    ExplicitPair(Ipv4Addr, Ipv4Addr),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachInstancePlan {
    pub role: crate::trace::PeerRole,
    pub direct_peer: Option<DirectPeerTarget>,
    pub local_bind_ip: Option<Ipv4Addr>,
    pub warning: Option<String>,
}

/// Classifies loaded module filenames from a target process into `(has_forcebindip, has_nucleus_hooks)`.
pub fn classify_loaded_module_names(modules: &[String]) -> (bool, bool) {
    let mut has_forcebindip = false;
    let mut has_nucleus_hooks = false;
    for name in modules {
        let low = name.to_ascii_lowercase();
        if low.contains("bindip") || low.contains("forcebindip") {
            has_forcebindip = true;
        }
        if low.contains("protoinput") || low.contains("nucleus") || low.contains("xinputplus") {
            has_nucleus_hooks = true;
        }
    }
    (has_forcebindip, has_nucleus_hooks)
}

/// Parses a pair of distinct non-unspecified IPv4 addresses such as `"192.168.178.202,192.168.178.203"`.
pub fn parse_ip_pair(raw: &str) -> Result<(Ipv4Addr, Ipv4Addr)> {
    let parts: Vec<&str> = raw
        .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .collect();
    if parts.len() != 2 {
        bail!(
            "Expected two IPv4 addresses separated by a comma (e.g. 192.168.178.202,192.168.178.203), got '{}'",
            raw
        );
    }
    let ip1: Ipv4Addr = parts[0]
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid first IPv4 address '{}'", parts[0]))?;
    let ip2: Ipv4Addr = parts[1]
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid second IPv4 address '{}'", parts[1]))?;
    if ip1.is_unspecified() || ip2.is_unspecified() {
        bail!("Pair IPv4 addresses cannot be 0.0.0.0");
    }
    if ip1 == Ipv4Addr::LOCALHOST || ip2 == Ipv4Addr::LOCALHOST {
        bail!(
            "127.0.0.1 cannot be used because SCCT's Quazal::InterfaceTable::Build skips 127.0.0.1; use 127.0.0.2 and 127.0.0.3 instead"
        );
    }
    if ip1 == ip2 {
        bail!(
            "Pair IPv4 addresses must be distinct so both instances can bind ports 9100/9103 (got {} twice)",
            ip1
        );
    }
    Ok((ip1, ip2))
}

/// Computes the per-instance runtime network injection plan for Nucleus Co-op attach.
pub fn plan_nucleus_instance(
    slot_index: usize,
    mode: NucleusNetMode,
    info: &RunningGameInfo,
) -> AttachInstancePlan {
    match mode {
        NucleusNetMode::PreserveNucleusLan => {
            let warning = if slot_index >= 1 && !info.has_forcebindip {
                Some(
                    "ForceBindIP (BindIP.dll) was not detected in this instance. Without per-instance IP isolation, both instances bind 0.0.0.0:9100/9103 and collide! Switch to Built-in Loopback Pair (127.0.0.2 <-> 127.0.0.3) or Custom Adapter IP Pair.".to_string(),
                )
            } else {
                None
            };
            AttachInstancePlan {
                role: crate::trace::PeerRole::LanOrDirect,
                direct_peer: None,
                local_bind_ip: None,
                warning,
            }
        }
        NucleusNetMode::BuiltInLoopbackPair => {
            plan_paired_instance(slot_index, LOOPBACK_PAIR_HOST_IP, LOOPBACK_PAIR_CLIENT_IP, info)
        }
        NucleusNetMode::ExplicitPair(ip1, ip2) => {
            plan_paired_instance(slot_index, ip1, ip2, info)
        }
    }
}

fn plan_paired_instance(
    slot_index: usize,
    ip1: Ipv4Addr,
    ip2: Ipv4Addr,
    info: &RunningGameInfo,
) -> AttachInstancePlan {
    let (role, my_ip, peer_ip) = if slot_index.is_multiple_of(2) {
        (crate::trace::PeerRole::Host, ip1, ip2)
    } else {
        (crate::trace::PeerRole::Guest, ip2, ip1)
    };
    let warning = if info.has_forcebindip {
        Some(format!(
            "BindIP.dll (ForceBindIP) is already loaded in PID {} and may override explicit bind IP {}. Consider using 'Respect Nucleus Network' mode instead when Nucleus handles ForceBindIP.",
            info.pid, my_ip
        ))
    } else {
        None
    };
    AttachInstancePlan {
        role,
        direct_peer: Some(DirectPeerTarget {
            ip: peer_ip,
            disco_port: crate::net::DISCOVERY_PORT,
            game_port: crate::net::GAME_PORT,
        }),
        local_bind_ip: Some(my_ip),
        warning,
    }
}

/// Returns true if a suspended thread's 32-bit `Eip` lies inside any `.text` site we plan to patch.
pub fn eip_intersects_patch_sites(eip: u32, sites: &[(u32, usize)]) -> bool {
    sites.iter().any(|&(va, len)| {
        let end = va.saturating_add(len as u32);
        eip >= va && eip < end
    })
}

/// Prepares `System/splintercell3.exe` on disk for Nucleus Co-op LAN play by clearing any stale
/// Online Friend-Code target left from an earlier Internet session.
/// Returns `Ok(true)` if the EXE was checked/updated on disk, or `Ok(false)` if skipped because
/// `splintercell3.exe` is already running (in which case live attach clears the target in memory).
pub fn prepare_exe_for_nucleus_lan(
    game_root: &Path,
    bypass_checksum_disconnect: bool,
) -> Result<bool> {
    let sys_dir = crate::patcher::find_child_ci(game_root, "System");
    let exe_path = crate::patcher::find_child_ci(&sys_dir, "splintercell3.exe");
    if !exe_path.exists() {
        return Ok(false);
    }
    if !find_running_scct_processes().is_empty() {
        return Ok(false);
    }
    let exe_bak_path = sys_dir.join("splintercell3.exe.bak");
    let cur = std::fs::read(&exe_path)?;
    if !crate::net::is_online_coop_fix_applied(&cur) {
        return Ok(false);
    }
    match crate::net::update_direct_ip_in_exe(&exe_path, &exe_bak_path, None) {
        Ok(()) => {
            crate::net::sync_startup_checksum_bypass_in_exe(&exe_path, bypass_checksum_disconnect)?;
            Ok(true)
        }
        Err(err) => {
            let msg = format!("{:#}", err).to_ascii_lowercase();
            if msg.contains("being used by another process")
                || msg.contains("permission denied")
                || msg.contains("access is denied")
                || msg.contains("os error 32")
                || msg.contains("os error 5")
            {
                Ok(false)
            } else {
                Err(err)
            }
        }
    }
}

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
    child: Option<std::process::Child>,
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
            if let Some(mut child) = self.child.take() {
                let _ = child.wait();
            } else {
                while is_pid_alive(self.pid) {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
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
            if let Some(ref mut child) = self.child {
                matches!(child.try_wait(), Ok(None))
            } else {
                is_pid_alive(self.pid)
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
        let _guard = SESSION_PATH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (trace_path, dump_path, marker) =
            resolve_session_paths_with(game_root, self.peer_role, self.pid, is_pid_alive);
        self.trace_path = Some(trace_path.clone());
        self.dump_path = Some(dump_path.clone());
        self.trace_owner_marker = marker;
        (trace_path, dump_path)
    }

    /// Eagerly claims unique trace/dump paths for this process (avoids filename collisions
    /// when multiple concurrent instances share the same game directory, e.g. Nucleus Co-op).
    pub fn reserve_session_paths(&mut self, game_root: &Path) {
        let _ = self.ensure_session_paths(game_root);
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
unsafe fn read_proc_bytes(
    h_process: windows_sys::Win32::Foundation::HANDLE,
    addr: usize,
    out: &mut [u8],
) -> bool {
    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    let mut bytes_read: usize = 0;
    let ok = unsafe {
        ReadProcessMemory(
            h_process,
            addr as *const _,
            out.as_mut_ptr() as *mut _,
            out.len(),
            &mut bytes_read,
        )
    };
    ok != 0 && bytes_read == out.len()
}

#[cfg(windows)]
fn decode_utf16_nul(slice: &[u16]) -> String {
    let len = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    String::from_utf16_lossy(&slice[..len])
}

#[cfg(windows)]
fn inspect_process_modules(pid: u32) -> Option<(Option<PathBuf>, bool, bool, bool)> {
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_BAD_LENGTH, GetLastError, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE,
        TH32CS_SNAPMODULE32,
    };

    let mut snap = INVALID_HANDLE_VALUE;
    for _ in 0..4 {
        snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
        if snap != INVALID_HANDLE_VALUE {
            break;
        }
        let err = unsafe { GetLastError() };
        if err != ERROR_BAD_LENGTH {
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(15));
    }
    if snap == INVALID_HANDLE_VALUE {
        return None;
    }

    let mut me: MODULEENTRY32W = unsafe { std::mem::zeroed() };
    me.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

    let mut exe_path: Option<PathBuf> = None;
    let mut mod_names: Vec<String> = Vec::new();
    let mut loader_ready = false;

    let mut ok = unsafe { Module32FirstW(snap, &mut me) };
    while ok != 0 {
        let mod_name = decode_utf16_nul(&me.szModule);
        let mod_low = mod_name.to_ascii_lowercase();
        if exe_path.is_none() || mod_low == "splintercell3.exe" {
            let full = decode_utf16_nul(&me.szExePath);
            if !full.is_empty() {
                exe_path = Some(PathBuf::from(full));
            }
        }
        if mod_low == "ws2_32.dll" || mod_low == "kernel32.dll" {
            loader_ready = true;
        }
        mod_names.push(mod_name);
        ok = unsafe { Module32NextW(snap, &mut me) };
    }

    unsafe {
        CloseHandle(snap);
    }

    let (has_forcebindip, has_nucleus_hooks) = classify_loaded_module_names(&mod_names);
    Some((exe_path, has_forcebindip, has_nucleus_hooks, loader_ready))
}

#[cfg(windows)]
unsafe fn inspect_running_game_from_handle(
    pid: u32,
    h_process: windows_sys::Win32::Foundation::HANDLE,
    modules_info: Option<(Option<PathBuf>, bool, bool, bool)>,
) -> RunningGameInfo {
    let (exe_path, has_forcebindip, has_nucleus_hooks, _) =
        modules_info.unwrap_or((None, false, false, false));

    let mut mz = [0u8; 2];
    let has_mz = unsafe { read_proc_bytes(h_process, crate::net::PE_IMAGE_BASE as usize, &mut mz) }
        && &mz == b"MZ";

    let mut net_buf = vec![0u8; crate::net::NET_CAVE_HEX.len() / 2];
    let mut online_head = [0u8; crate::net::ONLINE_CAVE_ENABLED_OFFSET];
    let mut sock_buf = vec![0u8; crate::net::SOCKET_CAVE_HEX.len() / 2];
    let mut multi_buf = vec![0u8; crate::net::MULTI_NIC_LAN_CAVE_HEX.len() / 2];
    let has_mod_net_caves = has_mz
        && unsafe { read_proc_bytes(h_process, crate::net::NET_CAVE_VA as usize, &mut net_buf) }
        && unsafe { read_proc_bytes(h_process, crate::net::ONLINE_CAVE_VA as usize, &mut online_head) }
        && unsafe { read_proc_bytes(h_process, crate::net::SOCKET_CAVE_VA as usize, &mut sock_buf) }
        && unsafe {
            read_proc_bytes(
                h_process,
                crate::net::MULTI_NIC_LAN_CAVE_VA as usize,
                &mut multi_buf,
            )
        }
        && crate::net::is_net_cave_signature_present(&net_buf, &online_head, &sock_buf, &multi_buf);

    let mut online_target = None;
    let mut local_bind_ip = None;
    if has_mod_net_caves {
        let mut en = [0u8; 1];
        if unsafe { read_proc_bytes(h_process, CAVE_ONLINE_ENABLED_VA, &mut en) } && en[0] != 0 {
            let mut ip_b = [0u8; 4];
            let mut dport_b = [0u8; 2];
            let mut gport_b = [0u8; 4];
            if unsafe { read_proc_bytes(h_process, CAVE_ONLINE_IP_VA, &mut ip_b) }
                && unsafe { read_proc_bytes(h_process, CAVE_ONLINE_PORT_VA, &mut dport_b) }
                && unsafe { read_proc_bytes(h_process, JOIN_GAME_PORT_VA, &mut gport_b) }
            {
                online_target = Some((
                    Ipv4Addr::from(ip_b),
                    u16::from_be_bytes(dport_b),
                    u32::from_le_bytes(gport_b) as u16,
                ));
            }
        }
        let mut bind_b = [0u8; 4];
        if unsafe { read_proc_bytes(h_process, CAVE_LOCAL_BIND_IP_VA, &mut bind_b) } {
            let ip = Ipv4Addr::from(bind_b);
            if !ip.is_unspecified() {
                local_bind_ip = Some(ip);
            }
        }
    }

    let mut tick_b = [0u8; 1];
    let has_trace_hooks = has_mz
        && unsafe { read_proc_bytes(h_process, crate::trace::HOOK_TRACE_TICK_VA as usize, &mut tick_b) }
        && tick_b[0] == 0xE9;

    let mut ql_b = [0u8; 1];
    let has_quicksave_hooks = has_mz
        && unsafe {
            read_proc_bytes(
                h_process,
                crate::quicksave_persistence::HOOK_PAUSE_QUICKLOAD_VA as usize,
                &mut ql_b,
            )
        }
        && ql_b[0] == 0xE9;

    RunningGameInfo {
        pid,
        exe_path,
        has_forcebindip,
        has_nucleus_hooks,
        has_mod_net_caves,
        online_target,
        local_bind_ip,
        has_trace_hooks,
        has_quicksave_hooks,
    }
}

/// Inspects a single running `splintercell3.exe` process by PID.
#[cfg(windows)]
pub fn inspect_running_game(pid: u32) -> Option<RunningGameInfo> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
    };

    let mods = inspect_process_modules(pid);
    let h = unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return mods.map(|(exe_path, has_forcebindip, has_nucleus_hooks, _)| RunningGameInfo {
            pid,
            exe_path,
            has_forcebindip,
            has_nucleus_hooks,
            has_mod_net_caves: false,
            online_target: None,
            local_bind_ip: None,
            has_trace_hooks: false,
            has_quicksave_hooks: false,
        });
    }
    let info = unsafe { inspect_running_game_from_handle(pid, h, mods) };
    unsafe {
        CloseHandle(h);
    }
    Some(info)
}

#[cfg(not(windows))]
#[allow(dead_code)]
pub fn inspect_running_game(_pid: u32) -> Option<RunningGameInfo> {
    None
}

/// Returns true once a newly-spawned `splintercell3.exe` has finished initial PE/DLL loading
/// (so ForceBindIP / ProtoInput DLLs are visible and loader locks won't race live attach).
#[cfg(windows)]
pub fn is_process_initialized_for_attach(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
    };

    let Some((_, _, _, loader_ready)) = inspect_process_modules(pid) else {
        return false;
    };
    if !loader_ready {
        return false;
    }
    let h = unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return false;
    }
    let mut mz = [0u8; 2];
    let ok = unsafe { read_proc_bytes(h, crate::net::PE_IMAGE_BASE as usize, &mut mz) } && &mz == b"MZ";
    unsafe {
        CloseHandle(h);
    }
    ok
}

#[cfg(not(windows))]
pub fn is_process_initialized_for_attach(_pid: u32) -> bool {
    false
}

/// Enumerates all currently running `splintercell3.exe` processes sorted ascending by PID.
#[cfg(windows)]
pub fn find_running_scct_processes() -> Vec<RunningGameInfo> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };

    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return Vec::new();
    }

    let mut pids = Vec::new();
    let mut pe: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    let mut ok = unsafe { Process32FirstW(snap, &mut pe) };
    while ok != 0 {
        let exe_name = decode_utf16_nul(&pe.szExeFile);
        if exe_name.eq_ignore_ascii_case("splintercell3.exe") && pe.th32ProcessID != 0 {
            pids.push(pe.th32ProcessID);
        }
        ok = unsafe { Process32NextW(snap, &mut pe) };
    }

    unsafe {
        CloseHandle(snap);
    }

    pids.sort_unstable();
    pids.into_iter()
        .map(|pid| {
            inspect_running_game(pid).unwrap_or(RunningGameInfo {
                pid,
                exe_path: None,
                has_forcebindip: false,
                has_nucleus_hooks: false,
                has_mod_net_caves: false,
                online_target: None,
                local_bind_ip: None,
                has_trace_hooks: false,
                has_quicksave_hooks: false,
            })
        })
        .collect()
}

#[cfg(not(windows))]
pub fn find_running_scct_processes() -> Vec<RunningGameInfo> {
    Vec::new()
}

/// RAII guard that suspends every thread of a running 32-bit WOW64 process, verifies no thread's
/// `Eip` sits inside any `.text` patch window, and unconditionally resumes all threads on drop.
#[cfg(windows)]
struct SuspendedProcessGuard {
    threads: Vec<windows_sys::Win32::Foundation::HANDLE>,
}

#[cfg(windows)]
impl SuspendedProcessGuard {
    unsafe fn acquire(pid: u32, patch_sites: &[(u32, usize)]) -> Result<Self> {
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Diagnostics::Debug::{
            WOW64_CONTEXT, WOW64_CONTEXT_CONTROL, Wow64GetThreadContext,
        };
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
        };
        use windows_sys::Win32::System::Threading::{
            OpenThread, ResumeThread, SuspendThread, THREAD_GET_CONTEXT, THREAD_SUSPEND_RESUME,
            Wow64SuspendThread,
        };

        for attempt in 0..10 {
            let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
            if snap == INVALID_HANDLE_VALUE {
                bail!(
                    "CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) failed: {}",
                    std::io::Error::last_os_error()
                );
            }

            let mut suspended = Vec::new();
            let mut te: THREADENTRY32 = unsafe { std::mem::zeroed() };
            te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

            let mut ok = unsafe { Thread32First(snap, &mut te) };
            while ok != 0 {
                if te.th32OwnerProcessID == pid {
                    let ht = unsafe {
                        OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, 0, te.th32ThreadID)
                    };
                    if !ht.is_null() {
                        let prev = unsafe { Wow64SuspendThread(ht) };
                        let prev = if prev == u32::MAX {
                            unsafe { SuspendThread(ht) }
                        } else {
                            prev
                        };
                        if prev != u32::MAX {
                            suspended.push(ht);
                        } else {
                            unsafe {
                                CloseHandle(ht);
                            }
                        }
                    }
                }
                ok = unsafe { Thread32Next(snap, &mut te) };
            }

            unsafe {
                CloseHandle(snap);
            }

            let mut collision = false;
            if !patch_sites.is_empty() {
                for &ht in &suspended {
                    let mut ctx: WOW64_CONTEXT = unsafe { std::mem::zeroed() };
                    ctx.ContextFlags = WOW64_CONTEXT_CONTROL;
                    if unsafe { Wow64GetThreadContext(ht, &mut ctx) } != 0
                        && eip_intersects_patch_sites(ctx.Eip, patch_sites)
                    {
                        collision = true;
                        break;
                    }
                }
            }

            if !collision || attempt == 9 {
                return Ok(Self { threads: suspended });
            }

            for ht in suspended {
                unsafe {
                    ResumeThread(ht);
                    CloseHandle(ht);
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }

        Ok(Self {
            threads: Vec::new(),
        })
    }
}

#[cfg(windows)]
impl Drop for SuspendedProcessGuard {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::ResumeThread;
        for ht in self.threads.drain(..) {
            unsafe {
                ResumeThread(ht);
                CloseHandle(ht);
            }
        }
    }
}

#[cfg(windows)]
unsafe fn apply_runtime_patches_to_process(
    h_process: windows_sys::Win32::Foundation::HANDLE,
    direct_peer: Option<DirectPeerTarget>,
    local_bind_ip: Option<Ipv4Addr>,
    opts: LaunchRuntimeOptions,
    has_mod_net_caves: bool,
    is_live_attach: bool,
) -> usize {
    use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;

    unsafe {
        let zero = 0u32.to_le_bytes();

        if has_mod_net_caves && (opts.install_trace_hooks || opts.auto_resync || opts.monitor_desync_dump) {
            write_proc_bytes(h_process, CAVE_DESYNC_FLAG_VA, &[0u8; 8], false);
        }

        // 1. Explicitly zero out inherited socket and keepalive tick locations in .data on fresh launch
        //    (avoid clearing live keepalive timestamps when re-attaching unless caves are present).
        if has_mod_net_caves && opts.inject_lan_net_globals && !is_live_attach {
            write_proc_bytes(h_process, CAVE_INHERITED_SOCK_9100, &zero, false);
            write_proc_bytes(h_process, CAVE_INHERITED_SOCK_9103, &zero, false);
            write_proc_bytes(h_process, CAVE_INHERITED_PRIMED_9100, &zero, false);
            write_proc_bytes(h_process, CAVE_INHERITED_PRIMED_9103, &zero, false);
            write_proc_bytes(h_process, CAVE_LAST_9103_KEEPALIVE_VA, &zero, false);
            write_proc_bytes(h_process, CAVE_LAST_9100_KEEPALIVE_VA, &zero, false);
        }

        // 2. Configure ONLINE_CAVE, JOIN_GAME_PORT_VA, CAVE_LAN_PEER_VA, and CAVE_LOCAL_BIND_IP_VA
        if has_mod_net_caves {
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

        let _ = FlushInstructionCache(h_process, std::ptr::null(), 0);
        trace_buf_va
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
        let trace_va = apply_runtime_patches_to_process(
            h_process,
            direct_peer,
            local_bind_ip,
            opts,
            true,
            false,
        );
        // Resume the game thread
        ResumeThread(h_thread);
        CloseHandle(h_thread);
        trace_va
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

/// Attaches to an already-running `splintercell3.exe` process (e.g. launched by Nucleus Co-op,
/// Steam, or another external launcher), briefly suspends its threads to patch runtime network
/// globals and hooks safely, then resumes execution and returns a live `GameProcess` handle.
#[cfg(windows)]
pub fn attach_game(
    pid: u32,
    peer_role: crate::trace::PeerRole,
    direct_peer: Option<DirectPeerTarget>,
    local_bind_ip: Option<Ipv4Addr>,
    opts: LaunchRuntimeOptions,
) -> Result<(GameProcess, RunningGameInfo)> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_VM_OPERATION,
        PROCESS_VM_READ, PROCESS_VM_WRITE,
    };

    let desired_access = PROCESS_VM_READ
        | PROCESS_VM_WRITE
        | PROCESS_VM_OPERATION
        | PROCESS_QUERY_INFORMATION
        | PROCESS_SYNCHRONIZE;
    let h_process = unsafe { OpenProcess(desired_access, 0, pid) };
    if h_process.is_null() {
        let os_err = std::io::Error::last_os_error();
        if os_err.raw_os_error() == Some(5) {
            bail!(
                "Access denied opening splintercell3.exe (PID {}). If Nucleus Co-op is running as Administrator, run scct_coop_enhancer as Administrator too.",
                pid
            );
        }
        bail!("OpenProcess failed for PID {}: {}", pid, os_err);
    }

    let modules_info = inspect_process_modules(pid);
    let info = unsafe { inspect_running_game_from_handle(pid, h_process, modules_info) };

    let mut mz = [0u8; 2];
    if !unsafe { read_proc_bytes(h_process, crate::net::PE_IMAGE_BASE as usize, &mut mz) }
        || &mz != b"MZ"
    {
        unsafe {
            CloseHandle(h_process);
        }
        bail!(
            "PID {} does not have retail splintercell3.exe mapped at 0x{:08X} (process may still be initializing or is a different binary)",
            pid,
            crate::net::PE_IMAGE_BASE
        );
    }

    let mut patch_sites: Vec<(u32, usize)> = Vec::new();
    if info.has_mod_net_caves && opts.inject_nat_direct_target {
        patch_sites.push((crate::net::CAVE_ONLINE_ENABLED_VA, 1));
        patch_sites.push((crate::net::CAVE_ONLINE_IP_VA, 4));
        patch_sites.push((crate::net::CAVE_ONLINE_PORT_VA, 2));
        patch_sites.push((crate::net::JOIN_GAME_PORT_VA, 4));
    }
    if opts.install_trace_hooks || opts.auto_resync {
        patch_sites.push((
            crate::trace::HOOK_TRACE_RESET_VA,
            crate::trace::HOOK_TRACE_RESET_ORIG.len(),
        ));
        patch_sites.push((
            crate::trace::HOOK_TRACE_TICK_VA,
            crate::trace::HOOK_TRACE_TICK_ORIG.len(),
        ));
        patch_sites.push((
            crate::trace::HOOK_TRACE_SEND_VA,
            crate::trace::HOOK_TRACE_SEND_ORIG.len(),
        ));
        patch_sites.push((
            crate::trace::HOOK_TRACE_CMP_VA,
            crate::trace::HOOK_TRACE_CMP_ORIG.len(),
        ));
    }
    if opts.enable_persistent_quicksave_load {
        patch_sites.push((
            crate::quicksave_persistence::HOOK_PAUSE_QUICKLOAD_VA,
            crate::quicksave_persistence::HOOK_PAUSE_QUICKLOAD_ORIG.len(),
        ));
        patch_sites.push((
            crate::quicksave_persistence::HOOK_GAMEOVER_QUICKLOAD_VA,
            crate::quicksave_persistence::HOOK_GAMEOVER_QUICKLOAD_ORIG.len(),
        ));
        patch_sites.push((
            crate::quicksave_persistence::HOOK_COOP_QUICKLOAD_LEN_VA,
            crate::quicksave_persistence::HOOK_COOP_QUICKLOAD_LEN_ORIG.len(),
        ));
    }

    let trace_buf_va = {
        let _suspend_guard = match unsafe { SuspendedProcessGuard::acquire(pid, &patch_sites) } {
            Ok(g) => g,
            Err(e) => {
                unsafe {
                    CloseHandle(h_process);
                }
                return Err(e);
            }
        };
        unsafe {
            apply_runtime_patches_to_process(
                h_process,
                direct_peer,
                local_bind_ip,
                opts,
                info.has_mod_net_caves,
                true,
            )
        }
    };

    let peer_ip = direct_peer.map(|p| p.ip);
    let resync_coord = if opts.auto_resync {
        match crate::resync::ResyncCoordinator::new(peer_role, peer_ip, local_bind_ip) {
            Ok(coord) => Some(coord),
            Err(e) => {
                crate::scct_log!("  [RESYNC] Disabled for PID {} (UDP socket init failed: {:#})", pid, e);
                None
            }
        }
    } else {
        None
    };

    let updated_info =
        unsafe { inspect_running_game_from_handle(pid, h_process, inspect_process_modules(pid)) };

    Ok((
        GameProcess {
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
        },
        updated_info,
    ))
}

/// Re-applies runtime network target/bind globals (`ONLINE_CAVE`, `JOIN_GAME_PORT_VA`,
/// `G_LAN_PEER_VA`, `G_LOCAL_BIND_IP_VA`) in-place on an already-attached `splintercell3.exe`
/// process without spawning a duplicate monitor thread or reinstalling hooks.
#[cfg(windows)]
pub fn reconfigure_running_game_network(
    pid: u32,
    direct_peer: Option<DirectPeerTarget>,
    local_bind_ip: Option<Ipv4Addr>,
    opts: LaunchRuntimeOptions,
) -> Result<RunningGameInfo> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
        PROCESS_VM_WRITE,
    };

    let desired_access =
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;
    let h_process = unsafe { OpenProcess(desired_access, 0, pid) };
    if h_process.is_null() {
        let os_err = std::io::Error::last_os_error();
        if os_err.raw_os_error() == Some(5) {
            bail!(
                "Access denied opening splintercell3.exe (PID {}). If Nucleus Co-op is running as Administrator, run scct_coop_enhancer as Administrator too.",
                pid
            );
        }
        bail!("OpenProcess failed for PID {}: {}", pid, os_err);
    }

    let modules_info = inspect_process_modules(pid);
    let info = unsafe { inspect_running_game_from_handle(pid, h_process, modules_info) };

    let mut patch_sites: Vec<(u32, usize)> = Vec::new();
    if info.has_mod_net_caves && opts.inject_nat_direct_target {
        patch_sites.push((crate::net::CAVE_ONLINE_ENABLED_VA, 1));
        patch_sites.push((crate::net::CAVE_ONLINE_IP_VA, 4));
        patch_sites.push((crate::net::CAVE_ONLINE_PORT_VA, 2));
        patch_sites.push((crate::net::JOIN_GAME_PORT_VA, 4));
    }

    let net_only_opts = LaunchRuntimeOptions {
        install_trace_hooks: false,
        monitor_desync_dump: false,
        auto_resync: false,
        enable_persistent_quicksave_load: false,
        inject_lan_net_globals: opts.inject_lan_net_globals,
        inject_nat_direct_target: opts.inject_nat_direct_target,
    };

    {
        let _suspend_guard = match unsafe { SuspendedProcessGuard::acquire(pid, &patch_sites) } {
            Ok(g) => g,
            Err(e) => {
                unsafe {
                    CloseHandle(h_process);
                }
                return Err(e);
            }
        };
        unsafe {
            let _ = apply_runtime_patches_to_process(
                h_process,
                direct_peer,
                local_bind_ip,
                net_only_opts,
                info.has_mod_net_caves,
                true,
            );
        }
    }

    let updated_info =
        unsafe { inspect_running_game_from_handle(pid, h_process, inspect_process_modules(pid)) };
    unsafe {
        CloseHandle(h_process);
    }
    Ok(updated_info)
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
        child: Some(child),
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

#[cfg(not(windows))]
pub fn attach_game(
    pid: u32,
    _peer_role: crate::trace::PeerRole,
    _direct_peer: Option<DirectPeerTarget>,
    _local_bind_ip: Option<Ipv4Addr>,
    _opts: LaunchRuntimeOptions,
) -> Result<(GameProcess, RunningGameInfo)> {
    bail!(
        "Live process attach (PID {}) is only supported on Windows (where splintercell3.exe runs natively)",
        pid
    )
}

#[cfg(not(windows))]
pub fn reconfigure_running_game_network(
    pid: u32,
    _direct_peer: Option<DirectPeerTarget>,
    _local_bind_ip: Option<Ipv4Addr>,
    _opts: LaunchRuntimeOptions,
) -> Result<RunningGameInfo> {
    bail!(
        "Live process reconfigure (PID {}) is only supported on Windows (where splintercell3.exe runs natively)",
        pid
    )
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

    #[test]
    fn classify_loaded_module_names_detects_forcebindip_and_nucleus() {
        let mods = vec![
            "splintercell3.exe".to_string(),
            "BindIP.dll".to_string(),
            "ProtoInputHooks32.dll".to_string(),
            "ws2_32.dll".to_string(),
        ];
        assert_eq!(super::classify_loaded_module_names(&mods), (true, true));

        let plain = vec!["splintercell3.exe".to_string(), "ws2_32.dll".to_string()];
        assert_eq!(super::classify_loaded_module_names(&plain), (false, false));
    }

    #[test]
    fn parse_ip_pair_validates_format_and_distinctness() {
        assert_eq!(
            super::parse_ip_pair("192.168.178.202, 192.168.178.203").unwrap(),
            (
                std::net::Ipv4Addr::new(192, 168, 178, 202),
                std::net::Ipv4Addr::new(192, 168, 178, 203),
            )
        );
        assert!(super::parse_ip_pair("192.168.1.10,192.168.1.10").is_err());
        assert!(super::parse_ip_pair("0.0.0.0,192.168.1.10").is_err());
        assert!(super::parse_ip_pair("127.0.0.1,127.0.0.2").is_err());
        assert_eq!(
            super::parse_ip_pair("127.0.0.2,127.0.0.3").unwrap(),
            (
                std::net::Ipv4Addr::new(127, 0, 0, 2),
                std::net::Ipv4Addr::new(127, 0, 0, 3),
            )
        );
        assert!(super::parse_ip_pair("192.168.1.10").is_err());
    }

    #[test]
    fn plan_nucleus_instance_handles_all_three_modes() {
        let base_info = super::RunningGameInfo {
            pid: 4242,
            exe_path: None,
            has_forcebindip: false,
            has_nucleus_hooks: true,
            has_mod_net_caves: true,
            online_target: None,
            local_bind_ip: None,
            has_trace_hooks: false,
            has_quicksave_hooks: false,
        };

        // 1. PreserveNucleusLan clears online target and leaves local_bind_ip = None
        let p0 = super::plan_nucleus_instance(0, super::NucleusNetMode::PreserveNucleusLan, &base_info);
        assert_eq!(p0.direct_peer, None);
        assert_eq!(p0.local_bind_ip, None);
        assert!(p0.warning.is_none());

        let p1 = super::plan_nucleus_instance(1, super::NucleusNetMode::PreserveNucleusLan, &base_info);
        assert_eq!(p1.direct_peer, None);
        assert_eq!(p1.local_bind_ip, None);
        assert!(p1.warning.is_some()); // warns ForceBindIP not detected on 2nd instance

        let fb_info = super::RunningGameInfo {
            has_forcebindip: true,
            ..base_info.clone()
        };
        let p1_fb = super::plan_nucleus_instance(1, super::NucleusNetMode::PreserveNucleusLan, &fb_info);
        assert!(p1_fb.warning.is_none());

        // 2. BuiltInLoopbackPair assigns 127.0.0.2 <-> 127.0.0.3 symmetrically (avoiding 127.0.0.1!)
        assert_eq!(super::LOOPBACK_PAIR_HOST_IP, std::net::Ipv4Addr::new(127, 0, 0, 2));
        assert_eq!(super::LOOPBACK_PAIR_CLIENT_IP, std::net::Ipv4Addr::new(127, 0, 0, 3));
        let lb0 = super::plan_nucleus_instance(0, super::NucleusNetMode::BuiltInLoopbackPair, &base_info);
        let lb1 = super::plan_nucleus_instance(1, super::NucleusNetMode::BuiltInLoopbackPair, &base_info);
        assert_eq!(lb0.role, crate::trace::PeerRole::Host);
        assert_eq!(lb0.local_bind_ip, Some(super::LOOPBACK_PAIR_HOST_IP));
        assert_eq!(lb0.direct_peer.unwrap().ip, super::LOOPBACK_PAIR_CLIENT_IP);
        assert_eq!(lb1.role, crate::trace::PeerRole::Guest);
        assert_eq!(lb1.local_bind_ip, Some(super::LOOPBACK_PAIR_CLIENT_IP));
        assert_eq!(lb1.direct_peer.unwrap().ip, super::LOOPBACK_PAIR_HOST_IP);
        assert!(lb0.warning.is_none());

        let summary_with_net = super::RunningGameInfo {
            local_bind_ip: Some(super::LOOPBACK_PAIR_HOST_IP),
            online_target: Some((super::LOOPBACK_PAIR_CLIENT_IP, 9100, 9103)),
            ..base_info.clone()
        }
        .summary_line();
        assert!(summary_with_net.contains("bind=127.0.0.2"));
        assert!(summary_with_net.contains("peer=127.0.0.3:9100/9103"));

        // Warns if ForceBindIP is already injected when BuiltInLoopbackPair is selected
        let lb_fb = super::plan_nucleus_instance(0, super::NucleusNetMode::BuiltInLoopbackPair, &fb_info);
        assert!(lb_fb.warning.is_some());

        // 3. ExplicitPair assigns ip1 <-> ip2
        let ip1 = std::net::Ipv4Addr::new(10, 0, 0, 1);
        let ip2 = std::net::Ipv4Addr::new(10, 0, 0, 2);
        let ex0 = super::plan_nucleus_instance(0, super::NucleusNetMode::ExplicitPair(ip1, ip2), &base_info);
        let ex1 = super::plan_nucleus_instance(1, super::NucleusNetMode::ExplicitPair(ip1, ip2), &base_info);
        assert_eq!(ex0.local_bind_ip, Some(ip1));
        assert_eq!(ex0.direct_peer.unwrap().ip, ip2);
        assert_eq!(ex1.local_bind_ip, Some(ip2));
        assert_eq!(ex1.direct_peer.unwrap().ip, ip1);
    }

    #[test]
    fn eip_intersects_patch_sites_checks_half_open_bounds() {
        let sites = [(0x10A7_92A6u32, 6usize), (0x10DF_86BAu32, 6usize)];
        assert!(!super::eip_intersects_patch_sites(0x10A7_92A5, &sites));
        assert!(super::eip_intersects_patch_sites(0x10A7_92A6, &sites));
        assert!(super::eip_intersects_patch_sites(0x10A7_92AB, &sites));
        assert!(!super::eip_intersects_patch_sites(0x10A7_92AC, &sites));
        assert!(super::eip_intersects_patch_sites(0x10DF_86BC, &sites));
    }
}
