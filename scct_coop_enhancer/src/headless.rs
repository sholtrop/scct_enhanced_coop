use anyhow::{Context, Result, bail};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use crate::launcher::{
    DirectPeerTarget, GameProcess, LaunchRuntimeOptions, NucleusNetMode, RunningGameInfo,
    attach_game, find_running_scct_processes, is_process_initialized_for_attach, launch_game,
    plan_nucleus_instance, prepare_exe_for_nucleus_lan,
};
use crate::net::{sync_startup_checksum_bypass_in_exe, update_direct_target_in_exe};
use crate::patcher::find_child_ci;
use crate::quicksave_persistence::{
    PersistentQuickSaveHandle, restore_latest_quick_saves, spawn_quicksave_persistence,
};
use crate::stun::{
    PollPeerResult, notify_server_disconnect, poll_server_for_peer, punch_udp_holes,
    register_with_server, resolve_peer_endpoint, stun_query,
};

pub struct HeadlessOptions<'a> {
    pub game_root: &'a Path,
    pub server_host: &'a str,
    pub stun_port: u16,
    pub api_port: u16,
    pub no_launch: bool,
    pub bypass_checksum_disconnect: bool,
    pub auto_resync: bool,
    pub bind_ip: Option<Ipv4Addr>,
    pub attach: bool,
    pub watch: bool,
    pub target_pids: &'a [u32],
}

pub struct AttachModeOptions<'a> {
    pub game_root: &'a Path,
    pub bypass_checksum_disconnect: bool,
    pub auto_resync: bool,
    pub bind_ip: Option<Ipv4Addr>,
    pub net_mode: NucleusNetMode,
    pub watch: bool,
    pub target_pids: &'a [u32],
}

struct SessionGuard<'a> {
    server_host: &'a str,
    api_port: u16,
    code: String,
    active: bool,
}

impl<'a> SessionGuard<'a> {
    fn new(server_host: &'a str, api_port: u16, code: String) -> Self {
        Self {
            server_host,
            api_port,
            code,
            active: true,
        }
    }

    fn finish(&mut self) {
        if self.active {
            let _ = notify_server_disconnect(
                self.server_host,
                self.api_port,
                &self.code,
                Some("Session finished"),
            );
            self.active = false;
        }
    }
}

impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = notify_server_disconnect(
                self.server_host,
                self.api_port,
                &self.code,
                Some("Session terminated"),
            );
        }
    }
}

fn bind_local_sockets(bind_ip: Option<Ipv4Addr>) -> Result<(UdpSocket, UdpSocket)> {
    crate::ip::bind_coop_udp_sockets(bind_ip)
}

fn discover_endpoints(
    sock_disco: &UdpSocket,
    sock_game: &UdpSocket,
    server_host: &str,
    stun_port: u16,
    api_port: u16,
    bind_ip: Option<Ipv4Addr>,
) -> Result<(SocketAddr, SocketAddr, Option<Ipv4Addr>)> {
    println!(
        "  [STUN] Discovering public endpoints via {}:{}...",
        server_host, stun_port
    );

    let disco_ext = stun_query(sock_disco, server_host, stun_port).with_context(|| {
        format!(
            "STUN discovery failed on port 9100 with {}:{}",
            server_host, stun_port
        )
    })?;
    let game_ext = stun_query(sock_game, server_host, stun_port).with_context(|| {
        format!(
            "STUN discovery failed on port 9103 with {}:{}",
            server_host, stun_port
        )
    })?;

    let my_local_ip = crate::ip::resolve_local_ip_for_coop(bind_ip, server_host, api_port);

    println!(
        "  [STUN] Discovery external: {} | Game external: {}",
        disco_ext, game_ext
    );
    if let Some(local) = my_local_ip {
        println!("  [LOCAL] Selected LAN IP: {}", local);
    }

    Ok((disco_ext, game_ext, my_local_ip))
}

pub fn run_headless_host(opts: HeadlessOptions) -> Result<()> {
    let sys_dir = find_child_ci(opts.game_root, "System");
    let exe_path = find_child_ci(&sys_dir, "splintercell3.exe");
    if !exe_path.exists() {
        bail!(
            "Missing System/splintercell3.exe in {}",
            opts.game_root.display()
        );
    }

    let (sock_disco, sock_game) = bind_local_sockets(opts.bind_ip)?;
    let (mut disco_ext, mut game_ext, my_local_ip) = discover_endpoints(
        &sock_disco,
        &sock_game,
        opts.server_host,
        opts.stun_port,
        opts.api_port,
        opts.bind_ip,
    )?;

    println!("  [HOST] Registering room with rendezvous server...");
    let code = register_with_server(
        opts.server_host,
        opts.api_port,
        None,
        disco_ext,
        game_ext,
        my_local_ip,
    )?;

    let mut guard = SessionGuard::new(opts.server_host, opts.api_port, code.clone());

    println!("\n======================================================================");
    println!("  Splinter Cell: Chaos Theory - Headless Co-op Host");
    println!("======================================================================");
    println!("  Friend Code: {}", code);
    println!("  Share this code with your co-op partner to connect!");
    println!("  Waiting for partner to connect... (Press Ctrl+C to cancel)");
    println!("======================================================================\n");

    let mut wait_ticks: u32 = 0;
    let (peer_disco, peer_game, peer_local_ip) = loop {
        thread::sleep(Duration::from_millis(1000));
        match poll_server_for_peer(opts.server_host, opts.api_port, &code, Some("host")) {
            Ok(PollPeerResult::Paired(disco, game, local_ip)) => {
                println!("\n  [HOST] Partner connected! Exchanging connection details...");
                break (disco, game, local_ip);
            }
            Ok(PollPeerResult::Waiting) => {
                wait_ticks = wait_ticks.wrapping_add(1);
                print!(".");
                let _ = std::io::stdout().flush();
                if wait_ticks.is_multiple_of(10)
                    && let (Ok(new_disco), Ok(new_game)) = (
                        stun_query(&sock_disco, opts.server_host, opts.stun_port),
                        stun_query(&sock_game, opts.server_host, opts.stun_port),
                    )
                    && (new_disco != disco_ext || new_game != game_ext)
                {
                    disco_ext = new_disco;
                    game_ext = new_game;
                    let _ = register_with_server(
                        opts.server_host,
                        opts.api_port,
                        Some(code.clone()),
                        disco_ext,
                        game_ext,
                        my_local_ip,
                    );
                }
            }
            Ok(PollPeerResult::Disconnected(reason)) => {
                println!();
                bail!("Host session ended by server: {}", reason);
            }
            Err(e) => {
                println!();
                bail!("Server polling error: {:#}", e);
            }
        }
    };

    println!("\n  [PUNCH] Performing UDP hole punch with partner...");
    punch_udp_holes(&sock_disco, &sock_game, peer_disco, peer_game);

    let (peer_ip, peer_disco_port, peer_game_port, is_lan) = resolve_peer_endpoint(
        disco_ext,
        my_local_ip,
        peer_disco,
        peer_game,
        peer_local_ip,
    );

    if is_lan {
        println!(
            "  [NET] Detected partner on local network (LAN): {}:{}",
            peer_ip, peer_game_port
        );
    } else {
        println!(
            "  [NET] Connected to partner across Internet: {}:{}",
            peer_ip, peer_game_port
        );
    }

    drop(sock_disco);
    drop(sock_game);

    let direct_target = DirectPeerTarget {
        ip: peer_ip,
        disco_port: peer_disco_port,
        game_port: peer_game_port,
    };

    if opts.attach {
        let quicksave_guard = prepare_and_watch_quicksaves(opts.game_root);
        let proc = attach_single_peer_process(
            opts.game_root,
            crate::trace::PeerRole::Host,
            Some(direct_target),
            opts.bind_ip,
            opts.auto_resync,
            opts.watch,
            opts.target_pids,
        )?;
        println!("  [ATTACHED] Host target injected into running Chaos Theory (PID: {})!", proc.pid);
        println!("\n  ================================================================");
        println!("  Instructions:");
        println!("    In game, select: Co-op -> Enhanced Coop -> Host Game");
        println!("    (If already inside the Co-op menu, back out to Main Menu and re-enter)");
        println!("    Waiting for game to exit...");
        println!("  ================================================================\n");

        proc.wait_for_exit_monitoring_desync(opts.game_root);
        drop(quicksave_guard);
        guard.finish();

        println!("  [EXIT] Game exited. Co-op session closed cleanly.");
        return Ok(());
    }

    let exe_bak_path = sys_dir.join("splintercell3.exe.bak");
    update_direct_target_in_exe(
        &exe_path,
        &exe_bak_path,
        Some(peer_ip),
        peer_disco_port,
        peer_game_port,
    )?;
    sync_startup_checksum_bypass_in_exe(&exe_path, opts.bypass_checksum_disconnect)?;

    if opts.no_launch {
        println!("  [READY] Peer target written to splintercell3.exe (--no-launch specified).");
        println!("  You can now start Chaos Theory manually.");
        println!("  Press Enter to finish and terminate the session...");
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        guard.finish();
        return Ok(());
    }

    let quicksave_guard = prepare_and_watch_quicksaves(opts.game_root);

    println!("  [LAUNCH] Launching Chaos Theory Co-op...");
    let proc = launch_game(
        &exe_path,
        opts.game_root,
        crate::trace::PeerRole::Host,
        Some(direct_target),
        opts.bind_ip,
        LaunchRuntimeOptions {
            auto_resync: opts.auto_resync,
            ..LaunchRuntimeOptions::default()
        },
    )?;

    println!("  [RUNNING] Game running (PID: {})!", proc.pid);
    println!("\n  ================================================================");
    println!("  Instructions:");
    println!("    In game, select: Co-op -> Enhanced Coop -> Host Game");
    println!("    Waiting for game to exit...");
    println!("  ================================================================\n");

    proc.wait_for_exit_monitoring_desync(opts.game_root);
    drop(quicksave_guard);
    guard.finish();

    println!("  [EXIT] Game exited. Co-op session closed cleanly.");
    Ok(())
}

pub fn run_headless_join(opts: HeadlessOptions, target_code: &str) -> Result<()> {
    let target_code = target_code.trim().to_uppercase();
    if target_code.is_empty() {
        bail!("Friend Code cannot be empty");
    }

    let sys_dir = find_child_ci(opts.game_root, "System");
    let exe_path = find_child_ci(&sys_dir, "splintercell3.exe");
    if !exe_path.exists() {
        bail!(
            "Missing System/splintercell3.exe in {}",
            opts.game_root.display()
        );
    }

    let (sock_disco, sock_game) = bind_local_sockets(opts.bind_ip)?;
    let (disco_ext, game_ext, my_local_ip) = discover_endpoints(
        &sock_disco,
        &sock_game,
        opts.server_host,
        opts.stun_port,
        opts.api_port,
        opts.bind_ip,
    )?;

    println!("\n======================================================================");
    println!("  Splinter Cell: Chaos Theory - Headless Co-op Join");
    println!("======================================================================");
    println!("  Joining Friend Code: {}", target_code);
    println!("  Connecting to host via rendezvous server...");
    println!("======================================================================\n");

    let (peer_disco, peer_game, peer_local_ip) = crate::stun::join_with_server(
            opts.server_host,
            opts.api_port,
            &target_code,
            disco_ext,
            game_ext,
            my_local_ip,
        )?;

    let mut guard = SessionGuard::new(opts.server_host, opts.api_port, target_code.clone());

    println!("  [JOIN] Paired with host! Performing UDP hole punch...");
    punch_udp_holes(&sock_disco, &sock_game, peer_disco, peer_game);

    let (peer_ip, peer_disco_port, peer_game_port, is_lan) = resolve_peer_endpoint(
        disco_ext,
        my_local_ip,
        peer_disco,
        peer_game,
        peer_local_ip,
    );

    if is_lan {
        println!(
            "  [NET] Detected host on local network (LAN): {}:{}",
            peer_ip, peer_game_port
        );
    } else {
        println!(
            "  [NET] Connected to host across Internet: {}:{}",
            peer_ip, peer_game_port
        );
    }

    drop(sock_disco);
    drop(sock_game);

    let direct_target = DirectPeerTarget {
        ip: peer_ip,
        disco_port: peer_disco_port,
        game_port: peer_game_port,
    };

    if opts.attach {
        let quicksave_guard = prepare_and_watch_quicksaves(opts.game_root);
        let proc = attach_single_peer_process(
            opts.game_root,
            crate::trace::PeerRole::Guest,
            Some(direct_target),
            opts.bind_ip,
            opts.auto_resync,
            opts.watch,
            opts.target_pids,
        )?;
        println!("  [ATTACHED] Host target injected into running Chaos Theory (PID: {})!", proc.pid);
        println!("\n  ================================================================");
        println!("  Instructions:");
        println!("    In game, select: Co-op -> Enhanced Coop to join your friend's game");
        println!("    (If already inside the Co-op menu, back out to Main Menu and re-enter)");
        println!("    Waiting for game to exit...");
        println!("  ================================================================\n");

        proc.wait_for_exit_monitoring_desync(opts.game_root);
        drop(quicksave_guard);
        guard.finish();

        println!("  [EXIT] Game exited. Co-op session closed cleanly.");
        return Ok(());
    }

    let exe_bak_path = sys_dir.join("splintercell3.exe.bak");
    update_direct_target_in_exe(
        &exe_path,
        &exe_bak_path,
        Some(peer_ip),
        peer_disco_port,
        peer_game_port,
    )?;
    sync_startup_checksum_bypass_in_exe(&exe_path, opts.bypass_checksum_disconnect)?;

    if opts.no_launch {
        println!("  [READY] Host target written to splintercell3.exe (--no-launch specified).");
        println!("  You can now start Chaos Theory manually.");
        println!("  Press Enter to finish and terminate the session...");
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        guard.finish();
        return Ok(());
    }

    let quicksave_guard = prepare_and_watch_quicksaves(opts.game_root);

    println!("  [LAUNCH] Launching Chaos Theory Co-op...");
    let proc = launch_game(
        &exe_path,
        opts.game_root,
        crate::trace::PeerRole::Guest,
        Some(direct_target),
        opts.bind_ip,
        LaunchRuntimeOptions {
            auto_resync: opts.auto_resync,
            ..LaunchRuntimeOptions::default()
        },
    )?;

    println!("  [RUNNING] Game running (PID: {})!", proc.pid);
    println!("\n  ================================================================");
    println!("  Instructions:");
    println!("    In game, select: Co-op -> Enhanced Coop to join your friend's game");
    println!("    Waiting for game to exit...");
    println!("  ================================================================\n");

    proc.wait_for_exit_monitoring_desync(opts.game_root);
    drop(quicksave_guard);
    guard.finish();

    println!("  [EXIT] Game exited. Co-op session closed cleanly.");
    Ok(())
}

fn prepare_and_watch_quicksaves(game_root: &Path) -> PersistentQuickSaveHandle {
    match restore_latest_quick_saves(game_root) {
        Ok(report) if report.restored_count > 0 => {
            println!(
                "  [QUICKSAVE] Restored {} previous co-op quick save(s) to {}",
                report.restored_count,
                report.profile_dir.display()
            );
        }
        Err(e) => {
            eprintln!("  [QUICKSAVE] Could not restore previous co-op quick saves: {:#}", e);
        }
        _ => {}
    }
    spawn_quicksave_persistence(game_root.to_path_buf())
}

pub fn run_headless_lan(opts: HeadlessOptions) -> Result<()> {
    if opts.attach {
        return run_headless_attach(AttachModeOptions {
            game_root: opts.game_root,
            bypass_checksum_disconnect: opts.bypass_checksum_disconnect,
            auto_resync: opts.auto_resync,
            bind_ip: opts.bind_ip,
            net_mode: NucleusNetMode::PreserveNucleusLan,
            watch: opts.watch,
            target_pids: opts.target_pids,
        });
    }

    let sys_dir = find_child_ci(opts.game_root, "System");
    let exe_path = find_child_ci(&sys_dir, "splintercell3.exe");
    if !exe_path.exists() {
        bail!(
            "Missing System/splintercell3.exe in {}",
            opts.game_root.display()
        );
    }

    let exe_bak_path = sys_dir.join("splintercell3.exe.bak");
    crate::net::update_direct_ip_in_exe(&exe_path, &exe_bak_path, None)
        .context("Failed to prepare splintercell3.exe for LAN mode")?;
    sync_startup_checksum_bypass_in_exe(&exe_path, opts.bypass_checksum_disconnect)?;

    let adapter_desc = match opts.bind_ip {
        Some(ip) => format!("{}", ip),
        None => "Auto (All Adapters)".to_string(),
    };

    if opts.no_launch {
        println!(
            "  [READY] splintercell3.exe prepared for LAN mode (adapter: {}, --no-launch specified).",
            adapter_desc
        );
        return Ok(());
    }

    let quicksave_guard = prepare_and_watch_quicksaves(opts.game_root);

    println!(
        "  [LAUNCH] Launching Chaos Theory in LAN mode (adapter: {})...",
        adapter_desc
    );
    let proc = launch_game(
        &exe_path,
        opts.game_root,
        crate::trace::PeerRole::LanOrDirect,
        None,
        opts.bind_ip,
        LaunchRuntimeOptions {
            auto_resync: opts.auto_resync,
            ..LaunchRuntimeOptions::default()
        },
    )?;

    println!("  [RUNNING] Game running (PID: {})!", proc.pid);
    println!("\n  ================================================================");
    println!("  Instructions:");
    println!("    In game, select: Co-op -> Enhanced Coop to host or join on LAN");
    println!("    Waiting for game to exit...");
    println!("  ================================================================\n");

    proc.wait_for_exit_monitoring_desync(opts.game_root);
    drop(quicksave_guard);

    println!("  [EXIT] Game exited. Co-op LAN session closed cleanly.");
    Ok(())
}

fn log_attach_diagnostics(info: &RunningGameInfo, warning: Option<&str>) {
    println!("  [ATTACH] {}", info.summary_line());
    if !info.has_mod_net_caves {
        eprintln!(
            "  [WARNING] PID {} does not have SCCT Enhanced Coop PE network caves loaded!",
            info.pid
        );
        if let Some(ref p) = info.exe_path {
            eprintln!("            Executable: {}", p.display());
        }
        eprintln!(
            "            If using Nucleus Co-op, delete Nucleus's cached 'content' folder for Chaos Theory, run Install Mod first, then relaunch Nucleus."
        );
    }
    if let Some(warn) = warning {
        println!("  [NOTE] {}", warn);
    }
}

fn attach_single_peer_process(
    game_root: &Path,
    peer_role: crate::trace::PeerRole,
    direct_peer: Option<DirectPeerTarget>,
    bind_ip: Option<Ipv4Addr>,
    auto_resync: bool,
    watch: bool,
    target_pids: &[u32],
) -> Result<GameProcess> {
    let pid = if let Some(&explicit) = target_pids.first() {
        explicit
    } else {
        let mut announced_wait = false;
        loop {
            let running = find_running_scct_processes();
            if let Some(first) = running.first() {
                if !watch || is_process_initialized_for_attach(first.pid) {
                    break first.pid;
                }
            }
            if !watch {
                bail!(
                    "No running splintercell3.exe process found. Launch Chaos Theory first, or pass --watch."
                );
            }
            if !announced_wait {
                println!("  [WATCH] Waiting for splintercell3.exe to start...");
                announced_wait = true;
            }
            thread::sleep(Duration::from_millis(250));
        }
    };

    let (mut proc, info) = attach_game(
        pid,
        peer_role,
        direct_peer,
        bind_ip,
        LaunchRuntimeOptions {
            auto_resync,
            ..LaunchRuntimeOptions::default()
        },
    )?;
    proc.reserve_session_paths(game_root);
    log_attach_diagnostics(&info, None);
    Ok(proc)
}

struct MonitoredInstance {
    proc: GameProcess,
    desync_dumped: bool,
    trace_notified: bool,
}

fn format_nucleus_mode(mode: NucleusNetMode, bind_ip: Option<Ipv4Addr>) -> String {
    match mode {
        NucleusNetMode::PreserveNucleusLan => match bind_ip {
            Some(ip) => format!("LAN Attach (explicit bind IP: {})", ip),
            None => "Respect Nucleus Network (ForceBindIP / KM-TEST Loopback / LAN)".to_string(),
        },
        NucleusNetMode::BuiltInLoopbackPair => {
            "Built-in Loopback Pair (127.0.0.2 <-> 127.0.0.3)".to_string()
        }
        NucleusNetMode::ExplicitPair(ip1, ip2) => format!("Custom IP Pair ({} <-> {})", ip1, ip2),
    }
}

pub fn run_headless_attach(opts: AttachModeOptions) -> Result<()> {
    match prepare_exe_for_nucleus_lan(opts.game_root, opts.bypass_checksum_disconnect) {
        Ok(true) => {
            println!("  [NET] Cleared any stale online Friend-Code target on disk for LAN/Nucleus.");
        }
        Ok(false) => {
            println!("  [NET] Skipping disk EXE pre-clean (already running or vanilla); runtime memory will be synced on attach.");
        }
        Err(e) => {
            eprintln!("  [NET] Warning: could not pre-clean splintercell3.exe on disk: {:#}", e);
        }
    }

    let quicksave_guard = prepare_and_watch_quicksaves(opts.game_root);

    println!("\n======================================================================");
    println!(
        "  Splinter Cell: Chaos Theory - {}",
        if opts.watch {
            "Nucleus Co-op Companion (Watch & Attach)"
        } else {
            "Live Process Attach"
        }
    );
    println!("======================================================================");
    println!(
        "  Network Mode: {}",
        format_nucleus_mode(opts.net_mode, opts.bind_ip)
    );
    if !opts.target_pids.is_empty() {
        println!("  Target PIDs:  {:?}", opts.target_pids);
    }
    if opts.watch {
        println!("  Watching for splintercell3.exe instances (Press Ctrl+C to stop)...");
    }
    println!("======================================================================\n");

    let mut attached: Vec<MonitoredInstance> = Vec::new();
    let mut known_pids: HashSet<u32> = HashSet::new();
    let mut pending_new_pids: HashMap<u32, Instant> = HashMap::new();
    let mut next_slot: usize = 0;
    let mut ever_attached = false;
    let mut idle_notice_printed = false;
    let mut last_scan = Instant::now() - Duration::from_secs(1);

    let pid_matches = |pid: u32| opts.target_pids.is_empty() || opts.target_pids.contains(&pid);

    // Initial scan: attach immediately to any already-running splintercell3.exe instances.
    let initial = find_running_scct_processes();
    for info in initial {
        if !pid_matches(info.pid) {
            continue;
        }
        if !known_pids.insert(info.pid) {
            continue;
        }
        let mut plan = plan_nucleus_instance(next_slot, opts.net_mode, &info);
        if matches!(opts.net_mode, NucleusNetMode::PreserveNucleusLan) && opts.bind_ip.is_some() {
            plan.local_bind_ip = opts.bind_ip;
        }
        match attach_game(
            info.pid,
            plan.role,
            plan.direct_peer,
            plan.local_bind_ip,
            LaunchRuntimeOptions {
                auto_resync: opts.auto_resync,
                ..LaunchRuntimeOptions::default()
            },
        ) {
            Ok((mut proc, updated_info)) => {
                proc.reserve_session_paths(opts.game_root);
                log_attach_diagnostics(&updated_info, plan.warning.as_deref());
                println!(
                    "  [READY] Attached Instance #{} (PID {}, role={}, bind={:?}, peer={:?})",
                    next_slot + 1,
                    proc.pid,
                    proc.peer_role.as_str(),
                    plan.local_bind_ip,
                    plan.direct_peer.map(|p| p.ip)
                );
                next_slot += 1;
                ever_attached = true;
                attached.push(MonitoredInstance {
                    proc,
                    desync_dumped: false,
                    trace_notified: false,
                });
            }
            Err(e) => {
                eprintln!("  [ATTACH ERROR] Failed to attach PID {}: {:#}", info.pid, e);
            }
        }
    }

    if !opts.watch && attached.is_empty() {
        drop(quicksave_guard);
        bail!(
            "No running splintercell3.exe process found. Launch Chaos Theory (or Nucleus Co-op) first, or run with --nucleus / --attach --watch."
        );
    }

    if !attached.is_empty() {
        println!(
            "\n  >>> Monitoring {} attached instance(s). In game, go to Co-op -> Enhanced Coop.",
            attached.len()
        );
        println!(
            "  >>> (If an instance was already inside the Co-op menu, back out to Main Menu and re-enter.)\n"
        );
    }

    loop {
        if opts.watch && last_scan.elapsed() >= Duration::from_millis(250) {
            last_scan = Instant::now();
            let running = find_running_scct_processes();
            let live_set: HashSet<u32> = running.iter().map(|i| i.pid).collect();
            pending_new_pids.retain(|pid, _| live_set.contains(pid));

            for info in running {
                if !pid_matches(info.pid) || known_pids.contains(&info.pid) {
                    continue;
                }
                let first_seen = *pending_new_pids
                    .entry(info.pid)
                    .or_insert_with(Instant::now);
                // Wait briefly so Windows loader, ForceBindIP (BindIP.dll), and ProtoInput finish init.
                if first_seen.elapsed() < Duration::from_millis(1500)
                    || !is_process_initialized_for_attach(info.pid)
                {
                    continue;
                }
                pending_new_pids.remove(&info.pid);
                known_pids.insert(info.pid);

                let mut plan = plan_nucleus_instance(next_slot, opts.net_mode, &info);
                if matches!(opts.net_mode, NucleusNetMode::PreserveNucleusLan)
                    && opts.bind_ip.is_some()
                {
                    plan.local_bind_ip = opts.bind_ip;
                }
                match attach_game(
                    info.pid,
                    plan.role,
                    plan.direct_peer,
                    plan.local_bind_ip,
                    LaunchRuntimeOptions {
                        auto_resync: opts.auto_resync,
                        ..LaunchRuntimeOptions::default()
                    },
                ) {
                    Ok((mut proc, updated_info)) => {
                        proc.reserve_session_paths(opts.game_root);
                        log_attach_diagnostics(&updated_info, plan.warning.as_deref());
                        println!(
                            "  [READY] Auto-attached Instance #{} (PID {}, role={}, bind={:?}, peer={:?})",
                            next_slot + 1,
                            proc.pid,
                            proc.peer_role.as_str(),
                            plan.local_bind_ip,
                            plan.direct_peer.map(|p| p.ip)
                        );
                        next_slot += 1;
                        ever_attached = true;
                        idle_notice_printed = false;
                        attached.push(MonitoredInstance {
                            proc,
                            desync_dumped: false,
                            trace_notified: false,
                        });
                    }
                    Err(e) => {
                        eprintln!("  [ATTACH ERROR] Failed to attach PID {}: {:#}", info.pid, e);
                    }
                }
            }
        }

        let mut i = 0;
        while i < attached.len() {
            let alive = attached[i].proc.is_alive();
            let pid = attached[i].proc.pid;
            let role_str = attached[i].proc.peer_role.as_str();
            let poll = {
                let slot = &mut attached[i];
                slot.proc.poll_monitor_once(
                    opts.game_root,
                    &mut slot.desync_dumped,
                    &mut slot.trace_notified,
                )
            };
            if let Some(trace_path) = poll.trace_started {
                println!(
                    "  >>> [TRACE PID {}] Recording startup sync/tick trace ({}) to: {}",
                    pid,
                    role_str,
                    trace_path.display()
                );
            }
            for line in poll.resync_logs {
                println!("  [PID {}] {}", pid, line);
            }
            if let Some(desync_res) = poll.desync {
                match desync_res {
                    Ok(report) => {
                        println!(
                            "\n  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
                        );
                        println!(
                            "  >>> [DESYNC DETECTED PID {}] Simulation lockstep mismatch detected!",
                            pid
                        );
                        println!("  >>> [MISMATCH SLOTS] {}", report.mismatched_slots);
                        println!(
                            "  >>> [DESYNC DUMP]   Actor state:  {}",
                            report.dump_path.display()
                        );
                        if let Some(ref tp) = report.trace_path {
                            println!("  >>> [STARTUP TRACE] Sync trace:   {}", tp.display());
                        }
                        println!(
                            "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "  >>> [DESYNC ERROR PID {}] Failed to dump desync state: {:#}",
                            pid, e
                        );
                    }
                }
            }
            if !alive {
                let exited = attached.remove(i);
                exited.proc.wait_for_exit();
                println!("  [EXIT] Chaos Theory (PID {}) has exited.", pid);
                let _ = quicksave_guard.flush();
            } else {
                i += 1;
            }
        }

        if attached.is_empty() {
            if !opts.watch {
                break;
            }
            if ever_attached && !idle_notice_printed {
                println!(
                    "  [WATCH] All attached instances exited. Still watching for new Nucleus Co-op launches (Ctrl+C to quit)..."
                );
                idle_notice_printed = true;
                next_slot = 0;
            }
        }

        let any_resync = attached.iter().any(|m| m.proc.resync_coord.is_some());
        let sleep_ms = if any_resync { 10 } else { 50 };
        thread::sleep(Duration::from_millis(sleep_ms));
    }

    drop(quicksave_guard);
    println!("  [EXIT] All monitored Chaos Theory instances exited cleanly.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bind_local_sockets() {
        let (s1, s2) = bind_local_sockets(None).expect("can bind auto sockets");
        assert!(s1.local_addr().is_ok());
        assert!(s2.local_addr().is_ok());

        let (l1, l2) = bind_local_sockets(Some(Ipv4Addr::LOCALHOST)).expect("can bind loopback");
        assert_eq!(l1.local_addr().unwrap().ip(), Ipv4Addr::LOCALHOST);
        assert_eq!(l2.local_addr().unwrap().ip(), Ipv4Addr::LOCALHOST);
    }

    #[test]
    fn test_empty_join_code_fails() {
        let dir = std::env::temp_dir();
        let opts = HeadlessOptions {
            game_root: &dir,
            server_host: "127.0.0.1",
            stun_port: 3478,
            api_port: 8080,
            no_launch: true,
            bypass_checksum_disconnect: false,
            auto_resync: false,
            bind_ip: None,
            attach: false,
            watch: false,
            target_pids: &[],
        };
        let err = run_headless_join(opts, "   ").unwrap_err();
        assert!(err.to_string().contains("cannot be empty"));
    }

    #[test]
    fn test_missing_game_root_fails() {
        let dir = std::env::temp_dir().join("nonexistent_game_root_12345");
        let opts = HeadlessOptions {
            game_root: &dir,
            server_host: "127.0.0.1",
            stun_port: 3478,
            api_port: 8080,
            no_launch: true,
            bypass_checksum_disconnect: false,
            auto_resync: false,
            bind_ip: None,
            attach: false,
            watch: false,
            target_pids: &[],
        };
        let err = run_headless_host(opts).unwrap_err();
        assert!(err.to_string().contains("Missing System/splintercell3.exe"));
    }

    #[test]
    fn test_lan_missing_game_root_fails() {
        let dir = std::env::temp_dir().join("nonexistent_game_root_lan_12345");
        let opts = HeadlessOptions {
            game_root: &dir,
            server_host: "127.0.0.1",
            stun_port: 3478,
            api_port: 8080,
            no_launch: true,
            bypass_checksum_disconnect: false,
            auto_resync: false,
            bind_ip: Some(Ipv4Addr::new(192, 168, 178, 202)),
            attach: false,
            watch: false,
            target_pids: &[],
        };
        let err = run_headless_lan(opts).unwrap_err();
        assert!(err.to_string().contains("Missing System/splintercell3.exe"));
    }

    #[test]
    fn test_attach_without_running_process_returns_helpful_error() {
        let dir = std::env::temp_dir().join("nonexistent_attach_root_12345");
        let err = run_headless_attach(AttachModeOptions {
            game_root: &dir,
            bypass_checksum_disconnect: false,
            auto_resync: false,
            bind_ip: None,
            net_mode: NucleusNetMode::PreserveNucleusLan,
            watch: false,
            target_pids: &[],
        })
        .unwrap_err();
        assert!(err.to_string().contains("No running splintercell3.exe"));
    }
}
