use anyhow::{Context, Result, bail};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::Path;
use std::thread;
use std::time::Duration;

use crate::flags::{FlagState, sync_all_flags};
use crate::launcher::launch_game;
use crate::net::update_direct_target_in_exe;
use crate::patcher::find_child_ci;
use crate::quicksave_persistence::spawn_quicksave_persistence;
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
    pub flags: &'a [FlagState],
    pub bind_ip: Option<Ipv4Addr>,
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

    // Sync any configured patch flags
    sync_all_flags(opts.game_root, opts.flags)?;

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

    let exe_bak_path = sys_dir.join("splintercell3.exe.bak");
    update_direct_target_in_exe(
        &exe_path,
        &exe_bak_path,
        Some(peer_ip),
        peer_disco_port,
        peer_game_port,
    )?;

    if opts.no_launch {
        println!("  [READY] Peer target written to splintercell3.exe (--no-launch specified).");
        println!("  You can now start Chaos Theory manually.");
        println!("  Press Enter to finish and terminate the session...");
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        guard.finish();
        return Ok(());
    }

    let quicksave_guard = spawn_quicksave_persistence(opts.game_root.to_path_buf());

    println!("  [LAUNCH] Launching Chaos Theory Co-op...");
    let proc = launch_game(
        &exe_path,
        opts.game_root,
        Some(peer_ip),
        peer_disco_port,
        peer_game_port,
        opts.bind_ip,
    )?;

    println!("  [RUNNING] Game running (PID: {})!", proc.pid);
    println!("\n  ================================================================");
    println!("  Instructions:");
    println!("    In game, select: Co-op -> Enhanced Coop -> Host Game");
    println!("    Waiting for game to exit...");
    println!("  ================================================================\n");

    proc.wait_for_exit();
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

    // Sync any configured patch flags
    sync_all_flags(opts.game_root, opts.flags)?;

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

    let exe_bak_path = sys_dir.join("splintercell3.exe.bak");
    update_direct_target_in_exe(
        &exe_path,
        &exe_bak_path,
        Some(peer_ip),
        peer_disco_port,
        peer_game_port,
    )?;

    if opts.no_launch {
        println!("  [READY] Host target written to splintercell3.exe (--no-launch specified).");
        println!("  You can now start Chaos Theory manually.");
        println!("  Press Enter to finish and terminate the session...");
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        guard.finish();
        return Ok(());
    }

    let quicksave_guard = spawn_quicksave_persistence(opts.game_root.to_path_buf());

    println!("  [LAUNCH] Launching Chaos Theory Co-op...");
    let proc = launch_game(
        &exe_path,
        opts.game_root,
        Some(peer_ip),
        peer_disco_port,
        peer_game_port,
        opts.bind_ip,
    )?;

    println!("  [RUNNING] Game running (PID: {})!", proc.pid);
    println!("\n  ================================================================");
    println!("  Instructions:");
    println!("    In game, select: Co-op -> Enhanced Coop to join your friend's game");
    println!("    Waiting for game to exit...");
    println!("  ================================================================\n");

    proc.wait_for_exit();
    drop(quicksave_guard);
    guard.finish();

    println!("  [EXIT] Game exited. Co-op session closed cleanly.");
    Ok(())
}

pub fn run_headless_lan(opts: HeadlessOptions) -> Result<()> {
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
    sync_all_flags(opts.game_root, opts.flags)?;

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

    let quicksave_guard = spawn_quicksave_persistence(opts.game_root.to_path_buf());

    println!(
        "  [LAUNCH] Launching Chaos Theory in LAN mode (adapter: {})...",
        adapter_desc
    );
    let proc = launch_game(
        &exe_path,
        opts.game_root,
        None,
        crate::net::DISCOVERY_PORT,
        crate::net::GAME_PORT,
        opts.bind_ip,
    )?;

    println!("  [RUNNING] Game running (PID: {})!", proc.pid);
    println!("\n  ================================================================");
    println!("  Instructions:");
    println!("    In game, select: Co-op -> Enhanced Coop to host or join on LAN");
    println!("    Waiting for game to exit...");
    println!("  ================================================================\n");

    proc.wait_for_exit();
    drop(quicksave_guard);

    println!("  [EXIT] Game exited. Co-op LAN session closed cleanly.");
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
            flags: &[],
            bind_ip: None,
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
            flags: &[],
            bind_ip: None,
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
            flags: &[],
            bind_ip: Some(Ipv4Addr::new(192, 168, 178, 202)),
        };
        let err = run_headless_lan(opts).unwrap_err();
        assert!(err.to_string().contains("Missing System/splintercell3.exe"));
    }
}
