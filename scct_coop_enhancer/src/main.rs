#![windows_subsystem = "windows"]

mod gui;
mod headless;
mod ip;
mod launcher;
mod levels;
mod net;
mod patcher;
mod quicksave_persistence;
mod resync;
mod stun;
mod trace;
mod umd;
mod upk;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "scct_coop_enhancer",
    version,
    about = "Splinter Cell: Chaos Theory Enhanced Coop installer and online/LAN launcher: converts all 11 Single Player missions for Co-op, adds 5-character Friend Code NAT traversal, fixes multi-NIC LAN joining, enables persistent co-op quick saves, and fixes sync/desync issues."
)]
struct Args {
    /// Path to SCCT game root folder or System folder (auto-detects current folder if omitted)
    #[arg(long)]
    game_dir: Option<PathBuf>,

    /// Skip applying the multi-NIC LAN networking fix to splintercell3.exe
    #[arg(long)]
    no_net_fix: bool,

    /// Remove all appended Coop levels and restore 100% vanilla SCCT
    #[arg(long)]
    restore: bool,

    /// Host a co-op match headless and wait for a partner to join
    #[arg(long)]
    host: bool,

    /// Join a co-op match headless using a Friend Code
    #[arg(long, value_name = "CODE")]
    join: Option<String>,

    /// Launch the game in standard LAN mode with multi-NIC fixes applied (headless)
    #[arg(long)]
    lan: bool,

    /// Attach to already-running splintercell3.exe process(es) instead of launching (for Nucleus Co-op / external launchers)
    #[arg(long)]
    attach: bool,

    /// Nucleus Co-op companion mode: pre-clean stale online targets, watch for Nucleus-launched splintercell3.exe instances, and auto-attach hooks/networking
    #[arg(long)]
    nucleus: bool,

    /// Keep watching for newly-started splintercell3.exe processes when using --attach (enabled automatically by --nucleus)
    #[arg(long)]
    watch: bool,

    /// Target specific splintercell3.exe PID(s) when using --attach (repeatable)
    #[arg(long = "pid", value_name = "PID")]
    pids: Vec<u32>,

    /// Pair 2 attached/Nucleus instances over built-in loopback addresses (127.0.0.2 <-> 127.0.0.3; default for --nucleus, no ForceBindIP or virtual adapters needed)
    #[arg(long)]
    pair_loopback: bool,

    /// Pair 2 attached/Nucleus instances over two explicit local IPv4 addresses (e.g. 192.168.178.202,192.168.178.203)
    #[arg(long, value_name = "IP1,IP2")]
    pair_ips: Option<String>,

    /// Leave IP binding to Nucleus Co-op / ForceBindIP (0.0.0.0) instead of built-in 127.0.0.2 <-> 127.0.0.3 loopback pairing
    #[arg(long)]
    respect_nucleus_net: bool,

    /// Bind sockets and game LAN traffic to a specific local IPv4 adapter address (default: auto/all adapters)
    #[arg(long, value_name = "IP")]
    bind_ip: Option<std::net::Ipv4Addr>,

    /// Rendezvous / STUN server hostname
    #[arg(long, default_value = stun::DEFAULT_SERVER_HOST)]
    server_host: String,

    /// STUN server port
    #[arg(long, default_value_t = stun::DEFAULT_STUN_PORT)]
    stun_port: u16,

    /// Rendezvous HTTP API port
    #[arg(long, default_value_t = stun::DEFAULT_API_PORT)]
    api_port: u16,

    /// Do not automatically launch the game executable after pairing
    #[arg(long)]
    no_launch: bool,

    /// Bypass lockstep checksum disconnect (Trace Mode; CLI-only, default: off)
    #[arg(long, visible_alias = "bypass-startup-checksum")]
    bypass_checksum_disconnect: bool,

    /// Automatically resync Host -> Client simulation state in memory on lockstep checksum mismatch
    #[arg(long, visible_alias = "auto-resync")]
    resync: bool,

    /// Show advanced developer / debug flag controls in the launcher UI
    #[arg(long)]
    dev: bool,

    /// Run in headless CLI mode instead of launching GUI
    #[arg(long)]
    cli: bool,
}

fn validate_and_resolve_nucleus_net_mode(args: &Args) -> Result<launcher::NucleusNetMode> {
    let mode_count = usize::from(args.host)
        + usize::from(args.join.is_some())
        + usize::from(args.lan)
        + usize::from(args.nucleus);
    if mode_count > 1 {
        anyhow::bail!("Cannot combine --host, --join, --lan, and --nucleus at the same time.");
    }
    if args.pair_loopback && args.pair_ips.is_some() {
        anyhow::bail!("Cannot combine --pair-loopback and --pair-ips at the same time.");
    }
    if args.respect_nucleus_net && (args.pair_loopback || args.pair_ips.is_some()) {
        anyhow::bail!(
            "Cannot combine --respect-nucleus-net with --pair-loopback or --pair-ips."
        );
    }
    if (args.pair_loopback || args.pair_ips.is_some()) && (args.host || args.join.is_some()) {
        anyhow::bail!("Cannot combine --pair-loopback or --pair-ips with --host or --join.");
    }
    if args.pair_loopback {
        Ok(launcher::NucleusNetMode::BuiltInLoopbackPair)
    } else if let Some(ref raw) = args.pair_ips {
        let (ip1, ip2) = launcher::parse_ip_pair(raw)?;
        Ok(launcher::NucleusNetMode::ExplicitPair(ip1, ip2))
    } else if args.respect_nucleus_net {
        Ok(launcher::NucleusNetMode::PreserveNucleusLan)
    } else if args.nucleus && args.bind_ip.is_none() {
        Ok(launcher::NucleusNetMode::BuiltInLoopbackPair)
    } else {
        Ok(launcher::NucleusNetMode::PreserveNucleusLan)
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let nucleus_net_mode = validate_and_resolve_nucleus_net_mode(&args)?;

    let is_headless = args.restore
        || args.cli
        || args.host
        || args.join.is_some()
        || args.lan
        || args.attach
        || args.nucleus;

    // If restore, cli, host, join, lan, attach, or nucleus is specified, run in headless CLI mode
    if is_headless {
        #[cfg(windows)]
        {
            unsafe extern "system" {
                fn AttachConsole(dwProcessId: u32) -> i32;
            }
            const ATTACH_PARENT_PROCESS: u32 = 0xFFFF_FFFF;
            unsafe {
                AttachConsole(ATTACH_PARENT_PROCESS);
            }
        }

        let game_root = patcher::resolve_game_root(args.game_dir.as_deref())?;
        if args.restore {
            patcher::restore_vanilla(&game_root)?;
            return Ok(());
        }

        let bind_ip = args.bind_ip.filter(|ip| !ip.is_unspecified());

        if args.nucleus || (args.attach && !args.host && args.join.is_none() && !args.lan) {
            headless::run_headless_attach(headless::AttachModeOptions {
                game_root: &game_root,
                bypass_checksum_disconnect: args.bypass_checksum_disconnect,
                auto_resync: args.resync,
                bind_ip,
                net_mode: nucleus_net_mode,
                watch: args.nucleus || args.watch,
                target_pids: &args.pids,
            })?;
            return Ok(());
        }

        if args.lan {
            let opts = headless::HeadlessOptions {
                game_root: &game_root,
                server_host: &args.server_host,
                stun_port: args.stun_port,
                api_port: args.api_port,
                no_launch: args.no_launch,
                bypass_checksum_disconnect: args.bypass_checksum_disconnect,
                auto_resync: args.resync,
                bind_ip,
                attach: args.attach,
                watch: args.watch,
                target_pids: &args.pids,
            };
            headless::run_headless_lan(opts)?;
            return Ok(());
        }

        if args.host {
            let opts = headless::HeadlessOptions {
                game_root: &game_root,
                server_host: &args.server_host,
                stun_port: args.stun_port,
                api_port: args.api_port,
                no_launch: args.no_launch,
                bypass_checksum_disconnect: args.bypass_checksum_disconnect,
                auto_resync: args.resync,
                bind_ip,
                attach: args.attach,
                watch: args.watch,
                target_pids: &args.pids,
            };
            headless::run_headless_host(opts)?;
            return Ok(());
        }

        if let Some(ref code) = args.join {
            let opts = headless::HeadlessOptions {
                game_root: &game_root,
                server_host: &args.server_host,
                stun_port: args.stun_port,
                api_port: args.api_port,
                no_launch: args.no_launch,
                bypass_checksum_disconnect: args.bypass_checksum_disconnect,
                auto_resync: args.resync,
                bind_ip,
                attach: args.attach,
                watch: args.watch,
                target_pids: &args.pids,
            };
            headless::run_headless_join(opts, code)?;
            return Ok(());
        }

        patcher::apply_all(&game_root, args.no_net_fix, args.bypass_checksum_disconnect)?;
        return Ok(());
    }

    // Default: Launch GUI!
    let initial_bind_ip = args.bind_ip.filter(|ip| !ip.is_unspecified());
    if let Err(e) = gui::run_gui(args.game_dir.clone(), initial_bind_ip, args.resync, args.dev) {
        #[cfg(windows)]
        {
            unsafe extern "system" {
                fn AttachConsole(dwProcessId: u32) -> i32;
                fn MessageBoxA(
                    hWnd: *mut std::ffi::c_void,
                    lpText: *const u8,
                    lpCaption: *const u8,
                    uType: u32,
                ) -> i32;
            }
            const ATTACH_PARENT_PROCESS: u32 = 0xFFFF_FFFF;
            unsafe {
                AttachConsole(ATTACH_PARENT_PROCESS);
            }
            let err_msg = format!(
                "Failed to initialize GUI:\n\n{}\n\nTo run in command-line mode instead, launch with the --cli flag.\0",
                e
            );
            let caption = b"SCCT Coop Enhancer Error\0";
            unsafe {
                MessageBoxA(
                    std::ptr::null_mut(),
                    err_msg.as_ptr(),
                    caption.as_ptr(),
                    0x0000_0010, // MB_ICONERROR
                );
            }
        }
        eprintln!("Failed to initialize GUI: {e}");
        eprintln!("To run in command-line mode instead, launch with the --cli flag.");
        std::process::exit(1);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_dev_flag_defaults_false_and_parses() {
        let default_args = Args::try_parse_from(["scct_coop_enhancer"]).unwrap();
        assert!(!default_args.dev);
        assert!(!default_args.resync);
        assert!(!default_args.bypass_checksum_disconnect);

        let dev_args = Args::try_parse_from(["scct_coop_enhancer", "--dev"]).unwrap();
        assert!(dev_args.dev);
    }

    #[test]
    fn test_cli_nucleus_and_attach_flags_parse_and_validate() {
        let nuc = Args::try_parse_from(["scct_coop_enhancer", "--nucleus"]).unwrap();
        assert!(nuc.nucleus);
        assert_eq!(
            validate_and_resolve_nucleus_net_mode(&nuc).unwrap(),
            launcher::NucleusNetMode::BuiltInLoopbackPair
        );

        let respect = Args::try_parse_from([
            "scct_coop_enhancer",
            "--nucleus",
            "--respect-nucleus-net",
        ])
        .unwrap();
        assert_eq!(
            validate_and_resolve_nucleus_net_mode(&respect).unwrap(),
            launcher::NucleusNetMode::PreserveNucleusLan
        );

        let lb =
            Args::try_parse_from(["scct_coop_enhancer", "--nucleus", "--pair-loopback"]).unwrap();
        assert_eq!(
            validate_and_resolve_nucleus_net_mode(&lb).unwrap(),
            launcher::NucleusNetMode::BuiltInLoopbackPair
        );

        let pair = Args::try_parse_from([
            "scct_coop_enhancer",
            "--attach",
            "--pid",
            "1234",
            "--pid",
            "5678",
            "--pair-ips",
            "192.168.178.202,192.168.178.203",
        ])
        .unwrap();
        assert!(pair.attach);
        assert_eq!(pair.pids, vec![1234, 5678]);
        assert_eq!(
            validate_and_resolve_nucleus_net_mode(&pair).unwrap(),
            launcher::NucleusNetMode::ExplicitPair(
                std::net::Ipv4Addr::new(192, 168, 178, 202),
                std::net::Ipv4Addr::new(192, 168, 178, 203),
            )
        );

        let bad_combo =
            Args::try_parse_from(["scct_coop_enhancer", "--nucleus", "--host"]).unwrap();
        assert!(validate_and_resolve_nucleus_net_mode(&bad_combo).is_err());

        let bad_pair = Args::try_parse_from([
            "scct_coop_enhancer",
            "--nucleus",
            "--pair-loopback",
            "--pair-ips",
            "10.0.0.1,10.0.0.2",
        ])
        .unwrap();
        assert!(validate_and_resolve_nucleus_net_mode(&bad_pair).is_err());
    }

    #[test]
    fn test_default_mod_flags_all_standard_enabled_except_opt_in_desync_bypass() {
        let flags = patcher::ModFlags::default();
        assert_eq!(flags, patcher::ModFlags::standard_coop());
        assert!(!flags.runtime_bypass_checksum_disconnect);
        assert!(!flags.coop_aizone_enable);
        for desc in patcher::FLAG_DESCRIPTORS {
            let expected = !matches!(desc.short_name, "bypass_checksum_dc" | "coop_aizone");
            assert_eq!(
                (desc.get)(&flags),
                expected,
                "Unexpected default value for flag {}",
                desc.short_name
            );
        }
    }
}
