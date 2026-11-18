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

fn main() -> Result<()> {
    let args = Args::parse();

    let mode_count = usize::from(args.host) + usize::from(args.join.is_some()) + usize::from(args.lan);
    if mode_count > 1 {
        anyhow::bail!("Cannot combine --host, --join, and --lan at the same time.");
    }

    let is_headless = args.restore || args.cli || args.host || args.join.is_some() || args.lan;

    // If restore, cli, host, or join is specified, run directly in headless CLI mode
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
