#![windows_subsystem = "windows"]

mod flags;
mod gui;
mod headless;
mod ip;
mod launcher;
mod levels;
mod net;
mod patcher;
mod quicksave_persistence;
mod stun;
mod umd;
mod upk;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "patch_sp_levels",
    about = "Convert all 11 SCCT Single Player missions to standalone Coop maps, append them to the Coop Mission Select dropdown, and fix multi-NIC LAN joining."
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

    /// Apply all experimental gameplay fixes (security camera alarms and non-lethal game over) to splintercell3.exe
    #[arg(long)]
    gameplay_fixes: bool,

    /// Enable an optional patch flag by ID (e.g. --enable-flag camera_alarms)
    #[arg(long = "enable-flag", value_name = "FLAG")]
    enable_flags: Vec<String>,

    /// Disable an optional patch flag by ID (e.g. --disable-flag nonlethal_gameover)
    #[arg(long = "disable-flag", value_name = "FLAG")]
    disable_flags: Vec<String>,

    /// List all available patch flags
    #[arg(long)]
    list_flags: bool,

    /// Run in headless CLI mode instead of launching GUI
    #[arg(long)]
    cli: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.list_flags {
        println!("Available patch flags:");
        for def in flags::ALL_FLAGS {
            let exp = if def.experimental {
                " [EXPERIMENTAL]"
            } else {
                ""
            };
            let def_status = if def.default_enabled {
                "enabled"
            } else {
                "disabled"
            };
            println!(
                "  {:<20} {}{} (default: {})",
                def.id, def.name, exp, def_status
            );
            println!("                       {}", def.description);
        }
        return Ok(());
    }

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

        let mut flag_states = flags::load_flag_states(&game_root);
        if flag_states.is_empty() {
            flag_states = flags::default_flag_states();
        }
        if args.gameplay_fixes {
            for f in &mut flag_states {
                f.enabled = true;
            }
        }
        for id in &args.enable_flags {
            if let Some(f) = flag_states
                .iter_mut()
                .find(|f| flags::flag_matches_id(f.def.id, id))
            {
                f.enabled = true;
            } else {
                anyhow::bail!(
                    "Unknown flag to enable: '{}'. Run with --list-flags to see available flags.",
                    id
                );
            }
        }
        for id in &args.disable_flags {
            if let Some(f) = flag_states
                .iter_mut()
                .find(|f| flags::flag_matches_id(f.def.id, id))
            {
                f.enabled = false;
            } else {
                anyhow::bail!(
                    "Unknown flag to disable: '{}'. Run with --list-flags to see available flags.",
                    id
                );
            }
        }

        let bind_ip = args.bind_ip.filter(|ip| !ip.is_unspecified());

        if args.lan {
            let opts = headless::HeadlessOptions {
                game_root: &game_root,
                server_host: &args.server_host,
                stun_port: args.stun_port,
                api_port: args.api_port,
                no_launch: args.no_launch,
                flags: &flag_states,
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
                flags: &flag_states,
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
                flags: &flag_states,
                bind_ip,
            };
            headless::run_headless_join(opts, code)?;
            return Ok(());
        }

        patcher::apply_all(&game_root, args.no_net_fix, &flag_states)?;
        return Ok(());
    }

    // Default: Launch GUI!
    let initial_bind_ip = args.bind_ip.filter(|ip| !ip.is_unspecified());
    if let Err(e) = gui::run_gui(args.game_dir.clone(), initial_bind_ip) {
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
