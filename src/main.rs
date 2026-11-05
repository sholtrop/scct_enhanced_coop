#![allow(dead_code)]
#![windows_subsystem = "windows"]

mod gui;
mod levels;
mod net;
mod patcher;
mod umd;
mod upk;
mod ip;

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

    /// Run in headless CLI mode instead of launching GUI
    #[arg(long)]
    cli: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // If restore or --cli is specified, run directly in CLI mode
    if args.restore || args.cli {
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
        } else {
            patcher::apply_all(&game_root, args.no_net_fix)?;
        }
        return Ok(());
    }

    // Default: Launch GUI!
    // If GUI launch fails (e.g. headless environment without DISPLAY), fallback gracefully to CLI.
    if let Err(e) = gui::run_gui(args.game_dir.clone()) {
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
        eprintln!("Could not initialize GUI ({}). Running in CLI mode...", e);
        let game_root = patcher::resolve_game_root(args.game_dir.as_deref())?;
        patcher::apply_all(&game_root, args.no_net_fix)?;
    }

    Ok(())
}
