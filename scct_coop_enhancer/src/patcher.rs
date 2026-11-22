use anyhow::{Context, Result, bail};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

type LogCallback = Box<dyn Fn(&str) + Send + Sync>;
static LOG_SINK: Mutex<Option<LogCallback>> = Mutex::new(None);

pub fn set_log_sink<F>(f: F)
where
    F: Fn(&str) + Send + Sync + 'static,
{
    if let Ok(mut sink) = LOG_SINK.lock() {
        *sink = Some(Box::new(f));
    }
}

pub fn clear_log_sink() {
    if let Ok(mut sink) = LOG_SINK.lock() {
        *sink = None;
    }
}

pub fn log_msg(msg: &str) {
    println!("{}", msg);
    if let Ok(sink) = LOG_SINK.lock() {
        #[allow(clippy::collapsible_if)]
        if let Some(ref cb) = *sink {
            cb(msg);
        }
    }
}

#[macro_export]
macro_rules! scct_log {
    ($($arg:tt)*) => {{
        let s = format!($($arg)*);
        $crate::patcher::log_msg(&s);
    }};
}

use crate::levels::{SP_COOP_LEVELS, VANILLA_COOP_STEMS};
use crate::net::{
    NetExeFlags, is_ai_visibility_culling_disabled, is_lan_bind_hooks_applied,
    is_lobby_alttab_unready_nop_patched, is_menu_caption_patched, is_menu_redirect_patched,
    is_nat_direct_hooks_applied, is_pause_always_ready_patched,
    is_startup_checksum_bypass_patched, patch_ai_visibility_culling_disabled_bytes,
    patch_pause_always_ready_bytes, read_pe_vanilla_vsizes,
    revert_ai_visibility_culling_disabled_bytes, revert_pause_always_ready_bytes,
    sync_net_flags_to_exe_bytes,
};
use crate::umd::{
    ExtractedLevelInfo, UmdPatchOptions, append_missions_to_map_rotation, build_appended_coop_ini,
    detect_umd_options_fast, extract_sp_level_info_from_umd, patch_umd_with_options,
};
use crate::upk::{
    UpkPatchOptions, detect_upk_options_from_maps, patch_sp_map_to_coop_with_options,
};

pub const MOD_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const VERSION_FILENAME: &str = "scct_coop_version.txt";

pub fn parse_version_str(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some(stripped) = trimmed.strip_prefix("version=") {
        stripped.trim().to_string()
    } else if let Some(stripped) = trimmed.strip_prefix('v') {
        stripped.trim().to_string()
    } else {
        trimmed.to_string()
    }
}

/// Check if the Co-op Mod version file exists in System/ or the game root.
/// Returns `Some(version_string)` if installed, or `None` if vanilla.
pub fn get_installed_version(game_root: &Path) -> Option<String> {
    let system_dir = find_child_ci(game_root, "System");
    let ver_file = find_child_ci(&system_dir, VERSION_FILENAME);
    if ver_file.is_file()
        && let Ok(content) = std::fs::read_to_string(&ver_file)
    {
        let ver = parse_version_str(&content);
        if !ver.is_empty() {
            return Some(ver);
        }
    }
    let root_file = find_child_ci(game_root, VERSION_FILENAME);
    if root_file.is_file()
        && let Ok(content) = std::fs::read_to_string(&root_file)
    {
        let ver = parse_version_str(&content);
        if !ver.is_empty() {
            return Some(ver);
        }
    }
    None
}

/// Writes `scct_coop_version.txt` containing the current mod version to System/.
pub fn write_version_file(game_root: &Path) -> Result<()> {
    let system_dir = find_child_ci(game_root, "System");
    if system_dir.is_dir() {
        let ver_file = system_dir.join(VERSION_FILENAME);
        std::fs::write(&ver_file, format!("{}\n", MOD_VERSION))
            .with_context(|| format!("Writing {}", ver_file.display()))?;
        scct_log!("  [VER] Created {} (v{})", VERSION_FILENAME, MOD_VERSION);
    }
    Ok(())
}

/// Deletes `scct_coop_version.txt` from System/ and the game root during uninstallation.
pub fn remove_version_file(game_root: &Path) -> Result<()> {
    let system_dir = find_child_ci(game_root, "System");
    let ver_file = find_child_ci(&system_dir, VERSION_FILENAME);
    if ver_file.is_file() {
        let _ = std::fs::remove_file(&ver_file);
        scct_log!("  [VER] Removed {}", ver_file.display());
    }
    let root_file = find_child_ci(game_root, VERSION_FILENAME);
    if root_file.is_file() {
        let _ = std::fs::remove_file(&root_file);
    }
    Ok(())
}

/// Find a case-insensitive child in `parent`. If not found, returns `parent.join(child)`.
pub fn find_child_ci(parent: &Path, child: &str) -> PathBuf {
    let direct = parent.join(child);
    if direct.exists() {
        return direct;
    }
    let child_lower = child.to_lowercase();
    if let Ok(entries) = std::fs::read_dir(parent) {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().to_lowercase() == child_lower {
                return entry.path();
            }
        }
    }
    direct
}

/// Validate whether `candidate` is a valid game root directory by confirming
/// that `System/splintercell3.exe` (or `System/splintercell3.exe.bak`) exists.
///
/// Returns the canonical / normalized game root path if valid.
pub fn validate_game_root(candidate: &Path) -> Option<PathBuf> {
    if !candidate.exists() {
        return None;
    }

    // 1. Direct check: candidate contains System/splintercell3.exe
    let sys = find_child_ci(candidate, "System");
    if find_child_ci(&sys, "splintercell3.exe").is_file()
        || find_child_ci(&sys, "splintercell3.exe.bak").is_file()
    {
        return Some(candidate.to_path_buf());
    }

    // 2. Check if candidate itself is the "System" directory
    if candidate
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        == Some("system".to_string())
        && (find_child_ci(candidate, "splintercell3.exe").is_file()
            || find_child_ci(candidate, "splintercell3.exe.bak").is_file())
        && let Some(parent) = candidate.parent()
    {
        return Some(parent.to_path_buf());
    }

    // 3. Check if candidate contains splintercell3.exe directly
    if find_child_ci(candidate, "splintercell3.exe").is_file()
        || find_child_ci(candidate, "splintercell3.exe.bak").is_file()
    {
        if let Some(parent) = candidate.parent() {
            if parent
                .file_name()
                .map(|n| n.to_string_lossy().to_lowercase())
                == Some("system".to_string())
                && let Some(grandparent) = parent.parent()
            {
                return Some(grandparent.to_path_buf());
            }
            return Some(parent.to_path_buf());
        }
        return Some(candidate.to_path_buf());
    }

    None
}

/// Auto-detect common Splinter Cell Chaos Theory installation locations:
/// - Current working directory and parent directories
/// - Running executable directory and parent directories
/// - `<disk>\Program Files (x86)\Steam\steamapps\common\Splintercell Chaos Theory`
/// - `<disk>\SteamLibrary\steamapps\common\Splintercell Chaos Theory`
///
/// Returns all detected valid game root paths (deduplicated).
pub fn auto_detect_game_roots() -> Vec<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    // 1. Current working directory and immediate neighborhood
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.clone());
        if let Some(parent) = cwd.parent() {
            candidates.push(parent.to_path_buf());
        }
        candidates.push(
            cwd.join("scct_game_files")
                .join("Tom Clancy's Splinter Cell Chaos Theory"),
        );
        candidates.push(
            cwd.join("clean_scct_files")
                .join("Tom Clancy's Splinter Cell Chaos Theory"),
        );
    }

    // 2. Running executable directory and parent
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        candidates.push(dir.to_path_buf());
        if let Some(parent) = dir.parent() {
            candidates.push(parent.to_path_buf());
        }
    }

    // Folder naming variations across Steam, Uplay, and retail
    let game_folder_names = [
        "Splintercell Chaos Theory",
        "Tom Clancy's Splinter Cell Chaos Theory",
        "Splinter Cell Chaos Theory",
        "Splinter Cell 3",
        "SCCT",
    ];

    // 3. Scan all Windows drive letters (C through Z)
    for drive in b'C'..=b'Z' {
        let letter = drive as char;
        let drive_prefixes = [
            format!(r"{}:\Program Files (x86)\Steam\steamapps\common", letter),
            format!(r"{}:\Program Files\Steam\steamapps\common", letter),
            format!(r"{}:\SteamLibrary\steamapps\common", letter),
            format!(r"{}:\Steam\steamapps\common", letter),
            format!(r"{}:\Games\Steam\steamapps\common", letter),
            format!(r"{}:\Games\SteamLibrary\steamapps\common", letter),
            format!(r"{}:\Games", letter),
            format!(r"{}:\", letter),
        ];
        for prefix in &drive_prefixes {
            for folder in &game_folder_names {
                candidates.push(PathBuf::from(format!(r"{}\{}", prefix, folder)));
            }
        }
    }

    // 4. Linux Steam and Wine / Proton paths
    if let Ok(home) = std::env::var("HOME") {
        let linux_prefixes = [
            format!("{}/.local/share/Steam/steamapps/common", home),
            format!("{}/.steam/steam/steamapps/common", home),
            format!("{}/.steam/root/steamapps/common", home),
            format!(
                "{}/.var/app/com.valvesoftware.Steam/.local/share/Steam/steamapps/common",
                home
            ),
            format!(
                "{}/.wine/drive_c/Program Files (x86)/Steam/steamapps/common",
                home
            ),
            format!("{}/.wine/drive_c/SteamLibrary/steamapps/common", home),
        ];
        for prefix in &linux_prefixes {
            for folder in &game_folder_names {
                candidates.push(PathBuf::from(format!("{}/{}", prefix, folder)));
            }
        }
    }

    let mut detected: Vec<PathBuf> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for candidate in candidates {
        if let Some(valid) = validate_game_root(&candidate) {
            let key = valid
                .canonicalize()
                .unwrap_or_else(|_| valid.clone())
                .to_string_lossy()
                .to_lowercase();
            if seen.insert(key) {
                detected.push(valid);
            }
        }
    }

    detected
}

pub fn resolve_game_root(explicit_arg: Option<&Path>) -> Result<PathBuf> {
    if let Some(arg) = explicit_arg {
        if let Some(valid) = validate_game_root(arg) {
            scct_log!("  [INIT] Using specified game root: {}", valid.display());
            return Ok(valid);
        }
        let abs = if arg.is_absolute() {
            arg.to_path_buf()
        } else {
            std::env::current_dir()?.join(arg)
        };
        if let Some(valid) = validate_game_root(&abs) {
            scct_log!("  [INIT] Using specified game root: {}", valid.display());
            return Ok(valid);
        }
        scct_log!(
            "  [INIT] Using specified path as game root: {}",
            abs.display()
        );
        return Ok(abs);
    }

    let detected = auto_detect_game_roots();
    if let Some(first) = detected.first() {
        scct_log!("  [INIT] Auto-detected game root: {}", first.display());
        return Ok(first.clone());
    }

    let cwd = std::env::current_dir().context("Failed to get current directory")?;
    Ok(cwd)
}

pub fn ensure_clean_sp_maps_and_cleanup(
    maps_dir: &Path,
    gen_loadings_dir: &Path,
    active_coop_stems: &HashSet<String>,
) -> Result<()> {
    if !maps_dir.exists() {
        bail!("Maps directory does not exist: {}", maps_dir.display());
    }

    // Restore any SP .scl that has a .scl.bak backup
    let mut map_entries: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(maps_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        map_entries.push(name);
    }
    map_entries.sort();

    for fname in &map_entries {
        let low = fname.to_lowercase();
        if low.ends_with(".scl.bak") {
            let stem = &fname[..fname.len() - 4];
            let sp_scl = maps_dir.join(stem);
            let sp_bak = maps_dir.join(fname);
            let needs_restore = if !sp_scl.exists() {
                true
            } else {
                let sz_scl = sp_scl.metadata()?.len();
                let sz_bak = sp_bak.metadata()?.len();
                sz_scl != sz_bak
            };
            if needs_restore {
                std::fs::copy(&sp_bak, &sp_scl)?;
                scct_log!("  [SP ] Restored vanilla {} from {}", stem, fname);
            }
        }
    }

    // Remove obsolete generated *_COOP files
    for fname in &map_entries {
        let low = fname.to_lowercase();
        let target = maps_dir.join(fname);

        for suffix in &["_sound.occ", "_sound.uns", ".scl", ".ini"] {
            if low.ends_with(suffix) {
                let stem = &low[..low.len() - suffix.len()];
                if stem.ends_with("_coop")
                    && !VANILLA_COOP_STEMS.contains(&stem)
                    && !active_coop_stems.contains(stem)
                {
                    let _ = std::fs::remove_file(&target);
                }
                break;
            }
        }
    }

    // Clean obsolete Coop loading screens
    if gen_loadings_dir.is_dir() {
        let re_loading = Regex::new(r"(?i)^(.+)_loading_[12]\.dds$").unwrap();

        if let Ok(entries) = std::fs::read_dir(gen_loadings_dir) {
            for entry in entries.flatten() {
                let fname = entry.file_name().to_string_lossy().to_string();
                let target = entry.path();
                if let Some(m) = re_loading.captures(&fname).and_then(|c| c.get(1)) {
                    let stem = m.as_str().to_lowercase();
                    if stem.ends_with("_coop")
                        && !VANILLA_COOP_STEMS.contains(&stem.as_str())
                        && !active_coop_stems.contains(&stem)
                    {
                        let _ = std::fs::remove_file(&target);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Bytecode pattern in `System/Echelon.u` (`EPlayerController.SwitchEEV`, export 6827):
/// `if (!(Level.bMultiplayerMap)) goto 0x0014; return;`
/// Token: 07 14 00 19 01 90 06 00 04 2d 01 d3 01 [04 0b]
const ECHELON_U_EEV_GATE_ORIG: &[u8] = &[
    0x07, 0x14, 0x00, 0x19, 0x01, 0x90, 0x06, 0x00, 0x04, 0x2d, 0x01, 0xd3, 0x01, 0x04, 0x0b,
];

/// Patched bytecode in `System/Echelon.u` (`EPlayerController.SwitchEEV`, export 6827):
/// Replaces `return;` (0x04 0x0b) at mem 0x0012 with two EX_Nothing opcodes (0x0b 0x0b).
/// If `Level.bMultiplayerMap` is True, it falls through the NOPs to mem 0x0014 and calls ProcessEEV().
const ECHELON_U_EEV_GATE_PATCHED: &[u8] = &[
    0x07, 0x14, 0x00, 0x19, 0x01, 0x90, 0x06, 0x00, 0x04, 0x2d, 0x01, 0xd3, 0x01, 0x0b, 0x0b,
];

pub fn is_echelon_u_eev_patched(data: &[u8]) -> bool {
    data.windows(ECHELON_U_EEV_GATE_PATCHED.len())
        .any(|w| w == ECHELON_U_EEV_GATE_PATCHED)
}

pub fn revert_echelon_u_eev_bytes(data: &mut [u8]) -> bool {
    let nlen = ECHELON_U_EEV_GATE_PATCHED.len();
    if let Some(pos) = data
        .windows(nlen)
        .position(|w| w == ECHELON_U_EEV_GATE_PATCHED)
    {
        data[pos..pos + nlen].copy_from_slice(ECHELON_U_EEV_GATE_ORIG);
        return true;
    }
    false
}

pub fn patch_echelon_u_eev_bytes(data: &mut [u8]) -> Result<usize> {
    assert_eq!(
        ECHELON_U_EEV_GATE_ORIG.len(),
        ECHELON_U_EEV_GATE_PATCHED.len()
    );
    let nlen = ECHELON_U_EEV_GATE_ORIG.len();
    if let Some(pos) = data
        .windows(nlen)
        .position(|w| w == ECHELON_U_EEV_GATE_ORIG)
    {
        data[pos..pos + nlen].copy_from_slice(ECHELON_U_EEV_GATE_PATCHED);
        return Ok(pos);
    }
    if let Some(pos) = data
        .windows(nlen)
        .position(|w| w == ECHELON_U_EEV_GATE_PATCHED)
    {
        return Ok(pos);
    }
    bail!("Could not locate EPlayerController.SwitchEEV gate bytecode pattern in Echelon.u");
}

/// Security camera alarm check in `splintercell3.exe` (`EAIZone::StartAlarm`, VA 0x1099BCA4):
/// In multiplayer (`Level->bMultiplayerMap == 1`), `jne 0x1099bccc` (75 1c) skips `TriggerAlarm`.
/// Patch: `75 1c` -> `90 90` (nop; nop).
pub const CAMERA_ALARM_GATE_ORIG: &[u8] = &[
    0x8B, 0x45, 0x78, 0xF6, 0x80, 0xCC, 0x05, 0x00, 0x00, 0x01, 0x75, 0x1C, 0x8B, 0x91, 0xB4, 0x02,
    0x00, 0x00,
];
pub const CAMERA_ALARM_GATE_PATCHED: &[u8] = &[
    0x8B, 0x45, 0x78, 0xF6, 0x80, 0xCC, 0x05, 0x00, 0x00, 0x01, 0x90, 0x90, 0x8B, 0x91, 0xB4, 0x02,
    0x00, 0x00,
];

/// Security camera & sensor universal alarm dispatch in `splintercell3.exe` (`EAIZone::StartAlarm`, VA 0x1099BBB7):
/// At 0x1099BBBD, if `bForceAlarm == 0` (and `bCallFromZone == 0`), `StartAlarm` branches to only alert local guards
/// and returns without triggering the alarm sirens or raising the alarm stage.
/// Turrets, ceiling cameras, and secondary sensors pass `bForceAlarm = 0`.
/// Patch: Replace `jne 0x1099bc53` (0f 85 90 00 00 00) with unconditional `jmp 0x1099bc53; nop` (e9 91 00 00 00 90)
/// so that ALL cameras, sensors, and turrets trigger the alarm dispatch unconditionally upon detection.
pub const CAMERA_ALARM_UNIVERSAL_ORIG: &[u8] = &[
    0x8B, 0x5C, 0x24, 0x40, 0x85, 0xDB, 0x0F, 0x85, 0x90, 0x00, 0x00, 0x00, 0x85, 0xC9,
];
pub const CAMERA_ALARM_UNIVERSAL_PATCHED: &[u8] = &[
    0x8B, 0x5C, 0x24, 0x40, 0x85, 0xDB, 0xE9, 0x91, 0x00, 0x00, 0x00, 0x90, 0x85, 0xC9,
];

/// Security camera alarm force in `splintercell3.exe` (`ESensor::ProcessDetectedPawn`, VA 0x10C57B14):
/// At 0x10C57B22, ESensor calls `EAIZone::StartAlarm(..., bForceAlarm=0)`.
/// Passing bForceAlarm=0 causes `StartAlarm` to only alert local guards and return without ever triggering the alarm sirens.
/// Patch: `push $0x0` (6a 00) -> `push $0x1` (6a 01) forces base alarm triggering upon detection.
pub const CAMERA_ALARM_FORCE_ORIG: &[u8] = &[
    0x8B, 0x8E, 0xF8, 0x03, 0x00, 0x00, 0x85, 0xC9, 0x74, 0x29, 0x8B, 0x45, 0x00, 0x50, 0x6A, 0x00,
    0x05, 0xE8, 0x00, 0x00,
];
pub const CAMERA_ALARM_FORCE_PATCHED: &[u8] = &[
    0x8B, 0x8E, 0xF8, 0x03, 0x00, 0x00, 0x85, 0xC9, 0x74, 0x29, 0x8B, 0x45, 0x00, 0x50, 0x6A, 0x01,
    0x05, 0xE8, 0x00, 0x00,
];

const CAMERA_ALARM_SITES: &[BytePatchSite] = &[
    (
        "EAIZone::StartAlarm gate (0x1099BCA4)",
        CAMERA_ALARM_GATE_ORIG,
        CAMERA_ALARM_GATE_PATCHED,
    ),
    (
        "EAIZone::StartAlarm universal dispatch (0x1099BBB7)",
        CAMERA_ALARM_UNIVERSAL_ORIG,
        CAMERA_ALARM_UNIVERSAL_PATCHED,
    ),
    (
        "ESensor::ProcessDetectedPawn alarm force (0x10C57B14)",
        CAMERA_ALARM_FORCE_ORIG,
        CAMERA_ALARM_FORCE_PATCHED,
    ),
];

pub fn patch_camera_alarm_bytes(data: &mut [u8]) -> Result<usize> {
    patch_byte_sites(data, CAMERA_ALARM_SITES, "camera alarm")
}

/// Non-lethal mission failure Game Over menu in `splintercell3.exe` (`CInGameMenusManager::ThrowMenuEvent(0)`, VA 0x10B25809):
/// When `EndMission(False, 0)` is called in multiplayer, `ThrowMenuEvent(0)` checks viewport and exits
/// without displaying any UI or ending the mission.
/// Patch: Replace the 40 dead bytes with `OpenPauseMenu(0, 0)` call, which displays the multiplayer Game Over screen.
pub const NONLETHAL_GAMEOVER_ORIG: &[u8] = &[
    0x8B, 0x7E, 0x04, 0x85, 0xFF, 0x74, 0x09, 0x8B, 0xCF, 0xE8, 0xC9, 0x84, 0xEE, 0xFF, 0xEB, 0x02,
    0x33, 0xC0, 0x8B, 0x48, 0x44, 0x8B, 0x69, 0x2C, 0x8B, 0xCF, 0xE8, 0xF8, 0x89, 0xEE, 0xFF, 0x3B,
    0x45, 0x00, 0x0F, 0x85, 0xDD, 0x0F, 0x00, 0x00,
];
pub const NONLETHAL_GAMEOVER_PATCHED: &[u8] = &[
    0x6A, 0x00, 0x6A, 0x00, 0x8B, 0xCE, 0xE8, 0x3C, 0xC7, 0xFF, 0xFF, 0xEB, 0x25, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
];

/// Co-op starting AI zone activation in `splintercell3.exe` (`EchelonGameInfo::execAddPlayerInZones`, VA 0x10C10CB9):
/// At 0x10C10CC2, if `Level->bMultiplayerMap == 1`, it checks whether the zone contains player `StartPoints`.
/// In converted SP maps, none of the EAIZones have `StartPoints`, so NO starting zones (including the 'HQ' zone
/// containing Lambert, Grim, Redding, and Turtle as the radio speakers) are enabled on map start.
/// This causes all mission radio dialogues, Lambert reprimands, and failure dialogues to fail because their
/// speaker pawn controller is dormant/NULL.
/// Patch: Replace `je 0x10c10cfe` (74 33) with unconditional `jmp 0x10c10cfe` (eb 33), enabling all `bEnableAtStart`
/// zones at map start in both single-player and multiplayer.
pub const COOP_AIZONE_ENABLE_ORIG: &[u8] = &[
    0xF6, 0x81, 0xC0, 0x02, 0x00, 0x00, 0x02, 0x74, 0x48, 0xF6, 0x80, 0xCC, 0x05, 0x00, 0x00, 0x01,
    0x74, 0x33,
];
pub const COOP_AIZONE_ENABLE_PATCHED: &[u8] = &[
    0xF6, 0x81, 0xC0, 0x02, 0x00, 0x00, 0x02, 0x74, 0x48, 0xF6, 0x80, 0xCC, 0x05, 0x00, 0x00, 0x01,
    0xEB, 0x33,
];

/// Mission end co-op dispatch in `splintercell3.exe` (`EPattern::execEndMission`, VA 0x10B937BB):
/// In clean retail, `execEndMission` tests `Members[0]->bIsPlayer` before checking `Level->bMultiplayerMap`.
/// If `Members[0]` is NULL or not a player pawn, it aborts without calling `EndMissionCoop`.
/// Patch: Check `Level->bMultiplayerMap` first; if multiplayer, jump directly to 0x10B937D8
/// (`Level->Game->pPlayerList[0]->EndMissionCoop(bMissionComplete, iFailureType)`).
pub const COOP_ENDMISSION_DISPATCH_ORIG: &[u8] = &[
    0x8B, 0x8F, 0xC8, 0x02, 0x00, 0x00, 0x8A, 0x91, 0xC0, 0x02, 0x00, 0x00, 0xB0, 0x01, 0x84, 0xD0,
    0x74, 0x3D, 0x8B, 0x7F, 0x78, 0x84, 0x87, 0xCC, 0x05, 0x00, 0x00, 0x74, 0x23,
];
pub const COOP_ENDMISSION_DISPATCH_PATCHED: &[u8] = &[
    0x8B, 0x7F, 0x78, 0xF6, 0x87, 0xCC, 0x05, 0x00, 0x00, 0x01, 0x75, 0x11, 0xEB, 0x32, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
];

const NONLETHAL_GAMEOVER_MENU_SITES: &[BytePatchSite] = &[(
    "CInGameMenusManager::ThrowMenuEvent(0) Game Over (0x10B25809)",
    NONLETHAL_GAMEOVER_ORIG,
    NONLETHAL_GAMEOVER_PATCHED,
)];

const COOP_AIZONE_ENABLE_SITES: &[BytePatchSite] = &[(
    "EchelonGameInfo::execAddPlayerInZones AI zone enable (0x10C10CB9)",
    COOP_AIZONE_ENABLE_ORIG,
    COOP_AIZONE_ENABLE_PATCHED,
)];

const COOP_ENDMISSION_DISPATCH_SITES: &[BytePatchSite] = &[(
    "EPattern::execEndMission multiplayer dispatch (0x10B937BB)",
    COOP_ENDMISSION_DISPATCH_ORIG,
    COOP_ENDMISSION_DISPATCH_PATCHED,
)];

const NONLETHAL_GAMEOVER_SITES: &[BytePatchSite] = &[
    NONLETHAL_GAMEOVER_MENU_SITES[0],
    COOP_ENDMISSION_DISPATCH_SITES[0],
];

pub fn patch_nonlethal_gameover_bytes(data: &mut [u8]) -> Result<usize> {
    let menu_pos = patch_byte_sites(data, NONLETHAL_GAMEOVER_SITES, "non-lethal game over")?;
    // Match e83f055/HEAD: actively revert COOP_AIZONE_ENABLE back to vanilla (74 33)
    // so lockstep simulation does not desync when standard fixes are applied.
    revert_coop_aizone_enable_bytes(data);
    Ok(menu_pos)
}

pub fn is_camera_alarm_patched(data: &[u8]) -> bool {
    are_byte_sites_patched(data, CAMERA_ALARM_SITES)
}

pub fn is_nonlethal_gameover_patched(data: &[u8]) -> bool {
    are_byte_sites_patched(data, NONLETHAL_GAMEOVER_SITES)
        && !is_coop_aizone_enable_patched(data)
}

pub fn is_nonlethal_gameover_menu_patched(data: &[u8]) -> bool {
    are_byte_sites_patched(data, NONLETHAL_GAMEOVER_MENU_SITES)
}

pub fn patch_nonlethal_gameover_menu_bytes(data: &mut [u8]) -> Result<usize> {
    patch_byte_sites(
        data,
        NONLETHAL_GAMEOVER_MENU_SITES,
        "non-lethal game over menu",
    )
}

pub fn revert_nonlethal_gameover_menu_bytes(data: &mut [u8]) -> bool {
    revert_byte_sites(data, NONLETHAL_GAMEOVER_MENU_SITES)
}

pub fn is_coop_aizone_enable_patched(data: &[u8]) -> bool {
    are_byte_sites_patched(data, COOP_AIZONE_ENABLE_SITES)
}

pub fn patch_coop_aizone_enable_bytes(data: &mut [u8]) -> Result<usize> {
    patch_byte_sites(
        data,
        COOP_AIZONE_ENABLE_SITES,
        "execAddPlayerInZones AI zone enable",
    )
}

pub fn revert_coop_aizone_enable_bytes(data: &mut [u8]) -> bool {
    revert_byte_sites(data, COOP_AIZONE_ENABLE_SITES)
}

pub fn is_coop_endmission_dispatch_patched(data: &[u8]) -> bool {
    are_byte_sites_patched(data, COOP_ENDMISSION_DISPATCH_SITES)
}

pub fn patch_coop_endmission_dispatch_bytes(data: &mut [u8]) -> Result<usize> {
    patch_byte_sites(
        data,
        COOP_ENDMISSION_DISPATCH_SITES,
        "EPattern::execEndMission coop dispatch",
    )
}

pub fn revert_coop_endmission_dispatch_bytes(data: &mut [u8]) -> bool {
    revert_byte_sites(data, COOP_ENDMISSION_DISPATCH_SITES)
}

/// Render-only synchronized RNG redirection in `splintercell3.exe` (`FDynamicLight` flicker,
/// `AEPawn::vt+0x70` eye animation, and `AESensor::vt+0x70` look jitter):
///
/// The multiplayer lockstep checks `MT19937` call counts (`slot=5`). Functions called strictly
/// during local camera rendering or `VisibleZoneMask`-culled visual effects must use
/// `appUnsyncedFrand` (`0x10CCAC70`) / `appUnsyncedRand` (`0x10CCAC20`) rather than synced
/// `appFrand` (`0x10CCAC40`) / `appRand` (`0x10CCAC00`), or differing P1/P2 viewpoints desync
/// the RNG counter on Step 7 (e.g. `04_Penthouse_COOP` `Light2` flickering right at spawn).
///
/// 1. `FDynamicLight` flicker (`0x10AC04B0`, call @ `0x10AC04C1`): `appFrand` -> `appUnsyncedFrand`.
pub const FDYNAMICLIGHT_FLICKER_RNG_ORIG: &[u8] = &[
    0x74, 0x04, 0x3C, 0x03, 0x75, 0x4C, 0x80, 0xB9, 0xE4, 0x02, 0x00, 0x00, 0x02, 0x75, 0x43, 0xDD,
    0xD8, 0xE8, 0x7A, 0xA7, 0x20, 0x00, 0x8B, 0x0E, 0x0F, 0xB6, 0x91, 0xB7, 0x02, 0x00, 0x00, 0x8B,
];
pub const FDYNAMICLIGHT_FLICKER_RNG_PATCHED: &[u8] = &[
    0x74, 0x04, 0x3C, 0x03, 0x75, 0x4C, 0x80, 0xB9, 0xE4, 0x02, 0x00, 0x00, 0x02, 0x75, 0x43, 0xDD,
    0xD8, 0xE8, 0xAA, 0xA7, 0x20, 0x00, 0x8B, 0x0E, 0x0F, 0xB6, 0x91, 0xB7, 0x02, 0x00, 0x00, 0x8B,
];

/// 2. `AEPawn::vt+0x70` `bEyeAnimation` (`0x10B8638C`, calls @ `0x10B86392`, `0x10B863C7`,
///    `0x10B863E8`, `0x10B86409`): facial bones in the same function already use `appUnsyncedFrand`;
///    eye animation still called synced `appFrand`/`appRand` under `VisibleZoneMask` culling.
pub const AEPAWN_EYE_ANIM_RNG_ORIG: &[u8] = &[
    0x0F, 0x8A, 0x0A, 0x01, 0x00, 0x00, 0xE8, 0xA9, 0x48, 0x14, 0x00, 0x39, 0xAE, 0xD4, 0x07, 0x00,
    0x00, 0xD8, 0x0D, 0x38, 0xA2, 0x0B, 0x11, 0xD8, 0x05, 0x40, 0xA2, 0x0B, 0x11, 0xD9, 0x9E, 0xCC,
    0x07, 0x00, 0x00, 0x0F, 0x85, 0x9C, 0x00, 0x00, 0x00, 0x89, 0xAE, 0xD8, 0x07, 0x00, 0x00, 0x89,
    0xAE, 0xD4, 0x07, 0x00, 0x00, 0x89, 0xAE, 0xD0, 0x07, 0x00, 0x00, 0xE8, 0x34, 0x48, 0x14, 0x00,
    0x99, 0xB9, 0x70, 0x17, 0x00, 0x00, 0xF7, 0xF9, 0x8B, 0x8E, 0xD4, 0x07, 0x00, 0x00, 0x81, 0xEA,
    0xB8, 0x0B, 0x00, 0x00, 0x03, 0xCA, 0x89, 0x8E, 0xD4, 0x07, 0x00, 0x00, 0xE8, 0x13, 0x48, 0x14,
    0x00, 0x99, 0xB9, 0x70, 0x17, 0x00, 0x00, 0xF7, 0xF9, 0x8B, 0x9E, 0xD8, 0x07, 0x00, 0x00, 0x81,
    0xEA, 0xB8, 0x0B, 0x00, 0x00, 0x03, 0xDA, 0x89, 0x9E, 0xD8, 0x07, 0x00, 0x00, 0xE8, 0x32, 0x48,
    0x14, 0x00, 0xD8, 0x0D, 0x3C, 0xA2,
];
pub const AEPAWN_EYE_ANIM_RNG_PATCHED: &[u8] = &[
    0x0F, 0x8A, 0x0A, 0x01, 0x00, 0x00, 0xE8, 0xD9, 0x48, 0x14, 0x00, 0x39, 0xAE, 0xD4, 0x07, 0x00,
    0x00, 0xD8, 0x0D, 0x38, 0xA2, 0x0B, 0x11, 0xD8, 0x05, 0x40, 0xA2, 0x0B, 0x11, 0xD9, 0x9E, 0xCC,
    0x07, 0x00, 0x00, 0x0F, 0x85, 0x9C, 0x00, 0x00, 0x00, 0x89, 0xAE, 0xD8, 0x07, 0x00, 0x00, 0x89,
    0xAE, 0xD4, 0x07, 0x00, 0x00, 0x89, 0xAE, 0xD0, 0x07, 0x00, 0x00, 0xE8, 0x54, 0x48, 0x14, 0x00,
    0x99, 0xB9, 0x70, 0x17, 0x00, 0x00, 0xF7, 0xF9, 0x8B, 0x8E, 0xD4, 0x07, 0x00, 0x00, 0x81, 0xEA,
    0xB8, 0x0B, 0x00, 0x00, 0x03, 0xCA, 0x89, 0x8E, 0xD4, 0x07, 0x00, 0x00, 0xE8, 0x33, 0x48, 0x14,
    0x00, 0x99, 0xB9, 0x70, 0x17, 0x00, 0x00, 0xF7, 0xF9, 0x8B, 0x9E, 0xD8, 0x07, 0x00, 0x00, 0x81,
    0xEA, 0xB8, 0x0B, 0x00, 0x00, 0x03, 0xDA, 0x89, 0x9E, 0xD8, 0x07, 0x00, 0x00, 0xE8, 0x62, 0x48,
    0x14, 0x00, 0xD8, 0x0D, 0x3C, 0xA2,
];

/// 3. `AESensor::vt+0x70` visual look jitter (`0x10C56F0B`, calls @ `0x10C56F13`, `0x10C56F28`,
///    `0x10C56F3D`): called under `VisibleZoneMask` culling; switches to `appUnsyncedFrand`.
pub const AESENSOR_LOOK_RNG_ORIG: &[u8] = &[
    0xC4, 0x05, 0x0F, 0x8A, 0xBA, 0x00, 0x00, 0x00, 0xE8, 0x28, 0x3D, 0x07, 0x00, 0xD8, 0x0D, 0x90,
    0x87, 0x0E, 0x11, 0xD8, 0x25, 0x7C, 0x69, 0x10, 0x11, 0xD9, 0x5C, 0x24, 0x10, 0xE8, 0x13, 0x3D,
    0x07, 0x00, 0xD8, 0x0D, 0x90, 0x87, 0x0E, 0x11, 0xD8, 0x25, 0x7C, 0x69, 0x10, 0x11, 0xD9, 0x5C,
    0x24, 0x18, 0xE8, 0xFE, 0x3C, 0x07, 0x00, 0xDC, 0x0D, 0xE0, 0x45, 0x0D, 0x11, 0xDC, 0x05, 0xF0,
];
pub const AESENSOR_LOOK_RNG_PATCHED: &[u8] = &[
    0xC4, 0x05, 0x0F, 0x8A, 0xBA, 0x00, 0x00, 0x00, 0xE8, 0x58, 0x3D, 0x07, 0x00, 0xD8, 0x0D, 0x90,
    0x87, 0x0E, 0x11, 0xD8, 0x25, 0x7C, 0x69, 0x10, 0x11, 0xD9, 0x5C, 0x24, 0x10, 0xE8, 0x43, 0x3D,
    0x07, 0x00, 0xD8, 0x0D, 0x90, 0x87, 0x0E, 0x11, 0xD8, 0x25, 0x7C, 0x69, 0x10, 0x11, 0xD9, 0x5C,
    0x24, 0x18, 0xE8, 0x2E, 0x3D, 0x07, 0x00, 0xDC, 0x0D, 0xE0, 0x45, 0x0D, 0x11, 0xDC, 0x05, 0xF0,
];

type BytePatchSite = (&'static str, &'static [u8], &'static [u8]);

fn patch_byte_sites(data: &mut [u8], sites: &[BytePatchSite], context: &str) -> Result<usize> {
    let mut first_pos = None;
    for &(name, orig, patched) in sites {
        assert_eq!(orig.len(), patched.len());
        let len = orig.len();
        if let Some(pos) = data.windows(len).position(|w| w == orig) {
            data[pos..pos + len].copy_from_slice(patched);
            first_pos.get_or_insert(pos);
        } else if let Some(pos) = data.windows(len).position(|w| w == patched) {
            first_pos.get_or_insert(pos);
        } else {
            bail!(
                "Could not locate {} {} pattern in splintercell3.exe",
                name,
                context
            );
        }
    }
    Ok(first_pos.unwrap_or(0))
}

fn are_byte_sites_patched(data: &[u8], sites: &[BytePatchSite]) -> bool {
    sites
        .iter()
        .all(|&(_, _, patched)| data.windows(patched.len()).any(|w| w == patched))
}

fn revert_byte_sites_count(data: &mut [u8], sites: &[BytePatchSite]) -> usize {
    let mut reverted = 0usize;
    for &(_, orig, patched) in sites {
        let len = patched.len();
        if let Some(pos) = data.windows(len).position(|w| w == patched) {
            data[pos..pos + len].copy_from_slice(orig);
            reverted += 1;
        }
    }
    reverted
}

fn revert_byte_sites(data: &mut [u8], sites: &[BytePatchSite]) -> bool {
    revert_byte_sites_count(data, sites) > 0
}

const RENDER_RNG_SITES: &[BytePatchSite] = &[
    (
        "FDynamicLight flicker (0x10AC04C1)",
        FDYNAMICLIGHT_FLICKER_RNG_ORIG,
        FDYNAMICLIGHT_FLICKER_RNG_PATCHED,
    ),
    (
        "AEPawn::vt+0x70 eye animation (0x10B86392..0x10B86409)",
        AEPAWN_EYE_ANIM_RNG_ORIG,
        AEPAWN_EYE_ANIM_RNG_PATCHED,
    ),
    (
        "AESensor::vt+0x70 look jitter (0x10C56F13..0x10C56F3D)",
        AESENSOR_LOOK_RNG_ORIG,
        AESENSOR_LOOK_RNG_PATCHED,
    ),
];

/// Redirects render-only `appFrand`/`appRand` calls to `appUnsyncedFrand`/`appUnsyncedRand`.
pub fn patch_unsynced_render_rng_bytes(data: &mut [u8]) -> Result<usize> {
    patch_byte_sites(data, RENDER_RNG_SITES, "RNG")
}

/// Returns whether all render-only RNG redirections are applied.
pub fn is_unsynced_render_rng_patched(data: &[u8]) -> bool {
    are_byte_sites_patched(data, RENDER_RNG_SITES)
}

/// Exclude render-mutated `Pawn->Controller->Location/Rotation` from `UserChecksum0` in
/// `AEPawn::Tick` (`0x10B8A517..0x10B8A547`):
///
/// `AEPawn::Tick` already hashes `Pawn->Location` (`0x10B8A503`) and `Pawn->Rotation`
/// (`0x10B8A515`). For player pawns (`[esi+0x2C] & 0x20`), it also hashed
/// `Controller->Location` and `Controller->Rotation`, even though `Viewport::Draw` ->
/// `PlayerCalcView` -> `AEPlayerCam::execFollowingCalcView` (`UpdateLocationForSam` at
/// `0x10C08150` / `SetLocation` at `0x10C0D7AC`) overwrites `m_EPC->Location` during rendering
/// outside lockstep ticks. Changing `je 0x10B8A548` (`0x74 0x27`) at `0x10B8A51F` to
/// `jmp 0x10B8A548` (`0xEB 0x27`) preserves `Pawn->Location`/`Rotation` checksums while
/// ignoring camera/render-driven controller transforms.
pub const AEPAWN_CONTROLLER_CHECKSUM_ORIG: &[u8] = &[
    0x8A, 0x46, 0x2C, 0x83, 0xC4, 0x18, 0xA8, 0x20, 0x74, 0x27, 0x8B, 0x86, 0xB4, 0x02, 0x00, 0x00,
    0x6A, 0x01, 0x8D, 0x88, 0xE8, 0x00, 0x00, 0x00, 0x51, 0x50, 0xFF, 0xD7, 0x8B, 0x86, 0xB4, 0x02,
    0x00, 0x00, 0x6A, 0x01, 0x8D, 0x90, 0xF4, 0x00, 0x00, 0x00, 0x52, 0x50, 0xFF, 0xD3, 0x83, 0xC4,
    0x18,
];
pub const AEPAWN_CONTROLLER_CHECKSUM_PATCHED: &[u8] = &[
    0x8A, 0x46, 0x2C, 0x83, 0xC4, 0x18, 0xA8, 0x20, 0xEB, 0x27, 0x8B, 0x86, 0xB4, 0x02, 0x00, 0x00,
    0x6A, 0x01, 0x8D, 0x88, 0xE8, 0x00, 0x00, 0x00, 0x51, 0x50, 0xFF, 0xD7, 0x8B, 0x86, 0xB4, 0x02,
    0x00, 0x00, 0x6A, 0x01, 0x8D, 0x90, 0xF4, 0x00, 0x00, 0x00, 0x52, 0x50, 0xFF, 0xD3, 0x83, 0xC4,
    0x18,
];

const CONTROLLER_CHECKSUM_SITES: &[BytePatchSite] = &[(
    "AEPawn::Tick Controller Location/Rotation checksum (0x10B8A517)",
    AEPAWN_CONTROLLER_CHECKSUM_ORIG,
    AEPAWN_CONTROLLER_CHECKSUM_PATCHED,
)];

/// Excludes `Pawn->Controller->Location/Rotation` from `UserChecksum0` in `AEPawn::Tick`.
pub fn patch_controller_checksum_bytes(data: &mut [u8]) -> Result<usize> {
    patch_byte_sites(data, CONTROLLER_CHECKSUM_SITES, "checksum")
}

/// Returns whether the `AEPawn::Tick` controller checksum exclusion patch is applied.
pub fn is_controller_checksum_patched(data: &[u8]) -> bool {
    are_byte_sites_patched(data, CONTROLLER_CHECKSUM_SITES)
}

/// Skeletal bone evaluation & `LastRenderTime` determinism fixes in `splintercell3.exe`:
///
/// 1. `USkeletalMeshInstance::GetBoneMatrix` (`0x109D243C`, file offset `0x0D241E..0x0D2448`):
///    NOPs the `je` bypass when `bForceCompute == 0` so stale-frame bone queries evaluate `GetFrame`
///    even for meshes off-screen on the local client (prevents 1-tick AI transition lag such as
///    `04_Penthouse_COOP` `EUSNationalGuardSoldier3` at Step 120).
pub const USKELMESH_GETBONEMATRIX_ORIG: &[u8] = &[
    0x8B, 0x46, 0x64, 0x3B, 0x05, 0x3C, 0x8B, 0x1C, 0x11, 0x7F, 0x3B, 0x7C, 0x0B, 0x8B, 0x4E, 0x60,
    0x3B, 0x0D, 0x38, 0x8B, 0x1C, 0x11, 0x73, 0x2E, 0x8B, 0x44, 0x24, 0x14, 0x85, 0xC0, 0x74, 0x26,
    0x8B, 0x16, 0x8B, 0xCE, 0xFF, 0x92, 0x80, 0x00, 0x00, 0x00,
];
pub const USKELMESH_GETBONEMATRIX_PATCHED: &[u8] = &[
    0x8B, 0x46, 0x64, 0x3B, 0x05, 0x3C, 0x8B, 0x1C, 0x11, 0x7F, 0x3B, 0x7C, 0x0B, 0x8B, 0x4E, 0x60,
    0x3B, 0x0D, 0x38, 0x8B, 0x1C, 0x11, 0x73, 0x2E, 0x8B, 0x44, 0x24, 0x14, 0x85, 0xC0, 0x90, 0x90,
    0x8B, 0x16, 0x8B, 0xCE, 0xFF, 0x92, 0x80, 0x00, 0x00, 0x00,
];

/// 2. `USkeletalMeshInstance::GetBoneLocation` (`0x109D24E0`, file offset `0x0D24C2..0x0D24EC`).
pub const USKELMESH_GETBONELOCATION_ORIG: &[u8] = &[
    0x8B, 0x43, 0x64, 0x3B, 0x05, 0x3C, 0x8B, 0x1C, 0x11, 0x7F, 0x3B, 0x7C, 0x0B, 0x8B, 0x4B, 0x60,
    0x3B, 0x0D, 0x38, 0x8B, 0x1C, 0x11, 0x73, 0x2E, 0x8B, 0x44, 0x24, 0x78, 0x85, 0xC0, 0x74, 0x26,
    0x8B, 0x13, 0x8B, 0xCB, 0xFF, 0x92, 0x80, 0x00, 0x00, 0x00,
];
pub const USKELMESH_GETBONELOCATION_PATCHED: &[u8] = &[
    0x8B, 0x43, 0x64, 0x3B, 0x05, 0x3C, 0x8B, 0x1C, 0x11, 0x7F, 0x3B, 0x7C, 0x0B, 0x8B, 0x4B, 0x60,
    0x3B, 0x0D, 0x38, 0x8B, 0x1C, 0x11, 0x73, 0x2E, 0x8B, 0x44, 0x24, 0x78, 0x85, 0xC0, 0x90, 0x90,
    0x8B, 0x13, 0x8B, 0xCB, 0xFF, 0x92, 0x80, 0x00, 0x00, 0x00,
];

/// 3. `USkeletalMeshInstance::GetBoneCoords` (`0x109D25A6`, file offset `0x0D2585..0x0D25B2`).
pub const USKELMESH_GETBONECOORDS_ORIG: &[u8] = &[
    0x8B, 0x43, 0x64, 0x3B, 0x05, 0x3C, 0x8B, 0x1C, 0x11, 0x7F, 0x3E, 0x7C, 0x0B, 0x8B, 0x4B, 0x60,
    0x3B, 0x0D, 0x38, 0x8B, 0x1C, 0x11, 0x73, 0x31, 0x8B, 0x84, 0x24, 0x38, 0x01, 0x00, 0x00, 0x85,
    0xC0, 0x74, 0x26, 0x8B, 0x13, 0x8B, 0xCB, 0xFF, 0x92, 0x80, 0x00, 0x00, 0x00,
];
pub const USKELMESH_GETBONECOORDS_PATCHED: &[u8] = &[
    0x8B, 0x43, 0x64, 0x3B, 0x05, 0x3C, 0x8B, 0x1C, 0x11, 0x7F, 0x3E, 0x7C, 0x0B, 0x8B, 0x4B, 0x60,
    0x3B, 0x0D, 0x38, 0x8B, 0x1C, 0x11, 0x73, 0x31, 0x8B, 0x84, 0x24, 0x38, 0x01, 0x00, 0x00, 0x85,
    0xC0, 0x90, 0x90, 0x8B, 0x13, 0x8B, 0xCB, 0xFF, 0x92, 0x80, 0x00, 0x00, 0x00,
];

/// 4. `USkeletalMeshInstance::GetAttachmentCoords` (`0x109E1AC1`, file offset `0x0E1AA0..0x0E1ACD`).
pub const USKELMESH_GETATTACHMENTCOORDS_ORIG: &[u8] = &[
    0x8B, 0x43, 0x64, 0x3B, 0x05, 0x3C, 0x8B, 0x1C, 0x11, 0x7F, 0x3E, 0x7C, 0x0B, 0x8B, 0x4B, 0x60,
    0x3B, 0x0D, 0x38, 0x8B, 0x1C, 0x11, 0x73, 0x31, 0x8B, 0x84, 0x24, 0x48, 0x01, 0x00, 0x00, 0x85,
    0xC0, 0x74, 0x26, 0x8B, 0x13, 0x8B, 0xCB, 0xFF, 0x92, 0x80, 0x00, 0x00, 0x00,
];
pub const USKELMESH_GETATTACHMENTCOORDS_PATCHED: &[u8] = &[
    0x8B, 0x43, 0x64, 0x3B, 0x05, 0x3C, 0x8B, 0x1C, 0x11, 0x7F, 0x3E, 0x7C, 0x0B, 0x8B, 0x4B, 0x60,
    0x3B, 0x0D, 0x38, 0x8B, 0x1C, 0x11, 0x73, 0x31, 0x8B, 0x84, 0x24, 0x48, 0x01, 0x00, 0x00, 0x85,
    0xC0, 0x90, 0x90, 0x8B, 0x13, 0x8B, 0xCB, 0xFF, 0x92, 0x80, 0x00, 0x00, 0x00,
];

/// 5. `USkeletalMeshInstance::GetFrame` (`0x109F5309`, file offset `0x0F52EF..0x0F5315`):
///    Changes `je 0x109F5341` (`74 36`) -> `jmp 0x109F5341` (`EB 36`) so `[esp+0x38]` keeps
///    `(CachedFrameCounter == GFrameCounter)` — `UViewport::Draw` still skins vertices into the D3D
///    buffer, then exits cleanly at `0x109F5E5A` without double-stepping bone rotation controllers.
pub const USKELMESH_GETFRAME_ORIG: &[u8] = &[
    0x8B, 0x0D, 0x94, 0x27, 0x23, 0x11, 0x8B, 0x9C, 0x24, 0xF4, 0x02, 0x00, 0x00, 0x3B, 0xCE, 0x8B,
    0x8C, 0x24, 0xF8, 0x02, 0x00, 0x00, 0x89, 0x44, 0x24, 0x38, 0x74, 0x36, 0x3B, 0xDE, 0x74, 0x2C,
    0x8B, 0x43, 0x78, 0x3B, 0xC6,
];
pub const USKELMESH_GETFRAME_PATCHED: &[u8] = &[
    0x8B, 0x0D, 0x94, 0x27, 0x23, 0x11, 0x8B, 0x9C, 0x24, 0xF4, 0x02, 0x00, 0x00, 0x3B, 0xCE, 0x8B,
    0x8C, 0x24, 0xF8, 0x02, 0x00, 0x00, 0x89, 0x44, 0x24, 0x38, 0xEB, 0x36, 0x3B, 0xDE, 0x74, 0x2C,
    0x8B, 0x43, 0x78, 0x3B, 0xC6,
];

/// 6. `AEAIController::PawnWasRenderedRecently` (`0x10B9A66D`, file offset `0x29A650..0x29A678`):
///    Changes `jp 0x10B9A675` (`7A 06`) -> `jmp 0x10B9A675` (`EB 06`) so `LastRenderTime <= 0.2f`
///    AI scoring, attachment updates, ambient triggers, and `GetEyeInfo` behave identically.
pub const AEAICONTROLLER_RENDER_GATE_ORIG: &[u8] = &[
    0x8B, 0x41, 0x78, 0xD9, 0x80, 0x30, 0x04, 0x00, 0x00, 0x8B, 0x89, 0x1C, 0x04, 0x00, 0x00, 0xD8,
    0x61, 0x50, 0xD8, 0x1D, 0xA8, 0xCA, 0x0B, 0x11, 0xDF, 0xE0, 0xF6, 0xC4, 0x05, 0x7A, 0x06, 0xB8,
    0x01, 0x00, 0x00, 0x00, 0xC3, 0x33, 0xC0, 0xC3,
];
pub const AEAICONTROLLER_RENDER_GATE_PATCHED: &[u8] = &[
    0x8B, 0x41, 0x78, 0xD9, 0x80, 0x30, 0x04, 0x00, 0x00, 0x8B, 0x89, 0x1C, 0x04, 0x00, 0x00, 0xD8,
    0x61, 0x50, 0xD8, 0x1D, 0xA8, 0xCA, 0x0B, 0x11, 0xDF, 0xE0, 0xF6, 0xC4, 0x05, 0xEB, 0x06, 0xB8,
    0x01, 0x00, 0x00, 0x00, 0xC3, 0x33, 0xC0, 0xC3,
];

/// 7. `AEAIController` off-screen `1.75x` `GroundSpeed` boost (`0x10BB53D0`, file offset `0x2B53B0..0x2B53EE`):
///    Changes `jne 0x10BB53EE` (`75 1C`) -> `jmp 0x10BB53EE` (`EB 1C`) to disable the unsynced
///    off-screen speed multiplier.
pub const AEAICONTROLLER_OFFSCREEN_SPEED_ORIG: &[u8] = &[
    0x8B, 0x56, 0x78, 0x8B, 0x8E, 0x1C, 0x04, 0x00, 0x00, 0xD9, 0x82, 0x30, 0x04, 0x00, 0x00, 0xD8,
    0x61, 0x50, 0x83, 0xC4, 0x0C, 0xD8, 0x1D, 0xA8, 0xCA, 0x0B, 0x11, 0xDF, 0xE0, 0xF6, 0xC4, 0x41,
    0x75, 0x1C, 0x83, 0xFB, 0x04, 0x74, 0x05, 0x83, 0xFB, 0x06, 0x75, 0x12, 0xD9, 0x81, 0xE8, 0x02,
    0x00, 0x00, 0xD8, 0x0D, 0x28, 0x88, 0x0E, 0x11, 0xD9, 0x99, 0xE8, 0x02, 0x00, 0x00,
];
pub const AEAICONTROLLER_OFFSCREEN_SPEED_PATCHED: &[u8] = &[
    0x8B, 0x56, 0x78, 0x8B, 0x8E, 0x1C, 0x04, 0x00, 0x00, 0xD9, 0x82, 0x30, 0x04, 0x00, 0x00, 0xD8,
    0x61, 0x50, 0x83, 0xC4, 0x0C, 0xD8, 0x1D, 0xA8, 0xCA, 0x0B, 0x11, 0xDF, 0xE0, 0xF6, 0xC4, 0x41,
    0xEB, 0x1C, 0x83, 0xFB, 0x04, 0x74, 0x05, 0x83, 0xFB, 0x06, 0x75, 0x12, 0xD9, 0x81, 0xE8, 0x02,
    0x00, 0x00, 0xD8, 0x0D, 0x28, 0x88, 0x0E, 0x11, 0xD9, 0x99, 0xE8, 0x02, 0x00, 0x00,
];

pub const SKEL_BONE_SYNC_SITES: &[BytePatchSite] = &[
    (
        "USKELMESH_GETBONEMATRIX_SYNC (0x109D243C)",
        USKELMESH_GETBONEMATRIX_ORIG,
        USKELMESH_GETBONEMATRIX_PATCHED,
    ),
    (
        "USKELMESH_GETBONELOCATION_SYNC (0x109D24E0)",
        USKELMESH_GETBONELOCATION_ORIG,
        USKELMESH_GETBONELOCATION_PATCHED,
    ),
    (
        "USKELMESH_GETBONECOORDS_SYNC (0x109D25A6)",
        USKELMESH_GETBONECOORDS_ORIG,
        USKELMESH_GETBONECOORDS_PATCHED,
    ),
    (
        "USKELMESH_GETATTACHMENTCOORDS_SYNC (0x109E1AC1)",
        USKELMESH_GETATTACHMENTCOORDS_ORIG,
        USKELMESH_GETATTACHMENTCOORDS_PATCHED,
    ),
    (
        "USKELMESH_GETFRAME_ONCE_PER_TICK (0x109F5309)",
        USKELMESH_GETFRAME_ORIG,
        USKELMESH_GETFRAME_PATCHED,
    ),
    (
        "AEAICONTROLLER_RENDER_GATE_SYNC (0x10B9A66D)",
        AEAICONTROLLER_RENDER_GATE_ORIG,
        AEAICONTROLLER_RENDER_GATE_PATCHED,
    ),
    (
        "AEAICONTROLLER_OFFSCREEN_SPEED_SYNC (0x10BB53D0)",
        AEAICONTROLLER_OFFSCREEN_SPEED_ORIG,
        AEAICONTROLLER_OFFSCREEN_SPEED_PATCHED,
    ),
];

/// Enforces deterministic skeletal bone evaluation and neutralizes `LastRenderTime` AI gates.
pub fn patch_skel_bone_sync_bytes(data: &mut [u8]) -> Result<usize> {
    patch_byte_sites(
        data,
        SKEL_BONE_SYNC_SITES,
        "skeletal bone / LastRenderTime sync",
    )
}

/// Returns whether all skeletal bone / `LastRenderTime` sync fixes are applied.
pub fn is_skel_bone_sync_patched(data: &[u8]) -> bool {
    are_byte_sites_patched(data, SKEL_BONE_SYNC_SITES)
}

pub fn revert_camera_alarm_bytes(data: &mut [u8]) -> bool {
    revert_byte_sites(data, CAMERA_ALARM_SITES)
}

pub fn revert_nonlethal_gameover_bytes(data: &mut [u8]) -> bool {
    let mut reverted = revert_byte_sites(data, NONLETHAL_GAMEOVER_SITES);
    reverted |= revert_coop_aizone_enable_bytes(data);
    reverted
}

pub fn revert_unsynced_render_rng_bytes(data: &mut [u8]) -> bool {
    revert_byte_sites(data, RENDER_RNG_SITES)
}

pub fn revert_controller_checksum_bytes(data: &mut [u8]) -> bool {
    revert_byte_sites(data, CONTROLLER_CHECKSUM_SITES)
}

pub fn revert_skel_bone_sync_bytes(data: &mut [u8]) -> usize {
    revert_byte_sites_count(data, SKEL_BONE_SYNC_SITES)
}

pub const SKEL_GETFRAME_ONCE_SITES: &[BytePatchSite] = &[(
    "USKELMESH_GETFRAME_ONCE_PER_TICK (0x109F5309)",
    USKELMESH_GETFRAME_ORIG,
    USKELMESH_GETFRAME_PATCHED,
)];

pub const SKEL_BONE_FORCE_COMPUTE_SITES: &[BytePatchSite] = &[
    (
        "USKELMESH_GETBONEMATRIX_SYNC (0x109D243C)",
        USKELMESH_GETBONEMATRIX_ORIG,
        USKELMESH_GETBONEMATRIX_PATCHED,
    ),
    (
        "USKELMESH_GETBONELOCATION_SYNC (0x109D24E0)",
        USKELMESH_GETBONELOCATION_ORIG,
        USKELMESH_GETBONELOCATION_PATCHED,
    ),
    (
        "USKELMESH_GETBONECOORDS_SYNC (0x109D25A6)",
        USKELMESH_GETBONECOORDS_ORIG,
        USKELMESH_GETBONECOORDS_PATCHED,
    ),
    (
        "USKELMESH_GETATTACHMENTCOORDS_SYNC (0x109E1AC1)",
        USKELMESH_GETATTACHMENTCOORDS_ORIG,
        USKELMESH_GETATTACHMENTCOORDS_PATCHED,
    ),
];

pub const AI_RENDER_GATE_SYNC_SITES: &[BytePatchSite] = &[
    (
        "AEAICONTROLLER_RENDER_GATE_SYNC (0x10B9A66D)",
        AEAICONTROLLER_RENDER_GATE_ORIG,
        AEAICONTROLLER_RENDER_GATE_PATCHED,
    ),
    (
        "AEAICONTROLLER_OFFSCREEN_SPEED_SYNC (0x10BB53D0)",
        AEAICONTROLLER_OFFSCREEN_SPEED_ORIG,
        AEAICONTROLLER_OFFSCREEN_SPEED_PATCHED,
    ),
];

pub fn is_skel_getframe_once_patched(data: &[u8]) -> bool {
    are_byte_sites_patched(data, SKEL_GETFRAME_ONCE_SITES)
}

pub fn patch_skel_getframe_once_bytes(data: &mut [u8]) -> Result<usize> {
    patch_byte_sites(data, SKEL_GETFRAME_ONCE_SITES, "GetFrame once-per-tick")
}

pub fn revert_skel_getframe_once_bytes(data: &mut [u8]) -> bool {
    revert_byte_sites(data, SKEL_GETFRAME_ONCE_SITES)
}

pub fn is_skel_bone_force_compute_patched(data: &[u8]) -> bool {
    are_byte_sites_patched(data, SKEL_BONE_FORCE_COMPUTE_SITES)
}

pub fn patch_skel_bone_force_compute_bytes(data: &mut [u8]) -> Result<usize> {
    patch_byte_sites(
        data,
        SKEL_BONE_FORCE_COMPUTE_SITES,
        "skeletal bone force-compute",
    )
}

pub fn revert_skel_bone_force_compute_bytes(data: &mut [u8]) -> bool {
    revert_byte_sites(data, SKEL_BONE_FORCE_COMPUTE_SITES)
}

pub fn is_ai_render_gate_sync_patched(data: &[u8]) -> bool {
    are_byte_sites_patched(data, AI_RENDER_GATE_SYNC_SITES)
}

pub fn patch_ai_render_gate_sync_bytes(data: &mut [u8]) -> Result<usize> {
    patch_byte_sites(data, AI_RENDER_GATE_SYNC_SITES, "AI render gate / speed")
}

pub fn revert_ai_render_gate_sync_bytes(data: &mut [u8]) -> bool {
    revert_byte_sites(data, AI_RENDER_GATE_SYNC_SITES)
}

/// Logical feature groups used to organize all 28 mod toggles cleanly in the UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlagGroup {
    Networking,
    MenusLobby,
    SyncAiSkel,
    Gameplay,
    ArchivesMaps,
    RuntimeDiag,
}

impl FlagGroup {
    pub const ALL: &[FlagGroup] = &[
        FlagGroup::Networking,
        FlagGroup::MenusLobby,
        FlagGroup::SyncAiSkel,
        FlagGroup::Gameplay,
        FlagGroup::ArchivesMaps,
        FlagGroup::RuntimeDiag,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            FlagGroup::Networking => "1. Networking & Connection (EXE)",
            FlagGroup::MenusLobby => "2. Menus & Lobby QoL (EXE)",
            FlagGroup::SyncAiSkel => "3. Lockstep Sync, AI & Skeletal Fixes (EXE)",
            FlagGroup::Gameplay => "4. Gameplay & Script Fixes (EXE + Echelon.u)",
            FlagGroup::ArchivesMaps => "5. Archives, Map INI & UPK Conversion (UMD + Maps)",
            FlagGroup::RuntimeDiag => "6. Runtime Launch, Persistence & Diagnostics",
        }
    }
}

/// Metadata table entry driving UI rendering, summaries, and toggle logic without duplication.
pub struct FlagDescriptor {
    pub group: FlagGroup,
    pub short_name: &'static str,
    pub label: &'static str,
    pub tooltip: &'static str,
    pub requires_heavy_rebuild: bool,
    pub get: fn(&ModFlags) -> bool,
    pub get_mut: fn(&mut ModFlags) -> &mut bool,
}

/// Comprehensive 28-flag configuration covering every modification `scct_coop_enhancer`
/// makes across `.exe`, `.u`, `.umd`, `.ini`, `Data/Maps/*.scl` UPKs, and runtime launch hooks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModFlags {
    // 1. Networking & Connection
    pub net_multi_nic_adapter_fix: bool,
    pub net_nat_and_direct_ip: bool,
    // 2. Menus & Lobby QoL
    pub menu_redirect_online_to_lan: bool,
    pub menu_enhanced_coop_caption: bool,
    pub lobby_alttab_unready_nop: bool,
    pub pause_always_ready: bool,
    // 3. Lockstep Sync, AI & Skeletal Fixes
    pub skel_getframe_once_per_tick: bool,
    pub skel_bone_force_compute: bool,
    pub ai_render_gate_sync: bool,
    pub disable_ai_visibility_cull: bool,
    pub unsynced_render_rng: bool,
    pub exclude_controller_checksum: bool,
    // 4. Gameplay & Script Fixes
    pub camera_alarm_fixes: bool,
    pub nonlethal_gameover_menu: bool,
    pub coop_aizone_enable: bool,
    pub coop_endmission_dispatch: bool,
    pub eev_remote_hacking: bool,
    // 5. Archives & Map UPK Conversion
    pub umd_coop_missions_and_loc: bool,
    pub umd_lan_menu_caption: bool,
    pub loose_map_rotation_ini: bool,
    pub install_sp_coop_maps: bool,
    pub upk_detach_speakers: bool,
    pub upk_coop_player_mesh: bool,
    pub upk_use_default_sound_map_false: bool,
    // 6. Runtime Launch, Persistence & Diagnostics
    pub runtime_startup_trace_hooks: bool,
    pub runtime_desync_monitor_dump: bool,
    pub runtime_bypass_checksum_disconnect: bool,
    pub runtime_quicksave_persistence: bool,
}

pub const FLAG_DESCRIPTORS: &[FlagDescriptor] = &[
    // 1. Networking & Connection
    FlagDescriptor {
        group: FlagGroup::Networking,
        short_name: "net_lan_bind",
        label: "Multi-NIC Adapter Promotion, 0.0.0.0 Bind & LAN Sender IP (11 hooks)",
        tooltip: "NET_CAVE + SOCKET_CAVE + MULTI_NIC_LAN_CAVE + 11 bind/recvfrom/session hooks and .data bind/peer globals.",
        requires_heavy_rebuild: false,
        get: |f| f.net_multi_nic_adapter_fix,
        get_mut: |f| &mut f.net_multi_nic_adapter_fix,
    },
    FlagDescriptor {
        group: FlagGroup::Networking,
        short_name: "net_nat_direct",
        label: "Direct-IP Broadcast Replication, 3s Keepalive & StationURL Rewrite (5 hooks)",
        tooltip: "ONLINE_CAVE + JOIN_GAME_PORT + Poll keepalive, WSASendTo, HandleBrowseReply StationURL, and SendTo/SendToIP hooks.",
        requires_heavy_rebuild: false,
        get: |f| f.net_nat_and_direct_ip,
        get_mut: |f| &mut f.net_nat_and_direct_ip,
    },
    // 2. Menus & Lobby QoL
    FlagDescriptor {
        group: FlagGroup::MenusLobby,
        short_name: "menu_redirect",
        label: "Co-op 'Online' Button -> LAN Room List (0x10B524CA)",
        tooltip: "Redirects P_MenuCoop's Online button directly into the LAN room browser.",
        requires_heavy_rebuild: false,
        get: |f| f.menu_redirect_online_to_lan,
        get_mut: |f| &mut f.menu_redirect_online_to_lan,
    },
    FlagDescriptor {
        group: FlagGroup::MenusLobby,
        short_name: "menu_caption",
        label: "MainMenuCoop LAN Caption -> 'ENHANCED COOP' (0x10B4BB86)",
        tooltip: "Replaces the MainMenuCoop LAN button localization lookup in EXE with L\"ENHANCED COOP\".",
        requires_heavy_rebuild: false,
        get: |f| f.menu_enhanced_coop_caption,
        get_mut: |f| &mut f.menu_enhanced_coop_caption,
    },
    FlagDescriptor {
        group: FlagGroup::MenusLobby,
        short_name: "lobby_alttab_nop",
        label: "Lobby Alt-Tab Unready Prevention NOP (0x10A3D58B)",
        tooltip: "NOPs SetLocalPlayerReady(0, 1) in UGameEngine::SetPause so clients don't unready on focus loss.",
        requires_heavy_rebuild: false,
        get: |f| f.lobby_alttab_unready_nop,
        get_mut: |f| &mut f.lobby_alttab_unready_nop,
    },
    FlagDescriptor {
        group: FlagGroup::MenusLobby,
        short_name: "pause_ready",
        label: "Force Pause Menu IsPlayerReady -> 1 (0x109639E0)",
        tooltip: "Allows pausing/quicksaving without 'WaitRemote' popup.",
        requires_heavy_rebuild: false,
        get: |f| f.pause_always_ready,
        get_mut: |f| &mut f.pause_always_ready,
    },
    // 3. Lockstep Sync, AI & Skeletal Fixes
    FlagDescriptor {
        group: FlagGroup::SyncAiSkel,
        short_name: "skel_getframe_once",
        label: "#1 SkelMesh GetFrame Once Per Tick (0x109F5309)",
        tooltip: "Avoids multiple SkelMesh GetFrame animations advancing per frame.",
        requires_heavy_rebuild: false,
        get: |f| f.skel_getframe_once_per_tick,
        get_mut: |f| &mut f.skel_getframe_once_per_tick,
    },
    FlagDescriptor {
        group: FlagGroup::SyncAiSkel,
        short_name: "skel_bone_force",
        label: "#2 SkelMesh Bone Matrix Force-Compute + LastRenderTime (4 sites)",
        tooltip: "Forces bone transform evaluation regardless of local visibility/culling.",
        requires_heavy_rebuild: false,
        get: |f| f.skel_bone_force_compute,
        get_mut: |f| &mut f.skel_bone_force_compute,
    },
    FlagDescriptor {
        group: FlagGroup::SyncAiSkel,
        short_name: "ai_render_gate",
        label: "#3 AI bIsRendered / DrawFrameCounter Sync Gate (0x10B9A66D, 0x10BB53D0)",
        tooltip: "Removes camera DrawFrameCounter dependency in AEAIController checks.",
        requires_heavy_rebuild: false,
        get: |f| f.ai_render_gate_sync,
        get_mut: |f| &mut f.ai_render_gate_sync,
    },
    FlagDescriptor {
        group: FlagGroup::SyncAiSkel,
        short_name: "ai_vis_cull",
        label: "#4 Disable AI Visibility Tick-Culling (AEAIPawn::vt+0x2BC @ 0x10C1852C)",
        tooltip: "Prevents off-screen AI pawns from skipping AEPawn::Tick / patterns asymmetrically.",
        requires_heavy_rebuild: false,
        get: |f| f.disable_ai_visibility_cull,
        get_mut: |f| &mut f.disable_ai_visibility_cull,
    },
    FlagDescriptor {
        group: FlagGroup::SyncAiSkel,
        short_name: "unsynced_rng",
        label: "#5 Render-Only RNG -> appUnsynced* (FDynamicLight, EyeAnim, Sensor)",
        tooltip: "Switches visual-only RNG calls from synced MT19937 to appUnsyncedFrand/Rand.",
        requires_heavy_rebuild: false,
        get: |f| f.unsynced_render_rng,
        get_mut: |f| &mut f.unsynced_render_rng,
    },
    FlagDescriptor {
        group: FlagGroup::SyncAiSkel,
        short_name: "ctrl_checksum",
        label: "#6 Exclude Pawn->Controller from UserChecksum0 (0x10B8A517)",
        tooltip: "Excludes Pawn->Controller pointer offset from simulation checksum.",
        requires_heavy_rebuild: false,
        get: |f| f.exclude_controller_checksum,
        get_mut: |f| &mut f.exclude_controller_checksum,
    },
    // 4. Gameplay & Script Fixes
    FlagDescriptor {
        group: FlagGroup::Gameplay,
        short_name: "camera_alarms",
        label: "Security Camera Alarm Fixes (0x1099BCA4, 0x1099BBB7, 0x10C57B14)",
        tooltip: "Fixes GetPawnType/Owner assertions on security cameras in Co-op.",
        requires_heavy_rebuild: false,
        get: |f| f.camera_alarm_fixes,
        get_mut: |f| &mut f.camera_alarm_fixes,
    },
    FlagDescriptor {
        group: FlagGroup::Gameplay,
        short_name: "gameover_menu",
        label: "Non-Lethal Game Over Co-op Menu Suppression (0x10B25809)",
        tooltip: "Prevents CInGameMenusManager::ThrowMenuEvent(0) crashes on objective/non-lethal fail.",
        requires_heavy_rebuild: false,
        get: |f| f.nonlethal_gameover_menu,
        get_mut: |f| &mut f.nonlethal_gameover_menu,
    },
    FlagDescriptor {
        group: FlagGroup::Gameplay,
        short_name: "coop_aizone",
        label: "execAddPlayerInZones AI Zone Wake (0x10C10CB9)",
        tooltip: "Wakes AI zones around both players in multiplayer (OFF by default since commit e83f055; patching eb 33 caused lockstep startup desyncs).",
        requires_heavy_rebuild: false,
        get: |f| f.coop_aizone_enable,
        get_mut: |f| &mut f.coop_aizone_enable,
    },
    FlagDescriptor {
        group: FlagGroup::Gameplay,
        short_name: "coop_endmission",
        label: "EPattern::execEndMission Multiplayer Dispatch (0x10B937BB)",
        tooltip: "Enables SP mission-complete EPattern triggers to end Co-op missions properly.",
        requires_heavy_rebuild: false,
        get: |f| f.coop_endmission_dispatch,
        get_mut: |f| &mut f.coop_endmission_dispatch,
    },
    FlagDescriptor {
        group: FlagGroup::Gameplay,
        short_name: "eev_hacking",
        label: "System/Echelon.u SwitchEEV Co-op Remote Hacking",
        tooltip: "Removes multiplayer EEV remote hacking restriction in Echelon.u bytecode.",
        requires_heavy_rebuild: false,
        get: |f| f.eev_remote_hacking,
        get_mut: |f| &mut f.eev_remote_hacking,
    },
    // 5. Archives & Map UPK Conversion
    FlagDescriptor {
        group: FlagGroup::ArchivesMaps,
        short_name: "umd_missions_loc",
        label: "dynamic-pc.umd: SP Co-op MapRotation, LoadingScreens, Seoul 1/2, *_COOP Loc",
        tooltip: "Appends SP Co-op missions, loading screens, Seoul names, and cloned *_COOP.<lang> loc inside dynamic-pc.umd (~2s rewrite).",
        requires_heavy_rebuild: true,
        get: |f| f.umd_coop_missions_and_loc,
        get_mut: |f| &mut f.umd_coop_missions_and_loc,
    },
    FlagDescriptor {
        group: FlagGroup::ArchivesMaps,
        short_name: "umd_lan_caption",
        label: "dynamic-pc.umd: PreGame_PC LanCaption=ENHANCED COOP",
        tooltip: "Updates PreGame_PC.<lang> LanCaption inside dynamic-pc.umd (~2s rewrite).",
        requires_heavy_rebuild: true,
        get: |f| f.umd_lan_menu_caption,
        get_mut: |f| &mut f.umd_lan_menu_caption,
    },
    FlagDescriptor {
        group: FlagGroup::ArchivesMaps,
        short_name: "loose_map_rot",
        label: "Loose System/MapRotation.ini: Append SP Co-op Missions",
        tooltip: "Appends *_COOP missions to loose System/MapRotation.ini if present.",
        requires_heavy_rebuild: false,
        get: |f| f.loose_map_rotation_ini,
        get_mut: |f| &mut f.loose_map_rotation_ini,
    },
    FlagDescriptor {
        group: FlagGroup::ArchivesMaps,
        short_name: "sp_coop_maps",
        label: "Generate Data/Maps/*_COOP.{scl,ini,occ,uns} & GenLoadings DDS",
        tooltip: "Converts all 11 SP maps into Data/Maps/*_COOP.scl and removes them when OFF.",
        requires_heavy_rebuild: true,
        get: |f| f.install_sp_coop_maps,
        get_mut: |f| &mut f.install_sp_coop_maps,
    },
    FlagDescriptor {
        group: FlagGroup::ArchivesMaps,
        short_name: "upk_detach_speakers",
        label: "UPK: Detach HQ/Lambert Speaker Pawns (Strip CurrentEAIZone)",
        tooltip: "Strips CurrentEAIZone from speaker pawns inside generated *_COOP.scl maps.",
        requires_heavy_rebuild: true,
        get: |f| f.upk_detach_speakers,
        get_mut: |f| &mut f.upk_detach_speakers,
    },
    FlagDescriptor {
        group: FlagGroup::ArchivesMaps,
        short_name: "upk_coop_mesh",
        label: "UPK: Force CoopAnims.COOP_Player SamMesh/StartMesh",
        tooltip: "Imports CoopAnims.COOP_Player and swaps SamMesh/StartMesh inside *_COOP.scl.",
        requires_heavy_rebuild: true,
        get: |f| f.upk_coop_player_mesh,
        get_mut: |f| &mut f.upk_coop_player_mesh,
    },
    FlagDescriptor {
        group: FlagGroup::ArchivesMaps,
        short_name: "upk_sound_map",
        label: "UPK: Inject UseDefaultSoundMap=False When Absent (Penthouse)",
        tooltip: "Adds UseDefaultSoundMap=False to LevelInfo0 when absent inside *_COOP.scl.",
        requires_heavy_rebuild: true,
        get: |f| f.upk_use_default_sound_map_false,
        get_mut: |f| &mut f.upk_use_default_sound_map_false,
    },
    // 6. Runtime Launch, Persistence & Diagnostics
    FlagDescriptor {
        group: FlagGroup::RuntimeDiag,
        short_name: "trace_hooks",
        label: "VirtualAllocEx Trace Hooks & scct_startup_trace*.txt",
        tooltip: "Injects ResetChecksums / ULevel::Tick / SyncStepCommit / SimChecksumCmp trace probes at launch.",
        requires_heavy_rebuild: false,
        get: |f| f.runtime_startup_trace_hooks,
        get_mut: |f| &mut f.runtime_startup_trace_hooks,
    },
    FlagDescriptor {
        group: FlagGroup::RuntimeDiag,
        short_name: "desync_monitor",
        label: "Poll SyncEngine Desync Flag & Write scct_desync_dump*.txt",
        tooltip: "Polls process memory for SyncEngine desync flags and writes diagnostic dumps.",
        requires_heavy_rebuild: false,
        get: |f| f.runtime_desync_monitor_dump,
        get_mut: |f| &mut f.runtime_desync_monitor_dump,
    },
    FlagDescriptor {
        group: FlagGroup::RuntimeDiag,
        short_name: "bypass_checksum_dc",
        label: "Bypass Checksum Disconnect Cave (0x10DF8750 -> 0x110B6FE0, Opt-In)",
        tooltip: "Logs checksum mismatches without dropping lockstep connection (not active in standard preset).",
        requires_heavy_rebuild: false,
        get: |f| f.runtime_bypass_checksum_disconnect,
        get_mut: |f| &mut f.runtime_bypass_checksum_disconnect,
    },
    FlagDescriptor {
        group: FlagGroup::RuntimeDiag,
        short_name: "quicksave_persist",
        label: "Auto-Backup & Restore CacheCoopQuickSave*.sav Files",
        tooltip: "Backs up and restores Co-op quicksaves across launches.",
        requires_heavy_rebuild: false,
        get: |f| f.runtime_quicksave_persistence,
        get_mut: |f| &mut f.runtime_quicksave_persistence,
    },
];

impl Default for ModFlags {
    fn default() -> Self {
        Self::standard_coop()
    }
}

fn sync_exe_toggle(
    exe_bytes: &mut [u8],
    enabled: bool,
    is_patched: fn(&[u8]) -> bool,
    patch: fn(&mut [u8]) -> Result<usize>,
    revert: fn(&mut [u8]) -> bool,
) -> Result<()> {
    if enabled {
        if !is_patched(exe_bytes) {
            patch(exe_bytes)?;
        }
    } else {
        revert(exe_bytes);
    }
    Ok(())
}

impl ModFlags {
    /// Standard Co-op Mod preset: 26/28 standard features enabled; keeps Checksum Disconnect Bypass and COOP_AIZONE_ENABLE OFF.
    pub const fn standard_coop() -> Self {
        Self {
            net_multi_nic_adapter_fix: true,
            net_nat_and_direct_ip: true,
            menu_redirect_online_to_lan: true,
            menu_enhanced_coop_caption: true,
            lobby_alttab_unready_nop: true,
            pause_always_ready: true,
            skel_getframe_once_per_tick: true,
            skel_bone_force_compute: true,
            ai_render_gate_sync: true,
            disable_ai_visibility_cull: true,
            unsynced_render_rng: true,
            exclude_controller_checksum: true,
            camera_alarm_fixes: true,
            nonlethal_gameover_menu: true,
            coop_aizone_enable: false,
            coop_endmission_dispatch: true,
            eev_remote_hacking: true,
            umd_coop_missions_and_loc: true,
            umd_lan_menu_caption: true,
            loose_map_rotation_ini: true,
            install_sp_coop_maps: true,
            upk_detach_speakers: true,
            upk_coop_player_mesh: true,
            upk_use_default_sound_map_false: true,
            runtime_startup_trace_hooks: true,
            runtime_desync_monitor_dump: true,
            runtime_bypass_checksum_disconnect: false,
            runtime_quicksave_persistence: true,
        }
    }

    /// 100% Vanilla preset: every mod feature disabled and reverted on disk & launch.
    pub const fn all_disabled() -> Self {
        Self {
            net_multi_nic_adapter_fix: false,
            net_nat_and_direct_ip: false,
            menu_redirect_online_to_lan: false,
            menu_enhanced_coop_caption: false,
            lobby_alttab_unready_nop: false,
            pause_always_ready: false,
            skel_getframe_once_per_tick: false,
            skel_bone_force_compute: false,
            ai_render_gate_sync: false,
            disable_ai_visibility_cull: false,
            unsynced_render_rng: false,
            exclude_controller_checksum: false,
            camera_alarm_fixes: false,
            nonlethal_gameover_menu: false,
            coop_aizone_enable: false,
            coop_endmission_dispatch: false,
            eev_remote_hacking: false,
            umd_coop_missions_and_loc: false,
            umd_lan_menu_caption: false,
            loose_map_rotation_ini: false,
            install_sp_coop_maps: false,
            upk_detach_speakers: false,
            upk_coop_player_mesh: false,
            upk_use_default_sound_map_false: false,
            runtime_startup_trace_hooks: false,
            runtime_desync_monitor_dump: false,
            runtime_bypass_checksum_disconnect: false,
            runtime_quicksave_persistence: false,
        }
    }

    /// Networking-only preset for testing pure Multi-NIC / Direct-IP on vanilla Co-op maps.
    pub const fn net_only() -> Self {
        Self {
            net_multi_nic_adapter_fix: true,
            net_nat_and_direct_ip: true,
            ..Self::all_disabled()
        }
    }

    /// Minimal sync isolation preset: Networking + #4 AI Vis Cull + #6 Ctrl Checksum + Trace/Desync Diags.
    pub const fn minimal_coop_sync() -> Self {
        Self {
            net_multi_nic_adapter_fix: true,
            net_nat_and_direct_ip: true,
            disable_ai_visibility_cull: true,
            exclude_controller_checksum: true,
            runtime_startup_trace_hooks: true,
            runtime_desync_monitor_dump: true,
            ..Self::all_disabled()
        }
    }

    #[cfg(test)]
    pub const fn without_skel_suspects() -> Self {
        Self {
            skel_getframe_once_per_tick: false,
            skel_bone_force_compute: false,
            ..Self::standard_coop()
        }
    }

    pub const fn net_exe_flags(&self) -> NetExeFlags {
        NetExeFlags {
            lan_bind: self.net_multi_nic_adapter_fix,
            nat_direct: self.net_nat_and_direct_ip,
            menu_redirect: self.menu_redirect_online_to_lan,
            menu_caption: self.menu_enhanced_coop_caption,
            lobby_alttab_unready_nop: self.lobby_alttab_unready_nop,
            pause_always_ready: self.pause_always_ready,
            bypass_checksum_disconnect: self.runtime_bypass_checksum_disconnect,
        }
    }

    pub const fn upk_options(&self) -> UpkPatchOptions {
        UpkPatchOptions {
            detach_speakers: self.upk_detach_speakers,
            coop_player_mesh: self.upk_coop_player_mesh,
            use_default_sound_map_false: self.upk_use_default_sound_map_false,
        }
    }

    pub const fn umd_options(&self) -> UmdPatchOptions {
        UmdPatchOptions {
            coop_missions_and_loc: self.umd_coop_missions_and_loc,
            lan_menu_caption: self.umd_lan_menu_caption,
        }
    }

    pub fn summary_line(&self) -> String {
        let total = FLAG_DESCRIPTORS.len();
        let enabled_count = FLAG_DESCRIPTORS.iter().filter(|d| (d.get)(self)).count();
        let disabled: Vec<&str> = FLAG_DESCRIPTORS
            .iter()
            .filter_map(|d| (!(d.get)(self)).then_some(d.short_name))
            .collect();
        if disabled.is_empty() {
            format!("{}/{} enabled", enabled_count, total)
        } else if disabled.len() <= 6 {
            format!(
                "{}/{} enabled (OFF: {})",
                enabled_count,
                total,
                disabled.join(", ")
            )
        } else {
            let active: Vec<&str> = FLAG_DESCRIPTORS
                .iter()
                .filter_map(|d| (d.get)(self).then_some(d.short_name))
                .collect();
            if active.is_empty() {
                format!("0/{} enabled (100% Vanilla)", total)
            } else {
                format!("{}/{} enabled (ON: {})", enabled_count, total, active.join(", "))
            }
        }
    }

    /// Applies/reverts ONLY the 10 non-network gameplay/sync/pause `.exe` byte sites.
    pub fn apply_gameplay_to_exe_bytes(&self, exe_bytes: &mut [u8]) -> Result<()> {
        type ExeSiteToggle = (
            bool,
            fn(&[u8]) -> bool,
            fn(&mut [u8]) -> Result<usize>,
            fn(&mut [u8]) -> bool,
        );
        let exe_toggles: [ExeSiteToggle; 10] = [
            (
                self.skel_getframe_once_per_tick,
                is_skel_getframe_once_patched,
                patch_skel_getframe_once_bytes,
                revert_skel_getframe_once_bytes,
            ),
            (
                self.skel_bone_force_compute,
                is_skel_bone_force_compute_patched,
                patch_skel_bone_force_compute_bytes,
                revert_skel_bone_force_compute_bytes,
            ),
            (
                self.ai_render_gate_sync,
                is_ai_render_gate_sync_patched,
                patch_ai_render_gate_sync_bytes,
                revert_ai_render_gate_sync_bytes,
            ),
            (
                self.disable_ai_visibility_cull,
                is_ai_visibility_culling_disabled,
                patch_ai_visibility_culling_disabled_bytes,
                revert_ai_visibility_culling_disabled_bytes,
            ),
            (
                self.unsynced_render_rng,
                is_unsynced_render_rng_patched,
                patch_unsynced_render_rng_bytes,
                revert_unsynced_render_rng_bytes,
            ),
            (
                self.exclude_controller_checksum,
                is_controller_checksum_patched,
                patch_controller_checksum_bytes,
                revert_controller_checksum_bytes,
            ),
            (
                self.camera_alarm_fixes,
                is_camera_alarm_patched,
                patch_camera_alarm_bytes,
                revert_camera_alarm_bytes,
            ),
            (
                self.nonlethal_gameover_menu,
                is_nonlethal_gameover_menu_patched,
                patch_nonlethal_gameover_menu_bytes,
                revert_nonlethal_gameover_menu_bytes,
            ),
            (
                self.coop_aizone_enable,
                is_coop_aizone_enable_patched,
                patch_coop_aizone_enable_bytes,
                revert_coop_aizone_enable_bytes,
            ),
            (
                self.coop_endmission_dispatch,
                is_coop_endmission_dispatch_patched,
                patch_coop_endmission_dispatch_bytes,
                revert_coop_endmission_dispatch_bytes,
            ),
        ];
        for (enabled, is_patched, patch, revert) in exe_toggles {
            sync_exe_toggle(exe_bytes, enabled, is_patched, patch, revert)?;
        }
        Ok(())
    }

    /// Applies/reverts ALL `.exe` mod flags (gameplay/sync + networking/menus/pause/bypass).
    pub fn apply_to_exe_bytes(
        &self,
        exe_bytes: &mut [u8],
        direct_target: Option<(Ipv4Addr, u16, u16)>,
        vanilla_vsizes: Option<(u32, u32)>,
    ) -> Result<()> {
        self.apply_gameplay_to_exe_bytes(exe_bytes)?;
        sync_net_flags_to_exe_bytes(
            exe_bytes,
            &self.net_exe_flags(),
            direct_target,
            vanilla_vsizes,
        )?;
        Ok(())
    }

    pub fn detect_from_disk(game_root: &Path, prev: Option<&ModFlags>) -> Option<Self> {
        let system_dir = find_child_ci(game_root, "System");
        let exe_path = find_child_ci(&system_dir, "splintercell3.exe");
        let exe_bytes = std::fs::read(&exe_path).ok()?;

        let net_lan = is_lan_bind_hooks_applied(&exe_bytes);
        let net_nat = is_nat_direct_hooks_applied(&exe_bytes);
        let mod_installed = get_installed_version(game_root).is_some()
            || system_dir.join("splintercell3.exe.bak").exists();
        if !net_lan && !net_nat && !mod_installed {
            return None;
        }

        let echelon_u_path = find_child_ci(&system_dir, "Echelon.u");
        let eev_remote_hacking = std::fs::read(&echelon_u_path)
            .map(|buf| is_echelon_u_eev_patched(&buf))
            .unwrap_or(false);

        let umd_path = find_child_ci(&system_dir, "dynamic-pc.umd");
        let umd_opts = detect_umd_options_fast(&umd_path).unwrap_or(UmdPatchOptions {
            coop_missions_and_loc: false,
            lan_menu_caption: false,
        });

        let loose_rot = find_child_ci(&system_dir, "MapRotation.ini");
        let loose_map_rotation_ini = loose_rot.is_file()
            && std::fs::read(&loose_rot)
                .map(|b| {
                    String::from_utf8_lossy(&b)
                        .to_ascii_lowercase()
                        .contains("01_lighthouse_coop")
                })
                .unwrap_or(false);

        let data_dir = find_child_ci(game_root, "Data");
        let maps_dir = find_child_ci(&data_dir, "Maps");
        let upk_detected = if maps_dir.exists() {
            detect_upk_options_from_maps(&maps_dir)
        } else {
            None
        };
        let install_sp_coop_maps = upk_detected.is_some();
        let upk_opts = upk_detected.unwrap_or_else(|| {
            prev.map_or(
                UpkPatchOptions {
                    detach_speakers: false,
                    coop_player_mesh: false,
                    use_default_sound_map_false: false,
                },
                |p| p.upk_options(),
            )
        });

        let (trace, mon, qs) = prev.map_or((true, true, true), |p| {
            (
                p.runtime_startup_trace_hooks,
                p.runtime_desync_monitor_dump,
                p.runtime_quicksave_persistence,
            )
        });

        Some(Self {
            net_multi_nic_adapter_fix: net_lan,
            net_nat_and_direct_ip: net_nat,
            menu_redirect_online_to_lan: is_menu_redirect_patched(&exe_bytes),
            menu_enhanced_coop_caption: is_menu_caption_patched(&exe_bytes),
            lobby_alttab_unready_nop: is_lobby_alttab_unready_nop_patched(&exe_bytes),
            pause_always_ready: is_pause_always_ready_patched(&exe_bytes),
            skel_getframe_once_per_tick: is_skel_getframe_once_patched(&exe_bytes),
            skel_bone_force_compute: is_skel_bone_force_compute_patched(&exe_bytes),
            ai_render_gate_sync: is_ai_render_gate_sync_patched(&exe_bytes),
            disable_ai_visibility_cull: is_ai_visibility_culling_disabled(&exe_bytes),
            unsynced_render_rng: is_unsynced_render_rng_patched(&exe_bytes),
            exclude_controller_checksum: is_controller_checksum_patched(&exe_bytes),
            camera_alarm_fixes: is_camera_alarm_patched(&exe_bytes),
            nonlethal_gameover_menu: is_nonlethal_gameover_menu_patched(&exe_bytes),
            coop_aizone_enable: is_coop_aizone_enable_patched(&exe_bytes),
            coop_endmission_dispatch: is_coop_endmission_dispatch_patched(&exe_bytes),
            eev_remote_hacking,
            umd_coop_missions_and_loc: umd_opts.coop_missions_and_loc,
            umd_lan_menu_caption: umd_opts.lan_menu_caption,
            loose_map_rotation_ini,
            install_sp_coop_maps,
            upk_detach_speakers: upk_opts.detach_speakers,
            upk_coop_player_mesh: upk_opts.coop_player_mesh,
            upk_use_default_sound_map_false: upk_opts.use_default_sound_map_false,
            runtime_startup_trace_hooks: trace,
            runtime_desync_monitor_dump: mon,
            runtime_bypass_checksum_disconnect: is_startup_checksum_bypass_patched(&exe_bytes),
            runtime_quicksave_persistence: qs,
        })
    }
}

/// Clears a file's read-only flag when set before overwriting it.
pub(crate) fn clear_readonly_if_needed(path: &Path) {
    if let Ok(mut perms) = std::fs::metadata(path).map(|m| m.permissions())
        && perms.readonly()
    {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            perms.set_mode(perms.mode() | 0o200);
        }
        #[cfg(not(unix))]
        #[allow(clippy::permissions_set_readonly_false)]
        {
            perms.set_readonly(false);
        }
        let _ = std::fs::set_permissions(path, perms);
    }
}

fn write_file_clearing_readonly(path: &Path, data: &[u8]) -> Result<()> {
    clear_readonly_if_needed(path);
    std::fs::write(path, data).with_context(|| format!("Writing {}", path.display()))
}

fn has_any_generated_coop_artifacts(maps_dir: &Path, gen_loadings_dir: &Path) -> bool {
    for dir in [maps_dir, gen_loadings_dir] {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for ent in rd.flatten() {
                if ent
                    .file_name()
                    .to_string_lossy()
                    .to_ascii_lowercase()
                    .contains("_coop")
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Synchronizes all 28 mod flags incrementally: `.exe`, `Echelon.u`, loose `MapRotation.ini`,
/// `dynamic-pc.umd`, and `Data/Maps/*_COOP.*` / `GenLoadings` are only rewritten when out of sync.
pub fn sync_mod_flags(
    game_root: &Path,
    flags: &ModFlags,
    direct_target: Option<(Ipv4Addr, u16, u16)>,
) -> Result<()> {
    sync_mod_flags_inner(game_root, flags, direct_target, false)
}

fn sync_mod_flags_inner(
    game_root: &Path,
    flags: &ModFlags,
    direct_target: Option<(Ipv4Addr, u16, u16)>,
    force_reinstall: bool,
) -> Result<()> {
    let system_dir = find_child_ci(game_root, "System");
    let exe_path = find_child_ci(&system_dir, "splintercell3.exe");
    let exe_bak_path = system_dir.join("splintercell3.exe.bak");
    if !exe_path.exists() {
        bail!("Missing System/splintercell3.exe: {}", exe_path.display());
    }

    // 1. Sync System/splintercell3.exe
    let orig_exe =
        std::fs::read(&exe_path).with_context(|| format!("Reading {}", exe_path.display()))?;
    let vanilla_vsizes = if exe_bak_path.exists() {
        std::fs::read(&exe_bak_path)
            .ok()
            .and_then(|b| read_pe_vanilla_vsizes(&b).ok())
    } else {
        None
    };

    let mut exe_bytes = if force_reinstall && exe_bak_path.exists() {
        std::fs::read(&exe_bak_path)
            .with_context(|| format!("Reading {}", exe_bak_path.display()))?
    } else {
        orig_exe.clone()
    };
    if let Err(err) = flags.apply_to_exe_bytes(&mut exe_bytes, direct_target, vanilla_vsizes) {
        if !force_reinstall && exe_bak_path.exists() {
            // Upgrade cleanly from an older mod cave revision using the vanilla .bak copy.
            exe_bytes = std::fs::read(&exe_bak_path)
                .with_context(|| format!("Reading {}", exe_bak_path.display()))?;
            flags.apply_to_exe_bytes(&mut exe_bytes, direct_target, vanilla_vsizes)?;
        } else {
            return Err(err);
        }
    }
    if exe_bytes != orig_exe {
        if !exe_bak_path.exists() {
            std::fs::copy(&exe_path, &exe_bak_path)?;
            scct_log!("  [BAK] Backed up vanilla EXE -> {}", exe_bak_path.display());
        }
        write_file_clearing_readonly(&exe_path, &exe_bytes)?;
    }

    // 2. Sync System/Echelon.u
    let echelon_u_path = find_child_ci(&system_dir, "Echelon.u");
    let echelon_u_bak_path = system_dir.join("Echelon.u.bak");
    if echelon_u_path.exists() {
        let orig_echelon = std::fs::read(&echelon_u_path)
            .with_context(|| format!("Reading {}", echelon_u_path.display()))?;
        let mut echelon_bytes = if force_reinstall && echelon_u_bak_path.exists() {
            std::fs::read(&echelon_u_bak_path)
                .with_context(|| format!("Reading {}", echelon_u_bak_path.display()))?
        } else {
            orig_echelon.clone()
        };
        if flags.eev_remote_hacking {
            if !is_echelon_u_eev_patched(&echelon_bytes) {
                patch_echelon_u_eev_bytes(&mut echelon_bytes)?;
            }
        } else {
            revert_echelon_u_eev_bytes(&mut echelon_bytes);
        }
        if echelon_bytes != orig_echelon {
            if !echelon_u_bak_path.exists() && !is_echelon_u_eev_patched(&orig_echelon) {
                std::fs::copy(&echelon_u_path, &echelon_u_bak_path)?;
            }
            write_file_clearing_readonly(&echelon_u_path, &echelon_bytes)?;
        }
    }

    // 3. Sync loose System/MapRotation.ini
    let loose_rot = find_child_ci(&system_dir, "MapRotation.ini");
    if loose_rot.is_file() {
        let loose_bak = system_dir.join("MapRotation.ini.bak");
        let cur_rot = std::fs::read(&loose_rot)?;
        let cur_has_coop = String::from_utf8_lossy(&cur_rot)
            .to_ascii_lowercase()
            .contains("01_lighthouse_coop");
        if flags.loose_map_rotation_ini {
            if force_reinstall || !cur_has_coop {
                if !loose_bak.exists() && !cur_has_coop {
                    std::fs::copy(&loose_rot, &loose_bak)?;
                }
                let src_rot = if loose_bak.exists() {
                    std::fs::read(&loose_bak)?
                } else {
                    cur_rot.clone()
                };
                let coop_names: Vec<&str> = SP_COOP_LEVELS.iter().map(|s| s.coop_map).collect();
                let new_rot = append_missions_to_map_rotation(&src_rot, &coop_names);
                if new_rot != cur_rot {
                    write_file_clearing_readonly(&loose_rot, &new_rot)?;
                    scct_log!("  [INI ] Updated loose System/MapRotation.ini");
                }
            }
        } else if (cur_has_coop || force_reinstall) && loose_bak.exists() {
            let bak_bytes = std::fs::read(&loose_bak)?;
            if bak_bytes != cur_rot {
                write_file_clearing_readonly(&loose_rot, &bak_bytes)?;
                scct_log!("  [INI ] Restored loose System/MapRotation.ini from .bak");
            }
        }
    }

    // 4. Sync System/dynamic-pc.umd (only rewrite when TOC/options differ!)
    let umd_path = find_child_ci(&system_dir, "dynamic-pc.umd");
    let umd_bak_path = system_dir.join("dynamic-pc.umd.bak");
    let mut extracted_from_umd: Option<HashMap<String, ExtractedLevelInfo>> = None;
    if umd_path.exists() || umd_bak_path.exists() {
        let want_umd = flags.umd_options();
        let cur_umd = if umd_path.exists() {
            detect_umd_options_fast(&umd_path)
        } else {
            None
        };
        let need_umd_sync = if !want_umd.coop_missions_and_loc && !want_umd.lan_menu_caption {
            if umd_bak_path.exists() {
                let len_diff = match (std::fs::metadata(&umd_path), std::fs::metadata(&umd_bak_path)) {
                    (Ok(m1), Ok(m2)) => m1.len() != m2.len(),
                    _ => true,
                };
                len_diff || cur_umd != Some(want_umd)
            } else {
                false
            }
        } else {
            force_reinstall || cur_umd != Some(want_umd)
        };

        if need_umd_sync {
            extracted_from_umd = patch_umd_with_options(
                &umd_path,
                &umd_bak_path,
                SP_COOP_LEVELS,
                &want_umd,
            )?;
        }
    }

    // 5. Sync Data/Maps/*_COOP.* + GenLoadings/*_COOP_loading_*.dds
    let data_dir = find_child_ci(game_root, "Data");
    let maps_dir = find_child_ci(&data_dir, "Maps");
    let magma_dir = find_child_ci(&data_dir, "Magma");
    let datapc_dir = find_child_ci(&magma_dir, "DataPC");
    let textures_dir = find_child_ci(&datapc_dir, "Textures");
    let gen_loadings_dir = find_child_ci(&textures_dir, "GenLoadings");

    if maps_dir.exists() {
        let active_stems: HashSet<String> = SP_COOP_LEVELS
            .iter()
            .map(|s| s.coop_map.to_lowercase())
            .collect();
        if !flags.install_sp_coop_maps {
            if has_any_generated_coop_artifacts(&maps_dir, &gen_loadings_dir) {
                ensure_clean_sp_maps_and_cleanup(&maps_dir, &gen_loadings_dir, &HashSet::new())?;
                scct_log!("  [MAP] Removed generated *_COOP.{{scl,ini,occ,uns,dds}} files");
            }
        } else if umd_path.exists() || umd_bak_path.exists() {
            let want_upk = flags.upk_options();
            let cur_upk = detect_upk_options_from_maps(&maps_dir);
            let all_present = SP_COOP_LEVELS.iter().all(|s| {
                maps_dir.join(format!("{}.scl", s.coop_map)).exists()
                    && maps_dir.join(format!("{}.ini", s.coop_map)).exists()
            });
            if force_reinstall || !all_present || cur_upk != Some(want_upk) {
                let extracted = match extracted_from_umd {
                    Some(e) => e,
                    None => {
                        let umd_src = if umd_bak_path.exists() {
                            &umd_bak_path
                        } else {
                            &umd_path
                        };
                        extract_sp_level_info_from_umd(umd_src, SP_COOP_LEVELS)?
                    }
                };
                ensure_clean_sp_maps_and_cleanup(&maps_dir, &gen_loadings_dir, &active_stems)?;
                std::fs::create_dir_all(&gen_loadings_dir)?;
                let disk_ci = build_maps_ci_map(&maps_dir);

                for (coop_map, info) in &extracted {
                    let spec = &info.spec;
                    let src_map = spec.source_map;
                    let src_scl_path = resolve_clean_sp_scl_path(&maps_dir, &disk_ci, src_map)?;
                    let dst_scl_path = maps_dir.join(format!("{}.scl", coop_map));
                    let summary = patch_sp_map_to_coop_with_options(
                        &src_scl_path,
                        &dst_scl_path,
                        spec.p1_offset,
                        spec.spawn_offset,
                        &want_upk,
                    )?;

                    for sfx_ext in &["_sound.occ", "_sound.uns"] {
                        let sfx_key = format!("{}{}", src_map.to_lowercase(), sfx_ext);
                        if let Some(orig) = disk_ci.get(&sfx_key) {
                            std::fs::copy(
                                maps_dir.join(orig),
                                maps_dir.join(format!("{}{}", coop_map, sfx_ext)),
                            )?;
                        }
                    }

                    let ini_bytes = build_appended_coop_ini(
                        &info.src_ini,
                        &info.canonical_src,
                        coop_map,
                        spec.identity,
                    );
                    std::fs::write(maps_dir.join(format!("{}.ini", coop_map)), ini_bytes)?;

                    for (idx, dds_bytes) in &info.loading_dds {
                        let dds_out =
                            gen_loadings_dir.join(format!("{}_loading_{}.dds", coop_map, idx));
                        std::fs::write(dds_out, dds_bytes)?;
                    }

                    let detached_info = if summary.detached_speakers.is_empty() {
                        String::new()
                    } else {
                        format!(" | Detached: {}", summary.detached_speakers.join(", "))
                    };
                    scct_log!(
                        "  [COOP] {:22} (ID={:3}): {:9} B | P1=({:.1}, {:.1}, {:.1}) -> P2=({:.1}, {:.1}, {:.1}){}",
                        coop_map,
                        spec.identity,
                        summary.size,
                        summary.p1_loc.0,
                        summary.p1_loc.1,
                        summary.p1_loc.2,
                        summary.p2_loc.0,
                        summary.p2_loc.1,
                        summary.p2_loc.2,
                        detached_info,
                    );
                }
            }
        }
    }

    scct_log!("  [FLAGS] Mod state synced: {}", flags.summary_line());
    Ok(())
}

#[allow(dead_code)]
pub fn are_gameplay_fixes_applied(exe_path: &Path) -> bool {
    if let Ok(data) = std::fs::read(exe_path) {
        is_camera_alarm_patched(&data)
            && is_nonlethal_gameover_patched(&data)
            && is_unsynced_render_rng_patched(&data)
            && is_controller_checksum_patched(&data)
            && is_skel_bone_sync_patched(&data)
            && is_pause_always_ready_patched(&data)
            && is_ai_visibility_culling_disabled(&data)
    } else {
        false
    }
}

#[allow(dead_code)]
pub fn revert_exe_fixes(exe_path: &Path) -> Result<bool> {
    if !exe_path.exists() {
        return Ok(false);
    }
    let mut data = std::fs::read(exe_path)?;
    let mut changed = false;

    if revert_camera_alarm_bytes(&mut data) {
        scct_log!("  [EXE] Reverted security camera alarm patch");
        changed = true;
    }

    if revert_nonlethal_gameover_bytes(&mut data) {
        scct_log!("  [EXE] Reverted non-lethal game over patch");
        changed = true;
    }

    if revert_unsynced_render_rng_bytes(&mut data) {
        scct_log!("  [EXE] Reverted render-only RNG -> appUnsynced* patch");
        changed = true;
    }

    if revert_controller_checksum_bytes(&mut data) {
        scct_log!("  [EXE] Reverted Pawn->Controller checksum exclusion patch");
        changed = true;
    }

    let reverted_skel = revert_skel_bone_sync_bytes(&mut data);
    if reverted_skel > 0 {
        scct_log!(
            "  [EXE] Reverted {} skeletal bone / LastRenderTime sync site(s)",
            reverted_skel
        );
        changed = true;
    }

    if revert_pause_always_ready_bytes(&mut data) {
        scct_log!("  [EXE] Reverted client always ready for unpause");
        changed = true;
    }

    if revert_ai_visibility_culling_disabled_bytes(&mut data) {
        scct_log!("  [EXE] Restored vanilla AI visibility tick-culling (0x10C1852C)");
        changed = true;
    }

    if changed {
        std::fs::write(exe_path, &data)?;
    }
    Ok(changed)
}

pub fn patch_exe_fixes(exe_path: &Path, exe_bak_path: &Path) -> Result<()> {
    if !exe_bak_path.exists() {
        if !exe_path.exists() {
            bail!("Missing System/splintercell3.exe: {}", exe_path.display());
        }
        scct_log!(
            "  [BAK] Creating clean splintercell3.exe backup -> {} ...",
            exe_bak_path.display()
        );
        std::fs::copy(exe_path, exe_bak_path)?;
    }

    let mut data =
        std::fs::read(exe_path).with_context(|| format!("Reading {}", exe_path.display()))?;
    let mut modified = false;

    if !is_camera_alarm_patched(&data) {
        let cam_off = patch_camera_alarm_bytes(&mut data)?;
        scct_log!("  [EXE] Patched security camera alarms @ 0x{:06X}", cam_off);
        modified = true;
    }

    if !is_nonlethal_gameover_patched(&data) {
        let go_off = patch_nonlethal_gameover_bytes(&mut data)?;
        scct_log!(
            "  [EXE] Patched non-lethal mission Game Over & AI zones @ 0x{:06X}",
            go_off
        );
        modified = true;
    }

    if !is_unsynced_render_rng_patched(&data) {
        let rng_off = patch_unsynced_render_rng_bytes(&mut data)?;
        scct_log!(
            "  [EXE] Patched render-only RNG -> appUnsynced* @ 0x{:06X}",
            rng_off
        );
        modified = true;
    }

    if !is_controller_checksum_patched(&data) {
        let ctrl_off = patch_controller_checksum_bytes(&mut data)?;
        scct_log!(
            "  [EXE] Excluded Pawn->Controller from UserChecksum0 @ 0x{:06X}",
            ctrl_off
        );
        modified = true;
    }

    if !is_skel_bone_sync_patched(&data) {
        let skel_off = patch_skel_bone_sync_bytes(&mut data)?;
        scct_log!(
            "  [EXE] Patched skeletal bone & LastRenderTime sync (7 sites, first @ 0x{:06X})",
            skel_off
        );
        modified = true;
    }

    if !is_pause_always_ready_patched(&data) {
        let ready_off = patch_pause_always_ready_bytes(&mut data)?;
        scct_log!(
            "  [EXE] Patched client always ready for unpause @ 0x{:06X}",
            ready_off
        );
        modified = true;
    }

    if !is_ai_visibility_culling_disabled(&data) {
        let cull_off = patch_ai_visibility_culling_disabled_bytes(&mut data)?;
        scct_log!(
            "  [EXE] Disabled AI visibility tick-culling (0x10C1852C) @ 0x{:06X}",
            cull_off
        );
        modified = true;
    }

    if modified {
        write_file_clearing_readonly(exe_path, &data)?;
    }

    Ok(())
}

fn build_maps_ci_map(maps_dir: &Path) -> std::collections::HashMap<String, String> {
    let mut disk_ci = std::collections::HashMap::new();
    if let Ok(entries) = std::fs::read_dir(maps_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            disk_ci.insert(name.to_lowercase(), name);
        }
    }
    disk_ci
}

fn resolve_clean_sp_scl_path(
    maps_dir: &Path,
    disk_ci: &std::collections::HashMap<String, String>,
    src_map: &str,
) -> Result<PathBuf> {
    let bak_key = format!("{}.scl.bak", src_map.to_lowercase());
    let scl_key = format!("{}.scl", src_map.to_lowercase());
    if let Some(orig) = disk_ci.get(&bak_key) {
        Ok(maps_dir.join(orig))
    } else if let Some(orig) = disk_ci.get(&scl_key) {
        Ok(maps_dir.join(orig))
    } else {
        bail!(
            "Missing source SP map for {} in {}",
            src_map,
            maps_dir.display()
        );
    }
}

pub fn apply_all(
    game_root: &Path,
    skip_net_fix: bool,
    bypass_checksum_disconnect: bool,
) -> Result<()> {
    let mut flags = ModFlags::standard_coop();
    if skip_net_fix {
        flags.net_multi_nic_adapter_fix = false;
        flags.net_nat_and_direct_ip = false;
        flags.menu_redirect_online_to_lan = false;
        flags.menu_enhanced_coop_caption = false;
        flags.lobby_alttab_unready_nop = false;
    }
    flags.runtime_bypass_checksum_disconnect = bypass_checksum_disconnect;
    apply_all_with_flags(game_root, &flags)
}

/// Cleanly applies `flags` from `.bak` backups where present and writes the mod version marker.
pub fn apply_all_with_flags(game_root: &Path, flags: &ModFlags) -> Result<()> {
    scct_log!(
        "\n=== Installing SCCT Co-op Enhancer (v{}, {}) ===",
        MOD_VERSION,
        flags.summary_line()
    );
    sync_mod_flags_inner(game_root, flags, None, true)?;
    write_version_file(game_root)?;
    scct_log!("\nSuccess! Mod state applied (v{}).", MOD_VERSION);
    Ok(())
}

pub fn restore_vanilla(game_root: &Path) -> Result<()> {
    let system_dir = find_child_ci(game_root, "System");
    let data_dir = find_child_ci(game_root, "Data");
    let maps_dir = find_child_ci(&data_dir, "Maps");

    let magma_dir = find_child_ci(&data_dir, "Magma");
    let datapc_dir = find_child_ci(&magma_dir, "DataPC");
    let textures_dir = find_child_ci(&datapc_dir, "Textures");
    let gen_loadings_dir = find_child_ci(&textures_dir, "GenLoadings");

    let exe_path = find_child_ci(&system_dir, "splintercell3.exe");
    let exe_bak_path = system_dir.join("splintercell3.exe.bak");

    let umd_path = find_child_ci(&system_dir, "dynamic-pc.umd");
    let umd_bak_path = system_dir.join("dynamic-pc.umd.bak");

    let engine_u_path = find_child_ci(&system_dir, "Engine.u");
    let engine_u_bak_path = system_dir.join("Engine.u.bak");

    let echelon_u_path = find_child_ci(&system_dir, "Echelon.u");
    let echelon_u_bak_path = system_dir.join("Echelon.u.bak");

    scct_log!("=== Restoring 100% Vanilla Splinter Cell: Chaos Theory ===");
    if exe_bak_path.exists() {
        std::fs::copy(&exe_bak_path, &exe_path)?;
        scct_log!("  [EXE] Restored vanilla System/splintercell3.exe");
    }

    if engine_u_bak_path.exists() {
        std::fs::copy(&engine_u_bak_path, &engine_u_path)?;
        scct_log!("  [UPK] Restored vanilla System/Engine.u");
    }

    if echelon_u_bak_path.exists() {
        std::fs::copy(&echelon_u_bak_path, &echelon_u_path)?;
        scct_log!("  [UPK] Restored vanilla System/Echelon.u");
    }

    if umd_bak_path.exists() {
        std::fs::copy(&umd_bak_path, &umd_path)?;
        scct_log!("  [UMD] Restored vanilla System/dynamic-pc.umd");
    }

    ensure_clean_sp_maps_and_cleanup(&maps_dir, &gen_loadings_dir, &HashSet::new())?;
    scct_log!("  [MAP] Removed all generated *_COOP.{{scl,ini,occ,uns,dds}} files");

    let loose_rot = find_child_ci(&system_dir, "MapRotation.ini");
    let loose_bak = system_dir.join("MapRotation.ini.bak");
    if loose_bak.exists() {
        std::fs::copy(&loose_bak, &loose_rot)?;
        scct_log!("  [INI] Restored loose System/MapRotation.ini");
    }

    remove_version_file(game_root)?;

    scct_log!("\nVanilla SCCT restoration complete!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_game_root() {
        let clean_path = Path::new("../clean_scct_files/Tom Clancy's Splinter Cell Chaos Theory");
        if clean_path.exists() {
            assert!(validate_game_root(clean_path).is_some());
            assert!(validate_game_root(&clean_path.join("System")).is_some());
        }
    }

    #[test]
    fn test_version_file_crud() {
        let dir = std::env::temp_dir().join("scct_test_ver_crud");
        let sys = dir.join("System");
        let _ = std::fs::create_dir_all(&sys);

        assert_eq!(get_installed_version(&dir), None);
        write_version_file(&dir).unwrap();
        assert_eq!(get_installed_version(&dir), Some(MOD_VERSION.to_string()));
        remove_version_file(&dir).unwrap();
        assert_eq!(get_installed_version(&dir), None);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_patch_echelon_u_eev_bytes() {
        let mut buf = vec![0xAA; 64];
        buf.extend_from_slice(ECHELON_U_EEV_GATE_ORIG);
        buf.extend_from_slice(&[0xBB; 32]);

        let off1 = patch_echelon_u_eev_bytes(&mut buf).unwrap();
        assert_eq!(off1, 64);
        assert_eq!(
            &buf[64..64 + ECHELON_U_EEV_GATE_PATCHED.len()],
            ECHELON_U_EEV_GATE_PATCHED
        );

        // Idempotent second call
        let off2 = patch_echelon_u_eev_bytes(&mut buf).unwrap();
        assert_eq!(off2, 64);
    }

    #[test]
    fn test_patch_camera_alarm_bytes() {
        let mut buf = vec![0xCC; 48];
        buf.extend_from_slice(CAMERA_ALARM_GATE_ORIG);
        buf.extend_from_slice(&[0xDD; 32]);
        buf.extend_from_slice(CAMERA_ALARM_UNIVERSAL_ORIG);
        buf.extend_from_slice(&[0xEE; 32]);
        buf.extend_from_slice(CAMERA_ALARM_FORCE_ORIG);
        buf.extend_from_slice(&[0xFF; 32]);

        assert!(!is_camera_alarm_patched(&buf));

        let off1 = patch_camera_alarm_bytes(&mut buf).unwrap();
        assert_eq!(off1, 48);
        assert_eq!(
            &buf[48..48 + CAMERA_ALARM_GATE_PATCHED.len()],
            CAMERA_ALARM_GATE_PATCHED
        );
        assert!(is_camera_alarm_patched(&buf));

        // Idempotent second call
        let off2 = patch_camera_alarm_bytes(&mut buf).unwrap();
        assert_eq!(off2, 48);
        assert!(is_camera_alarm_patched(&buf));

        // Revert
        assert!(revert_camera_alarm_bytes(&mut buf));
        assert!(!is_camera_alarm_patched(&buf));
        assert_eq!(
            &buf[48..48 + CAMERA_ALARM_GATE_ORIG.len()],
            CAMERA_ALARM_GATE_ORIG
        );
    }

    #[test]
    fn test_patch_nonlethal_gameover_bytes() {
        let mut buf = vec![0xEE; 36];
        buf.extend_from_slice(NONLETHAL_GAMEOVER_ORIG);
        buf.extend_from_slice(&[0xFF; 24]);
        buf.extend_from_slice(COOP_AIZONE_ENABLE_ORIG);
        buf.extend_from_slice(&[0xAA; 24]);
        buf.extend_from_slice(COOP_ENDMISSION_DISPATCH_ORIG);
        buf.extend_from_slice(&[0xBB; 24]);

        assert!(!is_nonlethal_gameover_patched(&buf));

        let off1 = patch_nonlethal_gameover_bytes(&mut buf).unwrap();
        assert_eq!(off1, 36);
        assert_eq!(
            &buf[36..36 + NONLETHAL_GAMEOVER_PATCHED.len()],
            NONLETHAL_GAMEOVER_PATCHED
        );
        assert!(is_nonlethal_gameover_patched(&buf));

        // Idempotent second call
        let off2 = patch_nonlethal_gameover_bytes(&mut buf).unwrap();
        assert_eq!(off2, 36);
        assert!(is_nonlethal_gameover_patched(&buf));

        // COOP_AIZONE_ENABLE must stay vanilla (74 33) and be reverted if previously patched
        let az_off = 36 + NONLETHAL_GAMEOVER_ORIG.len() + 24;
        assert_eq!(
            &buf[az_off..az_off + COOP_AIZONE_ENABLE_ORIG.len()],
            COOP_AIZONE_ENABLE_ORIG
        );
        buf[az_off..az_off + COOP_AIZONE_ENABLE_PATCHED.len()]
            .copy_from_slice(COOP_AIZONE_ENABLE_PATCHED);
        assert!(!is_nonlethal_gameover_patched(&buf));
        patch_nonlethal_gameover_bytes(&mut buf).unwrap();
        assert!(is_nonlethal_gameover_patched(&buf));
        assert_eq!(
            &buf[az_off..az_off + COOP_AIZONE_ENABLE_ORIG.len()],
            COOP_AIZONE_ENABLE_ORIG
        );

        // Revert
        assert!(revert_nonlethal_gameover_bytes(&mut buf));
        assert!(!is_nonlethal_gameover_patched(&buf));
        assert_eq!(
            &buf[36..36 + NONLETHAL_GAMEOVER_ORIG.len()],
            NONLETHAL_GAMEOVER_ORIG
        );
        assert_eq!(
            &buf[az_off..az_off + COOP_AIZONE_ENABLE_ORIG.len()],
            COOP_AIZONE_ENABLE_ORIG
        );
    }

    #[test]
    fn test_patch_exe_fixes_on_clean_exe() {
        let p1 = Path::new(
            "../clean_scct_files/Tom Clancy's Splinter Cell Chaos Theory/System/splintercell3.exe",
        );
        let p2 = Path::new(
            "../../clean_scct_files/Tom Clancy's Splinter Cell Chaos Theory/System/splintercell3.exe",
        );
        let clean_exe = if p1.exists() {
            p1
        } else if p2.exists() {
            p2
        } else {
            return;
        };

        let dir = std::env::temp_dir().join(format!("scct_test_exe_fixes_{}", std::process::id()));
        let sys = dir.join("System");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&sys).unwrap();
        let test_exe = sys.join("splintercell3.exe");
        let test_bak = sys.join("splintercell3.exe.bak");
        std::fs::copy(clean_exe, &test_exe).unwrap();

        let vanilla_bytes = std::fs::read(&test_exe).unwrap();
        assert!(!is_camera_alarm_patched(&vanilla_bytes));
        assert!(!is_nonlethal_gameover_patched(&vanilla_bytes));
        assert!(!is_unsynced_render_rng_patched(&vanilla_bytes));
        assert!(!is_controller_checksum_patched(&vanilla_bytes));
        assert!(!is_skel_bone_sync_patched(&vanilla_bytes));
        assert!(!is_pause_always_ready_patched(&vanilla_bytes));
        assert!(!is_ai_visibility_culling_disabled(&vanilla_bytes));
        assert!(!are_gameplay_fixes_applied(&test_exe));

        patch_exe_fixes(&test_exe, &test_bak).unwrap();

        let patched_bytes = std::fs::read(&test_exe).unwrap();
        assert!(is_camera_alarm_patched(&patched_bytes));
        assert!(is_nonlethal_gameover_patched(&patched_bytes));
        assert!(is_unsynced_render_rng_patched(&patched_bytes));
        assert!(is_controller_checksum_patched(&patched_bytes));
        assert!(is_skel_bone_sync_patched(&patched_bytes));
        assert!(is_pause_always_ready_patched(&patched_bytes));
        assert!(is_ai_visibility_culling_disabled(&patched_bytes));
        assert!(are_gameplay_fixes_applied(&test_exe));
        assert!(test_bak.exists());

        // Idempotent
        patch_exe_fixes(&test_exe, &test_bak).unwrap();
        let patched_again = std::fs::read(&test_exe).unwrap();
        assert_eq!(patched_bytes, patched_again);

        // Clean revert
        assert!(revert_exe_fixes(&test_exe).unwrap());
        let reverted = std::fs::read(&test_exe).unwrap();
        assert_eq!(reverted, vanilla_bytes);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_patch_unsynced_render_rng_bytes() {
        let mut buf = vec![0x90; 24];
        let light_off = buf.len();
        buf.extend_from_slice(FDYNAMICLIGHT_FLICKER_RNG_ORIG);
        buf.extend_from_slice(&[0x90; 16]);
        let eye_off = buf.len();
        buf.extend_from_slice(AEPAWN_EYE_ANIM_RNG_ORIG);
        buf.extend_from_slice(&[0x90; 16]);
        let sensor_off = buf.len();
        buf.extend_from_slice(AESENSOR_LOOK_RNG_ORIG);
        buf.extend_from_slice(&[0x90; 24]);
        let orig_snapshot = buf.clone();

        assert!(!is_unsynced_render_rng_patched(&buf));
        let pos = patch_unsynced_render_rng_bytes(&mut buf).unwrap();
        assert_eq!(pos, light_off);
        assert!(is_unsynced_render_rng_patched(&buf));
        assert_eq!(
            &buf[light_off..light_off + FDYNAMICLIGHT_FLICKER_RNG_PATCHED.len()],
            FDYNAMICLIGHT_FLICKER_RNG_PATCHED
        );
        assert_eq!(
            &buf[eye_off..eye_off + AEPAWN_EYE_ANIM_RNG_PATCHED.len()],
            AEPAWN_EYE_ANIM_RNG_PATCHED
        );
        assert_eq!(
            &buf[sensor_off..sensor_off + AESENSOR_LOOK_RNG_PATCHED.len()],
            AESENSOR_LOOK_RNG_PATCHED
        );

        // Idempotent
        patch_unsynced_render_rng_bytes(&mut buf).unwrap();
        assert!(is_unsynced_render_rng_patched(&buf));

        // Partial site detection & repair
        buf[light_off..light_off + FDYNAMICLIGHT_FLICKER_RNG_ORIG.len()]
            .copy_from_slice(FDYNAMICLIGHT_FLICKER_RNG_ORIG);
        assert!(!is_unsynced_render_rng_patched(&buf));
        patch_unsynced_render_rng_bytes(&mut buf).unwrap();
        assert!(is_unsynced_render_rng_patched(&buf));

        // Revert restores exact vanilla bytes
        assert!(revert_unsynced_render_rng_bytes(&mut buf));
        assert!(!is_unsynced_render_rng_patched(&buf));
        assert_eq!(buf, orig_snapshot);
    }

    #[test]
    fn test_patch_controller_checksum_bytes() {
        let mut buf = vec![0x90; 16];
        let site_off = buf.len();
        buf.extend_from_slice(AEPAWN_CONTROLLER_CHECKSUM_ORIG);
        buf.extend_from_slice(&[0x90; 16]);
        let orig_snapshot = buf.clone();

        assert!(!is_controller_checksum_patched(&buf));
        let pos = patch_controller_checksum_bytes(&mut buf).unwrap();
        assert_eq!(pos, site_off);
        assert!(is_controller_checksum_patched(&buf));
        assert_eq!(
            &buf[site_off..site_off + AEPAWN_CONTROLLER_CHECKSUM_PATCHED.len()],
            AEPAWN_CONTROLLER_CHECKSUM_PATCHED
        );
        // Only the je->jmp opcode byte changed (0x74 -> 0xEB), preserving rel8 offset 0x27
        assert_eq!(buf[site_off + 8], 0xEB);
        assert_eq!(buf[site_off + 9], 0x27);

        // Idempotent
        patch_controller_checksum_bytes(&mut buf).unwrap();
        assert!(is_controller_checksum_patched(&buf));

        // Clean revert
        assert!(revert_controller_checksum_bytes(&mut buf));
        assert!(!is_controller_checksum_patched(&buf));
        assert_eq!(buf, orig_snapshot);
    }

    #[test]
    fn test_patch_skel_bone_sync_bytes() {
        let mut buf = vec![0x90; 16];
        let mut offsets = Vec::new();
        for &(_name, orig, _patched) in SKEL_BONE_SYNC_SITES {
            offsets.push(buf.len());
            buf.extend_from_slice(orig);
            buf.extend_from_slice(&[0xCC; 12]);
        }
        let orig_snapshot = buf.clone();

        assert!(!is_skel_bone_sync_patched(&buf));
        let first_pos = patch_skel_bone_sync_bytes(&mut buf).unwrap();
        assert_eq!(first_pos, offsets[0]);
        assert!(is_skel_bone_sync_patched(&buf));

        for (idx, &(_name, _orig, patched)) in SKEL_BONE_SYNC_SITES.iter().enumerate() {
            let off = offsets[idx];
            assert_eq!(&buf[off..off + patched.len()], patched);
        }

        // Idempotent second call
        patch_skel_bone_sync_bytes(&mut buf).unwrap();
        assert!(is_skel_bone_sync_patched(&buf));

        // Partial site revert detection & re-patch
        let (_, getframe_orig, _) = SKEL_BONE_SYNC_SITES[4];
        let gf_off = offsets[4];
        buf[gf_off..gf_off + getframe_orig.len()].copy_from_slice(getframe_orig);
        assert!(!is_skel_bone_sync_patched(&buf));
        patch_skel_bone_sync_bytes(&mut buf).unwrap();
        assert!(is_skel_bone_sync_patched(&buf));

        // Revert all 7 sites cleanly
        assert_eq!(revert_skel_bone_sync_bytes(&mut buf), 7);
        assert!(!is_skel_bone_sync_patched(&buf));
        assert_eq!(buf, orig_snapshot);
    }

    #[test]
    fn test_mod_flags_descriptor_table_integrity() {
        assert_eq!(FLAG_DESCRIPTORS.len(), 28);
        let mut seen = HashSet::new();
        for d in FLAG_DESCRIPTORS {
            assert!(seen.insert(d.short_name), "duplicate short_name {}", d.short_name);
        }
        let mut flags = ModFlags::all_disabled();
        for d in FLAG_DESCRIPTORS {
            assert!(!(d.get)(&flags));
            *(d.get_mut)(&mut flags) = true;
            assert!((d.get)(&flags));
        }
        // After flipping every descriptor true, only runtime_bypass_checksum_disconnect and coop_aizone_enable differ from standard_coop
        let mut expected_all = ModFlags::standard_coop();
        expected_all.coop_aizone_enable = true;
        expected_all.runtime_bypass_checksum_disconnect = true;
        assert_eq!(flags, expected_all);
    }

    #[test]
    fn test_exe_patch_flags_roundtrip_on_clean_files() {
        let p1 = Path::new("../clean_scct_files/Tom Clancy's Splinter Cell Chaos Theory");
        let p2 = Path::new("../../clean_scct_files/Tom Clancy's Splinter Cell Chaos Theory");
        let clean_root = if p1.exists() {
            p1
        } else if p2.exists() {
            p2
        } else {
            return;
        };
        let clean_exe = clean_root.join("System/splintercell3.exe");
        let clean_echelon = clean_root.join("System/Echelon.u");
        if !clean_exe.exists() {
            return;
        }

        let dir =
            std::env::temp_dir().join(format!("scct_test_patch_flags_{}", std::process::id()));
        let sys = dir.join("System");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&sys).unwrap();
        let test_exe = sys.join("splintercell3.exe");
        let test_bak = sys.join("splintercell3.exe.bak");
        let test_echelon = sys.join("Echelon.u");
        std::fs::copy(&clean_exe, &test_exe).unwrap();
        if clean_echelon.exists() {
            std::fs::copy(&clean_echelon, &test_echelon).unwrap();
        }
        let loose_rot = sys.join("MapRotation.ini");
        std::fs::write(&loose_rot, b"[MapRotation]\r\nMaps=01_Panama\r\n").unwrap();
        let vanilla_exe = std::fs::read(&test_exe).unwrap();

        // Vanilla exe returns None from detect_from_disk
        assert_eq!(ModFlags::detect_from_disk(&dir, None), None);

        // Mark mod installed and apply standard_coop (no UMD/Maps in this temp dir)
        write_version_file(&dir).unwrap();
        let std_flags = ModFlags::standard_coop();
        sync_mod_flags(&dir, &std_flags, None).unwrap();
        let expected_on_exe_only = ModFlags {
            eev_remote_hacking: clean_echelon.exists(),
            umd_coop_missions_and_loc: false,
            umd_lan_menu_caption: false,
            install_sp_coop_maps: false,
            ..std_flags
        };
        assert_eq!(
            ModFlags::detect_from_disk(&dir, Some(&std_flags)),
            Some(expected_on_exe_only)
        );

        // Disable #1 & #2 SkelMesh suspects + test net_only & minimal_coop_sync presets
        let no_skel = ModFlags::without_skel_suspects();
        sync_mod_flags(&dir, &no_skel, None).unwrap();
        let after_no_skel = std::fs::read(&test_exe).unwrap();
        assert!(!is_skel_getframe_once_patched(&after_no_skel));
        assert!(!is_skel_bone_force_compute_patched(&after_no_skel));
        assert!(is_ai_render_gate_sync_patched(&after_no_skel));
        assert!(is_ai_visibility_culling_disabled(&after_no_skel));
        assert!(is_unsynced_render_rng_patched(&after_no_skel));
        assert!(is_controller_checksum_patched(&after_no_skel));
        assert!(is_camera_alarm_patched(&after_no_skel));
        assert!(is_nonlethal_gameover_patched(&after_no_skel));
        assert!(is_pause_always_ready_patched(&after_no_skel));

        let min_sync = ModFlags::minimal_coop_sync();
        sync_mod_flags(&dir, &min_sync, None).unwrap();
        assert_eq!(
            ModFlags::detect_from_disk(&dir, Some(&min_sync)),
            Some(min_sync)
        );
        assert!(!String::from_utf8_lossy(&std::fs::read(&loose_rot).unwrap())
            .contains("01_Lighthouse_COOP"));

        // Disable all 28 flags -> exe bytes match 100% vanilla and Echelon.u reverts
        let all_off = ModFlags::all_disabled();
        sync_mod_flags(&dir, &all_off, None).unwrap();
        assert_eq!(std::fs::read(&test_exe).unwrap(), vanilla_exe);
        if clean_echelon.exists() {
            assert!(!is_echelon_u_eev_patched(&std::fs::read(&test_echelon).unwrap()));
        }
        assert_eq!(ModFlags::detect_from_disk(&dir, Some(&all_off)), Some(all_off));

        // Verify apply_gameplay_to_exe_bytes + pause_always_ready matches patch_exe_fixes equivalence
        let mut via_gameplay = vanilla_exe.clone();
        std_flags.apply_gameplay_to_exe_bytes(&mut via_gameplay).unwrap();
        patch_pause_always_ready_bytes(&mut via_gameplay).unwrap();
        patch_exe_fixes(&test_exe, &test_bak).unwrap();
        assert_eq!(via_gameplay, std::fs::read(&test_exe).unwrap());

        // Verify upgrading from an older mod cave revision succeeds cleanly via .bak fallback
        sync_mod_flags(&dir, &std_flags, None).unwrap();
        let mut stale_cave_exe = std::fs::read(&test_exe).unwrap();
        let stale_off = crate::net::va_to_text_off(crate::net::MULTI_NIC_LAN_CAVE_VA + 0x55).unwrap();
        stale_cave_exe[stale_off] ^= 0xFF;
        std::fs::write(&test_exe, &stale_cave_exe).unwrap();
        sync_mod_flags(&dir, &std_flags, None).unwrap();
        assert!(crate::net::is_lan_bind_hooks_applied(
            &std::fs::read(&test_exe).unwrap()
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_echelon_u_revert_bytes() {
        let mut buf = vec![0xAA; 32];
        buf.extend_from_slice(ECHELON_U_EEV_GATE_ORIG);
        buf.extend_from_slice(&[0xBB; 16]);
        let orig = buf.clone();

        assert!(!is_echelon_u_eev_patched(&buf));
        assert!(!revert_echelon_u_eev_bytes(&mut buf));
        patch_echelon_u_eev_bytes(&mut buf).unwrap();
        assert!(is_echelon_u_eev_patched(&buf));
        assert!(revert_echelon_u_eev_bytes(&mut buf));
        assert!(!is_echelon_u_eev_patched(&buf));
        assert_eq!(buf, orig);
    }
}
