use anyhow::{Context, Result, bail};
use regex::Regex;
use std::collections::HashSet;
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
use crate::net::apply_online_coop_fix;
use crate::umd::{
    append_missions_to_map_rotation, build_appended_coop_ini, normalize_umd_payload_baseline,
    parse_umd_archive, patch_umd_for_all_sp_levels,
};
use crate::upk::patch_sp_map_to_coop;

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

    // Remove stale artifacts or obsolete *_COOP files
    for fname in &map_entries {
        let low = fname.to_lowercase();
        let target = maps_dir.join(fname);
        if low.ends_with("_.scl")
            || low.ends_with("_.ini")
            || low.ends_with("__sound.occ")
            || low.ends_with("__sound.uns")
        {
            let _ = std::fs::remove_file(&target);
            continue;
        }

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

    // Clean loading screens
    if gen_loadings_dir.is_dir() {
        let re_double_under = Regex::new(r"(?i)^.+__loading_[12]\.dds$").unwrap();
        let re_loading = Regex::new(r"(?i)^(.+)_loading_[12]\.dds$").unwrap();

        if let Ok(entries) = std::fs::read_dir(gen_loadings_dir) {
            for entry in entries.flatten() {
                let fname = entry.file_name().to_string_lossy().to_string();
                let target = entry.path();
                if re_double_under.is_match(&fname) {
                    let _ = std::fs::remove_file(&target);
                    continue;
                }
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

pub fn patch_echelon_u_eev(echelon_u_path: &Path, echelon_u_bak_path: &Path) -> Result<()> {
    if !echelon_u_bak_path.exists() {
        if !echelon_u_path.exists() {
            bail!("Missing System/Echelon.u: {}", echelon_u_path.display());
        }
        scct_log!(
            "  [BAK] Creating clean Echelon.u backup -> {} ...",
            echelon_u_bak_path.display()
        );
        std::fs::copy(echelon_u_path, echelon_u_bak_path)?;
    }

    let mut data = std::fs::read(echelon_u_bak_path)?;
    let offset = patch_echelon_u_eev_bytes(&mut data)?;
    std::fs::write(echelon_u_path, &data)?;
    scct_log!(
        "  [UPK] Patched System/Echelon.u EPlayerController.SwitchEEV @ 0x{:06X} (EEV distance hacking enabled in Co-op)",
        offset
    );
    Ok(())
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

pub fn patch_camera_alarm_bytes(data: &mut [u8]) -> Result<usize> {
    assert_eq!(
        CAMERA_ALARM_GATE_ORIG.len(),
        CAMERA_ALARM_GATE_PATCHED.len()
    );
    assert_eq!(
        CAMERA_ALARM_UNIVERSAL_ORIG.len(),
        CAMERA_ALARM_UNIVERSAL_PATCHED.len()
    );
    assert_eq!(
        CAMERA_ALARM_FORCE_ORIG.len(),
        CAMERA_ALARM_FORCE_PATCHED.len()
    );

    let gate_len = CAMERA_ALARM_GATE_ORIG.len();
    let gate_pos = if let Some(pos) = data.windows(gate_len).position(|w| w == CAMERA_ALARM_GATE_ORIG) {
        data[pos..pos + gate_len].copy_from_slice(CAMERA_ALARM_GATE_PATCHED);
        pos
    } else if let Some(pos) = data.windows(gate_len).position(|w| w == CAMERA_ALARM_GATE_PATCHED) {
        pos
    } else {
        bail!("Could not locate EAIZone::StartAlarm camera alarm gate pattern in splintercell3.exe");
    };

    let univ_len = CAMERA_ALARM_UNIVERSAL_ORIG.len();
    if let Some(pos) = data.windows(univ_len).position(|w| w == CAMERA_ALARM_UNIVERSAL_ORIG) {
        data[pos..pos + univ_len].copy_from_slice(CAMERA_ALARM_UNIVERSAL_PATCHED);
    } else if !data.windows(univ_len).any(|w| w == CAMERA_ALARM_UNIVERSAL_PATCHED) {
        bail!("Could not locate EAIZone::StartAlarm universal alarm force pattern in splintercell3.exe");
    }

    let force_len = CAMERA_ALARM_FORCE_ORIG.len();
    if let Some(pos) = data.windows(force_len).position(|w| w == CAMERA_ALARM_FORCE_ORIG) {
        data[pos..pos + force_len].copy_from_slice(CAMERA_ALARM_FORCE_PATCHED);
    } else if !data.windows(force_len).any(|w| w == CAMERA_ALARM_FORCE_PATCHED) {
        bail!("Could not locate ESensor::ProcessDetectedPawn camera alarm force pattern in splintercell3.exe");
    }

    Ok(gate_pos)
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

pub fn patch_nonlethal_gameover_bytes(data: &mut [u8]) -> Result<usize> {
    assert_eq!(
        NONLETHAL_GAMEOVER_ORIG.len(),
        NONLETHAL_GAMEOVER_PATCHED.len()
    );
    assert_eq!(
        COOP_AIZONE_ENABLE_ORIG.len(),
        COOP_AIZONE_ENABLE_PATCHED.len()
    );
    assert_eq!(
        COOP_ENDMISSION_DISPATCH_ORIG.len(),
        COOP_ENDMISSION_DISPATCH_PATCHED.len()
    );

    let nlen = NONLETHAL_GAMEOVER_ORIG.len();
    let menu_pos = if let Some(pos) = data
        .windows(nlen)
        .position(|w| w == NONLETHAL_GAMEOVER_ORIG)
    {
        data[pos..pos + nlen].copy_from_slice(NONLETHAL_GAMEOVER_PATCHED);
        pos
    } else if let Some(pos) = data
        .windows(nlen)
        .position(|w| w == NONLETHAL_GAMEOVER_PATCHED)
    {
        pos
    } else {
        bail!("Could not locate ThrowMenuEvent(0) non-lethal game over pattern in splintercell3.exe");
    };

    let aizone_len = COOP_AIZONE_ENABLE_ORIG.len();
    if let Some(pos) = data.windows(aizone_len).position(|w| w == COOP_AIZONE_ENABLE_ORIG) {
        data[pos..pos + aizone_len].copy_from_slice(COOP_AIZONE_ENABLE_PATCHED);
    } else if !data.windows(aizone_len).any(|w| w == COOP_AIZONE_ENABLE_PATCHED) {
        bail!("Could not locate EchelonGameInfo::AddPlayerInZones AI zone enable pattern in splintercell3.exe");
    }

    let endm_len = COOP_ENDMISSION_DISPATCH_ORIG.len();
    if let Some(pos) = data.windows(endm_len).position(|w| w == COOP_ENDMISSION_DISPATCH_ORIG) {
        data[pos..pos + endm_len].copy_from_slice(COOP_ENDMISSION_DISPATCH_PATCHED);
    } else if !data.windows(endm_len).any(|w| w == COOP_ENDMISSION_DISPATCH_PATCHED) {
        bail!("Could not locate EPattern::execEndMission multiplayer dispatch pattern in splintercell3.exe");
    }

    Ok(menu_pos)
}

pub fn is_camera_alarm_patched(data: &[u8]) -> bool {
    let gate_len = CAMERA_ALARM_GATE_PATCHED.len();
    let univ_len = CAMERA_ALARM_UNIVERSAL_PATCHED.len();
    let force_len = CAMERA_ALARM_FORCE_PATCHED.len();
    data.windows(gate_len).any(|w| w == CAMERA_ALARM_GATE_PATCHED)
        && data.windows(univ_len).any(|w| w == CAMERA_ALARM_UNIVERSAL_PATCHED)
        && data.windows(force_len).any(|w| w == CAMERA_ALARM_FORCE_PATCHED)
}

pub fn is_nonlethal_gameover_patched(data: &[u8]) -> bool {
    let nlen = NONLETHAL_GAMEOVER_PATCHED.len();
    let aizone_len = COOP_AIZONE_ENABLE_PATCHED.len();
    let endm_len = COOP_ENDMISSION_DISPATCH_PATCHED.len();
    data.windows(nlen).any(|w| w == NONLETHAL_GAMEOVER_PATCHED)
        && data.windows(aizone_len).any(|w| w == COOP_AIZONE_ENABLE_PATCHED)
        && data.windows(endm_len).any(|w| w == COOP_ENDMISSION_DISPATCH_PATCHED)
}

pub fn revert_camera_alarm_bytes(data: &mut [u8]) -> bool {
    let gate_len = CAMERA_ALARM_GATE_PATCHED.len();
    let univ_len = CAMERA_ALARM_UNIVERSAL_PATCHED.len();
    let force_len = CAMERA_ALARM_FORCE_PATCHED.len();
    let mut reverted = false;

    if let Some(pos) = data.windows(gate_len).position(|w| w == CAMERA_ALARM_GATE_PATCHED) {
        data[pos..pos + gate_len].copy_from_slice(CAMERA_ALARM_GATE_ORIG);
        reverted = true;
    }
    if let Some(pos) = data.windows(univ_len).position(|w| w == CAMERA_ALARM_UNIVERSAL_PATCHED) {
        data[pos..pos + univ_len].copy_from_slice(CAMERA_ALARM_UNIVERSAL_ORIG);
        reverted = true;
    }
    if let Some(pos) = data.windows(force_len).position(|w| w == CAMERA_ALARM_FORCE_PATCHED) {
        data[pos..pos + force_len].copy_from_slice(CAMERA_ALARM_FORCE_ORIG);
        reverted = true;
    }
    reverted
}

pub fn revert_nonlethal_gameover_bytes(data: &mut [u8]) -> bool {
    let nlen = NONLETHAL_GAMEOVER_PATCHED.len();
    let aizone_len = COOP_AIZONE_ENABLE_PATCHED.len();
    let endm_len = COOP_ENDMISSION_DISPATCH_PATCHED.len();
    let mut reverted = false;

    if let Some(pos) = data.windows(nlen).position(|w| w == NONLETHAL_GAMEOVER_PATCHED) {
        data[pos..pos + nlen].copy_from_slice(NONLETHAL_GAMEOVER_ORIG);
        reverted = true;
    }
    if let Some(pos) = data.windows(aizone_len).position(|w| w == COOP_AIZONE_ENABLE_PATCHED) {
        data[pos..pos + aizone_len].copy_from_slice(COOP_AIZONE_ENABLE_ORIG);
        reverted = true;
    }
    if let Some(pos) = data.windows(endm_len).position(|w| w == COOP_ENDMISSION_DISPATCH_PATCHED) {
        data[pos..pos + endm_len].copy_from_slice(COOP_ENDMISSION_DISPATCH_ORIG);
        reverted = true;
    }
    reverted
}

#[allow(dead_code)]
pub fn are_gameplay_fixes_applied(exe_path: &Path) -> bool {
    if let Ok(data) = std::fs::read(exe_path) {
        is_camera_alarm_patched(&data) && is_nonlethal_gameover_patched(&data)
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

    let mut data = std::fs::read(exe_path)
        .with_context(|| format!("Reading {}", exe_path.display()))?;
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

    if modified {
        if let Ok(mut perms) = std::fs::metadata(exe_path).map(|m| m.permissions()) {
            if perms.readonly() {
                perms.set_readonly(false);
                let _ = std::fs::set_permissions(exe_path, perms);
            }
        }
        std::fs::write(exe_path, &data)
            .with_context(|| format!("Writing {}", exe_path.display()))?;
    }
    Ok(())
}

pub fn apply_all(
    game_root: &Path,
    skip_net_fix: bool,
    flags: &[crate::flags::FlagState],
) -> Result<()> {
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

    let echelon_u_path = find_child_ci(&system_dir, "Echelon.u");
    let echelon_u_bak_path = system_dir.join("Echelon.u.bak");

    scct_log!("\n=== Step 1: Multi-NIC LAN, Online Coop & Gameplay Fixes (`splintercell3.exe`) ===");
    if skip_net_fix {
        if exe_bak_path.exists() {
            std::fs::copy(&exe_bak_path, &exe_path)?;
        }
        scct_log!("  [SKIP] Skipped EXE networking fix (--no-net-fix)");
    } else {
        apply_online_coop_fix(&exe_path, &exe_bak_path, None)?;
    }
    patch_exe_fixes(&exe_path, &exe_bak_path)?;
    crate::flags::sync_all_flags(game_root, flags)?;

    scct_log!(
        "\n=== Step 2: Patching `System/dynamic-pc.umd` & `System/Echelon.u` (Coop Dropdown & Remote Hacking) ==="
    );
    let extracted = patch_umd_for_all_sp_levels(&umd_path, &umd_bak_path, SP_COOP_LEVELS)?;
    if echelon_u_path.exists() || echelon_u_bak_path.exists() {
        patch_echelon_u_eev(&echelon_u_path, &echelon_u_bak_path)?;
    }

    scct_log!("\n=== Step 3: Building All 11 Coop-Patched SP Maps (`Data/Maps/*_COOP.scl`) ===");
    let active_stems: HashSet<String> = SP_COOP_LEVELS
        .iter()
        .map(|s| s.coop_map.to_lowercase())
        .collect();
    ensure_clean_sp_maps_and_cleanup(&maps_dir, &gen_loadings_dir, &active_stems)?;

    std::fs::create_dir_all(&gen_loadings_dir)?;

    let mut disk_ci = std::collections::HashMap::new();
    if let Ok(entries) = std::fs::read_dir(&maps_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            disk_ci.insert(name.to_lowercase(), name);
        }
    }

    for (coop_map, info) in &extracted {
        let spec = &info.spec;
        let src_map = spec.source_map;
        let identity = spec.identity;
        let spawn_offset = spec.spawn_offset;

        let bak_key = format!("{}.scl.bak", src_map.to_lowercase());
        let scl_key = format!("{}.scl", src_map.to_lowercase());

        let src_scl_path = if let Some(orig) = disk_ci.get(&bak_key) {
            maps_dir.join(orig)
        } else if let Some(orig) = disk_ci.get(&scl_key) {
            maps_dir.join(orig)
        } else {
            bail!(
                "Missing source SP map for {} in {}",
                src_map,
                maps_dir.display()
            );
        };

        let dst_scl_path = maps_dir.join(format!("{}.scl", coop_map));
        let summary =
            patch_sp_map_to_coop(&src_scl_path, &dst_scl_path, spec.p1_offset, spawn_offset)?;

        // Copy matching sound files
        for sfx_ext in &["_sound.occ", "_sound.uns"] {
            let sfx_key = format!("{}{}", src_map.to_lowercase(), sfx_ext);
            if let Some(orig) = disk_ci.get(&sfx_key) {
                let src_sfx = maps_dir.join(orig);
                let dst_sfx = maps_dir.join(format!("{}{}", coop_map, sfx_ext));
                std::fs::copy(src_sfx, dst_sfx)?;
            }
        }

        // Write loose INI
        let ini_bytes =
            build_appended_coop_ini(&info.src_ini, &info.canonical_src, coop_map, identity);
        std::fs::write(maps_dir.join(format!("{}.ini", coop_map)), ini_bytes)?;

        // Write loading DDS
        for (idx, dds_bytes) in &info.loading_dds {
            let dds_out = gen_loadings_dir.join(format!("{}_loading_{}.dds", coop_map, idx));
            std::fs::write(dds_out, dds_bytes)?;
        }

        scct_log!(
            "  [COOP] {:22} (ID={:3}): {:9} B | P1=({:.1}, {:.1}, {:.1}) -> P2=({:.1}, {:.1}, {:.1})",
            coop_map,
            identity,
            summary.size,
            summary.p1_loc.0,
            summary.p1_loc.1,
            summary.p1_loc.2,
            summary.p2_loc.0,
            summary.p2_loc.1,
            summary.p2_loc.2
        );
    }

    // Loose MapRotation.ini in System if present
    let loose_rot = find_child_ci(&system_dir, "MapRotation.ini");
    if loose_rot.is_file() {
        let loose_bak = system_dir.join("MapRotation.ini.bak");
        if !loose_bak.exists() {
            std::fs::copy(&loose_rot, &loose_bak)?;
        }
        let mut rot_raw = std::fs::read(&loose_bak)?;
        let target = b"01_Lighthouse   ";
        let replacement = b"00_Training_COOP";
        while let Some(pos) = rot_raw.windows(target.len()).position(|w| w == target) {
            rot_raw[pos..pos + target.len()].copy_from_slice(replacement);
        }
        let coop_names: Vec<&str> = SP_COOP_LEVELS.iter().map(|s| s.coop_map).collect();
        let new_rot = append_missions_to_map_rotation(&rot_raw, &coop_names);
        std::fs::write(&loose_rot, new_rot)?;
        scct_log!("  [INI ] Updated loose System/MapRotation.ini");
    }

    write_version_file(game_root)?;

    scct_log!(
        "\nSuccess! Patched {} SP missions into Coop + applied multi-NIC LAN fix (v{}).",
        SP_COOP_LEVELS.len(),
        MOD_VERSION
    );
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
        let mut umd_data = std::fs::read(&umd_bak_path)?;
        let (_footer, entries, index_by_lower) = parse_umd_archive(&umd_data)?;
        normalize_umd_payload_baseline(&mut umd_data, &entries, &index_by_lower);
        std::fs::write(&umd_path, &umd_data)?;
        scct_log!(
            "  [UMD] Restored vanilla System/dynamic-pc.umd ({} bytes)",
            umd_data.len()
        );
    }

    ensure_clean_sp_maps_and_cleanup(&maps_dir, &gen_loadings_dir, &HashSet::new())?;
    scct_log!("  [MAP] Removed all generated *_COOP.{{scl,ini,occ,uns,dds}} files");

    let loose_rot = find_child_ci(&system_dir, "MapRotation.ini");
    let loose_bak = system_dir.join("MapRotation.ini.bak");
    if loose_bak.exists() {
        let mut rot_raw = std::fs::read(&loose_bak)?;
        let target = b"01_Lighthouse   ";
        let replacement = b"00_Training_COOP";
        while let Some(pos) = rot_raw.windows(target.len()).position(|w| w == target) {
            rot_raw[pos..pos + target.len()].copy_from_slice(replacement);
        }
        std::fs::write(&loose_rot, rot_raw)?;
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

        // Revert
        assert!(revert_nonlethal_gameover_bytes(&mut buf));
        assert!(!is_nonlethal_gameover_patched(&buf));
        assert_eq!(
            &buf[36..36 + NONLETHAL_GAMEOVER_ORIG.len()],
            NONLETHAL_GAMEOVER_ORIG
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

        patch_exe_fixes(&test_exe, &test_bak).unwrap();

        let patched_bytes = std::fs::read(&test_exe).unwrap();
        assert!(is_camera_alarm_patched(&patched_bytes));
        assert!(is_nonlethal_gameover_patched(&patched_bytes));
        assert!(test_bak.exists());

        // Idempotent
        patch_exe_fixes(&test_exe, &test_bak).unwrap();
        let patched_again = std::fs::read(&test_exe).unwrap();
        assert_eq!(patched_bytes, patched_again);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
