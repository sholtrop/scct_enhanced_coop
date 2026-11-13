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

/// Bytecode pattern in `System/Engine.u` (`LevelInfo.PostBeginPlay`, export 2008):
/// In single-player, map name is e.g. "04_Penthouse.scl" -> Left(temp, InStr(temp, '.')) -> "04_Penthouse".
/// In co-op, map name is e.g. "04_Penthouse_COOP.scl" -> "04_Penthouse_COOP".
/// DynamicLoadObject("EchelonPattern.V" $ temp) fails because V04_Penthouse_COOP does not exist in EchelonPattern.u.
/// This causes Level.VarObject to remain None, crashing/aborting maps whose initial pattern logic (e.g. Penthouse PO1 -> BP01)
/// calls ChangeVariableValue(out int Variable) with Level.VarObject on tick 0.
///
/// Patch:
/// If SoundMapName != "", use SoundMapName directly ("04_Penthouse"), so VarObject is loaded and spawned cleanly.
/// If SoundMapName == "", falls back to GetCurrentMapName() (preserving 00_Training_COOP and custom maps).
pub const ENGINE_U_LEVELINFO_ORIG: &[u8] = &[
    0x0f, 0x00, 0x40, 0x02, 0x65, 0x8b, 0x16, 0x07, 0x36, 0x00, 0x97, 0x7e, 0x00, 0x40, 0x02, 0x1f,
    0x2e, 0x00, 0x16, 0x25, 0x16, 0x0f, 0x00, 0x40, 0x02, 0x80, 0x00, 0x40, 0x02, 0x7e, 0x00, 0x40,
    0x02, 0x1f, 0x2e, 0x00, 0x16, 0x16, 0x07, 0x4a, 0x00, 0x2d, 0x01, 0x79, 0x16, 0x0f, 0x01, 0x7a,
    0x16, 0x00, 0x40, 0x02,
];

pub const ENGINE_U_LEVELINFO_PATCHED: &[u8] = &[
    // temp = SoundMapName; (7 bytes)
    0x0f, 0x00, 0x40, 0x02, 0x01, 0x7a, 0x16,
    // if (!(temp == "")) goto 0x004a; (10 bytes)
    0x07, 0x4a, 0x00, 0x7a, 0x00, 0x40, 0x02, 0x1f, 0x00, 0x16,
    // temp = GetCurrentMapName(); (7 bytes)
    0x0f, 0x00, 0x40, 0x02, 0x65, 0x8b, 0x16,
    // temp = Left(temp, InStr(temp, '.')); (17 bytes)
    0x0f, 0x00, 0x40, 0x02, 0x80, 0x00, 0x40, 0x02, 0x7e, 0x00, 0x40, 0x02, 0x1f, 0x2e, 0x00, 0x16,
    0x16, // 11 x EX_Nothing (NOPs) to pad out to 52 bytes:
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
];

pub fn patch_engine_u_levelinfo_bytes(data: &mut [u8]) -> Result<usize> {
    assert_eq!(
        ENGINE_U_LEVELINFO_ORIG.len(),
        ENGINE_U_LEVELINFO_PATCHED.len()
    );
    let nlen = ENGINE_U_LEVELINFO_ORIG.len();
    if let Some(pos) = data
        .windows(nlen)
        .position(|w| w == ENGINE_U_LEVELINFO_ORIG)
    {
        data[pos..pos + nlen].copy_from_slice(ENGINE_U_LEVELINFO_PATCHED);
        return Ok(pos);
    }
    if let Some(pos) = data
        .windows(nlen)
        .position(|w| w == ENGINE_U_LEVELINFO_PATCHED)
    {
        return Ok(pos);
    }
    bail!("Could not locate LevelInfo.PostBeginPlay bytecode pattern in Engine.u");
}

pub fn is_engine_u_levelinfo_patched(data: &[u8]) -> bool {
    let nlen = ENGINE_U_LEVELINFO_PATCHED.len();
    data.windows(nlen).any(|w| w == ENGINE_U_LEVELINFO_PATCHED)
}

pub fn revert_engine_u_levelinfo_bytes(data: &mut [u8]) -> bool {
    let nlen = ENGINE_U_LEVELINFO_PATCHED.len();
    if let Some(pos) = data
        .windows(nlen)
        .position(|w| w == ENGINE_U_LEVELINFO_PATCHED)
    {
        data[pos..pos + nlen].copy_from_slice(ENGINE_U_LEVELINFO_ORIG);
        true
    } else {
        false
    }
}

#[allow(dead_code)]
pub fn patch_engine_u(engine_u_path: &Path, engine_u_bak_path: &Path) -> Result<()> {
    if !engine_u_bak_path.exists() {
        if !engine_u_path.exists() {
            bail!("Missing System/Engine.u: {}", engine_u_path.display());
        }
        scct_log!(
            "  [BAK] Creating clean Engine.u backup -> {} ...",
            engine_u_bak_path.display()
        );
        std::fs::copy(engine_u_path, engine_u_bak_path)?;
    }

    let mut data = std::fs::read(engine_u_bak_path)?;
    let offset = patch_engine_u_levelinfo_bytes(&mut data)?;
    if let Ok(mut perms) = std::fs::metadata(engine_u_path).map(|m| m.permissions()) {
        if perms.readonly() {
            perms.set_readonly(false);
            let _ = std::fs::set_permissions(engine_u_path, perms);
        }
    }
    std::fs::write(engine_u_path, &data)?;
    scct_log!(
        "  [UPK] Patched System/Engine.u LevelInfo.PostBeginPlay @ 0x{:06X} (Coop VarObject & SoundMap fix)",
        offset
    );
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

pub fn patch_camera_alarm_bytes(data: &mut [u8]) -> Result<usize> {
    assert_eq!(
        CAMERA_ALARM_GATE_ORIG.len(),
        CAMERA_ALARM_GATE_PATCHED.len()
    );
    let nlen = CAMERA_ALARM_GATE_ORIG.len();
    if let Some(pos) = data.windows(nlen).position(|w| w == CAMERA_ALARM_GATE_ORIG) {
        data[pos..pos + nlen].copy_from_slice(CAMERA_ALARM_GATE_PATCHED);
        return Ok(pos);
    }
    if let Some(pos) = data
        .windows(nlen)
        .position(|w| w == CAMERA_ALARM_GATE_PATCHED)
    {
        return Ok(pos);
    }
    bail!("Could not locate EAIZone::StartAlarm camera alarm pattern in splintercell3.exe");
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

pub fn patch_nonlethal_gameover_bytes(data: &mut [u8]) -> Result<usize> {
    assert_eq!(
        NONLETHAL_GAMEOVER_ORIG.len(),
        NONLETHAL_GAMEOVER_PATCHED.len()
    );
    let nlen = NONLETHAL_GAMEOVER_ORIG.len();
    if let Some(pos) = data
        .windows(nlen)
        .position(|w| w == NONLETHAL_GAMEOVER_ORIG)
    {
        data[pos..pos + nlen].copy_from_slice(NONLETHAL_GAMEOVER_PATCHED);
        return Ok(pos);
    }
    if let Some(pos) = data
        .windows(nlen)
        .position(|w| w == NONLETHAL_GAMEOVER_PATCHED)
    {
        return Ok(pos);
    }
    bail!("Could not locate ThrowMenuEvent(0) non-lethal game over pattern in splintercell3.exe");
}

pub fn is_camera_alarm_patched(data: &[u8]) -> bool {
    let nlen = CAMERA_ALARM_GATE_PATCHED.len();
    data.windows(nlen).any(|w| w == CAMERA_ALARM_GATE_PATCHED)
}

pub fn is_nonlethal_gameover_patched(data: &[u8]) -> bool {
    let nlen = NONLETHAL_GAMEOVER_PATCHED.len();
    data.windows(nlen).any(|w| w == NONLETHAL_GAMEOVER_PATCHED)
}

pub fn revert_camera_alarm_bytes(data: &mut [u8]) -> bool {
    let nlen = CAMERA_ALARM_GATE_PATCHED.len();
    if let Some(pos) = data
        .windows(nlen)
        .position(|w| w == CAMERA_ALARM_GATE_PATCHED)
    {
        data[pos..pos + nlen].copy_from_slice(CAMERA_ALARM_GATE_ORIG);
        true
    } else {
        false
    }
}

pub fn revert_nonlethal_gameover_bytes(data: &mut [u8]) -> bool {
    let nlen = NONLETHAL_GAMEOVER_PATCHED.len();
    if let Some(pos) = data
        .windows(nlen)
        .position(|w| w == NONLETHAL_GAMEOVER_PATCHED)
    {
        data[pos..pos + nlen].copy_from_slice(NONLETHAL_GAMEOVER_ORIG);
        true
    } else {
        false
    }
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

#[allow(dead_code)]
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

    let mut data = std::fs::read(exe_path)?;
    let cam_off = patch_camera_alarm_bytes(&mut data)?;
    scct_log!("  [EXE] Patched security camera alarms @ 0x{:06X}", cam_off);
    let go_off = patch_nonlethal_gameover_bytes(&mut data)?;
    scct_log!(
        "  [EXE] Patched non-lethal mission Game Over @ 0x{:06X}",
        go_off
    );
    std::fs::write(exe_path, &data)?;
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

    scct_log!("\n=== Step 1: Multi-NIC LAN & Online Coop Networking Fix (`splintercell3.exe`) ===");
    if skip_net_fix {
        if exe_bak_path.exists() {
            std::fs::copy(&exe_bak_path, &exe_path)?;
        }
        scct_log!("  [SKIP] Skipped EXE networking fix (--no-net-fix)");
    } else {
        apply_online_coop_fix(&exe_path, &exe_bak_path, None)?;
    }
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

        let off1 = patch_camera_alarm_bytes(&mut buf).unwrap();
        assert_eq!(off1, 48);
        assert_eq!(
            &buf[48..48 + CAMERA_ALARM_GATE_PATCHED.len()],
            CAMERA_ALARM_GATE_PATCHED
        );

        // Idempotent second call
        let off2 = patch_camera_alarm_bytes(&mut buf).unwrap();
        assert_eq!(off2, 48);
        assert!(is_camera_alarm_patched(&buf));
    }

    #[test]
    fn test_patch_nonlethal_gameover_bytes() {
        let mut buf = vec![0xEE; 36];
        buf.extend_from_slice(NONLETHAL_GAMEOVER_ORIG);
        buf.extend_from_slice(&[0xFF; 24]);

        let off1 = patch_nonlethal_gameover_bytes(&mut buf).unwrap();
        assert_eq!(off1, 36);
        assert_eq!(
            &buf[36..36 + NONLETHAL_GAMEOVER_PATCHED.len()],
            NONLETHAL_GAMEOVER_PATCHED
        );

        // Idempotent second call
        let off2 = patch_nonlethal_gameover_bytes(&mut buf).unwrap();
        assert_eq!(off2, 36);
        assert!(is_nonlethal_gameover_patched(&buf));
    }

    #[test]
    fn test_patch_engine_u_levelinfo_bytes() {
        let mut buf = vec![0x12; 40];
        buf.extend_from_slice(ENGINE_U_LEVELINFO_ORIG);
        buf.extend_from_slice(&[0x34; 20]);

        assert!(!is_engine_u_levelinfo_patched(&buf));

        let off1 = patch_engine_u_levelinfo_bytes(&mut buf).unwrap();
        assert_eq!(off1, 40);
        assert_eq!(
            &buf[40..40 + ENGINE_U_LEVELINFO_PATCHED.len()],
            ENGINE_U_LEVELINFO_PATCHED
        );
        assert!(is_engine_u_levelinfo_patched(&buf));

        // Idempotent second call
        let off2 = patch_engine_u_levelinfo_bytes(&mut buf).unwrap();
        assert_eq!(off2, 40);
        assert!(is_engine_u_levelinfo_patched(&buf));

        // Revert test
        assert!(revert_engine_u_levelinfo_bytes(&mut buf));
        assert!(!is_engine_u_levelinfo_patched(&buf));
        assert_eq!(
            &buf[40..40 + ENGINE_U_LEVELINFO_ORIG.len()],
            ENGINE_U_LEVELINFO_ORIG
        );
        assert!(!revert_engine_u_levelinfo_bytes(&mut buf));
    }
}
