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
use crate::net::{apply_online_coop_fix, load_direct_ip_ini, save_direct_ip_ini};
use crate::umd::{
    append_missions_to_map_rotation, build_appended_coop_ini, normalize_umd_payload_baseline,
    parse_umd_archive, patch_umd_for_all_sp_levels,
};
use crate::upk::patch_sp_map_to_coop;
use std::net::Ipv4Addr;

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
        candidates.push(cwd.join("scct_game_files").join("Tom Clancy's Splinter Cell Chaos Theory"));
        candidates.push(cwd.join("clean_scct_files").join("Tom Clancy's Splinter Cell Chaos Theory"));
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
            format!("{}/.var/app/com.valvesoftware.Steam/.local/share/Steam/steamapps/common", home),
            format!("{}/.wine/drive_c/Program Files (x86)/Steam/steamapps/common", home),
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
        scct_log!("  [INIT] Using specified path as game root: {}", abs.display());
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

pub fn apply_all(game_root: &Path, skip_net_fix: bool) -> Result<()> {
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

    scct_log!("\n=== Step 1: Multi-NIC LAN & Online Coop Networking Fix (`splintercell3.exe`) ===");
    if skip_net_fix {
        if exe_bak_path.exists() {
            std::fs::copy(&exe_bak_path, &exe_path)?;
        }
        scct_log!("  [SKIP] Skipped EXE networking fix (--no-net-fix)");
    } else {
        let ini_path = system_dir.join("direct_ip.ini");
        let target_ip = load_direct_ip_ini(&ini_path);
        apply_online_coop_fix(&exe_path, &exe_bak_path, target_ip)?;
    }

    scct_log!("\n=== Step 2: Patching `System/dynamic-pc.umd` (Coop Dropdown + Localization) ===");
    let extracted = patch_umd_for_all_sp_levels(&umd_path, &umd_bak_path, SP_COOP_LEVELS)?;

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
        let summary = patch_sp_map_to_coop(&src_scl_path, &dst_scl_path, spawn_offset)?;

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

    scct_log!(
        "\nSuccess! Patched {} SP missions into Coop + applied multi-NIC LAN fix.",
        SP_COOP_LEVELS.len()
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

    scct_log!("=== Restoring 100% Vanilla Splinter Cell: Chaos Theory ===");
    if exe_bak_path.exists() {
        std::fs::copy(&exe_bak_path, &exe_path)?;
        scct_log!("  [EXE] Restored vanilla System/splintercell3.exe");
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

    scct_log!("\nVanilla SCCT restoration complete!");
    Ok(())
}

pub fn apply_online_patch(game_root: &Path, target_ip: Option<Ipv4Addr>) -> Result<()> {
    let system_dir = find_child_ci(game_root, "System");
    let exe_path = find_child_ci(&system_dir, "splintercell3.exe");
    let exe_bak_path = system_dir.join("splintercell3.exe.bak");
    let ini_path = system_dir.join("direct_ip.ini");

    apply_online_coop_fix(&exe_path, &exe_bak_path, target_ip)?;
    save_direct_ip_ini(&ini_path, target_ip)?;
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
}
