use anyhow::{bail, Context, Result};
use regex::Regex;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

static LOG_SINK: Mutex<Option<Box<dyn Fn(&str) + Send + Sync>>> = Mutex::new(None);

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
use crate::net::apply_lan_networking_fix;
use crate::umd::{
    append_missions_to_map_rotation, build_appended_coop_ini, normalize_umd_payload_baseline,
    parse_umd_archive, patch_umd_for_all_sp_levels,
};
use crate::upk::patch_sp_map_to_coop;

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

/// Resolves the SCCT game root.
/// Priority:
/// 1. If explicit `game_dir` is provided:
///    - If it contains `splintercell3.exe` (directly in `game_dir`), root is `game_dir.parent()`.
///    - Else if `game_dir/System/splintercell3.exe` exists, root is `game_dir`.
///    - Else root is `game_dir`.
/// 2. If running from the current directory:
///    - Check if current directory contains `splintercell3.exe` or `splintercell3.exe.bak`.
///      If so, current directory IS `System`, so game root is `current_dir.parent()`.
///    - Else check if current directory contains `System/splintercell3.exe`.
///      If so, game root is `current_dir`.
/// 3. Check next to the current running executable:
///    - If `exe_dir` contains `splintercell3.exe`, root is `exe_dir.parent()`.
///    - If `exe_dir/System/splintercell3.exe` exists, root is `exe_dir`.
/// 4. Fallback default: `current_dir`.
pub fn resolve_game_root(explicit_arg: Option<&Path>) -> Result<PathBuf> {
    if let Some(arg) = explicit_arg {
        let abs = if arg.is_absolute() {
            arg.to_path_buf()
        } else {
            std::env::current_dir()?.join(arg)
        };

        if abs.join("splintercell3.exe").is_file() || abs.join("splintercell3.exe.bak").is_file() {
            let root = abs.parent().unwrap_or(&abs).to_path_buf();
            scct_log!("  [INIT] Detected splintercell3.exe in specified folder: {}", abs.display());
            scct_log!("  [INIT] Using game root: {}", root.display());
            return Ok(root);
        }

        let sys_exe = find_child_ci(&find_child_ci(&abs, "System"), "splintercell3.exe");
        if sys_exe.is_file() {
            scct_log!("  [INIT] Using game root: {}", abs.display());
            return Ok(abs);
        }

        scct_log!("  [INIT] Using specified path as game root: {}", abs.display());
        return Ok(abs);
    }

    // Check current working directory first (User requirement: check current folder for splintercell3.exe)
    let cwd = std::env::current_dir().context("Failed to get current directory")?;
    if cwd.join("splintercell3.exe").is_file() || cwd.join("splintercell3.exe.bak").is_file() {
        let root = cwd.parent().unwrap_or(&cwd).to_path_buf();
        scct_log!("  [INIT] Detected splintercell3.exe in current folder: {}", cwd.display());
        scct_log!("  [INIT] Using game root: {}", root.display());
        return Ok(root);
    }

    let cwd_sys = find_child_ci(&cwd, "System");
    let cwd_sys_exe = find_child_ci(&cwd_sys, "splintercell3.exe");
    if cwd_sys_exe.is_file() {
        scct_log!("  [INIT] Detected System/splintercell3.exe in current folder: {}", cwd.display());
        return Ok(cwd);
    }

    // Check directory of our running executable
    if let Ok(current_bin) = std::env::current_exe() {
        if let Some(bin_dir) = current_bin.parent() {
            if bin_dir.join("splintercell3.exe").is_file()
                || bin_dir.join("splintercell3.exe.bak").is_file()
            {
                let root = bin_dir.parent().unwrap_or(bin_dir).to_path_buf();
                scct_log!("  [INIT] Detected splintercell3.exe next to patcher: {}", bin_dir.display());
                scct_log!("  [INIT] Using game root: {}", root.display());
                return Ok(root);
            }
            let bin_sys = find_child_ci(bin_dir, "System");
            if find_child_ci(&bin_sys, "splintercell3.exe").is_file() {
                scct_log!("  [INIT] Detected System/splintercell3.exe near patcher: {}", bin_dir.display());
                return Ok(bin_dir.to_path_buf());
            }
        }
    }

    // Default fallback to cwd
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
                if let Some(caps) = re_loading.captures(&fname) {
                    if let Some(m) = caps.get(1) {
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

    crate::integrity::verify_game_files_integrity(game_root)?;

    scct_log!("\n=== Step 1: Multi-NIC LAN Coop Networking Fix (`splintercell3.exe`) ===");
    if skip_net_fix {
        if exe_bak_path.exists() {
            std::fs::copy(&exe_bak_path, &exe_path)?;
        }
        scct_log!("  [SKIP] Skipped EXE networking fix (--no-net-fix)");
    } else {
        apply_lan_networking_fix(&exe_path, &exe_bak_path)?;
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
            bail!("Missing source SP map for {} in {}", src_map, maps_dir.display());
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
        let ini_bytes = build_appended_coop_ini(
            &info.src_ini,
            &info.canonical_src,
            coop_map,
            identity,
        );
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
