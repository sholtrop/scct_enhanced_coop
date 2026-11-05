use anyhow::{bail, Context, Result};
use md5::{Digest, Md5};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const CLEAN_EXE_MD5: &str = "46cd0fed7c83269e516767de9f809e76";
pub const PATCHED_EXE_MD5: &str = "786856d202043f5f7c3d76315f9d5c96";

pub const CLEAN_UMD_MD5: &str = "22e79861cc0750f4353d5e8821b2cb1e";
pub const PATCHED_UMD_MD5: &str = "efd3762a36b911f914596e48daf552e1";
pub const PATCHED_UMD_MD5_PREV: &str = "107a09ee139ef2c3f1ab76969ad1fb55";

pub const CLEAN_MAPS: &[(&str, &str)] = &[
    ("01_Lighthouse.scl", "0ad2d1ac79dbc2e9a5b042b2e23c45e5"),
    ("02_CargoShip.scl", "9eb92254487752e6428cec4d91c0a012"),
    ("03_Bank.scl", "e0f3e9f5e7060ff6428c7e83c75db999"),
    ("04_Penthouse.scl", "d251b6a1941bf29600fa2abee752f8c1"),
    ("05_Displace01.scl", "17bb9cef08fad2ac4e21acb2ae90a544"),
    ("06_Hokkaido.scl", "5865518ed3f53d57c86cbefe4cbc668c"),
    ("07_Battery.scl", "1c71002e9577320faa4b29a8ea3cc0a0"),
    ("08_SeoulOne.scl", "99b1771374249d0c8ff578af46743b5a"),
    ("09_SeoulTwo.scl", "660a2affa72a68b2142c1a977f8f05d5"),
    ("10_BathHouse.scl", "ee6a6fc91d6ced6f3bdc31750db95d07"),
    ("11_KokuboSosho.scl", "13f7914729ca64279d036c45a046d950"),
];

pub fn compute_file_md5(path: &Path) -> Result<String> {
    let mut file = File::open(path).with_context(|| format!("Opening {}", path.display()))?;
    let mut hasher = Md5::new();
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let res = hasher.finalize();
    let mut out = String::with_capacity(32);
    for b in res {
        use std::fmt::Write;
        let _ = write!(out, "{:02x}", b);
    }
    Ok(out)
}

fn check_file(
    file_path: &Path,
    display_name: &str,
    expected_clean_md5: &str,
    allowed_alt_md5s: &[&str],
) -> Result<()> {
    if !file_path.is_file() {
        bail!(
            "Missing game file: {}\n\
            Please ensure you are using an official / Steam version of Tom Clancy's Splinter Cell Chaos Theory.",
            display_name
        );
    }

    let actual_md5 = compute_file_md5(file_path)?;
    if actual_md5.eq_ignore_ascii_case(expected_clean_md5) {
        return Ok(());
    }
    for alt in allowed_alt_md5s {
        if actual_md5.eq_ignore_ascii_case(alt) {
            return Ok(());
        }
    }

    bail!(
        "File integrity check failed for '{}'!\n\
        Expected official / Steam MD5: {}\n\
        Found MD5: {}\n\n\
        Please verify you have an official / Steam version of Tom Clancy's Splinter Cell: Chaos Theory (v1.05).\n\
        Modified, repacked, or pirated game files are not supported.",
        display_name,
        expected_clean_md5,
        actual_md5
    );
}

pub fn verify_game_files_integrity(game_root: &Path) -> Result<()> {
    crate::scct_log!("=== Verifying Game Files Integrity (Steam / Official v1.05) ===");

    let system_dir = crate::patcher::find_child_ci(game_root, "System");
    let data_dir = crate::patcher::find_child_ci(game_root, "Data");
    let maps_dir = crate::patcher::find_child_ci(&data_dir, "Maps");

    // 1. Check splintercell3.exe
    let exe_bak = system_dir.join("splintercell3.exe.bak");
    let exe_path = crate::patcher::find_child_ci(&system_dir, "splintercell3.exe");
    let (target_exe, disp_exe, alt_exe): (PathBuf, &str, &[&str]) = if exe_bak.is_file() {
        (exe_bak, "System/splintercell3.exe.bak", &[])
    } else {
        (exe_path, "System/splintercell3.exe", &[PATCHED_EXE_MD5])
    };
    check_file(&target_exe, disp_exe, CLEAN_EXE_MD5, alt_exe)?;
    crate::scct_log!("  [OK ] System/splintercell3.exe verified");

    // 2. Check dynamic-pc.umd
    let umd_bak = system_dir.join("dynamic-pc.umd.bak");
    let umd_path = crate::patcher::find_child_ci(&system_dir, "dynamic-pc.umd");
    let (target_umd, disp_umd, alt_umd): (PathBuf, &str, &[&str]) = if umd_bak.is_file() {
        (umd_bak, "System/dynamic-pc.umd.bak", &[])
    } else {
        (umd_path, "System/dynamic-pc.umd", &[PATCHED_UMD_MD5, PATCHED_UMD_MD5_PREV])
    };
    check_file(&target_umd, disp_umd, CLEAN_UMD_MD5, alt_umd)?;
    crate::scct_log!("  [OK ] System/dynamic-pc.umd verified");

    // 3. Check all 11 source SP .scl maps
    let mut disk_ci = HashMap::new();
    if let Ok(entries) = std::fs::read_dir(&maps_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            disk_ci.insert(name.to_lowercase(), name);
        }
    }

    for (map_file, expected_md5) in CLEAN_MAPS {
        let low = map_file.to_lowercase();
        let bak_key = format!("{}.bak", low);

        let (map_path, disp_name) = if let Some(orig_bak) = disk_ci.get(&bak_key) {
            (maps_dir.join(orig_bak), format!("Data/Maps/{}", orig_bak))
        } else if let Some(orig) = disk_ci.get(&low) {
            (maps_dir.join(orig), format!("Data/Maps/{}", orig))
        } else {
            bail!(
                "Missing required SP map: Data/Maps/{}\n\
                Please ensure you are using an official / Steam version of Tom Clancy's Splinter Cell Chaos Theory.",
                map_file
            );
        };

        check_file(&map_path, &disp_name, expected_md5, &[])?;
    }
    crate::scct_log!("  [OK ] All 11 Single Player maps verified");

    Ok(())
}
