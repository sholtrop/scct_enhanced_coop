use anyhow::{Context, Result, bail};
use std::path::Path;
use crate::patcher::{
    MOD_VERSION, find_child_ci, get_installed_version, is_camera_alarm_patched,
    is_nonlethal_gameover_patched, patch_camera_alarm_bytes, patch_nonlethal_gameover_bytes,
    revert_camera_alarm_bytes, revert_nonlethal_gameover_bytes,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PatchFlagDef {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub experimental: bool,
    pub default_enabled: bool,
}

pub static ALL_FLAGS: &[PatchFlagDef] = &[];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlagState {
    pub def: PatchFlagDef,
    pub enabled: bool,
}

#[allow(dead_code)]
impl FlagState {
    pub fn new(def: PatchFlagDef, enabled: bool) -> Self {
        Self { def, enabled }
    }
}

pub fn flag_matches_id(def_id: &str, query_id: &str) -> bool {
    def_id.eq_ignore_ascii_case(query_id)
}

#[allow(dead_code)]
pub fn find_flag_def(id: &str) -> Option<PatchFlagDef> {
    ALL_FLAGS.iter().find(|d| flag_matches_id(d.id, id)).copied()
}

/// Creates default flag states (before any game root is selected).
pub fn default_flag_states() -> Vec<FlagState> {
    ALL_FLAGS
        .iter()
        .map(|def| FlagState {
            def: *def,
            enabled: def.default_enabled,
        })
        .collect()
}

/// Query if a specific flag is currently applied on disk.
pub fn is_flag_applied(game_root: &Path, flag_id: &str) -> bool {
    let sys_dir = find_child_ci(game_root, "System");
    let exe_path = find_child_ci(&sys_dir, "splintercell3.exe");
    if let Ok(data) = std::fs::read(&exe_path) {
        match flag_id {
            "camera_alarms" => is_camera_alarm_patched(&data),
            "nonlethal_gameover" => is_nonlethal_gameover_patched(&data),
            _ => false,
        }
    } else {
        false
    }
}

/// Query disk status for all defined flags in the given game installation.
pub fn load_flag_states(game_root: &Path) -> Vec<FlagState> {
    let sys_dir = find_child_ci(game_root, "System");
    let exe_bak_path = sys_dir.join("splintercell3.exe.bak");
    let installed_ver = get_installed_version(game_root);

    ALL_FLAGS
        .iter()
        .map(|def| {
            let enabled = if !exe_bak_path.exists() {
                // Vanilla game not yet modded: use flag's default
                def.default_enabled
            } else if let Some(ref ver) = installed_ver {
                if ver != MOD_VERSION {
                    // Upgrading from an older mod version: automatically enable new default fixes
                    is_flag_applied(game_root, def.id) || def.default_enabled
                } else {
                    // Current mod version: preserve applied disk state
                    is_flag_applied(game_root, def.id)
                }
            } else {
                is_flag_applied(game_root, def.id) || def.default_enabled
            };

            FlagState {
                def: *def,
                enabled,
            }
        })
        .collect()
}

/// Apply or revert a specific flag on disk.
pub fn set_flag_applied(game_root: &Path, flag_id: &str, enable: bool) -> Result<()> {
    let sys_dir = find_child_ci(game_root, "System");
    let exe_path = find_child_ci(&sys_dir, "splintercell3.exe");
    let exe_bak_path = sys_dir.join("splintercell3.exe.bak");

    if !exe_path.exists() {
        bail!("Missing System/splintercell3.exe in {}", game_root.display());
    }

    if enable && !exe_bak_path.exists() {
        crate::scct_log!(
            "  [BAK] Creating clean splintercell3.exe backup -> {} ...",
            exe_bak_path.display()
        );
        std::fs::copy(&exe_path, &exe_bak_path)?;
    }

    let mut data = std::fs::read(&exe_path)
        .with_context(|| format!("Reading {}", exe_path.display()))?;
    let mut modified = false;

    match flag_id {
        "camera_alarms" => {
            if enable {
                if !is_camera_alarm_patched(&data) {
                    let off = patch_camera_alarm_bytes(&mut data)?;
                    crate::scct_log!("  [EXE] Patched security camera alarms @ 0x{:06X}", off);
                    modified = true;
                }
            } else if revert_camera_alarm_bytes(&mut data) {
                crate::scct_log!("  [EXE] Reverted security camera alarms");
                modified = true;
            }
        }
        "nonlethal_gameover" => {
            if enable {
                if !is_nonlethal_gameover_patched(&data) {
                    let off = patch_nonlethal_gameover_bytes(&mut data)?;
                    crate::scct_log!("  [EXE] Patched non-lethal mission Game Over @ 0x{:06X}", off);
                    modified = true;
                }
            } else if revert_nonlethal_gameover_bytes(&mut data) {
                crate::scct_log!("  [EXE] Reverted non-lethal mission Game Over");
                modified = true;
            }
        }
        _ => bail!("Unknown patch flag ID: {}", flag_id),
    }

    if modified {
        if let Ok(mut perms) = std::fs::metadata(&exe_path).map(|m| m.permissions()) {
            if perms.readonly() {
                perms.set_readonly(false);
                let _ = std::fs::set_permissions(&exe_path, perms);
            }
        }
        std::fs::write(&exe_path, &data)
            .with_context(|| format!("Writing {}", exe_path.display()))?;
    }
    Ok(())
}

/// Synchronize all flags in `flags` against the target game on disk.
/// Reads target files once, updates any flags that differ, and writes back if modified.
pub fn sync_all_flags(game_root: &Path, flags: &[FlagState]) -> Result<()> {
    if flags.is_empty() {
        return Ok(());
    }

    let sys_dir = find_child_ci(game_root, "System");

    let exe_path = find_child_ci(&sys_dir, "splintercell3.exe");
    let exe_bak_path = sys_dir.join("splintercell3.exe.bak");

    if exe_path.exists() {
        let any_exe_enable = flags.iter().any(|f| {
            f.enabled && (f.def.id == "camera_alarms" || f.def.id == "nonlethal_gameover")
        });
        if any_exe_enable && !exe_bak_path.exists() {
            crate::scct_log!(
                "  [BAK] Creating clean splintercell3.exe backup -> {} ...",
                exe_bak_path.display()
            );
            std::fs::copy(&exe_path, &exe_bak_path)?;
        }

        let mut data = std::fs::read(&exe_path)
            .with_context(|| format!("Reading {}", exe_path.display()))?;
        let mut modified = false;

        for flag in flags {
            match flag.def.id {
                "camera_alarms" => {
                    if flag.enabled {
                        if !is_camera_alarm_patched(&data) {
                            let off = patch_camera_alarm_bytes(&mut data)?;
                            crate::scct_log!("  [EXE] Patched security camera alarms @ 0x{:06X}", off);
                            modified = true;
                        }
                    } else if revert_camera_alarm_bytes(&mut data) {
                        crate::scct_log!("  [EXE] Reverted security camera alarms");
                        modified = true;
                    }
                }
                "nonlethal_gameover" => {
                    if flag.enabled {
                        if !is_nonlethal_gameover_patched(&data) {
                            let off = patch_nonlethal_gameover_bytes(&mut data)?;
                            crate::scct_log!("  [EXE] Patched non-lethal mission Game Over @ 0x{:06X}", off);
                            modified = true;
                        }
                    } else if revert_nonlethal_gameover_bytes(&mut data) {
                        crate::scct_log!("  [EXE] Reverted non-lethal mission Game Over");
                        modified = true;
                    }
                }
                _ => {}
            }
        }

        if modified {
            if let Ok(mut perms) = std::fs::metadata(&exe_path).map(|m| m.permissions()) {
                if perms.readonly() {
                    perms.set_readonly(false);
                    let _ = std::fs::set_permissions(&exe_path, perms);
                }
            }
            std::fs::write(&exe_path, &data)
                .with_context(|| format!("Writing {}", exe_path.display()))?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patcher::{
        CAMERA_ALARM_FORCE_ORIG, CAMERA_ALARM_GATE_ORIG, CAMERA_ALARM_UNIVERSAL_ORIG,
        COOP_AIZONE_ENABLE_ORIG, COOP_ENDMISSION_DISPATCH_ORIG, NONLETHAL_GAMEOVER_ORIG,
    };

    #[test]
    fn test_flag_definitions_and_defaults() {
        assert_eq!(ALL_FLAGS.len(), 0);
        assert!(find_flag_def("camera_alarms").is_none());
        assert!(find_flag_def("nonlethal_gameover").is_none());
        assert!(find_flag_def("penthouse_varobject").is_none());
        assert!(find_flag_def("coop_varobject").is_none());
        assert!(find_flag_def("nonexistent_flag").is_none());

        let defaults = default_flag_states();
        assert!(defaults.is_empty());
    }

    #[test]
    fn test_mock_exe_flag_sync_and_revert() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("scct_test_flags_{}", std::process::id()));
        let sys_dir = dir.join("System");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&sys_dir)?;
        let exe_path = sys_dir.join("splintercell3.exe");

        // Construct mock exe data with vanilla patterns
        let mut mock_data = Vec::new();
        mock_data.extend_from_slice(&[0x90; 100]);
        mock_data.extend_from_slice(CAMERA_ALARM_GATE_ORIG);
        mock_data.extend_from_slice(&[0x90; 100]);
        mock_data.extend_from_slice(CAMERA_ALARM_UNIVERSAL_ORIG);
        mock_data.extend_from_slice(&[0x90; 100]);
        mock_data.extend_from_slice(CAMERA_ALARM_FORCE_ORIG);
        mock_data.extend_from_slice(&[0x90; 100]);
        mock_data.extend_from_slice(NONLETHAL_GAMEOVER_ORIG);
        mock_data.extend_from_slice(&[0x90; 100]);
        mock_data.extend_from_slice(COOP_AIZONE_ENABLE_ORIG);
        mock_data.extend_from_slice(&[0x90; 100]);
        mock_data.extend_from_slice(COOP_ENDMISSION_DISPATCH_ORIG);
        mock_data.extend_from_slice(&[0x90; 100]);
        std::fs::write(&exe_path, &mock_data)?;

        // Initially neither flag should be applied on disk
        assert!(!is_flag_applied(&dir, "camera_alarms"));
        assert!(!is_flag_applied(&dir, "nonlethal_gameover"));

        // Enable only camera alarms
        set_flag_applied(&dir, "camera_alarms", true)?;
        assert!(is_flag_applied(&dir, "camera_alarms"));
        assert!(!is_flag_applied(&dir, "nonlethal_gameover"));

        // Check backup was created
        let exe_bak_path = sys_dir.join("splintercell3.exe.bak");
        assert!(exe_bak_path.exists());

        // Revert camera alarms
        set_flag_applied(&dir, "camera_alarms", false)?;
        assert!(!is_flag_applied(&dir, "camera_alarms"));

        // Test set_flag_applied enabling nonlethal_gameover
        set_flag_applied(&dir, "nonlethal_gameover", true)?;
        assert!(!is_flag_applied(&dir, "camera_alarms"));
        assert!(is_flag_applied(&dir, "nonlethal_gameover"));

        // Revert nonlethal_gameover
        set_flag_applied(&dir, "nonlethal_gameover", false)?;
        assert!(!is_flag_applied(&dir, "camera_alarms"));
        assert!(!is_flag_applied(&dir, "nonlethal_gameover"));

        // Sync with empty flags succeeds
        sync_all_flags(&dir, &[])?;

        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}
