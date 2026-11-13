use anyhow::{Context, Result, bail};
use std::path::Path;
use crate::patcher::{
    find_child_ci,
    is_camera_alarm_patched,
    is_engine_u_levelinfo_patched,
    is_nonlethal_gameover_patched,
    patch_camera_alarm_bytes,
    patch_engine_u_levelinfo_bytes,
    patch_nonlethal_gameover_bytes,
    revert_camera_alarm_bytes,
    revert_engine_u_levelinfo_bytes,
    revert_nonlethal_gameover_bytes,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PatchFlagDef {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub experimental: bool,
    pub default_enabled: bool,
}

pub static ALL_FLAGS: &[PatchFlagDef] = &[
    PatchFlagDef {
        id: "camera_alarms",
        name: "Security Camera Alarms",
        description: "Enables security cameras to trigger base alarms in Co-op mode (splintercell3.exe patch).",
        experimental: false,
        default_enabled: false,
    },
    PatchFlagDef {
        id: "penthouse_varobject",
        name: "Penthouse / Level VarObject Fix",
        description: "Patches System/Engine.u LevelInfo.PostBeginPlay to resolve Level.VarObject from SoundMapName, fixing instant disconnects in Penthouse and other converted SP maps.",
        experimental: false,
        default_enabled: false,
    },
    PatchFlagDef {
        id: "nonlethal_gameover",
        name: "Non-Lethal Mission Game Over",
        description: "Triggers multiplayer Game Over screen on civilian/guard kill in non-lethal missions (splintercell3.exe patch). Warning: May cause hang on startup.",
        experimental: true,
        default_enabled: false,
    },
];

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
        || (def_id.eq_ignore_ascii_case("penthouse_varobject")
            && query_id.eq_ignore_ascii_case("coop_varobject"))
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

    if flag_matches_id("penthouse_varobject", flag_id) {
        let engine_u_path = find_child_ci(&sys_dir, "Engine.u");
        if let Ok(data) = std::fs::read(&engine_u_path) {
            is_engine_u_levelinfo_patched(&data)
        } else {
            false
        }
    } else {
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
}

/// Query disk status for all defined flags in the given game installation.
pub fn load_flag_states(game_root: &Path) -> Vec<FlagState> {
    ALL_FLAGS
        .iter()
        .map(|def| {
            let enabled = is_flag_applied(game_root, def.id);
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

    if flag_matches_id("penthouse_varobject", flag_id) {
        let engine_u_path = find_child_ci(&sys_dir, "Engine.u");
        let engine_u_bak_path = sys_dir.join("Engine.u.bak");

        if !engine_u_path.exists() && !engine_u_bak_path.exists() {
            bail!("Missing System/Engine.u in {}", game_root.display());
        }

        if enable && !engine_u_bak_path.exists() {
            crate::scct_log!(
                "  [BAK] Creating clean Engine.u backup -> {} ...",
                engine_u_bak_path.display()
            );
            std::fs::copy(&engine_u_path, &engine_u_bak_path)?;
        }

        let mut data = std::fs::read(&engine_u_path)
            .with_context(|| format!("Reading {}", engine_u_path.display()))?;
        let mut modified = false;

        if enable {
            if !is_engine_u_levelinfo_patched(&data) {
                let off = patch_engine_u_levelinfo_bytes(&mut data)?;
                crate::scct_log!(
                    "  [UPK] Patched System/Engine.u LevelInfo.PostBeginPlay @ 0x{:06X} (Coop VarObject & SoundMap fix)",
                    off
                );
                modified = true;
            }
        } else if revert_engine_u_levelinfo_bytes(&mut data) {
            crate::scct_log!("  [UPK] Reverted System/Engine.u LevelInfo.PostBeginPlay");
            modified = true;
        }

        if modified {
            if let Ok(mut perms) = std::fs::metadata(&engine_u_path).map(|m| m.permissions()) {
                if perms.readonly() {
                    perms.set_readonly(false);
                    let _ = std::fs::set_permissions(&engine_u_path, perms);
                }
            }
            std::fs::write(&engine_u_path, &data)
                .with_context(|| format!("Writing {}", engine_u_path.display()))?;
        }
        return Ok(());
    }

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
    let sys_dir = find_child_ci(game_root, "System");

    // 1. Sync splintercell3.exe flags
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

    // 2. Sync Engine.u flags (penthouse_varobject)
    let engine_u_path = find_child_ci(&sys_dir, "Engine.u");
    let engine_u_bak_path = sys_dir.join("Engine.u.bak");

    if engine_u_path.exists() || engine_u_bak_path.exists() {
        if let Some(flag) = flags.iter().find(|f| flag_matches_id(f.def.id, "penthouse_varobject")) {
            if flag.enabled && !engine_u_bak_path.exists() && engine_u_path.exists() {
                crate::scct_log!(
                    "  [BAK] Creating clean Engine.u backup -> {} ...",
                    engine_u_bak_path.display()
                );
                std::fs::copy(&engine_u_path, &engine_u_bak_path)?;
            }

            if engine_u_path.exists() {
                let mut data = std::fs::read(&engine_u_path)
                    .with_context(|| format!("Reading {}", engine_u_path.display()))?;
                let mut modified = false;

                if flag.enabled {
                    if !is_engine_u_levelinfo_patched(&data) {
                        let off = patch_engine_u_levelinfo_bytes(&mut data)?;
                        crate::scct_log!(
                            "  [UPK] Patched System/Engine.u LevelInfo.PostBeginPlay @ 0x{:06X} (Coop VarObject & SoundMap fix)",
                            off
                        );
                        modified = true;
                    }
                } else if revert_engine_u_levelinfo_bytes(&mut data) {
                    crate::scct_log!("  [UPK] Reverted System/Engine.u LevelInfo.PostBeginPlay");
                    modified = true;
                }

                if modified {
                    if let Ok(mut perms) = std::fs::metadata(&engine_u_path).map(|m| m.permissions()) {
                        if perms.readonly() {
                            perms.set_readonly(false);
                            let _ = std::fs::set_permissions(&engine_u_path, perms);
                        }
                    }
                    std::fs::write(&engine_u_path, &data)
                        .with_context(|| format!("Writing {}", engine_u_path.display()))?;
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patcher::{CAMERA_ALARM_GATE_ORIG, ENGINE_U_LEVELINFO_ORIG, NONLETHAL_GAMEOVER_ORIG};

    #[test]
    fn test_flag_definitions_and_defaults() {
        assert_eq!(ALL_FLAGS.len(), 3);
        let cam = find_flag_def("camera_alarms").expect("camera_alarms flag exists");
        assert_eq!(cam.name, "Security Camera Alarms");
        assert!(!cam.experimental);
        assert!(!cam.default_enabled);

        let pvh = find_flag_def("penthouse_varobject").expect("penthouse_varobject flag exists");
        assert_eq!(pvh.name, "Penthouse / Level VarObject Fix");
        assert!(!pvh.experimental);
        assert!(!pvh.default_enabled);

        let coop_alias = find_flag_def("coop_varobject").expect("coop_varobject alias works");
        assert_eq!(coop_alias.id, "penthouse_varobject");

        let nl = find_flag_def("NONLETHAL_GAMEOVER").expect("case-insensitive lookup");
        assert_eq!(nl.name, "Non-Lethal Mission Game Over");
        assert!(nl.experimental);
        assert!(!nl.default_enabled);

        assert!(find_flag_def("nonexistent_flag").is_none());

        let defaults = default_flag_states();
        assert_eq!(defaults.len(), ALL_FLAGS.len());
        assert!(defaults.iter().all(|f| !f.enabled));
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
        mock_data.extend_from_slice(NONLETHAL_GAMEOVER_ORIG);
        mock_data.extend_from_slice(&[0x90; 100]);
        std::fs::write(&exe_path, &mock_data)?;

        // Initially neither flag should be applied
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

        // Test sync_all_flags enabling nonlethal_gameover
        let mut flags = load_flag_states(&dir);
        for f in &mut flags {
            if f.def.id == "nonlethal_gameover" {
                f.enabled = true;
            }
        }
        sync_all_flags(&dir, &flags)?;
        assert!(!is_flag_applied(&dir, "camera_alarms"));
        assert!(is_flag_applied(&dir, "nonlethal_gameover"));

        // Test sync_all_flags reverting both
        for f in &mut flags {
            f.enabled = false;
        }
        sync_all_flags(&dir, &flags)?;
        assert!(!is_flag_applied(&dir, "camera_alarms"));
        assert!(!is_flag_applied(&dir, "nonlethal_gameover"));

        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn test_mock_engine_u_flag_sync_and_revert() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("scct_test_engine_u_flags_{}", std::process::id()));
        let sys_dir = dir.join("System");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&sys_dir)?;
        let engine_u_path = sys_dir.join("Engine.u");

        let mut mock_data = Vec::new();
        mock_data.extend_from_slice(&[0x11; 50]);
        mock_data.extend_from_slice(ENGINE_U_LEVELINFO_ORIG);
        mock_data.extend_from_slice(&[0x22; 50]);
        std::fs::write(&engine_u_path, &mock_data)?;

        // Initially flag not applied
        assert!(!is_flag_applied(&dir, "penthouse_varobject"));
        assert!(!is_flag_applied(&dir, "coop_varobject"));

        // Enable penthouse_varobject
        set_flag_applied(&dir, "penthouse_varobject", true)?;
        assert!(is_flag_applied(&dir, "penthouse_varobject"));
        assert!(is_flag_applied(&dir, "coop_varobject"));

        let engine_u_bak_path = sys_dir.join("Engine.u.bak");
        assert!(engine_u_bak_path.exists());

        // Revert using alias coop_varobject
        set_flag_applied(&dir, "coop_varobject", false)?;
        assert!(!is_flag_applied(&dir, "penthouse_varobject"));
        assert!(!is_flag_applied(&dir, "coop_varobject"));

        // Test sync_all_flags enabling
        let mut flags = load_flag_states(&dir);
        for f in &mut flags {
            if f.def.id == "penthouse_varobject" {
                f.enabled = true;
            }
        }
        sync_all_flags(&dir, &flags)?;
        assert!(is_flag_applied(&dir, "penthouse_varobject"));

        // Test sync_all_flags disabling
        for f in &mut flags {
            f.enabled = false;
        }
        sync_all_flags(&dir, &flags)?;
        assert!(!is_flag_applied(&dir, "penthouse_varobject"));

        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}
