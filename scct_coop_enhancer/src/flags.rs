use anyhow::{Context, Result, bail};
use std::path::Path;
use crate::net::{
    is_ai_visibility_culling_disabled, is_pause_always_ready_patched,
    is_startup_checksum_bypass_patched, patch_ai_visibility_culling_disabled_bytes,
    patch_pause_always_ready_bytes, patch_startup_checksum_bypass_bytes,
    revert_ai_visibility_culling_disabled_bytes, revert_pause_always_ready_bytes,
    revert_startup_checksum_bypass_bytes,
};
use crate::patcher::{
    MOD_VERSION, are_coop_maps_keeping_speaker_zones, find_child_ci, get_installed_version,
    is_camera_alarm_patched, is_nonlethal_gameover_patched, patch_camera_alarm_bytes,
    patch_nonlethal_gameover_bytes, revert_camera_alarm_bytes, revert_nonlethal_gameover_bytes,
    sync_coop_maps_detach_state,
};

pub const FLAG_CLIENT_ALWAYS_READY_UNPAUSE: &str = "client_always_ready_unpause";
pub const FLAG_BYPASS_STARTUP_CHECKSUM: &str = "bypass_startup_checksum";
pub const FLAG_DISABLE_AI_VISIBILITY_CULLING: &str = "disable_ai_visibility_culling";
pub const FLAG_SKIP_UPK_PAWN_DETACH: &str = "skip_upk_pawn_detach";

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
        id: FLAG_CLIENT_ALWAYS_READY_UNPAUSE,
        name: "Client Always Ready for Unpause",
        description: "Forces Co-op pause menu IsPlayerReady (0x109639E0) to return 1 so Resume Game (unpause), QuickSave, and QuickLoad do not wait on the remote player. Disable to test vanilla pause/ready sync.",
        experimental: false,
        default_enabled: true,
    },
    PatchFlagDef {
        id: FLAG_BYPASS_STARTUP_CHECKSUM,
        name: "Bypass Checksum Disconnect (Trace Mode)",
        description: "Allows gameplay to continue past Step 7 checksum mismatches while still dumping the first mismatch and recording startup tick/checksum trace data.",
        experimental: true,
        default_enabled: false,
    },
    PatchFlagDef {
        id: FLAG_DISABLE_AI_VISIBILITY_CULLING,
        name: "Disable AI Visibility Tick-Culling",
        description: "Forces AEAIPawn::vt+0x2BC (0x10C1852C) to return 0 so AI pawns never skip simulation ticks based on LastRenderTime / 1.0s camera visibility. Enable to isolate render-gated AI desyncs.",
        experimental: true,
        default_enabled: false,
    },
    PatchFlagDef {
        id: FLAG_SKIP_UPK_PAWN_DETACH,
        name: "Do Not Detach Speaker Pawns in Map Assets",
        description: "Keeps vanilla CurrentEAIZone on HQ speaker pawns (Lambert/Grim/Redding) in *_COOP.scl maps instead of rewriting map UPKs to detach them (the alternative to COOP_AIZONE_ENABLE).",
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
    if flag_id == FLAG_SKIP_UPK_PAWN_DETACH {
        return are_coop_maps_keeping_speaker_zones(game_root);
    }

    let sys_dir = find_child_ci(game_root, "System");
    let exe_path = find_child_ci(&sys_dir, "splintercell3.exe");
    if let Ok(data) = std::fs::read(&exe_path) {
        match flag_id {
            FLAG_CLIENT_ALWAYS_READY_UNPAUSE => is_pause_always_ready_patched(&data),
            FLAG_BYPASS_STARTUP_CHECKSUM => is_startup_checksum_bypass_patched(&data),
            FLAG_DISABLE_AI_VISIBILITY_CULLING => is_ai_visibility_culling_disabled(&data),
            "camera_alarms" => is_camera_alarm_patched(&data),
            "nonlethal_gameover" => is_nonlethal_gameover_patched(&data),
            _ => false,
        }
    } else {
        false
    }
}

fn toggle_exe_patch(
    data: &mut [u8],
    enable: bool,
    is_patched: fn(&[u8]) -> bool,
    apply_fn: fn(&mut [u8]) -> Result<usize>,
    revert_fn: fn(&mut [u8]) -> bool,
    apply_msg: &str,
    revert_msg: &str,
) -> Result<bool> {
    if enable {
        if !is_patched(data) {
            let off = apply_fn(data)?;
            crate::scct_log!("  [EXE] {} @ 0x{:06X}", apply_msg, off);
            return Ok(true);
        }
    } else if revert_fn(data) {
        crate::scct_log!("  [EXE] {}", revert_msg);
        return Ok(true);
    }
    Ok(false)
}

/// Apply or revert one EXE flag inside an in-memory `splintercell3.exe` buffer.
fn apply_flag_to_exe_bytes(data: &mut [u8], flag_id: &str, enable: bool) -> Result<bool> {
    match flag_id {
        FLAG_CLIENT_ALWAYS_READY_UNPAUSE => toggle_exe_patch(
            data,
            enable,
            is_pause_always_ready_patched,
            patch_pause_always_ready_bytes,
            revert_pause_always_ready_bytes,
            "Patched client always ready for unpause",
            "Reverted client always ready for unpause",
        ),
        FLAG_BYPASS_STARTUP_CHECKSUM => toggle_exe_patch(
            data,
            enable,
            is_startup_checksum_bypass_patched,
            patch_startup_checksum_bypass_bytes,
            revert_startup_checksum_bypass_bytes,
            "Patched startup checksum disconnect bypass",
            "Reverted startup checksum disconnect bypass",
        ),
        FLAG_DISABLE_AI_VISIBILITY_CULLING => toggle_exe_patch(
            data,
            enable,
            is_ai_visibility_culling_disabled,
            patch_ai_visibility_culling_disabled_bytes,
            revert_ai_visibility_culling_disabled_bytes,
            "Disabled AI visibility tick-culling (0x10C1852C)",
            "Restored vanilla AI visibility tick-culling (0x10C1852C)",
        ),
        "camera_alarms" => toggle_exe_patch(
            data,
            enable,
            is_camera_alarm_patched,
            patch_camera_alarm_bytes,
            revert_camera_alarm_bytes,
            "Patched security camera alarms",
            "Reverted security camera alarms",
        ),
        "nonlethal_gameover" => toggle_exe_patch(
            data,
            enable,
            is_nonlethal_gameover_patched,
            patch_nonlethal_gameover_bytes,
            revert_nonlethal_gameover_bytes,
            "Patched non-lethal mission Game Over",
            "Reverted non-lethal mission Game Over",
        ),
        _ => bail!("Unknown patch flag ID: {}", flag_id),
    }
}

fn write_exe_clearing_readonly(exe_path: &Path, data: &[u8]) -> Result<()> {
    if let Ok(mut perms) = std::fs::metadata(exe_path).map(|m| m.permissions()) {
        if perms.readonly() {
            perms.set_readonly(false);
            let _ = std::fs::set_permissions(exe_path, perms);
        }
    }
    std::fs::write(exe_path, data).with_context(|| format!("Writing {}", exe_path.display()))?;
    Ok(())
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
    if flag_matches_id(flag_id, FLAG_SKIP_UPK_PAWN_DETACH) {
        sync_coop_maps_detach_state(game_root, !enable)?;
        return Ok(());
    }

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
    if apply_flag_to_exe_bytes(&mut data, flag_id, enable)? {
        write_exe_clearing_readonly(&exe_path, &data)?;
    }
    Ok(())
}

/// Synchronize EXE patch flags in `flags` against `System/splintercell3.exe`.
pub fn sync_exe_flags(game_root: &Path, flags: &[FlagState]) -> Result<()> {
    let exe_flags: Vec<&FlagState> = flags
        .iter()
        .filter(|f| !flag_matches_id(f.def.id, FLAG_SKIP_UPK_PAWN_DETACH))
        .collect();
    if exe_flags.is_empty() {
        return Ok(());
    }

    let sys_dir = find_child_ci(game_root, "System");
    let exe_path = find_child_ci(&sys_dir, "splintercell3.exe");
    let exe_bak_path = sys_dir.join("splintercell3.exe.bak");

    if exe_path.exists() {
        let any_exe_enable = exe_flags.iter().any(|f| f.enabled);
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

        for flag in exe_flags {
            if apply_flag_to_exe_bytes(&mut data, flag.def.id, flag.enabled)? {
                modified = true;
            }
        }

        if modified {
            write_exe_clearing_readonly(&exe_path, &data)?;
        }
    }

    Ok(())
}

/// Synchronize all flags in `flags` (EXE + UPK map detachment state) against disk.
pub fn sync_all_flags(game_root: &Path, flags: &[FlagState]) -> Result<()> {
    if flags.is_empty() {
        return Ok(());
    }
    sync_exe_flags(game_root, flags)?;
    if let Some(skip_flag) = flags
        .iter()
        .find(|f| flag_matches_id(f.def.id, FLAG_SKIP_UPK_PAWN_DETACH))
    {
        sync_coop_maps_detach_state(game_root, !skip_flag.enabled)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{
        AI_VISIBILITY_CULL_ORIG, HOOK_AI_VISIBILITY_CULL, HOOK_PAUSE_IS_PLAYER_READY,
        HOOK_SITE_CHECK_SIM_CHECKSUM, PAUSE_IS_PLAYER_READY_ORIG_HEX, SIM_CHECKSUM_CAVE_VA,
        SIM_CHECKSUM_ORIG, decode_hex, va_to_text_off,
    };
    use crate::patcher::{
        CAMERA_ALARM_FORCE_ORIG, CAMERA_ALARM_GATE_ORIG, CAMERA_ALARM_UNIVERSAL_ORIG,
        COOP_AIZONE_ENABLE_ORIG, COOP_ENDMISSION_DISPATCH_ORIG, NONLETHAL_GAMEOVER_ORIG,
    };

    #[test]
    fn test_flag_definitions_and_defaults() {
        assert_eq!(ALL_FLAGS.len(), 4);
        let ready_def = find_flag_def(FLAG_CLIENT_ALWAYS_READY_UNPAUSE)
            .expect("client_always_ready_unpause flag must exist");
        assert!(ready_def.default_enabled);
        let bypass_def = find_flag_def(FLAG_BYPASS_STARTUP_CHECKSUM)
            .expect("bypass_startup_checksum flag must exist");
        assert!(!bypass_def.default_enabled);
        assert!(bypass_def.experimental);
        let cull_def = find_flag_def(FLAG_DISABLE_AI_VISIBILITY_CULLING)
            .expect("disable_ai_visibility_culling flag must exist");
        assert!(!cull_def.default_enabled);
        assert!(cull_def.experimental);
        let skip_detach_def = find_flag_def(FLAG_SKIP_UPK_PAWN_DETACH)
            .expect("skip_upk_pawn_detach flag must exist");
        assert!(!skip_detach_def.default_enabled);
        assert!(skip_detach_def.experimental);
        assert!(find_flag_def("camera_alarms").is_none());
        assert!(find_flag_def("nonlethal_gameover").is_none());
        assert!(find_flag_def("penthouse_varobject").is_none());
        assert!(find_flag_def("coop_varobject").is_none());
        assert!(find_flag_def("nonexistent_flag").is_none());

        let defaults = default_flag_states();
        assert_eq!(defaults.len(), 4);
        assert_eq!(defaults[0].def.id, FLAG_CLIENT_ALWAYS_READY_UNPAUSE);
        assert!(defaults[0].enabled);
        assert_eq!(defaults[1].def.id, FLAG_BYPASS_STARTUP_CHECKSUM);
        assert!(!defaults[1].enabled);
        assert_eq!(defaults[2].def.id, FLAG_DISABLE_AI_VISIBILITY_CULLING);
        assert!(!defaults[2].enabled);
        assert_eq!(defaults[3].def.id, FLAG_SKIP_UPK_PAWN_DETACH);
        assert!(!defaults[3].enabled);
    }

    #[test]
    fn test_mock_exe_flag_sync_and_revert() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("scct_test_flags_{}", std::process::id()));
        let sys_dir = dir.join("System");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&sys_dir)?;
        let exe_path = sys_dir.join("splintercell3.exe");

        // Construct mock exe data with vanilla patterns and vanilla hook site bytes
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

        let ready_off = va_to_text_off(HOOK_PAUSE_IS_PLAYER_READY)?;
        let ready_orig = decode_hex(PAUSE_IS_PLAYER_READY_ORIG_HEX);
        let sim_chk_off = va_to_text_off(HOOK_SITE_CHECK_SIM_CHECKSUM)?;
        let cull_off = va_to_text_off(HOOK_AI_VISIBILITY_CULL)?;
        let sim_cave_off = va_to_text_off(SIM_CHECKSUM_CAVE_VA)?;
        assert!(mock_data.len() < ready_off);
        mock_data.resize(sim_cave_off + 32, 0x00);
        mock_data[ready_off..ready_off + ready_orig.len()].copy_from_slice(&ready_orig);
        mock_data[sim_chk_off..sim_chk_off + 8].copy_from_slice(SIM_CHECKSUM_ORIG);
        mock_data[cull_off..cull_off + 8].copy_from_slice(AI_VISIBILITY_CULL_ORIG);
        std::fs::write(&exe_path, &mock_data)?;

        // Initially no flag is applied on disk
        assert!(!is_flag_applied(&dir, FLAG_CLIENT_ALWAYS_READY_UNPAUSE));
        assert!(!is_flag_applied(&dir, FLAG_BYPASS_STARTUP_CHECKSUM));
        assert!(!is_flag_applied(&dir, FLAG_DISABLE_AI_VISIBILITY_CULLING));
        assert!(!is_flag_applied(&dir, FLAG_SKIP_UPK_PAWN_DETACH));
        assert!(!is_flag_applied(&dir, "camera_alarms"));
        assert!(!is_flag_applied(&dir, "nonlethal_gameover"));

        // Toggle client_always_ready_unpause on & off via set_flag_applied
        set_flag_applied(&dir, FLAG_CLIENT_ALWAYS_READY_UNPAUSE, true)?;
        assert!(is_flag_applied(&dir, FLAG_CLIENT_ALWAYS_READY_UNPAUSE));
        let exe_bak_path = sys_dir.join("splintercell3.exe.bak");
        assert!(exe_bak_path.exists());

        set_flag_applied(&dir, FLAG_CLIENT_ALWAYS_READY_UNPAUSE, false)?;
        assert!(!is_flag_applied(&dir, FLAG_CLIENT_ALWAYS_READY_UNPAUSE));

        // Toggle bypass_startup_checksum on & off via set_flag_applied
        set_flag_applied(&dir, FLAG_BYPASS_STARTUP_CHECKSUM, true)?;
        assert!(is_flag_applied(&dir, FLAG_BYPASS_STARTUP_CHECKSUM));
        set_flag_applied(&dir, FLAG_BYPASS_STARTUP_CHECKSUM, false)?;
        assert!(!is_flag_applied(&dir, FLAG_BYPASS_STARTUP_CHECKSUM));

        // Toggle disable_ai_visibility_culling on & off via set_flag_applied
        set_flag_applied(&dir, FLAG_DISABLE_AI_VISIBILITY_CULLING, true)?;
        assert!(is_flag_applied(&dir, FLAG_DISABLE_AI_VISIBILITY_CULLING));
        set_flag_applied(&dir, FLAG_DISABLE_AI_VISIBILITY_CULLING, false)?;
        assert!(!is_flag_applied(&dir, FLAG_DISABLE_AI_VISIBILITY_CULLING));

        // Sync flag enabled/disabled via sync_all_flags
        let mut states = default_flag_states();
        states[0].enabled = true;
        states[1].enabled = true;
        states[2].enabled = true;
        sync_all_flags(&dir, &states)?;
        assert!(is_flag_applied(&dir, FLAG_CLIENT_ALWAYS_READY_UNPAUSE));
        assert!(is_flag_applied(&dir, FLAG_BYPASS_STARTUP_CHECKSUM));
        assert!(is_flag_applied(&dir, FLAG_DISABLE_AI_VISIBILITY_CULLING));

        states[0].enabled = false;
        states[1].enabled = false;
        states[2].enabled = false;
        sync_all_flags(&dir, &states)?;
        assert!(!is_flag_applied(&dir, FLAG_CLIENT_ALWAYS_READY_UNPAUSE));
        assert!(!is_flag_applied(&dir, FLAG_BYPASS_STARTUP_CHECKSUM));
        assert!(!is_flag_applied(&dir, FLAG_DISABLE_AI_VISIBILITY_CULLING));

        // Real UPK map toggle test if clean 03_Bank.scl is available
        let clean_bank = [
            "../clean_scct_files/Tom Clancy's Splinter Cell Chaos Theory/Data/Maps/03_Bank.scl",
            "../../clean_scct_files/Tom Clancy's Splinter Cell Chaos Theory/Data/Maps/03_Bank.scl",
        ]
        .into_iter()
        .map(std::path::PathBuf::from)
        .find(|p| p.exists());
        if let Some(bank_src) = clean_bank {
            let maps_dir = dir.join("Data").join("Maps");
            std::fs::create_dir_all(&maps_dir)?;
            let sp_bank = maps_dir.join("03_Bank.scl");
            let coop_bank = maps_dir.join("03_Bank_COOP.scl");
            std::fs::copy(&bank_src, &sp_bank)?;
            crate::upk::patch_sp_map_to_coop_with_options(
                &sp_bank,
                &coop_bank,
                (0.0, 0.0, 0.0),
                (-55.0, -65.0, 8.0),
                true,
            )?;
            assert!(!is_flag_applied(&dir, FLAG_SKIP_UPK_PAWN_DETACH));

            set_flag_applied(&dir, FLAG_SKIP_UPK_PAWN_DETACH, true)?;
            assert!(is_flag_applied(&dir, FLAG_SKIP_UPK_PAWN_DETACH));

            set_flag_applied(&dir, FLAG_SKIP_UPK_PAWN_DETACH, false)?;
            assert!(!is_flag_applied(&dir, FLAG_SKIP_UPK_PAWN_DETACH));
        }

        // Enable only camera alarms
        set_flag_applied(&dir, "camera_alarms", true)?;
        assert!(is_flag_applied(&dir, "camera_alarms"));
        assert!(!is_flag_applied(&dir, "nonlethal_gameover"));

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
