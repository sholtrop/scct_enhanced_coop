use anyhow::{Context, Result, bail};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

pub const UPK_MAGIC: u32 = 0x9E2A83C1;
pub const HAVOK_MAGIC: &[u8] = b"\x33\x5a\x0d\xf0";

pub static P2_STRIP_PROPS: &[&str] = &[
    "PatternID",
    "JumpLabel",
    "UnconsciousPatternID",
    "UnconsciousLabel",
    "UnconsciousRevivePoint",
    "UnconsciousTimer",
    "UnconsciousEAIZonesToDisable",
    "ConversationTarget",
    "spotID",
    "nextNavigationPoint",
    "StartMesh",
    "Base",
    "RelativeLocation",
    "RelativeRotation",
];

pub fn read_compact_index(data: &[u8], offset: &mut usize) -> Result<i32> {
    if *offset >= data.len() {
        bail!("Unexpected EOF reading compact index");
    }
    let b0 = data[*offset];
    *offset += 1;
    let neg = (b0 & 0x80) != 0;
    let mut more = (b0 & 0x40) != 0;
    let mut val = (b0 & 0x3F) as i32;
    let mut shift = 6;
    while more {
        if *offset >= data.len() {
            bail!("Unexpected EOF reading compact index continuation");
        }
        let b = data[*offset];
        *offset += 1;
        more = (b & 0x80) != 0;
        val |= ((b & 0x7F) as i32) << shift;
        shift += 7;
    }
    if neg {
        val = -val;
    }
    Ok(val)
}

pub fn write_compact_index(val: i32) -> Vec<u8> {
    let neg = val < 0;
    let mut v = if neg { (-val) as u32 } else { val as u32 };
    let mut out = Vec::new();
    let mut b0 = (if neg { 0x80 } else { 0x00 }) | ((v & 0x3F) as u8);
    v >>= 6;
    if v > 0 {
        b0 |= 0x40;
    }
    out.push(b0);
    while v > 0 {
        let mut b = (v & 0x7F) as u8;
        v >>= 7;
        if v > 0 {
            b |= 0x80;
        }
        out.push(b);
    }
    out
}

pub fn read_fstring(data: &[u8], offset: &mut usize) -> Result<String> {
    let length = read_compact_index(data, offset)?;
    let mut s = if length < 0 {
        let byte_len = (-length * 2) as usize;
        if *offset + byte_len > data.len() {
            bail!("Unexpected EOF reading UTF-16LE FString");
        }
        let slice = &data[*offset..*offset + byte_len];
        let u16s: Vec<u16> = slice
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&chunk| u16::from_le_bytes(chunk))
            .collect();
        let decoded = String::from_utf16_lossy(&u16s);
        *offset += byte_len + 2; // skip null word
        decoded
    } else {
        let byte_len = length as usize;
        if *offset + byte_len > data.len() {
            bail!("Unexpected EOF reading Latin1 FString");
        }
        let slice = &data[*offset..*offset + byte_len];
        let decoded: String = slice.iter().map(|&b| b as char).collect();
        *offset += byte_len + 1; // skip null byte
        decoded
    };
    if s.ends_with('\0') {
        s.pop();
    }
    Ok(s)
}

pub fn write_fstring(s: &str) -> Vec<u8> {
    let raw: Vec<u8> = s.chars().map(|c| (c as u32 & 0xFF) as u8).collect();
    let mut out = write_compact_index(raw.len() as i32);
    out.extend_from_slice(&raw);
    out.push(0x00);
    out
}

pub fn serialize_bool_property(name_idx: i32, value: bool) -> Vec<u8> {
    let info = 3 | (if value { 0x80 } else { 0x00 });
    let mut out = write_compact_index(name_idx);
    out.push(info);
    out
}

pub fn serialize_int_property(name_idx: i32, value: i32) -> Vec<u8> {
    let info = 2 | (2 << 4);
    let mut out = write_compact_index(name_idx);
    out.push(info);
    out.extend_from_slice(&value.to_le_bytes());
    out
}

pub fn serialize_object_property(name_idx: i32, obj_ref: i32) -> Vec<u8> {
    let val_bytes = write_compact_index(obj_ref);
    let (size_code, size_bytes): (u8, Vec<u8>) = match val_bytes.len() {
        1 => (0, Vec::new()),
        2 => (1, Vec::new()),
        4 => (2, Vec::new()),
        len => (5, vec![len as u8]),
    };
    let info = 5 | (size_code << 4);
    let mut out = write_compact_index(name_idx);
    out.push(info);
    out.extend_from_slice(&size_bytes);
    out.extend_from_slice(&val_bytes);
    out
}

#[derive(Debug, Clone)]
pub struct ImportEntry {
    pub class_pkg: i32,
    pub class_name: i32,
    pub package_index: i32,
    pub obj_name: i32,
}

#[derive(Debug, Clone)]
pub struct ExportEntry {
    pub index: usize,
    pub class_idx: i32,
    pub super_idx: i32,
    pub package_index: i32,
    pub obj_name: i32,
    pub obj_flags: u32,
    pub serial_size: i32,
    pub serial_offset: i32,
}

#[derive(Debug, Clone)]
pub struct UpkTables {
    #[allow(dead_code)]
    pub version: u16,
    #[allow(dead_code)]
    pub lic_mode: u16,
    pub name_count: usize,
    pub name_offset: usize,
    pub names_end: usize,
    pub names: Vec<(String, u32)>,
    pub import_count: usize,
    pub import_offset: usize,
    pub imports_end: usize,
    pub imports: Vec<ImportEntry>,
    #[allow(dead_code)]
    pub export_count: usize,
    #[allow(dead_code)]
    pub export_offset: usize,
    pub exports_end: usize,
    pub exports: Vec<ExportEntry>,
}

pub fn parse_upk_tables(data: &[u8]) -> Result<UpkTables> {
    if data.len() < 0x28 {
        bail!("UPK file too small");
    }
    let magic = u32::from_le_bytes(data[0..4].try_into()?);
    if magic != UPK_MAGIC {
        bail!("Invalid UPK magic: 0x{:08X}", magic);
    }
    let version = u16::from_le_bytes(data[4..6].try_into()?);
    let lic_mode = u16::from_le_bytes(data[6..8].try_into()?);

    let name_count = u32::from_le_bytes(data[0x10..0x14].try_into()?) as usize;
    let name_offset = u32::from_le_bytes(data[0x14..0x18].try_into()?) as usize;
    let export_count = u32::from_le_bytes(data[0x18..0x1C].try_into()?) as usize;
    let export_offset = u32::from_le_bytes(data[0x1C..0x20].try_into()?) as usize;
    let import_count = u32::from_le_bytes(data[0x20..0x24].try_into()?) as usize;
    let import_offset = u32::from_le_bytes(data[0x24..0x28].try_into()?) as usize;

    let mut names = Vec::with_capacity(name_count);
    let mut off = name_offset;
    for _ in 0..name_count {
        let s = read_fstring(data, &mut off)?;
        let fl = u32::from_le_bytes(data[off..off + 4].try_into()?);
        off += 4;
        names.push((s, fl));
    }
    let names_end = off;

    let mut imports = Vec::with_capacity(import_count);
    off = import_offset;
    for _ in 0..import_count {
        let class_pkg = read_compact_index(data, &mut off)?;
        let class_name = read_compact_index(data, &mut off)?;
        let pkg_idx = i32::from_le_bytes(data[off..off + 4].try_into()?);
        off += 4;
        let obj_name = read_compact_index(data, &mut off)?;
        imports.push(ImportEntry {
            class_pkg,
            class_name,
            package_index: pkg_idx,
            obj_name,
        });
    }
    let imports_end = off;

    let mut exports = Vec::with_capacity(export_count);
    off = export_offset;
    for i in 0..export_count {
        let class_idx = read_compact_index(data, &mut off)?;
        let super_idx = read_compact_index(data, &mut off)?;
        let pkg_idx = i32::from_le_bytes(data[off..off + 4].try_into()?);
        off += 4;
        let obj_name = read_compact_index(data, &mut off)?;
        let obj_flags = u32::from_le_bytes(data[off..off + 4].try_into()?);
        off += 4;
        let serial_size = read_compact_index(data, &mut off)?;
        let serial_offset = if serial_size > 0 {
            read_compact_index(data, &mut off)?
        } else {
            0
        };
        exports.push(ExportEntry {
            index: i + 1,
            class_idx,
            super_idx,
            package_index: pkg_idx,
            obj_name,
            obj_flags,
            serial_size,
            serial_offset,
        });
    }
    let exports_end = off;

    Ok(UpkTables {
        version,
        lic_mode,
        name_count,
        name_offset,
        names_end,
        names,
        import_count,
        import_offset,
        imports_end,
        imports,
        export_count,
        export_offset,
        exports_end,
        exports,
    })
}

pub fn resolve_class_name(
    names: &[(String, u32)],
    imports: &[ImportEntry],
    exports: &[ExportEntry],
    class_idx: i32,
) -> String {
    if class_idx == 0 {
        return "Class".to_string();
    }
    if class_idx < 0 {
        let idx = (-class_idx - 1) as usize;
        if idx < imports.len() {
            let imp = &imports[idx];
            if (imp.obj_name as usize) < names.len() {
                return names[imp.obj_name as usize].0.clone();
            }
        }
        return "UnknownImport".to_string();
    }
    let idx = (class_idx - 1) as usize;
    if idx < exports.len() {
        let exp = &exports[idx];
        if (exp.obj_name as usize) < names.len() {
            return names[exp.obj_name as usize].0.clone();
        }
    }
    "UnknownExport".to_string()
}

pub fn parse_state_frame_end(data: &[u8], offset: usize) -> Result<usize> {
    let mut off = offset;
    let node = read_compact_index(data, &mut off)?;
    let _state_node = read_compact_index(data, &mut off)?;
    off += 12;
    if node != 0 {
        let _state_offset = read_compact_index(data, &mut off)?;
    }
    Ok(off)
}

#[derive(Debug, Clone)]
pub struct RawProperty {
    pub name: String,
    #[allow(dead_code)]
    pub name_idx: i32,
    #[allow(dead_code)]
    pub ptype: u8,
    #[allow(dead_code)]
    pub struct_name: Option<String>,
    #[allow(dead_code)]
    pub prop_start: usize,
    #[allow(dead_code)]
    pub val_end: usize,
    pub raw_full: Vec<u8>,
    pub raw_header: Vec<u8>,
    pub raw_val: Vec<u8>,
}

pub fn parse_tagged_properties_raw(
    names: &[(String, u32)],
    data: &[u8],
    offset: usize,
    end_offset: usize,
) -> Result<(Vec<RawProperty>, usize, usize)> {
    let mut props = Vec::new();
    let mut off = offset;
    while off < end_offset {
        let prop_start = off;
        let name_idx = read_compact_index(data, &mut off)?;
        if (name_idx as usize) >= names.len() {
            bail!("Name index {} out of range", name_idx);
        }
        let prop_name = &names[name_idx as usize].0;
        if prop_name == "None" {
            return Ok((props, prop_start, off));
        }

        if off >= data.len() {
            bail!("Truncated property info byte");
        }
        let info = data[off];
        off += 1;
        let ptype = info & 0x0F;
        let psize_code = (info >> 4) & 0x07;
        let array_flag = (info >> 7) & 0x01;

        let mut struct_name = None;
        if ptype == 10 {
            let s_idx = read_compact_index(data, &mut off)?;
            if (s_idx as usize) < names.len() {
                struct_name = Some(names[s_idx as usize].0.clone());
            }
        }

        let size: usize = match psize_code {
            0 => 1,
            1 => 2,
            2 => 4,
            3 => 12,
            4 => 16,
            5 => {
                let s = data[off] as usize;
                off += 1;
                s
            }
            6 => {
                let s = u16::from_le_bytes(data[off..off + 2].try_into()?) as usize;
                off += 2;
                s
            }
            _ => {
                let s = u32::from_le_bytes(data[off..off + 4].try_into()?) as usize;
                off += 4;
                s
            }
        };

        if array_flag != 0 && ptype != 3 {
            let b0 = data[off];
            if (b0 & 0x80) == 0 {
                off += 1;
            } else if (b0 & 0xC0) == 0x80 {
                off += 2;
            } else {
                off += 4;
            }
        }

        let val_start = off;
        if ptype != 3 {
            off += size;
        }
        let val_end = off;

        props.push(RawProperty {
            name: prop_name.clone(),
            name_idx,
            ptype,
            struct_name,
            prop_start,
            val_end,
            raw_full: data[prop_start..val_end].to_vec(),
            raw_header: data[prop_start..val_start].to_vec(),
            raw_val: data[val_start..val_end].to_vec(),
        });
    }
    bail!("Reached end_offset without finding None terminator");
}

#[derive(Debug, Clone)]
pub struct MapPatchSummary {
    pub size: usize,
    #[allow(dead_code)]
    pub p1_name: String,
    #[allow(dead_code)]
    pub p2_name: String,
    pub p1_loc: (f32, f32, f32),
    pub p2_loc: (f32, f32, f32),
    #[allow(dead_code)]
    pub havok_offset: usize,
    pub detached_speakers: Vec<String>,
}

#[allow(dead_code)]
pub fn patch_sp_map_to_coop(
    input_path: &Path,
    output_path: &Path,
    p1_offset: (f32, f32, f32),
    spawn_offset: (f32, f32, f32),
) -> Result<MapPatchSummary> {
    patch_sp_map_to_coop_with_options(input_path, output_path, p1_offset, spawn_offset, true)
}

struct SpeakerZoneMatch {
    oname: String,
    cname: String,
    exp_start: usize,
    prop_start: usize,
    first_none: usize,
    exp_end: usize,
    props: Vec<RawProperty>,
}

fn inspect_speaker_pawn_with_zone(
    data: &[u8],
    names: &[(String, u32)],
    imports: &[ImportEntry],
    exports: &[ExportEntry],
    e: &ExportEntry,
) -> Option<SpeakerZoneMatch> {
    if e.serial_size <= 0 {
        return None;
    }
    let oname = &names[e.obj_name as usize].0;
    let cname = resolve_class_name(names, imports, exports, e.class_idx);

    let is_lambert_class = cname.eq_ignore_ascii_case("ELambert");
    let is_lambert_name = oname.to_ascii_lowercase().starts_with("elambert");
    let is_candidate = is_lambert_class
        || is_lambert_name
        || cname.eq_ignore_ascii_case("EAIGenericNPC")
        || cname.to_ascii_lowercase().contains("pawn");

    if !is_candidate {
        return None;
    }

    let exp_start = e.serial_offset as usize;
    let exp_end = exp_start + (e.serial_size as usize);
    if exp_end > data.len() {
        return None;
    }

    let prop_start = parse_state_frame_end(data, exp_start).ok()?;
    let (props, first_none, _) =
        parse_tagged_properties_raw(names, data, prop_start, exp_end).ok()?;

    if !props.iter().any(|p| p.name == "CurrentEAIZone") {
        return None;
    }

    let mut is_speaker = is_lambert_class || is_lambert_name;
    if !is_speaker {
        for p in &props {
            if p.name == "Tag" && p.ptype == 6 && !p.raw_val.is_empty() {
                let mut tag_off = 0;
                if let Ok(tag_name_idx) = read_compact_index(&p.raw_val, &mut tag_off)
                    && (tag_name_idx as usize) < names.len()
                {
                    let tag_str = &names[tag_name_idx as usize].0;
                    if tag_str.eq_ignore_ascii_case("lambert")
                        || tag_str.eq_ignore_ascii_case("elambert")
                        || tag_str.eq_ignore_ascii_case("hq")
                        || tag_str.eq_ignore_ascii_case("headquarters")
                        || tag_str.eq_ignore_ascii_case("grim")
                        || tag_str.eq_ignore_ascii_case("redding")
                    {
                        is_speaker = true;
                        break;
                    }
                }
            }
        }
        if oname.eq_ignore_ascii_case("EAIGenericNPC20")
            || oname.eq_ignore_ascii_case("EAIGenericNPC29")
            || oname.eq_ignore_ascii_case("EAIGenericNPC43")
        {
            is_speaker = true;
        }
    }

    if !is_speaker {
        return None;
    }

    Some(SpeakerZoneMatch {
        oname: oname.clone(),
        cname,
        exp_start,
        prop_start,
        first_none,
        exp_end,
        props,
    })
}

/// Returns `true` if the given `.scl` map still has any HQ/speaker pawn with `CurrentEAIZone`.
pub fn map_has_attached_speaker_pawns(map_path: &Path) -> Result<bool> {
    let data =
        fs::read(map_path).with_context(|| format!("Reading map {}", map_path.display()))?;
    let upk = parse_upk_tables(&data)?;
    Ok(upk.exports.iter().any(|e| {
        inspect_speaker_pawn_with_zone(&data, &upk.names, &upk.imports, &upk.exports, e).is_some()
    }))
}

pub fn patch_sp_map_to_coop_with_options(
    input_path: &Path,
    output_path: &Path,
    p1_offset: (f32, f32, f32),
    spawn_offset: (f32, f32, f32),
    detach_speakers: bool,
) -> Result<MapPatchSummary> {
    let orig_data =
        fs::read(input_path).with_context(|| format!("Reading map {}", input_path.display()))?;

    let upk = parse_upk_tables(&orig_data)?;
    let mut names = upk.names.clone();
    let mut imports = upk.imports.clone();
    let mut exports = upk.exports.clone();

    let mut name_to_idx: HashMap<String, usize> = names
        .iter()
        .enumerate()
        .map(|(i, (n, _))| (n.clone(), i))
        .collect();

    let none_idx = *name_to_idx
        .get("None")
        .context("Missing 'None' in Name Table")?;
    let none_ci = write_compact_index(none_idx as i32);

    fn ensure_name(
        names: &mut Vec<(String, u32)>,
        name_to_idx: &mut HashMap<String, usize>,
        name_str: &str,
        flags: u32,
    ) -> i32 {
        if let Some(&idx) = name_to_idx.get(name_str) {
            return idx as i32;
        }
        let idx = names.len();
        names.push((name_str.to_string(), flags));
        name_to_idx.insert(name_str.to_string(), idx);
        idx as i32
    }

    let idx_b_multiplayer_map =
        ensure_name(&mut names, &mut name_to_idx, "bMultiplayerMap", 0x00070010);
    let idx_use_default_sound_map = ensure_name(
        &mut names,
        &mut name_to_idx,
        "UseDefaultSoundMap",
        0x00070010,
    );
    let idx_sam_mesh = ensure_name(&mut names, &mut name_to_idx, "SamMesh", 0x00070010);
    let idx_start_mesh = ensure_name(&mut names, &mut name_to_idx, "StartMesh", 0x00070010);
    let idx_coop_player = ensure_name(&mut names, &mut name_to_idx, "COOP_Player", 0x00070010);
    let idx_coop_anims = ensure_name(&mut names, &mut name_to_idx, "CoopAnims", 0x00070010);
    let idx_spot_id = ensure_name(&mut names, &mut name_to_idx, "spotID", 0x00070010);
    let idx_next_navigation_point = ensure_name(
        &mut names,
        &mut name_to_idx,
        "nextNavigationPoint",
        0x00070010,
    );

    let existing_export_names: HashSet<String> = exports
        .iter()
        .map(|e| names[e.obj_name as usize].0.clone())
        .collect();

    let mut p2_obj_name = "EchelonPlayerStartCoop".to_string();
    let mut suffix = 2;
    while existing_export_names.contains(&p2_obj_name) {
        p2_obj_name = format!("EchelonPlayerStartCoop{}", suffix);
        suffix += 1;
    }
    let idx_p2_obj_name = ensure_name(&mut names, &mut name_to_idx, &p2_obj_name, 0x00070010);

    let idx_core = *name_to_idx
        .get("Core")
        .context("Missing 'Core' in Name Table")? as i32;
    let idx_engine = *name_to_idx
        .get("Engine")
        .context("Missing 'Engine' in Name Table")? as i32;
    let idx_package = *name_to_idx
        .get("Package")
        .context("Missing 'Package' in Name Table")? as i32;
    let idx_skeletal_mesh = *name_to_idx
        .get("SkeletalMesh")
        .context("Missing 'SkeletalMesh' in Name Table")? as i32;

    imports.push(ImportEntry {
        class_pkg: idx_core,
        class_name: idx_package,
        package_index: 0,
        obj_name: idx_coop_anims,
    });
    let coop_anims_pkg_ref = -(imports.len() as i32);

    imports.push(ImportEntry {
        class_pkg: idx_engine,
        class_name: idx_skeletal_mesh,
        package_index: coop_anims_pkg_ref,
        obj_name: idx_coop_player,
    });
    let coop_player_mesh_ref = -(imports.len() as i32);

    let mut levelinfo_pos = None;
    let mut pstart1_pos = None;
    let mut mylevel_pos = None;

    for (pos, e) in exports.iter().enumerate() {
        let oname = &names[e.obj_name as usize].0;
        let cname = resolve_class_name(&names, &imports, &exports, e.class_idx);
        if levelinfo_pos.is_none() && (cname == "EchelonLevelInfo" || oname == "LevelInfo0") {
            levelinfo_pos = Some(pos);
        } else if pstart1_pos.is_none() && cname == "EchelonPlayerStart" {
            pstart1_pos = Some(pos);
        } else if mylevel_pos.is_none() && oname == "MyLevel" && cname == "Level" {
            mylevel_pos = Some(pos);
        }
    }

    let li_idx = levelinfo_pos.context("Missing LevelInfo in UPK")?;
    let ps1_idx = pstart1_pos.context("Missing EchelonPlayerStart in UPK")?;
    let ml_idx = mylevel_pos.context("Missing MyLevel in UPK")?;

    let new_pstart2_exp_idx = (exports.len() + 1) as i32;

    // 1. Patch LevelInfo0
    let li_start = exports[li_idx].serial_offset as usize;
    let li_end = li_start + (exports[li_idx].serial_size as usize);
    if &orig_data[li_end - none_ci.len()..li_end] != none_ci.as_slice() {
        bail!(
            "{}: LevelInfo0 does not end with expected None CompactIndex",
            input_path.display()
        );
    }
    let li_prop_start = parse_state_frame_end(&orig_data, li_start)?;
    let (li_head_props, li_first_none, _) =
        parse_tagged_properties_raw(&names, &orig_data, li_prop_start, li_end)?;
    let mut filtered_li_head = Vec::new();
    let mut has_use_default_sound_map = false;
    for p in &li_head_props {
        if p.name == "UseDefaultSoundMap" {
            has_use_default_sound_map = true;
        }
        if p.name != "SamMesh" && p.name != "bMultiplayerMap" {
            filtered_li_head.extend_from_slice(&p.raw_full);
        }
    }
    let mut li_coop_props = serialize_bool_property(idx_b_multiplayer_map, true);
    if !has_use_default_sound_map {
        // Penthouse (and any map missing it) needs UseDefaultSoundMap = False so
        // SoundMapName is not overwritten to <Map>_COOP, which DareAudio cannot find in MAPS.SM0.
        li_coop_props.extend_from_slice(&serialize_bool_property(idx_use_default_sound_map, false));
    }
    li_coop_props.extend_from_slice(&serialize_object_property(
        idx_sam_mesh,
        coop_player_mesh_ref,
    ));

    let mut patched_levelinfo_bytes = Vec::new();
    patched_levelinfo_bytes.extend_from_slice(&orig_data[li_start..li_prop_start]);
    patched_levelinfo_bytes.extend_from_slice(&li_coop_props);
    patched_levelinfo_bytes.extend_from_slice(&filtered_li_head);
    patched_levelinfo_bytes.extend_from_slice(&orig_data[li_first_none..li_end]);

    // 2. Patch Player 1's EchelonPlayerStart
    let ps1_start = exports[ps1_idx].serial_offset as usize;
    let ps1_end = ps1_start + (exports[ps1_idx].serial_size as usize);
    let ps1_prop_start = parse_state_frame_end(&orig_data, ps1_start)?;
    let ps1_state_frame = &orig_data[ps1_start..ps1_prop_start];
    let (ps1_props, _ps1_none_off, ps1_after_none) =
        parse_tagged_properties_raw(&names, &orig_data, ps1_prop_start, ps1_end)?;
    if ps1_after_none != ps1_end {
        bail!(
            "{}: EchelonPlayerStart has unexpected trailing bytes",
            input_path.display()
        );
    }

    let mut ps1_kept = Vec::new();
    for p in &ps1_props {
        if p.name != "StartMesh" && p.name != "nextNavigationPoint" && p.name != "spotID" {
            if p.name == "Location" && p.raw_val.len() == 12 && p1_offset != (0.0, 0.0, 0.0) {
                let x = f32::from_le_bytes(p.raw_val[0..4].try_into()?);
                let y = f32::from_le_bytes(p.raw_val[4..8].try_into()?);
                let z = f32::from_le_bytes(p.raw_val[8..12].try_into()?);
                let target_p1 = (x + p1_offset.0, y + p1_offset.1, z + p1_offset.2);
                ps1_kept.extend_from_slice(&p.raw_header);
                ps1_kept.extend_from_slice(&target_p1.0.to_le_bytes());
                ps1_kept.extend_from_slice(&target_p1.1.to_le_bytes());
                ps1_kept.extend_from_slice(&target_p1.2.to_le_bytes());
            } else {
                ps1_kept.extend_from_slice(&p.raw_full);
            }
        }
    }
    let mut ps1_extra = serialize_object_property(idx_next_navigation_point, new_pstart2_exp_idx);
    ps1_extra.extend_from_slice(&serialize_object_property(
        idx_start_mesh,
        coop_player_mesh_ref,
    ));

    let mut patched_ps1_bytes = Vec::new();
    patched_ps1_bytes.extend_from_slice(ps1_state_frame);
    patched_ps1_bytes.extend_from_slice(&ps1_kept);
    patched_ps1_bytes.extend_from_slice(&ps1_extra);
    patched_ps1_bytes.extend_from_slice(&none_ci);

    // 3. Build Player 2's EchelonPlayerStartCoop
    let mut ps2_chunks = serialize_int_property(idx_spot_id, 2);
    ps2_chunks.extend_from_slice(&serialize_object_property(
        idx_start_mesh,
        coop_player_mesh_ref,
    ));

    let p2_strip_set: HashSet<&str> = P2_STRIP_PROPS.iter().copied().collect();
    let mut p1_loc: Option<(f32, f32, f32)> = None;
    let mut p2_loc: Option<(f32, f32, f32)> = None;

    for p in &ps1_props {
        if p2_strip_set.contains(p.name.as_str()) {
            continue;
        }
        if p.name == "Location" && p.raw_val.len() == 12 {
            let x = f32::from_le_bytes(p.raw_val[0..4].try_into()?);
            let y = f32::from_le_bytes(p.raw_val[4..8].try_into()?);
            let z = f32::from_le_bytes(p.raw_val[8..12].try_into()?);
            let final_p1 = if p1_offset != (0.0, 0.0, 0.0) {
                (x + p1_offset.0, y + p1_offset.1, z + p1_offset.2)
            } else {
                (x, y, z)
            };
            p1_loc = Some(final_p1);
            let target_p2 = (x + spawn_offset.0, y + spawn_offset.1, z + spawn_offset.2);
            p2_loc = Some(target_p2);

            ps2_chunks.extend_from_slice(&p.raw_header);
            ps2_chunks.extend_from_slice(&target_p2.0.to_le_bytes());
            ps2_chunks.extend_from_slice(&target_p2.1.to_le_bytes());
            ps2_chunks.extend_from_slice(&target_p2.2.to_le_bytes());
        } else {
            ps2_chunks.extend_from_slice(&p.raw_full);
        }
    }
    let p1_loc = p1_loc.context("Player 1 EchelonPlayerStart has no Location")?;
    let p2_loc = p2_loc.unwrap();

    let mut patched_ps2_bytes = Vec::new();
    patched_ps2_bytes.extend_from_slice(ps1_state_frame);
    patched_ps2_bytes.extend_from_slice(&ps2_chunks);
    patched_ps2_bytes.extend_from_slice(&none_ci);

    // 4. Patch MyLevel
    let ml_start = exports[ml_idx].serial_offset as usize;
    let ml_end = ml_start + (exports[ml_idx].serial_size as usize);
    let ml_raw = &orig_data[ml_start..ml_end];

    if ml_raw.len() < none_ci.len() || &ml_raw[..none_ci.len()] != none_ci.as_slice() {
        bail!(
            "{}: MyLevel does not begin with None CompactIndex",
            input_path.display()
        );
    }
    let arr_hdr_off = none_ci.len();
    let db_num = i32::from_le_bytes(ml_raw[arr_hdr_off..arr_hdr_off + 4].try_into()?);
    let db_max = i32::from_le_bytes(ml_raw[arr_hdr_off + 4..arr_hdr_off + 8].try_into()?);
    if db_num != db_max {
        bail!(
            "{}: MyLevel db_num={} != db_max={}",
            input_path.display(),
            db_num,
            db_max
        );
    }

    let mut off = arr_hdr_off + 8;
    let mut insert_pos_in_ml = None;
    let pstart1_exp_index = exports[ps1_idx].index as i32;

    for _ in 0..db_num {
        let actor_ref = read_compact_index(ml_raw, &mut off)?;
        if actor_ref == pstart1_exp_index {
            insert_pos_in_ml = Some(off);
        }
    }
    let insert_pos_in_ml =
        insert_pos_in_ml.context("P1 PlayerStart not found in MyLevel.Actors")?;

    let mut patched_mylevel_bytes = Vec::new();
    patched_mylevel_bytes.extend_from_slice(&none_ci);
    patched_mylevel_bytes.extend_from_slice(&(db_num + 1).to_le_bytes());
    patched_mylevel_bytes.extend_from_slice(&(db_max + 1).to_le_bytes());
    patched_mylevel_bytes.extend_from_slice(&ml_raw[arr_hdr_off + 8..insert_pos_in_ml]);
    patched_mylevel_bytes.extend_from_slice(&write_compact_index(new_pstart2_exp_idx));
    patched_mylevel_bytes.extend_from_slice(&ml_raw[insert_pos_in_ml..]);

    // 5. Detach HQ/Lambert speaker pawns from their AI zones.
    // In retail SP, speaker pawns (Lambert, Grim, Redding) on certain maps (Bank, Displace,
    // CargoShip, Penthouse, Battery, SeoulOne, KokuboSosho) were assigned to off-map dummy
    // HQ zones. In multiplayer, off-map zones never wake up, preventing APawn::PreBeginPlay()
    // from enabling the pawn and spawning its AIController. In maps where radio dialogue
    // worked natively (Lighthouse, Bathhouse, Training, Hokkaido), CurrentEAIZone is None,
    // which triggers immediate controller spawning at startup identically on Host and Guest.
    // Stripping CurrentEAIZone brings all maps to parity cleanly without any binary hacks.
    let mut detached_speakers = Vec::new();
    let mut patched_speakers: Vec<(usize, Vec<u8>)> = Vec::new();

    if detach_speakers {
        for (pos, e) in exports.iter().enumerate() {
            let Some(m) =
                inspect_speaker_pawn_with_zone(&orig_data, &names, &imports, &exports, e)
            else {
                continue;
            };
            let mut patched_bytes = Vec::new();
            patched_bytes.extend_from_slice(&orig_data[m.exp_start..m.prop_start]);
            for p in &m.props {
                if p.name != "CurrentEAIZone" {
                    patched_bytes.extend_from_slice(&p.raw_full);
                }
            }
            patched_bytes.extend_from_slice(&orig_data[m.first_none..m.exp_end]);
            patched_speakers.push((pos, patched_bytes));
            detached_speakers.push(format!("{}({})", m.oname, m.cname));
        }
    }

    // 6. Build output stream
    let mut out_stream = Vec::from(&orig_data[..upk.import_offset]);

    exports[ml_idx].serial_offset = out_stream.len() as i32;
    exports[ml_idx].serial_size = patched_mylevel_bytes.len() as i32;
    out_stream.extend_from_slice(&patched_mylevel_bytes);

    exports[li_idx].serial_offset = out_stream.len() as i32;
    exports[li_idx].serial_size = patched_levelinfo_bytes.len() as i32;
    out_stream.extend_from_slice(&patched_levelinfo_bytes);

    exports[ps1_idx].serial_offset = out_stream.len() as i32;
    exports[ps1_idx].serial_size = patched_ps1_bytes.len() as i32;
    out_stream.extend_from_slice(&patched_ps1_bytes);

    for (spk_pos, spk_bytes) in &patched_speakers {
        exports[*spk_pos].serial_offset = out_stream.len() as i32;
        exports[*spk_pos].serial_size = spk_bytes.len() as i32;
        out_stream.extend_from_slice(spk_bytes);
    }

    let pstart2_exp = ExportEntry {
        index: new_pstart2_exp_idx as usize,
        class_idx: exports[ps1_idx].class_idx,
        super_idx: exports[ps1_idx].super_idx,
        package_index: exports[ps1_idx].package_index,
        obj_name: idx_p2_obj_name,
        obj_flags: exports[ps1_idx].obj_flags,
        serial_size: patched_ps2_bytes.len() as i32,
        serial_offset: out_stream.len() as i32,
    };
    exports.push(pstart2_exp);
    out_stream.extend_from_slice(&patched_ps2_bytes);

    // 6. Serialize Name Table, Import Table, Export Table, Havok Stream
    let new_name_offset = out_stream.len();
    out_stream.extend_from_slice(&orig_data[upk.name_offset..upk.names_end]);
    for (name_str, flags) in &names[upk.name_count..] {
        out_stream.extend_from_slice(&write_fstring(name_str));
        out_stream.extend_from_slice(&flags.to_le_bytes());
    }

    let new_import_offset = out_stream.len();
    out_stream.extend_from_slice(&orig_data[upk.import_offset..upk.imports_end]);
    for imp in &imports[upk.import_count..] {
        out_stream.extend_from_slice(&write_compact_index(imp.class_pkg));
        out_stream.extend_from_slice(&write_compact_index(imp.class_name));
        out_stream.extend_from_slice(&imp.package_index.to_le_bytes());
        out_stream.extend_from_slice(&write_compact_index(imp.obj_name));
    }

    let new_export_offset = out_stream.len();
    for exp in &exports {
        out_stream.extend_from_slice(&write_compact_index(exp.class_idx));
        out_stream.extend_from_slice(&write_compact_index(exp.super_idx));
        out_stream.extend_from_slice(&exp.package_index.to_le_bytes());
        out_stream.extend_from_slice(&write_compact_index(exp.obj_name));
        out_stream.extend_from_slice(&exp.obj_flags.to_le_bytes());
        out_stream.extend_from_slice(&write_compact_index(exp.serial_size));
        if exp.serial_size > 0 {
            out_stream.extend_from_slice(&write_compact_index(exp.serial_offset));
        }
    }
    let new_exports_end = out_stream.len();

    let havok_stream = &orig_data[upk.exports_end..];
    if havok_stream.len() < 4 || &havok_stream[..4] != HAVOK_MAGIC {
        bail!(
            "{}: Unexpected Havok header {:?}",
            input_path.display(),
            &havok_stream[..4]
        );
    }
    out_stream.extend_from_slice(havok_stream);

    // 7. Update UPK header counts and offsets
    out_stream[0x10..0x14].copy_from_slice(&(names.len() as u32).to_le_bytes());
    out_stream[0x14..0x18].copy_from_slice(&(new_name_offset as u32).to_le_bytes());
    out_stream[0x18..0x1C].copy_from_slice(&(exports.len() as u32).to_le_bytes());
    out_stream[0x1C..0x20].copy_from_slice(&(new_export_offset as u32).to_le_bytes());
    out_stream[0x20..0x24].copy_from_slice(&(imports.len() as u32).to_le_bytes());
    out_stream[0x24..0x28].copy_from_slice(&(new_import_offset as u32).to_le_bytes());

    if out_stream.len() >= 0xAD {
        let gen_count = u32::from_le_bytes(out_stream[0xA1..0xA5].try_into()?);
        if gen_count == 1 {
            out_stream[0xA5..0xA9].copy_from_slice(&(exports.len() as u32).to_le_bytes());
            out_stream[0xA9..0xAD].copy_from_slice(&(names.len() as u32).to_le_bytes());
        }
    }

    fs::write(output_path, &out_stream)
        .with_context(|| format!("Writing patched map {}", output_path.display()))?;

    Ok(MapPatchSummary {
        size: out_stream.len(),
        p1_name: names[exports[ps1_idx].obj_name as usize].0.clone(),
        p2_name: p2_obj_name,
        p1_loc,
        p2_loc,
        havok_offset: new_exports_end,
        detached_speakers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_patch_sp_map_detaches_speaker_pawn() {
        let candidates = [
            PathBuf::from("../clean_scct_files/Tom Clancy's Splinter Cell Chaos Theory/Data/Maps/03_Bank.scl"),
            PathBuf::from("../../clean_scct_files/Tom Clancy's Splinter Cell Chaos Theory/Data/Maps/03_Bank.scl"),
        ];
        let bank_src = candidates.into_iter().find(|p| p.exists());
        let Some(bank_src) = bank_src else {
            eprintln!("Skipping test_patch_sp_map_detaches_speaker_pawn (clean 03_Bank.scl not found)");
            return;
        };

        let temp_dir = std::env::temp_dir().join(format!("scct_upk_test_{}", std::process::id()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let out_map = temp_dir.join("03_Bank_COOP.scl");

        let summary = patch_sp_map_to_coop(
            &bank_src,
            &out_map,
            (0.0, 0.0, 0.0),
            (-55.0, -65.0, 8.0),
        )
        .expect("patch_sp_map_to_coop failed");

        assert!(
            summary
                .detached_speakers
                .iter()
                .any(|s| s.contains("EAIGenericNPC20")),
            "Expected EAIGenericNPC20 to be detached, got: {:?}",
            summary.detached_speakers
        );

        let patched_data = std::fs::read(&out_map).expect("read patched map");
        let upk = parse_upk_tables(&patched_data).expect("parse upk tables");

        // Verify EAIGenericNPC20 has NO CurrentEAIZone in patched map
        let mut found_speaker = false;
        for exp in &upk.exports {
            let oname = &upk.names[exp.obj_name as usize].0;
            if oname == "EAIGenericNPC20" {
                found_speaker = true;
                let exp_start = exp.serial_offset as usize;
                let exp_end = exp_start + (exp.serial_size as usize);
                let prop_start = parse_state_frame_end(&patched_data, exp_start).expect("parse state frame");
                let (props, _, _) = parse_tagged_properties_raw(&upk.names, &patched_data, prop_start, exp_end)
                    .expect("parse properties");

                assert!(
                    !props.iter().any(|p| p.name == "CurrentEAIZone"),
                    "CurrentEAIZone must be stripped from EAIGenericNPC20"
                );
                assert!(
                    props.iter().any(|p| p.name == "Tag"),
                    "Tag property should be preserved"
                );
                assert!(
                    props.iter().any(|p| p.name == "Location"),
                    "Location property should be preserved"
                );
            }
        }
        assert!(found_speaker, "EAIGenericNPC20 not found in exports");

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_patch_sp_map_preserves_speaker_pawn_when_detach_disabled() {
        let candidates = [
            PathBuf::from("../clean_scct_files/Tom Clancy's Splinter Cell Chaos Theory/Data/Maps/03_Bank.scl"),
            PathBuf::from("../../clean_scct_files/Tom Clancy's Splinter Cell Chaos Theory/Data/Maps/03_Bank.scl"),
        ];
        let bank_src = candidates.into_iter().find(|p| p.exists());
        let Some(bank_src) = bank_src else {
            eprintln!("Skipping test_patch_sp_map_preserves_speaker_pawn_when_detach_disabled (clean 03_Bank.scl not found)");
            return;
        };

        let temp_dir =
            std::env::temp_dir().join(format!("scct_upk_keep_zone_test_{}", std::process::id()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let kept_map = temp_dir.join("03_Bank_COOP_keep.scl");
        let detached_map = temp_dir.join("03_Bank_COOP_detach.scl");

        let summary_keep = patch_sp_map_to_coop_with_options(
            &bank_src,
            &kept_map,
            (0.0, 0.0, 0.0),
            (-55.0, -65.0, 8.0),
            false,
        )
        .expect("patch_sp_map_to_coop_with_options(false) failed");
        assert!(summary_keep.detached_speakers.is_empty());
        assert!(map_has_attached_speaker_pawns(&kept_map).unwrap());

        let summary_detach = patch_sp_map_to_coop_with_options(
            &bank_src,
            &detached_map,
            (0.0, 0.0, 0.0),
            (-55.0, -65.0, 8.0),
            true,
        )
        .expect("patch_sp_map_to_coop_with_options(true) failed");
        assert!(!summary_detach.detached_speakers.is_empty());
        assert!(!map_has_attached_speaker_pawns(&detached_map).unwrap());

        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
