use anyhow::{bail, Result};
use regex::Regex;
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::Path;

use crate::levels::{LevelSpec, DEFAULT_COOP_EMISSION_MANAGER, DEFAULT_COOP_LOADOUTS, LANG_EXTS};

pub const UMD_MAGIC: u32 = 0x40FD_724D;
pub const UMD_VERSION: u32 = 1;

#[derive(Debug, Clone)]
pub struct UmdFooter {
    pub tag: u32,
    pub toc_offset: u32,
    pub total_size: u32,
    pub version: u32,
    pub magic: u32,
}

#[derive(Debug, Clone)]
pub struct UmdEntry {
    pub raw_name: Vec<u8>,
    pub path: String,
    pub offset: usize,
    pub size: usize,
    pub flags: u32,
}

#[derive(Debug, Clone)]
pub struct ExtractedLevelInfo {
    pub spec: LevelSpec,
    pub canonical_src: String,
    pub src_ini: Vec<u8>,
    pub loading_dds: HashMap<u8, Vec<u8>>,
}

pub fn parse_umd_archive(data: &[u8]) -> Result<(UmdFooter, Vec<UmdEntry>, HashMap<String, usize>)> {
    if data.len() < 20 {
        bail!("UMD file too small ({} bytes)", data.len());
    }
    let footer_start = data.len() - 20;
    let tag = u32::from_le_bytes(data[footer_start..footer_start + 4].try_into()?);
    let toc_offset = u32::from_le_bytes(data[footer_start + 4..footer_start + 8].try_into()?);
    let total_size = u32::from_le_bytes(data[footer_start + 8..footer_start + 12].try_into()?);
    let version = u32::from_le_bytes(data[footer_start + 12..footer_start + 16].try_into()?);
    let magic = u32::from_le_bytes(data[footer_start + 16..footer_start + 20].try_into()?);

    if magic != UMD_MAGIC || version != UMD_VERSION {
        bail!(
            "Invalid UMD footer: magic=0x{:08X}, version={}",
            magic,
            version
        );
    }
    if total_size as usize != data.len() {
        bail!(
            "UMD total_size ({}) != file size ({})",
            total_size,
            data.len()
        );
    }

    let mut pos = toc_offset as usize;
    let count = crate::upk::read_compact_index(data, &mut pos)?;
    let mut entries = Vec::with_capacity(count as usize);
    let mut index_by_lower = HashMap::new();

    for idx in 0..count {
        let name_len = crate::upk::read_compact_index(data, &mut pos)? as usize;
        if pos + name_len > data.len() {
            bail!("UMD entry name extends past EOF");
        }
        let raw_name = data[pos..pos + name_len].to_vec();
        pos += name_len;
        let trimmed_name = if raw_name.ends_with(&[0]) {
            &raw_name[..raw_name.len() - 1]
        } else {
            &raw_name[..]
        };
        let path_str: String = trimmed_name.iter().map(|&b| b as char).collect();

        if pos + 12 > data.len() {
            bail!("UMD entry header extends past EOF");
        }
        let file_off = u32::from_le_bytes(data[pos..pos + 4].try_into()?) as usize;
        let file_size = u32::from_le_bytes(data[pos + 4..pos + 8].try_into()?) as usize;
        let flags = u32::from_le_bytes(data[pos + 8..pos + 12].try_into()?);
        pos += 12;

        index_by_lower.insert(path_str.to_lowercase(), idx as usize);
        entries.push(UmdEntry {
            raw_name,
            path: path_str,
            offset: file_off,
            size: file_size,
            flags,
        });
    }

    if pos != data.len() - 20 {
        bail!("UMD TOC did not end cleanly at 20-byte footer");
    }

    let footer = UmdFooter {
        tag,
        toc_offset,
        total_size,
        version,
        magic,
    };
    Ok((footer, entries, index_by_lower))
}

pub fn serialize_umd_toc_and_footer(
    payload: &mut Vec<u8>,
    entries: &[UmdEntry],
    tag: u32,
) {
    let new_toc_offset = payload.len() as u32;
    payload.extend_from_slice(&crate::upk::write_compact_index(entries.len() as i32));
    for ent in entries {
        payload.extend_from_slice(&crate::upk::write_compact_index(ent.raw_name.len() as i32));
        payload.extend_from_slice(&ent.raw_name);
        payload.extend_from_slice(&(ent.offset as u32).to_le_bytes());
        payload.extend_from_slice(&(ent.size as u32).to_le_bytes());
        payload.extend_from_slice(&ent.flags.to_le_bytes());
    }
    let new_total_size = (payload.len() + 20) as u32;
    payload.extend_from_slice(&tag.to_le_bytes());
    payload.extend_from_slice(&new_toc_offset.to_le_bytes());
    payload.extend_from_slice(&new_total_size.to_le_bytes());
    payload.extend_from_slice(&UMD_VERSION.to_le_bytes());
    payload.extend_from_slice(&UMD_MAGIC.to_le_bytes());
}

fn replace_in_place(slice: &mut [u8], target: &[u8], replacement: &[u8]) {
    assert_eq!(target.len(), replacement.len());
    let tlen = target.len();
    let mut i = 0;
    while i + tlen <= slice.len() {
        if &slice[i..i + tlen] == target {
            slice[i..i + tlen].copy_from_slice(replacement);
            i += tlen;
        } else {
            i += 1;
        }
    }
}

pub fn normalize_umd_payload_baseline(
    payload: &mut [u8],
    entries: &[UmdEntry],
    index_by_lower: &HashMap<String, usize>,
) {
    for vpath in &["system\\maprotation.ini", "data\\maps\\00_training_coop.ini"] {
        if let Some(&idx) = index_by_lower.get(*vpath) {
            let ent = &entries[idx];
            let off = ent.offset;
            let size = ent.size;
            if off + size <= payload.len() {
                let slice = &mut payload[off..off + size];
                replace_in_place(slice, b"01_Lighthouse   ", b"00_Training_COOP");
            }
        }
    }

    let fra_path = "data\\system\\localization\\00_training_coop.fra";
    if let Some(&idx) = index_by_lower.get(fra_path) {
        let ent = &entries[idx];
        let off = ent.offset;
        let size = ent.size;
        if off + size <= payload.len() {
            let slice = &mut payload[off..off + size];
            replace_in_place(slice, b"MapName=LIGHTHOUSE       .", b"MapName=ENTRAINEMENT COOP.");
        }
    }
}

pub fn get_ini_key_value(ini_bytes: &[u8], section: &str, key: &str) -> Option<String> {
    let text = String::from_utf8_lossy(ini_bytes);
    let sec_header = format!("[{}]", section).to_lowercase();
    let key_prefix = format!("{}=", key).to_lowercase();

    let mut in_section = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            if trimmed.to_lowercase() == sec_header {
                in_section = true;
            } else if in_section {
                break;
            }
            continue;
        }
        if in_section {
            let trimmed_left = line.trim_start();
            if trimmed_left.to_lowercase().starts_with(&key_prefix) {
                let val = &trimmed_left[key_prefix.len()..];
                return Some(val.trim().to_string());
            }
        }
    }
    None
}

pub fn append_missions_to_map_rotation(
    rot_bytes: &[u8],
    coop_map_names: &[&str],
) -> Vec<u8> {
    let text = rot_bytes.iter().map(|&b| b as char).collect::<String>();

    let idx_re = Regex::new(r"(?im)^MissionCoop\[(\d+)\]\s*=").unwrap();
    let val_re = Regex::new(r#"(?im)^MissionCoop\[\d+\]\s*=\s*"?([^"\r\n]+)"?"#).unwrap();

    let indices: Vec<usize> = idx_re
        .captures_iter(&text)
        .filter_map(|c| c.get(1).and_then(|m| m.as_str().parse::<usize>().ok()))
        .collect();

    let mut existing_values: HashSet<String> = val_re
        .captures_iter(&text)
        .filter_map(|c| c.get(1).map(|m| m.as_str().trim().to_lowercase()))
        .collect();

    let mut next_idx = if indices.is_empty() {
        0
    } else {
        indices.into_iter().max().unwrap() + 1
    };

    let mut lines_to_add = Vec::new();
    for coop_name in coop_map_names {
        if existing_values.contains(&coop_name.to_lowercase()) {
            continue;
        }
        lines_to_add.push(format!("MissionCoop[{}]=\"{}\"", next_idx, coop_name));
        existing_values.insert(coop_name.to_lowercase());
        next_idx += 1;
    }

    if lines_to_add.is_empty() {
        return rot_bytes.to_vec();
    }

    let base = text.trim_end_matches(&['\r', '\n'][..]);
    let combined = format!("{}\r\n{}\r\n", base, lines_to_add.join("\r\n"));
    combined.chars().map(|c| c as u8).collect()
}

pub fn append_loading_screen_sections(
    ls_bytes: &[u8],
    levels: &[LevelSpec],
) -> Vec<u8> {
    let raw_lower = ls_bytes.to_ascii_lowercase();

    let extract_section_lines = |sec_name_lower: &[u8]| -> Vec<Vec<u8>> {
        let mut hdr = Vec::with_capacity(sec_name_lower.len() + 2);
        hdr.push(b'[');
        hdr.extend_from_slice(sec_name_lower);
        hdr.push(b']');

        let idx = match raw_lower
            .windows(hdr.len())
            .position(|window| window == hdr.as_slice())
        {
            Some(i) => i,
            None => return Vec::new(),
        };

        let end = match ls_bytes[idx + 1..]
            .windows(3)
            .position(|w| w == b"\r\n[")
        {
            Some(p) => idx + 1 + p,
            None => ls_bytes.len(),
        };

        let block = &ls_bytes[idx..end];
        let mut lines = Vec::new();
        let mut first = true;
        for line in block.split(|&b| b == b'\n') {
            let mut line = line;
            if line.ends_with(b"\r") {
                line = &line[..line.len() - 1];
            }
            if first {
                first = false;
                continue;
            }
            if !line.is_empty() {
                lines.push(line.to_vec());
            }
        }
        lines
    };

    let coop_tips: Vec<Vec<u8>> = extract_section_lines(b"00_training_coop")
        .into_iter()
        .filter(|ln| ln.to_ascii_lowercase().starts_with(b"tip"))
        .collect();

    let mut appended_blocks: Vec<Vec<u8>> = Vec::new();

    for spec in levels {
        let src_sec = spec.source_map.to_ascii_lowercase();
        let dst_sec = spec.coop_map.to_ascii_lowercase();

        let dst_hdr = format!("[{}]", dst_sec).into_bytes();
        if raw_lower
            .windows(dst_hdr.len())
            .any(|w| w == dst_hdr.as_slice())
        {
            continue;
        }

        let src_lines = extract_section_lines(src_sec.as_bytes());
        let src_meta: Vec<Vec<u8>> = src_lines
            .into_iter()
            .filter(|ln| {
                let low = ln.to_ascii_lowercase();
                low.starts_with(b"location=")
                    || low.starts_with(b"date=")
                    || low.starts_with(b"time=")
                    || low.starts_with(b"overview=")
            })
            .collect();

        let mut block_lines: Vec<Vec<u8>> = Vec::new();
        block_lines.push(dst_hdr);
        block_lines.extend(src_meta);
        block_lines.extend(coop_tips.clone());

        appended_blocks.push(block_lines.join(&b"\r\n"[..]));
    }

    if appended_blocks.is_empty() {
        return ls_bytes.to_vec();
    }

    let mut base_end = ls_bytes.len();
    while base_end > 0 && (ls_bytes[base_end - 1] == b'\r' || ls_bytes[base_end - 1] == b'\n') {
        base_end -= 1;
    }
    let base = &ls_bytes[..base_end];

    let mut result = Vec::with_capacity(base.len() + appended_blocks.len() * 200);
    result.extend_from_slice(base);
    result.extend_from_slice(b"\r\n\r\n");
    for (i, block) in appended_blocks.iter().enumerate() {
        if i > 0 {
            result.extend_from_slice(b"\r\n\r\n");
        }
        result.extend_from_slice(block);
    }
    result.extend_from_slice(b"\r\n");
    result
}

fn remove_sec(s: &str, name: &str) -> String {
    let low = s.to_lowercase();
    let t = format!("[{}]", name).to_lowercase();
    if let Some(idx) = low.find(&t) {
        let rest = &low[idx + t.len()..];
        let end = match rest.find("\n[") {
            Some(n_idx) => {
                let mut e = idx + t.len() + n_idx;
                if e > 0 && s.as_bytes()[e - 1] == b'\r' {
                    e -= 1;
                }
                e
            }
            None => s.len(),
        };
        let mut res = String::with_capacity(s.len());
        res.push_str(&s[..idx]);
        res.push_str(&s[end..]);
        res
    } else {
        s.to_string()
    }
}

fn replace_sec(s: &str, name: &str, repl: &str) -> String {
    let low = s.to_lowercase();
    let t = format!("[{}]", name).to_lowercase();
    if let Some(idx) = low.find(&t) {
        let rest = &low[idx + t.len()..];
        let end = match rest.find("\n[") {
            Some(n_idx) => {
                let mut e = idx + t.len() + n_idx;
                if e > 0 && s.as_bytes()[e - 1] == b'\r' {
                    e -= 1;
                }
                e
            }
            None => s.len(),
        };
        let mut res = String::with_capacity(s.len() + repl.len());
        res.push_str(&s[..idx]);
        res.push_str(repl);
        res.push_str(&s[end..]);
        res
    } else {
        s.to_string()
    }
}

pub fn build_appended_coop_ini(
    src_ini_bytes: &[u8],
    source_map: &str,
    coop_map: &str,
    identity: u8,
) -> Vec<u8> {
    let mut text: String = src_ini_bytes.iter().map(|&b| b as char).collect();

    let re_map = Regex::new(r"(?im)^MapName=.*$").unwrap();
    let re_start = Regex::new(r"(?im)^StartMap=.*$").unwrap();
    let re_ident = Regex::new(r"(?im)^Identity=.*$").unwrap();
    let re_mp = Regex::new(r"(?im)^Multiplayer=.*$").unwrap();
    let re_xbl = Regex::new(r"(?im)^XboxLiveContent=.*$").unwrap();
    let re_loc = Regex::new(r"(?im)^LocalizationFile=.*$").unwrap();
    let re_flag = Regex::new(r"(?im)^Flag=.*\r?\n").unwrap();

    text = re_map.replace_all(&text, format!("MapName={}", coop_map)).to_string();
    text = re_start.replace_all(&text, format!("StartMap={}", coop_map)).to_string();
    text = re_ident.replace_all(&text, format!("Identity={}", identity)).to_string();
    text = re_mp.replace_all(&text, "Multiplayer=true").to_string();
    text = re_xbl.replace_all(&text, "XboxLiveContent=0").to_string();
    text = re_loc.replace_all(&text, format!("LocalizationFile=Localization\\{}", source_map)).to_string();
    text = re_flag.replace_all(&text, "").to_string();

    text = remove_sec(&text, "LOADOUT_STEALTH");
    text = remove_sec(&text, "LOADOUT_ASSAULT");

    if !text.to_uppercase().contains("[LOADOUT_HOST]") {
        let em_replacement = format!(
            "{}\r\n\r\n{}\r\n",
            DEFAULT_COOP_EMISSION_MANAGER.replace('\n', "\r\n").trim_end_matches(&['\r', '\n'][..]),
            DEFAULT_COOP_LOADOUTS.replace('\n', "\r\n").trim_end_matches(&['\r', '\n'][..])
        );
        text = replace_sec(&text, "Echelon.EMissionManager", &em_replacement);
    }

    text = text.replace("\r\n", "\n").replace('\r', "\n").replace('\n', "\r\n");
    if !text.ends_with("\r\n") {
        text.push_str("\r\n");
    }

    text.chars().map(|c| c as u8).collect()
}

pub fn validate_level_specs(
    levels: &[LevelSpec],
    payload: &[u8],
    entries: &[UmdEntry],
    index_by_lower: &HashMap<String, usize>,
) -> Result<()> {
    let mut used_identities: HashMap<u8, String> = HashMap::new();
    let mut used_map_names: HashSet<String> = HashSet::new();

    for ent in entries {
        let vpath = &ent.path;
        let vpath_lower = vpath.to_lowercase();
        if vpath_lower.starts_with("data\\maps\\") && vpath_lower.ends_with(".ini") {
            let off = ent.offset;
            let size = ent.size;
            let ini_bytes = &payload[off..off + size];
            let stem = match vpath.rsplit('\\').next() {
                Some(name) if name.len() > 4 => &name[..name.len() - 4],
                _ => continue,
            };
            used_map_names.insert(stem.to_lowercase());
            if let Some(id_val) = get_ini_key_value(ini_bytes, "General", "Identity")
                .and_then(|s| s.trim().parse::<u8>().ok())
            {
                used_identities.insert(id_val, stem.to_string());
            }
        }
    }

    let mut seen_ids = HashSet::new();
    let mut seen_names = HashSet::new();

    for spec in levels {
        let coop_map = spec.coop_map;
        let src_map = spec.source_map;
        let ident = spec.identity;
        if ident == 0 || ident == 255 {
            bail!("{}: Identity={} outside uint8 1..254", coop_map, ident);
        }
        if let Some(coll) = used_identities.get(&ident) {
            bail!("{}: Identity={} collides with {}", coop_map, ident, coll);
        }
        if !seen_ids.insert(ident) || !seen_names.insert(coop_map.to_lowercase()) {
            bail!("Duplicate level spec for {}", coop_map);
        }
        if used_map_names.contains(&coop_map.to_lowercase()) {
            bail!("{} collides with vanilla map name", coop_map);
        }
        let src_ini_key = format!("data\\maps\\{}.ini", src_map.to_lowercase());
        if !index_by_lower.contains_key(&src_ini_key) {
            bail!("Missing Data\\Maps\\{}.ini in UMD", src_map);
        }
    }

    Ok(())
}

fn append_virtual_file(
    payload: &mut Vec<u8>,
    entries: &mut [UmdEntry],
    index_by_lower: &HashMap<String, usize>,
    vpath_lower: &str,
    new_bytes: &[u8],
) -> (String, usize, usize, usize) {
    let pad = (-(payload.len() as isize) & 3) as usize;
    if pad > 0 {
        payload.resize(payload.len() + pad, 0);
    }
    let new_off = payload.len();
    payload.extend_from_slice(new_bytes);
    let ent_idx = index_by_lower[vpath_lower];
    let old_sz = entries[ent_idx].size;
    entries[ent_idx].offset = new_off;
    entries[ent_idx].size = new_bytes.len();
    (entries[ent_idx].path.clone(), new_off, old_sz, new_bytes.len())
}

pub fn patch_umd_for_all_sp_levels(
    umd_path: &Path,
    umd_bak_path: &Path,
    levels: &[LevelSpec],
) -> Result<HashMap<String, ExtractedLevelInfo>> {
    if !umd_bak_path.exists() {
        if !umd_path.exists() {
            bail!("Missing UMD archive: {}", umd_path.display());
        }
        crate::scct_log!("  [BAK] Creating clean UMD backup -> {} ...", umd_bak_path.display());
        std::fs::copy(umd_path, umd_bak_path)?;
    }

    let raw_umd = std::fs::read(umd_bak_path)?;
    let (footer, mut entries, index_by_lower) = parse_umd_archive(&raw_umd)?;
    let mut payload = raw_umd[..footer.toc_offset as usize].to_vec();

    normalize_umd_payload_baseline(&mut payload, &entries, &index_by_lower);
    validate_level_specs(levels, &payload, &entries, &index_by_lower)?;

    let mut extracted = HashMap::new();
    for spec in levels {
        let src_map = spec.source_map;
        let coop_map = spec.coop_map;
        let ini_idx = index_by_lower[&format!("data\\maps\\{}.ini", src_map.to_lowercase())];
        let ini_ent = &entries[ini_idx];
        let src_ini_bytes = payload[ini_ent.offset..ini_ent.offset + ini_ent.size].to_vec();

        let loc_val = get_ini_key_value(&src_ini_bytes, "General", "LocalizationFile");
        let canonical_src = loc_val
            .as_deref()
            .and_then(|s| s.rsplit('\\').next())
            .unwrap_or(src_map)
            .to_string();

        let mut dds_map = HashMap::new();
        for idx in [1u8, 2u8] {
            let dds_key = format!(
                "data\\magma\\datapc\\textures\\genloadings\\{}_loading_{}.dds",
                src_map.to_lowercase(),
                idx
            );
            if let Some(&d_idx) = index_by_lower.get(&dds_key) {
                let d_ent = &entries[d_idx];
                dds_map.insert(idx, payload[d_ent.offset..d_ent.offset + d_ent.size].to_vec());
            }
        }

        extracted.insert(
            coop_map.to_string(),
            ExtractedLevelInfo {
                spec: *spec,
                canonical_src,
                src_ini: src_ini_bytes,
                loading_dds: dds_map,
            },
        );
    }

    let rot_idx = index_by_lower["system\\maprotation.ini"];
    let rot_ent = &entries[rot_idx];
    let orig_rot = payload[rot_ent.offset..rot_ent.offset + rot_ent.size].to_vec();
    let coop_names: Vec<&str> = levels.iter().map(|s| s.coop_map).collect();
    let new_rot = append_missions_to_map_rotation(&orig_rot, &coop_names);
    let (rpath, roff, rold, rnew) = append_virtual_file(
        &mut payload,
        &mut entries,
        &index_by_lower,
        "system\\maprotation.ini",
        &new_rot,
    );
    crate::scct_log!(
        "  [UMD] Updated {} @ 0x{:08X} ({} -> {} bytes, +{} Coop missions)",
        rpath,
        roff,
        rold,
        rnew,
        coop_names.len()
    );

    for lang in LANG_EXTS {
        let ls_key = format!("data\\system\\localization\\loadingscreens.{}", lang);
        if !index_by_lower.contains_key(&ls_key) {
            continue;
        }
        let ls_idx = index_by_lower[&ls_key];
        let ls_ent = &entries[ls_idx];
        let orig_ls = payload[ls_ent.offset..ls_ent.offset + ls_ent.size].to_vec();
        let new_ls = append_loading_screen_sections(&orig_ls, levels);
        let (lpath, loff, lold, lnew) = append_virtual_file(
            &mut payload,
            &mut entries,
            &index_by_lower,
            &ls_key,
            &new_ls,
        );
        crate::scct_log!(
            "  [UMD] Updated {} @ 0x{:08X} ({} -> {} bytes)",
            lpath, loff, lold, lnew
        );
    }

    // Update Seoul 1 and Seoul 2 mission display names in localization files
    let seoul_missions = [("08_seoulone", "SEOUL 1"), ("09_seoultwo", "SEOUL 2")];
    let re_map = Regex::new(r"(?im)^MapName=.*$").unwrap();
    for lang in LANG_EXTS {
        for (stem, name_en) in seoul_missions {
            let loc_key = format!("data\\system\\localization\\{}.{}", stem, lang);
            if !index_by_lower.contains_key(&loc_key) {
                continue;
            }
            let loc_idx = index_by_lower[&loc_key];
            let loc_ent = &entries[loc_idx];
            let orig_bytes = payload[loc_ent.offset..loc_ent.offset + loc_ent.size].to_vec();
            let text = orig_bytes.iter().map(|&b| b as char).collect::<String>();

            let display_name = match *lang {
                "esp" => if name_en == "SEOUL 1" { "SEÚL 1" } else { "SEÚL 2" },
                "ita" => if name_en == "SEOUL 1" { "SEUL 1" } else { "SEUL 2" },
                _ => name_en,
            };

            let new_text = re_map.replace(&text, format!("MapName={}", display_name)).to_string();
            let new_bytes: Vec<u8> = new_text.chars().map(|c| c as u8).collect();
            let (lpath, loff, lold, lnew) = append_virtual_file(
                &mut payload,
                &mut entries,
                &index_by_lower,
                &loc_key,
                &new_bytes,
            );
            crate::scct_log!(
                "  [UMD] Updated {} @ 0x{:08X} ({} -> {} bytes, MapName={})",
                lpath, loff, lold, lnew, display_name
            );
        }
    }

    serialize_umd_toc_and_footer(&mut payload, &entries, footer.tag);
    std::fs::write(umd_path, &payload)?;
    crate::scct_log!("  [UMD] Wrote {} ({} bytes)", umd_path.display(), payload.len());

    Ok(extracted)
}

