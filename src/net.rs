use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

pub const PE_IMAGE_BASE: u32 = 0x10900000;
pub const PE_TEXT_RVA: u32 = 0x00001000;
pub const PE_TEXT_RAW_OFF: u32 = 0x00001000;
pub const PE_TEXT_RAW_SIZE: u32 = 0x007B6000;
pub const PE_TEXT_PATCHED_VSIZE: u32 = 0x007B5800;
pub const PE_DATA_PATCHED_VSIZE: u32 = 0x001A2400;
pub const G_LAN_PEER_VA: u32 = 0x113303A0;
pub const G_DIRECT_IP_U32_VA: u32 = 0x113303A4;
pub const G_DIRECT_IP_ENABLED_VA: u32 = 0x113303A8;

pub const NET_CAVE_VA: u32 = 0x110B6450;
pub const NET_CAVE_HEX: &str = "\
53515256575583ec2831c089e7b90a000000fcf3abc7042402000035a1a00333\
1185c07505b80808080889442404c7442420100000006a116a026a02ff15ac76\
0b1189c683feff744289e06a105056ff1560760b1185c0752b8d4c24208d4424\
10515056ff15bc760b1185c075168b44241485c0740e3c7f740a663da9fe7404\
8944242456ff156c760b118b44242483c4285d5f5e5a595bc3608b4c244c83f9\
017e758d7c245ce854ffffff85c0741489fe89caf606017405394608744083c6\
4c4a75f0f6070174118b470885c0740a3c7f7406663da9fe753e8d774c8d51ff\
f6060174118b460885c0740a3c7f7406663da9fe750883c64c4a75e4eb1a39fe\
7416b9130000008b078b168917890683c70483c6044975ef618d4424748d4c24\
44e9aa54e4ff85c074738b680c6085ed7460837d0000745a837d04007454e8bd\
feffff85c074128d75048b0e85c974093901743683c604ebf18b4d008b0185c0\
740a3c7f7406663da9fe75268d75048b0e85c9741d8b0185c0740a3c7f740666\
3da9fe750583c604ebe58b5500894d008916618b450031dbe93af3d2ffe928f4\
d2ffff742418ff742418ff742418ff742418ff742418ff742418ff1580760b11\
83f8407c3151528b4c241c85c9742566833902751f66817902238c75178b5104\
85d2741080fa7f740b83faff74068915a00333115a59c21800a1a003331185c0\
741e50ff15b0760b1185c074138d5764e80c0000008d97e5000000e801000000\
c389c6b9100000008a1e881a84db740946424975f3c642ff00c36089dfe8b7ff\
ffff618b44246c6a20e9d549a6ff6089f7e8a3ffffff6183c4248b36e9a94ea6\
ff56575389ce8b7c24108b5f04c74704000000006a1057ffb68c000000ff15c0\
760b1183f8ff751f895f046a1057ffb68c000000ff15c0760b1183f8ff75085b\
5f5e30c0c20400c706010000006a1089e05057ffb68c000000ff15bc760b1183\
c40485db7403895f04578d4e08e80e6bcfff5b5f5eb001c20400";

pub const HOOK1_GET_LOCAL_ADAPTER_IP: u32 = 0x110B64E9;
pub const HOOK2_QUAZAL_INTERFACE_TABLE: u32 = 0x110B6576;
pub const RECV_FROM_WRAPPER: u32 = 0x110B65F2;
pub const HOOK3_ON_SESSION_INFO: u32 = 0x110B668A;
pub const HOOK4_ON_SESSION_ADDRESSES: u32 = 0x110B669E;
pub const QUAZAL_SOCKET_BIND: u32 = 0x110B66B1;

pub fn decode_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex byte"))
        .collect()
}

pub fn make_jmp(src: u32, dst: u32, size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(size);
    out.push(0xE9);
    let rel = (dst as i64) - ((src as i64) + 5);
    out.extend_from_slice(&(rel as i32).to_le_bytes());
    while out.len() < size {
        out.push(0x90);
    }
    out
}

pub fn make_mov_ebp_imm(value: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(6);
    out.push(0xBD);
    out.extend_from_slice(&value.to_le_bytes());
    out.push(0x90);
    out
}

pub fn make_call(src: u32, dst: u32, size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(size);
    out.push(0xE8);
    let rel = (dst as i64) - ((src as i64) + 5);
    out.extend_from_slice(&(rel as i32).to_le_bytes());
    while out.len() < size {
        out.push(0x90);
    }
    out
}

pub const ONLINE_CAVE_VA: u32 = 0x110B6740;
pub const ONLINE_CAVE_HEX: &str = "\
ff742418ff742418ff742418ff742418ff742418ff742418ff15a8760b1150\
b00084c0744b8b54241885d2744366833a02753d66817a02238c7535837a04ff\
7406837a04007529ff7204b800000000894204ff74242052ff742420ff742420\
ff742420ff742420ff15a8760b118f420458c21800";
pub const ONLINE_CAVE_ENABLED_OFFSET: usize = 0x20;
pub const ONLINE_CAVE_IP_OFFSET: usize = 0x4B;

pub const HOOK_SENDTO_PROBE: u32 = 0x10EFC586;
pub const HOOK_COOP_ONLINE_MENU: u32 = 0x10B524CA;
pub const COOP_LAN_MENU_DEST: u32 = 0x10B524EB;

pub struct PatchSite {
    pub va: u32,
    pub orig: Vec<u8>,
    pub new: Vec<u8>,
    pub desc: &'static str,
}

pub fn get_net_sites() -> Vec<PatchSite> {
    vec![
        PatchSite {
            va: 0x10EFBA18,
            orig: decode_hex("8d4424748d4c2444"),
            new: make_jmp(0x10EFBA18, HOOK1_GET_LOCAL_ADAPTER_IP, 8),
            desc: "GetLocalAdapterIP: promote route-matched NIC to adapter 0",
        },
        PatchSite {
            va: 0x10DE591F,
            orig: decode_hex("8b680c8b450033db"),
            new: make_jmp(0x10DE591F, HOOK2_QUAZAL_INTERFACE_TABLE, 8),
            desc: "Quazal InterfaceTable: promote route-matched IP",
        },
        PatchSite {
            va: 0x10EFC62C,
            orig: decode_hex("8b2d80760b11"),
            new: make_mov_ebp_imm(RECV_FROM_WRAPPER),
            desc: "GS_Socket::RecvFrom: recvfrom -> RecvFromWrapper",
        },
        PatchSite {
            va: 0x10EFC7AC,
            orig: decode_hex("8b2d80760b11"),
            new: make_mov_ebp_imm(RECV_FROM_WRAPPER),
            desc: "GS_Socket::RecvFromIP: recvfrom -> RecvFromWrapper",
        },
        PatchSite {
            va: 0x10B1B06D,
            orig: decode_hex("8b44246c6a20"),
            new: make_jmp(0x10B1B06D, HOOK3_ON_SESSION_INFO, 6),
            desc: "CLanManager session info: join IP = real sender IP",
        },
        PatchSite {
            va: 0x10B1B555,
            orig: decode_hex("83c4248b36"),
            new: make_jmp(0x10B1B555, HOOK4_ON_SESSION_ADDRESSES, 5),
            desc: "CLanManager session addresses: join IP = real sender IP",
        },
        PatchSite {
            va: 0x10DE6510,
            orig: decode_hex("56578b7c24"),
            new: make_jmp(0x10DE6510, QUAZAL_SOCKET_BIND, 5),
            desc: "Quazal SocketDriver::Bind -> 0.0.0.0",
        },
    ]
}

pub fn va_to_text_off(va: u32) -> Result<usize> {
    if va < PE_IMAGE_BASE {
        bail!("VA 0x{:08X} < ImageBase", va);
    }
    let rva = va - PE_IMAGE_BASE;
    if !(PE_TEXT_RVA..PE_TEXT_RVA + PE_TEXT_RAW_SIZE).contains(&rva) {
        bail!("VA 0x{:08X} outside .text", va);
    }
    Ok((PE_TEXT_RAW_OFF + (rva - PE_TEXT_RVA)) as usize)
}

pub fn pe_section_headers(pe: &[u8]) -> Result<HashMap<Vec<u8>, usize>> {
    if pe.len() < 0x40 || &pe[..2] != b"MZ" {
        bail!("Invalid MZ header in splintercell3.exe");
    }
    let pe_off = u32::from_le_bytes(pe[0x3C..0x40].try_into()?) as usize;
    if pe.len() < pe_off + 0x18 || &pe[pe_off..pe_off + 4] != b"PE\0\0" {
        bail!("Invalid PE header in splintercell3.exe");
    }
    let img_base = u32::from_le_bytes(pe[pe_off + 0x34..pe_off + 0x38].try_into()?);
    if img_base != PE_IMAGE_BASE {
        bail!("Unexpected ImageBase 0x{:08X}", img_base);
    }
    let num_sec = u16::from_le_bytes(pe[pe_off + 6..pe_off + 8].try_into()?) as usize;
    let opt_sz = u16::from_le_bytes(pe[pe_off + 0x14..pe_off + 0x16].try_into()?) as usize;
    let sec_table = pe_off + 0x18 + opt_sz;

    let mut map = HashMap::new();
    for i in 0..num_sec {
        let entry_off = sec_table + i * 40;
        if pe.len() < entry_off + 40 {
            bail!("Truncated section headers table");
        }
        let raw_name = &pe[entry_off..entry_off + 8];
        let name_trimmed = match raw_name.iter().position(|&b| b == 0) {
            Some(idx) => &raw_name[..idx],
            None => raw_name,
        };
        map.insert(name_trimmed.to_vec(), entry_off);
    }
    Ok(map)
}

pub fn is_lan_and_zerotier_fix_applied(pe_bytes: &[u8]) -> bool {
    let secs = match pe_section_headers(pe_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let cave = decode_hex(NET_CAVE_HEX);
    let o = match va_to_text_off(NET_CAVE_VA) {
        Ok(off) => off,
        Err(_) => return false,
    };
    if pe_bytes.len() < o + cave.len() || &pe_bytes[o..o + cave.len()] != cave.as_slice() {
        return false;
    }
    for site in get_net_sites() {
        let so = match va_to_text_off(site.va) {
            Ok(off) => off,
            Err(_) => return false,
        };
        if pe_bytes.len() < so + site.new.len() || &pe_bytes[so..so + site.new.len()] != site.new.as_slice() {
            return false;
        }
    }
    let text_entry = match secs.get(b".text".as_slice()) {
        Some(&off) => off,
        None => return false,
    };
    let data_entry = match secs.get(b".data".as_slice()) {
        Some(&off) => off,
        None => return false,
    };
    let text_vs = u32::from_le_bytes(pe_bytes[text_entry + 8..text_entry + 12].try_into().unwrap());
    let data_vs = u32::from_le_bytes(pe_bytes[data_entry + 8..data_entry + 12].try_into().unwrap());
    text_vs >= PE_TEXT_PATCHED_VSIZE && data_vs >= PE_DATA_PATCHED_VSIZE
}

pub fn apply_lan_networking_fix(exe_path: &Path, exe_bak_path: &Path) -> Result<()> {
    if !exe_bak_path.exists() {
        if !exe_path.exists() {
            bail!("Missing executable: {}", exe_path.display());
        }
        let cur_data = fs::read(exe_path).with_context(|| format!("Reading {}", exe_path.display()))?;
        if is_lan_and_zerotier_fix_applied(&cur_data) {
            crate::scct_log!("  [NET] Multi-NIC LAN fix is already present in splintercell3.exe");
            return Ok(());
        }
        fs::copy(exe_path, exe_bak_path)
            .with_context(|| format!("Backing up {} to {}", exe_path.display(), exe_bak_path.display()))?;
        crate::scct_log!("  [BAK] Backed up vanilla EXE -> {}", exe_bak_path.display());
    }

    let mut buf = fs::read(exe_bak_path).with_context(|| format!("Reading {}", exe_bak_path.display()))?;
    if is_lan_and_zerotier_fix_applied(&buf) {
        fs::copy(exe_bak_path, exe_path)
            .with_context(|| format!("Copying {} to {}", exe_bak_path.display(), exe_path.display()))?;
        crate::scct_log!("  [NET] Applied multi-NIC LAN fix to splintercell3.exe");
        return Ok(());
    }

    let secs = pe_section_headers(&buf)?;
    let text_off = *secs.get(b".text".as_slice()).context("Missing .text section")?;
    let data_off = *secs.get(b".data".as_slice()).context("Missing .data section")?;

    let text_vs = u32::from_le_bytes(buf[text_off + 8..text_off + 12].try_into()?);
    let text_rva = u32::from_le_bytes(buf[text_off + 12..text_off + 16].try_into()?);
    let text_rs = u32::from_le_bytes(buf[text_off + 16..text_off + 20].try_into()?);
    let text_ro = u32::from_le_bytes(buf[text_off + 20..text_off + 24].try_into()?);

    if (text_rva, text_rs, text_ro) != (PE_TEXT_RVA, PE_TEXT_RAW_SIZE, PE_TEXT_RAW_OFF) {
        bail!("Unexpected .text layout - not retail splintercell3.exe");
    }

    let data_vs = u32::from_le_bytes(buf[data_off + 8..data_off + 12].try_into()?);
    let data_rva = u32::from_le_bytes(buf[data_off + 12..data_off + 16].try_into()?);
    if !(data_rva + PE_IMAGE_BASE <= G_LAN_PEER_VA && G_LAN_PEER_VA < data_rva + PE_IMAGE_BASE + 0x1A3000) {
        bail!("Unexpected .data layout");
    }

    let cave = decode_hex(NET_CAVE_HEX);
    let cave_off = va_to_text_off(NET_CAVE_VA)?;
    if buf[cave_off..cave_off + cave.len()].iter().any(|&b| b != 0) {
        bail!("Code cave at 0x{:08X} is non-zero in {}", NET_CAVE_VA, exe_bak_path.display());
    }

    let sites = get_net_sites();
    for site in &sites {
        let so = va_to_text_off(site.va)?;
        if &buf[so..so + site.orig.len()] != site.orig.as_slice() {
            bail!(
                "Unexpected bytes at 0x{:08X} in {}: {:02x?} (expected {:02x?})",
                site.va,
                exe_bak_path.display(),
                &buf[so..so + site.orig.len()],
                site.orig
            );
        }
    }

    buf[cave_off..cave_off + cave.len()].copy_from_slice(&cave);
    for site in &sites {
        let so = va_to_text_off(site.va)?;
        buf[so..so + site.new.len()].copy_from_slice(&site.new);
    }

    let new_text_vs = text_vs.max(PE_TEXT_PATCHED_VSIZE);
    let new_data_vs = data_vs.max(PE_DATA_PATCHED_VSIZE);
    buf[text_off + 8..text_off + 12].copy_from_slice(&new_text_vs.to_le_bytes());
    buf[data_off + 8..data_off + 12].copy_from_slice(&new_data_vs.to_le_bytes());

    if !is_lan_and_zerotier_fix_applied(&buf) {
        bail!("Self-verification of patched executable failed");
    }

    fs::write(exe_path, &buf).with_context(|| format!("Writing {}", exe_path.display()))?;
    crate::scct_log!(
        "  [NET] Patched System/splintercell3.exe (Multi-NIC LAN fix @ 0x{:08X}, 7 sites)",
        NET_CAVE_VA
    );
    Ok(())
}

pub fn get_online_sites() -> Vec<PatchSite> {
    vec![
        PatchSite {
            va: HOOK_SENDTO_PROBE,
            orig: decode_hex("ff15a8760b11"),
            new: make_call(HOOK_SENDTO_PROBE, ONLINE_CAVE_VA, 6),
            desc: "GS_Socket::SendTo: replicate UDP 9100 probe to Direct IP",
        },
        PatchSite {
            va: HOOK_COOP_ONLINE_MENU,
            orig: decode_hex("8b5640c68288000000018b4e408b016a01ff503c8b4e14b0015f8841145ec20400"),
            new: make_jmp(HOOK_COOP_ONLINE_MENU, COOP_LAN_MENU_DEST, 33),
            desc: "P_MenuCoop Online button -> redirect to LAN room list",
        },
    ]
}

pub fn is_online_coop_fix_applied(pe_bytes: &[u8]) -> bool {
    let o = match va_to_text_off(ONLINE_CAVE_VA) {
        Ok(off) => off,
        Err(_) => return false,
    };
    let template = decode_hex(ONLINE_CAVE_HEX);
    if pe_bytes.len() < o + template.len() {
        return false;
    }
    for (i, &expected) in template.iter().enumerate() {
        if i == ONLINE_CAVE_ENABLED_OFFSET
            || (ONLINE_CAVE_IP_OFFSET..ONLINE_CAVE_IP_OFFSET + 4).contains(&i)
        {
            continue;
        }
        if pe_bytes[o + i] != expected {
            return false;
        }
    }
    for site in get_online_sites() {
        let so = match va_to_text_off(site.va) {
            Ok(off) => off,
            Err(_) => return false,
        };
        if pe_bytes.len() < so + site.new.len()
            || &pe_bytes[so..so + site.new.len()] != site.new.as_slice()
        {
            return false;
        }
    }
    true
}

pub fn get_direct_ip_from_exe(pe_bytes: &[u8]) -> Option<Ipv4Addr> {
    if !is_online_coop_fix_applied(pe_bytes) {
        return None;
    }
    let o = va_to_text_off(ONLINE_CAVE_VA).ok()?;
    let enabled = pe_bytes[o + ONLINE_CAVE_ENABLED_OFFSET] == 1;
    if !enabled {
        return None;
    }
    let ip_bytes: [u8; 4] = pe_bytes[o + ONLINE_CAVE_IP_OFFSET..o + ONLINE_CAVE_IP_OFFSET + 4]
        .try_into()
        .ok()?;
    let ip = Ipv4Addr::from(ip_bytes);
    if ip.is_unspecified() {
        None
    } else {
        Some(ip)
    }
}

pub fn set_direct_ip_in_exe(pe_bytes: &mut [u8], ip: Option<Ipv4Addr>) -> Result<()> {
    if !is_online_coop_fix_applied(pe_bytes) {
        bail!("Online coop fix is not applied to executable");
    }
    let o = va_to_text_off(ONLINE_CAVE_VA)?;
    match ip {
        Some(addr) => {
            pe_bytes[o + ONLINE_CAVE_ENABLED_OFFSET] = 1;
            pe_bytes[o + ONLINE_CAVE_IP_OFFSET..o + ONLINE_CAVE_IP_OFFSET + 4]
                .copy_from_slice(&addr.octets());
        }
        None => {
            pe_bytes[o + ONLINE_CAVE_ENABLED_OFFSET] = 0;
            pe_bytes[o + ONLINE_CAVE_IP_OFFSET..o + ONLINE_CAVE_IP_OFFSET + 4]
                .copy_from_slice(&[0, 0, 0, 0]);
        }
    }
    Ok(())
}

pub fn apply_online_coop_fix(
    exe_path: &Path,
    exe_bak_path: &Path,
    target_ip: Option<Ipv4Addr>,
) -> Result<()> {
    // Ensure base LAN multi-NIC fix is applied first
    apply_lan_networking_fix(exe_path, exe_bak_path)?;

    let mut buf = fs::read(exe_path).with_context(|| format!("Reading {}", exe_path.display()))?;

    if is_online_coop_fix_applied(&buf) {
        set_direct_ip_in_exe(&mut buf, target_ip)?;
        fs::write(exe_path, &buf).with_context(|| format!("Writing {}", exe_path.display()))?;
        if let Some(ip) = target_ip {
            crate::scct_log!("  [NET] Direct Host IP updated in splintercell3.exe -> {}", ip);
        } else {
            crate::scct_log!("  [NET] Online Coop patch active in splintercell3.exe (LAN mode)");
        }
        return Ok(());
    }

    let cave_off = va_to_text_off(ONLINE_CAVE_VA)?;
    let mut cave = decode_hex(ONLINE_CAVE_HEX);
    if let Some(ip) = target_ip {
        cave[ONLINE_CAVE_ENABLED_OFFSET] = 1;
        cave[ONLINE_CAVE_IP_OFFSET..ONLINE_CAVE_IP_OFFSET + 4].copy_from_slice(&ip.octets());
    }

    let sites = get_online_sites();
    for site in &sites {
        let so = va_to_text_off(site.va)?;
        if &buf[so..so + site.orig.len()] != site.orig.as_slice() {
            bail!(
                "Unexpected bytes at 0x{:08X} for online fix: {:02x?} (expected {:02x?})",
                site.va,
                &buf[so..so + site.orig.len()],
                site.orig
            );
        }
    }

    buf[cave_off..cave_off + cave.len()].copy_from_slice(&cave);
    for site in &sites {
        let so = va_to_text_off(site.va)?;
        buf[so..so + site.new.len()].copy_from_slice(&site.new);
    }

    if !is_online_coop_fix_applied(&buf) {
        bail!("Self-verification of online coop fix failed");
    }

    fs::write(exe_path, &buf).with_context(|| format!("Writing {}", exe_path.display()))?;
    if let Some(ip) = target_ip {
        crate::scct_log!(
            "  [NET] Applied Online Coop fix to System/splintercell3.exe (Direct IP: {})",
            ip
        );
    } else {
        crate::scct_log!("  [NET] Applied Online Coop fix to System/splintercell3.exe");
    }
    Ok(())
}

pub fn update_direct_ip_in_exe(
    exe_path: &Path,
    exe_bak_path: &Path,
    target_ip: Option<Ipv4Addr>,
) -> Result<()> {
    apply_online_coop_fix(exe_path, exe_bak_path, target_ip)
}

pub fn save_direct_ip_ini(ini_path: &Path, ip: Option<Ipv4Addr>) -> Result<()> {
    let content = match ip {
        Some(addr) => format!("[Online]\nEnabled = 1\nHostIP = {}\n", addr),
        None => "[Online]\nEnabled = 0\nHostIP = \n".to_string(),
    };
    fs::write(ini_path, content)?;
    Ok(())
}

pub fn load_direct_ip_ini(ini_path: &Path) -> Option<Ipv4Addr> {
    let content = fs::read_to_string(ini_path).ok()?;
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("HostIP") {
            let val = rest.trim().trim_start_matches('=').trim();
            if let Ok(ip) = val.parse::<Ipv4Addr>()
                && !ip.is_unspecified()
            {
                return Some(ip);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_call_and_jmp() {
        let call_bytes = make_call(HOOK_SENDTO_PROBE, ONLINE_CAVE_VA, 6);
        assert_eq!(call_bytes.len(), 6);
        assert_eq!(call_bytes[0], 0xE8);
        assert_eq!(call_bytes[5], 0x90);

        let jmp_bytes = make_jmp(HOOK_COOP_ONLINE_MENU, COOP_LAN_MENU_DEST, 33);
        assert_eq!(jmp_bytes.len(), 33);
        assert_eq!(jmp_bytes[0], 0xE9);
        assert_eq!(&jmp_bytes[1..5], &0x1Ci32.to_le_bytes());
        for &b in &jmp_bytes[5..] {
            assert_eq!(b, 0x90);
        }
    }

    #[test]
    fn test_online_cave_hex_integrity() {
        let bytes = decode_hex(ONLINE_CAVE_HEX);
        assert_eq!(bytes.len(), 116);
        assert_eq!(bytes[ONLINE_CAVE_ENABLED_OFFSET], 0x00);
        assert_eq!(&bytes[ONLINE_CAVE_IP_OFFSET..ONLINE_CAVE_IP_OFFSET + 4], &[0, 0, 0, 0]);
    }

    #[test]
    fn test_direct_ip_ini() {
        let dir = std::env::temp_dir();
        let ini_path = dir.join("test_direct_ip.ini");

        let test_ip = Ipv4Addr::new(82, 165, 45, 112);
        save_direct_ip_ini(&ini_path, Some(test_ip)).unwrap();
        let loaded = load_direct_ip_ini(&ini_path);
        assert_eq!(loaded, Some(test_ip));

        save_direct_ip_ini(&ini_path, None).unwrap();
        let cleared = load_direct_ip_ini(&ini_path);
        assert_eq!(cleared, None);

        let _ = fs::remove_file(ini_path);
    }

    #[test]
    fn test_apply_online_coop_fix() {
        let clean_exe = Path::new("../clean_scct_files/Tom Clancy's Splinter Cell Chaos Theory/System/splintercell3.exe");
        if !clean_exe.exists() {
            return;
        }

        let dir = std::env::temp_dir();
        let test_exe = dir.join("test_scct3_online.exe");
        let test_bak = dir.join("test_scct3_online.exe.bak");

        let _ = fs::copy(clean_exe, &test_exe);

        let test_ip = Ipv4Addr::new(82, 165, 45, 112);
        apply_online_coop_fix(&test_exe, &test_bak, Some(test_ip)).unwrap();

        let buf = fs::read(&test_exe).unwrap();
        assert!(is_online_coop_fix_applied(&buf));
        assert_eq!(get_direct_ip_from_exe(&buf), Some(test_ip));

        // Test clearing IP
        set_direct_ip_in_exe(&mut buf.clone(), None).unwrap();
        apply_online_coop_fix(&test_exe, &test_bak, None).unwrap();
        let buf2 = fs::read(&test_exe).unwrap();
        assert!(is_online_coop_fix_applied(&buf2));
        assert_eq!(get_direct_ip_from_exe(&buf2), None);

        let _ = fs::remove_file(test_exe);
        let _ = fs::remove_file(test_bak);
    }
}



