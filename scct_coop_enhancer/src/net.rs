use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

pub const PE_IMAGE_BASE: u32 = 0x10900000;
pub const PE_TEXT_RVA: u32 = 0x00001000;
pub const PE_TEXT_RAW_OFF: u32 = 0x00001000;
pub const PE_TEXT_RAW_SIZE: u32 = 0x007B6000;
pub const PE_TEXT_PATCHED_VSIZE: u32 = 0x007B6000;
pub const PE_DATA_PATCHED_VSIZE: u32 = 0x001A2400;
pub const G_LAN_PEER_VA: u32 = 0x113303A0;
pub const G_DIRECT_IP_U32_VA: u32 = 0x113303A4;
pub const G_DIRECT_IP_ENABLED_VA: u32 = 0x113303A8;

pub const G_INHERITED_SOCK_9100_VA: u32 = 0x113303D0;
pub const G_INHERITED_SOCK_9103_VA: u32 = 0x113303D4;
pub const G_INHERITED_PRIMED_9100_VA: u32 = 0x113303D8;
pub const G_INHERITED_PRIMED_9103_VA: u32 = 0x113303DC;
pub const G_LAST_9103_KEEPALIVE_VA: u32 = 0x113303E0;
pub const G_LAST_9100_KEEPALIVE_VA: u32 = 0x113303E4;

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
83f8407c3151528b4c241c85c9742566833902751f90909090909090908b5104\
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

pub const SOCKET_CAVE_VA: u32 = 0x110B67C0;
pub const HOOK_DISCOVERY_SOCKET: u32 = 0x110B67C0;
pub const HOOK_DISCOVERY_BIND: u32 = 0x110B67E0;
pub const HOOK_QUAZAL_SOCKET: u32 = 0x110B6800;
pub const HOOK_QUAZAL_BIND: u32 = 0x110B6820;
/// Discovery bind implementation: checks UDP port 9100, disables `SIO_UDP_CONNRESET`,
/// handles primed sockets, and forces `INADDR_ANY` (`0.0.0.0`) so multi-NIC / WSL machines
/// route and receive on all interfaces.
pub const HOOK_DISCOVERY_BIND_ANY: u32 = 0x110B6850;
/// Port-aware Quazal `SocketDriver::Bind` implementation (`0x110B6892`):
/// inspects bound `sin_port` at `[driver + 0x0A]` (`9100` vs `9103`) so Online Co-op punches
/// `peer_disco_port` from `:9100` and `peer_game_port` from `:9103`.
pub const HOOK_QUAZAL_BIND_IMPL: u32 = 0x110B6892;
/// Port-aware Quazal UDP poll hook (`SocketDriver::HasRecvCompleted` @ `0x10DE53B0`):
/// sends a 3s keepalive from `:9100` -> `peer_disco_port` and `:9103` -> `peer_game_port`
/// so both CGNAT pinholes stay open independently.
pub const HOOK_QUAZAL_POLL: u32 = 0x110B6920;
/// Discovery `recvfrom` wrapper (Versus `GS_Socket::RecvFrom`): sends a 4-byte `"SCPK"` keepalive
/// every 3s in Online mode, strips incoming `"SCPK"` keepalives, and captures `G_LAN_PEER_VA`.
pub const HOOK_DISCOVERY_RECVFROM: u32 = 0x110B69A2;
/// Quazal `SocketDriver::SendTo` `WSASendTo` hook (`0x10DE65CA`): replicates Co-op UDP `9100`
/// `LANSessionDiscovery` broadcasts (`255.255.255.255` / `0.0.0.0`) as direct unicast packets
/// to `(CAVE_ONLINE_IP_VA, CAVE_ONLINE_PORT_VA)` before calling `WSASendTo`.
pub const HOOK_QUAZAL_WSASENDTO: u32 = 0x110B6A52;
/// Quazal `BrowseProtocol::HandleBrowseReply` URL hook (`0x10DC36CE`): extracts the real UDP sender
/// IP from `Message::m_pSenderURL` into `G_LAN_PEER_VA` and rewrites the discovered `StationURL`
/// `address`/`port` via `StationURL::SetInetAddress` (`0x10D92AF0`) so joining works across
/// WAN/CGNAT (`CAVE_ONLINE_IP_VA` + `JOIN_GAME_PORT_VA`) and multi-NIC/WSL LAN setups.
pub const HOOK_BROWSE_REPLY_URL: u32 = 0x110B6AD5;

pub const SOCKET_CAVE_HEX: &str = "\
a1d003331185c0740dc705d003331100000000c20c00ff25ac760b1190909090\
eb6e909090909090909090909090909090909090909090909090909090909090\
a1d403331185c0740dc705d403331100000000c21800ff25b8760b1190909090\
eb70909090909090909090909090909090909090909090909090909090909090\
909090909090909090909090909090908b44240885c0743466817802238c752c\
8b442404e83e030000833dd803331100740fc705d80333110000000031c0c20c\
008b442408c7400400000000ff25c0760b115689ce8b868c000000e807030000\
833ddc03331100750dff74240889f1e8fdfdffffeb17c705dc03331100000000\
57538b7c241031dbe92afeffff84c0744b803d60670b110074400fb7560a6681\
fa238c741f6681fa238f752eff1504730b11a3e00333118b868c000000e8de02\
0000eb16ff1504730b11a3e40333118b868c000000e824030000b0015ec20400\
803d60670b1100746e83390175690fb7510a6681fa238c74336681fa238f7557\
51ff1504730b1189c22b05e00333113db80b000072408915e00333118b0c248b\
818c000000e876020000eb2a51ff1504730b1189c22b05e40333113db80b0000\
72148915e40333118b0c248b818c000000e8a8020000598b8194000000e914ea\
d2ff803d60670b11007424ff1504730b1189c22b05e40333113db80b0000720f\
8915e40333118b442404e86f020000ff742418ff742418ff742418ff742418ff\
742418ff742418ff1580760b1183f80475338b54240885d27455837c240c047c\
4e813a5343504b7546f64424100274bf6a006a006a006a0452ff742418ff1580\
760b11ebaa83f8407c258b4c241485c9741d6683390275178b510485d2741080\
fa7f740b83faff74068915a0033311c21800803d60670b110074748b44241885\
c0746c66817802238c75648b500483faff740485d275588b0d83670b1185c974\
4e0fb7158e670b1185d274438b44240885c0743bc1e21066ba020083ec108914\
24894c2404c744240800000000c744240c0000000089e18b5424146a10516a00\
ff30ff700452ff15a8760b1183c410ff25c4760b1153565783ec2089ce89fb89\
e1e8da67cfff31c08944241089442414894424188944241c31ff85db742b8b4b\
2885c9742489e050e873bccdff84c074188b44240485c074103c7f740c83f8ff\
740789c7a3a0033311803d60670b1100743ca183670b1185c0750689f885c074\
5d0fb715d67eb51085d27505ba8f23000086f266c70424020066895424028944\
240489e05089f1e884bfcdffeb3085ff742c89f1e897b6cdff6685c07505b88f\
23000086e066c7042402006689442402897c240489e05089f1e852bfcdff8b06\
83c4205f5e5bc383f8ff743383ec08c7042400000000c7442404000000008d4c\
240489e26a006a00516a006a006a0452680c00009850ff15d0760b1183c408c3\
83f8ff74588b0d83670b1185c9744e0fb715d67eb51085d2744386f2c1e21066\
ba020083ec14891424894c2404c744240800000000c744240c00000000c74424\
10ffff000089e18d5424106a10516a006a025250ff15a8760b1183c414c383f8\
ff74568b0d83670b1185c9744c0fb7158e670b1185d27441c1e21066ba020083\
ec14891424894c2404c744240800000000c744240c00000000c7442410534350\
4b89e18d5424106a10516a006a045250ff15a8760b1183c414c3";

pub const HOOK_SITE_DISCOVERY_SOCKET: u32 = 0x10EFBFF9;
pub const HOOK_SITE_DISCOVERY_BIND: u32 = 0x10EFC0A3;
pub const HOOK_SITE_DISCOVERY_BIND_IP: u32 = 0x10EFC109;
pub const HOOK_SITE_QUAZAL_SOCKET: u32 = 0x10DE6490;
pub const HOOK_SITE_QUAZAL_POLL: u32 = 0x10DE53B0;
pub const HOOK_SITE_QUAZAL_WSASENDTO: u32 = 0x10DE65CA;
pub const HOOK_SITE_BROWSE_REPLY_URL: u32 = 0x10DC36CE;

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
/// Hook_SendToProbe (replaces `call [sendto]` at 0x10EFC586):
/// ```text
/// +00 push [esp+18] x6 ; call [sendto]        ; original send (broadcast)
/// +1E push eax                                 ; save result
/// +1F mov al, ENABLED ; test al,al ; jz exit
/// +25 mov edx,[esp+18]                         ; edx = sockaddr_in *to
/// +29 cmp word [edx+2], htons(9100) ; jne exit
/// +31 cmp dword [edx+4], -1 ; je repl          ; 255.255.255.255
/// +37 cmp dword [edx+4], 0  ; jne exit         ; 0.0.0.0
/// +3D push [edx+4] ; push [edx]                ; save addr + family/port
/// +42 mov eax, PEER_IP ; mov [edx+4], eax
/// +4A mov word [edx+2], PEER_PORT              ; peer's (NAT-mapped) port
/// +50 push [esp+24] (tolen) ; push edx (to) ; push [esp+24] x4 (flags,len,buf,s)
/// +65 call [sendto]                            ; unicast copy to peer
/// +6B mov edx,[esp+20] ; pop [edx] ; pop [edx+4] ; restore caller's sockaddr
/// +74 exit: pop eax ; ret 18
/// ```
pub const ONLINE_CAVE_HEX: &str = "\
ff742418ff742418ff742418ff742418ff742418ff742418ff15a8760b1150\
b00084c0744f8b54241866817a02238c7543837a04ff7406837a04007537ff72\
04ff32b80000000089420466c74202238cff74242452ff742424ff742424ff74\
2424ff742424ff15a8760b118b5424208f028f420458c21800";
pub const ONLINE_CAVE_ENABLED_OFFSET: usize = 0x20;
pub const ONLINE_CAVE_IP_OFFSET: usize = 0x43;
/// Big-endian (network order) destination port for the unicast copy. Defaults to 9100.
pub const ONLINE_CAVE_PORT_OFFSET: usize = 0x4E;
pub const CAVE_ONLINE_ENABLED_VA: u32 = ONLINE_CAVE_VA + ONLINE_CAVE_ENABLED_OFFSET as u32;
pub const CAVE_ONLINE_IP_VA: u32 = ONLINE_CAVE_VA + ONLINE_CAVE_IP_OFFSET as u32;
pub const CAVE_ONLINE_PORT_VA: u32 = ONLINE_CAVE_VA + ONLINE_CAVE_PORT_OFFSET as u32;
pub const DISCOVERY_PORT: u16 = 9100;
pub const GAME_PORT: u16 = 9103;

/// `GS_Socket::SendTo(const char*, u16)` — called by LAN room discovery (`"255.255.255.255"`, `9100`).
pub const HOOK_SENDTO_STR: u32 = 0x10EFC4F9;
/// `GS_Socket::SendToIP(u32, u16)` — secondary `sendto` wrapper.
pub const HOOK_SENDTO_PROBE: u32 = 0x10EFC586;
pub const HOOK_COOP_ONLINE_MENU: u32 = 0x10B524CA;
pub const COOP_LAN_MENU_DEST: u32 = 0x10B524EB;
/// `MainMenuCoop` button 0 (`"LAN"`) caption setup (`0x10B4BB86..0x10B4BBA5`):
/// replaces `Localize(L"MainMenuCoop", L"LanCaption", L"PreGame_PC")` with `L"ENHANCED COOP"`.
pub const HOOK_MAIN_MENU_COOP_LAN_CAPTION: u32 = 0x10B4BB86;
/// UTF-16LE `L"ENHANCED COOP\0"` (28 bytes) stored in `.text` cave at `0x110B6CA0`.
pub const ENHANCED_COOP_WSTR_VA: u32 = 0x110B6CA0;
pub const ENHANCED_COOP_WSTR_HEX: &str =
    "45004e00480041004e00430045004400200043004f004f0050000000";
/// `push 0x0000238F` (`9103`) immediate used to format `prudp:/address=%s;port=%d` when joining Coop.
pub const JOIN_GAME_PORT_PUSH_VA: u32 = 0x10B57ED5;
pub const JOIN_GAME_PORT_VA: u32 = 0x10B57ED6;

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
            new: make_mov_ebp_imm(HOOK_DISCOVERY_RECVFROM),
            desc: "GS_Socket::RecvFrom: recvfrom -> HookDiscoveryRecvFrom",
        },
        PatchSite {
            va: 0x10EFC7AC,
            orig: decode_hex("8b2d80760b11"),
            new: make_mov_ebp_imm(HOOK_DISCOVERY_RECVFROM),
            desc: "GS_Socket::RecvFromIP: recvfrom -> HookDiscoveryRecvFrom",
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
            new: make_jmp(0x10DE6510, HOOK_QUAZAL_BIND, 5),
            desc: "Quazal SocketDriver::Bind -> HookQuazalBind (0.0.0.0 + punch)",
        },
        PatchSite {
            va: HOOK_SITE_QUAZAL_POLL,
            orig: decode_hex("8b8194000000"),
            new: make_jmp(HOOK_SITE_QUAZAL_POLL, HOOK_QUAZAL_POLL, 6),
            desc: "Quazal SocketDriver::HasRecvCompleted -> 3s CGNAT keepalive",
        },
        PatchSite {
            va: HOOK_SITE_DISCOVERY_SOCKET,
            orig: decode_hex("ff15ac760b11"),
            new: make_call(HOOK_SITE_DISCOVERY_SOCKET, HOOK_DISCOVERY_SOCKET, 6),
            desc: "GS_Socket::CreateUDP: ingest primed socket if present",
        },
        PatchSite {
            va: HOOK_SITE_DISCOVERY_BIND,
            orig: decode_hex("ff15c0760b11"),
            new: make_call(HOOK_SITE_DISCOVERY_BIND, HOOK_DISCOVERY_BIND, 6),
            desc: "GS_Socket::Bind: bind UDP 9100 to 0.0.0.0",
        },
        PatchSite {
            va: HOOK_SITE_DISCOVERY_BIND_IP,
            orig: decode_hex("ff15c0760b11"),
            new: make_call(HOOK_SITE_DISCOVERY_BIND_IP, HOOK_DISCOVERY_BIND, 6),
            desc: "GS_Socket::BindIP: bind UDP 9100 to 0.0.0.0",
        },
        PatchSite {
            va: HOOK_SITE_QUAZAL_SOCKET,
            orig: decode_hex("ff15b8760b11"),
            new: make_call(HOOK_SITE_QUAZAL_SOCKET, HOOK_QUAZAL_SOCKET, 6),
            desc: "Quazal Net-Z WSASocketW: ingest primed socket if present",
        },
        PatchSite {
            va: HOOK_SITE_QUAZAL_WSASENDTO,
            orig: decode_hex("ff15c4760b11"),
            new: make_call(HOOK_SITE_QUAZAL_WSASENDTO, HOOK_QUAZAL_WSASENDTO, 6),
            desc: "Quazal SocketDriver::SendTo: replicate UDP 9100 WSASendTo broadcast to peer",
        },
        PatchSite {
            va: HOOK_SITE_BROWSE_REPLY_URL,
            orig: decode_hex("e8bdd9fcff"),
            new: make_call(HOOK_SITE_BROWSE_REPLY_URL, HOOK_BROWSE_REPLY_URL, 5),
            desc: "Quazal HandleBrowseReply: rewrite SessionDescriptor StationURL IP/port",
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

    let sock_cave = decode_hex(SOCKET_CAVE_HEX);
    let so_sock = match va_to_text_off(SOCKET_CAVE_VA) {
        Ok(off) => off,
        Err(_) => return false,
    };
    if pe_bytes.len() < so_sock + sock_cave.len()
        || &pe_bytes[so_sock..so_sock + sock_cave.len()] != sock_cave.as_slice()
    {
        return false;
    }

    for site in get_net_sites() {
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
            crate::scct_log!("  [NET] Multi-NIC LAN & STUN fix is already present in splintercell3.exe");
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
        crate::scct_log!("  [NET] Applied multi-NIC LAN & STUN fix to splintercell3.exe");
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
    if &buf[cave_off..cave_off + cave.len()] != cave.as_slice()
        && buf[cave_off..cave_off + cave.len()].iter().any(|&b| b != 0)
    {
        let mut prev_net_cave = cave.clone();
        // Previous NET_CAVE had `66 81 79 02 23 8c 75 17` at 0x110B6625 (+0x1D5)
        prev_net_cave[0x1D5..0x1DD].copy_from_slice(&decode_hex("66817902238c7517"));
        if &buf[cave_off..cave_off + cave.len()] != prev_net_cave.as_slice() {
            bail!("Code cave at 0x{:08X} is non-zero in {}", NET_CAVE_VA, exe_bak_path.display());
        }
    }

    let sock_cave = decode_hex(SOCKET_CAVE_HEX);
    let sock_cave_off = va_to_text_off(SOCKET_CAVE_VA)?;
    if &buf[sock_cave_off..sock_cave_off + sock_cave.len()] != sock_cave.as_slice()
        && buf[sock_cave_off..sock_cave_off + sock_cave.len()].iter().any(|&b| b != 0)
    {
        let old_v1 = decode_hex(
            "a1d003331185c0740bc705d003331100000000c20c00ff25ac760b1190909090\
             833dd803331100740ec705d80333110000000031c0c20c00ff25c0760b119090\
             a1d403331185c0740bc705d403331100000000c21800ff25b8760b1190909090\
             833ddc033311007505e983feffffc705dc0333110000000056575389ce8b7c24\
             10e9b1feffff",
        );
        let old_v2 = decode_hex(
            "a1d003331185c0740dc705d003331100000000c20c00ff25ac760b1190909090\
             833dd803331100740fc705d80333110000000031c0c20c00e953000000909090\
             a1d403331185c0740dc705d403331100000000c21800ff25b8760b1190909090\
             833ddc033311007505e983feffffc705dc0333110000000056575389ce8b7c24\
             10e9b1feffff90909090909090909090\
             803d60670b110074178b44240885c0740f66817802238c7507c7400400000000\
             ff25c0760b11",
        );
        let old_v3 = decode_hex(
            "a1d003331185c0740dc705d003331100000000c20c00ff25ac760b1190909090\
             eb6e909090909090909090909090909090909090909090909090909090909090\
             a1d403331185c0740dc705d403331100000000c21800ff25b8760b1190909090\
             eb70909090909090909090909090909090909090909090909090909090909090\
             909090909090909090909090909090908b44240885c0743466817802238c752c\
             8b442404e881010000833dd803331100740fc705d80333110000000031c0c20c\
             008b442408c7400400000000ff25c0760b115689ce8b868c000000e84a010000\
             833ddc03331100750dff74240889f1e8fdfdffffeb17c705dc03331100000000\
             57538b7c241031dbe92afeffff84c07421803d60670b11007416ff1504730b11\
             a3e00333118b868c000000e833010000b0015ec20400803d60670b1100743083\
             3901752b51ff1504730b1189c22b05e00333113db80b000072148915e0033311\
             8b0c248b818c000000e8f5000000598b8194000000e97cead2ff803d60670b11\
             007424ff1504730b1189c22b05e40333113db80b0000720f8915e40333118b44\
             2404e81a010000ff742418ff742418ff742418ff742418ff742418ff742418ff\
             1580760b1183f80475338b54240885d27455837c240c047c4e813a5343504b75\
             46f64424100274bf6a006a006a006a0452ff742418ff1580760b11ebaa83f840\
             7c258b4c241485c9741d6683390275178b510485d2741080fa7f740b83faff74\
             068915a0033311c2180083f8ff743383ec08c7042400000000c7442404000000\
             008d4c240489e26a006a00516a006a006a0452680c00009850ff15d0760b1183\
             c408c383f8ff74588b0d83670b1185c9744e0fb715d67eb51085d2744386f2c1\
             e21066ba020083ec14891424894c2404c744240800000000c744240c00000000\
             c7442410ffff000089e18d5424106a10516a006a025250ff15a8760b1183c414\
             c383f8ff74568b0d83670b1185c9744c0fb7158e670b1185d27441c1e21066ba\
             020083ec14891424894c2404c744240800000000c744240c00000000c7442410\
             5343504b89e18d5424106a10516a006a045250ff15a8760b1183c414c3",
        );
        let matches_old = [&old_v1, &old_v2, &old_v3].iter().any(|old| {
            buf[sock_cave_off..sock_cave_off + old.len()] == *old.as_slice()
                && buf[sock_cave_off + old.len()..sock_cave_off + sock_cave.len()]
                    .iter()
                    .all(|&b| b == 0)
        });
        if !matches_old {
            bail!("Code cave at 0x{:08X} is non-zero in {}", SOCKET_CAVE_VA, exe_bak_path.display());
        }
    }

    let sites = get_net_sites();
    for site in &sites {
        let so = va_to_text_off(site.va)?;
        let cur = &buf[so..so + site.orig.len()];
        if cur != site.orig.as_slice() && cur != site.new.as_slice() {
            let old_quazal_bind = make_jmp(0x10DE6510, QUAZAL_SOCKET_BIND, 5);
            let old_recv_wrap = make_mov_ebp_imm(RECV_FROM_WRAPPER);
            let old_disc_rf_v3 = make_mov_ebp_imm(0x110B693A);
            let old_poll_v3 = make_jmp(HOOK_SITE_QUAZAL_POLL, 0x110B68F6, 6);
            if (site.va == 0x10DE6510 && cur == old_quazal_bind.as_slice())
                || ((site.va == 0x10EFC62C || site.va == 0x10EFC7AC)
                    && (cur == old_recv_wrap.as_slice() || cur == old_disc_rf_v3.as_slice()))
                || (site.va == HOOK_SITE_QUAZAL_POLL && cur == old_poll_v3.as_slice())
            {
                // allow upgrading older hook versions cleanly
            } else {
                bail!(
                    "Unexpected bytes at 0x{:08X} in {}: {:02x?} (expected {:02x?})",
                    site.va,
                    exe_bak_path.display(),
                    cur,
                    site.orig
                );
            }
        }
    }

    buf[cave_off..cave_off + cave.len()].copy_from_slice(&cave);
    buf[sock_cave_off..sock_cave_off + sock_cave.len()].copy_from_slice(&sock_cave);
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
        "  [NET] Patched System/splintercell3.exe (Multi-NIC LAN + NAT hooks @ 0x{:08X}, {} sites)",
        NET_CAVE_VA,
        sites.len()
    );
    Ok(())
}

pub fn get_online_sites() -> Vec<PatchSite> {
    vec![
        PatchSite {
            va: HOOK_SENDTO_STR,
            orig: decode_hex("ff15a8760b11"),
            new: make_call(HOOK_SENDTO_STR, ONLINE_CAVE_VA, 6),
            desc: "GS_Socket::SendTo: replicate UDP 9100 broadcast to Direct IP",
        },
        PatchSite {
            va: HOOK_SENDTO_PROBE,
            orig: decode_hex("ff15a8760b11"),
            new: make_call(HOOK_SENDTO_PROBE, ONLINE_CAVE_VA, 6),
            desc: "GS_Socket::SendToIP: replicate UDP 9100 probe to Direct IP",
        },
        PatchSite {
            va: HOOK_COOP_ONLINE_MENU,
            orig: decode_hex("8b5640c68288000000018b4e408b016a01ff503c8b4e14b0015f8841145ec20400"),
            new: make_jmp(HOOK_COOP_ONLINE_MENU, COOP_LAN_MENU_DEST, 33),
            desc: "P_MenuCoop Online button -> redirect to LAN room list",
        },
        PatchSite {
            va: HOOK_MAIN_MENU_COOP_LAN_CAPTION,
            orig: decode_hex("6a0153536880430d1168c82c0e116820f40d11e8120918008b4e4883c41850"),
            new: decode_hex("8b4e4868a06c0b11eb15909090909090909090909090909090909090909090"),
            desc: "MainMenuCoop LAN button -> display 'ENHANCED COOP'",
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
            || (ONLINE_CAVE_PORT_OFFSET..ONLINE_CAVE_PORT_OFFSET + 2).contains(&i)
        {
            continue;
        }
        if pe_bytes[o + i] != expected {
            return false;
        }
    }
    let wstr = decode_hex(ENHANCED_COOP_WSTR_HEX);
    let wstr_off = match va_to_text_off(ENHANCED_COOP_WSTR_VA) {
        Ok(off) => off,
        Err(_) => return false,
    };
    if pe_bytes.len() < wstr_off + wstr.len()
        || &pe_bytes[wstr_off..wstr_off + wstr.len()] != wstr.as_slice()
    {
        return false;
    }
    let jp_off = match va_to_text_off(JOIN_GAME_PORT_PUSH_VA) {
        Ok(off) => off,
        Err(_) => return false,
    };
    if pe_bytes.len() < jp_off + 5
        || pe_bytes[jp_off] != 0x68
        || pe_bytes[jp_off + 3..jp_off + 5] != [0, 0]
    {
        return false;
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
    set_direct_target_in_exe(pe_bytes, ip, DISCOVERY_PORT, GAME_PORT)
}

/// Write the peer IP, discovery port, and gameplay port into the patched executable.
pub fn set_direct_target_in_exe(
    pe_bytes: &mut [u8],
    ip: Option<Ipv4Addr>,
    disco_port: u16,
    game_port: u16,
) -> Result<()> {
    if !is_online_coop_fix_applied(pe_bytes) {
        bail!("Online coop fix is not applied to executable");
    }
    let o = va_to_text_off(ONLINE_CAVE_VA)?;
    write_online_cave_target(&mut pe_bytes[o..], ip, disco_port);
    let jp_off = va_to_text_off(JOIN_GAME_PORT_VA)?;
    let eff_game_port = match ip {
        Some(_) if game_port != 0 => game_port,
        _ => GAME_PORT,
    };
    pe_bytes[jp_off..jp_off + 4].copy_from_slice(&(eff_game_port as u32).to_le_bytes());
    Ok(())
}

fn write_online_cave_target(cave: &mut [u8], ip: Option<Ipv4Addr>, port: u16) {
    let (enabled, ip_bytes, port) = match ip {
        Some(addr) => (1u8, addr.octets(), if port == 0 { DISCOVERY_PORT } else { port }),
        None => (0u8, [0u8; 4], DISCOVERY_PORT),
    };
    cave[ONLINE_CAVE_ENABLED_OFFSET] = enabled;
    cave[ONLINE_CAVE_IP_OFFSET..ONLINE_CAVE_IP_OFFSET + 4].copy_from_slice(&ip_bytes);
    cave[ONLINE_CAVE_PORT_OFFSET..ONLINE_CAVE_PORT_OFFSET + 2].copy_from_slice(&port.to_be_bytes());
}

pub fn apply_online_coop_fix(
    exe_path: &Path,
    exe_bak_path: &Path,
    target_ip: Option<Ipv4Addr>,
) -> Result<()> {
    apply_online_coop_fix_with_ports(exe_path, exe_bak_path, target_ip, DISCOVERY_PORT, GAME_PORT)
}

pub fn apply_online_coop_fix_with_ports(
    exe_path: &Path,
    exe_bak_path: &Path,
    target_ip: Option<Ipv4Addr>,
    disco_port: u16,
    game_port: u16,
) -> Result<()> {
    // Ensure base LAN multi-NIC fix is applied first
    apply_lan_networking_fix(exe_path, exe_bak_path)?;

    let mut buf = fs::read(exe_path).with_context(|| format!("Reading {}", exe_path.display()))?;

    if is_online_coop_fix_applied(&buf) {
        set_direct_target_in_exe(&mut buf, target_ip, disco_port, game_port)?;
        fs::write(exe_path, &buf).with_context(|| format!("Writing {}", exe_path.display()))?;
        crate::scct_log!("  [NET] Online Coop fix active in System/splintercell3.exe");
        return Ok(());
    }

    let cave_off = va_to_text_off(ONLINE_CAVE_VA)?;
    let mut cave = decode_hex(ONLINE_CAVE_HEX);
    write_online_cave_target(&mut cave, target_ip, disco_port);

    let wstr_off = va_to_text_off(ENHANCED_COOP_WSTR_VA)?;
    let wstr = decode_hex(ENHANCED_COOP_WSTR_HEX);
    if &buf[wstr_off..wstr_off + wstr.len()] != wstr.as_slice()
        && buf[wstr_off..wstr_off + wstr.len()].iter().any(|&b| b != 0)
    {
        bail!(
            "Code cave at 0x{:08X} is non-zero in {}",
            ENHANCED_COOP_WSTR_VA,
            exe_path.display()
        );
    }

    let jp_push_off = va_to_text_off(JOIN_GAME_PORT_PUSH_VA)?;
    if buf[jp_push_off] != 0x68 || buf[jp_push_off + 3..jp_push_off + 5] != [0, 0] {
        bail!(
            "Unexpected bytes at 0x{:08X} for join port immediate: {:02x?}",
            JOIN_GAME_PORT_PUSH_VA,
            &buf[jp_push_off..jp_push_off + 5]
        );
    }

    let sites = get_online_sites();
    for site in &sites {
        let so = va_to_text_off(site.va)?;
        let cur = &buf[so..so + site.orig.len()];
        if cur != site.orig.as_slice() && cur != site.new.as_slice() {
            bail!(
                "Unexpected bytes at 0x{:08X} for online fix: {:02x?} (expected {:02x?})",
                site.va,
                cur,
                site.orig
            );
        }
    }

    buf[cave_off..cave_off + cave.len()].copy_from_slice(&cave);
    buf[wstr_off..wstr_off + wstr.len()].copy_from_slice(&wstr);
    let eff_game_port = match target_ip {
        Some(_) if game_port != 0 => game_port,
        _ => GAME_PORT,
    };
    let jp_off = va_to_text_off(JOIN_GAME_PORT_VA)?;
    buf[jp_off..jp_off + 4].copy_from_slice(&(eff_game_port as u32).to_le_bytes());

    for site in &sites {
        let so = va_to_text_off(site.va)?;
        buf[so..so + site.new.len()].copy_from_slice(&site.new);
    }

    if !is_online_coop_fix_applied(&buf) {
        bail!("Self-verification of online coop fix failed");
    }

    fs::write(exe_path, &buf).with_context(|| format!("Writing {}", exe_path.display()))?;
    crate::scct_log!("  [NET] Applied Online Coop fix to System/splintercell3.exe");
    Ok(())
}

pub fn update_direct_ip_in_exe(
    exe_path: &Path,
    exe_bak_path: &Path,
    target_ip: Option<Ipv4Addr>,
) -> Result<()> {
    apply_online_coop_fix(exe_path, exe_bak_path, target_ip)
}

pub fn update_direct_target_in_exe(
    exe_path: &Path,
    exe_bak_path: &Path,
    target_ip: Option<Ipv4Addr>,
    disco_port: u16,
    game_port: u16,
) -> Result<()> {
    apply_online_coop_fix_with_ports(exe_path, exe_bak_path, target_ip, disco_port, game_port)
}

pub fn save_direct_target_ini(
    ini_path: &Path,
    ip: Option<Ipv4Addr>,
    disco_port: u16,
    game_port: u16,
) -> Result<()> {
    let content = match ip {
        Some(addr) => format!(
            "[Online]\nEnabled = 1\nHostIP = {}\nHostPort = {}\nHostGamePort = {}\n",
            addr, disco_port, game_port
        ),
        None => "[Online]\nEnabled = 0\nHostIP = \nHostPort = \nHostGamePort = \n".to_string(),
    };
    fs::write(ini_path, content)?;
    Ok(())
}

pub fn save_direct_ip_ini(ini_path: &Path, ip: Option<Ipv4Addr>) -> Result<()> {
    save_direct_target_ini(ini_path, ip, DISCOVERY_PORT, GAME_PORT)
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
        let call_bytes = make_call(HOOK_SENDTO_STR, ONLINE_CAVE_VA, 6);
        assert_eq!(call_bytes.len(), 6);
        assert_eq!(call_bytes[0], 0xE8);
        assert_eq!(call_bytes[5], 0x90);

        let call_bytes_probe = make_call(HOOK_SENDTO_PROBE, ONLINE_CAVE_VA, 6);
        assert_eq!(call_bytes_probe.len(), 6);
        assert_eq!(call_bytes_probe[0], 0xE8);
        assert_eq!(call_bytes_probe[5], 0x90);

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
        assert_eq!(bytes.len(), 120);
        assert_eq!(bytes[ONLINE_CAVE_ENABLED_OFFSET], 0x00);
        assert_eq!(&bytes[ONLINE_CAVE_IP_OFFSET..ONLINE_CAVE_IP_OFFSET + 4], &[0, 0, 0, 0]);
        assert_eq!(&bytes[ONLINE_CAVE_PORT_OFFSET..ONLINE_CAVE_PORT_OFFSET + 2], &[0x23, 0x8C]);

        // Verify exit jump targets jump directly to pop eax (offset 0x74)
        assert_eq!(bytes[0x23], 0x74);
        assert_eq!(bytes[0x24], 0x4F);
        assert_eq!(bytes[0x2F], 0x75);
        assert_eq!(bytes[0x30], 0x43);
        assert_eq!(bytes[0x35], 0x74);
        assert_eq!(bytes[0x36], 0x06);
        assert_eq!(bytes[0x3B], 0x75);
        assert_eq!(bytes[0x3C], 0x37);

        // Verify stack offsets for replicated sendto
        assert_eq!(&bytes[0x50..0x54], &[0xFF, 0x74, 0x24, 0x24]);
        assert_eq!(bytes[0x54], 0x52);
        assert_eq!(&bytes[0x55..0x59], &[0xFF, 0x74, 0x24, 0x24]);
        assert_eq!(&bytes[0x59..0x5D], &[0xFF, 0x74, 0x24, 0x24]);
        assert_eq!(&bytes[0x5D..0x61], &[0xFF, 0x74, 0x24, 0x24]);
        assert_eq!(&bytes[0x61..0x65], &[0xFF, 0x74, 0x24, 0x24]);
    }

    #[test]
    fn test_socket_cave_jump_targets() {
        let net_cave = decode_hex(NET_CAVE_HEX);
        assert_eq!(net_cave.len(), 730);
        // Ensure RecvFromWrapper in NET_CAVE no longer filters sender port == 9100
        assert_eq!(&net_cave[0x1D5..0x1DD], &[0x90; 8]);

        let bytes = decode_hex(SOCKET_CAVE_HEX);
        assert_eq!(bytes.len(), 1242);
        assert!(SOCKET_CAVE_VA + (bytes.len() as u32) < 0x110B7000);

        // Hook 1: Discovery Socket (0x110B67C0)
        assert_eq!(bytes[7], 0x74);
        assert_eq!(bytes[8], 0x0D);
        assert_eq!(&bytes[22..28], &[0xFF, 0x25, 0xAC, 0x76, 0x0B, 0x11]);

        // Hook 2: Discovery Bind (0x110B67E0 -> short jmp +0x6E to 0x110B6850)
        assert_eq!(&bytes[0x20..0x22], &[0xEB, 0x6E]);

        // Hook 3: Quazal Socket (0x110B6800)
        assert_eq!(bytes[0x40 + 7], 0x74);
        assert_eq!(bytes[0x40 + 8], 0x0D);
        assert_eq!(&bytes[0x40 + 22..0x40 + 28], &[0xFF, 0x25, 0xB8, 0x76, 0x0B, 0x11]);

        // Hook 4: Quazal Bind (0x110B6820 -> short jmp +0x70 to 0x110B6892)
        assert_eq!(&bytes[0x60..0x62], &[0xEB, 0x70]);

        // HookDiscoveryBindImpl at 0x110B6850 (+0x90): mov eax, [esp+8]
        let bind_impl_off = (HOOK_DISCOVERY_BIND_ANY - SOCKET_CAVE_VA) as usize;
        assert_eq!(&bytes[bind_impl_off..bind_impl_off + 4], &[0x8B, 0x44, 0x24, 0x08]);

        // HookQuazalBindImpl at 0x110B6892: push esi; mov esi, ecx
        let qbind_impl_off = (HOOK_QUAZAL_BIND_IMPL - SOCKET_CAVE_VA) as usize;
        assert_eq!(&bytes[qbind_impl_off..qbind_impl_off + 3], &[0x56, 0x89, 0xCE]);

        // HookQuazalPoll at 0x110B6920: cmp byte ptr ds:[0x110B6760], 0
        let poll_off = (HOOK_QUAZAL_POLL - SOCKET_CAVE_VA) as usize;
        assert_eq!(
            &bytes[poll_off..poll_off + 7],
            &[0x80, 0x3D, 0x60, 0x67, 0x0B, 0x11, 0x00]
        );

        // HookDiscoveryRecvFrom at 0x110B69A2: cmp byte ptr ds:[0x110B6760], 0
        let rf_off = (HOOK_DISCOVERY_RECVFROM - SOCKET_CAVE_VA) as usize;
        assert_eq!(
            &bytes[rf_off..rf_off + 7],
            &[0x80, 0x3D, 0x60, 0x67, 0x0B, 0x11, 0x00]
        );

        // HookQuazalWSASendTo at 0x110B6A52: cmp byte ptr ds:[0x110B6760], 0
        let wsa_off = (HOOK_QUAZAL_WSASENDTO - SOCKET_CAVE_VA) as usize;
        assert_eq!(
            &bytes[wsa_off..wsa_off + 7],
            &[0x80, 0x3D, 0x60, 0x67, 0x0B, 0x11, 0x00]
        );

        // HookBrowseReplyUrl at 0x110B6AD5: push ebx; push esi; push edi; sub esp, 0x20
        let br_off = (HOOK_BROWSE_REPLY_URL - SOCKET_CAVE_VA) as usize;
        assert_eq!(
            &bytes[br_off..br_off + 6],
            &[0x53, 0x56, 0x57, 0x83, 0xEC, 0x20]
        );
    }

    #[test]
    fn test_direct_ip_ini() {
        let dir = std::env::temp_dir();
        let ini_path = dir.join("test_direct_ip.ini");

        let test_ip = Ipv4Addr::new(82, 165, 45, 112);
        save_direct_target_ini(&ini_path, Some(test_ip), 2380, 2383).unwrap();
        let loaded = load_direct_ip_ini(&ini_path);
        assert_eq!(loaded, Some(test_ip));

        save_direct_ip_ini(&ini_path, None).unwrap();
        let cleared = load_direct_ip_ini(&ini_path);
        assert_eq!(cleared, None);

        let _ = fs::remove_file(ini_path);
    }

    #[test]
    fn test_apply_online_coop_fix() {
        let p1 = Path::new("../clean_scct_files/Tom Clancy's Splinter Cell Chaos Theory/System/splintercell3.exe");
        let p2 = Path::new("../../clean_scct_files/Tom Clancy's Splinter Cell Chaos Theory/System/splintercell3.exe");
        let clean_exe = if p1.exists() {
            p1
        } else if p2.exists() {
            p2
        } else {
            return;
        };

        let dir = std::env::temp_dir();
        let test_exe = dir.join("test_scct3_online.exe");
        let test_bak = dir.join("test_scct3_online.exe.bak");

        let _ = fs::copy(clean_exe, &test_exe);

        let test_ip = Ipv4Addr::new(109, 38, 141, 172);
        apply_online_coop_fix_with_ports(&test_exe, &test_bak, Some(test_ip), 2380, 2383).unwrap();

        let buf = fs::read(&test_exe).unwrap();
        assert!(is_online_coop_fix_applied(&buf));
        assert_eq!(get_direct_ip_from_exe(&buf), Some(test_ip));
        let jp_off = va_to_text_off(JOIN_GAME_PORT_VA).unwrap();
        assert_eq!(&buf[jp_off..jp_off + 4], &2383u32.to_le_bytes());
        let dp_off = va_to_text_off(CAVE_ONLINE_PORT_VA).unwrap();
        assert_eq!(&buf[dp_off..dp_off + 2], &2380u16.to_be_bytes());

        // Verify "ENHANCED COOP\0" UTF-16LE string and MainMenuCoop button site
        let wstr_off = va_to_text_off(ENHANCED_COOP_WSTR_VA).unwrap();
        let expected_wstr: Vec<u8> = "ENHANCED COOP\0"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert_eq!(&buf[wstr_off..wstr_off + expected_wstr.len()], expected_wstr.as_slice());
        let caption_site_off = va_to_text_off(HOOK_MAIN_MENU_COOP_LAN_CAPTION).unwrap();
        assert_eq!(
            &buf[caption_site_off..caption_site_off + 10],
            &[0x8B, 0x4E, 0x48, 0x68, 0xA0, 0x6C, 0x0B, 0x11, 0xEB, 0x15]
        );

        // Test clearing IP resets ports back to defaults (9100 / 9103)
        apply_online_coop_fix(&test_exe, &test_bak, None).unwrap();
        let buf2 = fs::read(&test_exe).unwrap();
        assert!(is_online_coop_fix_applied(&buf2));
        assert_eq!(get_direct_ip_from_exe(&buf2), None);
        assert_eq!(&buf2[jp_off..jp_off + 4], &(GAME_PORT as u32).to_le_bytes());
        assert_eq!(&buf2[dp_off..dp_off + 2], &DISCOVERY_PORT.to_be_bytes());

        let _ = fs::remove_file(test_exe);
        let _ = fs::remove_file(test_bak);
    }
}



