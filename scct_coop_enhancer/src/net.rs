use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

pub const PE_IMAGE_BASE: u32 = 0x10900000;
pub const PE_TEXT_RVA: u32 = 0x00001000;
pub const PE_TEXT_RAW_OFF: u32 = 0x00001000;
pub const PE_TEXT_RAW_SIZE: u32 = 0x007B6000;
pub const PE_TEXT_PATCHED_VSIZE: u32 = 0x007B6000;
pub const PE_DATA_PATCHED_VSIZE: u32 = 0x001A3000;
pub const PE_TEXT_VANILLA_VSIZE: u32 = 0x007B544A;
pub const PE_DATA_VANILLA_VSIZE: u32 = 0x001A2389;
pub const G_LAN_PEER_VA: u32 = 0x113303A0;
/// Optional explicit local IPv4 bind address (network byte order) injected by the launcher into `.data` `.bss`.
/// `0` = Auto (all adapters: bind `0.0.0.0`, fan out `:9100` LAN broadcasts on all UP non-loopback non-APIPA interfaces).
/// Non-zero = bind `:9100`/`:9103`, advertise `StationURL`, and broadcast strictly on this adapter (plus same-PC unicast).
#[cfg_attr(not(windows), allow(dead_code))]
pub const G_LOCAL_BIND_IP_VA: u32 = 0x113303A4;
#[cfg_attr(not(windows), allow(dead_code))]
pub const G_LAST_9103_KEEPALIVE_VA: u32 = 0x113303E0;
#[cfg_attr(not(windows), allow(dead_code))]
pub const G_LAST_9100_KEEPALIVE_VA: u32 = 0x113303E4;

pub const NET_CAVE_VA: u32 = 0x110B6450;
pub const NET_CAVE_HEX: &str = "\
e96b0800009083ec2831c089e7b90a000000fcf3abc7042402000035a1a00333\
1185c07505b80808080889442404c7442420100000006a116a026a02ff15ac76\
0b1189c683feff744289e06a105056ff1560760b1185c0752b8d4c24208d4424\
10515056ff15bc760b1185c075168b44241485c0740e3c7f740a663da9fe7404\
8944242456ff156c760b118b44242483c4285d5f5e5a595bc3608b4c244c83f9\
017e758d7c245ce854ffffff85c0741489fe89caf606017405394608744083c6\
4c4a75f0f6070174118b470885c0740a3c7f7406663da9fe753e8d774c8d51ff\
f6060174118b460885c0740a3c7f7406663da9fe750883c64c4a75e4eb1a39fe\
7416b9130000008b078b168917890683c70483c6044975ef618d4424748d4c24\
44e9aa54e4ff85c074738b680c6085ed7460837d0000745ae94807000090e8bd\
feffff85c074128d75048b0e85c974093901743683c604ebf18b4d008b0185c0\
740a3c7f7406663da9fe75268d75048b0e85c9741d8b0185c0740a3c7f740666\
3da9fe750583c604ebe58b5500894d008916618b450031dbe93af3d2ffe928f4\
d2ffff742418ff742418ff742418ff742418ff742418ff742418ff1580760b11\
83f8407c3151528b4c241c85c9742566833902751f90909090909090908b5104\
85d27410909090909083faff74068915a00333115a59c21800a1a003331185c0\
741e50ff15b0760b1185c074138d5764e80c0000008d97e5000000e801000000\
c389c6b9100000008a1e881a84db740946424975f3c642ff00c36089dfe8b7ff\
ffff618b44246c6a20e9d549a6ff6089f7e8a3ffffff6183c4248b36e9a94ea6\
ff56575389ce8b7c2410e93d06000090909090906a1057ffb68c000000ff15c0\
760b1183f8ff751f895f046a1057ffb68c000000ff15c0760b1183f8ff75085b\
5f5e30c0c20400c706010000006a1089e05057ffb68c000000ff15bc760b1183\
c404e9f50500009090578d4e08e80e6bcfff5b5f5eb001c20400";

pub const HOOK1_GET_LOCAL_ADAPTER_IP: u32 = 0x110B64E9;
pub const HOOK2_QUAZAL_INTERFACE_TABLE: u32 = 0x110B6576;
pub const HOOK3_ON_SESSION_INFO: u32 = 0x110B668A;
pub const HOOK4_ON_SESSION_ADDRESSES: u32 = 0x110B669E;

pub const SOCKET_CAVE_VA: u32 = 0x110B67C0;
pub const HOOK_DISCOVERY_SOCKET: u32 = 0x110B67C0;
pub const HOOK_DISCOVERY_BIND: u32 = 0x110B67E0;
pub const HOOK_QUAZAL_SOCKET: u32 = 0x110B6800;
pub const HOOK_QUAZAL_BIND: u32 = 0x110B6820;
/// Discovery bind implementation: checks UDP port 9100, disables `SIO_UDP_CONNRESET`,
/// handles primed sockets, and forces `INADDR_ANY` (`0.0.0.0`) so multi-NIC / WSL machines
/// route and receive on all interfaces.
#[cfg(test)]
pub const HOOK_DISCOVERY_BIND_ANY: u32 = 0x110B6850;
#[cfg(test)]
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
00e9a1040000909090909090ff25c0760b115689ce8b868c000000e807030000\
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
760b11ebaa83f8407c258b4c241485c9741d6683390275178b510485d2741090\
9090909083faff74068915a0033311c21800803d60670b110074748b44241885\
c0746c66817802238c75648b500483faff740485d275588b0d83670b1185c974\
4e0fb7158e670b1185d274438b44240885c0743bc1e21066ba020083ec108914\
24894c2404c744240800000000c744240c0000000089e18b5424146a10516a00\
ff30ff700452e9e100000090909090e9de0200009053565783ec2089ce89fb89\
e1e8da67cfff31c08944241089442414894424188944241c31ff85db742b8b4b\
2885c9742489e050e873bccdff84c074188b44240485c074109090909083f8ff\
740789c7a3a0033311803d60670b1100743ca183670b1185c0750689f885c074\
5d0fb715d67eb51085d27505ba8f23000086f266c70424020066895424028944\
240489e05089f1e884bfcdffeb3085ff742c89f1e897b6cdff6685c07505b88f\
23000086e066c7042402006689442402897c240489e05089f1e852bfcdff8b06\
83c4205f5e5bc3e9b9010000ff15a8760b1183c41085c07818833da403331100\
740f8b54241085d27402890231c0c22400e9dc01000090909090909090909090\
83f8ff74588b0d83670b1185c9744e0fb715d67eb51085d2744386f2c1e21066\
ba020083ec14891424894c2404c744240800000000c744240c00000000c74424\
10ffff000089e18d5424106a10516a006a025250ff15a8760b1183c414c383f8\
ff74568b0d83670b1185c9744c0fb7158e670b1185d27441c1e21066ba020083\
ec14891424894c2404c744240800000000c744240c00000000c7442410534350\
4b89e18d5424106a10516a006a045250ff15a8760b1183c414c3";

/// Multi-NIC LAN & Adapter-Bind Extension Cave (`0x110B6CC0..0x110B6FDD`).
/// Leaves `ENHANCED_COOP_WSTR_VA` (`0x110B6CA0..0x110B6CBC`) and `0x110B7000` (`.rdata`) untouched.
pub const MULTI_NIC_LAN_CAVE_VA: u32 = 0x110B6CC0;
#[cfg(test)]
pub const MULTI_NIC_PROBE_VA: u32 = 0x110B6CC0;
#[cfg(test)]
pub const MULTI_NIC_HOOK2_VA: u32 = 0x110B6CD5;
#[cfg(test)]
pub const MULTI_NIC_QBIND_SETIP_VA: u32 = 0x110B6CFC;
#[cfg(test)]
pub const MULTI_NIC_QBIND_FINISH_VA: u32 = 0x110B6D0C;
#[cfg(test)]
pub const MULTI_NIC_DISCO_BIND_VA: u32 = 0x110B6D27;
#[cfg(test)]
pub const MULTI_NIC_PREP_SOCKET_VA: u32 = 0x110B6D65;
#[cfg(test)]
pub const MULTI_NIC_WSASENDTO_TAIL_VA: u32 = 0x110B6DB2;

pub const MULTI_NIC_LAN_CAVE_HEX: &str = "\
a1a403331185c07401c3535152565755e981f7ffffa1a403331185c0740f8b4d\
00890131c0894504e9f5f8ffff837d04000f8597f8ffffe9e6f8ffff8b5f04a1\
a4033311894704e9b8f9ffffa1a403331185c0750a39470475089385c0740389\
4704e9f2f9ffff8b4424088b15a403331189500485d20f8450fbffffff74240c\
50ff74240cff15c0760b1183f8ff75108b442408c7400400000000e92cfbffff\
31c0c20c0083f8ff74475389c383ec0831c0890424894424048d4c240489e250\
505150506a0452680c00009853ff15d0760b11c704240100000089e26a04526a\
0468ffff000053ff15b4760b1183c4085bc3803d60670b1100752c8b44241885\
c0742466817802238c751c8b500483faff740485d27510837c240c007409837c\
2408007402eb35ff25c4760b11894de08b4d0c8d55dc6a10526a00ff31ff7104\
50ff15a8760b11c38d55fc6a04525068ffff000053ff15b4760b11c35589e581\
ecf4040000535657a1a403331185c07523c745ec100000008d4dec8d55cc5152\
ff7508ff15bc760b1185c075058b45d0eb0231c08945f831c0c745dc0200238c\
8945e48945e8c745cc0200238c8945d48945d8c745fc010000008945ec50508d\
4dec5168c00400008d950cfbffff525050687f740440ff7508ff15d0760b1185\
c00f852a0100008b4dec81f9c00400007605b9c00400008db50cfbffff8d3c0e\
8d464c39f80f87e70000008a06a8010f84d5000000a8040f85cd0000008b4608\
85c00f84c20000003c7f0f84ba000000663da9fe0f84b00000008b563885d274\
0a89c321d3f7d209d3eb0383cbff8945f4895df03b45f8740a89c18b4508e8ca\
feffff837df80074188b45f43b45f8757989d98b4508e8b2feffffc645fc02eb\
6983fbff740a89d98b4508e89dfeffff6a116a026a02ff15ac760b1183f8ff74\
4989c36a0458e89dfeffff6a2058e895feffff8b45f48945d08d55cc6a105253\
ff15c0760b1185c0751983c9ff89d8e859feffff8b4df083f9ff740789d8e84a\
feffff53ff156c760b1183c64ce90effffff807dfc0275198b551485d274078b\
4d0c8b09890a31c05f5e5b89ec5dc224005f5e5b89ec5dff25c4760b11";

pub const HOOK_SITE_DISCOVERY_SOCKET: u32 = 0x10EFBFF9;
pub const HOOK_SITE_DISCOVERY_BIND: u32 = 0x10EFC0A3;
pub const HOOK_SITE_DISCOVERY_BIND_IP: u32 = 0x10EFC109;
pub const HOOK_SITE_QUAZAL_SOCKET: u32 = 0x10DE6490;
pub const HOOK_SITE_QUAZAL_POLL: u32 = 0x10DE53B0;
pub const HOOK_SITE_QUAZAL_WSASENDTO: u32 = 0x10DE65CA;
pub const HOOK_SITE_BROWSE_REPLY_URL: u32 = 0x10DC36CE;
/// `SimStation::CheckSimulationChecksum` (`0x10DF8750`): called by `SyncEngine::Step` (`0x10DF414A`).
/// Verifies simulation lockstep synchronization between Host and Guest.
pub const HOOK_SITE_CHECK_SIM_CHECKSUM: u32 = 0x10DF8750;
pub const SIM_CHECKSUM_ORIG: &[u8] = &[0x6A, 0x05, 0xE8, 0xC9, 0xFE, 0xFF, 0xFF, 0xC3];
pub const SIM_CHECKSUM_HOOK_BYTES: &[u8] = &[0xE9, 0x8B, 0xE8, 0x2B, 0x00, 0x90, 0x90, 0x90];

/// Code cave in .text (`0x110B6FE0..0x110B7000`, 32 bytes) for Trace Mode desync bypass:
/// runs the real `0x10DF8620(5)` check, flags `0x11330400 = 1` & increments `[0x11330404]`
/// on mismatch so the diagnostic dump still fires, then returns `al = 1` so gameplay continues.
pub const SIM_CHECKSUM_CAVE_VA: u32 = 0x110B6FE0;
pub const CAVE_DESYNC_FLAG_VA: u32 = 0x11330400;
pub const CAVE_DESYNC_COUNT_VA: u32 = 0x11330404;
pub const STARTUP_CHECKSUM_BYPASS_CAVE_BYTES: [u8; 32] = [
    0x6A, 0x05,                               // push 5
    0xE8, 0x39, 0x16, 0xD4, 0xFF,             // call 0x10DF8620
    0x84, 0xC0,                               // test al, al
    0x75, 0x0D,                               // jne 0x110B6FF8
    0xFF, 0x05, 0x04, 0x04, 0x33, 0x11,       // inc dword ptr ds:[0x11330404]
    0xC6, 0x05, 0x00, 0x04, 0x33, 0x11, 0x01, // mov byte ptr ds:[0x11330400], 1
    0xB0, 0x01,                               // mov al, 1
    0xC3,                                     // ret
    0x90, 0x90, 0x90, 0x90, 0x90,             // nop x 5
];

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
#[cfg(any(windows, test))]
pub const CAVE_ONLINE_ENABLED_VA: u32 = ONLINE_CAVE_VA + ONLINE_CAVE_ENABLED_OFFSET as u32;
#[cfg(any(windows, test))]
pub const CAVE_ONLINE_IP_VA: u32 = ONLINE_CAVE_VA + ONLINE_CAVE_IP_OFFSET as u32;
#[cfg(any(windows, test))]
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
pub const ENHANCED_COOP_WSTR_HEX: &str = "45004e00480041004e00430045004400200043004f004f0050000000";
/// `push 0x0000238F` (`9103`) immediate used to format `prudp:/address=%s;port=%d` when joining Coop.
pub const JOIN_GAME_PORT_PUSH_VA: u32 = 0x10B57ED5;
pub const JOIN_GAME_PORT_VA: u32 = 0x10B57ED6;
/// `UGameEngine::SetPause` (`0x10A3D58B..0x10A3D596`): `SetLocalPlayerReady(0, 1)` call
/// (`push 1; push 0; call 0x1095da20; add esp, 8`) run when losing window activation (Alt-Tab)
/// as a ready Co-op lobby client. Replaced with 12 `NOP`s so Alt-Tabbing does not unready.
pub const HOOK_SETPAUSE_LOBBY_UNREADY: u32 = 0x10A3D58B;
pub const SETPAUSE_LOBBY_UNREADY_ORIG_HEX: &str = "6a016a00e88c04f2ff83c408";
pub const SETPAUSE_LOBBY_UNREADY_NOP_LEN: usize = 12;
/// Co-op pause menu `IsPlayerReady(bool remote)` (`0x109639E0`): returns `[player + 0x8F]` (ready flag)
/// of the local (`arg = 0`) or remote (`arg = 1`) player. Its only 6 callers are in the in-game ESC
/// pause menu (`0x10B2934A`/`0x10B29448` gate QuickSave/QuickLoad behind "WaitRemote" popups;
/// `0x10B29D61..0x10B29E7C` enable `B_ResumeGame` only when both are ready). Replaced with
/// `mov eax, 1; ret` so both players always count as ready.
pub const HOOK_PAUSE_IS_PLAYER_READY: u32 = 0x109639E0;
pub const PAUSE_IS_PLAYER_READY_ORIG_HEX: &str = "a19c551f1183ec28";
pub const PAUSE_IS_PLAYER_READY_NEW_HEX: &str = "b801000000c39090";

/// `AEAIPawn::[vt+0x2BC]` (`0x10C18480`) render-visibility tick cull gate at VA `0x10C1852C`
/// (immediately after once-only static `FName` initialization, with zero `.reloc` entries):
/// returns `1` to skip `AEPawn::Tick` (`0x10B89DD0`) & pattern updates when `[esi+0x424] & 4`,
/// `LastRenderTime ([esi+0x50]) == 0.0f`, or `TimeSeconds - LastRenderTime > 1.0f`.
/// Patching with `xor eax, eax; pop esi; ret` disables visibility-gated AI tick culling.
pub const HOOK_AI_VISIBILITY_CULL: u32 = 0x10C1852C;
pub const AI_VISIBILITY_CULL_ORIG: &[u8] = &[0x80, 0x7E, 0x4C, 0x07, 0x74, 0x61, 0x8B, 0x8E];
pub const AI_VISIBILITY_CULL_PATCHED: &[u8] = &[0x33, 0xC0, 0x5E, 0xC3, 0x90, 0x90, 0x90, 0x90];

pub struct PatchSite {
    pub va: u32,
    pub orig: Vec<u8>,
    pub new: Vec<u8>,
    #[allow(dead_code)]
    pub desc: &'static str,
}

/// Returns the 11 Multi-NIC adapter promotion, socket/bind `0.0.0.0`, and LAN sender IP hook sites.
pub fn get_lan_bind_sites() -> Vec<PatchSite> {
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
    ]
}

/// Returns the 5 Direct-IP broadcast replication & NAT traversal hooks.
pub fn get_nat_direct_sites() -> Vec<PatchSite> {
    vec![
        PatchSite {
            va: HOOK_SITE_QUAZAL_POLL,
            orig: decode_hex("8b8194000000"),
            new: make_jmp(HOOK_SITE_QUAZAL_POLL, HOOK_QUAZAL_POLL, 6),
            desc: "Quazal SocketDriver::HasRecvCompleted -> 3s CGNAT keepalive",
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
    ]
}

pub fn get_menu_redirect_site() -> PatchSite {
    PatchSite {
        va: HOOK_COOP_ONLINE_MENU,
        orig: decode_hex("8b5640c68288000000018b4e408b016a01ff503c8b4e14b0015f8841145ec20400"),
        new: make_jmp(HOOK_COOP_ONLINE_MENU, COOP_LAN_MENU_DEST, 33),
        desc: "P_MenuCoop Online button -> redirect to LAN room list",
    }
}

pub fn get_menu_caption_site() -> PatchSite {
    PatchSite {
        va: HOOK_MAIN_MENU_COOP_LAN_CAPTION,
        orig: decode_hex("6a0153536880430d1168c82c0e116820f40d11e8120918008b4e4883c41850"),
        new: decode_hex("8b4e4868a06c0b11eb15909090909090909090909090909090909090909090"),
        desc: "MainMenuCoop LAN button -> display 'ENHANCED COOP'",
    }
}

pub fn get_lobby_alttab_unready_site() -> PatchSite {
    PatchSite {
        va: HOOK_SETPAUSE_LOBBY_UNREADY,
        orig: decode_hex(SETPAUSE_LOBBY_UNREADY_ORIG_HEX),
        new: vec![0x90; SETPAUSE_LOBBY_UNREADY_NOP_LEN],
        desc: "UGameEngine::SetPause: prevent coop lobby client unreadying on Alt-Tab",
    }
}

pub fn get_net_sites() -> Vec<PatchSite> {
    let mut sites = get_lan_bind_sites();
    sites.extend(get_nat_direct_sites().into_iter().take(3));
    sites
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

/// Reads the `.text` and `.data` VirtualSize values from a PE executable.
pub fn read_pe_vanilla_vsizes(pe: &[u8]) -> Result<(u32, u32)> {
    let secs = pe_section_headers(pe)?;
    let text_entry = *secs.get(b".text".as_slice()).context("Missing .text section")?;
    let data_entry = *secs.get(b".data".as_slice()).context("Missing .data section")?;
    let text_vs = u32::from_le_bytes(pe[text_entry + 8..text_entry + 12].try_into()?);
    let data_vs = u32::from_le_bytes(pe[data_entry + 8..data_entry + 12].try_into()?);
    Ok((text_vs, data_vs))
}

fn pe_has_patched_vsizes(pe: &[u8]) -> bool {
    read_pe_vanilla_vsizes(pe)
        .is_ok_and(|(text_vs, data_vs)| text_vs >= PE_TEXT_PATCHED_VSIZE && data_vs >= PE_DATA_PATCHED_VSIZE)
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

    let multi_cave = decode_hex(MULTI_NIC_LAN_CAVE_HEX);
    let so_multi = match va_to_text_off(MULTI_NIC_LAN_CAVE_VA) {
        Ok(off) => off,
        Err(_) => return false,
    };
    if pe_bytes.len() < so_multi + multi_cave.len()
        || &pe_bytes[so_multi..so_multi + multi_cave.len()] != multi_cave.as_slice()
    {
        return false;
    }

    if !is_sim_checksum_site_valid(pe_bytes) {
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
    let text_vs = u32::from_le_bytes(
        pe_bytes[text_entry + 8..text_entry + 12]
            .try_into()
            .unwrap(),
    );
    let data_vs = u32::from_le_bytes(
        pe_bytes[data_entry + 8..data_entry + 12]
            .try_into()
            .unwrap(),
    );
    text_vs >= PE_TEXT_PATCHED_VSIZE && data_vs >= PE_DATA_PATCHED_VSIZE
}

pub fn apply_lan_networking_fix(exe_path: &Path, exe_bak_path: &Path) -> Result<()> {
    if !exe_bak_path.exists() {
        if !exe_path.exists() {
            bail!("Missing executable: {}", exe_path.display());
        }
        let cur_data =
            fs::read(exe_path).with_context(|| format!("Reading {}", exe_path.display()))?;
        if is_lan_and_zerotier_fix_applied(&cur_data) {
            crate::scct_log!(
                "  [NET] Multi-NIC LAN & STUN fix is already present in splintercell3.exe"
            );
            crate::patcher::patch_exe_fixes(exe_path, exe_bak_path)?;
            return Ok(());
        }
        fs::copy(exe_path, exe_bak_path).with_context(|| {
            format!(
                "Backing up {} to {}",
                exe_path.display(),
                exe_bak_path.display()
            )
        })?;
        crate::scct_log!(
            "  [BAK] Backed up vanilla EXE -> {}",
            exe_bak_path.display()
        );
    }

    let preserve_bypass = exe_path.exists()
        && fs::read(exe_path)
            .ok()
            .is_some_and(|cur| is_startup_checksum_bypass_patched(&cur));

    let mut buf =
        fs::read(exe_bak_path).with_context(|| format!("Reading {}", exe_bak_path.display()))?;

    let secs = pe_section_headers(&buf)?;
    let text_off = *secs
        .get(b".text".as_slice())
        .context("Missing .text section")?;
    let data_off = *secs
        .get(b".data".as_slice())
        .context("Missing .data section")?;

    let text_vs = u32::from_le_bytes(buf[text_off + 8..text_off + 12].try_into()?);
    let text_rva = u32::from_le_bytes(buf[text_off + 12..text_off + 16].try_into()?);
    let text_rs = u32::from_le_bytes(buf[text_off + 16..text_off + 20].try_into()?);
    let text_ro = u32::from_le_bytes(buf[text_off + 20..text_off + 24].try_into()?);

    if (text_rva, text_rs, text_ro) != (PE_TEXT_RVA, PE_TEXT_RAW_SIZE, PE_TEXT_RAW_OFF) {
        bail!("Unexpected .text layout - not retail splintercell3.exe");
    }

    let data_vs = u32::from_le_bytes(buf[data_off + 8..data_off + 12].try_into()?);
    let data_rva = u32::from_le_bytes(buf[data_off + 12..data_off + 16].try_into()?);
    if !(data_rva + PE_IMAGE_BASE <= G_LAN_PEER_VA
        && G_LAN_PEER_VA < data_rva + PE_IMAGE_BASE + 0x1A3000)
    {
        bail!("Unexpected .data layout");
    }

    let cave = decode_hex(NET_CAVE_HEX);
    let cave_off = va_to_text_off(NET_CAVE_VA)?;
    if &buf[cave_off..cave_off + cave.len()] != cave.as_slice()
        && buf[cave_off..cave_off + cave.len()].iter().any(|&b| b != 0)
    {
        bail!(
            "Code cave at 0x{:08X} is non-zero in {}",
            NET_CAVE_VA,
            exe_bak_path.display()
        );
    }

    let sock_cave = decode_hex(SOCKET_CAVE_HEX);
    let sock_cave_off = va_to_text_off(SOCKET_CAVE_VA)?;
    if &buf[sock_cave_off..sock_cave_off + sock_cave.len()] != sock_cave.as_slice()
        && buf[sock_cave_off..sock_cave_off + sock_cave.len()]
            .iter()
            .any(|&b| b != 0)
    {
        bail!(
            "Code cave at 0x{:08X} is non-zero in {}",
            SOCKET_CAVE_VA,
            exe_bak_path.display()
        );
    }

    let multi_cave = decode_hex(MULTI_NIC_LAN_CAVE_HEX);
    let multi_cave_off = va_to_text_off(MULTI_NIC_LAN_CAVE_VA)?;
    if &buf[multi_cave_off..multi_cave_off + multi_cave.len()] != multi_cave.as_slice()
        && buf[multi_cave_off..multi_cave_off + multi_cave.len()]
            .iter()
            .any(|&b| b != 0)
    {
        bail!(
            "Code cave at 0x{:08X} is non-zero in {}",
            MULTI_NIC_LAN_CAVE_VA,
            exe_bak_path.display()
        );
    }

    let sites = get_net_sites();
    for site in &sites {
        let so = va_to_text_off(site.va)?;
        let cur = &buf[so..so + site.orig.len()];
        if cur != site.orig.as_slice() && cur != site.new.as_slice() {
            bail!(
                "Unexpected bytes at 0x{:08X} in {}: {:02x?} (expected {:02x?})",
                site.va,
                exe_bak_path.display(),
                cur,
                site.orig
            );
        }
    }

    buf[cave_off..cave_off + cave.len()].copy_from_slice(&cave);
    buf[sock_cave_off..sock_cave_off + sock_cave.len()].copy_from_slice(&sock_cave);
    buf[multi_cave_off..multi_cave_off + multi_cave.len()].copy_from_slice(&multi_cave);

    let sim_chk_off = va_to_text_off(HOOK_SITE_CHECK_SIM_CHECKSUM)?;
    let sim_cave_off = va_to_text_off(SIM_CHECKSUM_CAVE_VA)?;
    if preserve_bypass {
        patch_startup_checksum_bypass_bytes(&mut buf)?;
    } else {
        if buf.len() >= sim_chk_off + 8 {
            buf[sim_chk_off..sim_chk_off + 8].copy_from_slice(SIM_CHECKSUM_ORIG);
        }
        if buf.len() >= sim_cave_off + 32 {
            buf[sim_cave_off..sim_cave_off + 32].fill(0);
        }
    }
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
    crate::patcher::patch_exe_fixes(exe_path, exe_bak_path)?;
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
        PatchSite {
            va: HOOK_SETPAUSE_LOBBY_UNREADY,
            orig: decode_hex(SETPAUSE_LOBBY_UNREADY_ORIG_HEX),
            new: vec![0x90; SETPAUSE_LOBBY_UNREADY_NOP_LEN],
            desc: "UGameEngine::SetPause: prevent coop lobby client unreadying on Alt-Tab",
        },
    ]
}

fn is_text_patch_applied(pe_bytes: &[u8], va: u32, patched: &[u8]) -> bool {
    let Ok(off) = va_to_text_off(va) else {
        return false;
    };
    pe_bytes.len() >= off + patched.len() && &pe_bytes[off..off + patched.len()] == patched
}

fn patch_text_site_bytes(
    pe_bytes: &mut [u8],
    va: u32,
    orig: &[u8],
    patched: &[u8],
    label: &str,
) -> Result<usize> {
    assert_eq!(orig.len(), patched.len());
    let off = va_to_text_off(va)?;
    if pe_bytes.len() < off + orig.len() {
        bail!("PE image too short for {} patch @ 0x{:08X}", label, va);
    }
    let cur = &pe_bytes[off..off + orig.len()];
    if cur == patched {
        return Ok(off);
    }
    if cur != orig {
        bail!(
            "Unexpected bytes at 0x{:08X} for {}: {:02x?} (expected {:02x?})",
            va,
            label,
            cur,
            orig
        );
    }
    pe_bytes[off..off + patched.len()].copy_from_slice(patched);
    Ok(off)
}

fn revert_text_site_bytes(pe_bytes: &mut [u8], va: u32, orig: &[u8], patched: &[u8]) -> bool {
    assert_eq!(orig.len(), patched.len());
    let Ok(off) = va_to_text_off(va) else {
        return false;
    };
    if pe_bytes.len() < off + patched.len() || &pe_bytes[off..off + patched.len()] != patched {
        return false;
    }
    pe_bytes[off..off + orig.len()].copy_from_slice(orig);
    true
}

fn is_cave_bytes_applied(pe_bytes: &[u8], va: u32, expected: &[u8]) -> bool {
    let Ok(off) = va_to_text_off(va) else {
        return false;
    };
    pe_bytes.len() >= off + expected.len() && &pe_bytes[off..off + expected.len()] == expected
}

fn are_sites_applied(pe_bytes: &[u8], sites: &[PatchSite]) -> bool {
    sites
        .iter()
        .all(|site| is_text_patch_applied(pe_bytes, site.va, &site.new))
}

fn sync_cave_bytes(
    pe_bytes: &mut [u8],
    va: u32,
    expected: &[u8],
    enable: bool,
    label: &str,
) -> Result<bool> {
    let off = va_to_text_off(va)?;
    if pe_bytes.len() < off + expected.len() {
        bail!("PE image too short for {} cave @ 0x{:08X}", label, va);
    }
    let slice = &mut pe_bytes[off..off + expected.len()];
    if enable {
        if slice == expected {
            return Ok(false);
        }
        if slice.iter().any(|&b| b != 0) {
            bail!(
                "Code cave for {} at 0x{:08X} contains unexpected non-zero bytes",
                label,
                va
            );
        }
        slice.copy_from_slice(expected);
        Ok(true)
    } else if slice.iter().any(|&b| b != 0) {
        slice.fill(0);
        Ok(true)
    } else {
        Ok(false)
    }
}

fn sync_sites_bytes(
    pe_bytes: &mut [u8],
    sites: &[PatchSite],
    enable: bool,
    label: &str,
) -> Result<bool> {
    let mut changed = false;
    for site in sites {
        if enable {
            let so = va_to_text_off(site.va)?;
            if pe_bytes.len() < so + site.orig.len() {
                bail!("PE image too short for {} @ 0x{:08X}", label, site.va);
            }
            let cur = &pe_bytes[so..so + site.orig.len()];
            if cur == site.new.as_slice() {
                continue;
            }
            if cur != site.orig.as_slice() {
                bail!(
                    "Unexpected bytes at 0x{:08X} for {}: {:02x?} (expected {:02x?})",
                    site.va,
                    label,
                    cur,
                    site.orig
                );
            }
            pe_bytes[so..so + site.new.len()].copy_from_slice(&site.new);
            changed = true;
        } else if revert_text_site_bytes(pe_bytes, site.va, &site.orig, &site.new) {
            changed = true;
        }
    }
    Ok(changed)
}

/// Returns whether the optional `HOOK_PAUSE_IS_PLAYER_READY` (`0x109639E0`) patch is applied.
pub fn is_pause_always_ready_patched(pe_bytes: &[u8]) -> bool {
    let new = decode_hex(PAUSE_IS_PLAYER_READY_NEW_HEX);
    is_text_patch_applied(pe_bytes, HOOK_PAUSE_IS_PLAYER_READY, &new)
}

/// Patches `IsPlayerReady` (`0x109639E0`) to always return `1` (idempotent).
pub fn patch_pause_always_ready_bytes(pe_bytes: &mut [u8]) -> Result<usize> {
    let orig = decode_hex(PAUSE_IS_PLAYER_READY_ORIG_HEX);
    let new = decode_hex(PAUSE_IS_PLAYER_READY_NEW_HEX);
    patch_text_site_bytes(
        pe_bytes,
        HOOK_PAUSE_IS_PLAYER_READY,
        &orig,
        &new,
        "IsPlayerReady",
    )
}

/// Reverts `IsPlayerReady` (`0x109639E0`) back to vanilla bytes if patched.
pub fn revert_pause_always_ready_bytes(pe_bytes: &mut [u8]) -> bool {
    let orig = decode_hex(PAUSE_IS_PLAYER_READY_ORIG_HEX);
    let new = decode_hex(PAUSE_IS_PLAYER_READY_NEW_HEX);
    revert_text_site_bytes(pe_bytes, HOOK_PAUSE_IS_PLAYER_READY, &orig, &new)
}

/// Returns whether AI visibility tick-culling (`AEAIPawn::vt+0x2BC` @ `0x10C1852C`) is disabled.
pub fn is_ai_visibility_culling_disabled(pe_bytes: &[u8]) -> bool {
    is_text_patch_applied(pe_bytes, HOOK_AI_VISIBILITY_CULL, AI_VISIBILITY_CULL_PATCHED)
}

/// Patches `AEAIPawn::vt+0x2BC` (`0x10C1852C`) to return `0`, disabling visibility tick-culling (idempotent).
pub fn patch_ai_visibility_culling_disabled_bytes(pe_bytes: &mut [u8]) -> Result<usize> {
    patch_text_site_bytes(
        pe_bytes,
        HOOK_AI_VISIBILITY_CULL,
        AI_VISIBILITY_CULL_ORIG,
        AI_VISIBILITY_CULL_PATCHED,
        "AEAIPawn::vt+0x2BC",
    )
}

/// Reverts `AEAIPawn::vt+0x2BC` (`0x10C1852C`) back to vanilla visibility culling bytes.
pub fn revert_ai_visibility_culling_disabled_bytes(pe_bytes: &mut [u8]) -> bool {
    revert_text_site_bytes(
        pe_bytes,
        HOOK_AI_VISIBILITY_CULL,
        AI_VISIBILITY_CULL_ORIG,
        AI_VISIBILITY_CULL_PATCHED,
    )
}

fn is_sim_checksum_site_valid(pe_bytes: &[u8]) -> bool {
    let Ok(sim_chk_off) = va_to_text_off(HOOK_SITE_CHECK_SIM_CHECKSUM) else {
        return false;
    };
    if pe_bytes.len() < sim_chk_off + 8 {
        return false;
    }
    &pe_bytes[sim_chk_off..sim_chk_off + 8] == SIM_CHECKSUM_ORIG
        || is_startup_checksum_bypass_patched(pe_bytes)
}

/// Returns whether the Trace Mode startup checksum disconnect bypass (`0x10DF8750` -> `0x110B6FE0`) is active.
pub fn is_startup_checksum_bypass_patched(pe_bytes: &[u8]) -> bool {
    let (Ok(chk_off), Ok(cave_off)) = (
        va_to_text_off(HOOK_SITE_CHECK_SIM_CHECKSUM),
        va_to_text_off(SIM_CHECKSUM_CAVE_VA),
    ) else {
        return false;
    };
    pe_bytes.len() >= chk_off + 8
        && pe_bytes.len() >= cave_off + 32
        && &pe_bytes[chk_off..chk_off + 8] == SIM_CHECKSUM_HOOK_BYTES
        && pe_bytes[cave_off..cave_off + 32] == STARTUP_CHECKSUM_BYPASS_CAVE_BYTES
}

/// Patches `0x10DF8750` (`SimStation::CheckSimulationChecksum`) to log mismatches without disconnecting (idempotent).
pub fn patch_startup_checksum_bypass_bytes(pe_bytes: &mut [u8]) -> Result<usize> {
    let chk_off = va_to_text_off(HOOK_SITE_CHECK_SIM_CHECKSUM)?;
    let cave_off = va_to_text_off(SIM_CHECKSUM_CAVE_VA)?;
    if pe_bytes.len() < chk_off + 8 || pe_bytes.len() < cave_off + 32 {
        bail!(
            "PE image too short for CheckSimulationChecksum trace bypass @ 0x{:08X}",
            HOOK_SITE_CHECK_SIM_CHECKSUM
        );
    }
    if is_startup_checksum_bypass_patched(pe_bytes) {
        return Ok(chk_off);
    }
    let cur_site = &pe_bytes[chk_off..chk_off + 8];
    if cur_site != SIM_CHECKSUM_ORIG && cur_site != SIM_CHECKSUM_HOOK_BYTES {
        bail!(
            "Unexpected bytes at 0x{:08X} for CheckSimulationChecksum: {:02x?}",
            HOOK_SITE_CHECK_SIM_CHECKSUM,
            cur_site
        );
    }
    let cur_cave = &pe_bytes[cave_off..cave_off + 32];
    if cur_cave.iter().any(|&b| b != 0) && cur_cave != STARTUP_CHECKSUM_BYPASS_CAVE_BYTES {
        bail!(
            "Code cave at 0x{:08X} contains unexpected bytes: {:02x?}",
            SIM_CHECKSUM_CAVE_VA,
            cur_cave
        );
    }
    pe_bytes[cave_off..cave_off + 32].copy_from_slice(&STARTUP_CHECKSUM_BYPASS_CAVE_BYTES);
    pe_bytes[chk_off..chk_off + 8].copy_from_slice(SIM_CHECKSUM_HOOK_BYTES);
    Ok(chk_off)
}

/// Reverts the Trace Mode startup checksum disconnect bypass back to vanilla `SIM_CHECKSUM_ORIG`.
pub fn revert_startup_checksum_bypass_bytes(pe_bytes: &mut [u8]) -> bool {
    if !is_startup_checksum_bypass_patched(pe_bytes) {
        return false;
    }
    let (Ok(chk_off), Ok(cave_off)) = (
        va_to_text_off(HOOK_SITE_CHECK_SIM_CHECKSUM),
        va_to_text_off(SIM_CHECKSUM_CAVE_VA),
    ) else {
        return false;
    };
    pe_bytes[chk_off..chk_off + 8].copy_from_slice(SIM_CHECKSUM_ORIG);
    pe_bytes[cave_off..cave_off + 32].fill(0);
    true
}

/// Enables or disables the CLI-only startup checksum disconnect bypass (`0x10DF8750` -> `0x110B6FE0`) in `exe_path`.
pub fn sync_startup_checksum_bypass_in_exe(exe_path: &Path, enable: bool) -> Result<()> {
    if !exe_path.exists() {
        return Ok(());
    }
    let mut data = fs::read(exe_path).with_context(|| format!("Reading {}", exe_path.display()))?;
    let changed = if enable {
        if !is_startup_checksum_bypass_patched(&data) {
            let off = patch_startup_checksum_bypass_bytes(&mut data)?;
            crate::scct_log!(
                "  [EXE] Patched startup checksum disconnect bypass @ 0x{:06X}",
                off
            );
            true
        } else {
            false
        }
    } else if revert_startup_checksum_bypass_bytes(&mut data) {
        crate::scct_log!("  [EXE] Reverted startup checksum disconnect bypass");
        true
    } else {
        false
    };
    if changed {
        crate::patcher::clear_readonly_if_needed(exe_path);
        fs::write(exe_path, &data).with_context(|| format!("Writing {}", exe_path.display()))?;
    }
    Ok(())
}

/// Returns whether only the `ONLINE_CAVE` template and `JOIN_GAME_PORT` push immediate are valid.
pub fn is_nat_direct_caves_applied(pe_bytes: &[u8]) -> bool {
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
    let jp_off = match va_to_text_off(JOIN_GAME_PORT_PUSH_VA) {
        Ok(off) => off,
        Err(_) => return false,
    };
    pe_bytes.len() >= jp_off + 5
        && pe_bytes[jp_off] == 0x68
        && pe_bytes[jp_off + 3..jp_off + 5] == [0, 0]
}

/// Returns whether the 11 LAN/multi-NIC bind & discovery hooks + caves are applied.
pub fn is_lan_bind_hooks_applied(pe_bytes: &[u8]) -> bool {
    let net_cave = decode_hex(NET_CAVE_HEX);
    let sock_cave = decode_hex(SOCKET_CAVE_HEX);
    let multi_cave = decode_hex(MULTI_NIC_LAN_CAVE_HEX);
    is_cave_bytes_applied(pe_bytes, NET_CAVE_VA, &net_cave)
        && is_cave_bytes_applied(pe_bytes, SOCKET_CAVE_VA, &sock_cave)
        && is_cave_bytes_applied(pe_bytes, MULTI_NIC_LAN_CAVE_VA, &multi_cave)
        && are_sites_applied(pe_bytes, &get_lan_bind_sites())
        && pe_has_patched_vsizes(pe_bytes)
}

/// Returns whether the 5 Direct-IP broadcast replication & NAT traversal hooks + caves are applied.
pub fn is_nat_direct_hooks_applied(pe_bytes: &[u8]) -> bool {
    let sock_cave = decode_hex(SOCKET_CAVE_HEX);
    let multi_cave = decode_hex(MULTI_NIC_LAN_CAVE_HEX);
    is_cave_bytes_applied(pe_bytes, SOCKET_CAVE_VA, &sock_cave)
        && is_cave_bytes_applied(pe_bytes, MULTI_NIC_LAN_CAVE_VA, &multi_cave)
        && is_nat_direct_caves_applied(pe_bytes)
        && are_sites_applied(pe_bytes, &get_nat_direct_sites())
        && pe_has_patched_vsizes(pe_bytes)
}

/// Returns whether the P_MenuCoop "Online" -> LAN menu redirect hook (`0x10B524CA`) is applied.
pub fn is_menu_redirect_patched(pe_bytes: &[u8]) -> bool {
    are_sites_applied(pe_bytes, &[get_menu_redirect_site()])
}

/// Returns whether the MainMenuCoop "ENHANCED COOP" button caption patch (`0x10B4BB86`) is applied.
pub fn is_menu_caption_patched(pe_bytes: &[u8]) -> bool {
    let wstr = decode_hex(ENHANCED_COOP_WSTR_HEX);
    is_cave_bytes_applied(pe_bytes, ENHANCED_COOP_WSTR_VA, &wstr)
        && are_sites_applied(pe_bytes, &[get_menu_caption_site()])
}

/// Returns whether the Alt-Tab coop lobby unready NOP patch (`0x10A3D58B`) is applied.
pub fn is_lobby_alttab_unready_nop_patched(pe_bytes: &[u8]) -> bool {
    are_sites_applied(pe_bytes, &[get_lobby_alttab_unready_site()])
}

pub fn is_online_coop_fix_applied(pe_bytes: &[u8]) -> bool {
    if !is_nat_direct_caves_applied(pe_bytes) {
        return false;
    }
    let wstr = decode_hex(ENHANCED_COOP_WSTR_HEX);
    if !is_cave_bytes_applied(pe_bytes, ENHANCED_COOP_WSTR_VA, &wstr) {
        return false;
    }
    if !are_sites_applied(pe_bytes, &get_online_sites()) {
        return false;
    }
    is_sim_checksum_site_valid(pe_bytes)
}

/// Write the peer IP, discovery port, and gameplay port into the patched executable.
pub fn set_direct_target_in_exe(
    pe_bytes: &mut [u8],
    ip: Option<Ipv4Addr>,
    disco_port: u16,
    game_port: u16,
) -> Result<()> {
    if !is_nat_direct_caves_applied(pe_bytes) {
        bail!("Direct-IP NAT cave is not applied to executable");
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

/// Subset of mod feature flags that modify PE code caves and networking/menu hooks in `splintercell3.exe`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetExeFlags {
    pub lan_bind: bool,
    pub nat_direct: bool,
    pub menu_redirect: bool,
    pub menu_caption: bool,
    pub lobby_alttab_unready_nop: bool,
    pub pause_always_ready: bool,
    pub bypass_checksum_disconnect: bool,
}

fn sync_online_cave_and_port(
    pe_bytes: &mut [u8],
    enable: bool,
    direct_target: Option<(Ipv4Addr, u16, u16)>,
) -> Result<bool> {
    let mut cave = decode_hex(ONLINE_CAVE_HEX);
    let cave_off = va_to_text_off(ONLINE_CAVE_VA)?;
    if pe_bytes.len() < cave_off + cave.len() {
        bail!("PE image too short for ONLINE_CAVE");
    }
    let jp_push_off = va_to_text_off(JOIN_GAME_PORT_PUSH_VA)?;
    let jp_off = va_to_text_off(JOIN_GAME_PORT_VA)?;
    let mut changed = false;

    if enable {
        let (ip, dport, gport) = match direct_target {
            Some((ip, dp, gp)) => (Some(ip), dp, gp),
            None => (None, DISCOVERY_PORT, GAME_PORT),
        };
        write_online_cave_target(&mut cave, ip, dport);
        if &pe_bytes[cave_off..cave_off + cave.len()] != cave.as_slice() {
            if !is_nat_direct_caves_applied(pe_bytes)
                && pe_bytes[cave_off..cave_off + cave.len()].iter().any(|&b| b != 0)
            {
                bail!(
                    "Code cave at 0x{:08X} is non-zero and unrecognized",
                    ONLINE_CAVE_VA
                );
            }
            pe_bytes[cave_off..cave_off + cave.len()].copy_from_slice(&cave);
            changed = true;
        }
        if pe_bytes.len() < jp_push_off + 5
            || pe_bytes[jp_push_off] != 0x68
            || pe_bytes[jp_push_off + 3..jp_push_off + 5] != [0, 0]
        {
            bail!(
                "Unexpected bytes at 0x{:08X} for join port immediate",
                JOIN_GAME_PORT_PUSH_VA
            );
        }
        let eff_game_port = match ip {
            Some(_) if gport != 0 => gport,
            _ => GAME_PORT,
        };
        let port_bytes = (eff_game_port as u32).to_le_bytes();
        if pe_bytes[jp_off..jp_off + 4] != port_bytes {
            pe_bytes[jp_off..jp_off + 4].copy_from_slice(&port_bytes);
            changed = true;
        }
    } else {
        if pe_bytes[cave_off..cave_off + cave.len()].iter().any(|&b| b != 0) {
            pe_bytes[cave_off..cave_off + cave.len()].fill(0);
            changed = true;
        }
        let default_port_bytes = (GAME_PORT as u32).to_le_bytes();
        if pe_bytes.len() >= jp_off + 4 && pe_bytes[jp_off..jp_off + 4] != default_port_bytes {
            pe_bytes[jp_off..jp_off + 4].copy_from_slice(&default_port_bytes);
            changed = true;
        }
    }
    Ok(changed)
}

/// Synchronizes all networking, menu, pause-ready, and checksum-bypass hooks in `pe_bytes` to match `flags`.
/// Returns `Ok(true)` if any bytes in `pe_bytes` were modified.
pub fn sync_net_flags_to_exe_bytes(
    pe_bytes: &mut [u8],
    flags: &NetExeFlags,
    direct_target: Option<(Ipv4Addr, u16, u16)>,
    vanilla_vsizes: Option<(u32, u32)>,
) -> Result<bool> {
    let mut changed = false;

    // 1. Revert disabled hook sites BEFORE zeroing code caves they target.
    if !flags.lan_bind {
        changed |= sync_sites_bytes(pe_bytes, &get_lan_bind_sites(), false, "LAN/multi-NIC hooks")?;
    }
    if !flags.nat_direct {
        changed |= sync_sites_bytes(pe_bytes, &get_nat_direct_sites(), false, "Direct-IP/NAT hooks")?;
    }
    if !flags.menu_redirect {
        changed |= sync_sites_bytes(pe_bytes, &[get_menu_redirect_site()], false, "Online->LAN menu redirect")?;
    }
    if !flags.menu_caption {
        changed |= sync_sites_bytes(pe_bytes, &[get_menu_caption_site()], false, "ENHANCED COOP caption")?;
    }
    if !flags.lobby_alttab_unready_nop {
        changed |= sync_sites_bytes(pe_bytes, &[get_lobby_alttab_unready_site()], false, "Lobby Alt-Tab unready NOP")?;
    }
    if !flags.pause_always_ready {
        changed |= revert_pause_always_ready_bytes(pe_bytes);
    }
    if !flags.bypass_checksum_disconnect {
        changed |= revert_startup_checksum_bypass_bytes(pe_bytes);
    }

    // 2. Sync caves (write enabled caves before enabling sites; zero disabled caves after reverting sites).
    let need_base_caves = flags.lan_bind || flags.nat_direct;
    let net_cave = decode_hex(NET_CAVE_HEX);
    let sock_cave = decode_hex(SOCKET_CAVE_HEX);
    let multi_cave = decode_hex(MULTI_NIC_LAN_CAVE_HEX);
    changed |= sync_cave_bytes(pe_bytes, NET_CAVE_VA, &net_cave, need_base_caves, "NET_CAVE")?;
    changed |= sync_cave_bytes(pe_bytes, SOCKET_CAVE_VA, &sock_cave, need_base_caves, "SOCKET_CAVE")?;
    changed |= sync_cave_bytes(pe_bytes, MULTI_NIC_LAN_CAVE_VA, &multi_cave, need_base_caves, "MULTI_NIC_LAN_CAVE")?;
    changed |= sync_online_cave_and_port(pe_bytes, flags.nat_direct, direct_target)?;

    let wstr = decode_hex(ENHANCED_COOP_WSTR_HEX);
    changed |= sync_cave_bytes(pe_bytes, ENHANCED_COOP_WSTR_VA, &wstr, flags.menu_caption, "ENHANCED_COOP_WSTR")?;

    // 3. Apply enabled hook sites.
    if flags.lan_bind {
        changed |= sync_sites_bytes(pe_bytes, &get_lan_bind_sites(), true, "LAN/multi-NIC hooks")?;
    }
    if flags.nat_direct {
        changed |= sync_sites_bytes(pe_bytes, &get_nat_direct_sites(), true, "Direct-IP/NAT hooks")?;
    }
    if flags.menu_redirect {
        changed |= sync_sites_bytes(pe_bytes, &[get_menu_redirect_site()], true, "Online->LAN menu redirect")?;
    }
    if flags.menu_caption {
        changed |= sync_sites_bytes(pe_bytes, &[get_menu_caption_site()], true, "ENHANCED COOP caption")?;
    }
    if flags.lobby_alttab_unready_nop {
        changed |= sync_sites_bytes(pe_bytes, &[get_lobby_alttab_unready_site()], true, "Lobby Alt-Tab unready NOP")?;
    }
    if flags.pause_always_ready && !is_pause_always_ready_patched(pe_bytes) {
        patch_pause_always_ready_bytes(pe_bytes)?;
        changed = true;
    }
    if flags.bypass_checksum_disconnect && !is_startup_checksum_bypass_patched(pe_bytes) {
        patch_startup_checksum_bypass_bytes(pe_bytes)?;
        changed = true;
    }

    // 4. Sync PE section VirtualSizes so caves & BSS globals map cleanly when active,
    //    or restore exact vanilla VirtualSizes when every cave is zeroed.
    let secs = pe_section_headers(pe_bytes)?;
    let text_off = *secs.get(b".text".as_slice()).context("Missing .text section")?;
    let data_off = *secs.get(b".data".as_slice()).context("Missing .data section")?;
    let cur_text_vs = u32::from_le_bytes(pe_bytes[text_off + 8..text_off + 12].try_into()?);
    let cur_data_vs = u32::from_le_bytes(pe_bytes[data_off + 8..data_off + 12].try_into()?);
    let (v_text_vs, v_data_vs) = vanilla_vsizes.unwrap_or((PE_TEXT_VANILLA_VSIZE, PE_DATA_VANILLA_VSIZE));

    let any_text_cave = need_base_caves || flags.menu_caption || flags.bypass_checksum_disconnect;
    let target_text_vs = if any_text_cave {
        cur_text_vs.max(PE_TEXT_PATCHED_VSIZE)
    } else {
        v_text_vs
    };
    if cur_text_vs != target_text_vs {
        pe_bytes[text_off + 8..text_off + 12].copy_from_slice(&target_text_vs.to_le_bytes());
        changed = true;
    }

    let need_data_bss = need_base_caves || flags.bypass_checksum_disconnect;
    let target_data_vs = if need_data_bss {
        cur_data_vs.max(PE_DATA_PATCHED_VSIZE)
    } else {
        v_data_vs
    };
    if cur_data_vs != target_data_vs {
        pe_bytes[data_off + 8..data_off + 12].copy_from_slice(&target_data_vs.to_le_bytes());
        changed = true;
    }

    Ok(changed)
}

fn write_online_cave_target(cave: &mut [u8], ip: Option<Ipv4Addr>, port: u16) {
    let (enabled, ip_bytes, port) = match ip {
        Some(addr) => (
            1u8,
            addr.octets(),
            if port == 0 { DISCOVERY_PORT } else { port },
        ),
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
        crate::patcher::patch_exe_fixes(exe_path, exe_bak_path)?;
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

    let sim_chk_off = va_to_text_off(HOOK_SITE_CHECK_SIM_CHECKSUM)?;
    if !is_startup_checksum_bypass_patched(&buf)
        && buf.len() >= sim_chk_off + 8
        && &buf[sim_chk_off..sim_chk_off + 8] == SIM_CHECKSUM_HOOK_BYTES
    {
        buf[sim_chk_off..sim_chk_off + 8].copy_from_slice(SIM_CHECKSUM_ORIG);
    }

    if !is_online_coop_fix_applied(&buf) {
        bail!("Self-verification of online coop fix failed");
    }

    fs::write(exe_path, &buf).with_context(|| format!("Writing {}", exe_path.display()))?;
    crate::scct_log!("  [NET] Applied Online Coop fix to System/splintercell3.exe");
    crate::patcher::patch_exe_fixes(exe_path, exe_bak_path)?;
    Ok(())
}

pub fn update_direct_ip_in_exe(
    exe_path: &Path,
    exe_bak_path: &Path,
    target_ip: Option<Ipv4Addr>,
) -> Result<()> {
    apply_online_coop_fix(exe_path, exe_bak_path, target_ip)
}

pub fn is_net_cave_signature_present(
    net_cave: &[u8],
    online_cave_head: &[u8],
    sock_cave: &[u8],
    multi_cave: &[u8],
) -> bool {
    let expected_net = decode_hex(NET_CAVE_HEX);
    let expected_online = decode_hex(&ONLINE_CAVE_HEX[..ONLINE_CAVE_ENABLED_OFFSET * 2]);
    let expected_sock = decode_hex(SOCKET_CAVE_HEX);
    let expected_multi = decode_hex(MULTI_NIC_LAN_CAVE_HEX);
    net_cave.len() >= expected_net.len()
        && online_cave_head.len() >= expected_online.len()
        && sock_cave.len() >= expected_sock.len()
        && multi_cave.len() >= expected_multi.len()
        && net_cave[..expected_net.len()] == expected_net[..]
        && online_cave_head[..expected_online.len()] == expected_online[..]
        && sock_cave[..expected_sock.len()] == expected_sock[..]
        && multi_cave[..expected_multi.len()] == expected_multi[..]
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
        assert_eq!(
            &bytes[ONLINE_CAVE_IP_OFFSET..ONLINE_CAVE_IP_OFFSET + 4],
            &[0, 0, 0, 0]
        );
        assert_eq!(
            &bytes[ONLINE_CAVE_PORT_OFFSET..ONLINE_CAVE_PORT_OFFSET + 2],
            &[0x23, 0x8C]
        );

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
        assert_eq!(
            &bytes[0x40 + 22..0x40 + 28],
            &[0xFF, 0x25, 0xB8, 0x76, 0x0B, 0x11]
        );

        // Hook 4: Quazal Bind (0x110B6820 -> short jmp +0x70 to 0x110B6892)
        assert_eq!(&bytes[0x60..0x62], &[0xEB, 0x70]);

        // HookDiscoveryBindImpl at 0x110B6850 (+0x90): mov eax, [esp+8]
        let bind_impl_off = (HOOK_DISCOVERY_BIND_ANY - SOCKET_CAVE_VA) as usize;
        assert_eq!(
            &bytes[bind_impl_off..bind_impl_off + 4],
            &[0x8B, 0x44, 0x24, 0x08]
        );

        // HookQuazalBindImpl at 0x110B6892: push esi; mov esi, ecx
        let qbind_impl_off = (HOOK_QUAZAL_BIND_IMPL - SOCKET_CAVE_VA) as usize;
        assert_eq!(
            &bytes[qbind_impl_off..qbind_impl_off + 3],
            &[0x56, 0x89, 0xCE]
        );

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
    fn test_multi_nic_lan_cave_integrity_and_trampolines() {
        let net_cave = decode_hex(NET_CAVE_HEX);
        let sock_cave = decode_hex(SOCKET_CAVE_HEX);
        let multi_cave = decode_hex(MULTI_NIC_LAN_CAVE_HEX);

        const { assert!(ENHANCED_COOP_WSTR_VA + 28 <= MULTI_NIC_LAN_CAVE_VA); }
        assert!(MULTI_NIC_LAN_CAVE_VA + (multi_cave.len() as u32) <= 0x110B7000);

        // Verify NET_CAVE trampolines
        assert_eq!(
            &net_cave[0x00..0x06],
            make_jmp(NET_CAVE_VA, MULTI_NIC_PROBE_VA, 6).as_slice()
        );
        assert_eq!(
            &net_cave[0x138..0x13E],
            make_jmp(NET_CAVE_VA + 0x138, MULTI_NIC_HOOK2_VA, 6).as_slice()
        );
        assert_eq!(
            &net_cave[0x26A..0x274],
            make_jmp(NET_CAVE_VA + 0x26A, MULTI_NIC_QBIND_SETIP_VA, 10).as_slice()
        );
        assert_eq!(
            &net_cave[0x2C2..0x2C9],
            make_jmp(NET_CAVE_VA + 0x2C2, MULTI_NIC_QBIND_FINISH_VA, 7).as_slice()
        );

        // Verify SOCKET_CAVE trampolines
        assert_eq!(
            &sock_cave[0xC1..0xCC],
            make_jmp(SOCKET_CAVE_VA + 0xC1, MULTI_NIC_DISCO_BIND_VA, 11).as_slice()
        );
        assert_eq!(
            &sock_cave[0x30F..0x315],
            make_jmp(SOCKET_CAVE_VA + 0x30F, MULTI_NIC_WSASENDTO_TAIL_VA, 6).as_slice()
        );
        assert_eq!(
            &sock_cave[0x3E7..0x3EC],
            make_jmp(SOCKET_CAVE_VA + 0x3E7, MULTI_NIC_PREP_SOCKET_VA, 5).as_slice()
        );
        assert_eq!(&sock_cave[0x416..0x420], &[0x90; 10]);

        // Verify Hook2 jump-back targets land on `popa` (0x110B65E2) in NET_CAVE,
        // avoiding the `mov [esi], edx` corruption of InterfaceTable->m_count at 0x110B65E0.
        assert_eq!(
            &multi_cave[0x28..0x2D],
            make_jmp(MULTI_NIC_LAN_CAVE_VA + 0x28, 0x110B65E2, 5).as_slice()
        );
        assert_eq!(
            &multi_cave[0x37..0x3C],
            make_jmp(MULTI_NIC_LAN_CAVE_VA + 0x37, 0x110B65E2, 5).as_slice()
        );

        // Verify MULTI_NIC_QBIND_FINISH_VA preserves non-zero getsockname() IPs (e.g. ForceBindIP)
        // when G_LOCAL_BIND_IP_VA == 0, while still falling back to saved ebx when getsockname is 0.
        let qfinish_off = (MULTI_NIC_QBIND_FINISH_VA - MULTI_NIC_LAN_CAVE_VA) as usize;
        assert_eq!(
            &multi_cave[qfinish_off..qfinish_off + 27],
            &[
                0xA1, 0xA4, 0x03, 0x33, 0x11, // mov eax, ds:[0x113303a4]
                0x85, 0xC0,                   // test eax, eax
                0x75, 0x0A,                   // jne +0x0A (0x110B6D1F)
                0x39, 0x47, 0x04,             // cmp [edi+4], eax (eax==0)
                0x75, 0x08,                   // jne +0x08 (0x110B6D22: keep ForceBindIP IP)
                0x93,                         // xchg eax, ebx
                0x85, 0xC0,                   // test eax, eax
                0x74, 0x03,                   // je  +0x03 (0x110B6D22)
                0x89, 0x47, 0x04,             // mov [edi+4], eax
                0xE9, 0xF2, 0xF9, 0xFF, 0xFF, // jmp 0x110B6719
            ]
        );

        // Verify loopback (127.x.x.x) filters are NOPped in NET_CAVE recvfrom, SOCKET_CAVE recvfrom,
        // and HOOK_BROWSE_REPLY_URL while keeping 0.0.0.0 and 255.255.255.255 filters intact.
        let net_loopback_off = (0x110B6634 - NET_CAVE_VA) as usize;
        assert_eq!(&net_cave[net_loopback_off..net_loopback_off + 5], &[0x90; 5]);
        assert_eq!(
            &net_cave[net_loopback_off + 5..net_loopback_off + 10],
            &[0x83, 0xFA, 0xFF, 0x74, 0x06]
        );

        let sock_recv_loopback_off = (0x110B6A3F - SOCKET_CAVE_VA) as usize;
        assert_eq!(
            &sock_cave[sock_recv_loopback_off..sock_recv_loopback_off + 5],
            &[0x90; 5]
        );
        assert_eq!(
            &sock_cave[sock_recv_loopback_off + 5..sock_recv_loopback_off + 10],
            &[0x83, 0xFA, 0xFF, 0x74, 0x06]
        );

        let loopback_filter_off = (0x110B6B19 - SOCKET_CAVE_VA) as usize;
        assert_eq!(
            &sock_cave[loopback_filter_off..loopback_filter_off + 4],
            &[0x90, 0x90, 0x90, 0x90]
        );
        assert_eq!(
            &sock_cave[loopback_filter_off + 4..loopback_filter_off + 9],
            &[0x83, 0xF8, 0xFF, 0x74, 0x07]
        );

        // Verify HOOK_QUAZAL_WSASENDTO pinned-IP unicast short-circuit trampoline (0x110B6AC6 -> 0x110B6BAC)
        let sendto_tramp_off = (0x110B6AC6 - SOCKET_CAVE_VA) as usize;
        assert_eq!(
            &sock_cave[sendto_tramp_off..sendto_tramp_off + 9],
            &[0xE9, 0xE1, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90]
        );
        let sendto_helper_off = (0x110B6BAC - SOCKET_CAVE_VA) as usize;
        assert_eq!(
            &sock_cave[sendto_helper_off..sendto_helper_off + 42],
            decode_hex(
                "ff15a8760b1183c41085c07818833da403331100740f8b54241085d27402890231c0c22400e9dc010000"
            )
            .as_slice()
        );

        // Verify full live-process PE cave signature detection helper catches outdated caves too
        let online_cave = decode_hex(ONLINE_CAVE_HEX);
        assert!(is_net_cave_signature_present(
            &net_cave,
            &online_cave[..ONLINE_CAVE_ENABLED_OFFSET],
            &sock_cave,
            &multi_cave,
        ));
        let mut outdated_sock = sock_cave.clone();
        outdated_sock[sock_recv_loopback_off] = 0x80;
        assert!(!is_net_cave_signature_present(
            &net_cave,
            &online_cave[..ONLINE_CAVE_ENABLED_OFFSET],
            &outdated_sock,
            &multi_cave,
        ));
    }

    #[test]
    fn test_apply_online_coop_fix() {
        let p1 = Path::new(
            "../clean_scct_files/Tom Clancy's Splinter Cell Chaos Theory/System/splintercell3.exe",
        );
        let p2 = Path::new(
            "../../clean_scct_files/Tom Clancy's Splinter Cell Chaos Theory/System/splintercell3.exe",
        );
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
        let _ = fs::remove_file(&test_exe);
        let _ = fs::remove_file(&test_bak);

        let _ = fs::copy(clean_exe, &test_exe);

        let unready_off = va_to_text_off(HOOK_SETPAUSE_LOBBY_UNREADY).unwrap();
        let unready_orig = decode_hex(SETPAUSE_LOBBY_UNREADY_ORIG_HEX);
        let clean_bytes = fs::read(&test_exe).unwrap();
        assert_eq!(
            &clean_bytes[unready_off..unready_off + SETPAUSE_LOBBY_UNREADY_NOP_LEN],
            unready_orig.as_slice()
        );

        let test_ip = Ipv4Addr::new(109, 38, 141, 172);
        apply_online_coop_fix_with_ports(&test_exe, &test_bak, Some(test_ip), 2380, 2383).unwrap();

        let buf = fs::read(&test_exe).unwrap();
        assert!(is_online_coop_fix_applied(&buf));
        assert!(crate::patcher::is_camera_alarm_patched(&buf));
        assert!(crate::patcher::is_nonlethal_gameover_patched(&buf));
        assert_eq!(
            &buf[unready_off..unready_off + SETPAUSE_LOBBY_UNREADY_NOP_LEN],
            &[0x90; SETPAUSE_LOBBY_UNREADY_NOP_LEN]
        );
        let ip_off = va_to_text_off(CAVE_ONLINE_IP_VA).unwrap();
        assert_eq!(&buf[ip_off..ip_off + 4], &test_ip.octets());
        let ready_off = va_to_text_off(HOOK_PAUSE_IS_PLAYER_READY).unwrap();
        assert_eq!(
            &clean_bytes[ready_off..ready_off + 8],
            decode_hex(PAUSE_IS_PLAYER_READY_ORIG_HEX).as_slice()
        );
        // Standard fixes now enable IsPlayerReady and disable AI visibility culling by default
        assert_eq!(
            &buf[ready_off..ready_off + 8],
            decode_hex(PAUSE_IS_PLAYER_READY_NEW_HEX).as_slice()
        );
        assert!(is_pause_always_ready_patched(&buf));
        assert!(is_ai_visibility_culling_disabled(&buf));
        let mut toggled = buf.clone();
        assert!(revert_pause_always_ready_bytes(&mut toggled));
        assert!(!is_pause_always_ready_patched(&toggled));
        assert!(is_online_coop_fix_applied(&toggled));
        assert_eq!(patch_pause_always_ready_bytes(&mut toggled).unwrap(), ready_off);
        assert!(is_pause_always_ready_patched(&toggled));
        assert!(is_online_coop_fix_applied(&toggled));
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
        assert_eq!(
            &buf[wstr_off..wstr_off + expected_wstr.len()],
            expected_wstr.as_slice()
        );
        let caption_site_off = va_to_text_off(HOOK_MAIN_MENU_COOP_LAN_CAPTION).unwrap();
        assert_eq!(
            &buf[caption_site_off..caption_site_off + 10],
            &[0x8B, 0x4E, 0x48, 0x68, 0xA0, 0x6C, 0x0B, 0x11, 0xEB, 0x15]
        );

        // Test clearing IP resets ports back to defaults (9100 / 9103)
        apply_online_coop_fix(&test_exe, &test_bak, None).unwrap();
        let buf2 = fs::read(&test_exe).unwrap();
        assert!(is_online_coop_fix_applied(&buf2));
        let en_off = va_to_text_off(CAVE_ONLINE_ENABLED_VA).unwrap();
        assert_eq!(buf2[en_off], 0);
        assert_eq!(&buf2[jp_off..jp_off + 4], &(GAME_PORT as u32).to_le_bytes());
        assert_eq!(&buf2[dp_off..dp_off + 2], &DISCOVERY_PORT.to_be_bytes());

        let _ = fs::remove_file(test_exe);
        let _ = fs::remove_file(test_bak);
    }

    #[test]
    fn test_setpause_lobby_unready_site_integrity() {
        assert_eq!(va_to_text_off(HOOK_SETPAUSE_LOBBY_UNREADY).unwrap(), 0x13D58B);

        let orig = decode_hex(SETPAUSE_LOBBY_UNREADY_ORIG_HEX);
        assert_eq!(orig.len(), SETPAUSE_LOBBY_UNREADY_NOP_LEN);
        // push 1; push 0; call SetLocalPlayerReady (0x1095DA20); add esp, 8
        assert_eq!(&orig[0..4], &[0x6A, 0x01, 0x6A, 0x00]);
        assert_eq!(orig[4], 0xE8);
        let rel = i32::from_le_bytes(orig[5..9].try_into().unwrap()) as i64;
        let call_target = (HOOK_SETPAUSE_LOBBY_UNREADY as i64 + 4 + 5 + rel) as u32;
        assert_eq!(call_target, 0x1095DA20);
        assert_eq!(&orig[9..12], &[0x83, 0xC4, 0x08]);

        let sites = get_online_sites();
        let site = sites
            .iter()
            .find(|s| s.va == HOOK_SETPAUSE_LOBBY_UNREADY)
            .expect("SetPause lobby unready patch site registered in get_online_sites");
        assert_eq!(site.orig, orig);
        assert_eq!(site.new, vec![0x90; SETPAUSE_LOBBY_UNREADY_NOP_LEN]);
    }

    #[test]
    fn test_pause_is_player_ready_site_integrity() {
        let ready_off = va_to_text_off(HOOK_PAUSE_IS_PLAYER_READY).unwrap();
        assert_eq!(ready_off, 0x0639E0);

        let orig = decode_hex(PAUSE_IS_PLAYER_READY_ORIG_HEX);
        let new = decode_hex(PAUSE_IS_PLAYER_READY_NEW_HEX);
        assert_eq!(orig.len(), new.len());
        // mov eax, [0x111F559C]; sub esp, 0x28
        assert_eq!(&orig[0..5], &[0xA1, 0x9C, 0x55, 0x1F, 0x11]);
        // mov eax, 1; ret
        assert_eq!(&new[0..6], &[0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]);

        // Managed via optional UI flag rather than get_online_sites()
        let sites = get_online_sites();
        assert!(sites.iter().all(|s| s.va != HOOK_PAUSE_IS_PLAYER_READY));

        let mut mock = vec![0u8; ready_off + orig.len()];
        mock[ready_off..ready_off + orig.len()].copy_from_slice(&orig);
        assert!(!is_pause_always_ready_patched(&mock));
        assert_eq!(patch_pause_always_ready_bytes(&mut mock).unwrap(), ready_off);
        assert!(is_pause_always_ready_patched(&mock));
        assert_eq!(&mock[ready_off..ready_off + new.len()], new.as_slice());
        assert!(revert_pause_always_ready_bytes(&mut mock));
        assert!(!is_pause_always_ready_patched(&mock));
        assert_eq!(&mock[ready_off..ready_off + orig.len()], orig.as_slice());
    }

    #[test]
    fn test_multi_nic_lan_patch_on_clean_exe() {
        let p1 = Path::new(
            "../clean_scct_files/Tom Clancy's Splinter Cell Chaos Theory/System/splintercell3.exe",
        );
        let p2 = Path::new(
            "../../clean_scct_files/Tom Clancy's Splinter Cell Chaos Theory/System/splintercell3.exe",
        );
        let clean_exe = if p1.exists() {
            p1
        } else if p2.exists() {
            p2
        } else {
            return;
        };

        let dir = std::env::temp_dir();
        let test_exe = dir.join("test_scct3_multi_nic.exe");
        let test_bak = dir.join("test_scct3_multi_nic.exe.bak");
        let _ = fs::remove_file(&test_exe);
        let _ = fs::remove_file(&test_bak);
        fs::copy(clean_exe, &test_exe).unwrap();

        let vanilla = fs::read(&test_exe).unwrap();
        assert!(!is_lan_and_zerotier_fix_applied(&vanilla));

        apply_lan_networking_fix(&test_exe, &test_bak).unwrap();
        let patched = fs::read(&test_exe).unwrap();
        assert!(is_lan_and_zerotier_fix_applied(&patched));
        assert!(crate::patcher::is_camera_alarm_patched(&patched));
        assert!(crate::patcher::is_nonlethal_gameover_patched(&patched));

        let multi_cave = decode_hex(MULTI_NIC_LAN_CAVE_HEX);
        let multi_off = va_to_text_off(MULTI_NIC_LAN_CAVE_VA).unwrap();
        assert_eq!(
            &patched[multi_off..multi_off + multi_cave.len()],
            multi_cave.as_slice()
        );

        let sim_chk_off = va_to_text_off(HOOK_SITE_CHECK_SIM_CHECKSUM).unwrap();
        assert_eq!(
            &vanilla[sim_chk_off..sim_chk_off + 8],
            SIM_CHECKSUM_ORIG
        );
        assert_eq!(
            &patched[sim_chk_off..sim_chk_off + 8],
            SIM_CHECKSUM_ORIG
        );

        // Idempotent when re-applied
        apply_lan_networking_fix(&test_exe, &test_bak).unwrap();
        let patched_again = fs::read(&test_exe).unwrap();
        assert_eq!(patched, patched_again);

        // Zeroing MULTI_NIC_LAN_CAVE must fail is_lan_and_zerotier_fix_applied
        let mut partial = patched.clone();
        partial[multi_off..multi_off + multi_cave.len()].fill(0);
        assert!(!is_lan_and_zerotier_fix_applied(&partial));

        let _ = fs::remove_file(&test_exe);
        let _ = fs::remove_file(&test_bak);
    }

    #[test]
    fn test_startup_checksum_bypass_cave_and_toggle() {
        // Verify relative call displacement from 0x110B6FE2 to 0x10DF8620
        let rel_call = i32::from_le_bytes(STARTUP_CHECKSUM_BYPASS_CAVE_BYTES[3..7].try_into().unwrap());
        assert_eq!((SIM_CHECKSUM_CAVE_VA + 7).wrapping_add(rel_call as u32), 0x10DF8620);
        // Verify jnz target lands at 0x110B6FF8 (mov al, 1; ret)
        assert_eq!(STARTUP_CHECKSUM_BYPASS_CAVE_BYTES[0x09], 0x75);
        assert_eq!(
            0x110B6FE9u32 + 2 + (STARTUP_CHECKSUM_BYPASS_CAVE_BYTES[0x0A] as u32),
            0x110B6FF8
        );
        assert_eq!(
            &STARTUP_CHECKSUM_BYPASS_CAVE_BYTES[0x18..0x1B],
            &[0xB0, 0x01, 0xC3]
        );

        let chk_off = va_to_text_off(HOOK_SITE_CHECK_SIM_CHECKSUM).unwrap();
        let cave_off = va_to_text_off(SIM_CHECKSUM_CAVE_VA).unwrap();
        let mut mock = vec![0u8; cave_off + 32];
        mock[chk_off..chk_off + 8].copy_from_slice(SIM_CHECKSUM_ORIG);

        assert!(!is_startup_checksum_bypass_patched(&mock));
        assert_eq!(patch_startup_checksum_bypass_bytes(&mut mock).unwrap(), chk_off);
        assert!(is_startup_checksum_bypass_patched(&mock));
        assert_eq!(&mock[chk_off..chk_off + 8], SIM_CHECKSUM_HOOK_BYTES);
        assert_eq!(&mock[cave_off..cave_off + 32], &STARTUP_CHECKSUM_BYPASS_CAVE_BYTES);

        // Idempotent re-apply
        assert_eq!(patch_startup_checksum_bypass_bytes(&mut mock).unwrap(), chk_off);
        assert!(is_sim_checksum_site_valid(&mock));

        // Clean revert restores vanilla bytes and clears cave
        assert!(revert_startup_checksum_bypass_bytes(&mut mock));
        assert!(!is_startup_checksum_bypass_patched(&mock));
        assert_eq!(&mock[chk_off..chk_off + 8], SIM_CHECKSUM_ORIG);
        assert!(mock[cave_off..cave_off + 32].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_ai_visibility_culling_toggle() {
        let cull_off = va_to_text_off(HOOK_AI_VISIBILITY_CULL).unwrap();
        assert_eq!(cull_off, 0x31852C);
        let mut mock = vec![0u8; cull_off + 16];
        mock[cull_off..cull_off + 8].copy_from_slice(AI_VISIBILITY_CULL_ORIG);

        assert!(!is_ai_visibility_culling_disabled(&mock));
        assert_eq!(
            patch_ai_visibility_culling_disabled_bytes(&mut mock).unwrap(),
            cull_off
        );
        assert!(is_ai_visibility_culling_disabled(&mock));
        assert_eq!(&mock[cull_off..cull_off + 8], AI_VISIBILITY_CULL_PATCHED);
        // Idempotent
        assert_eq!(
            patch_ai_visibility_culling_disabled_bytes(&mut mock).unwrap(),
            cull_off
        );
        // Revert
        assert!(revert_ai_visibility_culling_disabled_bytes(&mut mock));
        assert!(!is_ai_visibility_culling_disabled(&mock));
        assert_eq!(&mock[cull_off..cull_off + 8], AI_VISIBILITY_CULL_ORIG);

        let clean_candidates = [
            "../clean_scct_files/Tom Clancy's Splinter Cell Chaos Theory/System/splintercell3.exe",
            "../../clean_scct_files/Tom Clancy's Splinter Cell Chaos Theory/System/splintercell3.exe",
        ];
        if let Some(p) = clean_candidates
            .iter()
            .map(std::path::Path::new)
            .find(|p| p.exists())
        {
            let mut real_exe = std::fs::read(p).unwrap();
            assert!(!is_ai_visibility_culling_disabled(&real_exe));
            assert_eq!(
                &real_exe[cull_off..cull_off + 8],
                AI_VISIBILITY_CULL_ORIG
            );
            patch_ai_visibility_culling_disabled_bytes(&mut real_exe).unwrap();
            assert!(is_ai_visibility_culling_disabled(&real_exe));
            assert!(revert_ai_visibility_culling_disabled_bytes(&mut real_exe));
            assert!(!is_ai_visibility_culling_disabled(&real_exe));
        }
    }

    #[test]
    fn test_sync_net_flags_granular_and_vanilla_roundtrip() {
        let pe_off = 0x100usize;
        let opt_sz = 0xE0usize;
        let sec_table = pe_off + 0x18 + opt_sz;
        let mut vanilla = vec![0u8; (PE_TEXT_RAW_OFF + PE_TEXT_RAW_SIZE) as usize];
        vanilla[0..2].copy_from_slice(b"MZ");
        vanilla[0x3C..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
        vanilla[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        vanilla[pe_off + 6..pe_off + 8].copy_from_slice(&2u16.to_le_bytes());
        vanilla[pe_off + 0x14..pe_off + 0x16].copy_from_slice(&(opt_sz as u16).to_le_bytes());
        vanilla[pe_off + 0x34..pe_off + 0x38].copy_from_slice(&PE_IMAGE_BASE.to_le_bytes());
        vanilla[sec_table..sec_table + 5].copy_from_slice(b".text");
        vanilla[sec_table + 8..sec_table + 12].copy_from_slice(&PE_TEXT_VANILLA_VSIZE.to_le_bytes());
        vanilla[sec_table + 12..sec_table + 16].copy_from_slice(&PE_TEXT_RVA.to_le_bytes());
        vanilla[sec_table + 16..sec_table + 20].copy_from_slice(&PE_TEXT_RAW_SIZE.to_le_bytes());
        vanilla[sec_table + 20..sec_table + 24].copy_from_slice(&PE_TEXT_RAW_OFF.to_le_bytes());
        let data_sec = sec_table + 40;
        vanilla[data_sec..data_sec + 5].copy_from_slice(b".data");
        vanilla[data_sec + 8..data_sec + 12].copy_from_slice(&PE_DATA_VANILLA_VSIZE.to_le_bytes());
        vanilla[data_sec + 12..data_sec + 16].copy_from_slice(&0x007B7000u32.to_le_bytes());

        // Populate vanilla original bytes for all sites
        for site in get_lan_bind_sites()
            .into_iter()
            .chain(get_nat_direct_sites())
            .chain([
                get_menu_redirect_site(),
                get_menu_caption_site(),
                get_lobby_alttab_unready_site(),
            ])
        {
            let off = va_to_text_off(site.va).unwrap();
            vanilla[off..off + site.orig.len()].copy_from_slice(&site.orig);
        }
        let jp_push = va_to_text_off(JOIN_GAME_PORT_PUSH_VA).unwrap();
        vanilla[jp_push] = 0x68;
        vanilla[jp_push + 1..jp_push + 5].copy_from_slice(&(GAME_PORT as u32).to_le_bytes());
        let pause_off = va_to_text_off(HOOK_PAUSE_IS_PLAYER_READY).unwrap();
        let pause_orig = decode_hex(PAUSE_IS_PLAYER_READY_ORIG_HEX);
        vanilla[pause_off..pause_off + pause_orig.len()].copy_from_slice(&pause_orig);
        let sim_off = va_to_text_off(HOOK_SITE_CHECK_SIM_CHECKSUM).unwrap();
        vanilla[sim_off..sim_off + SIM_CHECKSUM_ORIG.len()].copy_from_slice(SIM_CHECKSUM_ORIG);

        let mut work = vanilla.clone();
        let all_on = NetExeFlags {
            lan_bind: true,
            nat_direct: true,
            menu_redirect: true,
            menu_caption: true,
            lobby_alttab_unready_nop: true,
            pause_always_ready: true,
            bypass_checksum_disconnect: true,
        };
        let target = Some((Ipv4Addr::new(198, 51, 100, 42), 19100, 19103));
        assert!(sync_net_flags_to_exe_bytes(&mut work, &all_on, target, None).unwrap());
        assert!(is_lan_bind_hooks_applied(&work));
        assert!(is_nat_direct_hooks_applied(&work));
        assert!(is_menu_redirect_patched(&work));
        assert!(is_menu_caption_patched(&work));
        assert!(is_lobby_alttab_unready_nop_patched(&work));
        assert!(is_pause_always_ready_patched(&work));
        assert!(is_startup_checksum_bypass_patched(&work));
        assert!(!sync_net_flags_to_exe_bytes(&mut work, &all_on, target, None).unwrap());

        // Toggle only menu + lan off while keeping nat_direct ON -> set_direct_target_in_exe works!
        let nat_only = NetExeFlags {
            lan_bind: false,
            nat_direct: true,
            menu_redirect: false,
            menu_caption: false,
            lobby_alttab_unready_nop: false,
            pause_always_ready: false,
            bypass_checksum_disconnect: false,
        };
        assert!(sync_net_flags_to_exe_bytes(&mut work, &nat_only, target, None).unwrap());
        assert!(!is_lan_bind_hooks_applied(&work));
        assert!(is_nat_direct_hooks_applied(&work));
        assert!(!is_menu_redirect_patched(&work));
        assert!(!is_menu_caption_patched(&work));
        assert!(!is_lobby_alttab_unready_nop_patched(&work));
        assert!(!is_pause_always_ready_patched(&work));
        assert!(!is_startup_checksum_bypass_patched(&work));
        set_direct_target_in_exe(&mut work, Some(Ipv4Addr::new(203, 0, 113, 5)), 9101, 9104)
            .unwrap();

        // Turn EVERYTHING off -> 100% byte-identical to vanilla
        let all_off = NetExeFlags {
            lan_bind: false,
            nat_direct: false,
            menu_redirect: false,
            menu_caption: false,
            lobby_alttab_unready_nop: false,
            pause_always_ready: false,
            bypass_checksum_disconnect: false,
        };
        assert!(sync_net_flags_to_exe_bytes(&mut work, &all_off, None, None).unwrap());
        assert_eq!(work, vanilla);
        assert!(!sync_net_flags_to_exe_bytes(&mut work, &all_off, None, None).unwrap());
    }
}
