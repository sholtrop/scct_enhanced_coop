# SCCT Networking, Quazal Net-Z & NAT Traversal

This document summarizes the networking architecture of *Splinter Cell: Chaos Theory* (`System/splintercell3.exe`, retail PE32 `ImageBase = 0x10900000`), why vanilla Co-op fails on multi-NIC / virtual-adapter LANs and over the Internet, and the hook architecture used for LAN and STUN/CGNAT play.

---

## 1. PE Section & Cave Memory Map (`splintercell3.exe`)

### 1.1 Section Layout

| Section | Virtual Address | Vanilla `VirtualSize` | Expanded `VirtualSize` | `RawOffset` | `RawSize` | Characteristics |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `.text` | `0x10901000` | `0x007B544A` | `0x007B6000` | `0x00001000` | `0x007B6000` | `0x60000020` (`R-X`) |
| `.rdata` | `0x110B7000` | `0x000D6BAB` | *(unchanged)* | `0x007B7000` | `0x000D7000` | `0x40000040` (`R--`) |
| `.data` | `0x1118E000` | `0x001A2389` | `0x001A3000` | `0x0088E000` | `0x00065000` | `0xC0000040` (`RW-`) |
| `.rsrc` | `0x11331000` | `0x00003430` | *(unchanged)* | `0x008F3000` | `0x00004000` | `0x40000040` (`R--`) |
| `.reloc` | `0x11335000` | `0x00071EA8` | *(unchanged)* | `0x008F7000` | `0x00072000` | `0x42000040` (`R--`) |

Because `.text` has `RVA == RawOffset == 0x1000`, any `.text` virtual address maps directly to file offset via `file_offset = va - 0x10900000`. Expanding `.text.VirtualSize` to `0x007B6000` exposes `2,998` (`0xBB6`) zero-padded bytes at `0x110B644A..0x110B7000` as executable code caves. Expanding `.data.VirtualSize` to `0x001A3000` exposes zero-initialized BSS state past `0x11330389`.

### 1.2 `.text` Code Cave Allocation (`0x110B6450..0x110B7000`)

| Region | VA Range | Purpose |
| :--- | :--- | :--- |
| `NET_CAVE` | `0x110B6450..0x110B672A` | `ConnectRouteProbe` (`connect()` + `getsockname()`), `GetLocalAdapterIP` hook (`0x110B64E9`), `Quazal::InterfaceTable` hook (`0x110B6576`), `GS_Socket` recv/session hooks (`0x110B65F2`, `0x110B668A`, `0x110B669E`), and `QUAZAL_SOCKET_BIND` helper (`0x110B66B1`). |
| `ONLINE_CAVE` | `0x110B6740..0x110B67B8` | `GS_Socket` `sendto` broadcast-to-unicast replicator + runtime target bytes (`ENABLED` @ `0x110B6760`, `PEER_IP` @ `0x110B6783`, big-endian `PEER_PORT` @ `0x110B678E`). |
| `SOCKET_CAVE` | `0x110B67C0..0x110B6C9A` | Socket/bind wrappers (`0.0.0.0` bind, `SIO_UDP_CONNRESET` disable), port-aware `:9100`/`:9103` punch & 3 s keepalive poll (`0x110B6920`), `GS_Socket::RecvFrom` keepalive filter (`0x110B69A2`), `Quazal::SocketDriver::SendTo` `WSASendTo` unicast replicator (`0x110B6A52`), and `HandleBrowseReply` `StationURL` rewriter (`0x110B6AD5`). |
| `ENHANCED_COOP_WSTR` | `0x110B6CA0..0x110B6CBC` | UTF-16LE `L"ENHANCED COOP\0"` (28 bytes). |
| `MULTI_NIC_LAN_CAVE` | `0x110B6CC0..0x110B6FDD` | Explicit local adapter bind (`G_LOCAL_BIND_IP_VA`) and multi-NIC LAN broadcast fan-out across all active non-loopback interfaces. |
| `SIM_CHECKSUM_CAVE` | `0x110B6FE0..0x110B7000` | Optional 32-byte lockstep checksum trace/bypass cave (`CheckSimulationChecksum` hook). |

### 1.3 `.data` BSS Globals (`0x113303A0..0x11330408`)

| VA | Type | Purpose |
| :--- | :--- | :--- |
| `0x113303A0` | `u32` (BE IPv4) | `G_LAN_PEER_VA`: real UDP sender IPv4 captured from incoming discovery replies or pre-seeded by the launcher for routable subnets. |
| `0x113303A4` | `u32` (BE IPv4) | `G_LOCAL_BIND_IP_VA`: optional explicit local adapter bind IP (`0` = Auto / `0.0.0.0` across all interfaces). |
| `0x113303D0`..`0x113303DC` | `u32[4]` | Optional inherited socket / primed-bind slots (zeroed when spawning with `bInheritHandles = FALSE`). |
| `0x113303E0` | `u32` (`DWORD` ms) | `G_LAST_9103_KEEPALIVE_VA`: `GetTickCount()` timestamp for `:9103` → `peer_game_port` keepalives. |
| `0x113303E4` | `u32` (`DWORD` ms) | `G_LAST_9100_KEEPALIVE_VA`: `GetTickCount()` timestamp for `:9100` → `peer_disco_port` keepalives. |
| `0x11330400`..`0x11330407` | `u32[2]` | Desync flag (`0x11330400`) and mismatch counter (`0x11330404`). |

### 1.4 Key `WS2_32.dll` & `KERNEL32.dll` IAT Entries

| IAT VA | Function |
| :--- | :--- |
| `0x110B7304` | `KERNEL32!GetTickCount` |
| `0x110B765C` | `WS2_32!WSAGetLastError` |
| `0x110B7660` | `WS2_32!connect` |
| `0x110B766C` | `WS2_32!closesocket` |
| `0x110B7680` | `WS2_32!recvfrom` |
| `0x110B76A8` | `WS2_32!sendto` |
| `0x110B76AC` | `WS2_32!socket` |
| `0x110B76B0` | `WS2_32!inet_ntoa` |
| `0x110B76B8` | `WS2_32!WSASocketW` |
| `0x110B76BC` | `WS2_32!getsockname` |
| `0x110B76C0` | `WS2_32!bind` |
| `0x110B76C4` | `WS2_32!WSASendTo` |
| `0x110B76D0` | `WS2_32!WSAIoctl` (`SIO_UDP_CONNRESET = 0x9800000C`) |

---

## 2. Two Separate UDP `9100` Stacks

`splintercell3.exe` contains **two independent UDP `9100` networking stacks**:

1. **Ubisoft `GS_LanEngine` / `GS_Socket` / `CLanManager`** (`0x10EFB900..0x10EFC800`, `0x10B1B000..0x10B1B600`):
   - Uses synchronous Winsock `socket()` (`0x10EFBFF9`), `bind()` (`0x10EFC0A3` / `0x10EFC109`), `sendto()` (`0x10EFC4F9` / `0x10EFC586`), and `recvfrom()` (`0x10EFC62C` / `0x10EFC7AC`).
   - Used by legacy LAN browsing paths.

2. **Quazal Net-Z (`Quazal::SocketDriver` / `LANSessionDiscovery` / `BrowseProtocol`)** (`0x10DC3000..0x10DE6700`) — **used by Co-op**:
   - Co-op uses `Quazal::SocketDriver` for **both** UDP `9100` (session discovery) and UDP `9103` (PRUDP gameplay).
   - Both sockets are created with overlapped `WSASocketW` (`0x10DE6490`), bound via `Quazal::SocketDriver::Bind` (`0x10DE6510`), polled via `Quazal::SocketDriver::HasRecvCompleted` (`0x10DE53B0`), and sent via `WSASendTo` (`0x10DE65CA`).
   - Key `Quazal::SocketDriver` fields:
     - `[driver + 0x00]`: Overlapped receive armed flag (`1` = `WSARecvFrom` active).
     - `[driver + 0x08]`: Local `sockaddr_in`; **`WORD [driver + 0x0A]`** is the big-endian bound port (`0x8C23` in little-endian register = `htons(9100)`, `0x8F23` = `htons(9103)`).
     - `[driver + 0x8C]`: Underlying Winsock `SOCKET` handle.
     - `[driver + 0x94]`: Overlapped wrapper pointer (completion byte at `[eax + 0x18] == 2`).

> [!IMPORTANT]
> Hooking only `GS_Socket::SendTo` (`0x10EFC4F9`) does not intercept Co-op room discovery, because Co-op broadcasts `255.255.255.255:9100` via Quazal's `WSASendTo` (`0x10DE65CA`) and processes replies inside `Quazal::BrowseProtocol::HandleBrowseReply` (`0x10DC3680`).

---

## 3. Why Vanilla Fails on Multi-NIC LAN & Over NAT/CGNAT

1. **Wrong Adapter Selection & Binding**:
   - On Windows hosts with WSL, Hyper-V, Docker, or VPN adapters, `GetLocalAdapterIP` (`0x10EFBA18`) and `Quazal::InterfaceTable` (`0x10DE591F`) frequently put a virtual/unroutable NIC in slot `0`.
   - The host then binds to that wrong IP and embeds it inside its `StationURL` (e.g. `prudp:/address=172.24.0.1;port=9103;sid=1;type=3`).
2. **Hardcoded `9103` Join Port & Private LAN IP in `StationURL`**:
   - Over the Internet, a host's `BrowseReply` `StationURL` always contains its private RFC1918 LAN IP and port `9103`, whereas the guest must connect PRUDP to `(Host_Public_IP, Host_Mapped_9103_Port)`.
   - Additionally, `P_MenuCoopJoin` formats its join URL using a hardcoded `push 0x238F` (`9103`) immediate at `0x10B57ED5` (`JOIN_GAME_PORT_VA = 0x10B57ED6`).
3. **Windows `SIO_UDP_CONNRESET` (`WSAECONNRESET`)**:
   - Unreachable ICMP replies during hole-punching cause Winsock UDP sockets to return `WSAECONNRESET` (`10054`) on subsequent `WSARecvFrom` calls unless `SIO_UDP_CONNRESET` (`0x9800000C`) is disabled via `WSAIoctl`.

---

## 4. `BrowseProtocol::HandleBrowseReply` & `StationURL` Rewriting

At `0x10DC36CE` inside `Quazal::BrowseProtocol::HandleBrowseReply` (`0x10DC3680`):

- `ecx` (`[esp+0x48]`) is the host's target `Quazal::StationURL*` from `SessionDescriptor`.
- `edi` is the incoming `Quazal::Message*`, where `[edi + 0x28]` (`m_pSenderURL`) holds the **actual UDP source IP:port** observed by `WSARecvFrom`.
- Useful native `Quazal::StationURL` methods:
  - `0x10D91090`: `StationURL::GetURLString()` (original call at `0x10DC36CE`).
  - `0x10D92190`: `uint16_t __thiscall StationURL::GetPortNumber()`.
  - `0x10D92770`: `bool __thiscall StationURL::ExtractInetAddress(sockaddr_in* out)`.
  - `0x10D92AF0`: `void __thiscall StationURL::SetInetAddress(const sockaddr_in* in)` — rewrites `address=<ip>;port=<port>` in place while preserving `sid`, `type`, `natm`, and `natf` parameters.

`HOOK_BROWSE_REPLY_URL` (`0x110B6AD5`) extracts the real UDP sender IP from `m_pSenderURL` into `G_LAN_PEER_VA` (`0x113303A0`), then rewrites the discovered `StationURL` via `SetInetAddress`:
- **Online mode (`CAVE_ONLINE_ENABLED_VA != 0`)**: rewrites to `(CAVE_ONLINE_IP_VA, JOIN_GAME_PORT_VA)`.
- **LAN mode (`CAVE_ONLINE_ENABLED_VA == 0`)**: preserves the advertised port (`9103`) and overwrites the IP with the real UDP sender IP, fixing multi-NIC / WSL hosts automatically.

---

## 5. Complete Hook Site Reference

### 5.1 Multi-NIC LAN & Quazal Socket Hooks

| Patch VA | Original Bytes | Purpose |
| :--- | :--- | :--- |
| `0x10EFBA18` | `8d4424748d4c2444` | `GetLocalAdapterIP`: promotes explicit `G_LOCAL_BIND_IP_VA` or route-probed NIC to slot `0`. |
| `0x10DE591F` | `8b680c8b450033db` | `Quazal::InterfaceTable`: promotes route-matched / bound IPv4 to index `0`. |
| `0x10EFC62C` / `0x10EFC7AC` | `8b2d80760b11` | `GS_Socket::RecvFrom[IP]`: sends 3 s `"SCPK"` keepalives in Online mode, strips incoming `"SCPK"`, captures `G_LAN_PEER_VA`. |
| `0x10B1B06D` / `0x10B1B555` | `8b44246c6a20` / `83c4248b36` | `CLanManager`: rewrites advertised session IP strings with `inet_ntoa(G_LAN_PEER_VA)`. |
| `0x10DE6510` | `56578b7c24` | `Quazal::SocketDriver::Bind`: disables `SIO_UDP_CONNRESET`, binds `0.0.0.0` (or `G_LOCAL_BIND_IP_VA`), and in Online mode punches `:9100` → `peer_disco_port` (`"SCPK"`) or `:9103` → `peer_game_port` (`0xFFFF`). |
| `0x10DE53B0` | `8b8194000000` | `Quazal::SocketDriver::HasRecvCompleted`: sends 3,000 ms keepalives independently on `:9100` and `:9103` while Online mode is active. |
| `0x10EFBFF9` / `0x10DE6490` | `ff15ac760b11` / `ff15b8760b11` | `GS_Socket::CreateUDP` / `Quazal::SocketDriver::Create` socket wrappers. |
| `0x10EFC0A3` / `0x10EFC109` | `ff15c0760b11` | `GS_Socket::Bind[IP]`: disables `SIO_UDP_CONNRESET` and binds `0.0.0.0` (or `G_LOCAL_BIND_IP_VA`) on UDP `9100`. |
| `0x10DE65CA` | `ff15c4760b11` | `Quazal::SocketDriver::SendTo`: replicates UDP `9100` broadcasts (`255.255.255.255`/`0.0.0.0`) as unicast to `(CAVE_ONLINE_IP_VA, CAVE_ONLINE_PORT_VA)` in Online mode, or fans out across interfaces in LAN mode. |
| `0x10DC36CE` | `e8bdd9fcff` | `Quazal::BrowseProtocol::HandleBrowseReply`: `HOOK_BROWSE_REPLY_URL` (`StationURL` IP/port rewrite). |

### 5.2 Direct-IP & Join Port Hooks

| Patch VA | Original Bytes | Purpose |
| :--- | :--- | :--- |
| `0x10EFC4F9` / `0x10EFC586` | `ff15a8760b11` | `GS_Socket::SendTo[IP]`: replicates UDP `9100` broadcasts to `(CAVE_ONLINE_IP_VA, CAVE_ONLINE_PORT_VA)`. |
| `0x10B57ED5` | `68 8f 23 00 00` | `P_MenuCoopJoin`: replaces `push 9103` immediate (`JOIN_GAME_PORT_VA = 0x10B57ED6`) with the peer's mapped `:9103` port. |

---

## 6. STUN & CGNAT Hole-Punching Flow

1. **Pre-Launch STUN & Rendezvous**:
   - Both players bind temporary UDP sockets on local ports `9100` and `9103` and query an RFC 5389 STUN server (UDP `3478`) to discover their external mapped `(public_ip, disco_port, game_port)` endpoints (supporting Port-Block Allocation CGNATs).
   - Host registers a 5-character Crockford Base32 friend code with the HTTP signaling server; Guest joins with that code and both learn each other's public and local LAN endpoints.
   - If both peers share the same public IPv4 and are on a matching local subnet, they switch automatically to direct LAN (`:9100`/`:9103`).
   - Otherwise, both sides fire initial UDP hole-punch packets on `:9100 ↔ peer_disco_port` and `:9103 ↔ peer_game_port`, then **close both temporary sockets** before starting the game.
2. **Suspended Launch & Runtime Injection (`CREATE_SUSPENDED`, `bInheritHandles = FALSE`)**:
   - Inheriting raw Winsock handles across `CreateProcessA` causes socket collisions because SCCT destroys and recreates UDP `9100` and `9103` across menu transitions.
   - Instead, the launcher spawns `splintercell3.exe` suspended (`bInheritHandles = FALSE`), writes `CAVE_ONLINE_ENABLED_VA`, `CAVE_ONLINE_IP_VA`, `CAVE_ONLINE_PORT_VA`, `JOIN_GAME_PORT_VA`, `G_LAN_PEER_VA`, and `G_LOCAL_BIND_IP_VA` directly into process memory, and resumes the main thread.
   - When Quazal binds local `:9100` and `:9103`, Endpoint-Independent / PBA NATs reuse the same external port mapping, `HOOK_QUAZAL_BIND_IMPL` immediately sends a fresh outbound punch on each socket, and `HOOK_QUAZAL_POLL` keeps both NAT pinholes alive every 3 seconds.

See [`../scct_coop_enhancer/src/net.rs`](../scct_coop_enhancer/src/net.rs), [`../scct_coop_enhancer/src/launcher.rs`](../scct_coop_enhancer/src/launcher.rs), [`../scct_coop_enhancer/src/stun.rs`](../scct_coop_enhancer/src/stun.rs), and [`../scct_coop_server/`](../scct_coop_server/).
