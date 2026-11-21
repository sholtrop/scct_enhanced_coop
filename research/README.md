# Splinter Cell: Chaos Theory — Technical Research & File Formats

Self-contained engineering notes and standalone Python tools documenting the file formats, engine internals, Co-op level format, networking stack, lockstep simulation, and menu system of *Splinter Cell: Chaos Theory* (retail PC `splintercell3.exe`, PE32 `ImageBase = 0x10900000`).

---

## Documentation

| Document | Contents |
| :--- | :--- |
| [`upk-and-umd-formats.md`](./upk-and-umd-formats.md) | UE 2.5 UPK/SCL/U package layout (Version 100 / Licensee 124), `CompactIndex`, `FString`, tagged `UObject` properties, `TLazyArray` + Havok `hkWorld` constraints, UnrealScript bytecode format, and `System/dynamic-pc.umd` archive layout. |
| [`coop-levels-and-gameplay.md`](./coop-levels-and-gameplay.md) | Engine and UnrealScript differences between Single-Player and Co-op maps, complete checklist for converting an SP level to Co-op, and native gameplay differences gated on `bMultiplayerMap` (cameras/alarms, non-lethal failure, EEV remote hacking, HQ voice lines, pause/alt-tab behavior, persistent quick saves). |
| [`networking-and-nat.md`](./networking-and-nat.md) | PE `.text`/`.data` cave layout, `WS2_32`/`KERNEL32` IAT map, Ubisoft `GS_Socket` vs. Quazal Net-Z (`Quazal::SocketDriver` on both UDP `9100` and `9103`), `BrowseProtocol::HandleBrowseReply` / `StationURL` rewriting, Multi-NIC LAN fixes, and STUN/CGNAT hole-punching. |
| [`lockstep-sync-and-desyncs.md`](./lockstep-sync-and-desyncs.md) | Deterministic lockstep engine globals, `UserChecksum0/1` and `MT19937` checksum slots, render-vs-simulation desync root causes (render-only RNG, skeletal bone cache staleness, `LastRenderTime` AI gates, controller transform hashing), and in-memory Host→Client resync mechanics. |
| [`magma-ui-and-menus.md`](./magma-ui-and-menus.md) | Magma UI (`*.mgb`) architecture, `UObject::Localize` ring buffer, Co-op menu controllers (`MainMenuCoop`, `P_MenuCoop`, `P_MenuCoopJoin`, lobby mission dropdown), and `dynamic-pc.umd` localization files. |

---

## Standalone Python Tools ([`scripts/`](./scripts/))

All scripts under [`scripts/`](./scripts/) use only the Python 3 standard library and accept explicit file paths (or `--game-dir` / `SCCT_GAME_ROOT`):

| Script | Purpose | Example |
| :--- | :--- | :--- |
| [`scripts/upk.py`](./scripts/upk.py) | Inspect `.scl` / `.u` / `.utx` / `.usx` / `.ukx` packages (header, tables, properties, `MyLevel.Actors`, `TextBuffer`) and save edits while preserving `TLazyArray` offsets and Havok tails. | `python3 scripts/upk.py props Data/Maps/01_Lighthouse.scl --export LevelInfo0` |
| [`scripts/uscript.py`](./scripts/uscript.py) | Disassemble SCCT UnrealScript `Function`/`State` exports (tracking disk vs. memory offsets) and list `iNative` indices from `System/*.u`. | `python3 scripts/uscript.py disasm System/Echelon.u --export EPlayerController.SwitchEEV --disk` |
| [`scripts/umd.py`](./scripts/umd.py) | Inspect, list, read, extract, and update virtual files inside `System/dynamic-pc.umd`. | `python3 scripts/umd.py cat System/dynamic-pc.umd System\\MapRotation.ini` |
| [`scripts/exe_info.py`](./scripts/exe_info.py) | Inspect `splintercell3.exe` PE sections, VA↔offset mappings, PE exports, `GRegisterNative` `iNative`→C++ bindings, and ASCII/UTF-16LE string xrefs. | `python3 scripts/exe_info.py natives System/splintercell3.exe --system-dir System/ --grep EndMission` |
| [`scripts/validate_coop_map.py`](./scripts/validate_coop_map.py) | Validate whether a `.scl` map (and its companion `.ini`, audio, loading screens, localization, and `MapRotation.ini` entries) will be accepted as a Co-op level by the game, printing everything missing or misconfigured. | `python3 scripts/validate_coop_map.py Data/Maps/01_Lighthouse_COOP.scl --game-dir /path/to/SCCT` |

For production Rust implementations of the UPK converter, UMD patcher, PE binary patches, and runtime hooks, see [`../scct_coop_enhancer/src/`](../scct_coop_enhancer/src/).
