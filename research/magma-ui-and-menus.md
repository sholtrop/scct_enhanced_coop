# Magma Menu UI, Localization & Mission Lists

*Splinter Cell: Chaos Theory*'s menus use Ubisoft's **Magma** UI framework: compiled binary widget layouts (`Data\Magma\DataPC\*.mgb`, e.g. `main_PC.mgb` and `online_PC.mgb`) inside `System/dynamic-pc.umd`, driven by native C++ page controllers in `splintercell3.exe` (`0x10B20000..0x10B80000`). The `.mgb` layouts contain **no hardcoded map names**; mission lists are populated dynamically from `System\MapRotation.ini` and per-map `.ini` files.

---

## 1. Core Native UI & Localization Primitives

| VA | Function / Symbol | Behavior |
| :--- | :--- | :--- |
| `0x10CCC4B0` | `UObject::Localize` | `const wchar_t* __cdecl Localize(Section, Key, Package, LangExt, bOptional, Unknown)` (`0x18` bytes stack args). Reads `Data\System\Localization\<Package>.<lang>` from `dynamic-pc.umd` (or loose fallback) into a 256-slot rotating ring buffer of `wchar_t[1024]` (`2,048` B/slot) at `0x11254F50` (index at `0x112D4F50 & 0xFF`). |
| `0x10D2FC80` | `CMagmaListWidget::AddItem` | `void __thiscall AddItem(this, const wchar_t* Caption, int UserData)` (`ret 8`). Appends a clickable row to `[this + 0x68]`. Note MSVC stack scheduling: callers often `push UserData` *before* pushing the 6 `Localize` args, pop `0x18`, then `push eax` (`Caption`) and call `0x10D2FC80`. |
| `0x10B721A0` | `SetWidgetLocalizedText` | `void __cdecl SetWidgetLocalizedText(Page, WidgetName, Section, Key, Package, Flag)` — sets static text labels such as `"L_Title"` (`0x110DAF00`). |
| `0x10B71AF0` | `FindListWidget` | Looks up a named list widget (e.g. `"Lst_menu"` at `0x110DF888`) on a Magma page (`[esi + 0x38]`). |

---

## 2. Co-op Menu Hierarchy

### 2.1 `MainMenuCoop` (`0x10B4BAE0..0x10B4BC9D`)

Populates `this->Lst_menu` (`[esi + 0x48]`) with 4 items (`0x10B4BB85..0x10B4BC18`):

| Index | VA Range | `Localize(Section, Key, L"PreGame_PC")` | Vanilla English Text |
| :--- | :--- | :--- | :--- |
| `0` | `0x10B4BB85..0x10B4BBA9` | `MainMenuCoop` / `LanCaption` (`0x110E2CC8`) | `"LAN"` |
| `1` | `0x10B4BBAA..0x10B4BBCE` | `MainMenuCoop` / `OnlineCaption` (`0x110E2CAC`) | `"ONLINE"` |
| `2` | `0x10B4BBCF..0x10B4BBF3` | `MainMenuCoop` / `SettingsCaption` (`0x110E2C8C`) | `"SETTINGS"` |
| `3` | `0x10B4BBF4..0x10B4BC18` | `MenuSolo` / `ProfileManagement` (`0x110E2C68`) | `"PROFILE MANAGEMENT"` |

`L"LanCaption"` (`0x110E2CC8`) has only **one** code reference in `splintercell3.exe` (`0x10B4BB8F`). Replacing `0x10B4BB86..0x10B4BBA5` (31 bytes) with `mov ecx, [esi+0x48]; push 0x110B6CA0; jmp 0x10B4BBA5` (+ NOPs) changes Button 0 to `L"ENHANCED COOP"` without affecting Versus menus or internal protocol strings. Patching `[MainMenuCoop] LanCaption=ENHANCED COOP` in `Data\System\Localization\PreGame_PC.{int,fra,deu,esp,ita}` provides the same label via UMD localization.

### 2.2 `P_MenuCoop` (`0x10B52220..0x10B52530`, VTable `0x110E3278`)

- Sets `"L_Title"` to `CoopCommon.MainTitleLan` (`"COOP LAN"`) and populates `"Lst_menu"` (`[esi + 0x44]`) with `JoinCaption` (`0`) and `CreateCaption` (`1`).
- Selection handler (`0x10B52490`) reads `WORD [Lst_menu + 0xA8]`:
  - `0x10B524EB`: enters the LAN/Direct room list (`[edx + 0x88] = 0`).
  - `0x10B524CA` (33 bytes): originally set `[edx + 0x88] = 1` for the defunct Ubi.com login. Patching `0x10B524CA` to `jmp 0x10B524EB` (+ NOPs) redirects **ONLINE** straight to the LAN/Direct room browser.

### 2.3 Co-op Lobby Mission Select Dropdown (`0x10B74050..0x10B74400`)

- `0x10B74230` builds a dynamic `TArray<INT>` of mission indices from `Profile->CoopMaps` (`[edi + 0x88]`/`[edi + 0x8C]`, populated from `System\MapRotation.ini` `MissionCoop[...]` where `FStartMap->Multiplayer != 0`), then appends any discovered map with `XboxLiveContent != 0` (`0x10B741F0`).
  - Setting `XboxLiveContent=0` in custom `Data/Maps/<Map>_COOP.ini` files prevents converted maps from appearing twice in the dropdown.
- Localized display titles are resolved by `0x10B736C0` from `[GENERAL] MapName=` in `Data\System\Localization\<LocalizationFile>.<lang>`.

---

## 3. Localization & Configuration Files in `dynamic-pc.umd`

All localization files exist in five language extensions: `.int` (English), `.fra` (French), `.deu` (German), `.esp` (Spanish), and `.ita` (Italian).

| UMD Virtual Path | Purpose |
| :--- | :--- |
| `System\MapRotation.ini` | Lists `MissionSP[0..10]` and `MissionCoop[0..N]` map stems loaded into the profile mission tables. |
| `Data\Maps\<Map>.ini` | Per-map metadata parsed by `FStartMap::LoadFromIni` (`0x10AE8CE0`): `Multiplayer`, `Identity`, `XboxLiveContent`, `LocalizationFile`, `[EMissionManager]`, `[LOADOUT_HOST]`, `[LOADOUT_CLIENT]`. |
| `Data\System\Localization\PreGame_PC.<lang>` | Pre-game and Co-op menu captions (`[MainMenuCoop]`, `[CoopCommon]`, `[MenuSolo]`). |
| `Data\System\Localization\LoadingScreens.<lang>` | Per-map loading screen text (`[<map_lower>]`: `Location=`, `Date=`, `Time=`, `Overview=`, `Tip*`). |
| `Data\System\Localization\<Map>.<lang>` | `[GENERAL]` (`MapName=`), `[Interaction]`, `[Computer]`, and `[Email]` strings. Note: `08_SeoulOne` and `09_SeoulTwo` share the vanilla `"SEOUL"` title unless disambiguated. |
| `Data\System\Localization\P_<Map>.<lang>` | Pattern voice subtitles, mission objectives, and recon notes referenced directly by `EPattern` default properties in `System/EchelonPattern.u`. |

See [`../scct_coop_enhancer/src/umd.rs`](../scct_coop_enhancer/src/umd.rs) and [`../scct_coop_enhancer/src/net.rs`](../scct_coop_enhancer/src/net.rs) for the implementation of these UMD and menu patches.
