# Co-op vs. Single-Player Levels & Gameplay Mechanics

Converting a _Splinter Cell: Chaos Theory_ Single-Player mission into a playable Co-op mission requires changes across three layers: the `.scl` map package, companion metadata / `dynamic-pc.umd` entries, and native/script gates controlled by `LevelInfo.bMultiplayerMap`.

---

## 1. How the Engine Distinguishes Co-op from Single-Player Maps

### 1.1 Native Checks in `UGameEngine::LoadMap` (`0x10A40EE0`)

During map load, `UGameEngine::LoadMap` enforces two hard requirements before entering Co-op mode (`GEngine + 0xA8 != 0`):

1. **`LevelInfo0->bMultiplayerMap` check**:
   - `GLevel` is at `[GEngine + 0x17C]`, `GLevel->Actors.Data` at `[GLevel + 0x28]`, and `Actors[0]` is `LevelInfo0` (`AEchelonLevelInfo`).
   - Bit `0` of `[LevelInfo0 + 0x5CC]` is `bMultiplayerMap`.
   - If `bMultiplayerMap == 0`, `LoadMap` clears `GEngine + 0xA8` to `0`, aborting Co-op mode.

2. **`APlayerStart` count (`>= 2`) & `PlayerStartList` construction**:
   - `LoadMap` zeroes `LevelInfo0->PlayerStartList` (`+0x5D4`), iterates over `MyLevel.Actors`, and links every actor passing `IsA(APlayerStart)` into `PlayerStartList` via `ANavigationPoint::nextNavigationPoint` (`+0x2E8`), counting matches.
   - **If `bMultiplayerMap == 1` and fewer than 2 `APlayerStart` actors exist in `MyLevel.Actors`, `LoadMap` clears both `GEngine + 0xA8` and `GEngine + 0xA4` and falls back to Single-Player spawning.**
   - When `GEngine + 0xA8 != 0` succeeds, `LoadMap` spawns both players via `SpawnPlayActor` with `PlayerID=0` (Host / Player 1) and `PlayerID=2` (Client / Player 2).

3. **Co-op animation preload (`AEchelonLevelInfo::PostBeginPlay`, `0x10C14E20` → `0x10C13D60`)**:
   - When `bMultiplayerMap == 1`, the engine automatically loads `"ESam.SamRapel"` into `LevelInfo0->aSamAnims` (`+0x424`) so co-op rappel/boost animations are available.

### 1.2 UnrealScript Login & Spawn Pipeline (`Engine.u`, `Echelon.u`)

- **`EchelonLevelInfo.PostBeginPlay`**: Defaults `SamMesh` to `ESam.SamA` if unset. Native Co-op maps instead set `LevelInfo0.SamMesh` and/or `EchelonPlayerStart.StartMesh` to `SkeletalMesh'CoopAnims.COOP_Player'`.
- **`EchelonGameInfo.Login`**: Checks `ParseOption(Options, "Multi")` and selects `Echelon.ECoopPlayerController`.
- **`EchelonGameInfo.SpawnNewPlayerController`**: Reads `PlayerID` (`0` for Player 1, `2` for Player 2) and calls `FindPlayerStart(None, byte(playerID), Portal)`.
- **`EchelonGameInfo.FindPlayerStart`**: Walks `Level.PlayerStartList` via `nextNavigationPoint` and selects the first unused `EchelonPlayerStart` where `spotID == int(InTeam)`.
  - Player 1 requires `spotID = 0` (the default value when omitted).
  - Player 2 requires `spotID = 2` (`IntProperty = 2`).
- **`EchelonGameInfo.RestartPlayer`**: When `StartSpot.spotID == 2`, dynamically assigns Player 2's skins (`Coop_Heros.COOP_Player2_*`) onto the pawn's `Skins[0..10]`.

---

## 2. Structural Differences: Vanilla Co-op vs. Single-Player `.scl`

| Property / Structure                                    | Vanilla Co-op (e.g. `01_Panama.scl`)     | Vanilla SP (e.g. `01_Lighthouse.scl`)                             | Required for Converted `_COOP.scl`                                                                                                                                                                             |
| :------------------------------------------------------ | :--------------------------------------- | :---------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `LevelInfo0.bMultiplayerMap`                            | `True`                                   | Omitted (`False`)                                                 | Set `bMultiplayerMap = True`                                                                                                                                                                                   |
| `LevelInfo0.SamMesh`                                    | `SkeletalMesh'CoopAnims.COOP_Player'`    | Omitted (`ESam.SamA`)                                             | Import & set `CoopAnims.COOP_Player`                                                                                                                                                                           |
| `LevelInfo0.UseDefaultSoundMap`                         | Varies                                   | Present (`False`) on 10/11 SP maps; **missing on `04_Penthouse`** | Force `UseDefaultSoundMap = False` so `SoundMapName` isn't overwritten to `<Map>_COOP` (which breaks DareAudio `MAPS.SM0`/`MAPS.LM0` lookup)                                                                   |
| `APlayerStart` count in `MyLevel.Actors`                | `2`                                      | `1`                                                               | Add a 2nd `EchelonPlayerStart` export and insert its ref into `MyLevel.Actors`                                                                                                                                 |
| Player 1 start (`spotID = 0`)                           | Has mission `PatternID`/`JumpLabel`      | Has mission `PatternID`/`JumpLabel`                               | Keep `PatternID`/`JumpLabel`; set `StartMesh = COOP_Player` and link `nextNavigationPoint` to Player 2 start                                                                                                   |
| Player 2 start (`spotID = 2`)                           | `spotID = 2`, no `PatternID`/`JumpLabel` | Missing                                                           | Clone Player 1 start with `spotID = 2`, offset `Location`, `StartMesh = COOP_Player`, and strip `PatternID`, `JumpLabel`, `Unconscious*`, `ConversationTarget`, `Base`, `RelativeLocation`, `RelativeRotation` |
| Off-map HQ speaker pawns (`Lambert`, `Grim`, `Redding`) | Not gated behind SP-only AI zones        | Assigned to dummy `HQ` `EAIZone` on 7/11 SP maps                  | Strip `CurrentEAIZone` from HQ speaker pawns so `APawn::PreBeginPlay()` spawns their `AIController` immediately on startup (matching Lighthouse/Bathhouse/Hokkaido)                                            |

---

## 3. Complete Checklist to Convert a Single-Player Level to Co-op

### 3.1 Map Package (`Data/Maps/<Map>_COOP.scl`)

Using a `TLazyArray`-safe UPK writer (see [`upk-and-umd-formats.md`](./upk-and-umd-formats.md) and [`../scct_coop_enhancer/src/upk.rs`](../scct_coop_enhancer/src/upk.rs)):

1. Add required names (`bMultiplayerMap`, `spotID`, `nextNavigationPoint`, `UseDefaultSoundMap`, `SamMesh`, `StartMesh`, `CoopAnims`, `COOP_Player`, and unique P2 actor name e.g. `EchelonPlayerStartCoop`) to the Name Table.
2. Add two Import entries:
   - `Core.Package` `CoopAnims` (outer `0`)
   - `Engine.SkeletalMesh` `COOP_Player` (outer = `CoopAnims` import ref)
3. Rewrite `LevelInfo0` with `bMultiplayerMap = True`, `UseDefaultSoundMap = False`, and `SamMesh = CoopAnims.COOP_Player`.
4. Update Player 1's `EchelonPlayerStart` (`StartMesh = CoopAnims.COOP_Player`, `nextNavigationPoint = <P2 export ref>`).
5. Append Player 2's `EchelonPlayerStartCoop` export with `spotID = 2`, `StartMesh = CoopAnims.COOP_Player`, a safe non-overlapping `Location` offset from Player 1, and trigger/attachment properties stripped (`PatternID`, `JumpLabel`, `UnconsciousPatternID`, `UnconsciousLabel`, `UnconsciousRevivePoint`, `UnconsciousTimer`, `UnconsciousEAIZonesToDisable`, `ConversationTarget`, `Base`, `RelativeLocation`, `RelativeRotation`).
6. Increment `MyLevel.Actors` `db_num`/`db_max` by 1 and insert Player 2's export index right after Player 1's start.
7. Strip `CurrentEAIZone` from off-map HQ radio speaker pawns (`ELambert`, `EAIGenericNPC*` tagged `Lambert`/`HQ`/`Headquarters`/`Grim`/`Redding`) so radio voice lines and mission reprimands work cleanly in multiplayer.
8. Preserve pre-table bytes intact and copy the trailing Havok `hkWorld` stream (`33 5A 0D F0`) verbatim after the rebuilt Export Table.

### 3.2 Companion Loose Files & `dynamic-pc.umd` Entries

| Asset                             | Path / Location                                                                           | Requirements                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| :-------------------------------- | :---------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Map INI                           | `Data/Maps/<Map>_COOP.ini` (loose file)                                                   | Derived from the SP map INI in `dynamic-pc.umd`: set `Multiplayer=true`, unique `Identity` (`203..213`, avoiding vanilla Co-op IDs), **`XboxLiveContent=0`** (nonzero causes duplicate entries in the Coop Lobby Mission Select dropdown at `0x10B741F0`), `LocalizationFile=<SourceMap>`, Co-op `EMissionManager`, and `[LOADOUT_HOST]` / `[LOADOUT_CLIENT]` sections.                                                                          |
| Audio files                       | `Data/Maps/<Map>_COOP_sound.{occ,uns}` (loose copies)                                     | Copied from the corresponding SP `_sound.occ` and `_sound.uns` files.                                                                                                                                                                                                                                                                                                                                                                            |
| Loading textures                  | `Data/Magma/DataPC/Textures/GenLoadings/<Map>_COOP_loading_{1,2}.dds` (loose copies)      | Extracted from the SP map's `GenLoadings` entries in `dynamic-pc.umd` (loaded by `LoadLoadingScreenTextures` at `0x10B65340`).                                                                                                                                                                                                                                                                                                                   |
| Mission list                      | `System\MapRotation.ini` (inside `dynamic-pc.umd` + loose `System/MapRotation.ini`)       | Append `MissionCoop[7..17]="<Map>_COOP"` after the 7 vanilla Co-op entries (`0..6`).                                                                                                                                                                                                                                                                                                                                                             |
| Loading text                      | `Data\System\Localization\LoadingScreens.{int,fra,deu,esp,ita}` (inside `dynamic-pc.umd`) | Add `[<map>_coop]` sections copying `Location=`, `Date=`, `Time=`, `Overview=` from the SP section plus Co-op `Tip*` entries.                                                                                                                                                                                                                                                                                                                    |
| Computers / emails / interactions | `Data\System\Localization\<Map>_COOP.{int,fra,deu,esp,ita}` (inside `dynamic-pc.umd`)     | Clone from `<SourceMap>.<lang>` for all 5 languages. `AEComputer` (`0x10C40870`/`0x10C40A50`) and `ECustomObjectiveInteraction.PostBeginPlay` (`EchelonIngredient.u` Export `1524`) derive `"Localization\\" + StripMapExtension(URL.Map)` from the loaded `.scl` stem and **ignore** `LocalizationFile=` in the map INI. (`P_<Map>.*` subtitle files do not need cloning because `EPattern` defaults hardcode `"Localization\\P_<SourceMap>"`.) |

---

## 4. Gameplay Systems Affected by `bMultiplayerMap = True`

Setting `LevelInfo0.bMultiplayerMap = True` enables Co-op play, but also activates several retail multiplayer bypasses in `splintercell3.exe` and `System/Echelon.u`.

### 4.1 Security Cameras, Sensors & Turrets Not Triggering Alarms

When a sensor detects a player, `ESensor::ProcessDetectedPawn` (`0x10C57B14`) calls `EAIZone::StartAlarm` (`0x1099BB50`). Two checks block alarms in Co-op:

1. **Multiplayer alarm gate (`0x1099BCA4`, branch at `0x1099BCAE`)**:
   - Tests `Level->bMultiplayerMap` (`test byte ptr [eax+0x5CC], 1`); if nonzero, `jne 0x1099BCCC` (`75 1C`) jumps completely over the `TriggerAlarm` dispatch (`0x10A7BCB0`).
   - Patch: `75 1C` → `90 90` (`nop; nop`).
2. **`bForceAlarm == 0` early exit (`0x1099BBB7`, branch at `0x1099BBBD`) & `ESensor` call (`0x10C57B22`)**:
   - Wall cameras (`0x10C57B42`), ceiling 360 cameras (`0x10C542E3`), secondary optical sensors (`0x10C56758`), and turrets (`0x10C5DF94`) pass `bForceAlarm = 0`, causing `StartAlarm` to alert nearby guards and return early (`ret 0x1C` at `0x1099BC50`) without sounding sirens or raising the alarm stage.
   - Patch: replace `jne 0x1099BC53` (`0F 85 90 00 00 00`) at `0x1099BBBD` with unconditional `jmp 0x1099BC53; nop` (`E9 91 00 00 00 90`), and change `push 0` (`6A 00`) → `push 1` (`6A 01`) at `0x10C57B22`.

### 4.2 Non-Lethal Mission Failures Not Ending the Mission

On strict no-kill missions (e.g. Displace, Seoul, Kokubo Sosho), killing an NPC fires `AIEvent 190` (`AI_DEAD`) to the mission pattern, which calls `EndMission(False, 0)` (`iNative 2238`, `EPattern::execEndMission` @ `0x10B93750`). Two issues prevented Game Over in Co-op:

1. **`EPattern::execEndMission` `Members[0]` gate (`0x10B937BB`)**:
   - Vanilla checked `Members[0]->bIsPlayer` before branching on `Level->bMultiplayerMap`; if `Members[0]` was null/non-player, it aborted before calling `ECoopPlayerController.EndMissionCoop`.
   - Patch (`0x10B937BB`): test `Level->bMultiplayerMap` first and branch directly to `0x10B937D8` (`pPlayerList[0]->EndMissionCoop`).
2. **Unimplemented multiplayer Game Over UI in `CInGameMenusManager::ThrowMenuEvent(0)` (`0x10B25809`)**:
   - `EndMission` sets `MISSION.m_eMissionStatus = 2` (Failed) and calls `NotifyMenu(0)` → `ThrowMenuEvent(0)`. When `IsMultiplayer() != 0`, `0x10B25809..0x10B2582B` exits without opening any UI.
   - Patch (`0x10B25809`, 40 bytes): replace the dead MP branch with `push 0; push 0; mov ecx, esi; call 0x10B21F50; jmp 0x10B2583B` (+ NOPs), invoking `OpenPauseMenu(0, 0)`, which renders the multiplayer `GAME OVER / RESTART / LEAVE MISSION` menu and pauses both players.

### 4.3 EEV Binoculars & Remote Distance Hacking (`System/Echelon.u`)

`ECoopPlayerController` inherits the entire EEV stack (`ZoomToggle` → `SwitchEEV` → `s_EEV`, native `EEEV::Tick` @ `0x10C21090`, `AEGameplayObject::EEVed` @ `0x10BEDB80`, and `EHackingGameplay` @ `0x10BF5440`). The only blocker is an explicit guard at the top of `EPlayerController.SwitchEEV` (`System/Echelon.u`, Export `6827`, bytecode start `0x0AABA6`):

```unrealscript
// mem 0x0000 (file 0x0AABA6):
if (!(Level.bMultiplayerMap)) goto 0x0014;
// mem 0x0012 (file 0x0AABB3):
return;   // bytes: 04 0B -> patch to 0B 0B (EX_Nothing; EX_Nothing)
```

Replacing `04 0B` with `0B 0B` at file offset `0x0AABB3` keeps file size and jump offsets unchanged while restoring EEV scanning and remote hacking in Co-op.

### 4.4 Off-Map HQ AI Zones (`EAIZone`) vs. Speaker Detachment

In `EchelonGameInfo::execAddPlayerInZones` (`0x10C10C30`), when `Level->bMultiplayerMap == 1` (`0x10C10CC2`), zones with `bEnableAtStart = True` are enabled **only** if their `StartPoints` array (`[zone + 0x3D0]`) matches a player start. Converted SP maps have empty `StartPoints` on all `EAIZone`s.

- **Important pitfall**: Globally bypassing the `StartPoints` check (`0x10C10CC9`: `74 33` → `EB 33`) wakes up **every** `bEnableAtStart` combat zone at once and can desync vanilla Co-op levels.
- **Clean solution**: Strip `CurrentEAIZone` solely from off-map HQ radio speaker pawns in converted `_COOP.scl` files (Section 3.1 step 7). Their AI controllers spawn immediately on both Host and Client so `AEPattern::execSpeech` (`0x10B980BF`) never encounters `Members[idx] == NULL`.

### 4.5 Lobby Alt-Tab & Pause Menu Readiness

Important to disable this when you're testing locally with two instances of the game that you're alt-tabbing between:

- **Lobby Alt-Tab Unready (`0x10A3D58B`, 12 bytes)**: `UGameEngine::SetPause` calls `SetLocalPlayerReady(0, 1)` (`6A 01 6A 00 E8 8C 04 F2 FF 83 C4 08`) whenever a ready Co-op lobby client loses window focus. NOPing these 12 bytes prevents Alt-Tabbing from unreadying.
- **Pause Menu Always Ready (`0x109639E0`, 8 bytes)**: `IsPlayerReady(bool remote)` returns `[player + 0x8F]` and is called only by the in-game ESC pause menu (`0x10B2934A`, `0x10B29448`, `0x10B29D61..0x10B29E7C`) to gate Quick Save, Quick Load, and Resume behind "WaitRemote" prompts. Patching `0x109639E0` with `mov eax, 1; ret` (`B8 01 00 00 00 C3 90 90`) marks both players ready immediately.

But very importantly, the games will desync if you keep one instance alt-tabbed. Use [Fusion Fix](https://fusionfix.io/games/scct/) and configure it to run in _borderless fullscreen_ to prevent this.

### 4.6 Persistent Co-op Quick Saves

Vanilla Co-op writes transient quick saves to the player's profile folder:

- `CacheCoopQuickSaveHost.sav`
- `CacheCoopQuickSaveClient.sav`

Even if those `.sav` files are backed up and restored onto disk before launching a new session, the game disables **Quick Load** in a fresh process for two reasons:

1. Menu UI readiness flags (`[menu + 0xFEC]`) are checked at `0x10B28732` (Pause menu) and `0x10B29EB8` (Game Over menu), which stay `0` until a Quick Save occurs in the current process.
2. The quick-load filename `FString` on `UGameEngine` (`[engine + 0xE0]`, length at `[engine + 0xE4]`, checked at `0x10B23919`) is empty until the first save of the session.

By installing three runtime hooks at launch (see [`../scct_coop_enhancer/src/quicksave_persistence.rs`](../scct_coop_enhancer/src/quicksave_persistence.rs)):

- **`0x10B28732`** (Pause) and **`0x10B29EB8`** (Game Over): when `[eax + 0xFEC] == 0`, format `<save_cache_prefix>CoopQuickSave{Host|Client}.sav` using the save path global at `0x11230570` (`+0x40`/`+0x44`) and `IsCoopHost` (`0x1095B880`), check `GFileManager->FileSize` (`[0x111C88A4]`, `vt+0x10`), and set `[eax + 0xFEC] = 1` if the restored `.sav` file exists (`> 0` bytes).
- **`0x10B23919`** (CoopQuickLoad): when `[UGameEngine + 0xE4] <= 1`, populate `[UGameEngine + 0xE0]` with the resolved `.sav` path so the engine loads the restored snapshot seamlessly.
