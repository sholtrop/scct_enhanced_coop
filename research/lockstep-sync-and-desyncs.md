# Lockstep Simulation, Checksums & Desync Root Causes

*Splinter Cell: Chaos Theory* Co-op does **not** replicate full actor transforms over the network. Both peers run a **deterministic lockstep simulation** fed by synchronized player inputs and verified continuously by rolling checksums. Any divergence between Host and Client triggers a lockstep disconnect (`SyncEngine->Status = 6`).

---

## 1. Engine Memory Map (`splintercell3.exe`, `ImageBase = 0x10900000`)

### 1.1 Core Simulation & Checksum Globals

| Symbol / Role | VA / Offset | Description |
| :--- | :--- | :--- |
| `GEngine` | `0x111F5554` | Pointer to `UGameEngine*`. `GLevel` = `[GEngine + 0x17C]`; `GEngine + 0xA8` = active Co-op flag. |
| `GLevel->Actors` | `[GLevel + 0x28]` / `+0x2C` | `TArray<AActor*>` `Data` pointer (`+0x28`) and `Num` count (`+0x2C`). `Actors[0]` is `LevelInfo0` (`TimeSeconds` at `[LevelInfo0 + 0x430]`). |
| `GNames` | `0x1130DFC0` | Global `FName` table. |
| `GFrameCounter` | `0x111C8B38` (low) / `0x111C8B3C` (high) | 64-bit engine frame counter incremented at the end of `UGameEngine::Tick` (`0x10A43D14`). |
| `SyncEngine` | `0x111F55A4` | Pointer to `SyncEngine*`. Current simulation step = `[SyncEngine + 0x5C]`; status = `[SyncEngine + 0x68]` (`6` = desync disconnect). |
| `WarmupFlag` | `0x111F55E0` | `0` during initial 5-step startup warmup (`0x111F55E4` increments `0..5`), `1` during active gameplay. |
| `UserChecksum0` | `0x111F5F14` | Running `u32` simulation accumulator (`slot=0`) folded from active Pawn positions/rotations in `AEPawn::Tick`. |
| `UserChecksum1` | `0x111F5F18` | Secondary `u32` accumulator folded from active `AEInventoryItem::Tick` (`0x10BEA537`) transforms. |
| `LocalSimStation` | `0x1131B3BC` | Pointer to local `SimStation*`. Running cumulative checksum = `[SimStation + 0xB0C]`. |
| `SimStation::GetSlotChecksum` | `0x10DF9460` | Given `ecx = SimStation + 0x48`: `slot=0` at `+0x1A0`, `slot=1` at `+0x2F4`, `slot=2` at `+0x448`, `slot=3` at `+0x59C`, `slot=4` at `+0x6F0`, `slot=5` at `+0x04C`. |

### 1.2 Synchronized `MT19937` RNG State

The lockstep RNG (`SyncRNG::Rand` @ `0x1095BA10` → `0x10DF21C0` → `0x10DC73D0`) is embedded directly inside `SyncEngine` at **`SyncEngine + 0xB8`**:

- `mt[624]` state array: `SyncEngine + 0xB8 .. +0xA77` (`2,496` bytes)
- `mti` index (`0..=624`): `SyncEngine + 0xA78`
- `mag01[2]` (`{0, 0x9908B0DF}`): `SyncEngine + 0xA7C .. +0xA83`

### 1.3 Checksum Verification & Disconnect Sites

- **`SimStation::CheckSimulationChecksum`** (`0x10DF8620`):
  - Called via `0x10DF2C90` for `slot=0` (`UserChecksum0` / pawn simulation state) and via `0x10DF8750` for `slot=5` (`MT19937` / full simulation state).
  - At **`0x10DF86BA`**, `cmp eax, ecx` compares local vs. remote checksum; `0x10DF86C0` executes `setne bl`, and `0x10DF86D9` branches on mismatch to set `SyncEngine->Status = 6` and disconnect the session.
- **Disconnect UI state (`0x111F559C`)**:
  - `0x10B4D1C0` displays `SessionDisconnectMsg` whenever the session object at `0x111F559C` is null, `[obj + 0x38] == 0`, or the Quazal state mapper `0x10D810C0` leaves states `1`/`2`.

---

## 2. Render-vs-Simulation Desync Root Causes in Retail `splintercell3.exe`

In `UGameEngine::Tick` (`0x10A43920..0x10A43ED7`), each frame executes:
1. `0x10A43AB9`: `GLevel->Tick(LEVELTICK_All, DeltaSeconds)` (lockstep simulation)
2. `0x10A43CE9`: `Client->Tick` → `UViewport::Draw` (local camera rendering — different on Host vs. Client!)
3. `0x10A43D14`: `GFrameCounter++`

Four distinct classes of bugs in retail `splintercell3.exe` allow **local rendering/visibility differences** between the two players' cameras to mutate lockstep simulation state or checksums:

### 2.1 Render-Only Calls Consuming Synced `MT19937` RNG (`slot=5` Mismatch)

`appRand` (`0x10CCAC00`) and `appFrand` (`0x10CCAC40`) advance the lockstep `MT19937` stream, whereas `appUnsyncedRand` (`0x10CCAC20`) and `appUnsyncedFrand` (`0x10CCAC70`) do not. Three purely visual, camera-culled code paths erroneously call the synced functions:

| Site | VA(s) | Trigger | Fix |
| :--- | :--- | :--- | :--- |
| `FDynamicLight` flicker | `0x10AC04C1` (in `0x10AC0410`) | Per-visible-chunk dynamic light brightness (`LT_Flicker` + `LE_EPP_Omni`/`Spotlight`). Different player camera angles evaluate different visible chunk counts and diverge `slot=5` immediately (e.g. `04_Penthouse` `Light2` at spawn). | Redirect `appFrand` → `appUnsyncedFrand` (`0x10CCAC70`). |
| `AEPawn::vt+0x70` eye animation | `0x10B86392`, `0x10B863C7`, `0x10B863E8`, `0x10B86409` | Invoked under `VisibleZoneMask`-filtered `vt+0x238`; facial bones in the same function already use `appUnsyncedFrand`. | Redirect `appFrand`/`appRand` → `appUnsyncedFrand`/`appUnsyncedRand`. |
| `AESensor::vt+0x70` look jitter | `0x10C56F13`, `0x10C56F28`, `0x10C56F3D` | Invoked under `VisibleZoneMask`-filtered `vt+0x238`. | Redirect `appFrand` → `appUnsyncedFrand`. |

### 2.2 Stale Skeletal Bone Caches on Off-Screen AI (`slot=0` Mismatch)

During `UViewport::Draw`, `USkeletalMeshInstance::Render` (`0x109FC003`) calls `USkeletalMeshInstance::GetFrame` (`0x109F5240`) only on **rendered** meshes. Meanwhile, AI gameplay logic (`UETransitionController::StartTransition` @ `0x10C2EF31`, `FinishTransition` @ `0x10C31451`, foot checks @ `0x10B8BD03`/`0x10B870AA`) queries bones with `bForceCompute = 0`. When `CachedFrameCounter < GFrameCounter` and `bForceCompute == 0`, the engine skips `GetFrame`, leaving unrendered AI with 1+ tick stale bones on one peer while the other peer renders them fresh:

1. **Force bone evaluation on stale frame (`bForceCompute == 0` bypass)**:
   - `USkeletalMeshInstance::GetBoneMatrix` (`0x109D243C`)
   - `USkeletalMeshInstance::GetBoneLocation` (`0x109D24E0`)
   - `USkeletalMeshInstance::GetBoneCoords` (`0x109D25A6`)
   - `USkeletalMeshInstance::GetAttachmentCoords` (`0x109E1AC1`)
   - Patch: NOP the `je` skip (`74 26` → `90 90`) at all four sites so stale-frame bone queries always evaluate `GetFrame` deterministically even off-screen.
2. **Prevent double bone-controller stepping (`USkeletalMeshInstance::GetFrame`, `0x109F5309`)**:
   - Once gameplay calls `GetFrame` during `GLevel->Tick`, `UViewport::Draw` later calls `GetFrame` on the same frame to skin D3D vertices. At `0x109F5309`, `je 0x109F5341` (`74 36`) cleared the "already updated this frame" flag `[esp+0x38]` whenever `Owner->LastRenderTime != Level->TimeSeconds`, causing bone rotation controllers (`0x109F84A6..0x109F85E5`) to step twice on the rendered peer.
   - Patch: `74 36` → `EB 36` (`jmp 0x109F5341`), preserving vertex skinning while exiting cleanly at `0x109F5E5A` without double-stepping bone controllers.

### 2.3 Local `LastRenderTime` Gameplay Gates

`Actor->LastRenderTime` (`[Actor + 0x50]`) is written strictly by local visibility traversal (`0x10ABFF4A`, `0x10AF7145`, `0x10AFD1EA`), yet three AI routines branch gameplay logic on it:

| Site | VA | Vanilla Behavior | Patch |
| :--- | :--- | :--- | :--- |
| `AEAIPawn::vt+0x2BC` | `0x10C1852C` (in `0x10C18480`) | Returns `1` (skipping `AEPawn::Tick` physics & `UserChecksum0`) when `LastRenderTime == 0.0f` or `TimeSeconds - LastRenderTime > 1.0f`. | `xor eax, eax; pop esi; ret` (`33 C0 5E C3 90 90 90 90`) — disables visibility-gated AI tick culling. |
| `AEAIController::PawnWasRenderedRecently` | `0x10B9A66D` (in `0x10B9A650`) | Checks `TimeSeconds - Pawn->LastRenderTime <= 0.2f` across 4 callers (AI target scoring `+8` @ `0x10940309`, attachment updates @ `0x10B8A3E9`, ambient `SRABegin` @ `0x10B9CBBB`, `GetEyeInfo` @ `0x10C192E5`). | `7A 06` (`jp`) → `EB 06` (`jmp`), returning `0` identically on both peers. |
| Off-screen AI `1.75x` speed boost | `0x10BB53D0` (in `0x10BB53B0`) | Multiplies `Pawn->GroundSpeed` (`[ecx+0x2E8]`) by `1.75f` when `TimeSeconds - LastRenderTime > 0.2f`. | `75 1C` (`jne`) → `EB 1C` (`jmp`), disabling the off-screen speed boost. |

### 2.4 Render-Mutated Controller Transforms Hashed into `UserChecksum0`

In `AEPawn::Tick` (`0x10B8A503..0x10B8A547`), the engine folds `Pawn->Location` and `Pawn->Rotation` into `UserChecksum0`, and for player pawns (`[esi+0x2C] & 0x20`) also folds `Controller->Location` (`+0xE8`) and `Controller->Rotation` (`+0xF4`). However, `UViewport::Draw` → `PlayerCalcView` → `AEPlayerCam::execFollowingCalcView` (`0x10C08150` / `0x10C0D7AC`) overwrites `Controller->Location` during local camera rendering outside lockstep ticks.

- Patch (`0x10B8A51F`): change `je 0x10B8A548` (`74 27`) → `jmp 0x10B8A548` (`EB 27`) to keep `Pawn->Location`/`Rotation` checksummed while excluding camera-mutated `Controller` transforms.

---

## 3. Runtime Tracing & In-Memory Resync Architecture

For debugging or recovering from residual desyncs, the launcher supports runtime hooks injected via `VirtualAllocEx` (see [`../scct_coop_enhancer/src/trace.rs`](../scct_coop_enhancer/src/trace.rs) and [`../scct_coop_enhancer/src/resync.rs`](../scct_coop_enhancer/src/resync.rs)):

- **Lockstep Trace Ring Buffer**: Hooks `SyncEngine` reset, tick (`0x10A792A6`), checksum send, and checksum compare (`0x10DF86BA`) into a shared memory ring buffer, writing `System/scct_startup_trace*.txt` and dumping all `GLevel->Actors` transforms into `System/scct_desync_dump*.txt` if a mismatch occurs.
- **Experimental Host → Client In-Memory Resync (`--resync`)**:
  1. Traps mismatches at `0x10DF86BA` before `SyncEngine->Status = 6` disconnects the session.
  2. Parks both peers at a deterministic simulation step barrier (`0x10A792A6`).
  3. Streams a CRC32-verified chunked UDP snapshot (`"SCRS"`) from Host to Client containing `UserChecksum0/1`, `SimStation` slot accumulators, `SyncEngine + 0xB8..+0xA83` (`MT19937`), and active `AEPawn`/`AEAIController` simulation fields.
  4. Validates every actor's `(actor_index, NameIndex, ClassNameIndex)` before writing in place, invalidates modified pawns' `USkeletalMeshInstance->CachedFrameCounter`, and releases the barrier on `ACK`.

See [`../scct_coop_enhancer/src/patcher.rs`](../scct_coop_enhancer/src/patcher.rs) for exact byte signatures of every determinism patch.
