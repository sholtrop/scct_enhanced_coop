//! Engine-level Co-op Interaction Lock, SoftBody Rope Sync & Multi-Player Volume Fixes for
//! `splintercell3.exe`.
//!
//! All patch sites live at verified fixed `.text` file offsets (`VA - 0x1090_0000`, where
//! `.text` has `VA = 0x1090_1000` and `PointerToRawData = 0x001000`) with **zero** PE base
//! relocations, **zero** PE exports, and **zero** callers/references into any repurposed dead
//! inline-function cave.
//!
//! Three independent, 100% lockstep-deterministic toggles are provided:
//!
//! 1. **Co-op Interaction Lock, Lifecycle & Multi-Player `IPC` Fixes** (`COOP_INTERACTION_LOCK_SITES`):
//!    - Fixes `UGlobalInteractionManager::InitInteract` (`0x1099EAF2`): unlocks ALL previously
//!      locked entries (`0..Num-1`, not just `[0]`) and falls through to `0x1099EB0A` so the new
//!      exclusive `AEInteractObject` is always tracked in `node->LockedList` (prevents permanent
//!      orphaned `bLock = 1` / greyed-out interactions).
//!    - Fixes `UGlobalInteractionManager::PostInteract` (`0x1099DDF2`, `0x1099DE2A`): clears
//!      `obj->bLock` unconditionally even if `obj` was not present in `node->LockedList`.
//!    - Fixes `AEInteractObject::Destroy` (`0x1099E6FF`, `0x1099E753` -> `0x10A9C7E0`): removes
//!      destroyed objects from every `GIM` player node's `LockedList` and `CoopActionObj` slot
//!      before freeing (eliminates dangling pointers / UAF from `Destroy()`-without-`PostInteract`
//!      subclasses like `EBombInteraction`, `EHotWireInteraction`, `EPumpInteraction`, etc.).
//!    - Adds a deterministic stale-lock reclaimer before `UGlobalInteractionManager::Tick`
//!      (`0x10C15EC1` -> `0x1099CCB0`): each simulation tick, for every `GIM` player node with
//!      locked entries, if the player is in `s_PlayerWalking` (`eventCanPerformCloseInteraction()
//!      != 0` @ `0x1099CD20`) or dead/unpossessed (`Pawn == NULL || Pawn->Health <= 0`), unlocks
//!      and clears `node->LockedList`. This broadly fixes every SP interaction that omits
//!      `Super.PostInteract` (`ESBRopeClimbInteraction` on Bank/Displace/Battery,
//!      `ERappellingInteraction` & `ERapelBottomInteraction` on Displace/SeoulOne,
//!      `EProMoveInteraction`, `AEShutterInteraction`, interrupted `s_Computer`, etc.) while
//!      keeping ropes/rappels safely locked while a player is actively climbing/rappelling.
//!    - Fixes multi-player `AEInteractObject::InteractionPlayerController` (`+0x2B8`) clobbering:
//!      * `AEInteractObject::UnTouch` (`0x1099E785` -> `0x10A99160`) and
//!        `execResetPlayerInteraction` (`0x1099F3AD`, delegated to `UnTouch`) only clear `+0x2B8`
//!        when it belongs to the removing player, and reassign it to another player who still has
//!        `this` in their `EInteractionManager` if one exists.
//!      * `AEInteractObject::InitInteract` (`0x1099F3F0` -> `0x1099F3BC`) sets `+0x2B8 = Instigator`
//!        for player controllers before `eventInitInteract`.
//!      * `AEVentInteraction::InitInteract` (`0x10C6D60E`) reads `Instigator` (`[esp+0x14]`)
//!        directly instead of potentially-stale `[esi+0x2B8]`.
//!      * `AEInteractObject::CPPIsAvailable` (`0x1099D1E5` -> `0x1099D850`) guards against NULL
//!        `InteractionPlayerController` / `Pawn`.
//!
//! 2. **Multi-Player `EAIVolume.PawnLeavingVolume` Guard** (`COOP_AIVOLUME_LEAVE_SITES`):
//!    - Hooks `APhysicsVolume::SetZone` (`0x10A9731B` -> `0x10A9CA50`): in multiplayer
//!      (`Level->bMultiplayerMap != 0`), when a player pawn leaves an `AEAIVolume` (vtable
//!      `0x110C92B8`) with `PLPatternID != NAME_None` (`+0x3C4`), if any other living player pawn
//!      is still inside that volume (`otherPawn->PhysicsVolume == vol || vol->Encompasses(loc)`),
//!      temporarily zeroes `PLPatternID` across `ProcessEvent(PawnLeavingVolume)` and restores it
//!      immediately afterward. Fixes `05_Displace01` `EAIVolume0` (`RappelActivationTrig` ->
//!      `RoofVentilation.RappelOff`) disabling `RappelPipe` while Player 2 is still at the shaft,
//!      and protects all 12 SP `EAIVolume` `PLPatternID` zones across the campaign.
//!
//! 3. **`USoftBody::Tick` Off-Screen Render Gate Sync** (`COOP_SOFTBODY_SYNC_SITES`):
//!    - `USoftBody::Tick` (`0x10A4B480`, shared by `USoftBody`, `UESBCloth`, `UESBCustom`,
//!      `UESBPatch`, `UESBStripDoor`, `UESBRopeClimb`, `UESBRope`) skips `vtable+0x98` (`Update()`)
//!      whenever `SoftBody->LastRenderTime (+0x170) + 5.0f <= Level->TimeSeconds (+0x430)`.
//!      `LastRenderTime` initializes to `-10.0f` and is only written by `USoftBody::Render`
//!      (`0x10A514D4`) when the local camera renders the actor.
//!    - In Co-op, when one player climbs a softbody rope (e.g., `03_Bank_COOP` roof
//!      `ESBRopeClimbActor0`) while the remote peer's camera is elsewhere, the remote peer never
//!      runs `UESBRopeClimb::Update` (`0x10C7DF60` — `SatisfyConstraints` unroll + `MoveActor` on
//!      the attached pawn + synced `appFrand()`), leaving the climber frozen at the entry pose and
//!      triggering an immediate lockstep desync.
//!    - NOPing `jne 0x10A4B4AB` (`75 08` -> `90 90`) at `0x10A4B4A1` (inside zero-reloc slice
//!      `0x14B49E..0x14B4AC`) makes all `USoftBody` ticks 100% deterministic across both peers.

use anyhow::{Result, bail};

/// Fixed-offset `.exe` patch descriptor: `(name, file_offset, orig_bytes, patched_bytes)`.
pub type FixedBytePatchSite = (&'static str, usize, &'static [u8], &'static [u8]);

/// Flag 1 (`coop_interaction_lock_fixes`): 16 zero-reloc sites in `splintercell3.exe`.
pub const COOP_INTERACTION_LOCK_SITES: &[FixedBytePatchSite] = &[
    // Cave: unlock_node_list(ecx = PlayerNode*) @ VA 0x1099D640 (47 bytes; dead SelectNext/Prev)
    (
        "CAVE_UNLOCK_NODE_LIST (0x1099D640)",
        0x09D640,
        &[
            0x8B, 0x51, 0x2C, 0x8B, 0x41, 0x34, 0x4A, 0x3B, 0xC2, 0x7D, 0x07, 0x40, 0x89, 0x41,
            0x34, 0xB0, 0x01, 0xC3, 0xC7, 0x41, 0x34, 0x00, 0x00, 0x00, 0x00, 0xB0, 0x01, 0xC3,
            0xCC, 0xCC, 0xCC, 0xCC, 0x8B, 0x41, 0x34, 0x85, 0xC0, 0x7F, 0x03, 0x8B, 0x41, 0x2C,
            0x48, 0x89, 0x41, 0x34, 0xB0,
        ],
        &[
            0x52, 0x51, 0x8B, 0x51, 0x10, 0x85, 0xD2, 0x7E, 0x1C, 0x50, 0x8B, 0x49, 0x0C, 0x85,
            0xC9, 0x74, 0x13, 0x8B, 0x01, 0x85, 0xC0, 0x74, 0x07, 0x80, 0xA0, 0xBC, 0x02, 0x00,
            0x00, 0xFE, 0x83, 0xC1, 0x04, 0x4A, 0x75, 0xED, 0x58, 0x59, 0xC7, 0x41, 0x10, 0x00,
            0x00, 0x00, 0x00, 0x5A, 0xC3,
        ],
    ),
    // Cave: gim_tick_hook(ecx = GIM*) @ VA 0x1099CCB0 (68 bytes; dead inline accessors)
    (
        "CAVE_GIM_TICK_HOOK (0x1099CCB0)",
        0x09CCB0,
        &[
            0x8B, 0x44, 0x24, 0x04, 0x89, 0x41, 0x3C, 0xC2, 0x04, 0x00, 0xCC, 0xCC, 0xCC, 0xCC,
            0xCC, 0xCC, 0x8B, 0x41, 0x04, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
            0xCC, 0xCC, 0xCC, 0xCC, 0x8B, 0x44, 0x24, 0x04, 0x8B, 0x11, 0xC1, 0xE0, 0x04, 0x03,
            0xC2, 0xC2, 0x04, 0x00, 0xCC, 0xCC, 0x8B, 0x41, 0x04, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC,
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xC7, 0x41, 0x04, 0x00,
        ],
        &[
            0x51, 0x56, 0x8B, 0x71, 0x40, 0x85, 0xF6, 0x74, 0x34, 0x83, 0x7E, 0x10, 0x00, 0x7E,
            0x2A, 0x8B, 0x4E, 0x08, 0x85, 0xC9, 0x74, 0x1C, 0x8B, 0x81, 0xB4, 0x02, 0x00, 0x00,
            0x85, 0xC0, 0x74, 0x12, 0x83, 0xB8, 0x20, 0x04, 0x00, 0x00, 0x00, 0x7E, 0x09, 0xE8,
            0x42, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x74, 0x07, 0x89, 0xF1, 0xE8, 0x57, 0x09, 0x00,
            0x00, 0x8B, 0x36, 0xEB, 0xC8, 0x5E, 0x59, 0xE9, 0x4C, 0x20, 0x00, 0x00,
        ],
    ),
    // Cave: AEInteractObject::CPPIsAvailable NULL guard @ VA 0x1099D850 (27 bytes; dead GetCurrentInteraction)
    (
        "CAVE_CPP_IS_AVAIL_GUARD (0x1099D850)",
        0x09D850,
        &[
            0x8B, 0x41, 0x34, 0x85, 0xC0, 0x7C, 0x0F, 0x8B, 0x51, 0x2C, 0x4A, 0x3B, 0xC2, 0x7F,
            0x07, 0x8B, 0x49, 0x28, 0x8B, 0x04, 0x81, 0xC3, 0x33, 0xC0, 0xC3, 0xCC, 0xCC,
        ],
        &[
            0x85, 0xC0, 0x74, 0x0F, 0x8B, 0x88, 0xB4, 0x02, 0x00, 0x00, 0x85, 0xC9, 0x74, 0x05,
            0xE9, 0x88, 0xF9, 0xFF, 0xFF, 0x83, 0xC4, 0x10, 0xE9, 0x2D, 0xFA, 0xFF, 0xFF,
        ],
    ),
    // Cave: AEInteractObject::Destroy GIM LockedList cleanup @ VA 0x10A9C7E0 (80 bytes; dead inline helpers)
    (
        "CAVE_DESTROY_CLEANUP (0x10A9C7E0)",
        0x19C7E0,
        &[
            0x8D, 0x41, 0x08, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
            0xCC, 0xCC, 0x8B, 0xC1, 0x8B, 0x4C, 0x24, 0x04, 0x8B, 0x11, 0x89, 0x10, 0xC2, 0x04,
            0x00, 0xCC, 0xCC, 0xCC, 0x8B, 0x01, 0x25, 0x00, 0x00, 0xC0, 0xFF, 0xC3, 0xCC, 0xCC,
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x8B, 0x01, 0xC1, 0xE8, 0x16, 0xC3, 0xCC, 0xCC,
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xC2, 0x04, 0x00, 0xCC, 0xCC, 0xCC,
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        ],
        &[
            0x80, 0xA7, 0xBC, 0x02, 0x00, 0x00, 0xFE, 0x8B, 0x47, 0x78, 0x85, 0xC0, 0x74, 0x40,
            0x8B, 0x80, 0xD8, 0x05, 0x00, 0x00, 0x85, 0xC0, 0x74, 0x36, 0x8B, 0x48, 0x40, 0x85,
            0xC9, 0x74, 0x2F, 0x39, 0x79, 0x18, 0x75, 0x07, 0xC7, 0x41, 0x18, 0x00, 0x00, 0x00,
            0x00, 0x8B, 0x51, 0x10, 0x85, 0xD2, 0x7E, 0x18, 0x8B, 0x41, 0x0C, 0x85, 0xC0, 0x74,
            0x11, 0x39, 0x38, 0x74, 0x08, 0x83, 0xC0, 0x04, 0x4A, 0x75, 0xF6, 0xEB, 0x05, 0xE8,
            0x16, 0x0E, 0xF0, 0xFF, 0x8B, 0x09, 0xEB, 0xCD, 0x5F, 0xC3,
        ],
    ),
    // Cave: AEInteractObject::UnTouch multi-player IPC ownership preservation @ VA 0x10A99160 (118 bytes)
    (
        "CAVE_UNTOUCH_TAIL (0x10A99160)",
        0x199160,
        &[
            0x8B, 0x54, 0x24, 0x08, 0x8B, 0xC1, 0x8B, 0x4C, 0x24, 0x04, 0x89, 0x08, 0x8A, 0x4C,
            0x24, 0x0C, 0x89, 0x50, 0x04, 0x88, 0x48, 0x08, 0xC2, 0x0C, 0x00, 0xCC, 0xCC, 0xCC,
            0xCC, 0xCC, 0xCC, 0xCC, 0x8A, 0x41, 0x5E, 0x84, 0xC0, 0x76, 0x15, 0x8B, 0x44, 0x24,
            0x04, 0x8A, 0x51, 0x5F, 0x0C, 0x21, 0x84, 0xD0, 0x75, 0x08, 0xB8, 0x01, 0x00, 0x00,
            0x00, 0xC2, 0x04, 0x00, 0x33, 0xC0, 0xC2, 0x04, 0x00, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x8B, 0x44, 0x24, 0x04,
            0x85, 0xC0, 0x8B, 0x44, 0x24, 0x08, 0x74, 0x20, 0x85, 0xC0, 0x75, 0x14, 0x8A, 0x41,
            0x5E, 0x84, 0xC0, 0x76, 0x2E, 0x8B, 0x44, 0x24, 0x0C, 0x8A, 0x51, 0x5F, 0x0C, 0x21,
            0x84, 0xD0, 0x75, 0x21, 0xB8, 0x01,
        ],
        &[
            0x50, 0x8B, 0x88, 0x00, 0x04, 0x00, 0x00, 0x85, 0xC9, 0x74, 0x06, 0x56, 0xE8, 0xEF,
            0x52, 0xF0, 0xFF, 0x58, 0x39, 0x86, 0xB8, 0x02, 0x00, 0x00, 0x75, 0x58, 0xC7, 0x86,
            0xB8, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x46, 0x78, 0x85, 0xC0, 0x74,
            0x47, 0x8B, 0x80, 0xD8, 0x05, 0x00, 0x00, 0x85, 0xC0, 0x74, 0x3D, 0x8B, 0x48, 0x40,
            0x85, 0xC9, 0x74, 0x36, 0x8B, 0x51, 0x08, 0x85, 0xD2, 0x74, 0x24, 0x8B, 0x82, 0x00,
            0x04, 0x00, 0x00, 0x85, 0xC0, 0x74, 0x1A, 0x53, 0x8B, 0x58, 0x2C, 0x85, 0xDB, 0x7E,
            0x11, 0x8B, 0x40, 0x28, 0x85, 0xC0, 0x74, 0x0A, 0x39, 0x30, 0x74, 0x0B, 0x83, 0xC0,
            0x04, 0x4B, 0x75, 0xF6, 0x5B, 0x8B, 0x09, 0xEB, 0xCD, 0x5B, 0x89, 0x96, 0xB8, 0x02,
            0x00, 0x00, 0x5E, 0xC2, 0x04, 0x00,
        ],
    ),
    // Hook: GIM::InitInteract @ 0x1099EAF2 (unlock full LockedList & fall through to add new obj)
    (
        "HOOK_GIM_INIT_INTERACT (0x1099EAF2)",
        0x09EAF2,
        &[
            0x8B, 0x46, 0x0C, 0x8B, 0x00, 0x83, 0xA0, 0xBC, 0x02, 0x00, 0x00, 0xFE, 0xC7, 0x46,
            0x10, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x5E, 0x08, 0xEB, 0x18,
        ],
        &[
            0x89, 0xF1, 0xE8, 0x47, 0xEB, 0xFF, 0xFF, 0xEB, 0x0F, 0x90, 0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        ],
    ),
    // Hook: GIM::PostInteract @ 0x1099DDF2 (reuse unlock_node_list + unconditional bLock clear epilogue)
    (
        "HOOK_GIM_POST_INTERACT_1 (0x1099DDF2)",
        0x09DDF2,
        &[
            0x33, 0xD2, 0x85, 0xF6, 0x7E, 0x25, 0xEB, 0x06, 0x8D, 0x9B, 0x00, 0x00, 0x00, 0x00,
            0x8B, 0x41, 0x0C, 0x8B, 0x04, 0x90, 0x84, 0x98, 0xBC, 0x02, 0x00, 0x00, 0x74, 0x07,
            0x83, 0xA0, 0xBC, 0x02, 0x00, 0x00, 0xFE, 0x8B, 0x41, 0x10, 0x42, 0x3B, 0xD0, 0x7C,
            0xE3, 0xC7, 0x41, 0x10, 0x00, 0x00, 0x00, 0x00,
        ],
        &[
            0xE8, 0x49, 0xF8, 0xFF, 0xFF, 0xEB, 0x2B, 0x85, 0xFF, 0x74, 0x07, 0x80, 0xA7, 0xBC,
            0x02, 0x00, 0x00, 0xFE, 0x5F, 0x5E, 0x5B, 0xC2, 0x08, 0x00, 0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        ],
    ),
    // Hook: GIM::PostInteract epilogue redirect @ 0x1099DE2A -> 0x1099DDF9
    (
        "HOOK_GIM_POST_INTERACT_2 (0x1099DE2A)",
        0x09DE2A,
        &[0x5F, 0x5E, 0x5B],
        &[0xEB, 0xCD, 0x90],
    ),
    // Hook: AEInteractObject::Destroy editor-mode branch target adjustment @ 0x1099E6FF
    (
        "HOOK_DESTROY_JE (0x1099E6FF)",
        0x09E6FF,
        &[0x75, 0x53],
        &[0x75, 0x58],
    ),
    // Hook: AEInteractObject::Destroy epilogue -> CAVE_DESTROY_CLEANUP @ 0x1099E753
    (
        "HOOK_DESTROY_TAIL (0x1099E753)",
        0x09E753,
        &[0x5E, 0x5F, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC],
        &[0x5E, 0xE9, 0x87, 0xE0, 0x0F, 0x00, 0x5F, 0xC3],
    ),
    // Hook: AEInteractObject::UnTouch -> CAVE_UNTOUCH_TAIL @ 0x1099E785
    (
        "HOOK_UNTOUCH (0x1099E785)",
        0x09E785,
        &[
            0x8B, 0x88, 0x00, 0x04, 0x00, 0x00, 0x56, 0xE8, 0xCF, 0xFC, 0xFF, 0xFF, 0xC7, 0x86,
            0xB8, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        &[
            0xE9, 0xD6, 0xA9, 0x0F, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        ],
    ),
    // Hook: execResetPlayerInteraction -> AEInteractObject::UnTouch + inline cave init_interact_set_ipc @ 0x1099F3AD
    (
        "HOOK_RESET_AND_INIT_IPC (0x1099F3AD)",
        0x09F3AD,
        &[
            0x85, 0xC0, 0x74, 0x36, 0xF6, 0x40, 0x2C, 0x20, 0x74, 0x30, 0x8B, 0x80, 0xB4, 0x02,
            0x00, 0x00, 0x85, 0xC0, 0x75, 0x10, 0x8B, 0x8F, 0xB8, 0x02, 0x00, 0x00, 0x85, 0xC9,
            0x74, 0x02, 0x8B, 0xC1, 0x85, 0xC0, 0x74, 0x16, 0x8B, 0x88, 0x00, 0x04, 0x00, 0x00,
            0x57, 0xE8, 0x83, 0xF0, 0xFF, 0xFF, 0xC7, 0x87, 0xB8, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x5F, 0x5E, 0x59, 0xC2, 0x08, 0x00, 0xCC, 0xCC, 0xCC,
        ],
        &[
            0x50, 0x89, 0xF9, 0xE8, 0xAB, 0xF3, 0xFF, 0xFF, 0x5F, 0x5E, 0x59, 0xC2, 0x08, 0x00,
            0x90, 0x53, 0x56, 0x57, 0x8B, 0x7C, 0x24, 0x10, 0x85, 0xFF, 0x74, 0x0F, 0xF6, 0x87,
            0xC0, 0x02, 0x00, 0x00, 0x01, 0x74, 0x06, 0x89, 0xB9, 0xB8, 0x02, 0x00, 0x00, 0xE9,
            0x1C, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        ],
    ),
    // Hook: AEInteractObject::InitInteract -> init_interact_set_ipc @ 0x1099F3F0
    (
        "HOOK_INIT_INTERACT (0x1099F3F0)",
        0x09F3F0,
        &[0x53, 0x56, 0x57, 0x8B, 0x7C, 0x24, 0x10],
        &[0xE9, 0xC7, 0xFF, 0xFF, 0xFF, 0x90, 0x90],
    ),
    // Hook: AEInteractObject::CPPIsAvailable -> CAVE_CPP_IS_AVAIL_GUARD @ 0x1099D1E5
    (
        "HOOK_CPP_IS_AVAILABLE (0x1099D1E5)",
        0x09D1E5,
        &[0x8B, 0x88, 0xB4, 0x02, 0x00, 0x00],
        &[0xE9, 0x66, 0x06, 0x00, 0x00, 0x90],
    ),
    // Hook: AEVentInteraction::InitInteract -> use Instigator [esp+0x14] instead of stale IPC @ 0x10C6D60E
    (
        "HOOK_VENT_INIT_INTERACT (0x10C6D60E)",
        0x36D60E,
        &[0x8B, 0xBE, 0xB8, 0x02, 0x00, 0x00],
        &[0x8B, 0x7C, 0x24, 0x14, 0x90, 0x90],
    ),
    // Hook: AEchelonLevelInfo::Tick -> CAVE_GIM_TICK_HOOK @ 0x10C15EC1
    (
        "HOOK_GIM_TICK_CALL (0x10C15EC1)",
        0x315EC1,
        &[0xE8, 0x7A, 0x8E, 0xD8, 0xFF],
        &[0xE8, 0xEA, 0x6D, 0xD8, 0xFF],
    ),
];

/// Flag 2 (`coop_aivolume_leave_guard`): 2 zero-reloc sites in `splintercell3.exe`.
pub const COOP_AIVOLUME_LEAVE_SITES: &[FixedBytePatchSite] = &[
    // Cave: aivolume_leave_guard_hook @ VA 0x10A9CA50 (186 bytes; dead inline helpers)
    (
        "CAVE_AIVOL_LEAVE (0x10A9CA50)",
        0x19CA50,
        &[
            0x8B, 0x44, 0x24, 0x04, 0x83, 0xC0, 0x0C, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
            0xCC, 0xCC, 0x8B, 0x44, 0x24, 0x04, 0x8A, 0x08, 0x8B, 0x54, 0x24, 0x08, 0x33, 0xC0,
            0x3A, 0x0A, 0x1B, 0xC0, 0xF7, 0xD8, 0xC2, 0x08, 0x00, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x8B, 0x01, 0x8B, 0x4C, 0x24, 0x04, 0x2B, 0x01,
            0xF7, 0xD8, 0x1B, 0xC0, 0x40, 0xC2, 0x04, 0x00, 0x8B, 0x01, 0xC3, 0xCC, 0xCC, 0xCC,
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x8B, 0x44, 0x24, 0x04,
            0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x8B, 0xC1,
            0x8B, 0x4C, 0x24, 0x04, 0x89, 0x08, 0xC2, 0x04, 0x00, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
            0x8B, 0x44, 0x24, 0x04, 0x83, 0xC0, 0x15, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
            0xCC, 0xCC, 0x8B, 0x44, 0x24, 0x04, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
            0xCC, 0xCC, 0xCC, 0xCC, 0x8B, 0x44, 0x24, 0x04, 0x83, 0xC0, 0x08, 0xC3, 0xCC, 0xCC,
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x8B, 0x44, 0x24, 0x04, 0x83, 0xC0, 0x04, 0xC3,
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xE9, 0x4B, 0x10, 0x06, 0x00, 0xCC,
            0xCC, 0xCC, 0xCC, 0xCC,
        ],
        &[
            0x6A, 0x00, 0x50, 0x81, 0xFD, 0xB8, 0x92, 0x0C, 0x11, 0x75, 0x29, 0x83, 0xBF, 0xC4,
            0x03, 0x00, 0x00, 0x00, 0x74, 0x20, 0xF6, 0x46, 0x2C, 0x20, 0x74, 0x1A, 0x8B, 0x46,
            0x78, 0x85, 0xC0, 0x74, 0x13, 0xF6, 0x80, 0xCC, 0x05, 0x00, 0x00, 0x01, 0x74, 0x0A,
            0x8B, 0x80, 0xD0, 0x05, 0x00, 0x00, 0x85, 0xC0, 0x75, 0x1D, 0x58, 0xFF, 0x74, 0x24,
            0x0C, 0xFF, 0x74, 0x24, 0x0C, 0x50, 0x89, 0xF9, 0xFF, 0x55, 0x10, 0x58, 0x85, 0xC0,
            0x74, 0x06, 0x89, 0x87, 0xC4, 0x03, 0x00, 0x00, 0xC2, 0x08, 0x00, 0x53, 0x8B, 0x98,
            0xE4, 0x02, 0x00, 0x00, 0x8B, 0x88, 0xE0, 0x02, 0x00, 0x00, 0xE3, 0x54, 0x4B, 0x78,
            0x51, 0x8B, 0x04, 0x99, 0x85, 0xC0, 0x74, 0xF6, 0x8B, 0x80, 0xB4, 0x02, 0x00, 0x00,
            0x85, 0xC0, 0x74, 0xEC, 0x39, 0xF0, 0x74, 0xE8, 0x83, 0xB8, 0x20, 0x04, 0x00, 0x00,
            0x00, 0x7E, 0xDF, 0x39, 0xB8, 0xE4, 0x00, 0x00, 0x00, 0x74, 0x1F, 0x51, 0xFF, 0xB0,
            0xF0, 0x00, 0x00, 0x00, 0xFF, 0xB0, 0xEC, 0x00, 0x00, 0x00, 0xFF, 0xB0, 0xE8, 0x00,
            0x00, 0x00, 0x89, 0xF9, 0xE8, 0xDD, 0x2A, 0xFF, 0xFF, 0x59, 0x85, 0xC0, 0x74, 0xB8,
            0x31, 0xC0, 0x87, 0x87, 0xC4, 0x03, 0x00, 0x00, 0x89, 0x44, 0x24, 0x08, 0x5B, 0xE9,
            0x7A, 0xFF, 0xFF, 0xFF,
        ],
    ),
    // Hook: APhysicsVolume::SetZone -> CAVE_AIVOL_LEAVE @ 0x10A9731B
    (
        "HOOK_SETZONE_LEAVE (0x10A9731B)",
        0x19731B,
        &[0x50, 0x8B, 0xCF, 0xFF, 0x55, 0x10],
        &[0xE8, 0x30, 0x57, 0x00, 0x00, 0x90],
    ),
];

/// Flag 3 (`softbody_render_gate_sync`): 1 zero-reloc site in `splintercell3.exe`.
pub const COOP_SOFTBODY_SYNC_SITES: &[FixedBytePatchSite] = &[
    // USoftBody::Tick @ 0x10A4B49E: NOP `jne 0x10A4B4AB` (75 08 -> 90 90) so off-screen
    // softbody ropes/cloth always execute Update() deterministically on both lockstep peers.
    (
        "USOFTBODY_TICK_RENDER_GATE (0x10A4B49E)",
        0x14B49E,
        &[
            0xF6, 0xC4, 0x41, 0x75, 0x08, 0x8B, 0x11, 0xFF, 0xA2, 0x98, 0x00, 0x00, 0x00, 0xC3,
        ],
        &[
            0xF6, 0xC4, 0x41, 0x90, 0x90, 0x8B, 0x11, 0xFF, 0xA2, 0x98, 0x00, 0x00, 0x00, 0xC3,
        ],
    ),
];

fn are_fixed_sites_patched(data: &[u8], sites: &[FixedBytePatchSite]) -> bool {
    sites.iter().all(|&(_name, off, _orig, patched)| {
        data.get(off..off + patched.len()) == Some(patched)
    })
}

fn patch_fixed_sites(data: &mut [u8], sites: &[FixedBytePatchSite], label: &str) -> Result<usize> {
    // Validate every site BEFORE mutating any byte so partial failures never corrupt the buffer.
    for &(name, off, orig, patched) in sites {
        debug_assert_eq!(orig.len(), patched.len());
        let Some(slice) = data.get(off..off + orig.len()) else {
            bail!(
                "splintercell3.exe too small for {} site {} @ 0x{:06X} ({} bytes)",
                label,
                name,
                off,
                orig.len()
            );
        };
        if slice != orig && slice != patched {
            bail!(
                "Unexpected bytes at {} site {} @ 0x{:06X} (cannot safely patch)",
                label,
                name,
                off
            );
        }
    }
    let mut first_off = 0usize;
    for (idx, &(_name, off, _orig, patched)) in sites.iter().enumerate() {
        if idx == 0 {
            first_off = off;
        }
        data[off..off + patched.len()].copy_from_slice(patched);
    }
    Ok(first_off)
}

fn revert_fixed_sites(data: &mut [u8], sites: &[FixedBytePatchSite]) -> bool {
    let mut any = false;
    for &(_name, off, orig, patched) in sites {
        if let Some(slice) = data.get_mut(off..off + orig.len())
            && slice == patched
        {
            slice.copy_from_slice(orig);
            any = true;
        }
    }
    any
}

pub fn is_coop_interaction_lock_fixes_patched(data: &[u8]) -> bool {
    are_fixed_sites_patched(data, COOP_INTERACTION_LOCK_SITES)
}

pub fn patch_coop_interaction_lock_fixes_bytes(data: &mut [u8]) -> Result<usize> {
    patch_fixed_sites(
        data,
        COOP_INTERACTION_LOCK_SITES,
        "Co-op interaction lock/IPC fix",
    )
}

pub fn revert_coop_interaction_lock_fixes_bytes(data: &mut [u8]) -> bool {
    revert_fixed_sites(data, COOP_INTERACTION_LOCK_SITES)
}

pub fn is_coop_aivolume_leave_guard_patched(data: &[u8]) -> bool {
    are_fixed_sites_patched(data, COOP_AIVOLUME_LEAVE_SITES)
}

pub fn patch_coop_aivolume_leave_guard_bytes(data: &mut [u8]) -> Result<usize> {
    patch_fixed_sites(
        data,
        COOP_AIVOLUME_LEAVE_SITES,
        "Co-op EAIVolume PawnLeavingVolume guard",
    )
}

pub fn revert_coop_aivolume_leave_guard_bytes(data: &mut [u8]) -> bool {
    revert_fixed_sites(data, COOP_AIVOLUME_LEAVE_SITES)
}

pub fn is_softbody_render_gate_sync_patched(data: &[u8]) -> bool {
    are_fixed_sites_patched(data, COOP_SOFTBODY_SYNC_SITES)
}

pub fn patch_softbody_render_gate_sync_bytes(data: &mut [u8]) -> Result<usize> {
    patch_fixed_sites(
        data,
        COOP_SOFTBODY_SYNC_SITES,
        "USoftBody::Tick off-screen render gate sync",
    )
}

pub fn revert_softbody_render_gate_sync_bytes(data: &mut [u8]) -> bool {
    revert_fixed_sites(data, COOP_SOFTBODY_SYNC_SITES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn make_synthetic_buf(sites: &[FixedBytePatchSite]) -> Vec<u8> {
        let max_end = sites
            .iter()
            .map(|&(_, off, orig, _)| off + orig.len())
            .max()
            .unwrap_or(0);
        let mut buf = vec![0x90u8; max_end + 16];
        for &(_, off, orig, _) in sites {
            buf[off..off + orig.len()].copy_from_slice(orig);
        }
        buf
    }

    #[test]
    fn test_coop_interaction_lock_sites_synthetic_roundtrip() {
        let mut buf = make_synthetic_buf(COOP_INTERACTION_LOCK_SITES);
        let orig_snapshot = buf.clone();

        assert!(!is_coop_interaction_lock_fixes_patched(&buf));
        assert!(!revert_coop_interaction_lock_fixes_bytes(&mut buf));

        let first = patch_coop_interaction_lock_fixes_bytes(&mut buf).unwrap();
        assert_eq!(first, COOP_INTERACTION_LOCK_SITES[0].1);
        assert!(is_coop_interaction_lock_fixes_patched(&buf));

        // Idempotent second call
        patch_coop_interaction_lock_fixes_bytes(&mut buf).unwrap();
        assert!(is_coop_interaction_lock_fixes_patched(&buf));

        // Partial revert detection and clean re-apply
        let (_, off, orig, _) = COOP_INTERACTION_LOCK_SITES[5];
        buf[off..off + orig.len()].copy_from_slice(orig);
        assert!(!is_coop_interaction_lock_fixes_patched(&buf));
        patch_coop_interaction_lock_fixes_bytes(&mut buf).unwrap();
        assert!(is_coop_interaction_lock_fixes_patched(&buf));

        // Full clean revert matches original snapshot byte-for-byte
        assert!(revert_coop_interaction_lock_fixes_bytes(&mut buf));
        assert!(!is_coop_interaction_lock_fixes_patched(&buf));
        assert_eq!(buf, orig_snapshot);

        // Corrupted bytes fail atomically without mutating other sites
        let (_, bad_off, _, _) = COOP_INTERACTION_LOCK_SITES[3];
        buf[bad_off] ^= 0xFF;
        let corrupted = buf.clone();
        assert!(patch_coop_interaction_lock_fixes_bytes(&mut buf).is_err());
        assert_eq!(buf, corrupted);
    }

    #[test]
    fn test_coop_aivolume_leave_sites_synthetic_roundtrip() {
        let mut buf = make_synthetic_buf(COOP_AIVOLUME_LEAVE_SITES);
        let orig_snapshot = buf.clone();

        assert!(!is_coop_aivolume_leave_guard_patched(&buf));
        assert!(!revert_coop_aivolume_leave_guard_bytes(&mut buf));

        let first = patch_coop_aivolume_leave_guard_bytes(&mut buf).unwrap();
        assert_eq!(first, COOP_AIVOLUME_LEAVE_SITES[0].1);
        assert!(is_coop_aivolume_leave_guard_patched(&buf));

        // Idempotent
        patch_coop_aivolume_leave_guard_bytes(&mut buf).unwrap();
        assert!(is_coop_aivolume_leave_guard_patched(&buf));

        // Clean revert
        assert!(revert_coop_aivolume_leave_guard_bytes(&mut buf));
        assert!(!is_coop_aivolume_leave_guard_patched(&buf));
        assert_eq!(buf, orig_snapshot);

        // Unexpected bytes rejected atomically
        let (_, bad_off, _, _) = COOP_AIVOLUME_LEAVE_SITES[1];
        buf[bad_off] ^= 0xFF;
        let corrupted = buf.clone();
        assert!(patch_coop_aivolume_leave_guard_bytes(&mut buf).is_err());
        assert_eq!(buf, corrupted);
    }

    #[test]
    fn test_softbody_render_gate_sync_sites_synthetic_roundtrip() {
        let mut buf = make_synthetic_buf(COOP_SOFTBODY_SYNC_SITES);
        let orig_snapshot = buf.clone();

        assert!(!is_softbody_render_gate_sync_patched(&buf));
        assert!(!revert_softbody_render_gate_sync_bytes(&mut buf));

        let first = patch_softbody_render_gate_sync_bytes(&mut buf).unwrap();
        assert_eq!(first, COOP_SOFTBODY_SYNC_SITES[0].1);
        assert!(is_softbody_render_gate_sync_patched(&buf));

        // Idempotent
        patch_softbody_render_gate_sync_bytes(&mut buf).unwrap();
        assert!(is_softbody_render_gate_sync_patched(&buf));

        // Clean revert
        assert!(revert_softbody_render_gate_sync_bytes(&mut buf));
        assert!(!is_softbody_render_gate_sync_patched(&buf));
        assert_eq!(buf, orig_snapshot);

        // Unexpected bytes rejected atomically
        let (_, bad_off, _, _) = COOP_SOFTBODY_SYNC_SITES[0];
        buf[bad_off] ^= 0xFF;
        let corrupted = buf.clone();
        assert!(patch_softbody_render_gate_sync_bytes(&mut buf).is_err());
        assert_eq!(buf, corrupted);
    }

    #[test]
    fn test_interaction_and_aivolume_sites_non_overlapping_and_targets_valid() {
        let mut ranges: Vec<(&str, usize, usize)> = Vec::new();
        for site in COOP_INTERACTION_LOCK_SITES
            .iter()
            .chain(COOP_AIVOLUME_LEAVE_SITES.iter())
            .chain(COOP_SOFTBODY_SYNC_SITES.iter())
        {
            let (name, off, orig, patched) = *site;
            assert_eq!(orig.len(), patched.len(), "length mismatch in {}", name);
            assert_ne!(orig, patched, "no-op site {}", name);
            let end = off + orig.len();
            for &(oname, ostart, oend) in &ranges {
                assert!(
                    off >= oend || end <= ostart,
                    "overlap between {} (0x{:X}..0x{:X}) and {} (0x{:X}..0x{:X})",
                    name,
                    off,
                    end,
                    oname,
                    ostart,
                    oend
                );
            }
            ranges.push((name, off, end));
        }

        // Verify key relative call/jmp displacements directly
        let check_rel32 = |site_va: u32, patch_bytes: &[u8], rel_pos: usize, expected_target: u32| {
            let rel = i32::from_le_bytes(
                patch_bytes[rel_pos..rel_pos + 4].try_into().unwrap(),
            );
            let actual = (site_va + rel_pos as u32 + 4).wrapping_add(rel as u32);
            assert_eq!(
                actual, expected_target,
                "rel32 target mismatch at VA 0x{:08X}+0x{:X}",
                site_va, rel_pos
            );
        };

        // HOOK_GIM_TICK_CALL (0x10C15EC1) -> CAVE_GIM_TICK_HOOK (0x1099CCB0)
        check_rel32(0x10C1_5EC1, COOP_INTERACTION_LOCK_SITES[15].3, 1, 0x1099_CCB0);
        // CAVE_GIM_TICK_HOOK calls 0x1099CD20, 0x1099D640, jmps 0x1099ED40
        check_rel32(0x1099_CCB0, COOP_INTERACTION_LOCK_SITES[1].3, 0x2A, 0x1099_CD20);
        check_rel32(0x1099_CCB0, COOP_INTERACTION_LOCK_SITES[1].3, 0x35, 0x1099_D640);
        check_rel32(0x1099_CCB0, COOP_INTERACTION_LOCK_SITES[1].3, 0x40, 0x1099_ED40);
        // HOOK_GIM_INIT_INTERACT (0x1099EAF2) calls CAVE_UNLOCK_NODE_LIST (0x1099D640)
        check_rel32(0x1099_EAF2, COOP_INTERACTION_LOCK_SITES[5].3, 3, 0x1099_D640);
        // HOOK_GIM_POST_INTERACT_1 (0x1099DDF2) calls CAVE_UNLOCK_NODE_LIST (0x1099D640)
        check_rel32(0x1099_DDF2, COOP_INTERACTION_LOCK_SITES[6].3, 1, 0x1099_D640);
        // HOOK_DESTROY_TAIL (0x1099E753) jmps CAVE_DESTROY_CLEANUP (0x10A9C7E0)
        check_rel32(0x1099_E753, COOP_INTERACTION_LOCK_SITES[9].3, 2, 0x10A9_C7E0);
        // HOOK_UNTOUCH (0x1099E785) jmps CAVE_UNTOUCH_TAIL (0x10A99160)
        check_rel32(0x1099_E785, COOP_INTERACTION_LOCK_SITES[10].3, 1, 0x10A9_9160);
        // HOOK_INIT_INTERACT (0x1099F3F0) jmps CAVE_INIT_INTERACT_IPC (0x1099F3BC)
        check_rel32(0x1099_F3F0, COOP_INTERACTION_LOCK_SITES[12].3, 1, 0x1099_F3BC);
        // HOOK_CPP_IS_AVAILABLE (0x1099D1E5) jmps CAVE_CPP_IS_AVAIL_GUARD (0x1099D850)
        check_rel32(0x1099_D1E5, COOP_INTERACTION_LOCK_SITES[13].3, 1, 0x1099_D850);
        // HOOK_SETZONE_LEAVE (0x10A9731B) calls CAVE_AIVOL_LEAVE (0x10A9CA50)
        check_rel32(0x10A9_731B, COOP_AIVOLUME_LEAVE_SITES[1].3, 1, 0x10A9_CA50);
        // CAVE_AIVOL_LEAVE (0x10A9CA50) calls AVolume::Encompasses (0x10A8F5D0)
        check_rel32(0x10A9_CA50, COOP_AIVOLUME_LEAVE_SITES[0].3, 0x9F, 0x10A8_F5D0);
    }

    #[test]
    fn test_interaction_and_aivolume_patches_on_clean_retail_exe() {
        let p1 = Path::new("../clean_scct_files/Tom Clancy's Splinter Cell Chaos Theory/System/splintercell3.exe");
        let p2 = Path::new("../../clean_scct_files/Tom Clancy's Splinter Cell Chaos Theory/System/splintercell3.exe");
        let p3 = Path::new("../../../clean_scct_files/Tom Clancy's Splinter Cell Chaos Theory/System/splintercell3.exe");
        let exe_path = if p1.exists() {
            p1
        } else if p2.exists() {
            p2
        } else if p3.exists() {
            p3
        } else {
            return;
        };

        let vanilla = std::fs::read(exe_path).unwrap();
        let mut buf = vanilla.clone();

        // Parse PE base relocations and confirm ZERO reloc entries overlap any patched byte
        let pe_off = u32::from_le_bytes(vanilla[0x3C..0x40].try_into().unwrap()) as usize;
        let opt_off = pe_off + 24;
        let image_base = u32::from_le_bytes(vanilla[opt_off + 28..opt_off + 32].try_into().unwrap());
        let reloc_sz =
            u32::from_le_bytes(vanilla[opt_off + 96 + 44..opt_off + 96 + 48].try_into().unwrap())
                as usize;
        let num_secs = u16::from_le_bytes(vanilla[pe_off + 6..pe_off + 8].try_into().unwrap()) as usize;
        let opt_sz = u16::from_le_bytes(vanilla[pe_off + 20..pe_off + 22].try_into().unwrap()) as usize;
        let reloc_rva =
            u32::from_le_bytes(vanilla[opt_off + 96 + 40..opt_off + 96 + 44].try_into().unwrap());
        let mut reloc_fo = None;
        for s in 0..num_secs {
            let so = opt_off + opt_sz + s * 40;
            let vaddr = u32::from_le_bytes(vanilla[so + 12..so + 16].try_into().unwrap());
            let rptr = u32::from_le_bytes(vanilla[so + 20..so + 24].try_into().unwrap());
            if vaddr == reloc_rva {
                reloc_fo = Some(rptr as usize);
                break;
            }
        }
        let mut reloc_offs = std::collections::HashSet::new();
        if let Some(mut cur) = reloc_fo {
            let end = cur + reloc_sz;
            while cur + 8 <= end {
                let blk_rva = u32::from_le_bytes(vanilla[cur..cur + 4].try_into().unwrap());
                let blk_sz = u32::from_le_bytes(vanilla[cur + 4..cur + 8].try_into().unwrap()) as usize;
                if blk_sz == 0 {
                    break;
                }
                for k in 0..(blk_sz - 8) / 2 {
                    let entry = u16::from_le_bytes(
                        vanilla[cur + 8 + k * 2..cur + 10 + k * 2].try_into().unwrap(),
                    );
                    if (entry >> 12) != 0 {
                        let va = image_base + blk_rva + (entry & 0x0FFF) as u32;
                        if (0x1090_1000..0x110B_7000).contains(&va) {
                            reloc_offs.insert((va - image_base) as usize);
                        }
                    }
                }
                cur += blk_sz;
            }
        }
        for &(name, off, orig, _) in COOP_INTERACTION_LOCK_SITES
            .iter()
            .chain(COOP_AIVOLUME_LEAVE_SITES.iter())
            .chain(COOP_SOFTBODY_SYNC_SITES.iter())
        {
            assert_eq!(
                &vanilla[off..off + orig.len()],
                orig,
                "clean retail EXE mismatch at {} (0x{:06X})",
                name,
                off
            );
            for b in off..off + orig.len() {
                assert!(
                    !reloc_offs.contains(&b),
                    "relocation entry overlaps {} at file offset 0x{:06X}",
                    name,
                    b
                );
            }
        }

        // Independent toggle roundtrips on real retail EXE
        assert!(!is_coop_interaction_lock_fixes_patched(&buf));
        assert!(!is_coop_aivolume_leave_guard_patched(&buf));
        assert!(!is_softbody_render_gate_sync_patched(&buf));

        patch_coop_interaction_lock_fixes_bytes(&mut buf).unwrap();
        assert!(is_coop_interaction_lock_fixes_patched(&buf));
        assert!(!is_coop_aivolume_leave_guard_patched(&buf));
        assert!(!is_softbody_render_gate_sync_patched(&buf));

        patch_coop_aivolume_leave_guard_bytes(&mut buf).unwrap();
        assert!(is_coop_interaction_lock_fixes_patched(&buf));
        assert!(is_coop_aivolume_leave_guard_patched(&buf));
        assert!(!is_softbody_render_gate_sync_patched(&buf));

        patch_softbody_render_gate_sync_bytes(&mut buf).unwrap();
        assert!(is_coop_interaction_lock_fixes_patched(&buf));
        assert!(is_coop_aivolume_leave_guard_patched(&buf));
        assert!(is_softbody_render_gate_sync_patched(&buf));

        // Revert Flag 1 while keeping Flags 2 & 3 active
        assert!(revert_coop_interaction_lock_fixes_bytes(&mut buf));
        assert!(!is_coop_interaction_lock_fixes_patched(&buf));
        assert!(is_coop_aivolume_leave_guard_patched(&buf));
        assert!(is_softbody_render_gate_sync_patched(&buf));

        // Revert Flag 2 while keeping Flag 3 active
        assert!(revert_coop_aivolume_leave_guard_bytes(&mut buf));
        assert!(!is_coop_aivolume_leave_guard_patched(&buf));
        assert!(is_softbody_render_gate_sync_patched(&buf));

        // Revert Flag 3 -> 100% vanilla byte-for-byte
        assert!(revert_softbody_render_gate_sync_bytes(&mut buf));
        assert!(!is_softbody_render_gate_sync_patched(&buf));
        assert_eq!(buf, vanilla);
    }
}
