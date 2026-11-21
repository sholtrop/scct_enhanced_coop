# SCCT File Formats: UPK (`.scl`, `.u`) & UMD (`dynamic-pc.umd`)

*Splinter Cell: Chaos Theory* runs on a heavily customized **Unreal Engine 2.5** build (`FileVersion = 100`, `LicenseeMode = 124`). Game assets live in two primary container formats: Unreal Packages (`.scl`, `.u`, `.utx`, `.usx`, `.ukx`, `.uax`) and the virtual filesystem archive `System/dynamic-pc.umd`.

---

## 1. Common Primitives

### 1.1 `CompactIndex` (Variable-Length Signed Integer)

Used throughout UPK tables, tagged properties, UnrealScript bytecode, and UMD table-of-contents entries:

- **Byte 0 (`b0`)**:
  - Bit 7 (`0x80`): sign bit (`1` = negative).
  - Bit 6 (`0x40`): continuation bit (`1` = another byte follows).
  - Bits 5..0 (`0x3F`): lowest 6 bits of magnitude.
- **Continuation bytes (`b1..b4`)**:
  - Bit 7 (`0x80`): continuation bit.
  - Bits 6..0 (`0x7F`): next 7 bits of magnitude, shifted left by `6 + 7 * (i - 1)`.

### 1.2 `FString` Encoding

UPK `FString` (`NameTable` entries and `StrProperty` values) prefixes the string with a `CompactIndex` character count **excluding** the trailing NUL terminator:

| Length Sign | Encoding | Byte Size After Length |
| :--- | :--- | :--- |
| `length > 0` | Latin-1 / ANSI | `length` bytes + `1` NUL byte (`0x00`) |
| `length < 0` | UTF-16LE | `(-length) * 2` bytes + `2` NUL bytes (`0x00 0x00`) |
| `length == 0` | Empty string | `0` bytes |

> [!NOTE]
> Unlike UPK `FString`, UMD TOC entry paths store a `CompactIndex` byte count that **includes** the trailing `0x00` byte.

---

## 2. Unreal Packages (`.scl`, `.u`, `.utx`, `.usx`, `.ukx`)

### 2.1 Binary Header (`0x00..NameOffset`)

| Offset | Type | Value / Meaning |
| :--- | :--- | :--- |
| `0x00` | `u32` | Magic: `0x9E2A83C1` |
| `0x04` | `u16` | `FileVersion`: `100` (`0x0064`) |
| `0x06` | `u16` | `LicenseeMode`: `124` (`0x007C`) |
| `0x08` | `u32` | SCCT extra header word (`0`) |
| `0x0C` | `u32` | `PackageFlags` (e.g. `0x00000001` = `PKG_AllowDownload`) |
| `0x10` | `u32` | `NameCount` |
| `0x14` | `u32` | `NameOffset` (`0xAD` in base retail packages; `0xB3` in patch/DLC packages such as `05_NuclearPlant.scl` and `07_UNhq.scl`) |
| `0x18` | `u32` | `ExportCount` |
| `0x1C` | `u32` | `ExportOffset` |
| `0x20` | `u32` | `ImportCount` |
| `0x24` | `u32` | `ImportOffset` |
| `0x28` | `u32` | Build string marker: `0x0FF0ADDE` |
| `0x2C` | `CompactIndex` + bytes (XOR `0xFF`) | Compiler build stamp (length includes the trailing NUL byte, each payload byte XORed with `0xFF`; ends at `0x91` when `NameOffset = 0xAD` or `0x97` when `NameOffset = 0xB3`) |
| `after stamp` | `[u8; 16]` | Package GUID (`0x91` when `NameOffset = 0xAD`) |
| `+0x10` | `u32` | `GenerationCount` (`1`; at `0xA1` when `NameOffset = 0xAD`) |
| `+0x14` | `u32` | `Generation[0].ExportCount` (`0xA5` when `NameOffset = 0xAD`) |
| `+0x18` | `u32` | `Generation[0].NameCount` (`0xA9` when `NameOffset = 0xAD`) |

When adding names or exports, update both `0x10`/`0x18` **and** `Generation[0]` right after `GenerationCount` (locate it dynamically past the build stamp + 16-byte GUID, or `NameOffset - 8` when `GenerationCount == 1`).

### 2.2 Tables & Object References

All object references are signed `CompactIndex` integers (`i32` in fixed fields):

- `ref == 0`: `None` (null)
- `ref > 0`: 1-based index into `ExportTable` (`exports[ref - 1]`)
- `ref < 0`: 1-based index into `ImportTable` (`imports[-ref - 1]`)

Table entry layouts:

- **Name Table** (`NameCount` entries at `NameOffset`):
  - `Name : FString`
  - `Flags : u32` (commonly `0x00070010` for script/property names)
- **Import Table** (`ImportCount` entries at `ImportOffset`):
  - `ClassPackage : CompactIndex` (Name index, e.g. `Core`, `Engine`)
  - `ClassName : CompactIndex` (Name index, e.g. `Package`, `SkeletalMesh`)
  - `PackageIndex : i32` (signed outer object reference; `0` for top-level package imports)
  - `ObjectName : CompactIndex` (Name index)
- **Export Table** (`ExportCount` entries at `ExportOffset`):
  - `ClassIndex : CompactIndex` (`0` means `UClass` definition)
  - `SuperIndex : CompactIndex`
  - `PackageIndex : i32` (signed outer object reference)
  - `ObjectName : CompactIndex` (Name index)
  - `ObjectFlags : u32`
  - `SerialSize : CompactIndex`
  - `SerialOffset : CompactIndex` (present **only** if `SerialSize > 0`)

### 2.3 `UObject` Tagged Property Stream

Most `AActor` exports begin with an optional `FStateFrame` prefix before their property list:

```text
Node         : CompactIndex   (object ref; if != 0, an extra CompactIndex Offset follows)
StateNode    : CompactIndex
ProbeMask    : u64            (8 bytes)
LatentAction : u32            (4 bytes)
[Offset      : CompactIndex]  (present only when Node != 0)
```

Following the optional `StateFrame`, properties are serialized as a sequence of `FPropertyTag` records terminated by the Name index for `"None"`:

```text
NameIndex : CompactIndex  (stop if names[NameIndex] == "None")
InfoByte  : u8
    bits 0..3 : Type (1=Byte, 2=Int, 3=Bool, 4=Float, 5=Object, 6=Name,
                      9=Array, 10=Struct, 11=Vector, 12=Rotator, 13=Str, ...)
    bits 4..6 : SizeCode (0->1B, 1->2B, 2->4B, 3->12B, 4->16B,
                          5->u8 size, 6->u16 size, 7->u32 size)
    bit 7     : For BoolProperty (Type 3): the boolean value itself (0 payload bytes).
                For all other types: IsArrayIndex flag (array index follows size).
[StructName : CompactIndex]  (only if Type == 10)
[Size       : u8|u16|u32]    (only if SizeCode in 5..7)
[ArrayIndex : u8|u16]        (only if Type != 3 and bit 7 set; if b0 & 0x80, 2-byte big-endian)
[ValueBytes : Size bytes]    (omitted for BoolProperty)
```

> [!WARNING]
> **SCCT `LevelInfo` `FPropertyTag.Size` quirk**: On `EchelonLevelInfo`, the `Patrols` and `DynamicEvents` struct array properties can under-report `Size` relative to their inner nested struct termination bytes. Parsers walking `LevelInfo0` past those fields must resynchronize to the next valid property tag (see [`scripts/upk.py`](./scripts/upk.py)).

### 2.4 Critical Constraints for Editing `.scl` Map Packages

1. **`TLazyArray` Absolute File Offsets**:
   - Geometry, mesh, texture, and sound exports (`Model`, `StaticMesh`, `Texture`, `Sound`) store `TLazyArray` blocks prefixed with an **absolute 32-bit file offset (`SavedPos`)** pointing to the end of each array.
   - Shifting any byte inside the original export data block invalidates thousands of `TLazyArray` offsets and crashes the engine on map load.
   - **Safe write strategy**: Keep the original file prefix (`0x00 .. min(ImportOffset, ExportOffset)`) at identical byte offsets. Append any modified or newly created export payloads after that prefix, update their `ExportEntry.SerialOffset`/`SerialSize`, and write the expanded Name, Import, and Export tables at the end.

2. **`MyLevel` (`ULevel`) Export Layout**:
   - The `MyLevel` export (`class = Level`) holds the runtime actor list (`ULevelBase::Actors`) and contains no `TLazyArray` fields before the actor array:
     - Leading `CompactIndex` for `"None"` (empty property list)
     - `db_num : i32` and `db_max : i32` (`db_num == db_max`)
     - `db_num` `CompactIndex` object references (`Export` indices of every actor loaded into the level, starting with `Actors[0] = LevelInfo0`)
     - Remaining level data (URL, brushes, reachspecs, etc.)
   - Adding a new actor to a map requires both appending an `ExportEntry` **and** inserting its 1-based export index into `MyLevel.Actors` (incrementing `db_num` and `db_max`).

3. **Trailing Havok `hkWorld` Physics Stream**:
   - Every `.scl` map appends a raw Havok physics binary stream beginning with the 4-byte magic **`33 5A 0D F0`** immediately after the last byte of the Export Table (`exports_end .. EOF`).
   - Any tool rewriting a `.scl` file must copy this raw byte slice verbatim immediately after the new Export Table.

---

## 3. UnrealScript Bytecode (`.u` Packages)

`System/*.u` packages (`Core.u`, `Engine.u`, `Echelon.u`, `EchelonPattern.u`, `EchelonIngredient.u`, etc.) are standard SCCT UPK files containing `Class`, `State`, `Function`, `Property`, and `TextBuffer` (including original developer `CppText` C++ headers) exports.

### 3.1 `UStruct` / `UFunction` On-Disk Layout

```text
[Tagged properties]      Normally a single CompactIndex for "None" (0x00)
SuperField   : CompactIndex
Next         : CompactIndex
ScriptText   : CompactIndex
Children     : CompactIndex
FriendlyName : CompactIndex  (Name index)
Line         : i32
TextPos      : i32
Unknown      : u8            (SCCT-specific byte before ScriptSize)
ScriptSize   : i32           (in-memory bytecode size!)
Bytecode     : variable      (runs until in-memory offset reaches ScriptSize)
```

For `Function` exports, the bytecode is immediately followed by the `UFunction` trailer:

```text
iNative        : u16   (0 if pure UnrealScript; >0 indexes GNatives[])
OperPrecedence : u8
FunctionFlags  : u32   (0x40 = FUNC_Net, 0x1000 = FUNC_Operator, 0x2000 = FUNC_PreOperator)
[RepOffset     : u16]  (present when FUNC_Net is set)
```

### 3.2 Disk Offsets vs. Memory Offsets

- On disk, object references (`0x00`, `0x01`, `0x02`, `0x1C`, `0x20`, `0x2E`, etc.) and `FName` tokens (`0x1B`, `0x21`, `0x38`, `LabelTable` keys) are encoded as variable-length `CompactIndex` values (1–5 bytes).
- When loaded into memory, every object reference and `FName` expands to a fixed **4-byte** slot.
- `ScriptSize`, jump targets (`0x06 EX_Jump`, `0x07 EX_JumpIfNot`, `0x0A EX_Case`, `0x2F EX_Iterator`), and `0x0C EX_LabelTable` offsets are all **in-memory byte offsets**.
- For in-place `.u` bytecode patching without shifting jump targets or resizing exports, replace unwanted instructions with `0x0B` (`EX_Nothing` / NOP) of equal in-memory and on-disk length.

### 3.3 Native Opcode Dispatch

- Opcodes `0x70..0xFF` invoke `GNatives[op]` directly.
- Opcodes `0x60..0x6F` (`EX_ExtendedNative0..15`) read a second byte `b1` and invoke `GNatives[((op - 0x60) << 8) | b1]`.
- In `splintercell3.exe`, all `GNatives` slots are registered at startup via `GRegisterNative` (`0x10CEE250`). See [`scripts/uscript.py`](./scripts/uscript.py) and [`scripts/exe_info.py`](./scripts/exe_info.py) to disassemble bytecode and resolve `iNative` indices to C++ handlers.

---

## 4. UMD Archive Format (`System/dynamic-pc.umd`)

`System/dynamic-pc.umd` (~582 MiB, `20,252` virtual files in retail) is an uncompressed flat archive holding `.ini` configs, localization files (`.int`/`.fra`/`.deu`/`.esp`/`.ita`), loading screen `.dds` textures, Magma `.mgb`/`.mft` UI layouts, and other game data.

### 4.1 Binary Layout

```text
0x00000000 .. toc_offset : Contiguous raw payloads of all virtual files
toc_offset .. EOF - 20   : Table of Contents (TOC)
EOF - 20   .. EOF        : 20-byte Footer
```

**20-byte Footer** (5 little-endian `u32` values):

| Offset from `EOF - 20` | Field | Retail Value |
| :--- | :--- | :--- |
| `+0x00` | `tag` | `0x9FE3C5A3` (preserve unchanged when rebuilding) |
| `+0x04` | `toc_offset` | `0x244EB4EF` (file offset where TOC begins) |
| `+0x08` | `total_size` | Must equal total file size in bytes (`610,578,839` in retail) |
| `+0x0C` | `version` | `1` |
| `+0x10` | `magic` | `0x40FD724D` |

**TOC Layout** (at `toc_offset`):

```text
entry_count : CompactIndex
repeat entry_count times:
    name_len : CompactIndex  (byte length INCLUDING trailing 0x00)
    raw_name : u8[name_len]  (Latin-1 backslash-separated virtual path + 0x00)
    offset   : u32           (absolute file offset of payload)
    size     : u32           (payload byte size)
    flags    : u32           (0 for normal entries)
```

### 4.2 Virtual Filesystem Fallback (`FFileManagerUMD`)

Disassembly of `FFileManagerUMD::CreateFileReader` (`0x10CCFDE0`), `NormalizeUMDPath` (`0x10CD0120`), and `FFileManagerUMD::FileSize` (`0x10CD01F0`) shows:

- The engine looks up normalized backslash paths inside `dynamic-pc.umd` first.
- If a requested path is **not** present in the UMD TOC (for example, newly added `Data\Maps\<Map>_COOP.ini`, `_sound.occ`, `_sound.uns`, or `Data\Magma\DataPC\Textures\GenLoadings\<Map>_COOP_loading_1.dds`), `FFileManagerUMD` transparently falls back to `FFileManagerWindows` and loads the loose file from disk.
- Files that **already exist** inside `dynamic-pc.umd` (such as `System\MapRotation.ini`, `Data\System\Localization\PreGame_PC.*`, and `Data\System\Localization\LoadingScreens.*`) are served from the UMD unless updated inside the archive.

### 4.3 Safe Updating

To replace or add files in `dynamic-pc.umd` without rewriting unchanged payloads:

1. Keep bytes `[0 .. old_toc_offset)` intact so unchanged TOC offsets remain valid.
2. Append new/modified file payloads starting at `old_toc_offset` and update (or append) their TOC entries.
3. Serialize the new TOC and write a new 20-byte footer with updated `toc_offset` and `total_size`.

See [`scripts/umd.py`](./scripts/umd.py) for a standalone implementation (`info`, `list`, `cat`, `extract`, `upsert`) and [`../scct_coop_enhancer/src/umd.rs`](../scct_coop_enhancer/src/umd.rs) for the Rust implementation.
