#!/usr/bin/env python3
"""
Splinter Cell: Chaos Theory UPK (.scl, .u, .utx, .usx, .ukx, .uax) reader and
safe editing library / CLI.

Supports SCCT's modified Unreal Engine 2.5 package format (FileVersion 100,
LicenseeMode 124), including:
  - Header, XOR-0xFF build string, GUID, and generation metadata
  - CompactIndex and FString codecs
  - Name, Import, and Export tables
  - Tagged UObject property streams (with AActor StateFrame detection)
  - MyLevel.Actors (ULevelBase::Actors) array inspection
  - Trailing Havok hkWorld physics stream preservation on .scl map files
  - Safe TLazyArray-preserving serialization when modifying or adding exports

Usage examples:
  python3 upk.py info Data/Maps/01_Lighthouse.scl
  python3 upk.py names Data/Maps/01_Lighthouse.scl --grep PlayerStart
  python3 upk.py imports Data/Maps/01_Lighthouse.scl --grep Coop
  python3 upk.py exports Data/Maps/01_Lighthouse.scl --class EchelonPlayerStart
  python3 upk.py props Data/Maps/01_Lighthouse.scl --export LevelInfo0
  python3 upk.py actors Data/Maps/01_Lighthouse.scl --grep PlayerStart
  python3 upk.py text System/Echelon.u --outer EPlayerController
"""

from __future__ import annotations

import argparse
import os
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

UPK_MAGIC = 0x9E2A83C1
HEADER_BUILD_MARKER = 0x0FF0ADDE
HAVOK_MAGIC = b"\x33\x5a\x0d\xf0"

COMMON_ACTOR_SKIP_PROPS = {
    "Location",
    "Rotation",
    "DrawScale3D",
    "MainScale",
    "PostScale",
    "TempScale",
    "ColLocation",
    "Zone",
    "PhysicsVolume",
    "Level",
    "XLevel",
    "HavokData",
    "VisibleGroups",
    "SpecialEventAnims",
    "SpecialEventAnimsPlayer",
    "LinInterpol",
    "Region",
    "materStateInterpol",
    "LastRenderTime",
    "LastValueCalculated",
    "bEnabledForStreaming",
    "bHasOpaqueRenderPass",
    "bPathsChanged",
    "PerPixelLightsList",
    "RelevantLights",
    "RelevantAmbientColor",
    "Touching",
    "ColType",
    "ColFlagHavok",
    "ColFlagPlayer",
    "ColFlagNPC",
    "ColFlagProj",
    "ColFlagCamera",
    "ColFlagNPCShot",
    "ColFlagNPCVision",
    "ColRotation",
    "HeatOpacity",
    "HeatIntensity",
    "MaskingRadiusMultiplier",
    "SoundRadiusSaturation",
    "SoundRadiusInaudible",
    "SoundRadiusTransitLinear",
}

LEVELINFO_RESYNC_PROPS = {
    "DynamicEvents",
    "EAIZones",
    "CurrentSelectedEAIZone",
    "m_dT",
    "SoundMapName",
    "UseDefaultSoundMap",
}


def resolve_game_path(path_arg: str, game_dir: str | None = None) -> Path:
    """Resolve an explicit path or a path relative to --game-dir / SCCT_GAME_ROOT."""
    direct = Path(path_arg)
    if direct.exists():
        return direct
    root_str = game_dir or os.environ.get("SCCT_GAME_ROOT")
    if root_str:
        root = Path(root_str)
        for candidate in (
            root / path_arg,
            root / "System" / path_arg,
            root / "Data" / "Maps" / path_arg,
            root / "Data" / "Sounds" / path_arg,
            root / "Data" / "Textures" / path_arg,
            root / "Data" / "StaticMeshes" / path_arg,
        ):
            if candidate.exists():
                return candidate
    return direct


def read_compact_index(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a UE2 variable-length signed CompactIndex."""
    b0 = data[offset]
    offset += 1
    neg = (b0 & 0x80) != 0
    val = b0 & 0x3F
    if b0 & 0x40:
        shift = 6
        while True:
            b = data[offset]
            offset += 1
            val |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
    return (-val if neg else val), offset


def write_compact_index(val: int) -> bytes:
    """Encode a signed integer as a UE2 CompactIndex."""
    neg = val < 0
    v = -val if neg else val
    b0 = (0x80 if neg else 0x00) | (v & 0x3F)
    v >>= 6
    if v > 0:
        b0 |= 0x40
    out = bytearray([b0])
    while v > 0:
        b = v & 0x7F
        v >>= 7
        if v > 0:
            b |= 0x80
        out.append(b)
    return bytes(out)


def read_fstring(data: bytes, offset: int) -> tuple[str, int]:
    """Decode an SCCT UPK FString (length excludes trailing NUL)."""
    length, offset = read_compact_index(data, offset)
    if length < 0:
        byte_len = (-length) * 2
        text = data[offset : offset + byte_len].decode("utf-16-le", errors="replace")
        offset += byte_len + 2
    elif length > 0:
        text = data[offset : offset + length].decode("latin1", errors="replace")
        offset += length + 1
    else:
        text = ""
    return text.rstrip("\x00"), offset


def write_fstring(text: str) -> bytes:
    """Encode an ASCII/Latin-1 string as an SCCT UPK FString (length excludes NUL)."""
    raw = text.encode("latin1")
    return write_compact_index(len(raw)) + raw + b"\x00"


def read_xor_fstring(data: bytes, offset: int) -> tuple[str, int]:
    """Decode the XOR-0xFF build string stored at header offset 0x2C."""
    length, offset = read_compact_index(data, offset)
    if length < 0:
        byte_len = (-length) * 2
        raw = bytes(b ^ 0xFF for b in data[offset : offset + byte_len])
        offset += byte_len
        text = raw.decode("utf-16-le", errors="replace")
    else:
        raw = bytes(b ^ 0xFF for b in data[offset : offset + length])
        offset += length
        text = raw.decode("latin1", errors="replace")
    return text.rstrip("\x00"), offset


def serialize_bool_property(name_idx: int, value: bool) -> bytes:
    """Serialize a UE2 BoolProperty tag (value stored in bit 7 of info byte)."""
    info = 3 | (0x80 if value else 0x00)
    return write_compact_index(name_idx) + bytes([info])


def serialize_int_property(name_idx: int, value: int) -> bytes:
    """Serialize a UE2 IntProperty tag."""
    info = 2 | (2 << 4)
    return write_compact_index(name_idx) + bytes([info]) + struct.pack("<i", value)


def serialize_object_property(name_idx: int, obj_ref: int) -> bytes:
    """Serialize a UE2 ObjectProperty tag referencing an export (>0) or import (<0)."""
    val_bytes = write_compact_index(obj_ref)
    size_map = {1: (0, b""), 2: (1, b""), 4: (2, b"")}
    size_code, size_extra = size_map.get(len(val_bytes), (5, bytes([len(val_bytes)])))
    info = 5 | (size_code << 4)
    return write_compact_index(name_idx) + bytes([info]) + size_extra + val_bytes


@dataclass
class ImportEntry:
    class_pkg: int
    class_name: int
    package_index: int
    obj_name: int


@dataclass
class ExportEntry:
    index: int  # 1-based export index
    class_idx: int
    super_idx: int
    package_index: int
    obj_name: int
    obj_flags: int
    serial_size: int
    serial_offset: int


@dataclass
class PropertyTag:
    name: str
    prop_type: int
    struct_name: str | None
    array_index: int
    is_array: bool
    value_bytes: bytes
    raw_bytes: bytes


class UpkPackage:
    """Parser and TLazyArray-safe writer for SCCT Unreal Engine 2.5 packages."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        if len(self.data) < 0x28:
            raise ValueError(f"UPK file too small: {self.path}")

        magic = struct.unpack_from("<I", self.data, 0)[0]
        if magic != UPK_MAGIC:
            raise ValueError(f"Invalid UPK magic 0x{magic:08X} in {self.path}")

        self.version, self.licensee_mode = struct.unpack_from("<HH", self.data, 4)
        self.extra_header_u32, self.pkg_flags = struct.unpack_from("<II", self.data, 8)
        (
            self.name_count,
            self.name_offset,
            self.export_count,
            self.export_offset,
            self.import_count,
            self.import_offset,
        ) = struct.unpack_from("<IIIIII", self.data, 0x10)

        self.build_string: str | None = None
        if len(self.data) >= 0x30 and struct.unpack_from("<I", self.data, 0x28)[0] == HEADER_BUILD_MARKER:
            self.build_string, _ = read_xor_fstring(self.data, 0x2C)

        self.names: list[tuple[str, int]] = []
        off = self.name_offset
        for _ in range(self.name_count):
            name_str, off = read_fstring(self.data, off)
            flags = struct.unpack_from("<I", self.data, off)[0]
            off += 4
            self.names.append((name_str, flags))
        self.names_end = off

        self.imports: list[ImportEntry] = []
        off = self.import_offset
        for _ in range(self.import_count):
            cp, off = read_compact_index(self.data, off)
            cn, off = read_compact_index(self.data, off)
            outer = struct.unpack_from("<i", self.data, off)[0]
            off += 4
            on, off = read_compact_index(self.data, off)
            self.imports.append(ImportEntry(cp, cn, outer, on))
        self.imports_end = off

        self.exports: list[ExportEntry] = []
        off = self.export_offset
        for i in range(self.export_count):
            ci, off = read_compact_index(self.data, off)
            si, off = read_compact_index(self.data, off)
            outer = struct.unpack_from("<i", self.data, off)[0]
            off += 4
            on, off = read_compact_index(self.data, off)
            fl = struct.unpack_from("<I", self.data, off)[0]
            off += 4
            sz, off = read_compact_index(self.data, off)
            so, off = read_compact_index(self.data, off) if sz > 0 else (0, off)
            self.exports.append(ExportEntry(i + 1, ci, si, outer, on, fl, sz, so))
        self.exports_end = off

        self.trailing_data = self.data[self.exports_end :]
        self.has_havok_tail = self.trailing_data.startswith(HAVOK_MAGIC)

    def name_str(self, idx: int) -> str:
        if 0 <= idx < len(self.names):
            return self.names[idx][0]
        return f"<BadName:{idx}>"

    def find_name(self, text: str) -> int | None:
        for i, (s, _) in enumerate(self.names):
            if s == text:
                return i
        return None

    def ensure_name(self, text: str, flags: int = 0x00070010) -> int:
        existing = self.find_name(text)
        if existing is not None:
            return existing
        self.names.append((text, flags))
        return len(self.names) - 1

    def obj_name(self, ref: int) -> str:
        if ref == 0:
            return "None"
        if 0 < ref <= len(self.exports):
            return self.name_str(self.exports[ref - 1].obj_name)
        if ref < 0 and (-ref) <= len(self.imports):
            return self.name_str(self.imports[-ref - 1].obj_name)
        return f"<BadRef:{ref}>"

    def obj_full_name(self, ref: int) -> str:
        if ref == 0:
            return "None"
        parts: list[str] = []
        cur = ref
        for _ in range(16):
            if cur == 0:
                break
            if 0 < cur <= len(self.exports):
                exp = self.exports[cur - 1]
                parts.append(self.name_str(exp.obj_name))
                cur = exp.package_index
            elif cur < 0 and (-cur) <= len(self.imports):
                imp = self.imports[-cur - 1]
                parts.append(self.name_str(imp.obj_name))
                cur = imp.package_index
            else:
                break
        return ".".join(reversed(parts))

    def obj_class_name(self, ref: int) -> str:
        if ref == 0:
            return "None"
        if 0 < ref <= len(self.exports):
            ci = self.exports[ref - 1].class_idx
            return "Class" if ci == 0 else self.obj_name(ci)
        if ref < 0 and (-ref) <= len(self.imports):
            return self.name_str(self.imports[-ref - 1].class_name)
        return "Unknown"

    def export_bytes(self, exp_idx_1based: int) -> bytes:
        exp = self.exports[exp_idx_1based - 1]
        return self.data[exp.serial_offset : exp.serial_offset + exp.serial_size]

    def parse_props_at(self, buf: bytes, off: int, end: int) -> tuple[list[PropertyTag] | None, int]:
        props: list[PropertyTag] = []
        while off < end:
            pstart = off
            ni, off2 = read_compact_index(buf, off)
            if ni < 0 or ni >= len(self.names):
                return None, off
            pname = self.names[ni][0]
            if pname == "None":
                return props, off2
            off = off2
            if off >= end:
                return None, off
            info = buf[off]
            off += 1
            ptype = info & 0x0F
            if ptype == 0 or ptype > 15:
                return None, off
            sz_code = (info >> 4) & 0x07
            is_arr = (info & 0x80) != 0
            sname: str | None = None
            if ptype == 10:
                si, off = read_compact_index(buf, off)
                if si < 0 or si >= len(self.names):
                    return None, off
                sname = self.names[si][0]
            if sz_code == 0:
                sz = 1
            elif sz_code == 1:
                sz = 2
            elif sz_code == 2:
                sz = 4
            elif sz_code == 3:
                sz = 12
            elif sz_code == 4:
                sz = 16
            elif sz_code == 5:
                sz = buf[off]
                off += 1
            elif sz_code == 6:
                sz = struct.unpack_from("<H", buf, off)[0]
                off += 2
            else:
                sz = struct.unpack_from("<I", buf, off)[0]
                off += 4

            aidx = 0
            if is_arr and ptype != 3:
                b = buf[off]
                off += 1
                if b & 0x80:
                    b2 = buf[off]
                    off += 1
                    aidx = ((b & 0x7F) << 8) | b2
                else:
                    aidx = b

            if ptype != 3 and off + sz > end:
                return None, off
            val_bytes = b"" if ptype == 3 else buf[off : off + sz]
            if ptype != 3:
                off += sz

            # Workaround for SCCT FPropertyTag.Size under-reporting on LevelInfo
            # Patrols/DynamicEvents struct arrays.
            if pname in ("Patrols", "DynamicEvents") and off < end:
                while off < end:
                    try:
                        ni_peek, nxt_peek = read_compact_index(buf, off)
                        if (
                            self.name_str(ni_peek) in LEVELINFO_RESYNC_PROPS
                            and nxt_peek < end
                            and (buf[nxt_peek] & 0x0F) in range(1, 15)
                        ):
                            break
                    except Exception:
                        pass
                    off += 1

            props.append(
                PropertyTag(
                    name=pname,
                    prop_type=ptype,
                    struct_name=sname,
                    array_index=aidx,
                    is_array=is_arr,
                    value_bytes=val_bytes,
                    raw_bytes=buf[pstart:off],
                )
            )
        return props, off

    def parse_export_props(self, exp_idx_1based: int) -> list[PropertyTag]:
        exp = self.exports[exp_idx_1based - 1]
        so, end = exp.serial_offset, exp.serial_offset + exp.serial_size
        # Try AActor StateFrame prefix first.
        try:
            node, o = read_compact_index(self.data, so)
            _snode, o = read_compact_index(self.data, o)
            o += 12  # ProbeMask (u64) + LatentAction (u32)
            if node != 0:
                _, o = read_compact_index(self.data, o)  # StateFrame Offset
            if o < end:
                props, _ = self.parse_props_at(self.data, o, end)
                if props is not None:
                    return props
        except Exception:
            pass
        # Fall back to direct UObject property stream (no StateFrame).
        props, _ = self.parse_props_at(self.data, so, end)
        return props or []

    def format_prop_val(self, prop: PropertyTag) -> str:
        val_bytes = prop.value_bytes
        ptype = prop.prop_type
        if ptype == 1 and len(val_bytes) == 1:
            return f"{val_bytes[0]} (0x{val_bytes[0]:02x})"
        if ptype == 2 and len(val_bytes) == 4:
            return str(struct.unpack_from("<i", val_bytes, 0)[0])
        if ptype == 3:
            return str(prop.is_array)
        if ptype == 4 and len(val_bytes) == 4:
            return f"{struct.unpack_from('<f', val_bytes, 0)[0]:.4g}"
        if ptype == 5 and val_bytes:
            ref, _ = read_compact_index(val_bytes, 0)
            return f"Obj({ref}={self.obj_full_name(ref)} [{self.obj_class_name(ref)}])"
        if ptype == 6 and val_bytes:
            ref, _ = read_compact_index(val_bytes, 0)
            return f"Name({self.name_str(ref)})"
        if ptype == 13 and val_bytes:
            s, _ = read_fstring(val_bytes, 0)
            return repr(s)
        if ptype == 9 and val_bytes:
            cnt, o = read_compact_index(val_bytes, 0)
            refs: list[int] = []
            o_test = o
            ok = 0 < cnt <= 64
            while ok and len(refs) < cnt and o_test < len(val_bytes):
                try:
                    r, o_test = read_compact_index(val_bytes, o_test)
                    refs.append(r)
                except Exception:
                    ok = False
            if ok and len(refs) == cnt and o_test == len(val_bytes):
                items = ", ".join(
                    f"{r}={self.obj_name(r)}[{self.obj_class_name(r)}]" for r in refs
                )
                return f"Array(count={cnt}: [{items}])"
            return f"Array(count={cnt}, raw={val_bytes[:32].hex(' ')})"
        if ptype == 10:
            if prop.struct_name == "Vector" and len(val_bytes) == 12:
                x, y, z = struct.unpack("<fff", val_bytes)
                return f"Vector({x:.2f}, {y:.2f}, {z:.2f})"
            if prop.struct_name == "Rotator" and len(val_bytes) == 12:
                p, y, r = struct.unpack("<iii", val_bytes)
                return f"Rotator({p}, {y}, {r})"
            sub, _ = self.parse_props_at(val_bytes, 0, len(val_bytes))
            if sub:
                inner = ", ".join(f"{sp.name}={self.format_prop_val(sp)}" for sp in sub)
                return f"Struct({prop.struct_name}: {{{inner}}})"
        return val_bytes[:40].hex(" ")

    def read_mylevel_actors(self) -> list[int]:
        """Return the list of 1-based export indices stored in MyLevel.Actors."""
        for exp in self.exports:
            if self.name_str(exp.obj_name) == "MyLevel" and self.obj_class_name(exp.index) == "Level":
                raw = self.export_bytes(exp.index)
                _, off = read_compact_index(raw, 0)  # leading None property
                num, _max_cnt = struct.unpack_from("<ii", raw, off)
                off += 8
                actors: list[int] = []
                for _ in range(num):
                    ref, off = read_compact_index(raw, off)
                    actors.append(ref)
                return actors
        raise ValueError("MyLevel export not found in package")

    def save_preserving_lazy_arrays(
        self,
        out_path: Path | str,
        replaced_exports: dict[int, bytes] | None = None,
        appended_exports: list[tuple[ExportEntry, bytes]] | None = None,
    ) -> None:
        """
        Write a modified UPK/SCL package without shifting any pre-table bytes.

        Keeping original export payloads at their original file offsets preserves all
        absolute 32-bit TLazyArray SavedPos pointers inside Model/StaticMesh/Texture/Sound
        exports. Modified and newly added exports are appended before the rebuilt Name,
        Import, and Export tables, followed by the untouched Havok hkWorld tail (if any).
        """
        replaced_exports = replaced_exports or {}
        appended_exports = appended_exports or []

        # Preserve everything up to the original Import/Export table block.
        prefix_end = min(self.import_offset, self.export_offset)
        out = bytearray(self.data[:prefix_end])

        new_exports = [
            ExportEntry(
                e.index,
                e.class_idx,
                e.super_idx,
                e.package_index,
                e.obj_name,
                e.obj_flags,
                e.serial_size,
                e.serial_offset,
            )
            for e in self.exports
        ]

        for exp_idx, payload in replaced_exports.items():
            entry = new_exports[exp_idx - 1]
            entry.serial_offset = len(out)
            entry.serial_size = len(payload)
            out.extend(payload)

        for entry_template, payload in appended_exports:
            new_entry = ExportEntry(
                index=len(new_exports) + 1,
                class_idx=entry_template.class_idx,
                super_idx=entry_template.super_idx,
                package_index=entry_template.package_index,
                obj_name=entry_template.obj_name,
                obj_flags=entry_template.obj_flags,
                serial_size=len(payload),
                serial_offset=len(out),
            )
            new_exports.append(new_entry)
            out.extend(payload)

        new_name_offset = len(out)
        out.extend(self.data[self.name_offset : self.names_end])
        for name_str, flags in self.names[self.name_count :]:
            out.extend(write_fstring(name_str))
            out.extend(struct.pack("<I", flags))

        new_import_offset = len(out)
        out.extend(self.data[self.import_offset : self.imports_end])
        for imp in self.imports[self.import_count :]:
            out.extend(write_compact_index(imp.class_pkg))
            out.extend(write_compact_index(imp.class_name))
            out.extend(struct.pack("<i", imp.package_index))
            out.extend(write_compact_index(imp.obj_name))

        new_export_offset = len(out)
        for exp in new_exports:
            out.extend(write_compact_index(exp.class_idx))
            out.extend(write_compact_index(exp.super_idx))
            out.extend(struct.pack("<i", exp.package_index))
            out.extend(write_compact_index(exp.obj_name))
            out.extend(struct.pack("<I", exp.obj_flags))
            out.extend(write_compact_index(exp.serial_size))
            if exp.serial_size > 0:
                out.extend(write_compact_index(exp.serial_offset))

        if self.trailing_data:
            out.extend(self.trailing_data)

        struct.pack_into("<II", out, 0x10, len(self.names), new_name_offset)
        struct.pack_into("<II", out, 0x18, len(new_exports), new_export_offset)
        struct.pack_into("<II", out, 0x20, len(self.imports), new_import_offset)
        if len(out) >= 0xAD and struct.unpack_from("<I", out, 0xA1)[0] == 1:
            struct.pack_into("<II", out, 0xA5, len(new_exports), len(self.names))

        Path(out_path).write_bytes(bytes(out))


def _cmd_info(args: argparse.Namespace) -> None:
    pkg = UpkPackage(resolve_game_path(args.file, args.game_dir))
    print(f"File:       {pkg.path} ({len(pkg.data):,} bytes)")
    print(f"Version:    {pkg.version}  Licensee: {pkg.licensee_mode}  Flags: 0x{pkg.pkg_flags:08X}")
    if pkg.build_string:
        print(f"Build:      {pkg.build_string}")
    print(f"Names:      {pkg.name_count} @ 0x{pkg.name_offset:X}..0x{pkg.names_end:X}")
    print(f"Imports:    {pkg.import_count} @ 0x{pkg.import_offset:X}..0x{pkg.imports_end:X}")
    print(f"Exports:    {pkg.export_count} @ 0x{pkg.export_offset:X}..0x{pkg.exports_end:X}")
    if pkg.trailing_data:
        tag = "Havok hkWorld" if pkg.has_havok_tail else "unknown trailing data"
        print(f"Tail:       {len(pkg.trailing_data):,} bytes @ 0x{pkg.exports_end:X} ({tag})")


def _cmd_names(args: argparse.Namespace) -> None:
    pkg = UpkPackage(resolve_game_path(args.file, args.game_dir))
    pat = re.compile(args.grep, re.I) if args.grep else None
    for idx, (s, fl) in enumerate(pkg.names):
        if pat and not pat.search(s):
            continue
        print(f"[{idx}] {s!r} (flags=0x{fl:08X})")


def _cmd_imports(args: argparse.Namespace) -> None:
    pkg = UpkPackage(resolve_game_path(args.file, args.game_dir))
    pat = re.compile(args.grep, re.I) if args.grep else None
    for idx, imp in enumerate(pkg.imports, start=1):
        full = pkg.obj_full_name(-idx)
        line = f"[-{idx}] {full} (class={pkg.name_str(imp.class_pkg)}.{pkg.name_str(imp.class_name)})"
        if pat and not pat.search(line):
            continue
        print(line)


def _cmd_exports(args: argparse.Namespace) -> None:
    pkg = UpkPackage(resolve_game_path(args.file, args.game_dir))
    if args.classes_only:
        for cname in sorted({pkg.obj_class_name(e.index) for e in pkg.exports}):
            if args.class_pat and not re.search(args.class_pat, cname, re.I):
                continue
            print(cname)
        return

    c_re = re.compile(args.class_pat, re.I) if args.class_pat else None
    n_re = re.compile(args.name_pat, re.I) if args.name_pat else None
    o_re = re.compile(args.outer_pat, re.I) if args.outer_pat else None

    for exp in pkg.exports:
        cls = pkg.obj_class_name(exp.index)
        sup = pkg.obj_name(exp.super_idx)
        nm = pkg.name_str(exp.obj_name)
        out_nm = pkg.obj_full_name(exp.package_index)
        if c_re and not c_re.search(cls):
            continue
        if n_re and not n_re.search(nm):
            continue
        if o_re and not o_re.search(out_nm):
            continue
        print(f"[Exp {exp.index}] {out_nm}.{nm} (class={cls}, super={sup}, sz={exp.serial_size}, off=0x{exp.serial_offset:X})")


def _cmd_props(args: argparse.Namespace) -> None:
    pkg = UpkPackage(resolve_game_path(args.file, args.game_dir))
    c_re = re.compile(args.class_pat, re.I) if args.class_pat else None
    target = args.export

    for exp in pkg.exports:
        cls = pkg.obj_class_name(exp.index)
        nm = pkg.obj_name(exp.index)
        full = pkg.obj_full_name(exp.index)
        if target:
            if target.isdigit():
                if exp.index != int(target):
                    continue
            elif target.lower() not in (nm.lower(), full.lower()):
                continue
        if c_re and not c_re.search(cls):
            continue

        props = pkg.parse_export_props(exp.index)
        print(f"=== [Exp {exp.index}] {full} ({cls}) ===")
        for prop in props:
            if not args.include_common and prop.name in COMMON_ACTOR_SKIP_PROPS:
                continue
            if prop.name == "Patterns":
                cnt, o2 = read_compact_index(prop.value_bytes, 0)
                print(f"  Patterns (count={cnt}):")
                for i in range(cnt):
                    sub, o2 = pkg.parse_props_at(prop.value_bytes, o2, len(prop.value_bytes))
                    if not sub:
                        break
                    fields = ", ".join(f"{sp.name}={pkg.format_prop_val(sp)}" for sp in sub)
                    print(f"    [{i}] {fields}")
            else:
                print(f"  {prop.name}[{prop.array_index}] = {pkg.format_prop_val(prop)}")


def _cmd_actors(args: argparse.Namespace) -> None:
    pkg = UpkPackage(resolve_game_path(args.file, args.game_dir))
    grep_re = re.compile(args.grep, re.I) if args.grep else None
    near: tuple[float, float, float, float] | None = None
    if args.near:
        parts = [float(p.strip()) for p in args.near.split(",")]
        near = (parts[0], parts[1], parts[2], parts[3] if len(parts) == 4 else (args.radius or 500.0))

    actors = pkg.read_mylevel_actors()
    print(f"MyLevel.Actors count={len(actors)}:")
    for slot, ref in enumerate(actors):
        if ref == 0:
            continue
        loc: tuple[float, float, float] | None = None
        dist = 0.0
        if near is not None:
            for prop in pkg.parse_export_props(ref):
                if prop.name == "Location" and len(prop.value_bytes) == 12:
                    loc = struct.unpack("<fff", prop.value_bytes)
                    break
            if loc is None:
                continue
            dist = ((loc[0] - near[0]) ** 2 + (loc[1] - near[1]) ** 2 + (loc[2] - near[2]) ** 2) ** 0.5
            if dist > near[3]:
                continue

        line = f"  [{slot}] Exp {ref} ({pkg.obj_name(ref)} [{pkg.obj_class_name(ref)}])"
        if loc is not None:
            line += f" @ ({loc[0]:.1f}, {loc[1]:.1f}, {loc[2]:.1f}) dist={dist:.1f}"
        if grep_re is None or grep_re.search(line):
            print(line)


def _cmd_text(args: argparse.Namespace) -> None:
    pkg = UpkPackage(resolve_game_path(args.file, args.game_dir))
    o_re = re.compile(args.outer_pat, re.I) if args.outer_pat else None
    for exp in pkg.exports:
        if pkg.obj_class_name(exp.index) != "TextBuffer":
            continue
        full = pkg.obj_full_name(exp.index)
        if args.export and args.export.lower() not in full.lower():
            continue
        if o_re and not o_re.search(full):
            continue
        print(f"=== [Exp {exp.index}] {full} (sz={exp.serial_size}) ===")
        print(pkg.export_bytes(exp.index).decode("latin1", errors="replace"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect SCCT UPK / SCL / U packages.")
    parser.add_argument("--game-dir", help="Optional SCCT game root folder (or set SCCT_GAME_ROOT)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("info", help="Show UPK header, tables, and Havok tail summary")
    s.add_argument("file")
    s.set_defaults(func=_cmd_info)

    s = sub.add_parser("names", help="List Name Table entries")
    s.add_argument("file")
    s.add_argument("--grep")
    s.set_defaults(func=_cmd_names)

    s = sub.add_parser("imports", help="List Import Table entries")
    s.add_argument("file")
    s.add_argument("--grep")
    s.set_defaults(func=_cmd_imports)

    s = sub.add_parser("exports", help="List Export Table entries")
    s.add_argument("file")
    s.add_argument("--class", dest="class_pat")
    s.add_argument("--name", dest="name_pat")
    s.add_argument("--outer", dest="outer_pat")
    s.add_argument("--classes-only", action="store_true")
    s.set_defaults(func=_cmd_exports)

    s = sub.add_parser("props", help="Dump tagged UObject properties on matching exports")
    s.add_argument("file")
    s.add_argument("--export", help="1-based index, short name, or full dotted name")
    s.add_argument("--class", dest="class_pat")
    s.add_argument("--include-common", action="store_true")
    s.set_defaults(func=_cmd_props)

    s = sub.add_parser("actors", help="List actors in MyLevel.Actors")
    s.add_argument("file")
    s.add_argument("--grep")
    s.add_argument("--near", help="Filter by proximity: X,Y,Z[,Radius]")
    s.add_argument("--radius", type=float)
    s.set_defaults(func=_cmd_actors)

    s = sub.add_parser("text", help="Dump TextBuffer exports (e.g. embedded CppText)")
    s.add_argument("file")
    s.add_argument("--export")
    s.add_argument("--outer", dest="outer_pat")
    s.set_defaults(func=_cmd_text)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
