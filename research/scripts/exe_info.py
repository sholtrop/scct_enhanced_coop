#!/usr/bin/env python3
"""
Static PE32 analyzer for Splinter Cell: Chaos Theory (System/splintercell3.exe,
retail ImageBase = 0x10900000).

Provides:
  - PE section table, free .text cave summary, and VA <-> file-offset conversion
  - Export directory listing (UObject constructors, StaticClass, exec* thunks)
  - GRegisterNative (0x10CEE250) + .data FNativeEntry (int*exec*) extraction,
    optionally joined with System/*.u UFunction iNative slots
  - ASCII and UTF-16LE string search with immediate pointer xrefs

Usage examples:
  python3 exe_info.py sections System/splintercell3.exe
  python3 exe_info.py va2off System/splintercell3.exe 0x10A40EE0
  python3 exe_info.py exports System/splintercell3.exe --grep execEndMission
  python3 exe_info.py natives System/splintercell3.exe --system-dir System/ --grep Speech
  python3 exe_info.py strings System/splintercell3.exe bMultiplayerMap LanCaption
"""

from __future__ import annotations

import argparse
import re
import struct
from pathlib import Path
from typing import Any

from uscript import build_native_table

GREGISTER_NATIVE_VA = 0x10CEE250


class PE32:
    """Minimal PE32 reader for 32-bit Windows executables."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        if self.data[:2] != b"MZ":
            raise ValueError(f"Not a PE executable: {self.path}")
        e_lfanew = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            raise ValueError(f"Invalid PE signature in {self.path}")

        num_sec = struct.unpack_from("<H", self.data, e_lfanew + 6)[0]
        opt_sz = struct.unpack_from("<H", self.data, e_lfanew + 20)[0]
        opt_off = e_lfanew + 24
        self.image_base = struct.unpack_from("<I", self.data, opt_off + 28)[0]
        self.exp_rva, self.exp_sz = struct.unpack_from("<II", self.data, opt_off + 96)

        sec_off = opt_off + opt_sz
        self.sections: dict[str, dict[str, int]] = {}
        for i in range(num_sec):
            raw_name, vsz, rva, rsz, rptr, _, _, _, _, chars = struct.unpack_from(
                "<8sIIIIIIHHI", self.data, sec_off + i * 40
            )
            name = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="replace")
            self.sections[name] = {
                "va_start": self.image_base + rva,
                "va_end": self.image_base + rva + vsz,
                "rva": rva,
                "vsz": vsz,
                "raw_start": rptr,
                "raw_end": rptr + rsz,
                "rsz": rsz,
                "chars": chars,
            }

    def va_to_off(self, va: int) -> int | None:
        rva = va - self.image_base
        for sec in self.sections.values():
            if sec["rva"] <= rva < sec["rva"] + max(sec["vsz"], sec["rsz"]):
                off = sec["raw_start"] + (rva - sec["rva"])
                return off if off < sec["raw_end"] else None
        return None

    def off_to_va(self, off: int) -> int | None:
        for sec in self.sections.values():
            if sec["raw_start"] <= off < sec["raw_end"]:
                return sec["va_start"] + (off - sec["raw_start"])
        return None

    def read_u32_va(self, va: int) -> int | None:
        off = self.va_to_off(va)
        if off is None or off + 4 > len(self.data):
            return None
        return struct.unpack_from("<I", self.data, off)[0]

    def read_utf16le_va(self, va: int, max_chars: int = 256) -> str | None:
        off = self.va_to_off(va)
        if off is None:
            return None
        end = off
        limit = min(len(self.data) - 1, off + max_chars * 2)
        while end < limit and self.data[end : end + 2] != b"\x00\x00":
            end += 2
        if end == off or end >= limit:
            return None
        try:
            s = self.data[off:end].decode("utf-16-le")
            return s if s.isprintable() else None
        except UnicodeDecodeError:
            return None

    def parse_exports(self) -> list[dict[str, Any]]:
        if not self.exp_rva:
            return []
        eoff = self.va_to_off(self.image_base + self.exp_rva)
        if eoff is None:
            return []
        _nf, num_names, af_rva, an_rva, ao_rva = struct.unpack_from("<IIIII", self.data, eoff + 20)
        funcs_off = self.va_to_off(self.image_base + af_rva)
        names_off = self.va_to_off(self.image_base + an_rva)
        ords_off = self.va_to_off(self.image_base + ao_rva)
        if funcs_off is None or names_off is None or ords_off is None:
            return []
        exports: list[dict[str, Any]] = []
        for i in range(num_names):
            nrva = struct.unpack_from("<I", self.data, names_off + i * 4)[0]
            ord_idx = struct.unpack_from("<H", self.data, ords_off + i * 2)[0]
            frva = struct.unpack_from("<I", self.data, funcs_off + ord_idx * 4)[0]
            noff = self.va_to_off(self.image_base + nrva)
            if noff is None:
                continue
            end = self.data.find(b"\x00", noff)
            name = self.data[noff:end].decode("ascii", errors="replace")
            exports.append({"ordinal": ord_idx, "name": name, "va": self.image_base + frva})
        return sorted(exports, key=lambda x: x["va"])

    def find_rel32_calls(self, target_va: int) -> list[int]:
        text = self.sections[".text"]
        start = text["raw_start"]
        end = min(text["raw_end"], len(self.data))
        hits: list[int] = []
        pos = start
        while pos < end - 5:
            idx = self.data.find(b"\xe8", pos, end - 4)
            if idx == -1:
                break
            va = text["va_start"] + (idx - start)
            rel = struct.unpack_from("<i", self.data, idx + 1)[0]
            if va + 5 + rel == target_va:
                hits.append(idx)
            pos = idx + 1
        return hits

    def extract_inatives(self) -> tuple[dict[int, int], dict[int, list[str]]]:
        """Extract GRegisterNative (iNative -> C++ VA) and .data FNativeEntry symbols."""
        gnatives: dict[int, int] = {}
        for idx in self.find_rel32_calls(GREGISTER_NATIVE_VA):
            ptr_slot = None
            inum = None
            if self.data[idx - 10] == 0x68 and self.data[idx - 5] == 0x68:
                ptr_slot = struct.unpack_from("<I", self.data, idx - 9)[0]
                inum = struct.unpack_from("<i", self.data, idx - 4)[0]
            elif self.data[idx - 7] == 0x68 and self.data[idx - 2] == 0x6A:
                ptr_slot = struct.unpack_from("<I", self.data, idx - 6)[0]
                inum = struct.unpack_from("<b", self.data, idx - 1)[0]
            if ptr_slot is not None and inum is not None and inum >= 0:
                fn_va = self.read_u32_va(ptr_slot)
                if fn_va:
                    gnatives[inum] = fn_va

        text = self.sections[".text"]
        rdata = self.sections[".rdata"]
        data_sec = self.sections[".data"]
        fentry_by_fn: dict[int, list[str]] = {}
        d_start = data_sec["raw_start"]
        d_end = min(data_sec["raw_end"], len(self.data)) - 8
        for off in range(d_start, d_end, 4):
            s_ptr, fn_ptr = struct.unpack_from("<II", self.data, off)
            if (
                rdata["va_start"] <= s_ptr < rdata["va_end"]
                and text["va_start"] <= fn_ptr < text["va_end"]
            ):
                s = self.read_utf16le_va(s_ptr, max_chars=160)
                if s and s.startswith("int") and "exec" in s:
                    fentry_by_fn.setdefault(fn_ptr, []).append(s)

        return gnatives, fentry_by_fn


def _cmd_sections(args: argparse.Namespace) -> None:
    pe = PE32(args.exe)
    print(f"File: {pe.path} ({len(pe.data):,} bytes)  ImageBase: 0x{pe.image_base:08X}")
    print(f"{'Section':<10} {'VA Start':<12} {'VirtSize':<12} {'RawOff':<12} {'RawSize':<12} {'Chars'}")
    for name, sec in pe.sections.items():
        print(
            f"{name:<10} 0x{sec['va_start']:08X}   0x{sec['vsz']:08X}   "
            f"0x{sec['raw_start']:08X}   0x{sec['rsz']:08X}   0x{sec['chars']:08X}"
        )
    text = pe.sections.get(".text")
    if text and text["rsz"] > text["vsz"]:
        slack = text["rsz"] - text["vsz"]
        print(f"\n.text slack padding: {slack} bytes at 0x{text['va_end']:08X}..0x{text['va_start'] + text['rsz']:08X}")


def _cmd_va2off(args: argparse.Namespace) -> None:
    pe = PE32(args.exe)
    val = int(args.address, 0)
    off = pe.va_to_off(val)
    va = pe.off_to_va(val)
    print(f"Input: 0x{val:08X}")
    print(f"  As VA     -> file offset: {f'0x{off:08X}' if off is not None else 'unmapped'}")
    print(f"  As offset -> VA:          {f'0x{va:08X}' if va is not None else 'unmapped'}")


def _cmd_exports(args: argparse.Namespace) -> None:
    pe = PE32(args.exe)
    pat = re.compile(args.grep, re.I) if args.grep else None
    for exp in pe.parse_exports():
        if pat and not pat.search(exp["name"]):
            continue
        print(f"0x{exp['va']:08X}  ord={exp['ordinal']:<4d}  {exp['name']}")


def _cmd_natives(args: argparse.Namespace) -> None:
    pe = PE32(args.exe)
    gnatives, fentry_by_fn = pe.extract_inatives()
    u_natives = build_native_table(Path(args.system_dir)) if args.system_dir else {}
    pat = re.compile(args.grep, re.I) if args.grep else None

    for inum in sorted(set(gnatives) | set(u_natives)):
        fn_va = gnatives.get(inum)
        syms = ", ".join(fentry_by_fn.get(fn_va, [])) if fn_va else ""
        uinfo = u_natives.get(inum)
        uname = f"{uinfo['package']}.{uinfo['owner']}.{uinfo['name']}" if uinfo else ""
        va_str = f"0x{fn_va:08X}" if fn_va else "          "
        line = f"{inum:5d} (0x{inum:03X})  {va_str}  {syms:<42}  {uname}"
        if pat and not pat.search(line):
            continue
        print(line)


def _cmd_strings(args: argparse.Namespace) -> None:
    pe = PE32(args.exe)
    for target in args.patterns:
        print(f"=== {target!r} ===")
        for enc_name, pat in (
            ("ASCII", target.encode("ascii") + b"\x00"),
            ("UTF16", target.encode("utf-16-le") + b"\x00\x00"),
        ):
            pos = 0
            while True:
                idx = pe.data.find(pat, pos)
                if idx == -1:
                    break
                va = pe.off_to_va(idx)
                if va is not None:
                    needle = struct.pack("<I", va)
                    refs: list[str] = []
                    rpos = 0
                    while True:
                        ridx = pe.data.find(needle, rpos)
                        if ridx == -1:
                            break
                        rva = pe.off_to_va(ridx)
                        if rva is not None:
                            refs.append(f"0x{rva:08X}")
                        rpos = ridx + 1
                    print(f"  [{enc_name}] VA=0x{va:08X} (off=0x{idx:08X}) refs={refs}")
                pos = idx + 1


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect SCCT splintercell3.exe PE structure and symbols.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("sections", help="Print PE sections and .text cave slack")
    s.add_argument("exe")
    s.set_defaults(func=_cmd_sections)

    s = sub.add_parser("va2off", help="Convert between virtual address and raw file offset")
    s.add_argument("exe")
    s.add_argument("address", help="Hex or decimal VA/offset (e.g. 0x10A40EE0)")
    s.set_defaults(func=_cmd_va2off)

    s = sub.add_parser("exports", help="List PE export table entries")
    s.add_argument("exe")
    s.add_argument("--grep")
    s.set_defaults(func=_cmd_exports)

    s = sub.add_parser("natives", help="Dump GRegisterNative iNative -> C++ VA bindings")
    s.add_argument("exe")
    s.add_argument("--system-dir", help="Optional System/ directory to join UnrealScript names from *.u")
    s.add_argument("--grep")
    s.set_defaults(func=_cmd_natives)

    s = sub.add_parser("strings", help="Search ASCII/UTF-16LE strings and find 32-bit VA xrefs")
    s.add_argument("exe")
    s.add_argument("patterns", nargs="+")
    s.set_defaults(func=_cmd_strings)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
