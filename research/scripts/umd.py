#!/usr/bin/env python3
"""
Splinter Cell: Chaos Theory UMD (System/dynamic-pc.umd) archive reader,
extractor, and updater.

UMD binary layout:
  [raw virtual file payloads ...]
  [TOC at footer.toc_offset]:
      entry_count : CompactIndex
      for each entry:
          name_len : CompactIndex (includes trailing NUL byte)
          name     : Latin-1 bytes + 0x00 (backslash-separated virtual path)
          offset   : uint32 LE (absolute file offset)
          size     : uint32 LE (payload byte size)
          flags    : uint32 LE (typically 0)
  [20-byte trailing footer at EOF - 20]:
      tag        : uint32 LE (preserved on rebuild; 0x9FE3C5A3 in retail)
      toc_offset : uint32 LE
      total_size : uint32 LE (must equal total file size in bytes)
      version    : uint32 LE (1)
      magic      : uint32 LE (0x40FD724D)

Usage examples:
  python3 umd.py info System/dynamic-pc.umd
  python3 umd.py list System/dynamic-pc.umd --grep MapRotation
  python3 umd.py cat System/dynamic-pc.umd System\\MapRotation.ini
  python3 umd.py extract System/dynamic-pc.umd ./unpacked --grep "Localization\\\\01_Lighthouse"
  python3 umd.py upsert System/dynamic-pc.umd System\\MapRotation.ini ./MapRotation.ini -o dynamic-pc.new.umd
"""

from __future__ import annotations

import argparse
import re
import struct
from dataclasses import dataclass
from pathlib import Path

from upk import read_compact_index, write_compact_index

UMD_MAGIC = 0x40FD724D
UMD_VERSION = 1


@dataclass
class UmdEntry:
    index: int
    raw_name: bytes
    path: str
    offset: int
    size: int
    flags: int


class UmdArchive:
    """Seek-based reader and rebuild-safe writer for SCCT .umd archives."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.total_size = self.path.stat().st_size
        if self.total_size < 20:
            raise ValueError(f"UMD file too small ({self.total_size} bytes): {self.path}")

        with self.path.open("rb") as f:
            f.seek(self.total_size - 20)
            tag, toc_offset, footer_total_size, version, magic = struct.unpack("<IIIII", f.read(20))
            if magic != UMD_MAGIC or version != UMD_VERSION:
                raise ValueError(
                    f"Invalid UMD footer in {self.path}: magic=0x{magic:08X}, version={version}"
                )
            if footer_total_size != self.total_size:
                raise ValueError(
                    f"UMD footer total_size ({footer_total_size}) != file size ({self.total_size})"
                )
            self.tag = tag
            self.toc_offset = toc_offset

            f.seek(toc_offset)
            toc_bytes = f.read(self.total_size - 20 - toc_offset)

        count, pos = read_compact_index(toc_bytes, 0)
        self.entries: list[UmdEntry] = []
        self._by_lower: dict[str, UmdEntry] = {}
        for idx in range(count):
            name_len, pos = read_compact_index(toc_bytes, pos)
            raw_name = toc_bytes[pos : pos + name_len]
            pos += name_len
            vpath = raw_name.rstrip(b"\x00").decode("latin1", errors="replace")
            offset, size, flags = struct.unpack_from("<III", toc_bytes, pos)
            pos += 12
            entry = UmdEntry(idx, raw_name, vpath, offset, size, flags)
            self.entries.append(entry)
            self._by_lower[vpath.lower()] = entry

    def find(self, virtual_path: str) -> UmdEntry | None:
        normalized = virtual_path.replace("/", "\\").lower()
        return self._by_lower.get(normalized)

    def read_entry(self, entry: UmdEntry) -> bytes:
        with self.path.open("rb") as f:
            f.seek(entry.offset)
            return f.read(entry.size)

    def write_with_updates(self, updates: dict[str, bytes], out_path: Path | str) -> None:
        """
        Insert or replace virtual files and write a valid UMD archive.

        Existing unchanged payloads stay at their original offsets; updated or new
        payloads are written starting at the previous TOC offset, followed by the
        rebuilt TOC and 20-byte footer.
        """
        entries = [
            UmdEntry(e.index, e.raw_name, e.path, e.offset, e.size, e.flags) for e in self.entries
        ]
        by_lower = {e.path.lower(): e for e in entries}

        # Copy the data region [0 .. toc_offset) unmodified.
        out = Path(out_path)
        with self.path.open("rb") as src, out.open("wb") as dst:
            remaining = self.toc_offset
            chunk_size = 8 * 1024 * 1024
            while remaining > 0:
                chunk = src.read(min(chunk_size, remaining))
                if not chunk:
                    raise EOFError("Unexpected EOF copying UMD data section")
                dst.write(chunk)
                remaining -= len(chunk)

            cursor = self.toc_offset
            for raw_vpath, payload in updates.items():
                vpath = raw_vpath.replace("/", "\\")
                existing = by_lower.get(vpath.lower())
                if existing is not None:
                    existing.offset = cursor
                    existing.size = len(payload)
                else:
                    raw_name = vpath.encode("latin1") + b"\x00"
                    entry = UmdEntry(len(entries), raw_name, vpath, cursor, len(payload), 0)
                    entries.append(entry)
                    by_lower[vpath.lower()] = entry
                dst.write(payload)
                cursor += len(payload)

            new_toc_offset = cursor
            toc = bytearray(write_compact_index(len(entries)))
            for entry in entries:
                toc.extend(write_compact_index(len(entry.raw_name)))
                toc.extend(entry.raw_name)
                toc.extend(struct.pack("<III", entry.offset, entry.size, entry.flags))
            dst.write(toc)

            new_total_size = new_toc_offset + len(toc) + 20
            footer = struct.pack(
                "<IIIII", self.tag, new_toc_offset, new_total_size, UMD_VERSION, UMD_MAGIC
            )
            dst.write(footer)


def _cmd_info(args: argparse.Namespace) -> None:
    umd = UmdArchive(args.umd)
    print(f"File:       {umd.path} ({umd.total_size:,} bytes)")
    print(f"Tag:        0x{umd.tag:08X}")
    print(f"TOC Offset: 0x{umd.toc_offset:08X}")
    print(f"Entries:    {len(umd.entries):,}")


def _cmd_list(args: argparse.Namespace) -> None:
    umd = UmdArchive(args.umd)
    pat = re.compile(args.grep, re.I) if args.grep else None
    for entry in umd.entries:
        if pat and not pat.search(entry.path):
            continue
        print(f"[{entry.index}] {entry.path} (off=0x{entry.offset:X}, sz={entry.size}, flags=0x{entry.flags:X})")


def _cmd_cat(args: argparse.Namespace) -> None:
    umd = UmdArchive(args.umd)
    q = args.target.replace("/", "\\").lower()
    matched = False
    for entry in umd.entries:
        if (q.isdigit() and entry.index == int(q)) or entry.path.lower() == q or q in entry.path.lower():
            matched = True
            raw = umd.read_entry(entry)
            print(f"=== [{entry.index}] {entry.path} (off=0x{entry.offset:X}, sz={entry.size}) ===")
            if raw.startswith(b"\xff\xfe"):
                print(raw.decode("utf-16-le", errors="replace"))
            else:
                print(raw.decode("latin1", errors="replace"))
            if not args.all:
                return
    if not matched:
        raise SystemExit(f"No UMD entry matching {args.target!r}")


def _cmd_extract(args: argparse.Namespace) -> None:
    umd = UmdArchive(args.umd)
    out_root = Path(args.out_dir)
    pat = re.compile(args.grep, re.I) if args.grep else None
    count = 0
    with umd.path.open("rb") as f:
        for entry in umd.entries:
            if pat and not pat.search(entry.path):
                continue
            rel = Path(*[p for p in entry.path.replace("\\", "/").split("/") if p and p != ".."])
            dst = out_root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            f.seek(entry.offset)
            dst.write_bytes(f.read(entry.size))
            count += 1
    print(f"Extracted {count} file(s) to {out_root}")


def _cmd_upsert(args: argparse.Namespace) -> None:
    umd = UmdArchive(args.umd)
    payload = Path(args.local_file).read_bytes()
    out_path = Path(args.output)
    if out_path.resolve() == umd.path.resolve():
        raise SystemExit("Refusing to overwrite input UMD in place; specify a separate -o output path.")
    umd.write_with_updates({args.virtual_path: payload}, out_path)
    print(f"Wrote updated UMD to {out_path} ({args.virtual_path} = {len(payload):,} bytes)")


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect, unpack, and update SCCT .umd archives.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("info", help="Show UMD footer and entry count")
    s.add_argument("umd")
    s.set_defaults(func=_cmd_info)

    s = sub.add_parser("list", help="List virtual files in a UMD archive")
    s.add_argument("umd")
    s.add_argument("--grep", help="Case-insensitive regex filter on virtual path")
    s.set_defaults(func=_cmd_list)

    s = sub.add_parser("cat", help="Print a virtual text/INI/localization file")
    s.add_argument("umd")
    s.add_argument("target", help="Entry index, exact virtual path, or substring")
    s.add_argument("--all", action="store_true", help="Print all matching entries")
    s.set_defaults(func=_cmd_cat)

    s = sub.add_parser("extract", help="Unpack matching virtual files to a directory")
    s.add_argument("umd")
    s.add_argument("out_dir")
    s.add_argument("--grep", help="Case-insensitive regex filter (omit to extract all files)")
    s.set_defaults(func=_cmd_extract)

    s = sub.add_parser("upsert", help="Insert or replace a virtual file and write a new UMD")
    s.add_argument("umd")
    s.add_argument("virtual_path", help=r"Virtual path inside UMD, e.g. System\MapRotation.ini")
    s.add_argument("local_file", help="Path to replacement/new payload on disk")
    s.add_argument("-o", "--output", required=True, help="Output .umd path")
    s.set_defaults(func=_cmd_upsert)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
