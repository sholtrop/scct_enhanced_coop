#!/usr/bin/env python3
"""
Splinter Cell: Chaos Theory UnrealScript bytecode disassembler (UE 2.5,
package version 100 / licensee 124).

On-disk UStruct / UFunction layout in SCCT:
  [tagged properties, normally single None]
  SuperField(ci) Next(ci) ScriptText(ci) Children(ci) FriendlyName(name ci)
  Line(i32) TextPos(i32) Unknown(u8) ScriptSize(i32)  # ScriptSize is in-memory size
  bytecode...
  UFunction trailer: iNative(u16) OperPrecedence(u8) FunctionFlags(u32) [RepOffset(u16)]

In memory, object references and FNames occupy 4 bytes whereas on disk they are
CompactIndex values. Jump targets and LabelTable offsets are memory offsets, so the
disassembler tracks both disk and memory offsets simultaneously.

Usage examples:
  python3 uscript.py disasm System/Echelon.u --export EPlayerController.SwitchEEV --disk
  python3 uscript.py disasm System/Engine.u --export LevelInfo.PostBeginPlay --disk
  python3 uscript.py disasm System/EchelonPattern.u --export P_03_Bank_Communications.Pattern --label Intro
  python3 uscript.py natives --system-dir System/ --grep EndMission
"""

from __future__ import annotations

import argparse
import os
import re
import struct
from pathlib import Path
from typing import Any

from upk import UpkPackage, read_compact_index, resolve_game_path

FUNC_OPERATOR = 0x1000
FUNC_PREOPERATOR = 0x2000

CAST_NAMES = {
    0x39: "Vector", 0x3A: "int", 0x3B: "bool", 0x3C: "float", 0x3D: "byte",
    0x3E: "bool", 0x3F: "float", 0x40: "byte", 0x41: "int", 0x42: "float",
    0x43: "byte", 0x44: "int", 0x45: "bool", 0x46: "byte", 0x47: "int",
    0x48: "bool", 0x49: "float", 0x4A: "string", 0x4B: "string", 0x4C: "string",
    0x4D: "string", 0x4E: "string", 0x4F: "string", 0x50: "string", 0x51: "string",
    0x52: "string", 0x53: "string", 0x54: "string", 0x55: "string", 0x56: "string",
    0x57: "string", 0x58: "byte", 0x59: "int", 0x5A: "bool", 0x5B: "float",
    0x5C: "Vector", 0x5D: "Rotator", 0x5E: "bool", 0x5F: "bool",
}


class DisasmError(Exception):
    pass


def parse_struct_header(data: bytes, so: int, sz: int) -> dict[str, int]:
    """Parse an SCCT UStruct/UFunction/UState header and return bytecode bounds."""
    o = so
    ni, o = read_compact_index(data, o)
    if ni != 0:
        o = so
    hdr: dict[str, int] = {}
    hdr["super"], o = read_compact_index(data, o)
    hdr["next"], o = read_compact_index(data, o)
    hdr["script_text"], o = read_compact_index(data, o)
    hdr["children"], o = read_compact_index(data, o)
    hdr["friendly_name"], o = read_compact_index(data, o)
    hdr["line"], hdr["text_pos"] = struct.unpack_from("<ii", data, o)
    o += 8
    hdr["unknown_u8"] = data[o]
    o += 1
    hdr["script_size"] = struct.unpack_from("<i", data, o)[0]
    o += 4
    hdr["code_start"] = o
    hdr["end"] = so + sz
    return hdr


class UScriptDisassembler:
    """Decodes SCCT UnrealScript bytecode into readable UnrealScript-like statements."""

    def __init__(self, pkg: UpkPackage, code: bytes, script_size: int, natives: dict[int, dict[str, Any]] | None = None):
        self.pkg = pkg
        self.code = code
        self.script_size = script_size
        self.natives = natives or {}
        self.pos = 0
        self.mem = 0
        self.labels: dict[int, str] = {}

    def u8(self) -> int:
        v = self.code[self.pos]
        self.pos += 1
        self.mem += 1
        return v

    def u16(self) -> int:
        v = struct.unpack_from("<H", self.code, self.pos)[0]
        self.pos += 2
        self.mem += 2
        return v

    def i32(self) -> int:
        v = struct.unpack_from("<i", self.code, self.pos)[0]
        self.pos += 4
        self.mem += 4
        return v

    def f32(self) -> float:
        v = struct.unpack_from("<f", self.code, self.pos)[0]
        self.pos += 4
        self.mem += 4
        return v

    def obj(self) -> int:
        v, self.pos = read_compact_index(self.code, self.pos)
        self.mem += 4
        return v

    def name(self) -> str:
        v, self.pos = read_compact_index(self.code, self.pos)
        self.mem += 4
        return self.pkg.name_str(v)

    def cstr(self) -> str:
        end = self.code.find(b"\x00", self.pos)
        if end < 0:
            raise DisasmError("unterminated string")
        s = self.code[self.pos : end].decode("latin1", errors="replace")
        n = end + 1 - self.pos
        self.pos += n
        self.mem += n
        return s

    def ustr(self) -> str:
        start = self.pos
        while True:
            if self.pos + 1 >= len(self.code):
                raise DisasmError("unterminated unicode string")
            if self.code[self.pos] == 0 and self.code[self.pos + 1] == 0:
                break
            self.pos += 2
        s = self.code[start : self.pos].decode("utf-16-le", errors="replace")
        self.pos += 2
        self.mem += self.pos - start
        return s

    def args(self) -> list[str]:
        out: list[str] = []
        while True:
            if self.pos >= len(self.code):
                raise DisasmError("EOF in argument list")
            if self.code[self.pos] == 0x16:
                self.u8()
                return out
            out.append(self.expr())

    def native_call(self, inative: int) -> str:
        info = self.natives.get(inative)
        a = self.args()
        if not info:
            return f"Native{inative}({', '.join(a)})"
        fn = info["friendly"] or info["name"]
        fl = info["flags"]
        if fl & FUNC_PREOPERATOR and len(a) == 1:
            return f"{fn}{a[0]}"
        if fl & FUNC_OPERATOR and len(a) == 2:
            return f"({a[0]} {fn} {a[1]})"
        if fl & FUNC_OPERATOR and len(a) == 1:
            return f"{a[0]}{fn}"
        return f"{fn}({', '.join(a)})"

    def expr(self) -> str:
        if self.pos >= len(self.code):
            raise DisasmError("EOF")
        op_pos = self.pos
        op = self.u8()
        if op in (0x00, 0x01):
            return self.pkg.obj_name(self.obj())
        if op == 0x02:
            return f"default.{self.pkg.obj_name(self.obj())}"
        if op == 0x04:
            return f"return {self.expr()}".rstrip()
        if op == 0x05:
            self.u8()
            return f"switch ({self.expr()})"
        if op == 0x06:
            return f"goto 0x{self.u16():04x}"
        if op == 0x07:
            tgt = self.u16()
            return f"if (!({self.expr()})) goto 0x{tgt:04x}"
        if op == 0x08:
            return "stop"
        if op == 0x09:
            self.u16()
            return f"assert({self.expr()})"
        if op == 0x0A:
            nxt = self.u16()
            if nxt == 0xFFFF:
                return "default:"
            return f"case {self.expr()}:  (next 0x{nxt:04x})"
        if op == 0x0B:
            return ""
        if op == 0x0C:
            entries: list[str] = []
            while self.pos < len(self.code):
                nm = self.name()
                off = self.i32()
                if nm == "None":
                    break
                self.labels[off] = nm
                entries.append(f"{nm}=0x{off:04x}")
            return f"LabelTable({', '.join(entries)})"
        if op == 0x0D:
            return f"GotoLabel({self.expr()})"
        if op == 0x0E:
            return self.expr()
        if op in (0x0F, 0x14):
            lhs = self.expr()
            return f"{lhs} = {self.expr()}"
        if op in (0x10, 0x1A):
            idx = self.expr()
            return f"{self.expr()}[{idx}]"
        if op == 0x11:
            a = [self.expr() for _ in range(4)]
            return f"new({a[0]}, {a[1]}, {a[2]}) {a[3]}"
        if op == 0x12:
            o = self.expr()
            self.u16()
            self.u8()
            return f"{o}.static.{self.expr()}"
        if op == 0x13:
            c = self.pkg.obj_name(self.obj())
            return f"class<{c}>({self.expr()})"
        if op == 0x16:
            return ")"
        if op == 0x17:
            return "self"
        if op == 0x18:
            self.u16()
            return self.expr()
        if op == 0x19:
            o = self.expr()
            self.u16()
            self.u8()
            return f"{o}.{self.expr()}"
        if op == 0x1B:
            fn = self.name()
            return f"{fn}({', '.join(self.args())})"
        if op == 0x1C:
            ref = self.obj()
            return f"{self.pkg.obj_full_name(ref)}({', '.join(self.args())})"
        if op == 0x1D:
            return str(self.i32())
        if op == 0x1E:
            return f"{self.f32():g}"
        if op == 0x1F:
            return repr(self.cstr())
        if op == 0x20:
            ref = self.obj()
            return f"{self.pkg.obj_class_name(ref)}'{self.pkg.obj_full_name(ref)}'"
        if op == 0x21:
            return f"'{self.name()}'"
        if op == 0x22:
            return f"rot({self.i32()},{self.i32()},{self.i32()})"
        if op == 0x23:
            return f"vect({self.f32():g},{self.f32():g},{self.f32():g})"
        if op in (0x24, 0x2C):
            return str(self.u8())
        if op == 0x25:
            return "0"
        if op == 0x26:
            return "1"
        if op == 0x27:
            return "True"
        if op == 0x28:
            return "False"
        if op == 0x29:
            return f"NativeParm({self.pkg.obj_name(self.obj())})"
        if op == 0x2A:
            return "None"
        if op == 0x2D:
            return self.expr()
        if op == 0x2E:
            c = self.pkg.obj_name(self.obj())
            return f"{c}({self.expr()})"
        if op == 0x2F:
            e = self.expr()
            end = self.u16()
            return f"foreach {e}  (end 0x{end:04x})"
        if op == 0x30:
            return "IteratorPop"
        if op == 0x31:
            return "IteratorNext"
        if op in (0x32, 0x33):
            self.obj()
            a = self.expr()
            b = self.expr()
            return f"({a} {'==' if op == 0x32 else '!='} {b})"
        if op == 0x34:
            return repr(self.ustr())
        if op == 0x36:
            m = self.pkg.obj_name(self.obj())
            return f"{self.expr()}.{m}"
        if op == 0x37:
            return f"{self.expr()}.Length"
        if op == 0x38:
            fn = self.name()
            return f"global.{fn}({', '.join(self.args())})"
        if op == 0x39:
            ct = self.u8()
            return f"{CAST_NAMES.get(ct, f'cast{ct:02x}')}({self.expr()})"
        if op == 0x40:
            a, i, n = self.expr(), self.expr(), self.expr()
            return f"{a}.Insert({i}, {n})"
        if op == 0x41:
            a, i, n = self.expr(), self.expr(), self.expr()
            return f"{a}.Remove({i}, {n})"
        if 0x60 <= op <= 0x6F:
            return self.native_call(((op - 0x60) << 8) | self.u8())
        if op >= 0x70:
            return self.native_call(op)
        raise DisasmError(f"unknown opcode 0x{op:02x} at disk+0x{op_pos:04x}")

    def run(self) -> tuple[list[tuple[int, int, str]], str | None]:
        stmts: list[tuple[int, int, str]] = []
        err: str | None = None
        while self.pos < len(self.code) and self.mem < self.script_size:
            m, d = self.mem, self.pos
            try:
                s = self.expr()
            except (DisasmError, IndexError, struct.error) as exc:
                err = f"stopped at mem 0x{m:04x} / disk +0x{d:04x}: {exc}"
                break
            stmts.append((m, d, s))
        return stmts, err


def build_native_table(system_dir: Path) -> dict[int, dict[str, Any]]:
    """Scan all *.u packages in System/ to build an iNative -> metadata table."""
    natives: dict[int, dict[str, Any]] = {}
    for u_file in sorted(system_dir.glob("*.u")):
        try:
            pkg = UpkPackage(u_file)
        except Exception:
            continue
        for exp in pkg.exports:
            if pkg.obj_class_name(exp.index) != "Function" or exp.serial_size <= 0:
                continue
            try:
                hdr = parse_struct_header(pkg.data, exp.serial_offset, exp.serial_size)
                code = pkg.data[hdr["code_start"] : hdr["end"]]
                dis = UScriptDisassembler(pkg, code, hdr["script_size"])
                _, err = dis.run()
                if err:
                    continue
                tail = hdr["code_start"] + dis.pos
                inative, prec, flags = struct.unpack_from("<HBI", pkg.data, tail)
            except Exception:
                continue
            if inative == 0:
                continue
            natives[inative] = {
                "friendly": pkg.name_str(hdr["friendly_name"]),
                "name": pkg.name_str(exp.obj_name),
                "owner": pkg.obj_name(exp.package_index),
                "package": u_file.stem,
                "prec": prec,
                "flags": flags,
            }
    return natives


def _find_exports(pkg: UpkPackage, target: str) -> list[int]:
    if target in ("*", "all"):
        return [e.index for e in pkg.exports]
    hits: list[int] = []
    for exp in pkg.exports:
        if target.isdigit():
            if exp.index == int(target):
                hits.append(exp.index)
        elif target.lower() in (pkg.obj_name(exp.index).lower(), pkg.obj_full_name(exp.index).lower()):
            hits.append(exp.index)
    return hits


def _resolve_system_dir(explicit: str | None, file_path: Path | None = None) -> Path | None:
    if explicit:
        return Path(explicit)
    if file_path is not None and file_path.parent.is_dir() and list(file_path.parent.glob("*.u")):
        return file_path.parent
    env_root = os.environ.get("SCCT_GAME_ROOT")
    if env_root:
        cand = Path(env_root) / "System"
        if cand.is_dir():
            return cand
    return None


def _cmd_disasm(args: argparse.Namespace) -> None:
    pkg_path = resolve_game_path(args.file, args.game_dir)
    pkg = UpkPackage(pkg_path)
    sys_dir = _resolve_system_dir(args.system_dir, pkg_path)
    natives = build_native_table(sys_dir) if sys_dir else {}
    hits = _find_exports(pkg, args.export)
    if not hits:
        print(f"No export matching {args.export!r}")
        return

    lbl_re = re.compile(args.label, re.I) if args.label else None
    grep_re = re.compile(args.grep, re.I) if args.grep else None
    is_all = args.export in ("*", "all")

    for idx in hits:
        cls = pkg.obj_class_name(idx)
        if cls not in ("Function", "State"):
            if not is_all:
                print(f"[Exp {idx}] {pkg.obj_full_name(idx)} is {cls}, expected Function or State")
            continue
        exp = pkg.exports[idx - 1]
        hdr = parse_struct_header(pkg.data, exp.serial_offset, exp.serial_size)
        code = pkg.data[hdr["code_start"] : hdr["end"]]
        dis = UScriptDisassembler(pkg, code, hdr["script_size"], natives)
        stmts, err = dis.run()

        lines: list[tuple[int, str, str, str]] = []
        cur_label: str | None = None
        for mem_off, disk_off, stmt in stmts:
            if mem_off in dis.labels:
                cur_label = dis.labels[mem_off]
            if lbl_re and not (cur_label and lbl_re.search(cur_label)):
                continue
            if grep_re and not grep_re.search(stmt):
                continue
            if stmt:
                extra = f" (code+0x{disk_off:04x} file=0x{hdr['code_start'] + disk_off:06X})" if args.disk else ""
                where = f"[{cur_label}] " if cur_label else ""
                lines.append((mem_off, extra, where, stmt))

        if grep_re and not lines:
            continue

        print(
            f"=== [Exp {idx}] {pkg.obj_full_name(idx)} ({cls}) "
            f"super={pkg.obj_full_name(hdr['super'])} ScriptSize={hdr['script_size']} ==="
        )
        if cls == "Function" and not err:
            tail = hdr["code_start"] + dis.pos
            if tail + 7 <= hdr["end"]:
                inative, _prec, flags = struct.unpack_from("<HBI", pkg.data, tail)
                print(f"    iNative={inative} FunctionFlags=0x{flags:08X}")
        for mem_off, extra, where, stmt in lines:
            print(f"    0x{mem_off:04x}{extra}: {where}{stmt}")
        if err:
            print(f"  !! {err}")


def _cmd_natives(args: argparse.Namespace) -> None:
    sys_dir = _resolve_system_dir(args.system_dir)
    if not sys_dir or not sys_dir.is_dir():
        raise SystemExit("Pass --system-dir <path/to/System> or set SCCT_GAME_ROOT.")
    natives = build_native_table(sys_dir)
    pat = re.compile(args.grep, re.I) if args.grep else None
    for k in sorted(natives):
        v = natives[k]
        line = f"{k:5d} 0x{k:03X}  {v['package']}.{v['owner']}.{v['name']}  [{v['friendly']}] flags=0x{v['flags']:08X}"
        if pat and not pat.search(line):
            continue
        print(line)


def main() -> None:
    parser = argparse.ArgumentParser(description="Disassemble SCCT UnrealScript bytecode.")
    parser.add_argument("--game-dir", help="Optional SCCT game root folder (or set SCCT_GAME_ROOT)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("disasm", help="Disassemble Function/State exports in a .u package")
    s.add_argument("file", help="Path to .u package (e.g. System/Echelon.u)")
    s.add_argument("--export", required=True, help="1-based index, short name, full dotted name, or 'all'")
    s.add_argument("--system-dir", help="Directory containing *.u files for native name resolution")
    s.add_argument("--label", help="Regex filter on state label name")
    s.add_argument("--grep", help="Regex filter on disassembled statements")
    s.add_argument("--disk", action="store_true", help="Print code-relative and absolute file offsets")
    s.set_defaults(func=_cmd_disasm)

    s = sub.add_parser("natives", help="List iNative function bindings across System/*.u")
    s.add_argument("--system-dir", help="Directory containing *.u files")
    s.add_argument("--grep", help="Regex filter")
    s.set_defaults(func=_cmd_natives)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
