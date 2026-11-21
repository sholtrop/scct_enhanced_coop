#!/usr/bin/env python3
"""
Validator for Splinter Cell: Chaos Theory Co-op maps (.scl + optional game files).

Checks whether a map satisfies the engine's hard Co-op requirements (UGameEngine::LoadMap,
EchelonGameInfo.FindPlayerStart, UPK/Havok integrity, INI/MapRotation registration) and
flags common conversion pitfalls (wrong SamMesh/StartMesh, UseDefaultSoundMap audio loss,
overlapping spawn points, attached HQ speaker pawns, missing localization or audio files).

Usage examples:
  python3 validate_coop_map.py Data/Maps/01_Panama.scl
  python3 validate_coop_map.py Data/Maps/01_Lighthouse_COOP.scl --game-dir "/path/to/SCCT"
  python3 validate_coop_map.py Data/Maps/01_Lighthouse.scl --scl-only
  python3 validate_coop_map.py --all --game-dir "/path/to/SCCT"
"""

from __future__ import annotations

import argparse
import math
import os
import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

from umd import UmdArchive
from upk import UpkPackage, read_compact_index, resolve_game_path

HQ_SPEAKER_TAGS = {"lambert", "elambert", "hq", "headquarters", "grim", "redding"}
P2_HAZARD_PROPS = {"Base", "RelativeLocation", "RelativeRotation"}


@dataclass
class ValidationReport:
    map_path: Path
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    passes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def _find_child_ci(parent: Path, name: str) -> Path | None:
    if not parent.is_dir():
        return None
    direct = parent / name
    if direct.exists():
        return direct
    low = name.lower()
    for entry in parent.iterdir():
        if entry.name.lower() == low:
            return entry
    return None


def _find_rel_ci(root: Path, rel_parts: list[str]) -> Path | None:
    cur = root
    for part in rel_parts:
        nxt = _find_child_ci(cur, part)
        if nxt is None:
            return None
        cur = nxt
    return cur


def _detect_game_root(map_path: Path, explicit: str | None) -> Path | None:
    if explicit:
        root = Path(explicit)
        return root if root.is_dir() else None
    env_root = os.environ.get("SCCT_GAME_ROOT")
    if env_root and Path(env_root).is_dir():
        return Path(env_root)
    # Infer <root>/Data/Maps/<map>.scl
    resolved = map_path.resolve()
    if len(resolved.parents) >= 3:
        cand = resolved.parents[2]
        if _find_rel_ci(cand, ["System", "dynamic-pc.umd"]) is not None:
            return cand
    return None


def _decode_text(raw: bytes) -> str:
    if raw.startswith(b"\xff\xfe"):
        return raw.decode("utf-16-le", errors="replace")
    return raw.decode("latin1", errors="replace")


def _read_virtual_or_loose(game_root: Path, umd: UmdArchive | None, vpath: str) -> tuple[bytes | None, str | None]:
    parts = [p for p in vpath.replace("\\", "/").split("/") if p]
    if umd is not None:
        entry = umd.find(vpath)
        if entry is not None:
            return umd.read_entry(entry), f"dynamic-pc.umd:{entry.path}"
    loose = _find_rel_ci(game_root, parts)
    if loose is not None and loose.is_file():
        return loose.read_bytes(), str(loose)
    return None, None


def _parse_ini_kv(text: str) -> dict[str, dict[str, str]]:
    sections: dict[str, dict[str, str]] = {}
    cur = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(";") or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            cur = line[1:-1].strip().lower()
            sections.setdefault(cur, {})
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            sections.setdefault(cur, {})[k.strip().lower()] = v.strip().strip('"')
    return sections


def _parse_map_rotation_coop(text: str) -> list[str]:
    found: list[str] = []
    for raw_line in text.splitlines():
        m = re.match(r'^\s*MissionCoop\[\d+\]\s*=\s*"?([^"\r\n;]+)"?', raw_line, re.I)
        if m:
            found.append(m.group(1).strip())
    return found


def _collect_coop_identities(
    game_root: Path, umd: UmdArchive | None, coop_stems: list[str]
) -> dict[int, list[str]]:
    id_map: dict[int, list[str]] = {}
    seen_stems: set[str] = set()
    for stem in coop_stems:
        low = stem.lower()
        if low in seen_stems:
            continue
        seen_stems.add(low)
        raw, _ = _read_virtual_or_loose(game_root, umd, f"Data\\Maps\\{stem}.ini")
        if raw is None:
            continue
        ini = _parse_ini_kv(_decode_text(raw))
        ident_s = ini.get("general", {}).get("identity")
        if ident_s and ident_s.isdigit():
            id_map.setdefault(int(ident_s), []).append(stem)
    return id_map


def _prop_obj_full_name(pkg: UpkPackage, props_by_name: dict, key: str) -> str | None:
    prop = props_by_name.get(key)
    if prop is None or prop.prop_type != 5 or not prop.value_bytes:
        return None
    ref, _ = read_compact_index(prop.value_bytes, 0)
    return pkg.obj_full_name(ref)


def _prop_int(props_by_name: dict, key: str, default: int | None = None) -> int | None:
    prop = props_by_name.get(key)
    if prop is None or prop.prop_type != 2 or len(prop.value_bytes) != 4:
        return default
    return struct.unpack_from("<i", prop.value_bytes, 0)[0]


def _prop_bool(props_by_name: dict, key: str) -> bool | None:
    prop = props_by_name.get(key)
    if prop is None or prop.prop_type != 3:
        return None
    return prop.is_array


def _prop_str(props_by_name: dict, key: str) -> str | None:
    prop = props_by_name.get(key)
    if prop is None or prop.prop_type != 13 or not prop.value_bytes:
        return None
    return pkg_fstring_safe(prop.value_bytes)


def pkg_fstring_safe(val_bytes: bytes) -> str:
    from upk import read_fstring

    s, _ = read_fstring(val_bytes, 0)
    return s


def _prop_vector(props_by_name: dict, key: str) -> tuple[float, float, float] | None:
    prop = props_by_name.get(key)
    if prop is None or len(prop.value_bytes) != 12:
        return None
    return struct.unpack("<fff", prop.value_bytes)


def _find_attached_hq_speakers(pkg: UpkPackage) -> list[str]:
    flagged: list[str] = []
    for exp in pkg.exports:
        if exp.serial_size <= 0:
            continue
        oname = pkg.name_str(exp.obj_name)
        cname = pkg.obj_class_name(exp.index)
        is_lambert = cname.lower() == "elambert" or oname.lower().startswith("elambert")
        is_candidate = is_lambert or cname.lower() == "eaigenericnpc" or "pawn" in cname.lower()
        if not is_candidate:
            continue
        props = pkg.parse_export_props(exp.index)
        props_map = {p.name: p for p in props}
        if "CurrentEAIZone" not in props_map:
            continue

        is_speaker = is_lambert
        if not is_speaker:
            tag_prop = props_map.get("Tag")
            if tag_prop is not None and tag_prop.prop_type == 6 and tag_prop.value_bytes:
                ni, _ = read_compact_index(tag_prop.value_bytes, 0)
                if pkg.name_str(ni).lower() in HQ_SPEAKER_TAGS:
                    is_speaker = True
        if is_speaker:
            zone_ref = _prop_obj_full_name(pkg, props_map, "CurrentEAIZone") or "?"
            flagged.append(f"{oname} ({cname}, CurrentEAIZone={zone_ref})")
    return flagged


def validate_scl(
    map_path: Path,
    game_root: Path | None = None,
    umd: UmdArchive | None = None,
    check_game_files: bool = True,
) -> ValidationReport:
    rep = ValidationReport(map_path=map_path)
    if not map_path.is_file():
        rep.errors.append(f"Map file not found: {map_path}")
        return rep

    # 1. Parse UPK header and tables
    try:
        pkg = UpkPackage(map_path)
    except Exception as exc:
        rep.errors.append(f"Failed to parse UPK package: {exc}")
        return rep

    if pkg.version != 100 or pkg.licensee_mode != 124:
        rep.errors.append(
            f"Unexpected UPK version/licensee ({pkg.version}/{pkg.licensee_mode}); "
            "SCCT expects FileVersion=100, LicenseeMode=124."
        )
    else:
        rep.passes.append("UPK header magic/version/licensee valid (100/124)")

    # Locate GenerationCount dynamically past the variable-length 0x0FF0ADDE build string + 16-byte GUID
    if len(pkg.data) >= 0x30 and struct.unpack_from("<I", pkg.data, 0x28)[0] == 0x0FF0ADDE:
        try:
            slen, pos = read_compact_index(pkg.data, 0x2C)
            gen_off = pos + max(0, slen) + 16
            if gen_off + 12 <= len(pkg.data):
                gen_count = struct.unpack_from("<I", pkg.data, gen_off)[0]
                if gen_count >= 1 and gen_off + 4 + gen_count * 8 <= len(pkg.data):
                    gen_exp, gen_names = struct.unpack_from("<II", pkg.data, gen_off + 4)
                    if gen_exp != pkg.export_count or gen_names != pkg.name_count:
                        rep.errors.append(
                            f"Generation[0] header mismatch: Gen[0]=(exports={gen_exp}, names={gen_names}) "
                            f"!= header=(exports={pkg.export_count}, names={pkg.name_count})."
                        )
                    else:
                        rep.passes.append("Generation[0] counts match UPK header")
        except Exception as exc:
            rep.errors.append(f"Failed to parse UPK Generation header: {exc}")

    # Validate table indices & export byte ranges
    bad_exports = 0
    for exp in pkg.exports:
        if not (0 <= exp.obj_name < pkg.name_count):
            bad_exports += 1
        elif exp.serial_size > 0 and (
            exp.serial_offset <= 0 or exp.serial_offset + exp.serial_size > len(pkg.data)
        ):
            bad_exports += 1
    if bad_exports:
        rep.errors.append(f"{bad_exports} export(s) have invalid NameTable indices or out-of-bounds offsets.")
    else:
        rep.passes.append(f"All {pkg.export_count} exports have valid offsets and name references")

    # 2. Trailing Havok hkWorld physics stream
    if not pkg.has_havok_tail:
        rep.errors.append(
            "Missing trailing Havok hkWorld physics stream (expected magic 33 5A 0D F0 immediately after ExportTable)."
        )
    else:
        rep.passes.append(f"Havok hkWorld stream present ({len(pkg.trailing_data):,} bytes)")

    # 3. MyLevel.Actors integrity
    try:
        actors = pkg.read_mylevel_actors()
    except Exception as exc:
        rep.errors.append(f"Failed to read MyLevel.Actors: {exc}")
        return rep

    invalid_actor_refs = [r for r in actors if r < 0 or r > pkg.export_count]
    if invalid_actor_refs:
        rep.errors.append(f"MyLevel.Actors contains {len(invalid_actor_refs)} out-of-range export reference(s).")
    elif not actors:
        rep.errors.append("MyLevel.Actors is empty.")
    else:
        rep.passes.append(f"MyLevel.Actors valid ({len(actors)} entries)")

    actor_set = {r for r in actors if r > 0}

    # 4. LevelInfo0 checks
    li_exp = None
    if actors and 0 < actors[0] <= pkg.export_count:
        li_exp = pkg.exports[actors[0] - 1]
    else:
        li_exp = next(
            (e for e in pkg.exports if pkg.obj_class_name(e.index) == "EchelonLevelInfo" or pkg.obj_name(e.index) == "LevelInfo0"),
            None,
        )

    if li_exp is None or (
        pkg.obj_class_name(li_exp.index) != "EchelonLevelInfo" and pkg.obj_name(li_exp.index) != "LevelInfo0"
    ):
        rep.errors.append("MyLevel.Actors[0] is not LevelInfo0 (EchelonLevelInfo).")
        li_props_map: dict = {}
    else:
        li_props = pkg.parse_export_props(li_exp.index)
        li_props_map = {p.name: p for p in li_props}
        bmp = _prop_bool(li_props_map, "bMultiplayerMap")
        if bmp is not True:
            rep.errors.append(
                "LevelInfo0.bMultiplayerMap is not True (UGameEngine::LoadMap will clear GEngine+0xA8 and abort Co-op)."
            )
        else:
            rep.passes.append("LevelInfo0.bMultiplayerMap = True")

        # SoundMapName vs UseDefaultSoundMap check
        sound_map_name = _prop_str(li_props_map, "SoundMapName")
        use_default_sound = _prop_bool(li_props_map, "UseDefaultSoundMap")
        map_stem = map_path.stem
        if sound_map_name and sound_map_name.lower() != map_stem.lower() and use_default_sound is not False:
            rep.warnings.append(
                f"LevelInfo0.SoundMapName={sound_map_name!r} differs from filename {map_stem!r}, "
                "but UseDefaultSoundMap is not explicitly False (PostBeginPlay will overwrite "
                "SoundMapName and break DareAudio sound bank loading)."
            )
        else:
            rep.passes.append("SoundMapName / UseDefaultSoundMap configuration OK")

    # 5. PlayerStart checks (UGameEngine::LoadMap + EchelonGameInfo.FindPlayerStart)
    starts = [
        exp
        for exp in pkg.exports
        if exp.index in actor_set and pkg.obj_class_name(exp.index) in ("EchelonPlayerStart", "PlayerStart")
    ]
    if len(starts) < 2:
        rep.errors.append(
            f"Only {len(starts)} PlayerStart actor(s) in MyLevel.Actors; Co-op requires at least 2 "
            "(UGameEngine::LoadMap falls back to Single Player if < 2)."
        )
    else:
        rep.passes.append(f"Found {len(starts)} PlayerStart actors in MyLevel.Actors")

    p1_starts = []
    p2_starts = []
    start_details = []
    for st in starts:
        sp = {p.name: p for p in pkg.parse_export_props(st.index)}
        spot_id = _prop_int(sp, "spotID", 0)
        start_mesh = _prop_obj_full_name(pkg, sp, "StartMesh")
        loc = _prop_vector(sp, "Location")
        has_pattern = "PatternID" in sp or "JumpLabel" in sp
        info = (st, sp, spot_id, start_mesh, loc, has_pattern)
        start_details.append(info)
        if spot_id == 0:
            p1_starts.append(info)
        elif spot_id == 2:
            p2_starts.append(info)

    if not p1_starts:
        rep.errors.append("Missing Player 1 spawn: no EchelonPlayerStart with spotID=0 (or omitted default).")
    if not p2_starts:
        rep.errors.append("Missing Player 2 spawn: no EchelonPlayerStart with spotID=2 (Client PlayerID is 2).")
    if p1_starts and p2_starts:
        rep.passes.append("Both Player 1 (spotID=0) and Player 2 (spotID=2) spawns present")

    # Co-op skeletal mesh check (LevelInfo0.SamMesh or per-start StartMesh)
    li_sam_mesh = _prop_obj_full_name(pkg, li_props_map, "SamMesh")
    li_is_coop_mesh = li_sam_mesh is not None and li_sam_mesh.lower() == "coopanims.coop_player"
    mesh_targets = (p1_starts[:1] + p2_starts[:1]) or start_details[:1]
    if mesh_targets:
        bad_mesh_starts = []
        for st, _, spot_id, smesh, _, _ in mesh_targets:
            eff_mesh = smesh if smesh is not None else li_sam_mesh
            if eff_mesh is None or eff_mesh.lower() != "coopanims.coop_player":
                bad_mesh_starts.append(f"{pkg.obj_name(st.index)}(spotID={spot_id}) -> {eff_mesh or 'ESam.SamA (default)'}")
        if bad_mesh_starts:
            rep.warnings.append(
                "Co-op player mesh is not CoopAnims.COOP_Player on: "
                + ", ".join(bad_mesh_starts)
                + " (set LevelInfo0.SamMesh and/or EchelonPlayerStart.StartMesh to CoopAnims.COOP_Player)."
            )
        else:
            mesh_src = "LevelInfo0.SamMesh" if li_is_coop_mesh else "EchelonPlayerStart.StartMesh"
            rep.passes.append(f"Co-op skeletal mesh configured (CoopAnims.COOP_Player via {mesh_src})")
    elif not li_is_coop_mesh:
        rep.warnings.append(
            f"LevelInfo0.SamMesh is {li_sam_mesh or 'ESam.SamA (default)'}; Co-op maps expect CoopAnims.COOP_Player."
        )

    if p1_starts and p2_starts:
        # Spawn proximity & duplicate pattern checks
        p1_loc = p1_starts[0][4]
        p2_loc = p2_starts[0][4]
        if p1_loc is None or p2_loc is None:
            rep.warnings.append("One or more EchelonPlayerStart actors is missing a Location property.")
        else:
            dist = math.dist(p1_loc, p2_loc)
            if dist < 20.0:
                rep.warnings.append(
                    f"Player 1 and Player 2 spawn points are only {dist:.1f} units apart "
                    f"(P1={tuple(round(v, 1) for v in p1_loc)}, P2={tuple(round(v, 1) for v in p2_loc)}); "
                    "players may spawn stuck inside each other."
                )
            else:
                rep.passes.append(f"P1/P2 spawn separation OK ({dist:.1f} units)")

        if p1_starts[0][5] and p2_starts[0][5]:
            rep.warnings.append(
                "Both spotID=0 and spotID=2 starts define PatternID/JumpLabel; "
                "strip PatternID/JumpLabel from the secondary start to avoid double-firing startup patterns."
            )

        p2_hazards = [k for k in P2_HAZARD_PROPS if k in p2_starts[0][1]]
        if p2_hazards:
            rep.warnings.append(
                f"Player 2 start ({pkg.obj_name(p2_starts[0][0].index)}) retains attachment properties "
                f"{', '.join(p2_hazards)}; strip these if cloned from an attached SP start."
            )

    # 6. HQ radio speaker pawn EAIZone attachment check
    attached_speakers = _find_attached_hq_speakers(pkg)
    if attached_speakers:
        rep.warnings.append(
            "Off-map HQ speaker pawn(s) still have CurrentEAIZone set "
            f"({', '.join(attached_speakers)}); radio voice lines may be silent in Co-op unless detached."
        )
    else:
        rep.passes.append("No HQ radio speaker pawns gated behind CurrentEAIZone")

    # 7. Companion files & dynamic-pc.umd checks (optional)
    if check_game_files and game_root is not None:
        stem = map_path.stem
        maps_dir = _find_rel_ci(game_root, ["Data", "Maps"])

        # Audio companion files
        for ext in ("_sound.occ", "_sound.uns"):
            if maps_dir is None or _find_child_ci(maps_dir, f"{stem}{ext}") is None:
                rep.warnings.append(f"Missing audio file Data/Maps/{stem}{ext}")

        # MapRotation.ini registration
        mr_raw, mr_src = _read_virtual_or_loose(game_root, umd, "System\\MapRotation.ini")
        coop_list = _parse_map_rotation_coop(_decode_text(mr_raw)) if mr_raw else []
        in_map_rotation = any(m.lower() == stem.lower() for m in coop_list)

        # Map .ini check
        ini_raw, ini_src = _read_virtual_or_loose(game_root, umd, f"Data\\Maps\\{stem}.ini")
        if ini_raw is None:
            rep.errors.append(
                f"Missing Data/Maps/{stem}.ini (neither loose on disk nor in dynamic-pc.umd); "
                "FStartMap::LoadFromIni cannot register the level."
            )
        else:
            ini = _parse_ini_kv(_decode_text(ini_raw))
            gen = ini.get("general", {})
            mp_val = gen.get("multiplayer", "").lower()
            if mp_val not in ("true", "1"):
                rep.errors.append(f"Data/Maps/{stem}.ini ({ini_src}) does not set Multiplayer=true.")
            else:
                rep.passes.append(f"Map INI found with Multiplayer=true ({ini_src})")

            ident_s = gen.get("identity")
            if not ident_s or not ident_s.isdigit():
                rep.errors.append(f"Data/Maps/{stem}.ini is missing a valid numeric Identity=<N>.")
            else:
                ident = int(ident_s)
                id_map = _collect_coop_identities(game_root, umd, coop_list + [stem])
                dups = [m for m in id_map.get(ident, []) if m.lower() != stem.lower()]
                if dups:
                    rep.warnings.append(
                        f"Data/Maps/{stem}.ini Identity={ident} collides with: {', '.join(dups)}."
                    )

            xbl = gen.get("xboxlivecontent", "0")
            xbl_nonzero = xbl.isdigit() and int(xbl) != 0
            if not in_map_rotation and not xbl_nonzero:
                rep.errors.append(
                    f"{stem!r} is not listed under MissionCoop[...] in System/MapRotation.ini "
                    f"({mr_src or 'missing'}); it will not appear in the Co-op Mission Select menu."
                )
            elif in_map_rotation and xbl_nonzero:
                rep.warnings.append(
                    f"Data/Maps/{stem}.ini has XboxLiveContent={xbl} while also listed in MapRotation.ini; "
                    "this causes duplicate entries in the Co-op Lobby dropdown (set XboxLiveContent=0)."
                )
            elif in_map_rotation:
                rep.passes.append("Registered in System/MapRotation.ini (MissionCoop)")

            if "loadout_host" not in ini or "loadout_client" not in ini:
                rep.warnings.append(
                    f"Data/Maps/{stem}.ini is missing [LOADOUT_HOST] and/or [LOADOUT_CLIENT] sections."
                )

            loc_file = gen.get("localizationfile", "")
            if loc_file:
                loc_stem = loc_file.replace("/", "\\").split("\\")[-1]
                loc_raw, _ = _read_virtual_or_loose(
                    game_root, umd, f"Data\\System\\Localization\\{loc_stem}.int"
                )
                if loc_raw is None:
                    rep.warnings.append(
                        f"LocalizationFile target Data/System/Localization/{loc_stem}.int not found "
                        "(lobby mission title may fail to localize)."
                    )

        # Per-map localization for computers/emails/interactions
        map_loc_raw, _ = _read_virtual_or_loose(
            game_root, umd, f"Data\\System\\Localization\\{stem}.int"
        )
        if map_loc_raw is None:
            rep.warnings.append(
                f"Missing Data/System/Localization/{stem}.int (computers, emails, and custom "
                "objective prompts derive their localization path directly from the .scl stem)."
            )
        else:
            rep.passes.append(f"Per-map localization found (Data/System/Localization/{stem}.int)")

        # Loading screen text & DDS textures
        ls_raw, _ = _read_virtual_or_loose(
            game_root, umd, "Data\\System\\Localization\\LoadingScreens.int"
        )
        if ls_raw is None or f"[{stem.lower()}]" not in _decode_text(ls_raw).lower():
            rep.warnings.append(
                f"Missing [{stem.lower()}] section in Data/System/Localization/LoadingScreens.int."
            )

        for idx in (1, 2):
            dds_raw, _ = _read_virtual_or_loose(
                game_root, umd, f"Data\\Magma\\DataPC\\Textures\\GenLoadings\\{stem}_loading_{idx}.dds"
            )
            if dds_raw is None:
                rep.warnings.append(
                    f"Missing loading screen texture Data/Magma/DataPC/Textures/GenLoadings/{stem}_loading_{idx}.dds."
                )

    return rep


def _print_report(rep: ValidationReport, verbose: bool) -> None:
    status = "VALID" if rep.ok else "INVALID"
    if rep.ok and rep.warnings:
        status = "VALID (with warnings)"
    print(f"=== {rep.map_path.name}: {status} ===")
    if verbose:
        for msg in rep.passes:
            print(f"  [PASS] {msg}")
    for msg in rep.errors:
        print(f"  [FAIL] {msg}")
    for msg in rep.warnings:
        print(f"  [WARN] {msg}")
    if rep.ok and not rep.warnings and not verbose:
        print(f"  All {len(rep.passes)} checks passed.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate whether one or more SCCT .scl maps are valid Co-op levels."
    )
    parser.add_argument("maps", nargs="*", help="Path(s) to .scl map file(s)")
    parser.add_argument("--game-dir", help="SCCT game root folder (auto-detected if omitted)")
    parser.add_argument("--all", action="store_true", help="Validate all .scl maps in Data/Maps/")
    parser.add_argument(
        "--scl-only",
        action="store_true",
        help="Validate only the .scl UPK structure without checking .ini, audio, or dynamic-pc.umd",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Print passing checks too")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero if any warnings are found")
    args = parser.parse_args()

    targets: list[Path] = [resolve_game_path(m, args.game_dir) for m in args.maps]
    if args.all:
        root_hint = Path(args.game_dir) if args.game_dir else (
            Path(os.environ["SCCT_GAME_ROOT"]) if "SCCT_GAME_ROOT" in os.environ else None
        )
        if root_hint is None:
            raise SystemExit("--all requires --game-dir <path> or SCCT_GAME_ROOT.")
        maps_dir = _find_rel_ci(root_hint, ["Data", "Maps"])
        if maps_dir is None:
            raise SystemExit(f"Could not find Data/Maps under {root_hint}")
        targets.extend(sorted(p for p in maps_dir.glob("*.scl") if p.name.lower() != "menu.scl"))

    if not targets:
        parser.error("Provide at least one .scl file path (or use --all --game-dir <path>).")

    umd_cache: dict[Path, UmdArchive | None] = {}
    any_failed = False

    for map_path in targets:
        game_root = None if args.scl_only else _detect_game_root(map_path, args.game_dir)
        umd = None
        if game_root is not None:
            if game_root not in umd_cache:
                umd_path = _find_rel_ci(game_root, ["System", "dynamic-pc.umd"])
                umd_cache[game_root] = UmdArchive(umd_path) if umd_path is not None else None
            umd = umd_cache[game_root]

        rep = validate_scl(map_path, game_root=game_root, umd=umd, check_game_files=not args.scl_only)
        _print_report(rep, verbose=args.verbose)
        if not rep.ok or (args.strict and rep.warnings):
            any_failed = True

    sys.exit(1 if any_failed else 0)


if __name__ == "__main__":
    main()
