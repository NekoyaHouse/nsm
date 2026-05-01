from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import math
import json
from pathlib import Path
import re
import struct
from typing import Iterable

from extractors.bom_v3_end_to_end_parser import decode_bom_v3
from extractors.ysgp_container_scanner import scan_file


HEX_HASH_RE = re.compile(rb"[0-9a-f]{64}")
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
PROPERTY_NAME_RE = re.compile(r"^\s*<name>\s+(?P<name>.+?)\s*$", re.IGNORECASE | re.MULTILINE)
PROPERTY_FORMAT_RE = re.compile(r"^\s*<format>\s+(?P<format>\d+)\s*$", re.IGNORECASE | re.MULTILINE)
COMPILED_ANIM_NAME_EXCLUDES = {
    "animations",
    "bones",
    "format_version",
    "loop",
    "position",
    "rotation",
    "scale",
    "timeline",
    "true",
    "false",
    "catmullrom",
    "hold_on_last_frame",
    "lerp_mode",
    "pre",
    "post",
    "block",
    "entity",
    "player",
    "default",
}
COMPILED_MODEL_NAME_EXCLUDES = {
    "geometry",
    "unknown",
    "default",
    "bones",
    "cubes",
    "pivot",
    "rotation",
    "locators",
    "texturewidth",
    "textureheight",
    "format_version",
    "visible_bounds_width",
    "visible_bounds_height",
    "visible_bounds_offset",
}


@dataclass(frozen=True)
class PropertyAsset:
    ordinal: int
    tag: str
    label: str
    hash_hex: str

    @property
    def display_name(self) -> str:
        if self.label and self.label.lower() != self.tag.lower():
            return f"{self.tag}_{self.label}"
        return self.tag


@dataclass(frozen=True)
class AssetRegion:
    asset: PropertyAsset
    marker_offset: int
    region_end: int
    region_len: int
    exact_kind: str | None
    exact_payload_offset: int | None
    exact_payload_len: int | None
    exact_payload_sha256: str | None
    exact_hash_match: bool
    nearby_strings: tuple[str, ...]
    name_like_strings: tuple[str, ...]
    animation_headers: tuple[dict[str, object], ...]
    raw_section: bytes
    exact_payload: bytes | None


@dataclass(frozen=True)
class AssetScanResult:
    path: Path
    decoded: bytes
    assets: tuple[AssetRegion, ...]


def _sanitize_name(name: str) -> str:
    out = []
    for ch in name:
        if ch.isalnum() or ch in ("-", "_", "."):
            out.append(ch)
        else:
            out.append("_")
    return "".join(out).strip("_") or "asset"


def _read_property_name(path: Path) -> str | None:
    text = scan_file(path, dump=False).property_text
    match = PROPERTY_NAME_RE.search(text)
    if match is None:
        return None
    return match.group("name").strip() or None


def _read_property_format(path: Path) -> int | None:
    text = scan_file(path, dump=False).property_text
    match = PROPERTY_FORMAT_RE.search(text)
    if match is None:
        return None
    return int(match.group("format"))


def parse_property_assets(property_text: str) -> list[PropertyAsset]:
    assets: list[PropertyAsset] = []
    counts: dict[str, int] = {}
    for line in property_text.splitlines():
        stripped = line.strip()
        if not stripped or not stripped.startswith("<"):
            continue
        close = stripped.find(">")
        if close <= 1:
            continue
        tag = stripped[1:close].strip().lower().replace("-", "_")
        rest = stripped[close + 1:].strip()
        hash_match = re.search(r"([0-9a-f]{64})$", rest, re.IGNORECASE)
        if hash_match is None:
            continue
        label = rest[:hash_match.start()].strip().lower()
        label = label.replace(" ", "_")
        key = f"{tag}:{label}"
        counts[key] = counts.get(key, 0) + 1
        if counts[key] > 1:
            if label:
                label = f"{label}_{counts[key]}"
            else:
                label = str(counts[key])
        assets.append(
            PropertyAsset(
                ordinal=len(assets),
                tag=tag,
                label=label,
                hash_hex=hash_match.group(1).lower(),
            )
        )
    return assets


def _extract_ascii_strings(buf: bytes, limit: int = 8) -> tuple[str, ...]:
    values: list[str] = []
    for match in re.finditer(rb"[ -~]{4,}", buf):
        text = match.group().decode("ascii", "replace")
        if text not in values:
            values.append(text)
        if len(values) >= limit:
            break
    return tuple(values)


def _extract_name_like_strings(buf: bytes, limit: int = 128) -> tuple[str, ...]:
    values: list[str] = []
    seen: set[str] = set()
    for match in re.finditer(rb"[A-Za-z_][A-Za-z0-9_.-]{2,}", buf):
        text = match.group().decode("ascii", "replace")
        lower = text.lower()
        if all(ch in "0123456789abcdef" for ch in lower):
            continue
        alpha = sum(ch.isalpha() for ch in text)
        if alpha < 3:
            continue
        if alpha * 2 < len(text):
            continue
        if text in seen:
            continue
        seen.add(text)
        values.append(text)
        if len(values) >= limit:
            break
    return tuple(values)


def _classify_region_kind(region: AssetRegion) -> str:
    if region.exact_kind == "png":
        return "texture_png"
    name = region.asset.display_name
    if "animation" in name:
        return "compiled_animation"
    if "model" in name or name == "model":
        return "compiled_model"
    return "unknown_binary"


def _guess_loop_mode(code: int) -> str:
    mapping = {
        1: "loop_true",
        2: "once_or_default",
        3: "hold_on_last_frame",
    }
    return mapping.get(code, f"unknown_{code}")


def _canonical_animation_stub_name(file_name: str) -> str:
    if file_name.endswith(".section.bin"):
        return file_name[:-12] + ".decompiled.json"
    return file_name + ".decompiled.json"


def _canonical_model_stub_name(file_name: str) -> str:
    if file_name.endswith(".section.bin"):
        return file_name[:-12] + ".decompiled.json"
    return file_name + ".decompiled.json"


def _guess_bone_names(names: Iterable[str], clip_names: set[str]) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for name in names:
        lower = name.lower()
        if name in clip_names:
            continue
        if lower in COMPILED_ANIM_NAME_EXCLUDES:
            continue
        if lower.startswith("math.") or lower.startswith("query.") or lower.startswith("ysm."):
            continue
        if "." in name:
            continue
        if len(name) < 3:
            continue
        alpha = sum(ch.isalpha() for ch in name)
        if alpha < 2:
            continue
        if name in seen:
            continue
        seen.add(name)
        values.append(name)
    return values[:96]


def _guess_model_bone_names(names: Iterable[str]) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for name in names:
        lower = name.lower()
        if lower in COMPILED_MODEL_NAME_EXCLUDES:
            continue
        if lower.startswith("math.") or lower.startswith("query.") or lower.startswith("ysm."):
            continue
        if len(name) < 3:
            continue
        if "." in name and not name.startswith("v."):
            continue
        alpha = sum(ch.isalpha() for ch in name)
        if alpha < 2:
            continue
        if name in seen:
            continue
        seen.add(name)
        values.append(name)
    return values[:128]


def _guess_model_root_names(bone_names: Iterable[str]) -> list[str]:
    roots: list[str] = []
    for name in bone_names:
        lower = name.lower()
        if lower in {"mroot", "root", "allbody", "upperbody", "upbody", "head"} or lower.endswith("root"):
            roots.append(name)
    if not roots:
        roots = list(bone_names)[:1]
    return roots[:8]


def _guess_model_parent_map(bone_names: list[str]) -> dict[str, str]:
    parent_map: dict[str, str] = {}
    lowered = {name.lower(): name for name in bone_names}
    for name in bone_names:
        lower = name.lower()
        if lower.endswith("2") and lower[:-1] in lowered:
            parent_map[name] = lowered[lower[:-1]]
        elif lower.startswith("m") and lower[1:] in lowered:
            parent_map[name] = lowered[lower[1:]]
        elif lower.startswith("left") and "leftarm" in lowered and lower not in {"leftarm", "leftforearm"}:
            parent_map.setdefault(name, lowered["leftarm"])
        elif lower.startswith("right") and "rightarm" in lowered and lower not in {"rightarm", "rightforearm"}:
            parent_map.setdefault(name, lowered["rightarm"])
    return parent_map


def build_model_decompile_stub(
    asset_name: str,
    section_sha256: str,
    names: Iterable[str],
) -> dict[str, object]:
    bone_names = _guess_model_bone_names(names)
    roots = _guess_model_root_names(bone_names)
    parent_map = _guess_model_parent_map(bone_names)
    bones: dict[str, object] = {}
    for name in bone_names:
        entry: dict[str, object] = {}
        if name in roots:
            entry["__root_guess"] = True
        parent = parent_map.get(name)
        if parent is not None:
            entry["__guessed_parent"] = parent
        bones[name] = entry
    return {
        "__compiled_decompile": {
            "status": "partial",
            "asset_name": asset_name,
            "section_sha256": section_sha256,
            "bone_count_guess": len(bone_names),
            "root_count_guess": len(roots),
            "notes": [
                "Recovered from compiled YSM model section.",
                "Bone names are evidence-backed from embedded strings.",
                "Root and parent links are conservative guesses only.",
                "Geometry cubes, pivots, rotations, and UVs are not reconstructed yet.",
            ],
        },
        "model": {
            "bones": bones,
            "__root_names_guess": roots,
        },
    }


def _public_geometry_identifier(asset_name: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_.-]+", ".", asset_name.strip().lower()).strip(".")
    return f"geometry.{clean or 'unknown'}"


def build_model_public_json(
    asset_name: str,
    names: Iterable[str],
) -> dict[str, object]:
    bone_names = _guess_model_bone_names(names)
    parent_map = _guess_model_parent_map(bone_names)
    roots = set(_guess_model_root_names(bone_names))
    bones: list[dict[str, object]] = []
    for name in bone_names:
        entry: dict[str, object] = {"name": name}
        parent = parent_map.get(name)
        if parent is not None and name not in roots:
            entry["parent"] = parent
        bones.append(entry)
    return {
        "format_version": "1.12.0",
        "minecraft:geometry": [
            {
                "description": {
                    "identifier": _public_geometry_identifier(asset_name),
                },
                "bones": bones,
            }
        ],
    }


def build_animation_decompile_stub(
    asset_name: str,
    section_sha256: str,
    names: Iterable[str],
    animation_headers: Iterable[dict[str, object]],
) -> dict[str, object]:
    headers = list(animation_headers)
    clip_names = {str(h["name"]) for h in headers}
    bone_names = _guess_bone_names(names, clip_names)
    animations: dict[str, object] = {}
    for header in headers:
        name = str(header["name"])
        entry: dict[str, object] = {
            "animation_length": header["seconds_guess"],
            "__ticks_f32": header["ticks_f32"],
            "__loop_code": header["loop_code"],
            "__loop_mode_guess": header["loop_mode_guess"],
            "__offset": header["offset"],
            "__bone_names_guess": bone_names,
            "bones": {},
        }
        loop_guess = header["loop_mode_guess"]
        if loop_guess == "loop_true":
            entry["loop"] = True
        elif loop_guess == "hold_on_last_frame":
            entry["loop"] = "hold_on_last_frame"
        animations[name] = entry
    return {
        "format_version": "1.8.0",
        "__compiled_decompile": {
            "status": "partial",
            "asset_name": asset_name,
            "section_sha256": section_sha256,
            "clip_count": len(headers),
            "bone_name_count_guess": len(bone_names),
            "notes": [
                "Recovered from compiled YSM animation section.",
                "Clip names, durations, and loop modes are evidence-backed.",
                "Bone lists are guessed from embedded strings.",
                "Keyframe channels are not reconstructed yet.",
            ],
        },
        "animations": animations,
    }


def build_animation_public_json(
    animation_headers: Iterable[dict[str, object]],
) -> dict[str, object]:
    animations: dict[str, object] = {}
    for header in animation_headers:
        name = str(header["name"])
        entry: dict[str, object] = {
            "animation_length": header["seconds_guess"],
            "bones": {},
        }
        loop_guess = header["loop_mode_guess"]
        if loop_guess == "loop_true":
            entry["loop"] = True
        elif loop_guess == "hold_on_last_frame":
            entry["loop"] = "hold_on_last_frame"
        animations[name] = entry
    return {
        "format_version": "1.8.0",
        "animations": animations,
    }


def _parse_animation_headers(section: bytes) -> tuple[dict[str, object], ...]:
    headers: list[dict[str, object]] = []
    seen_offsets: set[int] = set()
    if len(section) < 74:
        return tuple()

    for off in range(66, len(section) - 12):
        name_len = None
        tag = None
        if off == 66:
            name_len = section[65]
            tag = section[64]
        elif off >= 4 and section[off - 4:off - 1] == b"\x00\x00\x00":
            name_len = section[off - 1]
            tag = 0
        if name_len is None or name_len < 3 or name_len > 32:
            continue
        end = off + name_len
        if end + 8 > len(section):
            continue
        name_bytes = section[off:end]
        if not re.fullmatch(rb"[A-Za-z_][A-Za-z0-9_.-]{2,31}", name_bytes):
            continue
        name = name_bytes.decode("ascii", "replace")
        ticks = struct.unpack_from("<f", section, end)[0]
        code = int.from_bytes(section[end + 4:end + 8], "little")
        if code < 1 or code > 3:
            continue
        if not (math.isinf(ticks) or (0.0 <= ticks <= 4096.0)):
            continue
        if off in seen_offsets:
            continue
        seen_offsets.add(off)
        headers.append(
            {
                "offset": off,
                "tag_byte": tag,
                "name_len": name_len,
                "name": name,
                "ticks_f32": ticks,
                "seconds_guess": (ticks / 20.0) if math.isfinite(ticks) else None,
                "loop_code": code,
                "loop_mode_guess": _guess_loop_mode(code),
            }
        )
    return tuple(headers)


def _parse_png_end(buf: bytes, off: int) -> int | None:
    if off < 0 or off + 8 > len(buf) or buf[off:off + 8] != PNG_MAGIC:
        return None
    pos = off + 8
    while pos + 12 <= len(buf):
        chunk_len = int.from_bytes(buf[pos:pos + 4], "big")
        chunk_type = buf[pos + 4:pos + 8]
        chunk_end = pos + 12 + chunk_len
        if chunk_end > len(buf):
            return None
        pos = chunk_end
        if chunk_type == b"IEND":
            return pos
    return None


def _try_parse_json_at(buf: bytes, off: int) -> bytes | None:
    if off < 0 or off >= len(buf) or buf[off] != 0x7B:
        return None
    depth = 0
    in_str = False
    esc = False
    for end in range(off, len(buf)):
        c = buf[end]
        if in_str:
            if esc:
                esc = False
            elif c == 0x5C:
                esc = True
            elif c == 0x22:
                in_str = False
            continue
        if c == 0x22:
            in_str = True
        elif c == 0x7B:
            depth += 1
        elif c == 0x7D:
            depth -= 1
            if depth == 0:
                blob = buf[off:end + 1]
                try:
                    json.loads(blob.decode("utf-8"))
                except Exception:
                    return None
                return blob
    return None


def _find_exact_payload(
    data: bytes,
    marker_offset: int,
    expected_hash: str,
    next_marker_offset: int,
) -> tuple[str | None, int | None, bytes | None]:
    content_probe_start = marker_offset + 64
    content_probe_end = min(next_marker_offset, marker_offset + 0x2000)

    for start in range(content_probe_start, min(content_probe_start + 0x10, len(data))):
        end = _parse_png_end(data, start)
        if end is None:
            continue
        payload = data[start:end]
        if hashlib.sha256(payload).hexdigest() == expected_hash:
            return ("png", start, payload)

    for start in range(content_probe_start, content_probe_end):
        if data[start] != 0x7B:
            continue
        payload = _try_parse_json_at(data, start)
        if payload is None:
            continue
        if hashlib.sha256(payload).hexdigest() == expected_hash:
            return ("json", start, payload)

    return (None, None, None)


def scan_bom_v3_payload_assets(path: Path) -> AssetScanResult:
    scan = scan_file(path, dump=False)
    property_assets = parse_property_assets(scan.property_text)
    decoded = decode_bom_v3(path).decompressed

    located: list[tuple[int, PropertyAsset]] = []
    for asset in property_assets:
        marker = decoded.find(asset.hash_hex.encode("ascii"))
        if marker < 0:
            continue
        located.append((marker, asset))
    located.sort(key=lambda item: item[0])

    assets: list[AssetRegion] = []
    for idx, (marker, asset) in enumerate(located):
        next_marker = len(decoded)
        if idx + 1 < len(located):
            next_marker = located[idx + 1][0]
        kind, payload_off, payload = _find_exact_payload(
            decoded,
            marker_offset=marker,
            expected_hash=asset.hash_hex,
            next_marker_offset=next_marker,
        )
        assets.append(
            AssetRegion(
                asset=asset,
                marker_offset=marker,
                region_end=next_marker,
                region_len=next_marker - marker,
                exact_kind=kind,
                exact_payload_offset=payload_off,
                exact_payload_len=len(payload) if payload is not None else None,
                exact_payload_sha256=hashlib.sha256(payload).hexdigest() if payload is not None else None,
                exact_hash_match=(payload is not None),
                nearby_strings=_extract_ascii_strings(decoded[marker: min(next_marker, marker + 0x200)]),
                name_like_strings=_extract_name_like_strings(decoded[marker:next_marker]),
                animation_headers=_parse_animation_headers(decoded[marker:next_marker]) if "animation" in asset.display_name else tuple(),
                raw_section=decoded[marker:next_marker],
                exact_payload=payload,
            )
        )

    return AssetScanResult(
        path=path,
        decoded=decoded,
        assets=tuple(assets),
    )


def dump_asset_regions(result: AssetScanResult) -> list[Path]:
    outputs: list[Path] = []
    base = result.path.with_suffix("")
    bundle_assets: list[dict[str, object]] = []
    first_marker = min((region.marker_offset for region in result.assets), default=len(result.decoded))
    for region in result.assets:
        stem = f"{base.name}.{region.asset.ordinal:02d}.{_sanitize_name(region.asset.display_name)}"
        raw_path = result.path.with_name(f"{stem}.section.bin")
        raw_path.write_bytes(region.raw_section)
        outputs.append(raw_path)
        manifest = {
            "source_file": str(result.path),
            "asset_ordinal": region.asset.ordinal,
            "asset_tag": region.asset.tag,
            "asset_label": region.asset.label,
            "asset_display_name": region.asset.display_name,
            "asset_hash": region.asset.hash_hex,
            "marker_offset": region.marker_offset,
            "region_end": region.region_end,
            "region_len": region.region_len,
            "region_kind": _classify_region_kind(region),
            "exact_kind": region.exact_kind,
            "exact_payload_offset": region.exact_payload_offset,
            "exact_payload_len": region.exact_payload_len,
            "exact_payload_sha256": region.exact_payload_sha256,
            "exact_hash_match": region.exact_hash_match,
            "nearby_strings": list(region.nearby_strings),
            "name_like_strings": list(region.name_like_strings),
            "animation_headers": list(region.animation_headers),
        }
        manifest_path = result.path.with_name(f"{stem}.manifest.json")
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        outputs.append(manifest_path)
        entry = {
            "asset_ordinal": region.asset.ordinal,
            "asset_display_name": region.asset.display_name,
            "asset_hash": region.asset.hash_hex,
            "region_kind": _classify_region_kind(region),
            "marker_offset": region.marker_offset,
            "region_end": region.region_end,
            "region_len": region.region_len,
            "section_file": raw_path.name,
            "manifest_file": manifest_path.name,
            "exact_kind": region.exact_kind,
            "exact_file": None,
        }
        if region.exact_payload is not None and region.exact_kind is not None:
            ext = "png" if region.exact_kind == "png" else "json"
            exact_path = result.path.with_name(f"{stem}.{ext}")
            exact_path.write_bytes(region.exact_payload)
            outputs.append(exact_path)
            entry["exact_file"] = exact_path.name
        if region.animation_headers:
            stub = build_animation_decompile_stub(
                asset_name=region.asset.display_name,
                section_sha256=hashlib.sha256(region.raw_section).hexdigest(),
                names=region.name_like_strings,
                animation_headers=region.animation_headers,
            )
            stub_path = result.path.with_name(f"{stem}.decompiled.json")
            stub_path.write_text(json.dumps(stub, indent=2), encoding="utf-8")
            outputs.append(stub_path)
            entry["decompiled_file"] = stub_path.name
        elif _classify_region_kind(region) == "compiled_model":
            stub = build_model_decompile_stub(
                asset_name=region.asset.display_name,
                section_sha256=hashlib.sha256(region.raw_section).hexdigest(),
                names=region.name_like_strings,
            )
            stub_path = result.path.with_name(f"{stem}.decompiled.json")
            stub_path.write_text(json.dumps(stub, indent=2), encoding="utf-8")
            outputs.append(stub_path)
            entry["decompiled_file"] = stub_path.name
        bundle_assets.append(entry)
    bundle_manifest = {
        "source_file": str(result.path),
        "decoded_len": len(result.decoded),
        "prefix_before_first_marker_hex": result.decoded[:first_marker].hex(),
        "asset_count": len(bundle_assets),
        "assets": bundle_assets,
    }
    bundle_path = result.path.with_name(f"{base.name}.asset_bundle.json")
    bundle_path.write_text(json.dumps(bundle_manifest, indent=2), encoding="utf-8")
    outputs.append(bundle_path)
    return outputs


def _canonical_asset_base(asset: PropertyAsset) -> str:
    tag = asset.tag.lower()
    label = _sanitize_name(asset.label.lower()) if asset.label else ""
    mapping = {
        "main_model": "main",
        "model_main": "main",
        "arm_model": "arm",
        "model_arm": "arm",
        "model": "model",
        "main_animation": "main.animation",
        "animation_main": "main.animation",
        "arm_animation": "arm.animation",
        "extra_animation": "extra.animation",
        "tac_animation": "tac.animation",
        "carryon_animation": "carryon.animation",
    }
    if tag in mapping:
        return mapping[tag]
    if tag.startswith("texture_"):
        suffix = _sanitize_name(tag[len("texture_"):].replace("_", "."))
        return f"texture.{suffix}" if suffix else "texture"
    if tag == "texture":
        if label and label != "texture":
            return f"texture.{label}"
        return "texture"
    return _sanitize_name(asset.display_name.replace("_", "."))


def _canonical_section_filename(region: AssetRegion, used: dict[str, int]) -> str:
    base = _canonical_asset_base(region.asset)
    count = used.get(base, 0) + 1
    used[base] = count
    if count > 1:
        base = f"{base}.{count}"
    if region.exact_kind == "png":
        return f"{base}.png"
    if region.exact_kind == "json":
        return f"{base}.json"
    kind = _classify_region_kind(region)
    if kind == "compiled_model":
        suffix = ".section.bin" if base.endswith(".model") else ".model.section.bin"
        return f"{base}{suffix}"
    if kind == "compiled_animation":
        suffix = ".section.bin" if base.endswith(".animation") else ".animation.section.bin"
        return f"{base}{suffix}"
    return f"{base}.section.bin"


def _prune_modern_debug_outputs(out_dir: Path) -> None:
    for pattern in ("*.section.bin", "*.manifest.json", "*.decompiled.json", "asset_bundle.json", "decoded.bin"):
        for path in out_dir.glob(pattern):
            path.unlink(missing_ok=True)


def _clear_modern_output_dir(out_dir: Path) -> None:
    for pattern in (
        "*.json",
        "*.png",
        "*.ogg",
        "*.section.bin",
        "*.manifest.json",
        "*.decompiled.json",
        "property.txt",
        "decoded.bin",
        "asset_bundle.json",
        "oracle_restore.json",
    ):
        for path in out_dir.glob(pattern):
            path.unlink(missing_ok=True)


def dump_asset_folder(result: AssetScanResult, *, debug: bool = False) -> Path:
    folder_name = _sanitize_name(_read_property_name(result.path) or result.path.stem)
    codec_format = _read_property_format(result.path)
    out_dir = result.path.with_name(folder_name)
    if out_dir.exists() and codec_format is not None:
        out_dir = result.path.with_name(f"{folder_name}_format{codec_format}")
    out_dir.mkdir(parents=True, exist_ok=True)
    _clear_modern_output_dir(out_dir)

    scan = scan_file(result.path, dump=False)
    (out_dir / "property.txt").write_text(scan.property_text, encoding="utf-8")
    if debug:
        (out_dir / "decoded.bin").write_bytes(result.decoded)

    used: dict[str, int] = {}
    bundle_assets: list[dict[str, object]] = []
    first_marker = min((region.marker_offset for region in result.assets), default=len(result.decoded))

    for region in result.assets:
        file_name = _canonical_section_filename(region, used)
        kind = _classify_region_kind(region)
        asset_path: Path | None = None
        decompiled_name: str | None = None

        if region.exact_payload is not None and region.exact_kind is not None:
            asset_path = out_dir / file_name
            asset_path.write_bytes(region.exact_payload)
        elif kind == "compiled_model":
            public_name = file_name.replace(".model.section.bin", ".json").replace(".section.bin", ".json")
            asset_path = out_dir / public_name
            public_model = build_model_public_json(
                asset_name=region.asset.display_name,
                names=region.name_like_strings,
            )
            asset_path.write_text(json.dumps(public_model, indent=2), encoding="utf-8")
            if debug:
                debug_stub = build_model_decompile_stub(
                    asset_name=region.asset.display_name,
                    section_sha256=hashlib.sha256(region.raw_section).hexdigest(),
                    names=region.name_like_strings,
                )
                decompiled_name = _canonical_model_stub_name(file_name)
                (out_dir / decompiled_name).write_text(json.dumps(debug_stub, indent=2), encoding="utf-8")
        elif kind == "compiled_animation":
            if file_name.endswith(".animation.section.bin"):
                public_name = file_name[:-len(".animation.section.bin")] + ".animation.json"
            else:
                public_name = file_name.replace(".section.bin", ".json")
            asset_path = out_dir / public_name
            public_anim = build_animation_public_json(region.animation_headers)
            asset_path.write_text(json.dumps(public_anim, indent=2), encoding="utf-8")
            if debug:
                debug_stub = build_animation_decompile_stub(
                    asset_name=region.asset.display_name,
                    section_sha256=hashlib.sha256(region.raw_section).hexdigest(),
                    names=region.name_like_strings,
                    animation_headers=region.animation_headers,
                )
                decompiled_name = _canonical_animation_stub_name(file_name)
                (out_dir / decompiled_name).write_text(json.dumps(debug_stub, indent=2), encoding="utf-8")
        elif debug:
            asset_path = out_dir / file_name
            asset_path.write_bytes(region.raw_section)

        if asset_path is None:
            continue

        manifest = {
            "source_file": str(result.path),
            "asset_ordinal": region.asset.ordinal,
            "asset_tag": region.asset.tag,
            "asset_label": region.asset.label,
            "asset_display_name": region.asset.display_name,
            "asset_hash": region.asset.hash_hex,
            "region_kind": _classify_region_kind(region),
            "marker_offset": region.marker_offset,
            "region_end": region.region_end,
            "region_len": region.region_len,
            "exact_kind": region.exact_kind,
            "exact_payload_offset": region.exact_payload_offset,
            "exact_payload_len": region.exact_payload_len,
            "exact_payload_sha256": region.exact_payload_sha256,
            "exact_hash_match": region.exact_hash_match,
            "nearby_strings": list(region.nearby_strings),
            "name_like_strings": list(region.name_like_strings),
            "animation_headers": list(region.animation_headers),
            "export_file": asset_path.name,
        }
        manifest_name: str | None = None
        if debug:
            manifest_name = f"{asset_path.name}.manifest.json"
            (out_dir / manifest_name).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        bundle_assets.append(
            {
                "asset_ordinal": region.asset.ordinal,
                "asset_display_name": region.asset.display_name,
                "asset_hash": region.asset.hash_hex,
                "region_kind": _classify_region_kind(region),
                "export_file": asset_path.name,
                "manifest_file": manifest_name,
                "exact_kind": region.exact_kind,
                "decompiled_file": decompiled_name,
            }
        )

    bundle_manifest = {
        "source_file": str(result.path),
        "decoded_len": len(result.decoded),
        "prefix_before_first_marker_hex": result.decoded[:first_marker].hex(),
        "asset_count": len(bundle_assets),
        "assets": bundle_assets,
    }
    if debug:
        (out_dir / "asset_bundle.json").write_text(json.dumps(bundle_manifest, indent=2), encoding="utf-8")
    if not debug:
        _prune_modern_debug_outputs(out_dir)
    return out_dir


def _print_result(result: AssetScanResult, dump: bool) -> None:
    print(f"file: {result.path}")
    print(f"decoded_len: 0x{len(result.decoded):x}")
    print(f"property_hash_sections: {len(result.assets)}")
    dumped: set[Path] = set()
    if dump:
        dumped = set(dump_asset_regions(result))
    for region in result.assets:
        label = region.asset.display_name
        print(
            f"asset[{region.asset.ordinal}]: name={label!r} hash={region.asset.hash_hex} "
            f"marker=0x{region.marker_offset:x} region_len=0x{region.region_len:x}"
        )
        if region.exact_kind is None:
            print("  exact_payload: none")
        else:
            print(
                f"  exact_payload: kind={region.exact_kind} off=0x{region.exact_payload_offset:x} "
                f"len=0x{region.exact_payload_len:x} sha256_match={region.exact_hash_match}"
            )
        if region.nearby_strings:
            print("  strings: " + " | ".join(region.nearby_strings[:6]))
        if region.name_like_strings:
            preview = ", ".join(region.name_like_strings[:12])
            print(f"  names: {preview}")
        if region.animation_headers:
            for header in region.animation_headers[:8]:
                sec = header["seconds_guess"]
                sec_text = f"{sec:.5f}" if isinstance(sec, float) else "None"
                print(
                    "  anim: "
                    f"{header['name']} ticks={header['ticks_f32']!r} seconds={sec_text} "
                    f"loop_code={header['loop_code']} loop_guess={header['loop_mode_guess']}"
                )
        if dump:
            bundle_path = result.path.with_name(f"{result.path.with_suffix('').name}.asset_bundle.json")
            raw_path = result.path.with_name(
                f"{result.path.with_suffix('').name}.{region.asset.ordinal:02d}.{_sanitize_name(label)}.section.bin"
            )
            manifest_path = result.path.with_name(
                f"{result.path.with_suffix('').name}.{region.asset.ordinal:02d}.{_sanitize_name(label)}.manifest.json"
            )
            if region.asset.ordinal == 0:
                print(f"bundle_manifest: {bundle_path}")
            print(f"  dump_section: {raw_path}")
            print(f"  dump_manifest: {manifest_path}")
            if region.exact_payload is not None and region.exact_kind is not None:
                exact_ext = "png" if region.exact_kind == "png" else "json"
                exact_path = result.path.with_name(
                    f"{result.path.with_suffix('').name}.{region.asset.ordinal:02d}.{_sanitize_name(label)}.{exact_ext}"
                )
                print(f"  dump_exact: {exact_path}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Scan decompressed BOM v3 payload for property-hash-backed asset sections")
    ap.add_argument("paths", nargs="+", type=Path)
    ap.add_argument("--dump", action="store_true", help="dump raw hash-bounded sections and exact PNG/JSON payloads")
    ap.add_argument("--dump-folder", action="store_true", help="export into a model-named folder with canonical filenames")
    args = ap.parse_args()

    for path in args.paths:
        result = scan_bom_v3_payload_assets(path)
        _print_result(result, dump=args.dump)
        if args.dump_folder:
            out_dir = dump_asset_folder(result)
            print(f"dump_folder: {out_dir}")


if __name__ == "__main__":
    main()
