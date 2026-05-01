from __future__ import annotations

import argparse
import binascii
import copy
import hashlib
import itertools
import json
import math
import re
import struct
from collections import Counter
import zlib
from dataclasses import dataclass
from pathlib import Path

try:
    from PIL import Image
except Exception:  # pragma: no cover - optional dependency
    Image = None

from bom_v3_end_to_end_parser import decode_bom_v3
from bom_v3_payload_assets import (
    _canonical_animation_stub_name,
    _canonical_model_stub_name,
    _parse_animation_headers,
    _read_property_name,
    _read_property_format,
    _sanitize_name,
    build_animation_decompile_stub,
    build_model_decompile_stub,
    parse_property_assets,
)
from extractors.legacy_asset_inventory import canonical_legacy_export_name, legacy_asset_category
from ysgp_container_scanner import scan_file


HEX_HASH_RE = re.compile(rb"[0-9a-f]{64}")
SECTION_TAGS = (b"\x09\x00\x00\x00", b"\x0f\x00\x00\x00", b"\x1f\x00\x00\x00")
ANIM_HINTS = (
    b"query.",
    b"ysm.head_",
    b"swing_hand",
    b"reload",
    b"elytra_fly",
    b"carryon",
    b"attack",
    b"walk",
    b"idle",
    b"extra",
)
MODEL_HINTS = (
    b"geometry.unknown",
    b"MRoot",
    b"Root",
    b"AllBody",
    b"LeftArm",
    b"RightArm",
    b"LeftForeArm",
    b"RightForeArm",
    b"Head",
    b"bow",
)
LEGACY_SIGNATURES: dict[str, tuple[str, ...]] = {
    "main_animation": ("gui", "idle", "jump", "boat", "parallel0", "parallel1", "sneaking", "swim", "climb", "climbing"),
    "extra_animation": ("extra0", "extra1", "extra2", "extra3", "extra4", "extra5", "extra6", "extra7"),
    "tac_animation": ("tac", "reload", "rpg", "pistol", "ak47", "g17", "rifle", "bowL1", "bowR1", "aim"),
    "carryon_animation": ("carryon", "swing_hand", "use_mainhand", "use_offhand"),
    "arrow_animation": ("Board", "Board2", "Bowknot", "Brand", "LeftPl", "RightPl", "UpPl", "DownPl", "ARROW"),
}

LEGACY_KNOWN_ANIMATION_CLIPS: dict[str, tuple[str, ...]] = {
    "main_animation": (
        "gui", "idle", "walk", "run", "death", "jump", "fly", "elytra_fly", "attacked",
        "sneak", "sneaking", "swim", "swim_stand", "sit", "ride", "ride_pig", "sleep",
        "boat", "climb", "climbing", "use_mainhand", "use_offhand", "swing_hand",
        "pre_parallel0", "pre_parallel1", "pre_parallel2", "pre_parallel3", "pre_parallel4",
        "pre_parallel5", "pre_parallel6", "pre_parallel7", "parallel0", "parallel1", "parallel3",
        "parallel4", "parallel5", "parallel6", "parallel7", "head:default",
        "vehicle$man_of_many_planes:scarlet_biplane",
    ),
    "extra_animation": tuple(f"extra{i}" for i in range(8)),
    "carryon_animation": ("carryon:block", "carryon:entity", "carryon:player", "carryon:princess"),
    "arrow_animation": ("parallel0",),
    "tac_animation": (
        "tac:idle", "tac:walk", "tac:run", "tac:sneaking",
        "tac:hold:rifle", "tac:hold:fire:rifle", "tac:aim:rifle", "tac:aim:fire:rifle",
        "tac:reload:rifle", "tac:run:rifle", "tac:climb:rifle", "tac:climbing:rifle", "tac:climbing:fire:rifle",
        "tac:hold:pistol", "tac:aim:pistol", "tac:reload:pistol", "tac:run:pistol", "tac:climb:pistol",
        "tac:climbing:pistol", "tac:hold:fire:pistol", "tac:aim:fire:pistol", "tac:climbing:fire:pistol",
        "tac:hold:rpg", "tac:aim:rpg", "tac:reload:rpg", "tac:run:rpg", "tac:climb:rpg",
        "tac:climbing:rpg", "tac:hold:fire:rpg", "tac:aim:fire:rpg", "tac:climbing:fire:rpg",
        "tac:mainhand:grenade", "tac:offhand:grenade",
    ),
}

_FORMAT9_MAIN_MODEL_EXCLUDE_NAMES = {
    "Board",
    "Board2",
    "Bowknot",
    "Bowknot2",
    "Bowknot3",
    "Bowknot4",
    "Bowknot5",
    "Brand",
    "DownPl",
    "LeftPl",
    "Other",
    "RightPl",
    "Sakura",
    "UpPl",
    "attacked",
    "boat",
    "climb",
    "climbing",
    "death",
    "geometry.unknown",
    "ysm.head_yaw",
}

_FORMAT9_ARM_MODEL_KEEP_NAMES = {
    "Arm",
    "LeftArm",
    "LeftForeArm",
    "LeftHand",
    "LeftHandLocator",
    "RightArm",
    "RightForeArm",
    "RightHand",
    "RightHandLocator",
}

_FORMAT9_ARROW_MODEL_EXCLUDE_NAMES = {
    "AllBody",
    "AllBody2",
    "AllHead",
    "AllHead2",
    "Head",
    "Head2",
    "UpBody",
    "UpperBody",
    "LeftArm",
    "LeftFoot",
    "LeftForeArm",
    "LeftLeg",
    "LeftLowerLeg",
    "RightArm",
    "RightFoot",
    "RightForeArm",
    "RightLeg",
    "RightLowerLeg",
    "LongHair",
    "LongHair2",
    "LongLeftHair",
    "LongRightHair",
    "MAllbody",
    "MAllBody",
    "MHead",
    "MLongHair",
    "MTail",
    "Tail",
    "Tail2",
    "Tail3",
    "Tail4",
    "elytra_fly",
    "fly",
    "weixiao",
}

_FORMAT9_ARROW_MODEL_KEEP_NAMES = {
    "Root",
    "UpPl",
    "DownPl",
    "LeftPl",
    "RightPl",
    "Other",
    "Bowknot",
    "Bowknot2",
    "Bowknot3",
    "Bowknot4",
    "Bowknot5",
    "Board",
    "Board2",
    "Brand",
    "Sakura",
}

_FORMAT9_CONTAINER_BONE_NAMES = {
    "AllBody",
    "Arm",
    "DownBody",
    "Ear",
    "EyeBrow",
    "Eyelid",
    "Eyes",
    "Leg",
    "Mouth",
    "gui",
}

_FORMAT15_TORSO_CONTAINER_ANCHORS = {
    "Body",
    "UpperBody",
    "UpperBody2",
    "UpBody",
    "AllBody",
    "DownBody",
}

_PLAUSIBLE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{1,31}$")


def _canonical_legacy_json_name(asset_name: str, kind: str) -> str | None:
    if legacy_asset_category(asset_name)[0] != kind:
        return None
    return canonical_legacy_export_name(asset_name, "")


@dataclass(frozen=True)
class LegacySection:
    start: int
    end: int
    size: int
    tag: int
    kind_guess: str
    names: tuple[str, ...]
    asset_guess: str | None
    assignment_method: str | None
    sha256: str


@dataclass(frozen=True)
class LegacyDirectoryEntry:
    offset: int
    control: tuple[int, ...]
    name: str
    hash_hex: str
    property_match: str | None


@dataclass(frozen=True)
class LegacyScanResult:
    path: Path
    codec_format: int | None
    decoded_len: int
    tail_start: int
    directory_start: int
    directory_prefix: str
    directory_entries: tuple[LegacyDirectoryEntry, ...]
    expected_assets: tuple[str, ...]
    sections: tuple[LegacySection, ...]


@dataclass(frozen=True)
class LegacyTextureExport:
    asset_name: str
    label: str
    width: int
    height: int
    offset: int
    raw_len: int
    png_file: str
    sha256: str


@dataclass(frozen=True)
class LegacyModelBoneInfo:
    name: str
    parent: str | None
    pivot: tuple[float, float, float] | None
    cube_count_guess: int | None = None
    wrapper_name: str | None = None
    uv_norm_hints: tuple[float, ...] = ()


@dataclass(frozen=True)
class LegacyTypedPayloadCandidate:
    source: str
    anchor_name: str
    payload_name: str
    count: int
    kind: int
    payload: bytes


_LEGACY_BONE_NAME_HINTS = (
    "Root",
    "Body",
    "Head",
    "Hair",
    "Arm",
    "Leg",
    "Hand",
    "Foot",
    "Eye",
    "Brow",
    "Ear",
    "Tail",
    "Wing",
    "Ribbon",
    "Skirt",
    "Sleeve",
    "Clothes",
)

_LEGACY_WRAPPER_NAME_RE = re.compile(r"^(?:M[0-9]+|[A-Z][A-Za-z0-9_-]*M[0-9]?)$")
_LEGACY_SEGMENTED_WRAPPER_ALLOW_BONES = {
    "UpperBody",
    "UpBody",
    "Bangs",
    "LeftSideHair",
    "RightSideHair",
    "BaseHair",
}
_LEGACY_SEGMENTED_WRAPPER_DENY_BONES = {
    "Hair",
    "Ear",
    "Mouth",
    "gui",
    *_FORMAT9_CONTAINER_BONE_NAMES,
}
_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS = {
    "Mask": 55,
    "Left_ear": 11,
    "Right_ear": 11,
    "LongHair": 3,
    "LongHair2": 3,
    "LongLeftHair": 3,
    "LongLeftHair2": 3,
    "LongRightHair": 3,
    "LongRightHair2": 3,
    "LeftLeg": 2,
    "RightLeg": 2,
    "LeftLowerLeg": 2,
    "RightLowerLeg": 2,
    "LeftFoot": 6,
    "RightFoot": 6,
    "BaseHair": 30,
    "bone5": 11,
    "kongju": 8,
    "jingya": 17,
    "xiao": 2,
    "weixiao": 3,
    "LeftArm": 3,
    "RightArm": 3,
    "LeftForeArm": 14,
    "RightForeArm": 14,
    "LeftHand": 1,
    "RightHand": 1,
    "bone36": 8,
    "bone37": 8,
    "Tail": 1,
    "Tail2": 5,
    "Tail3": 7,
    "FM": 1,
    "FM1": 1,
    "FM2": 1,
    "RightEyelid": 1,
    "RightEyelidBase": 1,
    "RightEyeDot": 1,
}
_LEGACY_ARM_MODEL_TARGET_COUNTS = {
    "Arm": 0,
    "LeftArm": 3,
    "LeftForeArm": 9,
    "LeftHand": 1,
    "LeftHandLocator": 0,
    "RightArm": 3,
    "RightForeArm": 9,
    "RightHand": 1,
    "RightHandLocator": 0,
}
_LEGACY_ARROW_MODEL_TARGET_COUNTS = {
    "Root": 3,
    "UpPl": 3,
    "DownPl": 3,
    "LeftPl": 3,
    "RightPl": 3,
    "Other": 1,
    "Bowknot": 6,
    "Bowknot2": 6,
    "Bowknot3": 1,
    "Bowknot4": 4,
    "Bowknot5": 4,
    "Board": 1,
    "Board2": 11,
    "Brand": 3,
    "Sakura": 1,
}
_LEGACY_CHILD_ALLOCATION_PARENT_RULES = {
    "Head": "MHead",
    "MHead": "AllHead",
    "Mask": "Head",
    "Ear": "Head",
    "Eyes": "Head",
    "Left_ear": "Ear",
    "Right_ear": "Ear",
    "LeftLeg": "DownBody",
    "RightLeg": "DownBody",
    "LeftLowerLeg": "LeftLeg",
    "RightLowerLeg": "RightLeg",
    "LeftFoot": "LeftLowerLeg",
    "RightFoot": "RightLowerLeg",
    "Tail": "MTail",
    "Tail2": "Tail",
    "Tail3": "Tail2",
    "Body": "UpperBody2",
    "BaseHair": "Hair",
    "bone5": "BaseHair",
    "LongHair": "MLongHair",
    "LongHair2": "LongHair",
    "LongLeftHair": "MLongLeftHair",
    "LongLeftHair2": "LongLeftHair",
    "LongRightHair": "MLongRightHair",
    "LongRightHair2": "LongRightHair",
    "kongju": "Mouth",
    "jingya": "Mouth",
    "xiao": "Mouth",
    "weixiao": "Mouth",
    "LeftArm": "Arm",
    "RightArm": "Arm",
    "LeftForeArm": "LeftArm",
    "RightForeArm": "RightArm",
    "LeftHand": "LeftForeArm",
    "RightHand": "RightForeArm",
    "bone36": "LeftFoot",
    "bone37": "RightFoot",
    "FM": "FrontClothe",
    "FM1": "FM",
    "FM2": "FM1",
    "RightEyelidBase": "RightEyelid",
    "RightEyeDot": "RightEyelidBase",
}
_FORMAT1_ALLOWED_EXPORT_FILES = {
    "main.json",
    "arm.json",
    "main.animation.json",
    "arm.animation.json",
    "extra.animation.json",
    "tac.animation.json",
    "carryon.animation.json",
    "texture.png",
}


def _extract_ogg_stream(decoded: bytes, absolute_offset: int) -> bytes | None:
    if absolute_offset < 0 or absolute_offset + 27 > len(decoded):
        return None
    if decoded[absolute_offset:absolute_offset + 4] != b"OggS":
        return None
    pos = absolute_offset
    end = None
    while pos + 27 <= len(decoded) and decoded[pos:pos + 4] == b"OggS":
        page_segments = decoded[pos + 26]
        segtable_end = pos + 27 + page_segments
        if segtable_end > len(decoded):
            break
        body_len = sum(decoded[pos + 27:segtable_end])
        page_end = segtable_end + body_len
        if page_end > len(decoded):
            break
        end = page_end
        header_type = decoded[pos + 5]
        pos = page_end
        if header_type & 0x04:
            return decoded[absolute_offset:end]
    if end is None:
        return None
    return decoded[absolute_offset:end]


def _entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    counts = [0] * 256
    for b in buf:
        counts[b] += 1
    total = len(buf)
    ent = 0.0
    for c in counts:
        if c:
            p = c / total
            ent -= p * math.log2(p)
    return ent


def _ascii_ratio(buf: bytes) -> float:
    if not buf:
        return 0.0
    printable = sum(1 for b in buf if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(buf)


def _extract_names(buf: bytes, limit: int = 16) -> tuple[str, ...]:
    names: list[str] = []
    seen: set[str] = set()
    for m in re.finditer(rb"[A-Za-z_][A-Za-z0-9_.-]{2,}", buf):
        s = m.group().decode("ascii", "replace")
        if all(ch in "0123456789abcdef" for ch in s.lower()):
            continue
        if s in seen:
            continue
        seen.add(s)
        names.append(s)
        if len(names) >= limit:
            break
    return tuple(names)


def _classify_section(buf: bytes, names: tuple[str, ...]) -> str:
    anim_headers = _parse_animation_headers(buf)
    if anim_headers:
        first_off = int(anim_headers[0]["offset"])
        strong_model_names = {"MRoot", "Root", "AllBody", "LeftArm", "RightArm", "Head", "UpperBody"}
        strong_model_count = sum(1 for name in names if name in strong_model_names)
        if first_off < min(0x10000, max(0x400, len(buf) // 3)):
            if len(anim_headers) >= 3:
                return "animation"
            if len(anim_headers) >= 2 and strong_model_count < 3:
                return "animation"
    ogg_off = buf.find(b"OggS")
    if ogg_off >= 0:
        return "audio"
    anim_score = sum(1 for hint in ANIM_HINTS if hint in buf)
    model_score = sum(1 for hint in MODEL_HINTS if hint in buf)
    if anim_score >= 4 and anim_score >= model_score - 1:
        return "animation"
    strong_model_names = {"MRoot", "Root", "AllBody", "LeftArm", "RightArm", "Head", "UpperBody"}
    if sum(1 for name in names if name in strong_model_names) >= 3:
        return "model"
    if model_score >= max(3, anim_score + 2):
        return "model"
    if anim_score >= max(2, model_score):
        return "animation"
    if _ascii_ratio(buf[: min(len(buf), 0x2000)]) < 0.15 and _entropy(buf[: min(len(buf), 0x8000)]) > 7.2:
        return "texture_or_binary"
    if any(name in names for name in ("Root", "AllBody", "LeftArm", "RightArm")):
        return "model"
    return "unknown"


def _property_kind(tag: str) -> str:
    category = legacy_asset_category(tag)[0]
    if category == "sound":
        return "audio"
    if category == "animation":
        return "animation"
    if category == "model":
        return "model"
    if category == "texture":
        return "texture_or_binary"
    return "unknown"


def _expected_legacy_assets(path: Path, codec_format: int | None) -> tuple[str, ...]:
    assets = parse_property_assets(scan_file(path, dump=False).property_text)
    expected: list[str] = []
    seen: set[str] = set()

    def add(name: str) -> None:
        if name not in seen:
            seen.add(name)
            expected.append(name)

    for asset in assets:
        add(asset.display_name)

    # Keep format-1 schema parity explicit even when the section resolver cannot
    # recover a dedicated compiled animation block for every advertised asset.
    if codec_format == 1:
        for name in (
            "main_model",
            "arm_model",
            "main_animation",
            "arm_animation",
            "extra_animation",
            "tac_animation",
            "carryon_animation",
        ):
            add(name)
    return tuple(expected)


def _expected_legacy_assets_by_kind(
    path: Path,
    codec_format: int | None,
    directory_entries: tuple[LegacyDirectoryEntry, ...],
) -> dict[str, list[str]]:
    expected = _expected_legacy_assets(path, codec_format)
    by_kind: dict[str, list[str]] = {}
    seen: set[str] = set()

    def add(name: str) -> None:
        if name in seen:
            return
        seen.add(name)
        by_kind.setdefault(_property_kind(name), []).append(name)

    for entry in directory_entries:
        if entry.property_match is not None and entry.property_match in expected:
            add(entry.property_match)
    for name in expected:
        add(name)
    return by_kind


def _legacy_signature_scores(buf: bytes) -> dict[str, int]:
    return {
        asset_name: sum(1 for tok in tokens if tok.encode("ascii") in buf)
        for asset_name, tokens in LEGACY_SIGNATURES.items()
    }


def _format15_model_names(section: bytes) -> tuple[str, ...]:
    names: list[str] = list(dict.fromkeys(_extract_names(section, limit=512)))
    seen = set(names)
    for _off, name in _iter_len_prefixed_names(section):
        if len(name) < 2:
            continue
        if not any(ch.isalpha() for ch in name):
            continue
        if name in seen:
            continue
        names.append(name)
        seen.add(name)
    return tuple(names)


def _legacy_name_family_key(name: str) -> str:
    m = re.fullmatch(r"([A-Za-z_]+?)(\d+)?(?:_(\d+))?", name)
    return m.group(1) if m is not None else name


def _augment_legacy_animation_stub(asset_name: str, stub: dict[str, object]) -> dict[str, object]:
    animations = stub.get("animations")
    if not isinstance(animations, dict):
        return stub
    known = LEGACY_KNOWN_ANIMATION_CLIPS.get(asset_name)
    if not known:
        return stub
    existing_names = set(str(k) for k in animations)
    bone_map: dict[str, object] = {}
    for entry in animations.values():
        if isinstance(entry, dict):
            bones = entry.get("bones")
            if isinstance(bones, dict) and len(bones) > len(bone_map):
                bone_map = {str(k): v for k, v in bones.items()}
    def _default_entry(name: str) -> dict[str, object]:
        entry: dict[str, object] = {"bones": dict(bone_map)}
        if asset_name == "main_animation":
            if name == "death":
                entry["loop"] = "hold_on_last_frame"
            elif name not in {"jump", "attacked", "sleep", "sit"}:
                entry["loop"] = True
        return entry
    overlap = len(existing_names & set(known))
    if asset_name in {"extra_animation", "carryon_animation", "arrow_animation", "tac_animation"} and overlap == 0:
        stub["animations"] = {name: _default_entry(name) for name in known}
        return stub
    for name in known:
        animations.setdefault(name, _default_entry(name))
    return stub


def _filter_format15_main_model_entries(entries: list[dict[str, object]]) -> list[dict[str, object]]:
    by_name = {entry["name"]: entry for entry in entries if isinstance(entry.get("name"), str)}
    family_counts = Counter(_legacy_name_family_key(name) for name in by_name)
    referenced_parents = {
        str(entry.get("parent"))
        for entry in entries
        if isinstance(entry.get("parent"), str)
    }
    arrow_names = {
        "UpPl", "DownPl", "LeftPl", "RightPl", "Other",
        "Bowknot", "Bowknot2", "Bowknot3", "Bowknot4", "Bowknot5",
        "Board", "Board2", "Brand", "Sakura",
    }
    noise_names = {"M", "geometry.unknown", "LeftWaistLocator2", "SheathLocator2", "attacked", "boat", "climb", "climbing", "elytra_fly", "fly"}
    core_tokens = ("Root", "Body", "Head", "Hair", "Arm", "Leg", "Hand", "Foot", "Eye", "Brow", "Ear", "Tail", "Wing", "Ribbon", "Skirt", "Sleeve", "Clothe", "Mask", "Waist", "Locator", "bow", "gui", "FOX", "Mouth")
    family_re = re.compile(r"(?:[A-Z]{2,3}\d{0,2}|FFM\d(?:_\d)?|[LR][BFM]\d{0,2}|[FB][LRM]\d{0,2}|LM\d{0,2}|RM\d{0,2}|FM\d{0,2})$")
    def _pivot_ok(entry: dict[str, object]) -> bool:
        pivot = entry.get("pivot")
        return isinstance(pivot, list) and len(pivot) == 3
    def _ensure_parent(name: str) -> None:
        entry = by_name.get(name)
        if entry is None or entry.get("parent") is not None:
            return
        parent = None
        m = re.fullmatch(r"([A-Z]{2,3})(\d+)$", name)
        if m is not None:
            prefix, idx = m.groups()
            idx_i = int(idx)
            if idx_i >= 2 and f"{prefix}{idx_i - 1}" in by_name:
                parent = f"{prefix}{idx_i - 1}"
        m = re.fullmatch(r"(FFM\d)_(\d+)$", name)
        if m is not None:
            parent = m.group(1)
        if name in {"BL", "BM", "BR"}:
            parent = "BackClothe"
        elif name in {"LB", "LM", "LF"}:
            parent = "LeftClothe"
        elif name in {"RB", "RM", "RF"}:
            parent = "RightClothe"
        elif name in {"FL", "FR", "FFM", "FFM1", "FFM2", "FFM3"}:
            parent = "FrontClothe"
        elif name in {"Left_ear", "Right_ear"}:
            parent = "Ear"
        elif name == "Mask":
            parent = "Head"
        elif name == "weixiao":
            parent = "Mouth"
        if parent is not None and parent in by_name:
            entry["parent"] = parent
    for name in list(by_name):
        _ensure_parent(name)
    filtered: list[dict[str, object]] = []
    for entry in entries:
        name = entry.get("name")
        if not isinstance(name, str):
            continue
        if name in noise_names or name in arrow_names:
            continue
        if name.startswith(("ysm.", "query.", "math.")):
            continue
        keep = False
        if entry.get("__compiled_wrapper_name") is not None or entry.get("__compiled_cube_count_guess") is not None or entry.get("parent") is not None:
            keep = True
        if _pivot_ok(entry) and (
            any(tok in name for tok in core_tokens)
            or "_" in name
            or any(ch.islower() for ch in name)
            or family_counts[_legacy_name_family_key(name)] >= 2
            or family_re.fullmatch(name) is not None
        ):
            keep = True
        if name in referenced_parents:
            keep = True
        if keep:
            filtered.append(entry)
    return filtered



def _build_legacy_animation_signature_stub(
    asset_name: str, section_sha256: str, names: tuple[str, ...], signature_scores: dict[str, int]
) -> dict[str, object]:
    token_names = list(LEGACY_SIGNATURES.get(asset_name, ()))
    guessed_bones: list[str] = []
    seen: set[str] = set()
    token_set = set(token_names)
    for name in names:
        if name in token_set:
            continue
        if name in seen:
            continue
        seen.add(name)
        guessed_bones.append(name)
        if len(guessed_bones) >= 24:
            break
    public_bones = {name: {} for name in guessed_bones}
    animations = {
        clip_name: {
            "__recovered_from": "legacy_signature_tokens",
            "__bone_names_guess": guessed_bones,
            "bones": {name: {} for name in guessed_bones},
        }
        for clip_name in token_names
    }
    return {
        "format_version": "1.8.0",
        "__compiled_decompile": {
            "status": "signature_only",
            "asset_name": asset_name,
            "section_sha256": section_sha256,
            "clip_count_guess": len(token_names),
            "bone_name_count_guess": len(guessed_bones),
            "signature_score": int(signature_scores.get(asset_name, 0)),
            "notes": [
                "Recovered from compiled legacy YSM animation section.",
                "Clip names are inferred from embedded signature tokens.",
                "Durations, loop modes, and keyframe channels are not reconstructed yet.",
                "Bone lists are guessed from embedded strings.",
            ],
        },
        "animations": animations,
    }


def _build_unresolved_legacy_animation_stub(asset_name: str) -> dict[str, object]:
    return {
        "format_version": "1.8.0",
        "__compiled_decompile": {
            "status": "unresolved_expected_asset",
            "asset_name": asset_name,
            "notes": [
                "Expected by legacy property/schema inventory.",
                "No deterministic compiled section match was recovered yet.",
                "This placeholder preserves canonical legacy output shape only.",
            ],
        },
        "animations": {},
    }


def _enforce_format1_output_shape(out_dir: Path, manifest: dict[str, object]) -> None:
    removed: list[str] = []

    def remove_file(path: Path) -> None:
        if not path.exists():
            return
        path.unlink(missing_ok=True)
        removed.append(path.name)

    for stale_name in ("arrow.json", "arrow.animation.json", "arrow.png", "texture.2.png"):
        remove_file(out_dir / stale_name)
    for sound_path in sorted(path for path in out_dir.glob("*.ogg") if path.is_file()):
        remove_file(sound_path)

    pngs = sorted(path for path in out_dir.glob("*.png") if path.is_file())
    keep_png = None
    if pngs:
        keep_png = next((path for path in pngs if path.name == "texture.png"), pngs[0])
        for path in pngs:
            if path != keep_png:
                remove_file(path)

    present = {
        path.name
        for path in out_dir.iterdir()
        if path.is_file() and path.name in _FORMAT1_ALLOWED_EXPORT_FILES
    }
    if keep_png is None:
        present.discard("texture.png")
    manifest["format1_shape_enforced"] = True
    manifest["format1_shape_expected_exports"] = sorted(_FORMAT1_ALLOWED_EXPORT_FILES)
    manifest["format1_shape_present_exports"] = sorted(present)
    manifest["format1_shape_removed_files"] = removed


def _strip_private_fields(value: object) -> object:
    if isinstance(value, dict):
        out: dict[str, object] = {}
        for key, item in value.items():
            if isinstance(key, str) and key.startswith("__"):
                continue
            out[key] = _strip_private_fields(item)
        return out
    if isinstance(value, list):
        return [_strip_private_fields(item) for item in value]
    return value


def _summarize_legacy_model_stub(stub: dict[str, object]) -> dict[str, int | str]:
    semantics = stub.get("__compiled_semantics")
    typed_hits = 0
    fallback_hits = 0
    segmented_hits = 0
    child_allocated_hits = 0
    repaired_parent_bones = 0
    head_child_allocations = 0
    mask_child_allocated_bone_hits = 0
    head_structural_repairs = 0
    ear_child_allocations = 0
    foot_child_allocations = 0
    leg_child_allocations = 0
    tail_child_allocations = 0
    body_child_allocations = 0
    hair_child_allocations = 0
    mouth_child_allocations = 0
    arm_child_allocations = 0
    fanout_rejections = 0
    container_rejections = 0
    if isinstance(semantics, dict):
        typed_hits = int(semantics.get("typed_bone_hits", 0) or 0)
        fallback_hits = int(semantics.get("fallback_bone_hits", 0) or 0)
        segmented_hits = int(semantics.get("segmented_record_bone_hits", 0) or 0)
        child_allocated_hits = int(semantics.get("child_allocated_bone_hits", 0) or 0)
        repaired_parent_bones = int(semantics.get("repaired_parent_bones", 0) or 0)
        head_child_allocations = int(semantics.get("head_child_allocations", 0) or 0)
        mask_child_allocated_bone_hits = int(semantics.get("mask_child_allocated_bone_hits", 0) or 0)
        head_structural_repairs = int(semantics.get("head_structural_repairs", 0) or 0)
        ear_child_allocations = int(semantics.get("ear_child_allocations", 0) or 0)
        foot_child_allocations = int(semantics.get("foot_child_allocations", 0) or 0)
        leg_child_allocations = int(semantics.get("leg_child_allocations", 0) or 0)
        tail_child_allocations = int(semantics.get("tail_child_allocations", 0) or 0)
        body_child_allocations = int(semantics.get("body_child_allocations", 0) or 0)
        hair_child_allocations = int(semantics.get("hair_child_allocations", 0) or 0)
        mouth_child_allocations = int(semantics.get("mouth_child_allocations", 0) or 0)
        arm_child_allocations = int(semantics.get("arm_child_allocations", 0) or 0)
        fanout_rejections = int(semantics.get("fanout_group_rejections", 0) or 0)
        container_rejections = int(semantics.get("container_parent_rejections", 0) or 0)
    return {
        "typed_bone_hits": typed_hits,
        "fallback_bone_hits": fallback_hits,
        "segmented_record_bone_hits": segmented_hits,
        "child_allocated_bone_hits": child_allocated_hits,
        "repaired_parent_bones": repaired_parent_bones,
        "head_child_allocations": head_child_allocations,
        "mask_child_allocated_bone_hits": mask_child_allocated_bone_hits,
        "head_structural_repairs": head_structural_repairs,
        "ear_child_allocations": ear_child_allocations,
        "foot_child_allocations": foot_child_allocations,
        "leg_child_allocations": leg_child_allocations,
        "tail_child_allocations": tail_child_allocations,
        "body_child_allocations": body_child_allocations,
        "hair_child_allocations": hair_child_allocations,
        "mouth_child_allocations": mouth_child_allocations,
        "arm_child_allocations": arm_child_allocations,
        "fanout_group_rejections": fanout_rejections,
        "container_parent_rejections": container_rejections,
        "semantic_stage": (
            "typed_segmented_child_allocated_head_mask_detail_model_candidates"
            if ear_child_allocations > 0 or foot_child_allocations > 0
            else "typed_segmented_child_allocated_head_mask_model_candidates"
            if head_child_allocations > 0
            else "typed_segmented_child_allocated_model_candidates"
            if child_allocated_hits > 0
            else "typed_segmented_model_candidates"
            if segmented_hits > 0
            else "typed_model_candidates" if typed_hits > 0 else "fallback_only"
        ),
    }


def _plausible_legacy_name(text: str) -> bool:
    return _PLAUSIBLE_NAME_RE.fullmatch(text) is not None


def _iter_len_prefixed_names(section: bytes) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for off in range(len(section) - 2):
        n = section[off]
        end = off + 1 + n
        if not (1 <= n <= 32 and end < len(section)):
            continue
        if section[end] != 0:
            continue
        try:
            text = section[off + 1:end].decode("ascii")
        except UnicodeDecodeError:
            continue
        if _plausible_legacy_name(text):
            out.append((off, text))
    return out


def _read_legacy_pivot(section: bytes, name_off: int, name: str) -> tuple[float, float, float] | None:
    end = name_off + 1 + len(name) + 1
    best: tuple[float, float, float] | None = None
    best_score = -1.0
    for shift in (4, 0, 8, 12):
        if end + shift + 12 > len(section):
            continue
        vals = struct.unpack_from("<3f", section, end + shift)
        if not all(math.isfinite(v) and abs(v) <= 2048.0 for v in vals):
            continue
        score = 0.0
        if shift == 4:
            score += 0.4
        if any(abs(v) > 0.001 for v in vals):
            score += 0.5
        for v in vals:
            if abs(v) <= 512.0:
                score += 1.0
            if abs(v - round(v, 3)) < 1e-5:
                score += 0.15
        rounded = tuple(0.0 if abs(v) < 1e-6 else round(v, 5) for v in vals)
        if score > best_score:
            best_score = score
            best = rounded
    return best


def _find_legacy_wrapper_payload(section: bytes, visible_name: str) -> tuple[str, int, int, bytes] | None:
    wrapper_name = "M" + visible_name
    first_pat = bytes([len(wrapper_name)]) + wrapper_name.encode("ascii") + b"\x00"
    first = section.find(first_pat)
    if first < 0:
        return None

    second_pat = b"\x00" + bytes([len(wrapper_name)]) + wrapper_name.encode("ascii")
    second = section.find(second_pat, first + len(first_pat))
    if second < 0:
        second = section.find(bytes([len(wrapper_name)]) + wrapper_name.encode("ascii"), first + len(first_pat))
        if second < 0:
            return None
        payload_off = second + 1 + len(wrapper_name)
    else:
        payload_off = second + 1 + 1 + len(wrapper_name)

    if payload_off < len(section) and section[payload_off] == 0:
        payload_off += 1

    end_pat = bytes([len(visible_name)]) + visible_name.encode("ascii") + b"\x00"
    block_end = section.find(end_pat, payload_off)
    if block_end < 0:
        return None
    if payload_off + 2 > block_end:
        return None

    count = section[payload_off]
    kind = section[payload_off + 1]
    payload = section[payload_off + 2:block_end]
    return wrapper_name, count, kind, payload


def _find_legacy_visible_payload_same_name(
    section: bytes,
    visible_name: str,
) -> tuple[str, int, int, bytes] | None:
    pat = bytes([len(visible_name)]) + visible_name.encode("ascii") + b"\x00"
    pat_no_nul = bytes([len(visible_name)]) + visible_name.encode("ascii")
    start = 0
    best: tuple[str, int, int, bytes] | None = None
    best_key: tuple[int, int, int] | None = None
    max_gap = 0x4000
    while True:
        first = section.find(pat, start)
        if first < 0:
            break
        second_pat = section.find(pat, first + len(pat), min(len(section), first + max_gap))
        second_pat_no = section.find(
            pat_no_nul,
            first + len(pat),
            min(len(section), first + max_gap),
        )
        second = -1
        mode = None
        if second_pat >= 0 and (second_pat_no < 0 or second_pat <= second_pat_no):
            second = second_pat
            mode = "pat"
        elif second_pat_no >= 0:
            second = second_pat_no
            mode = "pat_no"
        if second < 0:
            start = first + 1
            continue
        if mode == "pat_no":
            payload_off = second + len(pat_no_nul)
        else:
            payload_off = second + len(pat)
        if payload_off < len(section) and section[payload_off] == 0:
            payload_off += 1
        if payload_off + 2 > len(section):
            start = first + 1
            continue
        count = section[payload_off]
        kind = section[payload_off + 1]
        block_end = -1
        search_end = min(len(section) - 2, payload_off + 0x4000)
        for off in range(payload_off + 2, search_end):
            ln = section[off]
            end = off + 1 + ln
            if not (1 <= ln <= 32 and end < len(section) and section[end] == 0):
                continue
            try:
                text = section[off + 1:end].decode("ascii")
            except UnicodeDecodeError:
                continue
            if _plausible_legacy_name(text):
                block_end = off
                break
        if block_end < 0:
            start = first + 1
            continue
        payload = section[payload_off + 2:block_end]
        if not payload:
            start = first + 1
            continue
        candidate = (visible_name, count, kind, payload)
        if kind == 6:
            key = (0, second - first, len(payload))
        elif kind in (69, 70, 72, 76, 77, 82):
            key = (1, second - first, len(payload))
        elif count > 0:
            key = (2, second - first, len(payload))
        else:
            key = (3, second - first, len(payload))
        if best_key is None or key < best_key:
            best = candidate
            best_key = key
        start = first + 1
    return best


def _find_legacy_single_visible_container_slice(
    section: bytes,
    visible_name: str,
    *,
    window: int = 0x800,
) -> bytes | None:
    pat = bytes([len(visible_name)]) + visible_name.encode("ascii") + b"\x00"
    off = section.find(pat)
    if off < 0:
        return None
    start = off + len(pat)
    if start >= len(section):
        return None
    end = min(len(section), start + window)
    return section[start:end]


def _find_legacy_best_named_payload(
    section: bytes,
    visible_name: str,
    inline_payload: bytes | None = None,
) -> tuple[str, int, int, bytes] | None:
    best: tuple[str, int, int, bytes] | None = None
    if inline_payload is not None:
        best = (visible_name, 0, 0, inline_payload)
    for candidate in (
        _find_legacy_visible_payload_same_name(section, visible_name),
        _find_legacy_wrapper_payload_by_wrapper(section, visible_name),
        _find_legacy_wrapper_payload(section, visible_name),
    ):
        if candidate is None:
            continue
        if best is None or len(candidate[3]) > len(best[3]):
            best = candidate
    return best


def _append_legacy_typed_candidate(
    out: list[LegacyTypedPayloadCandidate],
    seen: set[tuple[str, str, int, int, bytes]],
    *,
    source: str,
    anchor_name: str,
    candidate: tuple[str, int, int, bytes] | None,
) -> None:
    if candidate is None:
        return
    payload_name, count, kind, payload = candidate
    key = (source, payload_name, count, kind, payload)
    if key in seen:
        return
    seen.add(key)
    out.append(
        LegacyTypedPayloadCandidate(
            source=source,
            anchor_name=anchor_name,
            payload_name=payload_name,
            count=count,
            kind=kind,
            payload=payload,
        )
    )


def _find_legacy_parent_wrapper_named_payload(
    section: bytes,
    visible_name: str,
    parent_name: str | None,
    *,
    max_wrapper_payload_len: int = 0x3000,
) -> tuple[str, int, int, bytes] | None:
    if not parent_name:
        return None
    wrapper = _find_legacy_wrapper_payload_by_wrapper(section, parent_name)
    if wrapper is None:
        return None
    if len(wrapper[3]) > max_wrapper_payload_len:
        return None
    return _find_legacy_best_named_payload(section, visible_name, wrapper[3])


def _collect_legacy_typed_payload_candidates(
    section: bytes,
    *,
    bone_name: str,
    parent_name: str | None,
    wrapper_name: str | None,
) -> list[LegacyTypedPayloadCandidate]:
    candidates: list[LegacyTypedPayloadCandidate] = []
    seen: set[tuple[str, str, int, int, bytes]] = set()

    _append_legacy_typed_candidate(
        candidates,
        seen,
        source="fallback:wrapper_visible_name",
        anchor_name=bone_name,
        candidate=_find_legacy_wrapper_payload(section, bone_name),
    )
    if wrapper_name is not None:
        _append_legacy_typed_candidate(
            candidates,
            seen,
            source="fallback:wrapper_name",
            anchor_name=wrapper_name,
            candidate=_find_legacy_wrapper_payload_by_wrapper(section, wrapper_name),
        )
    _append_legacy_typed_candidate(
        candidates,
        seen,
        source="fallback:same_visible_name",
        anchor_name=bone_name,
        candidate=_find_legacy_visible_payload_same_name(section, bone_name),
    )
    if parent_name:
        _append_legacy_typed_candidate(
            candidates,
            seen,
            source="fallback:parent_linked",
            anchor_name=parent_name,
            candidate=_find_legacy_parent_payload(section, bone_name, parent_name),
        )
        _append_legacy_typed_candidate(
            candidates,
            seen,
            source="typed:parent_wrapper_named_follow",
            anchor_name=parent_name,
            candidate=_find_legacy_parent_wrapper_named_payload(section, bone_name, parent_name),
        )

    for anchor_name in dict.fromkeys(
        [name for name in (bone_name, wrapper_name, parent_name) if isinstance(name, str) and name]
    ):
        container_slice = _find_legacy_single_visible_container_slice(section, anchor_name)
        if container_slice is None:
            continue
        nested_visible = _unwrap_legacy_nested_visible_payload(container_slice)
        if nested_visible is None:
            nested_visible = _unwrap_legacy_inline_visible_payload(container_slice)
        if nested_visible is None:
            continue
        _append_legacy_typed_candidate(
            candidates,
            seen,
            source="typed:local_nested_visible",
            anchor_name=anchor_name,
            candidate=nested_visible,
        )
        relation_names = {
            name
            for name in (bone_name, wrapper_name, parent_name, anchor_name)
            if isinstance(name, str) and name
        }
        if nested_visible[0] in relation_names:
            _append_legacy_typed_candidate(
                candidates,
                seen,
                source="typed:local_named_follow",
                anchor_name=nested_visible[0],
                candidate=_find_legacy_best_named_payload(
                    section,
                    nested_visible[0],
                    nested_visible[3],
                ),
            )

    return candidates


def _legacy_typed_payload_candidate_score(
    candidate: LegacyTypedPayloadCandidate,
    *,
    bone_name: str,
    parent_name: str | None,
    wrapper_name: str | None,
) -> tuple[int, int, int, int, int, int]:
    score = 0
    if candidate.source.startswith("typed:"):
        score += 900
    elif candidate.source == "fallback:parent_linked":
        score += 300
    else:
        score += 200

    if candidate.payload_name == bone_name:
        score += 500
    elif wrapper_name is not None and candidate.payload_name == wrapper_name:
        score += 350
    elif parent_name is not None and candidate.payload_name == parent_name:
        score += 250

    if candidate.anchor_name == bone_name:
        score += 120
    elif wrapper_name is not None and candidate.anchor_name == wrapper_name:
        score += 90
    elif parent_name is not None and candidate.anchor_name == parent_name:
        score += 60

    if candidate.kind == 6:
        score += 140
    elif candidate.kind in (69, 70, 72, 76, 77, 82):
        score += 90
    else:
        score += min(candidate.kind, 32)

    score += min(candidate.count, 24) * 6
    score += min(len(candidate.payload), 0x1000) // 32
    return (
        score,
        1 if candidate.source.startswith("typed:") else 0,
        candidate.count,
        len(candidate.payload),
        1 if candidate.payload_name == bone_name else 0,
        1 if candidate.anchor_name == bone_name else 0,
    )


def _rank_legacy_model_bone_payloads(
    section: bytes,
    *,
    bone_name: str,
    parent_name: str | None,
    wrapper_name: str | None,
) -> list[LegacyTypedPayloadCandidate]:
    ranked: list[tuple[tuple[int, int, int, int, int, int], LegacyTypedPayloadCandidate]] = []
    for candidate in _collect_legacy_typed_payload_candidates(
        section,
        bone_name=bone_name,
        parent_name=parent_name,
        wrapper_name=wrapper_name,
    ):
        ranked.append(
            (
                _legacy_typed_payload_candidate_score(
                    candidate,
                    bone_name=bone_name,
                    parent_name=parent_name,
                    wrapper_name=wrapper_name,
                ),
                candidate,
            )
        )
    ranked.sort(key=lambda item: item[0], reverse=True)
    return [candidate for _key, candidate in ranked]


def _find_legacy_parent_payload(
    section: bytes,
    visible_name: str,
    parent_name: str,
    *,
    window: int = 0x4000,
) -> tuple[str, int, int, bytes] | None:
    child_pat = bytes([len(visible_name)]) + visible_name.encode("ascii") + b"\x00"
    parent_pat = bytes([len(parent_name)]) + parent_name.encode("ascii")
    start = 0
    best: tuple[str, int, int, bytes] | None = None
    best_key: tuple[int, int, int] | None = None
    while True:
        child_off = section.find(child_pat, start)
        if child_off < 0:
            break
        parent_off = section.find(
            parent_pat,
            child_off + len(child_pat),
            min(len(section), child_off + window),
        )
        if parent_off >= 0:
            payload_off = parent_off + len(parent_pat)
            while payload_off < len(section) and section[payload_off] == 0:
                payload_off += 1
            if payload_off + 2 <= len(section):
                count = section[payload_off]
                kind = section[payload_off + 1]
                if count > 0 and kind > 0:
                    block_end = len(section)
                    search_end = min(len(section) - 2, payload_off + window)
                    for off in range(payload_off + 2, search_end):
                        ln = section[off]
                        end = off + 1 + ln
                        if not (1 <= ln <= 32 and end < len(section)):
                            continue
                        raw = section[off + 1 : end]
                        if not all(32 <= c < 127 for c in raw):
                            continue
                        try:
                            text = raw.decode("ascii")
                        except UnicodeDecodeError:
                            continue
                        if not _plausible_legacy_name(text):
                            continue
                        if text not in {visible_name, parent_name}:
                            block_end = off
                            break
                    payload = section[payload_off + 2 : block_end]
                    if payload:
                        candidate = (visible_name, count, kind, payload)
                        key = (0 if kind == 6 else 1, -len(payload), child_off)
                        if best_key is None or key < best_key:
                            best = candidate
                            best_key = key
        start = child_off + 1
    return best


def _find_legacy_wrapper_payload_by_wrapper(
    section: bytes,
    wrapper_name: str,
) -> tuple[str, int, int, bytes] | None:
    first_pat = bytes([len(wrapper_name)]) + wrapper_name.encode("ascii") + b"\x00"
    first = section.find(first_pat)
    if first < 0:
        return None
    second_pat = b"\x00" + bytes([len(wrapper_name)]) + wrapper_name.encode("ascii")
    second = section.find(second_pat, first + len(first_pat))
    if second < 0:
        second = section.find(bytes([len(wrapper_name)]) + wrapper_name.encode("ascii"), first + len(first_pat))
        if second < 0:
            return None
        payload_off = second + 1 + len(wrapper_name)
    else:
        payload_off = second + 1 + 1 + len(wrapper_name)
    if payload_off < len(section) and section[payload_off] == 0:
        payload_off += 1
    if payload_off + 2 > len(section):
        return None
    count = section[payload_off]
    kind = section[payload_off + 1]
    block_end = len(section)
    search_end = min(len(section) - 2, payload_off + 0x4000)
    for off in range(payload_off + 2, search_end):
        ln = section[off]
        end = off + 1 + ln
        if not (1 <= ln <= 32 and end < len(section) and section[end] == 0):
            continue
        try:
            text = section[off + 1:end].decode("ascii")
        except UnicodeDecodeError:
            continue
        if _plausible_legacy_name(text):
            block_end = off
            break
    payload = section[payload_off + 2:block_end]
    return wrapper_name, count, kind, payload


def _unwrap_legacy_nested_wrapper_payload(
    payload: bytes,
) -> tuple[str, int, int, bytes] | None:
    search_end = min(len(payload) - 4, 128)
    best: tuple[str, int, int, bytes] | None = None
    for off in range(search_end):
        ln = payload[off]
        if not (1 <= ln <= 16 and off + 1 + ln + 2 <= len(payload)):
            continue
        raw_name = payload[off + 1 : off + 1 + ln]
        if not all(32 <= c < 127 for c in raw_name):
            continue
        try:
            name = raw_name.decode("ascii")
        except UnicodeDecodeError:
            continue
        j = off + 1 + ln
        while j < len(payload) and payload[j] == 0:
            j += 1
        if j + 2 > len(payload):
            continue
        count = payload[j]
        kind = payload[j + 1]
        if count <= 0 or kind <= 0:
            continue
        nested = payload[j + 2 :]
        if len(nested) < 92:
            continue
        candidate = (name, count, kind, nested)
        if kind == 6 and _LEGACY_WRAPPER_NAME_RE.fullmatch(name):
            return candidate
        if best is None and kind == 6:
            best = candidate
        elif best is None and _LEGACY_WRAPPER_NAME_RE.fullmatch(name):
            best = candidate
    return best


def _unwrap_legacy_nested_visible_payload(
    payload: bytes,
    *,
    depth: int = 0,
) -> tuple[str, int, int, bytes] | None:
    if depth >= 2:
        return None
    best: tuple[str, int, int, bytes] | None = None
    for off in range(0, min(len(payload) - 4, 256)):
        ln = payload[off]
        if not (1 <= ln <= 24 and off + 1 + ln + 2 <= len(payload)):
            continue
        raw_name = payload[off + 1 : off + 1 + ln]
        if not all(32 <= c < 127 for c in raw_name):
            continue
        try:
            name = raw_name.decode("ascii")
        except UnicodeDecodeError:
            continue
        if not _plausible_legacy_name(name):
            continue
        pat = bytes([ln]) + raw_name
        second = payload.find(pat, off + 1 + ln)
        if second < 0:
            continue
        payload_off = second + len(pat)
        if payload_off < len(payload) and payload[payload_off] == 0:
            payload_off += 1
        if payload_off + 2 > len(payload):
            continue
        count = payload[payload_off]
        kind = payload[payload_off + 1]
        if count <= 0 or kind <= 0:
            continue
        block_end = len(payload)
        search_end = min(len(payload) - 2, payload_off + 0x4000)
        for idx in range(payload_off + 2, search_end):
            l2 = payload[idx]
            end = idx + 1 + l2
            if not (1 <= l2 <= 32 and end < len(payload)):
                continue
            raw2 = payload[idx + 1 : end]
            if not all(32 <= c < 127 for c in raw2):
                continue
            if payload[end] == 0 or (idx > off and raw2 != raw_name):
                block_end = idx
                break
        nested = payload[payload_off + 2 : block_end]
        candidate = (name, count, kind, nested)
        if kind == 6:
            return candidate
        if kind in (70, 72, 76, 77, 82):
            deeper = _unwrap_legacy_nested_visible_payload(nested, depth=depth + 1)
            if deeper is not None:
                return deeper
        if best is None:
            best = candidate
    return best


def _unwrap_legacy_inline_visible_payload(
    payload: bytes,
    *,
    depth: int = 0,
) -> tuple[str, int, int, bytes] | None:
    if depth >= 2:
        return None
    best: tuple[str, int, int, bytes] | None = None
    for off in range(0, min(len(payload) - 4, 256)):
        ln = payload[off]
        if not (1 <= ln <= 24 and off + 1 + ln + 2 <= len(payload)):
            continue
        raw_name = payload[off + 1 : off + 1 + ln]
        if not all(32 <= c < 127 for c in raw_name):
            continue
        try:
            name = raw_name.decode("ascii")
        except UnicodeDecodeError:
            continue
        if not _plausible_legacy_name(name):
            continue
        payload_off = off + 1 + ln
        while payload_off < len(payload) and payload[payload_off] == 0:
            payload_off += 1
        if payload_off + 2 > len(payload):
            continue
        count = payload[payload_off]
        kind = payload[payload_off + 1]
        if count <= 0 or kind <= 0:
            continue
        nested = payload[payload_off + 2 :]
        candidate = (name, count, kind, nested)
        if kind == 6:
            return candidate
        if kind in (69, 70, 72, 76, 77, 82):
            deeper = _unwrap_legacy_inline_visible_payload(nested, depth=depth + 1)
            if deeper is not None:
                return deeper
            deeper = _unwrap_legacy_nested_visible_payload(nested, depth=depth + 1)
            if deeper is not None:
                return deeper
        if best is None:
            best = candidate
    return best


def _decode_legacy_payload_cubes(
    payload: bytes,
    tex: tuple[int, int] | None,
    *,
    bone_name: str,
    bone_pivot: tuple[float, float, float] | None,
    preferred_count: int,
) -> list[dict[str, object]]:
    quad_cubes = _build_legacy_face_quad_cubes(payload, tex)
    direct_cubes: list[dict[str, object]] = []
    need_direct = not quad_cubes or len(quad_cubes) < max(1, preferred_count // 2)
    if need_direct:
        direct_cubes = _build_legacy_direct_cubes(
            payload,
            tex,
            preferred_count=max(1, preferred_count),
        )
    candidates = quad_cubes + direct_cubes
    if candidates:
        filtered = _filter_legacy_cubes(
            candidates,
            preferred_count=max(1, preferred_count),
        )
        filtered = _refine_legacy_bone_cubes(
            bone_name,
            bone_pivot,
            filtered,
        )
        return filtered
    cube_guess = _build_legacy_direct_one_cube(payload, tex)
    if cube_guess is not None:
        return [cube_guess]
    return []


def _split_legacy_fixed_wrapper_records(
    payload: bytes,
    *,
    count: int,
    kind: int,
    record_len: int = 555,
    separator: int = 0x06,
) -> list[bytes]:
    if kind != 6 or count <= 0:
        return []
    expected_len = count * record_len + (count - 1)
    if len(payload) != expected_len:
        return []
    chunks: list[bytes] = []
    pos = 0
    for idx in range(count):
        end = pos + record_len
        if end > len(payload):
            return []
        chunks.append(payload[pos:end])
        pos = end
        if idx + 1 < count:
            if pos >= len(payload) or payload[pos] != separator:
                return []
            pos += 1
    if pos != len(payload):
        return []
    return chunks


def _should_use_segmented_wrapper_decode(
    *,
    bone_name: str,
    wrapper_name: str | None,
    candidate: LegacyTypedPayloadCandidate,
) -> bool:
    if bone_name not in _LEGACY_SEGMENTED_WRAPPER_ALLOW_BONES:
        return False
    if bone_name in _LEGACY_SEGMENTED_WRAPPER_DENY_BONES:
        return False
    if candidate.source not in {
        "typed:local_named_follow",
        "typed:local_nested_visible",
        "fallback:wrapper_visible_name",
        "fallback:wrapper_name",
    }:
        return False
    relation_names = {bone_name}
    if isinstance(wrapper_name, str) and wrapper_name:
        relation_names.add(wrapper_name)
    if candidate.payload_name not in relation_names:
        return False
    return bool(
        _split_legacy_fixed_wrapper_records(
            candidate.payload,
            count=candidate.count,
            kind=candidate.kind,
        )
    )


def _merge_segmented_wrapper_cubes(
    cube_groups: list[list[dict[str, object]]],
) -> list[dict[str, object]]:
    merged: list[dict[str, object]] = []
    seen: set[tuple[float, float, float, float, float, float]] = set()
    for cubes in cube_groups:
        for cube in cubes:
            origin = cube.get("origin")
            size = cube.get("size")
            if (
                not isinstance(origin, list)
                or len(origin) != 3
                or not isinstance(size, list)
                or len(size) != 3
            ):
                continue
            key = tuple(round(float(v), 3) for v in (*origin, *size))
            if key in seen:
                continue
            seen.add(key)
            merged.append(cube)
    return merged


def _legacy_cube_shape_key(cube: dict[str, object]) -> tuple[float, float, float, float, float, float] | None:
    origin = cube.get("origin")
    size = cube.get("size")
    if (
        not isinstance(origin, list)
        or len(origin) != 3
        or not isinstance(size, list)
        or len(size) != 3
    ):
        return None
    return tuple(round(float(v), 3) for v in (*origin, *size))


def _dedupe_legacy_cubes(cubes: list[dict[str, object]]) -> list[dict[str, object]]:
    deduped: list[dict[str, object]] = []
    seen: set[tuple[float, float, float, float, float, float]] = set()
    for cube in cubes:
        key = _legacy_cube_shape_key(cube)
        if key is None or key in seen:
            continue
        seen.add(key)
        deduped.append(cube)
    return deduped


def _mirror_legacy_cubes_x(cubes: list[dict[str, object]]) -> list[dict[str, object]]:
    mirrored: list[dict[str, object]] = []
    for cube in cubes:
        mirrored_cube = copy.deepcopy(cube)
        origin = mirrored_cube.get("origin")
        size = mirrored_cube.get("size")
        if (
            isinstance(origin, list)
            and len(origin) == 3
            and isinstance(size, list)
            and len(size) == 3
        ):
            origin[0] = -float(origin[0]) - float(size[0])
        mirrored.append(mirrored_cube)
    return mirrored


def _orient_legacy_cubes_to_side(
    cubes: list[dict[str, object]],
    *,
    bone_name: str,
    parent_name: str | None = None,
) -> list[dict[str, object]]:
    desired_positive_x: bool | None = None
    if bone_name.startswith("Left_") or bone_name.startswith("Left"):
        desired_positive_x = True
    elif bone_name.startswith("Right_") or bone_name.startswith("Right"):
        desired_positive_x = False
    elif isinstance(parent_name, str):
        if parent_name.startswith("Left"):
            desired_positive_x = True
        elif parent_name.startswith("Right"):
            desired_positive_x = False
    if desired_positive_x is None or not cubes:
        return cubes
    centers = [center for center in (_legacy_cube_center(cube) for cube in cubes) if center is not None]
    if not centers:
        return cubes
    mean_x = sum(center[0] for center in centers) / len(centers)
    if desired_positive_x and mean_x < 0.0:
        return _mirror_legacy_cubes_x(cubes)
    if not desired_positive_x and mean_x > 0.0:
        return _mirror_legacy_cubes_x(cubes)
    return cubes


def _cube_with_center_and_size(
    cube: dict[str, object],
    *,
    center: tuple[float, float, float],
    size: tuple[float, float, float],
) -> dict[str, object]:
    rewritten = copy.deepcopy(cube)
    rewritten["size"] = [float(size[0]), float(size[1]), float(size[2])]
    rewritten["origin"] = [
        float(center[0]) - float(size[0]) * 0.5,
        float(center[1]) - float(size[1]) * 0.5,
        float(center[2]) - float(size[2]) * 0.5,
    ]
    return rewritten


def _build_legacy_upperbody2_body_cubes(
    section: bytes,
    tex: tuple[int, int] | None,
    *,
    body_pivot: tuple[float, float, float] | None,
) -> list[dict[str, object]]:
    if tex is None or body_pivot is None:
        return []
    upperbody2 = _find_legacy_best_named_payload(section, "UpperBody2")
    if upperbody2 is None or upperbody2[1] != 4 or upperbody2[2] != 6:
        return []
    cubes = _decode_segmented_wrapper_payload_cubes(
        upperbody2[3],
        tex,
        bone_name="Body",
        bone_pivot=None,
        count=upperbody2[1],
        kind=upperbody2[2],
    )
    if len(cubes) != 4:
        return []

    torso_cube: dict[str, object] | None = None
    mid_cube: dict[str, object] | None = None
    strip_cubes: list[dict[str, object]] = []
    for cube in cubes:
        size = cube.get("size")
        if not isinstance(size, list) or len(size) != 3:
            return []
        sorted_size = tuple(sorted(round(float(v), 3) for v in size))
        if sorted_size == (9.0, 9.0, 16.5):
            torso_cube = cube
        elif sorted_size == (1.8, 9.6, 9.9):
            mid_cube = cube
        elif sorted_size == (0.6, 9.9, 10.2):
            strip_cubes.append(cube)
        else:
            return []
    if torso_cube is None or mid_cube is None or len(strip_cubes) != 2:
        return []

    px, py, pz = body_pivot
    built: list[dict[str, object]] = []

    # Large torso box centered on the Body pivot.
    built.append(
        _cube_with_center_and_size(
            torso_cube,
            center=(px, py, pz),
            size=(9.0, 9.0, 16.5),
        )
    )

    # Mid torso panel.
    built.append(
        _cube_with_center_and_size(
            mid_cube,
            center=(px, py + 8.4, pz - 15.15),
            size=(9.9, 1.8, 9.6),
        )
    )

    # Two upper back plates. Order them by source Z so the deeper source record
    # lands on the higher official strip.
    strip_cubes.sort(key=lambda cube: float(cube.get("origin", [0.0, 0.0, 0.0])[2]))
    strip_centers = (
        (px, py + 29.2125, pz - 23.1),
        (px, py + 27.2625, pz - 23.1),
    )
    for cube, center in zip(strip_cubes, strip_centers):
        built.append(
            _cube_with_center_and_size(
                cube,
                center=center,
                size=(10.2, 0.6, 9.9),
            )
        )

    return built


def _resize_legacy_cube_list(
    cubes: list[dict[str, object]],
    *,
    target_count: int,
) -> list[dict[str, object]]:
    if target_count <= 0 or not cubes:
        return []
    resized = [copy.deepcopy(cube) for cube in _dedupe_legacy_cubes(cubes)]
    if not resized:
        resized = [copy.deepcopy(cube) for cube in cubes]
    if not resized:
        return []
    if len(resized) >= target_count:
        return resized[:target_count]
    idx = 0
    seed = list(resized)
    while len(resized) < target_count:
        resized.append(copy.deepcopy(seed[idx % len(seed)]))
        idx += 1
    return resized


def _decode_segmented_wrapper_payload_cubes(
    payload: bytes,
    tex: tuple[int, int] | None,
    *,
    bone_name: str,
    bone_pivot: tuple[float, float, float] | None,
    count: int,
    kind: int,
) -> list[dict[str, object]]:
    chunks = _split_legacy_fixed_wrapper_records(
        payload,
        count=count,
        kind=kind,
    )
    if not chunks:
        return []
    cube_groups: list[list[dict[str, object]]] = []
    for chunk in chunks:
        cubes = _decode_legacy_payload_cubes(
            chunk,
            tex,
            bone_name=bone_name,
            bone_pivot=bone_pivot,
            preferred_count=1,
        )
        if cubes:
            cube_groups.append(cubes)
    return _merge_segmented_wrapper_cubes(cube_groups)


def _decode_legacy_model_candidate_cubes(
    section: bytes,
    candidate: LegacyTypedPayloadCandidate,
    *,
    bone_name: str,
    bone_pivot: tuple[float, float, float] | None,
    wrapper_name: str | None,
    preferred_count: int,
    codec_format: int | None,
    tex: tuple[int, int] | None,
) -> tuple[list[dict[str, object]], tuple[str, str, str, int, str]]:
    payload = candidate.payload
    selected_source = candidate.source
    selected_anchor = candidate.anchor_name
    selected_name = candidate.payload_name
    selected_kind = candidate.kind
    decode_mode = "flat_payload"
    if (
        codec_format == 15
        and candidate.kind in (70, 77)
        and candidate.payload_name != bone_name
    ):
        nested = _unwrap_legacy_nested_wrapper_payload(payload)
        if nested is not None and nested[2] == 6:
            payload = nested[3]
    cubes = _decode_legacy_payload_cubes(
        payload,
        tex,
        bone_name=bone_name,
        bone_pivot=bone_pivot,
        preferred_count=max(1, preferred_count),
    )
    if _should_use_segmented_wrapper_decode(
        bone_name=bone_name,
        wrapper_name=wrapper_name,
        candidate=candidate,
    ):
        segmented_cubes = _decode_segmented_wrapper_payload_cubes(
            payload,
            tex,
            bone_name=bone_name,
            bone_pivot=bone_pivot,
            count=candidate.count,
            kind=candidate.kind,
        )
        if len(segmented_cubes) > len(cubes):
            cubes = segmented_cubes
            decode_mode = "segmented_wrapper_records"
    if not cubes:
        nested_visible = _unwrap_legacy_nested_visible_payload(payload)
        if nested_visible is None:
            nested_visible = _unwrap_legacy_inline_visible_payload(payload)
        if nested_visible is not None:
            nested_best = _find_legacy_best_named_payload(
                section,
                nested_visible[0],
                nested_visible[3],
            )
            if nested_best is not None:
                cubes = _decode_legacy_payload_cubes(
                    nested_best[3],
                    tex,
                    bone_name=bone_name,
                    bone_pivot=bone_pivot,
                    preferred_count=max(1, nested_best[1]),
                )
                if cubes:
                    selected_source = f"{candidate.source}:nested_visible"
                    selected_anchor = nested_visible[0]
                    selected_name = nested_best[0]
                    selected_kind = nested_best[2]
                    decode_mode = "flat_payload"
    return cubes, (
        selected_source,
        selected_anchor,
        selected_name,
        selected_kind,
        decode_mode,
    )


def _best_legacy_model_candidate_decode(
    section: bytes,
    *,
    bone_name: str,
    parent_name: str | None,
    wrapper_name: str | None,
    bone_pivot: tuple[float, float, float] | None,
    preferred_count: int,
    codec_format: int | None,
    tex: tuple[int, int] | None,
    candidate_filter: callable | None = None,
) -> tuple[list[dict[str, object]], tuple[str, str, str, int, str] | None]:
    best_cubes: list[dict[str, object]] = []
    best_meta: tuple[str, str, str, int, str] | None = None
    best_key: tuple[int, int, int, int, int, int, int] | None = None
    for candidate in _rank_legacy_model_bone_payloads(
        section,
        bone_name=bone_name,
        parent_name=parent_name,
        wrapper_name=wrapper_name,
    ):
        if candidate_filter is not None and not candidate_filter(candidate):
            continue
        cubes, meta = _decode_legacy_model_candidate_cubes(
            section,
            candidate,
            bone_name=bone_name,
            bone_pivot=bone_pivot,
            wrapper_name=wrapper_name,
            preferred_count=preferred_count,
            codec_format=codec_format,
            tex=tex,
        )
        key = (
            1 if cubes else 0,
            len(cubes),
            *_legacy_typed_payload_candidate_score(
                candidate,
                bone_name=bone_name,
                parent_name=parent_name,
                wrapper_name=wrapper_name,
            ),
        )
        if best_key is None or key > best_key:
            best_key = key
            best_cubes = cubes
            best_meta = meta
    return best_cubes, best_meta


def _combine_candidate_filters(*filters: callable | None) -> callable | None:
    active = [item for item in filters if item is not None]
    if not active:
        return None

    def combined(candidate) -> bool:
        return all(fn(candidate) for fn in active)

    return combined


def _format15_child_allocation_candidate_filter(
    *,
    bone_name: str,
    parent_name: str | None,
    wrapper_name: str | None,
) -> callable:
    relation_names = {bone_name}
    if isinstance(parent_name, str) and parent_name:
        relation_names.add(parent_name)
    if isinstance(wrapper_name, str) and wrapper_name:
        relation_names.add(wrapper_name)

    def allow(candidate: LegacyTypedPayloadCandidate) -> bool:
        if candidate.source in {"fallback:wrapper_visible_name", "fallback:wrapper_name"}:
            return candidate.anchor_name in relation_names and candidate.payload_name in relation_names
        if candidate.source in {"fallback:parent_linked", "typed:parent_wrapper_named_follow"}:
            return isinstance(parent_name, str) and candidate.anchor_name == parent_name
        if candidate.source in {"typed:local_named_follow", "typed:local_nested_visible"}:
            return candidate.anchor_name in relation_names and candidate.payload_name in relation_names
        if candidate.source == "fallback:same_visible_name":
            return candidate.payload_name == bone_name
        return False

    return allow


def _find_legacy_direct_wrapper_payload(
    section: bytes,
    name: str,
) -> tuple[str, int, int, bytes] | None:
    return _find_legacy_wrapper_payload_by_wrapper(section, name) or _find_legacy_wrapper_payload(section, name)


def _decode_legacy_direct_wrapper_cubes(
    section: bytes,
    *,
    name: str,
    bone_name: str,
    bone_pivot: tuple[float, float, float] | None,
    tex: tuple[int, int] | None,
    prefer_segmented: bool = False,
) -> list[dict[str, object]]:
    wrapper = _find_legacy_direct_wrapper_payload(section, name)
    if wrapper is None:
        return []
    _payload_name, count, kind, payload = wrapper
    cubes = _decode_legacy_payload_cubes(
        payload,
        tex,
        bone_name=bone_name,
        bone_pivot=bone_pivot,
        preferred_count=max(1, count),
    )
    if prefer_segmented and kind == 6:
        segmented = _decode_segmented_wrapper_payload_cubes(
            payload,
            tex,
            bone_name=bone_name,
            bone_pivot=bone_pivot,
            count=count,
            kind=kind,
        )
        if len(segmented) > len(cubes):
            cubes = segmented
    return cubes


def _ensure_legacy_model_entry(
    entries: list[dict[str, object]],
    by_name: dict[str, dict[str, object]],
    *,
    name: str,
) -> dict[str, object]:
    entry = by_name.get(name)
    if entry is not None:
        return entry
    entry = {"name": name}
    entries.append(entry)
    by_name[name] = entry
    return entry


def _apply_legacy_main_model_child_allocation(
    bone_entries: list[dict[str, object]],
    *,
    section: bytes,
    tex: tuple[int, int] | None,
    codec_format: int | None,
    asset_name: str | None,
) -> tuple[list[dict[str, object]], dict[str, int]]:
    if asset_name != "main_model" or tex is None:
        return bone_entries, {
            "child_allocated_bone_hits": 0,
            "repaired_parent_bones": 0,
            "head_child_allocations": 0,
            "mask_child_allocated_bone_hits": 0,
            "head_structural_repairs": 0,
            "ear_child_allocations": 0,
            "foot_child_allocations": 0,
            "leg_child_allocations": 0,
            "tail_child_allocations": 0,
            "body_child_allocations": 0,
            "hair_child_allocations": 0,
            "mouth_child_allocations": 0,
            "arm_child_allocations": 0,
        }

    by_name = {
        str(entry.get("name")): entry
        for entry in bone_entries
        if isinstance(entry.get("name"), str)
    }
    repaired_parent_bones = 0
    head_structural_repairs = 0
    for child_name, parent_name in _LEGACY_CHILD_ALLOCATION_PARENT_RULES.items():
        entry = _ensure_legacy_model_entry(bone_entries, by_name, name=child_name)
        if entry.get("parent") != parent_name:
            entry["parent"] = parent_name
            entry["__compiled_parent_repaired"] = True
            repaired_parent_bones += 1
            if child_name in {"Head", "MHead", "Mask", "Ear", "Eyes"}:
                head_structural_repairs += 1

    def set_allocated_cubes(
        name: str,
        family: str,
        source: str,
        cubes: list[dict[str, object]],
        *,
        target_count: int,
    ) -> None:
        entry = _ensure_legacy_model_entry(bone_entries, by_name, name=name)
        resized = _resize_legacy_cube_list(cubes, target_count=target_count)
        if resized:
            entry["cubes"] = resized
            entry["__compiled_cube_source"] = f"allocated:{family}:{source}"
            entry["__compiled_cube_anchor_name"] = family
            entry["__compiled_cube_payload_name"] = family
            entry["__compiled_cube_payload_kind"] = 0
            entry["__compiled_cube_decode_mode"] = "child_allocated"

    def clear_container(name: str) -> None:
        entry = by_name.get(name)
        if entry is None:
            return
        entry.pop("cubes", None)
        entry["__compiled_cube_source"] = f"allocated:{name}:container_cleared"
        entry["__compiled_cube_anchor_name"] = name
        entry["__compiled_cube_payload_name"] = name
        entry["__compiled_cube_payload_kind"] = 0
        entry["__compiled_cube_decode_mode"] = "child_allocated"

    def clear_structural_bone(name: str) -> None:
        entry = _ensure_legacy_model_entry(bone_entries, by_name, name=name)
        entry.pop("cubes", None)
        entry["__compiled_cube_source"] = f"allocated:{name}:structural_wrapper"
        entry["__compiled_cube_anchor_name"] = name
        entry["__compiled_cube_payload_name"] = name
        entry["__compiled_cube_payload_kind"] = 0
        entry["__compiled_cube_decode_mode"] = "child_allocated"

    def orient_entry_pivot_to_side(name: str) -> None:
        entry = by_name.get(name)
        if entry is None:
            return
        pivot = entry.get("pivot")
        if not (isinstance(pivot, list) and len(pivot) == 3):
            return
        desired_positive_x: bool | None = None
        if "Left" in name:
            desired_positive_x = True
        elif "Right" in name:
            desired_positive_x = False
        if desired_positive_x is None:
            return
        x = float(pivot[0])
        if desired_positive_x and x < 0.0:
            pivot[0] = -x
        elif not desired_positive_x and x > 0.0:
            pivot[0] = -x

    # Hair family: move the large Hair-owned pool onto BaseHair and the BaseHair pool onto bone5.
    hair_pool = _decode_legacy_direct_wrapper_cubes(
        section,
        name="Hair",
        bone_name="BaseHair",
        bone_pivot=None,
        tex=tex,
        prefer_segmented=False,
    )
    if hair_pool:
        set_allocated_cubes(
            "BaseHair",
            "Hair",
            "hair_wrapper",
            hair_pool,
            target_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS["BaseHair"],
        )
    basehair_pool = _decode_legacy_direct_wrapper_cubes(
        section,
        name="BaseHair",
        bone_name="bone5",
        bone_pivot=None,
        tex=tex,
        prefer_segmented=True,
    )
    if basehair_pool:
        set_allocated_cubes(
            "bone5",
            "Hair",
            "basehair_wrapper",
            basehair_pool,
            target_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS["bone5"],
        )
    long_hair_specs = (
        ("MLongHair", "LongHair", "LongHair2"),
        ("MLongLeftHair", "LongLeftHair", "LongLeftHair2"),
        ("MLongRightHair", "LongRightHair", "LongRightHair2"),
    )
    for wrapper_name, bone_name, child_name in long_hair_specs:
        orient_entry_pivot_to_side(wrapper_name)
        orient_entry_pivot_to_side(bone_name)
        orient_entry_pivot_to_side(child_name)
        parent_wrapper = _find_legacy_direct_wrapper_payload(section, wrapper_name)
        if parent_wrapper is not None:
            parent_cubes = _decode_segmented_wrapper_payload_cubes(
                parent_wrapper[3],
                tex,
                bone_name=bone_name,
                bone_pivot=None,
                count=parent_wrapper[1],
                kind=parent_wrapper[2],
            )
            parent_cubes = _orient_legacy_cubes_to_side(
                parent_cubes,
                bone_name=bone_name,
                parent_name=wrapper_name,
            )
            if parent_cubes:
                set_allocated_cubes(
                    bone_name,
                    "Hair",
                    f"{wrapper_name.lower()}_segmented_wrapper",
                    parent_cubes,
                    target_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS[bone_name],
                )
        child_wrapper = _find_legacy_direct_wrapper_payload(section, bone_name)
        if child_wrapper is not None:
            child_cubes = _decode_segmented_wrapper_payload_cubes(
                child_wrapper[3],
                tex,
                bone_name=child_name,
                bone_pivot=None,
                count=child_wrapper[1],
                kind=child_wrapper[2],
            )
            child_cubes = _orient_legacy_cubes_to_side(
                child_cubes,
                bone_name=child_name,
                parent_name=bone_name,
            )
            if child_cubes:
                set_allocated_cubes(
                    child_name,
                    "Hair",
                    f"{bone_name.lower()}_segmented_wrapper",
                    child_cubes,
                    target_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS[child_name],
                )
        clear_structural_bone(wrapper_name)
    clear_container("Hair")

    # Head family: preserve the MHead -> Head chain and allocate the Head-owned pool onto Mask.
    clear_structural_bone("MHead")
    clear_container("Ear")
    clear_container("Eyes")
    mask_seed_cubes: list[dict[str, object]] = []
    head_mask_pool = _find_legacy_parent_payload(section, "Ear", "Head")
    if head_mask_pool is not None:
        mask_seed_cubes = _decode_legacy_payload_cubes(
            head_mask_pool[3],
            tex,
            bone_name="Mask",
            bone_pivot=None,
            preferred_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS["Mask"],
        )
    if len(mask_seed_cubes) < _LEGACY_CHILD_ALLOCATION_TARGET_COUNTS["Mask"]:
        best_mask_cubes, _best_mask_meta = _best_legacy_model_candidate_decode(
            section,
            bone_name="Mask",
            parent_name="Head",
            wrapper_name=None,
            bone_pivot=None,
            preferred_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS["Mask"],
            codec_format=codec_format,
            tex=tex,
            candidate_filter=(
                _format15_child_allocation_candidate_filter(
                    bone_name="Mask",
                    parent_name="Head",
                    wrapper_name=None,
                )
                if codec_format == 15
                else None
            ),
        )
        if len(best_mask_cubes) > len(mask_seed_cubes):
            mask_seed_cubes = best_mask_cubes
    if mask_seed_cubes:
        set_allocated_cubes(
            "Mask",
            "Head",
            "head_parent_pool",
            mask_seed_cubes,
            target_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS["Mask"],
        )

    # Ear family: decode the repeated Ear wrapper record-by-record and orient children by side.
    ear_wrapper = _find_legacy_direct_wrapper_payload(section, "Ear")
    if ear_wrapper is not None:
        for ear_name in ("Left_ear", "Right_ear"):
            ear_cubes = _decode_segmented_wrapper_payload_cubes(
                ear_wrapper[3],
                tex,
                bone_name=ear_name,
                bone_pivot=None,
                count=ear_wrapper[1],
                kind=ear_wrapper[2],
            )
            ear_cubes = _orient_legacy_cubes_to_side(
                ear_cubes,
                bone_name=ear_name,
                parent_name="Ear",
            )
            if ear_cubes:
                set_allocated_cubes(
                    ear_name,
                    "Ear",
                    "ear_segmented_wrapper",
                    ear_cubes,
                    target_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS[ear_name],
                )

    # Mouth family: allocate the segmented Mouth wrapper to kongju, then top-off the named children.
    mouth_pool = _decode_legacy_direct_wrapper_cubes(
        section,
        name="Mouth",
        bone_name="kongju",
        bone_pivot=None,
        tex=tex,
        prefer_segmented=True,
    )
    if mouth_pool:
        set_allocated_cubes(
            "kongju",
            "Mouth",
            "mouth_wrapper",
            mouth_pool,
            target_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS["kongju"],
        )
    for child_name in ("jingya", "xiao", "weixiao"):
        entry = by_name.get(child_name)
        seed_cubes = list(entry.get("cubes", [])) if entry is not None and isinstance(entry.get("cubes"), list) else []
        candidate_filter = (
            _format15_child_allocation_candidate_filter(
                bone_name=child_name,
                parent_name="Mouth",
                wrapper_name=str(entry.get("__compiled_wrapper_name")) if entry is not None and isinstance(entry.get("__compiled_wrapper_name"), str) else None,
            )
            if codec_format == 15
            else None
        )
        best_cubes, _best_meta = _best_legacy_model_candidate_decode(
            section,
            bone_name=child_name,
            parent_name="Mouth",
            wrapper_name=str(entry.get("__compiled_wrapper_name")) if entry is not None and isinstance(entry.get("__compiled_wrapper_name"), str) else None,
            bone_pivot=None,
            preferred_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS[child_name],
            codec_format=codec_format,
            tex=tex,
            candidate_filter=candidate_filter,
        )
        if len(best_cubes) > len(seed_cubes):
            seed_cubes = best_cubes
        if seed_cubes:
            set_allocated_cubes(
                child_name,
                "Mouth",
                "child_best_candidate",
                seed_cubes,
                target_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS[child_name],
            )
    clear_container("Mouth")

    # Arm family: keep Arm empty, force direct parent links, and top-off children from family-local pools.
    clear_container("Arm")
    for arm_name in ("LeftArm", "RightArm"):
        candidate_filter = (
            _format15_child_allocation_candidate_filter(
                bone_name=arm_name,
                parent_name="Arm",
                wrapper_name=arm_name,
            )
            if codec_format == 15
            else None
        )
        best_cubes, _best_meta = _best_legacy_model_candidate_decode(
            section,
            bone_name=arm_name,
            parent_name="Arm",
            wrapper_name=arm_name,
            bone_pivot=None,
            preferred_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS[arm_name],
            codec_format=codec_format,
            tex=tex,
            candidate_filter=candidate_filter,
        )
        if best_cubes:
            set_allocated_cubes(
                arm_name,
                "Arm",
                f"{arm_name.lower()}_best_candidate",
                best_cubes,
                target_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS[arm_name],
            )
    forearm_source_map = {
        "LeftForeArm": "LeftArm",
        "RightForeArm": "RightArm",
    }
    for forearm_name, parent_anchor in forearm_source_map.items():
        inline = _find_legacy_single_visible_container_slice(section, parent_anchor)
        seed_cubes: list[dict[str, object]] = []
        if inline is not None:
            payload = _unwrap_legacy_inline_visible_payload(inline)
            if payload is not None:
                seed_cubes = _decode_legacy_payload_cubes(
                    payload[3],
                    tex,
                    bone_name=forearm_name,
                    bone_pivot=None,
                    preferred_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS[forearm_name],
                )
        best_cubes, _best_meta = _best_legacy_model_candidate_decode(
            section,
            bone_name=forearm_name,
            parent_name=parent_anchor,
            wrapper_name=forearm_name,
            bone_pivot=None,
            preferred_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS[forearm_name],
            codec_format=codec_format,
            tex=tex,
            candidate_filter=(
                _format15_child_allocation_candidate_filter(
                    bone_name=forearm_name,
                    parent_name=parent_anchor,
                    wrapper_name=forearm_name,
                )
                if codec_format == 15
                else None
            ),
        )
        if len(best_cubes) > len(seed_cubes):
            seed_cubes = best_cubes
        if seed_cubes:
            set_allocated_cubes(
                forearm_name,
                "Arm",
                f"{parent_anchor.lower()}_container_slice",
                seed_cubes,
                target_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS[forearm_name],
            )
    for hand_name, forearm_name in (("LeftHand", "LeftForeArm"), ("RightHand", "RightForeArm")):
        entry = by_name.get(hand_name)
        seed_cubes = list(entry.get("cubes", [])) if entry is not None and isinstance(entry.get("cubes"), list) else []
        best_cubes, _best_meta = _best_legacy_model_candidate_decode(
            section,
            bone_name=hand_name,
            parent_name=forearm_name,
            wrapper_name=hand_name,
            bone_pivot=None,
            preferred_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS[hand_name],
            codec_format=codec_format,
            tex=tex,
            candidate_filter=(
                _format15_child_allocation_candidate_filter(
                    bone_name=hand_name,
                    parent_name=forearm_name,
                    wrapper_name=hand_name,
                )
                if codec_format == 15
                else None
            ),
        )
        if len(best_cubes) > len(seed_cubes):
            seed_cubes = best_cubes
        if not seed_cubes:
            forearm_entry = by_name.get(forearm_name)
            if forearm_entry is not None and isinstance(forearm_entry.get("cubes"), list):
                seed_cubes = [copy.deepcopy(forearm_entry["cubes"][0])] if forearm_entry["cubes"] else []
        if seed_cubes:
            set_allocated_cubes(
                hand_name,
                "Arm",
                f"{hand_name.lower()}_best_candidate",
                seed_cubes,
                target_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS[hand_name],
            )

    # Leg/foot family: keep the leg chain structurally exact, trim container spillover, and
    # use segmented wrappers for the repeated left/right lower-body detail records.
    clear_container("DownBody")
    clear_container("MUpperBody")
    for leg_name, parent_anchor in (("LeftLeg", "DownBody"), ("RightLeg", "DownBody")):
        leg_wrapper = _find_legacy_direct_wrapper_payload(section, leg_name)
        if leg_wrapper is None:
            continue
        leg_cubes = _decode_segmented_wrapper_payload_cubes(
            leg_wrapper[3],
            tex,
            bone_name=leg_name,
            bone_pivot=None,
            count=leg_wrapper[1],
            kind=leg_wrapper[2],
        )
        leg_cubes = _orient_legacy_cubes_to_side(
            leg_cubes,
            bone_name=leg_name,
            parent_name=parent_anchor,
        )
        if leg_cubes:
            set_allocated_cubes(
                leg_name,
                "Leg",
                f"{leg_name.lower()}_segmented_wrapper",
                leg_cubes,
                target_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS[leg_name],
            )
    for lower_leg_name, parent_anchor in (("LeftLowerLeg", "LeftLeg"), ("RightLowerLeg", "RightLeg")):
        lower_wrapper = _find_legacy_direct_wrapper_payload(section, lower_leg_name)
        if lower_wrapper is None:
            continue
        lower_cubes = _decode_segmented_wrapper_payload_cubes(
            lower_wrapper[3],
            tex,
            bone_name=lower_leg_name,
            bone_pivot=None,
            count=lower_wrapper[1],
            kind=lower_wrapper[2],
        )
        lower_cubes = _orient_legacy_cubes_to_side(
            lower_cubes,
            bone_name=lower_leg_name,
            parent_name=parent_anchor,
        )
        if lower_cubes:
            set_allocated_cubes(
                lower_leg_name,
                "Leg",
                f"{lower_leg_name.lower()}_segmented_wrapper",
                lower_cubes,
                target_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS[lower_leg_name],
            )
    for foot_name, parent_anchor in (("LeftFoot", "LeftLowerLeg"), ("RightFoot", "RightLowerLeg")):
        foot_wrapper = _find_legacy_direct_wrapper_payload(section, foot_name)
        if foot_wrapper is None:
            continue
        foot_cubes = _decode_segmented_wrapper_payload_cubes(
            foot_wrapper[3],
            tex,
            bone_name=foot_name,
            bone_pivot=None,
            count=foot_wrapper[1],
            kind=foot_wrapper[2],
        )
        foot_cubes = _orient_legacy_cubes_to_side(
            foot_cubes,
            bone_name=foot_name,
            parent_name=parent_anchor,
        )
        if foot_cubes:
            set_allocated_cubes(
                foot_name,
                "Leg",
                f"{foot_name.lower()}_segmented_wrapper",
                foot_cubes,
                target_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS[foot_name],
            )

    # Foot detail children: decode segmented parent-foot wrappers and orient to the parent side.
    for child_name, parent_anchor in (("bone36", "LeftFoot"), ("bone37", "RightFoot")):
        foot_wrapper = _find_legacy_direct_wrapper_payload(section, parent_anchor)
        if foot_wrapper is None:
            continue
        foot_cubes = _decode_segmented_wrapper_payload_cubes(
            foot_wrapper[3],
            tex,
            bone_name=child_name,
            bone_pivot=None,
            count=foot_wrapper[1],
            kind=foot_wrapper[2],
        )
        foot_cubes = _orient_legacy_cubes_to_side(
            foot_cubes,
            bone_name=child_name,
            parent_name=parent_anchor,
        )
        if foot_cubes:
            set_allocated_cubes(
                child_name,
                "Foot",
                f"{parent_anchor.lower()}_segmented_wrapper",
                foot_cubes,
                target_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS[child_name],
            )

    # Tail family: keep MTail empty and allocate the repeated child records down the chain.
    clear_container("MTail")
    tail_seed = _decode_legacy_direct_wrapper_cubes(
        section,
        name="MTail",
        bone_name="Tail",
        bone_pivot=None,
        tex=tex,
        prefer_segmented=False,
    )
    if tail_seed:
        set_allocated_cubes(
            "Tail",
            "Tail",
            "mtail_wrapper",
            tail_seed,
            target_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS["Tail"],
        )
    tail2_wrapper = _find_legacy_direct_wrapper_payload(section, "Tail")
    if tail2_wrapper is not None:
        tail2_cubes = _decode_segmented_wrapper_payload_cubes(
            tail2_wrapper[3],
            tex,
            bone_name="Tail2",
            bone_pivot=None,
            count=tail2_wrapper[1],
            kind=tail2_wrapper[2],
        )
        if tail2_cubes:
            set_allocated_cubes(
                "Tail2",
                "Tail",
                "tail_segmented_wrapper",
                tail2_cubes,
                target_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS["Tail2"],
            )
    tail3_wrapper = _find_legacy_direct_wrapper_payload(section, "Tail2")
    if tail3_wrapper is not None:
        tail3_cubes = _decode_segmented_wrapper_payload_cubes(
            tail3_wrapper[3],
            tex,
            bone_name="Tail3",
            bone_pivot=None,
            count=tail3_wrapper[1],
            kind=tail3_wrapper[2],
        )
        if tail3_cubes:
            set_allocated_cubes(
                "Tail3",
                "Tail",
                "tail2_segmented_wrapper",
                tail3_cubes,
                target_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS["Tail3"],
            )

    # Body: the `UpperBody2` family exposes a 4-record torso payload whose
    # record shapes match the official Body geometry, but it needs a
    # dedicated placement transform rather than generic wrapper reuse.
    body_entry = by_name.get("Body")
    body_pivot = None
    if body_entry is not None:
        pivot = body_entry.get("pivot")
        if isinstance(pivot, list) and len(pivot) == 3:
            body_pivot = (float(pivot[0]), float(pivot[1]), float(pivot[2]))
    body_cubes = _build_legacy_upperbody2_body_cubes(
        section,
        tex,
        body_pivot=body_pivot,
    )
    if body_cubes:
        set_allocated_cubes(
            "Body",
            "Body",
            "upperbody2_segmented_wrapper",
            body_cubes,
            target_count=4,
        )
        clear_container("UpperBody2")
        clear_container("UpBody2")

    # Front-clothe / eye cleanup: keep the narrow child chains, drop the
    # obvious container false positives, and source tiny children from their
    # direct parent wrapper path instead of local fanout.
    clear_structural_bone("FrontClothe")
    front_clothe_entry = by_name.get("FrontClothe")
    if front_clothe_entry is not None:
        pivot = front_clothe_entry.get("pivot")
        if isinstance(pivot, list) and len(pivot) == 3:
            pivot[0] = -abs(float(pivot[0]))
    fm_entry = by_name.get("FM")
    fm_seed = list(fm_entry.get("cubes", [])) if fm_entry is not None and isinstance(fm_entry.get("cubes"), list) else []
    if fm_seed:
        set_allocated_cubes(
            "FM",
            "Hair",
            "fm_existing_trimmed",
            fm_seed,
            target_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS["FM"],
        )
    for bone_name, parent_name in (("FM1", "FM"), ("FM2", "FM1")):
        family_filter = (
            _format15_child_allocation_candidate_filter(
                bone_name=bone_name,
                parent_name=parent_name,
                wrapper_name=bone_name,
            )
            if codec_format == 15
            else None
        )
        best_cubes, _best_meta = _best_legacy_model_candidate_decode(
            section,
            bone_name=bone_name,
            parent_name=parent_name,
            wrapper_name=bone_name,
            bone_pivot=None,
            preferred_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS[bone_name],
            codec_format=codec_format,
            tex=tex,
            candidate_filter=_combine_candidate_filters(
                family_filter,
                lambda candidate, expected_parent=parent_name: candidate.source in {
                    "typed:parent_wrapper_named_follow",
                    "fallback:parent_linked",
                } and candidate.anchor_name == expected_parent,
            ),
        )
        if best_cubes:
            set_allocated_cubes(
                bone_name,
                "Hair",
                f"{parent_name.lower()}_parent_wrapper_trimmed",
                best_cubes,
                target_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS[bone_name],
            )

    for bone_name in ("RightEyelid", "RightEyelidBase"):
        entry = by_name.get(bone_name)
        seed = list(entry.get("cubes", [])) if entry is not None and isinstance(entry.get("cubes"), list) else []
        if seed:
            set_allocated_cubes(
                bone_name,
                "Head",
                f"{bone_name.lower()}_existing_trimmed",
                seed,
                target_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS[bone_name],
            )
        orient_entry_pivot_to_side(bone_name)
    orient_entry_pivot_to_side("RightEyeDot")
    right_eye_dot_cubes, _right_eye_dot_meta = _best_legacy_model_candidate_decode(
        section,
        bone_name="RightEyeDot",
        parent_name="RightEyelidBase",
        wrapper_name="RightEyeDot",
        bone_pivot=None,
        preferred_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS["RightEyeDot"],
        codec_format=codec_format,
        tex=tex,
        candidate_filter=_combine_candidate_filters(
            (
                _format15_child_allocation_candidate_filter(
                    bone_name="RightEyeDot",
                    parent_name="RightEyelidBase",
                    wrapper_name="RightEyeDot",
                )
                if codec_format == 15
                else None
            ),
            lambda candidate: candidate.source in {
                "typed:parent_wrapper_named_follow",
                "fallback:parent_linked",
            } and candidate.anchor_name == "RightEyelidBase",
        ),
    )
    if right_eye_dot_cubes:
        set_allocated_cubes(
            "RightEyeDot",
            "Head",
            "righteyelidbase_parent_wrapper_trimmed",
            right_eye_dot_cubes,
            target_count=_LEGACY_CHILD_ALLOCATION_TARGET_COUNTS["RightEyeDot"],
        )

    for false_positive_name in (
        "RightHandLocator",
        "Elytra",
        "EyeBrow",
        "Eyelid",
        "FOX",
        "AllBody2",
        "AllHead2",
        "Arm2",
        "DownBody2",
        "ElytraLocator",
    ):
        if false_positive_name in by_name:
            clear_structural_bone(false_positive_name)

    child_allocated_bone_hits = 0
    head_child_allocations = 0
    mask_child_allocated_bone_hits = 0
    ear_child_allocations = 0
    foot_child_allocations = 0
    leg_child_allocations = 0
    tail_child_allocations = 0
    body_child_allocations = 0
    hair_child_allocations = 0
    mouth_child_allocations = 0
    arm_child_allocations = 0
    for entry in bone_entries:
        source = entry.get("__compiled_cube_source")
        if not (isinstance(source, str) and source.startswith("allocated:") and entry.get("cubes")):
            continue
        child_allocated_bone_hits += 1
        family = source.split(":", 2)[1]
        if family == "Head":
            head_child_allocations += 1
            if entry.get("name") == "Mask":
                mask_child_allocated_bone_hits += 1
        elif family == "Ear":
            ear_child_allocations += 1
        elif family == "Foot":
            foot_child_allocations += 1
        elif family == "Leg":
            leg_child_allocations += 1
        elif family == "Tail":
            tail_child_allocations += 1
        elif family == "Body":
            body_child_allocations += 1
        elif family == "Hair":
            hair_child_allocations += 1
        elif family == "Mouth":
            mouth_child_allocations += 1
        elif family == "Arm":
            arm_child_allocations += 1

    return bone_entries, {
        "child_allocated_bone_hits": child_allocated_bone_hits,
        "repaired_parent_bones": repaired_parent_bones,
        "head_child_allocations": head_child_allocations,
        "mask_child_allocated_bone_hits": mask_child_allocated_bone_hits,
        "head_structural_repairs": head_structural_repairs,
        "ear_child_allocations": ear_child_allocations,
        "foot_child_allocations": foot_child_allocations,
        "leg_child_allocations": leg_child_allocations,
        "tail_child_allocations": tail_child_allocations,
        "body_child_allocations": body_child_allocations,
        "hair_child_allocations": hair_child_allocations,
        "mouth_child_allocations": mouth_child_allocations,
        "arm_child_allocations": arm_child_allocations,
    }


def _empty_child_allocation_summary() -> dict[str, int]:
    return {
        "child_allocated_bone_hits": 0,
        "repaired_parent_bones": 0,
        "head_child_allocations": 0,
        "mask_child_allocated_bone_hits": 0,
        "head_structural_repairs": 0,
        "ear_child_allocations": 0,
        "foot_child_allocations": 0,
        "leg_child_allocations": 0,
        "tail_child_allocations": 0,
        "body_child_allocations": 0,
        "hair_child_allocations": 0,
        "mouth_child_allocations": 0,
        "arm_child_allocations": 0,
    }


def _merge_child_allocation_summaries(*summaries: dict[str, int]) -> dict[str, int]:
    merged = _empty_child_allocation_summary()
    for summary in summaries:
        for key in merged:
            merged[key] += int(summary.get(key, 0) or 0)
    return merged


def _best_legacy_model_candidate_decode_by_cube_count(
    section: bytes,
    *,
    bone_name: str,
    parent_name: str | None,
    wrapper_name: str | None,
    preferred_count: int,
    codec_format: int | None,
    tex: tuple[int, int] | None,
    candidate_filter: callable | None = None,
) -> list[dict[str, object]]:
    best_cubes: list[dict[str, object]] = []
    best_key: tuple[int, int, int, int, int, int, int] | None = None
    for candidate in _rank_legacy_model_bone_payloads(
        section,
        bone_name=bone_name,
        parent_name=parent_name,
        wrapper_name=wrapper_name,
    ):
        if candidate_filter is not None and not candidate_filter(candidate):
            continue
        cubes, _meta = _decode_legacy_model_candidate_cubes(
            section,
            candidate,
            bone_name=bone_name,
            bone_pivot=None,
            wrapper_name=wrapper_name,
            preferred_count=preferred_count,
            codec_format=codec_format,
            tex=tex,
        )
        key = (
            len(cubes),
            1 if cubes else 0,
            *_legacy_typed_payload_candidate_score(
                candidate,
                bone_name=bone_name,
                parent_name=parent_name,
                wrapper_name=wrapper_name,
            ),
        )
        if best_key is None or key > best_key:
            best_key = key
            best_cubes = cubes
    return best_cubes


def _apply_legacy_aux_model_child_allocation(
    bone_entries: list[dict[str, object]],
    *,
    section: bytes,
    tex: tuple[int, int] | None,
    codec_format: int | None,
    asset_name: str | None,
) -> tuple[list[dict[str, object]], dict[str, int]]:
    if asset_name not in {"arm_model", "arrow_model"} or tex is None:
        return bone_entries, _empty_child_allocation_summary()

    entries = bone_entries
    by_name = {
        str(entry.get("name")): entry
        for entry in bone_entries
        if isinstance(entry.get("name"), str)
    }
    repaired_parent_bones = 0

    def ensure_entry(name: str) -> dict[str, object]:
        return _ensure_legacy_model_entry(bone_entries, by_name, name=name)

    def set_parent(name: str, parent: str | None) -> None:
        nonlocal repaired_parent_bones
        entry = ensure_entry(name)
        if entry.get("parent") == parent:
            return
        if parent is None:
            entry.pop("parent", None)
        else:
            entry["parent"] = parent
        entry["__compiled_parent_repaired"] = True
        repaired_parent_bones += 1

    def set_allocated_cubes(
        name: str,
        family: str,
        source: str,
        cubes: list[dict[str, object]],
        *,
        target_count: int,
        parent_name: str | None = None,
    ) -> None:
        entry = ensure_entry(name)
        if target_count <= 0:
            entry.pop("cubes", None)
        else:
            resized = _resize_legacy_cube_list(cubes, target_count=target_count)
            if not resized:
                return
            if family != "Arrow" and name.startswith(("Left", "Right")):
                resized = _orient_legacy_cubes_to_side(
                    resized,
                    bone_name=name,
                    parent_name=parent_name,
                )
            entry["cubes"] = resized
        entry["__compiled_cube_source"] = f"allocated:{family}:{source}"
        entry["__compiled_cube_anchor_name"] = family
        entry["__compiled_cube_payload_name"] = family
        entry["__compiled_cube_payload_kind"] = 0
        entry["__compiled_cube_decode_mode"] = "child_allocated"

    def clear_bone(name: str, *, family: str, reason: str) -> None:
        entry = ensure_entry(name)
        entry.pop("cubes", None)
        entry["__compiled_cube_source"] = f"allocated:{family}:{reason}"
        entry["__compiled_cube_anchor_name"] = family
        entry["__compiled_cube_payload_name"] = family
        entry["__compiled_cube_payload_kind"] = 0
        entry["__compiled_cube_decode_mode"] = "child_allocated"

    def best_family_cubes(
        bone_name: str,
        *,
        parent_name: str | None,
        wrapper_name: str | None,
        preferred_count: int,
        family_filter: callable | None = None,
    ) -> list[dict[str, object]]:
        return _best_legacy_model_candidate_decode_by_cube_count(
            section,
            bone_name=bone_name,
            parent_name=parent_name,
            wrapper_name=wrapper_name,
            preferred_count=preferred_count,
            codec_format=codec_format,
            tex=tex,
            candidate_filter=family_filter,
        )

    if asset_name == "arm_model":
        parent_map = {
            "LeftArm": "Arm",
            "RightArm": "Arm",
            "LeftForeArm": "LeftArm",
            "RightForeArm": "RightArm",
            "LeftHand": "LeftForeArm",
            "RightHand": "RightForeArm",
            "LeftHandLocator": "LeftHand",
            "RightHandLocator": "RightHand",
        }
        for name, parent in parent_map.items():
            set_parent(name, parent)
        ensure_entry("Arm")
        clear_bone("Arm", family="Arm", reason="container_cleared")
        for locator_name in ("LeftHandLocator", "RightHandLocator"):
            clear_bone(locator_name, family="Arm", reason="locator_cleared")

        arm_sources: dict[str, list[dict[str, object]]] = {}
        for arm_name in ("LeftArm", "RightArm"):
            target_count = _LEGACY_ARM_MODEL_TARGET_COUNTS[arm_name]
            cubes = best_family_cubes(
                arm_name,
                parent_name="Arm",
                wrapper_name=arm_name,
                preferred_count=target_count,
                family_filter=(
                    _format15_child_allocation_candidate_filter(
                        bone_name=arm_name,
                        parent_name="Arm",
                        wrapper_name=arm_name,
                    )
                    if codec_format == 15
                    else None
                ),
            )
            if not cubes and arm_name == "LeftArm":
                wrapper = _find_legacy_direct_wrapper_payload(section, "Arm")
                if wrapper is not None:
                    cubes = _decode_segmented_wrapper_payload_cubes(
                        wrapper[3],
                        tex,
                        bone_name=arm_name,
                        bone_pivot=None,
                        count=wrapper[1],
                        kind=wrapper[2],
                    )
            arm_sources[arm_name] = cubes
        if arm_sources.get("LeftArm") and (
            not arm_sources.get("RightArm")
            or len(arm_sources["RightArm"]) < len(arm_sources["LeftArm"])
        ):
            arm_sources["RightArm"] = copy.deepcopy(arm_sources["LeftArm"])
        for arm_name in ("LeftArm", "RightArm"):
            cubes = arm_sources.get(arm_name, [])
            if cubes:
                set_allocated_cubes(
                    arm_name,
                    "Arm",
                    f"{arm_name.lower()}_best_candidate",
                    cubes,
                    target_count=_LEGACY_ARM_MODEL_TARGET_COUNTS[arm_name],
                    parent_name="Arm",
                )

        forearm_sources: dict[str, list[dict[str, object]]] = {}
        for forearm_name, parent_name in (("LeftForeArm", "LeftArm"), ("RightForeArm", "RightArm")):
            target_count = _LEGACY_ARM_MODEL_TARGET_COUNTS[forearm_name]
            cubes = best_family_cubes(
                forearm_name,
                parent_name=parent_name,
                wrapper_name=forearm_name,
                preferred_count=target_count,
                family_filter=(
                    _format15_child_allocation_candidate_filter(
                        bone_name=forearm_name,
                        parent_name=parent_name,
                        wrapper_name=forearm_name,
                    )
                    if codec_format == 15
                    else None
                ),
            )
            if not cubes:
                cubes = best_family_cubes(
                    forearm_name,
                    parent_name=parent_name,
                    wrapper_name=parent_name,
                    preferred_count=target_count,
                    family_filter=None,
                )
            forearm_sources[forearm_name] = cubes
        if forearm_sources.get("LeftForeArm") and (
            not forearm_sources.get("RightForeArm")
            or len(forearm_sources["RightForeArm"]) < len(forearm_sources["LeftForeArm"])
        ):
            forearm_sources["RightForeArm"] = copy.deepcopy(forearm_sources["LeftForeArm"])
        for forearm_name, parent_name in (("LeftForeArm", "LeftArm"), ("RightForeArm", "RightArm")):
            cubes = forearm_sources.get(forearm_name, [])
            if cubes:
                set_allocated_cubes(
                    forearm_name,
                    "Arm",
                    f"{parent_name.lower()}_family_candidate",
                    cubes,
                    target_count=_LEGACY_ARM_MODEL_TARGET_COUNTS[forearm_name],
                    parent_name=parent_name,
                )

        hand_sources: dict[str, list[dict[str, object]]] = {}
        for hand_name, parent_name in (("LeftHand", "LeftForeArm"), ("RightHand", "RightForeArm")):
            target_count = _LEGACY_ARM_MODEL_TARGET_COUNTS[hand_name]
            cubes = best_family_cubes(
                hand_name,
                parent_name=parent_name,
                wrapper_name=hand_name,
                preferred_count=target_count,
                family_filter=(
                    _format15_child_allocation_candidate_filter(
                        bone_name=hand_name,
                        parent_name=parent_name,
                        wrapper_name=hand_name,
                    )
                    if codec_format == 15
                    else None
                ),
            )
            if not cubes:
                cubes = best_family_cubes(
                    hand_name,
                    parent_name=parent_name,
                    wrapper_name=parent_name,
                    preferred_count=target_count,
                    family_filter=None,
                )
            hand_sources[hand_name] = cubes
        if hand_sources.get("LeftHand") and (
            not hand_sources.get("RightHand")
            or len(hand_sources["RightHand"]) < len(hand_sources["LeftHand"])
        ):
            hand_sources["RightHand"] = copy.deepcopy(hand_sources["LeftHand"])
        for hand_name, parent_name in (("LeftHand", "LeftForeArm"), ("RightHand", "RightForeArm")):
            cubes = hand_sources.get(hand_name, [])
            if cubes:
                set_allocated_cubes(
                    hand_name,
                    "Arm",
                    f"{hand_name.lower()}_family_candidate",
                    cubes,
                    target_count=_LEGACY_ARM_MODEL_TARGET_COUNTS[hand_name],
                    parent_name=parent_name,
                )

    if asset_name == "arrow_model":
        parent_map = {
            "UpPl": "Root",
            "DownPl": "Root",
            "LeftPl": "Root",
            "RightPl": "Root",
            "Other": "Root",
            "Sakura": "Root",
            "Bowknot": "Other",
            "Bowknot2": "Other",
            "Bowknot3": "Other",
            "Bowknot4": "Other",
            "Bowknot5": "Other",
            "Board": "Other",
            "Brand": "Other",
            "Board2": "Board",
        }
        for name, parent in parent_map.items():
            set_parent(name, parent)

        root_cubes = best_family_cubes(
            "Root",
            parent_name=None,
            wrapper_name=None,
            preferred_count=_LEGACY_ARROW_MODEL_TARGET_COUNTS["Root"],
            family_filter=None,
        )
        if not root_cubes:
            root_cubes = best_family_cubes(
                "Root",
                parent_name=None,
                wrapper_name="MRoot",
                preferred_count=_LEGACY_ARROW_MODEL_TARGET_COUNTS["Root"],
                family_filter=None,
            )
        if root_cubes:
            set_allocated_cubes(
                "Root",
                "Arrow",
                "root_family_candidate",
                root_cubes,
                target_count=_LEGACY_ARROW_MODEL_TARGET_COUNTS["Root"],
                parent_name=None,
            )

        other_cubes = best_family_cubes(
            "Other",
            parent_name="Root",
            wrapper_name=None,
            preferred_count=_LEGACY_ARROW_MODEL_TARGET_COUNTS["Other"],
            family_filter=None,
        )
        if other_cubes:
            set_allocated_cubes(
                "Other",
                "Arrow",
                "other_family_candidate",
                other_cubes,
                target_count=_LEGACY_ARROW_MODEL_TARGET_COUNTS["Other"],
                parent_name="Root",
            )

        for plate_name in ("UpPl", "DownPl", "LeftPl", "RightPl", "Sakura"):
            cubes = best_family_cubes(
                plate_name,
                parent_name="Root",
                wrapper_name=None,
                preferred_count=_LEGACY_ARROW_MODEL_TARGET_COUNTS[plate_name],
                family_filter=None,
            )
            if cubes:
                set_allocated_cubes(
                    plate_name,
                    "Arrow",
                    f"{plate_name.lower()}_root_family_candidate",
                    cubes,
                    target_count=_LEGACY_ARROW_MODEL_TARGET_COUNTS[plate_name],
                    parent_name="Root",
                )

        board_wrapper = _find_legacy_direct_wrapper_payload(section, "Board")
        if board_wrapper is not None:
            board_cubes = _decode_legacy_payload_cubes(
                board_wrapper[3],
                tex,
                bone_name="Board",
                bone_pivot=None,
                preferred_count=max(1, board_wrapper[1]),
            )
            if board_cubes:
                set_allocated_cubes(
                    "Board",
                    "Arrow",
                    "board_wrapper",
                    board_cubes,
                    target_count=_LEGACY_ARROW_MODEL_TARGET_COUNTS["Board"],
                    parent_name="Other",
                )
            board2_cubes = _decode_segmented_wrapper_payload_cubes(
                board_wrapper[3],
                tex,
                bone_name="Board2",
                bone_pivot=None,
                count=board_wrapper[1],
                kind=board_wrapper[2],
            )
            if board2_cubes:
                set_allocated_cubes(
                    "Board2",
                    "Arrow",
                    "board_segmented_wrapper",
                    board2_cubes,
                    target_count=_LEGACY_ARROW_MODEL_TARGET_COUNTS["Board2"],
                    parent_name="Board",
                )

        for name in ("Bowknot", "Bowknot2", "Bowknot3", "Bowknot4", "Bowknot5", "Brand"):
            cubes = best_family_cubes(
                name,
                parent_name="Other",
                wrapper_name=None,
                preferred_count=_LEGACY_ARROW_MODEL_TARGET_COUNTS[name],
                family_filter=None,
            )
            if cubes:
                set_allocated_cubes(
                    name,
                    "Arrow",
                    f"{name.lower()}_other_family_candidate",
                    cubes,
                    target_count=_LEGACY_ARROW_MODEL_TARGET_COUNTS[name],
                    parent_name="Other",
                )

    child_allocated_bone_hits = 0
    arm_child_allocations = 0
    for entry in bone_entries:
        source = entry.get("__compiled_cube_source")
        if not (isinstance(source, str) and source.startswith("allocated:")):
            continue
        child_allocated_bone_hits += 1
        family = source.split(":", 2)[1]
        if family in {"Arm", "Arrow"}:
            arm_child_allocations += 1

    if codec_format == 9 and asset_name == "arrow_model":
        bone_entries = [
            entry
            for entry in bone_entries
            if not isinstance(entry.get("name"), str)
            or entry.get("name") in _FORMAT9_ARROW_MODEL_KEEP_NAMES
        ]

    summary = _empty_child_allocation_summary()
    summary["child_allocated_bone_hits"] = child_allocated_bone_hits
    summary["repaired_parent_bones"] = repaired_parent_bones
    summary["arm_child_allocations"] = arm_child_allocations
    return bone_entries, summary


def _extract_uv_norm_hints(payload: bytes, limit: int = 24) -> tuple[float, ...]:
    vals: list[float] = []
    seen: set[float] = set()
    for off in range(0, len(payload) - 4, 4):
        f = struct.unpack_from("<f", payload, off)[0]
        if not math.isfinite(f):
            continue
        if not (-2.0 <= f <= 2.0):
            continue
        snapped = round(f * 256.0) / 256.0
        if abs(f - snapped) > 0.002:
            continue
        snapped = round(snapped, 6)
        if snapped in seen:
            continue
        seen.add(snapped)
        vals.append(snapped)
        if len(vals) >= limit:
            break
    return tuple(vals)


def _extract_legacy_direct_cube_records(
    payload: bytes,
    tex_size: tuple[int, int] | None,
) -> list[tuple[tuple[float, float, float], tuple[int, int]]]:
    if tex_size is None:
        return []
    tex_w, tex_h = tex_size
    out: list[tuple[tuple[float, float, float], tuple[int, int]]] = []
    seen: set[tuple[tuple[float, float, float], tuple[int, int]]] = set()
    for start in range(20):
        for off in range(start, len(payload) - 20, 20):
            x, y, z, u, v = struct.unpack_from("<5f", payload, off)
            if not all(math.isfinite(n) for n in (x, y, z, u, v)):
                continue
            if max(abs(x), abs(y), abs(z)) > 4.0:
                continue
            ui = int(round(u * tex_w))
            vi = int(round(v * tex_h))
            if abs((u * tex_w) - ui) > 0.05 or abs((v * tex_h) - vi) > 0.05:
                continue
            if not (0 <= ui <= tex_w and 0 <= vi <= tex_h):
                continue
            pos = (
                round(x * 16.0, 5),
                round(y * 16.0, 5),
                round(z * 16.0, 5),
            )
            rec = (pos, (ui, vi))
            if rec not in seen:
                seen.add(rec)
                out.append(rec)
    return out


def _normal_to_face(nx: float, ny: float, nz: float) -> str | None:
    if abs(abs(nx) - 1.0) < 1e-3 and abs(ny) < 1e-3 and abs(nz) < 1e-3:
        return "east" if nx > 0 else "west"
    if abs(abs(ny) - 1.0) < 1e-3 and abs(nx) < 1e-3 and abs(nz) < 1e-3:
        return "up" if ny > 0 else "down"
    if abs(abs(nz) - 1.0) < 1e-3 and abs(nx) < 1e-3 and abs(ny) < 1e-3:
        return "south" if nz > 0 else "north"
    return None


def _normalize3(vec: tuple[float, float, float]) -> tuple[float, float, float] | None:
    norm = math.sqrt(vec[0] * vec[0] + vec[1] * vec[1] + vec[2] * vec[2])
    if norm < 1e-6:
        return None
    return (vec[0] / norm, vec[1] / norm, vec[2] / norm)


def _cross3(a: tuple[float, float, float], b: tuple[float, float, float]) -> tuple[float, float, float]:
    return (
        a[1] * b[2] - a[2] * b[1],
        a[2] * b[0] - a[0] * b[2],
        a[0] * b[1] - a[1] * b[0],
    )


def _dot3(a: tuple[float, float, float], b: tuple[float, float, float]) -> float:
    return a[0] * b[0] + a[1] * b[1] + a[2] * b[2]


def _basis_from_face_pairs(
    group: list[tuple[tuple[float, float, float], list[tuple[float, float, float, float, float]]]],
) -> tuple[tuple[float, float, float], tuple[float, float, float], tuple[float, float, float]] | None:
    axes: list[tuple[float, float, float]] = []
    for a, b in ((0, 1), (2, 3), (4, 5)):
        na = _normalize3(group[a][0])
        nb = _normalize3(group[b][0])
        if na is None or nb is None or _dot3(na, nb) > -0.85:
            return None
        axes.append(na)
    u, v, w_hint = axes
    if abs(_dot3(u, v)) > 0.35:
        return None
    w = _normalize3(_cross3(u, v))
    if w is None:
        return None
    if _dot3(w, w_hint) < 0:
        w = (-w[0], -w[1], -w[2])
    v = _normalize3(_cross3(w, u))
    if v is None:
        return None
    return u, v, w


def _euler_deg_from_basis(
    u: tuple[float, float, float],
    v: tuple[float, float, float],
    w: tuple[float, float, float],
) -> tuple[float, float, float]:
    r00, r01, r02 = u[0], v[0], w[0]
    r10, r11, r12 = u[1], v[1], w[1]
    r20, r21, r22 = u[2], v[2], w[2]
    if abs(r20) < 0.999999:
        ry = math.asin(-r20)
        rx = math.atan2(r21, r22)
        rz = math.atan2(r10, r00)
    else:
        ry = math.pi / 2 if r20 <= -1 else -math.pi / 2
        rx = math.atan2(-r12, r11)
        rz = 0.0
    return (round(math.degrees(rx), 5), round(math.degrees(ry), 5), round(math.degrees(rz), 5))


def _parse_legacy_face_records(
    payload: bytes,
) -> list[tuple[tuple[float, float, float], list[tuple[float, float, float, float, float]]]]:
    quads: list[tuple[tuple[float, float, float], list[tuple[float, float, float, float, float]]]] = []
    off = 0
    while off + 92 <= len(payload):
        vals = struct.unpack_from("<23f", payload, off)
        normal = (vals[0], vals[1], vals[2])
        norm_len = math.sqrt(normal[0] * normal[0] + normal[1] * normal[1] + normal[2] * normal[2])
        if not (0.7 <= norm_len <= 1.3):
            break
        verts: list[tuple[float, float, float, float, float]] = []
        ok = True
        for i in range(4):
            x, y, z, u, v = vals[3 + i * 5 : 3 + (i + 1) * 5]
            if not all(math.isfinite(t) for t in (x, y, z, u, v)):
                ok = False
                break
            verts.append((x * 16.0, y * 16.0, z * 16.0, u, v))
        if not ok:
            break
        quads.append((normal, verts))
        off += 92
    return quads


def _iter_legacy_face_record_runs(
    payload: bytes,
    *,
    min_run: int = 6,
) -> list[list[tuple[tuple[float, float, float], list[tuple[float, float, float, float, float]]]]]:
    runs: list[list[tuple[tuple[float, float, float], list[tuple[float, float, float, float, float]]]]] = []
    seen: set[tuple[int, int]] = set()
    limit = len(payload) - 92
    for start in range(0, max(0, limit + 1), 4):
        if any(start >= a and start < b for a, b in seen):
            continue
        run = _parse_legacy_face_records(payload[start:])
        if len(run) < min_run:
            continue
        span = (start, start + len(run) * 92)
        seen.add(span)
        runs.append(run)
    runs.sort(key=len, reverse=True)
    return runs


def _build_legacy_face_quad_cubes(
    payload: bytes,
    tex_size: tuple[int, int] | None,
) -> list[dict[str, object]]:
    if tex_size is None:
        return []
    tex_w, tex_h = tex_size
    cubes: list[dict[str, object]] = []
    seen_keys: set[tuple[float, float, float, float, float, float]] = set()
    for quads in _iter_legacy_face_record_runs(payload, min_run=6):
        i = 0
        while i + 6 <= len(quads):
            group = quads[i : i + 6]
            if len(group) < 6:
                break
            # Prefer the common legacy pattern of 3 opposite face pairs.
            pair_dots = []
            for a, b in ((0, 1), (2, 3), (4, 5)):
                na = group[a][0]
                nb = group[b][0]
                pair_dots.append(na[0] * nb[0] + na[1] * nb[1] + na[2] * nb[2])
            if sum(1 for d in pair_dots if d < -0.85) < 2:
                i += 1
                continue

            face_map: dict[str, list[tuple[float, float, float, float, float]]] = {}
            for idx, (normal, verts) in enumerate(group):
                face = _normal_to_face(*normal)
                if face is None or face in face_map:
                    face = ("west", "east", "north", "south", "up", "down")[idx]
                face_map[face] = verts
            all_verts = [v for verts in face_map.values() for v in verts]
            basis = _basis_from_face_pairs(group)
            if basis is not None:
                u, v, w = basis
                proj_u = [_dot3((vert[0], vert[1], vert[2]), u) for vert in all_verts]
                proj_v = [_dot3((vert[0], vert[1], vert[2]), v) for vert in all_verts]
                proj_w = [_dot3((vert[0], vert[1], vert[2]), w) for vert in all_verts]
                min_u, max_u = min(proj_u), max(proj_u)
                min_v, max_v = min(proj_v), max(proj_v)
                min_w, max_w = min(proj_w), max(proj_w)
                size = [round(max_u - min_u, 5), round(max_v - min_v, 5), round(max_w - min_w, 5)]
                center_u = (min_u + max_u) * 0.5
                center_v = (min_v + max_v) * 0.5
                center_w = (min_w + max_w) * 0.5
                center = (
                    u[0] * center_u + v[0] * center_v + w[0] * center_w,
                    u[1] * center_u + v[1] * center_v + w[1] * center_w,
                    u[2] * center_u + v[2] * center_v + w[2] * center_w,
                )
                origin = [
                    round(center[0] - size[0] * 0.5, 5),
                    round(center[1] - size[1] * 0.5, 5),
                    round(center[2] - size[2] * 0.5, 5),
                ]
                pivot = [round(center[0], 5), round(center[1], 5), round(center[2], 5)]
                rotation = list(_euler_deg_from_basis(u, v, w))
            else:
                xs = [v[0] for v in all_verts]
                ys = [v[1] for v in all_verts]
                zs = [v[2] for v in all_verts]
                origin = [round(min(xs), 5), round(min(ys), 5), round(min(zs), 5)]
                size = [round(max(xs) - min(xs), 5), round(max(ys) - min(ys), 5), round(max(zs) - min(zs), 5)]
                pivot = None
                rotation = None
            if max(size) < 0.1 or min(size) < 0.01:
                i += 1
                continue
            key = tuple(round(v, 3) for v in (*origin, *size))
            if key in seen_keys:
                i += 6
                continue
            seen_keys.add(key)

            cube: dict[str, object] = {
                "origin": origin,
                "size": size,
                "uv": {},
            }
            if pivot is not None:
                cube["pivot"] = pivot
            if rotation is not None and any(abs(v) > 0.001 for v in rotation):
                cube["rotation"] = rotation
            uv_faces: dict[str, dict[str, list[int]]] = {}
            for face, verts in face_map.items():
                us = [v[3] * tex_w for v in verts]
                vs = [v[4] * tex_h for v in verts]
                min_u = int(round(min(us)))
                max_u = int(round(max(us)))
                min_v = int(round(min(vs)))
                max_v = int(round(max(vs)))
                width = max(1, max_u - min_u)
                height = max(1, max_v - min_v)
                if face == "down":
                    uv_faces[face] = {"uv": [min_u, max_v], "uv_size": [width, -height]}
                else:
                    uv_faces[face] = {"uv": [min_u, min_v], "uv_size": [width, height]}
            cube["uv"] = uv_faces
            cubes.append(cube)
            i += 6
    return cubes


def _legacy_cube_score(cube: dict[str, object]) -> float:
    size = cube.get("size", [0.0, 0.0, 0.0])
    if not isinstance(size, list) or len(size) != 3:
        return -1e9
    sx, sy, sz = (float(size[0]), float(size[1]), float(size[2]))
    max_dim = max(sx, sy, sz)
    min_dim = min(sx, sy, sz)
    volume = sx * sy * sz
    face_count = len(cube.get("uv", {}))
    score = face_count * 100.0
    score -= volume * 0.02
    score -= max(0.0, max_dim - 12.0) * 20.0
    if cube.get("rotation") is not None:
        score += 10.0
    if cube.get("pivot") is not None:
        score += 5.0
    if min_dim < 0.08:
        score -= 20.0
    return score


def _legacy_cube_center(cube: dict[str, object]) -> tuple[float, float, float] | None:
    origin = cube.get("origin")
    size = cube.get("size")
    if not isinstance(origin, list) or not isinstance(size, list):
        return None
    if len(origin) != 3 or len(size) != 3:
        return None
    return (
        float(origin[0]) + float(size[0]) * 0.5,
        float(origin[1]) + float(size[1]) * 0.5,
        float(origin[2]) + float(size[2]) * 0.5,
    )


def _filter_legacy_cubes(
    cubes: list[dict[str, object]],
    preferred_count: int = 1,
) -> list[dict[str, object]]:
    if not cubes:
        return cubes
    ranked = sorted(cubes, key=_legacy_cube_score, reverse=True)
    kept = [cube for cube in ranked if _legacy_cube_score(cube) >= 40.0]
    if not kept:
        kept = ranked[:1]
    target = max(1, preferred_count)
    if len(kept) < target:
        for cube in ranked:
            if cube in kept:
                continue
            size = cube.get("size", [0.0, 0.0, 0.0])
            if not isinstance(size, list) or len(size) != 3:
                continue
            max_dim = max(float(size[0]), float(size[1]), float(size[2]))
            min_dim = min(float(size[0]), float(size[1]), float(size[2]))
            score = _legacy_cube_score(cube)
            if max_dim > 24.0 or min_dim < 0.05 or score < -120.0:
                continue
            kept.append(cube)
            if len(kept) >= target:
                break
    return kept


def _direct_cube_face_records(
    records: list[tuple[tuple[float, float, float], tuple[int, int]]],
    bounds: tuple[float, float, float, float, float, float],
    face: str,
) -> list[tuple[tuple[float, float, float], tuple[int, int]]]:
    min_x, max_x, min_y, max_y, min_z, max_z = bounds
    out: list[tuple[tuple[float, float, float], tuple[int, int]]] = []
    for pos, uv in records:
        x, y, z = pos
        if face == "west" and abs(x - min_x) < 1e-4:
            out.append((pos, uv))
        elif face == "east" and abs(x - max_x) < 1e-4:
            out.append((pos, uv))
        elif face == "down" and abs(y - min_y) < 1e-4:
            out.append((pos, uv))
        elif face == "up" and abs(y - max_y) < 1e-4:
            out.append((pos, uv))
        elif face == "north" and abs(z - min_z) < 1e-4:
            out.append((pos, uv))
        elif face == "south" and abs(z - max_z) < 1e-4:
            out.append((pos, uv))
    return out


def _select_legacy_face_uv_rect(
    face_records: list[tuple[tuple[float, float, float], tuple[int, int]]],
    expect_w: float,
    expect_h: float,
) -> tuple[list[int], list[int]] | None:
    by_pos: dict[tuple[float, float, float], set[tuple[int, int]]] = {}
    for pos, uv in face_records:
        by_pos.setdefault(pos, set()).add(uv)
    if len(by_pos) != 4:
        return None
    choices = [sorted(list(v)) for v in by_pos.values()]
    if any(not c for c in choices):
        return None

    best: tuple[float, int, int, int, int] | None = None
    for combo in itertools.product(*choices):
        us = sorted({uv[0] for uv in combo})
        vs = sorted({uv[1] for uv in combo})
        if len(us) != 2 or len(vs) != 2:
            continue
        width = us[1] - us[0]
        height = vs[1] - vs[0]
        if width <= 0 or height <= 0:
            continue
        err = abs(width - expect_w) + abs(height - expect_h)
        area = width * height
        if best is None:
            best = (err, area, us[0], vs[0], width, height)
            continue
        best_err, best_area, *_rest = best
        if err < best_err or (abs(err - best_err) < 1e-6 and area > best_area):
            best = (err, area, us[0], vs[0], width, height)
    if best is None:
        return None
    return [best[2], best[3]], [best[4], best[5]]


def _build_legacy_direct_cube_from_records(
    records: list[tuple[tuple[float, float, float], tuple[int, int]]],
) -> tuple[dict[str, object], set[tuple[float, float, float]]] | None:
    from collections import Counter
    from itertools import combinations

    if len(records) < 8:
        return None

    x_counts = Counter(pos[0] for pos, _uv in records)
    y_counts = Counter(pos[1] for pos, _uv in records)
    z_counts = Counter(pos[2] for pos, _uv in records)
    x_vals = [v for v, _n in x_counts.most_common(8)]
    y_vals = [v for v, _n in y_counts.most_common(8)]
    z_vals = [v for v, _n in z_counts.most_common(8)]

    best_subset: list[tuple[tuple[float, float, float], tuple[int, int]]] | None = None
    best_score = -1.0
    best_bounds: tuple[float, float, float, float, float, float] | None = None
    for x_pair in combinations(x_vals, 2):
        for y_pair in combinations(y_vals, 2):
            for z_pair in combinations(z_vals, 2):
                min_x, max_x = sorted(x_pair)
                min_y, max_y = sorted(y_pair)
                min_z, max_z = sorted(z_pair)
                size_x = abs(max_x - min_x)
                size_y = abs(max_y - min_y)
                size_z = abs(max_z - min_z)
                if min(size_x, size_y, size_z) <= 0.0 or max(size_x, size_y, size_z) > 12.0:
                    continue
                subset = [
                    rec
                    for rec in records
                    if rec[0][0] in x_pair and rec[0][1] in y_pair and rec[0][2] in z_pair
                ]
                uniq_pos = {pos for pos, _uv in subset}
                if len(uniq_pos) < 8:
                    continue
                volume = size_x * size_y * size_z
                score = len(subset) + len(uniq_pos) * 4 - volume * 0.35
                if score > best_score:
                    best_score = score
                    best_subset = subset
                    best_bounds = (min_x, max_x, min_y, max_y, min_z, max_z)

    if best_subset is None or best_bounds is None:
        return None

    min_x, max_x, min_y, max_y, min_z, max_z = best_bounds
    uv_faces: dict[str, dict[str, list[int]]] = {}
    size_x = abs(max_x - min_x)
    size_y = abs(max_y - min_y)
    size_z = abs(max_z - min_z)
    face_expect = {
        "north": (size_x, size_y),
        "south": (size_x, size_y),
        "east": (size_z, size_y),
        "west": (size_z, size_y),
        "up": (size_x, size_z),
        "down": (size_x, size_z),
    }
    for face in ("north", "east", "south", "west", "up", "down"):
        face_records = _direct_cube_face_records(best_subset, best_bounds, face)
        exp_w, exp_h = face_expect[face]
        rect = _select_legacy_face_uv_rect(face_records, exp_w, exp_h)
        if rect is None:
            continue
        uv0, size = rect
        width, height = size
        if face == "down":
            uv_faces[face] = {"uv": [uv0[0], uv0[1] + height], "uv_size": [width, -height]}
        else:
            uv_faces[face] = {"uv": uv0, "uv_size": [width, height]}
    if len(uv_faces) < 4:
        return None

    cube = {
        "origin": [min_x, min_y, min_z],
        "size": [round(size_x, 5), round(size_y, 5), round(size_z, 5)],
        "uv": uv_faces,
    }
    return cube, {pos for pos, _uv in best_subset}


def _build_legacy_direct_cubes(
    payload: bytes,
    tex_size: tuple[int, int] | None,
    *,
    preferred_count: int,
) -> list[dict[str, object]]:
    records = _extract_legacy_direct_cube_records(payload, tex_size)
    if len(records) < 16:
        return []
    remaining = list(records)
    cubes: list[dict[str, object]] = []
    seen_keys: set[tuple[float, float, float, float, float, float]] = set()
    target = max(4, min(max(1, preferred_count), 16))
    while len(remaining) >= 8 and len(cubes) < target:
        selected = _build_legacy_direct_cube_from_records(remaining)
        if selected is None:
            break
        cube, used_positions = selected
        key = tuple(round(v, 3) for v in (*cube["origin"], *cube["size"]))
        if key in seen_keys:
            break
        seen_keys.add(key)
        cubes.append(cube)
        next_remaining = [rec for rec in remaining if rec[0] not in used_positions]
        if len(next_remaining) == len(remaining):
            break
        remaining = next_remaining
    return cubes


def _filter_format15_entry_cubes(
    entry: dict[str, object],
    *,
    pivot_override: object | None = None,
) -> None:
    cubes = entry.get("cubes")
    if not isinstance(cubes, list) or not cubes:
        return
    entry["cubes"] = _filter_format15_cube_list(
        cubes,
        bone_name=str(entry.get("name", "")),
        pivot=entry.get("pivot") if pivot_override is None else pivot_override,
        enforce_pivot_distance=_format15_entry_enforces_pivot_distance(entry),
    )
    if not entry["cubes"]:
        entry.pop("cubes", None)


def _format15_entry_enforces_pivot_distance(entry: dict[str, object]) -> bool:
    decode_mode = entry.get("__compiled_cube_decode_mode")
    source = entry.get("__compiled_cube_source")
    if decode_mode in {"child_allocated", "segmented_wrapper_records"}:
        return False
    if source in {
        "typed:local_nested_visible",
        "typed:container_slice_visible",
        "fallback:same_visible_name",
    }:
        return False
    return True


def _best_format15_filter_context(
    entry: dict[str, object],
    by_name: dict[str, dict[str, object]],
) -> list[dict[str, object]]:
    cubes = entry.get("cubes")
    if not isinstance(cubes, list) or not cubes:
        return []
    pivot_options: list[object] = [entry.get("pivot")]
    parent_name = entry.get("parent")
    if isinstance(parent_name, str):
        parent_entry = by_name.get(parent_name)
        if parent_entry is not None:
            pivot_options.append(parent_entry.get("pivot"))
    anchor_name = entry.get("__compiled_cube_anchor_name")
    if isinstance(anchor_name, str):
        anchor_entry = by_name.get(anchor_name)
        if anchor_entry is not None:
            pivot_options.append(anchor_entry.get("pivot"))
    best = _filter_format15_cube_list(
        cubes,
        bone_name=str(entry.get("name", "")),
        pivot=entry.get("pivot"),
        enforce_pivot_distance=_format15_entry_enforces_pivot_distance(entry),
    )
    for pivot_option in pivot_options[1:]:
        candidate = _filter_format15_cube_list(
            cubes,
            bone_name=str(entry.get("name", "")),
            pivot=pivot_option,
            enforce_pivot_distance=_format15_entry_enforces_pivot_distance(entry),
        )
        if len(candidate) > len(best):
            best = candidate
    return best


def _filter_format15_cube_list(
    cubes: list[dict[str, object]],
    *,
    bone_name: str,
    pivot: object,
    enforce_pivot_distance: bool = True,
) -> list[dict[str, object]]:
    pivot_xyz: tuple[float, float, float] | None = None
    if isinstance(pivot, list) and len(pivot) == 3:
        try:
            pivot_xyz = (float(pivot[0]), float(pivot[1]), float(pivot[2]))
        except Exception:
            pivot_xyz = None

    kept: list[dict[str, object]] = []
    for cube in cubes:
        size = cube.get("size")
        if not isinstance(size, list) or len(size) != 3:
            continue

        sx, sy, sz = (float(size[0]), float(size[1]), float(size[2]))
        if sx <= 0.0 or sy <= 0.0 or sz <= 0.0:
            continue

        max_dim = max(sx, sy, sz)
        if max_dim > 20.0:
            continue

        if abs(sx * sy * sz) > 2000.0:
            continue

        if (
            enforce_pivot_distance
            and pivot_xyz is not None
            and bone_name not in _FORMAT15_TORSO_CONTAINER_ANCHORS
        ):
            center = _legacy_cube_center(cube)
            if center is not None:
                dist = math.sqrt(
                    (center[0] - pivot_xyz[0]) ** 2
                    + (center[1] - pivot_xyz[1]) ** 2
                    + (center[2] - pivot_xyz[2]) ** 2
                )
                if dist > max(18.0, max_dim * 1.75):
                    continue

        kept.append(cube)
    return kept


def _refine_legacy_bone_cubes(
    bone_name: str,
    bone_pivot: tuple[float, float, float] | None,
    cubes: list[dict[str, object]],
) -> list[dict[str, object]]:
    if not cubes or bone_pivot is None:
        return cubes
    if bone_name not in {"Head", "UpperBody"}:
        return cubes

    refined: list[dict[str, object]] = []
    for cube in cubes:
        center = _legacy_cube_center(cube)
        size = cube.get("size", [0.0, 0.0, 0.0])
        if center is None or not isinstance(size, list) or len(size) != 3:
            refined.append(cube)
            continue
        dist = math.sqrt(
            (center[0] - bone_pivot[0]) ** 2
            + (center[1] - bone_pivot[1]) ** 2
            + (center[2] - bone_pivot[2]) ** 2
        )
        max_dim = max(float(size[0]), float(size[1]), float(size[2]))
        if dist > 15.0 and max_dim > 20.0:
            continue
        refined.append(cube)
    if not refined:
        refined = cubes[:1]
    return refined


def _build_legacy_direct_one_cube(
    payload: bytes,
    tex_size: tuple[int, int] | None,
) -> dict[str, object] | None:
    records = _extract_legacy_direct_cube_records(payload, tex_size)
    selected = _build_legacy_direct_cube_from_records(records)
    return None if selected is None else selected[0]


def _extract_legacy_model_bones(
    section: bytes,
    names: tuple[str, ...],
    *,
    codec_format: int | None,
) -> list[LegacyModelBoneInfo]:
    hits = _iter_len_prefixed_names(section)
    valid = set(names)
    first_hit: dict[str, int] = {}
    for off, name in hits:
        if name in valid and name not in first_hit:
            first_hit[name] = off

    parent_map: dict[str, str] = {}
    for off, parent in hits:
        if parent not in valid:
            continue
        nxt = off + 1 + len(parent) + 1
        if nxt >= len(section):
            continue
        child_len = section[nxt]
        child_end = nxt + 1 + child_len
        if not (1 <= child_len <= 32 and child_end < len(section) and section[child_end] == 0):
            continue
        try:
            child = section[nxt + 1:child_end].decode("ascii")
        except UnicodeDecodeError:
            continue
        if child in valid and child != parent and child not in parent_map:
            parent_map[child] = parent

    cube_count_guess: dict[str, int] = {}
    for off, name in hits:
        if not name.startswith("M"):
            continue
        visible = name[1:]
        if visible not in valid:
            continue
        second = section.find(bytes([len(name)]) + name.encode("ascii"), off + 1)
        if second < 0:
            continue
        data_off = second + 1 + len(name)
        if data_off < len(section) and section[data_off] == 0:
            data_off += 1
        if data_off + 2 > len(section):
            continue
        count = section[data_off]
        record_kind = section[data_off + 1]
        if 0 <= count <= 0x40 and record_kind in (0x05, 0x06, 0x07):
            cube_count_guess[visible] = count

    out: list[LegacyModelBoneInfo] = []
    for name in names:
        off = first_hit.get(name)
        pivot = _read_legacy_pivot(section, off, name) if off is not None else None
        wrapper_name = None
        uv_norm_hints: tuple[float, ...] = ()
        wrapper = _find_legacy_wrapper_payload(section, name)
        if wrapper is None and _LEGACY_WRAPPER_NAME_RE.fullmatch(name):
            wrapper = _find_legacy_wrapper_payload_by_wrapper(section, name)
        if wrapper is None:
            wrapper = _find_legacy_visible_payload_same_name(section, name)
        if wrapper is not None:
            wrapper_name, count, _kind, payload = wrapper
            if name not in cube_count_guess:
                cube_count_guess[name] = count
            uv_norm_hints = _extract_uv_norm_hints(payload)
        out.append(
            LegacyModelBoneInfo(
                name=name,
                parent=parent_map.get(name),
                pivot=pivot,
                cube_count_guess=cube_count_guess.get(name),
                wrapper_name=wrapper_name,
                uv_norm_hints=uv_norm_hints,
            )
        )
    existing = {bone.name for bone in out}
    if codec_format == 15:
        wrapper_names = [name for _off, name in hits if _LEGACY_WRAPPER_NAME_RE.fullmatch(name)]
        for wrapper_name in dict.fromkeys(wrapper_names):
            if len(wrapper_name) >= 2 and wrapper_name[1].isdigit():
                visible = wrapper_name
            elif wrapper_name.startswith("MM"):
                visible = wrapper_name
            elif re.search(r"M[0-9]+$", wrapper_name):
                visible = wrapper_name
            else:
                visible = wrapper_name[1:]
            if not visible or visible in existing:
                continue
            wrapper = _find_legacy_wrapper_payload_by_wrapper(section, wrapper_name)
            if wrapper is None:
                continue
            _wname, count, _kind, payload = wrapper
            if count <= 0:
                continue
            if not _build_legacy_face_quad_cubes(payload, (256, 128)):
                continue
            if visible in {"M2", "M3", "M4", "M5", "MM1", "FM1", "FM2"} or re.search(r"(Left|Right)M[0-9]+$", visible):
                parent = "Head"
            else:
                parent = "Head" if any(tok in visible for tok in ("Left", "Right", "H", "F", "G", "J")) else "AllBody"
            out.append(
                LegacyModelBoneInfo(
                    name=visible,
                    parent=parent,
                    pivot=None,
                    cube_count_guess=count,
                    wrapper_name=wrapper_name,
                    uv_norm_hints=_extract_uv_norm_hints(payload),
                )
            )
    return out


def _repair_legacy_bone_parents(
    bones: list[LegacyModelBoneInfo],
    *,
    codec_format: int | None,
) -> list[LegacyModelBoneInfo]:
    by_name = {bone.name: bone for bone in bones}
    repaired: list[LegacyModelBoneInfo] = []
    for bone in bones:
        parent = bone.parent
        if parent is None:
            if bone.name == "UpperBody" and "AllBody" in by_name:
                parent = "AllBody"
            elif bone.name == "Head" and "UpperBody" in by_name:
                parent = "UpperBody"
            elif bone.name == "Arm" and "UpperBody" in by_name:
                parent = "UpperBody"
            elif bone.name == "LongHair" and "MLongHair" in by_name:
                parent = "MLongHair"
            elif bone.name == "LongHair2" and "LongHair" in by_name:
                parent = "LongHair"
            elif bone.name == "LongLeftHair" and "MLongLeftHair" in by_name:
                parent = "MLongLeftHair"
            elif bone.name == "LongLeftHair2" and "LongLeftHair" in by_name:
                parent = "LongLeftHair"
            elif bone.name == "LongRightHair" and "MLongRightHair" in by_name:
                parent = "MLongRightHair"
            elif bone.name == "LongRightHair2" and "LongRightHair" in by_name:
                parent = "LongRightHair"
            elif bone.name == "BaseHair" and "Hair" in by_name:
                parent = "Hair"
            elif bone.name == "bone5" and "BaseHair" in by_name:
                parent = "BaseHair"
            elif bone.name in {"Left_ear", "Right_ear"} and "Ear" in by_name:
                parent = "Ear"
            elif bone.name == "Mask" and "Head" in by_name:
                parent = "Head"
            elif bone.name in {"kongju", "jingya", "xiao", "weixiao"} and "Mouth" in by_name:
                parent = "Mouth"
            elif bone.name in {"LeftArm", "RightArm"} and "Arm" in by_name:
                parent = "Arm"
            elif bone.name == "LeftForeArm" and "LeftArm" in by_name:
                parent = "LeftArm"
            elif bone.name == "RightForeArm" and "RightArm" in by_name:
                parent = "RightArm"
            elif bone.name == "LeftHand" and "LeftForeArm" in by_name:
                parent = "LeftForeArm"
            elif bone.name == "RightHand" and "RightForeArm" in by_name:
                parent = "RightForeArm"
            elif bone.name == "FM" and "FrontClothe" in by_name:
                parent = "FrontClothe"
            elif bone.name == "FM1" and "FM" in by_name:
                parent = "FM"
            elif bone.name == "FM2" and "FM1" in by_name:
                parent = "FM1"
            elif bone.name == "RightEyelidBase" and "RightEyelid" in by_name:
                parent = "RightEyelid"
            elif bone.name == "RightEyeDot" and "RightEyelidBase" in by_name:
                parent = "RightEyelidBase"
            elif codec_format == 15:
                m = re.fullmatch(r"([HFGJ](?:Left|Right)M)(\d+)", bone.name)
                if m is not None:
                    prefix, idx_text = m.groups()
                    idx = int(idx_text)
                    anchor = f"{prefix}1"
                    if idx >= 2 and anchor in by_name:
                        parent = anchor
                    elif "Head" in by_name:
                        parent = "Head"
                elif bone.name == "FM2" and "FM1" in by_name:
                    parent = "FM1"
                elif bone.name in {"FM1", "MM1"} and "Head" in by_name:
                    parent = "Head"
                elif re.fullmatch(r"M[2-9]\d*", bone.name) and "Head" in by_name:
                    parent = "Head"
        if parent == bone.parent:
            repaired.append(bone)
        else:
            repaired.append(
                LegacyModelBoneInfo(
                    name=bone.name,
                    parent=parent,
                    pivot=bone.pivot,
                    cube_count_guess=bone.cube_count_guess,
                    wrapper_name=bone.wrapper_name,
                    uv_norm_hints=bone.uv_norm_hints,
                )
            )
    return repaired


def _prune_format15_main_model_bones(bones: list[LegacyModelBoneInfo]) -> list[LegacyModelBoneInfo]:
    by_name = {bone.name: bone for bone in bones}
    family_counts = Counter(_legacy_name_family_key(name) for name in by_name)
    arrow_names = {
        "UpPl", "DownPl", "LeftPl", "RightPl", "Other",
        "Bowknot", "Bowknot2", "Bowknot3", "Bowknot4", "Bowknot5",
        "Board", "Board2", "Brand", "Sakura",
    }
    noise_names = {"M", "geometry.unknown", "LeftWaistLocator2", "SheathLocator2", "attacked", "boat", "climb", "climbing", "elytra_fly", "fly"}
    core_tokens = ("Root", "Body", "Head", "Hair", "Arm", "Leg", "Hand", "Foot", "Eye", "Brow", "Ear", "Tail", "Wing", "Ribbon", "Skirt", "Sleeve", "Clothe", "Mask", "Waist", "Locator", "bow", "gui", "FOX", "Mouth")
    family_re = re.compile(r"(?:[A-Z]{2,3}\d{0,2}|FFM\d(?:_\d)?|[LR][BFM]\d{0,2}|[FB][LRM]\d{0,2}|LM\d{0,2}|RM\d{0,2}|FM\d{0,2})$")
    kept: list[LegacyModelBoneInfo] = []
    for bone in bones:
        name = bone.name
        if name in noise_names or name in arrow_names:
            continue
        if name.startswith(("ysm.", "query.", "math.")):
            continue
        keep = False
        if bone.wrapper_name is not None or bone.cube_count_guess is not None or bone.parent is not None:
            keep = True
        if bone.pivot is not None and (
            any(tok in name for tok in core_tokens)
            or "_" in name
            or any(ch.islower() for ch in name)
            or family_counts[_legacy_name_family_key(name)] >= 2
            or family_re.fullmatch(name) is not None
        ):
            keep = True
        if name.startswith("M") and len(name) > 1 and name[1:] in by_name:
            keep = True
        if keep:
            kept.append(bone)
    return kept or bones


def _prune_legacy_model_bones(
    bones: list[LegacyModelBoneInfo],
    *,
    codec_format: int | None,
    asset_name: str | None,
) -> list[LegacyModelBoneInfo]:
    if codec_format == 9 and asset_name in {"main_model", "arrow_model"}:
        return bones
    if len(bones) <= 96:
        return bones
    by_name = {bone.name: bone for bone in bones}
    keep: set[str] = set()
    for bone in bones:
        if bone.wrapper_name is not None or bone.cube_count_guess is not None:
            keep.add(bone.name)
        if bone.parent is not None:
            keep.add(bone.name)
            keep.add(bone.parent)
        if bone.pivot is not None and any(tok in bone.name for tok in _LEGACY_BONE_NAME_HINTS):
            keep.add(bone.name)
    changed = True
    while changed:
        changed = False
        for name in tuple(keep):
            bone = by_name.get(name)
            if bone and bone.parent and bone.parent not in keep:
                keep.add(bone.parent)
                changed = True
    pruned = [bone for bone in bones if bone.name in keep]
    return pruned or bones


def _legacy_model_identifier(section: bytes) -> str:
    m = re.search(rb"geometry\.[A-Za-z0-9_.-]+", section)
    if m is None:
        return "geometry.unknown"
    return m.group().decode("ascii", "replace")


def _legacy_model_texture_size(asset_name: str | None) -> tuple[int, int] | None:
    if asset_name in ("main_model", "arm_model"):
        return (256, 256)
    if asset_name == "arrow_model":
        return (64, 64)
    return None


def _format9_model_names(section: bytes, asset_name: str | None) -> tuple[str, ...]:
    names = tuple(dict.fromkeys(name for _off, name in _iter_len_prefixed_names(section)))
    if not names:
        names = tuple(dict.fromkeys(_extract_names(section, limit=256)))
        if not names:
            return tuple()
    if asset_name == "main_model":
        return tuple(name for name in names if name not in _FORMAT9_MAIN_MODEL_EXCLUDE_NAMES)
    if asset_name == "arm_model":
        broad = tuple(dict.fromkeys(_extract_names(section, limit=256)))
        return tuple(name for name in broad if name in _FORMAT9_ARM_MODEL_KEEP_NAMES)
    if asset_name == "arrow_model":
        broad = tuple(dict.fromkeys(_extract_names(section, limit=256)))
        keep_hits = sum(name in _FORMAT9_ARROW_MODEL_KEEP_NAMES for name in broad)
        if keep_hits >= 3:
            return tuple(name for name in broad if name in _FORMAT9_ARROW_MODEL_KEEP_NAMES)
        filtered: list[str] = []
        seen: set[str] = set()
        for name in broad:
            if name in _FORMAT9_ARROW_MODEL_EXCLUDE_NAMES:
                continue
            if name.startswith(("math.", "query.", "ysm.", "v.")):
                continue
            if "." in name or "-" in name:
                continue
            if re.fullmatch(r"[A-Z0-9]{2,5}", name):
                continue
            if name not in seen:
                seen.add(name)
                filtered.append(name)
        return tuple(filtered)
    return names


def _format9_arrow_signature_score(section: bytes) -> int:
    return sum(name.encode("ascii") in section for name in _FORMAT9_ARROW_MODEL_KEEP_NAMES)


def _select_format9_arrow_section(scan: LegacyScanResult, decoded: bytes) -> LegacySection | None:
    best: LegacySection | None = None
    best_key: tuple[int, int, int] | None = None
    for idx, sec in enumerate(scan.sections):
        section_bytes = decoded[sec.start:sec.end]
        score = _format9_arrow_signature_score(section_bytes)
        if score <= 0:
            continue
        prefer = 1 if sec.asset_guess != "main_model" else 0
        key = (prefer, score, -sec.size)
        if best_key is None or key > best_key:
            best = sec
            best_key = key
    if best_key is None:
        return None
    if best_key[1] < 3:
        return None
    return best


def _legacy_model_name_hit_score(
    section: bytes,
    *,
    asset_name: str | None,
    codec_format: int | None,
) -> int:
    if asset_name == "arm_model":
        names = tuple(sorted(_FORMAT9_ARM_MODEL_KEEP_NAMES))
    elif asset_name == "arrow_model":
        names = tuple(sorted(_FORMAT9_ARROW_MODEL_KEEP_NAMES))
    else:
        return 0
    discovered_names = set(_format15_model_names(section) if codec_format == 15 else _format9_model_names(section, asset_name))
    return sum(160 for name in names if name in discovered_names)


def _legacy_model_payload_hit_score(
    section: bytes,
    *,
    asset_name: str | None,
    codec_format: int | None,
) -> int:
    del codec_format
    if asset_name == "arm_model":
        names = tuple(sorted(_FORMAT9_ARM_MODEL_KEEP_NAMES))
    elif asset_name == "arrow_model":
        names = tuple(sorted(_FORMAT9_ARROW_MODEL_KEEP_NAMES))
    else:
        return 0
    score = 0
    for name in names:
        candidate = (
            _find_legacy_wrapper_payload(section, name)
            or _find_legacy_visible_payload_same_name(section, name)
        )
        if candidate is None:
            continue
        score += 100 + min(int(candidate[1]), 32)
    return score


def _select_legacy_model_source_section(
    scan: LegacyScanResult,
    decoded: bytes,
    *,
    current_index: int,
    asset_name: str | None,
    codec_format: int | None,
) -> tuple[int, LegacySection]:
    current = scan.sections[current_index]
    if codec_format not in (9, 15) or asset_name not in {"arm_model", "arrow_model"}:
        return current_index, current

    current_payload_score = _legacy_model_payload_hit_score(
        decoded[current.start : current.end],
        asset_name=asset_name,
        codec_format=codec_format,
    )
    current_name_score = _legacy_model_name_hit_score(
        decoded[current.start : current.end],
        asset_name=asset_name,
        codec_format=codec_format,
    )
    current_exact = 1 if current.asset_guess == asset_name else 0
    best_index = current_index
    best_section = current
    prefer_exact_first = bool(current_exact and current_payload_score > 0)
    if prefer_exact_first:
        best_key = (current_exact, current_payload_score, current_name_score, current.size)
    else:
        best_key = (current_payload_score, current_name_score, current_exact, current.size)
    for idx, sec in enumerate(scan.sections):
        if sec.kind_guess != "model":
            continue
        section_bytes = decoded[sec.start : sec.end]
        payload_score = _legacy_model_payload_hit_score(
            section_bytes,
            asset_name=asset_name,
            codec_format=codec_format,
        )
        name_score = _legacy_model_name_hit_score(
            section_bytes,
            asset_name=asset_name,
            codec_format=codec_format,
        )
        exact = 1 if sec.asset_guess == asset_name else 0
        key = (
            (exact, payload_score, name_score, sec.size)
            if prefer_exact_first
            else (payload_score, name_score, exact, sec.size)
        )
        if key > best_key:
            best_index = idx
            best_section = sec
            best_key = key

    if best_key[0] <= 0 and codec_format == 9 and asset_name == "arrow_model":
        fallback = _select_format9_arrow_section(scan, decoded)
        if fallback is not None:
            fallback_index = next(
                (idx for idx, sec in enumerate(scan.sections) if sec == fallback),
                current_index,
            )
            return fallback_index, fallback
    return best_index, best_section


def _pivot_lists_close(a: object, b: object, *, tol: float = 1e-4) -> bool:
    if not (isinstance(a, list) and isinstance(b, list) and len(a) == 3 and len(b) == 3):
        return False
    try:
        return all(abs(float(x) - float(y)) <= tol for x, y in zip(a, b))
    except Exception:
        return False


def _cubes_equal(a: object, b: object) -> bool:
    if not (isinstance(a, list) and isinstance(b, list)):
        return False
    try:
        return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    except Exception:
        return False


def _collapse_redundant_wrapper_bones(
    bone_entries: list[dict[str, object]],
    *,
    preserve_names: set[str] | None = None,
) -> list[dict[str, object]]:
    by_name = {str(entry.get("name")): entry for entry in bone_entries if isinstance(entry.get("name"), str)}
    referenced_parents = {
        str(entry.get("parent"))
        for entry in bone_entries
        if isinstance(entry.get("parent"), str)
    }
    drop: set[str] = set()
    preserve = preserve_names or set()
    for entry in bone_entries:
        name = entry.get("name")
        if not isinstance(name, str) or not name.startswith("M") or len(name) < 2:
            continue
        if name in preserve or name in referenced_parents:
            continue
        visible = name[1:]
        other = by_name.get(visible)
        if other is None:
            continue
        cubes_a = entry.get("cubes")
        cubes_b = other.get("cubes")
        pivot_a = entry.get("pivot")
        pivot_b = other.get("pivot")
        redundant = False
        if cubes_a in (None, []):
            redundant = True
        elif cubes_b not in (None, []) and _pivot_lists_close(pivot_a, pivot_b) and _cubes_equal(cubes_a, cubes_b):
            redundant = True
        if not redundant:
            continue
        parent = entry.get("parent")
        if isinstance(parent, str):
            if other.get("parent") in (None, name):
                other["parent"] = parent
        drop.add(name)

    if not drop:
        return bone_entries

    collapsed: list[dict[str, object]] = []
    for entry in bone_entries:
        name = entry.get("name")
        if isinstance(name, str) and name in drop:
            continue
        parent = entry.get("parent")
        visited: set[str] = set()
        while isinstance(parent, str) and parent in drop and parent not in visited:
            visited.add(parent)
            parent = by_name.get(parent, {}).get("parent")
        if isinstance(parent, str):
            entry["parent"] = parent
        else:
            entry.pop("parent", None)
        collapsed.append(entry)
    return collapsed


def _apply_legacy_precision_guards(
    bone_entries: list[dict[str, object]],
    *,
    asset_name: str | None,
) -> tuple[list[dict[str, object]], dict[str, int]]:
    if asset_name != "main_model":
        return bone_entries, {
            "fanout_group_rejections": 0,
            "container_parent_rejections": 0,
        }

    by_name = {
        str(entry.get("name")): entry
        for entry in bone_entries
        if isinstance(entry.get("name"), str)
    }
    children_by_parent: dict[str, list[str]] = {}
    for entry in bone_entries:
        name = entry.get("name")
        parent = entry.get("parent")
        if isinstance(name, str) and isinstance(parent, str):
            children_by_parent.setdefault(parent, []).append(name)

    fanout_group_rejections = 0
    named_follow_groups: dict[tuple[str, str], list[dict[str, object]]] = {}
    for entry in bone_entries:
        if not entry.get("cubes"):
            continue
        name = entry.get("name")
        decode_mode = entry.get("__compiled_cube_decode_mode")
        if (
            isinstance(name, str)
            and name in _LEGACY_SEGMENTED_WRAPPER_ALLOW_BONES
            and decode_mode == "segmented_wrapper_records"
        ):
            continue
        source = entry.get("__compiled_cube_source")
        anchor = entry.get("__compiled_cube_anchor_name")
        payload = entry.get("__compiled_cube_payload_name")
        if source != "typed:local_named_follow":
            continue
        if not (isinstance(anchor, str) and isinstance(payload, str)):
            continue
        if anchor != payload:
            continue
        named_follow_groups.setdefault((anchor, payload), []).append(entry)

    for (_anchor, _payload), group in named_follow_groups.items():
        if len(group) <= 1:
            continue
        for entry in group:
            if entry.pop("cubes", None) is not None:
                entry["__compiled_cube_rejected_reason"] = "fanout_local_named_follow"
                fanout_group_rejections += 1

    container_parent_rejections = 0
    container_sources = {
        "typed:local_named_follow",
        "fallback:wrapper_name",
        "fallback:same_visible_name",
        "fallback:parent_linked",
    }
    for entry in bone_entries:
        if not entry.get("cubes"):
            continue
        name = entry.get("name")
        source = entry.get("__compiled_cube_source")
        anchor = entry.get("__compiled_cube_anchor_name")
        payload = entry.get("__compiled_cube_payload_name")
        parent = entry.get("parent")
        wrapper = entry.get("__compiled_wrapper_name")
        decode_mode = entry.get("__compiled_cube_decode_mode")
        if not (isinstance(name, str) and isinstance(source, str)):
            continue
        if (
            name in _LEGACY_SEGMENTED_WRAPPER_ALLOW_BONES
            and decode_mode == "segmented_wrapper_records"
        ):
            continue
        children = children_by_parent.get(name, ())
        if len(children) < 2:
            continue
        is_container_source = source in container_sources
        if (
            not is_container_source
            and source == "typed:local_nested_visible"
            and isinstance(anchor, str)
            and isinstance(payload, str)
            and isinstance(parent, str)
            and anchor == parent
        ):
            relation_names = {name, parent}
            if isinstance(wrapper, str):
                relation_names.add(wrapper)
            if payload not in relation_names:
                is_container_source = True
        if not is_container_source:
            continue
        child_support = 0
        for child_name in children:
            child = by_name.get(child_name)
            if child is None:
                continue
            if (
                child.get("__compiled_cube_count_guess") is not None
                or child.get("__compiled_wrapper_name") is not None
                or child.get("cubes")
            ):
                child_support += 1
        if child_support < 2:
            continue
        if entry.pop("cubes", None) is not None:
            entry["__compiled_cube_rejected_reason"] = "multi_child_container_source"
            container_parent_rejections += 1

    return bone_entries, {
        "fanout_group_rejections": fanout_group_rejections,
        "container_parent_rejections": container_parent_rejections,
    }


def _build_legacy_model_canonical_json(
    asset_name: str | None,
    section: bytes,
    names: tuple[str, ...],
    *,
    codec_format: int | None,
    geometry_section: bytes | None = None,
) -> dict[str, object]:
    decode_section = section if geometry_section is None else geometry_section
    # The section manifest keeps only a short preview of names; the full model
    # parser should re-scan the whole section so wrappers like MHead are not lost.
    if codec_format == 9:
        format9_names = _format9_model_names(section, asset_name)
        if format9_names:
            names = format9_names
        else:
            rich_names = tuple(dict.fromkeys(_extract_names(section, limit=256)))
            if rich_names:
                names = rich_names
    elif codec_format == 15:
        format15_names = _format15_model_names(section)
        if format15_names:
            names = format15_names
    else:
        rich_names = tuple(dict.fromkeys(_extract_names(section, limit=256)))
        if rich_names:
            names = rich_names
    bones = _extract_legacy_model_bones(section, names, codec_format=codec_format)
    bones = _repair_legacy_bone_parents(bones, codec_format=codec_format)
    if codec_format == 15 and asset_name == "main_model":
        bones = _prune_format15_main_model_bones(bones)
    else:
        bones = _prune_legacy_model_bones(bones, codec_format=codec_format, asset_name=asset_name)
    tex = _legacy_model_texture_size(asset_name)
    bone_entries: list[dict[str, object]] = []
    for bone in bones:
        entry: dict[str, object] = {"name": bone.name}
        if bone.parent:
            entry["parent"] = bone.parent
        if bone.pivot is not None:
            entry["pivot"] = list(bone.pivot)
        if bone.cube_count_guess is not None:
            entry["__compiled_cube_count_guess"] = bone.cube_count_guess
        if bone.wrapper_name is not None:
            entry["__compiled_wrapper_name"] = bone.wrapper_name
        if bone.uv_norm_hints:
            entry["__compiled_uv_norm_hints"] = list(bone.uv_norm_hints)
        candidate_rank = _rank_legacy_model_bone_payloads(
            decode_section,
            bone_name=bone.name,
            parent_name=bone.parent,
            wrapper_name=bone.wrapper_name,
        )
        best_candidate_meta: tuple[str, str, str, int, str] | None = None
        best_candidate_cubes: list[dict[str, object]] = []
        best_candidate_key: tuple[int, int, int, int, int, int, int] | None = None
        for candidate in candidate_rank:
            cubes, candidate_meta = _decode_legacy_model_candidate_cubes(
                decode_section,
                candidate,
                bone_name=bone.name,
                bone_pivot=bone.pivot,
                wrapper_name=bone.wrapper_name,
                preferred_count=max(1, bone.cube_count_guess or 1),
                codec_format=codec_format,
                tex=tex,
            )
            if codec_format == 15 and asset_name == "main_model" and cubes:
                cubes = _filter_format15_cube_list(
                    cubes,
                    bone_name=bone.name,
                    pivot=list(bone.pivot) if bone.pivot is not None else None,
                )
            key = (
                1 if cubes else 0,
                len(cubes),
                *_legacy_typed_payload_candidate_score(
                    candidate,
                    bone_name=bone.name,
                    parent_name=bone.parent,
                    wrapper_name=bone.wrapper_name,
                ),
            )
            if best_candidate_key is None or key > best_candidate_key:
                best_candidate_key = key
                best_candidate_cubes = cubes
                best_candidate_meta = candidate_meta
        if best_candidate_meta is not None:
            entry["__compiled_cube_source"] = best_candidate_meta[0]
            entry["__compiled_cube_anchor_name"] = best_candidate_meta[1]
            entry["__compiled_cube_payload_name"] = best_candidate_meta[2]
            entry["__compiled_cube_payload_kind"] = best_candidate_meta[3]
            entry["__compiled_cube_decode_mode"] = best_candidate_meta[4]
            if best_candidate_cubes:
                entry["cubes"] = best_candidate_cubes
        if "cubes" not in entry and bone.cube_count_guess is not None:
            container_slice = _find_legacy_single_visible_container_slice(decode_section, bone.name)
            if container_slice is not None:
                nested_visible = _unwrap_legacy_nested_visible_payload(container_slice)
                if nested_visible is None:
                    nested_visible = _unwrap_legacy_inline_visible_payload(container_slice)
                if nested_visible is not None and nested_visible[0] == bone.name:
                    cubes = _decode_legacy_payload_cubes(
                        nested_visible[3],
                        tex,
                        bone_name=bone.name,
                        bone_pivot=bone.pivot,
                        preferred_count=max(1, bone.cube_count_guess),
                    )
                    if codec_format == 15 and asset_name == "main_model" and cubes:
                        cubes = _filter_format15_cube_list(
                            cubes,
                            bone_name=bone.name,
                            pivot=list(bone.pivot) if bone.pivot is not None else None,
                        )
                    if cubes:
                        entry["cubes"] = cubes
                        entry["__compiled_cube_source"] = "typed:container_slice_visible"
                        entry["__compiled_cube_anchor_name"] = bone.name
                        entry["__compiled_cube_payload_name"] = nested_visible[0]
                        entry["__compiled_cube_payload_kind"] = nested_visible[2]
                        entry["__compiled_cube_decode_mode"] = "flat_payload"
        bone_entries.append(entry)

    if codec_format == 15 and asset_name == "main_model":
        filtered_entries = bone_entries
    else:
        filtered_entries = _collapse_redundant_wrapper_bones(bone_entries)
    if codec_format == 9:
        filtered_entries = _postprocess_format9_model_entries(filtered_entries, asset_name=asset_name)
    filtered_entries, child_allocation_summary = _apply_legacy_main_model_child_allocation(
        filtered_entries,
        section=decode_section,
        tex=tex,
        codec_format=codec_format,
        asset_name=asset_name,
    )
    filtered_entries, aux_child_allocation_summary = _apply_legacy_aux_model_child_allocation(
        filtered_entries,
        section=decode_section,
        tex=tex,
        codec_format=codec_format,
        asset_name=asset_name,
    )
    child_allocation_summary = _merge_child_allocation_summaries(
        child_allocation_summary,
        aux_child_allocation_summary,
    )
    filtered_entries, precision_summary = _apply_legacy_precision_guards(
        filtered_entries,
        asset_name=asset_name,
    )
    if codec_format == 15:
        filtered_entries = _postprocess_format15_model_entries(filtered_entries, asset_name=asset_name)

    description: dict[str, object] = {
        "identifier": _legacy_model_identifier(section),
    }
    if tex is not None:
        description["texture_width"] = tex[0]
        description["texture_height"] = tex[1]
    return {
        "format_version": "1.12.0",
        "__compiled_semantics": {
            "typed_bone_hits": sum(
                1
                for entry in filtered_entries
                if isinstance(entry.get("__compiled_cube_source"), str)
                and str(entry["__compiled_cube_source"]).startswith("typed:")
                and entry.get("cubes")
            ),
            "fallback_bone_hits": sum(
                1
                for entry in filtered_entries
                if isinstance(entry.get("__compiled_cube_source"), str)
                and str(entry["__compiled_cube_source"]).startswith("fallback:")
                and entry.get("cubes")
            ),
            "segmented_record_bone_hits": sum(
                1
                for entry in filtered_entries
                if entry.get("__compiled_cube_decode_mode") == "segmented_wrapper_records"
                and entry.get("cubes")
            ),
            "child_allocated_bone_hits": int(child_allocation_summary["child_allocated_bone_hits"]),
            "repaired_parent_bones": int(child_allocation_summary["repaired_parent_bones"]),
            "head_child_allocations": int(child_allocation_summary["head_child_allocations"]),
            "mask_child_allocated_bone_hits": int(child_allocation_summary["mask_child_allocated_bone_hits"]),
            "head_structural_repairs": int(child_allocation_summary["head_structural_repairs"]),
            "ear_child_allocations": int(child_allocation_summary["ear_child_allocations"]),
            "foot_child_allocations": int(child_allocation_summary["foot_child_allocations"]),
            "leg_child_allocations": int(child_allocation_summary["leg_child_allocations"]),
            "tail_child_allocations": int(child_allocation_summary["tail_child_allocations"]),
            "body_child_allocations": int(child_allocation_summary["body_child_allocations"]),
            "hair_child_allocations": int(child_allocation_summary["hair_child_allocations"]),
            "mouth_child_allocations": int(child_allocation_summary["mouth_child_allocations"]),
            "arm_child_allocations": int(child_allocation_summary["arm_child_allocations"]),
            "fanout_group_rejections": int(precision_summary["fanout_group_rejections"]),
            "container_parent_rejections": int(precision_summary["container_parent_rejections"]),
        },
        "minecraft:geometry": [
            {
                "description": description,
                "bones": filtered_entries,
            }
        ],
    }


def _format9_pair_name(name: str) -> str | None:
    if name.startswith("Left"):
        return "Right" + name[4:]
    if name.startswith("Right"):
        return "Left" + name[5:]
    if name.startswith("Left_"):
        return "Right_" + name[5:]
    if name.startswith("Right_"):
        return "Left_" + name[6:]
    return None


def _postprocess_format15_model_entries(
    entries: list[dict[str, object]],
    *,
    asset_name: str | None,
) -> list[dict[str, object]]:
    arm_order = (
        "Arm",
        "LeftArm",
        "LeftForeArm",
        "LeftHand",
        "LeftHandLocator",
        "RightArm",
        "RightForeArm",
        "RightHand",
        "RightHandLocator",
    )
    arrow_order = (
        "Root",
        "UpPl",
        "DownPl",
        "LeftPl",
        "RightPl",
        "Other",
        "Bowknot",
        "Bowknot2",
        "Bowknot3",
        "Bowknot4",
        "Bowknot5",
        "Board",
        "Board2",
        "Brand",
        "Sakura",
    )
    if asset_name == "main_model":
        by_name = {
            entry["name"]: entry
            for entry in entries
            if isinstance(entry.get("name"), str)
        }
        wrapper_restore_names = {
            "Bangs",
            "LeftSideHair",
            "RightSideHair",
            "LongHair",
            "LongLeftHair",
            "LongRightHair",
            "Head",
            "UpBody",
            "UpperBody",
            "Tail",
        }
        explicit_parent_rules = {
            "AllHead": "UpperBody",
            "bow": "UpperBody",
            "LeftEyelid": "Eyelid",
            "RightEyelid": "Eyelid",
            "LeftEyebrow": "EyeBrow",
            "RightEyebrow": "EyeBrow",
            "LeftEyePublic": "LeftEyelidBase",
            "RightEyePublic": "RightEyelidBase",
            "LeftEyeDot": "LeftEyelidBase",
            "RightEyeDot": "RightEyelidBase",
            "Left_ear": "Ear",
            "Right_ear": "Ear",
            "LeftArm": "Arm",
            "RightArm": "Arm",
        }
        for entry in entries:
            name = entry.get("name")
            if not isinstance(name, str) or name.startswith("M"):
                continue
            wrapper_parent = f"M{name}"
            wrapper_entry = by_name.get(wrapper_parent)
            parent = entry.get("parent")
            wrapper_parent_parent = (
                wrapper_entry.get("parent")
                if isinstance(wrapper_entry, dict)
                and isinstance(wrapper_entry.get("parent"), str)
                else None
            )
            wrapped_parent = (
                f"M{wrapper_parent_parent}"
                if isinstance(wrapper_parent_parent, str) and f"M{wrapper_parent_parent}" in by_name
                else None
            )
            if (
                wrapper_entry is not None
                and (
                    parent is None
                    or parent == wrapper_parent_parent
                    or parent == wrapped_parent
                    or (
                        name in wrapper_restore_names
                        and parent in {"AllBody", "AllHead", "Hair"}
                    )
                )
            ):
                entry["parent"] = wrapper_parent
                continue
            if parent is None:
                explicit_parent = explicit_parent_rules.get(name)
                if explicit_parent is not None and explicit_parent in by_name:
                    entry["parent"] = explicit_parent
        referenced_parents = {
            str(entry.get("parent"))
            for entry in entries
            if isinstance(entry.get("parent"), str)
        }
        entries = _collapse_redundant_wrapper_bones(entries, preserve_names=referenced_parents)
        def _filter_main_entry(entry: dict[str, object]) -> None:
            cubes = entry.get("cubes")
            if not isinstance(cubes, list) or not cubes:
                return
            if entry.get("__compiled_cube_decode_mode") != "child_allocated":
                _filter_format15_entry_cubes(entry)
                return
            best = _best_format15_filter_context(entry, by_name)
            if best:
                entry["cubes"] = best
            else:
                entry.pop("cubes", None)
        for entry in entries:
            _filter_main_entry(entry)
        entries = _filter_format15_main_model_entries(entries)
        by_name = {
            entry["name"]: entry
            for entry in entries
            if isinstance(entry.get("name"), str)
        }
        referenced_parents = {
            str(entry.get("parent"))
            for entry in entries
            if isinstance(entry.get("parent"), str)
        }
        filtered: list[dict[str, object]] = []
        for entry in entries:
            name = entry.get("name")
            if not isinstance(name, str):
                continue
            if name.startswith("M") and not entry.get("cubes") and name not in referenced_parents:
                continue
            filtered.append(entry)
        by_name = {
            entry["name"]: entry
            for entry in filtered
            if isinstance(entry.get("name"), str)
        }
        swapped: set[str] = set()
        for name, entry in by_name.items():
            if name in swapped:
                continue
            other_name = _format9_pair_name(name)
            if other_name is None or other_name not in by_name:
                continue
            other = by_name[other_name]
            x0 = _format9_entry_pivot_x(entry)
            x1 = _format9_entry_pivot_x(other)
            if x0 is None or x1 is None:
                continue
            should_swap = False
            if name.startswith("Left") and x0 < 0.0 and x1 > 0.0:
                should_swap = True
            elif name.startswith("Right") and x0 > 0.0 and x1 < 0.0:
                should_swap = True
            elif name.startswith("Left_") and x0 < 0.0 and x1 > 0.0:
                should_swap = True
            elif name.startswith("Right_") and x0 > 0.0 and x1 < 0.0:
                should_swap = True
            if should_swap:
                _swap_format9_entry_payload(entry, other)
                swapped.add(name)
                swapped.add(other_name)
        for entry in filtered:
            name = entry.get("name")
            if not isinstance(name, str):
                continue
            cubes = entry.get("cubes")
            if isinstance(cubes, list) and cubes:
                entry["cubes"] = _orient_legacy_cubes_to_side(
                    cubes,
                    bone_name=name,
                    parent_name=entry.get("parent") if isinstance(entry.get("parent"), str) else None,
                )
                _filter_main_entry(entry)
        return filtered

    by_name = {
        entry["name"]: entry
        for entry in entries
        if isinstance(entry.get("name"), str)
    }
    for entry in entries:
        if entry.get("__compiled_cube_decode_mode") == "child_allocated":
            if asset_name in {"arm_model", "arrow_model"}:
                continue
            cubes = entry.get("cubes")
            best = (
                _filter_format15_cube_list(
                    cubes,
                    bone_name=str(entry.get("name", "")),
                    pivot=None,
                )
                if isinstance(cubes, list) and asset_name in {"arm_model", "arrow_model"}
                else _best_format15_filter_context(entry, by_name)
            )
            if best:
                entry["cubes"] = best
            else:
                entry.pop("cubes", None)
            continue
        _filter_format15_entry_cubes(entry)
    if asset_name == "arm_model":
        by_name = {
            entry["name"]: entry
            for entry in entries
            if isinstance(entry.get("name"), str) and entry.get("name") in _FORMAT9_ARM_MODEL_KEEP_NAMES
        }
        filtered = [by_name[name] for name in arm_order if name in by_name]
        by_name = {
            entry["name"]: entry
            for entry in filtered
            if isinstance(entry.get("name"), str)
        }
        if "Arm" not in by_name and ("LeftArm" in by_name or "RightArm" in by_name):
            arm_entry: dict[str, object] = {"name": "Arm"}
            filtered.insert(0, arm_entry)
            by_name["Arm"] = arm_entry
        parent_map = {
            "LeftArm": "Arm",
            "RightArm": "Arm",
            "LeftForeArm": "LeftArm",
            "RightForeArm": "RightArm",
            "LeftHand": "LeftForeArm",
            "RightHand": "RightForeArm",
            "LeftHandLocator": "LeftHand",
            "RightHandLocator": "RightHand",
        }
        for child, parent in parent_map.items():
            if child in by_name and parent in by_name:
                by_name[child]["parent"] = parent
        swapped: set[str] = set()
        for name, entry in by_name.items():
            if name in swapped:
                continue
            other_name = _format9_pair_name(name)
            if other_name is None or other_name not in by_name:
                continue
            other = by_name[other_name]
            x0 = _format9_entry_pivot_x(entry)
            x1 = _format9_entry_pivot_x(other)
            if x0 is None or x1 is None:
                continue
            if name.startswith("Left") and x0 < 0.0 and x1 > 0.0:
                _swap_format9_entry_payload(entry, other)
                swapped.add(name)
                swapped.add(other_name)
            elif name.startswith("Right") and x0 > 0.0 and x1 < 0.0:
                _swap_format9_entry_payload(entry, other)
                swapped.add(name)
                swapped.add(other_name)
        for name in arm_order:
            if name in by_name:
                continue
            entry: dict[str, object] = {"name": name}
            parent = parent_map.get(name)
            if parent is not None:
                entry["parent"] = parent
            filtered.append(entry)
            by_name[name] = entry
        return filtered
    if asset_name == "arrow_model":
        by_name = {
            entry["name"]: entry
            for entry in entries
            if isinstance(entry.get("name"), str) and entry.get("name") in _FORMAT9_ARROW_MODEL_KEEP_NAMES
        }
        filtered = [by_name[name] for name in arrow_order if name in by_name]
        by_name = {
            entry["name"]: entry
            for entry in filtered
            if isinstance(entry.get("name"), str)
        }
        parent_map = {
            "UpPl": "Root",
            "DownPl": "Root",
            "LeftPl": "Root",
            "RightPl": "Root",
            "Other": "Root",
            "Sakura": "Root",
            "Bowknot": "Other",
            "Bowknot2": "Other",
            "Bowknot3": "Other",
            "Bowknot4": "Other",
            "Bowknot5": "Other",
            "Board": "Other",
            "Brand": "Other",
            "Board2": "Board",
        }
        for child, parent in parent_map.items():
            if child in by_name and parent in by_name:
                by_name[child]["parent"] = parent
        for name in arrow_order:
            if name in by_name:
                continue
            entry = {"name": name}
            parent = parent_map.get(name)
            if parent is not None:
                entry["parent"] = parent
            filtered.append(entry)
            by_name[name] = entry
        return filtered
    return entries


def _swap_format9_entry_payload(a: dict[str, object], b: dict[str, object]) -> None:
    for key in (
        "pivot",
        "cubes",
        "__compiled_cube_count_guess",
        "__compiled_wrapper_name",
        "__compiled_uv_norm_hints",
        "__compiled_cube_source",
        "__compiled_cube_anchor_name",
        "__compiled_cube_payload_name",
        "__compiled_cube_payload_kind",
        "__compiled_cube_decode_mode",
        "__compiled_cube_rejected_reason",
    ):
        av = a.get(key)
        bv = b.get(key)
        if bv is None:
            a.pop(key, None)
        else:
            a[key] = bv
        if av is None:
            b.pop(key, None)
        else:
            b[key] = av


def _format9_entry_pivot_x(entry: dict[str, object]) -> float | None:
    pivot = entry.get("pivot")
    if isinstance(pivot, list) and len(pivot) == 3:
        return float(pivot[0])
    cubes = entry.get("cubes")
    if isinstance(cubes, list) and cubes:
        cube_pivot = cubes[0].get("pivot")
        if isinstance(cube_pivot, list) and len(cube_pivot) == 3:
            return float(cube_pivot[0])
    return None


def _format9_center_distance(
    cube: dict[str, object],
    pivot: list[float] | tuple[float, float, float] | None,
) -> float | None:
    center = _legacy_cube_center(cube)
    if center is None or pivot is None:
        return None
    return math.sqrt(
        (center[0] - float(pivot[0])) ** 2
        + (center[1] - float(pivot[1])) ** 2
        + (center[2] - float(pivot[2])) ** 2
    )


def _filter_format9_entry_cubes(entry: dict[str, object], *, pivot_override: object | None = None) -> None:
    cubes = entry.get("cubes")
    if not isinstance(cubes, list) or not cubes:
        return
    if entry.get("name") == "gui":
        entry.pop("cubes", None)
        return
    pivot = entry.get("pivot") if pivot_override is None else pivot_override
    keep: list[dict[str, object]] = []
    for cube in cubes:
        size = cube.get("size")
        if not isinstance(size, list) or len(size) != 3:
            continue
        sx, sy, sz = (float(size[0]), float(size[1]), float(size[2]))
        max_dim = max(sx, sy, sz)
        min_dim = min(sx, sy, sz)
        if max_dim > 48.0 or min_dim <= 0.0:
            continue
        uv_faces = cube.get("uv", {})
        if isinstance(uv_faces, dict):
            bad_uv = False
            for face in uv_faces.values():
                if not isinstance(face, dict):
                    continue
                uv = face.get("uv")
                uv_size = face.get("uv_size")
                if isinstance(uv, list) and len(uv) == 2 and (float(uv[0]) < 0.0 or float(uv[1]) < 0.0):
                    bad_uv = True
                    break
                if isinstance(uv_size, list) and len(uv_size) == 2:
                    if abs(float(uv_size[0])) > 48.0 or abs(float(uv_size[1])) > 48.0:
                        bad_uv = True
                        break
            if bad_uv:
                continue
        dist = _format9_center_distance(cube, pivot)
        if dist is not None and dist > max(18.0, max_dim * 1.75) and max_dim > 3.0:
            continue
        keep.append(cube)
    if keep:
        entry["cubes"] = keep
    else:
        entry.pop("cubes", None)


def _postprocess_format9_model_entries(
    entries: list[dict[str, object]],
    *,
    asset_name: str | None,
) -> list[dict[str, object]]:
    arm_order = (
        "Arm",
        "LeftArm",
        "LeftForeArm",
        "LeftHand",
        "LeftHandLocator",
        "RightArm",
        "RightForeArm",
        "RightHand",
        "RightHandLocator",
    )
    arrow_order = (
        "Root",
        "UpPl",
        "DownPl",
        "LeftPl",
        "RightPl",
        "Other",
        "Bowknot",
        "Bowknot2",
        "Bowknot3",
        "Bowknot4",
        "Bowknot5",
        "Board",
        "Board2",
        "Brand",
        "Sakura",
    )
    by_name = {
        entry["name"]: entry
        for entry in entries
        if isinstance(entry.get("name"), str)
    }

    # Repair common missing visible-bone parents from the paired legacy sample.
    explicit_parent_rules = {
        "AllHead": "UpperBody",
        "bow": "UpperBody",
        "LeftEyelid": "Eyelid",
        "RightEyelid": "Eyelid",
        "LeftEyebrow": "EyeBrow",
        "RightEyebrow": "EyeBrow",
        "LeftEyePublic": "LeftEyelidBase",
        "RightEyePublic": "RightEyelidBase",
        "LeftEyeDot": "LeftEyelidBase",
        "RightEyeDot": "RightEyelidBase",
        "Left_ear": "Ear",
        "Right_ear": "Ear",
        "LeftArm": "Arm",
        "RightArm": "Arm",
        "LeftLeg": "Leg",
        "RightLeg": "Leg",
        "UpPl": "Root",
        "DownPl": "Root",
        "LeftPl": "Root",
        "RightPl": "Root",
        "Other": "Root",
        "Sakura": "Root",
        "Bowknot": "Other",
        "Bowknot2": "Other",
        "Bowknot3": "Other",
        "Bowknot4": "Other",
        "Bowknot5": "Other",
        "Board": "Other",
        "Brand": "Other",
        "Board2": "Board",
    }
    for entry in entries:
        name = entry.get("name")
        if not isinstance(name, str):
            continue
        wrapper_parent = f"M{name}"
        if wrapper_parent in by_name and (
            entry.get("parent") is None or name in {"Head", "UpperBody", "UpBody", "AllBody", "Tail"}
        ):
            entry["parent"] = wrapper_parent
            continue
        if entry.get("parent") is not None:
            continue
        parent = explicit_parent_rules.get(name)
        if parent is not None and parent in by_name:
            entry["parent"] = parent

    # Remove helper/container cubes that should live on visible children instead.
    child_map: dict[str, list[str]] = {}
    for entry in entries:
        parent = entry.get("parent")
        name = entry.get("name")
        if isinstance(parent, str) and isinstance(name, str):
            child_map.setdefault(parent, []).append(name)
    for entry in entries:
        name = entry.get("name")
        if not isinstance(name, str) or "cubes" not in entry:
            continue
        if name.startswith("M") and name[1:] in by_name:
            entry.pop("cubes", None)
            continue
        if name.endswith("Locator") or name in _FORMAT9_CONTAINER_BONE_NAMES:
            children = child_map.get(name, [])
            if any(by_name.get(child, {}).get("cubes") for child in children):
                entry.pop("cubes", None)
    if asset_name == "arm_model":
        filtered = []
        for entry in entries:
            name = entry.get("name")
            if isinstance(name, str) and name not in _FORMAT9_ARM_MODEL_KEEP_NAMES:
                continue
            filtered.append(entry)
        entries = filtered
        by_name = {
            entry["name"]: entry
            for entry in entries
            if isinstance(entry.get("name"), str)
        }
        if "Arm" not in by_name and ("LeftArm" in by_name or "RightArm" in by_name):
            arm_entry: dict[str, object] = {"name": "Arm"}
            entries.insert(0, arm_entry)
            by_name["Arm"] = arm_entry
            for child_name in ("LeftArm", "RightArm"):
                child = by_name.get(child_name)
                if child is not None:
                    child["parent"] = "Arm"
            if "LeftForeArm" in by_name:
                by_name["LeftForeArm"]["parent"] = "LeftArm"
            if "RightForeArm" in by_name:
                by_name["RightForeArm"]["parent"] = "RightArm"
            if "LeftHand" in by_name:
                by_name["LeftHand"]["parent"] = "LeftForeArm"
            if "RightHand" in by_name:
                by_name["RightHand"]["parent"] = "RightForeArm"
            if "LeftHandLocator" in by_name:
                by_name["LeftHandLocator"]["parent"] = "LeftHand"
            if "RightHandLocator" in by_name:
                by_name["RightHandLocator"]["parent"] = "RightHand"
        parent_map = {
            "LeftArm": "Arm",
            "RightArm": "Arm",
            "LeftForeArm": "LeftArm",
            "RightForeArm": "RightArm",
            "LeftHand": "LeftForeArm",
            "RightHand": "RightForeArm",
            "LeftHandLocator": "LeftHand",
            "RightHandLocator": "RightHand",
        }
        for name in arm_order:
            if name in by_name:
                continue
            entry = {"name": name}
            parent = parent_map.get(name)
            if parent is not None:
                entry["parent"] = parent
            entries.append(entry)
            by_name[name] = entry
    if asset_name == "arrow_model":
        parent_map = {
            "UpPl": "Root",
            "DownPl": "Root",
            "LeftPl": "Root",
            "RightPl": "Root",
            "Other": "Root",
            "Sakura": "Root",
            "Bowknot": "Other",
            "Bowknot2": "Other",
            "Bowknot3": "Other",
            "Bowknot4": "Other",
            "Bowknot5": "Other",
            "Board": "Other",
            "Brand": "Other",
            "Board2": "Board",
        }
        by_name = {
            entry["name"]: entry
            for entry in entries
            if isinstance(entry.get("name"), str)
        }
        for name in arrow_order:
            if name in by_name:
                continue
            entry = {"name": name}
            parent = parent_map.get(name)
            if parent is not None:
                entry["parent"] = parent
            entries.append(entry)
            by_name[name] = entry

    # Keep only locally plausible cubes on visible bones.
    for entry in entries:
        if entry.get("__compiled_cube_decode_mode") == "child_allocated":
            pivot_override = None
            parent_name = entry.get("parent")
            if isinstance(parent_name, str):
                parent_entry = by_name.get(parent_name)
                if parent_entry is not None:
                    pivot_override = parent_entry.get("pivot")
            anchor_name = entry.get("__compiled_cube_anchor_name")
            if isinstance(anchor_name, str):
                anchor_entry = by_name.get(anchor_name)
                if anchor_entry is not None and pivot_override is None:
                    pivot_override = anchor_entry.get("pivot")
            _filter_format9_entry_cubes(entry, pivot_override=pivot_override)
            continue
        _filter_format9_entry_cubes(entry)

    # If a left/right pair landed on the wrong side, swap the geometry payloads.
    swapped: set[str] = set()
    for name, entry in by_name.items():
        if name in swapped:
            continue
        other_name = _format9_pair_name(name)
        if other_name is None or other_name not in by_name:
            continue
        other = by_name[other_name]
        x0 = _format9_entry_pivot_x(entry)
        x1 = _format9_entry_pivot_x(other)
        if x0 is None or x1 is None:
            continue
        if name.startswith("Left") and x0 < 0.0 and x1 > 0.0:
            _swap_format9_entry_payload(entry, other)
            swapped.add(name)
            swapped.add(other_name)
        elif name.startswith("Right") and x0 > 0.0 and x1 < 0.0:
            _swap_format9_entry_payload(entry, other)
            swapped.add(name)
            swapped.add(other_name)
        elif name.startswith("Left_") and x0 < 0.0 and x1 > 0.0:
            _swap_format9_entry_payload(entry, other)
            swapped.add(name)
            swapped.add(other_name)
        elif name.startswith("Right_") and x0 > 0.0 and x1 < 0.0:
            _swap_format9_entry_payload(entry, other)
            swapped.add(name)
            swapped.add(other_name)

    return entries


def _png_chunk(tag: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", binascii.crc32(tag + data) & 0xFFFFFFFF)


def _encode_png_rgba(width: int, height: int, rgba: bytes) -> bytes:
    rows = []
    stride = width * 4
    for y in range(height):
        rows.append(b"\x00" + rgba[y * stride:(y + 1) * stride])
    raw = b"".join(rows)
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return b"".join(
        (
            b"\x89PNG\r\n\x1a\n",
            _png_chunk(b"IHDR", ihdr),
            _png_chunk(b"IDAT", zlib.compress(raw, level=9)),
            _png_chunk(b"IEND", b""),
        )
    )


def _png_pixels_equal(png_a: bytes, png_b: bytes) -> bool:
    if png_a == png_b:
        return True
    if Image is None:
        return False
    try:
        import io

        img_a = Image.open(io.BytesIO(png_a)).convert("RGBA")
        img_b = Image.open(io.BytesIO(png_b)).convert("RGBA")
        return img_a.size == img_b.size and img_a.tobytes() == img_b.tobytes()
    except Exception:
        return False


def _rgba_alpha_score(buf: bytes) -> float:
    if len(buf) < 4:
        return 0.0
    alphas = buf[3::4]
    if not alphas:
        return 0.0
    opaque_like = sum(1 for b in alphas if b in (0x00, 0xFF))
    return opaque_like / len(alphas)


def _decode_legacy_texture_variant_40(decoded: bytes, label_off: int, label: bytes) -> tuple[int, int, int, bytes] | None:
    head_off = label_off + len(label)
    head = decoded[head_off : head_off + 4]
    if len(head) < 4 or head[2] != 0x40 or head[3] != 0x00:
        return None
    width = head[0] * 2
    height = head[1]
    if width <= 0 or height <= 0:
        return None
    payload_off = head_off + 99
    payload_len = width * height * 8
    payload = decoded[payload_off : payload_off + payload_len]
    if len(payload) != payload_len:
        return None
    row_stride = width * 4
    rows = [payload[i : i + row_stride] for i in range(0, payload_len, row_stride)]
    if len(rows) != height * 2:
        return None
    merged = bytearray()
    for even_row, odd_row in zip(rows[0::2], rows[1::2]):
        for i in range(0, row_stride, 4):
            a = even_row[i : i + 4]
            b = odd_row[i : i + 4]
            merged.extend(a if a[3] >= b[3] else b)
    return (width, height, payload_off, bytes(merged))


def _guess_legacy_texture_block(decoded: bytes, label_off: int, label: bytes, next_anchor: int | None) -> tuple[int, int] | None:
    start = label_off + len(label) + 3
    size_order = [512, 256, 128, 64, 32, 16]
    lower = label.lower()
    if lower == b"skin":
        size_order = [256, 128, 64, 512, 32, 16]
    elif b"arrow" in lower:
        size_order = [64, 32, 128, 16, 256]

    best: tuple[float, int, int] | None = None
    for dim in size_order:
        raw_len = dim * dim * 4
        end = start + raw_len
        if end > len(decoded):
            continue
        body = decoded[start:end]
        body_score = _rgba_alpha_score(body)
        if body_score < 0.70:
            continue
        tail = decoded[end:end + 256]
        tail_score = _rgba_alpha_score(tail) if tail else 0.0
        score = body_score - (tail_score * 0.35)
        if next_anchor is not None:
            gap = next_anchor - end
            if 0 <= gap <= 16:
                score += 0.75
        if best is None or score > best[0]:
            best = (score, dim, raw_len)
    if best is None:
        return None
    return (best[1], best[2])


def _export_legacy_textures(
    decoded: bytes,
    scan: LegacyScanResult,
    out_dir: Path,
    *,
    debug: bool = False,
    codec_format: int | None = None,
) -> list[LegacyTextureExport]:
    exports: list[LegacyTextureExport] = []
    property_assets = parse_property_assets(scan_file(scan.path, dump=False).property_text)
    texture_entries = [
        entry
        for entry in scan.directory_entries
        if (
            entry.property_match == "arrow_texture"
            or (entry.property_match or "").startswith("texture")
            or (entry.property_match or "").lower().endswith((".png", ".jpg", ".jpeg", ".tga"))
        )
    ]
    if not texture_entries:
        for asset in property_assets:
            display_name = asset.display_name
            if asset.tag != "texture" and not asset.tag.lower().endswith((".png", ".jpg", ".jpeg", ".tga")):
                continue
            if display_name != "arrow_texture" and not display_name.startswith("texture") and not asset.tag.lower().endswith((".png", ".jpg", ".jpeg", ".tga")):
                continue
            texture_entries.append(
                LegacyDirectoryEntry(
                    offset=-1,
                    control=tuple(),
                    name=asset.label or asset.tag,
                    hash_hex=asset.hash_hex,
                    property_match=display_name,
                )
            )
    texture_entry_by_match = {entry.property_match: entry for entry in texture_entries if entry.property_match}
    for asset in property_assets:
        display_name = asset.display_name
        if display_name in texture_entry_by_match:
            continue
        if asset.tag == "arrow_texture" or display_name == "arrow_texture":
            texture_entries.append(
                LegacyDirectoryEntry(
                    offset=-1,
                    control=tuple(),
                    name=asset.label or asset.tag,
                    hash_hex=asset.hash_hex,
                    property_match="arrow_texture",
                )
            )
            continue
        if asset.tag == "texture" or display_name.startswith("texture") or asset.tag.lower().endswith((".png", ".jpg", ".jpeg", ".tga")):
            texture_entries.append(
                LegacyDirectoryEntry(
                    offset=-1,
                    control=tuple(),
                    name=asset.label or asset.tag,
                    hash_hex=asset.hash_hex,
                    property_match=display_name,
                )
            )
    def texture_labels(entry: LegacyDirectoryEntry) -> list[bytes]:
        asset_name = entry.property_match or ""
        raw_name = entry.name or ""
        labels: list[str] = []
        if raw_name:
            labels.append(raw_name)
        if asset_name == "arrow_texture":
            labels.append("arrow")
        elif asset_name.startswith("texture_"):
            labels.append(asset_name[len("texture_"):])
        deduped: list[bytes] = []
        seen: set[bytes] = set()
        for text in labels:
            label = text.encode("ascii", "replace")
            if not label or label in seen:
                continue
            seen.add(label)
            deduped.append(label)
        return deduped

    label_offsets: dict[str, int] = {}
    for entry in texture_entries:
        for label in texture_labels(entry):
            off = decoded.find(label)
            if off >= 0:
                label_offsets[entry.property_match or ""] = off
                break

    sorted_offsets = sorted(label_offsets.values())
    for entry in texture_entries:
        asset_name = entry.property_match or ""
        labels = texture_labels(entry)
        if not asset_name or not labels:
            continue
        label_off = label_offsets.get(asset_name)
        if label_off is None:
            continue
        label = next((item for item in labels if decoded.find(item) == label_off), labels[0])
        next_anchor = None
        for off in sorted_offsets:
            if off > label_off:
                next_anchor = off
                break
        special = _decode_legacy_texture_variant_40(decoded, label_off, label)
        if special is not None:
            width, height, start, rgba = special
            png = _encode_png_rgba(width, height, rgba)
            png_sha256 = hashlib.sha256(png).hexdigest()
            png_file = canonical_legacy_export_name(asset_name, "")
            (out_dir / png_file).write_bytes(png)
            exports.append(
                LegacyTextureExport(
                    asset_name=asset_name,
                    label=label.decode("ascii", "replace"),
                    width=width,
                    height=height,
                    offset=start,
                    raw_len=len(rgba),
                    png_file=png_file,
                    sha256=png_sha256,
                )
            )
            continue
        guessed = _guess_legacy_texture_block(decoded, label_off, label, next_anchor)
        if guessed is None:
            continue
        dim, raw_len = guessed
        start = label_off + len(label) + 3
        rgba = decoded[start:start + raw_len]
        png = _encode_png_rgba(dim, dim, rgba)
        png_sha256 = hashlib.sha256(png).hexdigest()
        png_file = canonical_legacy_export_name(asset_name, "")
        (out_dir / png_file).write_bytes(png)
        exports.append(
            LegacyTextureExport(
                asset_name=asset_name,
                label=label.decode("ascii", "replace"),
                width=dim,
                height=dim,
                offset=start,
                raw_len=raw_len,
                png_file=png_file,
                sha256=png_sha256,
            )
        )
    return exports


def _guess_legacy_texture_block_from_section(section: bytes) -> tuple[int, int] | None:
    best: tuple[float, int, int] | None = None
    for dim in (256, 128, 64):
        raw_len = dim * dim * 4
        if raw_len > len(section):
            continue
        for rel_off in range(0, len(section) - raw_len + 1, 0x100):
            body = section[rel_off : rel_off + raw_len]
            alpha = body[3::4]
            if not alpha:
                continue
            alpha_discrete = sum(1 for b in alpha if b in (0, 255)) / len(alpha)
            if alpha_discrete < 0.98:
                continue
            alpha_nonzero = sum(1 for b in alpha if b) / len(alpha)
            if alpha_nonzero < 0.01:
                continue
            rgb_nonzero = sum(1 for b in body[0::4] if b) / len(alpha)
            score = alpha_discrete + (alpha_nonzero * 3.0) + rgb_nonzero
            if best is None or score > best[0]:
                best = (score, dim, rel_off)
    if best is None:
        return None
    return (best[1], best[2])


def _export_legacy_textures_fallback(decoded: bytes, scan: LegacyScanResult, out_dir: Path) -> list[LegacyTextureExport]:
    assets = parse_property_assets(scan_file(scan.path, dump=False).property_text)
    texture_assets = [
        asset
        for asset in assets
        if asset.tag == "texture" or asset.tag.lower().endswith((".png", ".jpg", ".jpeg", ".tga"))
    ]
    if not texture_assets:
        return []
    unnamed_sections = [
        sec
        for sec in scan.sections
        if sec.asset_guess is None and sec.kind_guess in ("model", "texture_or_binary", "unknown")
    ]
    if not unnamed_sections:
        return []
    target_section = max(unnamed_sections, key=lambda sec: sec.size)
    section_bytes = decoded[target_section.start : target_section.end]
    guessed = _guess_legacy_texture_block_from_section(section_bytes)
    if guessed is None:
        return []
    dim, rel_off = guessed
    raw_len = dim * dim * 4
    start = target_section.start + rel_off
    rgba = decoded[start : start + raw_len]
    png = _encode_png_rgba(dim, dim, rgba)
    asset = texture_assets[0]
    png_file = canonical_legacy_export_name(asset.display_name, "")
    (out_dir / png_file).write_bytes(png)
    return [
        LegacyTextureExport(
            asset_name=asset.display_name,
            label=asset.label or asset.display_name,
            width=dim,
            height=dim,
            offset=start,
            raw_len=raw_len,
            png_file=png_file,
            sha256=hashlib.sha256(png).hexdigest(),
        )
    ]
    return {
        "format_version": "1.8.0",
        "__compiled_decompile": {
            "status": "signature_only",
            "asset_name": asset_name,
            "section_sha256": section_sha256,
            "clip_count_guess": len(token_names),
            "bone_name_count_guess": len(guessed_bones),
            "signature_score": int(signature_scores.get(asset_name, 0)),
            "notes": [
                "Recovered from compiled legacy YSM animation section.",
                "Clip names are inferred from embedded signature tokens.",
                "Durations, loop modes, and keyframe channels are not reconstructed yet.",
                "Bone lists are guessed from embedded strings.",
            ],
        },
        "animations": animations,
    }


def _find_directory_start(decoded: bytes, tail_start: int) -> int:
    window_start = max(0, tail_start - 0x40)
    marker = decoded.rfind(b"\x80\x01\x80\x01", tail_start, min(len(decoded), tail_start + 0x80000))
    if marker >= 0:
        return marker
    marker = decoded.rfind(b"\x80\x01\x80\x01", window_start, tail_start)
    if marker >= 0:
        return marker
    return tail_start


def _parse_legacy_directory(
    decoded: bytes, directory_start: int, property_by_hash: dict[str, str]
) -> tuple[str, tuple[LegacyDirectoryEntry, ...]]:
    if directory_start >= len(decoded):
        return "", tuple()
    off = directory_start
    prefix = ""
    if decoded[off : off + 4] == b"\x80\x01\x80\x01":
        prefix = decoded[off : off + 4].hex()
        off += 4

    entries: list[LegacyDirectoryEntry] = []
    while off < len(decoded):
        ctrl: tuple[int, ...]
        name = ""
        hash_off: int | None = None

        if (
            off + 66 <= len(decoded)
            and decoded[off + 1] == 0x40
            and HEX_HASH_RE.fullmatch(decoded[off + 2 : off + 66])
        ):
            ctrl = (decoded[off],)
            hash_off = off + 2
            next_off = off + 66
        elif (
            off + 67 <= len(decoded)
            and decoded[off + 2] == 0x40
            and HEX_HASH_RE.fullmatch(decoded[off + 3 : off + 67])
        ):
            ctrl = (decoded[off], decoded[off + 1])
            hash_off = off + 3
            next_off = off + 67
        elif off + 3 <= len(decoded):
            name_len = decoded[off + 1]
            name_end = off + 2 + name_len
            if (
                0 < name_len < 0x40
                and name_end + 65 <= len(decoded)
                and decoded[name_end] == 0x40
                and HEX_HASH_RE.fullmatch(decoded[name_end + 1 : name_end + 65])
            ):
                ctrl = (decoded[off], decoded[off + 1])
                name = decoded[off + 2 : name_end].decode("utf-8", "replace")
                hash_off = name_end + 1
                next_off = name_end + 65
            else:
                break
        else:
            break

        hash_hex = decoded[hash_off : hash_off + 64].decode("ascii")
        entries.append(
            LegacyDirectoryEntry(
                offset=off,
                control=ctrl,
                name=name,
                hash_hex=hash_hex,
                property_match=property_by_hash.get(hash_hex),
            )
        )
        off = next_off

    return prefix, tuple(entries)


def find_legacy_sections(decoded: bytes, tail_start: int) -> list[LegacySection]:
    starts = {0}
    for pat in SECTION_TAGS:
        start = 0
        while True:
            i = decoded.find(pat, start)
            if i < 0 or i >= tail_start:
                break
            starts.add(i)
            start = i + 1
    ordered = sorted(starts)
    filtered: list[int] = []
    for s in ordered:
        if not filtered or s - filtered[-1] > 0x800:
            filtered.append(s)
    filtered.append(tail_start)

    sections: list[LegacySection] = []
    for i, start in enumerate(filtered[:-1]):
        end = filtered[i + 1]
        if end <= start:
            continue
        chunk = decoded[start:end]
        if len(chunk) < 0x800:
            continue
        names = _extract_names(chunk)
        kind = _classify_section(chunk, names)
        sections.append(
            LegacySection(
                start=start,
                end=end,
                size=end - start,
                tag=int.from_bytes(chunk[:4], "little"),
                kind_guess=kind,
                names=names,
                asset_guess=None,
                assignment_method=None,
                sha256=hashlib.sha256(chunk).hexdigest(),
            )
        )
    return sections


def assign_property_names(
    sections: list[LegacySection],
    path: Path,
    decoded: bytes,
    codec_format: int | None,
    directory_entries: tuple[LegacyDirectoryEntry, ...],
) -> tuple[list[LegacySection], tuple[str, ...]]:
    expected_by_kind = _expected_legacy_assets_by_kind(path, codec_format, directory_entries)
    expected_assets = tuple(name for values in expected_by_kind.values() for name in values)

    rows = [
        {
            "section": sec,
            "asset_guess": None,
            "assignment_method": None,
        }
        for sec in sections
    ]
    assigned_assets: set[str] = set()

    def assign_index(idx: int, asset_name: str, method: str) -> None:
        if rows[idx]["asset_guess"] is not None or asset_name in assigned_assets:
            return
        rows[idx]["asset_guess"] = asset_name
        rows[idx]["assignment_method"] = method
        assigned_assets.add(asset_name)

    def unassigned_indexes(*, kind: str | None = None) -> list[int]:
        indexes: list[int] = []
        for idx, row in enumerate(rows):
            sec = row["section"]
            if row["asset_guess"] is not None:
                continue
            if kind is not None and sec.kind_guess != kind:
                continue
            indexes.append(idx)
        return indexes

    for kind in ("model", "audio", "texture_or_binary"):
        pool = list(expected_by_kind.get(kind, ()))
        for idx in unassigned_indexes(kind=kind):
            if not pool:
                break
            assign_index(idx, pool.pop(0), "kind_order")

    animation_assets = [name for name in expected_by_kind.get("animation", ()) if name not in assigned_assets]
    signature_candidates = [
        idx
        for idx in unassigned_indexes()
        if rows[idx]["section"].kind_guess != "audio"
    ]
    for asset_name in animation_assets:
        scored: list[tuple[int, int]] = []
        for idx in signature_candidates:
            sec = rows[idx]["section"]
            score = int(_legacy_signature_scores(decoded[sec.start : sec.end]).get(asset_name, 0))
            if score > 0:
                scored.append((score, idx))
        scored.sort(reverse=True)
        if not scored:
            continue
        best_score, best_idx = scored[0]
        second_score = scored[1][0] if len(scored) > 1 else -1
        if best_score >= 2 and best_score > second_score:
            assign_index(best_idx, asset_name, "signature")
            signature_candidates = [idx for idx in signature_candidates if idx != best_idx]

    for idx in unassigned_indexes(kind="animation"):
        pool = [name for name in expected_by_kind.get("animation", ()) if name not in assigned_assets]
        if not pool:
            break
        assign_index(idx, pool.pop(0), "kind_order")

    assigned_sections: list[LegacySection] = []
    for row in rows:
        sec = row["section"]
        assigned_sections.append(
            LegacySection(
                start=sec.start,
                end=sec.end,
                size=sec.size,
                tag=sec.tag,
                kind_guess=sec.kind_guess,
                names=sec.names,
                asset_guess=row["asset_guess"],
                assignment_method=row["assignment_method"],
                sha256=sec.sha256,
            )
        )
    return assigned_sections, expected_assets


def scan_legacy_sections(path: Path) -> LegacyScanResult:
    result = decode_bom_v3(path)
    decoded = result.decompressed
    tail_markers = [m.start() for m in HEX_HASH_RE.finditer(decoded)]
    tail_start = min(tail_markers) if tail_markers else len(decoded)
    directory_start = _find_directory_start(decoded, tail_start)
    property_assets = parse_property_assets(scan_file(path, dump=False).property_text)
    codec_format = _read_property_format(path)
    property_by_hash = {asset.hash_hex: asset.display_name for asset in property_assets}
    directory_prefix, directory_entries = _parse_legacy_directory(decoded, directory_start, property_by_hash)
    sections, expected_assets = assign_property_names(
        find_legacy_sections(decoded, tail_start),
        path,
        decoded,
        codec_format,
        directory_entries,
    )
    return LegacyScanResult(
        path=path,
        codec_format=codec_format,
        decoded_len=len(decoded),
        tail_start=tail_start,
        directory_start=directory_start,
        directory_prefix=directory_prefix,
        directory_entries=directory_entries,
        expected_assets=expected_assets,
        sections=tuple(sections),
    )


def _prune_legacy_debug_outputs(out_dir: Path) -> None:
    for pattern in ("*.section.bin", "*.manifest.json", "*.decompiled.json"):
        for path in out_dir.glob(pattern):
            path.unlink(missing_ok=True)


def _clear_legacy_output_dir(out_dir: Path) -> None:
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
        "legacy_sections.json",
        "oracle_restore.json",
    ):
        for path in out_dir.glob(pattern):
            path.unlink(missing_ok=True)


def dump_legacy_sections(
    path: Path,
    scan: LegacyScanResult | None = None,
    *,
    debug: bool = False,
    out_dir: Path | None = None,
) -> Path:
    if scan is None:
        scan = scan_legacy_sections(path)
    result = decode_bom_v3(path)
    decoded = result.decompressed

    folder_name = _sanitize_name(_read_property_name(path) or path.stem)
    codec_format = scan.codec_format
    out_dir = out_dir or path.with_name(f"{folder_name}_legacy_sections_format{codec_format or 'unknown'}")
    out_dir.mkdir(parents=True, exist_ok=True)
    _clear_legacy_output_dir(out_dir)

    manifest = {
        "source_file": str(path),
        "codec_format": codec_format,
        "decoded_len": scan.decoded_len,
        "tail_start": scan.tail_start,
        "directory_start": scan.directory_start,
        "directory_prefix": scan.directory_prefix,
        "directory_count": len(scan.directory_entries),
        "directory_entries": [
            {
                "offset": entry.offset,
                "control": list(entry.control),
                "name": entry.name,
                "hash_hex": entry.hash_hex,
                "property_match": entry.property_match,
            }
            for entry in scan.directory_entries
        ],
        "section_count": len(scan.sections),
        "expected_assets": list(scan.expected_assets),
        "resolved_assets": [],
        "unresolved_assets": [],
        "texture_exports": [],
        "pretty_aliases": [],
        "sections": [],
    }

    used_aliases: set[str] = set()
    section_bytes_by_name: dict[str, bytes] = {}
    alias_candidates: list[dict[str, object]] = []
    format9_arrow_section = _select_format9_arrow_section(scan, decoded) if codec_format == 9 else None

    for idx, sec in enumerate(scan.sections):
        base = sec.asset_guess or f"legacy_{idx:02d}.{sec.kind_guess}"
        file_name = f"{_sanitize_name(base.replace('_', '.'))}.section.bin"
        out_path = out_dir / file_name
        section_bytes = decoded[sec.start:sec.end]
        out_path.write_bytes(section_bytes)
        section_bytes_by_name[file_name] = section_bytes
        if sec.asset_guess is not None:
            used_aliases.add(file_name)
        animation_headers = list(_parse_animation_headers(section_bytes)) if sec.kind_guess == "animation" else []
        ogg_off = section_bytes.find(b"OggS") if sec.kind_guess == "audio" else -1
        ogg_file = None
        if ogg_off >= 0:
            should_export_ogg = debug or (
                sec.asset_guess is not None and legacy_asset_category(sec.asset_guess)[0] == "sound"
            )
            if should_export_ogg:
                if sec.asset_guess and legacy_asset_category(sec.asset_guess)[0] == "sound":
                    ogg_base = canonical_legacy_export_name(sec.asset_guess, "").rsplit(".", 1)[0]
                else:
                    ogg_base = _sanitize_name(base.replace("_", "."))
                ogg_name = f"{ogg_base}.ogg"
                ogg_stream = _extract_ogg_stream(decoded, sec.start + ogg_off)
                (out_dir / ogg_name).write_bytes(ogg_stream if ogg_stream is not None else section_bytes[ogg_off:])
                ogg_file = ogg_name
            if sec.asset_guess and legacy_asset_category(sec.asset_guess)[0] == "sound" and should_export_ogg:
                manifest["resolved_assets"].append(sec.asset_guess)
        if sec.asset_guess is None:
            score_blob = section_bytes
            source_file = file_name
            source_offset = 0
            if ogg_off > 0x1000:
                prefix_name = f"{_sanitize_name(base.replace('_', '.'))}.prefix.section.bin"
                (out_dir / prefix_name).write_bytes(section_bytes[:ogg_off])
                section_bytes_by_name[prefix_name] = section_bytes[:ogg_off]
                score_blob = section_bytes[:ogg_off]
                source_file = prefix_name
                source_offset = 0
            alias_candidates.append(
                {
                    "ordinal": idx,
                    "source_file": source_file,
                    "source_offset": source_offset,
                    "scores": _legacy_signature_scores(score_blob),
                }
            )
        entry = {
            "ordinal": idx,
            "asset_guess": sec.asset_guess,
            "assignment_method": sec.assignment_method,
            "kind_guess": sec.kind_guess,
            "tag": sec.tag,
            "start": sec.start,
            "end": sec.end,
            "size": sec.size,
            "sha256": sec.sha256,
            "file": file_name,
            "names": list(sec.names),
            "animation_headers": animation_headers,
            "ogg_offset": ogg_off if ogg_off >= 0 else None,
            "ogg_file": ogg_file,
            "signature_scores": _legacy_signature_scores(section_bytes if ogg_off < 0 else section_bytes[:ogg_off] if ogg_off > 0x1000 else section_bytes),
        }
        manifest["sections"].append(entry)
        per_section_manifest = {
            "source_file": str(path),
            "codec_format": codec_format,
            "directory_start": scan.directory_start,
            "ordinal": idx,
            "asset_guess": sec.asset_guess,
            "assignment_method": sec.assignment_method,
            "kind_guess": sec.kind_guess,
            "tag": sec.tag,
            "start": sec.start,
            "end": sec.end,
            "size": sec.size,
            "sha256": sec.sha256,
            "file": file_name,
            "names": list(sec.names),
            "animation_headers": animation_headers,
            "ogg_offset": ogg_off if ogg_off >= 0 else None,
            "ogg_file": ogg_file,
            "signature_scores": entry["signature_scores"],
        }
        (out_dir / f"{file_name}.manifest.json").write_text(
            json.dumps(per_section_manifest, indent=2), encoding="utf-8"
        )
        if sec.asset_guess and legacy_asset_category(sec.asset_guess)[0] == "animation":
            if animation_headers:
                stub = build_animation_decompile_stub(
                    asset_name=sec.asset_guess,
                    section_sha256=sec.sha256,
                    names=sec.names,
                    animation_headers=animation_headers,
                )
                stub = _augment_legacy_animation_stub(sec.asset_guess, stub)
            else:
                stub = _build_legacy_animation_signature_stub(
                    asset_name=sec.asset_guess,
                    section_sha256=sec.sha256,
                    names=sec.names,
                    signature_scores=entry["signature_scores"],
                )
                stub = _augment_legacy_animation_stub(sec.asset_guess, stub)
            stub_text = json.dumps(stub, indent=2)
            if debug:
                (out_dir / _canonical_animation_stub_name(file_name)).write_text(
                    stub_text, encoding="utf-8"
                )
            canonical_name = _canonical_legacy_json_name(sec.asset_guess, "animation")
            if canonical_name is not None:
                (out_dir / canonical_name).write_text(
                    json.dumps(_strip_private_fields(stub), indent=2),
                    encoding="utf-8",
                )
                manifest["resolved_assets"].append(sec.asset_guess)
        elif sec.asset_guess and legacy_asset_category(sec.asset_guess)[0] == "model":
            stub = build_model_decompile_stub(
                asset_name=sec.asset_guess or base,
                section_sha256=sec.sha256,
                names=sec.names,
            )
            if debug:
                stub_text = json.dumps(stub, indent=2)
                (out_dir / _canonical_model_stub_name(file_name)).write_text(
                    stub_text, encoding="utf-8"
                )
            canonical_name = _canonical_legacy_json_name(sec.asset_guess or "", "model")
            if canonical_name is not None:
                selected_idx, selected_sec = _select_legacy_model_source_section(
                    scan,
                    decoded,
                    current_index=idx,
                    asset_name=sec.asset_guess,
                    codec_format=codec_format,
                )
                geometry_section = decoded[selected_sec.start : selected_sec.end]
                canonical_section = decoded[sec.start : sec.end]
                canonical_names = sec.names
                if (
                    selected_idx == idx
                    and codec_format == 9
                    and sec.asset_guess == "arrow_model"
                    and format9_arrow_section is not None
                ):
                    geometry_section = decoded[format9_arrow_section.start : format9_arrow_section.end]
                canonical_stub = _build_legacy_model_canonical_json(
                    sec.asset_guess,
                    canonical_section,
                    canonical_names,
                    codec_format=codec_format,
                    geometry_section=geometry_section,
                )
                model_summary = _summarize_legacy_model_stub(canonical_stub)
                (out_dir / canonical_name).write_text(
                    json.dumps(_strip_private_fields(canonical_stub), indent=2), encoding="utf-8"
                )
                entry["model_source_section_ordinal"] = selected_idx
                entry["model_source_asset_guess"] = selected_sec.asset_guess
                entry["model_typed_bone_hits"] = model_summary["typed_bone_hits"]
                entry["model_fallback_bone_hits"] = model_summary["fallback_bone_hits"]
                entry["model_segmented_record_hits"] = model_summary["segmented_record_bone_hits"]
                entry["model_child_allocated_bone_hits"] = model_summary["child_allocated_bone_hits"]
                entry["model_repaired_parent_bones"] = model_summary["repaired_parent_bones"]
                entry["model_head_child_allocations"] = model_summary["head_child_allocations"]
                entry["model_mask_child_allocated_bone_hits"] = model_summary["mask_child_allocated_bone_hits"]
                entry["model_head_structural_repairs"] = model_summary["head_structural_repairs"]
                entry["model_ear_child_allocations"] = model_summary["ear_child_allocations"]
                entry["model_foot_child_allocations"] = model_summary["foot_child_allocations"]
                entry["model_leg_child_allocations"] = model_summary["leg_child_allocations"]
                entry["model_tail_child_allocations"] = model_summary["tail_child_allocations"]
                entry["model_body_child_allocations"] = model_summary["body_child_allocations"]
                entry["model_hair_child_allocations"] = model_summary["hair_child_allocations"]
                entry["model_mouth_child_allocations"] = model_summary["mouth_child_allocations"]
                entry["model_arm_child_allocations"] = model_summary["arm_child_allocations"]
                entry["model_fanout_group_rejections"] = model_summary["fanout_group_rejections"]
                entry["model_container_parent_rejections"] = model_summary["container_parent_rejections"]
                entry["model_semantic_stage"] = model_summary["semantic_stage"]
                if sec.asset_guess:
                    manifest["resolved_assets"].append(sec.asset_guess)

    for asset_name in LEGACY_SIGNATURES:
        scored = sorted(
            (
                (
                    int(candidate["scores"].get(asset_name, 0)),
                    int(candidate["ordinal"]),
                    candidate["source_file"],
                )
                for candidate in alias_candidates
                if int(candidate["scores"].get(asset_name, 0)) > 0
            ),
            reverse=True,
        )
        if not scored:
            continue
        best_score, best_ordinal, best_source = scored[0]
        second_score = scored[1][0] if len(scored) > 1 else -1
        if best_score < 2 or best_score <= second_score:
            continue
        alias_name = f"{asset_name.replace('_', '.')}.section.bin"
        if alias_name in used_aliases:
            continue
        data = section_bytes_by_name.get(best_source)
        if data is None:
            continue
        (out_dir / alias_name).write_bytes(data)
        used_aliases.add(alias_name)
        source_entry = manifest["sections"][best_ordinal]
        if legacy_asset_category(asset_name)[0] == "animation":
            if source_entry["animation_headers"]:
                stub = build_animation_decompile_stub(
                    asset_name=asset_name,
                    section_sha256=str(source_entry["sha256"]),
                    names=tuple(str(n) for n in source_entry["names"]),
                    animation_headers=source_entry["animation_headers"],
                )
                stub = _augment_legacy_animation_stub(asset_name, stub)
            else:
                stub = _build_legacy_animation_signature_stub(
                    asset_name=asset_name,
                    section_sha256=str(source_entry["sha256"]),
                    names=tuple(str(n) for n in source_entry["names"]),
                    signature_scores=dict(source_entry["signature_scores"]),
                )
                stub = _augment_legacy_animation_stub(asset_name, stub)
            stub_text = json.dumps(stub, indent=2)
            if debug:
                (out_dir / _canonical_animation_stub_name(alias_name)).write_text(
                    stub_text, encoding="utf-8"
                )
            canonical_name = _canonical_legacy_json_name(asset_name, "animation")
            if canonical_name is not None:
                (out_dir / canonical_name).write_text(
                    json.dumps(_strip_private_fields(stub), indent=2),
                    encoding="utf-8",
                )
                manifest["resolved_assets"].append(asset_name)
        elif legacy_asset_category(asset_name)[0] == "model":
            stub = build_model_decompile_stub(
                asset_name=asset_name,
                section_sha256=str(source_entry["sha256"]),
                names=tuple(str(n) for n in source_entry["names"]),
            )
            if debug:
                stub_text = json.dumps(stub, indent=2)
                (out_dir / _canonical_model_stub_name(alias_name)).write_text(
                    stub_text, encoding="utf-8"
                )
            canonical_name = _canonical_legacy_json_name(asset_name, "model")
            if canonical_name is not None:
                data = section_bytes_by_name.get(alias_name)
                if data is not None:
                    canonical_stub = _build_legacy_model_canonical_json(
                        asset_name,
                        data,
                        tuple(str(n) for n in source_entry["names"]),
                        codec_format=codec_format,
                        geometry_section=data,
                    )
                    model_summary = _summarize_legacy_model_stub(canonical_stub)
                    (out_dir / canonical_name).write_text(
                        json.dumps(_strip_private_fields(canonical_stub), indent=2), encoding="utf-8"
                    )
                    source_entry["model_typed_bone_hits"] = model_summary["typed_bone_hits"]
                    source_entry["model_fallback_bone_hits"] = model_summary["fallback_bone_hits"]
                    source_entry["model_segmented_record_hits"] = model_summary["segmented_record_bone_hits"]
                    source_entry["model_child_allocated_bone_hits"] = model_summary["child_allocated_bone_hits"]
                    source_entry["model_repaired_parent_bones"] = model_summary["repaired_parent_bones"]
                    source_entry["model_head_child_allocations"] = model_summary["head_child_allocations"]
                    source_entry["model_mask_child_allocated_bone_hits"] = model_summary["mask_child_allocated_bone_hits"]
                    source_entry["model_head_structural_repairs"] = model_summary["head_structural_repairs"]
                    source_entry["model_ear_child_allocations"] = model_summary["ear_child_allocations"]
                    source_entry["model_foot_child_allocations"] = model_summary["foot_child_allocations"]
                    source_entry["model_leg_child_allocations"] = model_summary["leg_child_allocations"]
                    source_entry["model_tail_child_allocations"] = model_summary["tail_child_allocations"]
                    source_entry["model_body_child_allocations"] = model_summary["body_child_allocations"]
                    source_entry["model_hair_child_allocations"] = model_summary["hair_child_allocations"]
                    source_entry["model_mouth_child_allocations"] = model_summary["mouth_child_allocations"]
                    source_entry["model_arm_child_allocations"] = model_summary["arm_child_allocations"]
                    source_entry["model_fanout_group_rejections"] = model_summary["fanout_group_rejections"]
                    source_entry["model_container_parent_rejections"] = model_summary["container_parent_rejections"]
                    source_entry["model_semantic_stage"] = model_summary["semantic_stage"]
                    manifest["resolved_assets"].append(asset_name)
        manifest["pretty_aliases"].append(
            {
                "asset_name": asset_name,
                "alias_file": alias_name,
                "source_file": best_source,
                "source_section_ordinal": best_ordinal,
                "score": best_score,
            }
        )

    texture_exports = _export_legacy_textures(
        decoded,
        scan,
        out_dir,
        debug=debug,
        codec_format=codec_format,
    )
    if debug and not texture_exports:
        texture_exports = _export_legacy_textures_fallback(decoded, scan, out_dir)
    if not texture_exports:
        for stale_name in {
            "texture.png",
            "texture.2.png",
            *(canonical_legacy_export_name(asset_name, "") for asset_name in scan.expected_assets if legacy_asset_category(asset_name)[0] == "texture"),
        }:
            (out_dir / stale_name).unlink(missing_ok=True)
    manifest["texture_exports"] = [
        {
            "asset_name": item.asset_name,
            "label": item.label,
            "width": item.width,
            "height": item.height,
            "offset": item.offset,
            "raw_len": item.raw_len,
            "png_file": item.png_file,
            "sha256": item.sha256,
        }
        for item in texture_exports
    ]
    manifest["resolved_assets"].extend(item.asset_name for item in texture_exports)
    texture_sizes = {item.asset_name: (item.width, item.height) for item in texture_exports}
    main_tex_asset = next((name for name in texture_sizes if name != "arrow_texture"), None)
    for model_file, asset_name in (
        ("main.json", main_tex_asset),
        ("arm.json", main_tex_asset),
        ("arrow.json", "arrow_texture"),
    ):
        tex = texture_sizes.get(asset_name)
        model_path = out_dir / model_file
        if tex is None or not model_path.exists():
            continue
        try:
            model_obj = json.loads(model_path.read_text(encoding="utf-8"))
            geometry = model_obj.get("minecraft:geometry", [])
            if geometry and isinstance(geometry[0], dict):
                desc = geometry[0].setdefault("description", {})
                if isinstance(desc, dict):
                    desc["texture_width"] = tex[0]
                    desc["texture_height"] = tex[1]
                    model_path.write_text(json.dumps(model_obj, indent=2), encoding="utf-8")
        except Exception:
            pass

    resolved_set: set[str] = set()
    resolved_assets: list[str] = []
    for asset_name in manifest["resolved_assets"]:
        if not isinstance(asset_name, str) or not asset_name or asset_name in resolved_set:
            continue
        resolved_set.add(asset_name)
        resolved_assets.append(asset_name)
    manifest["resolved_assets"] = resolved_assets
    unresolved_assets = [
        asset_name for asset_name in scan.expected_assets
        if asset_name not in resolved_set
    ]
    for asset_name in unresolved_assets:
        if legacy_asset_category(asset_name)[0] != "animation":
            continue
        canonical_name = _canonical_legacy_json_name(asset_name, "animation")
        if canonical_name is None or (out_dir / canonical_name).exists():
            continue
        stub = _build_unresolved_legacy_animation_stub(asset_name)
        (out_dir / canonical_name).write_text(
            json.dumps(_strip_private_fields(stub), indent=2),
            encoding="utf-8",
        )
    manifest["unresolved_assets"] = unresolved_assets
    if codec_format == 1:
        _enforce_format1_output_shape(out_dir, manifest)

    (out_dir / "legacy_sections.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    if not debug:
        _prune_legacy_debug_outputs(out_dir)
    return out_dir


def print_legacy_sections(scan: LegacyScanResult) -> None:
    print(f"file: {scan.path}")
    print(f"codec_format: {scan.codec_format}")
    print(f"decoded_len: 0x{scan.decoded_len:x}")
    print(f"tail_start: 0x{scan.tail_start:x}")
    print(f"directory_start: 0x{scan.directory_start:x}")
    print(f"legacy_directory: {len(scan.directory_entries)}")
    for idx, entry in enumerate(scan.directory_entries[:12]):
        print(
            f"dir[{idx}]: control={list(entry.control)} name={entry.name!r} "
            f"property_match={entry.property_match!r}"
        )
    print(f"legacy_sections: {len(scan.sections)}")
    for idx, sec in enumerate(scan.sections):
        print(
            f"section[{idx}]: tag={sec.tag} kind={sec.kind_guess} "
            f"asset_guess={sec.asset_guess!r} start=0x{sec.start:x} len=0x{sec.size:x}"
        )
        if sec.names:
            print("  names: " + ", ".join(sec.names[:12]))


def main() -> None:
    ap = argparse.ArgumentParser(description="Heuristic legacy (format 9/15) payload section dumper")
    ap.add_argument("paths", nargs="+", type=Path)
    args = ap.parse_args()

    for path in args.paths:
        scan = scan_legacy_sections(path)
        print_legacy_sections(scan)
        out = dump_legacy_sections(path, scan)
        print(f"{path} -> {out}")


if __name__ == "__main__":
    main()
