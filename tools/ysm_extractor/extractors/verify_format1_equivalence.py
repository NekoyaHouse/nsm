from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bom_v3_legacy_sections import dump_legacy_sections
from extractors.verify_legacy_pair import _describe_model_diff, _json_equal, _load_json
from extractors.ysm_legacy_native_lift import export_legacy_native_lift
from extractors.bom_v3_end_to_end_parser import decode_bom_v3


FORMAT1_MODEL_FILES = ("main.json", "arm.json")
FORMAT1_ANIMATION_FILES = (
    "main.animation.json",
    "arm.animation.json",
    "extra.animation.json",
    "tac.animation.json",
    "carryon.animation.json",
)
FORBIDDEN_FORMAT1_FILES = ("arrow.json", "arrow.animation.json")


@dataclass(frozen=True)
class Format1Comparison:
    models_equal: bool
    animations_equal: bool
    textures_equal: bool
    sounds_equal: bool
    asset_hashes_equal: bool
    model_metadata_hashes_equal: bool
    shape_ok: bool
    hash_mismatches: tuple[str, ...]
    metadata_mismatches: tuple[str, ...]
    shape_issues: tuple[str, ...]
    details: tuple[str, ...]

    @property
    def overall_equivalent(self) -> bool:
        return (
            self.models_equal
            and self.animations_equal
            and self.textures_equal
            and self.sounds_equal
            and self.asset_hashes_equal
            and self.model_metadata_hashes_equal
            and self.shape_ok
        )


def _round_num(value: Any) -> Any:
    if isinstance(value, float):
        return round(value, 5)
    return value


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _metadata_hash(path: Path) -> tuple[str, dict[str, Any]]:
    obj = _load_json(path)
    geometry = obj.get("minecraft:geometry", [])
    geom = geometry[0] if isinstance(geometry, list) and geometry and isinstance(geometry[0], dict) else {}
    desc = geom.get("description", {}) if isinstance(geom, dict) else {}
    bones = []
    raw_bones = geom.get("bones", []) if isinstance(geom, dict) else []
    if isinstance(raw_bones, list):
        for bone in raw_bones:
            if not isinstance(bone, dict):
                continue
            bones.append(
                {
                    "name": bone.get("name"),
                    "parent": bone.get("parent"),
                    "pivot": _round_num(bone.get("pivot")),
                    "rotation": _round_num(bone.get("rotation")),
                    "cube_count": len(bone.get("cubes", [])) if isinstance(bone.get("cubes"), list) else 0,
                }
            )
    bones.sort(key=lambda item: str(item.get("name", "")))
    payload = {
        "identifier": desc.get("identifier") if isinstance(desc, dict) else None,
        "texture_width": desc.get("texture_width") if isinstance(desc, dict) else None,
        "texture_height": desc.get("texture_height") if isinstance(desc, dict) else None,
        "bone_count": len(bones),
        "cube_total": sum(int(item["cube_count"]) for item in bones),
        "bones": bones,
    }
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest(), payload


def _layout_roots(root: Path) -> tuple[Path, Path, Path, Path]:
    model_root = root / "models"
    animation_root = root / "animations"
    texture_root = root / "textures"
    sound_root = root / "sounds"
    if any(path.is_dir() for path in (model_root, animation_root, texture_root, sound_root)):
        return (
            model_root if model_root.is_dir() else root,
            animation_root if animation_root.is_dir() else root,
            texture_root if texture_root.is_dir() else root,
            sound_root if sound_root.is_dir() else root,
        )
    return root, root, root, root


def _collect_format1_assets(root: Path) -> tuple[dict[str, Path], list[Path], list[Path]]:
    model_root, animation_root, texture_root, sound_root = _layout_roots(root)
    assets: dict[str, Path] = {}
    for name in FORMAT1_MODEL_FILES:
        path = model_root / name
        if path.is_file():
            assets[name] = path
    for name in FORMAT1_ANIMATION_FILES:
        path = animation_root / name
        if path.is_file():
            assets[name] = path
    pngs = sorted(path for path in texture_root.glob("*.png") if path.is_file())
    if len(pngs) == 1:
        assets[pngs[0].name] = pngs[0]
    oggs = sorted(path for path in sound_root.glob("*.ogg") if path.is_file())
    return assets, pngs, oggs


def _asset_hashes(root: Path) -> dict[str, str]:
    assets, _pngs, _oggs = _collect_format1_assets(root)
    return {name: _sha256_file(path) for name, path in sorted(assets.items())}


def _model_metadata_hashes(root: Path) -> dict[str, str]:
    model_root, _animation_root, _texture_root, _sound_root = _layout_roots(root)
    hashes: dict[str, str] = {}
    for name in FORMAT1_MODEL_FILES:
        path = model_root / name
        if not path.is_file():
            continue
        hashes[name] = _metadata_hash(path)[0]
    return hashes


def _shape_issues(root: Path) -> list[str]:
    issues: list[str] = []
    model_root, animation_root, texture_root, sound_root = _layout_roots(root)
    for name in FORMAT1_MODEL_FILES:
        if not (model_root / name).is_file():
            issues.append(f"missing required model: {name}")
    for name in FORMAT1_ANIMATION_FILES:
        if not (animation_root / name).is_file():
            issues.append(f"missing required animation: {name}")
    for name in FORBIDDEN_FORMAT1_FILES:
        forbidden = model_root / name if name.endswith(".json") and not name.endswith(".animation.json") else animation_root / name
        if forbidden.is_file():
            issues.append(f"forbidden format1 export present: {name}")
    pngs = sorted(path for path in texture_root.glob("*.png") if path.is_file())
    if len(pngs) != 1:
        issues.append(f"expected exactly one texture png, found {len(pngs)}")
    oggs = sorted(path for path in sound_root.glob("*.ogg") if path.is_file())
    if oggs:
        issues.append(f"forbidden sound exports present: {', '.join(path.name for path in oggs)}")
    return issues


def _compare_model_group(left_root: Path, right_root: Path, *, top_bones: int) -> tuple[bool, list[str]]:
    model_left_root, _animation_left_root, _texture_left_root, _sound_left_root = _layout_roots(left_root)
    model_right_root, _animation_right_root, _texture_right_root, _sound_right_root = _layout_roots(right_root)
    equal = True
    details: list[str] = []
    for name in FORMAT1_MODEL_FILES:
        left = model_left_root / name
        right = model_right_root / name
        if _json_equal(left, right, model=True):
            continue
        equal = False
        details.extend(_describe_model_diff(left, right, name, name, top_bones=top_bones))
    return equal, details


def _compare_animation_group(left_root: Path, right_root: Path) -> bool:
    _model_left_root, animation_left_root, _texture_left_root, _sound_left_root = _layout_roots(left_root)
    _model_right_root, animation_right_root, _texture_right_root, _sound_right_root = _layout_roots(right_root)
    return all(
        _json_equal(animation_left_root / name, animation_right_root / name, model=False)
        for name in FORMAT1_ANIMATION_FILES
    )


def _compare_hash_sets(
    left_hashes: dict[str, str],
    right_hashes: dict[str, str],
) -> tuple[bool, list[str]]:
    mismatches: list[str] = []
    for name in sorted(set(left_hashes) | set(right_hashes)):
        if left_hashes.get(name) != right_hashes.get(name):
            mismatches.append(name)
    return not mismatches, mismatches


def _compare_metadata_sets(
    left_hashes: dict[str, str],
    right_hashes: dict[str, str],
) -> tuple[bool, list[str]]:
    mismatches: list[str] = []
    for name in FORMAT1_MODEL_FILES:
        if left_hashes.get(name) != right_hashes.get(name):
            mismatches.append(name)
    return not mismatches, mismatches


def _compare_format1_exports(left_root: Path, right_root: Path, *, top_bones: int) -> Format1Comparison:
    left_assets, left_pngs, left_oggs = _collect_format1_assets(left_root)
    right_assets, right_pngs, right_oggs = _collect_format1_assets(right_root)
    left_asset_hashes = {name: _sha256_file(path) for name, path in sorted(left_assets.items())}
    right_asset_hashes = {name: _sha256_file(path) for name, path in sorted(right_assets.items())}
    left_metadata = _model_metadata_hashes(left_root)
    right_metadata = _model_metadata_hashes(right_root)

    models_equal, details = _compare_model_group(left_root, right_root, top_bones=top_bones)
    animations_equal = _compare_animation_group(left_root, right_root)
    textures_equal = len(left_pngs) == len(right_pngs) == 1 and left_asset_hashes.get(left_pngs[0].name) == right_asset_hashes.get(right_pngs[0].name)
    sounds_equal = not left_oggs and not right_oggs
    asset_hashes_equal, hash_mismatches = _compare_hash_sets(left_asset_hashes, right_asset_hashes)
    model_metadata_hashes_equal, metadata_mismatches = _compare_metadata_sets(left_metadata, right_metadata)
    shape_issues = _shape_issues(left_root) + [f"reference: {item}" for item in _shape_issues(right_root)]

    return Format1Comparison(
        models_equal=models_equal,
        animations_equal=animations_equal,
        textures_equal=textures_equal,
        sounds_equal=sounds_equal,
        asset_hashes_equal=asset_hashes_equal,
        model_metadata_hashes_equal=model_metadata_hashes_equal,
        shape_ok=not shape_issues,
        hash_mismatches=tuple(hash_mismatches),
        metadata_mismatches=tuple(metadata_mismatches),
        shape_issues=tuple(shape_issues),
        details=tuple(details),
    )


def verify_format1_against_snapshot(
    ysm_path: Path,
    *,
    official_export_root: Path,
    top_bones: int = 10,
) -> int:
    ysm_path = ysm_path.resolve()
    official_export_root = official_export_root.resolve()
    codec_format = decode_bom_v3(ysm_path).codec_format
    if codec_format != 1:
        raise SystemExit(f"expected format 1, got {codec_format!r}")
    with tempfile.TemporaryDirectory(prefix="format1_heur_", dir="/tmp") as heur_tmp, tempfile.TemporaryDirectory(
        prefix="format1_native_", dir="/tmp"
    ) as native_tmp:
        heur_dir = Path(heur_tmp)
        native_dir = Path(native_tmp)
        with contextlib.redirect_stdout(io.StringIO()):
            dump_legacy_sections(ysm_path, out_dir=heur_dir, debug=False)
            export_legacy_native_lift(ysm_path, out_dir=native_dir)

        heuristic_vs_official = _compare_format1_exports(heur_dir, official_export_root, top_bones=top_bones)
        native_vs_official = _compare_format1_exports(native_dir, official_export_root, top_bones=top_bones)
        heuristic_vs_native = _compare_format1_exports(heur_dir, native_dir, top_bones=top_bones)

        print(f"file: {ysm_path}")
        print("codec_format: 1")
        print(f"official_export_root: {official_export_root}")
        print(f"heuristic_dump_folder: {heur_dir}")
        print(f"native_lift_dump_folder: {native_dir}")

        for label, root in (
            ("official", official_export_root),
            ("heuristic", heur_dir),
            ("native_lift", native_dir),
        ):
            for name, digest in sorted(_asset_hashes(root).items()):
                print(f"{label}_asset_hash: {name} {digest}")
            for name, digest in sorted(_model_metadata_hashes(root).items()):
                print(f"{label}_model_metadata_hash: {name} {digest}")

        print(f"heuristic_models_equal: {str(heuristic_vs_official.models_equal).lower()}")
        print(f"heuristic_animations_equal: {str(heuristic_vs_official.animations_equal).lower()}")
        print(f"heuristic_textures_equal: {str(heuristic_vs_official.textures_equal).lower()}")
        print(f"heuristic_sounds_equal: {str(heuristic_vs_official.sounds_equal).lower()}")
        print(f"heuristic_asset_hashes_equal: {str(heuristic_vs_official.asset_hashes_equal).lower()}")
        print(
            f"heuristic_model_metadata_hashes_equal: "
            f"{str(heuristic_vs_official.model_metadata_hashes_equal).lower()}"
        )
        print(f"heuristic_shape_ok: {str(heuristic_vs_official.shape_ok).lower()}")
        print(f"heuristic_overall_equivalent: {str(heuristic_vs_official.overall_equivalent).lower()}")

        print(f"native_lift_models_equal: {str(native_vs_official.models_equal).lower()}")
        print(f"native_lift_animations_equal: {str(native_vs_official.animations_equal).lower()}")
        print(f"native_lift_textures_equal: {str(native_vs_official.textures_equal).lower()}")
        print(f"native_lift_sounds_equal: {str(native_vs_official.sounds_equal).lower()}")
        print(f"native_lift_asset_hashes_equal: {str(native_vs_official.asset_hashes_equal).lower()}")
        print(
            f"native_lift_model_metadata_hashes_equal: "
            f"{str(native_vs_official.model_metadata_hashes_equal).lower()}"
        )
        print(f"native_lift_shape_ok: {str(native_vs_official.shape_ok).lower()}")
        print(f"native_lift_overall_equivalent: {str(native_vs_official.overall_equivalent).lower()}")

        print(
            f"heuristic_vs_native_asset_hashes_equal: "
            f"{str(heuristic_vs_native.asset_hashes_equal).lower()}"
        )
        print(
            f"heuristic_vs_native_model_metadata_hashes_equal: "
            f"{str(heuristic_vs_native.model_metadata_hashes_equal).lower()}"
        )
        print(f"heuristic_vs_native_shape_ok: {str(heuristic_vs_native.shape_ok).lower()}")

        for label, report in (
            ("heuristic", heuristic_vs_official),
            ("native_lift", native_vs_official),
            ("heuristic_vs_native", heuristic_vs_native),
        ):
            for name in report.hash_mismatches:
                print(f"{label}_hash_mismatch: {name}")
            for name in report.metadata_mismatches:
                print(f"{label}_metadata_hash_mismatch: {name}")
            for item in report.shape_issues:
                print(f"{label}_shape_issue: {item}")
            for item in report.details:
                print(f"{label}_detail: {item}")

        ok = (
            heuristic_vs_official.overall_equivalent
            and native_vs_official.overall_equivalent
            and heuristic_vs_native.asset_hashes_equal
            and heuristic_vs_native.model_metadata_hashes_equal
            and heuristic_vs_native.shape_ok
        )
        return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Verify format-1 heuristic and source-less native_lift exports against an official snapshot."
    )
    ap.add_argument("ysm_path", type=Path)
    ap.add_argument(
        "--official-export-root",
        type=Path,
        required=True,
        help="canonical format-1 official export snapshot or raw export root",
    )
    ap.add_argument("--top-bones", type=int, default=10, help="number of top per-bone deltas to print")
    args = ap.parse_args()
    return verify_format1_against_snapshot(
        args.ysm_path,
        official_export_root=args.official_export_root,
        top_bones=args.top_bones,
    )


if __name__ == "__main__":
    raise SystemExit(main())
