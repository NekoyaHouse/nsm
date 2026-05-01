from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import tempfile
from pathlib import Path
from typing import Any

from bom_v3_legacy_sections import dump_legacy_sections
from extractors.verify_legacy_pair import (
    _compare_export_tree,
    _load_json,
    _print_report,
    verify_legacy_pair,
)
from extractors.ysm_legacy_native_lift import export_legacy_native_lift, parse_legacy_native_state


def _expected_asset_map(root: Path, state) -> dict[str, Path]:
    assets: dict[str, Path] = {}
    from extractors.verify_legacy_pair import _resolve_expected_export_file

    for name in state.expected_model_files:
        path = _resolve_expected_export_file(root, name, kind="model")
        if path is not None:
            assets[name] = path
    for name in state.expected_animation_files:
        path = _resolve_expected_export_file(root, name, kind="animation")
        if path is not None:
            assets[name] = path
    for name in state.expected_texture_files:
        path = _resolve_expected_export_file(root, name, kind="texture")
        if path is not None:
            assets[name] = path
    for name in state.expected_sound_files:
        path = _resolve_expected_export_file(root, name, kind="sound")
        if path is not None:
            assets[name] = path
    return assets


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _round_num(value: Any) -> Any:
    if isinstance(value, float):
        return round(value, 5)
    return value


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


def verify_format9_against_native_lift(ysm_path: Path, *, top_bones: int = 10) -> int:
    ysm_path = ysm_path.resolve()
    state = parse_legacy_native_state(ysm_path)
    with tempfile.TemporaryDirectory(prefix="format9_heur_", dir="/tmp") as heur_tmp, tempfile.TemporaryDirectory(
        prefix="format9_native_", dir="/tmp"
    ) as native_tmp:
        heur_dir = Path(heur_tmp)
        native_dir = Path(native_tmp)
        with contextlib.redirect_stdout(io.StringIO()):
            dump_legacy_sections(ysm_path, out_dir=heur_dir, debug=False)
            export_legacy_native_lift(ysm_path, out_dir=native_dir)

        report = _compare_export_tree(heur_dir, native_dir, state=state, top_bones=top_bones)
        heur_assets = _expected_asset_map(heur_dir, state)
        native_assets = _expected_asset_map(native_dir, state)
        all_asset_names = sorted(set(heur_assets) | set(native_assets))
        hash_mismatches: list[str] = []
        for relpath in all_asset_names:
            heur_path = heur_assets.get(relpath)
            native_path = native_assets.get(relpath)
            if heur_path is None or native_path is None:
                hash_mismatches.append(relpath)
                continue
            if _sha256_file(heur_path) != _sha256_file(native_path):
                hash_mismatches.append(relpath)

        metadata_mismatches: list[str] = []
        for model_name in ("main.json", "arm.json", "arrow.json"):
            heur_path = heur_dir / model_name
            native_path = native_dir / model_name
            if not heur_path.exists() and not native_path.exists():
                continue
            if not heur_path.exists() or not native_path.exists():
                metadata_mismatches.append(model_name)
                continue
            heur_hash, heur_meta = _metadata_hash(heur_path)
            native_hash, native_meta = _metadata_hash(native_path)
            if heur_hash != native_hash:
                metadata_mismatches.append(model_name)
                print(f"metadata_mismatch: {model_name}")
                print(
                    f"metadata_detail: {model_name}: "
                    f"heur_bones={heur_meta['bone_count']} native_bones={native_meta['bone_count']} "
                    f"heur_cubes={heur_meta['cube_total']} native_cubes={native_meta['cube_total']}"
                )

        print(f"file: {ysm_path}")
        print("codec_format: 9")
        print(f"heuristic_dump_folder: {heur_dir}")
        print(f"native_lift_dump_folder: {native_dir}")
        print(f"models_equal: {str(report.models_equal).lower()}")
        print(f"animations_equal: {str(report.animations_equal).lower()}")
        print(f"textures_equal: {str(report.textures_equal).lower()}")
        print(f"sounds_equal: {str(report.sounds_equal).lower()}")
        print(f"overall_equivalent: {str(report.overall_equivalent).lower()}")
        print(f"asset_hashes_equal: {str(not hash_mismatches).lower()}")
        print(f"model_metadata_hashes_equal: {str(not metadata_mismatches).lower()}")
        for relpath in hash_mismatches:
            print(f"hash_mismatch: {relpath}")
        for relpath in metadata_mismatches:
            print(f"metadata_hash_mismatch: {relpath}")
        for item in report.mismatches:
            print(f"mismatch: {item}")
        for item in report.details:
            print(f"detail: {item}")
        return 0 if report.overall_equivalent and not hash_mismatches and not metadata_mismatches else 1


def verify_format9(ysm_path: Path, source_root: Path | None) -> int:
    report = verify_legacy_pair(ysm_path, source_root, expected_format=9)
    _print_report(report, show_official=True, official_jar=None)
    return 0 if report.overall_equivalent else 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Verify oracle-free format 9 extraction against a paired source tree."
    )
    ap.add_argument("ysm_path", type=Path)
    ap.add_argument(
        "--source-root",
        type=Path,
        help="paired source tree; if omitted, auto-discover the best nearby source-oracle candidate",
    )
    ap.add_argument(
        "--compare-native-lift",
        action="store_true",
        help="compare fresh format-9 heuristic output against fresh native_lift output instead of a source tree",
    )
    ap.add_argument("--top-bones", type=int, default=10, help="number of top per-bone deltas to print")
    args = ap.parse_args()
    if args.compare_native_lift:
        return verify_format9_against_native_lift(args.ysm_path, top_bones=args.top_bones)
    return verify_format9(args.ysm_path, args.source_root)


if __name__ == "__main__":
    raise SystemExit(main())
