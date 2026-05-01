from __future__ import annotations

import argparse
import contextlib
import io
import json
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bom_v3_legacy_sections import _png_pixels_equal
from extractors.bom_v3_end_to_end_parser import decode_bom_v3, export_bom_v3_assets
from extractors.bom_v3_source_oracle import find_best_source_oracle
from extractors.ysm_legacy_native_lift import export_legacy_native_lift, parse_legacy_native_state
from extractors.ysm262_official import probe_ysm262_official

SOUND_GLOB = "*.ogg"


@dataclass(frozen=True)
class BoneSummary:
    cube_count: int
    pivot: tuple[float, float, float] | None


@dataclass(frozen=True)
class ComparisonReport:
    root: Path
    models_equal: bool
    animations_equal: bool
    textures_equal: bool
    sounds_equal: bool
    mismatches: tuple[str, ...]
    details: tuple[str, ...]

    @property
    def overall_equivalent(self) -> bool:
        return self.models_equal and self.animations_equal and self.textures_equal and self.sounds_equal


@dataclass(frozen=True)
class VerificationReport:
    ysm_path: Path
    codec_format: int
    backend: str
    dump_folder: Path
    source_root: Path | None
    source_report: ComparisonReport | None = None
    official_report: ComparisonReport | None = None
    official_vs_source_report: ComparisonReport | None = None

    @property
    def primary_report(self) -> ComparisonReport:
        if self.source_report is not None:
            return self.source_report
        if self.official_report is not None:
            return self.official_report
        raise RuntimeError("verification report has no comparisons")

    @property
    def models_equal(self) -> bool:
        return self.primary_report.models_equal

    @property
    def animations_equal(self) -> bool:
        return self.primary_report.animations_equal

    @property
    def textures_equal(self) -> bool:
        return self.primary_report.textures_equal

    @property
    def sounds_equal(self) -> bool:
        return self.primary_report.sounds_equal

    @property
    def mismatches(self) -> tuple[str, ...]:
        return self.primary_report.mismatches

    @property
    def details(self) -> tuple[str, ...]:
        return self.primary_report.details

    @property
    def overall_equivalent(self) -> bool:
        return self.primary_report.overall_equivalent


def _round_num(value: Any) -> Any:
    if isinstance(value, float):
        return round(value, 5)
    return value


def _canon_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _canon_json(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [_canon_json(item) for item in value]
    return _round_num(value)


def _canon_model_json(obj: dict[str, Any]) -> dict[str, Any]:
    canon = _canon_json(obj)
    geometry = canon.get("minecraft:geometry")
    if not isinstance(geometry, list):
        return canon
    normalized_geometry: list[dict[str, Any]] = []
    for geom in geometry:
        if not isinstance(geom, dict):
            normalized_geometry.append(geom)
            continue
        bones = geom.get("bones")
        if isinstance(bones, list):
            geom = dict(geom)
            geom["bones"] = sorted(
                [bone for bone in bones if isinstance(bone, dict)],
                key=lambda bone: str(bone.get("name", "")),
            )
        normalized_geometry.append(geom)
    canon["minecraft:geometry"] = normalized_geometry
    return canon


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _json_equal(extracted: Path | None, source: Path | None, *, model: bool) -> bool:
    if extracted is None or source is None:
        return extracted is source
    if not extracted.exists() or not source.exists():
        return extracted.exists() == source.exists()
    out_obj = _load_json(extracted)
    src_obj = _load_json(source)
    if model:
        return _canon_model_json(out_obj) == _canon_model_json(src_obj)
    return _canon_json(out_obj) == _canon_json(src_obj)


def _find_geometry_bones(obj: Any) -> list[dict[str, Any]]:
    if not isinstance(obj, dict):
        return []
    geometry = obj.get("minecraft:geometry")
    if not isinstance(geometry, list):
        return []
    for geom in geometry:
        if not isinstance(geom, dict):
            continue
        bones = geom.get("bones")
        if isinstance(bones, list):
            return [bone for bone in bones if isinstance(bone, dict)]
    return []


def _model_bone_summary(path: Path) -> dict[str, BoneSummary]:
    bones = _find_geometry_bones(_load_json(path))
    out: dict[str, BoneSummary] = {}
    for bone in bones:
        name = bone.get("name")
        if not isinstance(name, str):
            continue
        cubes = bone.get("cubes")
        pivot = bone.get("pivot")
        pivot_tuple: tuple[float, float, float] | None = None
        if isinstance(pivot, list) and len(pivot) == 3:
            try:
                pivot_tuple = tuple(float(v) for v in pivot)
            except Exception:
                pivot_tuple = None
        out[name] = BoneSummary(
            cube_count=len(cubes) if isinstance(cubes, list) else 0,
            pivot=pivot_tuple,
        )
    return out


def _cube_total(summary: dict[str, BoneSummary]) -> int:
    return sum(item.cube_count for item in summary.values())


def _format_name_list(names: list[str], *, limit: int = 8) -> str:
    if not names:
        return "-"
    clipped = names[:limit]
    suffix = "" if len(names) <= limit else f" (+{len(names) - limit} more)"
    return ", ".join(clipped) + suffix


def _pivot_delta(a: tuple[float, float, float] | None, b: tuple[float, float, float] | None) -> float:
    if a is None or b is None:
        return 0.0
    return round(sum(abs(x - y) for x, y in zip(a, b)), 5)


def _describe_model_diff(extracted: Path, source: Path, out_name: str, src_rel: str, *, top_bones: int) -> list[str]:
    details: list[str] = []
    if not extracted.exists() or not source.exists():
        details.append(
            f"{out_name}: missing file extracted={extracted.exists()} source={source.exists()} ({src_rel})"
        )
        return details

    out_summary = _model_bone_summary(extracted)
    src_summary = _model_bone_summary(source)
    missing = sorted(set(src_summary) - set(out_summary))
    extra = sorted(set(out_summary) - set(src_summary))
    details.append(
        f"{out_name}: bones extracted={len(out_summary)} source={len(src_summary)}; "
        f"cubes extracted={_cube_total(out_summary)} source={_cube_total(src_summary)}"
    )
    if missing:
        details.append(f"{out_name}: missing bones: {_format_name_list(missing)}")
    if extra:
        details.append(f"{out_name}: extra bones: {_format_name_list(extra)}")

    cube_deltas: list[tuple[int, str, int, int]] = []
    pivot_deltas: list[tuple[float, str, tuple[float, float, float] | None, tuple[float, float, float] | None]] = []
    for name in sorted(set(out_summary) & set(src_summary)):
        out_item = out_summary[name]
        src_item = src_summary[name]
        if out_item.cube_count != src_item.cube_count:
            cube_deltas.append(
                (abs(out_item.cube_count - src_item.cube_count), name, out_item.cube_count, src_item.cube_count)
            )
        delta = _pivot_delta(out_item.pivot, src_item.pivot)
        if delta > 0.01:
            pivot_deltas.append((delta, name, out_item.pivot, src_item.pivot))

    cube_deltas.sort(key=lambda item: (-item[0], item[1]))
    pivot_deltas.sort(key=lambda item: (-item[0], item[1]))
    if cube_deltas:
        rendered = ", ".join(
            f"{name}({out_count}->{src_count})"
            for _, name, out_count, src_count in cube_deltas[:top_bones]
        )
        details.append(f"{out_name}: top cube deltas: {rendered}")
    if pivot_deltas:
        rendered = ", ".join(
            f"{name}(L1={delta:.3f})"
            for delta, name, _, _ in pivot_deltas[:top_bones]
        )
        details.append(f"{out_name}: top pivot deltas: {rendered}")
    return details


def _animation_clip_summary(path: Path) -> dict[str, dict[str, Any]]:
    obj = _load_json(path)
    animations = obj.get("animations")
    if not isinstance(animations, dict):
        return {}
    summary: dict[str, dict[str, Any]] = {}
    for clip_name, clip in animations.items():
        if not isinstance(clip_name, str) or not isinstance(clip, dict):
            continue
        bones = clip.get("bones")
        bone_map = bones if isinstance(bones, dict) else {}
        channel_count = 0
        keyframe_count = 0
        for bone_value in bone_map.values():
            if not isinstance(bone_value, dict):
                continue
            channel_count += len(bone_value)
            for channel_value in bone_value.values():
                if isinstance(channel_value, list):
                    keyframe_count += len(channel_value)
                elif channel_value is not None:
                    keyframe_count += 1
        summary[clip_name] = {
            "loop": clip.get("loop"),
            "length": clip.get("animation_length", clip.get("length")),
            "bones": sorted(name for name in bone_map if isinstance(name, str)),
            "channel_count": channel_count,
            "keyframe_count": keyframe_count,
        }
    return summary


def _describe_animation_diff(extracted: Path, source: Path, out_name: str, *, top_clips: int) -> list[str]:
    details: list[str] = []
    if not extracted.exists() or not source.exists():
        details.append(
            f"{out_name}: missing file extracted={extracted.exists()} source={source.exists()}"
        )
        return details

    out_summary = _animation_clip_summary(extracted)
    src_summary = _animation_clip_summary(source)
    missing = sorted(set(src_summary) - set(out_summary))
    extra = sorted(set(out_summary) - set(src_summary))
    details.append(
        f"{out_name}: clips extracted={len(out_summary)} source={len(src_summary)}"
    )
    if missing:
        details.append(f"{out_name}: missing clips: {_format_name_list(missing, limit=top_clips)}")
    if extra:
        details.append(f"{out_name}: extra clips: {_format_name_list(extra, limit=top_clips)}")

    loop_mismatches: list[str] = []
    length_mismatches: list[str] = []
    bone_mismatches: list[tuple[int, str, int, int]] = []
    channel_mismatches: list[tuple[int, str, int, int, int, int]] = []
    for name in sorted(set(out_summary) & set(src_summary)):
        out_item = out_summary[name]
        src_item = src_summary[name]
        if out_item["loop"] != src_item["loop"]:
            loop_mismatches.append(name)
        if out_item["length"] != src_item["length"]:
            length_mismatches.append(name)
        out_bones = set(out_item["bones"])
        src_bones = set(src_item["bones"])
        if out_bones != src_bones:
            bone_mismatches.append((abs(len(out_bones) - len(src_bones)), name, len(out_bones), len(src_bones)))
        if (
            out_item["channel_count"] != src_item["channel_count"]
            or out_item["keyframe_count"] != src_item["keyframe_count"]
        ):
            channel_mismatches.append(
                (
                    abs(int(out_item["keyframe_count"]) - int(src_item["keyframe_count"])),
                    name,
                    int(out_item["channel_count"]),
                    int(src_item["channel_count"]),
                    int(out_item["keyframe_count"]),
                    int(src_item["keyframe_count"]),
                )
            )
    if loop_mismatches:
        details.append(f"{out_name}: loop mismatches: {_format_name_list(loop_mismatches, limit=top_clips)}")
    if length_mismatches:
        details.append(f"{out_name}: duration mismatches: {_format_name_list(length_mismatches, limit=top_clips)}")
    if bone_mismatches:
        bone_mismatches.sort(key=lambda item: (-item[0], item[1]))
        rendered = ", ".join(
            f"{name}({out_bones}->{src_bones})"
            for _, name, out_bones, src_bones in bone_mismatches[:top_clips]
        )
        details.append(f"{out_name}: top bone-count deltas: {rendered}")
    if channel_mismatches:
        channel_mismatches.sort(key=lambda item: (-item[0], item[1]))
        rendered = ", ".join(
            f"{name}(channels {out_channels}->{src_channels}, keys {out_keys}->{src_keys})"
            for _, name, out_channels, src_channels, out_keys, src_keys in channel_mismatches[:top_clips]
        )
        details.append(f"{out_name}: top channel/key deltas: {rendered}")
    return details


def _resolve_expected_export_file(root: Path, file_name: str, *, kind: str) -> Path | None:
    subdir = {
        "model": "models",
        "animation": "animations",
        "texture": "textures",
        "sound": "sounds",
    }.get(kind, "")
    candidates = [root / file_name]
    if subdir:
        candidates.append(root / subdir / file_name)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    matches = sorted(path for path in root.rglob(file_name) if path.is_file())
    if len(matches) == 1:
        return matches[0]
    return matches[0] if matches else None


def _verify_json_group(
    left_root: Path,
    right_root: Path,
    file_names: tuple[str, ...],
    *,
    kind: str,
    model: bool,
    top_bones: int,
) -> tuple[list[str], list[str]]:
    mismatches: list[str] = []
    details: list[str] = []
    for file_name in file_names:
        out_path = _resolve_expected_export_file(left_root, file_name, kind=kind)
        src_path = _resolve_expected_export_file(right_root, file_name, kind=kind)
        if _json_equal(out_path, src_path, model=model):
            continue
        mismatches.append(file_name)
        if model:
            details.extend(
                _describe_model_diff(
                    out_path or (left_root / file_name),
                    src_path or (right_root / file_name),
                    file_name,
                    file_name,
                    top_bones=top_bones,
                )
            )
        elif kind == "animation":
            details.extend(
                _describe_animation_diff(
                    out_path or (left_root / file_name),
                    src_path or (right_root / file_name),
                    file_name,
                    top_clips=top_bones,
                )
            )
        else:
            details.append(
                f"{file_name}: missing file extracted={bool(out_path and out_path.exists())} "
                f"source={bool(src_path and src_path.exists())}"
            )
    return mismatches, details


def _verify_textures(
    left_root: Path,
    right_root: Path,
    file_names: tuple[str, ...],
) -> tuple[list[str], list[str]]:
    mismatches: list[str] = []
    details: list[str] = []
    for file_name in file_names:
        out_path = _resolve_expected_export_file(left_root, file_name, kind="texture")
        src_path = _resolve_expected_export_file(right_root, file_name, kind="texture")
        if out_path is None or src_path is None:
            mismatches.append(file_name)
            details.append(
                f"{file_name}: missing texture extracted={out_path is not None} source={src_path is not None}"
            )
            continue
        if not _png_pixels_equal(out_path.read_bytes(), src_path.read_bytes()):
            mismatches.append(file_name)
            details.append(f"{file_name}: texture pixels differ")
    return mismatches, details


def _verify_sounds(
    left_root: Path,
    right_root: Path,
    file_names: tuple[str, ...],
) -> tuple[list[str], list[str]]:
    mismatches: list[str] = []
    details: list[str] = []
    for file_name in file_names:
        out_path = _resolve_expected_export_file(left_root, file_name, kind="sound")
        src_path = _resolve_expected_export_file(right_root, file_name, kind="sound")
        if out_path is None or src_path is None:
            mismatches.append(file_name)
            details.append(
                f"{file_name}: missing sound extracted={out_path is not None} source={src_path is not None}"
            )
            continue
        if out_path.read_bytes() != src_path.read_bytes():
            mismatches.append(file_name)
            details.append(f"{file_name}: sound bytes differ")
    return mismatches, details


def _compare_export_tree(
    left_root: Path,
    right_root: Path,
    *,
    state,
    top_bones: int,
    asset_scope: str = "full",
) -> ComparisonReport:
    if asset_scope == "animations":
        model_mismatches = []
        model_details = []
    else:
        model_mismatches, model_details = _verify_json_group(
            left_root,
            right_root,
            state.expected_model_files,
            kind="model",
            model=True,
            top_bones=top_bones,
        )
    if asset_scope in {"models", "animations"}:
        animation_mismatches: list[str] = []
        texture_mismatches: list[str] = []
        sound_mismatches: list[str] = []
        texture_details: list[str] = []
        sound_details: list[str] = []
        animation_details: list[str] = []
        if asset_scope == "animations":
            animation_mismatches, animation_details = _verify_json_group(
                left_root,
                right_root,
                state.expected_animation_files,
                kind="animation",
                model=False,
                top_bones=top_bones,
            )
    else:
        animation_mismatches, animation_details = _verify_json_group(
            left_root,
            right_root,
            state.expected_animation_files,
            kind="animation",
            model=False,
            top_bones=top_bones,
        )
        texture_mismatches, texture_details = _verify_textures(
            left_root,
            right_root,
            state.expected_texture_files,
        )
        sound_mismatches, sound_details = _verify_sounds(
            left_root,
            right_root,
            state.expected_sound_files,
        )
    return ComparisonReport(
        root=right_root,
        models_equal=not model_mismatches,
        animations_equal=not animation_mismatches,
        textures_equal=not texture_mismatches,
        sounds_equal=not sound_mismatches,
        mismatches=tuple(model_mismatches + animation_mismatches + texture_mismatches + sound_mismatches),
        details=tuple(model_details + animation_details + texture_details + sound_details),
    )


def _prepare_comparison_root(root: Path) -> tuple[Path, tempfile.TemporaryDirectory[str] | None]:
    if root.is_file() and zipfile.is_zipfile(root):
        tmp = tempfile.TemporaryDirectory(prefix="ysm_oracle_zip_", dir="/tmp")
        with zipfile.ZipFile(root) as zf:
            zf.extractall(tmp.name)
        extracted_root = Path(tmp.name)
        children = [child for child in extracted_root.iterdir() if child.is_dir()]
        if len(children) == 1:
            return children[0], tmp
        return extracted_root, tmp
    return root, None


def verify_legacy_pair(
    ysm_path: Path,
    source_root: Path | None,
    *,
    official_export_root: Path | None = None,
    backend: str = "heuristic",
    expected_format: int | None = None,
    top_bones: int = 10,
    asset_scope: str = "full",
) -> VerificationReport:
    if source_root is None and official_export_root is None:
        best_dir, match_count, asset_count = find_best_source_oracle(ysm_path, include_archives=True)
        if best_dir is None or match_count == 0:
            raise SystemExit("no matching nearby source tree found and no official export root was provided")
        source_root = best_dir
        print(f"auto_source_root: {source_root} ({match_count}/{asset_count})")

    result = decode_bom_v3(ysm_path)
    if expected_format is not None and result.codec_format != expected_format:
        raise SystemExit(f"expected format {expected_format}, got {result.codec_format!r}")
    if result.codec_format not in (1, 9, 15):
        raise SystemExit(f"expected legacy format 1/9/15, got {result.codec_format!r}")
    state = parse_legacy_native_state(ysm_path)

    if backend == "heuristic":
        with contextlib.redirect_stdout(io.StringIO()):
            out_dir = export_bom_v3_assets(
                ysm_path,
                result.codec_format,
                scan_assets=False,
                dump_assets=False,
                dump_folder=True,
                debug=False,
            )
    elif backend == "native_lift":
        out_dir = export_legacy_native_lift(
            ysm_path,
        )
    else:
        raise SystemExit(f"unsupported backend {backend!r}")

    source_report = None
    official_report = None
    official_vs_source_report = None
    source_compare_root: Path | None = None
    official_compare_root: Path | None = None
    source_tmp: tempfile.TemporaryDirectory[str] | None = None
    official_tmp: tempfile.TemporaryDirectory[str] | None = None
    try:
        if source_root is not None:
            source_compare_root, source_tmp = _prepare_comparison_root(source_root)
            source_report = _compare_export_tree(
                out_dir,
                source_compare_root,
                state=state,
                top_bones=top_bones,
                asset_scope=asset_scope,
            )
        if official_export_root is not None:
            official_compare_root, official_tmp = _prepare_comparison_root(official_export_root)
            official_report = _compare_export_tree(
                out_dir,
                official_compare_root,
                state=state,
                top_bones=top_bones,
                asset_scope=asset_scope,
            )
            if source_compare_root is not None:
                official_vs_source_report = _compare_export_tree(
                    official_compare_root,
                    source_compare_root,
                    state=state,
                    top_bones=top_bones,
                    asset_scope=asset_scope,
                )
    finally:
        if source_tmp is not None:
            source_tmp.cleanup()
        if official_tmp is not None:
            official_tmp.cleanup()

    return VerificationReport(
        ysm_path=ysm_path,
        codec_format=result.codec_format,
        backend=backend,
        dump_folder=out_dir,
        source_root=source_root,
        source_report=source_report,
        official_report=official_report,
        official_vs_source_report=official_vs_source_report,
    )


def _print_report(report: VerificationReport, *, show_official: bool, official_jar: Path | None) -> None:
    if show_official:
        baseline = probe_ysm262_official(official_jar)
        if baseline is not None:
            print(f"official_jar: {baseline.jar_path}")
            print(f"official_jar_sha256: {baseline.jar_sha256}")
            print(f"official_native_entries: {', '.join(baseline.native_entries) or '-'}")
            if baseline.native_sha256:
                print(f"official_native_sha256: {', '.join(baseline.native_sha256)}")
            if baseline.loader_classes:
                print(f"official_loader_classes: {', '.join(baseline.loader_classes)}")
            if baseline.export_classes:
                print(f"official_export_classes: {', '.join(baseline.export_classes)}")
        else:
            print("official_jar: not_found")

    print(f"file: {report.ysm_path}")
    print(f"codec_format: {report.codec_format}")
    print(f"backend: {report.backend}")
    print(f"source_root: {report.source_root if report.source_root is not None else '-'}")
    print(f"dump_folder: {report.dump_folder}")
    print(f"models_equal: {str(report.models_equal).lower()}")
    print(f"animations_equal: {str(report.animations_equal).lower()}")
    print(f"textures_equal: {str(report.textures_equal).lower()}")
    print(f"sounds_equal: {str(report.sounds_equal).lower()}")
    print(f"overall_equivalent: {str(report.overall_equivalent).lower()}")
    for item in report.mismatches:
        print(f"mismatch: {item}")
    for item in report.details:
        print(f"detail: {item}")
    if report.official_report is not None:
        print(f"official_export_root: {report.official_report.root}")
        print(f"python_vs_official_models_equal: {str(report.official_report.models_equal).lower()}")
        print(f"python_vs_official_animations_equal: {str(report.official_report.animations_equal).lower()}")
        print(f"python_vs_official_textures_equal: {str(report.official_report.textures_equal).lower()}")
        print(f"python_vs_official_sounds_equal: {str(report.official_report.sounds_equal).lower()}")
        print(f"python_vs_official_overall_equivalent: {str(report.official_report.overall_equivalent).lower()}")
        for item in report.official_report.mismatches:
            print(f"python_vs_official_mismatch: {item}")
        for item in report.official_report.details:
            print(f"python_vs_official_detail: {item}")
    if report.official_vs_source_report is not None:
        print(f"official_vs_source_root: {report.official_vs_source_report.root}")
        print(f"official_vs_source_models_equal: {str(report.official_vs_source_report.models_equal).lower()}")
        print(f"official_vs_source_animations_equal: {str(report.official_vs_source_report.animations_equal).lower()}")
        print(f"official_vs_source_textures_equal: {str(report.official_vs_source_report.textures_equal).lower()}")
        print(f"official_vs_source_sounds_equal: {str(report.official_vs_source_report.sounds_equal).lower()}")
        print(f"official_vs_source_overall_equivalent: {str(report.official_vs_source_report.overall_equivalent).lower()}")
        for item in report.official_vs_source_report.mismatches:
            print(f"official_vs_source_mismatch: {item}")
        for item in report.official_vs_source_report.details:
            print(f"official_vs_source_detail: {item}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Verify legacy format 1/9/15 extraction against a paired source tree and/or official export snapshot."
    )
    ap.add_argument("ysm_path", type=Path)
    ap.add_argument(
        "--backend",
        choices=("heuristic", "native_lift"),
        default="heuristic",
        help="which Python extraction lane to verify",
    )
    ap.add_argument(
        "--source-root",
        type=Path,
        help="paired source tree; if omitted, auto-discover the best nearby source-oracle candidate when required",
    )
    ap.add_argument(
        "--official-export-root",
        type=Path,
        help="optional official 2.6.2 export snapshot or export root for direct python-vs-official comparison",
    )
    ap.add_argument("--expected-format", type=int, choices=(1, 9, 15))
    ap.add_argument(
        "--asset-scope",
        choices=("full", "models", "animations"),
        default="full",
        help="compare the full declared export set, only model JSONs, or only animation JSONs",
    )
    ap.add_argument("--top-bones", type=int, default=10, help="number of top per-bone deltas to print")
    ap.add_argument("--official-jar", type=Path, help="override the 2.6.2 official jar path for baseline reporting")
    ap.add_argument(
        "--no-official-baseline",
        action="store_true",
        help="skip printing the official 2.6.2 jar/native/export baseline summary",
    )
    args = ap.parse_args()

    report = verify_legacy_pair(
        args.ysm_path,
        args.source_root,
        official_export_root=args.official_export_root,
        backend=args.backend,
        expected_format=args.expected_format,
        top_bones=args.top_bones,
        asset_scope=args.asset_scope,
    )
    _print_report(
        report,
        show_official=not args.no_official_baseline,
        official_jar=args.official_jar,
    )
    return 0 if report.overall_equivalent else 1


if __name__ == "__main__":
    raise SystemExit(main())
