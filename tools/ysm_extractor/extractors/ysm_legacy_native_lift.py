from __future__ import annotations

import argparse
import contextlib
import io
import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from bom_v3_legacy_sections import dump_legacy_sections, scan_legacy_sections
from extractors.bom_v3_end_to_end_parser import decode_bom_v3
from extractors.bom_v3_payload_assets import (
    _read_property_name,
    _sanitize_name,
    parse_property_assets,
)
from extractors.legacy_asset_inventory import (
    build_legacy_declared_export_inventory,
    canonical_legacy_export_name,
    legacy_asset_category,
)
from extractors.bom_v3_source_oracle import find_best_source_oracle, restore_from_source_oracle
from extractors.ysgp_container_scanner import scan_file
from extractors.ysm262_oracle import snapshot_official_export


NATIVE_DISPATCH_CHAIN = (
    "0x5190e0 FUN_005190e0 inner decoded-section parser/dispatcher",
    "0x526ce0 FUN_00526ce0 legacy intermediate schema loader",
    "0x520500 FUN_00520500 shared low-format builder/materializer",
)

@dataclass(frozen=True)
class LegacyNativeAssetSpec:
    ordinal: int
    tag: str
    label: str
    hash_hex: str
    category: str
    family: str
    export_name: str


@dataclass(frozen=True)
class LegacySanityIssue:
    severity: str
    path: str
    message: str


@dataclass(frozen=True)
class LegacyNativeState:
    path: Path
    property_name: str | None
    codec_format: int
    decoded_len: int
    generic_families: tuple[str, ...]
    has_arrow_family: bool
    has_sound_resource: bool
    expected_model_files: tuple[str, ...]
    expected_animation_files: tuple[str, ...]
    expected_texture_files: tuple[str, ...]
    expected_sound_files: tuple[str, ...]
    expected_texture_count: int
    expected_sound_count: int
    assets: tuple[LegacyNativeAssetSpec, ...]
    native_dispatch_chain: tuple[str, ...]


@dataclass(frozen=True)
class LegacyNativeExportResult:
    out_dir: Path
    state: LegacyNativeState
    materialization_backend: str
    source_root: Path | None
    official_export_root: Path | None
    source_match_count: int
    source_asset_count: int
    sanity_issues: tuple[LegacySanityIssue, ...]


def _default_out_dir(ysm_path: Path, codec_format: int) -> Path:
    folder_name = _sanitize_name(_read_property_name(ysm_path) or ysm_path.stem)
    return ysm_path.with_name(f"{folder_name}_native_lift_format{codec_format}")


def _state_from_assets(ysm_path: Path) -> LegacyNativeState:
    result = decode_bom_v3(ysm_path)
    codec_format = result.codec_format
    if codec_format not in (1, 9, 15):
        raise RuntimeError(f"legacy native lift only supports formats 1, 9, and 15; got {codec_format!r}")

    assets = parse_property_assets(scan_file(ysm_path, dump=False).property_text)
    inventory = build_legacy_declared_export_inventory(tuple(assets), codec_format)
    asset_specs = tuple(
        LegacyNativeAssetSpec(
            ordinal=asset.ordinal,
            tag=asset.tag,
            label=asset.label,
            hash_hex=asset.hash_hex,
            category=legacy_asset_category(asset.tag)[0],
            family=legacy_asset_category(asset.tag)[1],
            export_name=canonical_legacy_export_name(asset.tag, asset.label, codec_format),
        )
        for asset in assets
    )
    texture_count = len(inventory.texture_files)
    sound_count = len(inventory.sound_files)
    has_arrow_family = any(asset.family == "arrow" for asset in asset_specs)
    return LegacyNativeState(
        path=ysm_path,
        property_name=_read_property_name(ysm_path),
        codec_format=codec_format,
        decoded_len=len(result.decompressed),
        generic_families=("main", "arm"),
        has_arrow_family=has_arrow_family,
        has_sound_resource=sound_count > 0,
        expected_model_files=inventory.model_files,
        expected_animation_files=inventory.animation_files,
        expected_texture_files=inventory.texture_files,
        expected_sound_files=inventory.sound_files,
        expected_texture_count=texture_count,
        expected_sound_count=sound_count,
        assets=asset_specs,
        native_dispatch_chain=NATIVE_DISPATCH_CHAIN,
    )


def parse_legacy_native_state(path: Path) -> LegacyNativeState:
    return _state_from_assets(path.resolve())


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _iter_model_bones(path: Path) -> list[dict[str, Any]]:
    obj = _load_json(path)
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


def _vector_has_nonfinite(values: Any) -> bool:
    if not isinstance(values, list):
        return False
    for value in values:
        if not isinstance(value, (int, float)):
            continue
        if not math.isfinite(float(value)):
            return True
    return False


def _run_sanity_checks(state: LegacyNativeState, out_dir: Path) -> tuple[LegacySanityIssue, ...]:
    issues: list[LegacySanityIssue] = []
    for file_name in state.expected_model_files:
        path = out_dir / file_name
        if not path.exists():
            issues.append(LegacySanityIssue("error", file_name, "missing expected model output"))
            continue
        try:
            bones = _iter_model_bones(path)
        except Exception as exc:
            issues.append(LegacySanityIssue("error", file_name, f"unreadable model json: {exc}"))
            continue
        for bone in bones:
            bone_name = str(bone.get("name", "<unnamed>"))
            pivot = bone.get("pivot")
            if _vector_has_nonfinite(pivot):
                issues.append(LegacySanityIssue("error", file_name, f"{bone_name}: non-finite pivot"))
            if isinstance(pivot, list) and len(pivot) >= 2:
                try:
                    if abs(float(pivot[1])) > 128.0:
                        issues.append(
                            LegacySanityIssue(
                                "warning",
                                file_name,
                                f"{bone_name}: suspicious pivot Y {float(pivot[1]):.3f}",
                            )
                        )
                except Exception:
                    pass
            cubes = bone.get("cubes")
            if not isinstance(cubes, list):
                continue
            for index, cube in enumerate(cubes):
                if not isinstance(cube, dict):
                    continue
                origin = cube.get("origin")
                size = cube.get("size")
                if _vector_has_nonfinite(origin):
                    issues.append(LegacySanityIssue("error", file_name, f"{bone_name}: cube[{index}] non-finite origin"))
                if _vector_has_nonfinite(size):
                    issues.append(LegacySanityIssue("error", file_name, f"{bone_name}: cube[{index}] non-finite size"))
                if isinstance(origin, list):
                    try:
                        if any(abs(float(v)) > 256.0 for v in origin[:3]):
                            issues.append(
                                LegacySanityIssue(
                                    "warning",
                                    file_name,
                                    f"{bone_name}: cube[{index}] suspicious origin {origin[:3]}",
                                )
                            )
                    except Exception:
                        pass
                if isinstance(size, list):
                    try:
                        if any(abs(float(v)) > 256.0 for v in size[:3]):
                            issues.append(
                                LegacySanityIssue(
                                    "warning",
                                    file_name,
                                    f"{bone_name}: cube[{index}] suspicious size {size[:3]}",
                                )
                            )
                    except Exception:
                        pass

    for file_name in state.expected_animation_files:
        if not (out_dir / file_name).exists():
            issues.append(LegacySanityIssue("error", file_name, "missing expected animation output"))
    for file_name in state.expected_texture_files:
        if not (out_dir / file_name).exists():
            issues.append(LegacySanityIssue("error", file_name, "missing expected texture output"))
    for file_name in state.expected_sound_files:
        if not (out_dir / file_name).exists():
            issues.append(LegacySanityIssue("error", file_name, "missing expected sound output"))
    return tuple(issues)


def _write_state_files(
    out_dir: Path,
    state: LegacyNativeState,
    *,
    materialization_backend: str | None = None,
    used_source_oracle: bool | None = None,
    semantic_stage: str | None = None,
    record_family_counts: dict[str, int] | None = None,
    builder_family_counts: dict[str, int] | None = None,
    source_root: Path | None = None,
    official_export_root: Path | None = None,
    source_match_count: int = 0,
    source_asset_count: int = 0,
    sanity_issues: tuple[LegacySanityIssue, ...] = (),
) -> None:
    state_manifest = {
        "path": str(state.path),
        "property_name": state.property_name,
        "codec_format": state.codec_format,
        "decoded_len": state.decoded_len,
        "generic_families": list(state.generic_families),
        "has_arrow_family": state.has_arrow_family,
        "has_sound_resource": state.has_sound_resource,
        "expected_model_files": list(state.expected_model_files),
        "expected_animation_files": list(state.expected_animation_files),
        "expected_texture_files": list(state.expected_texture_files),
        "expected_sound_files": list(state.expected_sound_files),
        "expected_texture_count": state.expected_texture_count,
        "expected_sound_count": state.expected_sound_count,
        "native_dispatch_chain": list(state.native_dispatch_chain),
        "assets": [asdict(asset) for asset in state.assets],
    }
    (out_dir / "native_lift_state.json").write_text(json.dumps(state_manifest, indent=2), encoding="utf-8")
    manifest = {
        "source_file": str(state.path),
        "property_name": state.property_name,
        "codec_format": state.codec_format,
        "materialization_backend": materialization_backend,
        "used_source_oracle": used_source_oracle,
        "semantic_stage": semantic_stage,
        "record_family_counts": record_family_counts or {},
        "builder_family_counts": builder_family_counts or {},
        "source_root": str(source_root) if source_root is not None else None,
        "official_export_root": str(official_export_root) if official_export_root is not None else None,
        "source_match_count": source_match_count,
        "source_asset_count": source_asset_count,
        "sanity_issue_count": len(sanity_issues),
        "error_level_sanity_count": sum(1 for item in sanity_issues if item.severity == "error"),
        "warning_level_sanity_count": sum(1 for item in sanity_issues if item.severity == "warning"),
        "sanity_issues": [asdict(item) for item in sanity_issues],
    }
    (out_dir / "native_lift_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def _record_family_counts(scan) -> dict[str, int]:
    counts: dict[str, int] = {
        "sections_total": len(scan.sections),
        "directory_entries": len(scan.directory_entries),
    }
    for section in scan.sections:
        key = f"{section.kind_guess}_sections"
        counts[key] = counts.get(key, 0) + 1
    return counts


def _builder_family_counts(state: LegacyNativeState) -> dict[str, int]:
    return {
        "generic_families": len(state.generic_families),
        "arrow_families": 1 if state.has_arrow_family else 0,
        "sound_resources": 1 if state.has_sound_resource else 0,
        "model_outputs": len(state.expected_model_files),
        "animation_outputs": len(state.expected_animation_files),
        "texture_outputs": len(state.expected_texture_files),
        "sound_outputs": len(state.expected_sound_files),
    }


def _read_legacy_sections_summary(out_dir: Path) -> dict[str, int]:
    manifest_path = out_dir / "legacy_sections.json"
    if not manifest_path.exists():
        return {}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    sections = manifest.get("sections")
    if not isinstance(sections, list):
        return {}
    routed_outputs = 0
    model_outputs = 0
    typed_model_outputs = 0
    typed_bone_hits = 0
    segmented_model_outputs = 0
    segmented_bone_hits = 0
    child_allocated_model_outputs = 0
    child_allocated_bone_hits = 0
    head_child_allocated_model_outputs = 0
    head_child_allocated_bone_hits = 0
    detail_child_allocated_model_outputs = 0
    detail_child_allocated_bone_hits = 0
    for entry in sections:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("asset_guess", "")).endswith("_model"):
            model_outputs += 1
            if entry.get("model_source_section_ordinal") is not None:
                routed_outputs += 1
            hits = int(entry.get("model_typed_bone_hits", 0) or 0)
            typed_bone_hits += hits
            if hits > 0:
                typed_model_outputs += 1
            segmented_hits = int(entry.get("model_segmented_record_hits", 0) or 0)
            segmented_bone_hits += segmented_hits
            if segmented_hits > 0:
                segmented_model_outputs += 1
            child_hits = int(entry.get("model_child_allocated_bone_hits", 0) or 0)
            child_allocated_bone_hits += child_hits
            if child_hits > 0:
                child_allocated_model_outputs += 1
            head_child_hits = int(entry.get("model_head_child_allocations", 0) or 0)
            head_child_allocated_bone_hits += head_child_hits
            if head_child_hits > 0:
                head_child_allocated_model_outputs += 1
            detail_child_hits = (
                int(entry.get("model_ear_child_allocations", 0) or 0)
                + int(entry.get("model_foot_child_allocations", 0) or 0)
                + int(entry.get("model_leg_child_allocations", 0) or 0)
                + int(entry.get("model_tail_child_allocations", 0) or 0)
                + int(entry.get("model_body_child_allocations", 0) or 0)
            )
            detail_child_allocated_bone_hits += detail_child_hits
            if detail_child_hits > 0:
                detail_child_allocated_model_outputs += 1
    return {
        "legacy_sections_model_outputs": model_outputs,
        "legacy_sections_model_source_routed_outputs": routed_outputs,
        "legacy_sections_typed_model_outputs": typed_model_outputs,
        "legacy_sections_typed_model_bone_hits": typed_bone_hits,
        "legacy_sections_segmented_model_outputs": segmented_model_outputs,
        "legacy_sections_segmented_model_bone_hits": segmented_bone_hits,
        "legacy_sections_child_allocated_model_outputs": child_allocated_model_outputs,
        "legacy_sections_child_allocated_model_bone_hits": child_allocated_bone_hits,
        "legacy_sections_head_child_allocated_model_outputs": head_child_allocated_model_outputs,
        "legacy_sections_head_child_allocated_model_bone_hits": head_child_allocated_bone_hits,
        "legacy_sections_detail_child_allocated_model_outputs": detail_child_allocated_model_outputs,
        "legacy_sections_detail_child_allocated_model_bone_hits": detail_child_allocated_bone_hits,
    }


def export_legacy_native_lift(
    path: Path,
    out_dir: Path | None = None,
    *,
    debug: bool = False,
    source_root: Path | None = None,
    official_export_root: Path | None = None,
) -> Path:
    del debug
    ysm_path = path.resolve()
    state = parse_legacy_native_state(ysm_path)
    out_dir = (out_dir or _default_out_dir(ysm_path, state.codec_format)).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    materialization_backend: str
    chosen_source_root: Path | None = source_root.resolve() if source_root is not None else None
    chosen_official_root: Path | None = official_export_root.resolve() if official_export_root is not None else None
    source_match_count = 0
    source_asset_count = len(state.assets)
    used_source_oracle = False
    semantic_stage = "schema_only"
    record_family_counts: dict[str, int] = {}

    if chosen_official_root is not None:
        snapshot_official_export(chosen_official_root, out_dir=out_dir, ysm_path=ysm_path)
        materialization_backend = "official_export_snapshot"
        semantic_stage = "official_snapshot_baseline"
    else:
        if chosen_source_root is None:
            if state.codec_format in (1, 9, 15):
                scan = scan_legacy_sections(ysm_path)
                with contextlib.redirect_stdout(io.StringIO()):
                    dump_legacy_sections(ysm_path, scan=scan, debug=False, out_dir=out_dir)
                materialization_backend = "legacy_sections_source_less"
                semantic_stage = "source_less_partial"
                record_family_counts = _record_family_counts(scan)
                section_summary = _read_legacy_sections_summary(out_dir)
                if section_summary:
                    record_family_counts.update(section_summary)
                    child_allocated_outputs = section_summary.get("legacy_sections_child_allocated_model_outputs", 0)
                    head_child_allocated_outputs = section_summary.get("legacy_sections_head_child_allocated_model_outputs", 0)
                    detail_child_allocated_outputs = section_summary.get("legacy_sections_detail_child_allocated_model_outputs", 0)
                    segmented_outputs = section_summary.get("legacy_sections_segmented_model_outputs", 0)
                    typed_outputs = section_summary.get("legacy_sections_typed_model_outputs", 0)
                    routed_outputs = section_summary.get("legacy_sections_model_source_routed_outputs", 0)
                    if detail_child_allocated_outputs > 0 and routed_outputs > 0:
                        semantic_stage = "source_less_family_routed_typed_segmented_child_allocated_head_mask_detail_model_partial"
                    elif detail_child_allocated_outputs > 0:
                        semantic_stage = "source_less_typed_segmented_child_allocated_head_mask_detail_model_partial"
                    elif head_child_allocated_outputs > 0 and routed_outputs > 0:
                        semantic_stage = "source_less_family_routed_typed_segmented_child_allocated_head_mask_model_partial"
                    elif head_child_allocated_outputs > 0:
                        semantic_stage = "source_less_typed_segmented_child_allocated_head_mask_model_partial"
                    elif child_allocated_outputs > 0 and routed_outputs > 0:
                        semantic_stage = "source_less_family_routed_typed_segmented_child_allocated_model_partial"
                    elif child_allocated_outputs > 0:
                        semantic_stage = "source_less_typed_segmented_child_allocated_model_partial"
                    elif segmented_outputs > 0 and routed_outputs > 0:
                        semantic_stage = "source_less_family_routed_typed_segmented_model_partial"
                    elif segmented_outputs > 0:
                        semantic_stage = "source_less_typed_segmented_model_partial"
                    elif typed_outputs > 0 and routed_outputs > 0:
                        semantic_stage = "source_less_family_routed_typed_model_partial"
                    elif typed_outputs > 0:
                        semantic_stage = "source_less_typed_model_partial"
                    elif routed_outputs > 0:
                        semantic_stage = "source_less_family_routed_partial"
            else:
                best_source, source_match_count, source_asset_count = find_best_source_oracle(ysm_path)
                if best_source is not None:
                    chosen_source_root = best_source.resolve()
        if chosen_source_root is not None:
            summary = restore_from_source_oracle(
                ysm_path,
                chosen_source_root,
                out_dir=out_dir,
                clean=True,
                prefer_source_filenames=False,
            )
            source_match_count = summary.match_count
            source_asset_count = summary.asset_count
            if source_match_count == 0:
                raise RuntimeError(f"source oracle {chosen_source_root} did not match any property-hash assets for {ysm_path.name}")
            materialization_backend = "source_oracle_exact_restore"
            used_source_oracle = True
            semantic_stage = "oracle_exact_materialization"
        elif chosen_official_root is None and state.codec_format not in (1, 9, 15):
            raise RuntimeError(
                "native lift export still needs --official-export-root or --source-root for this format; "
                "source-less semantic export is only prepared for legacy 1/9/15 at the moment"
            )

    sanity_issues = _run_sanity_checks(state, out_dir)
    _write_state_files(
        out_dir,
        state,
        materialization_backend=materialization_backend,
        used_source_oracle=used_source_oracle,
        semantic_stage=semantic_stage,
        record_family_counts=record_family_counts,
        builder_family_counts=_builder_family_counts(state),
        source_root=chosen_source_root,
        official_export_root=chosen_official_root,
        source_match_count=source_match_count,
        source_asset_count=source_asset_count,
        sanity_issues=sanity_issues,
    )
    return out_dir


def dump_legacy_native_schema(path: Path, out_dir: Path | None = None) -> Path:
    ysm_path = path.resolve()
    state = parse_legacy_native_state(ysm_path)
    out_dir = (out_dir or _default_out_dir(ysm_path, state.codec_format)).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    _write_state_files(out_dir, state)
    return out_dir


def _print_state_summary(state: LegacyNativeState) -> None:
    print(f"file: {state.path}")
    print(f"property_name: {state.property_name}")
    print(f"codec_format: {state.codec_format}")
    print(f"decoded_len: {state.decoded_len}")
    print(f"generic_families: {', '.join(state.generic_families)}")
    print(f"has_arrow_family: {str(state.has_arrow_family).lower()}")
    print(f"has_sound_resource: {str(state.has_sound_resource).lower()}")
    print(f"expected_model_files: {', '.join(state.expected_model_files)}")
    print(f"expected_animation_files: {', '.join(state.expected_animation_files)}")
    print(f"expected_texture_files: {', '.join(state.expected_texture_files)}")
    print(f"expected_sound_files: {', '.join(state.expected_sound_files)}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Schema-first Python lift for YSM legacy export research. This path is strict: it models the recovered native families and only materializes exact outputs when an oracle baseline is available."
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    export = sub.add_parser("export", help="materialize a legacy export folder through the strict native-lift lane")
    export.add_argument("ysm_path", type=Path)
    export.add_argument("--out-dir", type=Path)
    export.add_argument("--source-root", type=Path, help="optional source-oracle tree for exact restore materialization")
    export.add_argument("--official-export-root", type=Path, help="optional real YSM export root or snapshot to normalize")
    export.add_argument("--debug", action="store_true", help="reserved for future semantic record dumps")

    dump = sub.add_parser("dump-schema", help="dump the recovered native state model without materializing assets")
    dump.add_argument("ysm_path", type=Path)
    dump.add_argument("--out-dir", type=Path)

    args = ap.parse_args()
    if args.cmd == "dump-schema":
        out_dir = dump_legacy_native_schema(args.ysm_path, out_dir=args.out_dir)
        state = parse_legacy_native_state(args.ysm_path.resolve())
        _print_state_summary(state)
        print(f"schema_dump: {out_dir}")
        return 0

    out_dir = export_legacy_native_lift(
        args.ysm_path,
        out_dir=args.out_dir,
        debug=args.debug,
        source_root=args.source_root,
        official_export_root=args.official_export_root,
    )
    manifest = json.loads((out_dir / "native_lift_manifest.json").read_text(encoding="utf-8"))
    state = parse_legacy_native_state(args.ysm_path.resolve())
    _print_state_summary(state)
    print(f"materialization_backend: {manifest['materialization_backend']}")
    print(f"used_source_oracle: {str(bool(manifest['used_source_oracle'])).lower()}")
    print(f"semantic_stage: {manifest['semantic_stage']}")
    if manifest["source_root"] is not None:
        print(f"source_root: {manifest['source_root']}")
        print(f"source_match: {manifest['source_match_count']}/{manifest['source_asset_count']}")
    if manifest["official_export_root"] is not None:
        print(f"official_export_root: {manifest['official_export_root']}")
    print(f"sanity_issue_count: {manifest['sanity_issue_count']}")
    print(f"error_level_sanity_count: {manifest['error_level_sanity_count']}")
    print(f"warning_level_sanity_count: {manifest['warning_level_sanity_count']}")
    print(f"dump_folder: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
