from __future__ import annotations

import argparse
from pathlib import Path

from extractors.bom_v3_source_oracle import find_best_source_oracle
from extractors.verify_legacy_pair import _compare_export_tree, verify_legacy_pair
from extractors.ysm_legacy_native_lift import parse_legacy_native_state


def verify_format15_equivalence(
    ysm_path: Path,
    source_root: Path | None,
    *,
    top_bones: int = 10,
    asset_scope: str = "full",
) -> int:
    ysm_path = ysm_path.resolve()
    state = parse_legacy_native_state(ysm_path)
    if state.codec_format != 15:
        raise SystemExit(f"expected format 15, got {state.codec_format!r}")

    if source_root is None:
        best_root, match_count, asset_count = find_best_source_oracle(ysm_path, include_archives=True)
        if best_root is not None and match_count > 0:
            source_root = best_root
            print(f"auto_source_root: {source_root} ({match_count}/{asset_count})")

    heuristic_report = verify_legacy_pair(
        ysm_path,
        source_root,
        backend="heuristic",
        expected_format=15,
        top_bones=top_bones,
        asset_scope=asset_scope,
    )
    native_report = verify_legacy_pair(
        ysm_path,
        source_root,
        backend="native_lift",
        expected_format=15,
        top_bones=top_bones,
        asset_scope=asset_scope,
    )
    heuristic_vs_native = _compare_export_tree(
        heuristic_report.dump_folder,
        native_report.dump_folder,
        state=state,
        top_bones=top_bones,
        asset_scope=asset_scope,
    )

    print(f"file: {ysm_path}")
    print("codec_format: 15")
    print(f"source_root: {source_root if source_root is not None else '-'}")
    print(f"heuristic_dump_folder: {heuristic_report.dump_folder}")
    print(f"native_lift_dump_folder: {native_report.dump_folder}")
    print(f"heuristic_vs_native_models_equal: {str(heuristic_vs_native.models_equal).lower()}")
    print(f"heuristic_vs_native_animations_equal: {str(heuristic_vs_native.animations_equal).lower()}")
    print(f"heuristic_vs_native_textures_equal: {str(heuristic_vs_native.textures_equal).lower()}")
    print(f"heuristic_vs_native_sounds_equal: {str(heuristic_vs_native.sounds_equal).lower()}")
    print(f"heuristic_vs_native_overall_equivalent: {str(heuristic_vs_native.overall_equivalent).lower()}")
    for item in heuristic_vs_native.mismatches:
        print(f"heuristic_vs_native_mismatch: {item}")
    for item in heuristic_vs_native.details:
        print(f"heuristic_vs_native_detail: {item}")

    if heuristic_report.source_report is not None:
        report = heuristic_report.source_report
        print(f"heuristic_vs_oracle_models_equal: {str(report.models_equal).lower()}")
        print(f"heuristic_vs_oracle_animations_equal: {str(report.animations_equal).lower()}")
        print(f"heuristic_vs_oracle_textures_equal: {str(report.textures_equal).lower()}")
        print(f"heuristic_vs_oracle_sounds_equal: {str(report.sounds_equal).lower()}")
        print(f"heuristic_vs_oracle_overall_equivalent: {str(report.overall_equivalent).lower()}")
        for item in report.mismatches:
            print(f"heuristic_vs_oracle_mismatch: {item}")
        for item in report.details:
            print(f"heuristic_vs_oracle_detail: {item}")
    if native_report.source_report is not None:
        report = native_report.source_report
        print(f"native_lift_vs_oracle_models_equal: {str(report.models_equal).lower()}")
        print(f"native_lift_vs_oracle_animations_equal: {str(report.animations_equal).lower()}")
        print(f"native_lift_vs_oracle_textures_equal: {str(report.textures_equal).lower()}")
        print(f"native_lift_vs_oracle_sounds_equal: {str(report.sounds_equal).lower()}")
        print(f"native_lift_vs_oracle_overall_equivalent: {str(report.overall_equivalent).lower()}")
        for item in report.mismatches:
            print(f"native_lift_vs_oracle_mismatch: {item}")
        for item in report.details:
            print(f"native_lift_vs_oracle_detail: {item}")

    ok = heuristic_vs_native.overall_equivalent
    if source_root is not None:
        ok = ok and bool(heuristic_report.source_report and heuristic_report.source_report.overall_equivalent)
        ok = ok and bool(native_report.source_report and native_report.source_report.overall_equivalent)
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Verify format-15 heuristic and source-less native_lift exports against each other and a nearby folder/zip oracle when available."
    )
    ap.add_argument("ysm_path", type=Path)
    ap.add_argument("--source-root", type=Path, help="optional paired source tree or zip archive")
    ap.add_argument(
        "--asset-scope",
        choices=("full", "models", "animations"),
        default="full",
        help="compare the full declared export set, only model JSONs, or only animation JSONs",
    )
    ap.add_argument("--top-bones", type=int, default=10, help="number of top per-bone deltas to print")
    args = ap.parse_args()
    return verify_format15_equivalence(
        args.ysm_path,
        args.source_root,
        top_bones=args.top_bones,
        asset_scope=args.asset_scope,
    )


if __name__ == "__main__":
    raise SystemExit(main())
