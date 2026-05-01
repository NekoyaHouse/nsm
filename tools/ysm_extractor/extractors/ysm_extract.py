from __future__ import annotations

import argparse
import base64
import json
import os
import shlex
import sys
from pathlib import Path
from typing import Iterable

from extractors.bom_v3_end_to_end_parser import decode_bom_v3, export_or_restore_bom_v3_assets
from extractors.ysm262_oracle import (
    DEFAULT_FORGE_VERSION_ID,
    DEFAULT_HEADED_DEBUG_PROFILE_ID,
    DEFAULT_HEADED_DEBUG_PROFILE_NAME,
    DEFAULT_MINECRAFT_ROOT,
    HeadedModelTraceConfig,
    capture_legacy_export,
    summarize_model_trace,
    _parse_model_trace_family_filter,
    snapshot_official_export,
    stage_headed_host_bundle,
)
from extractors.ysgp_compact_v2_parser import extract_entry_payloads, parse_compact_v2_file
from ysgp_outer_v3_static import MAGIC_PREFIX


def _sanitize_name(name: str) -> str:
    out: list[str] = []
    for ch in name:
        if ch.isalnum() or ch in ("-", "_", "."):
            out.append(ch)
        else:
            out.append("_")
    return "".join(out) or "entry"


def _format_family(codec_format: int | None) -> str:
    if codec_format == 31:
        return "modern_31"
    if codec_format in (1, 9, 15):
        return "legacy_1_9_15"
    if codec_format is None:
        return "unknown"
    return f"unsupported_{codec_format}"


def _detect_container(data: bytes) -> tuple[str, int | None]:
    if data.startswith(MAGIC_PREFIX):
        return ("bom_v3", 3)
    if data[:4] == b"YSGP" and len(data) >= 8:
        ver_be = int.from_bytes(data[4:8], "big")
        return ("compact_ysgp", ver_be)
    return ("unknown", None)


def _handle_bom_v3(path: Path, args: argparse.Namespace) -> None:
    result = decode_bom_v3(path)
    exported_dir: Path | None = None

    print(f"file: {path}")
    print("container: bom_v3")
    print(f"codec_format: {result.codec_format}")
    print(f"format_family: {_format_family(result.codec_format)}")
    print(f"prelude_skip: {result.prelude_skip}")
    print(f"wrapped_offset: 0x{result.wrapped_offset:x}")
    print(f"transcoded_zst_len: 0x{len(result.transcoded_zst):x}")
    print(f"decoded_len: 0x{len(result.decompressed):x}")
    print(f"decoded_head64: {result.decompressed[:64].hex()}")

    if args.dump_zst:
        zst_path = path.with_name(f"{path.stem}.transcoded.zst")
        zst_path.write_bytes(result.transcoded_zst)
        print(f"dump_zst: {zst_path}")

    if args.dump_decoded:
        decoded_path = path.with_name(f"{path.stem}.decoded.bin")
        decoded_path.write_bytes(result.decompressed)
        print(f"dump_decoded: {decoded_path}")

    if args.scan_assets or args.dump_assets or args.dump_folder or args.source_oracle is not None:
        exported_dir, source_oracle_path, oracle = export_or_restore_bom_v3_assets(
            path,
            result.codec_format,
            scan_assets=args.scan_assets,
            dump_assets=args.dump_assets,
            dump_folder=args.dump_folder,
            debug=args.debug,
            source_oracle=args.source_oracle,
            legacy_auto_source_oracle=args.auto_source_oracle,
        )
        if exported_dir is not None:
            print(f"dump_folder: {exported_dir}")
        if oracle is not None and source_oracle_path is not None:
            if args.source_oracle is not None:
                print(f"source_oracle_restore: {oracle.out_dir}")
            else:
                print(f"source_oracle_auto: {source_oracle_path} ({oracle.match_count}/{oracle.asset_count})")
                print(f"source_oracle_restore: {oracle.out_dir}")
            print(f"source_oracle_match: {oracle.match_count}/{oracle.asset_count}")
            print(f"exact_restore_complete: {str(oracle.exact_complete).lower()}")


def _dump_compact_entries(path: Path, dump_entries: bool) -> None:
    container = parse_compact_v2_file(path)
    print(f"file: {path}")
    print("container: compact_v2")
    print(f"version_be: {container.version_be}")
    print(f"header_md5_16: {container.header_md5_16.hex()}")
    print(f"header_md5_verified: {container.header_md5_verified}")
    print(f"entry_count: {len(container.entries)}")

    for entry, payload, key in extract_entry_payloads(container):
        if entry.name_decoded is not None:
            name = entry.name_decoded
        else:
            try:
                name = base64.b64decode(entry.name_b64, validate=False).decode("utf-8", "replace")
            except Exception:
                name = entry.name_b64.decode("ascii", "replace")
        print(
            f"entry[{entry.index}]: off=0x{entry.entry_offset:x} id={entry.entry_id.hex()} "
            f"name={name!r} payload_len=0x{entry.payload_len:x} key_len=0x{entry.key_len:x}"
        )

        if dump_entries:
            base_name = _sanitize_name(name)
            payload_path = path.with_name(f"{path.stem}.entry_{entry.index:02d}.{base_name}.payload.bin")
            key_path = path.with_name(f"{path.stem}.entry_{entry.index:02d}.{base_name}.key.bin")
            payload_path.write_bytes(payload)
            key_path.write_bytes(key)
            print(f"entry[{entry.index}].payload_dump: {payload_path}")
            print(f"entry[{entry.index}].key_dump: {key_path}")


def _handle_compact(path: Path, version_be: int, args: argparse.Namespace) -> None:
    if version_be == 2:
        _dump_compact_entries(path, dump_entries=args.dump_entries)
        return
    if version_be == 1:
        print(f"file: {path}")
        print("container: compact_v1")
        print("status: detected but not yet integrated in this unified extractor")
        return
    print(f"file: {path}")
    print(f"container: compact_ysgp(version={version_be})")
    print("status: unsupported")


def _iter_inputs(paths: Iterable[str]) -> Iterable[Path]:
    for p in paths:
        yield Path(p)


def _interactive_banner() -> str:
    return "\n".join(
        (
            "YSM Extract",
            "-----------",
            "Mode: heuristic extractor output, not official/native export parity.",
            "For official export capture use: capture-legacy-export <sample.ysm>",
            "Toggle options, then run extraction.",
            "Commands: number=toggle  s=source oracle path  r=run  q=quit",
        )
    )


def _interactive_option_rows(args: argparse.Namespace) -> list[tuple[str, str, str]]:
    return [
        ("1", "dump_folder", "Export canonical asset folder"),
        ("2", "scan_assets", "Scan decoded payload for assets"),
        ("3", "dump_assets", "Dump discovered assets"),
        ("4", "dump_decoded", "Dump fully decoded payload"),
        ("5", "dump_zst", "Dump transcoded zstd stream"),
        ("6", "debug", "Keep debug artifacts"),
        ("7", "dump_entries", "Compact v2: dump per-entry payload/key blobs"),
        ("8", "auto_source_oracle", "Auto source-oracle restore for legacy 1/9/15"),
    ]


def _print_interactive_menu(args: argparse.Namespace) -> None:
    print(_interactive_banner())
    for key, attr, label in _interactive_option_rows(args):
        mark = "x" if bool(getattr(args, attr)) else " "
        print(f" {key}. [{mark}] {label}")
    src = str(args.source_oracle) if args.source_oracle is not None else "(auto/off)"
    print(f" s.     Source oracle path: {src}")


def _prompt_paths() -> list[str]:
    while True:
        raw = input("YSM path(s): ").strip()
        if not raw:
            print("Enter at least one file path.")
            continue
        parts = shlex.split(raw)
        if not parts:
            print("Enter at least one file path.")
            continue
        return parts


def _interactive_args(base_args: argparse.Namespace) -> argparse.Namespace:
    args = argparse.Namespace(**vars(base_args))
    if not args.dump_folder and not args.scan_assets and not args.dump_assets and not args.dump_entries:
        args.dump_folder = True
    while True:
        print()
        _print_interactive_menu(args)
        choice = input("Select option: ").strip().lower()
        if choice in {"q", "quit", "exit"}:
            raise SystemExit(0)
        if choice in {"r", "run", ""}:
            args.inputs = _prompt_paths()
            return args
        if choice == "s":
            raw = input("Source oracle path (empty to clear): ").strip()
            args.source_oracle = Path(raw).expanduser() if raw else None
            continue
        toggles = {key: attr for key, attr, _label in _interactive_option_rows(args)}
        attr = toggles.get(choice)
        if attr is None:
            print("Unknown selection.")
            continue
        setattr(args, attr, not bool(getattr(args, attr)))
        if attr == "auto_source_oracle" and args.auto_source_oracle and args.source_oracle is not None:
            # manual path still wins; leave it set
            pass


def build_argparser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Unified YSM extractor entrypoint for BOM v3 (formats 1/9/15/31) and compact YSGP v2.",
        epilog=(
            "Bare input extraction and interactive mode use the heuristic Python extractor, which can differ from "
            "official YSM export output for legacy files.\n\n"
            "Utility commands:\n"
            "  snapshot <official-export-root>\n"
            "  stage-headed-host --out-dir <bundle-dir>\n"
            "  capture-legacy-export <sample.ysm> [options]\n"
            "  summarize-model-trace <intercept.log> [options]"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("inputs", nargs="*", help="Input YSM/YSGP files")
    ap.add_argument("--interactive", action="store_true", help="launch interactive menu mode")

    ap.add_argument("--dump-zst", action="store_true", help="BOM v3: dump transcoded zstd stream")
    ap.add_argument("--dump-decoded", action="store_true", help="BOM v3: dump fully decoded payload")
    ap.add_argument("--scan-assets", action="store_true", help="BOM v3: scan decoded payload for assets")
    ap.add_argument("--dump-assets", action="store_true", help="BOM v3: dump discovered assets")
    ap.add_argument("--dump-folder", action="store_true", help="BOM v3: export canonical asset folder")
    ap.add_argument("--debug", action="store_true", help="keep debug artifacts like section bins, manifests, decompiled stubs, and heuristic fallbacks")

    ap.add_argument(
        "--source-oracle",
        type=Path,
        help="BOM v3: restore exact files from this source folder or zip archive",
    )
    ap.add_argument(
        "--no-auto-source-oracle",
        action="store_true",
        help="Legacy 1/9/15: disable automatic nearby source-oracle lookup",
    )

    ap.add_argument(
        "--dump-entries",
        action="store_true",
        help="Compact v2: dump per-entry payload/key blobs",
    )
    return ap


def build_command_argparser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="YSM extractor utility commands for native-truth legacy export capture and snapshotting."
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    snap = sub.add_parser("snapshot", help="normalize an official export folder into a canonical snapshot")
    snap.add_argument("export_root", type=Path, help="official export folder to snapshot")
    snap.add_argument("--out-dir", type=Path, help="output folder for the normalized snapshot")
    snap.add_argument("--ysm-path", type=Path, help="optional source .ysm path for naming/manifest context")
    snap.add_argument("--official-jar", type=Path, help="override the 2.6.2 official jar path")

    headed = sub.add_parser("stage-headed-host", help="stage a headed host debug bundle for the real Forge client")
    headed.add_argument(
        "--out-dir",
        type=Path,
        help="bundle output directory; defaults to ROOT/debug_runtime/headed_host_bundle or $YSM262_DEBUG_RUNTIME_ROOT/headed_host_bundle",
    )
    headed.add_argument("--minecraft-root", type=Path, default=DEFAULT_MINECRAFT_ROOT, help="Minecraft runtime root to mirror")
    headed.add_argument("--version-id", default=DEFAULT_FORGE_VERSION_ID, help="Forge version id for the dedicated launcher profile")
    headed.add_argument(
        "--launcher-profiles",
        type=Path,
        default=DEFAULT_MINECRAFT_ROOT / "launcher_profiles.json",
        help="launcher_profiles.json to inspect when preparing the profile payload",
    )
    headed.add_argument("--profile-id", default=DEFAULT_HEADED_DEBUG_PROFILE_ID, help="launcher profile id to create/update")
    headed.add_argument("--profile-name", default=DEFAULT_HEADED_DEBUG_PROFILE_NAME, help="launcher profile display name")
    headed.add_argument("--model-trace", action="store_true", help="enable the focused model-state trace lane in the headed wrapper")
    headed.add_argument("--model-trace-sample", help="sample path/name substring that arms focused model tracing")
    headed.add_argument("--model-trace-families", help="comma-separated bone/family tokens to highlight in model-trace scans")
    headed.add_argument("--model-trace-export-filter", default="main.json", help="export json basename to treat as the main model truth target")
    headed.add_argument("--model-trace-rel", default="0x4e2c80", help="inline-hook rel target for the focused model trace lane")
    headed.add_argument("--model-trace-patch-len", type=int, default=16, help="patch length for the focused model trace hook")
    headed.add_argument("--model-trace-limit", type=int, default=32, help="budget of focused model-trace invocations")
    headed.add_argument("--model-trace-scan-bytes", default="0x240", help="bytes to scan per candidate object during model trace")
    headed.add_argument("--model-trace-string-limit", type=int, default=64, help="max string observations per model-trace object")
    headed.add_argument("--model-trace-vector-limit", type=int, default=48, help="max float3 observations per model-trace object")

    capture = sub.add_parser(
        "capture-legacy-export",
        help="stage one legacy .ysm into the headed client path for trace and optional export/snapshot capture",
    )
    capture.add_argument("ysm_path", type=Path, help="legacy .ysm sample to stage")
    capture.add_argument("--out-dir", type=Path, help="capture bundle output directory")
    capture.add_argument("--minecraft-root", type=Path, default=DEFAULT_MINECRAFT_ROOT, help="Minecraft runtime root to mirror")
    capture.add_argument("--version-id", default=DEFAULT_FORGE_VERSION_ID, help="Forge version id for the dedicated launcher profile")
    capture.add_argument(
        "--launcher-profiles",
        type=Path,
        default=DEFAULT_MINECRAFT_ROOT / "launcher_profiles.json",
        help="launcher_profiles.json to inspect when preparing the profile payload",
    )
    capture.add_argument("--profile-id", help="launcher profile id to create/update")
    capture.add_argument("--profile-name", help="launcher profile display name")
    capture.add_argument("--model-id", help="override the imported model id used by `/ysm export`")
    capture.add_argument("--extra", help="optional extra argument string to append to `/ysm export <model_id>`")
    capture.add_argument("--export-root", type=Path, help="override the raw official export root to harvest")
    capture.add_argument("--snapshot-dir", type=Path, help="output folder for the canonical official snapshot")
    capture.add_argument("--keep-existing", action="store_true", help="do not clear staged custom/export state before preparing the capture")
    capture.add_argument("--trace-only", action="store_true", help="stage a load-and-trace bundle without instructing any `/ysm export` flow")
    capture.add_argument("--model-trace", action="store_true", help="enable the focused model-state trace lane in the staged headed wrapper")
    capture.add_argument("--model-trace-sample", help="sample path/name substring that arms focused model tracing; defaults to the staged ysm filename")
    capture.add_argument("--model-trace-families", help="comma-separated bone/family tokens to highlight in model-trace scans")
    capture.add_argument("--model-trace-export-filter", default="main.json", help="export json basename to treat as the main model truth target")
    capture.add_argument("--model-trace-rel", default="0x4e2c80", help="inline-hook rel target for the focused model trace lane")
    capture.add_argument("--model-trace-patch-len", type=int, default=16, help="patch length for the focused model trace hook")
    capture.add_argument("--model-trace-limit", type=int, default=32, help="budget of focused model-trace invocations")
    capture.add_argument("--model-trace-scan-bytes", default="0x240", help="bytes to scan per candidate object during model trace")
    capture.add_argument("--model-trace-string-limit", type=int, default=64, help="max string observations per model-trace object")
    capture.add_argument("--model-trace-vector-limit", type=int, default=48, help="max float3 observations per model-trace object")

    summarize = sub.add_parser("summarize-model-trace", help="summarize structured model-trace observations and optional snapshot bones")
    summarize.add_argument("intercept_log", type=Path, help="headed-host intercept log to analyze")
    summarize.add_argument("--snapshot-root", type=Path, help="optional official snapshot root to join with model-trace observations")
    summarize.add_argument("--model-name", default="main.json", help="canonical model json name to summarize from the snapshot")
    summarize.add_argument("--family-filter", help="optional comma-separated bone/family tokens to keep")
    summarize.add_argument("--json", action="store_true", help="print JSON instead of plain text")
    return ap


def _run_command(args: argparse.Namespace) -> int:
    if args.cmd == "snapshot":
        out = snapshot_official_export(
            args.export_root,
            out_dir=args.out_dir,
            ysm_path=args.ysm_path,
            official_jar=args.official_jar,
        )
        print(f"official_export_snapshot: {out}")
        return 0

    if args.cmd == "stage-headed-host":
        model_trace = HeadedModelTraceConfig(
            enabled=args.model_trace,
            sample_hint=args.model_trace_sample,
            family_filter=_parse_model_trace_family_filter(args.model_trace_families),
            export_filter=args.model_trace_export_filter,
            trace_rel=int(args.model_trace_rel, 0),
            patch_len=args.model_trace_patch_len,
            budget=args.model_trace_limit,
            scan_bytes=int(args.model_trace_scan_bytes, 0),
            string_limit=args.model_trace_string_limit,
            vector_limit=args.model_trace_vector_limit,
        )
        out = stage_headed_host_bundle(
            args.out_dir,
            minecraft_root=args.minecraft_root,
            version_id=args.version_id,
            launcher_profiles=args.launcher_profiles,
            profile_id=args.profile_id,
            profile_name=args.profile_name,
            model_trace=model_trace,
        )
        print(f"headed_host_bundle: {out}")
        return 0

    if args.cmd == "summarize-model-trace":
        summary = summarize_model_trace(
            args.intercept_log,
            snapshot_root=args.snapshot_root,
            family_filter=_parse_model_trace_family_filter(args.family_filter),
            model_name=args.model_name,
        )
        if args.json:
            print(json.dumps(summary, indent=2))
            return 0
        print(f"intercept_log: {summary['intercept_log']}")
        print(f"snapshot_root: {summary['snapshot_root']}")
        print(f"model_name: {summary['model_name']}")
        print(f"event_count: {len(summary['events'])}")
        for item in summary["events"]:
            print(f"event: {item}")
        print(f"object_count: {len(summary['objects'])}")
        for label, payload in summary["objects"].items():
            print(
                f"object: {label} strings={len(payload['strings'])} ptr_strings={len(payload['ptr_strings'])} float3={len(payload['float3'])}"
            )
        if summary["candidate_hook_rels"]:
            print(f"candidate_hook_rel_count: {len(summary['candidate_hook_rels'])}")
            for item in summary["candidate_hook_rels"][:20]:
                print(f"candidate_hook_rel: {item['rel']} hits={item['hits']}")
        if summary["bone_summaries"]:
            print(f"bone_count: {len(summary['bone_summaries'])}")
            for bone in summary["bone_summaries"][:40]:
                print(
                    f"bone: {bone['name']} parent={bone['parent']} pivot={bone['pivot']} cubes={bone['cube_count']} trace_hits={len(bone['matching_trace_labels'])}"
                )
        return 0

    model_trace = HeadedModelTraceConfig(
        enabled=args.model_trace,
        sample_hint=args.model_trace_sample,
        family_filter=_parse_model_trace_family_filter(args.model_trace_families),
        export_filter=args.model_trace_export_filter,
        trace_rel=int(args.model_trace_rel, 0),
        patch_len=args.model_trace_patch_len,
        budget=args.model_trace_limit,
        scan_bytes=int(args.model_trace_scan_bytes, 0),
        string_limit=args.model_trace_string_limit,
        vector_limit=args.model_trace_vector_limit,
    )
    capture = capture_legacy_export(
        args.ysm_path,
        out_dir=args.out_dir,
        minecraft_root=args.minecraft_root,
        version_id=args.version_id,
        launcher_profiles=args.launcher_profiles,
        profile_id=args.profile_id,
        profile_name=args.profile_name,
        model_id=args.model_id,
        extra=args.extra,
        export_root=args.export_root,
        snapshot_dir=args.snapshot_dir,
        keep_existing=args.keep_existing,
        model_trace=model_trace,
        trace_only=args.trace_only,
    )
    manifest = json.loads(capture.manifest_path.read_text(encoding="utf-8"))
    print(f"legacy_capture_bundle: {capture.bundle_root}")
    print(f"staged_sample: {capture.sample_copy}")
    print(f"raw_export_root: {capture.export_root}")
    if manifest["suggested_export_command"] is not None:
        print(f"suggested_export_command: {manifest['suggested_export_command']}")
    else:
        print("suggested_export_command: none (trace-only load path)")
        print(f"trace_log: {capture.bundle_root / 'trace' / 'ysm262_intercept.log'}")
    if manifest["selected_export_root"] is not None:
        print(f"selected_export_root: {manifest['selected_export_root']}")
    if manifest["official_snapshot_root"] is not None:
        print(f"official_export_snapshot: {manifest['official_snapshot_root']}")
    else:
        print("official_export_snapshot: pending")
    if manifest["verify_command"] is not None:
        print(f"verify_command: {manifest['verify_command']}")
    print(f"capture_manifest: {capture.manifest_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in {"snapshot", "stage-headed-host", "capture-legacy-export", "summarize-model-trace"}:
        args = build_command_argparser().parse_args(argv)
        return _run_command(args)

    args = build_argparser().parse_args(argv)
    args.auto_source_oracle = not args.no_auto_source_oracle
    if args.interactive or not args.inputs:
        if not sys.stdin.isatty():
            raise SystemExit("interactive mode requires a TTY")
        print("note: interactive mode uses the heuristic Python extractor.")
        print("note: for official/native legacy export capture use `capture-legacy-export <sample.ysm>`.")
        args = _interactive_args(args)

    for i, path in enumerate(_iter_inputs(args.inputs)):
        if i:
            print()
        path = Path(os.path.expanduser(str(path)))
        data = path.read_bytes()
        kind, ver = _detect_container(data)
        if kind == "bom_v3":
            _handle_bom_v3(path, args)
            continue
        if kind == "compact_ysgp" and ver is not None:
            _handle_compact(path, ver, args)
            continue
        print(f"file: {path}")
        print("container: unknown")
        print("status: unsupported")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
