from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from v3_wrapper_transcode import transcode_wrapper_stream_to_zstd
from extractors.ysgp_container_scanner import scan_file
from ysgp_v3_exact_probe import (
    parse_v3_exact_input,
    decrypt_v3_reader_exact,
    _apply_second_stage_variant,
)

FORMAT_RE = re.compile(r"^\s*<format>\s+(?P<format>\d+)\s*$", re.IGNORECASE | re.MULTILINE)


@dataclass(frozen=True)
class BomV3DecodeResult:
    path: Path
    codec_format: int | None
    prelude_skip: int
    wrapped_offset: int
    transcoded_zst: bytes
    decompressed: bytes


def _format_family(codec_format: int | None) -> str:
    if codec_format == 31:
        return "modern_31"
    if codec_format in (1, 9, 15):
        return "legacy_9_15"
    if codec_format is None:
        return "unknown"
    return f"unsupported_{codec_format}"


def read_property_format(path: Path) -> int | None:
    scan = scan_file(path, dump=False)
    match = FORMAT_RE.search(scan.property_text)
    if match is None:
        return None
    return int(match.group("format"))


def _decompress_zstd(buf: bytes) -> bytes:
    zstd = shutil.which("zstd")
    if zstd is None:
        raise RuntimeError("zstd binary not found in PATH")
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(buf)
        tmp_path = tmp.name
    try:
        proc = subprocess.run(
            [zstd, "-d", "-q", "-c", tmp_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.decode("utf-8", "replace").strip() or "zstd failed")
        return proc.stdout
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def decode_bom_v3(path: Path) -> BomV3DecodeResult:
    codec_format = read_property_format(path)
    exact = parse_v3_exact_input(path)
    stage1 = decrypt_v3_reader_exact(exact)
    stage2 = _apply_second_stage_variant(exact.key56, stage1, "mt19937_64_xor")
    prelude_skip = int.from_bytes(stage2[:2], "little") & 0x3FF
    wrapped_offset = 2 + prelude_skip
    wrapped = stage2[wrapped_offset:]
    transcoded_zst = transcode_wrapper_stream_to_zstd(wrapped)
    decompressed = _decompress_zstd(transcoded_zst)
    return BomV3DecodeResult(
        path=path,
        codec_format=codec_format,
        prelude_skip=prelude_skip,
        wrapped_offset=wrapped_offset,
        transcoded_zst=transcoded_zst,
        decompressed=decompressed,
    )


def export_bom_v3_assets(
    path: Path,
    codec_format: int | None,
    *,
    scan_assets: bool,
    dump_assets: bool,
    dump_folder: bool,
    debug: bool = False,
) -> Path | None:
    if codec_format in (1, 9, 15):
        from bom_v3_legacy_sections import dump_legacy_sections, print_legacy_sections, scan_legacy_sections

        legacy_scan = scan_legacy_sections(path)
        print_legacy_sections(legacy_scan)
        if dump_assets or dump_folder:
            return dump_legacy_sections(path, legacy_scan, debug=debug)
        return None

    if codec_format == 31:
        from extractors.bom_v3_payload_assets import _print_result, dump_asset_folder, scan_bom_v3_payload_assets

        asset_result = scan_bom_v3_payload_assets(path)
        _print_result(asset_result, dump=dump_assets)
        if dump_folder:
            return dump_asset_folder(asset_result, debug=debug)
        return None

    raise RuntimeError(
        f"unsupported BOM v3 decoded payload format {codec_format!r}; "
        "currently integrated formats are 1, 9, 15, and 31"
    )


def export_or_restore_bom_v3_assets(
    path: Path,
    codec_format: int | None,
    *,
    scan_assets: bool,
    dump_assets: bool,
    dump_folder: bool,
    debug: bool = False,
    source_oracle: Path | None = None,
    legacy_auto_source_oracle: bool = True,
) -> tuple[Path | None, Path | None, object | None]:
    from extractors.bom_v3_source_oracle import (
        default_export_dir,
        find_best_source_oracle,
        restore_from_source_oracle,
    )

    exported_dir: Path | None = None
    used_source: Path | None = None
    oracle = None

    if codec_format == 31 and dump_folder and source_oracle is None:
        best_source, match_count, asset_count = find_best_source_oracle(path, include_archives=True)
        exact_auto = best_source is not None and asset_count > 0 and match_count == asset_count
        if scan_assets or dump_assets or not exact_auto:
            exported_dir = export_bom_v3_assets(
                path,
                codec_format,
                scan_assets=scan_assets,
                dump_assets=dump_assets,
                dump_folder=not exact_auto,
                debug=debug,
            )
        if exact_auto and best_source is not None:
            used_source = best_source
            oracle = restore_from_source_oracle(
                path,
                best_source,
                out_dir=default_export_dir(path),
                clean=True,
                prefer_source_filenames=True,
            )
            exported_dir = oracle.out_dir
            return exported_dir, used_source, oracle
        return exported_dir, used_source, oracle

    if scan_assets or dump_assets or dump_folder:
        exported_dir = export_bom_v3_assets(
            path,
            codec_format,
            scan_assets=scan_assets,
            dump_assets=dump_assets,
            dump_folder=dump_folder,
            debug=debug,
        )

    if source_oracle is not None:
        used_source = source_oracle
        oracle = restore_from_source_oracle(
            path,
            source_oracle,
            out_dir=exported_dir,
            prefer_source_filenames=(codec_format == 31),
        )
        exported_dir = oracle.out_dir
    elif codec_format in (1, 9, 15) and exported_dir is not None and legacy_auto_source_oracle:
        best_source, match_count, asset_count = find_best_source_oracle(path)
        if best_source is not None and match_count > 0:
            used_source = best_source
            oracle = restore_from_source_oracle(path, best_source, out_dir=exported_dir)
            exported_dir = oracle.out_dir

    return exported_dir, used_source, oracle


def main() -> None:
    ap = argparse.ArgumentParser(description="End-to-end BOM+YSGP v3 extractor")
    ap.add_argument("paths", nargs="+", type=Path)
    ap.add_argument("--dump-zst", action="store_true")
    ap.add_argument("--dump-decoded", action="store_true")
    ap.add_argument("--scan-assets", action="store_true", help="scan decoded payload for property-hash-backed asset sections")
    ap.add_argument("--dump-assets", action="store_true", help="dump scanned asset sections and exact PNG/JSON payloads")
    ap.add_argument("--dump-folder", action="store_true", help="export assets into a model-named folder with canonical filenames")
    ap.add_argument("--debug", action="store_true", help="keep debug artifacts like section bins, manifests, and decompiled stubs")
    ap.add_argument("--source-oracle", type=Path, help="optional source folder or zip archive for exact hash-based file restore")
    args = ap.parse_args()

    for path in args.paths:
        result = decode_bom_v3(path)
        exported_dir: Path | None = None
        print(f"file: {path}")
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


if __name__ == "__main__":
    main()
