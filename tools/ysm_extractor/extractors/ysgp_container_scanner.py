from __future__ import annotations

import argparse
import math
from dataclasses import dataclass
from pathlib import Path


WINDOW_SIZE = 512
MERGE_GAP = 128
PRINTABLE_ASCII = set(range(0x20, 0x7F))
TEXT_WHITESPACE = {0x09, 0x0A, 0x0D}


@dataclass(frozen=True)
class ChunkReport:
    start: int
    end: int
    ascii_ratio: float
    entropy: float
    first64_hex: str
    dump_path: Path

    @property
    def length(self) -> int:
        return self.end - self.start


@dataclass(frozen=True)
class ScanResult:
    path: Path
    has_utf8_bom: bool
    has_ysgp_magic: bool
    property_end: int
    property_text: str
    chunks: list[ChunkReport]


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    n = len(data)
    for count in counts:
        if count == 0:
            continue
        p = count / n
        entropy -= p * math.log2(p)
    return entropy


def ascii_ratio(data: bytes) -> float:
    if not data:
        return 1.0
    ascii_like = 0
    for b in data:
        if b in PRINTABLE_ASCII or b in TEXT_WHITESPACE:
            ascii_like += 1
    return ascii_like / len(data)


def utf8_text_score(data: bytes) -> tuple[bool, float]:
    if not data:
        return True, 1.0
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False, 0.0

    printable = 0
    for ch in text:
        if ch.isprintable() or ch in "\r\n\t":
            printable += 1
    return True, printable / max(1, len(text))


def is_probably_text_window(data: bytes) -> bool:
    if not data:
        return False
    if b"\x00" in data:
        return False
    utf8_ok, printable_ratio = utf8_text_score(data)
    if not utf8_ok:
        return False
    return printable_ratio >= 0.70


def detect_property_end(data: bytes) -> int:
    if not data:
        return 0

    cursor = 0
    if data.startswith(b"\xef\xbb\xbf"):
        cursor = 3
    if data[cursor:cursor + 4] == b"YSGP":
        cursor += 4

    pos = cursor
    refined = cursor
    while pos < len(data):
        next_nl = data.find(b"\n", pos)
        if next_nl == -1:
            next_nl = len(data)
        else:
            next_nl += 1
        line = data[pos:next_nl]
        if not line:
            break
        if is_probably_text_window(line):
            refined = next_nl
            pos = next_nl
            continue
        break

    return refined


def detect_binary_chunks(data: bytes, start: int) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    in_chunk = False
    chunk_start = start
    pos = start

    while pos < len(data):
        window = data[pos:pos + WINDOW_SIZE]
        if not window:
            break
        text_like = is_probably_text_window(window)
        if not text_like:
            if not in_chunk:
                in_chunk = True
                chunk_start = pos
        else:
            if in_chunk:
                spans.append((chunk_start, pos))
                in_chunk = False
        pos += WINDOW_SIZE

    if in_chunk:
        spans.append((chunk_start, len(data)))

    if not spans:
        return []

    merged: list[tuple[int, int]] = [spans[0]]
    for start_i, end_i in spans[1:]:
        prev_start, prev_end = merged[-1]
        if start_i - prev_end <= MERGE_GAP:
            merged[-1] = (prev_start, end_i)
        else:
            merged.append((start_i, end_i))
    return merged


def dump_chunk(input_path: Path, index: int, start: int, end: int, data: bytes) -> Path:
    out = input_path.with_name(
        f"{input_path.stem}.chunk_{index:02d}.{start:08x}-{end:08x}.bin"
    )
    out.write_bytes(data[start:end])
    return out


def scan_file(path: Path, dump: bool = True) -> ScanResult:
    data = path.read_bytes()
    has_utf8_bom = data.startswith(b"\xef\xbb\xbf")
    magic_off = 3 if has_utf8_bom else 0
    has_ysgp_magic = data[magic_off:magic_off + 4] == b"YSGP"

    property_end = detect_property_end(data)
    property_bytes = data[:property_end]
    try:
        property_text = property_bytes.decode("utf-8")
    except UnicodeDecodeError:
        property_text = property_bytes.decode("utf-8", errors="replace")

    chunk_reports: list[ChunkReport] = []
    for idx, (start, end) in enumerate(detect_binary_chunks(data, property_end)):
        chunk = data[start:end]
        dump_path = dump_chunk(path, idx, start, end, data) if dump else path
        chunk_reports.append(
            ChunkReport(
                start=start,
                end=end,
                ascii_ratio=ascii_ratio(chunk),
                entropy=shannon_entropy(chunk),
                first64_hex=chunk[:64].hex(),
                dump_path=dump_path,
            )
        )

    return ScanResult(
        path=path,
        has_utf8_bom=has_utf8_bom,
        has_ysgp_magic=has_ysgp_magic,
        property_end=property_end,
        property_text=property_text,
        chunks=chunk_reports,
    )


def print_scan_result(result: ScanResult, show_property: bool) -> None:
    print(f"file: {result.path}")
    print(f"bom_utf8: {result.has_utf8_bom}")
    print(f"ysgp_magic: {result.has_ysgp_magic}")
    print(f"property_end: 0x{result.property_end:08x} ({result.property_end})")
    if show_property:
        print("property_block_begin")
        print(result.property_text.rstrip("\n"))
        print("property_block_end")
    if not result.chunks:
        print("candidate_chunks: none")
        return
    print(f"candidate_chunks: {len(result.chunks)}")
    for i, chunk in enumerate(result.chunks):
        print(f"chunk[{i}] start=0x{chunk.start:08x} end=0x{chunk.end:08x} length=0x{chunk.length:x}")
        print(f"chunk[{i}] ascii_ratio={chunk.ascii_ratio:.4f} entropy={chunk.entropy:.4f}")
        print(f"chunk[{i}] first64={chunk.first64_hex}")
        print(f"chunk[{i}] dump={chunk.dump_path}")


def compare_results(results: list[ScanResult]) -> None:
    print("compare_begin")
    if not results:
        print("no_results")
        print("compare_end")
        return

    max_chunks = max(len(r.chunks) for r in results)
    for result in results:
        offsets = ", ".join(f"0x{c.start:x}" for c in result.chunks) or "none"
        lengths = ", ".join(f"0x{c.length:x}" for c in result.chunks) or "none"
        print(f"{result.path.name}: property_end=0x{result.property_end:x} chunks={len(result.chunks)}")
        print(f"{result.path.name}: chunk_offsets={offsets}")
        print(f"{result.path.name}: chunk_lengths={lengths}")

    for idx in range(max_chunks):
        print(f"candidate_index[{idx}]")
        for result in results:
            if idx >= len(result.chunks):
                print(f"  {result.path.name}: missing")
                continue
            chunk = result.chunks[idx]
            rel = chunk.start / max(1, result.path.stat().st_size)
            print(
                f"  {result.path.name}: start=0x{chunk.start:x} len=0x{chunk.length:x} "
                f"rel_start={rel:.5f} first16={chunk.first64_hex[:32]}"
            )
    print("compare_end")


def build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Conservative YSGP headered v3 container scanner and chunk carver."
    )
    parser.add_argument("inputs", nargs="+", help="YSGP/.ysm files to scan")
    parser.add_argument(
        "--no-property",
        action="store_true",
        help="Do not print the decoded property block",
    )
    parser.add_argument(
        "--no-dump",
        action="store_true",
        help="Do not dump carved candidate chunks",
    )
    parser.add_argument(
        "--compare",
        action="store_true",
        help="Compare candidate chunk offsets/patterns across all input files",
    )
    return parser


def main() -> int:
    parser = build_argparser()
    args = parser.parse_args()

    results = [
        scan_file(Path(input_path), dump=not args.no_dump)
        for input_path in args.inputs
    ]

    for idx, result in enumerate(results):
        if idx:
            print()
        print_scan_result(result, show_property=not args.no_property)

    if args.compare or len(results) > 1:
        print()
        compare_results(results)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
