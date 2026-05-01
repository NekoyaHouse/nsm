from __future__ import annotations

import argparse
import base64
import hashlib
from dataclasses import dataclass
from pathlib import Path


MAGIC = b"YSGP"
VERSION_V2_BE = 2
HEADER_MD5_SIZE = 0x10


def _u32be(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 4], "big")


@dataclass(frozen=True)
class CompactV2Entry:
    index: int
    entry_offset: int
    name_b64: bytes
    name_decoded: str | None
    payload_len: int
    key_len: int
    entry_id: bytes
    payload_offset: int
    key_offset: int


@dataclass(frozen=True)
class CompactV2File:
    path: Path
    version_be: int
    header_md5_16: bytes
    header_md5_verified: bool
    entries: list[CompactV2Entry]


def parse_compact_v2_file(path: Path) -> CompactV2File:
    data = path.read_bytes()
    if len(data) < 8 + HEADER_MD5_SIZE:
        raise ValueError("file too short for compact YSGP v2 container")
    if data[:4] != MAGIC:
        raise ValueError("file does not start with YSGP")
    version = _u32be(data, 4)
    if version != VERSION_V2_BE:
        raise ValueError(f"expected compact v2 big-endian version 2, got {version}")

    header_md5_16 = data[8:24]
    off = 24
    entries: list[CompactV2Entry] = []
    while off < len(data):
        remaining = len(data) - off
        if remaining < 4:
            raise ValueError(f"truncated compact entry header at 0x{off:x}")

        name_len = _u32be(data, off)
        name_off = off + 4
        if name_off + name_len + 24 > len(data):
            raise ValueError(f"compact entry name overruns file at 0x{off:x}")

        name_b64 = data[name_off:name_off + name_len]
        try:
            name_decoded = base64.b64decode(name_b64, validate=True).decode("utf-8")
        except Exception:
            name_decoded = None

        payload_meta_off = name_off + name_len
        payload_len = _u32be(data, payload_meta_off)
        key_len = _u32be(data, payload_meta_off + 4)
        entry_id = data[payload_meta_off + 8:payload_meta_off + 24]
        payload_off = payload_meta_off + 24
        key_off = payload_off + payload_len
        next_off = key_off + key_len

        if next_off > len(data):
            raise ValueError(f"compact entry data overruns file at 0x{off:x}")

        entries.append(
            CompactV2Entry(
                index=len(entries),
                entry_offset=off,
                entry_id=entry_id,
                name_b64=name_b64,
                name_decoded=name_decoded,
                payload_len=payload_len,
                key_len=key_len,
                payload_offset=payload_off,
                key_offset=key_off,
            )
        )
        off = next_off

    if off != len(data):
        raise ValueError(f"compact v2 parser did not consume full file, stopped at 0x{off:x}")

    return CompactV2File(
        path=path,
        version_be=version,
        header_md5_16=header_md5_16,
        header_md5_verified=hashlib.md5(data[24:]).digest() == header_md5_16,
        entries=entries,
    )


def extract_entry_payloads(container: CompactV2File) -> list[tuple[CompactV2Entry, bytes, bytes]]:
    data = container.path.read_bytes()
    out: list[tuple[CompactV2Entry, bytes, bytes]] = []
    for entry in container.entries:
        payload = data[entry.payload_offset:entry.payload_offset + entry.payload_len]
        key = data[entry.key_offset:entry.key_offset + entry.key_len]
        out.append((entry, payload, key))
    return out


def print_compact_v2(container: CompactV2File) -> None:
    print(f"compact_v2.version_be: {container.version_be}")
    print(f"compact_v2.header_md5_16: {container.header_md5_16.hex()}")
    print(f"compact_v2.header_md5_verified: {container.header_md5_verified}")
    print(f"compact_v2.entries: {len(container.entries)}")
    for entry in container.entries:
        name = entry.name_decoded if entry.name_decoded is not None else entry.name_b64.decode("ascii", "replace")
        print(
            f"entry[{entry.index}] off=0x{entry.entry_offset:x} id={entry.entry_id.hex()} "
            f"name={name!r} payload_len=0x{entry.payload_len:x} key_len=0x{entry.key_len:x} "
            f"payload_off=0x{entry.payload_offset:x} key_off=0x{entry.key_offset:x}"
        )


def build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Static parser for compact YSGP v2 containers with repeated named entries."
    )
    parser.add_argument("inputs", nargs="+")
    return parser


def main() -> int:
    args = build_argparser().parse_args()
    for idx, input_path in enumerate(args.inputs):
        if idx:
            print()
        container = parse_compact_v2_file(Path(input_path))
        print(f"file: {input_path}")
        print_compact_v2(container)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
