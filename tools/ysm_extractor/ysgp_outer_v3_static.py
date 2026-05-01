from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

from ysgp_container_scanner import detect_property_end


MAGIC_PREFIX = b"\xef\xbb\xbfYSGP"
MASK64 = 0xFFFFFFFFFFFFFFFF


def _u8(data: bytes, off: int) -> int:
    return data[off]


def _u32_partial(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 4], "little")


def _u64(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 8], "little")


def _rol64(x: int, n: int) -> int:
    x &= MASK64
    return ((x << n) | (x >> (64 - n))) & MASK64


def _mul64(a: int, b: int) -> int:
    return (a * b) & MASK64


def _bswap64(x: int) -> int:
    return int.from_bytes((x & MASK64).to_bytes(8, "little"), "big")


def hash64_with_key(data: bytes, key: int) -> int:
    n = len(data)
    if n < 0x21:
        l3 = 0xAF29CE778879D9C7
        if n < 0x11:
            if n < 8:
                if n < 4:
                    if n != 0:
                        u10 = (
                            _mul64(((_u8(data, n - 1) << 2) | n), 0xE4986A230E5AAA17)
                            ^ _mul64(((_u8(data, n >> 1) << 8) | _u8(data, 0)), 0xAF29CE778879D9C7)
                        ) & MASK64
                        l3 = _mul64((u10 >> 47) ^ u10, 0xAF29CE778879D9C7)
                    final_l3 = l3
                else:
                    l3 = (n * 2 + 0xAF29CE778879D9C7) & MASK64
                    u10 = (n + _u32_partial(data, 0) * 8) & MASK64
                    u5 = _u32_partial(data, n - 4)
                    u10 = _mul64(u10 ^ u5, l3)
                    u10 = _mul64((u10 >> 47) ^ u5 ^ u10, l3)
                    u10 ^= (u10 >> 47)
                    final_l3 = _mul64(u10, l3)
            else:
                l3 = (n * 2 + 0xAF29CE778879D9C7) & MASK64
                u4 = (_u64(data, 0) + 0xAF29CE778879D9C7) & MASK64
                u5 = _u64(data, n - 8)
                u10 = (_mul64(_rol64(u5, 27), l3) + u4) & MASK64
                u5 = _mul64((_rol64(u4, 39) + u5) & MASK64, l3)
                u10 = _mul64(u10 ^ u5, l3)
                u10 = _mul64((u10 >> 47) ^ u5 ^ u10, l3)
                u10 ^= (u10 >> 47)
                final_l3 = _mul64(u10, l3)
        else:
            l3 = (n * 2 + 0xAF29CE778879D9C7) & MASK64
            u5 = _mul64(_u64(data, n - 8), l3)
            u10 = (_mul64(_u64(data, 0), 0x91AF10802CAB25A5) + _u64(data, 16)) & MASK64
            u4 = (_u64(data, 16) + 0xAF29CE778879D9C7) & MASK64
            u4 = (_rol64(u4, 46) + _mul64(_u64(data, 0), 0x91AF10802CAB25A5) + u5) & MASK64
            u10 = _mul64(
                (
                    _rol64(u5, 34)
                    + _rol64(u10, 21)
                    + _mul64(_u64(data, n - 16), 0xAF29CE778879D9C7)
                    ^ u4
                ) & MASK64,
                l3,
            )
            u10 = _mul64((u10 >> 47) ^ u4 ^ u10, l3)
            u10 ^= (u10 >> 47)
            final_l3 = _mul64(u10, l3)
    elif n < 0x41:
        l1 = (n * 2 + 0xAF29CE778879D9C7) & MASK64
        u10 = _u64(data, n - 0x20)
        l2 = _u64(data, n - 0x18)
        u5 = _u64(data, 16)
        l8 = (_u64(data, 24) * 9) & MASK64
        l15 = _u64(data, n - 8)
        l11 = _mul64(_u64(data, n - 0x10), l1)
        u7 = (_mul64(_u64(data, 0), 0xAF29CE778879D9C7) + l15) & MASK64
        u16 = u7 ^ u10
        u4 = (_mul64(_u64(data, 32), 0xAF29CE778879D9C7) + l8) & MASK64
        u7 = _mul64((((_rol64(u5, 34) + l2) * 9) + _rol64(u7, 43) + u16 + l8 + 1) & MASK64, l1)
        l3 = (_rol64(u4, 22) + l2) & MASK64
        u7 = _mul64((l8 + u16 + l11 + 1 + _bswap64(u7)) & MASK64, l1)
        u7 = _mul64((l15 + u4 + l2 + l3 + _bswap64(u7)) & MASK64, l1)
        u10 = (l11 + u10 + _mul64((u4 + l2 + u5 + _bswap64(u7)) & MASK64, l1)) & MASK64
        final_l3 = (_mul64((u10 >> 47) ^ u10, l1) + l3) & MASK64
    else:
        l3 = _u64(data, n - 0x28)
        l1 = _u64(data, n - 0x10)
        l2 = _u64(data, n - 0x38)
        l15 = _u64(data, n - 0x30)
        u10 = (l2 + l1) & MASK64
        u5 = (l15 + n) & MASK64
        u4 = _u64(data, n - 0x18)
        u7 = _mul64(u4 ^ u5, 0xDE0F6EE09BDBAB91)
        u5 = _mul64((u7 >> 47) ^ u5 ^ u7, 0xDE0F6EE09BDBAB91)
        u5 = _mul64((u5 >> 47) ^ u5, 0xDE0F6EE09BDBAB91)
        l8 = (_u64(data, n - 0x40) + n) & MASK64
        u14 = (l3 + l8 + u5) & MASK64
        u7 = (l2 + l15 + l8) & MASK64
        u16 = (u7 + l3) & MASK64
        u14 = (_rol64(u7, 20) + l8 + _rol64(u14, 43)) & MASK64
        l2 = _u64(data, n - 8)
        l15 = (_u64(data, n - 0x20) + u10 + 0x91AF10802CAB25A5) & MASK64
        u13 = (l3 + l2 + l15) & MASK64
        u4 = (u4 + l1 + l15) & MASK64
        u7 = (u4 + l2) & MASK64
        l3 = (_mul64(l3, 0x91AF10802CAB25A5) + _u64(data, 0)) & MASK64
        u4 = (_rol64(u4, 20) + l15 + _rol64(u13, 43)) & MASK64
        u13 = 0
        while (((n - 1) & 0xFFFFFFFFFFFFFFC0) != u13):
            l1 = _u64(data, u13 + 8)
            l2 = _u64(data, u13 + 0x10)
            u6 = (l3 + u16 + u10 + l1) & MASK64
            l15 = _u64(data, u13 + 0x30)
            u10 = (u10 + u14 + l15) & MASK64
            u6 = _mul64(_rol64(u6, 27), 0x91AF10802CAB25A5) ^ u4
            l8 = _u64(data, u13 + 0x28)
            u10 = (u16 + l8 + _mul64(_rol64(u10, 22), 0x91AF10802CAB25A5)) & MASK64
            l3 = _mul64(_rol64((u5 + u7) & MASK64, 31), 0x91AF10802CAB25A5)
            l11 = _u64(data, u13 + 0x18)
            l12 = (_mul64(u14, 0x91AF10802CAB25A5) + _u64(data, u13)) & MASK64
            u14 = (l1 + l2 + l12) & MASK64
            u16 = (u14 + l11) & MASK64
            l9 = (u4 + l3 + _u64(data, u13 + 0x20)) & MASK64
            l1 = _u64(data, u13 + 0x38)
            u4 = (l2 + u10 + l9 + l1) & MASK64
            u5 = (u7 + l12 + l11 + u6) & MASK64
            u14 = (l12 + _rol64(u14, 20) + _rol64(u5, 43)) & MASK64
            u5 = (l8 + l15 + l9) & MASK64
            u7 = (u5 + l1) & MASK64
            u4 = (l9 + _rol64(u5, 20) + _rol64(u4, 43)) & MASK64
            u13 += 0x40
            u5 = u6
        u5 = _mul64(u7 ^ u16, 0xDE0F6EE09BDBAB91)
        u5 = _mul64((u5 >> 47) ^ u16 ^ u5, 0xDE0F6EE09BDBAB91)
        u10 = (
            _mul64((u10 >> 47) ^ u10, 0x91AF10802CAB25A5)
            + u6
            + _mul64((u5 >> 47) ^ u5, 0xDE0F6EE09BDBAB91)
        ) & MASK64
        u5 = _mul64(u4 ^ u14, 0xDE0F6EE09BDBAB91)
        u5 = _mul64((u5 >> 47) ^ u14 ^ u5, 0xDE0F6EE09BDBAB91)
        u5 = _mul64((_mul64((u5 >> 47) ^ u5, 0xDE0F6EE09BDBAB91) + l3 ^ u10) & MASK64, 0xDE0F6EE09BDBAB91)
        u10 = _mul64((u5 >> 47) ^ u10 ^ u5, 0xDE0F6EE09BDBAB91)
        final_l3 = _mul64((u10 >> 47) ^ u10, 0xDE0F6EE09BDBAB91)

    u10 = _mul64((key ^ ((final_l3 + 0x50D6318877862639) & MASK64)) & MASK64, 0xDE0F6EE09BDBAB91)
    u10 = _mul64((u10 >> 47) ^ ((final_l3 + 0x50D6318877862639) & MASK64) ^ u10, 0xDE0F6EE09BDBAB91)
    return _mul64((u10 >> 47) ^ u10, 0xDE0F6EE09BDBAB91)


@dataclass(frozen=True)
class OuterV3Layout:
    path: Path
    property_end: int
    separator_offset: int
    version_offset: int
    version_value: int
    encoded_plus_key_and_trailer_offset: int
    trailing_hash_offset: int
    trailing_hash_le: int
    encoded_plus_key_len: int
    trailer_hash_verified: bool


def u32le(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 4], "little")


def u64le(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 8], "little")


def derive_selectors_from_hash(h: int) -> tuple[int, int]:
    sel_a = (h & 0x3F) | 0x40
    sel_b = 10 + 10 * (h % 3)
    return sel_a, sel_b


def parse_outer_v3_layout(path: Path) -> OuterV3Layout:
    data = path.read_bytes()
    if not data.startswith(MAGIC_PREFIX):
        raise ValueError("file does not start with UTF-8 BOM + YSGP")

    property_end = detect_property_end(data)
    if property_end + 5 + 8 > len(data):
        raise ValueError("file too short for proven outer v3 framing")

    separator_offset = property_end
    version_offset = property_end + 1
    version_value = u32le(data, version_offset)
    trailing_hash_offset = len(data) - 8
    trailing_hash_le = u64le(data, trailing_hash_offset)
    expected_trailer = hash64_with_key(data[:trailing_hash_offset], 0x9E5599DB80C67C29)

    if data[separator_offset] != 0:
        raise ValueError("expected 0x00 separator byte after property block")
    if version_value != 3:
        raise ValueError(f"expected outer version dword 3, got {version_value}")

    return OuterV3Layout(
        path=path,
        property_end=property_end,
        separator_offset=separator_offset,
        version_offset=version_offset,
        version_value=version_value,
        encoded_plus_key_and_trailer_offset=property_end + 5,
        trailing_hash_offset=trailing_hash_offset,
        trailing_hash_le=trailing_hash_le,
        encoded_plus_key_len=trailing_hash_offset - (property_end + 5),
        trailer_hash_verified=trailing_hash_le == expected_trailer,
    )


def print_layout(layout: OuterV3Layout) -> None:
    print(f"file: {layout.path}")
    print(f"property_end: 0x{layout.property_end:08x}")
    print(f"separator_offset: 0x{layout.separator_offset:08x}")
    print(f"version_offset: 0x{layout.version_offset:08x}")
    print(f"version_value: {layout.version_value}")
    print(
        "encoded_plus_key_offset: "
        f"0x{layout.encoded_plus_key_and_trailer_offset:08x}"
    )
    print(f"trailing_hash_offset: 0x{layout.trailing_hash_offset:08x}")
    print(f"trailing_hash_le: 0x{layout.trailing_hash_le:016x}")
    print(f"trailer_hash_verified: {layout.trailer_hash_verified}")
    print(f"encoded_plus_key_len: 0x{layout.encoded_plus_key_len:x}")
    print("note: encoded-section bytes and raw key-material are not yet split here")


def build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Static-only outer v3 YSGP layout parser for headered .ysm files."
    )
    parser.add_argument("inputs", nargs="+")
    parser.add_argument(
        "--derive-selectors",
        type=lambda x: int(x, 0),
        help="Given a recovered hash64 value, print the proven selector bytes",
    )
    return parser


def main() -> int:
    parser = build_argparser()
    args = parser.parse_args()

    if args.derive_selectors is not None:
        sel_a, sel_b = derive_selectors_from_hash(args.derive_selectors)
        print(f"hash=0x{args.derive_selectors:016x}")
        print(f"sel_a=0x{sel_a:02x}")
        print(f"sel_b={sel_b}")

    for idx, input_path in enumerate(args.inputs):
        if idx:
            print()
        print_layout(parse_outer_v3_layout(Path(input_path)))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
