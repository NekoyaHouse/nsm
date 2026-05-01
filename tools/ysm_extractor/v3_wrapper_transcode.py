from __future__ import annotations

from dataclasses import dataclass


ZSTD_FRAME_MAGIC = 0xFD2FB528
ZSTD_SKIPPABLE_MASK = 0xFFFFFFF0
ZSTD_SKIPPABLE_MAGIC = 0x184D2A50
WRAPPER_BLOCK_XOR = 0x00D4E9


@dataclass(frozen=True)
class WrapperBlock:
    last: bool
    wrapper_type: int
    stock_type: int
    block_size: int
    payload_size: int
    header_offset: int
    payload_offset: int
    next_offset: int


def zstd_frame_header_size(buf: bytes, off: int = 0) -> int:
    if off < 0 or off + 6 > len(buf):
        return -1
    if int.from_bytes(buf[off:off + 4], "little") != ZSTD_FRAME_MAGIC:
        return -1
    desc = buf[off + 4]
    single_segment = (desc >> 5) & 1
    dict_id_flag = desc & 0x3
    fcs_flag = desc >> 6

    size = 5
    if not single_segment:
        size += 1
    size += (0, 1, 2, 4)[dict_id_flag]
    if fcs_flag == 0:
        if single_segment:
            size += 1
    elif fcs_flag == 1:
        size += 2
    elif fcs_flag == 2:
        size += 4
    else:
        size += 8
    return size if off + size <= len(buf) else -1


def zstd_frame_checksum_flag(buf: bytes, off: int = 0) -> bool:
    if off < 0 or off + 5 > len(buf):
        return False
    if int.from_bytes(buf[off:off + 4], "little") != ZSTD_FRAME_MAGIC:
        return False
    desc = buf[off + 4]
    return ((desc >> 2) & 1) != 0


def parse_wrapper_block(buf: bytes, off: int) -> WrapperBlock:
    if off < 0 or off + 3 > len(buf):
        raise ValueError("short wrapper block header")
    b0 = buf[off]
    b1 = buf[off + 1]
    b2 = buf[off + 2]
    wrapper_type = (b0 >> 5) & 0x3
    if wrapper_type == 2:
        raise ValueError("wrapper block type 2 is reserved/error")
    block_size = ((((b0 & 0x1F) << 16) | (b2 << 8) | b1) ^ WRAPPER_BLOCK_XOR)
    if block_size < 0:
        raise ValueError("negative wrapper payload size")
    last = (b0 & 0x80) != 0
    stock_type = {0: 2, 1: 1, 3: 0}[wrapper_type]
    payload_size = 1 if wrapper_type == 1 else block_size
    payload_off = off + 3
    next_off = payload_off + payload_size
    if next_off > len(buf):
        raise ValueError("wrapper block overruns input")
    return WrapperBlock(
        last=last,
        wrapper_type=wrapper_type,
        stock_type=stock_type,
        block_size=block_size,
        payload_size=payload_size,
        header_offset=off,
        payload_offset=payload_off,
        next_offset=next_off,
    )


def build_stock_block_header(last: bool, stock_type: int, payload_size: int) -> bytes:
    if stock_type < 0 or stock_type > 2:
        raise ValueError("unsupported stock block type")
    if payload_size < 0 or payload_size > 0x1FFFFF:
        raise ValueError("unsupported stock payload size")
    hdr = (1 if last else 0) | (stock_type << 1) | (payload_size << 3)
    return hdr.to_bytes(4, "little")[:3]


def transcode_wrapper_stream_to_zstd(buf: bytes) -> bytes:
    """
    Evidence-backed transcode path:
    - preserve stock-looking frame header and skippable frames
    - rewrite each custom 3-byte wrapper block header into a stock Zstd block header
    - preserve block payload bytes as-is

    Wrapper type handling proven by the shared decompressor:
    - type 0: compressed, payload bytes == block size
    - type 1: RLE, payload bytes == 1, decoded size == block size
    - type 3: raw, payload bytes == block size
    """
    out = bytearray()
    off = 0
    end = len(buf)
    while off < end:
        if off + 4 > end:
            raise ValueError("truncated wrapper/frame lead")
        magic = int.from_bytes(buf[off:off + 4], "little")
        if magic == ZSTD_FRAME_MAGIC:
            hdr_size = zstd_frame_header_size(buf, off)
            if hdr_size < 0:
                raise ValueError("invalid zstd frame header")
            has_checksum = zstd_frame_checksum_flag(buf, off)
            out.extend(buf[off:off + hdr_size])
            off += hdr_size
            while True:
                blk = parse_wrapper_block(buf, off)
                out.extend(build_stock_block_header(blk.last, blk.stock_type, blk.block_size))
                out.extend(buf[blk.payload_offset:blk.next_offset])
                off = blk.next_offset
                if blk.last:
                    if has_checksum:
                        if off + 4 > end:
                            raise ValueError("truncated frame checksum")
                        out.extend(buf[off:off + 4])
                        off += 4
                    break
            continue
        if (magic & ZSTD_SKIPPABLE_MASK) == ZSTD_SKIPPABLE_MAGIC:
            if off + 8 > end:
                raise ValueError("truncated skippable frame")
            size = int.from_bytes(buf[off + 4:off + 8], "little")
            frame_end = off + 8 + size
            if frame_end > end:
                raise ValueError("skippable frame overruns input")
            out.extend(buf[off:frame_end])
            off = frame_end
            continue
        raise ValueError(f"unexpected wrapper/frame magic 0x{magic:08x} at 0x{off:x}")
    return bytes(out)
