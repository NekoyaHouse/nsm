from __future__ import annotations

import bom_v3_legacy_sections_priority as _impl


def _find_legacy_visible_payload_same_name(
    section: bytes,
    visible_name: str,
) -> tuple[str, int, int, bytes] | None:
    pat = bytes([len(visible_name)]) + visible_name.encode("ascii") + b"\x00"
    pat_no_nul = bytes([len(visible_name)]) + visible_name.encode("ascii")
    start = 0
    best: tuple[str, int, int, bytes] | None = None
    best_key: tuple[int, int, int] | None = None
    max_gap = 0x4000
    while True:
        first = section.find(pat, start)
        if first < 0:
            break
        second_pat = section.find(pat, first + len(pat), min(len(section), first + max_gap))
        second_pat_no = section.find(pat_no_nul, first + len(pat), min(len(section), first + max_gap))
        second = -1
        mode = None
        if second_pat >= 0 and (second_pat_no < 0 or second_pat <= second_pat_no):
            second = second_pat
            mode = "pat"
        elif second_pat_no >= 0:
            second = second_pat_no
            mode = "pat_no"
        if second < 0:
            start = first + 1
            continue
        if mode == "pat_no":
            payload_off = second + len(pat_no_nul)
        else:
            payload_off = second + len(pat)
        if payload_off < len(section) and section[payload_off] == 0:
            payload_off += 1
        if payload_off + 2 > len(section):
            start = first + 1
            continue
        count = section[payload_off]
        kind = section[payload_off + 1]
        block_end = -1
        search_end = min(len(section) - 2, payload_off + 0x4000)
        for off in range(payload_off + 2, search_end):
            ln = section[off]
            end = off + 1 + ln
            if not (1 <= ln <= 32 and end < len(section) and section[end] == 0):
                continue
            try:
                text = section[off + 1:end].decode("ascii")
            except UnicodeDecodeError:
                continue
            if _impl._plausible_legacy_name(text):
                block_end = off
                break
        if block_end < 0:
            start = first + 1
            continue
        payload = section[payload_off + 2:block_end]
        if not payload:
            start = first + 1
            continue
        candidate = (visible_name, count, kind, payload)
        if kind == 6:
            key = (0, second - first, len(payload))
        elif kind in (69, 70, 72, 76, 77, 82):
            key = (1, second - first, len(payload))
        elif count > 0:
            key = (2, second - first, len(payload))
        else:
            key = (3, second - first, len(payload))
        if best_key is None or key < best_key:
            best = candidate
            best_key = key
        start = first + 1
    return best


_impl._find_legacy_visible_payload_same_name = _find_legacy_visible_payload_same_name

for _name in dir(_impl):
    if _name.startswith("__"):
        continue
    globals()[_name] = getattr(_impl, _name)
