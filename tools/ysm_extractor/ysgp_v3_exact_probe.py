from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import shutil
import subprocess
import tempfile

from mt19937_64_reference import MT19937_64
from provider1_chacha_reference import Provider1State, chacha_xor_stream, make_state_hchacha
from v3_wrapper_transcode import transcode_wrapper_stream_to_zstd
from v3_seed_mix_reference import SECOND_STAGE_SEED_KEY, derive_selectors_exact, mix56_exact
from ysgp_end_to_end_extractor import (
    CandidateProfile,
    PROFILES,
    OUTER_KEY_HASH_KEY,
    _u64le,
    decrypt_candidate,
)
from ysgp_outer_v3_static import hash64_with_key, parse_outer_v3_layout


@dataclass(frozen=True)
class V3ExactInput:
    path: Path
    ciphertext: bytes
    key56: bytes
    outer_hash: int
    property_end: int
    encoded_offset: int
    key56_offset: int
    outer_hash_offset: int
    key_hash: int
    sel_a: int
    sel_b: int


@dataclass
class V3ExactCandidate:
    score: int
    rounds: int
    profile: CandidateProfile
    second_stage: str
    prelude_skip: int
    section_offset: int
    section_tag: int
    small_dword_count: int
    ascii_head_ratio: float
    zstd_header_ok: bool
    zstd_block_type: int
    zstd_block_size: int
    wrapper_block_ok: bool
    wrapper_block_type: int
    wrapper_block_size: int
    wrapper_transcode_ok: bool
    wrapper_transcode_zstd_ok: bool
    zstd_decompress_ok: bool
    plaintext: bytes


ZSTD_FRAME_MAGIC = 0xFD2FB528


@dataclass
class _RawSource:
    data: bytes
    pos: int = 0

    def read(self, max_len: int) -> bytes:
        if max_len <= 0 or self.pos >= len(self.data):
            return b""
        end = min(len(self.data), self.pos + max_len)
        chunk = self.data[self.pos:end]
        self.pos = end
        return chunk


@dataclass
class _V3Stage1Reader:
    lower: _RawSource
    state48: bytearray
    rounds: int
    next_refill_len: int
    postprocess_hash_key: int = OUTER_KEY_HASH_KEY
    side_shift_mode: str = "right"
    pending_len: int = 0
    pending_block: bytearray = field(default_factory=lambda: bytearray(64))
    side48: bytearray = field(default_factory=lambda: bytearray(48))

    @classmethod
    def from_input(
        cls,
        inp: V3ExactInput,
        *,
        postprocess_hash_key: int = OUTER_KEY_HASH_KEY,
        side_shift_mode: str = "right",
    ) -> "_V3Stage1Reader":
        state = make_state_hchacha(
            key32=inp.key56[:32],
            secondary16=inp.key56[32:48],
            secondary_qword64=_u64le(inp.key56, 48),
            rounds=inp.sel_b,
        )
        state48 = bytearray()
        state48.extend(state.key_or_subkey32)
        state48.extend(state.counter64.to_bytes(8, "little"))
        state48.extend(state.secondary_qword64.to_bytes(8, "little"))
        return cls(
            lower=_RawSource(inp.ciphertext),
            state48=state48,
            rounds=inp.sel_b,
            next_refill_len=inp.sel_a << 6,
            postprocess_hash_key=postprocess_hash_key,
            side_shift_mode=side_shift_mode,
        )

    def _provider_state(self) -> Provider1State:
        return Provider1State(
            key_or_subkey32=bytes(self.state48[:32]),
            counter64=_u64le(self.state48, 32),
            secondary_qword64=_u64le(self.state48, 40),
            rounds=self.rounds,
        )

    def _store_counter(self, state: Provider1State) -> None:
        self.state48[32:40] = state.counter64.to_bytes(8, "little")

    def _shift_side_state_right(self) -> None:
        old = bytes(self.side48)
        for i in range(48):
            self.side48[i] = ((old[i] >> 1) & 0x7F) | ((old[(i - 1) % 48] & 1) << 7)

    def _shift_side_state_left(self) -> None:
        old = bytes(self.side48)
        for i in range(48):
            self.side48[i] = ((old[i] << 1) & 0xFE) | ((old[(i + 1) % 48] >> 7) & 1)

    def _post_process_plain_chunk(self, plain_chunk: bytes) -> None:
        chunk_hash = hash64_with_key(plain_chunk, self.postprocess_hash_key)
        self.next_refill_len = (((chunk_hash & 0x3F) | 0x40) << 6)
        self.rounds = 10 + 10 * (chunk_hash % 3)
        if self.side_shift_mode == "right":
            self._shift_side_state_right()
        elif self.side_shift_mode == "left":
            self._shift_side_state_left()
        elif self.side_shift_mode != "none":
            raise ValueError(f"unsupported side_shift_mode {self.side_shift_mode}")
        _rolling_state_xor_update(self.state48, chunk_hash)

    def _transform_chunk(self, src: bytes, finalize: bool) -> bytes:
        state = self._provider_state()
        out = bytearray()
        off = 0

        if self.pending_len + len(src) >= 0x40:
            if self.pending_len != 0:
                need = 0x40 - self.pending_len
                self.pending_block[self.pending_len:self.pending_len + need] = src[:need]
                out.extend(chacha_xor_stream(state, bytes(self.pending_block[:0x40])))
                self.pending_len = 0
                off += need

            full = (len(src) - off) & ~0x3F
            if full != 0:
                out.extend(chacha_xor_stream(state, src[off:off + full]))
                off += full

        tail = src[off:]
        if tail:
            if finalize:
                self.pending_block[self.pending_len:self.pending_len + len(tail)] = tail
                self.pending_len += len(tail)
                out.extend(chacha_xor_stream(state, bytes(self.pending_block[:self.pending_len])))
                self.pending_len = 0
            else:
                self.pending_block[self.pending_len:self.pending_len + len(tail)] = tail
                self.pending_len += len(tail)
        elif finalize and self.pending_len:
            out.extend(chacha_xor_stream(state, bytes(self.pending_block[:self.pending_len])))
            self.pending_len = 0

        self._store_counter(state)
        return bytes(out)

    def read_all(self) -> bytes:
        out = bytearray()
        while True:
            requested = self.next_refill_len
            chunk = self.lower.read(requested)
            if not chunk:
                out.extend(self._transform_chunk(b"", finalize=True))
                break

            finalize = len(chunk) != requested
            plain = self._transform_chunk(chunk, finalize=finalize)
            out.extend(plain)
            if plain and not finalize:
                self._post_process_plain_chunk(plain)
            if finalize:
                break
        return bytes(out)


def _u32le(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 4], "little")


def _ascii_ratio(data: bytes) -> float:
    if not data:
        return 1.0
    printable = sum(0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D) for b in data)
    return printable / len(data)


def _parse_zstd_block_header(buf: bytes) -> tuple[bool, int, int]:
    if len(buf) < 9:
        return False, -1, -1
    if _u32le(buf, 0) != ZSTD_FRAME_MAGIC:
        return False, -1, -1

    desc = buf[4]
    single_segment = (desc >> 5) & 1
    dict_id_flag = desc & 0x3
    fcs_flag = desc >> 6

    off = 5
    if not single_segment:
        off += 1
    off += (0, 1, 2, 4)[dict_id_flag]
    if fcs_flag == 0:
        if single_segment:
            off += 1
    elif fcs_flag == 1:
        off += 2
    elif fcs_flag == 2:
        off += 4
    else:
        off += 8

    if len(buf) < off + 3:
        return False, -1, -1

    block_header = buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16)
    block_type = (block_header >> 1) & 0x3
    block_size = block_header >> 3
    return block_type != 3 and block_size <= 131072, block_type, block_size


def _zstd_frame_header_size(buf: bytes) -> int:
    if len(buf) < 6 or _u32le(buf, 0) != ZSTD_FRAME_MAGIC:
        return -1
    desc = buf[4]
    single_segment = (desc >> 5) & 1
    dict_id_flag = desc & 0x3
    fcs_flag = desc >> 6

    off = 5
    if not single_segment:
        off += 1
    off += (0, 1, 2, 4)[dict_id_flag]
    if fcs_flag == 0:
        if single_segment:
            off += 1
    elif fcs_flag == 1:
        off += 2
    elif fcs_flag == 2:
        off += 4
    else:
        off += 8
    return off if off <= len(buf) else -1


def _parse_ysm_wrapper_block_header(buf: bytes) -> tuple[bool, int, int]:
    hdr = _zstd_frame_header_size(buf)
    if hdr < 0 or len(buf) < hdr + 3:
        return False, -1, -1
    b0 = buf[hdr]
    b1 = buf[hdr + 1]
    b2 = buf[hdr + 2]
    block_type = (b0 >> 5) & 0x3
    block_size = ((b0 & 0x1F) << 16) | (b2 << 8) | b1
    block_size ^= 0x00D4E9
    ok = block_type != 2 and 0 <= block_size <= 131072
    return ok, block_type, block_size


def _try_zstd_decompress(buf: bytes) -> bool:
    if len(buf) < 4 or _u32le(buf, 0) != ZSTD_FRAME_MAGIC:
        return False
    zstd = shutil.which("zstd")
    if zstd is None:
        return False
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(buf)
        tmp_path = tmp.name
    try:
        proc = subprocess.run(
            [zstd, "-d", "-q", "-c", tmp_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return proc.returncode == 0
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def _derive_selectors_from_hash_exact(h: int) -> tuple[int, int]:
    sel_a = (h & 0x3F) | 0x40
    sel_b = 10 + 10 * (h % 3)
    return sel_a, sel_b


def parse_v3_exact_input(path: Path) -> V3ExactInput:
    layout = parse_outer_v3_layout(path)
    if not layout.trailer_hash_verified:
        raise ValueError("outer trailer hash does not verify")

    data = path.read_bytes()
    encoded_offset = layout.encoded_plus_key_and_trailer_offset
    outer_hash_offset = layout.trailing_hash_offset
    key56_offset = outer_hash_offset - 56
    if key56_offset <= encoded_offset:
        raise ValueError("file too short for proven v3 ciphertext + key56 + outer hash layout")

    ciphertext = data[encoded_offset:key56_offset]
    key56 = data[key56_offset:outer_hash_offset]
    outer_hash = _u64le(data, outer_hash_offset)
    key_hash, sel_a, sel_b = derive_selectors_exact(key56)

    return V3ExactInput(
        path=path,
        ciphertext=ciphertext,
        key56=key56,
        outer_hash=outer_hash,
        property_end=layout.property_end,
        encoded_offset=encoded_offset,
        key56_offset=key56_offset,
        outer_hash_offset=outer_hash_offset,
        key_hash=key_hash,
        sel_a=sel_a,
        sel_b=sel_b,
    )


def decrypt_v3_confirmed(inp: V3ExactInput) -> bytes:
    state = make_state_hchacha(
        key32=inp.key56[:32],
        secondary16=inp.key56[32:48],
        secondary_qword64=_u64le(inp.key56, 48),
        rounds=inp.sel_b,
    )
    return chacha_xor_stream(state, inp.ciphertext)


def _rolling_state_xor_update(state48: bytearray, chunk_hash: int) -> None:
    hash8 = chunk_hash.to_bytes(8, "little")
    for i in range(0x30):
        state48[i] ^= hash8[i & 7]


def decrypt_v3_chunk_rekey(inp: V3ExactInput) -> bytes:
    """
    Likely read-path reconstruction from FUN_005d78c0 + slot +0x20 call flow.

    Evidence-backed behavior:
    - initial chunk size is `sel_a << 6`
    - full raw ciphertext chunks are transformed with the current ChaCha state
    - after each full chunk with more data remaining, the raw chunk is hashed with
      the generic keyed hash and the first 0x30 bytes of state are XOR-updated
    - the next chunk size and round count derive from that chunk hash

    Remaining uncertainty:
    - the auxiliary 0x40..0x6f state bytes mutated by the same helper are not
      consumed by the recovered provider core, so they are omitted here
    """

    initial = make_state_hchacha(
        key32=inp.key56[:32],
        secondary16=inp.key56[32:48],
        secondary_qword64=_u64le(inp.key56, 48),
        rounds=inp.sel_b,
    )
    state48 = bytearray()
    state48.extend(initial.key_or_subkey32)
    state48.extend(initial.counter64.to_bytes(8, "little"))
    state48.extend(initial.secondary_qword64.to_bytes(8, "little"))

    rounds = inp.sel_b
    chunk_len = inp.sel_a << 6
    out = bytearray()
    off = 0
    total = len(inp.ciphertext)

    while off < total:
        take = min(chunk_len, total - off)
        chunk = inp.ciphertext[off:off + take]
        state = Provider1State(
            key_or_subkey32=bytes(state48[:32]),
            counter64=_u64le(state48, 32),
            secondary_qword64=_u64le(state48, 40),
            rounds=rounds,
        )
        plain_chunk = chacha_xor_stream(state, chunk)
        out.extend(plain_chunk)
        state48[32:40] = state.counter64.to_bytes(8, "little")
        off += take

        if off < total and take == chunk_len:
            chunk_hash = hash64_with_key(plain_chunk, OUTER_KEY_HASH_KEY)
            _rolling_state_xor_update(state48, chunk_hash)
            chunk_sel_a, chunk_sel_b = _derive_selectors_from_hash_exact(chunk_hash)
            chunk_len = chunk_sel_a << 6
            rounds = chunk_sel_b

    return bytes(out)


def decrypt_v3_reader_exact(inp: V3ExactInput) -> bytes:
    """
    Confirmed object-level reconstruction of the first-stage v3 reader:
    - lower source is the raw ciphertext span
    - requested refill length starts at sel_a << 6
    - produced plaintext chunks drive slot +0x20 post-processing
    - post-processing mutates the live 0x30-byte provider state in place
    """
    return _V3Stage1Reader.from_input(inp).read_all()


def decrypt_v3_reader_vtbl_17690(inp: V3ExactInput) -> bytes:
    """
    Likely BOM v3 reader variant tied to PTR_FUN_00e17690.

    Evidence:
    - slot +0x20 is FUN_005199b0, not FUN_005631f0
    - FUN_005199b0 hashes chunks with 0xd1c3d1d13a99752b
    - it applies the opposite side-state bit shift
    """
    return _V3Stage1Reader.from_input(
        inp,
        postprocess_hash_key=0xD1C3D1D13A99752B,
        side_shift_mode="left",
    ).read_all()


def _apply_second_stage_mt(key56: bytes, src: bytes) -> bytes:
    seed = mix56_exact(key56, SECOND_STAGE_SEED_KEY)
    return MT19937_64.from_seed(seed).xor_stream(src)


def _apply_second_stage_variant(key56: bytes, src: bytes, variant: str) -> bytes:
    if variant == "none":
        return src

    seed = mix56_exact(key56, SECOND_STAGE_SEED_KEY)
    mt = MT19937_64.from_seed(seed)

    if variant.startswith("mt19937_64_phase"):
        phase = int(variant.removeprefix("mt19937_64_phase"))
        return mt.xor_stream_phase(src, phase, "little")
    if variant.startswith("mt19937_64_be_phase"):
        phase = int(variant.removeprefix("mt19937_64_be_phase"))
        return mt.xor_stream_phase(src, phase, "big")
    if variant.startswith("mt19937_64_skip"):
        skip = int(variant.removeprefix("mt19937_64_skip"))
        for _ in range(skip):
            mt.next_u64()
        return mt.xor_stream(src)

    if variant == "mt19937_64_xor":
        return mt.xor_stream(src)
    if variant == "mt19937_64_xor_be":
        return mt.xor_stream_endian(src, "big")

    raise ValueError(f"unknown second-stage variant {variant}")


def _score_stream_plaintext(
    pt: bytes,
    derived_rounds: int,
    rounds: int,
    profile: CandidateProfile,
    second_stage: str,
) -> tuple[int, int, int, int, int, float, bool, int, int, bool, int, int, bool, bool, bool]:
    if len(pt) < 6:
        return (-10_000, 0, 0, 0, 0, 1.0, False, -1, -1, False, -1, -1, False, False, False)

    prelude_skip = int.from_bytes(pt[:2], "little") & 0x3FF
    section_offset = 2 + prelude_skip
    if section_offset + 4 > len(pt):
        return (-9_000, prelude_skip, section_offset, 0, 0, 1.0, False, -1, -1, False, -1, -1, False, False, False)

    section_tag = _u32le(pt, section_offset)
    dwords = [_u32le(pt, off) for off in range(0, min(len(pt), 32), 4)]
    small_dword_count = sum(1 for v in dwords if v < 0x100)
    ascii_head_ratio = _ascii_ratio(pt[:0x80])
    zstd_header_ok, zstd_block_type, zstd_block_size = _parse_zstd_block_header(pt[section_offset:])
    wrapper_block_ok, wrapper_block_type, wrapper_block_size = _parse_ysm_wrapper_block_header(
        pt[section_offset:]
    )
    wrapper_transcode_ok = False
    wrapper_transcode_zstd_ok = False
    if wrapper_block_ok:
        try:
            transcoded = transcode_wrapper_stream_to_zstd(pt[section_offset:])
            wrapper_transcode_ok = True
            wrapper_transcode_zstd_ok = _try_zstd_decompress(transcoded)
        except Exception:
            wrapper_transcode_ok = False
            wrapper_transcode_zstd_ok = False
    zstd_decompress_ok = _try_zstd_decompress(pt[section_offset:]) if zstd_header_ok else False

    score = 0
    if prelude_skip <= 0x100:
        score += 30
    elif prelude_skip <= 0x200:
        score += 10
    else:
        score -= 20

    if section_tag == ZSTD_FRAME_MAGIC:
        score += 1200
    elif (section_tag & 0xFFFFFFF0) == 0x184D2A50:
        score += 800
    elif 1 <= section_tag <= 31:
        score += 200
    elif section_tag < 0x100:
        score += 30
    elif section_tag < 0x10000:
        score += 10

    if zstd_header_ok:
        score += 200
    if wrapper_block_ok:
        score += 1000
        if wrapper_block_size <= 65536:
            score += 100
    if wrapper_transcode_ok:
        score += 400
    if wrapper_transcode_zstd_ok:
        score += 4000
    if zstd_decompress_ok:
        score += 5000
    score += small_dword_count * 6
    if rounds == derived_rounds:
        score += 20
    if profile.confidence == "confirmed":
        score += 10
    if second_stage == "mt19937_64_xor":
        score += 40
    if ascii_head_ratio > 0.6:
        score -= 10
    return (
        score,
        prelude_skip,
        section_offset,
        section_tag,
        small_dword_count,
        ascii_head_ratio,
        zstd_header_ok,
        zstd_block_type,
        zstd_block_size,
        zstd_decompress_ok,
        wrapper_block_type,
        wrapper_block_size,
        wrapper_block_ok,
        wrapper_transcode_ok,
        wrapper_transcode_zstd_ok,
    )


def enumerate_v3_exact_candidates(inp: V3ExactInput, extra_rounds: list[int]) -> list[V3ExactCandidate]:
    results: list[V3ExactCandidate] = []
    round_set = {inp.sel_b}
    round_set.update(r for r in extra_rounds if r > 0 and (r & 1) == 0)
    second_stage_variants = (
        "none",
        "mt19937_64_xor",
        "mt19937_64_xor_be",
        "mt19937_64_skip1",
        "mt19937_64_skip2",
        "mt19937_64_skip4",
    )
    for rounds in sorted(round_set):
        for profile in PROFILES:
            try:
                chacha_pt = decrypt_candidate(inp.ciphertext, inp.key56, rounds, profile)
            except Exception:
                continue

            for second_stage in second_stage_variants:
                pt = _apply_second_stage_variant(inp.key56, chacha_pt, second_stage)
                (
                    score,
                    prelude_skip,
                    section_offset,
                    section_tag,
                    small_count,
                    ascii_ratio,
                    zstd_header_ok,
                    zstd_block_type,
                    zstd_block_size,
                    zstd_decompress_ok,
                    wrapper_block_type,
                    wrapper_block_size,
                    wrapper_block_ok,
                    wrapper_transcode_ok,
                    wrapper_transcode_zstd_ok,
                ) = _score_stream_plaintext(
                    pt,
                    derived_rounds=inp.sel_b,
                    rounds=rounds,
                    profile=profile,
                    second_stage=second_stage,
                )
                results.append(
                    V3ExactCandidate(
                        score=score,
                        rounds=rounds,
                        profile=profile,
                        second_stage=second_stage,
                        prelude_skip=prelude_skip,
                        section_offset=section_offset,
                        section_tag=section_tag,
                        small_dword_count=small_count,
                        ascii_head_ratio=ascii_ratio,
                        zstd_header_ok=zstd_header_ok,
                        zstd_block_type=zstd_block_type,
                        zstd_block_size=zstd_block_size,
                        wrapper_block_ok=wrapper_block_ok,
                        wrapper_block_type=wrapper_block_type,
                        wrapper_block_size=wrapper_block_size,
                        wrapper_transcode_ok=wrapper_transcode_ok,
                        wrapper_transcode_zstd_ok=wrapper_transcode_zstd_ok,
                        zstd_decompress_ok=zstd_decompress_ok,
                        plaintext=pt,
                    )
                )
    rolling_profile = CandidateProfile(
        derivation_mode="rolling_chunk_hash_state_xor",
        state_layout="hchacha_qword_tail",
        counter0=0,
        confidence="likely",
    )
    try:
        chacha_pt = decrypt_v3_chunk_rekey(inp)
    except Exception:
        chacha_pt = b""
    if chacha_pt:
        for second_stage in second_stage_variants:
            pt = _apply_second_stage_variant(inp.key56, chacha_pt, second_stage)
            (
                score,
                prelude_skip,
                section_offset,
                section_tag,
                small_count,
                ascii_ratio,
                zstd_header_ok,
                zstd_block_type,
                zstd_block_size,
                zstd_decompress_ok,
                wrapper_block_type,
                wrapper_block_size,
                wrapper_block_ok,
                wrapper_transcode_ok,
                wrapper_transcode_zstd_ok,
            ) = _score_stream_plaintext(
                pt,
                derived_rounds=inp.sel_b,
                rounds=inp.sel_b,
                profile=rolling_profile,
                second_stage=second_stage,
            )
            results.append(
                V3ExactCandidate(
                    score=score,
                    rounds=inp.sel_b,
                    profile=rolling_profile,
                    second_stage=second_stage,
                    prelude_skip=prelude_skip,
                    section_offset=section_offset,
                    section_tag=section_tag,
                    small_dword_count=small_count,
                    ascii_head_ratio=ascii_ratio,
                    zstd_header_ok=zstd_header_ok,
                    zstd_block_type=zstd_block_type,
                    zstd_block_size=zstd_block_size,
                    wrapper_block_ok=wrapper_block_ok,
                    wrapper_block_type=wrapper_block_type,
                    wrapper_block_size=wrapper_block_size,
                    wrapper_transcode_ok=wrapper_transcode_ok,
                    wrapper_transcode_zstd_ok=wrapper_transcode_zstd_ok,
                    zstd_decompress_ok=zstd_decompress_ok,
                    plaintext=pt,
                )
            )
    exact_reader_profile = CandidateProfile(
        derivation_mode="exact_reader_live_workspace_post_005631f0",
        state_layout="hchacha_qword_tail",
        counter0=0,
        confidence="confirmed",
    )
    try:
        chacha_pt = decrypt_v3_reader_exact(inp)
    except Exception:
        chacha_pt = b""
    if chacha_pt:
        for second_stage in second_stage_variants:
            pt = _apply_second_stage_variant(inp.key56, chacha_pt, second_stage)
            (
                score,
                prelude_skip,
                section_offset,
                section_tag,
                small_count,
                ascii_ratio,
                zstd_header_ok,
                zstd_block_type,
                zstd_block_size,
                zstd_decompress_ok,
                wrapper_block_type,
                wrapper_block_size,
                wrapper_block_ok,
                wrapper_transcode_ok,
                wrapper_transcode_zstd_ok,
            ) = _score_stream_plaintext(
                pt,
                derived_rounds=inp.sel_b,
                rounds=inp.sel_b,
                profile=exact_reader_profile,
                second_stage=second_stage,
            )
            results.append(
                V3ExactCandidate(
                    score=score,
                    rounds=inp.sel_b,
                    profile=exact_reader_profile,
                    second_stage=second_stage,
                    prelude_skip=prelude_skip,
                    section_offset=section_offset,
                    section_tag=section_tag,
                    small_dword_count=small_count,
                    ascii_head_ratio=ascii_ratio,
                    zstd_header_ok=zstd_header_ok,
                    zstd_block_type=zstd_block_type,
                    zstd_block_size=zstd_block_size,
                    wrapper_block_ok=wrapper_block_ok,
                    wrapper_block_type=wrapper_block_type,
                    wrapper_block_size=wrapper_block_size,
                    wrapper_transcode_ok=wrapper_transcode_ok,
                    wrapper_transcode_zstd_ok=wrapper_transcode_zstd_ok,
                    zstd_decompress_ok=zstd_decompress_ok,
                    plaintext=pt,
                )
            )
    vtbl_17690_profile = CandidateProfile(
        derivation_mode="reader_vtbl_17690_live_workspace_post_005199b0",
        state_layout="hchacha_qword_tail",
        counter0=0,
        confidence="likely",
    )
    try:
        chacha_pt = decrypt_v3_reader_vtbl_17690(inp)
    except Exception:
        chacha_pt = b""
    if chacha_pt:
        for second_stage in second_stage_variants:
            pt = _apply_second_stage_variant(inp.key56, chacha_pt, second_stage)
            (
                score,
                prelude_skip,
                section_offset,
                section_tag,
                small_count,
                ascii_ratio,
                zstd_header_ok,
                zstd_block_type,
                zstd_block_size,
                zstd_decompress_ok,
                wrapper_block_type,
                wrapper_block_size,
                wrapper_block_ok,
                wrapper_transcode_ok,
                wrapper_transcode_zstd_ok,
            ) = _score_stream_plaintext(
                pt,
                derived_rounds=inp.sel_b,
                rounds=inp.sel_b,
                profile=vtbl_17690_profile,
                second_stage=second_stage,
            )
            results.append(
                V3ExactCandidate(
                    score=score,
                    rounds=inp.sel_b,
                    profile=vtbl_17690_profile,
                    second_stage=second_stage,
                    prelude_skip=prelude_skip,
                    section_offset=section_offset,
                    section_tag=section_tag,
                    small_dword_count=small_count,
                    ascii_head_ratio=ascii_ratio,
                    zstd_header_ok=zstd_header_ok,
                    zstd_block_type=zstd_block_type,
                    zstd_block_size=zstd_block_size,
                    wrapper_block_ok=wrapper_block_ok,
                    wrapper_block_type=wrapper_block_type,
                    wrapper_block_size=wrapper_block_size,
                    wrapper_transcode_ok=wrapper_transcode_ok,
                    wrapper_transcode_zstd_ok=wrapper_transcode_zstd_ok,
                    zstd_decompress_ok=zstd_decompress_ok,
                    plaintext=pt,
                )
            )
    results.sort(key=lambda cand: cand.score, reverse=True)
    return results


def is_valid_v3_stream_candidate(cand: V3ExactCandidate) -> bool:
    return (
        cand.section_tag == ZSTD_FRAME_MAGIC
        or (cand.section_tag & 0xFFFFFFF0) == 0x184D2A50
        or cand.zstd_header_ok
    )


def dump_v3_candidate(base: Path, rank: int, cand: V3ExactCandidate) -> Path:
    name = (
        f"{base.stem}.v3stream_{rank:02d}"
        f".score_{cand.score}"
        f".skip_{cand.prelude_skip}"
        f".off_{cand.section_offset}"
        f".tag_{cand.section_tag}"
        f".r{cand.rounds}"
        f".{cand.profile.derivation_mode}"
        f".{cand.profile.state_layout}"
        f".{cand.second_stage}"
        f".bin"
    )
    out_path = base.with_name(name)
    out_path.write_bytes(cand.plaintext)
    return out_path
