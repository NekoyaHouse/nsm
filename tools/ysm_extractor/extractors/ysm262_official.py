from __future__ import annotations

import hashlib
import zipfile
from dataclasses import dataclass
from pathlib import Path


YSM262_JAR_NAME = "ysm-2.6.2-forge+mc1.20.1-release.jar"
EXPORT_MARKERS = (
    b"commands.yes_steve_model.export.success",
    b"commands.yes_steve_model.export.failure",
    b"commands.yes_steve_model.export.not_exist",
)
LOADER_MARKER = b"libysm-core"


@dataclass(frozen=True)
class Ysm262OfficialBaseline:
    jar_path: Path
    jar_sha256: str
    native_entries: tuple[str, ...]
    native_sha256: tuple[str, ...]
    export_classes: tuple[str, ...]
    loader_classes: tuple[str, ...]


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def find_ysm262_jar(start: Path | None = None) -> Path | None:
    root = (start or Path(__file__)).resolve()
    if root.is_file():
        root = root.parent
    candidates = [root, *root.parents]
    seen: set[Path] = set()
    for base in candidates:
        if base in seen:
            continue
        seen.add(base)
        candidate = base / YSM262_JAR_NAME
        if candidate.is_file():
            return candidate
    return None


def probe_ysm262_official(jar_path: Path | None = None) -> Ysm262OfficialBaseline | None:
    jar_path = jar_path or find_ysm262_jar()
    if jar_path is None or not jar_path.is_file():
        return None

    jar_bytes = jar_path.read_bytes()
    native_entries: list[str] = []
    native_sha256: list[str] = []
    export_classes: list[str] = []
    loader_classes: list[str] = []

    with zipfile.ZipFile(jar_path) as zf:
        for name in zf.namelist():
            if "libysm-core" in name:
                native_entries.append(name)
                native_sha256.append(_sha256_hex(zf.read(name)))
                continue
            if not name.endswith(".class"):
                continue
            payload = zf.read(name)
            if any(marker in payload for marker in EXPORT_MARKERS):
                export_classes.append(name[:-6].replace("/", "."))
            if LOADER_MARKER in payload:
                loader_classes.append(name[:-6].replace("/", "."))

    return Ysm262OfficialBaseline(
        jar_path=jar_path,
        jar_sha256=_sha256_hex(jar_bytes),
        native_entries=tuple(native_entries),
        native_sha256=tuple(native_sha256),
        export_classes=tuple(sorted(set(export_classes))),
        loader_classes=tuple(sorted(set(loader_classes))),
    )

