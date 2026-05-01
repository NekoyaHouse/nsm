from __future__ import annotations

import sys
from pathlib import Path


def ensure_local_extractors(script_file: str) -> None:
    script_dir = Path(script_file).resolve().parent
    script_dir_str = str(script_dir)
    if script_dir_str not in sys.path:
        sys.path.insert(0, script_dir_str)

    extractors_dir = script_dir / "extractors"
    if extractors_dir.is_dir():
        return

    raise SystemExit(
        "Local extractor package is missing.\n"
        "This script expects the repo/bundle layout with an `extractors/` folder next to it.\n"
        "Do not `pip install extractors`; that package is unrelated.\n"
        f"Expected: {extractors_dir}"
    )
