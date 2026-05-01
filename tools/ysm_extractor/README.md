# YSM extractor helper

This folder contains the YSM Python extractor entrypoint used for decoding dumped model payloads.

## Quick start

```bash
cd tools/ysm_extractor
python3 ysm_extract.py --help
python3 ysm_extract.py path/to/model_dump
```

`ysm_extractor.py` is a compat wrapper and points to the same CLI.

## Notes

- `--help` is the fastest way to confirm available extraction/verification modes.
- This helper depends on the bundled scripts in this folder; no extra project files are required.
- `--help` output mentions parity caveats for heuristic extraction paths.
