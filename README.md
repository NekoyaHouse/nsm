# NoSteveModel

Alert! - The latest version YSM has changed the way it encrypts files, we are working hard to support the latest version.

## Extract dumped models

This repo now bundles a local `ysm_extractor` helper so you can convert the output from the dumper into readable assets without setting up the full YSM workspace.

1. Run the mod and dump a model as usual (zip file under `ysmdumper/<timestamp>/...`).
2. Open `tools/ysm_extractor`:
   - `cd tools/ysm_extractor`
3. Run:
   - `python3 ysm_extract.py --help`
4. Feed the dumper output path:
   - `python3 ysm_extract.py --dump-folder path/to/dumped_file.bin`

You can also run the shorthand alias:
- `python3 ysm_extractor.py ...`

If you only want JSON extraction, this is the fastest path to get a quick readable output.
