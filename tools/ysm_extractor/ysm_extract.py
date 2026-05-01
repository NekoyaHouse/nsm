from _extractor_bootstrap import ensure_local_extractors

ensure_local_extractors(__file__)

from extractors.ysm_extract import *  # noqa: F401,F403


if __name__ == "__main__":
    raise SystemExit(main())
