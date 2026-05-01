from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import textwrap
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from extractors.bom_v3_payload_assets import _read_property_format, _read_property_name, _sanitize_name
from extractors.bom_v3_source_oracle import find_best_source_oracle
from extractors.ysm262_official import find_ysm262_jar, probe_ysm262_official


CANONICAL_MODEL_FILES = ("main.json", "arm.json", "arrow.json")
CANONICAL_ANIMATION_FILES = (
    "main.animation.json",
    "extra.animation.json",
    "tac.animation.json",
    "carryon.animation.json",
    "arrow.animation.json",
)
SOUND_GLOB = "*.ogg"
PNG_GLOB = "*.png"
DEFAULT_MINECRAFT_ROOT = Path.home() / ".minecraft"
DEFAULT_FORGE_VERSION_ID = "1.20.1-forge-47.4.12"
DEFAULT_FALLBACK_ROOTS = (Path.home() / ".gradle",)
DEFAULT_FORGE_RUNTIME_COMPANIONS = ("fmlcore", "javafmllanguage", "lowcodelanguage", "mclanguage")
DEFAULT_FORGE_MCP_VERSION = "20230612.114412"
DEFAULT_BOOTSTRAP_MAIN_CLASS = "cpw.mods.bootstraplauncher.BootstrapLauncher"
DEFAULT_BOOTSTRAP_IGNORE_LIST_TEMPLATE = (
    "bootstraplauncher,securejarhandler,asm-commons,asm-util,asm-analysis,asm-tree,asm,"
    "JarJarFileSystems,client-extra,fmlcore,javafmllanguage,lowcodelanguage,mclanguage,forge-,{version_id}.jar"
)
DEFAULT_MCP_CLIENT_ARTIFACT_SUFFIXES = ("srg", "extra")
DEFAULT_HEADED_DEBUG_PROFILE_ID = "ysm-headed-debug"
DEFAULT_HEADED_DEBUG_PROFILE_NAME = "YSM Headed Debug"
DEFAULT_CAPTURE_PROFILE_ID_PREFIX = "ysm-headed-export"
DEFAULT_CAPTURE_PROFILE_NAME_PREFIX = "YSM Export"
DEFAULT_DEBUG_RUNTIME_ENV = "YSM262_DEBUG_RUNTIME_ROOT"


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _default_debug_runtime_root() -> Path:
    override = os.getenv(DEFAULT_DEBUG_RUNTIME_ENV)
    if override:
        return Path(override).expanduser().resolve()
    return _repo_root() / "debug_runtime"


def _default_headed_host_out_dir() -> Path:
    return _default_debug_runtime_root() / "headed_host_bundle"


def _default_vm_bundle_out_dir() -> Path:
    return _default_debug_runtime_root() / "vm_bundle_guest_gdb_use_case"


def _default_launcher_command_out_path() -> Path:
    return _default_debug_runtime_root() / "launcher" / "forgeclient_command_use_case.txt"


def _default_ghidra_root() -> Path:
    return _default_debug_runtime_root() / "ghidra"


def _default_ghidra_reports_dir() -> Path:
    return _default_ghidra_root() / "reports"


@dataclass(frozen=True)
class ExportLayout:
    root: Path
    model_pairs: tuple[tuple[str, str], ...]
    animation_pairs: tuple[tuple[str, str], ...]
    texture_root: Path
    sound_root: Path


@dataclass(frozen=True)
class RuntimeClasspathEntry:
    version_id: str
    kind: str
    source_path: Path
    bundle_path: Path
    logical_name: str


@dataclass(frozen=True)
class RuntimeAudit:
    minecraft_root: Path
    version_id: str
    main_class: str | None
    minecraft_version: str
    forge_version: str | None
    mcp_version: str | None
    entries: tuple[RuntimeClasspathEntry, ...]
    missing: tuple[dict[str, Any], ...]
    searched_version_ids: tuple[str, ...]


@dataclass(frozen=True)
class ForgeBootstrapInfo:
    main_class: str | None
    minecraft_version: str
    forge_version: str | None
    mcp_version: str | None
    ignore_list: str


@dataclass(frozen=True)
class LauncherReplayCommand:
    source_path: Path
    java_executable: str
    main_class: str
    jvm_args: tuple[str, ...]
    game_args: tuple[str, ...]
    launch_target: str | None
    raw_command: str


@dataclass(frozen=True)
class HeadedDebugLayout:
    root: Path
    game_dir: Path
    trace_dir: Path
    scripts_dir: Path
    native_tools_dir: Path
    bin_dir: Path


@dataclass(frozen=True)
class LegacyExportCapture:
    bundle_root: Path
    custom_dir: Path
    export_root: Path
    sample_copy: Path
    snapshot_root: Path
    manifest_path: Path


@dataclass(frozen=True)
class HeadedModelTraceConfig:
    enabled: bool = False
    sample_hint: str | None = None
    family_filter: tuple[str, ...] = tuple()
    export_filter: str = "main.json"
    trace_rel: int = 0x4E2C80
    patch_len: int = 16
    budget: int = 32
    scan_bytes: int = 0x240
    string_limit: int = 64
    vector_limit: int = 48


def detect_export_layout(root: Path) -> ExportLayout:
    model_dir = root / "models"
    animation_dir = root / "animations"
    texture_dir = root / "textures"
    sound_dir = root / "sounds"

    if model_dir.is_dir() or animation_dir.is_dir() or texture_dir.is_dir() or sound_dir.is_dir():
        model_pairs = tuple((name, f"models/{name}") for name in CANONICAL_MODEL_FILES)
        animation_pairs = tuple((name, f"animations/{name}") for name in CANONICAL_ANIMATION_FILES)
        return ExportLayout(
            root=root,
            model_pairs=model_pairs,
            animation_pairs=animation_pairs,
            texture_root=texture_dir if texture_dir.is_dir() else root,
            sound_root=sound_dir if sound_dir.is_dir() else root,
        )

    model_pairs = tuple((name, name) for name in CANONICAL_MODEL_FILES)
    animation_pairs = tuple((name, name) for name in CANONICAL_ANIMATION_FILES)
    return ExportLayout(
        root=root,
        model_pairs=model_pairs,
        animation_pairs=animation_pairs,
        texture_root=root,
        sound_root=root,
    )


def _clear_known_output_dir(out_dir: Path, patterns: Sequence[str]) -> None:
    for pattern in patterns:
        for path in out_dir.glob(pattern):
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink(missing_ok=True)


def _clear_dir_children(root: Path) -> None:
    if not root.exists():
        return
    for child in root.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink(missing_ok=True)


def _legacy_capture_stem(path: Path) -> str:
    return _sanitize_name(path.stem) or "legacy_capture"


def _default_capture_out_dir(ysm_path: Path) -> Path:
    return ysm_path.parent / f".tmp_headed_export_{_legacy_capture_stem(ysm_path)}"


def _default_capture_profile_id(ysm_path: Path) -> str:
    return f"{DEFAULT_CAPTURE_PROFILE_ID_PREFIX}-{_legacy_capture_stem(ysm_path)}"


def _default_capture_profile_name(ysm_path: Path) -> str:
    display_name = _read_property_name(ysm_path) or ysm_path.stem
    compact = re.sub(r"\s+", " ", display_name).strip()
    compact = compact[:48].rstrip() if compact else ysm_path.stem
    return f"{DEFAULT_CAPTURE_PROFILE_NAME_PREFIX} {compact}"


def _default_capture_profile_identity(
    ysm_path: Path,
    *,
    out_dir: Path,
    model_trace: HeadedModelTraceConfig,
) -> tuple[str, str]:
    profile_id = _default_capture_profile_id(ysm_path)
    profile_name = _default_capture_profile_name(ysm_path)
    if model_trace.enabled and model_trace.trace_rel != 0x4E2C80:
        hook_suffix = f"hook-{model_trace.trace_rel:x}"
        profile_id = f"{profile_id}-{hook_suffix}"
        profile_name = f"{profile_name} ({hook_suffix})"
        return profile_id, profile_name
    default_out_dir = _default_capture_out_dir(ysm_path).resolve()
    if out_dir != default_out_dir:
        out_suffix = _sanitize_name(out_dir.name) or "capture"
        profile_id = f"{profile_id}-{out_suffix}"
        profile_name = f"{profile_name} ({out_suffix[:24]})"
    return profile_id, profile_name


def _parse_model_trace_family_filter(raw: str | None) -> tuple[str, ...]:
    if raw is None:
        return tuple()
    values = [item.strip() for item in raw.split(",")]
    return tuple(item for item in values if item)


def _max_tree_mtime(root: Path) -> float:
    latest = root.stat().st_mtime
    for path in root.rglob("*"):
        try:
            latest = max(latest, path.stat().st_mtime)
        except FileNotFoundError:
            continue
    return latest


def _layout_file_count(layout: ExportLayout) -> int:
    count = sum(1 for canonical_name, relpath in layout.model_pairs if (layout.root / relpath).is_file())
    count += sum(1 for canonical_name, relpath in layout.animation_pairs if (layout.root / relpath).is_file())
    count += sum(1 for path in layout.texture_root.glob(PNG_GLOB) if path.is_file())
    count += sum(1 for path in layout.sound_root.glob(SOUND_GLOB) if path.is_file())
    return count


def _is_export_payload_root(root: Path) -> bool:
    if not root.is_dir():
        return False
    layout = detect_export_layout(root)
    return _layout_file_count(layout) > 0


def _candidate_export_roots(export_root: Path) -> list[Path]:
    if not export_root.is_dir():
        return []
    candidates: list[Path] = []
    for root in [export_root, *(path for path in export_root.rglob("*") if path.is_dir())]:
        if _is_export_payload_root(root):
            candidates.append(root)
    deduped: list[Path] = []
    seen: set[Path] = set()
    for root in sorted(candidates):
        if root in seen:
            continue
        seen.add(root)
        deduped.append(root)
    return deduped


def _select_export_root(candidates: Sequence[Path], *, model_id: str) -> Path | None:
    if not candidates:
        return None

    def score(root: Path) -> tuple[int, int, float]:
        parts = {part.lower() for part in root.parts}
        id_score = 1 if model_id.lower() in parts or model_id.lower() in root.name.lower() else 0
        file_score = _layout_file_count(detect_export_layout(root))
        mtime = _max_tree_mtime(root)
        return (id_score, file_score, mtime)

    return max(candidates, key=score)


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _platform_rule_name() -> str:
    if sys_platform := platform.system().lower():
        if sys_platform.startswith("linux"):
            return "linux"
        if sys_platform.startswith("darwin"):
            return "osx"
        if sys_platform.startswith("windows"):
            return "windows"
    return platform.system().lower()


def _platform_arch() -> str:
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        return "x86_64"
    if machine in {"aarch64", "arm64"}:
        return "arm64"
    return machine


def _rules_allow(library: dict[str, Any]) -> bool:
    rules = library.get("rules")
    if not rules:
        return True

    os_name = _platform_rule_name()
    arch = _platform_arch()
    allowed = False
    for rule in rules:
        action = rule.get("action")
        if action not in {"allow", "disallow"}:
            continue
        matches = True
        os_rule = rule.get("os") or {}
        if os_rule.get("name") and os_rule["name"] != os_name:
            matches = False
        if os_rule.get("arch") and os_rule["arch"] != arch:
            matches = False
        if rule.get("features"):
            matches = False
        if matches:
            allowed = action == "allow"
    return allowed


def _load_version_manifest(minecraft_root: Path, version_id: str) -> tuple[Path, dict[str, Any]]:
    path = minecraft_root / "versions" / version_id / f"{version_id}.json"
    if not path.is_file():
        raise FileNotFoundError(path)
    return path, json.loads(path.read_text(encoding="utf-8"))


def _find_fallback_artifact(relative_path: str, fallback_roots: Sequence[Path]) -> Path | None:
    rel = Path(relative_path)
    for root in fallback_roots:
        direct = root / rel
        if direct.is_file():
            return direct
        matches = list(root.rglob(rel.name))
        if matches:
            return matches[0]
    return None


def _extract_argument_value(arguments: Sequence[Any], flag: str) -> str | None:
    for index, value in enumerate(arguments):
        if value == flag and index + 1 < len(arguments):
            next_value = arguments[index + 1]
            if isinstance(next_value, str):
                return next_value
        if isinstance(value, str) and value.startswith(f"{flag}="):
            return value.split("=", 1)[1]
    return None


def _find_jvm_property(arguments: Sequence[Any], name: str) -> str | None:
    prefix = f"-D{name}="
    for value in arguments:
        if isinstance(value, str) and value.startswith(prefix):
            return value[len(prefix) :]
    return None


def _parse_launcher_command_file(
    command_file: Path,
    *,
    expected_main_classes: Sequence[str],
) -> LauncherReplayCommand:
    raw_command = command_file.read_text(encoding="utf-8").strip()
    if not raw_command:
        raise ValueError(f"launcher command file was empty: {command_file}")
    tokens = shlex.split(raw_command)
    if not tokens:
        raise ValueError(f"launcher command file had no tokens: {command_file}")

    if tokens[0] == "gdb":
        if "--args" not in tokens:
            raise ValueError("captured launcher command starts with gdb but has no --args separator")
        tokens = tokens[tokens.index("--args") + 1 :]
        if not tokens:
            raise ValueError("captured launcher command had no java invocation after --args")

    java_executable = tokens[0]
    main_class_index = -1
    for candidate in expected_main_classes:
        if not candidate:
            continue
        try:
            main_class_index = tokens.index(candidate, 1)
            break
        except ValueError:
            continue
    if main_class_index < 0:
        raise ValueError(
            "could not locate the launcher main class in the captured command; "
            f"looked for: {', '.join(candidate for candidate in expected_main_classes if candidate)}"
        )

    main_class = tokens[main_class_index]
    jvm_args = tuple(tokens[1:main_class_index])
    game_args = tuple(tokens[main_class_index + 1 :])
    return LauncherReplayCommand(
        source_path=command_file,
        java_executable=java_executable,
        main_class=main_class,
        jvm_args=jvm_args,
        game_args=game_args,
        launch_target=_extract_argument_value(game_args, "--launchTarget"),
        raw_command=raw_command,
    )


def _shell_quote_lines(values: Sequence[str]) -> str:
    return "\n".join(f"  {shlex.quote(value)}" for value in values)


def _write_launcher_replay_artifacts(
    out_dir: Path,
    *,
    command: LauncherReplayCommand,
    linux_native_name: str | None,
) -> dict[str, Any]:
    if linux_native_name is None:
        return {}

    runtime_dir = out_dir / "runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    scripts_dir = out_dir / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)

    override_flags = {
        "--username": "YSM262_FORGECLIENT_USERNAME",
        "--gameDir": "YSM262_FORGECLIENT_GAME_DIR",
        "--assetsDir": "YSM262_FORGECLIENT_ASSETS_DIR",
        "--assetIndex": "YSM262_FORGECLIENT_ASSET_INDEX",
        "--uuid": "YSM262_FORGECLIENT_UUID",
        "--accessToken": "YSM262_FORGECLIENT_ACCESS_TOKEN",
        "--clientId": "YSM262_FORGECLIENT_CLIENT_ID",
        "--xuid": "YSM262_FORGECLIENT_XUID",
        "--userType": "YSM262_FORGECLIENT_USER_TYPE",
        "--versionType": "YSM262_FORGECLIENT_VERSION_TYPE",
        "--quickPlayPath": "YSM262_FORGECLIENT_QUICK_PLAY_PATH",
    }

    captured_env_values: dict[str, str] = {}
    game_array_lines: list[str] = []
    index = 0
    while index < len(command.game_args):
        token = command.game_args[index]
        env_var = override_flags.get(token)
        if env_var and index + 1 < len(command.game_args):
            value = command.game_args[index + 1]
            captured_env_values[env_var] = value
            game_array_lines.append(f"  {shlex.quote(token)}")
            game_array_lines.append(f'  "${{{env_var}}}"')
            index += 2
            continue
        game_array_lines.append(f"  {shlex.quote(token)}")
        index += 1

    env_example_lines = [
        "# Optional overrides for scripts/run_forgeclient_replay.sh",
        "# Copy to forgeclient_session.env and replace values as needed.",
        "",
    ]
    env_runtime_lines = [
        "# Bundle-local captured session values for scripts/run_forgeclient_replay.sh",
        "# Regenerate or edit if the launcher session changes.",
        "",
    ]
    for flag, env_var in override_flags.items():
        captured = captured_env_values.get(env_var, "")
        rendered_value = shlex.quote(captured) if captured else "''"
        env_example_lines.append(f"{env_var}={rendered_value}")
        env_runtime_lines.append(f"{env_var}={rendered_value}")
    env_example_lines.append("")
    env_runtime_lines.append("")
    env_example = runtime_dir / "forgeclient_session.env.example"
    env_example.write_text("\n".join(env_example_lines), encoding="utf-8")
    env_runtime = runtime_dir / "forgeclient_session.env"
    env_runtime.write_text("\n".join(env_runtime_lines), encoding="utf-8")

    replay_manifest = {
        "source_command_file": str(command.source_path),
        "java_executable": command.java_executable,
        "main_class": command.main_class,
        "launch_target": command.launch_target,
        "jvm_arg_count": len(command.jvm_args),
        "game_arg_count": len(command.game_args),
        "override_env_vars": list(override_flags.values()),
        "captured_jvm_properties": {
            name: _find_jvm_property(command.jvm_args, name)
            for name in (
                "java.library.path",
                "jna.tmpdir",
                "org.lwjgl.system.SharedLibraryExtractPath",
                "io.netty.native.workdir",
                "minecraft.launcher.brand",
                "minecraft.launcher.version",
                "ignoreList",
                "mergeModules",
                "libraryDirectory",
            )
            if _find_jvm_property(command.jvm_args, name) is not None
        },
    }
    manifest_path = runtime_dir / "forgeclient_replay_manifest.json"
    manifest_path.write_text(json.dumps(replay_manifest, indent=2), encoding="utf-8")

    jvm_array_lines = _shell_quote_lines(command.jvm_args)
    game_array_lines_rendered = "\n".join(game_array_lines)
    replay_script = (
        textwrap.dedent(
        f"""\
#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${{BASH_SOURCE[0]}}")/.." && pwd)
BUILD_DIR="$ROOT/build/forgeclient_replay"
REAL_JAVA_EXE=$(readlink -f "$(command -v java)")
JAVA_HOME_DIR=$(dirname "$(dirname "$REAL_JAVA_EXE")")
NATIVE_LIB="$ROOT/native/{linux_native_name}"
DEFAULT_JAVA_EXE={shlex.quote(command.java_executable)}
SESSION_ENV_FILE="${{YSM262_FORGECLIENT_SESSION_ENV:-$ROOT/runtime/forgeclient_session.env}}"
DEFAULT_PID_FILE="$ROOT/runtime/forgeclient_replay.pid"
PRELOAD_MODE=off
USE_GDB=0
DRY_RUN=0
GDB_SCRIPT="$ROOT/gdb/ysm262_antidebug_min.gdb"
PID_FILE="${{YSM262_PID_FILE:-$DEFAULT_PID_FILE}}"
PAUSE_BEFORE_EXEC_MS=""
ALLOW_PTRACE_ANY=0

if [[ -f "$SESSION_ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$SESSION_ENV_FILE"
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --preload-mode)
      PRELOAD_MODE="${{2:-}}"
      shift 2
      ;;
    --gdb)
      USE_GDB=1
      shift
      ;;
    --gdb-script)
      GDB_SCRIPT="${{2:-}}"
      shift 2
      ;;
    --pid-file)
      PID_FILE="${{2:-}}"
      shift 2
      ;;
    --pause-before-exec-ms)
      PAUSE_BEFORE_EXEC_MS="${{2:-}}"
      shift 2
      ;;
    --allow-ptrace-any)
      ALLOW_PTRACE_ANY=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --help|-h)
      printf '%s\\n' \
        "usage: run_forgeclient_replay.sh [--preload-mode off|log|spoof] [--gdb] [--gdb-script /path/to/script.gdb] [--pid-file runtime/forgeclient_replay.pid] [--pause-before-exec-ms N] [--allow-ptrace-any] [--dry-run]" \
        "" \
        "notes:" \
        "  - replays a captured launcher-faithful forgeclient Java command" \
        "  - bundle-local session overrides are loaded from runtime/forgeclient_session.env when present" \
        "  - preload spoof mode reuses the same interposer defaults as the other VM probe launchers" \
        "  - --gdb defaults to the minimal anti-debug preset gdb/ysm262_antidebug_min.gdb" \
        "  - --pid-file defaults to runtime/forgeclient_replay.pid and writes the exact replay PID before exec" \
        "  - --pause-before-exec-ms keeps the pre-exec shell alive with that same PID before it becomes java" \
        "  - --allow-ptrace-any opts the replay target into same-user ptrace attaches under Yama ptrace_scope=1" \
        "  - --dry-run prints the final command after env overrides and exits"
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

JAVA_EXE="${{YSM262_FORGECLIENT_JAVA_EXE:-$DEFAULT_JAVA_EXE}}"
YSM262_FORGECLIENT_USERNAME=${{YSM262_FORGECLIENT_USERNAME:-''}}
YSM262_FORGECLIENT_GAME_DIR=${{YSM262_FORGECLIENT_GAME_DIR:-''}}
YSM262_FORGECLIENT_ASSETS_DIR=${{YSM262_FORGECLIENT_ASSETS_DIR:-''}}
YSM262_FORGECLIENT_ASSET_INDEX=${{YSM262_FORGECLIENT_ASSET_INDEX:-''}}
YSM262_FORGECLIENT_UUID=${{YSM262_FORGECLIENT_UUID:-''}}
YSM262_FORGECLIENT_ACCESS_TOKEN=${{YSM262_FORGECLIENT_ACCESS_TOKEN:-''}}
YSM262_FORGECLIENT_CLIENT_ID=${{YSM262_FORGECLIENT_CLIENT_ID:-''}}
YSM262_FORGECLIENT_XUID=${{YSM262_FORGECLIENT_XUID:-''}}
YSM262_FORGECLIENT_USER_TYPE=${{YSM262_FORGECLIENT_USER_TYPE:-''}}
YSM262_FORGECLIENT_VERSION_TYPE=${{YSM262_FORGECLIENT_VERSION_TYPE:-''}}
YSM262_FORGECLIENT_QUICK_PLAY_PATH=${{YSM262_FORGECLIENT_QUICK_PLAY_PATH:-''}}

if [[ "$PRELOAD_MODE" != "off" ]]; then
  mkdir -p "$BUILD_DIR"
  cc -shared -fPIC -O0 -g "$ROOT/native_tools/ysm262_intercept.c" \\
    -I"$JAVA_HOME_DIR/include" -I"$JAVA_HOME_DIR/include/linux" -pthread -ldl \\
    -o "$BUILD_DIR/libysm262_intercept.so"
  export LD_PRELOAD="$BUILD_DIR/libysm262_intercept.so${{LD_PRELOAD:+:$LD_PRELOAD}}"
  export YSM262_INTERCEPT_LOG="${{YSM262_INTERCEPT_LOG:-$BUILD_DIR/ysm262_intercept.log}}"
  if [[ "$PRELOAD_MODE" == "spoof" ]]; then
    export YSM262_SPOOF_PROC_SELF_EXE="${{YSM262_SPOOF_PROC_SELF_EXE:-$JAVA_EXE}}"
    export YSM262_SPOOF_DLADDR_LIBJVM="${{YSM262_SPOOF_DLADDR_LIBJVM:-$JAVA_HOME_DIR/lib/server/libjvm.so}}"
    export YSM262_SPOOF_DLADDR_JVM_ORIGINS="${{YSM262_SPOOF_DLADDR_JVM_ORIGINS:-1}}"
    export YSM262_SPOOF_PRCTL_VM="1"
    export YSM262_SPOOF_HOSTNAME="${{YSM262_SPOOF_HOSTNAME:-localhost}}"
    export YSM262_SPOOF_AFFINITY_ONECPU="${{YSM262_SPOOF_AFFINITY_ONECPU:-1}}"
  fi
fi

if [[ -n "$PID_FILE" ]]; then
  ALLOW_PTRACE_ANY=1
fi

JAVA_ARGS=(
__YSM262_JVM_ARRAY_LINES__
  {shlex.quote(command.main_class)}
)

GAME_ARGS=(
__YSM262_GAME_ARRAY_LINES__
)

JAVA_ARGS+=("${{GAME_ARGS[@]}}")

if [[ "$DRY_RUN" -eq 1 ]]; then
  printf '%q ' "$JAVA_EXE" "${{JAVA_ARGS[@]}}"
  printf '\\n'
  exit 0
fi

if [[ -n "$PID_FILE" ]]; then
  mkdir -p "$(dirname "$PID_FILE")"
  printf '%s\\n' "$$" > "$PID_FILE"
fi

if [[ -n "$PAUSE_BEFORE_EXEC_MS" ]]; then
  python3 - "$PAUSE_BEFORE_EXEC_MS" <<'PY'
import sys
import time

time.sleep(max(0.0, float(sys.argv[1]) / 1000.0))
PY
fi

if [[ "$USE_GDB" -eq 1 ]]; then
  GDB_ARGS=("-q")
  if [[ -n "$GDB_SCRIPT" ]]; then
    GDB_ARGS+=("-ex" "source $GDB_SCRIPT")
  fi
  exec gdb "${{GDB_ARGS[@]}}" --args "$JAVA_EXE" "${{JAVA_ARGS[@]}}"
fi

if [[ "$ALLOW_PTRACE_ANY" -eq 1 ]]; then
  mkdir -p "$BUILD_DIR"
  cc -O2 -g "$ROOT/native_tools/ysm262_ptrace_exec.c" -o "$BUILD_DIR/ysm262_ptrace_exec"
  if [[ -n "$PID_FILE" ]]; then
    export YSM262_PTRACE_EXEC_STOP="${{YSM262_PTRACE_EXEC_STOP:-1}}"
  fi
  exec "$BUILD_DIR/ysm262_ptrace_exec" "$JAVA_EXE" "${{JAVA_ARGS[@]}}"
fi

exec "$JAVA_EXE" "${{JAVA_ARGS[@]}}"
"""
        )
        .replace("__YSM262_JVM_ARRAY_LINES__", jvm_array_lines)
        .replace("__YSM262_GAME_ARRAY_LINES__", game_array_lines_rendered)
    )
    replay_script_path = scripts_dir / "run_forgeclient_replay.sh"
    replay_script_path.write_text(replay_script, encoding="utf-8")
    os.chmod(replay_script_path, 0o755)

    attach_script = textwrap.dedent(
        """\
#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PID_FILE="${1:-${YSM262_PID_FILE:-$ROOT/runtime/forgeclient_replay.pid}}"
EXTRA_GDB_SCRIPT="${2:-}"

wait_for_pid_file() {
  while [[ ! -s "$PID_FILE" ]]; do
    sleep 0.05
  done
}

process_ready() {
  local pid="$1"
  local cmdline
  [[ -r "/proc/$pid/cmdline" ]] || return 1
  cmdline=$(tr '\0' '\n' < "/proc/$pid/cmdline" 2>/dev/null || true)
  if printf '%s\n' "$cmdline" | grep -Eq 'cpw\\.mods\\.bootstraplauncher\\.BootstrapLauncher|forgeclient|ysm262_ptrace_exec'; then
    return 0
  fi
  local exe
  exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)
  [[ "${exe##*/}" == "java" || "${exe##*/}" == "ysm262_ptrace_exec" ]]
}

wait_for_exec_target() {
  local pid="$1"
  while kill -0 "$pid" 2>/dev/null; do
    if process_ready "$pid"; then
      return 0
    fi
    sleep 0.05
  done
  return 1
}

wait_for_pid_file
PID=$(tr -d '[:space:]' < "$PID_FILE")
if [[ -z "$PID" ]]; then
  echo "pid file is empty: $PID_FILE" >&2
  exit 1
fi
if ! wait_for_exec_target "$PID"; then
  echo "process died before becoming the replay java target: $PID" >&2
  exit 1
fi

GDB_ARGS=(
  -q
  -ex "set pagination off"
  -ex "set confirm off"
  -ex "handle SIGPIPE nostop noprint pass"
  -ex "handle SIGSTOP nostop noprint nopass"
  -ex "handle SIGXCPU nostop noprint pass"
  -ex "handle SIG33 nostop noprint pass"
)
if [[ -n "$EXTRA_GDB_SCRIPT" ]]; then
  GDB_ARGS+=(-ex "source $EXTRA_GDB_SCRIPT")
fi
GDB_ARGS+=(-ex "attach $PID" -ex c -ex c)

exec gdb "${GDB_ARGS[@]}"
"""
    )
    attach_script_path = scripts_dir / "attach_forgeclient_replay_pid.sh"
    attach_script_path.write_text(attach_script, encoding="utf-8")
    os.chmod(attach_script_path, 0o755)

    return {
        "manifest_path": str(manifest_path),
        "session_env_example": str(env_example),
        "session_env": str(env_runtime),
        "replay_script": str(replay_script_path),
        "attach_script": str(attach_script_path),
        "captured_launch_target": command.launch_target,
    }


def _resolve_forge_bootstrap_info(minecraft_root: Path, *, version_id: str) -> ForgeBootstrapInfo:
    _, manifest = _load_version_manifest(minecraft_root, version_id)
    game_args = manifest.get("arguments", {}).get("game", [])
    jvm_args = manifest.get("arguments", {}).get("jvm", [])
    minecraft_version = _extract_argument_value(game_args, "--fml.mcVersion") or version_id.partition("-forge-")[0] or version_id
    forge_version = _extract_argument_value(game_args, "--fml.forgeVersion") or (version_id.partition("-forge-")[2] or None)
    mcp_version = _extract_argument_value(game_args, "--fml.mcpVersion") or DEFAULT_FORGE_MCP_VERSION
    ignore_list = _find_jvm_property(jvm_args, "ignoreList") or DEFAULT_BOOTSTRAP_IGNORE_LIST_TEMPLATE.format(version_id=version_id)
    return ForgeBootstrapInfo(
        main_class=manifest.get("mainClass"),
        minecraft_version=minecraft_version,
        forge_version=forge_version,
        mcp_version=mcp_version,
        ignore_list=ignore_list.replace("${version_name}", version_id),
    )


def _collect_runtime_audit(
    minecraft_root: Path,
    *,
    version_id: str,
    fallback_roots: Sequence[Path] = DEFAULT_FALLBACK_ROOTS,
) -> RuntimeAudit:
    manifests: list[tuple[str, dict[str, Any]]] = []
    current_id = version_id
    seen: set[str] = set()
    bootstrap_info = _resolve_forge_bootstrap_info(minecraft_root, version_id=version_id)
    while current_id and current_id not in seen:
        seen.add(current_id)
        _, manifest = _load_version_manifest(minecraft_root, current_id)
        manifests.append((current_id, manifest))
        current_id = manifest.get("inheritsFrom")

    manifests.reverse()
    entries: list[RuntimeClasspathEntry] = []
    missing: list[dict[str, Any]] = []
    seen_bundle_paths: set[Path] = set()
    main_class = None

    def add_entry(
        *,
        manifest_version_id: str,
        kind: str,
        source_path: Path,
        bundle_path: Path,
        logical_name: str,
    ) -> None:
        if bundle_path in seen_bundle_paths:
            return
        seen_bundle_paths.add(bundle_path)
        entries.append(
            RuntimeClasspathEntry(
                version_id=manifest_version_id,
                kind=kind,
                source_path=source_path,
                bundle_path=bundle_path,
                logical_name=logical_name,
            )
        )

    for manifest_version_id, manifest in manifests:
        main_class = manifest.get("mainClass") or main_class
        for library in manifest.get("libraries", []):
            if not _rules_allow(library):
                continue
            artifact = library.get("downloads", {}).get("artifact")
            if not artifact:
                continue
            relative_path = artifact.get("path")
            if not relative_path:
                continue
            source_path = minecraft_root / "libraries" / relative_path
            source_origin = "minecraft"
            if not source_path.is_file():
                fallback = _find_fallback_artifact(relative_path, fallback_roots)
                if fallback is None:
                    missing.append(
                        {
                            "version_id": manifest_version_id,
                            "kind": "library",
                            "logical_name": library.get("name"),
                            "relative_path": relative_path,
                        }
                    )
                    continue
                source_path = fallback
                source_origin = "fallback"

            bundle_path = Path("runtime") / "libraries" / relative_path
            logical_name = f"{library.get('name')} [{source_origin}]"
            add_entry(
                manifest_version_id=manifest_version_id,
                kind="library",
                source_path=source_path,
                bundle_path=bundle_path,
                logical_name=logical_name,
            )

        version_jar = minecraft_root / "versions" / manifest_version_id / f"{manifest_version_id}.jar"
        if version_jar.is_file():
            bundle_path = Path("runtime") / "versions" / manifest_version_id / version_jar.name
            add_entry(
                manifest_version_id=manifest_version_id,
                kind="version_jar",
                source_path=version_jar,
                bundle_path=bundle_path,
                logical_name=f"{manifest_version_id}.jar [minecraft]",
            )

    forge_artifact_version = version_id.replace("-forge-", "-")
    forge_lib_dir = minecraft_root / "libraries" / "net" / "minecraftforge" / "forge" / forge_artifact_version
    for suffix in ("universal", "client"):
        forge_jar = forge_lib_dir / f"forge-{forge_artifact_version}-{suffix}.jar"
        if forge_jar.is_file():
            add_entry(
                manifest_version_id=version_id,
                kind=f"forge_{suffix}",
                source_path=forge_jar,
                bundle_path=Path("runtime") / "libraries" / "net" / "minecraftforge" / "forge" / forge_artifact_version / forge_jar.name,
                logical_name=f"forge-{forge_artifact_version}-{suffix}.jar [minecraft]",
            )

    for companion in DEFAULT_FORGE_RUNTIME_COMPANIONS:
        companion_jar = (
            minecraft_root
            / "libraries"
            / "net"
            / "minecraftforge"
            / companion
            / forge_artifact_version
            / f"{companion}-{forge_artifact_version}.jar"
        )
        if companion_jar.is_file():
            add_entry(
                manifest_version_id=version_id,
                kind=f"forge_companion_{companion}",
                source_path=companion_jar,
                bundle_path=(
                    Path("runtime")
                    / "libraries"
                    / "net"
                    / "minecraftforge"
                    / companion
                    / forge_artifact_version
                    / companion_jar.name
                ),
                logical_name=f"net.minecraftforge:{companion}:{forge_artifact_version} [minecraft supplemental]",
            )

    if bootstrap_info.mcp_version:
        client_artifact_version = f"{bootstrap_info.minecraft_version}-{bootstrap_info.mcp_version}"
        client_artifact_dir = (
            minecraft_root
            / "libraries"
            / "net"
            / "minecraft"
            / "client"
            / client_artifact_version
        )
        for suffix in DEFAULT_MCP_CLIENT_ARTIFACT_SUFFIXES:
            jar_name = f"client-{client_artifact_version}-{suffix}.jar"
            client_jar = client_artifact_dir / jar_name
            if client_jar.is_file():
                add_entry(
                    manifest_version_id=version_id,
                    kind=f"minecraft_client_{suffix}",
                    source_path=client_jar,
                    bundle_path=(
                        Path("runtime")
                        / "libraries"
                        / "net"
                        / "minecraft"
                        / "client"
                        / client_artifact_version
                        / jar_name
                    ),
                    logical_name=f"net.minecraft:client:{client_artifact_version}:{suffix} [minecraft supplemental]",
                )
            else:
                missing.append(
                    {
                        "version_id": version_id,
                        "kind": f"minecraft_client_{suffix}",
                        "logical_name": f"net.minecraft:client:{client_artifact_version}:{suffix}",
                        "relative_path": str(
                            Path("net") / "minecraft" / "client" / client_artifact_version / jar_name
                        ),
                    }
                )

    return RuntimeAudit(
        minecraft_root=minecraft_root,
        version_id=version_id,
        main_class=main_class,
        minecraft_version=bootstrap_info.minecraft_version,
        forge_version=bootstrap_info.forge_version,
        mcp_version=bootstrap_info.mcp_version,
        entries=tuple(entries),
        missing=tuple(missing),
        searched_version_ids=tuple(version_id for version_id, _ in manifests),
    )


def _write_runtime_bundle(out_dir: Path, audit: RuntimeAudit) -> dict[str, Any]:
    runtime_dir = out_dir / "runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)

    copied: list[str] = []
    for entry in audit.entries:
        target = out_dir / entry.bundle_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(entry.source_path, target)
        copied.append(str(entry.bundle_path))

    classpath_entries = [str(entry.bundle_path) for entry in audit.entries]
    (runtime_dir / "classpath.txt").write_text("\n".join(classpath_entries) + "\n", encoding="utf-8")
    bootstrap_launch_excluded = {
        str(entry.bundle_path)
        for entry in audit.entries
        if entry.kind == "version_jar"
        or entry.kind == "forge_client"
        or entry.kind.startswith("minecraft_client_")
    }
    bootstrap_legacy_entries = [entry for entry in classpath_entries if entry not in bootstrap_launch_excluded]
    (runtime_dir / "bootstrap_legacy_classpath.txt").write_text(
        "\n".join(bootstrap_legacy_entries) + "\n",
        encoding="utf-8",
    )
    report = {
        "minecraft_root": str(audit.minecraft_root),
        "version_id": audit.version_id,
        "searched_version_ids": list(audit.searched_version_ids),
        "main_class": audit.main_class,
        "minecraft_version": audit.minecraft_version,
        "forge_version": audit.forge_version,
        "mcp_version": audit.mcp_version,
        "bootstrap_launch_excluded_entries": sorted(bootstrap_launch_excluded),
        "bootstrap_legacy_classpath_entries": bootstrap_legacy_entries,
        "classpath_entries": [
            {
                "version_id": entry.version_id,
                "kind": entry.kind,
                "logical_name": entry.logical_name,
                "source_path": str(entry.source_path),
                "bundle_path": str(entry.bundle_path),
            }
            for entry in audit.entries
        ],
        "missing": list(audit.missing),
    }
    (runtime_dir / "runtime_audit.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def _find_candidate_jars_for_classes(minecraft_root: Path, class_names: Sequence[str]) -> dict[str, list[str]]:
    search_roots = [minecraft_root / "libraries", minecraft_root / "mods"]
    jar_paths = sorted(
        path
        for root in search_roots
        if root.is_dir()
        for path in root.rglob("*.jar")
        if path.is_file()
    )

    wanted = {name: name.replace(".", "/") + ".class" for name in class_names}
    results: dict[str, list[str]] = {name: [] for name in class_names}
    for jar_path in jar_paths:
        try:
            with zipfile.ZipFile(jar_path) as zf:
                names = set(zf.namelist())
        except zipfile.BadZipFile:
            continue
        for class_name, entry_name in wanted.items():
            if entry_name in names:
                results[class_name].append(str(jar_path))
    return results


def audit_minecraft_runtime(
    minecraft_root: Path,
    *,
    version_id: str,
    fallback_roots: Sequence[Path] = DEFAULT_FALLBACK_ROOTS,
    missing_classes: Sequence[str] = (),
) -> dict[str, Any]:
    audit = _collect_runtime_audit(minecraft_root, version_id=version_id, fallback_roots=fallback_roots)
    result: dict[str, Any] = {
        "minecraft_root": str(audit.minecraft_root),
        "version_id": audit.version_id,
        "searched_version_ids": list(audit.searched_version_ids),
        "main_class": audit.main_class,
        "entry_count": len(audit.entries),
        "missing_count": len(audit.missing),
        "missing": list(audit.missing),
    }
    if missing_classes:
        result["missing_class_candidates"] = _find_candidate_jars_for_classes(minecraft_root, missing_classes)
    return result


def _copy_known_files(
    export_root: Path,
    out_dir: Path,
    *,
    pairs: tuple[tuple[str, str], ...],
    copied: list[str],
) -> None:
    for canonical_name, relpath in pairs:
        src = export_root / relpath
        if not src.is_file():
            continue
        shutil.copy2(src, out_dir / canonical_name)
        copied.append(canonical_name)


def _copy_globbed(src_root: Path, out_dir: Path, pattern: str, copied: list[str]) -> None:
    if not src_root.is_dir():
        return
    for src in sorted(path for path in src_root.glob(pattern) if path.is_file()):
        shutil.copy2(src, out_dir / src.name)
        copied.append(src.name)


def _real_java_executable() -> Path:
    java = shutil.which("java")
    if java is None:
        raise RuntimeError("could not resolve java from PATH")
    return Path(java).resolve()


def _java_home_from_executable(java_executable: Path) -> Path:
    return java_executable.parent.parent


def _replace_with_symlink(target: Path, source: Path) -> None:
    if target.is_symlink() or target.is_file():
        target.unlink()
    elif target.is_dir():
        shutil.rmtree(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(source, target)


def _headed_debug_layout(out_dir: Path) -> HeadedDebugLayout:
    return HeadedDebugLayout(
        root=out_dir,
        game_dir=out_dir / "game",
        trace_dir=out_dir / "trace",
        scripts_dir=out_dir / "scripts",
        native_tools_dir=out_dir / "native_tools",
        bin_dir=out_dir / "bin",
    )


def _prepare_headed_game_dir(layout: HeadedDebugLayout, minecraft_root: Path) -> None:
    layout.root.mkdir(parents=True, exist_ok=True)
    layout.game_dir.mkdir(parents=True, exist_ok=True)
    layout.trace_dir.mkdir(parents=True, exist_ok=True)
    layout.scripts_dir.mkdir(parents=True, exist_ok=True)
    layout.native_tools_dir.mkdir(parents=True, exist_ok=True)
    layout.bin_dir.mkdir(parents=True, exist_ok=True)

    for name in ("logs", "crash-reports", "config", "saves", "screenshots", "defaultconfigs"):
        (layout.game_dir / name).mkdir(parents=True, exist_ok=True)

    for name in ("mods", "assets", "libraries", "runtime", "versions"):
        source = minecraft_root / name
        if source.exists():
            _replace_with_symlink(layout.game_dir / name, source)

    options_src = minecraft_root / "options.txt"
    if options_src.is_file():
        shutil.copy2(options_src, layout.game_dir / "options.txt")


def _copy_headed_host_assets(out_dir: Path) -> list[str]:
    repo_root = Path(__file__).resolve().parents[1]
    vm_debug_dir = repo_root / "vm_debug"
    copied: list[str] = []

    intercept_src = vm_debug_dir / "ysm262_intercept.c"
    if intercept_src.is_file():
        target = out_dir / "native_tools" / intercept_src.name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(intercept_src, target)
        copied.append(str(target.relative_to(out_dir)))

    return copied


def _build_headed_interposer(layout: HeadedDebugLayout) -> Path:
    java_executable = _real_java_executable()
    java_home = _java_home_from_executable(java_executable)
    source = layout.native_tools_dir / "ysm262_intercept.c"
    target = layout.native_tools_dir / "libysm262_intercept.so"
    if not source.is_file():
        raise FileNotFoundError(source)
    subprocess.run(
        [
            "cc",
            "-shared",
            "-fPIC",
            "-O0",
            "-g",
            str(source),
            "-I",
            str(java_home / "include"),
            "-I",
            str(java_home / "include" / "linux"),
            "-pthread",
            "-ldl",
            "-o",
            str(target),
        ],
        check=True,
    )
    return target


def _default_source_profile_id(launcher_profiles: dict[str, Any], version_id: str) -> str | None:
    profiles = launcher_profiles.get("profiles", {})
    if "forge" in profiles:
        return "forge"
    for profile_id, profile in profiles.items():
        if profile.get("lastVersionId") == version_id:
            return profile_id
    return None


def _write_headed_java_wrapper(
    layout: HeadedDebugLayout,
    *,
    real_java: Path,
    interposer_path: Path,
    model_trace: HeadedModelTraceConfig | None = None,
) -> Path:
    java_home = _java_home_from_executable(real_java)
    model_trace = model_trace or HeadedModelTraceConfig()
    default_model_trace = "1" if model_trace.enabled else "0"
    default_model_sample = shlex.quote(model_trace.sample_hint or "")
    default_model_families = shlex.quote(",".join(model_trace.family_filter))
    default_model_export_filter = shlex.quote(model_trace.export_filter)
    wrapper = textwrap.dedent(
        f"""\
        #!/usr/bin/env bash
        set -euo pipefail

        ROOT=$(cd "$(dirname "${{BASH_SOURCE[0]}}")/.." && pwd)
        TRACE_DIR="$ROOT/trace"
        REAL_JAVA="{real_java}"
        INTERPOSER="{interposer_path}"
        JAVA_HOME_DIR="{java_home}"
        DEFAULT_MODEL_TRACE="{default_model_trace}"
        DEFAULT_MODEL_SAMPLE={default_model_sample}
        DEFAULT_MODEL_FAMILIES={default_model_families}
        DEFAULT_MODEL_EXPORT_FILTER={default_model_export_filter}
        DEFAULT_VTABLE_REL="0x4d4140"
        DEFAULT_VTABLE_PATCH_LEN="17"
        DEFAULT_VTABLE_LIMIT="1"

        mkdir -p "$TRACE_DIR"

        {{
          printf 'cwd=%s\\n' "$PWD"
          printf 'real_java=%s\\n' "$REAL_JAVA"
          printf 'arg_count=%s\\n' "$#"
          idx=0
          for arg in "$@"; do
            printf 'argv[%s]=%q\\n' "$idx" "$arg"
            idx=$((idx + 1))
          done
        }} >> "${{YSM262_WRAPPER_ARGV_LOG:-$TRACE_DIR/java_wrapper_argv.log}}"

        env | sort > "${{YSM262_WRAPPER_ENV_LOG:-$TRACE_DIR/java_wrapper_env.log}}"

        export LD_PRELOAD="$INTERPOSER${{LD_PRELOAD:+:$LD_PRELOAD}}"
        export YSM262_INTERCEPT_LOG="${{YSM262_INTERCEPT_LOG:-$TRACE_DIR/ysm262_intercept.log}}"
        export YSM262_SPOOF_PROC_SELF_EXE="${{YSM262_SPOOF_PROC_SELF_EXE:-$REAL_JAVA}}"
        export YSM262_SPOOF_DLADDR_LIBJVM="${{YSM262_SPOOF_DLADDR_LIBJVM:-$JAVA_HOME_DIR/lib/server/libjvm.so}}"
        export YSM262_SPOOF_DLADDR_JVM_ORIGINS="${{YSM262_SPOOF_DLADDR_JVM_ORIGINS:-1}}"
        export YSM262_SPOOF_PRCTL_VM="${{YSM262_SPOOF_PRCTL_VM:-1}}"
        export YSM262_SPOOF_HOSTNAME="${{YSM262_SPOOF_HOSTNAME:-localhost}}"
        export YSM262_SPOOF_AFFINITY_ONECPU="${{YSM262_SPOOF_AFFINITY_ONECPU:-1}}"
        export YSM262_TRACE_JNI_ENV="${{YSM262_TRACE_JNI_ENV:-0}}"
        export YSM262_TRACE_CACHE_IO="${{YSM262_TRACE_CACHE_IO:-1}}"
        export YSM262_TRACE_CACHE_BT="${{YSM262_TRACE_CACHE_BT:-1}}"
        export YSM262_TRACE_CACHE_BT_FILTER="${{YSM262_TRACE_CACHE_BT_FILTER:-custom,server_index,server}}"
        export YSM262_TRACE_CACHE_BT_EVENTS="${{YSM262_TRACE_CACHE_BT_EVENTS:-fopen,openat,read,pread,pread64}}"
        export YSM262_TRACE_CACHE_BT_LIMIT="${{YSM262_TRACE_CACHE_BT_LIMIT:-24}}"
        export YSM262_TRACE_VTABLE_WORDS="${{YSM262_TRACE_VTABLE_WORDS:-4}}"
        export YSM262_TRACE_VTABLE_FIELD_CANDIDATES="${{YSM262_TRACE_VTABLE_FIELD_CANDIDATES:-4}}"
        export YSM262_TRACE_VTABLE_NESTED_WORDS="${{YSM262_TRACE_VTABLE_NESTED_WORDS:-4}}"
        export YSM262_TRACE_CHILD_VTABLE_REL="${{YSM262_TRACE_CHILD_VTABLE_REL:-0xd2b2b0}}"
        export YSM262_TRACE_CHILD_FOLLOW_OFFSET="${{YSM262_TRACE_CHILD_FOLLOW_OFFSET:-0x8090}}"
        export YSM262_TRACE_CHILD_FOLLOW_QWORD_INDEX="${{YSM262_TRACE_CHILD_FOLLOW_QWORD_INDEX:-0}}"
        export YSM262_TRACE_CHILD_FOLLOW_QWORD_DEPTH="${{YSM262_TRACE_CHILD_FOLLOW_QWORD_DEPTH:-3}}"
        export YSM262_TRACE_MODEL="${{YSM262_TRACE_MODEL:-$DEFAULT_MODEL_TRACE}}"
        export YSM262_TRACE_MODEL_SAMPLE="${{YSM262_TRACE_MODEL_SAMPLE:-$DEFAULT_MODEL_SAMPLE}}"
        export YSM262_TRACE_MODEL_FAMILIES="${{YSM262_TRACE_MODEL_FAMILIES:-$DEFAULT_MODEL_FAMILIES}}"
        export YSM262_TRACE_MODEL_EXPORT_FILTER="${{YSM262_TRACE_MODEL_EXPORT_FILTER:-$DEFAULT_MODEL_EXPORT_FILTER}}"
        export YSM262_TRACE_MODEL_REL="${{YSM262_TRACE_MODEL_REL:-0x{model_trace.trace_rel:x}}}"
        export YSM262_TRACE_MODEL_PATCH_LEN="${{YSM262_TRACE_MODEL_PATCH_LEN:-{model_trace.patch_len}}}"
        export YSM262_TRACE_MODEL_LIMIT="${{YSM262_TRACE_MODEL_LIMIT:-{model_trace.budget}}}"
        export YSM262_TRACE_MODEL_SCAN_BYTES="${{YSM262_TRACE_MODEL_SCAN_BYTES:-0x{model_trace.scan_bytes:x}}}"
        export YSM262_TRACE_MODEL_STRING_LIMIT="${{YSM262_TRACE_MODEL_STRING_LIMIT:-{model_trace.string_limit}}}"
        export YSM262_TRACE_MODEL_VECTOR_LIMIT="${{YSM262_TRACE_MODEL_VECTOR_LIMIT:-{model_trace.vector_limit}}}"

        if [[ "$YSM262_TRACE_MODEL" != "0" && "$YSM262_TRACE_MODEL" != "false" ]]; then
          DEFAULT_VTABLE_REL="$YSM262_TRACE_MODEL_REL"
          DEFAULT_VTABLE_PATCH_LEN="$YSM262_TRACE_MODEL_PATCH_LEN"
          DEFAULT_VTABLE_LIMIT="$YSM262_TRACE_MODEL_LIMIT"
        fi
        export YSM262_TRACE_VTABLE_DUMP="${{YSM262_TRACE_VTABLE_DUMP:-1}}"
        export YSM262_TRACE_VTABLE_REL="${{YSM262_TRACE_VTABLE_REL:-$DEFAULT_VTABLE_REL}}"
        export YSM262_TRACE_VTABLE_PATCH_LEN="${{YSM262_TRACE_VTABLE_PATCH_LEN:-$DEFAULT_VTABLE_PATCH_LEN}}"
        export YSM262_TRACE_VTABLE_LIMIT="${{YSM262_TRACE_VTABLE_LIMIT:-$DEFAULT_VTABLE_LIMIT}}"

        exec "$REAL_JAVA" "$@"
        """
    )
    target = layout.bin_dir / "java_wrapper.sh"
    target.write_text(wrapper, encoding="utf-8")
    os.chmod(target, 0o755)
    return target


def _write_headed_profile_payload(
    out_dir: Path,
    *,
    profile_id: str,
    profile_name: str,
    version_id: str,
    game_dir: Path,
    java_wrapper: Path,
    source_profile_id: str | None,
) -> Path:
    payload = {
        "profile_id": profile_id,
        "profile_name": profile_name,
        "version_id": version_id,
        "game_dir": str(game_dir),
        "java_dir": str(java_wrapper),
        "source_profile_id": source_profile_id,
        "icon": "Grass",
        "type": "custom",
    }
    target = out_dir / "launcher_profile_payload.json"
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return target


def _write_headed_profile_installer(out_dir: Path) -> Path:
    scripts_dir = out_dir / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    script = textwrap.dedent(
        """\
        #!/usr/bin/env python3
        from __future__ import annotations

        import argparse
        import json
        import shutil
        from pathlib import Path


        def choose_source_profile(profiles: dict[str, dict], payload: dict, explicit: str | None) -> tuple[str | None, dict]:
            if explicit and explicit in profiles:
                return explicit, dict(profiles[explicit])
            source_from_payload = payload.get("source_profile_id")
            if source_from_payload and source_from_payload in profiles:
                return source_from_payload, dict(profiles[source_from_payload])
            if "forge" in profiles:
                return "forge", dict(profiles["forge"])
            for profile_id, profile in profiles.items():
                if profile.get("lastVersionId") == payload["version_id"]:
                    return profile_id, dict(profile)
            return None, {}


        def main() -> int:
            root = Path(__file__).resolve().parents[1]
            payload = json.loads((root / "launcher_profile_payload.json").read_text(encoding="utf-8"))

            ap = argparse.ArgumentParser(description="Install the staged YSM headed-debug launcher profile.")
            ap.add_argument(
                "--launcher-profiles",
                type=Path,
                default=Path.home() / ".minecraft" / "launcher_profiles.json",
                help="launcher_profiles.json to update",
            )
            ap.add_argument("--profile-id", default=payload["profile_id"], help="profile id to create/update")
            ap.add_argument("--profile-name", default=payload["profile_name"], help="profile display name")
            ap.add_argument("--source-profile-id", help="existing profile id to copy javaArgs/icon defaults from")
            ap.add_argument("--dry-run", action="store_true", help="print the final profile JSON without writing")
            args = ap.parse_args()

            launcher_profiles = args.launcher_profiles
            data = json.loads(launcher_profiles.read_text(encoding="utf-8"))
            profiles = data.setdefault("profiles", {})
            source_profile_id, profile = choose_source_profile(profiles, payload, args.source_profile_id)

            profile.update(
                {
                    "name": args.profile_name,
                    "lastVersionId": payload["version_id"],
                    "gameDir": payload["game_dir"],
                    "javaDir": payload["java_dir"],
                    "type": payload.get("type", "custom"),
                    "icon": profile.get("icon", payload.get("icon", "Grass")),
                }
            )

            if args.dry_run:
                print(json.dumps(profile, indent=2))
                return 0

            backup = launcher_profiles.with_name(launcher_profiles.name + ".ysm262.backup")
            shutil.copy2(launcher_profiles, backup)
            profiles[args.profile_id] = profile
            launcher_profiles.write_text(json.dumps(data, indent=2), encoding="utf-8")
            print(f"updated_profile={args.profile_id}")
            print(f"backup={backup}")
            print(f"source_profile={source_profile_id}")
            return 0


        if __name__ == "__main__":
            raise SystemExit(main())
        """
    )
    target = scripts_dir / "install_launcher_profile.py"
    target.write_text(script, encoding="utf-8")
    os.chmod(target, 0o755)
    return target


def _write_headed_host_readme(
    out_dir: Path,
    *,
    version_id: str,
    minecraft_root: Path,
    profile_name: str,
    model_trace: HeadedModelTraceConfig | None = None,
) -> None:
    model_trace = model_trace or HeadedModelTraceConfig()
    model_trace_notes = ""
    if model_trace.enabled:
        family_text = ", ".join(model_trace.family_filter) if model_trace.family_filter else "(all discovered bone-name candidates)"
        model_trace_notes = textwrap.dedent(
            f"""\
            
            Model trace defaults in this bundle:
            - `YSM262_TRACE_MODEL=1`
            - `YSM262_TRACE_MODEL_SAMPLE={model_trace.sample_hint or '(auto from staged sample path)'}`
            - `YSM262_TRACE_MODEL_FAMILIES={family_text}`
            - `YSM262_TRACE_MODEL_EXPORT_FILTER={model_trace.export_filter}`
            - `YSM262_TRACE_MODEL_REL=0x{model_trace.trace_rel:x}`
            - `YSM262_TRACE_MODEL_PATCH_LEN={model_trace.patch_len}`
            - `YSM262_TRACE_MODEL_LIMIT={model_trace.budget}`
            - `YSM262_TRACE_MODEL_SCAN_BYTES=0x{model_trace.scan_bytes:x}`
            
            Suggested post-run summary:
            - `python3 ysm262_oracle.py summarize-model-trace trace/ysm262_intercept.log --json`
            - if you later obtain a matching snapshot: `python3 ysm262_oracle.py summarize-model-trace trace/ysm262_intercept.log --snapshot-root official_export_snapshot --json`
            """
        )
    text = textwrap.dedent(
        f"""\
        # YSM Headed Host Debug Bundle

        Purpose:
        - compatibility and porting research for Yes Steve Model legacy decoding
        - authentic native/debug tracing against the real Forge client shape
        - not malware development

        This bundle does not try to preserve the synthetic VM-only `err: 56` path.
        It is for running the real local Forge profile under an isolated `gameDir`
        while keeping the launcher-owned runtime roots from `{minecraft_root}`.

        Included:
        - `game/`
        - `bin/java_wrapper.sh`
        - `native_tools/ysm262_intercept.c`
        - `native_tools/libysm262_intercept.so`
        - `launcher_profile_payload.json`
        - `scripts/install_launcher_profile.py`
        - `headed_host_manifest.json`

        Suggested first use:
        1. `python3 scripts/install_launcher_profile.py`
        2. Launch the `{profile_name}` profile from the official launcher.
        3. Inspect:
           - `trace/java_wrapper_argv.log`
           - `trace/java_wrapper_env.log`
           - `trace/ysm262_intercept.log`
           - `game/logs/latest.log`
           - `game/logs/debug.log`

        Important notes:
        - default repo-local runtime-debug root is `ROOT/debug_runtime`; override with `{DEFAULT_DEBUG_RUNTIME_ENV}`
        - the canonical headed-host bundle path is `ROOT/debug_runtime/headed_host_bundle`
        - treat this headed bundle as a corroboration/control lane, not the primary live debugger
        - the primary live-debug path is now the guest-side `stage-vm` bootstrap harness under `gdb`
        - host-side `gdb` is still not the primary tool for this ELF
        - `YSM262_TRACE_JNI_ENV` defaults to `0` in the Java wrapper to preserve the authentic host path
        - if the process later dies with `SIGKILL` plus a `zenity` dialog, treat that as the separate anti-debug branch
        {model_trace_notes}
        """
    )
    (out_dir / "README.md").write_text(text, encoding="utf-8")


def stage_headed_host_bundle(
    out_dir: Path | None,
    *,
    minecraft_root: Path = DEFAULT_MINECRAFT_ROOT,
    version_id: str = DEFAULT_FORGE_VERSION_ID,
    launcher_profiles: Path | None = None,
    profile_id: str = DEFAULT_HEADED_DEBUG_PROFILE_ID,
    profile_name: str = DEFAULT_HEADED_DEBUG_PROFILE_NAME,
    model_trace: HeadedModelTraceConfig | None = None,
) -> Path:
    out_dir = (out_dir or _default_headed_host_out_dir()).resolve()
    launcher_profiles = launcher_profiles or (minecraft_root / "launcher_profiles.json")
    model_trace = model_trace or HeadedModelTraceConfig()
    out_dir.mkdir(parents=True, exist_ok=True)
    layout = _headed_debug_layout(out_dir)
    _prepare_headed_game_dir(layout, minecraft_root)
    copied_assets = _copy_headed_host_assets(out_dir)
    interposer_path = _build_headed_interposer(layout)
    real_java = _real_java_executable()
    java_wrapper = _write_headed_java_wrapper(
        layout,
        real_java=real_java,
        interposer_path=interposer_path,
        model_trace=model_trace,
    )

    source_profile_id = None
    if launcher_profiles.is_file():
        launcher_state = json.loads(launcher_profiles.read_text(encoding="utf-8"))
        source_profile_id = _default_source_profile_id(launcher_state, version_id)

    payload_path = _write_headed_profile_payload(
        out_dir,
        profile_id=profile_id,
        profile_name=profile_name,
        version_id=version_id,
        game_dir=layout.game_dir,
        java_wrapper=java_wrapper,
        source_profile_id=source_profile_id,
    )
    installer_path = _write_headed_profile_installer(out_dir)
    _write_headed_host_readme(
        out_dir,
        version_id=version_id,
        minecraft_root=minecraft_root,
        profile_name=profile_name,
        model_trace=model_trace,
    )

    manifest = {
        "purpose": (
            "Compatibility and porting research for Yes Steve Model legacy decoding. "
            "This headed-host bundle is for benign reverse-engineering and verification, not malware development."
        ),
        "minecraft_root": str(minecraft_root),
        "version_id": version_id,
        "launcher_profiles": str(launcher_profiles),
        "profile_id": profile_id,
        "profile_name": profile_name,
        "source_profile_id": source_profile_id,
        "game_dir": str(layout.game_dir),
        "trace_dir": str(layout.trace_dir),
        "real_java": str(real_java),
        "java_wrapper": str(java_wrapper),
        "interposer": str(interposer_path),
        "payload": str(payload_path),
        "installer": str(installer_path),
        "model_trace": {
            "enabled": model_trace.enabled,
            "sample_hint": model_trace.sample_hint,
            "family_filter": list(model_trace.family_filter),
            "export_filter": model_trace.export_filter,
            "trace_rel": hex(model_trace.trace_rel),
            "patch_len": model_trace.patch_len,
            "budget": model_trace.budget,
            "scan_bytes": hex(model_trace.scan_bytes),
            "string_limit": model_trace.string_limit,
            "vector_limit": model_trace.vector_limit,
        },
        "copied_assets": copied_assets,
        "symlinked_game_entries": sorted(
            path.name
            for path in layout.game_dir.iterdir()
            if path.is_symlink()
        ),
    }
    (out_dir / "headed_host_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return out_dir


def _write_legacy_capture_readme(
    capture: LegacyExportCapture,
    *,
    ysm_path: Path,
    model_id: str,
    suggested_command: str | None,
    source_root: Path | None,
    snapshot_ready: bool,
    model_trace: HeadedModelTraceConfig | None,
    trace_only: bool,
) -> None:
    model_trace = model_trace or HeadedModelTraceConfig()
    status_line = (
        f"- latest canonical snapshot: `{capture.snapshot_root}`"
        if snapshot_ready
        else "- no official export payload detected yet under the raw export root"
    )
    if snapshot_ready:
        verify_line = (
            f"- recommended verifier command after snapshot: `python3 verify_legacy_pair.py {ysm_path} --source-root {source_root} --official-export-root {capture.snapshot_root}`"
            if source_root is not None
            else f"- if you later choose a paired source tree manually: `python3 verify_legacy_pair.py {ysm_path} --source-root <source-tree> --official-export-root {capture.snapshot_root}`"
        )
    else:
        verify_line = "- verifier step is pending until a snapshot or other truth asset exists"
    model_trace_lines = ""
    if model_trace.enabled:
        model_trace_lines = textwrap.dedent(
            f"""\
            - model trace is enabled in the staged Java wrapper
            - sample filter: `{model_trace.sample_hint or ysm_path.name}`
            - export filter: `{model_trace.export_filter}`
            - trace rel: `0x{model_trace.trace_rel:x}`
            - after a run, summarize the trace with:
              `python3 ysm262_oracle.py summarize-model-trace {capture.bundle_root / "trace" / "ysm262_intercept.log"} --family-filter {",".join(model_trace.family_filter) if model_trace.family_filter else "<families>"} --json`
            - if you later obtain a matching snapshot, join it with:
              `python3 ysm262_oracle.py summarize-model-trace {capture.bundle_root / "trace" / "ysm262_intercept.log"} --snapshot-root {capture.snapshot_root} --json`
            """
        )
    in_game_flow = textwrap.dedent(
        f"""\
        In-game flow:
        1. `python3 {capture.bundle_root / "scripts" / "install_launcher_profile.py"}`
        2. Launch the staged profile from the official launcher.
        3. Join a world so YSM ingests the staged `custom/*.ysm` sample.
        4. Quit the game after the sample has clearly loaded.
        5. Inspect `{capture.bundle_root / "trace" / "ysm262_intercept.log"}` and run the trace summarizer.
        """
    )
    if not trace_only:
        command_line = suggested_command or "/ysm export <model_id>"
        in_game_flow = textwrap.dedent(
            f"""\
            In-game flow:
            1. `python3 {capture.bundle_root / "scripts" / "install_launcher_profile.py"}`
            2. Launch the staged profile from the official launcher.
            3. Join a world so YSM ingests the staged `custom/*.ysm` sample.
            4. Run:
               - `{command_line}`
            5. Quit the game, then rerun the same capture command to harvest the export into a canonical snapshot.
            """
        )
    notes = textwrap.dedent(
        """\
        Notes:
        - this capture helper stages the sample and harvests outputs when they exist; it does not try to automate the GUI/client session itself
        """
    )
    if not trace_only:
        notes += textwrap.dedent(
            """\
            - the official command root is `/ysm`
            - the export subcommand shape recovered from the jar is `/ysm export <model_id> [extra]`
            """
        )
    text = textwrap.dedent(
        f"""\
        # Legacy Export Capture

        Purpose:
        - use the real YSM `2.6.2` headed client/native export path as the truth lane for legacy formats
        - not heuristic Python reconstruction

        Sample:
        - source sample: `{ysm_path}`
        - staged custom pack: `{capture.sample_copy}`
        - imported model id: `{model_id}`

        Live paths:
        - headed bundle root: `{capture.bundle_root}`
        - custom input root: `{capture.custom_dir}`
        - raw official export root: `{capture.export_root}`
        {status_line}

        {in_game_flow}
        {notes}
        {model_trace_lines}
        {verify_line}
        """
    )
    (capture.bundle_root / "legacy_export_capture_README.md").write_text(text, encoding="utf-8")


def capture_legacy_export(
    ysm_path: Path,
    *,
    out_dir: Path | None = None,
    minecraft_root: Path = DEFAULT_MINECRAFT_ROOT,
    version_id: str = DEFAULT_FORGE_VERSION_ID,
    launcher_profiles: Path | None = None,
    profile_id: str | None = None,
    profile_name: str | None = None,
    model_id: str | None = None,
    extra: str | None = None,
    export_root: Path | None = None,
    snapshot_dir: Path | None = None,
    keep_existing: bool = False,
    model_trace: HeadedModelTraceConfig | None = None,
    trace_only: bool = False,
) -> LegacyExportCapture:
    ysm_path = ysm_path.resolve()
    if not ysm_path.is_file():
        raise FileNotFoundError(ysm_path)

    out_dir = (out_dir or _default_capture_out_dir(ysm_path)).resolve()
    model_trace = model_trace or HeadedModelTraceConfig()
    default_profile_id, default_profile_name = _default_capture_profile_identity(
        ysm_path,
        out_dir=out_dir,
        model_trace=model_trace,
    )
    profile_id = profile_id or default_profile_id
    profile_name = profile_name or default_profile_name
    model_id = model_id or ysm_path.stem
    if model_trace.enabled and model_trace.sample_hint is None:
        model_trace = HeadedModelTraceConfig(
            enabled=True,
            sample_hint=ysm_path.name,
            family_filter=model_trace.family_filter,
            export_filter=model_trace.export_filter,
            trace_rel=model_trace.trace_rel,
            patch_len=model_trace.patch_len,
            budget=model_trace.budget,
            scan_bytes=model_trace.scan_bytes,
            string_limit=model_trace.string_limit,
            vector_limit=model_trace.vector_limit,
        )
    launcher_profiles = launcher_profiles or (minecraft_root / "launcher_profiles.json")

    stage_headed_host_bundle(
        out_dir,
        minecraft_root=minecraft_root,
        version_id=version_id,
        launcher_profiles=launcher_profiles,
        profile_id=profile_id,
        profile_name=profile_name,
        model_trace=model_trace,
    )

    layout = _headed_debug_layout(out_dir)
    ysm_root = layout.game_dir / "config" / "yes_steve_model"
    custom_dir = ysm_root / "custom"
    export_root = (export_root or (ysm_root / "export")).resolve()
    snapshot_dir = (snapshot_dir or (out_dir / "official_export_snapshot")).resolve()
    manifest_path = out_dir / "legacy_export_capture.json"
    capture = LegacyExportCapture(
        bundle_root=out_dir,
        custom_dir=custom_dir,
        export_root=export_root,
        sample_copy=custom_dir / ysm_path.name,
        snapshot_root=snapshot_dir,
        manifest_path=manifest_path,
    )

    custom_dir.mkdir(parents=True, exist_ok=True)
    export_root.mkdir(parents=True, exist_ok=True)
    existing_candidates = _candidate_export_roots(export_root)
    previous_manifest: dict[str, Any] | None = None
    if manifest_path.is_file():
        try:
            previous_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            previous_manifest = None
    same_sample_as_previous = (
        previous_manifest is not None
        and previous_manifest.get("ysm_path") == str(ysm_path)
        and previous_manifest.get("model_id") == model_id
    )
    reuse_existing_export = bool(existing_candidates) and (keep_existing or same_sample_as_previous)
    if not keep_existing and not reuse_existing_export:
        _clear_dir_children(custom_dir)
        _clear_dir_children(export_root)
        if snapshot_dir.exists():
            shutil.rmtree(snapshot_dir)
    shutil.copy2(ysm_path, capture.sample_copy)

    candidates = existing_candidates if reuse_existing_export else _candidate_export_roots(export_root)
    selected_export_root = _select_export_root(candidates, model_id=model_id)
    snapshot_created = False
    if selected_export_root is not None:
        snapshot_official_export(
            selected_export_root,
            out_dir=snapshot_dir,
            ysm_path=ysm_path,
        )
        snapshot_created = True

    baseline = probe_ysm262_official()
    source_root, source_match_count, source_asset_count = find_best_source_oracle(ysm_path)
    suggested_command = None
    if not trace_only:
        suggested_command = f"/ysm export {model_id}"
        if extra:
            suggested_command = f"{suggested_command} {extra}"

    verify_command = None
    if snapshot_created:
        base = f"python3 verify_legacy_pair.py {ysm_path}"
        if source_root is not None:
            verify_command = f"{base} --source-root {source_root} --official-export-root {snapshot_dir}"
        else:
            verify_command = f"{base} --source-root <source-tree> --official-export-root {snapshot_dir}"

    manifest = {
        "purpose": (
            "Compatibility and porting research for Yes Steve Model legacy decoding. "
            "This capture tracks the real headed-client/native export path, not heuristic Python reconstruction."
        ),
        "status": (
            "snapshot_ready"
            if snapshot_created
            else ("staged_waiting_for_trace" if trace_only else "staged_waiting_for_export")
        ),
        "ysm_path": str(ysm_path),
        "property_name": _read_property_name(ysm_path),
        "codec_format": _read_property_format(ysm_path),
        "model_id": model_id,
        "extra": extra,
        "bundle_root": str(out_dir),
        "profile_id": profile_id,
        "profile_name": profile_name,
        "game_dir": str(layout.game_dir),
        "custom_dir": str(custom_dir),
        "sample_copy": str(capture.sample_copy),
        "sample_sha256": _hash_file(capture.sample_copy),
        "raw_export_root": str(export_root),
        "export_candidates": [str(path) for path in candidates],
        "selected_export_root": str(selected_export_root) if selected_export_root is not None else None,
        "official_snapshot_root": str(snapshot_dir) if snapshot_created else None,
        "official_jar": str(baseline.jar_path) if baseline is not None else None,
        "official_jar_sha256": baseline.jar_sha256 if baseline is not None else None,
        "official_native_entries": list(baseline.native_entries) if baseline is not None else [],
        "official_native_sha256": list(baseline.native_sha256) if baseline is not None else [],
        "trace_only": trace_only,
        "suggested_export_command": suggested_command,
        "source_root": str(source_root) if source_root is not None else None,
        "source_match_count": source_match_count,
        "source_asset_count": source_asset_count,
        "verify_command": verify_command,
        "model_trace": {
            "enabled": model_trace.enabled,
            "sample_hint": model_trace.sample_hint,
            "family_filter": list(model_trace.family_filter),
            "export_filter": model_trace.export_filter,
            "trace_rel": hex(model_trace.trace_rel),
            "patch_len": model_trace.patch_len,
            "budget": model_trace.budget,
            "scan_bytes": hex(model_trace.scan_bytes),
            "string_limit": model_trace.string_limit,
            "vector_limit": model_trace.vector_limit,
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    _write_legacy_capture_readme(
        capture,
        ysm_path=ysm_path,
        model_id=model_id,
        suggested_command=suggested_command,
        source_root=source_root,
        snapshot_ready=snapshot_created,
        model_trace=model_trace,
        trace_only=trace_only,
    )
    return capture


def _trace_family_matches(name: str, family_filter: Sequence[str]) -> bool:
    if not family_filter:
        return True
    lower_name = name.lower()
    for token in family_filter:
        lowered = token.lower()
        if lowered in lower_name or lower_name in lowered:
            return True
    return False


def _load_snapshot_bones(snapshot_root: Path, model_name: str) -> list[dict[str, Any]]:
    layout = detect_export_layout(snapshot_root)
    rel_path = next((rel for canonical, rel in layout.model_pairs if canonical == model_name), model_name)
    path = layout.root / rel_path
    if not path.is_file():
        return []
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        return []
    geometry = obj.get("minecraft:geometry")
    if not isinstance(geometry, list):
        return []
    for item in geometry:
        if not isinstance(item, dict):
            continue
        bones = item.get("bones")
        if isinstance(bones, list):
            return [bone for bone in bones if isinstance(bone, dict)]
    return []


def summarize_model_trace(
    intercept_log: Path,
    *,
    snapshot_root: Path | None = None,
    family_filter: Sequence[str] = tuple(),
    model_name: str = "main.json",
) -> dict[str, Any]:
    intercept_log = intercept_log.resolve()
    if not intercept_log.is_file():
        raise FileNotFoundError(intercept_log)

    summary: dict[str, Any] = {
        "intercept_log": str(intercept_log),
        "snapshot_root": str(snapshot_root.resolve()) if snapshot_root is not None else None,
        "model_name": model_name,
        "family_filter": list(family_filter),
        "events": [],
        "objects": {},
        "bone_summaries": [],
        "candidate_hook_rels": [],
    }

    object_hits: dict[str, dict[str, Any]] = {}
    lines = intercept_log.read_text(encoding="utf-8", errors="replace").splitlines()
    line_re = re.compile(r"^\[ysm262-intercept\]\s+model_trace\s+(\w+)\s+(.*)$")
    event_re = re.compile(r"^\[ysm262-intercept\]\s+model_trace\s+event=([^ ]+)\s+(.*)$")
    candidate_rels: dict[int, int] = {}
    event_indexes: list[int] = []
    for idx, raw_line in enumerate(lines):
        stripped = raw_line.strip()
        event_match = event_re.match(stripped)
        if event_match is not None:
            payload = f"event={event_match.group(1)} {event_match.group(2)}".strip()
            summary["events"].append(payload)
            event_indexes.append(idx)
            continue
        match = line_re.match(stripped)
        if match is None:
            continue
        kind = match.group(1)
        payload = match.group(2)
        if kind == "event":
            summary["events"].append(payload)
            event_indexes.append(idx)
            continue
        label_match = re.search(r"label=([^ ]+)", payload)
        if label_match is None:
            continue
        label = label_match.group(1)
        entry = object_hits.setdefault(label, {"strings": [], "ptr_strings": [], "float3": [], "object": None})
        if kind == "object":
            entry["object"] = payload
        elif kind == "string":
            entry["strings"].append(payload)
        elif kind == "ptr_string":
            entry["ptr_strings"].append(payload)
        elif kind == "float3":
            entry["float3"].append(payload)

    summary["objects"] = object_hits

    for idx in event_indexes:
        window = lines[max(0, idx - 25) : min(len(lines), idx + 45)]
        for line in window:
            if "libysm-core" not in line:
                continue
            if " caller=" not in line and " bt[" not in line:
                continue
            match = re.search(r"rel=0x([0-9a-fA-F]+)", line)
            if match is None:
                continue
            rel = int(match.group(1), 16)
            candidate_rels[rel] = candidate_rels.get(rel, 0) + 1
    summary["candidate_hook_rels"] = [
        {"rel": hex(rel), "hits": hits}
        for rel, hits in sorted(candidate_rels.items(), key=lambda item: (-item[1], item[0]))
    ]

    if snapshot_root is not None:
        bones = _load_snapshot_bones(snapshot_root.resolve(), model_name)
        for bone in bones:
            name = str(bone.get("name", ""))
            if not name or not _trace_family_matches(name, family_filter):
                continue
            matching_labels = []
            for label, payload in object_hits.items():
                observed_names = " ".join(payload["strings"] + payload["ptr_strings"])
                if name in observed_names:
                    matching_labels.append(label)
            summary["bone_summaries"].append(
                {
                    "name": name,
                    "parent": bone.get("parent"),
                    "pivot": bone.get("pivot"),
                    "cube_count": len(bone.get("cubes", [])) if isinstance(bone.get("cubes"), list) else 0,
                    "matching_trace_labels": matching_labels,
                }
            )

    return summary


def snapshot_official_export(
    export_root: Path,
    *,
    out_dir: Path | None = None,
    ysm_path: Path | None = None,
    official_jar: Path | None = None,
) -> Path:
    export_root = export_root.resolve()
    if not export_root.exists():
        raise FileNotFoundError(export_root)

    if out_dir is None:
        stem = ysm_path.stem if ysm_path is not None else export_root.name
        out_dir = export_root.parent / f"{stem}_official_export_snapshot"
    out_dir.mkdir(parents=True, exist_ok=True)
    _clear_known_output_dir(
        out_dir,
        (
            "*.json",
            "*.png",
            "*.ogg",
            "official_export_snapshot.json",
        ),
    )

    layout = detect_export_layout(export_root)
    copied: list[str] = []
    _copy_known_files(export_root, out_dir, pairs=layout.model_pairs, copied=copied)
    _copy_known_files(export_root, out_dir, pairs=layout.animation_pairs, copied=copied)
    _copy_globbed(layout.texture_root, out_dir, PNG_GLOB, copied)
    _copy_globbed(layout.sound_root, out_dir, SOUND_GLOB, copied)

    baseline = probe_ysm262_official(official_jar)
    manifest = {
        "purpose": (
            "Compatibility and porting research for Yes Steve Model legacy 9/15 decoding. "
            "This snapshot is for benign reverse-engineering and verification, not malware development."
        ),
        "export_root": str(export_root),
        "snapshot_root": str(out_dir),
        "ysm_path": str(ysm_path) if ysm_path is not None else None,
        "codec_format": _read_property_format(ysm_path) if ysm_path is not None else None,
        "official_jar": str(baseline.jar_path) if baseline is not None else None,
        "official_jar_sha256": baseline.jar_sha256 if baseline is not None else None,
        "official_native_entries": list(baseline.native_entries) if baseline is not None else [],
        "official_native_sha256": list(baseline.native_sha256) if baseline is not None else [],
        "official_loader_classes": list(baseline.loader_classes) if baseline is not None else [],
        "official_export_classes": list(baseline.export_classes) if baseline is not None else [],
        "copied_files": copied,
    }
    (out_dir / "official_export_snapshot.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return out_dir


def _write_vm_bundle_readme(
    out_dir: Path,
    *,
    jar_name: str,
    linux_native_name: str | None,
    sample_paths: Sequence[Path],
    launcher_replay: dict[str, Any] | None = None,
) -> None:
    samples_rendered = "\n".join(f"- `{path}`" for path in sample_paths) if sample_paths else "- none staged"
    java_run = (
        "gdb --args java -cp build YsmNativeStartupGateProbe "
        f"--jar official/{jar_name} --lib native/{linux_native_name} --pause-before-call-ms 3000"
        if linux_native_name is not None
        else "gdb --args java -cp build YsmNativeStartupGateProbe --jar official/<jar> --lib native/<libysm-core.so>"
    )
    replay_contents = ""
    replay_steps = ""
    if launcher_replay:
        replay_contents = textwrap.dedent(
            """\
            - `runtime/forgeclient_replay_manifest.json`
            - `runtime/forgeclient_session.env`
            - `runtime/forgeclient_session.env.example`
            - `scripts/run_forgeclient_replay.sh`
            - `scripts/attach_forgeclient_replay_pid.sh`
            """
        )
        replay_steps = textwrap.dedent(
            """\

            Launcher-faithful replay lane:
            1. `./scripts/run_forgeclient_replay.sh --dry-run`
            2. confirm the rendered command still targets `forgeclient`
            3. `./scripts/run_forgeclient_replay.sh --preload-mode spoof`
            4. if `gdb --args` is unstable on this host, use exact-PID attach instead:
               - terminal A: `./scripts/run_forgeclient_replay.sh --preload-mode spoof --pid-file runtime/forgeclient_replay.pid --pause-before-exec-ms 5000`
               - terminal B: `./scripts/attach_forgeclient_replay_pid.sh runtime/forgeclient_replay.pid`
            """
        )
    text = textwrap.dedent(
        f"""\
        # YSM 2.6.2 VM Bundle

        Purpose:
        - compatibility and porting research for legacy Yes Steve Model decoding
        - helping macOS players and forward-porting the mod
        - not malware development

        Suggested stack:
        - root-managed `qemu/libvirt`
        - Linux guest
        - `gdb`, `java`, `javac`, `jar`, `javap`

        QEMU/libvirt notes:
        - prefer snapshots/checkpoints before each debugging pass
        - disable guest-agent or tools-driven time synchronization where possible
        - avoid relying on VMware-specific keys like `tools.syncTime`; use the QEMU/libvirt equivalents on the host and in the guest config
        - use QEMU gdbstub or in-guest `gdb` as needed; do not assume a direct equivalent for every VMware anti-debug option

        Included samples:
        {samples_rendered}

        Bundle contents:
        - `official/{jar_name}`
        - `native/`
        - `runtime/classpath.txt`
        - `runtime/bootstrap_legacy_classpath.txt`
        - `runtime/runtime_audit.json`
        - `src/NativeLibraryLoadProbe.java`
        - `src/YsmNativeStartupGateProbe.java`
        - `src/YsmBootstrapProbeLaunchHandler.java`
        - `src/YsmBootstrapProbeMain.java`
        - `bootstrap_probe_resources/META-INF/services/cpw.mods.modlauncher.api.ILaunchHandlerService`
        - `native_tools/ysm262_dlopen_probe.c`
        - `native_tools/ysm262_jni_probe.c`
        - `native_tools/ysm262_intercept.c`
        - `stubs/src/`
        - `scripts/run_startup_gate_probe.sh`
        - `scripts/run_jni_probe.sh`
        - `scripts/run_bootstrap_probe.sh`
        - `scripts/native_antidebug_probe.py`
        - `scripts/ghidra_find_antidebug_refs.py`
        - `scripts/ghidra_recover_guard_mechanics.py`
        - `scripts/ghidra_dump_targets.py`
        - `scripts/attach_forgeclient_replay_pid.sh`
        - `gdb/ysm262_jni_bootstrap.gdb`
        - `gdb/ysm262_err56_trace.gdb`
        - `gdb/ysm262_startup_gate.gdb`
        - `gdb/ysm262_antidebug_min.gdb`
        - `gdb/ysm262_antidebug_route_trace.gdb`
        - `native_bundle_manifest.json`
        {replay_contents.rstrip()}

        Suggested first runtime checks inside the guest:
        1. `cat runtime/runtime_audit.json`
        2. `./scripts/run_bootstrap_probe.sh --phase scan`
        3. `./scripts/run_bootstrap_probe.sh --phase mc_bootstrap`
        4. `YSM262_TRACE_JNI_ENV=0 ./scripts/run_bootstrap_probe.sh --phase gather --invoke-native startup-gate --preload-mode spoof`
        5. `./scripts/run_jni_probe.sh --with-stubs --preload-mode spoof`

        Current primary live-debug lane:
        1. `cd <bundle-dir>`
        2. `YSM262_TRACE_JNI_ENV=0 ./scripts/run_bootstrap_probe.sh --phase gather --invoke-native startup-gate --preload-mode spoof`
        3. confirm the non-GDB control still reaches `err: 56`
        4. `YSM262_TRACE_JNI_ENV=0 ./scripts/run_bootstrap_probe.sh --gdb --phase gather --invoke-native startup-gate --preload-mode spoof --pause-before-native-call-ms 5000`
        5. inside gdb, the default preset auto-loads: `gdb/ysm262_err56_trace.gdb`
        6. let `JNI_OnLoad` install the absolute native breakpoints, then inspect the first `FUN_00516260` stop
        7. only fall back to the direct Java probe if the bootstrap path stops reproducing `err: 56`: `{java_run}`

        Separate anti-debug lane:
        1. `python3 scripts/native_antidebug_probe.py`
        2. confirm the bundle-local interposer is fresh:
           - `rg 'YSM262_TRACE_ANTIDEBUG|system-inline|kill-inline' native_tools/ysm262_intercept.c`
        3. run the Ghidra helpers inside the persistent project and read the repo-local reports:
           - `scripts/ghidra_find_antidebug_refs.py ../ghidra/reports/ghidra_antidebug_refs_report.txt`
           - `scripts/ghidra_recover_guard_mechanics.py ../ghidra/reports/ghidra_guard_mechanics_report.txt`
        4. use launcher-faithful replay without GDB first:
           - `YSM262_TRACE_ANTIDEBUG=1 ./scripts/run_forgeclient_replay.sh --preload-mode spoof`
        5. for debugger-triggered reproduction, prefer the minimal anti-debug preset:
           - `YSM262_TRACE_ANTIDEBUG=1 ./scripts/run_forgeclient_replay.sh --gdb --gdb-script gdb/ysm262_antidebug_min.gdb --preload-mode spoof`
        6. if `gdb --args` is unstable, use exact-PID attach instead of `--gdb`:
           - terminal A: `YSM262_TRACE_ANTIDEBUG=1 ./scripts/run_forgeclient_replay.sh --preload-mode spoof --pid-file runtime/forgeclient_replay.pid --pause-before-exec-ms 5000`
           - terminal B: `./scripts/attach_forgeclient_replay_pid.sh runtime/forgeclient_replay.pid`
        7. for route-mapping after the wrapper soup is understood, use the focused anti-debug route preset:
           - `YSM262_TRACE_ANTIDEBUG=1 ./scripts/run_forgeclient_replay.sh --gdb --gdb-script gdb/ysm262_antidebug_route_trace.gdb --preload-mode spoof`
           - or on the attach lane: `./scripts/attach_forgeclient_replay_pid.sh runtime/forgeclient_replay.pid gdb/ysm262_antidebug_route_trace.gdb`
           - it traces `FUN_010d4554`, `FUN_0123d0c1`, the `014ca8e5/014ca942` response branch, and the poison/system/kill terminals
           - if you want the GDB-side route output saved, launch with `YSM262_GDB_ROUTE_LOG=runtime/route_trace.gdb.log`
        8. if needed, simulate the first debugger hypothesis without GDB:
           - `YSM262_TRACE_ANTIDEBUG=1 YSM262_SIMULATE_PTRACE_TRACEME_EPERM=1 ./scripts/run_forgeclient_replay.sh --preload-mode spoof`
        9. once the caller rel is known, suppress only that caller:
           - `YSM262_SPOOF_ANTIDEBUG_ACTION=suppress`
           - `YSM262_SPOOF_ANTIDEBUG_CALLER_RELS=<hex,...>`

        Current verdict:
        - default repo-local runtime-debug root is `ROOT/debug_runtime`; override with `{DEFAULT_DEBUG_RUNTIME_ENV}`
        - the canonical replay bundle path is `ROOT/debug_runtime/vm_bundle_guest_gdb_use_case`
        - the canonical launcher command capture path is `ROOT/debug_runtime/launcher/forgeclient_command_use_case.txt`
        - the persistent Ghidra project and reports live under `ROOT/debug_runtime/ghidra/`
        - use this guest-side bootstrap + spoof + gdb lane as the primary dynamic debugger
        - use headed-host `0x4d4140` tracing only as a control/corroboration lane
        - do not spend time on new headed-host direct rel retargets unless guest-side resolver work is blocked
        {replay_steps.rstrip()}
        """
    )
    (out_dir / "README.md").write_text(text, encoding="utf-8")


def _write_load_probe(out_dir: Path) -> None:
    src_dir = out_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    source = textwrap.dedent(
        """\
        public final class NativeLibraryLoadProbe {
            public static void main(String[] args) {
                if (args.length != 1) {
                    System.err.println("usage: java NativeLibraryLoadProbe /absolute/path/to/libysm-core.so");
                    System.exit(2);
                }
                try {
                    System.load(args[0]);
                    System.out.println("load_ok");
                } catch (Throwable t) {
                    t.printStackTrace(System.err);
                    System.exit(1);
                }
            }
        }
        """
    )
    (src_dir / "NativeLibraryLoadProbe.java").write_text(source, encoding="utf-8")


def _default_linux_native_name(native_entries: Sequence[str]) -> str | None:
    for entry in native_entries:
        name = Path(entry).name
        if name.endswith(".so"):
            return name
    return Path(native_entries[0]).name if native_entries else None


def _write_startup_gate_launcher(out_dir: Path, *, jar_name: str, linux_native_name: str | None) -> None:
    if linux_native_name is None:
        return
    scripts_dir = out_dir / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    launcher = textwrap.dedent(
        f"""\
        #!/usr/bin/env bash
        set -euo pipefail

        ROOT=$(cd "$(dirname "${{BASH_SOURCE[0]}}")/.." && pwd)
        BUILD_DIR="$ROOT/build"
        SRC="$ROOT/src/YsmNativeStartupGateProbe.java"
        JAR="$ROOT/official/{jar_name}"
        LIB="$ROOT/native/{linux_native_name}"

        mkdir -p "$BUILD_DIR"
        javac -d "$BUILD_DIR" "$SRC"
        exec java -cp "$BUILD_DIR" YsmNativeStartupGateProbe --jar "$JAR" --lib "$LIB" "$@"
        """
    )
    target = scripts_dir / "run_startup_gate_probe.sh"
    target.write_text(launcher, encoding="utf-8")
    os.chmod(target, 0o755)


def _write_jni_probe_launcher(out_dir: Path, *, jar_name: str, linux_native_name: str | None) -> None:
    if linux_native_name is None:
        return
    scripts_dir = out_dir / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    launcher = textwrap.dedent(
        f"""\
        #!/usr/bin/env bash
        set -euo pipefail

        ROOT=$(cd "$(dirname "${{BASH_SOURCE[0]}}")/.." && pwd)
        BUILD_DIR="$ROOT/build/native"
        LIB="$ROOT/native/{linux_native_name}"
        OFFICIAL_JAR="$ROOT/official/{jar_name}"
        STUB_CLASSES="$ROOT/build/stubs"
        STUB_JAR="$ROOT/build/ysm262_vm_stubs.jar"
        REAL_JAVA_EXE=$(readlink -f "$(command -v java)")
        JAVA_HOME_DIR=$(dirname "$(dirname "$REAL_JAVA_EXE")")
        export LD_LIBRARY_PATH="$JAVA_HOME_DIR/lib/server${{LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}}"

        WITH_STUBS=0
        PRELOAD_MODE=off
        EXTRA_CP=()

        while [[ $# -gt 0 ]]; do
          case "$1" in
            --with-stubs)
              WITH_STUBS=1
              shift
              ;;
            --preload-mode)
              PRELOAD_MODE="${{2:-}}"
              shift 2
              ;;
            --classpath-append)
              EXTRA_CP+=("${{2:-}}")
              shift 2
              ;;
            --help|-h)
              cat <<'EOF'
        usage: run_jni_probe.sh [--with-stubs] [--preload-mode off|log|spoof] [--classpath-append /path/to/jar]

        notes:
          - spoof mode defaults YSM262_SPOOF_PROC_SELF_EXE to the resolved real java launcher
          - spoof mode also defaults hostname to localhost and affinity to cpu0-only to keep the native path stable
          - spoof mode also defaults dladdr JVM-origin spoofing to $JAVA_HOME_DIR/lib/server/libjvm.so
          - override YSM262_SPOOF_PROC_SELF_EXE explicitly if the VM guest should spoof a different launcher path
        EOF
              exit 0
              ;;
            *)
              echo "unknown argument: $1" >&2
              exit 2
              ;;
          esac
        done

        mkdir -p "$BUILD_DIR"
        cc -O0 -g "$ROOT/native_tools/ysm262_jni_probe.c" \
          -I"$JAVA_HOME_DIR/include" -I"$JAVA_HOME_DIR/include/linux" \
          -L"$JAVA_HOME_DIR/lib/server" -ljvm -ldl \
          -o "$BUILD_DIR/ysm262_jni_probe"
        cc -shared -fPIC -O0 -g "$ROOT/native_tools/ysm262_intercept.c" \
          -I"$JAVA_HOME_DIR/include" -I"$JAVA_HOME_DIR/include/linux" -pthread -ldl \
          -o "$BUILD_DIR/libysm262_intercept.so"

        CP="$OFFICIAL_JAR"
        while IFS= read -r rel; do
          [[ -z "$rel" ]] && continue
          CP="$CP:$ROOT/$rel"
        done < "$ROOT/runtime/classpath.txt"

        if [[ "$WITH_STUBS" -eq 1 ]]; then
          rm -rf "$STUB_CLASSES"
          mkdir -p "$STUB_CLASSES"
          find "$ROOT/stubs/src" -name '*.java' -print0 | xargs -0 javac -d "$STUB_CLASSES"
          jar --create --file "$STUB_JAR" -C "$STUB_CLASSES" .
          CP="$CP:$STUB_JAR"
        fi

        for extra in "${{EXTRA_CP[@]}}"; do
          CP="$CP:$extra"
        done

        if [[ "$PRELOAD_MODE" != "off" ]]; then
          export LD_PRELOAD="$BUILD_DIR/libysm262_intercept.so${{LD_PRELOAD:+:$LD_PRELOAD}}"
          export YSM262_INTERCEPT_LOG="${{YSM262_INTERCEPT_LOG:-$BUILD_DIR/ysm262_intercept.log}}"
          if [[ "$PRELOAD_MODE" == "spoof" ]]; then
            export YSM262_SPOOF_PROC_SELF_EXE="${{YSM262_SPOOF_PROC_SELF_EXE:-$REAL_JAVA_EXE}}"
            export YSM262_SPOOF_DLADDR_LIBJVM="${{YSM262_SPOOF_DLADDR_LIBJVM:-$JAVA_HOME_DIR/lib/server/libjvm.so}}"
            export YSM262_SPOOF_DLADDR_JVM_ORIGINS="${{YSM262_SPOOF_DLADDR_JVM_ORIGINS:-1}}"
            export YSM262_SPOOF_PRCTL_VM="1"
            export YSM262_SPOOF_HOSTNAME="${{YSM262_SPOOF_HOSTNAME:-localhost}}"
            export YSM262_SPOOF_AFFINITY_ONECPU="${{YSM262_SPOOF_AFFINITY_ONECPU:-1}}"
            export YSM262_TRACE_JNI_ENV="${{YSM262_TRACE_JNI_ENV:-1}}"
          fi
        fi

        exec "$BUILD_DIR/ysm262_jni_probe" "$LIB" "$CP"
        """
    )
    target = scripts_dir / "run_jni_probe.sh"
    target.write_text(launcher, encoding="utf-8")
    os.chmod(target, 0o755)


def _write_bootstrap_probe_launcher(
    out_dir: Path,
    *,
    jar_name: str,
    linux_native_name: str | None,
    version_id: str,
    bootstrap_info: ForgeBootstrapInfo,
) -> None:
    if linux_native_name is None:
        return
    scripts_dir = out_dir / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    launcher_main_class = bootstrap_info.main_class or DEFAULT_BOOTSTRAP_MAIN_CLASS
    forge_version = bootstrap_info.forge_version or (version_id.partition("-forge-")[2] or version_id)
    mcp_version = bootstrap_info.mcp_version or DEFAULT_FORGE_MCP_VERSION
    launcher = textwrap.dedent(
        f"""\
        #!/usr/bin/env bash
        set -euo pipefail

        ROOT=$(cd "$(dirname "${{BASH_SOURCE[0]}}")/.." && pwd)
        BUILD_DIR="$ROOT/build/bootstrap_probe"
        CLASS_DIR="$BUILD_DIR/classes"
        PROBE_JAR="$BUILD_DIR/ysm262_bootstrap_probe.jar"
        OFFICIAL_JAR="$ROOT/official/{jar_name}"
        NATIVE_LIB="$ROOT/native/{linux_native_name}"
        REAL_JAVA_EXE=$(readlink -f "$(command -v java)")
        JAVA_HOME_DIR=$(dirname "$(dirname "$REAL_JAVA_EXE")")
        PROBE_CP_FILE="$ROOT/runtime/bootstrap_legacy_classpath.txt"
        COMPILE_CP_FILE="$ROOT/runtime/classpath.txt"
        RESOURCE_DIR="$ROOT/bootstrap_probe_resources"
        LAUNCHER_MAIN_CLASS="{launcher_main_class}"
        DEFAULT_PHASE="scan"
        INVOKE_NATIVE="none"
        PRELOAD_MODE=off
        PAUSE_BEFORE_NATIVE_LOAD_MS=""
        PAUSE_BEFORE_NATIVE_CALL_MS=""
        USE_GDB=0
        GDB_SCRIPT="$ROOT/gdb/ysm262_err56_trace.gdb"
        EXTRA_ARGS=()

        render_classpath() {{
          local file="$1"
          local cp=""
          while IFS= read -r rel; do
            [[ -z "$rel" ]] && continue
            if [[ -z "$cp" ]]; then
              cp="$ROOT/$rel"
            else
              cp="$cp:$ROOT/$rel"
            fi
          done < "$file"
          printf '%s' "$cp"
        }}

        collect_module_path() {{
          local file="$1"
          local mp=""
          while IFS= read -r rel; do
            [[ -z "$rel" ]] && continue
            local name="${{rel##*/}}"
            case "$name" in
              bootstraplauncher-*.jar|securejarhandler-*.jar|asm-commons-*.jar|asm-util-*.jar|asm-analysis-*.jar|asm-tree-*.jar|asm-*.jar|JarJarFileSystems-*.jar)
                if [[ -z "$mp" ]]; then
                  mp="$ROOT/$rel"
                else
                  mp="$mp:$ROOT/$rel"
                fi
                ;;
            esac
          done < "$file"
          printf '%s' "$mp"
        }}

        collect_merge_modules() {{
          local file="$1"
          local merged=""
          while IFS= read -r rel; do
            [[ -z "$rel" ]] && continue
            local name="${{rel##*/}}"
            case "$name" in
              jna-*.jar|jna-platform-*.jar)
                if [[ -z "$merged" ]]; then
                  merged="$name"
                else
                  merged="$merged,$name"
                fi
                ;;
            esac
          done < "$file"
          printf '%s' "$merged"
        }}

        while [[ $# -gt 0 ]]; do
          case "$1" in
            --phase)
              DEFAULT_PHASE="${{2:-}}"
              shift 2
              ;;
            --invoke-native)
              INVOKE_NATIVE="${{2:-}}"
              shift 2
              ;;
            --preload-mode)
              PRELOAD_MODE="${{2:-}}"
              shift 2
              ;;
            --pause-before-native-load-ms)
              PAUSE_BEFORE_NATIVE_LOAD_MS="${{2:-}}"
              shift 2
              ;;
            --pause-before-native-call-ms)
              PAUSE_BEFORE_NATIVE_CALL_MS="${{2:-}}"
              shift 2
              ;;
            --gdb)
              USE_GDB=1
              shift
              ;;
            --gdb-script)
              GDB_SCRIPT="${{2:-}}"
              shift 2
              ;;
            --help|-h)
              cat <<'EOF'
        usage: run_bootstrap_probe.sh [--phase scan|mc_bootstrap|gather] [--invoke-native load-only|startup-gate] [--preload-mode off|log|spoof] [--pause-before-native-load-ms N] [--pause-before-native-call-ms N] [--gdb] [--gdb-script /path/to/script.gdb] [extra probe args]

        notes:
          - this launches the real Forge BootstrapLauncher path with a custom ForgeClientLaunchHandler target
          - later phases include earlier ones
          - native checkpoints reuse the official mod jar and staged native library to compare progress toward the format 15/9 decode path
          - preload spoof mode reuses the same interposer defaults as run_jni_probe.sh
          - --gdb defaults to sourcing gdb/ysm262_err56_trace.gdb before running the canonical bootstrap gather path
          - for the authentic host-side err:56 path, prefer YSM262_TRACE_JNI_ENV=0
        EOF
              exit 0
              ;;
            *)
              EXTRA_ARGS+=("$1")
              shift
              ;;
          esac
        done

        COMPILE_CP=$(render_classpath "$COMPILE_CP_FILE")
        MODULE_PATH=$(collect_module_path "$PROBE_CP_FILE")
        MERGE_MODULES=$(collect_merge_modules "$PROBE_CP_FILE")
        RUNTIME_CP=$(render_classpath "$PROBE_CP_FILE")
        RUNTIME_CP="$RUNTIME_CP:$PROBE_JAR"

        rm -rf "$CLASS_DIR"
        mkdir -p "$CLASS_DIR"
        javac -cp "$COMPILE_CP" -d "$CLASS_DIR" \
          "$ROOT/src/YsmBootstrapProbeLaunchHandler.java" \
          "$ROOT/src/YsmBootstrapProbeMain.java"
        rm -f "$PROBE_JAR"
        jar --create --file "$PROBE_JAR" -C "$CLASS_DIR" . -C "$RESOURCE_DIR" .

        if [[ "$PRELOAD_MODE" != "off" ]]; then
          mkdir -p "$BUILD_DIR"
          cc -shared -fPIC -O0 -g "$ROOT/native_tools/ysm262_intercept.c" \
            -I"$JAVA_HOME_DIR/include" -I"$JAVA_HOME_DIR/include/linux" -pthread -ldl \
            -o "$BUILD_DIR/libysm262_intercept.so"
          export LD_PRELOAD="$BUILD_DIR/libysm262_intercept.so${{LD_PRELOAD:+:$LD_PRELOAD}}"
          export YSM262_INTERCEPT_LOG="${{YSM262_INTERCEPT_LOG:-$BUILD_DIR/ysm262_intercept.log}}"
          if [[ "$PRELOAD_MODE" == "spoof" ]]; then
            export YSM262_SPOOF_PROC_SELF_EXE="${{YSM262_SPOOF_PROC_SELF_EXE:-$REAL_JAVA_EXE}}"
            export YSM262_SPOOF_DLADDR_LIBJVM="${{YSM262_SPOOF_DLADDR_LIBJVM:-$JAVA_HOME_DIR/lib/server/libjvm.so}}"
            export YSM262_SPOOF_DLADDR_JVM_ORIGINS="${{YSM262_SPOOF_DLADDR_JVM_ORIGINS:-1}}"
            export YSM262_SPOOF_PRCTL_VM="1"
            export YSM262_SPOOF_HOSTNAME="${{YSM262_SPOOF_HOSTNAME:-localhost}}"
            export YSM262_SPOOF_AFFINITY_ONECPU="${{YSM262_SPOOF_AFFINITY_ONECPU:-1}}"
            export YSM262_TRACE_JNI_ENV="${{YSM262_TRACE_JNI_ENV:-1}}"
          fi
        fi

        JAVA_ARGS=(
          "-Djava.net.preferIPv6Addresses=system"
          "-DignoreList={bootstrap_info.ignore_list}"
          "-DlibraryDirectory=$ROOT/runtime/libraries"
          "-p" "$MODULE_PATH"
          "--add-modules" "ALL-MODULE-PATH"
          "--add-opens" "java.base/java.util.jar=cpw.mods.securejarhandler"
          "--add-opens" "java.base/java.lang.invoke=cpw.mods.securejarhandler"
          "--add-exports" "java.base/sun.security.util=cpw.mods.securejarhandler"
          "--add-exports" "jdk.naming.dns/com.sun.jndi.dns=java.naming"
          "-cp" "$RUNTIME_CP"
          "$LAUNCHER_MAIN_CLASS"
          "--launchTarget" "ysmprobeclient"
          "--fml.forgeVersion" "{forge_version}"
          "--fml.mcVersion" "{bootstrap_info.minecraft_version}"
          "--fml.forgeGroup" "net.minecraftforge"
          "--fml.mcpVersion" "{mcp_version}"
          "--phase" "$DEFAULT_PHASE"
          "--official-jar" "$OFFICIAL_JAR"
          "--native-lib" "$NATIVE_LIB"
        )

        if [[ -n "$MERGE_MODULES" ]]; then
          JAVA_ARGS=("-DmergeModules=$MERGE_MODULES" "${{JAVA_ARGS[@]}}")
        fi
        if [[ "$INVOKE_NATIVE" != "none" ]]; then
          JAVA_ARGS+=("--invoke-native" "$INVOKE_NATIVE")
        fi
        if [[ -n "$PAUSE_BEFORE_NATIVE_LOAD_MS" ]]; then
          JAVA_ARGS+=("--pause-before-native-load-ms" "$PAUSE_BEFORE_NATIVE_LOAD_MS")
        fi
        if [[ -n "$PAUSE_BEFORE_NATIVE_CALL_MS" ]]; then
          JAVA_ARGS+=("--pause-before-native-call-ms" "$PAUSE_BEFORE_NATIVE_CALL_MS")
        fi
        JAVA_ARGS+=("${{EXTRA_ARGS[@]}}")

        if [[ "$USE_GDB" -eq 1 ]]; then
          GDB_ARGS=("-q")
          if [[ -n "$GDB_SCRIPT" ]]; then
            GDB_ARGS+=("-ex" "source $GDB_SCRIPT")
          fi
          exec gdb "${{GDB_ARGS[@]}}" --args java "${{JAVA_ARGS[@]}}"
        fi

        exec java "${{JAVA_ARGS[@]}}"
        """
    )
    target = scripts_dir / "run_bootstrap_probe.sh"
    target.write_text(launcher, encoding="utf-8")
    os.chmod(target, 0o755)


def _copy_vm_debug_assets(out_dir: Path) -> list[str]:
    repo_root = Path(__file__).resolve().parents[1]
    vm_debug_dir = repo_root / "vm_debug"
    copied: list[str] = []
    if not vm_debug_dir.is_dir():
        return copied

    src_dir = out_dir / "src"
    gdb_dir = out_dir / "gdb"
    src_dir.mkdir(parents=True, exist_ok=True)
    gdb_dir.mkdir(parents=True, exist_ok=True)

    for name in (
        "YsmNativeStartupGateProbe.java",
        "YsmBootstrapProbeLaunchHandler.java",
        "YsmBootstrapProbeMain.java",
        "ysm262_dlopen_probe.c",
        "ysm262_jni_probe.c",
        "ysm262_intercept.c",
        "ysm262_ptrace_exec.c",
    ):
        src = vm_debug_dir / name
        if src.is_file():
            target_dir = src_dir if name.endswith(".java") else out_dir / "native_tools"
            target_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, target_dir / src.name)
            copied.append(f"{target_dir.relative_to(out_dir)}/{src.name}")

    bootstrap_resource_dir = vm_debug_dir / "bootstrap_probe_resources"
    if bootstrap_resource_dir.is_dir():
        for src in sorted(path for path in bootstrap_resource_dir.rglob("*") if path.is_file()):
            rel = src.relative_to(vm_debug_dir)
            target = out_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, target)
            copied.append(str(rel))

    stubs_src = vm_debug_dir / "stubs" / "src"
    if stubs_src.is_dir():
        for src in sorted(path for path in stubs_src.rglob("*.java") if path.is_file()):
            rel = src.relative_to(vm_debug_dir)
            target = out_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, target)
            copied.append(str(rel))

    for name in (
        "ysm262_jni_bootstrap.gdb",
        "ysm262_err56_trace.gdb",
        "ysm262_startup_gate.gdb",
        "ysm262_antidebug_min.gdb",
        "ysm262_antidebug_route_trace.gdb",
    ):
        src = vm_debug_dir / name
        if src.is_file():
            shutil.copy2(src, gdb_dir / src.name)
            copied.append(f"gdb/{src.name}")

    return copied


def stage_vm_bundle(
    out_dir: Path | None,
    *,
    official_jar: Path | None = None,
    sample_paths: Sequence[Path] = (),
    launcher_command_file: Path | None = None,
    minecraft_root: Path = DEFAULT_MINECRAFT_ROOT,
    version_id: str = DEFAULT_FORGE_VERSION_ID,
) -> Path:
    out_dir = (out_dir or _default_vm_bundle_out_dir()).resolve()
    baseline = probe_ysm262_official(official_jar)
    if baseline is None:
        raise SystemExit("could not find ysm-2.6.2-forge+mc1.20.1-release.jar")

    out_dir.mkdir(parents=True, exist_ok=True)
    official_dir = out_dir / "official"
    native_dir = out_dir / "native"
    sample_dir = out_dir / "samples"
    official_dir.mkdir(exist_ok=True)
    native_dir.mkdir(exist_ok=True)
    sample_dir.mkdir(exist_ok=True)
    scripts_dir = out_dir / "scripts"
    scripts_dir.mkdir(exist_ok=True)

    jar_copy = official_dir / baseline.jar_path.name
    shutil.copy2(baseline.jar_path, jar_copy)

    with zipfile.ZipFile(baseline.jar_path) as zf:
        for entry in baseline.native_entries:
            target = native_dir / Path(entry).name
            target.write_bytes(zf.read(entry))

    staged_samples: list[Path] = []
    for sample in sample_paths:
        sample = sample.resolve()
        if not sample.is_file():
            raise FileNotFoundError(sample)
        shutil.copy2(sample, sample_dir / sample.name)
        staged_samples.append(Path("samples") / sample.name)

    repo_root = _repo_root()
    for helper_name in (
        "native_antidebug_probe.py",
        "ghidra_find_antidebug_refs.py",
        "ghidra_recover_guard_mechanics.py",
        "ghidra_dump_targets.py",
    ):
        helper = repo_root / helper_name
        if helper.is_file():
            shutil.copy2(helper, scripts_dir / helper.name)

    _write_load_probe(out_dir)
    copied_debug_assets = _copy_vm_debug_assets(out_dir)
    linux_native_name = _default_linux_native_name(baseline.native_entries)
    _write_startup_gate_launcher(out_dir, jar_name=baseline.jar_path.name, linux_native_name=linux_native_name)
    _write_jni_probe_launcher(out_dir, jar_name=baseline.jar_path.name, linux_native_name=linux_native_name)
    runtime_audit = _collect_runtime_audit(minecraft_root, version_id=version_id)
    bootstrap_info = _resolve_forge_bootstrap_info(minecraft_root, version_id=version_id)
    _write_bootstrap_probe_launcher(
        out_dir,
        jar_name=baseline.jar_path.name,
        linux_native_name=linux_native_name,
        version_id=version_id,
        bootstrap_info=bootstrap_info,
    )
    runtime_report = _write_runtime_bundle(out_dir, runtime_audit)
    launcher_replay: dict[str, Any] | None = None
    if launcher_command_file is not None:
        launcher_command_file = launcher_command_file.resolve()
        if not launcher_command_file.is_file():
            raise FileNotFoundError(launcher_command_file)
        replay_command = _parse_launcher_command_file(
            launcher_command_file,
            expected_main_classes=tuple(
                candidate
                for candidate in (runtime_report["main_class"], DEFAULT_BOOTSTRAP_MAIN_CLASS)
                if candidate
            ),
        )
        launcher_replay = _write_launcher_replay_artifacts(
            out_dir,
            command=replay_command,
            linux_native_name=linux_native_name,
        )
    _write_vm_bundle_readme(
        out_dir,
        jar_name=baseline.jar_path.name,
        linux_native_name=linux_native_name,
        sample_paths=staged_samples,
        launcher_replay=launcher_replay,
    )

    manifest = {
        "purpose": (
            "Compatibility and porting research for Yes Steve Model legacy 9/15 decoding. "
            "This bundle is for benign reverse-engineering and verification, not malware development."
        ),
        "official_jar": str(jar_copy),
        "official_jar_sha256": baseline.jar_sha256,
        "native_entries": list(baseline.native_entries),
        "native_sha256": list(baseline.native_sha256),
        "loader_classes": list(baseline.loader_classes),
        "export_classes": list(baseline.export_classes),
        "samples": [str(path) for path in staged_samples],
        "helper_scripts": sorted(path.name for path in scripts_dir.iterdir() if path.is_file()),
        "debug_assets": copied_debug_assets,
        "default_linux_native": linux_native_name,
        "minecraft_root": str(minecraft_root),
        "runtime_version_id": version_id,
        "runtime_main_class": runtime_report["main_class"],
        "runtime_minecraft_version": runtime_report["minecraft_version"],
        "runtime_forge_version": runtime_report["forge_version"],
        "runtime_mcp_version": runtime_report["mcp_version"],
        "runtime_entry_count": len(runtime_report["classpath_entries"]),
        "runtime_missing_count": len(runtime_report["missing"]),
        "launcher_replay": launcher_replay,
    }
    (out_dir / "native_bundle_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return out_dir


def main() -> int:
    ap = argparse.ArgumentParser(description="Tools for staging YSM 2.6.2 official export snapshots and debug bundles.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    snap = sub.add_parser("snapshot", help="normalize an official export folder into a canonical snapshot")
    snap.add_argument("export_root", type=Path, help="official export folder to snapshot")
    snap.add_argument("--out-dir", type=Path, help="output folder for the normalized snapshot")
    snap.add_argument("--ysm-path", type=Path, help="optional source .ysm path for naming/manifest context")
    snap.add_argument("--official-jar", type=Path, help="override the 2.6.2 official jar path")

    bundle = sub.add_parser("stage-vm", help="stage the primary guest-side qemu/libvirt VM debug bundle for 2.6.2")
    bundle.add_argument(
        "--out-dir",
        type=Path,
        help=(
            "bundle output directory; defaults to "
            f"{_default_vm_bundle_out_dir()} or ${DEFAULT_DEBUG_RUNTIME_ENV}/vm_bundle_guest_gdb_use_case"
        ),
    )
    bundle.add_argument("--official-jar", type=Path, help="override the 2.6.2 official jar path")
    bundle.add_argument("--sample", type=Path, action="append", default=[], help="optional sample .ysm to copy into the bundle")
    bundle.add_argument(
        "--launcher-command-file",
        type=Path,
        help="optional captured raw launcher command file to convert into a launcher-faithful forgeclient replay script",
    )
    bundle.add_argument("--minecraft-root", type=Path, default=DEFAULT_MINECRAFT_ROOT, help="Minecraft runtime root to harvest dependencies from")
    bundle.add_argument("--version-id", default=DEFAULT_FORGE_VERSION_ID, help="Forge version id to harvest runtime dependencies from")

    headed = sub.add_parser("stage-headed-host", help="stage a headed host control/debug bundle for the real Forge client")
    headed.add_argument(
        "--out-dir",
        type=Path,
        help=(
            "bundle output directory; defaults to "
            f"{_default_headed_host_out_dir()} or ${DEFAULT_DEBUG_RUNTIME_ENV}/headed_host_bundle"
        ),
    )
    headed.add_argument("--minecraft-root", type=Path, default=DEFAULT_MINECRAFT_ROOT, help="Minecraft runtime root to mirror")
    headed.add_argument("--version-id", default=DEFAULT_FORGE_VERSION_ID, help="Forge version id for the dedicated launcher profile")
    headed.add_argument(
        "--launcher-profiles",
        type=Path,
        default=DEFAULT_MINECRAFT_ROOT / "launcher_profiles.json",
        help="launcher_profiles.json to inspect when preparing the profile payload",
    )
    headed.add_argument("--profile-id", default=DEFAULT_HEADED_DEBUG_PROFILE_ID, help="launcher profile id to create/update")
    headed.add_argument("--profile-name", default=DEFAULT_HEADED_DEBUG_PROFILE_NAME, help="launcher profile display name")
    headed.add_argument("--model-trace", action="store_true", help="enable the focused model-state trace lane in the headed wrapper")
    headed.add_argument("--model-trace-sample", help="sample path/name substring that arms focused model tracing")
    headed.add_argument("--model-trace-families", help="comma-separated bone/family tokens to highlight in model-trace scans")
    headed.add_argument("--model-trace-export-filter", default="main.json", help="export json basename to treat as the main model truth target")
    headed.add_argument("--model-trace-rel", default="0x4e2c80", help="inline-hook rel target for the focused model trace lane")
    headed.add_argument("--model-trace-patch-len", type=int, default=16, help="patch length for the focused model trace hook")
    headed.add_argument("--model-trace-limit", type=int, default=32, help="budget of focused model-trace invocations")
    headed.add_argument("--model-trace-scan-bytes", default="0x240", help="bytes to scan per candidate object during model trace")
    headed.add_argument("--model-trace-string-limit", type=int, default=64, help="max string observations per model-trace object")
    headed.add_argument("--model-trace-vector-limit", type=int, default=48, help="max float3 observations per model-trace object")

    capture = sub.add_parser(
        "capture-legacy-export",
        help="stage one legacy .ysm into the headed client path for corroboration trace and optional export/snapshot capture",
    )
    capture.add_argument("ysm_path", type=Path, help="legacy .ysm sample to stage")
    capture.add_argument("--out-dir", type=Path, help="capture bundle output directory")
    capture.add_argument("--minecraft-root", type=Path, default=DEFAULT_MINECRAFT_ROOT, help="Minecraft runtime root to mirror")
    capture.add_argument("--version-id", default=DEFAULT_FORGE_VERSION_ID, help="Forge version id for the dedicated launcher profile")
    capture.add_argument(
        "--launcher-profiles",
        type=Path,
        default=DEFAULT_MINECRAFT_ROOT / "launcher_profiles.json",
        help="launcher_profiles.json to inspect when preparing the profile payload",
    )
    capture.add_argument("--profile-id", help="launcher profile id to create/update")
    capture.add_argument("--profile-name", help="launcher profile display name")
    capture.add_argument("--model-id", help="override the imported model id used by `/ysm export`")
    capture.add_argument("--extra", help="optional extra argument string to append to `/ysm export <model_id>`")
    capture.add_argument("--export-root", type=Path, help="override the raw official export root to harvest")
    capture.add_argument("--snapshot-dir", type=Path, help="output folder for the canonical official snapshot")
    capture.add_argument("--keep-existing", action="store_true", help="do not clear staged custom/export state before preparing the capture")
    capture.add_argument("--trace-only", action="store_true", help="stage a load-and-trace bundle without instructing any `/ysm export` flow")
    capture.add_argument("--model-trace", action="store_true", help="enable the focused model-state trace lane in the staged headed wrapper")
    capture.add_argument("--model-trace-sample", help="sample path/name substring that arms focused model tracing; defaults to the staged ysm filename")
    capture.add_argument("--model-trace-families", help="comma-separated bone/family tokens to highlight in model-trace scans")
    capture.add_argument("--model-trace-export-filter", default="main.json", help="export json basename to treat as the main model truth target")
    capture.add_argument("--model-trace-rel", default="0x4e2c80", help="inline-hook rel target for the focused model trace lane")
    capture.add_argument("--model-trace-patch-len", type=int, default=16, help="patch length for the focused model trace hook")
    capture.add_argument("--model-trace-limit", type=int, default=32, help="budget of focused model-trace invocations")
    capture.add_argument("--model-trace-scan-bytes", default="0x240", help="bytes to scan per candidate object during model trace")
    capture.add_argument("--model-trace-string-limit", type=int, default=64, help="max string observations per model-trace object")
    capture.add_argument("--model-trace-vector-limit", type=int, default=48, help="max float3 observations per model-trace object")

    summarize = sub.add_parser("summarize-model-trace", help="summarize structured model-trace observations and optional snapshot bones")
    summarize.add_argument("intercept_log", type=Path, help="headed-host intercept log to analyze")
    summarize.add_argument("--snapshot-root", type=Path, help="optional official snapshot root to join with model-trace observations")
    summarize.add_argument("--model-name", default="main.json", help="canonical model json name to summarize from the snapshot")
    summarize.add_argument("--family-filter", help="optional comma-separated bone/family tokens to keep")
    summarize.add_argument("--json", action="store_true", help="print JSON instead of plain text")

    audit = sub.add_parser("audit-runtime", help="audit required Forge/Minecraft runtime jars from ~/.minecraft")
    audit.add_argument("--minecraft-root", type=Path, default=DEFAULT_MINECRAFT_ROOT, help="Minecraft runtime root")
    audit.add_argument("--version-id", default=DEFAULT_FORGE_VERSION_ID, help="Forge version id to inspect")
    audit.add_argument("--missing-class", action="append", default=[], help="missing class name to search for under libraries/mods")
    audit.add_argument("--json", action="store_true", help="print machine-readable JSON")

    args = ap.parse_args()
    if args.cmd == "snapshot":
        out = snapshot_official_export(
            args.export_root,
            out_dir=args.out_dir,
            ysm_path=args.ysm_path,
            official_jar=args.official_jar,
        )
        print(f"official_export_snapshot: {out}")
        return 0

    if args.cmd == "stage-vm":
        out = stage_vm_bundle(
            args.out_dir,
            official_jar=args.official_jar,
            sample_paths=args.sample,
            launcher_command_file=args.launcher_command_file,
            minecraft_root=args.minecraft_root,
            version_id=args.version_id,
        )
        print(f"vm_bundle: {out}")
        return 0

    if args.cmd == "audit-runtime":
        report = audit_minecraft_runtime(
            args.minecraft_root,
            version_id=args.version_id,
            missing_classes=args.missing_class,
        )
        if args.json:
            print(json.dumps(report, indent=2))
            return 0
        print(f"minecraft_root: {report['minecraft_root']}")
        print(f"version_id: {report['version_id']}")
        print(f"searched_version_ids: {', '.join(report['searched_version_ids'])}")
        print(f"main_class: {report['main_class']}")
        print(f"entry_count: {report['entry_count']}")
        print(f"missing_count: {report['missing_count']}")
        for item in report["missing"]:
            print(f"missing: {item['kind']} {item['logical_name']} -> {item['relative_path']}")
        for class_name, candidates in report.get("missing_class_candidates", {}).items():
            print(f"class {class_name}: {', '.join(candidates) if candidates else '-'}")
        return 0

    if args.cmd == "stage-headed-host":
        model_trace = HeadedModelTraceConfig(
            enabled=args.model_trace,
            sample_hint=args.model_trace_sample,
            family_filter=_parse_model_trace_family_filter(args.model_trace_families),
            export_filter=args.model_trace_export_filter,
            trace_rel=int(args.model_trace_rel, 0),
            patch_len=args.model_trace_patch_len,
            budget=args.model_trace_limit,
            scan_bytes=int(args.model_trace_scan_bytes, 0),
            string_limit=args.model_trace_string_limit,
            vector_limit=args.model_trace_vector_limit,
        )
        out = stage_headed_host_bundle(
            args.out_dir,
            minecraft_root=args.minecraft_root,
            version_id=args.version_id,
            launcher_profiles=args.launcher_profiles,
            profile_id=args.profile_id,
            profile_name=args.profile_name,
            model_trace=model_trace,
        )
        print(f"headed_host_bundle: {out}")
        return 0

    if args.cmd == "capture-legacy-export":
        model_trace = HeadedModelTraceConfig(
            enabled=args.model_trace,
            sample_hint=args.model_trace_sample,
            family_filter=_parse_model_trace_family_filter(args.model_trace_families),
            export_filter=args.model_trace_export_filter,
            trace_rel=int(args.model_trace_rel, 0),
            patch_len=args.model_trace_patch_len,
            budget=args.model_trace_limit,
            scan_bytes=int(args.model_trace_scan_bytes, 0),
            string_limit=args.model_trace_string_limit,
            vector_limit=args.model_trace_vector_limit,
        )
        capture = capture_legacy_export(
            args.ysm_path,
            out_dir=args.out_dir,
            minecraft_root=args.minecraft_root,
            version_id=args.version_id,
            launcher_profiles=args.launcher_profiles,
            profile_id=args.profile_id,
            profile_name=args.profile_name,
            model_id=args.model_id,
            extra=args.extra,
            export_root=args.export_root,
            snapshot_dir=args.snapshot_dir,
            keep_existing=args.keep_existing,
            model_trace=model_trace,
            trace_only=args.trace_only,
        )
        manifest = json.loads(capture.manifest_path.read_text(encoding="utf-8"))
        print(f"legacy_capture_bundle: {capture.bundle_root}")
        print(f"staged_sample: {capture.sample_copy}")
        print(f"raw_export_root: {capture.export_root}")
        if manifest["suggested_export_command"] is not None:
            print(f"suggested_export_command: {manifest['suggested_export_command']}")
        else:
            print("suggested_export_command: none (trace-only load path)")
            print(f"trace_log: {capture.bundle_root / 'trace' / 'ysm262_intercept.log'}")
        if manifest["selected_export_root"] is not None:
            print(f"selected_export_root: {manifest['selected_export_root']}")
        if manifest["official_snapshot_root"] is not None:
            print(f"official_export_snapshot: {manifest['official_snapshot_root']}")
        else:
            print("official_export_snapshot: pending")
        if manifest["verify_command"] is not None:
            print(f"verify_command: {manifest['verify_command']}")
        print(f"capture_manifest: {capture.manifest_path}")
        return 0

    if args.cmd == "summarize-model-trace":
        summary = summarize_model_trace(
            args.intercept_log,
            snapshot_root=args.snapshot_root,
            family_filter=_parse_model_trace_family_filter(args.family_filter),
            model_name=args.model_name,
        )
        if args.json:
            print(json.dumps(summary, indent=2))
            return 0
        print(f"intercept_log: {summary['intercept_log']}")
        print(f"snapshot_root: {summary['snapshot_root']}")
        print(f"model_name: {summary['model_name']}")
        print(f"event_count: {len(summary['events'])}")
        for item in summary["events"]:
            print(f"event: {item}")
        print(f"object_count: {len(summary['objects'])}")
        for label, payload in summary["objects"].items():
            string_count = len(payload["strings"])
            ptr_string_count = len(payload["ptr_strings"])
            float_count = len(payload["float3"])
            print(f"object: {label} strings={string_count} ptr_strings={ptr_string_count} float3={float_count}")
        if summary["candidate_hook_rels"]:
            print(f"candidate_hook_rel_count: {len(summary['candidate_hook_rels'])}")
            for item in summary["candidate_hook_rels"][:20]:
                print(f"candidate_hook_rel: {item['rel']} hits={item['hits']}")
        if summary["bone_summaries"]:
            print(f"bone_count: {len(summary['bone_summaries'])}")
            for bone in summary["bone_summaries"][:40]:
                print(
                    f"bone: {bone['name']} parent={bone['parent']} pivot={bone['pivot']} cubes={bone['cube_count']} trace_hits={len(bone['matching_trace_labels'])}"
                )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
