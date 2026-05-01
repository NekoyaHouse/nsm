from __future__ import annotations

from dataclasses import dataclass

from extractors.bom_v3_payload_assets import PropertyAsset, _sanitize_name


IMAGE_SUFFIXES = (".png", ".jpg", ".jpeg", ".tga")
MODEL_TAGS = {
    "main_model": "main.json",
    "arm_model": "arm.json",
    "arrow_model": "arrow.json",
}


@dataclass(frozen=True)
class LegacyDeclaredExportInventory:
    model_files: tuple[str, ...]
    animation_files: tuple[str, ...]
    texture_files: tuple[str, ...]
    sound_files: tuple[str, ...]


def canonical_legacy_export_name(tag: str, label: str, codec_format: int | None = None) -> str:
    del codec_format
    tag = str(tag).lower()
    label = _sanitize_name(str(label).strip().lower())
    if tag in MODEL_TAGS:
        return MODEL_TAGS[tag]
    if tag.endswith("_animation"):
        stem = _sanitize_name(tag[: -len("_animation")] or label or "animation")
        return f"{stem.replace('_', '.')}.animation.json"
    if tag == "arrow_texture":
        return "arrow.png"
    if tag == "texture":
        return f"{label or 'texture'}.png"
    if tag.startswith("texture_"):
        stem = _sanitize_name(tag[len("texture_") :] or label or "texture")
        return f"{stem}.png"
    if tag.endswith(IMAGE_SUFFIXES):
        suffix = "".join(ch for ch in tag if ch in "._/" or ch.isalnum())
        stem = _sanitize_name(label or tag.rsplit(".", 1)[0] or "texture")
        ext = "." + suffix.rsplit(".", 1)[-1] if "." in suffix else ".png"
        return f"{stem}{ext}"
    if tag == "sound":
        return f"{label or 'sound'}.ogg"
    if tag.startswith("sound_"):
        stem = _sanitize_name(tag[len("sound_") :] or label or "sound")
        return f"{stem}.ogg"
    safe_tag = _sanitize_name(tag)
    if label:
        return f"{safe_tag}_{label}.bin"
    return f"{safe_tag}.bin"


def legacy_asset_category(tag: str) -> tuple[str, str]:
    tag = str(tag).lower()
    if tag in MODEL_TAGS:
        return ("model", tag.replace("_model", ""))
    if tag.endswith("_animation"):
        return ("animation", tag[: -len("_animation")] or "animation")
    if tag == "arrow_texture":
        return ("texture", "arrow")
    if tag == "texture" or tag.startswith("texture_") or tag.endswith(IMAGE_SUFFIXES):
        return ("texture", "main")
    if tag == "sound" or tag.startswith("sound_"):
        return ("sound", "sound")
    return ("binary", "other")


def build_legacy_declared_export_inventory(
    assets: tuple[PropertyAsset, ...] | list[PropertyAsset],
    codec_format: int | None = None,
) -> LegacyDeclaredExportInventory:
    categories: dict[str, list[str]] = {
        "model": [],
        "animation": [],
        "texture": [],
        "sound": [],
    }
    seen: dict[str, set[str]] = {key: set() for key in categories}
    for asset in assets:
        category, _family = legacy_asset_category(asset.tag)
        if category not in categories:
            continue
        export_name = canonical_legacy_export_name(asset.tag, asset.label, codec_format)
        if export_name in seen[category]:
            continue
        seen[category].add(export_name)
        categories[category].append(export_name)
    return LegacyDeclaredExportInventory(
        model_files=tuple(categories["model"]),
        animation_files=tuple(categories["animation"]),
        texture_files=tuple(categories["texture"]),
        sound_files=tuple(categories["sound"]),
    )
