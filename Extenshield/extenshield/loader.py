# loader.py
# Loads a Chrome extension so it can be scanned.
# The extension can be a folder, a .zip or a .crx file.

from __future__ import annotations

import io
import json
import zipfile
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ExtensionBundle:
    # holds the manifest and the js files of one extension
    name: str
    manifest: dict
    js_files: dict = field(default_factory=dict)   # filename: code
    source_path: str = ""

    @property
    def permissions(self) -> list:
        # normal + optional permissions
        perms = list(self.manifest.get("permissions", []))
        perms += list(self.manifest.get("optional_permissions", []))
        return perms

    @property
    def host_permissions(self) -> list:
        # host permissions. MV3 keeps them separate, MV2 mixes them into
        # permissions, so grab from both places
        hosts = list(self.manifest.get("host_permissions", []))
        for p in self.manifest.get("permissions", []):
            if isinstance(p, str) and ("://" in p or p == "<all_urls>"):
                hosts.append(p)
        return hosts


def _read_manifest_text(text: str) -> dict:
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"manifest.json is not valid JSON: {exc}") from exc


def load_from_folder(folder: str | Path) -> ExtensionBundle:
    folder = Path(folder)
    manifest_path = folder / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"No manifest.json found in {folder}")

    manifest = _read_manifest_text(manifest_path.read_text(encoding="utf-8", errors="ignore"))

    js_files = {}
    for js_path in folder.rglob("*.js"):
        rel = js_path.relative_to(folder).as_posix()
        js_files[rel] = js_path.read_text(encoding="utf-8", errors="ignore")

    name = manifest.get("name", folder.name)
    return ExtensionBundle(name=name, manifest=manifest, js_files=js_files,
                           source_path=str(folder))


def load_from_bytes(data: bytes, source_name: str = "extension") -> ExtensionBundle:
    # build an extension from zip/crx bytes in memory (used after downloading).
    # a .crx is a zip with a header in front, so find the zip start (PK bytes)
    # and read from there
    idx = data.find(b"PK\x03\x04")
    if idx == -1:
        raise ValueError(f"'{source_name}' does not look like a valid zip/crx file.")

    with zipfile.ZipFile(io.BytesIO(data[idx:])) as archive:
        names = archive.namelist()
        manifest_name = next((n for n in names if n.endswith("manifest.json")), None)
        if manifest_name is None:
            raise FileNotFoundError("No manifest.json inside the archive.")

        manifest = _read_manifest_text(
            archive.read(manifest_name).decode("utf-8", errors="ignore")
        )

        js_files = {}
        for n in names:
            if n.endswith(".js"):
                js_files[n] = archive.read(n).decode("utf-8", errors="ignore")

    name = manifest.get("name", source_name)
    return ExtensionBundle(name=name, manifest=manifest, js_files=js_files,
                           source_path=source_name)


def load_from_zip(zip_path: str | Path) -> ExtensionBundle:
    # read a .zip or .crx from disk, then reuse load_from_bytes
    zip_path = Path(zip_path)
    bundle = load_from_bytes(zip_path.read_bytes(), source_name=zip_path.stem)
    bundle.source_path = str(zip_path)
    return bundle


def load_extension(path: str | Path) -> ExtensionBundle:
    # pick the right loader depending on the path
    path = Path(path)
    if path.is_dir():
        return load_from_folder(path)
    if path.suffix.lower() in (".zip", ".crx"):
        return load_from_zip(path)
    raise ValueError(
        f"Don't know how to load '{path}'. Provide an extension folder, "
        f".zip, or .crx file."
    )
