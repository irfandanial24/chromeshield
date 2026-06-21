"""
loader.py
---------
Loads a Chrome extension from disk so the analyzer can inspect it.

An extension can come in a few shapes:
  - a plain folder containing manifest.json + scripts
  - a .zip file (the Chrome Web Store / developer download format)
  - a .crx file (Chrome's packaged format, which is just a ZIP with a small
    binary header in front)

This module hides those differences. It returns a simple ExtensionBundle
object with the parsed manifest and the text of every JavaScript file.
"""

from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ExtensionBundle:
    """Everything the analyzer needs from one extension."""
    name: str
    manifest: dict
    js_files: dict = field(default_factory=dict)   # {filename: source_code}
    source_path: str = ""

    @property
    def permissions(self) -> list:
        """Combined 'permissions' + 'optional_permissions' from the manifest."""
        perms = list(self.manifest.get("permissions", []))
        perms += list(self.manifest.get("optional_permissions", []))
        return perms

    @property
    def host_permissions(self) -> list:
        """
        Host permissions. In Manifest V3 these live under 'host_permissions';
        in V2 they were mixed into 'permissions'. We gather both so the tool
        works on old and new extensions.
        """
        hosts = list(self.manifest.get("host_permissions", []))
        # In MV2, host patterns appear inside 'permissions' too.
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


def load_from_zip(zip_path: str | Path) -> ExtensionBundle:
    """
    Works for both .zip and .crx files. A .crx is a ZIP with a header in front,
    so we scan for the ZIP magic bytes ('PK\\x03\\x04') and read from there.
    """
    zip_path = Path(zip_path)
    data = zip_path.read_bytes()

    # Strip any .crx header by jumping to the start of the real ZIP content.
    idx = data.find(b"PK\x03\x04")
    if idx == -1:
        raise ValueError(f"{zip_path} does not look like a valid zip/crx file.")
    if idx > 0:
        import io
        archive = zipfile.ZipFile(io.BytesIO(data[idx:]))
    else:
        archive = zipfile.ZipFile(zip_path)

    with archive:
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

    name = manifest.get("name", zip_path.stem)
    return ExtensionBundle(name=name, manifest=manifest, js_files=js_files,
                           source_path=str(zip_path))


def load_extension(path: str | Path) -> ExtensionBundle:
    """Smart loader: picks the right method based on the path."""
    path = Path(path)
    if path.is_dir():
        return load_from_folder(path)
    if path.suffix.lower() in (".zip", ".crx"):
        return load_from_zip(path)
    raise ValueError(
        f"Don't know how to load '{path}'. Provide an extension folder, "
        f".zip, or .crx file."
    )
