"""
webstore.py
-----------
Downloads a Chrome extension straight from the Chrome Web Store so the user
only has to paste a link - no hunting for files.

How it works:
  1. Pull the 32-character extension ID out of whatever the user pasted
     (a full Web Store URL, or just the bare ID).
  2. Ask Google's official extension-update server for that extension's .crx
     package. This is the same endpoint Chrome itself uses to fetch updates.
  3. Hand the downloaded bytes to the loader, which unpacks and analyzes them.

Only the standard library is used (urllib), so there are no extra installs.
Note: this downloads the package; it never *runs* the extension, so it is safe.
"""

from __future__ import annotations

import re
import urllib.request

from .loader import ExtensionBundle, load_from_bytes

# Google's update endpoint. {id} is filled in with the extension ID. The
# 'prodversion' just has to look like a real Chrome version; 'response=redirect'
# makes the server send us straight to the .crx download.
_CRX_ENDPOINT = (
    "https://clients2.google.com/service/update2/crx"
    "?response=redirect&acceptformat=crx2,crx3"
    "&prodversion=120.0&x=id%3D{id}%26installsource%3Dondemand%26uc"
)

# A Chrome extension ID is always 32 characters, each a letter from a to p.
_ID_PATTERN = re.compile(r"[a-p]{32}")


def extract_extension_id(url_or_id: str) -> str:
    """
    Find the extension ID inside a pasted Web Store URL or raw ID.

    Examples that all return 'mnjggcdmjocbbbhaepdhchncahnbgone':
      https://chromewebstore.google.com/detail/sponsorblock/mnjggcdmjocbbbhaepdhchncahnbgone
      https://chrome.google.com/webstore/detail/sponsorblock/mnjggcdmjocbbbhaepdhchncahnbgone
      mnjggcdmjocbbbhaepdhchncahnbgone
    """
    if not url_or_id:
        raise ValueError("Please paste a Chrome Web Store link or extension ID.")
    match = _ID_PATTERN.search(url_or_id.strip())
    if not match:
        raise ValueError(
            "Couldn't find a valid extension ID in that input. A Web Store link "
            "looks like '.../detail/name/<32-letter-id>'."
        )
    return match.group(0)


def download_crx(url_or_id: str, timeout: int = 30) -> tuple[str, bytes]:
    """Download the .crx package for an extension. Returns (extension_id, bytes)."""
    ext_id = extract_extension_id(url_or_id)
    crx_url = _CRX_ENDPOINT.format(id=ext_id)

    # A User-Agent header makes Google's server treat us like a normal client.
    request = urllib.request.Request(crx_url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = response.read()
    except Exception as exc:  # noqa: BLE001 - surface a friendly message
        raise ConnectionError(
            f"Could not download the extension (id {ext_id}). It may have been "
            f"removed, or there was a network problem. Details: {exc}"
        ) from exc

    if not data:
        raise ConnectionError(f"Downloaded an empty file for extension id {ext_id}.")
    return ext_id, data


def load_from_webstore(url_or_id: str) -> ExtensionBundle:
    """Download an extension from the Web Store and return it ready to analyze."""
    ext_id, data = download_crx(url_or_id)
    return load_from_bytes(data, source_name=ext_id)
