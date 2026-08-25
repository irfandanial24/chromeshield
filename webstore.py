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
    "&prodversion=130.0.0.0&x=id%3D{id}%26installsource%3Dondemand%26uc"
)

# A Chrome extension ID is always 32 characters, each a letter from a to p.
_ID_PATTERN = re.compile(r"[a-p]{32}")


class NotAnExtensionError(ValueError):
    """
    Raised when the pasted text is not a recognisable Chrome extension link/ID
    (e.g. the user pasted a YouTube link or random text). The dashboard catches
    this to show a clear 'this is not an extension' message.
    """


def extract_extension_id(url_or_id: str) -> str:
    """
    Find the extension ID inside a pasted Web Store URL or raw ID.

    Examples that all return 'mnjggcdmjocbbbhaepdhchncahnbgone':
      https://chromewebstore.google.com/detail/sponsorblock/mnjggcdmjocbbbhaepdhchncahnbgone
      https://chrome.google.com/webstore/detail/sponsorblock/mnjggcdmjocbbbhaepdhchncahnbgone
      mnjggcdmjocbbbhaepdhchncahnbgone

    Raises NotAnExtensionError if the input clearly isn't an extension link/ID.
    """
    if not url_or_id or not url_or_id.strip():
        raise NotAnExtensionError(
            "Please paste a Chrome Web Store extension link or a 32-character "
            "extension ID."
        )

    text = url_or_id.strip()
    match = _ID_PATTERN.search(text)
    if not match:
        # Give a more specific hint depending on what they pasted.
        if text.startswith("http"):
            raise NotAnExtensionError(
                "That link is not a Chrome Web Store extension. A valid link looks "
                "like: chromewebstore.google.com/detail/<name>/<32-letter-id>"
            )
        raise NotAnExtensionError(
            "That doesn't look like a Chrome extension. Paste a Chrome Web Store "
            "link, or the extension's 32-character ID (letters a–p only)."
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
        raise ConnectionError(
            f"Google returned no file for extension id {ext_id}. The extension may "
            f"have been removed or is not available for download. Try another "
            f"extension, or use the Upload tab with its .zip / .crx file instead."
        )
    return ext_id, data


def load_from_webstore(url_or_id: str) -> ExtensionBundle:
    """Download an extension from the Web Store and return it ready to analyze."""
    ext_id, data = download_crx(url_or_id)
    try:
        return load_from_bytes(data, source_name=ext_id)
    except (ValueError, FileNotFoundError) as exc:
        # We got *something* back, but it wasn't a real extension package -
        # usually means that extension ID does not exist on the Web Store.
        raise NotAnExtensionError(
            f"No Chrome extension was found for ID '{ext_id}'. Double-check the "
            f"Web Store link - this extension may not exist or has been removed."
        ) from exc
