# webstore.py
# Downloads an extension straight from the Chrome Web Store so the user only
# has to paste a link.
# Steps: get the extension id from the link, ask Google's update server for
# the .crx, then hand the bytes to the loader. It only downloads, never runs.

from __future__ import annotations

import re
import urllib.request

from .loader import ExtensionBundle, load_from_bytes

# Google's download endpoint. {id} is the extension id and response=redirect
# sends us straight to the .crx file.
_CRX_ENDPOINT = (
    "https://clients2.google.com/service/update2/crx"
    "?response=redirect&acceptformat=crx2,crx3"
    "&prodversion=130.0.0.0&x=id%3D{id}%26installsource%3Dondemand%26uc"
)

# an extension id is 32 characters, each a letter a to p
_ID_PATTERN = re.compile(r"[a-p]{32}")


class NotAnExtensionError(ValueError):
    # raised when the pasted text is not a real extension link/id,
    # so the dashboard can show a clear warning instead of a crash
    pass


def extract_extension_id(url_or_id: str) -> str:
    # find the 32-character id inside a pasted link (or the bare id)
    if not url_or_id or not url_or_id.strip():
        raise NotAnExtensionError(
            "Please paste a Chrome Web Store extension link or a 32-character "
            "extension ID."
        )

    text = url_or_id.strip()
    match = _ID_PATTERN.search(text)
    if not match:
        # give a hint based on what they pasted
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
    # download the .crx and return (id, bytes)
    ext_id = extract_extension_id(url_or_id)
    crx_url = _CRX_ENDPOINT.format(id=ext_id)

    # send a normal browser user-agent so Google replies as usual
    request = urllib.request.Request(crx_url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = response.read()
    except Exception as exc:  # show a friendly message instead of the raw error
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
    # download an extension from a link, ready to analyse
    ext_id, data = download_crx(url_or_id)
    try:
        return load_from_bytes(data, source_name=ext_id)
    except (ValueError, FileNotFoundError) as exc:
        # got something back but it was not a real extension package,
        # usually means the id does not exist on the store
        raise NotAnExtensionError(
            f"No Chrome extension was found for ID '{ext_id}'. Double-check the "
            f"Web Store link - this extension may not exist or has been removed."
        ) from exc
