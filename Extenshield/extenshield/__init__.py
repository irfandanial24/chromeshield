# extenshield package
# ties the modules together and gives two simple helpers:
# scan() for a file/folder and scan_url() for a Web Store link.

from .analyzer import analyze, analyze_path, Finding
from .loader import load_extension, ExtensionBundle
from .report import build_report, format_text, RiskReport
from .webstore import load_from_webstore, extract_extension_id

__version__ = "1.1.0"


def scan(path) -> RiskReport:
    # scan a folder / .zip / .crx and return the report
    ext, findings = analyze_path(path)
    return build_report(ext, findings)


def scan_url(url_or_id) -> RiskReport:
    # scan a Web Store link or extension id and return the report
    ext = load_from_webstore(url_or_id)
    return build_report(ext, analyze(ext))
