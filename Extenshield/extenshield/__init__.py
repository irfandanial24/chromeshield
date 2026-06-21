"""
ExtenShield - a rule-based static analyzer that detects malicious Chrome
browser extensions by inspecting their manifest and JavaScript.

Public helper: scan() loads an extension, analyzes it, and returns a RiskReport.
"""

from .analyzer import analyze, analyze_path, Finding
from .loader import load_extension, ExtensionBundle
from .report import build_report, format_text, RiskReport
from .webstore import load_from_webstore, extract_extension_id

__version__ = "1.1.0"


def scan(path) -> RiskReport:
    """One-call helper: a folder / .zip / .crx path -> RiskReport."""
    ext, findings = analyze_path(path)
    return build_report(ext, findings)


def scan_url(url_or_id) -> RiskReport:
    """One-call helper: a Chrome Web Store link or extension ID -> RiskReport."""
    ext = load_from_webstore(url_or_id)
    return build_report(ext, analyze(ext))
