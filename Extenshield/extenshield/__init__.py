"""
ExtenShield - a rule-based static analyzer that detects malicious Chrome
browser extensions by inspecting their manifest and JavaScript.

Public helper: scan() loads an extension, analyzes it, and returns a RiskReport.
"""

from .analyzer import analyze, analyze_path, Finding
from .loader import load_extension, ExtensionBundle
from .report import build_report, format_text, RiskReport

__version__ = "1.0.0"


def scan(path) -> RiskReport:
    """One-call helper: path -> RiskReport."""
    ext, findings = analyze_path(path)
    return build_report(ext, findings)
