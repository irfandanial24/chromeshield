# report.py
# Turns the findings into a score, a level and a report.
# score = sum of the finding weights, capped at 100, then put into a band.
# Simple on purpose so it can always be explained.

from __future__ import annotations

from dataclasses import dataclass, field

from .analyzer import Finding
from .loader import ExtensionBundle

# the four score bands (low, high, name, summary)
RISK_BANDS = [
    (0, 15, "MINIMAL", "Looks safe. Only low-risk behaviour detected."),
    (16, 35, "LOW", "Some elevated permissions, but nothing strongly malicious."),
    (36, 60, "MEDIUM", "Several risky behaviours. Review before installing."),
    (61, 100, "HIGH", "Strong indicators of malicious behaviour. Avoid."),
]


@dataclass
class RiskReport:
    extension_name: str
    score: int
    level: str
    summary: str
    findings: list = field(default_factory=list)
    source_path: str = ""
    # details about what was scanned (shown to the user)
    version: str = ""
    description: str = ""
    permissions: list = field(default_factory=list)
    host_permissions: list = field(default_factory=list)
    num_js_files: int = 0

    def to_dict(self) -> dict:
        return {
            "extension_name": self.extension_name,
            "score": self.score,
            "level": self.level,
            "summary": self.summary,
            "source_path": self.source_path,
            "version": self.version,
            "description": self.description,
            "permissions": self.permissions,
            "host_permissions": self.host_permissions,
            "num_js_files": self.num_js_files,
            "findings": [
                {
                    "category": f.category,
                    "name": f.name,
                    "severity": f.severity,
                    "weight": f.weight,
                    "reason": f.reason,
                    "evidence": f.evidence,
                }
                for f in self.findings
            ],
        }


def _level_for_score(score: int) -> tuple[str, str]:
    for low, high, level, summary in RISK_BANDS:
        if low <= score <= high:
            return level, summary
    return "HIGH", RISK_BANDS[-1][3]


def build_report(ext: ExtensionBundle, findings: list[Finding]) -> RiskReport:
    total = sum(f.weight for f in findings)
    score = min(100, total)
    level, summary = _level_for_score(score)

    # put the most serious findings first
    severity_order = {"high": 0, "medium": 1, "low": 2}
    findings_sorted = sorted(
        findings, key=lambda f: (severity_order.get(f.severity, 3), -f.weight)
    )

    return RiskReport(
        extension_name=ext.name,
        score=score,
        level=level,
        summary=summary,
        findings=findings_sorted,
        source_path=ext.source_path,
        version=ext.manifest.get("version", "unknown"),
        description=ext.manifest.get("description", ""),
        permissions=ext.permissions,
        host_permissions=ext.host_permissions,
        num_js_files=len(ext.js_files),
    )


def format_text(report: RiskReport) -> str:
    # plain-text report for the command line
    lines = []
    lines.append("=" * 64)
    lines.append(f"  ExtenShield report: {report.extension_name}")
    lines.append("=" * 64)
    lines.append(f"  Version    : {report.version}")
    lines.append(f"  Permissions: {len(report.permissions)}  |  Script files: {report.num_js_files}")
    if report.permissions:
        lines.append(f"  Requested  : {', '.join(report.permissions)}")
    if report.host_permissions:
        lines.append(f"  Site access: {', '.join(report.host_permissions)}")
    lines.append("-" * 64)
    lines.append(f"  Risk score : {report.score}/100")
    lines.append(f"  Risk level : {report.level}")
    lines.append(f"  Summary    : {report.summary}")
    lines.append("-" * 64)

    if not report.findings:
        lines.append("  No risky behaviour detected.")
    else:
        lines.append(f"  {len(report.findings)} finding(s):")
        lines.append("")
        for f in report.findings:
            tag = f.severity.upper().ljust(6)
            lines.append(f"  [{tag}] (+{f.weight}) {f.name}")
            lines.append(f"           {f.reason}")
            lines.append(f"           evidence: {f.evidence}")
            lines.append("")
    lines.append("=" * 64)
    return "\n".join(lines)
