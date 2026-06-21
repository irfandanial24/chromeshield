"""
report.py
---------
Turns a list of findings into a final risk score, a risk level, and a readable
report. The scoring approach is deliberately simple and explainable (important
for a project you have to defend):

  total_points = sum of the weights of every finding
  score        = min(100, total_points)        # capped at 100
  level        = band the score falls into

We cap at 100 so the number is easy to read as "risk out of 100". Because the
score is just a transparent sum of weighted rules, you can always explain
exactly WHY an extension got the score it did - there is no black box.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .analyzer import Finding
from .loader import ExtensionBundle

# Score bands. Tune these thresholds during your evaluation.
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

    def to_dict(self) -> dict:
        return {
            "extension_name": self.extension_name,
            "score": self.score,
            "level": self.level,
            "summary": self.summary,
            "source_path": self.source_path,
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

    # Show the most dangerous findings first.
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
    )


def format_text(report: RiskReport) -> str:
    """Render the report as plain text for the command line."""
    lines = []
    lines.append("=" * 64)
    lines.append(f"  ExtenShield report: {report.extension_name}")
    lines.append("=" * 64)
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
