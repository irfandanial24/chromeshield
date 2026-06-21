"""
analyzer.py
-----------
The heart of ExtenShield. It takes a loaded extension and checks it against
the rules in rules.py, collecting "findings". Each finding is one piece of
evidence (a dangerous permission, a broad host access, or a risky code
pattern) together with the points it contributes.

The scoring logic lives in report.py; this module's only job is to FIND
things. Keeping detection and scoring separate makes both easier to test.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from . import rules
from .loader import ExtensionBundle, load_extension


@dataclass
class Finding:
    category: str      # "permission" | "host" | "code"
    name: str          # short label, e.g. "cookies" or "eval()"
    severity: str      # "low" | "medium" | "high"
    weight: int        # risk points this finding contributes
    reason: str        # human-readable explanation
    evidence: str = "" # where we found it (file name, matched text, etc.)


# A single noisy pattern (e.g. lots of fetch calls) should not blow up the
# score, so we count each JS rule at most this many times.
MAX_HITS_PER_JS_RULE = 3


def _check_permissions(ext: ExtensionBundle) -> list[Finding]:
    findings = []
    declared = set(ext.permissions)
    for rule in rules.PERMISSION_RULES:
        if rule["name"] in declared:
            findings.append(Finding(
                category="permission",
                name=rule["name"],
                severity=rule["severity"],
                weight=rule["weight"],
                reason=rule["reason"],
                evidence=f'manifest permission: "{rule["name"]}"',
            ))
    return findings


def _check_host_permissions(ext: ExtensionBundle) -> list[Finding]:
    findings = []
    hosts = ext.host_permissions
    for rule in rules.HOST_PERMISSION_RULES:
        for host in hosts:
            if rule["pattern"] == host:
                findings.append(Finding(
                    category="host",
                    name=rule["pattern"],
                    severity=rule["severity"],
                    weight=rule["weight"],
                    reason=rule["reason"],
                    evidence=f'host permission: "{host}"',
                ))
                break  # one finding per rule is enough
    return findings


def _check_js(ext: ExtensionBundle) -> list[Finding]:
    findings = []
    for rule in rules.JS_PATTERN_RULES:
        pattern = re.compile(rule["regex"], re.IGNORECASE)
        hits = 0
        for filename, source in ext.js_files.items():
            for match in pattern.finditer(source):
                hits += 1
                snippet = match.group(0)[:60].replace("\n", " ")
                findings.append(Finding(
                    category="code",
                    name=rule["name"],
                    severity=rule["severity"],
                    weight=rule["weight"],
                    reason=rule["reason"],
                    evidence=f'{filename}: "{snippet}"',
                ))
                if hits >= MAX_HITS_PER_JS_RULE:
                    break
            if hits >= MAX_HITS_PER_JS_RULE:
                break
    return findings


def analyze(ext: ExtensionBundle) -> list[Finding]:
    """Run every rule group against the extension and return all findings."""
    findings = []
    findings += _check_permissions(ext)
    findings += _check_host_permissions(ext)
    findings += _check_js(ext)
    return findings


def analyze_path(path) -> tuple[ExtensionBundle, list[Finding]]:
    """Convenience: load an extension from disk and analyze it in one call."""
    ext = load_extension(path)
    return ext, analyze(ext)
