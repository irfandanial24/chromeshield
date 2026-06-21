"""
rules.py
--------
Rule definitions used by the ExtenShield static analyzer.

This file is intentionally simple and data-driven: each rule is just a
dictionary describing what to look for, how dangerous it is (weight), and a
human-readable explanation. Keeping the rules separate from the engine means
you can add or tune detections without touching the analysis code.

There are three rule groups:
  1. PERMISSION_RULES   - dangerous entries in manifest.json "permissions"
  2. HOST_PERMISSION_RULES - overly broad website access (host permissions)
  3. JS_PATTERN_RULES   - risky patterns found in the extension's JavaScript

Each weight is a number of "risk points". The analyzer adds up the points of
every rule that matches and converts the total into a 0-100 score.
"""

# ---------------------------------------------------------------------------
# 1. Dangerous permissions
# ---------------------------------------------------------------------------
# Chrome extensions request "permissions" in their manifest. Some are harmless
# (e.g. "storage"); others give powerful abilities that malware abuses.
# severity: "low" | "medium" | "high"  (used only for display/colour)
PERMISSION_RULES = [
    {
        "name": "tabs",
        "weight": 8,
        "severity": "medium",
        "reason": "Can read the URL and title of every tab the user has open.",
    },
    {
        "name": "webRequest",
        "weight": 12,
        "severity": "high",
        "reason": "Can intercept and read network requests (possible data theft).",
    },
    {
        "name": "webRequestBlocking",
        "weight": 14,
        "severity": "high",
        "reason": "Can block or modify network requests before they are sent.",
    },
    {
        "name": "cookies",
        "weight": 14,
        "severity": "high",
        "reason": "Can read and steal session cookies, enabling account hijacking.",
    },
    {
        "name": "history",
        "weight": 10,
        "severity": "medium",
        "reason": "Can read the user's full browsing history.",
    },
    {
        "name": "downloads",
        "weight": 9,
        "severity": "medium",
        "reason": "Can download files to the user's machine.",
    },
    {
        "name": "management",
        "weight": 12,
        "severity": "high",
        "reason": "Can disable or uninstall other extensions (e.g. security tools).",
    },
    {
        "name": "proxy",
        "weight": 13,
        "severity": "high",
        "reason": "Can reroute all of the user's traffic through an attacker proxy.",
    },
    {
        "name": "debugger",
        "weight": 16,
        "severity": "high",
        "reason": "Grants deep control over pages; very rarely needed legitimately.",
    },
    {
        "name": "clipboardRead",
        "weight": 11,
        "severity": "high",
        "reason": "Can read clipboard contents (passwords, wallet keys, etc.).",
    },
    {
        "name": "nativeMessaging",
        "weight": 12,
        "severity": "high",
        "reason": "Can talk to native apps outside the browser sandbox.",
    },
    {
        "name": "scripting",
        "weight": 7,
        "severity": "medium",
        "reason": "Can inject scripts into pages (powerful if combined with broad host access).",
    },
    {
        "name": "storage",
        "weight": 1,
        "severity": "low",
        "reason": "Local storage access - common and usually harmless.",
    },
]

# ---------------------------------------------------------------------------
# 2. Host permissions (which websites the extension can touch)
# ---------------------------------------------------------------------------
# Patterns like "<all_urls>" or "*://*/*" mean the extension can run on EVERY
# website, which is the single biggest red flag for content-stealing malware.
HOST_PERMISSION_RULES = [
    {
        "pattern": "<all_urls>",
        "weight": 18,
        "severity": "high",
        "reason": "Requests access to ALL websites (<all_urls>).",
    },
    {
        "pattern": "*://*/*",
        "weight": 18,
        "severity": "high",
        "reason": "Requests access to ALL websites (*://*/*).",
    },
    {
        "pattern": "http://*/*",
        "weight": 12,
        "severity": "medium",
        "reason": "Requests access to all HTTP websites.",
    },
    {
        "pattern": "https://*/*",
        "weight": 12,
        "severity": "medium",
        "reason": "Requests access to all HTTPS websites.",
    },
]

# ---------------------------------------------------------------------------
# 3. Risky JavaScript patterns (regular expressions)
# ---------------------------------------------------------------------------
# These regexes are searched across every .js file bundled in the extension.
# Each match is evidence of a behaviour that malware commonly uses. We cap how
# many times a single rule can add points (see analyzer) so one noisy file
# does not dominate the score.
JS_PATTERN_RULES = [
    {
        "name": "eval()",
        "regex": r"\beval\s*\(",
        "weight": 12,
        "severity": "high",
        "reason": "Uses eval() to run code from strings - classic obfuscation/remote-code technique.",
    },
    {
        "name": "Function constructor",
        "regex": r"new\s+Function\s*\(",
        "weight": 10,
        "severity": "high",
        "reason": "Builds code at runtime with new Function() - often hides malicious logic.",
    },
    {
        "name": "remote script injection",
        "regex": r"document\.createElement\(\s*['\"]script['\"]\s*\)",
        "weight": 9,
        "severity": "medium",
        "reason": "Creates <script> elements at runtime, often to load remote code.",
    },
    {
        "name": "cookie access",
        "regex": r"document\.cookie",
        "weight": 11,
        "severity": "high",
        "reason": "Reads document.cookie - can exfiltrate session tokens.",
    },
    {
        "name": "localStorage harvesting",
        "regex": r"localStorage\.(getItem|valueOf|length)|JSON\.stringify\(\s*localStorage",
        "weight": 7,
        "severity": "medium",
        "reason": "Reads localStorage in bulk - may harvest stored credentials/tokens.",
    },
    {
        "name": "data exfiltration (fetch/XHR to remote)",
        "regex": r"(fetch|XMLHttpRequest|navigator\.sendBeacon)\s*\(",
        "weight": 6,
        "severity": "medium",
        "reason": "Sends data to a server - benign on its own but risky with cookie/clipboard access.",
    },
    {
        "name": "base64 decode (atob)",
        "regex": r"\batob\s*\(",
        "weight": 6,
        "severity": "medium",
        "reason": "Decodes base64 strings - frequently used to hide payloads/URLs.",
    },
    {
        "name": "hex/obfuscated string blob",
        "regex": r"(\\x[0-9a-fA-F]{2}){8,}",
        "weight": 9,
        "severity": "high",
        "reason": "Long run of \\xNN escapes - a strong sign of obfuscated/packed code.",
    },
    {
        "name": "clipboard read",
        "regex": r"navigator\.clipboard\.readText",
        "weight": 10,
        "severity": "high",
        "reason": "Reads the clipboard, which may contain passwords or crypto keys.",
    },
    {
        "name": "keystroke logging",
        "regex": r"addEventListener\(\s*['\"]key(down|press|up)['\"]",
        "weight": 8,
        "severity": "medium",
        "reason": "Listens to keyboard events globally - possible keylogger.",
    },
    {
        "name": "crypto wallet targeting",
        "regex": r"(metamask|wallet|ethereum|web3|private[_-]?key|seed[_-]?phrase)",
        "weight": 10,
        "severity": "high",
        "reason": "References crypto wallets/keys - common target of malicious extensions.",
    },
    {
        "name": "hardcoded IP endpoint",
        "regex": r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        "weight": 9,
        "severity": "high",
        "reason": "Talks to a raw IP address instead of a domain - typical of C2 servers.",
    },
]
