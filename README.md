# 🛡️ ExtenShield — Malicious Browser Extension Detection System

ExtenShield is a **rule-based static analysis** tool that detects malicious
Google Chrome browser extensions. It inspects an extension's `manifest.json`
and its JavaScript code **without running it**, flags risky behaviours, and
produces a transparent **risk score out of 100** with a clear explanation for
every point awarded.

It was built as a Final Year Project. The design favours being **simple and
explainable** over being a black box — every decision the tool makes can be
traced back to a named rule, which makes it easy to present and defend.

---

## What problem does it solve?

Browser extensions run with powerful permissions: they can read the pages you
visit, intercept your network traffic, and access your cookies. Malicious or
hijacked extensions abuse this to steal sessions, log keystrokes, or inject
code. ExtenShield helps a user (or a reviewer) decide whether an extension is
safe **before** installing it.

---

## How it works (the pipeline)

```
  extension (folder / .zip / .crx)
            │
            ▼
   ┌──────────────────┐
   │   loader.py      │  unpack + read manifest.json and all .js files
   └──────────────────┘
            │
            ▼
   ┌──────────────────┐
   │   analyzer.py    │  match against rules → list of "findings"
   │   + rules.py     │
   └──────────────────┘
            │
            ▼
   ┌──────────────────┐
   │   report.py      │  sum weights → score (0–100) → risk level
   └──────────────────┘
            │
            ▼
     CLI (cli.py)  or  Web dashboard (app.py)
```

The tool checks three things:

1. **Dangerous permissions** in the manifest (e.g. `cookies`, `webRequest`,
   `debugger`, `management`).
2. **Over-broad host permissions** (e.g. `<all_urls>`, `*://*/*`) that let the
   extension run on every website.
3. **Risky JavaScript patterns** (e.g. `eval()`, `document.cookie`, clipboard
   reads, base64-decoded payloads, hardcoded IP endpoints, keystroke listeners,
   crypto-wallet references).

Each matched rule has a **weight** (risk points). The score is simply the sum
of those weights, capped at 100, then mapped to a band:

| Score  | Level    | Meaning                                            |
|--------|----------|----------------------------------------------------|
| 0–15   | MINIMAL  | Looks safe.                                        |
| 16–35  | LOW      | Elevated permissions, nothing strongly malicious.  |
| 36–60  | MEDIUM   | Several risky behaviours — review before install.  |
| 61–100 | HIGH     | Strong indicators of malicious behaviour — avoid.  |

Because the score is a plain weighted sum of named rules, you can always
explain **exactly why** an extension got the score it did.

---

## Project structure

```
Extenshield/
├── extenshield/            # the analysis engine (pure standard library)
│   ├── __init__.py         #   scan() helper + public API
│   ├── loader.py           #   load extension from folder / .zip / .crx
│   ├── rules.py            #   all detection rules + weights (edit me to tune)
│   ├── analyzer.py         #   matches rules against an extension -> findings
│   └── report.py           #   scoring + risk level + report formatting
├── cli.py                  # command-line interface
├── app.py                  # Streamlit web dashboard
├── samples/
│   ├── benign_extension/   #   harmless test extension (scores LOW)
│   └── malicious_extension/#   suspicious test sample (scores HIGH)
├── tests/
│   └── test_analyzer.py    # unit tests
├── requirements.txt
└── README.md
```

---

## Setup

The **core tool and tests need no installation** — they use only the Python
standard library (Python 3.8+).

The **web dashboard** needs Streamlit:

```bash
pip install -r requirements.txt
```

---

## Usage

### Command line

```bash
# Scan one of the included samples
python cli.py samples/malicious_extension
python cli.py samples/benign_extension

# Scan a .zip or .crx you downloaded
python cli.py path/to/extension.zip

# Get machine-readable JSON instead of text
python cli.py samples/malicious_extension --json
```

### Web dashboard

```bash
streamlit run app.py
```

Then upload a `.zip` / `.crx`, or type the path to an unpacked extension
folder, and read the risk report in your browser.

### As a Python library

```python
from extenshield import scan

report = scan("samples/malicious_extension")
print(report.score, report.level)
for f in report.findings:
    print(f.name, f.reason)
```

---

## Running the tests

```bash
python -m unittest discover -s tests
```

The tests confirm the benign sample scores LOW, the malicious sample scores
HIGH, and that key behaviours (cookie theft, `eval`, `<all_urls>`) are detected.

---

## Limitations & honest scope

This is **static** analysis, so it has known blind spots worth mentioning in
your report (examiners like seeing you understand the limits):

- It cannot see behaviour that only appears at **runtime** (dynamic analysis
  would be needed for that).
- Heavily **obfuscated or minified** code can hide patterns — the tool flags
  obfuscation itself, but cannot always decode it.
- Rules are **heuristics**: a legitimate extension with broad permissions may
  score higher than it deserves (a *false positive*), and a clever attacker
  could avoid the listed patterns (a *false negative*).

---

## Ideas for extending it (future work)

- Add **dynamic analysis** by loading the extension in a headless browser and
  watching its network calls.
- Replace or supplement the fixed weights with a **machine-learning classifier**
  trained on labelled extensions.
- Build a labelled **dataset** and report precision/recall to evaluate accuracy.
- Detect **remote code loading** from the Chrome Web Store policy angle.
