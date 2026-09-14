# app.py
# The ChromeShield web dashboard (Streamlit).
# Run it with: streamlit run app.py
# It scans an extension by link or upload and shows the risk report.
# Only the look is in this file - the scanning is in the chromeshield package.

import html
import tempfile
from pathlib import Path

import streamlit as st

from chromeshield import scan, scan_url
from chromeshield.report import RISK_BANDS
from chromeshield.webstore import NotAnExtensionError

st.set_page_config(page_title="ChromeShield", page_icon="🛡️", layout="wide")

# colours for each level and severity
LEVEL_COLOURS = {
    "MINIMAL": "#2e7d32",
    "LOW": "#9e9d24",
    "MEDIUM": "#ef6c00",
    "HIGH": "#c62828",
}
# gradient pairs for the score card
LEVEL_GRAD = {
    "MINIMAL": ("#43a047", "#2e7d32"),
    "LOW": ("#c0ca33", "#9e9d24"),
    "MEDIUM": ("#fb8c00", "#e65100"),
    "HIGH": ("#e53935", "#b71c1c"),
}
SEVERITY_COLOURS = {"high": "#c62828", "medium": "#ef6c00", "low": "#2e7d32"}

# keep scans between reruns for the recent-scans list
st.session_state.setdefault("history", [])
st.session_state.setdefault("report", None)


def remember(report):
    # add a scan to the recent list
    st.session_state.history.insert(0, report)
    st.session_state.history = st.session_state.history[:30]  # keep last 30
    st.session_state.report = report


# ---- styling (CSS) ----
CSS = """
<style>
  [data-testid="stToolbar"] {visibility: hidden;}
  header[data-testid="stHeader"] {display: none;}
  .stApp {
    background: linear-gradient(160deg, #f0eefe 0%, #e9eeff 50%, #e6f0ff 100%);
    background-attachment: fixed;
  }
  .block-container {padding-top: 1rem;}
  .stTabs [data-baseweb="tab"] {font-size: 16px; font-weight: 600;}

  /* top bar */
  .es-topbar {display:flex; justify-content:space-between; align-items:center; padding: 2px 6px 10px;}
  .es-topbar .brand {display:flex; align-items:center; gap:8px; font-weight:800; font-size:22px; color:#241a4d;}
  .es-topbar .nav {font-size:13px; color:#4a4a6a; font-weight:600;}

  /* hero */
  .es-hero {display:flex; align-items:center; gap:26px;
    background: linear-gradient(120deg, #6a11cb 0%, #3b5bff 55%, #2575fc 100%);
    border-radius: 22px; padding: 30px 36px; color:#fff; margin-bottom: 18px;
    box-shadow: 0 16px 40px rgba(101,87,255,.35);}
  .es-hero-icon {font-size: 56px; width:118px; height:118px; border-radius:50%; flex:0 0 auto;
    background: radial-gradient(circle at 40% 35%, rgba(255,255,255,.38), rgba(255,255,255,.06));
    display:flex; align-items:center; justify-content:center;
    box-shadow: 0 0 42px rgba(150,190,255,.55), inset 0 0 22px rgba(255,255,255,.25);}
  .es-hero .t {font-size: 40px; font-weight: 800; line-height: 1;}
  .es-hero .s {opacity:.95; margin-top: 8px; font-size: 16px;}
  .es-pill {display:inline-block; background: rgba(255,255,255,.16); color:#fff;
    padding: 7px 16px; border-radius: 999px; font-size: 13.5px; font-weight: 600;
    margin: 14px 8px 0 0; border: 1px solid rgba(255,255,255,.18);}

  /* big score card */
  .es-score {display:flex; align-items:center; gap:22px; border-radius:16px; padding:22px 26px;
    color:#fff; box-shadow:0 12px 28px rgba(0,0,0,.15); margin-bottom:12px;}
  .es-score-ic {font-size:44px; width:92px; height:92px; border-radius:50%; flex:0 0 auto;
    background:rgba(255,255,255,.18); display:flex; align-items:center; justify-content:center;}
  .es-score-name {font-size:14px; opacity:.9;}
  .es-score-num {font-size:46px; font-weight:800; line-height:1.05;}
  .es-score-lvl {display:inline-block; background:rgba(255,255,255,.22); padding:4px 13px;
    border-radius:8px; font-weight:800; font-size:14px; margin-top:5px; letter-spacing:.3px;}
  .es-score-sum {font-size:14px; margin-top:9px; opacity:.95;}

  /* white content panel */
  .es-panel {background:#fff; border:1px solid #e8ebf0; border-radius:16px; padding:18px 20px;
    margin:10px 0; box-shadow:0 3px 12px rgba(20,30,50,.05);}
  .es-ptitle {font-size:20px; font-weight:800; color:#1f2937; margin:2px 0 12px;}

  /* metric cards */
  .es-metrics {display:flex; gap:14px; flex-wrap:wrap;}
  .es-mcard {flex:1 1 150px; display:flex; align-items:center; gap:12px; border-radius:12px; padding:14px 16px;}
  .es-mcard.purple {background:#f1ecff;} .es-mcard.green {background:#e8f7ee;} .es-mcard.blue {background:#e9f1ff;}
  .es-micon {width:40px; height:40px; border-radius:10px; background:#fff; display:flex;
    align-items:center; justify-content:center; font-size:18px; box-shadow:0 2px 6px rgba(0,0,0,.06);}
  .es-mlabel {font-size:13px; color:#64748b;}
  .es-mval {font-size:22px; font-weight:800; color:#1f2937;}

  .es-desc {color:#64748b; font-size:13px; margin:12px 0 0; background:#f5f7fb; padding:9px 13px; border-radius:9px;}
  .es-access {margin-top:12px; font-size:13px; color:#334155; background:#f5f7fb; padding:10px 13px; border-radius:11px;}
  .es-alabel {font-weight:700; color:#475569; margin-right:6px;}
  .es-chip {display:inline-block; background:#eef2f7; color:#334155; font-size:12.5px;
    padding:4px 11px; border-radius:999px; margin:3px 5px 3px 0;}
  .es-dot {display:inline-block; width:7px; height:7px; border-radius:50%; background:#2e7d32;
    margin-right:6px; vertical-align:middle;}
  .es-chip.blue {background:#e9f1ff;} .es-dot.blue {background:#2575fc;}
  .es-muted {color:#94a3b8; font-size:13px;}

  /* finding cards */
  .es-find {background:#fff; border:1px solid #eef0f4; border-left:5px solid #999; border-radius:12px;
    padding:12px 16px; margin-bottom:10px; box-shadow:0 2px 8px rgba(20,30,50,.04);}
  .es-find-top {display:flex; align-items:center; gap:10px; flex-wrap:wrap;}
  .es-badge {color:#fff; font-size:11px; font-weight:800; padding:2px 9px; border-radius:6px; letter-spacing:.4px;}
  .es-fname {font-weight:700; color:#1f2937; font-size:15px;}
  .es-pts {background:#e8f7ee; color:#2e7d32; font-size:12px; font-weight:700; padding:2px 10px; border-radius:999px;}
  .es-freason {color:#475569; font-size:14px; margin-top:6px;}
  .es-fev {color:#94a3b8; font-size:12px; margin-top:6px; font-family:ui-monospace,monospace; word-break:break-all;}

  /* side panel */
  .es-side {background:#fff; border:1px solid #e8ebf0; border-radius:16px; padding:18px 20px;
    margin-bottom:16px; box-shadow:0 4px 14px rgba(20,30,50,.06);}
  .es-h {font-size:16px; color:#1f2937; font-weight:800; margin:0 0 14px; display:flex; align-items:center; gap:8px;}
  .es-fmt {display:flex; align-items:center; gap:12px; margin-bottom:12px;}
  .es-fmt .ic {width:38px; height:38px; border-radius:10px; display:flex; align-items:center;
    justify-content:center; font-size:16px;}
  .es-fmt .ic.teal {background:#d7f5ef;} .es-fmt .ic.blue {background:#e0ebff;} .es-fmt .ic.purple {background:#efe7ff;}
  .es-fmt .nm {font-weight:700; font-size:14px; color:#1f2937;}
  .es-fmt .ds {font-size:12.5px; color:#94a3b8;}
  .es-tip {color:#475569; font-size:13.5px; margin-bottom:9px; display:flex; align-items:flex-start; gap:8px;}
  .es-tip .ck {color:#2e7d32; font-weight:800;}
</style>
"""


def show_report(report):
    grad = LEVEL_GRAD.get(report.level, ("#666", "#333"))

    # score card
    st.markdown(
        f"""
        <div class="es-score" style="background:linear-gradient(135deg,{grad[0]} 0%,{grad[1]} 100%);">
          <div class="es-score-ic">🛡️</div>
          <div>
            <div class="es-score-name">{html.escape(report.extension_name)}</div>
            <div class="es-score-num">{report.score}/100</div>
            <div class="es-score-lvl">{report.level} RISK</div>
            <div class="es-score-sum">{html.escape(report.summary)}</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.expander("ℹ️ How is this rating determined?"):
        st.write(
            "Each risky thing found — a dangerous permission, broad website "
            "access, or a suspicious code pattern — adds **risk points**. The "
            "points are added up (capped at 100) to give the score, which falls "
            "into one of these bands:"
        )
        for low, high, level, meaning in RISK_BANDS:
            c = LEVEL_COLOURS.get(level, "#555")
            here = " ⬅️ **this extension**" if level == report.level else ""
            st.markdown(
                f"<span style='color:{c}; font-weight:700;'>{level}</span> "
                f"`{low}–{high}` — {meaning}{here}",
                unsafe_allow_html=True,
            )

    # extension scanned panel
    perms = report.permissions
    chips = "".join(
        f'<span class="es-chip"><span class="es-dot"></span>{html.escape(p)}</span>'
        for p in perms
    ) or '<span class="es-muted">none requested</span>'
    hosts = "".join(
        f'<span class="es-chip blue"><span class="es-dot blue"></span>{html.escape(h)}</span>'
        for h in report.host_permissions
    )
    desc = (f'<div class="es-desc">{html.escape(report.description)}</div>'
            if report.description else "")
    host_row = (f'<div class="es-access"><span class="es-alabel">&lt;/&gt; Website access:</span>{hosts}</div>'
                if report.host_permissions else "")
    st.markdown(
        f"""
        <div class="es-panel">
          <div class="es-ptitle">🔍 Extension scanned</div>
          <div class="es-metrics">
            <div class="es-mcard purple"><div class="es-micon">📦</div>
              <div><div class="es-mlabel">Version</div><div class="es-mval">{html.escape(str(report.version))}</div></div></div>
            <div class="es-mcard green"><div class="es-micon">👥</div>
              <div><div class="es-mlabel">Permissions</div><div class="es-mval">{len(perms)}</div></div></div>
            <div class="es-mcard blue"><div class="es-micon">📄</div>
              <div><div class="es-mlabel">Script files</div><div class="es-mval">{report.num_js_files}</div></div></div>
          </div>
          {desc}
          <div class="es-access"><span class="es-alabel">🛡️ Permissions:</span>{chips}</div>
          {host_row}
        </div>
        """,
        unsafe_allow_html=True,
    )

    # findings
    st.markdown('<div class="es-ptitle">🚩 Findings</div>', unsafe_allow_html=True)
    if not report.findings:
        st.success("No risky behaviour detected.")
        return
    st.markdown(
        f'<div class="es-muted" style="margin-bottom:10px;">{len(report.findings)} risky behaviour(s) found:</div>',
        unsafe_allow_html=True,
    )
    cards = ""
    for f in report.findings:
        c = SEVERITY_COLOURS.get(f.severity, "#999")
        cards += f"""
        <div class="es-find" style="border-left-color:{c};">
          <div class="es-find-top">
            <span class="es-badge" style="background:{c};">{f.severity.upper()}</span>
            <span class="es-fname">{html.escape(f.name)}</span>
            <span class="es-pts">+{f.weight} points</span>
          </div>
          <div class="es-freason">{html.escape(f.reason)}</div>
          <div class="es-fev">Evidence: {html.escape(f.evidence)}</div>
        </div>"""
    st.markdown(cards, unsafe_allow_html=True)


def side_panel():
    # right side panel: formats, tips, recent scans
    st.markdown(
        """
        <div class="es-side">
          <div class="es-h">📦 Supported Formats</div>
          <div class="es-fmt"><div class="ic teal">🔗</div>
            <div><div class="nm">Web Store link</div><div class="ds">Paste a Chrome Web Store URL</div></div></div>
          <div class="es-fmt"><div class="ic blue">📄</div>
            <div><div class="nm">.zip</div><div class="ds">Extension package (zipped)</div></div></div>
          <div class="es-fmt"><div class="ic purple">🧩</div>
            <div><div class="nm">.crx</div><div class="ds">Chrome extension file</div></div></div>
        </div>
        <div class="es-side">
          <div class="es-h">💡 Tips</div>
          <div class="es-tip"><span class="ck">✔</span> Only install extensions from trusted sources</div>
          <div class="es-tip"><span class="ck">✔</span> Review scan results carefully</div>
          <div class="es-tip"><span class="ck">✔</span> Scanning never runs the extension — it's safe</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # recent scans as buttons - click to reopen a result
    st.markdown('<div class="es-h" style="margin:2px 2px 10px;">🕘 Recent Scans</div>',
                unsafe_allow_html=True)
    if st.session_state.history:
        with st.container(height=320):
            for i, rep in enumerate(st.session_state.history):
                label = f"{rep.extension_name[:18]}  ·  {rep.score} {rep.level}"
                if st.button(label, key=f"recent_{i}", use_container_width=True):
                    st.session_state.report = rep
                    st.rerun()  # rerun so it shows by the scan box
    else:
        st.caption("No scans yet.")


# ---- page layout ----
st.markdown(CSS, unsafe_allow_html=True)

st.markdown(
    """
    <div class="es-topbar">
      <div class="brand">🛡️ ChromeShield</div>
      <div class="nav">🔒 Security First &nbsp;•&nbsp; Rule-Based Detection</div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="es-hero">
      <div class="es-hero-icon">🛡️</div>
      <div>
        <div class="t">ChromeShield</div>
        <div class="s">Scan a Chrome extension for malicious behaviour before you install it.</div>
        <div>
          <span class="es-pill">⚡ Fast Scanning</span>
          <span class="es-pill">🔒 Privacy Focused</span>
          <span class="es-pill">🛡️ Rule-Based Detection</span>
        </div>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

left, right = st.columns([2, 1], gap="large")

with left:
    tab_url, tab_upload = st.tabs(["🔗 Web Store link", "📁 Upload .zip / .crx"])

    with tab_url:
        url = st.text_input(
            "Chrome Web Store link or extension ID",
            placeholder="https://chromewebstore.google.com/detail/name/<extension-id>",
        )
        if st.button("Scan extension", type="primary") and url:
            with st.spinner("Downloading and scanning the extension..."):
                try:
                    remember(scan_url(url))
                except NotAnExtensionError as exc:
                    st.session_state.report = None
                    st.warning(f"⚠️ {exc}")
                except ConnectionError as exc:
                    st.session_state.report = None
                    st.error(f"🌐 {exc}")
                except Exception as exc:
                    st.session_state.report = None
                    st.error(f"Could not scan this extension: {exc}")

    with tab_upload:
        st.caption("Already have the extension as a file? Upload its .zip or .crx.")
        uploaded = st.file_uploader("Choose an extension package")
        if uploaded is not None:
            suffix = Path(uploaded.name).suffix.lower()
            if suffix not in (".zip", ".crx"):
                st.session_state.report = None
                st.warning("⚠️ That's not a Chrome extension package. Please upload "
                           "the extension's .zip or .crx file.")
            else:
                with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                    tmp.write(uploaded.getbuffer())
                    tmp_path = tmp.name
                try:
                    remember(scan(tmp_path))
                except (ValueError, FileNotFoundError):
                    st.session_state.report = None
                    st.warning("⚠️ This file is not a Chrome extension. Please upload "
                               "a valid extension package (.zip or .crx).")
                except Exception as exc:
                    st.session_state.report = None
                    st.error(f"Could not analyze this file: {exc}")

    # show the result below the scan box
    if st.session_state.report is not None:
        st.write("")
        show_report(st.session_state.report)

with right:
    side_panel()
