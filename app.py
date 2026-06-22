"""
app.py
------
The ExtenShield web dashboard, built with Streamlit.

Run it with:
    streamlit run app.py

It lets you scan a Chrome extension (by Web Store link or by uploading its
.zip / .crx) and shows a colourful risk report: the score, what was scanned,
how the rating was decided, and every risky behaviour found. A side panel lists
supported formats, tips, and your recent scans.
"""

import html
import tempfile
from pathlib import Path

import streamlit as st

from extenshield import scan, scan_url
from extenshield.report import RISK_BANDS
from extenshield.webstore import NotAnExtensionError

st.set_page_config(page_title="ExtenShield", page_icon="🛡️", layout="wide")

# Colours for each risk level and finding severity.
LEVEL_COLOURS = {
    "MINIMAL": "#2e7d32",
    "LOW": "#9e9d24",
    "MEDIUM": "#ef6c00",
    "HIGH": "#c62828",
}
SEVERITY_COLOURS = {"high": "#c62828", "medium": "#ef6c00", "low": "#2e7d32"}

# Remember scan results between reruns so we can show "Recent Scans".
st.session_state.setdefault("history", [])
st.session_state.setdefault("report", None)


def remember(report):
    """Add a scan to the recent-scans history (keep the latest few)."""
    st.session_state.history.insert(0, report)
    st.session_state.history = st.session_state.history[:30]  # keep up to 30
    st.session_state.report = report


# ---------------------------------------------------------------------------
# Styling
# ---------------------------------------------------------------------------
CSS = """
<style>
  [data-testid="stToolbar"] {visibility: hidden;}
  /* Remove Streamlit's default white header bar at the very top. */
  header[data-testid="stHeader"] {display: none;}
  .stApp {
    background: linear-gradient(135deg, #e0c3fc 0%, #8ec5fc 100%);
    background-attachment: fixed;
  }
  .block-container {padding-top: 1rem;}
  .stTabs [data-baseweb="tab"] {font-size: 16px; font-weight: 600;}
  div[data-testid="stMetric"] {
    background: #f3f6ff; border: 1px solid #e2e8ff;
    border-radius: 12px; padding: 12px 14px;
  }

  .es-topbar {display:flex; justify-content:space-between; align-items:center;
    padding: 4px 6px 12px;}
  .es-topbar .brand {display:flex; align-items:center; gap:8px;
    font-weight:800; font-size:20px; color:#26203f;}
  .es-topbar .nav {font-size:13px; color:#4a4a6a; font-weight:600;}

  .es-hero {background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%);
    border-radius: 18px; padding: 28px 32px; color:#fff; margin-bottom: 16px;
    box-shadow: 0 12px 30px rgba(101,87,255,.30);}
  .es-hero .t {font-size: 32px; font-weight: 800;}
  .es-hero .s {opacity:.92; margin-top: 6px; font-size: 15px; max-width: 540px;}
  .es-pill {display:inline-block; background: rgba(255,255,255,.18);
    color:#fff; padding: 6px 14px; border-radius: 999px; font-size: 13px;
    font-weight: 600; margin: 12px 8px 0 0;}

  .es-side {background:#fff; border:1px solid #e8ebf0; border-radius:14px;
    padding: 16px 18px; margin-bottom: 14px; box-shadow: 0 3px 12px rgba(20,30,50,.06);}
  .es-side h4 {margin:0 0 12px; font-size:14px; color:#1f2937; font-weight:700;}
  .es-h {font-size:14px; color:#1f2937; font-weight:700; margin:0 0 12px;}
  .es-fmt {display:flex; align-items:center; gap:10px; margin-bottom:10px;}
  .es-fmt .ic {width:30px; height:30px; border-radius:8px; background:#eef2ff;
    display:flex; align-items:center; justify-content:center; font-size:15px;}
  .es-fmt .nm {font-weight:700; font-size:13px; color:#1f2937;}
  .es-fmt .ds {font-size:12px; color:#94a3b8;}
  .es-tip {color:#475569; font-size:13px; margin-bottom:7px;}
  .es-recent {display:flex; justify-content:space-between; align-items:center;
    padding:8px 0; border-bottom:1px solid #f1f3f7; font-size:13px; color:#334155;}
</style>
"""


def show_report(report):
    colour = LEVEL_COLOURS.get(report.level, "#555")

    st.markdown(
        f"""
        <div style="border-radius:14px; padding:20px; background:{colour};
                    color:white; text-align:center;">
            <div style="font-size:14px; opacity:0.85;">{html.escape(report.extension_name)}</div>
            <div style="font-size:46px; font-weight:800;">{report.score}/100</div>
            <div style="font-size:20px; font-weight:700;">{report.level} RISK</div>
            <div style="font-size:14px; margin-top:4px;">{html.escape(report.summary)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.progress(report.score / 100)

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

    st.subheader("🔍 Extension scanned")
    c1, c2, c3 = st.columns(3)
    c1.metric("Version", report.version)
    c2.metric("Permissions", len(report.permissions))
    c3.metric("Script files", report.num_js_files)
    if report.description:
        st.caption(report.description)
    if report.permissions:
        st.write("**Permissions:** " + ", ".join(f"`{p}`" for p in report.permissions))
    if report.host_permissions:
        st.write("**Website access:** " +
                 ", ".join(f"`{h}`" for h in report.host_permissions))

    st.subheader("🚩 Findings")
    if not report.findings:
        st.success("No risky behaviour detected.")
        return
    st.write(f"{len(report.findings)} risky behaviour(s) found:")
    for f in report.findings:
        c = SEVERITY_COLOURS.get(f.severity, "#555")
        with st.container(border=True):
            st.markdown(
                f"<span style='color:{c}; font-weight:700;'>{f.severity.upper()}</span> "
                f"&nbsp; **{html.escape(f.name)}** &nbsp; `+{f.weight} points`",
                unsafe_allow_html=True,
            )
            st.write(f.reason)
            st.caption(f"Evidence: {f.evidence}")


def side_panel():
    """The right-hand panel: supported formats, tips, and recent scans."""
    st.markdown(
        """
        <div class="es-side">
          <div class="es-h">📦 Supported Formats</div>
          <div class="es-fmt"><div class="ic">🔗</div>
            <div><div class="nm">Web Store link</div><div class="ds">Paste a Chrome Web Store URL</div></div></div>
          <div class="es-fmt"><div class="ic">📄</div>
            <div><div class="nm">.zip</div><div class="ds">Extension package (zipped)</div></div></div>
          <div class="es-fmt"><div class="ic">🧩</div>
            <div><div class="nm">.crx</div><div class="ds">Chrome extension file</div></div></div>
        </div>
        <div class="es-side">
          <div class="es-h">💡 Tips</div>
          <div class="es-tip">✔️ Only install extensions from trusted sources</div>
          <div class="es-tip">✔️ Review scan results carefully</div>
          <div class="es-tip">✔️ Scanning never runs the extension — it's safe</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Recent scans as clickable buttons — clicking one re-opens that result.
    st.markdown('<div class="es-h" style="margin:2px 2px 8px;">🕘 Recent Scans</div>',
                unsafe_allow_html=True)
    if st.session_state.history:
        # A fixed-height container: when there are many scans, this box scrolls
        # instead of making the whole page longer.
        with st.container(height=320):
            for i, rep in enumerate(st.session_state.history):
                label = f"{rep.extension_name[:18]}  ·  {rep.score} {rep.level}"
                if st.button(label, key=f"recent_{i}", use_container_width=True):
                    st.session_state.report = rep
                    st.rerun()  # re-run so the result shows up by the scan box
    else:
        st.caption("No scans yet.")


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------
st.markdown(CSS, unsafe_allow_html=True)

st.markdown(
    """
    <div class="es-topbar">
      <div class="brand">🛡️ ExtenShield</div>
      <div class="nav">🔒 Security First &nbsp;•&nbsp; Rule-Based Detection</div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="es-hero">
      <div class="t">🛡️ ExtenShield</div>
      <div class="s">Scan a Chrome extension for malicious behaviour before you install it.</div>
      <div>
        <span class="es-pill">⚡ Fast Scanning</span>
        <span class="es-pill">🔒 Privacy Focused</span>
        <span class="es-pill">📋 Rule-Based Detection</span>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

left, right = st.columns([2, 1], gap="large")

with left:
    tab_url, tab_upload = st.tabs(["🔗 Web Store link", "📁 Upload .zip / .crx"])

    with tab_url:
        st.caption("Paste a Chrome Web Store link (or just the extension ID) and "
                   "ExtenShield will download the extension and scan it.")
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
                except Exception as exc:  # noqa: BLE001
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
                except Exception as exc:  # noqa: BLE001
                    st.session_state.report = None
                    st.error(f"Could not analyze this file: {exc}")

    # Show the result right here, just below the scan box (no long scroll).
    if st.session_state.report is not None:
        st.write("")
        show_report(st.session_state.report)

with right:
    side_panel()
