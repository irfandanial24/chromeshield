"""
app.py
------
A simple web dashboard for ExtenShield, built with Streamlit.

Run it with:
    streamlit run app.py

What it does:
  - lets you upload a .zip or .crx extension (or type a folder path)
  - runs the static analyzer
  - shows the risk score, level, and every finding with an explanation

Streamlit is used because it turns a plain Python script into a web app with
almost no boilerplate - good for a demo you have to present.
"""

import tempfile
from pathlib import Path

import streamlit as st

from extenshield import scan, scan_url
from extenshield.report import RISK_BANDS

st.set_page_config(page_title="ExtenShield", page_icon="🛡️", layout="centered")

# Colours for each risk level (used in the score banner).
LEVEL_COLOURS = {
    "MINIMAL": "#2e7d32",
    "LOW": "#9e9d24",
    "MEDIUM": "#ef6c00",
    "HIGH": "#c62828",
}
SEVERITY_COLOURS = {"high": "#c62828", "medium": "#ef6c00", "low": "#2e7d32"}


def show_report(report):
    colour = LEVEL_COLOURS.get(report.level, "#555")
    st.markdown(
        f"""
        <div style="border-radius:12px;padding:20px;background:{colour};color:white;text-align:center;">
            <div style="font-size:14px;opacity:0.85;">{report.extension_name}</div>
            <div style="font-size:48px;font-weight:700;">{report.score}/100</div>
            <div style="font-size:22px;font-weight:600;">{report.level} RISK</div>
            <div style="font-size:14px;margin-top:6px;">{report.summary}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # --- Score position on a 0-100 scale ---
    st.progress(report.score / 100)

    # --- How the level was decided (transparent scoring) ---
    with st.expander("ℹ️ How is this rating determined?"):
        st.write(
            "Every risky thing ExtenShield finds — a dangerous permission, "
            "broad website access, or a suspicious code pattern — adds a number "
            "of **risk points**. The points are added up (and capped at 100) to "
            "give the score. The score then falls into one of these bands:"
        )
        for low, high, level, meaning in RISK_BANDS:
            colour = LEVEL_COLOURS.get(level, "#555")
            here = " &nbsp;⬅️ **this extension**" if level == report.level else ""
            st.markdown(
                f"<span style='color:{colour};font-weight:700;'>{level}</span> "
                f"&nbsp;`{low}–{high}` &nbsp;— {meaning}{here}",
                unsafe_allow_html=True,
            )
        st.caption(
            f"This extension scored {report.score}, which lands in the "
            f"{report.level} band."
        )

    st.write("")

    # --- What was scanned (so the user sees exactly which extension this is) ---
    with st.container(border=True):
        st.markdown("#### 🔍 Extension scanned")
        c1, c2 = st.columns(2)
        c1.markdown(f"**Name:** {report.extension_name}")
        c1.markdown(f"**Version:** {report.version}")
        c2.markdown(f"**Permissions requested:** {len(report.permissions)}")
        c2.markdown(f"**Script files analysed:** {report.num_js_files}")
        if report.description:
            st.caption(report.description)
        if report.permissions:
            st.markdown("**Permissions:** " +
                        ", ".join(f"`{p}`" for p in report.permissions))
        if report.host_permissions:
            st.markdown("**Website access:** " +
                        ", ".join(f"`{h}`" for h in report.host_permissions))

    st.write("")
    if not report.findings:
        st.success("No risky behaviour detected.")
        return

    st.subheader(f"{len(report.findings)} finding(s)")
    for f in report.findings:
        sev_colour = SEVERITY_COLOURS.get(f.severity, "#555")
        with st.container(border=True):
            st.markdown(
                f"<span style='color:{sev_colour};font-weight:700;'>"
                f"{f.severity.upper()}</span> &nbsp; "
                f"<b>{f.name}</b> &nbsp; <code>+{f.weight}</code>",
                unsafe_allow_html=True,
            )
            st.write(f.reason)
            st.caption(f"Evidence: {f.evidence}")


st.title("🛡️ ExtenShield")
st.caption("Rule-based static analysis for detecting malicious Chrome extensions.")

tab_url, tab_upload = st.tabs(["🔗 Web Store link", "📁 Upload .zip / .crx"])

with tab_url:
    st.caption("Paste a Chrome Web Store link (or just the extension ID) and "
               "ExtenShield will download the extension and scan it for you.")
    url = st.text_input(
        "Chrome Web Store link or extension ID",
        placeholder="https://chromewebstore.google.com/detail/name/<extension-id>",
    )
    if st.button("Scan extension") and url:
        with st.spinner("Downloading and scanning the extension..."):
            try:
                report = scan_url(url)
                show_report(report)
            except Exception as exc:  # noqa: BLE001 - show a friendly message
                st.error(f"Could not scan this extension: {exc}")

with tab_upload:
    st.caption("Already have the extension as a file? Upload its .zip or .crx.")
    uploaded = st.file_uploader("Choose an extension package", type=["zip", "crx"])
    if uploaded is not None:
        suffix = Path(uploaded.name).suffix
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(uploaded.getbuffer())
            tmp_path = tmp.name
        try:
            report = scan(tmp_path)
            show_report(report)
        except Exception as exc:  # noqa: BLE001 - show any load/parse error to user
            st.error(f"Could not analyze this file: {exc}")
