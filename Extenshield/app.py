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

from extenshield import scan

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

tab_upload, tab_path = st.tabs(["Upload .zip / .crx", "Scan a folder path"])

with tab_upload:
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

with tab_path:
    folder = st.text_input("Path to an unpacked extension folder",
                           placeholder="samples/malicious_extension")
    if st.button("Scan folder") and folder:
        try:
            report = scan(folder)
            show_report(report)
        except Exception as exc:  # noqa: BLE001
            st.error(f"Could not analyze this folder: {exc}")
