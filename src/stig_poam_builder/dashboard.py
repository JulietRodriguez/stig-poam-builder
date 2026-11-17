"""Optional Streamlit dashboard.

    pip install -e ".[dashboard]"
    stig-poam dashboard            # or: streamlit run src/stig_poam_builder/dashboard.py

Upload checklists/scans (or use the synthetic samples), set the CAT due-date
rules, review the POA&M, and download every output. All processing runs in
this process on a temp directory; nothing is sent anywhere.
"""

from __future__ import annotations

import json
import tempfile
from datetime import UTC, date, datetime
from pathlib import Path

import pandas as pd  # installed with streamlit
import streamlit as st

from stig_poam_builder.config import load_rules
from stig_poam_builder.models import Cat
from stig_poam_builder.outputs import write_csv, write_oscal, write_xlsx
from stig_poam_builder.outputs.columns import emass_row
from stig_poam_builder.pipeline import run
from stig_poam_builder.summary import compute_summary, render_markdown

REPO = Path(__file__).resolve().parents[2]
SAMPLE_INPUTS = REPO / "samples" / "inputs"
SAMPLE_CCI = REPO / "samples" / "cci" / "U_CCI_List_SAMPLE.xml"
HAVE_SAMPLES = SAMPLE_INPUTS.is_dir() and SAMPLE_CCI.is_file()

st.set_page_config(page_title="stig-poam-builder", layout="wide")
st.title("STIG + ACAS → POA&M")
st.caption(
    "Use synthetic or sanitized data only. Never upload CUI or real system data to a "
    "machine that isn't authorized for it."
)

with st.sidebar:
    st.header("Inputs")
    use_samples = st.checkbox(
        "Use synthetic sample data", value=HAVE_SAMPLES, disabled=not HAVE_SAMPLES
    )
    uploads = st.file_uploader(
        "Checklists and scans (.ckl, .cklb, .nessus)",
        type=["ckl", "cklb", "nessus"],
        accept_multiple_files=True,
    )
    cci_upload = st.file_uploader("DISA CCI List (U_CCI_List.xml)", type=["xml"])
    st.header("Rules")
    system = st.text_input("System name", value="Demo System (synthetic)")
    as_of = st.date_input("As-of date", value=date.today())
    cat_i = st.number_input("CAT I days", min_value=1, value=30)
    cat_ii = st.number_input("CAT II days", min_value=1, value=90)
    cat_iii = st.number_input("CAT III days", min_value=1, value=180)
    include_nr = st.checkbox("POA&M Not Reviewed checks too", value=False)

if not uploads and not use_samples:
    st.info("Upload checklists/scans or tick 'Use synthetic sample data' to start.")
    st.stop()

rules = load_rules()
rules.days = {Cat.CAT_I: int(cat_i), Cat.CAT_II: int(cat_ii), Cat.CAT_III: int(cat_iii)}
rules.include_not_reviewed = include_nr

with tempfile.TemporaryDirectory() as tmp:
    tmpdir = Path(tmp)
    inputs: list[Path] = []
    for up in uploads or []:
        dest = tmpdir / Path(up.name).name
        dest.write_bytes(up.getvalue())
        inputs.append(dest)
    if use_samples:
        inputs.append(SAMPLE_INPUTS)
    cci_path: Path | None = None
    if cci_upload is not None:
        cci_path = tmpdir / "U_CCI_List.xml"
        cci_path.write_bytes(cci_upload.getvalue())
    elif use_samples:
        cci_path = SAMPLE_CCI

    try:
        result = run(inputs, rules, as_of, cci_list=cci_path)
    except Exception as exc:  # show parse/config errors in the UI instead of a stack trace
        st.error(f"Could not build the POA&M: {exc}")
        st.stop()

    if cci_path is None:
        st.warning("No CCI List loaded: STIG findings use the fallback control.")

    summary = compute_summary(result)
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("POA&M items", summary["poam_items"])
    c2.metric("Open instances", summary["open_instances"])
    c3.metric("CAT I", summary["items_by_cat"]["CAT I"])
    c4.metric("CAT II", summary["items_by_cat"]["CAT II"])
    c5.metric("CAT III", summary["items_by_cat"]["CAT III"])

    st.subheader("Open POA&M items by control family")
    family = pd.DataFrame.from_dict(
        {fam: v["items"] for fam, v in summary["by_family"].items()}, orient="index"
    )
    if not family.empty:
        st.bar_chart(family)  # index = family, one stacked series per CAT

    st.subheader("POA&M")
    table = pd.DataFrame([emass_row(i, result) for i in result.items])
    st.dataframe(table, hide_index=True)

    st.subheader("Summary")
    st.markdown(render_markdown(summary))

    stem = f"poam_{as_of.isoformat()}"
    xlsx = write_xlsx(result, tmpdir / f"{stem}.xlsx", system_name=system)
    csv_file = write_csv(result, tmpdir / f"{stem}.csv")
    oscal = write_oscal(result, tmpdir / f"{stem}.oscal.json", system, datetime.now(UTC))
    d1, d2, d3, d4 = st.columns(4)
    d1.download_button("eMASS-style XLSX", xlsx.read_bytes(), file_name=xlsx.name)
    d2.download_button("CSV", csv_file.read_bytes(), file_name=csv_file.name)
    d3.download_button("OSCAL 1.1.2 JSON", oscal.read_bytes(), file_name=oscal.name)
    d4.download_button(
        "Summary (JSON)", json.dumps(summary, indent=2), file_name=f"{stem}_summary.json"
    )
