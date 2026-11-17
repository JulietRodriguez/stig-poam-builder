"""Runs the Streamlit app headlessly with Streamlit's own AppTest harness.

Skipped when Streamlit isn't installed (it's an optional extra); CI installs it
in a dedicated job.
"""

from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest

APP = Path(__file__).resolve().parent.parent / "src" / "stig_poam_builder" / "dashboard.py"


def test_dashboard_runs_on_samples():
    at = AppTest.from_file(str(APP), default_timeout=60).run()
    assert not at.exception
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["POA&M items"] == "15"
    assert metrics["CAT I"] == "5"


def test_dashboard_without_inputs_prompts():
    at = AppTest.from_file(str(APP), default_timeout=60).run()
    at.sidebar.checkbox[0].uncheck().run()
    assert not at.exception
    assert any("Upload checklists" in i.value for i in at.info)
