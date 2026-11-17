import json
import subprocess
import sys
import tomllib

import pytest
from openpyxl import load_workbook

from stig_poam_builder import __version__
from stig_poam_builder.cli import main
from stig_poam_builder.outputs import validate_structure
from stig_poam_builder.pipeline import collect_inputs

from .conftest import SAMPLE_CCI, SAMPLES


def _build(tmp_path, *extra):
    return main(
        [
            "build",
            str(SAMPLES),
            "--cci-list",
            str(SAMPLE_CCI),
            "--out",
            str(tmp_path),
            "--as-of",
            "2026-11-17",
            "--system",
            "Demo",
            *extra,
        ]
    )


def test_build_all_outputs(tmp_path, capsys):
    assert _build(tmp_path) == 0
    out = capsys.readouterr().out
    assert "15 POA&M items (5 CAT I, 7 CAT II, 3 CAT III)" in out
    assert "3 checks are Not Reviewed" in out
    assert "CCI-009999" in out
    names = sorted(p.name for p in tmp_path.iterdir())
    assert names == [
        "poam_2026-11-17.csv",
        "poam_2026-11-17.oscal.json",
        "poam_2026-11-17.xlsx",
        "poam_2026-11-17_summary.json",
        "poam_2026-11-17_summary.md",
    ]
    doc = json.loads((tmp_path / "poam_2026-11-17.oscal.json").read_text())
    assert validate_structure(doc) == []
    wb = load_workbook(tmp_path / "poam_2026-11-17.xlsx")
    assert wb["POA&M"].max_row == 16


def test_build_selected_formats_and_not_reviewed(tmp_path, capsys):
    assert _build(tmp_path, "--formats", "csv", "--include-not-reviewed") == 0
    assert [p.name for p in tmp_path.iterdir()] == ["poam_2026-11-17.csv"]
    out = capsys.readouterr().out
    assert "Not Reviewed" not in out  # included, so no gap note


def test_build_with_rules_file(tmp_path):
    rules = tmp_path / "rules.toml"
    rules.write_text("[schedule]\ncat_i_days = 7\n")
    assert _build(tmp_path / "o", "--rules", str(rules), "--formats", "summary") == 0
    s = json.loads((tmp_path / "o" / "poam_2026-11-17_summary.json").read_text())
    assert s["poam_items"] == 15


def test_build_without_cci_list_warns(tmp_path, capsys):
    rc = main(["build", str(SAMPLES), "--out", str(tmp_path), "--formats", "summary"])
    assert rc == 0
    assert "no --cci-list" in capsys.readouterr().err


def test_errors_return_2(tmp_path, capsys):
    assert main(["build", str(tmp_path / "missing.ckl"), "--out", str(tmp_path)]) == 2
    bad = tmp_path / "bad.ckl"
    bad.write_text("<nope/>")
    assert main(["build", str(bad), "--out", str(tmp_path)]) == 2
    rules = tmp_path / "r.toml"
    rules.write_text("[schedule]\ncat_i_days = -1\n")
    assert main(["build", str(SAMPLES), "--rules", str(rules), "--out", str(tmp_path)]) == 2
    assert "error:" in capsys.readouterr().err


@pytest.mark.parametrize("args", [["--as-of", "11/17/2026"], ["--formats", "pdf"]])
def test_bad_arguments_exit(tmp_path, args):
    with pytest.raises(SystemExit):
        main(["build", str(SAMPLES), "--out", str(tmp_path), *args])


def test_init_rules(capsys):
    assert main(["init-rules"]) == 0
    parsed = tomllib.loads(capsys.readouterr().out)
    assert parsed["schedule"]["cat_i_days"] == 30


def test_version(capsys):
    with pytest.raises(SystemExit):
        main(["--version"])
    assert __version__ in capsys.readouterr().out


def test_collect_inputs(tmp_path):
    files = collect_inputs([SAMPLES, SAMPLES / "web01_demo-os.ckl"])
    assert len(files) == 4  # directory + duplicate explicit file collapse
    other = tmp_path / "notes.txt"
    other.write_text("x")
    assert collect_inputs([tmp_path]) == []  # non-input extensions ignored in dirs
    assert collect_inputs([other]) == [other]  # but explicit files are kept


def test_module_entry_point():
    proc = subprocess.run(
        [sys.executable, "-m", "stig_poam_builder", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert __version__ in proc.stdout


def test_dashboard_requires_streamlit(monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "streamlit", None)  # force ImportError
    assert main(["dashboard"]) == 2
    assert "pip install" in capsys.readouterr().err


def test_dashboard_launches_streamlit(monkeypatch):
    import types

    import stig_poam_builder.cli as cli

    monkeypatch.setitem(sys.modules, "streamlit", types.ModuleType("streamlit"))
    seen = {}
    monkeypatch.setattr(cli.subprocess, "call", lambda cmd: seen.setdefault("cmd", cmd) and 0)
    assert main(["dashboard"]) == 0
    assert seen["cmd"][1:4] == ["-m", "streamlit", "run"]
    assert seen["cmd"][4].endswith("dashboard.py")
