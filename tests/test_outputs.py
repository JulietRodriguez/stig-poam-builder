import csv
import json
import os
from dataclasses import replace
from datetime import UTC, date, datetime
from pathlib import Path

import pytest
from openpyxl import load_workbook

from stig_poam_builder.config import load_rules
from stig_poam_builder.models import Asset, Cat, Finding, SourceType, Status
from stig_poam_builder.outputs import (
    build_oscal_poam,
    validate_structure,
    write_csv,
    write_oscal,
    write_xlsx,
)
from stig_poam_builder.outputs.columns import (
    EMASS_COLUMNS,
    adjusted_severity,
    raw_severity,
    safe_cell,
)
from stig_poam_builder.outputs.csv_out import CSV_COLUMNS
from stig_poam_builder.outputs.oscal import statement_id
from stig_poam_builder.poam import build_poam

from .conftest import AS_OF, ROOT

GEN_AT = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)


def _evil_result():
    """A finding whose text tries spreadsheet formula injection."""
    f = Finding(
        source_type=SourceType.CKL,
        source_file="evil.ckl",
        asset=Asset(hostname="=cmd|' /C calc'!A0"),
        check_id="V-1",
        title='=HYPERLINK("http://evil.example","click")',
        status=Status.OPEN,
        cat=Cat.CAT_I,
        fix_text="@SUM(1+1)",
    )
    return build_poam([f], None, load_rules(), AS_OF)


# ---------- column helpers ----------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("=1+1", "'=1+1"),
        ("+1", "'+1"),
        ("-1", "'-1"),
        ("@x", "'@x"),
        ("normal", "normal"),
        (5, 5),
        (None, None),
    ],
)
def test_safe_cell(value, expected):
    assert safe_cell(value) == expected


def test_raw_and_adjusted_severity(result):
    by_id = {i.item_id: i for i in result.items}
    assert raw_severity(by_id["V-900001"]) == "High"  # CAT I
    assert raw_severity(by_id["V-900002"]) == "Moderate"  # CAT II
    assert raw_severity(by_id["V-900005"]) == "Low"  # CAT III
    assert raw_severity(by_id["ACAS-900101"]) == "Very High"  # Nessus critical
    assert raw_severity(by_id["ACAS-900103"]) == "High"  # Nessus high
    v3 = replace(by_id["V-900003"], cat=Cat.CAT_III)
    assert adjusted_severity(v3) == "Low"
    info = replace(by_id["ACAS-900104"], nessus_severity=0)
    assert raw_severity(info) == "Very Low"


# ---------- CSV ----------


def test_csv(result, tmp_path):
    path = write_csv(result, tmp_path / "poam.csv")
    with path.open(encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert list(rows[0].keys()) == CSV_COLUMNS
    assert len(rows) == len(result.items)
    first = rows[0]
    assert first["POA&M Item ID"] == result.items[0].item_id
    assert first["Scheduled Completion Date"] == result.items[0].scheduled_completion.isoformat()
    assert first["Status"] == "Ongoing"
    v10 = next(r for r in rows if r["POA&M Item ID"] == "V-900010")
    assert v10["Mapping Basis"] == "Fallback: no mapped CCI"
    assert v10["Unmapped CCIs"] == "CCI-009999"


def test_csv_neutralizes_formulas(tmp_path):
    path = write_csv(_evil_result(), tmp_path / "evil.csv")
    text = path.read_text(encoding="utf-8-sig")
    assert "'=HYPERLINK" in text
    assert "'@SUM" in text
    assert "'=cmd" in text


# ---------- XLSX ----------


def test_xlsx(result, tmp_path):
    path = write_xlsx(result, tmp_path / "poam.xlsx", system_name="Demo")
    wb = load_workbook(path)
    assert wb.sheetnames == ["POA&M", "Details", "Summary", "About"]
    ws = wb["POA&M"]
    assert [c.value for c in ws[1]] == EMASS_COLUMNS
    assert ws.max_row == len(result.items) + 1
    date_cell = ws.cell(row=2, column=EMASS_COLUMNS.index("Scheduled Completion Date") + 1)
    assert date_cell.value.date() == result.items[0].scheduled_completion
    assert ws.freeze_panes == "B2"
    summary = [[c.value for c in r] for r in wb["Summary"].iter_rows()]
    assert summary[-1][0] == "TOTAL"
    assert summary[-1][4] == len(result.items)
    about = {r[0].value: r[1].value for r in wb["About"].iter_rows()}
    assert "Not an official" in about["Template notice"]
    assert about["System"] == "Demo"


def test_xlsx_neutralizes_formulas(tmp_path):
    path = write_xlsx(_evil_result(), tmp_path / "evil.xlsx")
    ws = load_workbook(path)["POA&M"]
    values = [c.value for c in ws[2]]
    assert all(not (isinstance(v, str) and v.startswith(("=", "@"))) for v in values)
    assert ws.cell(row=2, column=EMASS_COLUMNS.index("Recommendations") + 1).data_type == "s"


def test_xlsx_empty(tmp_path):
    empty = build_poam([], None, load_rules(), AS_OF)
    wb = load_workbook(write_xlsx(empty, tmp_path / "e.xlsx"))
    assert wb["POA&M"].max_row == 1


# ---------- OSCAL ----------


@pytest.mark.parametrize(
    ("control", "expected"),
    [("AC-2", "ac-2_smt"), ("AC-2(4)", "ac-2.4_smt"), ("SI-2", "si-2_smt"), ("odd", "odd_smt")],
)
def test_statement_id(control, expected):
    assert statement_id(control) == expected


def test_oscal_structure(result):
    doc = build_oscal_poam(result, system_name="Demo", generated_at=GEN_AT)
    assert validate_structure(doc) == []
    root = doc["plan-of-action-and-milestones"]
    assert root["metadata"]["oscal-version"] == "1.1.2"
    assert root["metadata"]["last-modified"] == "2026-11-17T12:00:00Z"
    n = len(result.items)
    assert len(root["poam-items"]) == len(root["risks"]) == len(root["findings"]) == n
    assert len(root["observations"]) == n
    assert len(root["local-definitions"]["inventory-items"]) == 3
    risk = next(r for r in root["risks"] if r["title"].startswith("The demo OS must store"))
    assert risk["status"] == "open"
    assert risk["deadline"] == "2026-12-17T23:59:59Z"
    finding = root["findings"][0]
    assert finding["target"]["status"]["state"] == "not-satisfied"


def test_oscal_uuids_stable_across_runs(result, all_findings, catalog):
    a = build_oscal_poam(result, "Demo", GEN_AT)["plan-of-action-and-milestones"]
    later = build_poam(all_findings, catalog, load_rules(), date(2026, 12, 17))
    b = build_oscal_poam(later, "Demo", GEN_AT)["plan-of-action-and-milestones"]
    # same weakness -> same poam-item / risk / finding uuid next month
    assert [p["uuid"] for p in a["poam-items"]] == [p["uuid"] for p in b["poam-items"]]
    assert [r["uuid"] for r in a["risks"]] == [r["uuid"] for r in b["risks"]]
    # document and observations are point-in-time
    assert a["uuid"] != b["uuid"]
    assert a["observations"][0]["uuid"] != b["observations"][0]["uuid"]
    # different system -> different uuids
    c = build_oscal_poam(result, "Other", GEN_AT)["plan-of-action-and-milestones"]
    assert a["poam-items"][0]["uuid"] != c["poam-items"][0]["uuid"]


def test_oscal_empty_poam_is_valid():
    empty = build_poam([], None, load_rules(), AS_OF)
    doc = build_oscal_poam(empty, generated_at=GEN_AT)
    assert validate_structure(doc) == []
    assert doc["plan-of-action-and-milestones"]["poam-items"] == []


def test_validate_structure_catches_problems(result):
    doc = build_oscal_poam(result, "Demo", GEN_AT)
    root = doc["plan-of-action-and-milestones"]
    root["poam-items"][0]["related-risks"] = [{"risk-uuid": "not-a-uuid"}]
    root["risks"][0]["uuid"] = root["risks"][1]["uuid"]
    root["observations"][0]["subjects"][0]["subject-uuid"] = "x"
    root["metadata"]["oscal-version"] = "1.0.0"
    del root["findings"][0]["target"]["status"]
    errors = validate_structure(doc)
    joined = " | ".join(errors)
    assert "unknown risk-uuid" in joined
    assert "duplicate uuid" in joined
    assert "unknown subject" in joined
    assert "oscal-version" in joined
    assert "incomplete target" in joined
    assert validate_structure({}) == ["missing plan-of-action-and-milestones root"]


def test_write_oscal(result, tmp_path):
    path = write_oscal(result, tmp_path / "p.json", "Demo", GEN_AT)
    doc = json.loads(path.read_text())
    assert validate_structure(doc) == []


def _schema_path() -> Path | None:
    env = os.environ.get("OSCAL_POAM_SCHEMA")
    candidates = [Path(env)] if env else []
    candidates.append(ROOT / "schemas" / "oscal_poam_schema.json")
    return next((p for p in candidates if p.is_file()), None)


@pytest.mark.skipif(_schema_path() is None, reason="OSCAL POA&M JSON schema not downloaded")
def test_oscal_valid_against_official_schema(result, tmp_path):
    import sys

    sys.path.insert(0, str(ROOT / "tools"))
    from validate_oscal import validate

    good = write_oscal(result, tmp_path / "good.json", "Demo", GEN_AT)
    assert validate(_schema_path(), good) == []

    # and the validator really rejects a broken document
    doc = json.loads(good.read_text())
    root = doc["plan-of-action-and-milestones"]
    root["risks"][0]["status"] = ""
    root["poam-items"][0]["props"][0]["name"] = "has space"
    del root["metadata"]["title"]
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(doc))
    errors = validate(_schema_path(), bad)
    assert len(errors) >= 3
