import json

import pytest

from stig_poam_builder.models import Cat, SourceType, Status, normalize_status
from stig_poam_builder.parsers import (
    ParseError,
    detect_format,
    load_file,
    parse_ckl,
    parse_cklb,
    parse_nessus,
)

# ---------- status / severity normalization ----------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Open", Status.OPEN),
        ("open", Status.OPEN),
        ("NotAFinding", Status.NOT_A_FINDING),
        ("not_a_finding", Status.NOT_A_FINDING),
        ("Not_Applicable", Status.NOT_APPLICABLE),
        ("not_applicable", Status.NOT_APPLICABLE),
        ("Not_Reviewed", Status.NOT_REVIEWED),
        ("not_reviewed", Status.NOT_REVIEWED),
        ("", Status.NOT_REVIEWED),
        (None, Status.NOT_REVIEWED),
        ("garbage", Status.NOT_REVIEWED),
    ],
)
def test_normalize_status(raw, expected):
    assert normalize_status(raw) is expected


# ---------- CKL ----------


def test_ckl_sample_parses(samples_dir):
    findings = parse_ckl(samples_dir / "web01_demo-os.ckl")
    assert len(findings) == 10
    f = findings[0]
    assert f.source_type is SourceType.CKL
    assert f.check_id == "V-900001"
    assert f.stig_id == "DEMO-OS-000010"
    assert f.rule_id.startswith("SV-900001")
    assert f.cat is Cat.CAT_I
    assert f.status is Status.OPEN
    assert f.ccis == ["CCI-000196"]
    assert f.asset.hostname == "web01"
    assert f.asset.ip == "192.0.2.11"
    assert "Version 1 Release 2" in f.benchmark
    assert "Benchmark Date: 01 Oct 2026" in f.benchmark


def test_ckl_multiple_ccis_and_override(samples_dir):
    by_id = {f.check_id: f for f in parse_ckl(samples_dir / "web01_demo-os.ckl")}
    assert by_id["V-900007"].ccis == ["CCI-001453", "CCI-002450"]
    overridden = by_id["V-900003"]
    assert overridden.cat is Cat.CAT_II
    assert overridden.cat_override is Cat.CAT_III
    assert overridden.effective_cat is Cat.CAT_III
    assert "compensating control" in overridden.override_reason


def test_ckl_all_statuses_present(samples_dir):
    statuses = {f.status for f in parse_ckl(samples_dir / "web01_demo-os.ckl")}
    assert statuses == set(Status)


def test_ckl_rejects_wrong_root(tmp_path):
    p = tmp_path / "x.ckl"
    p.write_text("<NOTACHECKLIST/>")
    with pytest.raises(ParseError, match="expected <CHECKLIST>"):
        parse_ckl(p)


def test_ckl_rejects_malformed_xml(tmp_path):
    p = tmp_path / "x.ckl"
    p.write_text("<CHECKLIST><ASSET>")
    with pytest.raises(ParseError):
        parse_ckl(p)


def test_ckl_blocks_xml_entity_expansion(tmp_path):
    """defusedxml must refuse DTD entities (XXE / billion laughs)."""
    p = tmp_path / "evil.ckl"
    p.write_text(
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
        "<CHECKLIST><ASSET><HOST_NAME>&e;</HOST_NAME></ASSET></CHECKLIST>"
    )
    with pytest.raises(ParseError):
        parse_ckl(p)


def test_ckl_unknown_severity(tmp_path):
    p = tmp_path / "x.ckl"
    p.write_text(
        "<CHECKLIST><ASSET/><STIGS><iSTIG><VULN>"
        "<STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE><ATTRIBUTE_DATA>V-1</ATTRIBUTE_DATA></STIG_DATA>"
        "<STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>extreme</ATTRIBUTE_DATA></STIG_DATA>"
        "<STATUS>Open</STATUS></VULN></iSTIG></STIGS></CHECKLIST>"
    )
    with pytest.raises(ParseError, match="unknown severity"):
        parse_ckl(p)


# ---------- CKLB ----------


def test_cklb_sample_parses(samples_dir):
    findings = parse_cklb(samples_dir / "db01_demo-os.cklb")
    assert len(findings) == 10
    f = findings[0]
    assert f.source_type is SourceType.CKLB
    assert f.check_id == "V-900001"
    assert f.status is Status.OPEN
    assert f.asset.hostname == "db01"
    assert f.ccis == ["CCI-000196"]


def _cklb(rule_overrides: dict) -> dict:
    rule = {"group_id": "V-1", "severity": "high", "status": "open", "ccis": ["CCI-000366"]}
    rule.update(rule_overrides)
    return {"target_data": {"host_name": "h"}, "stigs": [{"display_name": "T", "rules": [rule]}]}


def test_cklb_severity_override_dict(tmp_path):
    p = tmp_path / "x.cklb"
    p.write_text(
        json.dumps(_cklb({"overrides": {"severity": {"severity": "medium", "reason": "r"}}}))
    )
    (f,) = parse_cklb(p)
    assert f.cat is Cat.CAT_I
    assert f.effective_cat is Cat.CAT_II
    assert f.override_reason == "r"


def test_cklb_severity_override_string(tmp_path):
    p = tmp_path / "x.cklb"
    p.write_text(json.dumps(_cklb({"overrides": {"severity": "low"}})))
    (f,) = parse_cklb(p)
    assert f.effective_cat is Cat.CAT_III


def test_cklb_dedupes_repeated_ccis_and_skips_ruleless(tmp_path):
    data = _cklb({"ccis": ["CCI-000366", "CCI-000366", ""]})
    data["stigs"][0]["rules"].append({"severity": "low"})  # no group_id -> skipped
    p = tmp_path / "x.cklb"
    p.write_text(json.dumps(data))
    (f,) = parse_cklb(p)
    assert f.ccis == ["CCI-000366"]


def test_cklb_rejects_non_checklist(tmp_path):
    p = tmp_path / "x.cklb"
    p.write_text(json.dumps({"hello": "world"}))
    with pytest.raises(ParseError, match="stigs"):
        parse_cklb(p)
    p.write_text("{not json")
    with pytest.raises(ParseError):
        parse_cklb(p)


def test_cklb_unknown_severity(tmp_path):
    p = tmp_path / "x.cklb"
    p.write_text(json.dumps(_cklb({"severity": "spicy"})))
    with pytest.raises(ParseError, match="unknown severity"):
        parse_cklb(p)


# ---------- Nessus ----------


def test_nessus_sample_parses(samples_dir):
    findings = parse_nessus(samples_dir / "monthly_scan.nessus")
    ids = sorted({f.check_id for f in findings})
    # 900199 is informational (dropped), 900200 is Policy Compliance (skipped)
    assert ids == ["900101", "900102", "900103", "900104", "900105"]
    assert all(f.status is Status.OPEN for f in findings)
    assert all(f.source_type is SourceType.NESSUS for f in findings)
    web = next(f for f in findings if f.check_id == "900101")
    assert web.asset.hostname == "web01"
    assert web.asset.ip == "192.0.2.11"
    assert web.cves == ["CVE-2099-0001"]
    assert web.iavas == ["2099-A-0001"]


def test_nessus_default_severity_mapping(samples_dir):
    cats = {f.check_id: f.cat for f in parse_nessus(samples_dir / "monthly_scan.nessus")}
    assert cats["900105"] is Cat.CAT_I  # critical
    assert cats["900103"] is Cat.CAT_I  # high
    assert cats["900102"] is Cat.CAT_II  # medium
    assert cats["900104"] is Cat.CAT_III  # low


def _nessus(item_attrs: str, body: str = "") -> str:
    return (
        "<NessusClientData_v2><Report><ReportHost name='10.0.0.1'><HostProperties>"
        "<tag name='host-ip'>10.0.0.1</tag></HostProperties>"
        f"<ReportItem pluginID='1' pluginName='p' pluginFamily='General' {item_attrs}>{body}</ReportItem>"
        "</ReportHost></Report></NessusClientData_v2>"
    )


def test_nessus_stig_severity_wins(tmp_path):
    p = tmp_path / "x.nessus"
    p.write_text(_nessus("severity='1'", "<stig_severity>I</stig_severity>"))
    (f,) = parse_nessus(p)
    assert f.cat is Cat.CAT_I
    assert f.nessus_severity == 1


def test_nessus_informational_opt_in(tmp_path):
    p = tmp_path / "x.nessus"
    p.write_text(_nessus("severity='0'"))
    assert parse_nessus(p) == []
    (f,) = parse_nessus(p, include_informational=True)
    assert f.cat is Cat.CAT_III


def test_nessus_custom_severity_map(tmp_path):
    p = tmp_path / "x.nessus"
    p.write_text(_nessus("severity='3'"))
    (f,) = parse_nessus(p, severity_map={3: Cat.CAT_II})
    assert f.cat is Cat.CAT_II


def test_nessus_host_falls_back_to_report_host_name(tmp_path):
    p = tmp_path / "x.nessus"
    p.write_text(_nessus("severity='2'"))
    (f,) = parse_nessus(p)
    assert f.asset.ip == "10.0.0.1"
    assert f.asset.label == "10.0.0.1"


def test_nessus_bad_severity_and_missing_plugin(tmp_path):
    p = tmp_path / "x.nessus"
    p.write_text(_nessus("severity='abc'"))
    assert parse_nessus(p) == []  # non-numeric severity -> 0 -> dropped
    p.write_text(_nessus("severity='2'").replace("pluginID='1'", ""))
    assert parse_nessus(p) == []


def test_nessus_rejects_wrong_root(tmp_path):
    p = tmp_path / "x.nessus"
    p.write_text("<NessusClientData/>")
    with pytest.raises(ParseError, match="NessusClientData_v2"):
        parse_nessus(p)
    p.write_text("not xml")
    with pytest.raises(ParseError):
        parse_nessus(p)


# ---------- format detection ----------


def test_detect_format_by_extension(sample_files):
    assert [detect_format(p) for p in sample_files] == ["ckl", "cklb", "nessus", "ckl"]


def test_detect_format_by_content(tmp_path, samples_dir):
    for src, expected in [
        ("web01_demo-os.ckl", "ckl"),
        ("db01_demo-os.cklb", "cklb"),
        ("monthly_scan.nessus", "nessus"),
    ]:
        renamed = tmp_path / f"export_{expected}.xml"
        renamed.write_bytes((samples_dir / src).read_bytes())
        assert detect_format(renamed) == expected
        assert load_file(renamed)


def test_detect_format_unknown(tmp_path):
    p = tmp_path / "x.txt"
    p.write_text("hello")
    with pytest.raises(ParseError, match="can't tell"):
        detect_format(p)
