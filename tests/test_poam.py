from dataclasses import replace
from datetime import date

from stig_poam_builder.config import load_rules
from stig_poam_builder.models import Asset, Cat, Finding, SourceType, Status
from stig_poam_builder.poam import build_poam

from .conftest import AS_OF


def _f(**kw) -> Finding:
    base = dict(
        source_type=SourceType.CKL,
        source_file="a.ckl",
        asset=Asset(hostname="h1"),
        check_id="V-1",
        title="t",
        status=Status.OPEN,
        cat=Cat.CAT_II,
        ccis=["CCI-000366"],
    )
    base.update(kw)
    return Finding(**base)


def test_only_open_items_by_default(result):
    assert {s for i in result.items for s in i.review_statuses} == {"Open"}


def test_one_item_per_weakness_with_all_devices(result):
    by_id = {i.item_id: i for i in result.items}
    # V-900001 open on web01 (ckl) and db01 (cklb), NaF on app01
    assert by_id["V-900001"].devices == ["db01", "web01"]
    assert by_id["V-900001"].merged_findings == 2
    # ACAS plugin 900102 seen on 3 hosts -> one item
    assert by_id["ACAS-900102"].devices == ["app01", "db01", "web01"]
    assert len(by_id) == len({i.item_id for i in result.items})


def test_expected_item_set(result):
    ids = sorted(i.item_id for i in result.items)
    assert ids == sorted(
        [
            "V-900001", "V-900002", "V-900003", "V-900004", "V-900005", "V-900006",
            "V-900007", "V-900008", "V-900009", "V-900010",
            "ACAS-900101", "ACAS-900102", "ACAS-900103", "ACAS-900104", "ACAS-900105",
        ]
    )  # fmt: skip


def test_cci_mapping_to_rev5_controls(result):
    by_id = {i.item_id: i for i in result.items}
    assert by_id["V-900006"].primary_control == "CM-6"
    assert by_id["V-900006"].mapping_basis == "CCI"
    assert by_id["V-900001"].primary_control == "IA-5(1)"
    assert by_id["V-900007"].controls == ["AC-17(2)", "SC-13"]
    assert by_id["V-900007"].ccis == ["CCI-001453", "CCI-002450"]


def test_unmapped_cci_falls_back(result):
    item = next(i for i in result.items if i.item_id == "V-900010")
    assert item.primary_control == "CM-6"
    assert item.mapping_basis == "Fallback: no mapped CCI"
    assert item.unmapped_ccis == ["CCI-009999"]
    assert result.unmapped_ccis == ["CCI-009999"]


def test_acas_default_control(result):
    acas = [i for i in result.items if i.kind == "ACAS"]
    assert {i.primary_control for i in acas} == {"SI-2"}
    assert {i.mapping_basis for i in acas} == {"ACAS default"}
    assert next(i for i in acas if i.check_id == "900101").nessus_severity == 4


def test_schedule_uses_raw_cat_not_override(result):
    by_id = {i.item_id: i for i in result.items}
    v3 = by_id["V-900003"]  # CAT II, overridden to CAT III on web01 only
    assert v3.raw_cat is Cat.CAT_II
    assert v3.cat is Cat.CAT_II  # app01 is still CAT II, the most severe wins
    assert v3.scheduled_completion == date(2027, 2, 15)  # +90 days
    assert v3.override_notes and "CAT II -> CAT III" in v3.override_notes[0]
    assert by_id["V-900001"].scheduled_completion == date(2026, 12, 17)  # CAT I +30
    assert by_id["V-900005"].scheduled_completion == date(2027, 5, 16)  # CAT III +180


def test_sorted_cat_then_control(result):
    ranks = [i.raw_cat.rank for i in result.items]
    assert ranks == sorted(ranks)
    assert result.items[0].raw_cat is Cat.CAT_I


def test_group_by_control(result):
    groups = result.by_control()
    assert "SI-2" in groups and len(groups["SI-2"]) == 5
    assert list(groups) == sorted(groups, key=lambda c: (c[:2], int(c[3:].split("(")[0])))


def test_not_reviewed_reported_and_optional(all_findings, catalog, tmp_path):
    rules = load_rules()
    default = build_poam(all_findings, catalog, rules, AS_OF)
    assert sorted(f.check_id for f in default.not_reviewed) == ["V-900006", "V-900010", "V-900010"]
    rules_toml = tmp_path / "r.toml"
    rules_toml.write_text("[poam]\ninclude_not_reviewed = true\n")
    with_nr = build_poam(all_findings, catalog, load_rules(rules_toml), AS_OF)
    v10 = next(i for i in with_nr.items if i.item_id == "V-900010")
    assert v10.devices == ["app01", "db01", "web01"]
    assert set(v10.review_statuses) == {"Open", "Not Reviewed"}


def test_ckl_and_cklb_of_same_host_dedupe():
    a = _f(source_type=SourceType.CKL, source_file="h1.ckl", asset=Asset(hostname="H1"))
    b = _f(source_type=SourceType.CKLB, source_file="h1.cklb", asset=Asset(hostname="h1"))
    (item,) = build_poam([a, b], None, load_rules(), AS_OF).items
    assert item.devices == ["H1"]
    assert item.merged_findings == 2
    assert item.source_files == ["h1.ckl", "h1.cklb"]


def test_no_catalog_means_fallback():
    (item,) = build_poam([_f()], None, load_rules(), AS_OF).items
    assert item.mapping_basis.startswith("Fallback")
    assert item.unmapped_ccis == ["CCI-000366"]


def test_partial_mapping_keeps_basis_cci(catalog):
    f = _f(ccis=["CCI-009999", "CCI-000366"])
    (item,) = build_poam([f], catalog, load_rules(), AS_OF).items
    assert item.mapping_basis == "CCI"
    assert item.primary_control == "CM-6"
    assert item.unmapped_ccis == ["CCI-009999"]


def test_long_description_truncated():
    f = _f(title="T", description="x" * 5000)
    (item,) = build_poam([f], None, load_rules(), AS_OF).items
    assert len(item.description) == 2000
    assert item.description.endswith("...")


def test_security_checks_text():
    f = _f(rule_id="SV-1r1_rule", stig_id="DEMO-1")
    (item,) = build_poam([f], None, load_rules(), AS_OF).items
    assert item.security_checks == "V-1; SV-1r1_rule; DEMO-1"
    n = replace(_f(), source_type=SourceType.NESSUS, check_id="123", ccis=[])
    (acas,) = build_poam([n], None, load_rules(), AS_OF).items
    assert acas.security_checks == "Plugin ID 123"
    assert acas.item_id == "ACAS-123"


def test_empty_input():
    res = build_poam([], None, load_rules(), AS_OF)
    assert res.items == [] and res.by_control() == {}
