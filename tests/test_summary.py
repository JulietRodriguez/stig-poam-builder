from stig_poam_builder.config import load_rules
from stig_poam_builder.poam import build_poam
from stig_poam_builder.summary import compute_summary, render_markdown

from .conftest import AS_OF


def test_summary_counts(result):
    s = compute_summary(result)
    assert s["poam_items"] == len(result.items) == 15
    assert s["items_by_cat"] == {"CAT I": 5, "CAT II": 7, "CAT III": 3}
    assert sum(s["items_by_cat"].values()) == s["poam_items"]
    assert sum(s["instances_by_cat"].values()) == s["open_instances"]
    assert s["open_instances"] > s["poam_items"]  # dedupe collapsed host-level repeats
    assert s["items_by_source"] == {"STIG": 10, "ACAS": 5}
    assert s["by_family"]["SI"]["items"]["CAT I"] == 3
    assert s["by_control"]["SI-2"] == 5
    assert s["inputs"]["hosts"] == ["app01", "db01", "web01"]
    assert s["inputs"]["stig_status_counts"]["Not Reviewed"] == 3
    assert s["not_reviewed"]["by_host"] == {"app01": 1, "db01": 1, "web01": 1}
    assert s["unmapped_ccis"] == ["CCI-009999"]
    assert s["fallback_items"] == ["V-900010"]
    assert s["overrides"] == ["V-900003"]


def test_family_totals_match(result):
    s = compute_summary(result)
    fam_total = sum(sum(v["items"].values()) for v in s["by_family"].values())
    assert fam_total == s["poam_items"]


def test_markdown(result):
    md = render_markdown(compute_summary(result))
    assert md.startswith("# POA&M Summary")
    assert "| POA&M items | 5 | 7 | 3 | 15 |" in md
    assert "## Open POA&M items by control family" in md
    assert "Not Reviewed (NOT included in the POA&M)" in md
    assert "CCI-009999" in md


def test_markdown_empty():
    md = render_markdown(compute_summary(build_poam([], None, load_rules(), AS_OF)))
    assert "**0 POA&M items**" in md
    assert "Mapping warnings" not in md
