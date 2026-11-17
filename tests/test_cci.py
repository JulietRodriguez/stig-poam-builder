import pytest

from stig_poam_builder.cci import (
    control_family,
    control_from_index,
    control_sort_key,
    load_cci_list,
)
from stig_poam_builder.parsers import ParseError

from .conftest import ROOT

SAMPLE_CCI = ROOT / "samples" / "cci" / "U_CCI_List_SAMPLE.xml"


@pytest.mark.parametrize(
    ("index", "expected"),
    [
        ("CM-6 b", "CM-6"),
        ("AC-2 (4) (a)", "AC-2(4)"),
        ("IA-5 (1) (c)", "IA-5(1)"),
        ("AU-12 c", "AU-12"),
        ("AC-3", "AC-3"),
        ("SC-13 b", "SC-13"),
        ("AC-02", "AC-2"),
        ("AC-2(4)", "AC-2(4)"),
        ("not a control", None),
        ("", None),
    ],
)
def test_control_from_index(index, expected):
    assert control_from_index(index) == expected


def test_control_family_and_sort():
    assert control_family("AC-2(4)") == "AC"
    ids = ["AC-11", "AC-2(4)", "AC-2", "AU-9", "AC-17(2)"]
    assert sorted(ids, key=control_sort_key) == ["AC-2", "AC-2(4)", "AC-11", "AC-17(2)", "AU-9"]


def test_load_sample_rev5():
    cat = load_cci_list(SAMPLE_CCI)
    assert len(cat) == 10
    assert cat.version == "SAMPLE"
    assert cat.controls_for("CCI-000366") == ["CM-6"]
    assert cat.controls_for("cci-000196") == ["IA-5(1)"]  # case-insensitive
    assert cat.controls_for("CCI-999999") == []
    # 800-53A assessment-procedure references are ignored
    assert cat.entries["CCI-000366"].references == ["CM-6 b"]


def test_load_sample_rev4_differs():
    rev4 = load_cci_list(SAMPLE_CCI, revision=4)
    rev5 = load_cci_list(SAMPLE_CCI, revision=5)
    assert rev4.entries["CCI-002450"].references == ["SC-13"]
    assert rev5.entries["CCI-002450"].references == ["SC-13 b"]


def test_load_without_namespace(tmp_path):
    p = tmp_path / "cci.xml"
    p.write_text(
        "<cci_list><cci_items><cci_item id='CCI-1'><references>"
        "<reference title='NIST SP 800-53 Revision 5' version='5' index='AC-2 (1)'/>"
        "<reference title='NIST SP 800-53 Revision 5' version='5' index='AC-2 (1) (b)'/>"
        "</references></cci_item><cci_item><references/></cci_item></cci_items></cci_list>"
    )
    cat = load_cci_list(p)
    assert cat.controls_for("CCI-1") == ["AC-2(1)"]  # duplicate control collapsed
    assert len(cat) == 1  # item without id skipped


def test_load_rejects_bad_files(tmp_path):
    p = tmp_path / "cci.xml"
    p.write_text("<other/>")
    with pytest.raises(ParseError, match="cci_list"):
        load_cci_list(p)
    p.write_text("<cci_list><cci_items/></cci_list>")
    with pytest.raises(ParseError, match="no cci_item"):
        load_cci_list(p)
    p.write_text("<<<")
    with pytest.raises(ParseError):
        load_cci_list(p)
