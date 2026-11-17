from datetime import date

import pytest

from stig_poam_builder.config import ConfigError, load_rules
from stig_poam_builder.models import Cat


def test_defaults():
    rules = load_rules()
    assert rules.days == {Cat.CAT_I: 30, Cat.CAT_II: 90, Cat.CAT_III: 180}
    assert rules.nist_revision == 5
    assert rules.stig_unmapped_control == "CM-6"
    assert rules.acas_control == "SI-2"
    assert rules.nessus_severity_map[4] is Cat.CAT_I
    assert rules.nessus_severity_map[2] is Cat.CAT_II
    assert rules.include_not_reviewed is False
    assert rules.due_date(Cat.CAT_I, date(2026, 11, 17)) == date(2026, 12, 17)


def test_partial_override_keeps_other_defaults(tmp_path):
    p = tmp_path / "rules.toml"
    p.write_text('[schedule]\ncat_i_days = 14\n[nessus.severity_map]\n"3" = "CAT II"\n')
    rules = load_rules(p)
    assert rules.days[Cat.CAT_I] == 14
    assert rules.days[Cat.CAT_II] == 90
    assert rules.nessus_severity_map[3] is Cat.CAT_II
    assert rules.nessus_severity_map[4] is Cat.CAT_I


@pytest.mark.parametrize(
    "toml",
    [
        "[schedule]\ncat_i_days = 0",
        "[schedule]\ncat_ii_days = 'soon'",
        "[schedule]\ncat_iii_days = true",
        "[mapping]\nnist_revision = 3",
        "[mapping]\nacas_control = 'patching'",
        "[mapping]\nstig_unmapped_control = 'cm-6'",
        "[nessus.severity_map]\n'9' = 'CAT I'",
        "[nessus.severity_map]\n'x' = 'CAT I'",
        "[nessus.severity_map]\n'2' = 'CAT IV'",
        "not = [valid toml",
    ],
)
def test_invalid_rules_rejected(tmp_path, toml):
    p = tmp_path / "rules.toml"
    p.write_text(toml)
    with pytest.raises(ConfigError):
        load_rules(p)


def test_missing_file(tmp_path):
    with pytest.raises(ConfigError):
        load_rules(tmp_path / "nope.toml")
