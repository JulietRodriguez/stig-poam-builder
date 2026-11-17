from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples" / "inputs"


@pytest.fixture
def samples_dir() -> Path:
    return SAMPLES


@pytest.fixture
def sample_files() -> list[Path]:
    return sorted(SAMPLES.iterdir())


AS_OF = __import__("datetime").date(2026, 11, 17)
SAMPLE_CCI = ROOT / "samples" / "cci" / "U_CCI_List_SAMPLE.xml"


@pytest.fixture
def catalog():
    from stig_poam_builder.cci import load_cci_list

    return load_cci_list(SAMPLE_CCI)


@pytest.fixture
def all_findings(sample_files):
    from stig_poam_builder.parsers import load_file

    out = []
    for p in sample_files:
        out.extend(load_file(p))
    return out


@pytest.fixture
def result(all_findings, catalog):
    from stig_poam_builder.config import load_rules
    from stig_poam_builder.poam import build_poam

    return build_poam(all_findings, catalog, load_rules(), AS_OF)
