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
