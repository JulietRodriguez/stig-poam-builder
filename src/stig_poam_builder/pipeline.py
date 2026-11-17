"""End-to-end pipeline shared by the CLI and the dashboard."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import date
from pathlib import Path

from .cci import CciCatalog, load_cci_list
from .config import Rules
from .models import Finding
from .parsers import load_file
from .poam import BuildResult, build_poam

INPUT_SUFFIXES = {".ckl", ".cklb", ".nessus"}


def collect_inputs(paths: Iterable[str | Path]) -> list[Path]:
    """Expand directories (recursively) into .ckl/.cklb/.nessus files.

    Files named explicitly are always included, whatever their extension, so a
    renamed export can still be passed directly. Output is sorted and
    de-duplicated so runs are repeatable.
    """
    found: set[Path] = set()
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            found.update(
                f for f in p.rglob("*") if f.is_file() and f.suffix.lower() in INPUT_SUFFIXES
            )
        elif p.is_file():
            found.add(p)
        else:
            raise FileNotFoundError(f"input not found: {p}")
    return sorted(found)


def load_findings(files: Iterable[Path], rules: Rules) -> list[Finding]:
    findings: list[Finding] = []
    for f in files:
        findings.extend(
            load_file(
                f,
                severity_map=rules.nessus_severity_map,
                include_informational=rules.include_informational,
            )
        )
    return findings


def run(
    inputs: Iterable[str | Path],
    rules: Rules,
    as_of: date,
    cci_list: str | Path | None = None,
) -> BuildResult:
    catalog: CciCatalog | None = None
    if cci_list:
        catalog = load_cci_list(cci_list, revision=rules.nist_revision)
    files = collect_inputs(inputs)
    return build_poam(load_findings(files, rules), catalog, rules, as_of)
