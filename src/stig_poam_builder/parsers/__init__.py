"""Input parsers. ``load_file`` picks the right one by extension, then content."""

from __future__ import annotations

from pathlib import Path

from ..models import Finding
from .ckl import parse_ckl
from .cklb import parse_cklb
from .common import ParseError
from .nessus import parse_nessus

__all__ = ["ParseError", "detect_format", "load_file", "parse_ckl", "parse_cklb", "parse_nessus"]


def detect_format(path: str | Path) -> str:
    """Return "ckl", "cklb", or "nessus" for a file.

    Extension first; for anything else, sniff the first bytes so a renamed
    export still loads.
    """
    path = Path(path)
    ext = path.suffix.lower().lstrip(".")
    if ext in {"ckl", "cklb", "nessus"}:
        return ext
    with path.open("rb") as fh:
        head = fh.read(4096).decode("utf-8", errors="ignore").lstrip("﻿ \r\n\t")
    if head.startswith("{"):
        return "cklb"
    if "<NessusClientData_v2" in head:
        return "nessus"
    if "<CHECKLIST" in head:
        return "ckl"
    raise ParseError(f"{path.name}: can't tell whether this is a .ckl, .cklb, or .nessus file")


def load_file(path: str | Path, **nessus_kwargs) -> list[Finding]:
    fmt = detect_format(path)
    if fmt == "ckl":
        return parse_ckl(path)
    if fmt == "cklb":
        return parse_cklb(path)
    return parse_nessus(path, **nessus_kwargs)
