"""Helpers shared by the parsers."""

from __future__ import annotations

import re


class ParseError(ValueError):
    """Raised when an input file is not the format it claims to be."""


_RELEASE_RE = re.compile(r"Release:\s*(\S+)", re.IGNORECASE)
_BENCH_DATE_RE = re.compile(r"Benchmark Date:\s*(.+)$", re.IGNORECASE)


def benchmark_label(title: str, version: str, release_info: str) -> str:
    """Build "<STIG title> :: Version X Release Y Benchmark Date: D".

    This is the conventional "Source Identifying Vulnerability" text for a STIG
    finding. ``release_info`` looks like "Release: 5 Benchmark Date: 07 Jun 2023".
    """
    title = title.strip() or "Unknown STIG"
    parts = []
    if version:
        parts.append(f"Version {version.strip()}")
    rel = _RELEASE_RE.search(release_info or "")
    if rel:
        parts.append(f"Release {rel.group(1)}")
    date = _BENCH_DATE_RE.search(release_info or "")
    if date:
        parts.append(f"Benchmark Date: {date.group(1).strip()}")
    return f"{title} :: {' '.join(parts)}" if parts else title
