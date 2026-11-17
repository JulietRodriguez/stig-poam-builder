"""CSV output: the eMASS-style columns followed by the analysis columns."""

from __future__ import annotations

import csv
from pathlib import Path

from ..poam import BuildResult
from .columns import DETAIL_COLUMNS, EMASS_COLUMNS, detail_row, emass_row, safe_cell

CSV_COLUMNS = EMASS_COLUMNS + [c for c in DETAIL_COLUMNS if c != "POA&M Item ID"]


def write_csv(result: BuildResult, path: str | Path) -> Path:
    path = Path(path)
    # utf-8-sig so Excel opens it with the right encoding.
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for item in result.items:
            row = {**emass_row(item, result), **detail_row(item)}
            row["Scheduled Completion Date"] = item.scheduled_completion.isoformat()
            writer.writerow({k: safe_cell(row[k]) for k in CSV_COLUMNS})
    return path
