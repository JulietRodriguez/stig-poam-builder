"""Command-line interface.

stig-poam build samples/inputs --cci-list samples/cci/U_CCI_List_SAMPLE.xml --out out/
stig-poam init-rules > my_rules.toml
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import UTC, date, datetime
from importlib import resources
from pathlib import Path

from . import __version__
from .config import ConfigError, load_rules
from .outputs import write_csv, write_oscal, write_xlsx
from .parsers import ParseError
from .pipeline import run
from .summary import compute_summary, render_markdown

FORMATS = ("xlsx", "csv", "oscal", "summary")


def _as_of(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"--as-of must be YYYY-MM-DD (got {value!r})") from exc


def _formats(value: str) -> list[str]:
    chosen = [v.strip().lower() for v in value.split(",") if v.strip()]
    bad = [v for v in chosen if v not in FORMATS]
    if bad or not chosen:
        raise argparse.ArgumentTypeError(
            f"--formats takes a comma list of {', '.join(FORMATS)} (got {value!r})"
        )
    return chosen


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="stig-poam",
        description="Turn STIG checklists (.ckl/.cklb) and ACAS scans (.nessus) into POA&Ms.",
    )
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="command", required=True)

    b = sub.add_parser("build", help="build POA&M outputs from checklists and scans")
    b.add_argument("inputs", nargs="+", help="files or directories (searched recursively)")
    b.add_argument(
        "--cci-list",
        help="DISA U_CCI_List.xml used to map CCIs to NIST 800-53 controls "
        "(without it, every STIG finding lands on the fallback control)",
    )
    b.add_argument("--rules", help="TOML rules file (see 'stig-poam init-rules')")
    b.add_argument("--out", default="out", help="output directory (default: out)")
    b.add_argument("--system", default="Example System", help="system name for the outputs")
    b.add_argument(
        "--as-of",
        type=_as_of,
        default=None,
        help="date the POA&M is opened; due dates count from it (default: today)",
    )
    b.add_argument(
        "--formats",
        type=_formats,
        default=list(FORMATS),
        help=f"comma list of outputs (default: {','.join(FORMATS)})",
    )
    b.add_argument(
        "--include-not-reviewed",
        action="store_true",
        help="also create POA&M items for Not Reviewed checks",
    )

    sub.add_parser("init-rules", help="print the default rules TOML to stdout")
    sub.add_parser("dashboard", help="launch the optional Streamlit dashboard")
    return ap


def _cmd_dashboard() -> int:
    try:
        import streamlit  # noqa: F401
    except ImportError:
        print(
            "error: the dashboard needs Streamlit: pip install 'stig-poam-builder[dashboard]'",
            file=sys.stderr,
        )
        return 2
    app = Path(__file__).with_name("dashboard.py")
    return subprocess.call([sys.executable, "-m", "streamlit", "run", str(app)])  # noqa: S603


def _cmd_build(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules)
    if args.include_not_reviewed:
        rules.include_not_reviewed = True
    as_of = args.as_of or date.today()
    if not args.cci_list:
        print(
            "warning: no --cci-list given; STIG findings will use the fallback control "
            f"{rules.stig_unmapped_control}. Download U_CCI_List.xml from DISA for real mapping.",
            file=sys.stderr,
        )

    result = run(args.inputs, rules, as_of, cci_list=args.cci_list)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stem = f"poam_{as_of.isoformat()}"
    written: list[Path] = []
    if "xlsx" in args.formats:
        written.append(write_xlsx(result, out / f"{stem}.xlsx", system_name=args.system))
    if "csv" in args.formats:
        written.append(write_csv(result, out / f"{stem}.csv"))
    if "oscal" in args.formats:
        written.append(
            write_oscal(
                result,
                out / f"{stem}.oscal.json",
                system_name=args.system,
                generated_at=datetime.now(UTC),
            )
        )
    summary = compute_summary(result)
    if "summary" in args.formats:
        md = out / f"{stem}_summary.md"
        md.write_text(render_markdown(summary) + "\n", encoding="utf-8")
        js = out / f"{stem}_summary.json"
        js.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        written += [md, js]

    cats = summary["items_by_cat"]
    print(
        f"{summary['poam_items']} POA&M items ({cats['CAT I']} CAT I, {cats['CAT II']} CAT II, "
        f"{cats['CAT III']} CAT III) from {len(summary['inputs']['files'])} files, "
        f"{len(summary['inputs']['hosts'])} hosts"
    )
    if summary["not_reviewed"]["total"] and not rules.include_not_reviewed:
        print(f"note: {summary['not_reviewed']['total']} checks are Not Reviewed (see summary)")
    if summary["unmapped_ccis"]:
        print(f"note: CCIs not in the CCI List: {', '.join(summary['unmapped_ccis'])}")
    for p in written:
        print(f"wrote {p}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "init-rules":
        text = resources.files("stig_poam_builder").joinpath("data/default_rules.toml").read_text()
        sys.stdout.write(text)
        return 0
    if args.command == "dashboard":
        return _cmd_dashboard()
    try:
        return _cmd_build(args)
    except (ParseError, ConfigError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
