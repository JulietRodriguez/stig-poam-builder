"""Summary report: open findings by CAT and control family.

Two counts are reported on purpose, because they answer different questions:

* POA&M items  - distinct weaknesses (what goes in the POA&M)
* open instances - weakness x device (how much remediation work there is)
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from .cci import control_sort_key
from .models import Cat, Status
from .poam import BuildResult

CATS = [Cat.CAT_I, Cat.CAT_II, Cat.CAT_III]


def compute_summary(result: BuildResult) -> dict[str, Any]:
    items = result.items
    stig_findings = [f for f in result.findings if f.source_type.is_stig]

    instances_by_cat: Counter[str] = Counter()
    family_items: dict[str, Counter[str]] = defaultdict(Counter)
    family_instances: dict[str, Counter[str]] = defaultdict(Counter)
    for item in items:
        n = len(item.assets)
        instances_by_cat[item.raw_cat.value] += n
        family_items[item.family][item.raw_cat.value] += 1
        family_instances[item.family][item.raw_cat.value] += n

    controls = Counter(item.primary_control for item in items)
    not_reviewed_by_host: Counter[str] = Counter(f.asset.label for f in result.not_reviewed)

    return {
        "as_of": result.as_of.isoformat(),
        "cci_list": result.catalog_label or "none (all STIG findings used fallback control)",
        "nist_revision": result.rules.nist_revision,
        "inputs": {
            "files": sorted({f.source_file for f in result.findings}),
            "hosts": sorted({f.asset.label for f in result.findings}),
            "stig_checks": len(stig_findings),
            "stig_status_counts": {
                s.value: sum(1 for f in stig_findings if f.status is s) for s in Status
            },
            "acas_findings": sum(1 for f in result.findings if not f.source_type.is_stig),
        },
        "poam_items": len(items),
        "open_instances": sum(len(i.assets) for i in items),
        "items_by_cat": {c.value: sum(1 for i in items if i.raw_cat is c) for c in CATS},
        "instances_by_cat": {c.value: instances_by_cat[c.value] for c in CATS},
        "items_by_source": {k: sum(1 for i in items if i.kind == k) for k in ("STIG", "ACAS")},
        "by_family": {
            fam: {
                "items": {c.value: family_items[fam][c.value] for c in CATS},
                "instances": {c.value: family_instances[fam][c.value] for c in CATS},
            }
            for fam in sorted(family_items)
        },
        "by_control": {ctl: controls[ctl] for ctl in sorted(controls, key=control_sort_key)},
        "not_reviewed": {
            "total": len(result.not_reviewed),
            "by_host": dict(sorted(not_reviewed_by_host.items())),
            "included_in_poam": result.rules.include_not_reviewed,
        },
        "unmapped_ccis": result.unmapped_ccis,
        "fallback_items": [i.item_id for i in items if i.mapping_basis.startswith("Fallback")],
        "overrides": [i.item_id for i in items if i.override_notes],
    }


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return "\n".join(out)


def render_markdown(summary: dict[str, Any]) -> str:
    s = summary
    inp = s["inputs"]
    cat_names = [c.value for c in CATS]
    lines = [
        "# POA&M Summary",
        "",
        f"- As of: **{s['as_of']}**",
        f"- Inputs: {len(inp['files'])} files, {len(inp['hosts'])} hosts "
        f"({inp['stig_checks']} STIG checks, {inp['acas_findings']} ACAS findings)",
        f"- Control mapping: NIST SP 800-53 Rev {s['nist_revision']} via {s['cci_list']}",
        f"- **{s['poam_items']} POA&M items** covering **{s['open_instances']} open instances** "
        "(weakness x device)",
        "",
        "## Open findings by CAT",
        "",
        _table(
            ["", *cat_names, "Total"],
            [
                ["POA&M items", *s["items_by_cat"].values(), s["poam_items"]],
                ["Open instances", *s["instances_by_cat"].values(), s["open_instances"]],
            ],
        ),
        "",
        "## Open POA&M items by control family",
        "",
        _table(
            ["Family", *cat_names, "Items", "Instances"],
            [
                [
                    fam,
                    *v["items"].values(),
                    sum(v["items"].values()),
                    sum(v["instances"].values()),
                ]
                for fam, v in s["by_family"].items()
            ],
        ),
        "",
        "## POA&M items by control",
        "",
        _table(["Control", "Items"], [[c, n] for c, n in s["by_control"].items()]),
        "",
        "## STIG review status (all checks)",
        "",
        _table(["Status", "Checks"], [[k, v] for k, v in inp["stig_status_counts"].items()]),
        "",
    ]
    nr = s["not_reviewed"]
    if nr["total"]:
        where = "included in" if nr["included_in_poam"] else "NOT included in"
        lines += [
            f"## Gaps: {nr['total']} checks Not Reviewed ({where} the POA&M)",
            "",
            _table(["Host", "Not Reviewed"], [[h, n] for h, n in nr["by_host"].items()]),
            "",
        ]
    if s["unmapped_ccis"] or s["fallback_items"]:
        lines += [
            "## Mapping warnings",
            "",
            f"- CCIs not found in the CCI List: {', '.join(s['unmapped_ccis']) or 'none'}",
            f"- Items on the fallback control: {', '.join(s['fallback_items']) or 'none'}",
            "",
        ]
    if s["overrides"]:
        lines += [f"Items with reviewer severity overrides: {', '.join(s['overrides'])}", ""]
    return "\n".join(lines)
