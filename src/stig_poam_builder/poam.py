"""Turn normalized findings into POA&M items.

Pipeline:  findings -> filter (Open, optionally Not Reviewed)
                    -> map CCIs to 800-53 controls
                    -> deduplicate into one item per weakness
                    -> assign Scheduled Completion Date by CAT
                    -> sort (CAT I first, then control)

Design decisions (see docs/design.md for the long form):

* One POA&M item per weakness, not per host. A STIG Vuln ID or ACAS plugin
  that is open on 40 hosts is one item with 40 "Devices Affected". That is how
  ISSOs keep a POA&M readable and how eMASS items are normally written.
* Item IDs are derived from the weakness ("V-220697", "ACAS-12345"), not a
  running counter, so next month's run gives the same item the same ID and
  the two POA&Ms can be diffed.
* The schedule uses the *original* (raw) CAT. A reviewer's severity override
  is recorded and shown, but it does not buy extra time on its own; that is a
  risk decision for the AO, not the tool.
* Each item has one primary control (the first mapped control in the rule's
  CCI order) for grouping; all mapped controls and CCIs are kept on the item.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date

from .cci import CciCatalog, control_family, control_sort_key
from .config import Rules
from .models import Asset, Cat, Finding, SourceType, Status

MAX_DESCRIPTION = 2000  # keep descriptions a reasonable size for POA&M fields


@dataclass
class PoamItem:
    item_id: str
    kind: str  # "STIG" or "ACAS"
    check_id: str
    title: str
    description: str
    fix_text: str
    raw_cat: Cat
    cat: Cat  # after reviewer overrides (most severe across hosts)
    primary_control: str
    controls: list[str]
    ccis: list[str]
    mapping_basis: str  # "CCI", "Fallback: no mapped CCI", or "ACAS default"
    scheduled_completion: date
    status: str
    sources: list[str] = field(default_factory=list)  # Source Identifying Vulnerability
    source_files: list[str] = field(default_factory=list)
    stig_ids: list[str] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)
    assets: list[Asset] = field(default_factory=list)
    review_statuses: list[str] = field(default_factory=list)
    unmapped_ccis: list[str] = field(default_factory=list)
    override_notes: list[str] = field(default_factory=list)
    finding_details: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    iavas: list[str] = field(default_factory=list)
    nessus_severity: int | None = None
    merged_findings: int = 0

    @property
    def devices(self) -> list[str]:
        return [a.label for a in self.assets]

    @property
    def family(self) -> str:
        return control_family(self.primary_control)

    @property
    def security_checks(self) -> str:
        """eMASS "Security Checks": STIG Vuln/Rule/STIG IDs or the ACAS plugin ID."""
        if self.kind == "ACAS":
            return f"Plugin ID {self.check_id}"
        return "; ".join([self.check_id, *self.rule_ids, *self.stig_ids])


@dataclass
class BuildResult:
    items: list[PoamItem]
    findings: list[Finding]
    not_reviewed: list[Finding]
    as_of: date
    rules: Rules
    catalog_label: str = ""

    def by_control(self) -> dict[str, list[PoamItem]]:
        groups: dict[str, list[PoamItem]] = defaultdict(list)
        for item in self.items:
            groups[item.primary_control].append(item)
        return dict(sorted(groups.items(), key=lambda kv: control_sort_key(kv[0])))

    @property
    def unmapped_ccis(self) -> list[str]:
        return sorted({c for item in self.items for c in item.unmapped_ccis})


def _add_unique(target: list, values) -> None:
    for v in values:
        if v and v not in target:
            target.append(v)


def _map_controls(
    finding: Finding, catalog: CciCatalog | None, rules: Rules
) -> tuple[list[str], str, list[str]]:
    """Return (controls, basis, unmapped_ccis) for one finding."""
    if finding.source_type is SourceType.NESSUS:
        return [rules.acas_control], "ACAS default", []
    controls: list[str] = []
    unmapped: list[str] = []
    for cci in finding.ccis:
        mapped = catalog.controls_for(cci) if catalog else []
        if mapped:
            _add_unique(controls, mapped)
        else:
            unmapped.append(cci)
    if controls:
        return controls, "CCI", unmapped
    return [rules.stig_unmapped_control], "Fallback: no mapped CCI", unmapped


def build_poam(
    findings: list[Finding],
    catalog: CciCatalog | None,
    rules: Rules,
    as_of: date,
) -> BuildResult:
    """Build POA&M items from findings. Pure function: no I/O."""
    wanted = {Status.OPEN}
    if rules.include_not_reviewed:
        wanted.add(Status.NOT_REVIEWED)

    groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for f in findings:
        if f.status in wanted:
            groups[f.dedupe_key].append(f)

    items: list[PoamItem] = []
    for (kind, check_id), group in groups.items():
        first = group[0]
        is_acas = kind == "acas"
        raw_cat = min((f.cat for f in group), key=lambda c: c.rank)
        eff_cat = min((f.effective_cat for f in group), key=lambda c: c.rank)

        controls: list[str] = []
        unmapped: list[str] = []
        basis = ""
        for f in group:
            c, b, u = _map_controls(f, catalog, rules)
            _add_unique(controls, c)
            _add_unique(unmapped, u)
            basis = basis or b
            if b == "CCI":
                basis = "CCI"

        description = first.title
        if first.description and first.description != first.title:
            description = f"{first.title}\n\n{first.description}"
        if len(description) > MAX_DESCRIPTION:
            description = description[: MAX_DESCRIPTION - 3] + "..."

        item = PoamItem(
            item_id=f"ACAS-{check_id}" if is_acas else check_id,
            kind="ACAS" if is_acas else "STIG",
            check_id=check_id,
            title=first.title,
            description=description,
            fix_text=first.fix_text,
            raw_cat=raw_cat,
            cat=eff_cat,
            primary_control=controls[0],
            controls=controls,
            ccis=[],
            mapping_basis=basis,
            scheduled_completion=rules.due_date(raw_cat, as_of),
            status=rules.poam_status,
            unmapped_ccis=unmapped,
        )
        seen_assets: set[str] = set()
        for f in group:
            _add_unique(item.ccis, f.ccis)
            _add_unique(item.sources, [f.benchmark])
            _add_unique(item.source_files, [f.source_file])
            _add_unique(item.stig_ids, [f.stig_id])
            _add_unique(item.rule_ids, [f.rule_id])
            _add_unique(item.review_statuses, [f.status.value])
            _add_unique(item.cves, f.cves)
            _add_unique(item.iavas, f.iavas)
            if f.asset.key not in seen_assets:
                seen_assets.add(f.asset.key)
                item.assets.append(f.asset)
            if f.finding_details:
                _add_unique(item.finding_details, [f"{f.asset.label}: {f.finding_details}"])
            if f.cat_override and f.cat_override != f.cat:
                note = f"{f.asset.label}: {f.cat.value} -> {f.cat_override.value}"
                if f.override_reason:
                    note += f" ({f.override_reason})"
                _add_unique(item.override_notes, [note])
            if f.nessus_severity is not None:
                item.nessus_severity = max(item.nessus_severity or 0, f.nessus_severity)
        item.assets.sort(key=lambda a: a.key)
        item.merged_findings = len(group)
        items.append(item)

    items.sort(
        key=lambda i: (i.raw_cat.rank, control_sort_key(i.primary_control), i.kind, i.check_id)
    )
    catalog_label = ""
    if catalog is not None:
        catalog_label = f"CCI List {catalog.version or '?'} ({len(catalog)} CCIs)".strip()
    return BuildResult(
        items=items,
        findings=list(findings),
        not_reviewed=[f for f in findings if f.status is Status.NOT_REVIEWED],
        as_of=as_of,
        rules=rules,
        catalog_label=catalog_label,
    )
