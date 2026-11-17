"""OSCAL 1.1.2 Plan of Action and Milestones (JSON).

How a POA&M item is expressed in OSCAL (one set per weakness):

    observation  - what was seen: the check, how (TEST), on which inventory items
    risk         - the weakness as a risk: status "open", deadline = due date
    finding      - the control statement it affects, state "not-satisfied"
    poam-item    - ties the three together; this is the POA&M line itself

Hosts become ``local-definitions.inventory-items`` so observations can point at
them by UUID.

UUIDs are deterministic (UUIDv5 over the system name + weakness), so the same
weakness keeps the same poam-item/risk/finding UUID across monthly runs. The
document UUID and observations include the as-of date, because those describe a
point in time.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .. import __version__
from ..models import Asset
from ..poam import BuildResult, PoamItem
from .columns import raw_severity

OSCAL_VERSION = "1.1.2"
NS = "https://github.com/JulietRodriguez/stig-poam-builder/ns/oscal"
_UUID_NS = uuid.UUID("6f1c1b0e-6a51-5d5e-9a4e-6b7d1f3f9a10")
UUID_RE = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[45][0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$"
)


def _uuid(*parts: str) -> str:
    return str(uuid.uuid5(_UUID_NS, "|".join(parts)))


def _line(text: str) -> str:
    """OSCAL plain strings can't contain line breaks or edge whitespace."""
    return " ".join((text or "").split()) or "-"


def _prop(name: str, value: str, ns: str | None = NS) -> dict[str, str]:
    p = {"name": name, "value": _line(value)}
    if ns:
        p["ns"] = ns
    return p


def statement_id(control: str) -> str:
    """'AC-2(4)' -> 'ac-2.4_smt' (NIST 800-53 Rev 5 OSCAL catalog statement IDs)."""
    m = re.match(r"^([A-Z]{2})-(\d+)(?:\((\d+)\))?$", control)
    if not m:
        return control.lower() + "_smt"
    fam, num, enh = m.groups()
    base = f"{fam.lower()}-{int(num)}"
    return f"{base}.{int(enh)}_smt" if enh else f"{base}_smt"


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _inventory_item(system: str, asset: Asset) -> dict[str, Any]:
    props = [_prop("asset-id", asset.label, ns=None)]
    if asset.fqdn:
        props.append(_prop("fqdn", asset.fqdn, ns=None))
    if asset.ip and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", asset.ip):
        props.append(_prop("ipv4-address", asset.ip, ns=None))
    if asset.mac:
        props.append(_prop("mac-address", asset.mac, ns=None))
    return {
        "uuid": _uuid(system, "asset", asset.key),
        "description": f"Host {asset.label} (from checklist/scan input).",
        "props": props,
    }


def build_oscal_poam(
    result: BuildResult,
    system_name: str = "Example System",
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    generated_at = generated_at or datetime.now(UTC)
    sys_key = system_name.strip() or "Example System"
    as_of = result.as_of.isoformat()

    assets: dict[str, Asset] = {}
    for item in result.items:
        for a in item.assets:
            assets.setdefault(a.key, a)
    inventory = [_inventory_item(sys_key, a) for _, a in sorted(assets.items())]
    asset_uuid = {k: _uuid(sys_key, "asset", k) for k in assets}

    observations, risks, findings, poam_items = [], [], [], []
    for item in result.items:
        obs_uuid = _uuid(sys_key, "observation", item.item_id, as_of)
        risk_uuid = _uuid(sys_key, "risk", item.item_id)
        finding_uuid = _uuid(sys_key, "finding", item.item_id)
        method = "ACAS vulnerability scan" if item.kind == "ACAS" else "STIG checklist review"

        observations.append(
            {
                "uuid": obs_uuid,
                "title": _line(f"{item.item_id}: {item.title}"),
                "description": f"{method} reported this weakness as open on "
                f"{len(item.assets)} device(s).",
                "props": [_prop("security-checks", item.security_checks)],
                "methods": ["TEST"],
                "types": ["finding"],
                "subjects": [
                    {"subject-uuid": asset_uuid[a.key], "type": "inventory-item"}
                    for a in item.assets
                ],
                "collected": _iso(generated_at),
                **({"remarks": "\n\n".join(item.finding_details)} if item.finding_details else {}),
            }
        )
        risk_props = [
            _prop("severity-category", item.raw_cat.value),
            _prop("raw-severity", raw_severity(item)),
            _prop("source", "\n".join(item.sources)),
        ]
        risk_props += [_prop("cci", c) for c in item.ccis]
        risk_props += [_prop("cve", c) for c in item.cves]
        risks.append(
            {
                "uuid": risk_uuid,
                "title": _line(item.title),
                "description": item.description,
                "statement": item.fix_text or "See the source checklist or scan for remediation.",
                "props": risk_props,
                "status": "open",
                "deadline": f"{item.scheduled_completion.isoformat()}T23:59:59Z",
                "related-observations": [{"observation-uuid": obs_uuid}],
            }
        )
        findings.append(
            {
                "uuid": finding_uuid,
                "title": _line(f"{item.primary_control} not satisfied: {item.item_id}"),
                "description": f"Open {item.raw_cat.value} weakness mapped to "
                f"{item.primary_control} ({item.mapping_basis}).",
                "target": {
                    "type": "statement-id",
                    "target-id": statement_id(item.primary_control),
                    "status": {"state": "not-satisfied"},
                },
                "related-observations": [{"observation-uuid": obs_uuid}],
                "related-risks": [{"risk-uuid": risk_uuid}],
            }
        )
        poam_items.append(_poam_item(sys_key, item, obs_uuid, risk_uuid, finding_uuid))

    return {
        "plan-of-action-and-milestones": {
            "uuid": _uuid(sys_key, "poam", as_of),
            "metadata": {
                "title": _line(f"Plan of Action and Milestones: {sys_key}"),
                "last-modified": _iso(generated_at),
                "version": as_of,
                "oscal-version": OSCAL_VERSION,
                "props": [_prop("generator", f"stig-poam-builder {__version__}")],
                "remarks": "Generated from STIG checklists and ACAS scan results. "
                "Review before submission.",
            },
            "system-id": {"identifier-type": "https://ietf.org/rfc/rfc4122", "id": _uuid(sys_key)},
            **({"local-definitions": {"inventory-items": inventory}} if inventory else {}),
            **({"observations": observations} if observations else {}),
            **({"risks": risks} if risks else {}),
            **({"findings": findings} if findings else {}),
            "poam-items": poam_items,
        }
    }


def _poam_item(sys_key: str, item: PoamItem, obs: str, risk: str, finding: str) -> dict[str, Any]:
    props = [
        _prop("poam-item-id", item.item_id),
        _prop("control", item.primary_control),
        _prop("severity-category", item.raw_cat.value),
        _prop("scheduled-completion-date", item.scheduled_completion.isoformat()),
    ]
    props += [_prop("related-control", c) for c in item.controls[1:]]
    out: dict[str, Any] = {
        "uuid": _uuid(sys_key, "poam-item", item.item_id),
        "title": _line(item.title),
        "description": item.description,
        "props": props,
        "related-findings": [{"finding-uuid": finding}],
        "related-observations": [{"observation-uuid": obs}],
        "related-risks": [{"risk-uuid": risk}],
    }
    if item.override_notes:
        out["remarks"] = "Severity overrides: " + "; ".join(item.override_notes)
    return out


def validate_structure(doc: dict[str, Any]) -> list[str]:
    """Checks JSON Schema can't do: required parts present, UUIDs well formed,
    and every related-* reference points at something that exists.

    Returns a list of problems (empty means OK). Full schema validation against
    NIST's published OSCAL 1.1.2 POA&M JSON Schema runs in CI
    (tools/validate_oscal.py).
    """
    errors: list[str] = []
    root = doc.get("plan-of-action-and-milestones")
    if not isinstance(root, dict):
        return ["missing plan-of-action-and-milestones root"]
    for key in ("uuid", "metadata", "poam-items"):
        if key not in root:
            errors.append(f"missing required '{key}'")
    meta = root.get("metadata", {})
    for key in ("title", "last-modified", "version", "oscal-version"):
        if key not in meta:
            errors.append(f"metadata missing '{key}'")
    if meta.get("oscal-version") != OSCAL_VERSION:
        errors.append(f"oscal-version is {meta.get('oscal-version')!r}, expected {OSCAL_VERSION}")

    seen: set[str] = set()

    def check_uuid(value: Any, where: str) -> None:
        if not isinstance(value, str) or not UUID_RE.match(value):
            errors.append(f"{where}: invalid uuid {value!r}")
        elif value in seen:
            errors.append(f"{where}: duplicate uuid {value}")
        else:
            seen.add(value)

    check_uuid(root.get("uuid"), "root")
    inv = {i.get("uuid") for i in root.get("local-definitions", {}).get("inventory-items", [])}
    for i in root.get("local-definitions", {}).get("inventory-items", []):
        check_uuid(i.get("uuid"), "inventory-item")
    obs = {o.get("uuid") for o in root.get("observations", [])}
    risks = {r.get("uuid") for r in root.get("risks", [])}
    fnds = {f.get("uuid") for f in root.get("findings", [])}

    for o in root.get("observations", []):
        check_uuid(o.get("uuid"), "observation")
        for key in ("description", "methods", "collected"):
            if key not in o:
                errors.append(f"observation {o.get('uuid')}: missing '{key}'")
        for s in o.get("subjects", []):
            if s.get("subject-uuid") not in inv:
                errors.append(f"observation {o.get('uuid')}: unknown subject {s}")
    for r in root.get("risks", []):
        check_uuid(r.get("uuid"), "risk")
        for key in ("title", "description", "statement", "status"):
            if key not in r:
                errors.append(f"risk {r.get('uuid')}: missing '{key}'")
        for ro in r.get("related-observations", []):
            if ro.get("observation-uuid") not in obs:
                errors.append(f"risk {r.get('uuid')}: unknown observation")
    for f in root.get("findings", []):
        check_uuid(f.get("uuid"), "finding")
        target = f.get("target", {})
        if not all(k in target for k in ("type", "target-id", "status")):
            errors.append(f"finding {f.get('uuid')}: incomplete target")
        for rr in f.get("related-risks", []):
            if rr.get("risk-uuid") not in risks:
                errors.append(f"finding {f.get('uuid')}: unknown risk")
    for p in root.get("poam-items", []):
        if "uuid" in p:
            check_uuid(p["uuid"], "poam-item")
        for key in ("title", "description"):
            if key not in p:
                errors.append(f"poam-item {p.get('uuid')}: missing '{key}'")
        for ref, pool, name in (
            ("related-findings", fnds, "finding-uuid"),
            ("related-observations", obs, "observation-uuid"),
            ("related-risks", risks, "risk-uuid"),
        ):
            for r in p.get(ref, []):
                if r.get(name) not in pool:
                    errors.append(f"poam-item {p.get('uuid')}: unknown {name}")
    return errors


def write_oscal(
    result: BuildResult,
    path: str | Path,
    system_name: str = "Example System",
    generated_at: datetime | None = None,
) -> Path:
    path = Path(path)
    doc = build_oscal_poam(result, system_name=system_name, generated_at=generated_at)
    problems = validate_structure(doc)
    if problems:  # pragma: no cover - would mean a bug in build_oscal_poam
        raise ValueError("generated OSCAL failed structural checks: " + "; ".join(problems))
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path
