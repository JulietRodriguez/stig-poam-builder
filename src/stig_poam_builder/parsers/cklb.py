"""Parser for STIG Viewer 3.x checklists (.cklb, JSON).

Layout (abridged; DISA publishes the full CKLB JSON schema with STIG Viewer 3):

    {
      "title": "...",
      "target_data": {"host_name": "", "ip_address": "", "fqdn": "", "mac_address": ""},
      "stigs": [{
        "stig_name": "...", "display_name": "...", "version": "2",
        "release_info": "Release: 5 Benchmark Date: 07 Jun 2023",
        "rules": [{
          "group_id": "V-220697", "rule_id": "SV-220697r569187_rule",
          "rule_version": "WN10-00-000005", "rule_title": "...",
          "severity": "medium", "status": "open",
          "ccis": ["CCI-000366"], "discussion": "...", "fix_text": "...",
          "finding_details": "", "comments": "", "overrides": {}
        }]
      }]
    }
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import Asset, Finding, SourceType, normalize_status, stig_severity_to_cat
from .common import ParseError, benchmark_label


def _s(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _override(rule: dict[str, Any]) -> tuple[str, str]:
    """Return (severity, reason) from a rule's ``overrides`` block, if any.

    STIG Viewer 3 stores a severity override as
    ``{"severity": {"severity": "low", "reason": "..."}}``; a flat string is
    accepted too so hand-edited files don't break the run.
    """
    overrides = rule.get("overrides") or {}
    sev = overrides.get("severity") if isinstance(overrides, dict) else None
    if isinstance(sev, dict):
        return _s(sev.get("severity")), _s(sev.get("reason"))
    if isinstance(sev, str):
        return sev, ""
    return "", ""


def parse_cklb(path: str | Path) -> list[Finding]:
    """Return one ``Finding`` per rule in the checklist (all statuses)."""
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ParseError(f"{path.name}: not a readable CKLB JSON file ({exc})") from exc
    if not isinstance(data, dict) or not isinstance(data.get("stigs"), list):
        raise ParseError(f"{path.name}: missing 'stigs' list; not a CKLB checklist")

    target = data.get("target_data") or {}
    asset = Asset(
        hostname=_s(target.get("host_name")),
        ip=_s(target.get("ip_address")),
        fqdn=_s(target.get("fqdn")),
        mac=_s(target.get("mac_address")),
    )

    findings: list[Finding] = []
    for stig in data["stigs"]:
        title = _s(stig.get("display_name")) or _s(stig.get("stig_name"))
        benchmark = benchmark_label(title, _s(stig.get("version")), _s(stig.get("release_info")))
        for rule in stig.get("rules") or []:
            vuln_id = _s(rule.get("group_id"))
            if not vuln_id:
                continue
            cat = stig_severity_to_cat(_s(rule.get("severity")))
            if cat is None:
                raise ParseError(
                    f"{path.name}: {vuln_id} has unknown severity {rule.get('severity')!r}"
                )
            override_sev, override_reason = _override(rule)
            ccis = [c for c in (_s(x) for x in rule.get("ccis") or []) if c]
            findings.append(
                Finding(
                    source_type=SourceType.CKLB,
                    source_file=path.name,
                    asset=asset,
                    check_id=vuln_id,
                    rule_id=_s(rule.get("rule_id")),
                    stig_id=_s(rule.get("rule_version")),
                    title=_s(rule.get("rule_title")),
                    status=normalize_status(_s(rule.get("status"))),
                    cat=cat,
                    benchmark=benchmark,
                    ccis=list(dict.fromkeys(ccis)),
                    description=_s(rule.get("discussion")),
                    fix_text=_s(rule.get("fix_text")),
                    finding_details=_s(rule.get("finding_details")),
                    comments=_s(rule.get("comments")),
                    cat_override=stig_severity_to_cat(override_sev),
                    override_reason=override_reason,
                )
            )
    return findings
