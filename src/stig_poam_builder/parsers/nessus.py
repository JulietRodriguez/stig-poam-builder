"""Parser for ACAS / Nessus scan exports (.nessus, NessusClientData_v2 XML).

Layout (abridged):

    <NessusClientData_v2>
      <Report name="...">
        <ReportHost name="10.0.0.5">
          <HostProperties><tag name="host-ip">10.0.0.5</tag><tag name="hostname">web01</tag>...
          <ReportItem port="445" severity="3" pluginID="12345" pluginName="..." pluginFamily="...">
            <synopsis/><description/><solution/><cve/>...<iava/><stig_severity>I</stig_severity>
          </ReportItem>
        </ReportHost>
      </Report>
    </NessusClientData_v2>

Severity: Nessus uses 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical. When a plugin
carries a ``stig_severity`` (I/II/III), that DoD-assigned CAT wins; otherwise the
mapping in ``NESSUS_TO_CAT`` is used (configurable in rules.toml).
"""

from __future__ import annotations

from pathlib import Path
from xml.etree.ElementTree import Element  # type only; parsing uses defusedxml

from defusedxml import ElementTree as SafeET

from ..models import Asset, Cat, Finding, SourceType, Status, stig_severity_to_cat
from .common import ParseError

# Default Nessus severity -> CAT used when a plugin has no stig_severity.
NESSUS_TO_CAT: dict[int, Cat] = {4: Cat.CAT_I, 3: Cat.CAT_I, 2: Cat.CAT_II, 1: Cat.CAT_III}

# Plugin families that are not vulnerabilities to POA&M.
# Policy Compliance results duplicate STIG checklist content (use the CKL for those).
SKIP_FAMILIES = {"Policy Compliance"}


def _child_text(el: Element, tag: str) -> str:
    child = el.find(tag)
    return (child.text or "").strip() if child is not None and child.text else ""


def _all_text(el: Element, tag: str) -> list[str]:
    out: list[str] = []
    for child in el.findall(tag):
        if child.text and child.text.strip() and child.text.strip() not in out:
            out.append(child.text.strip())
    return out


def _host_asset(host: Element) -> Asset:
    tags = {t.get("name", ""): (t.text or "").strip() for t in host.findall("./HostProperties/tag")}
    ip = tags.get("host-ip", "")
    fqdn = tags.get("host-fqdn", "")
    hostname = (
        tags.get("hostname") or tags.get("netbios-name") or (fqdn.split(".")[0] if fqdn else "")
    )
    return Asset(
        hostname=hostname or host.get("name", ""),
        ip=ip or host.get("name", ""),
        fqdn=fqdn,
        mac=tags.get("mac-address", ""),
    )


def parse_nessus(
    path: str | Path,
    severity_map: dict[int, Cat] | None = None,
    include_informational: bool = False,
) -> list[Finding]:
    """Return one OPEN ``Finding`` per (host, plugin) with severity > 0.

    A scan only reports what it found, so every ACAS finding is OPEN. Severity 0
    (informational) items are dropped unless ``include_informational`` is set,
    in which case they are treated as CAT III.
    """
    path = Path(path)
    sev_map = severity_map or NESSUS_TO_CAT
    try:
        root = SafeET.parse(path).getroot()
    except Exception as exc:
        raise ParseError(f"{path.name}: not a readable .nessus XML file ({exc})") from exc
    if root.tag != "NessusClientData_v2":
        raise ParseError(
            f"{path.name}: root element is <{root.tag}>, expected <NessusClientData_v2>"
        )

    findings: list[Finding] = []
    for host in root.iter("ReportHost"):
        asset = _host_asset(host)
        for item in host.findall("ReportItem"):
            family = item.get("pluginFamily", "")
            if family in SKIP_FAMILIES:
                continue
            try:
                severity = int(item.get("severity", "0"))
            except ValueError:
                severity = 0
            stig_cat = stig_severity_to_cat(_child_text(item, "stig_severity"))
            if severity == 0 and not include_informational:
                continue
            cat = stig_cat or sev_map.get(severity, Cat.CAT_III)
            plugin_id = item.get("pluginID", "")
            if not plugin_id:
                continue
            iavas = _all_text(item, "iava") + _all_text(item, "iavb") + _all_text(item, "iavt")
            findings.append(
                Finding(
                    source_type=SourceType.NESSUS,
                    source_file=path.name,
                    asset=asset,
                    check_id=plugin_id,
                    title=item.get("pluginName", "") or _child_text(item, "plugin_name"),
                    status=Status.OPEN,
                    cat=cat,
                    benchmark=f"ACAS: {family}" if family else "ACAS",
                    description=_child_text(item, "synopsis") or _child_text(item, "description"),
                    fix_text=_child_text(item, "solution"),
                    finding_details=_child_text(item, "plugin_output"),
                    nessus_severity=severity,
                    cves=_all_text(item, "cve"),
                    iavas=iavas,
                )
            )
    return findings
