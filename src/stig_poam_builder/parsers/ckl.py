"""Parser for STIG Viewer 2.x checklists (.ckl, XML).

Layout (abridged):

    <CHECKLIST>
      <ASSET><HOST_NAME/><HOST_IP/><HOST_FQDN/><HOST_MAC/>...</ASSET>
      <STIGS><iSTIG>
        <STIG_INFO><SI_DATA><SID_NAME>title</SID_NAME><SID_DATA>...</SID_DATA></SI_DATA>...
        <VULN>
          <STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE><ATTRIBUTE_DATA>V-1</ATTRIBUTE_DATA>
          ... (one STIG_DATA per attribute; CCI_REF repeats once per CCI)
          <STATUS>Open</STATUS><FINDING_DETAILS/><COMMENTS/>
          <SEVERITY_OVERRIDE/><SEVERITY_JUSTIFICATION/>
        </VULN>
      </iSTIG></STIGS>
    </CHECKLIST>

XML is parsed with defusedxml so a malicious checklist can't trigger XXE or
"billion laughs" entity expansion.
"""

from __future__ import annotations

from pathlib import Path
from xml.etree.ElementTree import Element  # type only; parsing uses defusedxml

from defusedxml import ElementTree as SafeET

from ..models import Asset, Finding, SourceType, normalize_status, stig_severity_to_cat
from .common import ParseError, benchmark_label


def _text(el: Element | None, tag: str) -> str:
    if el is None:
        return ""
    child = el.find(tag)
    return (child.text or "").strip() if child is not None and child.text else ""


def _stig_info(istig: Element) -> dict[str, str]:
    info: dict[str, str] = {}
    for si in istig.findall("./STIG_INFO/SI_DATA"):
        name = _text(si, "SID_NAME")
        if name:
            info[name] = _text(si, "SID_DATA")
    return info


def _vuln_attrs(vuln: Element) -> tuple[dict[str, str], list[str]]:
    attrs: dict[str, str] = {}
    ccis: list[str] = []
    for sd in vuln.findall("STIG_DATA"):
        name = _text(sd, "VULN_ATTRIBUTE")
        data = _text(sd, "ATTRIBUTE_DATA")
        if name == "CCI_REF":
            if data and data not in ccis:
                ccis.append(data)
        elif name and name not in attrs:
            attrs[name] = data
    return attrs, ccis


def parse_ckl(path: str | Path) -> list[Finding]:
    """Return one ``Finding`` per VULN in the checklist (all statuses)."""
    path = Path(path)
    try:
        root = SafeET.parse(path).getroot()
    except Exception as exc:  # defusedxml raises several exception types
        raise ParseError(f"{path.name}: not a readable CKL XML file ({exc})") from exc
    if root.tag != "CHECKLIST":
        raise ParseError(f"{path.name}: root element is <{root.tag}>, expected <CHECKLIST>")

    asset_el = root.find("ASSET")
    asset = Asset(
        hostname=_text(asset_el, "HOST_NAME"),
        ip=_text(asset_el, "HOST_IP"),
        fqdn=_text(asset_el, "HOST_FQDN"),
        mac=_text(asset_el, "HOST_MAC"),
    )

    findings: list[Finding] = []
    for istig in root.findall("./STIGS/iSTIG"):
        info = _stig_info(istig)
        benchmark = benchmark_label(
            info.get("title", ""), info.get("version", ""), info.get("releaseinfo", "")
        )
        for vuln in istig.findall("VULN"):
            attrs, ccis = _vuln_attrs(vuln)
            vuln_id = attrs.get("Vuln_Num", "")
            if not vuln_id:
                continue
            cat = stig_severity_to_cat(attrs.get("Severity"))
            if cat is None:
                raise ParseError(
                    f"{path.name}: {vuln_id} has unknown severity {attrs.get('Severity')!r}"
                )
            findings.append(
                Finding(
                    source_type=SourceType.CKL,
                    source_file=path.name,
                    asset=asset,
                    check_id=vuln_id,
                    rule_id=attrs.get("Rule_ID", ""),
                    stig_id=attrs.get("Rule_Ver", ""),
                    title=attrs.get("Rule_Title", ""),
                    status=normalize_status(_text(vuln, "STATUS")),
                    cat=cat,
                    benchmark=benchmark,
                    ccis=ccis,
                    description=attrs.get("Vuln_Discuss", ""),
                    fix_text=attrs.get("Fix_Text", ""),
                    finding_details=_text(vuln, "FINDING_DETAILS"),
                    comments=_text(vuln, "COMMENTS"),
                    cat_override=stig_severity_to_cat(_text(vuln, "SEVERITY_OVERRIDE")),
                    override_reason=_text(vuln, "SEVERITY_JUSTIFICATION"),
                )
            )
    return findings
