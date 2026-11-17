"""Generate the SYNTHETIC sample inputs in samples/inputs/.

Nothing here comes from a real system. Host names, IPs (RFC 5737 documentation
ranges), STIG rules (V-9xxxxx), plugin IDs (9xxxxx) and CVEs (CVE-2099-*) are
all invented. CCI numbers are real identifiers so the mapping step has
something to look up; see samples/cci/README.md for what that means.

Run:  python tools/make_samples.py
"""

from __future__ import annotations

import json
from pathlib import Path
from xml.sax.saxutils import escape

OUT = Path(__file__).resolve().parent.parent / "samples" / "inputs"

STIG_TITLE = "SYNTHETIC Demo Operating System Security Technical Implementation Guide"
STIG_VERSION = "1"
STIG_RELEASE = "Release: 2 Benchmark Date: 01 Oct 2026"

# (vuln_id, rule_ver, severity, title, ccis)
RULES = [
    (
        "V-900001",
        "DEMO-OS-000010",
        "high",
        "The demo OS must store only encrypted representations of passwords.",
        ["CCI-000196"],
    ),
    (
        "V-900002",
        "DEMO-OS-000020",
        "medium",
        "The demo OS must display the Standard Mandatory DoD Notice and Consent Banner before granting access.",
        ["CCI-000048"],
    ),
    (
        "V-900003",
        "DEMO-OS-000030",
        "medium",
        "The demo OS must enforce a limit of three consecutive invalid logon attempts.",
        ["CCI-000044"],
    ),
    (
        "V-900004",
        "DEMO-OS-000040",
        "medium",
        "The demo OS must generate audit records for privileged activity.",
        ["CCI-000172"],
    ),
    (
        "V-900005",
        "DEMO-OS-000050",
        "low",
        "The demo OS must protect audit tools from unauthorized modification.",
        ["CCI-001494"],
    ),
    (
        "V-900006",
        "DEMO-OS-000060",
        "medium",
        "The demo OS must be configured in accordance with the security configuration settings.",
        ["CCI-000366"],
    ),
    (
        "V-900007",
        "DEMO-OS-000070",
        "high",
        "The demo OS must use FIPS-validated cryptography to protect remote access sessions.",
        ["CCI-001453", "CCI-002450"],
    ),
    (
        "V-900008",
        "DEMO-OS-000080",
        "medium",
        "The demo OS must enforce approved authorizations for access to system files.",
        ["CCI-000213"],
    ),
    (
        "V-900009",
        "DEMO-OS-000090",
        "low",
        "The demo OS must protect the confidentiality of transmitted information.",
        ["CCI-002418"],
    ),
    (
        "V-900010",
        "DEMO-OS-000100",
        "medium",
        "The demo OS must disable an unsupported legacy service.",
        ["CCI-009999"],
    ),  # unmapped on purpose
]

# Per-host status for each rule (index-aligned with RULES).
WEB01 = [
    "Open",
    "NotAFinding",
    "Open",
    "Open",
    "Not_Applicable",
    "Open",
    "Open",
    "NotAFinding",
    "Open",
    "Not_Reviewed",
]
DB01 = [
    "open",
    "open",
    "not_a_finding",
    "open",
    "open",
    "not_reviewed",
    "open",
    "not_a_finding",
    "not_applicable",
    "open",
]
APP01 = [
    "NotAFinding",
    "Open",
    "Open",
    "NotAFinding",
    "Open",
    "Open",
    "NotAFinding",
    "Open",
    "Open",
    "Not_Reviewed",
]


def _sd(attr: str, data: str) -> str:
    return (
        f"<STIG_DATA><VULN_ATTRIBUTE>{attr}</VULN_ATTRIBUTE>"
        f"<ATTRIBUTE_DATA>{escape(data)}</ATTRIBUTE_DATA></STIG_DATA>"
    )


def make_ckl(
    host: str, ip: str, statuses: list[str], override: dict[str, tuple[str, str]] | None = None
) -> str:
    override = override or {}
    vulns = []
    for (vid, ver, sev, title, ccis), status in zip(RULES, statuses, strict=True):
        n = vid.split("-")[1]
        data = [
            _sd("Vuln_Num", vid),
            _sd("Severity", sev),
            _sd("Group_Title", f"SRG-OS-{n}-DEMO"),
            _sd("Rule_ID", f"SV-{n}r100{n[-2:]}_rule"),
            _sd("Rule_Ver", ver),
            _sd("Rule_Title", title),
            _sd("Vuln_Discuss", f"Synthetic discussion for {vid}. Not real STIG content."),
            _sd("Check_Content", f"Synthetic check procedure for {vid}."),
            _sd("Fix_Text", f"Synthetic fix: apply the configuration described in {ver}."),
            _sd("STIGRef", f"{STIG_TITLE} :: Version {STIG_VERSION}, {STIG_RELEASE}"),
        ]
        data += [_sd("CCI_REF", c) for c in ccis]
        sev_o, just = override.get(vid, ("", ""))
        details = "Synthetic finding detail: setting not configured." if status == "Open" else ""
        vulns.append(
            "<VULN>"
            + "".join(data)
            + f"<STATUS>{status}</STATUS><FINDING_DETAILS>{details}</FINDING_DETAILS>"
            + "<COMMENTS></COMMENTS>"
            + f"<SEVERITY_OVERRIDE>{sev_o}</SEVERITY_OVERRIDE>"
            + f"<SEVERITY_JUSTIFICATION>{escape(just)}</SEVERITY_JUSTIFICATION></VULN>"
        )
    si = "".join(
        f"<SI_DATA><SID_NAME>{k}</SID_NAME><SID_DATA>{escape(v)}</SID_DATA></SI_DATA>"
        for k, v in [
            ("version", STIG_VERSION),
            ("classification", "UNCLASSIFIED"),
            ("stigid", "SYNTHETIC_Demo_OS_STIG"),
            ("releaseinfo", STIG_RELEASE),
            ("title", STIG_TITLE),
        ]
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<!--SYNTHETIC SAMPLE DATA - not from any real system-->\n"
        "<CHECKLIST><ASSET><ROLE>Member Server</ROLE><ASSET_TYPE>Computing</ASSET_TYPE>"
        f"<HOST_NAME>{host}</HOST_NAME><HOST_IP>{ip}</HOST_IP><HOST_MAC>00:00:5E:00:53:{ip[-2:]}</HOST_MAC>"
        f"<HOST_FQDN>{host}.demo.example</HOST_FQDN><TARGET_COMMENT/><TECH_AREA/><TARGET_KEY>9999</TARGET_KEY>"
        "<WEB_OR_DATABASE>false</WEB_OR_DATABASE><WEB_DB_SITE/><WEB_DB_INSTANCE/></ASSET>"
        f"<STIGS><iSTIG><STIG_INFO>{si}</STIG_INFO>{''.join(vulns)}</iSTIG></STIGS></CHECKLIST>\n"
    )


def make_cklb(host: str, ip: str, statuses: list[str]) -> dict:
    rules = []
    for (vid, ver, sev, title, ccis), status in zip(RULES, statuses, strict=True):
        n = vid.split("-")[1]
        rules.append(
            {
                "group_id": vid,
                "rule_id": f"SV-{n}r100{n[-2:]}_rule",
                "rule_version": ver,
                "group_title": f"SRG-OS-{n}-DEMO",
                "rule_title": title,
                "severity": sev,
                "status": status,
                "ccis": ccis,
                "discussion": f"Synthetic discussion for {vid}. Not real STIG content.",
                "check_content": f"Synthetic check procedure for {vid}.",
                "fix_text": f"Synthetic fix: apply the configuration described in {ver}.",
                "finding_details": "Synthetic finding detail." if status == "open" else "",
                "comments": "",
                "overrides": {},
            }
        )
    return {
        "title": "SYNTHETIC SAMPLE DATA - not from any real system",
        "id": "00000000-0000-4000-8000-000000000001",
        "cklb_version": "1.0",
        "target_data": {
            "target_type": "Computing",
            "host_name": host,
            "ip_address": ip,
            "mac_address": f"00:00:5E:00:53:{ip[-2:]}",
            "fqdn": f"{host}.demo.example",
            "role": "Member Server",
            "comments": "",
        },
        "stigs": [
            {
                "stig_name": STIG_TITLE,
                "display_name": STIG_TITLE,
                "stig_id": "SYNTHETIC_Demo_OS_STIG",
                "version": STIG_VERSION,
                "release_info": STIG_RELEASE,
                "rules": rules,
            }
        ],
    }


# (plugin_id, name, family, severity, stig_severity or "", cves, iava)
PLUGINS = [
    (
        "900101",
        "SYNTHETIC: Demo Web Server < 9.9.1 Remote Code Execution",
        "Web Servers",
        4,
        "I",
        ["CVE-2099-0001"],
        "2099-A-0001",
    ),
    (
        "900102",
        "SYNTHETIC: Demo TLS Library Weak Cipher Suites Supported",
        "General",
        2,
        "",
        [],
        "",
    ),
    (
        "900103",
        "SYNTHETIC: Demo Database Missing Security Patch",
        "Databases",
        3,
        "",
        ["CVE-2099-0002", "CVE-2099-0003"],
        "2099-A-0002",
    ),
    ("900104", "SYNTHETIC: Demo SSH Server Banner Discloses Version", "Misc.", 1, "", [], ""),
    ("900105", "SYNTHETIC: Demo OS Unsupported Version Detected", "General", 4, "", [], ""),
    ("900199", "SYNTHETIC: Host Fully Qualified Domain Name Resolution", "General", 0, "", [], ""),
    (
        "900200",
        "SYNTHETIC: Demo OS STIG audit check (compliance result)",
        "Policy Compliance",
        3,
        "",
        [],
        "",
    ),
]

HOSTS = {
    "web01": ("192.0.2.11", ["900101", "900102", "900104", "900199", "900200"]),
    "db01": ("192.0.2.12", ["900102", "900103", "900199"]),
    "app01": ("192.0.2.13", ["900102", "900105", "900104", "900199"]),
}


def make_nessus() -> str:
    by_id = {p[0]: p for p in PLUGINS}
    hosts = []
    for host, (ip, plugin_ids) in HOSTS.items():
        items = []
        for pid in plugin_ids:
            _, name, family, sev, stig_sev, cves, iava = by_id[pid]
            body = (
                f"<synopsis>Synthetic synopsis for plugin {pid}.</synopsis>"
                f"<description>Synthetic description for plugin {pid}. Not real scan data.</description>"
                f"<solution>Synthetic solution: upgrade or reconfigure per vendor guidance.</solution>"
                f"<risk_factor>{['None', 'Low', 'Medium', 'High', 'Critical'][sev]}</risk_factor>"
                f"<plugin_output>Synthetic plugin output for {host}.</plugin_output>"
            )
            body += "".join(f"<cve>{c}</cve>" for c in cves)
            if iava:
                body += f"<iava>{iava}</iava>"
            if stig_sev:
                body += f"<stig_severity>{stig_sev}</stig_severity>"
            items.append(
                f'<ReportItem port="443" svc_name="www" protocol="tcp" severity="{sev}" '
                f'pluginID="{pid}" pluginName="{escape(name)}" pluginFamily="{family}">{body}</ReportItem>'
            )
        hosts.append(
            f'<ReportHost name="{ip}"><HostProperties>'
            f'<tag name="host-ip">{ip}</tag><tag name="hostname">{host}</tag>'
            f'<tag name="host-fqdn">{host}.demo.example</tag>'
            f'<tag name="operating-system">SYNTHETIC Demo OS 1.0</tag>'
            f'<tag name="HOST_END">Thu Oct 15 10:00:00 2026</tag>'
            f"</HostProperties>{''.join(items)}</ReportHost>"
        )
    return (
        '<?xml version="1.0" ?>\n'
        "<!--SYNTHETIC SAMPLE DATA - not from any real system-->\n"
        "<NessusClientData_v2><Policy><policyName>SYNTHETIC Demo Policy</policyName></Policy>"
        f'<Report name="SYNTHETIC Monthly Scan">{"".join(hosts)}</Report></NessusClientData_v2>\n'
    )


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "web01_demo-os.ckl").write_text(
        make_ckl(
            "web01",
            "192.0.2.11",
            WEB01,
            override={
                "V-900003": (
                    "low",
                    "Synthetic: compensating control - account lockout enforced upstream by IdP.",
                )
            },
        ),
        encoding="utf-8",
    )
    (OUT / "app01_demo-os.ckl").write_text(make_ckl("app01", "192.0.2.13", APP01), encoding="utf-8")
    (OUT / "db01_demo-os.cklb").write_text(
        json.dumps(make_cklb("db01", "192.0.2.12", DB01), indent=2) + "\n", encoding="utf-8"
    )
    (OUT / "monthly_scan.nessus").write_text(make_nessus(), encoding="utf-8")
    print(f"wrote synthetic samples to {OUT}")


if __name__ == "__main__":
    main()
