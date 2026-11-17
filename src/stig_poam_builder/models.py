"""Normalized data model shared by every parser and output writer.

Every input format (CKL XML, CKLB JSON, Nessus XML) is converted into a list of
``Finding`` objects. Everything downstream (mapping, dedupe, POA&M output) only
ever sees ``Finding``, so adding a new input format never touches the outputs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Status(StrEnum):
    """Checklist review status, normalized across CKL and CKLB spellings."""

    OPEN = "Open"
    NOT_A_FINDING = "Not a Finding"
    NOT_APPLICABLE = "Not Applicable"
    NOT_REVIEWED = "Not Reviewed"


class Cat(StrEnum):
    """DoD vulnerability severity category."""

    CAT_I = "CAT I"
    CAT_II = "CAT II"
    CAT_III = "CAT III"

    @property
    def rank(self) -> int:
        """Sort key: CAT I first."""
        return {"CAT I": 1, "CAT II": 2, "CAT III": 3}[self.value]


class SourceType(StrEnum):
    CKL = "ckl"
    CKLB = "cklb"
    NESSUS = "nessus"

    @property
    def is_stig(self) -> bool:
        return self in (SourceType.CKL, SourceType.CKLB)


# STIG severity words -> CAT. DISA STIGs use high/medium/low for CAT I/II/III.
STIG_SEVERITY_TO_CAT = {"high": Cat.CAT_I, "medium": Cat.CAT_II, "low": Cat.CAT_III}

# Status spellings seen in STIG Viewer 2 (.ckl) and STIG Viewer 3 (.cklb).
_STATUS_ALIASES = {
    "open": Status.OPEN,
    "notafinding": Status.NOT_A_FINDING,
    "not_a_finding": Status.NOT_A_FINDING,
    "not a finding": Status.NOT_A_FINDING,
    "not_applicable": Status.NOT_APPLICABLE,
    "not applicable": Status.NOT_APPLICABLE,
    "notapplicable": Status.NOT_APPLICABLE,
    "not_reviewed": Status.NOT_REVIEWED,
    "not reviewed": Status.NOT_REVIEWED,
    "notreviewed": Status.NOT_REVIEWED,
}


def normalize_status(raw: str | None) -> Status:
    """Map any CKL/CKLB status spelling to a ``Status``.

    Unknown or empty values become NOT_REVIEWED: if we can't tell a rule was
    checked, the safe assumption is that it wasn't.
    """
    if not raw:
        return Status.NOT_REVIEWED
    return _STATUS_ALIASES.get(raw.strip().lower(), Status.NOT_REVIEWED)


def stig_severity_to_cat(raw: str | None) -> Cat | None:
    """Map a STIG severity word (high/medium/low) or a CAT label to ``Cat``."""
    if not raw:
        return None
    value = raw.strip().lower()
    if value in STIG_SEVERITY_TO_CAT:
        return STIG_SEVERITY_TO_CAT[value]
    roman = value.replace("cat", "").strip().upper()
    return {"I": Cat.CAT_I, "II": Cat.CAT_II, "III": Cat.CAT_III}.get(roman)


@dataclass
class Asset:
    """The host a finding was observed on."""

    hostname: str = ""
    ip: str = ""
    fqdn: str = ""
    mac: str = ""

    @property
    def label(self) -> str:
        """Short display name used in "Devices Affected"."""
        return self.hostname or self.fqdn or self.ip or "unknown-host"

    @property
    def key(self) -> str:
        """Identity used to tell two assets apart (case-insensitive)."""
        return (self.hostname or self.fqdn or self.ip or "unknown-host").lower()


@dataclass
class Finding:
    """One check result on one asset from one source file."""

    source_type: SourceType
    source_file: str
    asset: Asset
    check_id: str  # Vuln ID (V-xxxxxx) for STIGs, plugin ID for Nessus
    title: str
    status: Status
    cat: Cat
    rule_id: str = ""  # SV-xxxxxx rXXXXXX_rule (changes every STIG release)
    stig_id: str = ""  # Rule_Ver / rule_version, e.g. WN10-00-000005
    benchmark: str = ""  # STIG title + version/release, or "ACAS" plugin family
    ccis: list[str] = field(default_factory=list)
    description: str = ""
    fix_text: str = ""
    finding_details: str = ""
    comments: str = ""
    cat_override: Cat | None = None  # reviewer-adjusted severity
    override_reason: str = ""
    nessus_severity: int | None = None  # 0-4 for ACAS findings
    cves: list[str] = field(default_factory=list)
    iavas: list[str] = field(default_factory=list)

    @property
    def effective_cat(self) -> Cat:
        """Severity after any documented reviewer override."""
        return self.cat_override or self.cat

    @property
    def dedupe_key(self) -> tuple[str, str]:
        """Two findings with the same key describe the same weakness.

        STIG rules are keyed on the Vuln ID (stable across STIG releases, unlike
        the Rule ID). ACAS findings are keyed on the plugin ID.
        """
        kind = "stig" if self.source_type.is_stig else "acas"
        return (kind, self.check_id)
