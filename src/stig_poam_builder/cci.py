"""Load DISA's CCI List and map CCIs to NIST SP 800-53 controls.

DISA publishes the CCI List as ``U_CCI_List.xml`` (namespace
``http://iase.disa.mil/cci``). Each ``cci_item`` carries ``reference`` elements,
one per document revision, for example::

    <cci_item id="CCI-000366">
      <definition>...</definition>
      <references>
        <reference creator="NIST" title="NIST SP 800-53 Revision 4" version="4" index="CM-6 b" />
        <reference creator="NIST" title="NIST SP 800-53 Revision 5" version="5" index="CM-6 b" />
        <reference creator="NIST" title="NIST SP 800-53A" version="1" index="CM-6.1 (iv)" />
      </references>
    </cci_item>

We read the 800-53 reference for the requested revision (5 by default), and
reduce its ``index`` to a control or enhancement ID: "CM-6 b" -> "CM-6",
"AC-2 (4) (a)" -> "AC-2(4)". Assessment-procedure references (800-53A) are
ignored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from defusedxml import ElementTree as SafeET

from .parsers.common import ParseError

_INDEX_RE = re.compile(r"^\s*([A-Z]{2})-(\d+)(?:\s*\((\d+)\))?")
CONTROL_ID_RE = re.compile(r"^[A-Z]{2}-\d+(\(\d+\))?$")


def control_from_index(index: str) -> str | None:
    """Reduce a CCI reference index to a control ID.

    >>> control_from_index("AC-2 (4) (a)")
    'AC-2(4)'
    >>> control_from_index("CM-6 b")
    'CM-6'
    """
    m = _INDEX_RE.match(index or "")
    if not m:
        return None
    family, number, enhancement = m.groups()
    base = f"{family}-{int(number)}"
    return f"{base}({int(enhancement)})" if enhancement else base


def control_family(control_id: str) -> str:
    """'AC-2(4)' -> 'AC'."""
    return control_id.split("-", 1)[0]


def control_sort_key(control_id: str) -> tuple[str, int, int]:
    """Sort AC-2 < AC-2(4) < AC-11 (numeric, not string, ordering)."""
    m = re.match(r"^([A-Z]{2})-(\d+)(?:\((\d+)\))?$", control_id)
    if not m:
        return (control_id, 0, 0)
    fam, num, enh = m.groups()
    return (fam, int(num), int(enh or 0))


@dataclass
class CciEntry:
    cci_id: str
    definition: str = ""
    references: list[str] = field(default_factory=list)  # raw 800-53 index strings
    controls: list[str] = field(default_factory=list)  # reduced control IDs


@dataclass
class CciCatalog:
    revision: int
    entries: dict[str, CciEntry] = field(default_factory=dict)
    version: str = ""
    publish_date: str = ""

    def controls_for(self, cci: str) -> list[str]:
        entry = self.entries.get(cci.strip().upper())
        return list(entry.controls) if entry else []

    def __len__(self) -> int:
        return len(self.entries)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _is_800_53_rev(ref_title: str, ref_version: str, revision: int) -> bool:
    title = ref_title.upper()
    if "800-53A" in title or "800-53" not in title:
        return False
    return ref_version.strip() == str(revision)


def load_cci_list(path: str | Path, revision: int = 5) -> CciCatalog:
    """Parse a DISA CCI List XML file into a lookup catalog."""
    path = Path(path)
    try:
        root = SafeET.parse(path).getroot()
    except Exception as exc:
        raise ParseError(f"{path.name}: not a readable CCI List XML file ({exc})") from exc
    if _local(root.tag) != "cci_list":
        raise ParseError(f"{path.name}: root element is not <cci_list>")

    catalog = CciCatalog(revision=revision)
    for el in root.iter():
        name = _local(el.tag)
        if name == "version" and not catalog.version:
            catalog.version = (el.text or "").strip()
        elif name == "publishdate" and not catalog.publish_date:
            catalog.publish_date = (el.text or "").strip()
        elif name == "cci_item":
            cci_id = (el.get("id") or "").strip().upper()
            if not cci_id:
                continue
            entry = CciEntry(cci_id=cci_id)
            for child in el.iter():
                cname = _local(child.tag)
                if cname == "definition":
                    entry.definition = (child.text or "").strip()
                elif cname == "reference" and _is_800_53_rev(
                    child.get("title", ""), child.get("version", ""), revision
                ):
                    index = child.get("index", "")
                    entry.references.append(index)
                    control = control_from_index(index)
                    if control and control not in entry.controls:
                        entry.controls.append(control)
            catalog.entries[cci_id] = entry
    if not catalog.entries:
        raise ParseError(f"{path.name}: no cci_item elements found")
    return catalog
