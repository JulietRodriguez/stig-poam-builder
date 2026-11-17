"""Configurable rules (TOML). Defaults ship in data/default_rules.toml.

TOML was chosen over YAML because ``tomllib`` is in the standard library
(Python 3.11+), so configuration adds no dependency.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from datetime import date, timedelta
from importlib import resources
from pathlib import Path
from typing import Any

from .cci import CONTROL_ID_RE
from .models import Cat, stig_severity_to_cat


class ConfigError(ValueError):
    pass


@dataclass
class Rules:
    days: dict[Cat, int] = field(default_factory=dict)
    nist_revision: int = 5
    stig_unmapped_control: str = "CM-6"
    acas_control: str = "SI-2"
    include_informational: bool = False
    nessus_severity_map: dict[int, Cat] = field(default_factory=dict)
    include_not_reviewed: bool = False
    poam_status: str = "Ongoing"
    office_org: str = ""
    resources_required: str = ""

    def due_date(self, cat: Cat, as_of: date) -> date:
        """Scheduled Completion Date for a weakness of this CAT opened on ``as_of``."""
        return as_of + timedelta(days=self.days[cat])


def _default_dict() -> dict[str, Any]:
    text = resources.files("stig_poam_builder").joinpath("data/default_rules.toml").read_text()
    return tomllib.loads(text)


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def _positive_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ConfigError(f"{name} must be a whole number of days >= 1 (got {value!r})")
    return value


def _control(value: Any, name: str) -> str:
    if not isinstance(value, str) or not CONTROL_ID_RE.match(value):
        raise ConfigError(f"{name} must look like 'CM-6' or 'AC-2(4)' (got {value!r})")
    return value


def load_rules(path: str | Path | None = None) -> Rules:
    """Load defaults, then overlay a user TOML file if given. Validates values."""
    raw = _default_dict()
    if path is not None:
        try:
            user = tomllib.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(f"can't read rules file {path}: {exc}") from exc
        raw = _merge(raw, user)

    sched, mapping = raw.get("schedule", {}), raw.get("mapping", {})
    nessus, poam = raw.get("nessus", {}), raw.get("poam", {})

    sev_map: dict[int, Cat] = {}
    for key, label in (nessus.get("severity_map") or {}).items():
        try:
            sev = int(key)
        except ValueError as exc:
            raise ConfigError(f"nessus.severity_map key {key!r} is not 0-4") from exc
        cat = stig_severity_to_cat(str(label))
        if sev not in range(5) or cat is None:
            raise ConfigError(f"nessus.severity_map entry {key!r} = {label!r} is invalid")
        sev_map[sev] = cat

    revision = mapping.get("nist_revision", 5)
    if revision not in (4, 5):
        raise ConfigError(f"mapping.nist_revision must be 4 or 5 (got {revision!r})")

    return Rules(
        days={
            Cat.CAT_I: _positive_int(sched.get("cat_i_days"), "schedule.cat_i_days"),
            Cat.CAT_II: _positive_int(sched.get("cat_ii_days"), "schedule.cat_ii_days"),
            Cat.CAT_III: _positive_int(sched.get("cat_iii_days"), "schedule.cat_iii_days"),
        },
        nist_revision=revision,
        stig_unmapped_control=_control(
            mapping.get("stig_unmapped_control"), "mapping.stig_unmapped_control"
        ),
        acas_control=_control(mapping.get("acas_control"), "mapping.acas_control"),
        include_informational=bool(nessus.get("include_informational", False)),
        nessus_severity_map=sev_map,
        include_not_reviewed=bool(poam.get("include_not_reviewed", False)),
        poam_status=str(poam.get("status", "Ongoing")),
        office_org=str(poam.get("office_org", "")),
        resources_required=str(poam.get("resources_required", "")),
    )
