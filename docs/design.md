# Design notes

Why stig-poam-builder works the way it does. Each section is a decision, the
reason for it, and what it costs.

## 1. One normalized `Finding` model

Every parser (CKL, CKLB, Nessus) returns the same `Finding` object: asset,
check ID, status, CAT, CCIs, text fields. Mapping, dedupe, and every output
only ever see `Finding`.

*Why:* adding a new input (for example SCC XCCDF results) means writing one
parser. Nothing downstream changes, and the tests for outputs don't care where
data came from.

## 2. Status and severity normalization

| Source | Raw value | Normalized |
|---|---|---|
| CKL | `Open`, `NotAFinding`, `Not_Applicable`, `Not_Reviewed` | Open / Not a Finding / Not Applicable / Not Reviewed |
| CKLB | `open`, `not_a_finding`, `not_applicable`, `not_reviewed` | same |
| STIG severity | `high` / `medium` / `low` | CAT I / CAT II / CAT III |
| Nessus severity | 4 / 3 / 2 / 1 / 0 | CAT I / CAT I / CAT II / CAT III / dropped (configurable) |
| Nessus `stig_severity` | I / II / III | wins over the table above |

An unknown or empty status becomes **Not Reviewed**. If the tool can't tell a
rule was checked, it should not assume it passed.

Only **Open** findings become POA&M items by default. **Not Reviewed** checks
are reported as a gap in the summary (per host), because an unreviewed check is
an assessment problem, not a known weakness. A rule switch can include them.

## 3. CCI -> NIST SP 800-53 Rev 5

STIG rules cite CCIs, and DISA's CCI List maps each CCI to an 800-53 reference
for Rev 4 and Rev 5. The parser:

* reads the reference for the chosen revision (Rev 5 default, Rev 4 for legacy
  packages) and ignores 800-53A assessment-procedure references;
* reduces the index to a control or enhancement: `AC-2 (4) (a)` -> `AC-2(4)`,
  `CM-6 b` -> `CM-6`;
* is namespace-agnostic, so a re-saved or older copy of the list still loads.

The CCI List is an input (`--cci-list`), not bundled. DISA updates it, and a
stale copy baked into a tool would quietly give wrong mappings. The repo only
ships a small sample excerpt for tests and the demo.

**Fallbacks.** A STIG rule whose CCIs don't map lands on `CM-6` (DISA's
catch-all CCI-000366 maps there) and is flagged in the output and the summary.
ACAS vulnerability findings map to `SI-2` (flaw remediation) by default. RA-5
is the control that *requires* scanning; a missing patch is a flaw-remediation
weakness. Both fallbacks are configurable.

## 4. One POA&M item per weakness, not per host

A STIG Vuln ID or ACAS plugin open on 40 hosts is **one** item with 40 entries
in Devices Affected. That keeps the POA&M readable and matches how ISSOs
normally write items.

* STIG findings dedupe on the **Vuln ID** (`V-xxxxxx`). The Rule ID
  (`SV-xxxxxxrNNNN_rule`) changes with every STIG release, so keying on it
  would split one weakness into two after a STIG update.
* ACAS findings dedupe on the **plugin ID**.
* The same host showing up twice (a `.ckl` and a `.cklb` of the same
  checklist, or two scans) counts once. Hosts match on hostname, then FQDN,
  then IP, case-insensitive.

The summary reports both **POA&M items** (distinct weaknesses) and **open
instances** (weakness x device), because leadership asks "how many items" and
the admins ask "how much work".

**Primary control.** eMASS POA&M items sit under one control, but a STIG rule
can cite CCIs that map to several. The item's primary control is the first
mapped control in the rule's CCI order; the rest are kept on the item
(Comments column, OSCAL `related-control` props).

## 5. Stable item IDs

Item IDs come from the weakness (`V-900001`, `ACAS-900101`), not a row
counter. Next month's run gives the same weakness the same ID, so two POA&Ms
can be diffed to see what closed and what's new. The OSCAL UUIDs for
poam-items, risks, and findings use the same idea (UUIDv5 over system name +
weakness).

## 6. Due dates from rules, using the raw CAT

`Scheduled Completion Date = as-of date + N days`, with N set per CAT in a
TOML rules file. The shipped values (30 / 90 / 180) are examples only. The
right numbers come from the AO or the organization.

The **raw** CAT drives the date. A reviewer's severity override is recorded and
shown (Severity column, Comments, OSCAL remarks) but does not extend the
deadline on its own. Downgrading a CAT is a risk decision for the AO.

The as-of date is an explicit input (default: today) so a run is reproducible
and tests are deterministic.

## 7. "eMASS-style", not "eMASS template"

The XLSX columns follow the eMASS POA&M fields that are publicly documented
(public POA&M tooling docs and the eMASS REST API field list). Component
templates differ (Navy, Army, and Marine Corps layouts are not identical), so
the workbook is labeled eMASS-style and says so on its About sheet.

The tool fills what it can know from the data: description, control, CCIs,
security checks, source, devices, raw severity, due date, a first milestone,
recommendations. It deliberately leaves **Likelihood, Impact, Relevance of
Threat, Residual Risk, Mitigations** blank. Those are assessor judgments.

## 8. OSCAL 1.1.2 mapping

| POA&M concept | OSCAL |
|---|---|
| Host | `local-definitions.inventory-items[]` |
| What the scan/checklist saw | `observations[]` (method TEST, subjects = hosts) |
| The weakness and its due date | `risks[]` (status `open`, `deadline`) |
| Control affected | `findings[]` (target `statement-id` e.g. `cm-6_smt`, state `not-satisfied`) |
| The POA&M line | `poam-items[]` linking the three above |

Validation is two layers:

1. `validate_structure()` (runs every time, no network): required fields,
   UUID format, no duplicate UUIDs, every `related-*` reference resolves.
   JSON Schema can't check cross-references.
2. CI downloads NIST's `oscal_poam_schema.json` for v1.1.2 (pinned by
   SHA-256) and validates the sample output against it. The schema uses
   `\p{L}`/`\p{N}` regex classes that Python's `re` lacks, so
   `tools/validate_oscal.py` translates just those two before validating.

## 9. Security of the tool itself

* XML is parsed with `defusedxml`. A checklist is untrusted input, and plain
  XML parsing can be abused (external entities, entity expansion). A test
  proves an XXE payload is rejected.
* Text that starts with `=`, `+`, `-`, or `@` is escaped before it goes into
  XLSX or CSV, so finding text can't become a live spreadsheet formula.
* `.gitignore` blocks `.ckl`, `.cklb`, and `.nessus` files outside the sample
  and test folders, so real data is hard to commit by accident.
* Two runtime dependencies (`openpyxl`, `defusedxml`). Config uses the
  standard library's `tomllib`.

## 10. CLI first, dashboard second

The CLI is what runs in a pipeline or a scheduled job. The Streamlit dashboard
is a thin view over the same `pipeline.run()`, so there's one implementation.
It's an optional extra so the core install stays small.
