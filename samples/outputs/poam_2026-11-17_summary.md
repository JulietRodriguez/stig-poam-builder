# POA&M Summary

- As of: **2026-11-17**
- Inputs: 4 files, 3 hosts (30 STIG checks, 8 ACAS findings)
- Control mapping: NIST SP 800-53 Rev 5 via CCI List SAMPLE (10 CCIs)
- **15 POA&M items** covering **26 open instances** (weakness x device)

## Open findings by CAT

|  | CAT I | CAT II | CAT III | Total |
|---|---|---|---|---|
| POA&M items | 5 | 7 | 3 | 15 |
| Open instances | 7 | 13 | 6 | 26 |

## Open POA&M items by control family

| Family | CAT I | CAT II | CAT III | Items | Instances |
|---|---|---|---|---|---|
| AC | 1 | 3 | 0 | 4 | 7 |
| AU | 0 | 1 | 1 | 2 | 4 |
| CM | 0 | 2 | 0 | 2 | 3 |
| IA | 1 | 0 | 0 | 1 | 2 |
| SC | 0 | 0 | 1 | 1 | 2 |
| SI | 3 | 1 | 1 | 5 | 8 |

## POA&M items by control

| Control | Items |
|---|---|
| AC-3 | 1 |
| AC-7 | 1 |
| AC-8 | 1 |
| AC-17(2) | 1 |
| AU-9 | 1 |
| AU-12 | 1 |
| CM-6 | 2 |
| IA-5(1) | 1 |
| SC-8 | 1 |
| SI-2 | 5 |

## STIG review status (all checks)

| Status | Checks |
|---|---|
| Open | 18 |
| Not a Finding | 7 |
| Not Applicable | 2 |
| Not Reviewed | 3 |

## Gaps: 3 checks Not Reviewed (NOT included in the POA&M)

| Host | Not Reviewed |
|---|---|
| app01 | 1 |
| db01 | 1 |
| web01 | 1 |

## Mapping warnings

- CCIs not found in the CCI List: CCI-009999
- Items on the fallback control: V-900010

Items with reviewer severity overrides: V-900003

