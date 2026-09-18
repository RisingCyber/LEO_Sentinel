# LEO Sentinel

A LEO satellite aggregator and mission classifier for signals and space-security research, built for the reconnaissance stage of the [SPARTA](https://sparta.aerospace.org) space
cybersecurity framework.

[![CI](https://github.com/RisingCyber/LEO_Sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/RisingCyber/LEO_Sentinel/actions/workflows/ci.yml)
![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![OWASP Top 10 2021](https://img.shields.io/badge/OWASP%20Top%2010-2021%20mapped-orange)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)

LEO Sentinel pulls publicly available Low Earth Orbit catalog data, classifies every object by mission type, operator, size, and lifecycle
status, and writes structured CSV/JSON output built as the supporting tool for the paper *"Hardening the High Frontier: LEO SmallSat Cybersecurity."*

<img width="1770" height="741" alt="LEO Sentinel CSV output in a spreadsheet, showing classified mission types, countries, and orbital parameters" src="https://github.com/user-attachments/assets/024ddb36-770c-41d9-820a-5c58b1da9803" />

---

## Contents

- [Why this exists](#why-this-exists)
- [Features](#features)
- [Quickstart](#quickstart)
- [Installation](#installation)
- [Usage](#usage)
- [Output schema](#output-schema)
- [Mission classification](#mission-classification)
- [SPARTA reconnaissance mapping](#sparta-reconnaissance-mapping)
- [Security architecture](#security-architecture-owasp-top-10-2021)
- [Data sources](#data-sources)
- [Testing & CI](#testing--ci)
- [Roadmap](#roadmap)
- [Legal & ethical use](#legal--ethical-use)
- [Contributing](#contributing)
- [License](#license)

---

## Why this exists

Anyone doing SDR-based signals research or space-security work starts with the same question: *what's actually up there, and what am I looking at?*
Raw SATCAT data answers that with catalog numbers and orbital elements useful, but not actionable on its own. LEO Sentinel adds the layer between
"here's a TLE" and "here's a prioritized research target": mission classification, operator attribution, an illustrative threat-tier estimate
grounded in published Aerospace Corporation research, and (optionally) known downlink frequency data from SatNOGS.

It's a **passive aggregation tool**. It only reads publicly published catalog data: see [Legal & ethical use](#legal--ethical-use).

## Features

- **Multi-source aggregation** : [CelesTrak](https://celestrak.org) SATCAT (primary, no auth), optional [Space-Track.org](https://www.space-track.org)
  supplement, optional [SatNOGS DB](https://db.satnogs.org) transmitter enrichment.
- **Mission classification engine** : a ~60-pattern, ordered regex taxonomy sorting objects into 18 classes (GNSS, weather, megaconstellation
  comms, military SATCOM, classified military, space stations, scientific, amateur radio, debris, and more). Run `--list-mission-classes` to print
  the full taxonomy with no network call.
- **Illustrative threat-tier heuristic** : maps each mission class to a band on the Bailey/Aerospace Corporation Tier I–VII adversary model
  (TOR-2021-01333-REV A), grounded in open-source incident history (e.g. Viasat KA-SAT, 2022). Explicitly labeled as a prioritization aid, never as intelligence.
- **Lifecycle & size classification** : flags newly-launched and recently-decayed objects from `LAUNCH_DATE`/`DECAY_DATE`, and buckets
  objects by radar cross-section into a coarse size class.
- **Cross-run anomaly triage** (`--diff-previous`) : diffs this run's catalog against the previous snapshot to surface new objects, vanished
  objects, and orbital-parameter shifts worth a human look. Documented as coarse triage, not confirmed maneuver detection.
- **Frequency enrichment** (`--enrich-frequencies`) : cross-references SatNOGS DB for known downlink frequency, modulation, transmitter count,
  and ITU frequency-violation flags.
- **Resilient by design** : disk caching, exponential-backoff retries, a `--diagnose` mode that shows exactly what a server sent back when JSON
  parsing fails (block page, rate limit, captive portal, WAF), and graceful per-source degradation (one source failing doesn't kill the run).
- **OWASP Top 10 (2021) mapped** : see [Security architecture](#security-architecture-owasp-top-10-2021).

## Quickstart

```bash
git clone https://github.com/RisingCyber/LEO_Sentinel.git
cd LEO_Sentinel
pip install -r requirements.txt

python3 leo_sentinel.py --format both --summary
```

Output lands in `./leo_data/` - `leo_satellites.csv`, `leo_satellites.json`,
plus a run log.

## Installation

**Option A - run the script directly:**

```bash
pip install -r requirements.txt
python3 leo_sentinel.py --help
```

**Option B - install as a CLI command:**

```bash
pip install -e .
leo-sentinel --help
```

Requires Python 3.8+. The single runtime dependency (`requests>=2.31.0`) is
version-pinned in `requirements.txt`.

## Usage

```text
python3 leo_sentinel.py [--format {csv,json,both}] [--out-dir PATH]
                        [--no-cache] [--verbose] [--summary]
                        [--enrich-frequencies] [--diff-previous]
                        [--diagnose] [--list-mission-classes]
```

| Flag | Description |
|---|---|
| `--format {csv,json,both}` | Output format (default: `csv`) |
| `--out-dir PATH` | Output directory (default: `./leo_data`) |
| `--no-cache` | Force a fresh download, ignoring the 6-hour disk cache |
| `--verbose`, `-v` | Verbose debug logging |
| `--summary` | Print the mission-class/country summary table after a run |
| `--user-agent STR` | Override the HTTP User-Agent (some WAFs block non-browser agents) |
| `--diagnose` | Single diagnostic request; prints raw HTTP status/headers/body and exits |
| `--enrich-frequencies` | Cross-reference SatNOGS DB for downlink frequency/mode data |
| `--diff-previous` | Diff this run against the previous snapshot for anomaly triage |
| `--list-mission-classes` | Print the full classification taxonomy and exit (no network) |
| `--version` | Print version and exit |

**Optional Space-Track.org credentials** (env vars only - never CLI args, so they never land in shell history):

```bash
export SPACETRACK_USER="you@example.com"
export SPACETRACK_PASS="..."
python3 leo_sentinel.py --format both --summary
```

### Examples

```bash
# Full run with a human-readable summary
python3 leo_sentinel.py --format both --summary

# See what every mission class means, with no network call
python3 leo_sentinel.py --list-mission-classes

# Enrich with known downlink frequencies for SDR tasking
python3 leo_sentinel.py --enrich-frequencies --summary

# Flag new/vanished objects and orbital-parameter shifts since last run
python3 leo_sentinel.py --diff-previous

# Troubleshoot a run that isn't returning data
python3 leo_sentinel.py --diagnose --verbose
```

## Output schema

Each row/object in `leo_satellites.csv` / `leo_satellites.json`:

| Field | Description |
|---|---|
| `norad_cat_id` | NORAD catalog number |
| `intl_designator` | International designator (`yyyy-nnn...`) |
| `name` | Object name |
| `country_code` / `country_name` | Owner/operator code and resolved name |
| `object_type` | `PAYLOAD`, `ROCKET BODY`, `DEBRIS`, etc. |
| `mission_class` / `mission_description` | Classification label and description - see [Mission classification](#mission-classification) |
| `illustrative_threat_tier` | Heuristic prioritization band — see caveat above |
| `lifecycle_status` | `NEWLY_LAUNCHED`, `RECENTLY_DECAYED`, `ESTABLISHED`, or `UNKNOWN` |
| `perigee_km` / `apogee_km` / `inclination_deg` / `period_min` | Orbital parameters |
| `rcs_size` / `size_class` | Radar cross-section bucket, raw and resolved |
| `launch_date` / `decay_date` | ISO 8601 dates where known |
| `current_in_orbit` | Ops status code |
| `orbit_class` | Always `LEO` (filter already applied) |
| `known_transmitter_count` / `primary_downlink_mhz` / `primary_downlink_mode` / `frequency_violation_flag` | Populated only with `--enrich-frequencies` |
| `data_source` | `CelesTrak` or `Space-Track.org` |
| `retrieved_utc` | Collection timestamp |

## Mission classification

The classifier runs an ordered set of regex patterns against each object's name (falling back to `OBJECT_TYPE` for debris/rocket bodies and anything
unmatched) and returns one of 18 classes — GNSS, weather, commercial and government Earth observation, communications megaconstellations, military
and classified military, missile warning, scientific, CubeSat, amateur radio, technology demonstrators, debris, and rocket bodies.

Run it yourself for the full, current list with descriptions and mapped threat tiers:

```bash
python3 leo_sentinel.py --list-mission-classes
```

## SPARTA reconnaissance mapping

LEO Sentinel supports the **Reconnaissance** tactic of the Aerospace Corporation's [Space Attack Research and Tactic Analysis (SPARTA)](https://sparta.aerospace.org)
framework — the publicly available body of knowledge on how spacecraft can be compromised, introduced in 2022 following the Viasat KA-SAT incident.

| Technique | Name | How this tool supports it |
|---|---|---|
| REC-0001 | Gather Spacecraft Design Information | `size_class` (RCS-derived), `object_type` |
| REC-0002 | Gather Spacecraft Descriptors | `norad_cat_id`, `intl_designator`, `name`, `country_name` |
| REC-0003 | Gather Spacecraft Communications Information | `--enrich-frequencies` (SatNOGS downlink/mode data) |
| REC-0004 | Gather Launch Information | `launch_date`, `intl_designator` |
| REC-0007 | Monitor for Safe-Mode Indicators | `--diff-previous` orbital-parameter shift flags |
| REC-0009 | Gather Mission Information | `mission_class`, `mission_description` |

## Security architecture (OWASP Top 10, 2021)

| Risk | Mitigation |
|---|---|
| A01 Broken Access Control | Output path validated against the target directory before every write; restricted permissions |
| A02 Cryptographic Failures | HTTPS-only; TLS certificate verification enforced, never disabled |
| A03 Injection | `csv.writer`/`json.dumps` for all structured output - no f-string concatenation into output formats; CSV/spreadsheet formula injection neutralized via leading-quote defusal |
| A04 Insecure Design | Rate-limiting, response size cap, strict timeouts; all external data treated as untrusted until validated |
| A05 Security Misconfiguration | No debug bypass, explicit error handling, no `shell=True` |
| A06 Vulnerable Components | Single dependency (`requests>=2.31`), version-pinned |
| A07 Identification & Auth Failures | Credentials via environment variables only - never CLI args, never logged |
| A08 Software/Data Integrity | Content-Type validation, response size limits enforced |
| A09 Logging & Monitoring Failures | Structured logging to file; credentials excluded from all log output |
| A10 SSRF | Strict URL allowlist (`celestrak.org`, `space-track.org`, `db.satnogs.org`); `urlparse` hostname validation before every request |

## Data sources

| Source | Auth | License / terms | Used for |
|---|---|---|---|
| [CelesTrak](https://celestrak.org) SATCAT | None | Free public data - see [CelesTrak's terms](https://celestrak.org/NORAD/documentation/) | Primary catalog |
| [Space-Track.org](https://www.space-track.org) | Free account (optional) | [Space-Track user agreement](https://www.space-track.org/documentation#/agreement) | Supplemental catalog |
| [SatNOGS DB](https://db.satnogs.org) | None | CC-BY-SA, community-maintained | Downlink frequency/mode enrichment |

SatNOGS DB is explicitly crowd-sourced per its own documentation treat `--enrich-frequencies` output as a research lead, not authoritative ground truth.

## Testing & CI

```bash
pip install -r requirements-dev.txt
pytest -v
```

The suite covers the pure, offline-computable logic, mission classification, orbital/size/lifecycle resolution, and the
sanitization/SSRF-allowlist helpers behind the OWASP controls above. It does **not** hit live network endpoints; use `--diagnose` against the real
APIs for that. GitHub Actions runs this suite on Python 3.9–3.12 for every push and pull request (`.github/workflows/ci.yml`). An optional
`workflow_dispatch` job (`.github/workflows/snapshot.yml`) runs a real collection and uploads the result as a downloadable artifact.

## Roadmap

Ideas under consideration, not yet built:

- GeoJSON/KML export for direct plotting in QGIS or Google Earth
- SQLite output option for ad-hoc querying alongside CSV/JSON
- A static HTML summary report (mission-class distribution, threat-tier breakdown) generated alongside the data files
- Enabling the weekly snapshot schedule once a few manual Actions runs have confirmed CelesTrak is reachable cleanly from GitHub-hosted runners

Issues and PRs proposing/implementing any of these are welcome.

## Legal & ethical use

This tool performs **passive aggregation** of publicly available orbital data only. Do not use this data to command, interfere with, jam, or
disrupt satellite operations. Such actions violate 47 U.S.C. § 333, the ITU Radio Regulations, and equivalent laws in Australia (Radiocommunications
Act 1992) and globally.

The `illustrative_threat_tier` field is a research prioritization heuristic derived from published, unclassified Aerospace Corporation work, it is
not intelligence, not satellite-specific, and not a substitute for a real risk assessment.

## Contributing

Issues and pull requests are welcome, particularly around new mission classification patterns, additional open data sources, and the roadmap
items above. Please run `pytest -v` before submitting a PR.

## License

[MIT](LICENSE) — research / educational use.

---

Built and maintained by [Australian Phoenix CyberOps - **Chad!**](https://github.com/RisingCyber)

---
