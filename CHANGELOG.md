# Changelog

All notable changes to LEO Sentinel are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.2.0] — 2026-09-18

### Added
- `--list-mission-classes` — prints the full mission-classification taxonomy
  (every `mission_class` label, its description, and the illustrative threat
  tier it maps to) and exits. Pure local introspection, no network access.
- `tests/test_classify.py` — pytest suite (64 tests) covering the pure
  classification, orbital, and input-sanitization functions offline.
- `conftest.py` so the test suite can import the top-level script directly.
- GitHub Actions CI (`.github/workflows/ci.yml`) — compiles the script and
  runs the test suite on Python 3.9–3.12 for every push/PR to `main`.
- Optional manual/weekly snapshot workflow
  (`.github/workflows/snapshot.yml`) that runs a real collection and
  uploads the CSV/JSON as a downloadable build artifact.
- `pyproject.toml` — the tool is now pip-installable (`pip install -e .`)
  and exposes a `leo-sentinel` console command.
- `requirements.txt` / `requirements-dev.txt`, `LICENSE` (MIT), `.gitignore`.
- Auto-detected terminal colour for the banner and `--summary` table
  (disabled for non-TTY output and when `NO_COLOR` is set, per
  [no-color.org](https://no-color.org); force with `FORCE_COLOR`).

### Fixed
- Malformed default `User-Agent` string sent a duplicated scheme
  (`https://https://github.com/RisingCyber`) — corrected to a single
  `https://`.
- Banner rendering used hardcoded padding that only lined up for the exact
  string lengths of v1.1.0; it's now computed dynamically so it can't drift
  out of alignment on future version bumps.

### Changed
- Version bumped 1.1.0 → 1.2.0. No changes to fetch, classification,
  or output logic — this release is packaging, testing, and presentation
  only. Data-source contracts, SSRF allowlist, and sanitization behavior
  are unchanged from 1.1.0.

## [1.1.0] — 2026-07-02

- Corrected the CelesTrak endpoint and query parameters against the
  live `satcat/records.php` API contract (previous versions guessed at
  parameters that don't exist).
- Added SatNOGS DB frequency/transmitter enrichment (`--enrich-frequencies`).
- Added cross-run diff / coarse maneuver-triage mode (`--diff-previous`).
- Added `--diagnose` mode for troubleshooting non-JSON responses.
