"""
Unit tests for LEO Sentinel's pure, locally-computed functions.

Scope is intentional: everything tested here runs offline, with no network
access — the mission classifier, orbital/size/lifecycle resolvers, and the
input-sanitization helpers that back the OWASP Top 10 controls described in
the README. Live data-source fetching (CelesTrak, Space-Track, SatNOGS) is
out of scope for CI and is exercised manually with --diagnose instead.

Run with:  pytest -v
"""
from pathlib import Path

import pytest

import leo_sentinel as ls


# ── classify_mission ──────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "name, object_type, expected_class",
    [
        ("ISS (ZARYA)", "PAYLOAD", "SPACE_STATION"),
        ("STARLINK-30123", "PAYLOAD", "COMMS_MEGACONST"),
        ("ONEWEB-0123", "PAYLOAD", "COMMS_MEGACONST"),
        ("GPS BIIF-12", "PAYLOAD", "GNSS"),
        ("NOAA 20", "PAYLOAD", "WEATHER"),
        ("LANDSAT 9", "PAYLOAD", "EO_CIVILIAN"),
        ("ICEYE-X21", "PAYLOAD", "EO_COMMERCIAL"),
        ("IRIDIUM 106", "PAYLOAD", "COMMS_COMMERCIAL"),
        ("USA-326", "PAYLOAD", "CLASSIFIED_MILITARY"),
        ("HUBBLE SPACE TELESCOPE", "PAYLOAD", "SCIENTIFIC"),
        ("AO-91", "PAYLOAD", "AMATEUR_RADIO"),
        ("SOME RANDOM SAT XYZ", "PAYLOAD", "UNKNOWN_PAYLOAD"),
    ],
)
def test_classify_mission_by_name(name, object_type, expected_class):
    mission_class, _description = ls.classify_mission(name, object_type)
    assert mission_class == expected_class


def test_classify_mission_object_type_fast_path_wins_over_name():
    # OBJECT_TYPE=ROCKET BODY short-circuits before any name pattern match,
    # even for a name that would otherwise match a payload pattern.
    mission_class, _ = ls.classify_mission("STARLINK-1007 R/B", "ROCKET BODY")
    assert mission_class == "ROCKET_BODY"


def test_classify_mission_debris_object_type():
    mission_class, _ = ls.classify_mission("FENGYUN 1C DEB", "DEBRIS")
    assert mission_class == "DEBRIS"


def test_classify_mission_unknown_non_payload_type():
    mission_class, _ = ls.classify_mission("MYSTERY OBJECT", "TBA")
    assert mission_class == "UNKNOWN"


def test_classify_mission_handles_empty_name():
    mission_class, _ = ls.classify_mission("", "PAYLOAD")
    assert mission_class == "UNKNOWN_PAYLOAD"


# ── is_leo ─────────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "perigee, apogee, expected",
    [
        (400.0, 420.0, True),           # typical Starlink-class shell
        (200.0, 2000.0, True),          # upper LEO boundary, inclusive
        (150.0, 400.0, True),           # lower LEO boundary, inclusive
        (149.9, 400.0, False),          # just below lower bound
        (400.0, 2000.1, False),         # just above upper bound
        (35786.0, 35786.0, False),      # GEO, not LEO
        (0.0, 400.0, False),            # zero/invalid perigee
        (400.0, 0.0, False),            # zero/invalid apogee
        (-100.0, 400.0, False),         # negative perigee
    ],
)
def test_is_leo(perigee, apogee, expected):
    assert ls.is_leo(perigee, apogee) is expected


# ── resolve_country ────────────────────────────────────────────────────────
def test_resolve_country_known_code():
    assert ls.resolve_country("us") == "United States"


def test_resolve_country_unknown_code_passes_through_uppercased():
    assert ls.resolve_country("zz") == "ZZ"


def test_resolve_country_empty():
    assert ls.resolve_country("") == "Unknown"


# ── resolve_size_class ─────────────────────────────────────────────────────
def test_resolve_size_class_prefers_string_bucket():
    assert ls.resolve_size_class("LARGE", rcs_numeric=0.01) == "SIZE_LARGE_RCS"


def test_resolve_size_class_falls_back_to_numeric_small():
    assert ls.resolve_size_class("", rcs_numeric=0.05) == "SIZE_SMALL_RCS"


def test_resolve_size_class_falls_back_to_numeric_medium():
    assert ls.resolve_size_class("N/A", rcs_numeric=0.5) == "SIZE_MEDIUM_RCS"


def test_resolve_size_class_falls_back_to_numeric_large():
    assert ls.resolve_size_class("", rcs_numeric=5.0) == "SIZE_LARGE_RCS"


def test_resolve_size_class_unknown_when_nothing_available():
    assert ls.resolve_size_class("", rcs_numeric=None) == "SIZE_UNKNOWN"


# ── resolve_threat_tier ────────────────────────────────────────────────────
def test_resolve_threat_tier_known_class():
    assert "nation-state" in ls.resolve_threat_tier("CLASSIFIED_MILITARY")


def test_resolve_threat_tier_unknown_class_uses_default():
    assert ls.resolve_threat_tier("NOT_A_REAL_CLASS") == ls.THREAT_TIER_DEFAULT


# ── resolve_lifecycle_status ───────────────────────────────────────────────
def test_resolve_lifecycle_status_newly_launched():
    from datetime import datetime, timedelta, timezone

    recent = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%d")
    assert ls.resolve_lifecycle_status(recent) == "NEWLY_LAUNCHED"


def test_resolve_lifecycle_status_established():
    assert ls.resolve_lifecycle_status("2015-01-01") == "ESTABLISHED"


def test_resolve_lifecycle_status_recently_decayed_overrides_launch():
    from datetime import datetime, timedelta, timezone

    recent_decay = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%Y-%m-%d")
    assert ls.resolve_lifecycle_status("2015-01-01", recent_decay) == "RECENTLY_DECAYED"


def test_resolve_lifecycle_status_unknown_on_missing_date():
    assert ls.resolve_lifecycle_status("") == "UNKNOWN"


def test_resolve_lifecycle_status_unknown_on_garbage_date():
    assert ls.resolve_lifecycle_status("not-a-date") == "UNKNOWN"


# ── sanitize_string / sanitize_code ────────────────────────────────────────
def test_sanitize_string_strips_control_chars_and_escapes_html():
    dirty = "  <script>alert(1)</script>\x07  "
    clean = ls.sanitize_string(dirty)
    assert "\x07" not in clean
    assert "<script>" not in clean


def test_sanitize_string_truncates_to_max_len():
    assert len(ls.sanitize_string("A" * 500, max_len=10)) == 10


def test_sanitize_string_none_is_empty():
    assert ls.sanitize_string(None) == ""


def test_sanitize_code_strips_disallowed_characters():
    assert ls.sanitize_code("US<script>", max_len=20) == "USscript"


def test_sanitize_code_allows_hyphen_and_slash():
    assert ls.sanitize_code("R/B-1") == "R/B-1"


# ── neutralize_csv_formula ─────────────────────────────────────────────────
@pytest.mark.parametrize("trigger", ["=", "+", "-", "@", "\t", "\r"])
def test_neutralize_csv_formula_defuses_trigger_chars(trigger):
    payload = f"{trigger}cmd|' /C calc'!A1"
    result = ls.neutralize_csv_formula(payload)
    assert result.startswith("'")
    assert result == "'" + payload


def test_neutralize_csv_formula_leaves_normal_strings_alone():
    assert ls.neutralize_csv_formula("STARLINK-1007") == "STARLINK-1007"


def test_neutralize_csv_formula_passes_through_non_strings():
    assert ls.neutralize_csv_formula(42) == 42
    assert ls.neutralize_csv_formula(3.14) == 3.14


# ── safe_float / safe_int ──────────────────────────────────────────────────
def test_safe_float_valid_and_invalid():
    assert ls.safe_float("400.5") == 400.5
    assert ls.safe_float("not-a-number", default=-1.0) == -1.0
    assert ls.safe_float(None, default=0.0) == 0.0


def test_safe_int_valid_and_invalid():
    assert ls.safe_int("25544") == 25544
    assert ls.safe_int("not-a-number", default=-1) == -1
    assert ls.safe_int(None, default=0) == 0


# ── validate_url (SSRF allowlist) ──────────────────────────────────────────
def test_validate_url_accepts_allowlisted_https():
    url = "https://celestrak.org/satcat/records.php?GROUP=active&FORMAT=JSON"
    assert ls.validate_url(url) == url


def test_validate_url_rejects_non_https():
    with pytest.raises(ValueError):
        ls.validate_url("http://celestrak.org/satcat/records.php")


def test_validate_url_rejects_non_allowlisted_domain():
    with pytest.raises(ValueError):
        ls.validate_url("https://evil.example.com/steal?data=1")


def test_validate_url_rejects_lookalike_domain():
    # Guards against domain-confusion tricks like "celestrak.org.evil.com"
    with pytest.raises(ValueError):
        ls.validate_url("https://celestrak.org.evil.com/records.php")


# ── validate_output_path (path traversal) ──────────────────────────────────
def test_validate_output_path_accepts_path_inside_base(tmp_path):
    base = tmp_path / "leo_data"
    base.mkdir()
    target = base / "leo_satellites.csv"
    assert ls.validate_output_path(target, base) == target.resolve()


def test_validate_output_path_rejects_traversal_outside_base(tmp_path):
    base = tmp_path / "leo_data"
    base.mkdir()
    escape = base / ".." / ".." / "etc" / "passwd"
    with pytest.raises(ValueError):
        ls.validate_output_path(escape, base)


# ── deduplicate_by_norad ───────────────────────────────────────────────────
def test_deduplicate_by_norad_keeps_first_occurrence():
    records = [
        {"norad_cat_id": 25544, "data_source": "CelesTrak"},
        {"norad_cat_id": 25544, "data_source": "Space-Track.org"},
        {"norad_cat_id": 48274, "data_source": "CelesTrak"},
    ]
    result = ls.deduplicate_by_norad(records)
    assert len(result) == 2
    assert next(r for r in result if r["norad_cat_id"] == 25544)["data_source"] == "CelesTrak"


def test_deduplicate_by_norad_drops_zero_id():
    records = [{"norad_cat_id": 0}, {"norad_cat_id": 0}]
    assert ls.deduplicate_by_norad(records) == []


# ── list_mission_classes (taxonomy introspection, no network) ─────────────
def test_list_mission_classes_runs_and_returns_zero(capsys):
    exit_code = ls.list_mission_classes()
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "MISSION_CLASS" in captured.out
    assert "CLASSIFIED_MILITARY" in captured.out
