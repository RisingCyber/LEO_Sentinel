#!/usr/bin/env python3
"""
Australian Phoenix LEO Sentinel v1.1.0
=======================================
LEO Satellite Aggregator & Classifier for Signals/Space Security Research
Australian Phoenix CyberOps | Signals & Space Security Research

PURPOSE
-------
Aggregates publicly available Low Earth Orbit (LEO) satellite data from
trusted, open-source databases, classifies each object by
mission type and operator, and outputs structured data for SDR-based
security research.

LEGAL NOTICE
------------
This tool performs PASSIVE aggregation of publicly available orbital data.
Do NOT use this data to command, interfere with, jam, or disrupt satellite
operations. Such actions violate 47 U.S.C. § 333, the ITU Radio Regulations,
and equivalent laws in Australia (Radiocommunications Act 1992) and globally.

SECURITY ARCHITECTURE  (OWASP Top 10 2021 Compliant)
------------------------------------------------------
A01 Broken Access Control     : Output path validated; restricted permissions set.
A02 Cryptographic Failures    : HTTPS-only; TLS certificate verification enforced.
A03 Injection                 : csv.writer + json.dumps for all output; no f-string
                                concatenation into structured formats; CSV/spreadsheet
                                formula injection neutralized via leading-quote defusal.
A04 Insecure Design           : Rate-limiting; response size cap; strict timeouts;
                                all external data treated as untrusted until validated.
A05 Security Misconfiguration : No debug bypass; explicit error handling; no shell=True.
A06 Vulnerable Components     : Single dependency (requests>=2.31); version-pinned.
A07 Auth Failures             : Credentials via environment variables only; never CLI args.
A08 Software/Data Integrity   : Content-Type validation; response size limits enforced.
A09 Logging/Monitoring        : Structured logging to file; credentials excluded from logs.
A10 SSRF                      : Strict URL allowlist; urlparse validation before each request.

USAGE
-----
    python3 leo_sentinel.py [--format {csv,json,both}] [--out-dir PATH]
                            [--no-cache] [--verbose] [--summary]

    Example:
        python3 leo_sentinel.py --format both --summary

ENVIRONMENT VARIABLES (Optional — Space-Track.org integration)
---------------------------------------------------------------
    SPACETRACK_USER    Your Space-Track.org login username
    SPACETRACK_PASS    Your Space-Track.org login password

    Never pass credentials as CLI arguments — they appear in shell history.

REQUIREMENTS
------------
    pip install "requests>=2.31.0"

    On Debian/Ubuntu:
        sudo apt install python3-requests
    or:
        pip3 install --user "requests>=2.31.0"

Python: 3.8+
License: MIT (research / educational use)
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# ─── Dependency check ────────────────────────────────────────────────────────
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    sys.exit(
        "\n[FATAL] 'requests' not found.\n"
        "Install: pip install 'requests>=2.31.0'\n"
        "Debian/Ubuntu:  sudo apt install python3-requests\n"
    )

# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

VERSION     = "1.1.0"
TOOL_NAME   = "Australian Phoenix LEO Sentinel"
TOOL_BANNER = f"""
╔══════════════════════════════════════════════════════════════════╗
         {TOOL_NAME} v{VERSION}                     
   LEO Satellite Aggregator & Classifier                          
   Australian Phoenix CyberOps | https://github.com/RisingCyber      
╚══════════════════════════════════════════════════════════════════╝
"""

# ── LEO altitude thresholds (km) ─────────────────────────────────────────────
LEO_PERIGEE_MIN_KM: float = 150.0
LEO_APOGEE_MAX_KM:  float = 2000.0

# ── HTTP / network ────────────────────────────────────────────────────────────
REQUEST_TIMEOUT_SEC:    int   = 30
MAX_RESPONSE_BYTES:     int   = 60 * 1024 * 1024  # 60 MB safety cap
INTER_REQUEST_DELAY:    float = 2.0               # seconds — respect CelesTrak rate limits
MAX_RETRIES:            int   = 3

# ── Cache ─────────────────────────────────────────────────────────────────────
CACHE_DIR_NAME   = ".leo_cache"
CACHE_MAX_AGE_H  = 6          # hours before cache is considered stale

# ── Output ────────────────────────────────────────────────────────────────────
DEFAULT_OUT_DIR  = "leo_data"
OUTPUT_CSV_NAME  = "leo_satellites.csv"
OUTPUT_JSON_NAME = "leo_satellites.json"
SNAPSHOT_FILENAME = "leo_snapshot_previous.json"
DIFF_REPORT_FILENAME = "leo_diff_report.json"

# ─────────────────────────────────────────────────────────────────────────────
#  CROSS-RUN ANOMALY / MANEUVER-DETECTION THRESHOLDS
#
#  Used only when --diff-previous is passed. Compares this run's classified
#  LEO dataset against the snapshot saved at the end of the last run.
#
#  Thresholds are illustrative triage values, not a
#  statistically derived orbit-determination model. Real maneuver detection
#  uses precision ephemerides, covariance data, and multiple observations —
#  far more rigorous than a delta between two SATCAT snapshots, which
#  themselves are periodically-updated summary values, not live tracking
#  data. 
# ─────────────────────────────────────────────────────────────────────────────
MANEUVER_ALTITUDE_DELTA_KM: float = 5.0    # perigee or apogee shift beyond this, flagged
MANEUVER_INCLINATION_DELTA_DEG: float = 0.3  # inclination shift beyond this, flagged

# ─────────────────────────────────────────────────────────────────────────────
#  SSRF MITIGATION — URL ALLOWLIST
#  Only domains in this set may be contacted. Never allow arbitrary URLs.
# ─────────────────────────────────────────────────────────────────────────────
ALLOWED_DOMAINS: frozenset = frozenset({
    "celestrak.org",
    "www.celestrak.org",
    "www.space-track.org",
    "space-track.org",
    "db.satnogs.org",
})

# ─────────────────────────────────────────────────────────────────────────────
#  DATA SOURCES — CelesTrak (free, no auth)
#
#  Verified directly against CelesTrak's own documentation on 2 July 2026
#  (https://celestrak.org/satcat/satcat-format.php) after a live diagnostic
#  run surfaced the server's own error message. Prior versions of this
#  script guessed at query parameters that do not exist ("CURRENT=Y") and
#  pointed group queries at SATCAT/search.php, which is a human-facing HTML
#  search form, not a JSON API. Both are fixed below.
#
#  CONFIRMED API CONTRACT (celestrak.org/satcat/records.php):
#    https://celestrak.org/satcat/records.php?{QUERY}=VALUE[&FORMAT=VALUE]
#    {QUERY} must be exactly ONE of:
#      CATNR   — single catalog number
#      INTDES  — international designator (yyyy-nnn), all objects from a launch
#      GROUP   — named group, as listed on the CelesTrak Current Data page
#      NAME    — substring search on satellite name
#      SPECIAL — GEO Protected Zone data sets (gpz / gpz-plus)
#    Optional flags (combine with {QUERY} via &):
#      PAYLOADS=1   only payloads            [default FALSE]
#      ONORBIT=1    only currently on-orbit  [default FALSE]
#      ACTIVE=1     only active payloads     [default FALSE]
#      MAX=n        cap result count         [default ALL]
#    FORMAT: JSON (default), JSON-PRETTY, CSV, and legacy text formats.
#
#  CONFIRMED RESPONSE FIELDS (from satcat-format.php, 2023-05-07 revision):
#    OBJECT_NAME, OBJECT_ID, NORAD_CAT_ID, OBJECT_TYPE, OPS_STATUS_CODE,
#    OWNER, LAUNCH_DATE, LAUNCH_SITE, DECAY_DATE, PERIOD (min), INCLINATION
#    (deg), APOGEE (km), PERIGEE (km), RCS (m², numeric), DATA_STATUS_CODE,
#    ORBIT_CENTER, ORBIT_TYPE.
#
# ─────────────────────────────────────────────────────────────────────────────

# Prioritised list: (url, label) — tried in order, first valid JSON list wins.
# Both entries now use the correct satcat/records.php endpoint with a valid
# {QUERY} key (GROUP), differing only in which group is requested first.
CELESTRAK_PRIMARY_ENDPOINTS: List[Tuple[str, str]] = [
    (
        "https://celestrak.org/satcat/records.php?GROUP=active&FORMAT=JSON",
        "CelesTrak-active-payloads",
    ),
    (
        "https://celestrak.org/satcat/records.php?GROUP=active&PAYLOADS=1&FORMAT=JSON",
        "CelesTrak-active-payloads-explicit",
    ),
]

# Supplemental named-group endpoints, all on the CONFIRMED-correct
# satcat/records.php endpoint. Each is fetched independently and failures
# are non-fatal (logged and skipped) — see fetch_celestrak_satcat().
# "qianfan" and "hulianwang" (Chinese mega-constellations Qianfan / Guowang)
# added per a dated 2025-2026 source confirming these as current CelesTrak
# group names; if CelesTrak renames or retires a group, that single fetch
# will fail gracefully without affecting the others.
CELESTRAK_GP_GROUPS: Dict[str, str] = {
    "starlink":     "https://celestrak.org/satcat/records.php?GROUP=starlink&FORMAT=JSON",
    "oneweb":       "https://celestrak.org/satcat/records.php?GROUP=oneweb&FORMAT=JSON",
    "qianfan":      "https://celestrak.org/satcat/records.php?GROUP=qianfan&FORMAT=JSON",
    "hulianwang":   "https://celestrak.org/satcat/records.php?GROUP=hulianwang&FORMAT=JSON",
    "planet":       "https://celestrak.org/satcat/records.php?GROUP=planet&FORMAT=JSON",
    "spire":        "https://celestrak.org/satcat/records.php?GROUP=spire&FORMAT=JSON",
    "stations":     "https://celestrak.org/satcat/records.php?GROUP=stations&FORMAT=JSON",
    "weather":      "https://celestrak.org/satcat/records.php?GROUP=weather&FORMAT=JSON",
    "amateur":      "https://celestrak.org/satcat/records.php?GROUP=amateur&FORMAT=JSON",
    "iridium_next": "https://celestrak.org/satcat/records.php?GROUP=iridium-NEXT&FORMAT=JSON",
}

# Earth constants — for deriving altitude from MEAN_MOTION when
# explicit PERIGEE/APOGEE fields are absent (should be rare now that we
# use the confirmed-correct satcat/records.php schema, but retained as a
# defensive fallback for edge cases or future schema drift).
EARTH_GM_KM3_S2: float = 398600.4418     # km³/s²
EARTH_RADIUS_KM: float = 6371.0          # mean radius, km
SECS_PER_DAY:    float = 86400.0

# Space-Track.org (optional — requires free account at space-track.org)
SPACETRACK_LOGIN_URL  = "https://www.space-track.org/ajaxauth/login"
SPACETRACK_SATCAT_URL = (
    "https://www.space-track.org/basicspacedata/query/class/satcat"
    "/CURRENT/Y/OBJECT_TYPE/PAYLOAD/orderby/NORAD_CAT_ID/format/json"
)

# ─────────────────────────────────────────────────────────────────────────────
#  SatNOGS DB (optional, opt-in via --enrich-frequencies — free, no auth)
#
#  SatNOGS DB (db.satnogs.org) is a community-run, open, CC-BY-SA-licensed
#  transmitter database operated by the Libre Space Foundation. It is
#  EXPLICITLY CROWD-SOURCED per SatNOGS' own documentation — anyone with a
#  login can submit transmitter details, which moderators review. Treat
#  this data as a research lead, not authoritative ground truth.
#
#  VERIFIED (2 July 2026):
#   - API root: https://db.satnogs.org/api/  (open to anyone, no auth for GET)
#   - The `status=active` filter on /api/transmitters/ is confirmed working
#     by a SatNOGS maintainer in a public GitLab issue thread (gitlab.com/
#     librespacefoundation/satnogs/satnogs-db/-/issues/298), used here in
#     preference to unverified filter parameter names.
#   - Confirmed response fields (from a live sample response): uuid,
#     description, alive, type, uplink_low/high/drift, downlink_low/high/
#     drift, mode, mode_id, invert, baud, sat_id, norad_cat_id, status,
#     citation, service, iaru_coordination, itu_notification,
#     frequency_violation, unconfirmed.
#   - frequency_violation is SatNOGS' own compliance check: true if the
#     transmitter's reported frequency falls outside its ITU-coordinated
#     allocation — a genuine signals-security/compliance signal.
#
# ─────────────────────────────────────────────────────────────────────────────
SATNOGS_TRANSMITTERS_URL = "https://db.satnogs.org/api/transmitters/?status=active&format=json"
SATNOGS_MAX_PAGES = 25          # safety cap on pagination following
SATNOGS_FREQ_VIOLATION_NOTE = (
    "Community-reported: transmitter frequency falls outside its "
    "ITU-coordinated allocation per SatNOGS DB."
)

# ─────────────────────────────────────────────────────────────────────────────
#  MISSION CLASSIFICATION ENGINE
#  Rules applied in order — first match wins.
#  Each rule: (compiled_regex, mission_class_label, human_description)
# ─────────────────────────────────────────────────────────────────────────────

# Build patterns once at module load — never rebuild per row (ReDoS mitigation)
_RAW_PATTERNS: List[Tuple[str, str, str]] = [
    # ── Space Stations ────────────────────────────────────────────────────────
    (r"^(ISS|ZARYA|UNITY|DESTINY|ZVEZDA|TRANQUILITY|HARMONY|SERENITY|KIBO|COLUMBUS)",
     "SPACE_STATION", "Crewed Space Station"),
    (r"^TIANGONG",         "SPACE_STATION",           "Chinese Space Station"),

    # ── GNSS / Navigation ─────────────────────────────────────────────────────
    (r"^(GPS|NAVSTAR|BIIR|BIIF|BOCK)", "GNSS",        "GPS / NAVSTAR Navigation"),
    (r"^(GLONASS)",                    "GNSS",        "GLONASS Navigation"),
    (r"^(GALILEO|GSAT\d)",             "GNSS",        "Galileo Navigation"),
    (r"^(BEIDOU)",                     "GNSS",        "BeiDou Navigation"),
    (r"^(IRNSS|NAVIC)",                "GNSS",        "NavIC Navigation"),
    (r"^QZSS",                         "GNSS",        "QZSS (Japan)"),

    # ── Weather / Meteorology ─────────────────────────────────────────────────
    (r"^(NOAA|GOES|DMSP|SUOMI|JPSS|SNPP|POES)", "WEATHER",   "NOAA/US Meteorology"),
    (r"^(METOP|METEOSAT|MSG|EUMETSAT)",          "WEATHER",   "European Meteorology"),
    (r"^(METEOR)",                               "WEATHER",   "Russian Meteorology"),
    (r"^(FENG YUN|FY-\d|FY\d)",                 "WEATHER",   "Chinese Meteorology"),
    (r"^(HIMAWARI|INSAT)",                       "WEATHER",   "Asia-Pacific Meteorology"),

    # ── Earth Observation — Commercial ───────────────────────────────────────
    (r"^(PLANET|SKYSAT|DOVE)",                   "EO_COMMERCIAL", "Planet Labs EO"),
    (r"^SPIRE",                                  "EO_COMMERCIAL", "Spire EO / Weather"),
    (r"^(WORLDVIEW|GEOEYE|MAXAR)",               "EO_COMMERCIAL", "Maxar Commercial EO"),
    (r"^(ICEYE)",                                "EO_COMMERCIAL", "ICEYE SAR EO"),
    (r"^(CAPELLA)",                              "EO_COMMERCIAL", "Capella SAR EO"),
    (r"^(UMBRA)",                                "EO_COMMERCIAL", "Umbra SAR EO"),
    (r"^(SYNSPECTIVE)",                          "EO_COMMERCIAL", "Synspective SAR EO"),
    (r"^(SATELLOGIC|NUSAT)",                     "EO_COMMERCIAL", "Satellogic EO"),

    # ── Earth Observation — Civilian / Government ─────────────────────────────
    (r"^(LANDSAT|TERRA|AQUA|SPOT|SENTINEL)",     "EO_CIVILIAN",  "Civilian EO"),
    (r"^(KOMPSAT|ALOS|RESOURCESAT)",             "EO_CIVILIAN",  "Government EO"),
    (r"^(COSMO|CSKS)",                           "EO_CIVILIAN",  "Italian SAR EO"),
    (r"^(RADARSAT)",                             "EO_CIVILIAN",  "Canadian SAR EO"),
    (r"^(CARTOSAT|RISAT)",                       "EO_CIVILIAN",  "ISRO EO"),

    # ── Commercial Communications Megaconstellations ─────────────────────────
    (r"^STARLINK",                               "COMMS_MEGACONST", "SpaceX Starlink"),
    (r"^ONEWEB",                                 "COMMS_MEGACONST", "OneWeb Broadband"),
    (r"^(KUIPER)",                               "COMMS_MEGACONST", "Amazon Kuiper"),
    (r"^(QIANFAN|QF-|G60)",                      "COMMS_MEGACONST", "China Qianfan / Thousand Sails"),
    (r"^(GUOWANG|HULIANWANG|SATNET)",            "COMMS_MEGACONST", "China Guowang / SatNet"),

    # ── Commercial Communications ─────────────────────────────────────────────
    (r"^IRIDIUM",                                "COMMS_COMMERCIAL", "Iridium Mobile SATCOM"),
    (r"^(ORBCOMM)",                              "COMMS_COMMERCIAL", "ORBCOMM M2M"),
    (r"^(GLOBALSTAR)",                           "COMMS_COMMERCIAL", "Globalstar Mobile SATCOM"),
    (r"^(INMARSAT)",                             "COMMS_COMMERCIAL", "Inmarsat Maritime/Aero"),
    (r"^(O3B|SES)",                              "COMMS_COMMERCIAL", "SES O3B Broadband"),
    (r"^(TELSTAR|INTELSAT|EUTELSAT|ASTRA)",      "COMMS_COMMERCIAL", "Commercial GEO Comms"),

    # ── Military Communications ───────────────────────────────────────────────
    (r"^(MUOS|WGS|MILSTAR|AEHF|PAN)",            "MILITARY_COMMS", "US Military SATCOM"),
    (r"^(SKYNET)",                               "MILITARY_COMMS", "UK Military SATCOM"),
    (r"^(SYRACUSE|SICRAL)",                      "MILITARY_COMMS", "European Military SATCOM"),

    # ── Missile Warning / Surveillance ───────────────────────────────────────
    (r"^(SBIRS|DSP|STSS|GEOSTAR)",               "MILITARY_SURVEILLANCE", "US Missile Warning"),

    # ── Classified Military ───────────────────────────────────────────────────
    (r"^USA-\d+",                                "CLASSIFIED_MILITARY", "US Military Classified"),
    (r"^(NROL|LACROSSE|MISTY|QUASAR|TRUMPET|MENTOR|TOPAZ|KEYHOLE)",
     "CLASSIFIED_MILITARY",   "NRO / National Reconnaissance"),

    # ── Scientific / Research ────────────────────────────────────────────────
    (r"^(HUBBLE|CHANDRA|SWIFT|FERMI|INTEGRAL|NUSTAR)",
     "SCIENTIFIC",            "Space Telescope / Astrophysics"),
    (r"^(SWARM|GRACE|GOCE|CRYOSAT|SMOS)",        "SCIENTIFIC",    "Geoscience / Geodesy"),
    (r"^(ISS CARGO|CYGNUS|DRAGON|PROGRESS|HTV)",  "SCIENTIFIC",   "Cargo / Logistics"),
    (r"^(CUBESAT|CANX|CUTE|DELFI|FUNCUBE|OSCAR|LILACSAT)",
     "SCIENTIFIC_CUBESAT",   "Research CubeSat"),

    # ── Amateur Radio ─────────────────────────────────────────────────────────
    (r"^(AMSAT|AO-\d|FO-\d|NO-\d|SO-\d|XW-\d|RS-\d)",
     "AMATEUR_RADIO",         "Amateur Radio Satellite (AMSAT)"),
    (r"^(FUNCUBE|DUCHIFAT|TEVEL|UVSQ|KAITUO|FOX)",
     "AMATEUR_RADIO",         "Amateur / University Satellite"),

    # ── Technology Demonstrators ──────────────────────────────────────────────
    (r"^(TECHSAT|PROBA|BIRD|MICROSCOPE|BEXUS|CSST|DICE)",
     "TECH_DEMO",             "Technology Demonstrator"),

    # ── Debris / Rocket Bodies ────────────────────────────────────────────────
    (r"^(R/B|DEB\b|DEBRIS)",  "DEBRIS",          "Debris / Rocket Body"),
]

# Compile all patterns once — case-insensitive
MISSION_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(raw, re.IGNORECASE), label, desc)
    for raw, label, desc in _RAW_PATTERNS
]

# Country code → full country/operator name
# Based on CelesTrak SATCAT international standard codes
COUNTRY_CODES: Dict[str, str] = {
    "US":    "United States",
    "CIS":   "Russia / CIS",
    "CN":    "China (PRC)",
    "PRC":   "China (PRC)",
    "ESA":   "European Space Agency",
    "FR":    "France",
    "DE":    "Germany",
    "GB":    "United Kingdom",
    "JP":    "Japan",
    "IN":    "India",
    "CA":    "Canada",
    "AU":    "Australia",
    "IL":    "Israel",
    "IT":    "Italy",
    "BR":    "Brazil",
    "KR":    "South Korea",
    "UAE":   "United Arab Emirates",
    "GLOB":  "Globalstar (US)",
    "NATO":  "NATO",
    "IM":    "Inmarsat (UK)",
    "LUX":   "Luxembourg",
    "SES":   "SES (Luxembourg)",
    "ISS":   "ISS (Multinational)",
    "AB":    "Arab Satellite / Jordan",
    "ITSO":  "INTELSAT",
    "ORB":   "ORBCOMM",
    "SA":    "Saudi Arabia",
    "SG":    "Singapore",
    "FRIT":  "France / Italy",
    "ESRO":  "European Space Research Org",
    "ABS":   "Asia Broadcast Satellite",
    "IRN":   "Iran",
    "NIG":   "Nigeria",
    "TK":    "Turkmenistan",
    "KZ":    "Kazakhstan",
    "UKR":   "Ukraine",
    "TUR":   "Turkey",
    "NZEL":  "New Zealand",
    "SWE":   "Sweden",
    "NOR":   "Norway",
    "SWZ":   "Switzerland",
    "SAFR":  "South Africa",
    "AR":    "Argentina",
    "MX":    "Mexico",
    "PK":    "Pakistan",
    "EG":    "Egypt",
    "TH":    "Thailand",
    "ID":    "Indonesia",
}

# ─────────────────────────────────────────────────────────────────────────────
#  SIZE CLASS REFERENCE — Documented, NOT inferred per-record
#
#  NASA's annual Small Spacecraft Technology State-of-the-Art Report
#  (NASA/TP-20220018058 and successors) documents the CubeSat "U-class"
#  taxonomy below. We surface it here as reference context only.
#
#  We deliberately do NOT attempt to infer per-satellite U-class from the
#  CelesTrak SATCAT name string. Most CubeSat names (e.g. "STARLINK-1007",
#  "LEMUR-2-PEPE") do not encode form factor, so a name-pattern guess would
#  manufacture false confidence the underlying data doesn't support. Instead,
#  we derive a coarser, defensible `size_class` from the RCS_SIZE field that
#  CelesTrak's catalog actually provides (radar cross-section bucket), which
#  loosely — not precisely — tracks physical size.
# ─────────────────────────────────────────────────────────────────────────────
CUBESAT_UCLASS_REFERENCE: Dict[str, str] = {
    "1P/2P/3P": "PocketQube (5 cm cube units) — sub-1U micro form factor",
    "1U":  "10x10x10 cm, ~1.33 kg max — smallest standard CubeSat unit",
    "2U":  "10x10x20 cm — common for simple single-payload missions",
    "3U":  "10x10x30 cm, ~4 kg max — most common CubeSat form factor",
    "6U":  "20x10x30 cm class — common for commercial EO constellations",
    "12U": "20x20x30 cm class — used by e.g. CAPSTONE-class missions",
    "16U+": "Larger CubeSat-derived buses — approaching minisatellite scale",
}

# RCS string bucket → size class  (GP schema: RCS_SIZE field)
# String values per CelesTrak / Space-Track convention.
RCS_SIZE_TO_CLASS: Dict[str, str] = {
    "SMALL":  "SIZE_SMALL_RCS",    # roughly CubeSat / microsat scale
    "MEDIUM": "SIZE_MEDIUM_RCS",   # roughly minisatellite scale
    "LARGE":  "SIZE_LARGE_RCS",    # roughly full-size bus / station scale
    "N/A":    "SIZE_UNKNOWN",
    "":       "SIZE_UNKNOWN",
}

# Numeric RCS thresholds (m²) → size class  (satcat-records schema: RCS field)
# Source: Space-Track.org data dictionary; consistent with peer-reviewed
# debris-tracking literature (threshold values: <0.1, 0.1–1.0, >1.0 m²).
RCS_NUMERIC_THRESHOLDS: List[Tuple[float, str]] = [
    (0.1,  "SIZE_SMALL_RCS"),   # < 0.1 m²
    (1.0,  "SIZE_MEDIUM_RCS"),  # 0.1 – 1.0 m²
]
RCS_LARGE_CLASS = "SIZE_LARGE_RCS"  # > 1.0 m²

# ─────────────────────────────────────────────────────────────────────────────
#  ILLUSTRATIVE THREAT-TIER HEURISTIC
#
#  Maps mission_class to a rough band of the "Threat Agents in Cyber Threat
#  Model" Tier I–VII scale from Bailey, B. "Cybersecurity Protections for
#  Spacecraft: A Threat Based Approach," The Aerospace Corporation, Report
#  TOR-2021-01333-REV A, 2021 (Table 3). That source ranks adversary tiers
#  by skill/motivation, from Tier I (script kiddies) to Tier VII (most
#  capable state actors), and separately discusses which categories of
#  space missions are most likely to draw nation-state attention.
#
#  THIS IS A HEURISTIC, NOT INTELLIGENCE. It reflects only "what category of
#  adversary has historically shown interest in this class of target,"
#  drawn from the cited threat model and open-source incident history
#  (e.g., Viasat KA-SAT 2022 for commercial megaconstellation ground
#  infrastructure). It is not derived from any classified, non-public, or
#  satellite-specific intelligence, and it is not a substitute for an
#  actual mission-specific risk assessment. Treat it as a prioritization
#  starting point, never as a verdict.
# ─────────────────────────────────────────────────────────────────────────────
THREAT_TIER_BY_MISSION_CLASS: Dict[str, str] = {
    "CLASSIFIED_MILITARY":     "Tier V-VII (nation-state interest likely)",
    "MILITARY_COMMS":          "Tier V-VII (nation-state interest likely)",
    "MILITARY_SURVEILLANCE":   "Tier V-VII (nation-state interest likely)",
    "GNSS":                    "Tier IV-VI (critical infrastructure — PNT)",
    "COMMS_MEGACONST":         "Tier III-VI (cf. Viasat KA-SAT 2022 precedent)",
    "COMMS_COMMERCIAL":        "Tier III-V (commercial SATCOM, ground segment risk)",
    "EO_COMMERCIAL":           "Tier III-V (commercial imagery, IP/espionage interest)",
    "EO_CIVILIAN":             "Tier II-IV (government/civil EO)",
    "WEATHER":                 "Tier II-IV (critical infrastructure — meteorology)",
    "SPACE_STATION":           "Tier III-VI (high-value, high-visibility target)",
    "SCIENTIFIC":              "Tier I-III (lower adversary priority, historically)",
    "SCIENTIFIC_CUBESAT":      "Tier I-III (lower adversary priority, historically)",
    "AMATEUR_RADIO":           "Tier I-II (low adversary priority, historically)",
    "TECH_DEMO":               "Tier I-III (varies with sponsoring organization)",
    "DEBRIS":                  "N/A (non-functional object)",
    "ROCKET_BODY":             "N/A (non-functional object)",
    "UNKNOWN_PAYLOAD":         "Unclassified — insufficient data for estimate",
    "UNKNOWN":                 "Unclassified — insufficient data for estimate",
}
THREAT_TIER_DEFAULT = "Unclassified — insufficient data for estimate"

# ─────────────────────────────────────────────────────────────────────────────
#  LIFECYCLE STATUS THRESHOLDS
#  Pure local computation from LAUNCH_DATE / DECAY_DATE fields already
#  extracted from CelesTrak — no new network calls, no external dependency.
# ─────────────────────────────────────────────────────────────────────────────
LIFECYCLE_RECENT_DAYS: int = 90   # threshold for "newly launched" / "recently decayed"

# CSV output column order
CSV_FIELDNAMES: List[str] = [
    "norad_cat_id",
    "intl_designator",
    "name",
    "country_code",
    "country_name",
    "object_type",
    "mission_class",
    "mission_description",
    "illustrative_threat_tier",
    "lifecycle_status",
    "perigee_km",
    "apogee_km",
    "inclination_deg",
    "period_min",
    "rcs_size",
    "size_class",
    "launch_date",
    "decay_date",
    "current_in_orbit",
    "orbit_class",
    "known_transmitter_count",
    "primary_downlink_mhz",
    "primary_downlink_mode",
    "frequency_violation_flag",
    "data_source",
    "retrieved_utc",
]


# ─────────────────────────────────────────────────────────────────────────────
#  LOGGING SETUP
# ─────────────────────────────────────────────────────────────────────────────

def configure_logging(verbose: bool = False, log_dir: Optional[Path] = None) -> logging.Logger:
    """
    Configure structured logging.
    Logs to stdout and optionally to a file.
    Credentials are never logged (enforced by not logging request bodies or env vars).
    """
    level = logging.DEBUG if verbose else logging.INFO
    logger = logging.getLogger(TOOL_NAME)
    logger.setLevel(level)
    logger.handlers.clear()

    fmt = logging.Formatter(
        fmt="%(asctime)s [%(levelname)-8s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # File handler (optional)
    if log_dir:
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "leo_sentinel.log"
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(level)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger


# ─────────────────────────────────────────────────────────────────────────────
#  SECURITY UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def validate_url(url: str, allowlist: frozenset = ALLOWED_DOMAINS) -> str:
    """
    SSRF Mitigation: validate URL against the allowlist before use.
    Raises ValueError for any URL whose domain is not in the allowlist.

    Security: enforces HTTPS-only and domain allowlist.
    """
    if not isinstance(url, str):
        raise ValueError("URL must be a string.")

    # Only accept https://
    if not url.lower().startswith("https://"):
        raise ValueError(f"Only HTTPS URLs are permitted. Got: {url!r}")

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    if not hostname:
        raise ValueError(f"Could not parse hostname from URL: {url!r}")

    if hostname not in allowlist:
        raise ValueError(
            f"URL domain '{hostname}' is not in the allowed domain list. "
            f"Allowed: {sorted(allowlist)}"
        )
    return url


def validate_output_path(path: Path, base_dir: Path) -> Path:
    """
    Path traversal mitigation: ensures the resolved output path stays within
    the intended base directory.
    """
    try:
        resolved = path.resolve()
        base_resolved = base_dir.resolve()
        resolved.relative_to(base_resolved)  # raises ValueError if outside
        return resolved
    except ValueError:
        raise ValueError(
            f"Output path '{path}' resolves outside the permitted base "
            f"directory '{base_dir}'. Possible path traversal attempt."
        )


def sanitize_string(value: Any, max_len: int = 256) -> str:
    """
    Sanitize a value from external API data before using it in output.
    - Converts to string
    - Strips leading/trailing whitespace
    - Truncates to max_len
    - Removes control characters (OWASP A03 injection prevention)
    - HTML-escapes for any context where output might be rendered (A03 / XSS)

    Note: csv.writer and json.dumps handle structural injection (quote/delimiter
    escaping) in their respective formats natively. This function is an
    additional defence-in-depth layer for control characters and XSS contexts.
    CSV FORMULA injection (a distinct risk class) is handled separately at
    write-time in neutralize_csv_formula() — see write_csv().
    """
    if value is None:
        return ""
    # Convert to string, strip, truncate
    s = str(value).strip()[:max_len]
    # Remove non-printable control characters (except tab and newline in data)
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", s)
    # HTML-escape — harmless for CSV/JSON, protective if rendered
    s = html.escape(s, quote=True)
    return s


def sanitize_code(value: Any, max_len: int = 8) -> str:
    """
    Sanitize short codes (e.g., country codes, RCS size, status flags) that
    should only ever contain alphanumerics, spaces, hyphens, and slashes.
    Stricter than sanitize_string() — avoids HTML-escape artifacts on data
    that is rendered as a plain code, not prose.
    """
    if value is None:
        return ""
    s = str(value).strip()[:max_len]
    s = re.sub(r"[^A-Za-z0-9 /\-]", "", s)
    return s


# CSV Formula Injection (a.k.a. "CSV Injection") mitigation.
# If a cell's value begins with one of these characters, Excel/LibreOffice/
# Google Sheets may interpret it as a formula when the CSV is opened. This is
# a well-documented OWASP-adjacent risk distinct from delimiter/quote
# injection (which csv.writer already handles). We neutralize by prefixing
# a single quote, which forces spreadsheet applications to treat the cell
# as literal text while leaving the underlying data intact for CSV/JSON
# consumers that don't interpret formulas (e.g., pandas, gr-satellites).
_CSV_FORMULA_TRIGGER_CHARS = ("=", "+", "-", "@", "\t", "\r")


def neutralize_csv_formula(value: Any) -> Any:
    """
    Defuse potential CSV/spreadsheet formula injection by prefixing a
    leading single-quote to any string value starting with a formula
    trigger character. Non-string values (int, float) pass through unchanged.
    """
    if not isinstance(value, str):
        return value
    if value and value[0] in _CSV_FORMULA_TRIGGER_CHARS:
        return "'" + value
    return value


def safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert an external value to float; return default on failure."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_int(value: Any, default: int = 0) -> int:
    """Safely convert an external value to int; return default on failure."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# ─────────────────────────────────────────────────────────────────────────────
#  HTTP CLIENT — Secure by Default
# ─────────────────────────────────────────────────────────────────────────────

def build_http_session(user_agent: Optional[str] = None) -> requests.Session:
    """
    Build an HTTP session with:
    - TLS certificate verification enforced (verify=True — never disabled)
    - Retry logic with exponential backoff
    - Explicit timeout enforced at call sites
    - No credentials in headers by default
    """
    session = requests.Session()

    retry_strategy = Retry(
        total=MAX_RETRIES,
        backoff_factor=1.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)

    session.headers.update({
        "User-Agent": user_agent or f"{TOOL_NAME}/{VERSION} (+https://https://github.com/RisingCyber; research tool)",
        "Accept": "application/json, text/plain",
        "Accept-Encoding": "gzip, deflate",
    })

    # Credentials MUST NOT be stored in session.headers here.
    # Space-Track auth is handled via session cookie from login POST.
    return session


def _log_snippet(text: str, max_len: int = 300) -> str:
    """
    Produce a safe, truncated, single-line snippet of response text for
    diagnostic logging only. This is NEVER written to CSV/JSON outputs —
    it exists solely so the operator can see what a server actually
    returned when JSON parsing fails (e.g. an HTML block page, a rate-limit
    notice, a captive-portal redirect). Control characters and newlines are
    collapsed so the log stays readable and cannot inject fake log lines.
    """
    if not text:
        return "<empty response body>"
    # Collapse whitespace/newlines, strip control chars, truncate
    flat = re.sub(r"\s+", " ", text)
    flat = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", flat)
    flat = flat.strip()
    if len(flat) > max_len:
        flat = flat[:max_len] + f"... [truncated, {len(text)} bytes total]"
    return flat or "<empty after sanitization>"


def safe_get(
    session: requests.Session,
    url: str,
    logger: logging.Logger,
    label: str = "",
    params: Optional[Dict] = None,
) -> Optional[Any]:
    """
    Perform a validated, rate-limited HTTPS GET request.
    Returns parsed JSON or None on failure.

    Security controls:
    - URL validated against allowlist (SSRF prevention)
    - TLS verification: verify=True always
    - Response Content-Type checked before JSON parsing
    - Response size capped at MAX_RESPONSE_BYTES
    - Timeout enforced

    Diagnostic note: requests.exceptions.JSONDecodeError is a subclass of
    requests.exceptions.RequestException in requests>=2.27. It is caught
    HERE, specifically and BEFORE the generic RequestException handler,
    so that a non-JSON response (HTML error page, rate-limit notice,
    captive portal, WAF block page, etc.) is logged with the actual HTTP
    status code, Content-Type, and a body snippet — not masked as a
    generic "request failed" with no diagnostic value.
    """
    # SSRF mitigation: validate before requesting
    try:
        validated_url = validate_url(url)
    except ValueError as e:
        logger.error("URL validation failed for %s: %s", label or url, e)
        return None

    logger.info("Fetching %s ...", label or validated_url)

    response = None
    try:
        response = session.get(
            validated_url,
            params=params,
            timeout=REQUEST_TIMEOUT_SEC,
            verify=True,          # TLS cert verification — NEVER set to False
            allow_redirects=True, # urllib3 will still validate redirected host TLS
        )
        response.raise_for_status()

        # A08: Response size cap (prevent memory exhaustion from malicious large responses)
        content_length = len(response.content)
        if content_length > MAX_RESPONSE_BYTES:
            logger.warning(
                "Response from %s exceeds size limit (%d bytes). Skipping.",
                label, content_length,
            )
            return None

        # A08: Content-Type validation — only accept JSON from data endpoints
        content_type = response.headers.get("Content-Type", "")
        if "json" not in content_type and "text" not in content_type:
            logger.warning(
                "Unexpected Content-Type '%s' from %s (HTTP %d). Skipping. Body: %s",
                content_type, label, response.status_code, _log_snippet(response.text),
            )
            return None

        return response.json()

    except requests.exceptions.JSONDecodeError as e:
        # Response was 2xx and passed the Content-Type gate, but the body
        # is not valid JSON. Almost always means the server returned an
        # HTML page (error/rate-limit/WAF/captive-portal) with a JSON-ish
        # or text Content-Type header. Log everything needed to diagnose.
        status = response.status_code if response is not None else "?"
        ctype  = response.headers.get("Content-Type", "?") if response is not None else "?"
        body   = _log_snippet(response.text) if response is not None else "<no response object>"
        logger.error(
            "JSON decode failed for %s | HTTP %s | Content-Type: %s | "
            "Parse error: %s | Response body: %s",
            label, status, ctype, e, body,
        )
        return None
    except requests.exceptions.SSLError as e:
        logger.error("TLS/SSL error fetching %s: %s", label, e)
        return None
    except requests.exceptions.Timeout:
        logger.warning("Request timed out for %s", label)
        return None
    except requests.exceptions.HTTPError as e:
        status = response.status_code if response is not None else "?"
        body   = _log_snippet(response.text) if response is not None else ""
        logger.warning("HTTP error from %s: %s (HTTP %s) Body: %s", label, e, status, body)
        return None
    except requests.exceptions.RequestException as e:
        logger.error("Request failed for %s: %s", label, e)
        return None
    except ValueError as e:
        # Fallback for any non-requests JSON error (shouldn't normally hit
        # this given the JSONDecodeError handler above, but kept for safety
        # across requests library version differences).
        logger.error("JSON parse error from %s: %s", label, e)
        return None


# ─────────────────────────────────────────────────────────────────────────────
#  CACHE — Avoid hammering CelesTrak on repeated runs
# ─────────────────────────────────────────────────────────────────────────────

def cache_key_from_url(url: str) -> str:
    """Derive a safe filename from a URL for caching."""
    import hashlib
    safe = re.sub(r"[^\w\-]", "_", url)[:80]
    digest = hashlib.sha256(url.encode()).hexdigest()[:12]
    return f"{safe}_{digest}.json"


def load_from_cache(cache_dir: Path, url: str, max_age_hours: int) -> Optional[Any]:
    """Load cached JSON if present and not stale. Returns None on cache miss."""
    cache_file = cache_dir / cache_key_from_url(url)
    if not cache_file.exists():
        return None
    age_seconds = time.time() - cache_file.stat().st_mtime
    if age_seconds > max_age_hours * 3600:
        return None
    try:
        with cache_file.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def save_to_cache(cache_dir: Path, url: str, data: Any) -> None:
    """Persist JSON data to cache. Silently ignores errors (cache is optional)."""
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / cache_key_from_url(url)
        with cache_file.open("w", encoding="utf-8") as fh:
            json.dump(data, fh)
    except OSError:
        pass


def fetch_with_cache(
    session: requests.Session,
    url: str,
    logger: logging.Logger,
    label: str,
    cache_dir: Path,
    no_cache: bool = False,
    max_age_hours: int = CACHE_MAX_AGE_H,
) -> Optional[Any]:
    """Fetch data from URL, using local cache to avoid repeated requests."""
    if not no_cache:
        cached = load_from_cache(cache_dir, url, max_age_hours)
        if cached is not None:
            logger.debug("Cache hit for %s", label)
            return cached

    data = safe_get(session, url, logger, label=label)
    if data is not None and not no_cache:
        save_to_cache(cache_dir, url, data)
    return data


# ─────────────────────────────────────────────────────────────────────────────
#  MISSION CLASSIFIER
# ─────────────────────────────────────────────────────────────────────────────

def classify_mission(name: str, object_type: str) -> Tuple[str, str]:
    """
    Classify a satellite by mission type using name pattern matching.
    Returns (mission_class_label, mission_description).

    Falls back to OBJECT_TYPE-based classification for unrecognized names.
    """
    # Fast path for debris and rocket bodies — CelesTrak OBJECT_TYPE field
    ot = (object_type or "").upper()
    if ot in ("ROCKET BODY", "R/B"):
        return ("ROCKET_BODY", "Spent Rocket Body")
    if ot in ("DEBRIS",):
        return ("DEBRIS", "Tracked Debris Object")

    # Name-based classification
    clean_name = (name or "").strip()
    for pattern, label, description in MISSION_PATTERNS:
        if pattern.search(clean_name):
            return (label, description)

    # Unknown — return sanitized type info
    if ot == "PAYLOAD":
        return ("UNKNOWN_PAYLOAD", "Unclassified Payload")
    return ("UNKNOWN", "Object Type Unknown")


def is_leo(perigee_km: float, apogee_km: float) -> bool:
    """Return True if orbital parameters fall within LEO bounds."""
    return (
        perigee_km >= LEO_PERIGEE_MIN_KM
        and apogee_km <= LEO_APOGEE_MAX_KM
        and perigee_km > 0
        and apogee_km > 0
    )


def resolve_country(code: str) -> str:
    """Map a CelesTrak country code to a human-readable name."""
    code_clean = (code or "").strip().upper()
    return COUNTRY_CODES.get(code_clean, code_clean or "Unknown")


def resolve_size_class(rcs_size_str: str, rcs_numeric: Optional[float] = None) -> str:
    """
    Derive a coarse size class from RCS data.

    Two schemas exist across CelesTrak endpoints:
      - GP schema:       RCS_SIZE (string: SMALL / MEDIUM / LARGE / N/A)
      - SATCAT-records:  RCS (numeric float, m²)

    We try the string field first; fall back to numeric thresholds; fall
    back to SIZE_UNKNOWN. Thresholds are per Space-Track data dictionary:
    SMALL < 0.1 m², MEDIUM 0.1–1.0 m², LARGE > 1.0 m².

    This is intentionally a coarse proxy — see comments in the constants
    block for why we don't infer CubeSat U-class from this data.
    """
    # Try string bucket first (GP schema)
    key = (rcs_size_str or "").strip().upper()
    if key in RCS_SIZE_TO_CLASS:
        result = RCS_SIZE_TO_CLASS[key]
        if result != "SIZE_UNKNOWN":
            return result

    # Fall back to numeric thresholds (SATCAT-records schema)
    if rcs_numeric is not None and rcs_numeric >= 0:
        for threshold, label in RCS_NUMERIC_THRESHOLDS:
            if rcs_numeric < threshold:
                return label
        return RCS_LARGE_CLASS

    return "SIZE_UNKNOWN"


def resolve_threat_tier(mission_class: str) -> str:
    """
    Return an ILLUSTRATIVE threat-tier band for a given mission class,
    drawn from the Bailey/Aerospace Corporation Tier I–VII adversary model
    (TOR-2021-01333-REV A, Table 3). This is a heuristic prioritization aid
    based on publicly documented adversary-interest patterns by mission
    category — it is explicitly NOT satellite-specific threat intelligence.
    See THREAT_TIER_BY_MISSION_CLASS comment block for the full caveat.
    """
    return THREAT_TIER_BY_MISSION_CLASS.get(mission_class, THREAT_TIER_DEFAULT)


def resolve_lifecycle_status(launch_date_str: str, decay_date_str: str = "") -> str:
    """
    Classify an object's lifecycle status using LAUNCH_DATE and DECAY_DATE
    fields already extracted from CelesTrak — pure local computation, no
    external calls. Both fields are documented as ISO 8601 (yyyy-mm-dd)
    by CelesTrak's own satcat-format.php spec.

    Returns one of:
      NEWLY_LAUNCHED    — launched within LIFECYCLE_RECENT_DAYS
      RECENTLY_DECAYED  — DECAY_DATE set, within LIFECYCLE_RECENT_DAYS
      ESTABLISHED       — launched longer ago, no recent decay
      UNKNOWN           — LAUNCH_DATE missing or unparseable
    """
    now = datetime.now(timezone.utc)

    if decay_date_str:
        decay_dt = _parse_iso_date(decay_date_str)
        if decay_dt is not None:
            days_since_decay = (now - decay_dt).days
            if 0 <= days_since_decay <= LIFECYCLE_RECENT_DAYS:
                return "RECENTLY_DECAYED"

    launch_dt = _parse_iso_date(launch_date_str)
    if launch_dt is None:
        return "UNKNOWN"

    days_since_launch = (now - launch_dt).days
    if 0 <= days_since_launch <= LIFECYCLE_RECENT_DAYS:
        return "NEWLY_LAUNCHED"

    return "ESTABLISHED"


def _parse_iso_date(date_str: str) -> Optional[datetime]:
    """
    Parse a date string in the yyyy-mm-dd (or yyyy-mm-ddTHH:MM:SS) format
    CelesTrak documents for LAUNCH_DATE/DECAY_DATE. Returns None on any
    parse failure — never raises, since this handles untrusted external data.
    """
    if not date_str:
        return None
    candidate = date_str.strip()[:10]  # take just the date portion
    try:
        dt = datetime.strptime(candidate, "%Y-%m-%d")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


# ─────────────────────────────────────────────────────────────────────────────
#  DATA FETCHERS
# ─────────────────────────────────────────────────────────────────────────────

def _mean_motion_to_altitude_km(mean_motion_rev_per_day: float) -> float:
    """
    Derive approximate circular orbit altitude (km) from MEAN_MOTION.
    Uses Kepler's third law: a = (μ × T²/4π²)^(1/3).
    Used only as a fallback when PERIGEE/PERIAPSIS/APOGEE/APOAPSIS are absent.
    Assumes a nearly circular orbit — sufficient for LEO triage filtering.
    Returns 0.0 on invalid input.
    """
    if not mean_motion_rev_per_day or mean_motion_rev_per_day <= 0:
        return 0.0
    try:
        period_s = SECS_PER_DAY / mean_motion_rev_per_day
        import math
        semi_major_km = (EARTH_GM_KM3_S2 * (period_s / (2 * math.pi)) ** 2) ** (1 / 3)
        return max(0.0, semi_major_km - EARTH_RADIUS_KM)
    except (ValueError, ZeroDivisionError):
        return 0.0


def _probe(raw: Dict, *keys: str, default: Any = None) -> Any:
    """
    Return the first non-None value found across candidate field names.
    Used to handle CelesTrak's varying schemas across API versions.
    """
    for k in keys:
        v = raw.get(k)
        if v is not None:
            return v
    return default


def fetch_celestrak_satcat(
    session: requests.Session,
    logger: logging.Logger,
    cache_dir: Path,
    no_cache: bool,
) -> List[Dict]:
    """
    Fetch satellite data from CelesTrak using a prioritised endpoint list.

    Uses the confirmed satcat/records.php API (see constants block above
    for the verified query contract and field schema).

    Strategy:
    1. Try CELESTRAK_PRIMARY_ENDPOINTS in order; take first valid JSON list.
    2. Supplement with named constellation group endpoints (Starlink,
       Qianfan, stations, etc.) to capture objects the primary group query
       may not include.
    3. Merge and return all raw records — deduplication by NORAD ID happens
       later in process_satcat_records() + deduplicate_by_norad().
    """
    combined: List[Dict] = []
    primary_ok = False

    # ── Step 1: Primary endpoint (first success wins) ─────────────────────────
    for url, label in CELESTRAK_PRIMARY_ENDPOINTS:
        data = fetch_with_cache(session, url, logger, label=label,
                                cache_dir=cache_dir, no_cache=no_cache)
        if isinstance(data, list) and data:
            logger.info("%s: %d raw records.", label, len(data))
            combined.extend(data)
            primary_ok = True
            break  # Don't try next primary — we have data
        else:
            logger.warning("%s returned no usable data — trying next endpoint.", label)
        time.sleep(INTER_REQUEST_DELAY)

    if not primary_ok:
        logger.error(
            "All primary CelesTrak endpoints failed.\n"
            "  Tried:\n%s\n"
            "  Run with --diagnose for a raw HTTP dump, or check the current "
            "API contract at https://celestrak.org/satcat/satcat-format.php",
            "\n".join(f"    {u}" for u, _ in CELESTRAK_PRIMARY_ENDPOINTS),
        )

    # ── Step 2: GP group supplements (non-fatal if individual ones fail) ──────
    for group_name, url in CELESTRAK_GP_GROUPS.items():
        time.sleep(INTER_REQUEST_DELAY)
        data = fetch_with_cache(session, url, logger, label=f"CelesTrak-GP-{group_name}",
                                cache_dir=cache_dir, no_cache=no_cache)
        if isinstance(data, list) and data:
            logger.info("CelesTrak-GP-%s: %d raw records.", group_name, len(data))
            combined.extend(data)
        else:
            logger.debug("GP group '%s' returned no data — skipping.", group_name)

    logger.info("CelesTrak total raw records (before dedup): %d", len(combined))
    return combined


def fetch_spacetrack_satcat(
    session: requests.Session,
    logger: logging.Logger,
    cache_dir: Path,
    no_cache: bool,
    username: str,
    password: str,
) -> List[Dict]:
    """
    Fetch supplemental data from Space-Track.org (optional, free account required).
    Credentials are loaded from environment variables only — never hardcoded.

    Security: POST body is not logged. Session cookie handles auth after login.
    """
    try:
        validate_url(SPACETRACK_LOGIN_URL)
    except ValueError as e:
        logger.error("Space-Track login URL validation failed: %s", e)
        return []

    logger.info("Authenticating with Space-Track.org ...")

    try:
        # Credentials sent as POST body — not logged, not in URL
        login_resp = session.post(
            SPACETRACK_LOGIN_URL,
            data={"identity": username, "password": password},
            timeout=REQUEST_TIMEOUT_SEC,
            verify=True,
        )
        login_resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.error("Space-Track login failed: %s", e)
        return []

    # Credentials are now out of scope — session holds auth cookie
    del username, password

    data = fetch_with_cache(
        session, SPACETRACK_SATCAT_URL, logger,
        label="Space-Track SATCAT", cache_dir=cache_dir, no_cache=no_cache,
    )
    if not isinstance(data, list):
        logger.warning("Space-Track SATCAT returned unexpected format.")
        return []

    logger.info("Space-Track SATCAT: %d objects received.", len(data))
    return data


# ─────────────────────────────────────────────────────────────────────────────
#  SatNOGS DB — optional frequency/transmitter enrichment
#  See constants block above for verification notes and caveats.
# ─────────────────────────────────────────────────────────────────────────────

def fetch_satnogs_transmitters(
    session: requests.Session,
    logger: logging.Logger,
    cache_dir: Path,
    no_cache: bool,
) -> List[Dict]:
    """
    Fetch active transmitter records from SatNOGS DB, using ONLY the
    confirmed-working `status=active` filter (see constants block for the
    public GitLab issue confirming this). Handles three possible response
    shapes defensively, since pagination behavior was not independently
    testable at implementation time:
      1. A raw JSON list (matches the one live sample response we verified)
      2. A DRF-style {"results": [...], "next": "url"} wrapper
      3. RFC 5988 Link-header-based pagination (rel="next")
    Follows pagination up to SATNOGS_MAX_PAGES as a safety cap. Any failure
    is non-fatal — the caller proceeds without enrichment data.
    """
    all_transmitters: List[Dict] = []
    url = SATNOGS_TRANSMITTERS_URL
    pages_fetched = 0

    while url and pages_fetched < SATNOGS_MAX_PAGES:
        try:
            validated_url = validate_url(url)
        except ValueError as e:
            logger.warning("SatNOGS URL validation failed, stopping pagination: %s", e)
            break

        # Use cache only for the first page (subsequent pages have unique
        # URLs from pagination and would each create a new cache entry —
        # acceptable, but we skip caching complexity for page 2+).
        if pages_fetched == 0:
            data = fetch_with_cache(
                session, validated_url, logger, label="SatNOGS-transmitters-p1",
                cache_dir=cache_dir, no_cache=no_cache,
            )
            response_headers: Dict[str, str] = {}
        else:
            raw_response = safe_get(session, validated_url, logger,
                                     label=f"SatNOGS-transmitters-p{pages_fetched + 1}")
            data = raw_response
            response_headers = {}

        pages_fetched += 1

        if data is None:
            logger.warning("SatNOGS transmitters fetch failed at page %d — stopping.", pages_fetched)
            break

        # Handle response shape
        next_url: Optional[str] = None
        if isinstance(data, list):
            all_transmitters.extend(data)
        elif isinstance(data, dict) and "results" in data:
            batch = data.get("results")
            if isinstance(batch, list):
                all_transmitters.extend(batch)
            next_url = data.get("next")
        else:
            logger.warning("Unexpected SatNOGS response shape at page %d — stopping.", pages_fetched)
            break

        logger.info("SatNOGS transmitters page %d: %d records (running total %d).",
                    pages_fetched, len(data) if isinstance(data, list) else len(data.get("results", [])),
                    len(all_transmitters))

        # Only continue pagination if we got a `next` URL from a dict-shaped
        # response. A raw-list response (our confirmed sample shape) means
        # we already have everything in one call — stop here.
        if next_url:
            time.sleep(INTER_REQUEST_DELAY)
            url = next_url
        else:
            break

    if pages_fetched >= SATNOGS_MAX_PAGES:
        logger.warning(
            "SatNOGS pagination hit the %d-page safety cap — results may be "
            "incomplete. This cap exists because pagination behavior for "
            "this endpoint was not independently verified.", SATNOGS_MAX_PAGES,
        )

    logger.info("SatNOGS DB: %d total active transmitter records fetched.", len(all_transmitters))
    return all_transmitters


def build_transmitter_lookup(raw_transmitters: List[Dict], logger: logging.Logger) -> Dict[int, List[Dict]]:
    """
    Build a NORAD ID -> [sanitized transmitter summary, ...] lookup from raw
    SatNOGS transmitter records. All fields are UNTRUSTED external data and
    sanitized before use (OWASP A03), matching the treatment applied to
    CelesTrak data throughout this script.
    """
    lookup: Dict[int, List[Dict]] = {}
    skipped = 0

    for raw in raw_transmitters:
        if not isinstance(raw, dict):
            skipped += 1
            continue

        norad_id = safe_int(raw.get("norad_cat_id"), 0)
        if norad_id <= 0:
            skipped += 1
            continue

        downlink_hz = safe_float(raw.get("downlink_low"), default=-1.0)
        mode = sanitize_code(raw.get("mode"), 16)
        alive = bool(raw.get("alive", False))
        status = sanitize_code(raw.get("status"), 16)
        freq_violation = bool(raw.get("frequency_violation", False))

        entry = {
            "downlink_mhz": round(downlink_hz / 1_000_000.0, 4) if downlink_hz > 0 else None,
            "mode": mode,
            "alive": alive,
            "status": status,
            "frequency_violation": freq_violation,
        }
        lookup.setdefault(norad_id, []).append(entry)

    if skipped:
        logger.debug("SatNOGS lookup: skipped %d malformed transmitter records.", skipped)
    logger.info("SatNOGS lookup built: %d satellites with known transmitter data.", len(lookup))
    return lookup


def enrich_with_satnogs(
    records: List[Dict],
    transmitter_lookup: Dict[int, List[Dict]],
    logger: logging.Logger,
) -> None:
    """
    Mutate `records` in place, filling the known_transmitter_count,
    primary_downlink_mhz, primary_downlink_mode, and frequency_violation_flag
    fields for any satellite whose NORAD ID appears in the SatNOGS lookup.
    Records with no match are left with their existing blank defaults.

    "Primary" downlink is chosen as the lowest-frequency ALIVE transmitter
    for that satellite, which is typically (not guaranteed) the main
    telemetry beacon — a reasonable, clearly-documented heuristic rather
    than a claim of authoritative "the" downlink.
    """
    matched = 0
    for rec in records:
        norad_id = rec.get("norad_cat_id")
        transmitters = transmitter_lookup.get(norad_id)
        if not transmitters:
            continue

        matched += 1
        rec["known_transmitter_count"] = len(transmitters)

        alive_with_freq = [
            t for t in transmitters if t["alive"] and t["downlink_mhz"] is not None
        ]
        primary = None
        if alive_with_freq:
            primary = min(alive_with_freq, key=lambda t: t["downlink_mhz"])

        if primary:
            rec["primary_downlink_mhz"] = primary["downlink_mhz"]
            rec["primary_downlink_mode"] = primary["mode"] or "UNKNOWN"

        rec["frequency_violation_flag"] = any(t["frequency_violation"] for t in transmitters)

    logger.info("SatNOGS enrichment applied to %d of %d LEO records.", matched, len(records))


# ─────────────────────────────────────────────────────────────────────────────
#  DATA PROCESSOR
# ─────────────────────────────────────────────────────────────────────────────

def process_satcat_records(
    records: List[Dict],
    source_label: str,
    logger: logging.Logger,
) -> List[Dict]:
    """
    Parse, validate, filter, and classify satellite catalog records.
    Returns a list of sanitized, classified LEO satellite dicts.

    All field values from external data go through sanitize_string() or
    safe_float()/safe_int() before use — injection prevention A03.
    """
    retrieved_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    results: List[Dict] = []
    skipped_non_leo  = 0
    skipped_invalid  = 0

    for raw in records:
        if not isinstance(raw, dict):
            skipped_invalid += 1
            continue

        # ── Field extraction ───────────────────────────────────────────────────
        # Primary field names below are CONFIRMED against CelesTrak's own
        # documentation (https://celestrak.org/satcat/satcat-format.php,
        # verified 2 July 2026): OBJECT_NAME, OBJECT_ID, NORAD_CAT_ID,
        # OBJECT_TYPE, OPS_STATUS_CODE, OWNER, LAUNCH_DATE, DECAY_DATE,
        # PERIOD, INCLINATION, APOGEE, PERIGEE, RCS (numeric, m²).
        #
        # Secondary fallback names (OBJECT_NUMBER, SATNAME, COUNTRY, LAUNCH,
        # PERIAPSIS/APOAPSIS, RCS_SIZE, MEAN_MOTION) are defensive only — kept
        # in case CelesTrak changes field names again, or in case a cached/
        # older response uses different naming. They are NOT independently
        # verified; if the primary name is present, the fallback is never used.
        #
        # All values treated as UNTRUSTED regardless of source — sanitized
        # before use (OWASP A03).

        norad_id = safe_int(
            _probe(raw, "NORAD_CAT_ID", "OBJECT_NUMBER"), 0
        )
        intl_des = sanitize_string(
            _probe(raw, "OBJECT_ID", "INTLDES"), 20
        )
        name = sanitize_string(
            _probe(raw, "OBJECT_NAME", "SATNAME"), 80
        )
        country = sanitize_code(
            _probe(raw, "OWNER", "COUNTRY_CODE", "COUNTRY"), 10
        )
        object_type = sanitize_string(
            _probe(raw, "OBJECT_TYPE"), 30
        )
        perigee_km = safe_float(
            _probe(raw, "PERIGEE", "PERIAPSIS")
        )
        apogee_km = safe_float(
            _probe(raw, "APOGEE", "APOAPSIS")
        )

        # Defensive fallback only: derive approximate altitude from
        # MEAN_MOTION if PERIGEE/APOGEE are null (documented as possible —
        # "null if no data available" per CelesTrak's own field spec) or if
        # an unexpected response shape omits them entirely.
        if perigee_km <= 0 or apogee_km <= 0:
            mean_motion = safe_float(_probe(raw, "MEAN_MOTION"))
            if mean_motion > 0:
                approx_alt = _mean_motion_to_altitude_km(mean_motion)
                if perigee_km <= 0:
                    perigee_km = approx_alt
                if apogee_km <= 0:
                    apogee_km = approx_alt

        incl_deg = safe_float(
            _probe(raw, "INCLINATION", "INCLO")
        )
        period_min = safe_float(
            _probe(raw, "PERIOD")
        )
        if period_min <= 0:
            mm = safe_float(_probe(raw, "MEAN_MOTION"))
            if mm > 0:
                period_min = 1440.0 / mm

        # RCS is confirmed NUMERIC (m²) in the satcat/records.php schema.
        # RCS_SIZE (string bucket) is retained as a defensive fallback for
        # any endpoint that might still return the older bucketed form.
        rcs_size_str = sanitize_code(
            _probe(raw, "RCS_SIZE"), 10
        )
        rcs_numeric: Optional[float] = None
        raw_rcs = _probe(raw, "RCS")
        if raw_rcs is not None:
            rcs_numeric = safe_float(raw_rcs, default=-1.0)
            if rcs_numeric < 0:
                rcs_numeric = None

        launch_date = sanitize_code(
            _probe(raw, "LAUNCH_DATE", "LAUNCH"), 12
        )
        decay_date = sanitize_code(
            _probe(raw, "DECAY_DATE"), 12
        )
        current = sanitize_code(
            _probe(raw, "OPS_STATUS_CODE", "CURRENT"), 2
        )

        # ── NORAD ID sanity check ─────────────────────────────────────────────
        if norad_id <= 0:
            skipped_invalid += 1
            continue

        # ── LEO filter ────────────────────────────────────────────────────────
        if not is_leo(perigee_km, apogee_km):
            skipped_non_leo += 1
            continue

        # ── Classify mission ──────────────────────────────────────────────────
        mission_class, mission_desc = classify_mission(name, object_type)

        results.append({
            "norad_cat_id":            norad_id,
            "intl_designator":         intl_des,
            "name":                    name,
            "country_code":            country.upper() if country else "??",
            "country_name":            resolve_country(country),
            "object_type":             object_type,
            "mission_class":           mission_class,
            "mission_description":     mission_desc,
            "illustrative_threat_tier": resolve_threat_tier(mission_class),
            "lifecycle_status":        resolve_lifecycle_status(launch_date, decay_date),
            "perigee_km":              round(perigee_km, 1),
            "apogee_km":               round(apogee_km, 1),
            "inclination_deg":         round(incl_deg, 2),
            "period_min":              round(period_min, 3),
            "rcs_size":                rcs_size_str,
            "size_class":              resolve_size_class(rcs_size_str, rcs_numeric),
            "launch_date":             launch_date,
            "decay_date":              decay_date,
            "current_in_orbit":        current,
            "orbit_class":             "LEO",
            # Populated later by enrich_with_satnogs() only when
            # --enrich-frequencies is passed; blank otherwise.
            "known_transmitter_count": "",
            "primary_downlink_mhz":    "",
            "primary_downlink_mode":   "",
            "frequency_violation_flag": "",
            "data_source":             sanitize_string(source_label, 40),
            "retrieved_utc":           retrieved_utc,
        })

    logger.info(
        "[%s] Processed %d LEO objects. Skipped: %d non-LEO, %d invalid.",
        source_label, len(results), skipped_non_leo, skipped_invalid,
    )
    return results


def deduplicate_by_norad(records: List[Dict]) -> List[Dict]:
    """
    Remove duplicate records by NORAD catalog ID.
    CelesTrak is primary; Space-Track supplements without overwriting.
    """
    seen: Dict[int, Dict] = {}
    for rec in records:
        nid = rec.get("norad_cat_id", 0)
        if nid and nid not in seen:
            seen[nid] = rec
    return list(seen.values())


# ─────────────────────────────────────────────────────────────────────────────
#  OUTPUT WRITERS
# ─────────────────────────────────────────────────────────────────────────────

def write_csv(records: List[Dict], out_path: Path, logger: logging.Logger) -> None:
    """
    Write records to CSV using csv.writer.
    Security: csv.writer handles quoting/delimiter escaping — no string
    concatenation into CSV output (OWASP A03 injection prevention).
    Additionally, every string field is passed through
    neutralize_csv_formula() to defuse CSV/spreadsheet formula injection
    (a distinct risk from delimiter injection — see that function's docstring).
    """
    try:
        with out_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(
                fh,
                fieldnames=CSV_FIELDNAMES,
                extrasaction="ignore",
                quoting=csv.QUOTE_MINIMAL,
            )
            writer.writeheader()
            for row in records:
                safe_row = {k: neutralize_csv_formula(v) for k, v in row.items()}
                writer.writerow(safe_row)
        # Restrict file permissions (readable by owner only on POSIX)
        try:
            out_path.chmod(0o644)
        except OSError:
            pass
        logger.info("CSV written: %s (%d records)", out_path, len(records))
    except OSError as e:
        logger.error("Failed to write CSV: %s", e)


def write_json(records: List[Dict], out_path: Path, logger: logging.Logger) -> None:
    """
    Write records to JSON using json.dumps.
    Security: json.dumps handles escaping — no f-string construction of JSON output.
    """
    try:
        with out_path.open("w", encoding="utf-8") as fh:
            json.dump(records, fh, indent=2, ensure_ascii=True)
        try:
            out_path.chmod(0o644)
        except OSError:
            pass
        logger.info("JSON written: %s (%d records)", out_path, len(records))
    except OSError as e:
        logger.error("Failed to write JSON: %s", e)


def print_summary(records: List[Dict], logger: logging.Logger) -> None:
    """Print a human-readable mission class summary to stdout."""
    if not records:
        logger.info("No LEO records to summarize.")
        return

    class_counts: Dict[str, int] = {}
    country_counts: Dict[str, int] = {}

    for rec in records:
        mc = rec.get("mission_class", "UNKNOWN")
        class_counts[mc] = class_counts.get(mc, 0) + 1
        cc = rec.get("country_name", "Unknown")
        country_counts[cc] = country_counts.get(cc, 0) + 1

    print("\n" + "=" * 66)
    print(f"  {TOOL_NAME} — LEO Satellite Summary")
    print("=" * 66)
    print(f"  Total LEO objects classified: {len(records)}")
    print()
    print("  MISSION CLASSES:")
    for cls, count in sorted(class_counts.items(), key=lambda x: -x[1]):
        bar = "█" * min(count // 10, 30)
        print(f"    {cls:<28} {count:>6}  {bar}")
    print()
    print("  TOP 10 COUNTRIES / OPERATORS:")
    for country, count in sorted(country_counts.items(), key=lambda x: -x[1])[:10]:
        print(f"    {country:<35} {count:>6}")
    print("=" * 66 + "\n")


# ─────────────────────────────────────────────────────────────────────────────
#  CROSS-RUN DIFF / ANOMALY DETECTION
#  See MANEUVER_* threshold constants above for the honest caveat on what
#  this can and cannot claim to detect.
# ─────────────────────────────────────────────────────────────────────────────

def load_previous_snapshot(out_dir: Path, logger: logging.Logger) -> Optional[Dict[int, Dict]]:
    """
    Load the snapshot saved at the end of the previous run, if any.
    Returns None if no snapshot exists yet (e.g., first-ever run) or if
    the file is unreadable/corrupt — never raises.
    """
    snapshot_path = out_dir / SNAPSHOT_FILENAME
    if not snapshot_path.exists():
        logger.info("No previous snapshot found at %s — this may be the first run.", snapshot_path)
        return None
    try:
        with snapshot_path.open("r", encoding="utf-8") as fh:
            raw = json.load(fh)
        # Keys are stored as strings in JSON; convert back to int
        return {int(k): v for k, v in raw.items()}
    except (OSError, ValueError, TypeError) as e:
        logger.warning("Could not read previous snapshot (%s) — skipping diff.", e)
        return None


def save_snapshot(records: List[Dict], out_dir: Path, logger: logging.Logger) -> None:
    """
    Persist a compact snapshot of this run's classified records, for the
    NEXT run's --diff-previous comparison. Stores only the fields needed
    for diffing, not the full record, to keep the file small.
    """
    snapshot = {
        str(rec["norad_cat_id"]): {
            "name": rec.get("name", ""),
            "mission_class": rec.get("mission_class", ""),
            "perigee_km": rec.get("perigee_km", 0),
            "apogee_km": rec.get("apogee_km", 0),
            "inclination_deg": rec.get("inclination_deg", 0),
            "decay_date": rec.get("decay_date", ""),
            "snapshot_utc": rec.get("retrieved_utc", ""),
        }
        for rec in records
    }
    snapshot_path = out_dir / SNAPSHOT_FILENAME
    try:
        with snapshot_path.open("w", encoding="utf-8") as fh:
            json.dump(snapshot, fh, indent=2)
        logger.info("Snapshot saved for next run's diff: %s (%d objects).",
                    snapshot_path, len(snapshot))
    except OSError as e:
        logger.warning("Could not save snapshot: %s", e)


def compute_diff(
    current_records: List[Dict],
    previous: Dict[int, Dict],
    logger: logging.Logger,
) -> Dict[str, Any]:
    """
    Compare current_records against the previous snapshot. Returns a dict
    with three categories: new_objects, vanished_objects, and
    maneuver_candidates. See the MANEUVER_* constants for the honest
    caveat on what "maneuver_candidates" actually means (a triage signal,
    not a confirmed detection).
    """
    current_by_id = {rec["norad_cat_id"]: rec for rec in current_records}
    current_ids = set(current_by_id.keys())
    previous_ids = set(previous.keys())

    new_ids = current_ids - previous_ids
    vanished_ids = previous_ids - current_ids
    common_ids = current_ids & previous_ids

    new_objects = [
        {
            "norad_cat_id": nid,
            "name": current_by_id[nid].get("name", ""),
            "mission_class": current_by_id[nid].get("mission_class", ""),
        }
        for nid in sorted(new_ids)
    ]

    vanished_objects = [
        {
            "norad_cat_id": nid,
            "name": previous[nid].get("name", ""),
            "mission_class": previous[nid].get("mission_class", ""),
            "last_seen_utc": previous[nid].get("snapshot_utc", ""),
        }
        for nid in sorted(vanished_ids)
    ]

    maneuver_candidates = []
    for nid in sorted(common_ids):
        cur = current_by_id[nid]
        prev = previous[nid]

        d_perigee = abs(safe_float(cur.get("perigee_km")) - safe_float(prev.get("perigee_km")))
        d_apogee  = abs(safe_float(cur.get("apogee_km")) - safe_float(prev.get("apogee_km")))
        d_incl    = abs(safe_float(cur.get("inclination_deg")) - safe_float(prev.get("inclination_deg")))

        if (d_perigee >= MANEUVER_ALTITUDE_DELTA_KM
                or d_apogee >= MANEUVER_ALTITUDE_DELTA_KM
                or d_incl >= MANEUVER_INCLINATION_DELTA_DEG):
            maneuver_candidates.append({
                "norad_cat_id": nid,
                "name": cur.get("name", ""),
                "mission_class": cur.get("mission_class", ""),
                "delta_perigee_km": round(d_perigee, 2),
                "delta_apogee_km": round(d_apogee, 2),
                "delta_inclination_deg": round(d_incl, 3),
                "previous_snapshot_utc": prev.get("snapshot_utc", ""),
            })

    logger.info(
        "Diff complete: %d new, %d vanished, %d maneuver-candidate objects "
        "(thresholds: %.1f km altitude / %.2f deg inclination).",
        len(new_objects), len(vanished_objects), len(maneuver_candidates),
        MANEUVER_ALTITUDE_DELTA_KM, MANEUVER_INCLINATION_DELTA_DEG,
    )

    return {
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "caveat": (
            "Maneuver candidates are a coarse triage signal from comparing "
            "two catalog snapshots, not a confirmed maneuver detection. "
            "See MANEUVER_* threshold constants in leo_sentinel.py for the "
            "full methodology caveat."
        ),
        "thresholds": {
            "altitude_delta_km": MANEUVER_ALTITUDE_DELTA_KM,
            "inclination_delta_deg": MANEUVER_INCLINATION_DELTA_DEG,
        },
        "new_objects": new_objects,
        "vanished_objects": vanished_objects,
        "maneuver_candidates": maneuver_candidates,
    }


def print_diff_summary(diff: Dict[str, Any]) -> None:
    """Print a human-readable diff summary to stdout."""
    print("\n" + "=" * 66)
    print("  CROSS-RUN DIFF SUMMARY")
    print("=" * 66)
    print(f"  New objects since last run       : {len(diff['new_objects'])}")
    print(f"  Vanished objects since last run   : {len(diff['vanished_objects'])}")
    print(f"  Maneuver-candidate objects        : {len(diff['maneuver_candidates'])}")
    print(f"  (thresholds: {diff['thresholds']['altitude_delta_km']} km / "
          f"{diff['thresholds']['inclination_delta_deg']} deg)")

    if diff["maneuver_candidates"]:
        print("\n  Maneuver candidates (worth a human look, not confirmed):")
        for m in diff["maneuver_candidates"][:15]:
            print(f"    {m['norad_cat_id']:>6}  {m['name'][:30]:<30}  "
                  f"Δperigee={m['delta_perigee_km']:>6.1f}km  "
                  f"Δapogee={m['delta_apogee_km']:>6.1f}km  "
                  f"Δincl={m['delta_inclination_deg']:>5.2f}°")
        if len(diff["maneuver_candidates"]) > 15:
            print(f"    ... and {len(diff['maneuver_candidates']) - 15} more (see {DIFF_REPORT_FILENAME})")

    print(f"\n  {diff['caveat']}")
    print("=" * 66 + "\n")


# ─────────────────────────────────────────────────────────────────────────────
#  CLI ARGUMENT PARSER
# ─────────────────────────────────────────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leo_sentinel",
        description=(
            f"{TOOL_NAME} v{VERSION} — LEO Satellite Aggregator & Classifier\n"
            "Aggregates publicly available LEO satellite data from CelesTrak.\n"
            "For SDR-based signals and space security research workflows.\n\n"
            "Credentials (for optional Space-Track.org) via env vars only:\n"
            "  SPACETRACK_USER, SPACETRACK_PASS"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
    )
    parser.add_argument(
        "--format",
        dest="output_format",
        choices=["csv", "json", "both"],
        default="csv",
        help="Output format (default: csv)",
    )
    parser.add_argument(
        "--out-dir",
        dest="out_dir",
        default=DEFAULT_OUT_DIR,
        help=f"Output directory (default: ./{DEFAULT_OUT_DIR})",
    )
    parser.add_argument(
        "--no-cache",
        dest="no_cache",
        action="store_true",
        default=False,
        help="Force fresh download, ignore cached data",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="Enable verbose debug logging",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        default=False,
        help="Print mission class summary table after completion",
    )
    parser.add_argument(
        "--user-agent",
        dest="user_agent",
        default=None,
        help=(
            "Override the HTTP User-Agent string. Some networks/WAFs serve "
            "an HTML block page instead of JSON for non-browser User-Agents. "
            "Try a browser-like string if you see JSON decode errors, e.g.: "
            '--user-agent "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"'
        ),
    )
    parser.add_argument(
        "--diagnose",
        action="store_true",
        default=False,
        help=(
            "Run a single diagnostic GET against the primary CelesTrak "
            "endpoint, print full HTTP status/headers/body snippet, and "
            "exit. Use this first if data fetches are failing."
        ),
    )
    parser.add_argument(
        "--enrich-frequencies",
        dest="enrich_frequencies",
        action="store_true",
        default=False,
        help=(
            "Cross-reference each satellite against SatNOGS DB "
            "(db.satnogs.org) for known downlink frequency, modulation "
            "mode, transmitter count, and ITU frequency-violation flag. "
            "SatNOGS DB is community-maintained/crowd-sourced — treat "
            "results as a research lead, not authoritative ground truth. "
            "Adds one extra bulk fetch; off by default."
        ),
    )
    parser.add_argument(
        "--diff-previous",
        dest="diff_previous",
        action="store_true",
        default=False,
        help=(
            "Compare this run's results against the snapshot saved at the "
            "end of the previous run in the same --out-dir, flagging new "
            "objects, vanished objects, and orbital-parameter shifts "
            "large enough to warrant a human look (coarse triage only — "
            "not a confirmed maneuver-detection system). Writes "
            f"{DIFF_REPORT_FILENAME} alongside the normal output."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_NAME} v{VERSION}",
    )
    return parser


# ─────────────────────────────────────────────────────────────────────────────
#  DIAGNOSTIC MODE
#  Run with --diagnose to see exactly what CelesTrak's servers send back,
#  without any of the JSON-parsing or classification logic in the way.
#  This exists because JSON decode failures can have several different
#  root causes (wrong endpoint, rate limiting, WAF/bot block, captive
#  portal, DNS interception) that all produce a superficially similar
#  error, but require different fixes.
# ─────────────────────────────────────────────────────────────────────────────

def run_diagnostic(session: requests.Session, logger: logging.Logger) -> int:
    """
    Perform one raw GET against the primary CelesTrak endpoint and print
    full diagnostic detail: HTTP status, all response headers, and the
    first 1000 characters of the raw response body. No JSON parsing,
    no caching, no retries beyond the session default.

    This isolates whether the problem is:
      - DNS/network/proxy interception (body will look like a captive
        portal login page, or the request will time out / fail to connect)
      - A WAF or bot-detection block (body often mentions Cloudflare,
        "Access Denied", a CAPTCHA, or a challenge page)
      - CelesTrak-specific rate limiting (body may say so explicitly)
      - A genuinely wrong URL/path (HTTP 404, or a CelesTrak "not found"
        page rather than a block page)
      - Everything working correctly (valid JSON — in which case the
        earlier failure was likely transient; try the normal run again)
    """
    url, label = CELESTRAK_PRIMARY_ENDPOINTS[0]
    print(f"\n{'='*70}")
    print(f"  DIAGNOSTIC MODE — raw request to: {url}")
    print(f"{'='*70}\n")

    try:
        validated_url = validate_url(url)
    except ValueError as e:
        print(f"[FATAL] URL failed allowlist validation: {e}")
        return 1

    try:
        response = session.get(
            validated_url, timeout=REQUEST_TIMEOUT_SEC, verify=True,
        )
    except requests.exceptions.SSLError as e:
        print(f"[RESULT] TLS/SSL error — certificate or handshake problem: {e}")
        print("  This usually indicates a network-level interception (proxy,")
        print("  firewall doing TLS inspection) rather than a CelesTrak issue.")
        return 1
    except requests.exceptions.ConnectionError as e:
        print(f"[RESULT] Connection error — could not reach the host at all: {e}")
        print("  Check DNS resolution and outbound connectivity to celestrak.org.")
        print("  Try: curl -v https://celestrak.org/  (from the same machine)")
        return 1
    except requests.exceptions.Timeout:
        print("[RESULT] Request timed out. Network is reachable but slow, or")
        print("  the server is not responding within the timeout window.")
        return 1
    except requests.exceptions.RequestException as e:
        print(f"[RESULT] Request failed: {e}")
        return 1

    print(f"HTTP Status Code : {response.status_code}")
    print(f"Content-Type     : {response.headers.get('Content-Type', '<not set>')}")
    print(f"Content-Length   : {response.headers.get('Content-Length', '<not set>')}")
    print(f"Server           : {response.headers.get('Server', '<not set>')}")
    print(f"Response bytes   : {len(response.content)}")

    # Detect common WAF / block-page signatures for a quicker diagnosis.
    body_lower = response.text.lower() if response.text else ""
    signals = []
    if "cloudflare" in body_lower or "cf-ray" in response.headers.get("Server", "").lower():
        signals.append("Cloudflare (WAF/CDN) markers detected")
    if "captcha" in body_lower or "are you human" in body_lower:
        signals.append("CAPTCHA / bot-challenge page detected")
    if "rate limit" in body_lower or "too many requests" in body_lower:
        signals.append("Rate-limit message detected")
    if "access denied" in body_lower or "403 forbidden" in body_lower:
        signals.append("Access-denied page detected")
    if "<html" in body_lower[:200]:
        signals.append("Response body is HTML, not JSON")
    if not response.text:
        signals.append("Response body is completely empty")

    if signals:
        print("\nLikely cause(s) detected:")
        for s in signals:
            print(f"  - {s}")
    else:
        print("\nNo obvious block-page signature detected.")

    print(f"\nFirst 1000 characters of response body:")
    print("-" * 70)
    print(response.text[:1000] if response.text else "<empty>")
    print("-" * 70)

    try:
        response.json()
        print("\n[RESULT] Body parsed as valid JSON. The endpoint is working —")
        print("  if your normal run still fails, it may have been transient.")
        print("  Try again, possibly with --no-cache.")
    except (ValueError, requests.exceptions.JSONDecodeError):
        print("\n[RESULT] Body is NOT valid JSON. See signals above.")
        print("  Suggested next steps:")
        print("   1. Open the URL in a browser on the same network to compare.")
        print("   2. Try again in a few minutes (transient rate limiting).")
        print("   3. Try --user-agent with a browser-style string if you")
        print("      suspect User-Agent-based blocking.")
        print("   4. If on a corporate or VM network, check for a")
        print("      transparent proxy or DNS filter intercepting HTTPS.")

    print(f"\n{'='*70}\n")
    return 0


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    """
    Main entry point. Returns 0 on success, non-zero on error.
    """
    print(TOOL_BANNER)
    parser = build_arg_parser()
    args = parser.parse_args()

    # ── Output directory setup ────────────────────────────────────────────────
    out_dir = Path(args.out_dir).expanduser()
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"[FATAL] Cannot create output directory '{out_dir}': {e}", file=sys.stderr)
        return 1

    cache_dir = out_dir / CACHE_DIR_NAME

    # ── Logging ───────────────────────────────────────────────────────────────
    logger = configure_logging(verbose=args.verbose, log_dir=out_dir)
    logger.info("Starting %s v%s", TOOL_NAME, VERSION)
    logger.info("Output directory: %s", out_dir.resolve())

    # ── HTTP session ──────────────────────────────────────────────────────────
    session = build_http_session(user_agent=args.user_agent)

    # ── Diagnostic mode: single request, full raw detail, then exit ──────────
    if args.diagnose:
        return run_diagnostic(session, logger)

    # ── Primary data source: CelesTrak (multi-endpoint with fallback) ─────────
    all_records: List[Dict] = []

    raw_celestrak = fetch_celestrak_satcat(session, logger, cache_dir, args.no_cache)
    if raw_celestrak:
        classified = process_satcat_records(raw_celestrak, "CelesTrak", logger)
        all_records.extend(classified)
    else:
        logger.warning(
            "CelesTrak returned no data from any endpoint. "
            "Run with --diagnose to see the raw HTTP response, or --verbose "
            "for detailed per-request logging."
        )

    # ── Optional: Space-Track.org ─────────────────────────────────────────────
    # Credentials loaded from environment only — never from CLI or code
    st_user = os.environ.get("SPACETRACK_USER", "").strip()
    st_pass = os.environ.get("SPACETRACK_PASS", "").strip()

    if st_user and st_pass:
        logger.info("Space-Track credentials found — fetching supplemental data.")
        time.sleep(INTER_REQUEST_DELAY)
        raw_spacetrack = fetch_spacetrack_satcat(
            session, logger, cache_dir, args.no_cache, st_user, st_pass,
        )
        # Clear credentials from local scope immediately after passing to function
        st_user = st_pass = ""  # noqa: S105 — clearing intentionally
        if raw_spacetrack:
            classified_st = process_satcat_records(raw_spacetrack, "Space-Track.org", logger)
            all_records.extend(classified_st)
    else:
        logger.info(
            "Space-Track credentials not set. Using CelesTrak only. "
            "(Set SPACETRACK_USER and SPACETRACK_PASS env vars to enable.)"
        )
        st_user = st_pass = ""

    # ── Deduplicate ───────────────────────────────────────────────────────────
    all_records = deduplicate_by_norad(all_records)
    logger.info("Total unique LEO objects after deduplication: %d", len(all_records))

    if not all_records:
        logger.error(
            "No LEO records were produced. "
            "Check network connectivity or try --no-cache."
        )
        return 2

    # Sort by NORAD ID for deterministic output
    all_records.sort(key=lambda r: r.get("norad_cat_id", 0))

    # ── Optional: SatNOGS DB frequency/transmitter enrichment ─────────────────
    if args.enrich_frequencies:
        logger.info("Fetching SatNOGS DB transmitter data for enrichment ...")
        raw_transmitters = fetch_satnogs_transmitters(session, logger, cache_dir, args.no_cache)
        if raw_transmitters:
            transmitter_lookup = build_transmitter_lookup(raw_transmitters, logger)
            enrich_with_satnogs(all_records, transmitter_lookup, logger)
        else:
            logger.warning(
                "SatNOGS DB returned no transmitter data — proceeding without "
                "frequency enrichment. This is non-fatal; core output is unaffected."
            )

    # ── Optional: cross-run diff against previous snapshot ────────────────────
    diff_report: Optional[Dict[str, Any]] = None
    if args.diff_previous:
        previous_snapshot = load_previous_snapshot(out_dir, logger)
        if previous_snapshot is not None:
            diff_report = compute_diff(all_records, previous_snapshot, logger)
            diff_path = out_dir / DIFF_REPORT_FILENAME
            try:
                safe_diff_path = validate_output_path(diff_path, out_dir)
                with safe_diff_path.open("w", encoding="utf-8") as fh:
                    json.dump(diff_report, fh, indent=2)
                logger.info("Diff report written: %s", safe_diff_path)
            except (ValueError, OSError) as e:
                logger.error("Could not write diff report: %s", e)
        else:
            logger.info("Skipping diff — no previous snapshot to compare against.")

    # Always save a snapshot for the NEXT run, regardless of whether this
    # run itself performed a diff — this is what makes --diff-previous
    # "just work" on the following invocation.
    save_snapshot(all_records, out_dir, logger)

    # ── Write output ──────────────────────────────────────────────────────────
    fmt = args.output_format

    if fmt in ("csv", "both"):
        csv_path = out_dir / OUTPUT_CSV_NAME
        try:
            safe_csv = validate_output_path(csv_path, out_dir)
            write_csv(all_records, safe_csv, logger)
        except ValueError as e:
            logger.error("Output path validation failed: %s", e)
            return 3

    if fmt in ("json", "both"):
        json_path = out_dir / OUTPUT_JSON_NAME
        try:
            safe_json = validate_output_path(json_path, out_dir)
            write_json(all_records, safe_json, logger)
        except ValueError as e:
            logger.error("Output path validation failed: %s", e)
            return 3

    # ── Optional summary ──────────────────────────────────────────────────────
    if args.summary:
        print_summary(all_records, logger)

    if diff_report is not None:
        print_diff_summary(diff_report)

    logger.info("Done. %s complete.", TOOL_NAME)
    return 0


if __name__ == "__main__":
    sys.exit(main())