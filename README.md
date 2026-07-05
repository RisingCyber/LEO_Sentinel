# LEO_Sentinel
Australian Phoenix LEO Sentinel v1.1.0
=======================================
LEO Satellite Aggregator & Classifier for Signals/Space Security Research.

Australian Phoenix CyberOps | Signals & Space Security Research

PURPOSE
-------
Aggregates publicly available Low Earth Orbit (LEO) satellite data from
trusted, open-source databases, classifies each object by
mission type and operator, and outputs structured data for SDR-based
security research.


https://github.com/user-attachments/assets/58540901-7d41-4713-a2cb-20639c74bea4




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

SOME FEATURES AND DATABASES HAS BEEN REMOVED
---------------------------------------------
<img width="1770" height="741" alt="CSV" src="https://github.com/user-attachments/assets/024ddb36-770c-41d9-820a-5c58b1da9803" />

