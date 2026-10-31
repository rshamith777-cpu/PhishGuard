# EWB Cybersecurity Mini Project — Official Test Verification Evidence

**Project Name:** PhishGuard — Phishing URL Awareness & Intelligence Platform  
**Entry Point:** `phishing_checker.py`  
**Execution Environment:** Python 3.12.10 on Windows (x86_64)  
**Date of Verification:** 2026-10-31  
**Test Standard:** EWB Cybersecurity Mini Project Workbook (Mandatory Six Checks) + Defensive Heuristics

---

## 1. Complete Reconciliation of Detection Heuristics (12 Total)

Every analysis pass executes exactly 12 deterministic heuristic detectors across 4 modular agents:

| # | Check Identifier | Heuristic Name | Agent | Type |
|:---:|:---|:---|:---|:---:|
| **1** | `CHECK_1_AT_SYMBOL` | `@` Symbol in URL | Structure Analysis Agent | Mandatory EWB |
| **2** | `CHECK_2_URL_LENGTH` | Unusually Long URL (> 100) | Structure Analysis Agent | Mandatory EWB |
| **3** | `CHECK_3_IPV4_HOST` | IP Address Hostname | Hostname Intelligence Agent | Mandatory EWB |
| **4** | `CHECK_4_MANY_SEGMENTS` | Multiple Hostname Segments (>= 5) | Hostname Intelligence Agent | Mandatory EWB |
| **5** | `CHECK_5_PUNYCODE` | Punycode Encoded Hostname (`xn--`) | Hostname Intelligence Agent | Mandatory EWB |
| **6** | `CHECK_6_HTTP_SCHEME` | Unencrypted HTTP Scheme | Protocol Analysis Agent | Mandatory EWB |
| **7** | `ADV_URL_SHORTENER` | URL Shortening Service | Structure Analysis Agent | Advanced Defensive |
| **8** | `ADV_SUSPICIOUS_PARAMS` | Suspicious Query / Parameter Syntax | Structure Analysis Agent | Advanced Defensive |
| **9** | `ADV_SUSPICIOUS_ENCODING` | Obfuscated Encoding & Path Anomalies | Structure Analysis Agent | Advanced Defensive |
| **10** | `ADV_TYPOSQUATTING` | Typosquatting & Lookalike Domain | Hostname Intelligence Agent | Advanced Defensive |
| **11** | `ADV_MISLEADING_DOMAIN_STRUCTURE` | Misleading Brand Subdomain / Compound Domain | Hostname Intelligence Agent | Advanced Defensive |
| **12** | `ADV_PROTOCOL_PORT_ANOMALY` | Non-Standard Port or Protocol Scheme | Protocol Analysis Agent | Advanced Defensive |

---

## 2. Official Workbook Samples — Execution Record

### Sample 1: Legitimate Structure
- **Sample URL:** `https://www.example.com/login`
- **Expected Outcome:** No listed warning signs (0 indicators flagged).
- **Actual Result:** 
  - Indicator Count: `0 / 12`
  - Educational Classification: `NO LISTED WARNING SIGNS`
  - Findings: All 12 checks reported `[CLEAR]`.
- **Status:** **PASS**
- **Notes:** Honest educational notice generated: Absence of structural warning signs does not prove absolute safety.

### Sample 2: Direct IPv4 and Plaintext HTTP
- **Sample URL:** `http://192.0.2.10/account`
- **Expected Outcome:** IP-address hostname and HTTP scheme detected (2 indicators).
- **Actual Result:**
  - Indicator Count: `2 / 12`
  - Educational Classification: `REVIEW`
  - Detected Checks: `CHECK_3_IPV4_HOST`, `CHECK_6_HTTP_SCHEME`
- **Status:** **PASS**

### Sample 3: Userinfo Obfuscation and HTTP
- **Sample URL:** `http://example.com@sample.invalid/login`
- **Expected Outcome:** `@` symbol and HTTP scheme detected (2 indicators).
- **Actual Result:**
  - Indicator Count: `2 / 12`
  - Educational Classification: `REVIEW`
  - Detected Checks: `CHECK_1_AT_SYMBOL`, `CHECK_6_HTTP_SCHEME`
- **Status:** **PASS**

### Sample 4: Excessive Hostname Segments
- **Sample URL:** `https://a.b.c.d.e.example.invalid/path`
- **Expected Outcome:** Many hostname segments detected (>= 5 labels).
- **Actual Result:**
  - Indicator Count: `1 / 12`
  - Educational Classification: `REVIEW`
  - Detected Checks: `CHECK_4_MANY_SEGMENTS` (Found 7 dot-separated labels: `['a', 'b', 'c', 'd', 'e', 'example', 'invalid']`)
- **Status:** **PASS**

### Sample 5: Punycode Internationalized Domain
- **Sample URL:** `https://xn--example.invalid/`
- **Expected Outcome:** Punycode-style hostname detected (`xn--`).
- **Actual Result:**
  - Indicator Count: `1 / 12`
  - Educational Classification: `REVIEW`
  - Detected Checks: `CHECK_5_PUNYCODE` (Evidence: `['xn--example']`)
- **Status:** **PASS**

---

## 3. Automated Test Suite Summary
- **Suite Command:** `python -m unittest discover -s tests -p "test_*.py" -v`
- **Total Tests Run:** 29
- **Passed:** 29
- **Failed:** 0
- **Errors:** 0
- **Execution Time:** ~0.034s
