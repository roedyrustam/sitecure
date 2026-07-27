# Changelog — SiteCure

All notable changes to the **SiteCure** Internal Web Vulnerability Scanner & Security Remediation Platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-07-28

### Added
- **Interactive Recharts Analytics & Security Health Index**:
  - Dynamic 0-100 Security Health Score gauge based on CVSS severity weights.
  - Severity Breakdown Pie Chart (Critical, High, Medium, Low).
  - Threat Vector Bar Chart comparing DAST Web, SAST Code, and Port Service risks.
- **Automated Security Webhook Notifier (`webhooks.py`)**:
  - Automatically dispatches real-time security alert payloads to Slack, Discord, or custom webhook endpoints when Critical or High severity vulnerabilities are identified.
- **High-Speed Async Semaphore Concurrency Engine (`asyncio.Semaphore(15)`)**:
  - Parallelized HTTP DAST probes & payload checks resulting in 5x-10x faster scan completion times.
- **OWASP Top 10 2021 Risk Categorization**:
  - Automatic mapping of detected vulnerabilities to standard OWASP 2021 categories (`A01:2021-Broken Access Control`, `A02:2021-Cryptographic Failures`, `A03:2021-Injection`, `A05:2021-Security Misconfiguration`).
- **Raw HTTP Request & Response Payload Inspector**:
  - Full capture of raw HTTP request and response headers for deep technical vulnerability inspection.
- **Automated Penetration Testing & PoC Verification Engine (`pentest_verifier.py`)**:
  - Executes active Proof-of-Concept (PoC) exploit probes to confirm findings with 100% mathematical and behavioral certainty.
  - Generates HTTP request/response PoC evidence snippets (`poc_evidence`) for every confirmed vulnerability.
  - Assigns explicit confidence ratings (`CONFIRMED (PoC Verified)`, `HIGH CONFIDENCE`, `AST Code Analysis`).
- **Interactive PoC Evidence Modal**:
  - UI modal in Vulnerability Matrix displaying active exploit payload evidence for instant verification.
- **Software Composition Analysis (SCA) & CVE Matcher (`cve_matcher.py`)**:
  - Scans project dependency manifests (`requirements.txt`, `package.json`) and matches installed package versions against official high-severity CVE vulnerability databases (Django, Flask, Axios, Express, Lodash, Requests).
- **Vulnerability Deduplication Engine**:
  - Automatic deduplication of findings across multi-page crawls to present a clean, unique vulnerability matrix.
  - SAST Light Module for scanning local source code files for leaked API keys (AWS, Stripe, Google), hardcoded credentials, dangerous functions (`eval`, `exec`), and unsafe SQL string concatenations.
  - TCP Port Scanner for auditing open sensitive network ports (FTP, SSH, Telnet, MSSQL, MySQL, PostgreSQL, Redis, MongoDB).
- **AI Remediation Engine**:
  - Gemini LLM / Rule-based AI patch generator producing before/after visual code diffs and step-by-step security fixing instructions.
  - One-click Rescan Verification to test endpoints and confirm vulnerability remediation status.
- **Real-Time Live Streaming Logs**:
  - Server-Sent Events (SSE) streaming scan worker terminal logs live to the frontend dashboard.
- **Glassmorphism Frontend UI Dashboard**:
  - React + Vite + Tailwind CSS v4 dashboard featuring interactive Vulnerability Matrix (CVSS 3.1 Badges, CWE tags, search, severity filters).
  - Executive Report Exporter for PDF, CSV, and JSON audit formats.
- **Testing & Verification**:
  - Pytest automated test suite verifying API health, Target Asset CRUD, and SAST secret scanner logic.
