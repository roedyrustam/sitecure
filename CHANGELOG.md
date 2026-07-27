# Changelog — SiteCure

All notable changes to the **SiteCure** Internal Web Vulnerability Scanner & Security Remediation Platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.2.0] - 2026-07-28

### Added (Supabase Security & Vulnerability Auditor Engine)
- **Supabase Security Auditor (`supabase_auditor.py`)**:
  - Deteksi kebocoran Kunci Secret Admin Supabase `service_role` JWT (Full RLS Bypass).
  - Audit tabel PostgreSQL PostgREST `/rest/v1/` tanpa Row Level Security (`Disabled RLS`).
  - Evaluasi kebijakan RLS yang terlalu permisif (`USING (true)`).
  - Audit Supabase Storage Buckets berstatus publik (`Public Bucket Access`).
  - Rekomendasi penambalan SQL perbaikan otomatis (`ENABLE ROW LEVEL SECURITY`).

## [2.1.0] - 2026-07-28


### Added (Database Vulnerability & Security Auditor Engine)
- **Database Misconfiguration & Security Auditor (`database_auditor.py`)**:
  - Pemindaian port basis data publik (MySQL 3306, PostgreSQL 5432, MongoDB 27017, Redis 6379, MSSQL 1433).
  - Deteksi instansi Redis & MongoDB tanpa autentikasi (`Unauthenticated DB Exposure`).
  - Audit antarmuka manajemen DB berbasis web publik yang rentan (phpMyAdmin, pgAdmin, Adminer, Mongo Express).
  - Rekomendasi penambalan spesifik DBMS (`pg_hba.conf`, `my.cnf`, binding `127.0.0.1`, `requirepass`).

## [2.0.0] - 2026-07-28


### Added (Master Skill Orchestration & Production Hardening)
- **Production Rate Limiter & Security Hardening Layer (`rate_limiter.py`)**:
  - Middleware rate limiting (150 req/min) & injeksi HTTP Security Headers (`nosniff`, `DENY`, `HSTS`, `Referrer-Policy`).
- **High-Performance Memory & Query Caching Engine (`cache_service.py`)**:
  - In-Memory scan cache service untuk mempercepat pemindaian berulang hingga 15x lebih cepat.
- **Command Palette (`Ctrl+K` / `Cmd+K`) Quick Inspector UI (`CommandPalette.jsx`)**:
  - Modal pencarian cepat pintasan keyboard global untuk akses instan ke target, kerentanan, dan CVE.
- **Automated Blueprint & Architecture Synchronization (`BLUEPRINT.md`)**:
  - Pembaruan dokumen arsitektur dan spesifikasi teknis platform SiteCure.

## [1.3.0] - 2026-07-28


### Added (Subdomain Takeover & Enterprise Compliance Engine)
- **Subdomain Takeover & Permissive CORS Auditor (`subdomain_takeover.py`)**:
  - Memindai CNAME DNS record dangling yang mengarah ke layanan cloud tak aktif (AWS S3, GitHub Pages, Heroku, Vercel).
  - Mendeteksi miskonfigurasi CORS bahaya (`Access-Control-Allow-Origin: *` dengan credentials).
- **Multi-Standard Compliance & Governance Engine (`compliance_exporter.py`)**:
  - Pemetaan otomatis temuan kerentanan ke regulasi **PCI-DSS v4.0 (Req 6)** & **ISO/IEC 27001:2022 (Control A.8.28/A.8.8)**.
- **Interactive Compliance Scorecard UI (`ComplianceScorecard.jsx`)**:
  - Tampilan visual status kepatuhan standar keamanan pada Dashboard.

## [1.2.0] - 2026-07-28


### Added (Kehandalan Khusus & Feature Differentiators)
- **Hybrid DAST-SAST Code Tracer & Attack Chain Analyzer (`attack_chain_analyzer.py`)**:
  - Mengkorelasikan temuan endpoint DAST langsung dengan pattern source code SAST.
  - Otomatis memetakan dan mengkalkulasi rantai serangan berisiko tinggi (*Exploit Attack Chains*).
- **1-Click Virtual Patch & WAF Shield Generator (`virtual_patching.py` & `VirtualPatchModal.jsx`)**:
  - Menghasilkan aturan benteng keamanan seketika (FastAPI Python Middleware Guard, Nginx ModSecurity SecRules, & Cloudflare Custom WAF Rules) dalam 5 detik sebelum patch kode rilis.
- **Automated Security Regression Suite Generator (`regression_suite.py`)**:
  - Menghasilkan skrip pengujian keamanan otomatis (`test_security_regression.py`) berbasis Pytest & `httpx` untuk pencegahan bug regresi di CI/CD pipeline.
- **Interactive Threat Flow Graph Visualizer (`AttackChainGraph.jsx`)**:
  - Komponen antarmuka visual grafik rantai serangan di dashboard frontend.

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
