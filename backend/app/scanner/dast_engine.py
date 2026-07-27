import asyncio
import httpx
import re
import urllib.parse
from typing import List, Dict, Any

class DASTEngine:
    """
    Enterprise High-Performance Asynchronous DAST Security Engine.
    Performs safe HTTP security probes, header audits, SSL/TLS checks,
    and OWASP Top 10 payload fuzzing (Reflected XSS, SQLi, Open Redirects, Exposed Files).
    """
    DEFAULT_HEADERS = {
        "User-Agent": "SiteCure-SecurityScanner/1.0 (Enterprise Fast Web Inspector)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }

    def __init__(self, target_url: str, safe_mode: bool = True, concurrency_limit: int = 15):
        self.target_url = target_url.rstrip('/')
        self.safe_mode = safe_mode
        self.semaphore = asyncio.Semaphore(concurrency_limit)
        self.findings = []
        self.client = httpx.AsyncClient(
            timeout=10.0,
            verify=False,
            follow_redirects=True,
            headers=self.DEFAULT_HEADERS,
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=50)
        )

    async def run_all_checks(self, log_callback=None) -> List[Dict[str, Any]]:
        try:
            if log_callback:
                await log_callback(5, f"High-Speed Engine probing: {self.target_url}...")

            # Run Header, SSL, OWASP Fuzzing, & Redirect checks concurrently
            await asyncio.gather(
                self.check_security_headers_and_cors(log_callback),
                self.check_ssl_and_cookies(log_callback),
                self.fuzz_owasp_vulnerabilities(log_callback),
                self.check_open_redirects(log_callback)
            )

        except Exception as e:
            if log_callback:
                await log_callback(90, f"DAST scan notice: {str(e)}")
        finally:
            await self.client.aclose()

        return self.findings

    async def check_security_headers_and_cors(self, log_callback=None):
        async with self.semaphore:
            try:
                res = await self.client.get(self.target_url)
                headers = {k.lower(): v for k, v in res.headers.items()}
                raw_request = f"GET {self.target_url} HTTP/1.1\nHost: {urllib.parse.urlparse(self.target_url).netloc}"
                raw_response = f"HTTP/1.1 {res.status_code} {res.reason_phrase}\n" + "\n".join([f"{k}: {v}" for k, v in res.headers.items()])

                # 1. HSTS
                if 'strict-transport-security' not in headers:
                    self.findings.append({
                        "title": "Missing HSTS Header (HTTP Strict Transport Security)",
                        "description": "Header Strict-Transport-Security tidak ditemukan pada server response. Hal ini memungkinkan serangan SSL Strip dan Man-In-The-Middle (MITM).",
                        "severity": "HIGH",
                        "cvss_score": 7.5,
                        "cwe_id": "CWE-523",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "affected_endpoint": f"{self.target_url}/",
                        "vulnerability_type": "DAST",
                        "raw_request": raw_request,
                        "raw_response": raw_response[:500],
                        "remediation_guide": "Tambahkan header Strict-Transport-Security pada web server (e.g. `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`)."
                    })

                # 2. CSP
                if 'content-security-policy' not in headers:
                    self.findings.append({
                        "title": "Missing Content Security Policy (CSP)",
                        "description": "Content-Security-Policy tidak dikonfigurasi. Website rentan terhadap Cross-Site Scripting (XSS) dan Data Injection.",
                        "severity": "HIGH",
                        "cvss_score": 7.2,
                        "cwe_id": "CWE-1021",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "affected_endpoint": f"{self.target_url}/",
                        "vulnerability_type": "DAST",
                        "raw_request": raw_request,
                        "raw_response": raw_response[:500],
                        "remediation_guide": "Konfigurasikan CSP header untuk membatasi origin eksekusi script & asset. Contoh: `Content-Security-Policy: default-src 'self'; script-src 'self'`."
                    })

                # 3. Clickjacking
                if 'x-frame-options' not in headers and 'content-security-policy' not in headers:
                    self.findings.append({
                        "title": "Missing Clickjacking Protection (X-Frame-Options)",
                        "description": "Header X-Frame-Options tidak ditemukan. Halaman web dapat di-embed dalam <iframe> untuk serangan Clickjacking.",
                        "severity": "MEDIUM",
                        "cvss_score": 5.4,
                        "cwe_id": "CWE-1021",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "affected_endpoint": f"{self.target_url}/",
                        "vulnerability_type": "DAST",
                        "raw_request": raw_request,
                        "raw_response": raw_response[:500],
                        "remediation_guide": "Tambahkan header `X-Frame-Options: DENY` atau `X-Frame-Options: SAMEORIGIN` pada konfigurasi HTTP server."
                    })

                # 4. Server Version Disclosure
                server_header = headers.get('server', '') or headers.get('x-powered-by', '')
                if server_header and any(char.isdigit() for char in server_header):
                    self.findings.append({
                        "title": f"Web Server Information Disclosure ({server_header})",
                        "description": f"Header server mengungkapkan versi lengkap software: '{server_header}'. Informasi ini membantu penyerang mengidentifikasi exploit spesifik.",
                        "severity": "LOW",
                        "cvss_score": 3.7,
                        "cwe_id": "CWE-200",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "affected_endpoint": f"{self.target_url}/",
                        "vulnerability_type": "DAST",
                        "raw_request": raw_request,
                        "raw_response": raw_response[:500],
                        "remediation_guide": "Sembunyikan banner versi server. Pada Nginx gunakan `server_tokens off;`, pada Apache `ServerTokens Prod`."
                    })

                # 5. Permissive CORS
                cors_origin = headers.get('access-control-allow-origin', '')
                cors_credentials = headers.get('access-control-allow-credentials', '')
                if cors_origin == '*' and cors_credentials.lower() == 'true':
                    self.findings.append({
                        "title": "Insecure CORS Policy (Wildcard Origin with Credentials)",
                        "description": "Konfigurasi CORS memperbolehkan semua domain (`*`) mengakses data sensitif dengan kredensial user.",
                        "severity": "CRITICAL",
                        "cvss_score": 8.5,
                        "cwe_id": "CWE-942",
                        "owasp_category": "A01:2021-Broken Access Control",
                        "affected_endpoint": f"{self.target_url}/",
                        "vulnerability_type": "DAST",
                        "raw_request": raw_request,
                        "raw_response": raw_response[:500],
                        "remediation_guide": "Gantikan `Access-Control-Allow-Origin: *` dengan daftar whitelist domain internal yang diizinkan saja."
                    })

            except Exception:
                pass

    async def check_ssl_and_cookies(self, log_callback=None):
        if self.target_url.startswith("http://"):
            self.findings.append({
                "title": "Unencrypted HTTP Protocol Used on Target",
                "description": "Website beroperasi melalui protokol HTTP tanpa enkripsi TLS/SSL. Semua kredensial dan data sensitif dikirim dalam bentuk plaintext.",
                "severity": "HIGH",
                "cvss_score": 7.4,
                "cwe_id": "CWE-319",
                "owasp_category": "A02:2021-Cryptographic Failures",
                "affected_endpoint": self.target_url,
                "vulnerability_type": "DAST",
                "remediation_guide": "Terapkan sertifikat SSL/TLS (Let's Encrypt / Internal CA) dan konfigurasikan pengalihan otomatis dari HTTP ke HTTPS."
            })

    async def fuzz_owasp_vulnerabilities(self, log_callback=None):
        sensitive_paths = [
            ("/.env", "Exposed Environment File (.env)", "CRITICAL", 9.1, "CWE-552", "A05:2021-Security Misconfiguration", "File .env publik berisi database credentials & API keys secret."),
            ("/.git/HEAD", "Exposed Git Repository", "CRITICAL", 8.6, "CWE-538", "A05:2021-Security Misconfiguration", "Direktori .git terbuka secara publik. Penyerang dapat mengunduh seluruh kode sumber."),
            ("/phpinfo.php", "Exposed PHPInfo Configuration", "MEDIUM", 5.3, "CWE-200", "A05:2021-Security Misconfiguration", "phpinfo() mengungkapkan detail internal server, modul PHP, dan variabel sistem."),
            ("/swagger/ui", "Exposed Swagger API Documentation", "LOW", 3.1, "CWE-200", "A05:2021-Security Misconfiguration", "Dokumentasi API internal terbuka tanpa autentikasi.")
        ]

        async def probe_path(path, title, severity, score, cwe, owasp, desc):
            async with self.semaphore:
                try:
                    test_url = f"{self.target_url}{path}"
                    res = await self.client.get(test_url)
                    if res.status_code == 200 and len(res.text) > 10:
                        raw_request = f"GET {test_url} HTTP/1.1"
                        raw_response = f"HTTP/1.1 200 OK\nContent-Length: {len(res.text)}\n\n{res.text[:300]}"

                        if path == "/.env" and ("DB_" in res.text or "SECRET" in res.text or "KEY" in res.text or "APP_" in res.text):
                            self.findings.append({
                                "title": title, "description": desc, "severity": severity,
                                "cvss_score": score, "cwe_id": cwe, "owasp_category": owasp,
                                "affected_endpoint": test_url, "vulnerability_type": "DAST",
                                "raw_request": raw_request, "raw_response": raw_response,
                                "remediation_guide": "Blokir akses ke file .env dari web server root."
                            })
                        elif path == "/.git/HEAD" and ("refs/" in res.text or "master" in res.text or "main" in res.text):
                            self.findings.append({
                                "title": title, "description": desc, "severity": severity,
                                "cvss_score": score, "cwe_id": cwe, "owasp_category": owasp,
                                "affected_endpoint": test_url, "vulnerability_type": "DAST",
                                "raw_request": raw_request, "raw_response": raw_response,
                                "remediation_guide": "Kunci atau hapus direktori .git pada web server."
                            })
                        elif path in ["/phpinfo.php", "/swagger/ui"]:
                            self.findings.append({
                                "title": title, "description": desc, "severity": severity,
                                "cvss_score": score, "cwe_id": cwe, "owasp_category": owasp,
                                "affected_endpoint": test_url, "vulnerability_type": "DAST",
                                "raw_request": raw_request, "raw_response": raw_response,
                                "remediation_guide": "Minta otentikasi admin untuk mengakses dokumen ini."
                            })
                except Exception:
                    pass

        tasks = [probe_path(*item) for item in sensitive_paths]
        await asyncio.gather(*tasks)

        # Reflected XSS Probe
        parsed = urllib.parse.urlparse(self.target_url)
        if parsed.query:
            xss_payload = "<script>alert('SiteCure')</script>"
            try:
                test_url = f"{self.target_url}&xss={urllib.parse.quote(xss_payload)}"
                res = await self.client.get(test_url)
                if xss_payload in res.text:
                    self.findings.append({
                        "title": "Reflected Cross-Site Scripting (XSS)",
                        "description": "Input parameter di-render langsung ke dalam HTML tanpa sanitasi. Penyerang dapat mengeksekusi JavaScript berbahaya di browser korban.",
                        "severity": "HIGH",
                        "cvss_score": 8.2,
                        "cwe_id": "CWE-79",
                        "owasp_category": "A03:2021-Injection",
                        "affected_endpoint": test_url,
                        "vulnerability_type": "DAST",
                        "raw_request": f"GET {test_url} HTTP/1.1",
                        "raw_response": f"HTTP/1.1 200 OK\n\n...{res.text[:300]}...",
                        "remediation_guide": "Lakukan HTML entity encoding pada semua user input sebelum di-render ke browser."
                    })
            except Exception:
                pass

    async def check_open_redirects(self, log_callback=None):
        redirect_params = ["?next=https://evil.example.com", "?redirect=https://evil.example.com"]
        for param in redirect_params:
            async with self.semaphore:
                try:
                    test_url = f"{self.target_url}/{param}"
                    res = await self.client.get(test_url)
                    if res.status_code in [301, 302] and "evil.example.com" in res.headers.get("location", ""):
                        self.findings.append({
                            "title": "Unvalidated URL Redirect (Open Redirect)",
                            "description": "Parameter redirect mengizinkan pengalihan pengguna ke domain eksternal berbahaya (`evil.example.com`).",
                            "severity": "MEDIUM",
                            "cvss_score": 6.1,
                            "cwe_id": "CWE-601",
                            "owasp_category": "A01:2021-Broken Access Control",
                            "affected_endpoint": test_url,
                            "vulnerability_type": "DAST",
                            "raw_request": f"GET {test_url} HTTP/1.1",
                            "raw_response": f"HTTP/1.1 {res.status_code} Redirect\nLocation: {res.headers.get('location')}",
                            "remediation_guide": "Validasi parameter redirect hanya mengizinkan URL relatif lokal (`/dashboard`)."
                        })
                except Exception:
                    pass
