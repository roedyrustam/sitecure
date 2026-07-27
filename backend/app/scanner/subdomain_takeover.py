"""
Subdomain Takeover & Permissive CORS Auditor.
Memindai CNAME DNS record target untuk mendeteksi layanan cloud terabaikan (AWS S3, GitHub Pages, Heroku, Vercel)
serta mengevaluasi kebijakan CORS yang berbahaya.
"""

import httpx
import socket
from urllib.parse import urlparse
from typing import List, Dict, Any

class SubdomainTakeoverScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        parsed = urlparse(target_url)
        self.domain = parsed.netloc or parsed.path
        if ":" in self.domain:
            self.domain = self.domain.split(":")[0]

    async def scan_all(self) -> List[Dict[str, Any]]:
        findings = []
        
        # 1. Audit Permissive CORS Configuration
        cors_finding = await self._audit_cors()
        if cors_finding:
            findings.append(cors_finding)

        # 2. Audit Subdomain Takeover Risk
        takeover_finding = await self._audit_subdomain_takeover()
        if takeover_finding:
            findings.append(takeover_finding)

        return findings

    async def _audit_cors(self) -> Dict[str, Any]:
        try:
            headers = {"Origin": "https://evil-attacker-domain.com"}
            async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
                res = await client.get(self.target_url, headers=headers)
                
                acao = res.headers.get("Access-Control-Allow-Origin", "")
                acac = res.headers.get("Access-Control-Allow-Credentials", "")

                if acao == "https://evil-attacker-domain.com" and acac.lower() == "true":
                    return {
                        "title": "Critical Permissive CORS Misconfiguration (Arbitrary Origin Allowed with Credentials)",
                        "description": "Server merespon permintaan CORS dengan memantulkan Origin penyerang (https://evil-attacker-domain.com) dan mengizinkan Access-Control-Allow-Credentials: true. Hal ini memungkinkan situs jahat membaca data sensitif dan JWT/Session Cookie pengguna.",
                        "severity": "CRITICAL",
                        "cvss_score": 8.8,
                        "cwe_id": "CWE-942",
                        "affected_endpoint": self.target_url,
                        "vulnerability_type": "DAST",
                        "owasp_category": "A01:2021-Broken Access Control",
                        "confidence": "CONFIRMED (PoC Verified)",
                        "remediation_guide": "Hindari memantulkan nilai header Origin secara otomatis dan jangan gabungkan Access-Control-Allow-Credentials: true dengan wildcard atau origin tak terpercaya. Gunakan whitelist domain resmi yang diperbolehkan.",
                        "poc_evidence": f"Request Header 'Origin: https://evil-attacker-domain.com' -> Response Header 'Access-Control-Allow-Origin: https://evil-attacker-domain.com' & 'Access-Control-Allow-Credentials: true'"
                    }
                elif acao == "*":
                    return {
                        "title": "Overly Permissive CORS Policy (Wildcard Origin Allowed)",
                        "description": "Server mengizinkan domain mana pun (*) untuk membaca respon HTTP via Cross-Origin Resource Sharing.",
                        "severity": "LOW",
                        "cvss_score": 3.7,
                        "cwe_id": "CWE-942",
                        "affected_endpoint": self.target_url,
                        "vulnerability_type": "DAST",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "confidence": "HIGH CONFIDENCE",
                        "remediation_guide": "Batasi header Access-Control-Allow-Origin hanya untuk domain internal yang membutuhkan."
                    }
        except Exception:
            pass
        return None

    async def _audit_subdomain_takeover(self) -> Dict[str, Any]:
        # Dangling CNAME signatures for cloud services
        takeover_signatures = {
            "github.io": "There isn't a GitHub Pages site here.",
            "herokuapp.com": "Heroku | No such app",
            "s3.amazonaws.com": "The specified bucket does not exist",
            "azurewebsites.net": "404 Web Site not found",
            "netlify.app": "Not Found - Request ID"
        }

        try:
            # Simple CNAME check
            cname = socket.gethostbyname_ex(self.domain)[0]
            for cloud_domain, signature in takeover_signatures.items():
                if cloud_domain in cname:
                    # Probe endpoint for unclaimed service message
                    async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
                        res = await client.get(self.target_url)
                        if signature in res.text:
                            return {
                                "title": f"Subdomain Takeover Vulnerability (Dangling CNAME pointing to {cloud_domain})",
                                "description": f"Subdomain {self.domain} mengarah ke CNAME {cname} yang sudah tidak aktif atau dihapus di layanan cloud ({cloud_domain}). Penyerang dapat mendaftarkan nama yang sama di akun cloud mereka dan mengambil alih subdomain ini secara penuh.",
                                "severity": "HIGH",
                                "cvss_score": 8.1,
                                "cwe_id": "CWE-284",
                                "affected_endpoint": f"CNAME: {cname}",
                                "vulnerability_type": "DAST",
                                "owasp_category": "A05:2021-Security Misconfiguration",
                                "confidence": "CONFIRMED (PoC Verified)",
                                "remediation_guide": "Hapus record CNAME DNS yang mengarah ke akun cloud yang sudah tidak terpakai atau klaim kembali resource tersebut di dashboard cloud provider.",
                                "poc_evidence": f"CNAME {cname} returned signature: '{signature}'"
                            }
        except Exception:
            pass
        return None
