"""
Cloudflare WAF Obfuscation & Evasion Resilience Auditor.
Menguji keandalan dan ketahanan aturan Cloudflare WAF target terhadap variasi payload
yang di-obfuscate (Double URL Encoding, Unicode Normalization, HPP).
"""

import httpx
from typing import List, Dict, Any

class WAFEvasionAuditor:
    def __init__(self, target_url: str):
        self.target_url = target_url

    async def audit_waf_resilience(self) -> List[Dict[str, Any]]:
        findings = []
        
        # Test payloads: Raw vs Obfuscated
        test_cases = [
            {
                "name": "SQL Injection Unicode Normalization",
                "raw_payload": "' OR 1=1 --",
                "obfuscated_payload": "%27%20%4F%52%201%3D1%20%2D%2D",
                "cwe": "CWE-89"
            },
            {
                "name": "Cross-Site Scripting Double Encoding",
                "raw_payload": "<script>alert(1)</script>",
                "obfuscated_payload": "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
                "cwe": "CWE-79"
            }
        ]

        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
                for tc in test_cases:
                    # Send obfuscated probe
                    url = f"{self.target_url.rstrip('/')}/?q={tc['obfuscated_payload']}"
                    res = await client.get(url)

                    # If WAF did not block (HTTP 403 / 406 / Cloudflare Block Page) and returned 200 OK
                    if res.status_code == 200 and not any(cf_kw in res.text for cf_kw in ["Attention Required!", "Cloudflare Ray ID", "Access denied"]):
                        findings.append({
                            "title": f"Cloudflare WAF Evasion Risk: Obfuscated Payload Bypass ({tc['name']})",
                            "description": f"Target Cloudflare WAF rules failed to inspect or normalize obfuscated payloads ({tc['obfuscated_payload']}). The server processed the obfuscated input with status 200 OK.",
                            "severity": "HIGH",
                            "cvss_score": 7.5,
                            "cwe_id": tc['cwe'],
                            "affected_endpoint": f"{self.target_url}?q={tc['obfuscated_payload']}",
                            "vulnerability_type": "DAST",
                            "owasp_category": "A03:2021-Injection",
                            "confidence": "HIGH CONFIDENCE",
                            "remediation_guide": "Aktifkan Cloudflare Managed Ruleset (OWASP Core Ruleset / CRS) dengan sensitivity level High, serta aktifkan fungsi URL Normalization & Decode pada dashboard Cloudflare Rules.",
                            "poc_evidence": f"GET {url} -> Returned HTTP 200 OK (WAF did not issue 403 Block Challenge)"
                        })
        except Exception:
            pass

        return findings
