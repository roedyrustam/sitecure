"""
Virtual Patching & Instant Shield Generator Service.
Menghasilkan aturan WAF seketika (Nginx ModSecurity, Cloudflare WAF, FastAPI Middleware)
untuk membentengi server dalam 5 detik sebelum penambalan kode permanen rilis.
"""

from typing import Dict, Any

class VirtualPatchingService:
    @staticmethod
    def generate_virtual_patches(vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        title = vulnerability.get("title", "")
        cwe_id = vulnerability.get("cwe_id", "")
        endpoint = vulnerability.get("affected_endpoint", "/")
        vuln_id = vulnerability.get("id", 1)

        # Normalize path
        path = endpoint.split(" ")[-1] if " " in endpoint else endpoint
        if not path.startswith("/"):
            path = "/" + path

        # 1. FastAPI / Express Security Middleware Guard
        fastapi_guard = f'''# Virtual Patch Guard for {title} (ID #{vuln_id})
# Add this middleware to your FastAPI app/main.py
from fastapi import Request, HTTPException, status

@app.middleware("http")
async def sitecure_virtual_patch_shield(request: Request, call_next):
    if request.url.path == "{path}":
        query_params = str(request.query_params)
        body = await request.body()
        payload_str = (query_params + body.decode("utf-8", errors="ignore")).lower()
        
        # Block malicious SQL Injection / XSS patterns
        dangerous_patterns = ["union select", "drop table", "--", "or 1=1", "<script>", "javascript:", "eval("]
        for pattern in dangerous_patterns:
            if pattern in payload_str:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="[SiteCure Virtual Shield] Request blocked due to active threat payload."
                )
    return await call_next(request)
'''

        # 2. Nginx ModSecurity SecRule WAF Rule
        modsec_rule = f'''# SiteCure Instant Virtual Patch - ModSecurity WAF Rule
# Add to /etc/nginx/modsec/main.conf
SecRule REQUEST_URI "@contains {path}" \\
    "id:900{vuln_id:03d},\\
    phase:2,\\
    deny,\\
    status:403,\\
    msg:'[SiteCure Shield] Blocked attack payload matching vulnerability #{vuln_id}: {title}',\\
    logdata:'%{{MATCHED_VAR}}',\\
    severity:'CRITICAL',\\
    tag:'CWE/{cwe_id}'"
'''

        # 3. Cloudflare WAF Custom Expression
        cloudflare_expression = f'(http.request.uri.path contains "{path}" and (http.request.uri.query contains "select" or http.request.uri.query contains "script" or http.request.uri.query contains "\'"))'

        return {
            "vulnerability_id": vuln_id,
            "title": title,
            "cwe_id": cwe_id,
            "affected_endpoint": endpoint,
            "virtual_patches": {
                "fastapi_middleware": fastapi_guard,
                "nginx_modsecurity": modsec_rule,
                "cloudflare_waf": cloudflare_expression
            },
            "installation_guide": {
                "fastapi": "Salin fungsi middleware di atas ke file backend main.py untuk perlindungan tingkat aplikasi instant.",
                "nginx": "Masukkan SecRule ke konfigurasi ModSecurity Nginx dan jalankan 'nginx -s reload'.",
                "cloudflare": "Buat Custom WAF Rule di Dashboard Cloudflare -> Security -> WAF dan masukkan ekspresi di atas."
            }
        }
