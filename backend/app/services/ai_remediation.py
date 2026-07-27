import os
import json
import httpx
from app.config import settings

class AIRemediationService:
    """
    AI Remediation Service: Generates intelligent code patch diffs and step-by-step security fixing instructions.
    """
    @staticmethod
    async def generate_patch(vulnerability: dict, custom_context: str = None) -> dict:
        title = vulnerability.get("title", "")
        desc = vulnerability.get("description", "")
        severity = vulnerability.get("severity", "")
        cwe = vulnerability.get("cwe_id", "")
        endpoint = vulnerability.get("affected_endpoint", "")
        guide = vulnerability.get("remediation_guide", "")

        api_key = settings.GEMINI_API_KEY or os.getenv("GEMINI_API_KEY", "")

        prompt = f"""
Anda adalah Senior Security Engineer & DevSecOps Expert. 
Tolong buatkan rekomendasi penambalan celah keamanan (Security Remediation Patch) untuk temuan berikut:

- **Judul Celah:** {title}
- **Severity:** {severity} (CWE: {cwe})
- **Affected Endpoint:** {endpoint}
- **Deskripsi:** {desc}
- **Petunjuk Awal:** {guide}
- **Konteks Tambahan Kode:** {custom_context or "Tidak ada"}

Berikan respon dalam format JSON murni dengan struktur berikut (tanpa markdown tambahan):
{{
  "original_code": "Snippet kode rentan yang biasanya ditemukan",
  "patched_code": "Snippet kode yang sudah diperbaiki & tertambal dengan aman",
  "diff_text": "- kode_lama\\n+ kode_baru",
  "ai_explanation": "Penjelasan rinci mengapa perubahan ini mengamankan sistem dan bagaimana cara mengujinya."
}}
"""

        if api_key:
            try:
                async with httpx.AsyncClient(timeout=25.0) as client:
                    res = await client.post(
                        f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}",
                        json={"contents": [{"parts": [{"text": prompt}]}]}
                    )
                    if res.status_code == 200:
                        data = res.json()
                        text = data["candidates"][0]["content"]["parts"][0]["text"]
                        # Clean JSON formatting
                        clean_text = text.replace("```json", "").replace("```", "").strip()
                        return json.loads(clean_text)
            except Exception:
                pass

        # Fallback intelligent security patch generator (Rules Engine)
        return AIRemediationService._generate_rule_based_patch(vulnerability)

    @staticmethod
    def _generate_rule_based_patch(vulnerability: dict) -> dict:
        title = vulnerability.get("title", "").lower()
        
        if "hsts" in title:
            return {
                "original_code": "# Nginx Configuration (Unsafe)\nserver {\n    listen 443 ssl;\n    server_name internal.company.local;\n}",
                "patched_code": "# Nginx Configuration (Secured with HSTS)\nserver {\n    listen 443 ssl;\n    server_name internal.company.local;\n    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n}",
                "diff_text": "- server_name internal.company.local;\n+ server_name internal.company.local;\n+ add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;",
                "ai_explanation": "Penambahan header Strict-Transport-Security memastikan peramban (browser) selalu berkomunikasi menggunakan enkripsi HTTPS dan mencegah downgrade attack (SSL Strip)."
            }
        elif "csp" in title or "content security policy" in title:
            return {
                "original_code": "# HTTP Headers (Unsafe - Missing CSP)\nHTTP/1.1 200 OK\nContent-Type: text/html",
                "patched_code": "# HTTP Headers (Secured CSP)\nHTTP/1.1 200 OK\nContent-Type: text/html\nContent-Security-Policy: default-src 'self'; script-src 'self' 'nonce-rAnd0m123'; object-src 'none';",
                "diff_text": "+ Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-rAnd0m123'; object-src 'none';",
                "ai_explanation": "Membatasi sumber eksekusi script hanya dari asal yang sama ('self') secara efektif menetralkan serangan Cross-Site Scripting (XSS)."
            }
        elif "xss" in title:
            return {
                "original_code": "// Unsafe User Greeting in JS/HTML\ndocument.getElementById('greeting').innerHTML = 'Halo ' + username;",
                "patched_code": "// Secured User Greeting using textContent (Safe escaping)\ndocument.getElementById('greeting').textContent = 'Halo ' + username;",
                "diff_text": "- document.getElementById('greeting').innerHTML = 'Halo ' + username;\n+ document.getElementById('greeting').textContent = 'Halo ' + username;",
                "ai_explanation": "Mengganti `.innerHTML` dengan `.textContent` memasukkan teks sebagai karakter murni dan mencegah browser mengeksekusi tag `<script>` berbahaya."
            }
        elif "aws" in title or "stripe" in title or "secret" in title or "credentials" in title:
            return {
                "original_code": "# Unsafe Hardcoded Credentials\nAWS_SECRET_ACCESS_KEY = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\nSTRIPE_API_KEY = \"sk_live_51HzXXXXXXXXXXXXXXXXX\"",
                "patched_code": "# Secured Environment Variable Usage\nimport os\nAWS_SECRET_ACCESS_KEY = os.getenv(\"AWS_SECRET_ACCESS_KEY\")\nSTRIPE_API_KEY = os.getenv(\"STRIPE_API_KEY\")",
                "diff_text": "- AWS_SECRET_ACCESS_KEY = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n+ AWS_SECRET_ACCESS_KEY = os.getenv(\"AWS_SECRET_ACCESS_KEY\")",
                "ai_explanation": "Kunci API rahasia telah dipindahkan dari source code ke Environment Variables (`.env`). Pastikan file `.env` ditambahkan ke `.gitignore`."
            }
        else:
            return {
                "original_code": f"# Potensial kode berisiko pada: {vulnerability.get('affected_endpoint')}\n# Membutuhkan peninjauan sanitasi input & validasi otorisasi.",
                "patched_code": f"# Kode Perbaikan Keamanan\n# Lakukan validasi tipe data strictly dan gunakan prepared statements.",
                "diff_text": "- // Kode Berisiko\n+ // Kode Aman Ter-sanitasi",
                "ai_explanation": "Terapkan prinsip Defense-In-Depth dengan mengesahkan input pengguna, mengaktifkan otentikasi ketat, dan memperbarui library dependensi ke versi terbaru."
            }
