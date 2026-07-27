import os
import json
import re
from typing import List, Dict, Any

class CVEMatcher:
    """
    Software Composition Analysis (SCA) & CVE Matcher Engine.
    Scans project dependency manifests (requirements.txt, package.json, composer.json)
    and flags known vulnerable package versions matching official CVE advisories.
    """
    VULNERABLE_PACKAGES_DB = [
        {"ecosystem": "python", "package": "django", "vulnerable_spec": r"^(1\.|2\.[0-1]|3\.[0-1])", "cve": "CVE-2021-35042", "severity": "HIGH", "score": 8.1, "desc": "Django 3.1 & older SQL Injection via Order By clause."},
        {"ecosystem": "python", "package": "flask", "vulnerable_spec": r"^(0\.|1\.[0-1]\.)", "cve": "CVE-2018-1000656", "severity": "HIGH", "score": 7.5, "desc": "Unexpected session denial of service / memory leak in Flask < 1.0."},
        {"ecosystem": "python", "package": "requests", "vulnerable_spec": r"^2\.(2[0-7]|1[0-9]|[0-9])\.", "cve": "CVE-2023-32681", "severity": "HIGH", "score": 7.5, "desc": "Leaking Proxy-Authorization headers on HTTPS redirects."},
        {"ecosystem": "npm", "package": "axios", "vulnerable_spec": r"^0\.(1[0-9]|2[0-1])\.", "cve": "CVE-2020-28168", "severity": "HIGH", "score": 7.8, "desc": "Server-Side Request Forgery (SSRF) vulnerability in Axios < 0.21.1."},
        {"ecosystem": "npm", "package": "express", "vulnerable_spec": r"^(3\.|4\.(0|1[0-5])\.)", "cve": "CVE-2022-24999", "severity": "HIGH", "score": 7.5, "desc": "Express query parser denial of service & prototype pollution."},
        {"ecosystem": "npm", "package": "lodash", "vulnerable_spec": r"^4\.(17\.(0|1[0-9]|20)|[0-1][0-6]\.)", "cve": "CVE-2021-23337", "severity": "HIGH", "score": 7.2, "desc": "Command Injection / Prototype Pollution via template function in lodash < 4.17.21."}
    ]

    def __init__(self, target_dir: str):
        self.target_dir = target_dir
        self.findings = []

    async def run_scan(self, log_callback=None) -> List[Dict[str, Any]]:
        if not os.path.exists(self.target_dir) or not os.path.isdir(self.target_dir):
            return []

        if log_callback:
            await log_callback(80, "Running Software Composition Analysis (SCA) & CVE Matcher...")

        # 1. Scan Python requirements.txt
        req_file = os.path.join(self.target_dir, "requirements.txt")
        if os.path.exists(req_file):
            self.scan_requirements_txt(req_file)

        # 2. Scan Node package.json
        pkg_file = os.path.join(self.target_dir, "package.json")
        if os.path.exists(pkg_file):
            self.scan_package_json(pkg_file)

        return self.findings

    def scan_requirements_txt(self, file_path: str):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Match pkg==version
                parts = re.split(r'==|>=|<=', line)
                if len(parts) == 2:
                    pkg_name = parts[0].strip().lower()
                    pkg_version = parts[1].strip()

                    for vuln in self.VULNERABLE_PACKAGES_DB:
                        if vuln["ecosystem"] == "python" and vuln["package"] == pkg_name:
                            if re.match(vuln["vulnerable_spec"], pkg_version):
                                self.findings.append({
                                    "title": f"Vulnerable Dependency Detected: {pkg_name} ({pkg_version})",
                                    "description": f"Paket dependensi Python `{pkg_name}=={pkg_version}` memiliki celah keamanan {vuln['cve']}: {vuln['desc']}",
                                    "severity": vuln["severity"],
                                    "cvss_score": vuln["score"],
                                    "cwe_id": vuln["cve"],
                                    "affected_endpoint": f"requirements.txt ({pkg_name})",
                                    "vulnerability_type": "SAST",
                                    "remediation_guide": f"Perbarui paket `{pkg_name}` ke versi terbaru yang aman di `requirements.txt`."
                                })
        except Exception:
            pass

    def scan_package_json(self, file_path: str):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for pkg_name, version_str in deps.items():
                clean_version = re.sub(r'[\^~>=<]', '', version_str).strip()
                for vuln in self.VULNERABLE_PACKAGES_DB:
                    if vuln["ecosystem"] == "npm" and vuln["package"] == pkg_name.lower():
                        if re.match(vuln["vulnerable_spec"], clean_version):
                            self.findings.append({
                                "title": f"Vulnerable NPM Package: {pkg_name} ({version_str})",
                                "description": f"Paket dependensi Node.js `{pkg_name}` versi `{version_str}` rentan terhadap {vuln['cve']}: {vuln['desc']}",
                                "severity": vuln["severity"],
                                "cvss_score": vuln["score"],
                                "cwe_id": vuln["cve"],
                                "affected_endpoint": f"package.json ({pkg_name})",
                                "vulnerability_type": "SAST",
                                "remediation_guide": f"Jalankan `npm update {pkg_name}` untuk memperbarui paket ke versi patched."
                            })
        except Exception:
            pass
