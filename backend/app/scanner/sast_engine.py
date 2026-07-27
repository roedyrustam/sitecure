import os
import re
from typing import List, Dict, Any

class SASTEngine:
    """
    Static Application Security Testing (SAST) Light Engine
    Scans source code files & configurations for leaked API keys, hardcoded credentials, and unsafe coding practices.
    """
    SECRET_PATTERNS = [
        (r'AWS_SECRET_ACCESS_KEY\s*=\s*["\']([A-Za-z0-9/+=]{40})["\']', "Exposed AWS Secret Access Key", "CRITICAL", 9.8, "CWE-798"),
        (r'sk_live_[0-9a-zA-Z]{24}', "Exposed Stripe Live API Key", "CRITICAL", 9.5, "CWE-798"),
        (r'AIzaSy[A-Za-z0-9_-]{33}', "Exposed Google Cloud / Firebase API Key", "HIGH", 8.1, "CWE-798"),
        (r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\s*:\s*(["\'][^"\']+["\'])', "Potential Hardcoded Credentials", "MEDIUM", 6.5, "CWE-259"),
        (r'eval\([^)]+\)', "Use of Dangerous Function `eval()`", "HIGH", 7.8, "CWE-95"),
        (r'exec\([^)]+\)', "Use of Unsafe Function `exec()`", "HIGH", 7.8, "CWE-78"),
        (r'SELECT\s+.*\s+FROM\s+.*WHERE\s+.*\s*\+\s*.*', "Potential Raw SQL Injection String Concatenation", "HIGH", 8.5, "CWE-89")
    ]

    def __init__(self, target_dir_or_url: str):
        self.target_dir = target_dir_or_url
        self.findings = []

    async def run_scan(self, log_callback=None) -> List[Dict[str, Any]]:
        # If target path is a local directory
        if os.path.exists(self.target_dir) and os.path.isdir(self.target_dir):
            if log_callback:
                await log_callback(75, f"Scanning local codebase directory: {self.target_dir}...")
            
            for root, dirs, files in os.walk(self.target_dir):
                # Ignore node_modules, venv, .git, etc.
                dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'venv', '__pycache__', 'dist', 'build']]
                
                for file in files:
                    if file.endswith(('.py', '.js', '.jsx', '.ts', '.tsx', '.env', '.json', '.yml', '.yaml', '.php')):
                        file_path = os.path.join(root, file)
                        self.scan_file(file_path)
        else:
            if log_callback:
                await log_callback(80, "SAST local repository scan skipped (target is a remote URL).")

        return self.findings

    def scan_file(self, file_path: str):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            lines = content.splitlines()
            for line_no, line in enumerate(lines, 1):
                for pattern, title, severity, score, cwe in self.SECRET_PATTERNS:
                    match = re.search(pattern, line)
                    if match:
                        snippet = line.strip()
                        if len(snippet) > 100:
                            snippet = snippet[:97] + "..."

                        self.findings.append({
                            "title": f"{title} in {os.path.basename(file_path)}",
                            "description": f"Ditemukan indikasi pola keamanan berisiko di baris {line_no}: `{snippet}`.",
                            "severity": severity,
                            "cvss_score": score,
                            "cwe_id": cwe,
                            "affected_endpoint": f"{os.path.basename(file_path)}:L{line_no}",
                            "vulnerability_type": "SAST",
                            "remediation_guide": f"Pindahkan rahasia/kunci API dari kode sumber ke environment variables (`.env`) dan pastikan tidak ter-commit ke Git."
                        })
        except Exception:
            pass
