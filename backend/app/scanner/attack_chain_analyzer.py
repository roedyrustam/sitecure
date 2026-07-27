"""
Attack Chain & DAST-SAST Hybrid Correlation Analyzer.
Mengkorelasikan temuan DAST (endpoint HTTP) dan SAST (source code patterns) 
serta mendeteksi rantai eksploitasi (Exploit Attack Chains).
"""

from typing import List, Dict, Any

class AttackChainAnalyzer:
    def __init__(self, vulnerabilities: List[Dict[str, Any]]):
        self.vulnerabilities = vulnerabilities

    def analyze(self) -> Dict[str, Any]:
        """
        Menganalisis daftar kerentanan dan menghasilkan:
        1. Hybrid DAST-SAST Correlations
        2. Threat Attack Chains (Rantai Serangan)
        3. Composite Risk Level & Vector Map
        """
        dast_items = [v for v in self.vulnerabilities if v.get("cwe_id", "").startswith("CWE-") or "DAST" in str(v.get("affected_endpoint", ""))]
        sast_items = [v for v in self.vulnerabilities if "File:" in str(v.get("affected_endpoint", ""))]

        correlations = []
        # Match DAST endpoints with SAST code patterns
        for dast in dast_items:
            endpoint = str(dast.get("affected_endpoint", ""))
            matched_sast = []
            for sast in sast_items:
                sast_file = str(sast.get("affected_endpoint", ""))
                # Corelate route or parameter similarity
                if any(part in sast_file.lower() for part in ["api", "route", "controller", "main", "db"]) or dast.get("cwe_id") == sast.get("cwe_id"):
                    matched_sast.append(sast)
            
            if matched_sast:
                correlations.append({
                    "dast_vulnerability_id": dast.get("id"),
                    "dast_title": dast.get("title"),
                    "dast_endpoint": endpoint,
                    "severity": dast.get("severity"),
                    "matched_sast_count": len(matched_sast),
                    "sast_matches": [
                        {
                            "id": s.get("id"),
                            "title": s.get("title"),
                            "file": s.get("affected_endpoint")
                        } for s in matched_sast
                    ]
                })

        # Identify Attack Chains
        chains = []
        severities = [v.get("severity") for v in self.vulnerabilities]
        
        has_sqli = any("SQL Injection" in v.get("title", "") for v in self.vulnerabilities)
        has_xss = any("XSS" in v.get("title", "") or "Cross-Site" in v.get("title", "") for v in self.vulnerabilities)
        has_secrets = any("Secret" in v.get("title", "") or "API Key" in v.get("title", "") for v in self.vulnerabilities)
        has_open_ports = any("Port" in v.get("title", "") or "Service" in v.get("title", "") for v in self.vulnerabilities)
        has_headers = any("Header" in v.get("title", "") for v in self.vulnerabilities)

        # Chain 1: Secrets Leak -> Database/API Compromise
        if has_secrets and (has_sqli or has_open_ports):
            chains.append({
                "id": "chain-secrets-db",
                "title": "Secrets Exposure to Full Database Takeover Chain",
                "risk": "CRITICAL",
                "description": "Exposed hardcoded credentials/API keys in source code combined with SQL Injection or open database ports allow unauthenticated administrative access.",
                "nodes": [
                    {"step": 1, "type": "Reconnaissance", "label": "Leaked API Key / Credential in Source Code"},
                    {"step": 2, "type": "Exploitation", "label": "SQL Injection Fuzzing on Endpoint"},
                    {"step": 3, "type": "Impact", "label": "Full Remote Database & System Compromise"}
                ]
            })

        # Chain 2: Security Header Misconfig -> XSS & Session Hijacking
        if has_headers and has_xss:
            chains.append({
                "id": "chain-header-xss",
                "title": "Missing Security Headers to Stored XSS Session Theft Chain",
                "risk": "HIGH",
                "description": "Missing Content-Security-Policy (CSP) and X-Frame-Options allow reflected/stored XSS payloads to execute scripts and exfiltrate user session cookies.",
                "nodes": [
                    {"step": 1, "type": "Audit", "label": "Missing CSP & Anti-Clickjacking Headers"},
                    {"step": 2, "type": "Injection", "label": "Reflected XSS Execution on Unfiltered Parameter"},
                    {"step": 3, "type": "Exfiltration", "label": "Session Cookie & JWT Token Theft"}
                ]
            })

        # Default Chain if any vulnerabilities exist
        if not chains and self.vulnerabilities:
            top_vuln = self.vulnerabilities[0]
            chains.append({
                "id": "chain-generic-recon",
                "title": f"Target Endpoint Exposure ({top_vuln.get('severity', 'MEDIUM')} Risk Chain)",
                "risk": top_vuln.get("severity", "MEDIUM"),
                "description": f"Target vulnerability in {top_vuln.get('affected_endpoint')} can be leveraged by attackers for initial entry.",
                "nodes": [
                    {"step": 1, "type": "Recon", "label": "Endpoint Probing"},
                    {"step": 2, "type": "Fuzzing", "label": top_vuln.get("title")},
                    {"step": 3, "type": "Access", "label": "Unauthorized Feature Access"}
                ]
            })

        return {
            "total_vulnerabilities": len(self.vulnerabilities),
            "correlated_pairs_count": len(correlations),
            "correlations": correlations,
            "attack_chains_count": len(chains),
            "attack_chains": chains
        }
