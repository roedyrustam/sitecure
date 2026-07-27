"""
Multi-Standard Security Compliance & Governance Engine.
Memetakan temuan kerentanan ke standar industri enterprise:
1. OWASP Top 10 2021
2. PCI-DSS v4.0 (Payment Card Industry Data Security Standard)
3. ISO/IEC 27001:2022 (Annex A Controls)
"""

from typing import List, Dict, Any

class ComplianceExporter:
    @staticmethod
    def map_compliance(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        owasp_map = {}
        pci_dss_violations = []
        iso_27001_violations = []

        total = len(vulnerabilities)
        critical_high = sum(1 for v in vulnerabilities if v.get("severity") in ["CRITICAL", "HIGH"])

        # Mapping rules
        for v in vulnerabilities:
            title = v.get("title", "")
            severity = v.get("severity", "LOW")
            cwe = v.get("cwe_id", "")
            owasp = v.get("owasp_category", "A05:2021-Security Misconfiguration")

            # Group OWASP
            owasp_map[owasp] = owasp_map.get(owasp, 0) + 1

            # Map PCI-DSS v4.0 (Req 6: Software Security)
            if any(k in title.lower() for k in ["sql", "injection", "xss", "cors", "secret", "origin"]):
                pci_dss_violations.append({
                    "requirement": "PCI-DSS v4.0 Requirement 6.2.4",
                    "title": f"Software Security Vulnerability: {title}",
                    "severity": severity,
                    "cwe": cwe
                })

            # Map ISO/IEC 27001:2022
            if "secret" in title.lower() or "key" in title.lower() or "port" in title.lower():
                iso_27001_violations.append({
                    "control": "ISO 27001:2022 Control A.8.8 (Management of Technical Vulnerabilities)",
                    "title": title,
                    "severity": severity
                })
            else:
                iso_27001_violations.append({
                    "control": "ISO 27001:2022 Control A.8.28 (Secure Coding)",
                    "title": title,
                    "severity": severity
                })

        # Calculate Compliance Scores
        pci_pass = critical_high == 0
        iso_pass = critical_high == 0

        pci_score = 100 if pci_pass else max(0, 100 - (critical_high * 20))
        iso_score = 100 if iso_pass else max(0, 100 - (critical_high * 15))

        return {
            "summary": {
                "total_vulnerabilities": total,
                "critical_high_count": critical_high,
                "pci_dss_compliance_status": "COMPLIANT (PASS)" if pci_pass else "NON-COMPLIANT (FAIL)",
                "pci_dss_score": f"{pci_score}%",
                "iso_27001_compliance_status": "COMPLIANT (PASS)" if iso_pass else "ACTION REQUIRED",
                "iso_27001_score": f"{iso_score}%"
            },
            "standards": {
                "owasp_top_10_distribution": owasp_map,
                "pci_dss_violations_count": len(pci_dss_violations),
                "pci_dss_violations": pci_dss_violations,
                "iso_27001_violations_count": len(iso_27001_violations),
                "iso_27001_violations": iso_27001_violations
            }
        }
