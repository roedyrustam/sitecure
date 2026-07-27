import pytest
from app.scanner.subdomain_takeover import SubdomainTakeoverScanner
from app.services.compliance_exporter import ComplianceExporter

@pytest.mark.anyio
async def test_subdomain_takeover_scanner():
    scanner = SubdomainTakeoverScanner("https://example.com")
    findings = await scanner.scan_all()
    assert isinstance(findings, list)

def test_compliance_exporter():
    mock_vulns = [
        {
            "id": 1,
            "title": "SQL Injection in User Search",
            "severity": "CRITICAL",
            "cwe_id": "CWE-89",
            "owasp_category": "A03:2021-Injection"
        }
    ]
    report = ComplianceExporter.map_compliance(mock_vulns)
    assert "pci_dss_score" in report["summary"]
    assert "iso_27001_score" in report["summary"]
    assert len(report["standards"]["pci_dss_violations"]) > 0
