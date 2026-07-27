import pytest
from app.scanner.attack_chain_analyzer import AttackChainAnalyzer
from app.services.virtual_patching import VirtualPatchingService
from app.services.regression_suite import RegressionSuiteService

def test_attack_chain_analyzer():
    mock_vulns = [
        {
            "id": 1,
            "title": "SQL Injection in User Search",
            "severity": "CRITICAL",
            "cwe_id": "CWE-89",
            "affected_endpoint": "/api/users/search?q="
        },
        {
            "id": 2,
            "title": "AWS API Key Exposed in Code",
            "severity": "HIGH",
            "cwe_id": "CWE-798",
            "affected_endpoint": "File: app/config.py (Line 42)"
        }
    ]
    
    analyzer = AttackChainAnalyzer(mock_vulns)
    result = analyzer.analyze()
    
    assert result["total_vulnerabilities"] == 2
    assert result["attack_chains_count"] > 0
    assert result["attack_chains"][0]["risk"] == "CRITICAL"
    assert "Secrets Exposure" in result["attack_chains"][0]["title"]

def test_virtual_patching_service():
    mock_vuln = {
        "id": 101,
        "title": "Reflected XSS in Comments",
        "cwe_id": "CWE-79",
        "affected_endpoint": "/api/v1/comments"
    }
    
    patch = VirtualPatchingService.generate_virtual_patches(mock_vuln)
    
    assert patch["vulnerability_id"] == 101
    assert "fastapi_middleware" in patch["virtual_patches"]
    assert "SecRule" in patch["virtual_patches"]["nginx_modsecurity"]
    assert "http.request.uri.path" in patch["virtual_patches"]["cloudflare_waf"]

def test_regression_suite_service():
    mock_vulns = [
        {
            "id": 1,
            "title": "SQL Injection",
            "cwe_id": "CWE-89",
            "affected_endpoint": "/api/v1/search"
        }
    ]
    
    suite_code = RegressionSuiteService.generate_pytest_suite("http://localhost:8000", mock_vulns)
    
    assert "def test_regression_vuln_1_cwe_89():" in suite_code
    assert "httpx.get" in suite_code
    assert "assert response.status_code != 500" in suite_code
