import pytest
from app.scanner.origin_ip_finder import OriginIPFinder
from app.scanner.waf_evasion_auditor import WAFEvasionAuditor

@pytest.mark.anyio
async def test_origin_ip_finder():
    finder = OriginIPFinder("https://example.com")
    findings = await finder.scan_origin_exposure()
    assert isinstance(findings, list)

@pytest.mark.anyio
async def test_waf_evasion_auditor():
    auditor = WAFEvasionAuditor("https://example.com")
    findings = await auditor.audit_waf_resilience()
    assert isinstance(findings, list)
