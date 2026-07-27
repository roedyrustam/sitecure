import pytest
from app.scanner.supabase_auditor import SupabaseAuditor

@pytest.mark.anyio
async def test_supabase_auditor():
    auditor = SupabaseAuditor("https://example.supabase.co")
    findings = await auditor.run_supabase_audit()
    assert isinstance(findings, list)
