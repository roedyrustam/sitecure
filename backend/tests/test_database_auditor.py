import pytest
from app.scanner.database_auditor import DatabaseAuditor

@pytest.mark.anyio
async def test_database_auditor():
    auditor = DatabaseAuditor("http://127.0.0.1")
    findings = await auditor.run_database_audit()
    assert isinstance(findings, list)
