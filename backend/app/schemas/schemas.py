import datetime
from typing import Optional, List
from pydantic import BaseModel, HttpUrl

# Target Asset Schemas
class TargetAssetBase(BaseModel):
    name: str
    target_url: str
    asset_type: Optional[str] = "web"
    environment: Optional[str] = "internal"
    description: Optional[str] = None

class TargetAssetCreate(TargetAssetBase):
    pass

class TargetAssetResponse(TargetAssetBase):
    id: int
    created_at: datetime.datetime

    class Config:
        from_attributes = True

# Scan Job Schemas
class ScanJobCreate(BaseModel):
    target_id: int
    scan_type: Optional[str] = "full"

class ScanJobResponse(BaseModel):
    id: int
    target_id: int
    status: str
    scan_type: str
    progress_pct: int
    current_action: str
    started_at: datetime.datetime
    completed_at: Optional[datetime.datetime] = None
    total_findings: int

    class Config:
        from_attributes = True

# Vulnerability Schemas
class VulnerabilityResponse(BaseModel):
    id: int
    scan_job_id: int
    title: str
    description: str
    severity: str
    cvss_score: float
    cwe_id: Optional[str] = None
    affected_endpoint: str
    vulnerability_type: str
    owasp_category: Optional[str] = None
    confidence: Optional[str] = "HIGH CONFIDENCE"
    poc_evidence: Optional[str] = None
    raw_request: Optional[str] = None
    raw_response: Optional[str] = None
    remediation_guide: Optional[str] = None
    is_remediated: bool
    created_at: datetime.datetime

    class Config:
        from_attributes = True

# Remediation Patch Schemas
class PatchRequest(BaseModel):
    vulnerability_id: int
    custom_context: Optional[str] = None

class PatchResponse(BaseModel):
    id: int
    vulnerability_id: int
    original_code: Optional[str]
    patched_code: Optional[str]
    diff_text: Optional[str]
    ai_explanation: Optional[str]
    created_at: datetime.datetime

    class Config:
        from_attributes = True
