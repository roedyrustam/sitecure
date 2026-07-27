from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional

from app.db.database import get_db
from app.db import models
from app.schemas import schemas
from app.services.ai_remediation import AIRemediationService

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerability Matrix"])

@router.get("/", response_model=List[schemas.VulnerabilityResponse])
def get_vulnerabilities(
    severity: Optional[str] = None,
    is_remediated: Optional[bool] = None,
    db: Session = Depends(get_db)
):
    query = db.query(models.Vulnerability)
    if severity:
        query = query.filter(models.Vulnerability.severity == severity.upper())
    if is_remediated is not None:
        query = query.filter(models.Vulnerability.is_remediated == is_remediated)
    return query.order_by(models.Vulnerability.cvss_score.desc()).all()

@router.get("/{vuln_id}", response_model=schemas.VulnerabilityResponse)
def get_vulnerability(vuln_id: int, db: Session = Depends(get_db)):
    vuln = db.query(models.Vulnerability).filter(models.Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return vuln

@router.post("/generate-patch", response_model=schemas.PatchResponse)
async def generate_remediation_patch(request: schemas.PatchRequest, db: Session = Depends(get_db)):
    vuln = db.query(models.Vulnerability).filter(models.Vulnerability.id == request.vulnerability_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    vuln_dict = {
        "title": vuln.title,
        "description": vuln.description,
        "severity": vuln.severity,
        "cwe_id": vuln.cwe_id,
        "affected_endpoint": vuln.affected_endpoint,
        "remediation_guide": vuln.remediation_guide
    }

    # Check if patch already exists
    existing_patch = db.query(models.RemediationPatch).filter(models.RemediationPatch.vulnerability_id == vuln.id).first()
    if existing_patch:
        return existing_patch

    patch_data = await AIRemediationService.generate_patch(vuln_dict, request.custom_context)

    patch_record = models.RemediationPatch(
        vulnerability_id=vuln.id,
        original_code=patch_data.get("original_code"),
        patched_code=patch_data.get("patched_code"),
        diff_text=patch_data.get("diff_text"),
        ai_explanation=patch_data.get("ai_explanation")
    )
    db.add(patch_record)
    db.commit()
    db.refresh(patch_record)
    return patch_record

@router.post("/virtual-patch/{vuln_id}")
def generate_virtual_patch(vuln_id: int, db: Session = Depends(get_db)):
    vuln = db.query(models.Vulnerability).filter(models.Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    vuln_dict = {
        "id": vuln.id,
        "title": vuln.title,
        "cwe_id": vuln.cwe_id,
        "affected_endpoint": vuln.affected_endpoint
    }
    
    from app.services.virtual_patching import VirtualPatchingService
    return VirtualPatchingService.generate_virtual_patches(vuln_dict)

