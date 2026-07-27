import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Float, Boolean
from sqlalchemy.orm import relationship
from app.db.database import Base

class TargetAsset(Base):
    __tablename__ = "target_assets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    target_url = Column(String, nullable=False)
    asset_type = Column(String, default="web") # web, repo, api
    environment = Column(String, default="internal") # internal, dev, staging, prod
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scans = relationship("ScanJob", back_populates="target", cascade="all, delete-orphan")

class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("target_assets.id"), nullable=False)
    status = Column(String, default="pending") # pending, running, completed, failed
    scan_type = Column(String, default="full") # full, dast, sast, ports
    progress_pct = Column(Integer, default=0)
    current_action = Column(String, default="Initialized scan queue")
    started_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    total_findings = Column(Integer, default=0)

    target = relationship("TargetAsset", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String, nullable=False) # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cvss_score = Column(Float, default=0.0)
    cwe_id = Column(String, nullable=True)
    affected_endpoint = Column(String, nullable=False)
    vulnerability_type = Column(String, nullable=False) # DAST, SAST, PORT
    owasp_category = Column(String, nullable=True) # e.g. A03:2021-Injection
    confidence = Column(String, default="HIGH CONFIDENCE") # CONFIRMED (PoC Verified), HIGH CONFIDENCE, POTENTIAL
    poc_evidence = Column(Text, nullable=True) # Proof of Concept exploit evidence
    raw_request = Column(Text, nullable=True)
    raw_response = Column(Text, nullable=True)
    remediation_guide = Column(Text, nullable=True)
    is_remediated = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("ScanJob", back_populates="vulnerabilities")
    patches = relationship("RemediationPatch", back_populates="vulnerability", cascade="all, delete-orphan")

class RemediationPatch(Base):
    __tablename__ = "remediation_patches"

    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False)
    original_code = Column(Text, nullable=True)
    patched_code = Column(Text, nullable=True)
    diff_text = Column(Text, nullable=True)
    ai_explanation = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    vulnerability = relationship("Vulnerability", back_populates="patches")
