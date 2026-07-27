import asyncio
import json
import datetime
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from typing import List

from app.db.database import get_db, SessionLocal
from app.db import models
from app.schemas import schemas
from app.scanner.dast_engine import DASTEngine
from app.scanner.sast_engine import SASTEngine
from app.scanner.port_scanner import PortScanner
from app.scanner.web_crawler import WebCrawler
from app.scanner.cve_matcher import CVEMatcher

router = APIRouter(prefix="/scans", tags=["Security Scans"])

scan_log_queues = {}

async def run_scan_pipeline(scan_job_id: int):
    """
    Real-World Background Task Pipeline executing Web Crawler, DAST Fuzzer, SAST Engine, Port Scanner, & CVE Matcher.
    """
    db = SessionLocal()
    scan_job = db.query(models.ScanJob).filter(models.ScanJob.id == scan_job_id).first()
    if not scan_job:
        db.close()
        return

    target = scan_job.target
    scan_job.status = "running"
    scan_job.started_at = datetime.datetime.utcnow()
    db.commit()

    async def log_progress(pct: int, message: str):
        scan_job.progress_pct = pct
        scan_job.current_action = message
        db.commit()
        
        # Stream to SSE subscribers
        if scan_job_id in scan_log_queues:
            for q in scan_log_queues[scan_job_id]:
                await q.put(json.dumps({"progress": pct, "message": message, "time": datetime.datetime.now().strftime("%H:%M:%S")}))

    all_findings = []

    try:
        await log_progress(2, f"Initiating Deep Security Audit for target: {target.name} ({target.target_url})")

        # 1. Real Web Crawler & Form Discovery
        crawled_urls = [target.target_url]
        if scan_job.scan_type in ["full", "dast"] and target.target_url.startswith(("http://", "https://")):
            crawler = WebCrawler(target.target_url, max_depth=2, max_pages=15)
            crawl_res = await crawler.crawl(log_progress)
            crawled_urls = crawl_res.get("endpoints", [target.target_url])
            await log_progress(25, f"Discovered {len(crawled_urls)} target endpoints & routes for security fuzzing.")

        # 2. DAST Engine Fuzzing on Crawled Endpoints
        if scan_job.scan_type in ["full", "dast"]:
            await log_progress(30, "Executing DAST Fuzzing & Security Protocol Inspector...")
            for idx, url in enumerate(crawled_urls[:5]):
                dast = DASTEngine(url)
                dast_findings = await dast.run_all_checks(log_progress)
                all_findings.extend(dast_findings)

        # 3. SAST Execution
        if scan_job.scan_type in ["full", "sast"]:
            sast = SASTEngine(target.target_url)
            sast_findings = await sast.run_scan(log_progress)
            all_findings.extend(sast_findings)

            # CVE & Dependency Matcher
            cve_matcher = CVEMatcher(target.target_url)
            cve_findings = await cve_matcher.run_scan(log_progress)
            all_findings.extend(cve_findings)

        # 4. Port Scanner Execution
        if scan_job.scan_type in ["full", "ports"]:
            port_scan = PortScanner(target.target_url)
            port_findings = await port_scan.run_scan(log_progress)
            all_findings.extend(port_findings)

        # Deduplicate findings by title & endpoint
        seen = set()
        unique_findings = []
        for f in all_findings:
            key = (f["title"], f["affected_endpoint"])
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        # 5. Execute Automated PenTest & PoC Exploitation Verification
        await log_progress(85, "Executing PenTest PoC Verification & Proof Generation...")
        from app.scanner.pentest_verifier import PenTestVerifier
        verifier = PenTestVerifier()
        
        verified_findings = []
        for finding in unique_findings:
            v_finding = await verifier.verify_finding(finding)
            verified_findings.append(v_finding)

        # Persist Findings into Database
        await log_progress(95, f"Storing {len(verified_findings)} verified vulnerabilities with PoC proof evidence...")
        for finding in verified_findings:
            vuln = models.Vulnerability(
                scan_job_id=scan_job.id,
                title=finding["title"],
                description=finding["description"],
                severity=finding["severity"],
                cvss_score=finding["cvss_score"],
                cwe_id=finding.get("cwe_id"),
                affected_endpoint=finding["affected_endpoint"],
                vulnerability_type=finding["vulnerability_type"],
                owasp_category=finding.get("owasp_category"),
                confidence=finding.get("confidence", "HIGH CONFIDENCE"),
                poc_evidence=finding.get("poc_evidence"),
                raw_request=finding.get("raw_request"),
                raw_response=finding.get("raw_response"),
                remediation_guide=finding.get("remediation_guide")
            )
            db.add(vuln)

        scan_job.status = "completed"
        scan_job.progress_pct = 100
        scan_job.completed_at = datetime.datetime.utcnow()
        scan_job.total_findings = len(verified_findings)
        scan_job.current_action = f"Scan finished successfully. Found {len(verified_findings)} unique vulnerabilities."
        db.commit()

        # Send Webhook Alert Notification if configured
        from app.services.webhooks import WebhookNotifier
        webhook_url = getattr(target, "webhook_url", None)
        if webhook_url:
            await WebhookNotifier.send_vulnerability_alert(webhook_url, target.name, target.target_url, verified_findings)

        await log_progress(100, f"Audit Complete! Total {len(verified_findings)} vulnerabilities identified.")

    except Exception as e:
        scan_job.status = "failed"
        scan_job.current_action = f"Error during scan: {str(e)}"
        db.commit()
        await log_progress(100, f"Scan Failed: {str(e)}")
    finally:
        db.close()

@router.post("/", response_model=schemas.ScanJobResponse)
def trigger_scan(scan_in: schemas.ScanJobCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    target = db.query(models.TargetAsset).filter(models.TargetAsset.id == scan_in.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target asset not found")

    scan_job = models.ScanJob(
        target_id=target.id,
        scan_type=scan_in.scan_type,
        status="pending",
        progress_pct=0,
        current_action="Queued scan job"
    )
    db.add(scan_job)
    db.commit()
    db.refresh(scan_job)

    background_tasks.add_task(run_scan_pipeline, scan_job.id)
    return scan_job

@router.get("/", response_model=List[schemas.ScanJobResponse])
def get_scans(db: Session = Depends(get_db)):
    return db.query(models.ScanJob).order_by(models.ScanJob.id.desc()).all()

@router.get("/{scan_id}", response_model=schemas.ScanJobResponse)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(models.ScanJob).filter(models.ScanJob.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return scan

@router.get("/{scan_id}/stream")
async def stream_scan_logs(scan_id: int):
    queue = asyncio.Queue()
    if scan_id not in scan_log_queues:
        scan_log_queues[scan_id] = []
    scan_log_queues[scan_id].append(queue)

    async def event_generator():
        try:
            while True:
                data = await queue.get()
                yield f"data: {data}\n\n"
        except asyncio.CancelledError:
            scan_log_queues[scan_id].remove(queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@router.post("/rescan-vulnerability/{vulnerability_id}")
async def rescan_vulnerability(vulnerability_id: int, db: Session = Depends(get_db)):
    vuln = db.query(models.Vulnerability).filter(models.Vulnerability.id == vulnerability_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    target_url = vuln.scan.target.target_url
    dast = DASTEngine(target_url)
    findings = await dast.run_all_checks()

    still_present = any(f["title"].lower() == vuln.title.lower() for f in findings)
    
    if not still_present:
        vuln.is_remediated = True
        db.commit()
        return {"status": "remediated", "message": "Rescan verification PASSED! Vulnerability is fixed."}
    else:
        vuln.is_remediated = False
        db.commit()
        return {"status": "still_vulnerable", "message": "Rescan verification FAILED. Vulnerability is still active."}

@router.get("/{scan_id}/attack-chain")
def get_attack_chain(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(models.ScanJob).filter(models.ScanJob.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan job not found")

    vulns = [
        {
            "id": v.id,
            "title": v.title,
            "severity": v.severity,
            "cwe_id": v.cwe_id,
            "affected_endpoint": v.affected_endpoint
        }
        for v in scan.vulnerabilities
    ]

    from app.scanner.attack_chain_analyzer import AttackChainAnalyzer
    analyzer = AttackChainAnalyzer(vulns)
    return analyzer.analyze()

@router.get("/{scan_id}/regression-suite")
def get_regression_suite(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(models.ScanJob).filter(models.ScanJob.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan job not found")

    vulns = [
        {
            "id": v.id,
            "title": v.title,
            "cwe_id": v.cwe_id,
            "affected_endpoint": v.affected_endpoint
        }
        for v in scan.vulnerabilities
    ]

    from app.services.regression_suite import RegressionSuiteService
    suite_code = RegressionSuiteService.generate_pytest_suite(scan.target.target_url, vulns)
    return StreamingResponse(
        iter([suite_code]),
        media_type="text/x-python",
        headers={"Content-Disposition": f"attachment; filename=test_security_regression_scan_{scan_id}.py"}
    )

