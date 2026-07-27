import io
import datetime
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

from app.db.database import get_db
from app.db import models

router = APIRouter(prefix="/reports", tags=["Executive Reports"])

@router.get("/json/{scan_id}")
def get_json_report(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(models.ScanJob).filter(models.ScanJob.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan job not found")

    target = scan.target
    vulnerabilities = db.query(models.Vulnerability).filter(models.Vulnerability.scan_job_id == scan_id).all()

    report = {
        "report_title": f"SiteCure Security Audit Report - {target.name}",
        "generated_at": datetime.datetime.utcnow().isoformat(),
        "target": {
            "name": target.name,
            "url": target.target_url,
            "environment": target.environment,
            "asset_type": target.asset_type
        },
        "scan_summary": {
            "scan_id": scan.id,
            "scan_type": scan.scan_type,
            "status": scan.status,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "total_findings": len(vulnerabilities),
            "severity_counts": {
                "CRITICAL": sum(1 for v in vulnerabilities if v.severity == "CRITICAL"),
                "HIGH": sum(1 for v in vulnerabilities if v.severity == "HIGH"),
                "MEDIUM": sum(1 for v in vulnerabilities if v.severity == "MEDIUM"),
                "LOW": sum(1 for v in vulnerabilities if v.severity == "LOW"),
                "INFO": sum(1 for v in vulnerabilities if v.severity == "INFO")
            }
        },
        "vulnerabilities": [
            {
                "id": v.id,
                "title": v.title,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "cwe_id": v.cwe_id,
                "affected_endpoint": v.affected_endpoint,
                "vulnerability_type": v.vulnerability_type,
                "is_remediated": v.is_remediated,
                "remediation_guide": v.remediation_guide
            } for v in vulnerabilities
        ]
    }
    return report

@router.get("/pdf/{scan_id}")
def generate_pdf_report(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(models.ScanJob).filter(models.ScanJob.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan job not found")

    target = scan.target
    vulnerabilities = db.query(models.Vulnerability).filter(models.Vulnerability.scan_job_id == scan_id).all()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    story = []
    styles = getSampleStyleSheet()

    # Title
    title_style = ParagraphStyle(
        'TitleStyle',
        parent=styles['Heading1'],
        fontSize=20,
        textColor=colors.HexColor('#0F172A'),
        spaceAfter=12
    )
    story.append(Paragraph(f"SiteCure Security Audit Report", title_style))
    story.append(Paragraph(f"<b>Target:</b> {target.name} ({target.target_url}) | <b>Scan ID:</b> #{scan.id}", styles['Normal']))
    story.append(Paragraph(f"<b>Date:</b> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | <b>Environment:</b> {target.environment.upper()}", styles['Normal']))
    story.append(Spacer(1, 16))

    # Table of findings
    table_data = [["Severity", "CVSS", "Vulnerability Title", "Endpoint", "Status"]]
    for v in vulnerabilities:
        status_text = "FIXED" if v.is_remediated else "OPEN"
        table_data.append([v.severity, str(v.cvss_score), v.title[:35], v.affected_endpoint[:30], status_text])

    t = Table(table_data, colWidths=[65, 45, 210, 160, 55])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E293B')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,0), 8),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
        ('FONTSIZE', (0,0), (-1,-1), 9),
    ]))
    story.append(t)
    doc.build(story)

    buffer.seek(0)
    return Response(content=buffer.getvalue(), media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=sitecure_report_scan_{scan_id}.pdf"})

@router.get("/csv/{scan_id}")
def generate_csv_report(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(models.ScanJob).filter(models.ScanJob.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan job not found")

    vulnerabilities = db.query(models.Vulnerability).filter(models.Vulnerability.scan_job_id == scan_id).all()

    output = io.StringIO()
    output.write("id,severity,cvss_score,cwe_id,title,affected_endpoint,vulnerability_type,is_remediated\n")
    for v in vulnerabilities:
        title_clean = v.title.replace('"', '""')
        endpoint_clean = v.affected_endpoint.replace('"', '""')
        output.write(f'{v.id},{v.severity},{v.cvss_score},"{v.cwe_id}","{title_clean}","{endpoint_clean}",{v.vulnerability_type},{v.is_remediated}\n')

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=sitecure_report_scan_{scan_id}.csv"}
    )
