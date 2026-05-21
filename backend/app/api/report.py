import os
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.audit import GeneratedReport
from app.utils.security import require_admin

router = APIRouter(prefix="/api/report", tags=["Reports"])


@router.get("/{audit_id}")
def download_report(audit_id: str, admin=Depends(require_admin), db: Session = Depends(get_db)):
    report = (
        db.query(GeneratedReport)
        .filter(GeneratedReport.audit_id == audit_id)
        .order_by(GeneratedReport.generated_at.desc())
        .first()
    )
    if not report or not os.path.exists(report.file_path):
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(
        report.file_path,
        media_type="application/pdf",
        filename=f"audit_report_{audit_id[:8]}.pdf",
    )
