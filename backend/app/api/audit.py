import os
import secrets
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.audit import (
    Audit, SystemInfo, HardwareInfo, SoftwareEntry,
    NetworkInfo, SecurityInfo, PeripheralInfo, GeneratedReport,
)
from app.schemas.audit import AuditUploadPayload, AuditResponse, AuditDetailResponse
from app.utils.security import require_admin
from app.services.pdf_generator import generate_audit_pdf
from app.middleware.rate_limiter import limiter

router = APIRouter(prefix="/api/audit", tags=["Audit"])


@router.post("/generate-token")
def generate_verification_token(
    branch_name: str = "",
    branch_code: str = "",
    branch_officer: str = "",
    admin=Depends(require_admin),
    db: Session = Depends(get_db),
):
    token = secrets.token_hex(32)
    audit = Audit(
        verification_token=token,
        status="pending",
        branch_name=branch_name,
        branch_code=branch_code,
        branch_officer=branch_officer,
    )
    db.add(audit)
    db.commit()
    return {"verification_token": token}


@router.get("/download-agent")
def download_agent():
    """Serve the audit agent executable for download."""
    agent_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "agent", "SystemAuditAgent.exe")
    if not os.path.exists(agent_path):
        raise HTTPException(status_code=404, detail="Agent executable not found. Please contact administrator.")
    return FileResponse(
        agent_path,
        media_type="application/octet-stream",
        filename="SystemAuditAgent.exe",
    )


@router.get("/verify/{token}")
def verify_token(token: str, db: Session = Depends(get_db)):
    audit = db.query(Audit).filter(Audit.verification_token == token).first()
    if not audit:
        raise HTTPException(status_code=404, detail="Invalid verification token")
    return {"valid": True, "status": audit.status}


@router.post("/upload")
@limiter.limit("10/minute")
def upload_audit(request: Request, payload: AuditUploadPayload, db: Session = Depends(get_db)):
    audit = db.query(Audit).filter(
        Audit.verification_token == payload.verification_token
    ).first()

    if not audit:
        raise HTTPException(status_code=404, detail="Invalid verification token")

    if audit.status == "completed":
        raise HTTPException(status_code=409, detail="Audit already completed for this token")

    client_ip = request.client.host if request.client else "unknown"
    audit.hostname = payload.system_info.hostname
    audit.username = payload.system_info.logged_in_user
    audit.ip_address = client_ip
    audit.status = "completed"

    si = payload.system_info
    os_updates_data = [u.model_dump() for u in (payload.os_updates or [])]

    audit.system_info = SystemInfo(
        os_name=si.os_name, os_version=si.os_version, os_architecture=si.os_architecture,
        os_build=si.os_build, hostname=si.hostname, cs_name=si.cs_name or si.hostname,
        license_status=si.license_status,
        logged_in_user=si.logged_in_user, timezone=si.timezone,
        installed_browsers=si.installed_browsers, startup_programs=si.startup_programs,
        os_updates=os_updates_data,
    )

    hi = payload.hardware_info
    audit.hardware_info = HardwareInfo(
        cpu_name=hi.cpu_name, cpu_cores=hi.cpu_cores, cpu_threads=hi.cpu_threads,
        cpu_frequency=hi.cpu_frequency, ram_total=hi.ram_total, ram_available=hi.ram_available,
        disk_drives=hi.disk_drives, cd_drives=hi.cd_drives,
        compression_utilities=hi.compression_utilities,
        motherboard=hi.motherboard, bios_serial=hi.bios_serial, machine_uuid=hi.machine_uuid,
    )

    for sw in (payload.software_entries or []):
        audit.software_entries.append(
            SoftwareEntry(name=sw.name, version=sw.version, publisher=sw.publisher)
        )

    ni = payload.network_info
    audit.network_info = NetworkInfo(
        mac_address=ni.mac_address, mac_address_formatted=ni.mac_address_formatted,
        ip_address=ni.ip_address, adapters=ni.adapters,
    )

    sec = payload.security_info
    audit.security_info = SecurityInfo(
        antivirus_name=sec.antivirus_name, antivirus_status=sec.antivirus_status,
        antivirus_products=sec.antivirus_products,
        firewall_status=sec.firewall_status, defender_status=sec.defender_status,
        uac_enabled=sec.uac_enabled,
    )

    pi = payload.peripheral_info
    audit.peripheral_info = PeripheralInfo(
        printers=pi.printers, total_printers=pi.total_printers,
        usb_devices=pi.usb_devices,
    )

    db.commit()
    db.refresh(audit)

    pdf_path = generate_audit_pdf(audit, db)
    report = GeneratedReport(audit_id=audit.id, file_path=pdf_path)
    db.add(report)
    db.commit()

    return {"status": "success", "audit_id": str(audit.id)}


@router.get("/list", response_model=list[AuditResponse])
def list_audits(
    search: str = "",
    status: str = "",
    skip: int = 0,
    limit: int = 50,
    admin=Depends(require_admin),
    db: Session = Depends(get_db),
):
    query = db.query(Audit)
    if search:
        query = query.filter(
            (Audit.hostname.ilike(f"%{search}%")) | (Audit.username.ilike(f"%{search}%"))
        )
    if status:
        query = query.filter(Audit.status == status)
    audits = query.order_by(Audit.submitted_at.desc()).offset(skip).limit(limit).all()
    return [
        AuditResponse(
            id=str(a.id), verification_token=a.verification_token,
            hostname=a.hostname, username=a.username,
            submitted_at=a.submitted_at, ip_address=a.ip_address, status=a.status,
        )
        for a in audits
    ]


@router.get("/{audit_id}")
def get_audit(audit_id: str, admin=Depends(require_admin), db: Session = Depends(get_db)):
    audit = db.query(Audit).filter(Audit.id == audit_id).first()
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")

    def to_dict(obj, exclude=("id", "audit_id")):
        if obj is None:
            return None
        result = {}
        for c in obj.__table__.columns:
            if c.name in exclude:
                continue
            val = getattr(obj, c.name)
            if hasattr(val, 'isoformat'):
                val = val.isoformat()
            elif hasattr(val, 'hex'):
                val = str(val)
            result[c.name] = val
        return result

    return {
        "id": str(audit.id),
        "verification_token": audit.verification_token,
        "hostname": audit.hostname,
        "username": audit.username,
        "submitted_at": audit.submitted_at.isoformat() if audit.submitted_at else None,
        "ip_address": audit.ip_address,
        "status": audit.status,
        "branch_name": audit.branch_name,
        "branch_code": audit.branch_code,
        "branch_officer": audit.branch_officer,
        "system_info": to_dict(audit.system_info),
        "hardware_info": to_dict(audit.hardware_info),
        "software_entries": [to_dict(s) for s in audit.software_entries],
        "network_info": to_dict(audit.network_info),
        "security_info": to_dict(audit.security_info),
        "peripheral_info": to_dict(audit.peripheral_info),
    }
