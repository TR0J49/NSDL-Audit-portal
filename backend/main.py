# ==============================================================================
#                 NSDL WORKSTATION COMPLIANCE AUDIT BACKEND (FASTAPI)
# ==============================================================================
# Version: 2.0.0

from fastapi import Cookie, FastAPI, Query, Request, HTTPException
from fastapi.responses import FileResponse, Response, PlainTextResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator
from typing import Union, List, Optional
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import letter
import os
import json
import xml.etree.ElementTree as ET
from datetime import datetime
import logging
import re
import secrets
import hashlib
import threading
from pathlib import Path
from urllib.parse import quote

# Resolve project root (one level up from backend/)
BASE_DIR = Path(__file__).resolve().parent.parent


def env_list(name: str, default: str = "") -> List[str]:
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


def env_path(name: str, default: str) -> Path:
    value = os.getenv(name, default)
    return Path(value).expanduser().resolve()


APP_VERSION = os.getenv("APP_VERSION", "2.0.0")
APP_NAME = os.getenv("APP_NAME", "NSDL Workstation Compliance Portal")
ALLOWED_ORIGINS = env_list("ALLOWED_ORIGINS")
LOGS_DIR = env_path("LOGS_DIR", str(BASE_DIR / "logs"))
USER_INFO_DIR = env_path("USER_INFO_DIR", str(BASE_DIR / "user_info"))
SESSION_STORE_PATH = env_path("SESSION_STORE_PATH", str(USER_INFO_DIR / "sessions.json"))
DEFAULT_BRANCH_NAME = os.getenv("DEFAULT_BRANCH_NAME", "")
DEFAULT_BRANCH_CODE = os.getenv("DEFAULT_BRANCH_CODE", "")
DEFAULT_OFFICER_NAME = os.getenv("DEFAULT_OFFICER_NAME", "")

# Set up logging
LOGS_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOGS_DIR / "audit_backend.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("AuditBackend")

app = FastAPI(title=APP_NAME)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

USER_INFO_DIR.mkdir(parents=True, exist_ok=True)

# Persistent session status tracking. Raw tokens are never written to disk.
sessions = {}
session_lock = threading.Lock()


def hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_sessions() -> None:
    global sessions
    if not SESSION_STORE_PATH.exists():
        sessions = {}
        return
    try:
        sessions = json.loads(SESSION_STORE_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        logger.error(f"Failed to load session store: {e}")
        sessions = {}


def save_sessions() -> None:
    try:
        SESSION_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
        SESSION_STORE_PATH.write_text(json.dumps(sessions, indent=2), encoding="utf-8")
    except Exception as e:
        logger.error(f"Failed to persist session store: {e}")


def validate_client_id(client_id: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,80}", client_id or ""):
        raise HTTPException(status_code=400, detail="Invalid client session ID.")
    return client_id


def verify_audit_token(client_id: str, audit_token: str) -> dict:
    session = sessions.get(client_id)
    if not session:
        load_sessions()
        session = sessions.get(client_id)
    if not session or session.get("audit_token_hash") != hash_secret(audit_token or ""):
        raise HTTPException(status_code=403, detail="Invalid audit session token.")
    return session


def verify_portal_token(client_id: str, portal_token: Optional[str]) -> dict:
    session = sessions.get(client_id)
    if not session:
        load_sessions()
        session = sessions.get(client_id)
    if not session:
        raise HTTPException(status_code=404, detail="Audit session has not been found.")
    if session.get("portal_token_hash") != hash_secret(portal_token or ""):
        raise HTTPException(status_code=403, detail="Invalid portal session token.")
    return session


def sanitize_filename_part(value: str, fallback: str = "branch") -> str:
    clean = re.sub(r"[^A-Za-z0-9 ._-]+", "_", value or "").strip(" ._-")
    clean = re.sub(r"\s+", " ", clean)
    return clean[:80] or fallback


load_sessions()

# ------------------------------------------------------------------------------
# 1. PYDANTIC SCHEMA VALIDATION
# ------------------------------------------------------------------------------
class HotfixDetail(BaseModel):
    caption: str = ""
    cs_name: str = ""
    description: str = ""
    fix_id: str = ""
    installed_on: str = ""

class PrinterDetail(BaseModel):
    name: str = ""
    system_name: str = ""
    enable_bidi: str = "False"
    extended_printer_status: str = "0"
    port_name: str = ""

class AuditData(BaseModel):
    computer_name: str
    os_name: str
    os_version: str
    architecture: str
    license_status: str
    antivirus: Union[str, List[str]]
    mac_address: str
    drive_name: str
    printers: Union[List[PrinterDetail], List[str], str] = []
    hotfixes: Union[List[HotfixDetail], List[str], str] = []

    @validator('antivirus', pre=True, allow_reuse=True)
    def coerce_antivirus(cls, v):
        if v is None:
            return []
        if isinstance(v, list):
            return v
        return [v]

    @validator('printers', pre=True, allow_reuse=True)
    def coerce_printers(cls, v):
        if v is None:
            return []
        if isinstance(v, list):
            return v
        return [v]

    @validator('hotfixes', pre=True, allow_reuse=True)
    def coerce_hotfixes(cls, v):
        if v is None:
            return []
        if isinstance(v, list):
            return v
        return [v]

# ------------------------------------------------------------------------------
# 2. CORE SYSTEM ROUTING & SILENT VBS LAUNCHERS
# ------------------------------------------------------------------------------
@app.get("/")
def home():
    """Serves the premium audit portal UI."""
    return FileResponse(BASE_DIR / "frontend" / "index.html")

@app.get("/check-status")
def check_status(client_id: str = Query(...), portal_token: Optional[str] = Cookie(None)):
    """Allows frontend portal to poll active audit status in real-time."""
    cid = validate_client_id(client_id)
    session = verify_portal_token(cid, portal_token)
    return JSONResponse(content={
        "status": session.get("status", "pending"),
        "branch_name": session.get("branch_name", ""),
        "branch_code": session.get("branch_code", ""),
        "officer_name": session.get("officer_name", ""),
        "error": session.get("error")
    })

@app.get("/download-script", response_class=PlainTextResponse)
def download_script(request: Request, client_id: str = Query(...), audit_token: str = Query(...)):
    """Dynamically serves custom powershell script baked with actual server host url."""
    cid = validate_client_id(client_id)
    verify_audit_token(cid, audit_token)
    base_url = str(request.base_url).rstrip('/')
    try:
        with open(BASE_DIR / "scripts" / "audit.ps1", "r", encoding="utf-8") as f:
            script_content = f.read()
        dynamic_script = script_content.replace("API_BASE_URL_PLACEHOLDER", base_url)
        dynamic_script = dynamic_script.replace("CLIENT_ID_PLACEHOLDER", cid)
        dynamic_script = dynamic_script.replace("AUDIT_TOKEN_PLACEHOLDER", audit_token)
        return PlainTextResponse(content=dynamic_script)
    except Exception as e:
        logger.error(f"Failed to load scripts/audit.ps1: {e}")
        raise HTTPException(status_code=500, detail="PowerShell script source unavailable.")

@app.get("/download-vbs")
def download_vbs(
    request: Request,
    client_id: str = Query(...),
    branch_name: Optional[str] = Query(None),
    branch_code: Optional[str] = Query(None),
    officer_name: Optional[str] = Query(None)
):
    """Generates a .bat launcher that runs the PowerShell audit scan hidden in the background.
    Works on all Windows versions including Win 11 24H2+ where VBScript is deprecated."""
    cid = validate_client_id(client_id)
    base_url = str(request.base_url).rstrip('/')
    audit_token = secrets.token_urlsafe(32)
    portal_token = secrets.token_urlsafe(32)
    resolved_branch_name = (branch_name or DEFAULT_BRANCH_NAME).strip()
    resolved_branch_code = (branch_code or DEFAULT_BRANCH_CODE).strip()
    resolved_officer_name = (officer_name or DEFAULT_OFFICER_NAME).strip()

    with session_lock:
        sessions[cid] = {
            "status": "pending",
            "branch_name": resolved_branch_name,
            "branch_code": resolved_branch_code,
            "officer_name": resolved_officer_name,
            "audit_token_hash": hash_secret(audit_token),
            "portal_token_hash": hash_secret(portal_token),
            "pdf_path": None,
            "xml_path": None,
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "completed_at": None
        }
        save_sessions()

    script_url = f"{base_url}/download-script?client_id={quote(cid)}&audit_token={quote(audit_token)}"
    bat_content = f"""@echo off
start /min powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Invoke-RestMethod -Uri '{script_url}' | Invoke-Expression"
exit
"""
    headers = {
        "Content-Disposition": f"attachment; filename=verify_system_{cid}.bat",
        "Cache-Control": "no-store"
    }
    response = Response(content=bat_content, media_type="application/octet-stream", headers=headers)
    response.set_cookie(
        key="portal_token",
        value=portal_token,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="strict",
        max_age=3600
    )
    return response

# ------------------------------------------------------------------------------
# 3. PDF PAGE DECORATIONS (NSDL Style Page Border & Centered Footer)
# ------------------------------------------------------------------------------
def draw_page_decorations(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#A80000"))
    canvas.setLineWidth(1.5)
    canvas.rect(36, 36, doc.pagesize[0] - 72, doc.pagesize[1] - 72)

    canvas.setFont('Helvetica-Bold', 8)
    canvas.setFillColor(colors.HexColor("#A80000"))
    canvas.drawCentredString(doc.pagesize[0] / 2.0, 20, "INSPECTION REPORT BY NSDL E-GOVERNANCE")
    canvas.restoreState()

# ------------------------------------------------------------------------------
# Helper: build a standard 2-col table
# ------------------------------------------------------------------------------
def build_table(rows, col_widths=[180, 324]):
    t = Table(rows, colWidths=col_widths)
    t.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
    ]))
    return t

# ------------------------------------------------------------------------------
# 4. COMPLIANCE INGESTION AND EXPORTS (PDF & XML GENERATOR)
# ------------------------------------------------------------------------------
@app.post("/upload-audit")
def upload_audit(data: AuditData, client_id: str = Query(...), audit_token: str = Query(...)):
    cid = validate_client_id(client_id)
    verify_audit_token(cid, audit_token)
    logger.info(f"Uploading compliance audit for client session ID: {cid}")

    timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")

    # Load session branch info or fall back to defaults
    session_meta = sessions.get(cid, {})
    branch_name = session_meta.get("branch_name", DEFAULT_BRANCH_NAME)
    branch_code = session_meta.get("branch_code", DEFAULT_BRANCH_CODE)
    officer_name = session_meta.get("officer_name", DEFAULT_OFFICER_NAME)

    safe_branch_name = sanitize_filename_part(branch_name)
    file_prefix = USER_INFO_DIR / f"{safe_branch_name}_{timestamp}"
    json_path = Path(f"{file_prefix}.json")
    pdf_path = Path(f"{file_prefix}.pdf")
    xml_path = Path(f"{file_prefix}.xml")
    av_str = ", ".join(data.antivirus) if isinstance(data.antivirus, list) else data.antivirus
    generation_errors = []

    # Save JSON locally
    try:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data.dict(), f, indent=4)
    except Exception as e:
        logger.error(f"Failed to save JSON: {e}")
        generation_errors.append("JSON export failed")

    # Build NSDL Inspection Report PDF (matching sample format)
    try:
        doc = SimpleDocTemplate(str(pdf_path), pagesize=letter, leftMargin=54, rightMargin=54, topMargin=54, bottomMargin=54)

        title_style = ParagraphStyle('TitleStyle', fontName='Helvetica-Bold', fontSize=14, leading=16, alignment=1, spaceAfter=20)
        section_style = ParagraphStyle('SectionStyle', fontName='Helvetica-Bold', fontSize=10, leading=12, spaceBefore=14, spaceAfter=6)
        cell_b = ParagraphStyle('CellBold', fontName='Helvetica-Bold', fontSize=8, leading=10)
        cell_n = ParagraphStyle('CellNormal', fontName='Helvetica', fontSize=8, leading=10)

        elements = []

        # Title
        elements.append(Paragraph("Inspection Report", title_style))
        elements.append(Spacer(1, 10))

        # --- TINFC Details ---
        elements.append(Paragraph("TINFC Details", section_style))
        exec_dt = datetime.now().strftime("%d-%b-%Y_%H:%M:%S")
        consent_text = ("We provide approval to NSDL e-Governance Infrastructure Ltd.(NSDL e-Gov) "
                        "to capture the details regarding the System details and share the details with NSDL e-Gov.")
        tinfc_rows = [
            [Paragraph("TIN FC Branch Name", cell_b), Paragraph(branch_name, cell_n)],
            [Paragraph("TIN FC Branch Code", cell_b), Paragraph(branch_code, cell_n)],
            [Paragraph("TIN FC Branch Officer Name", cell_b), Paragraph(officer_name, cell_n)],
            [Paragraph("Execution DateTime", cell_b), Paragraph(exec_dt, cell_n)],
            [Paragraph("Consent", cell_b), Paragraph(consent_text, cell_n)],
        ]
        elements.append(build_table(tinfc_rows))
        elements.append(Spacer(1, 12))

        # --- Operating System ---
        elements.append(Paragraph("Operating System", section_style))
        os_rows = [
            [Paragraph("OS Name", cell_b), Paragraph(data.os_name, cell_n)],
            [Paragraph("OS Version", cell_b), Paragraph(data.os_version, cell_n)],
            [Paragraph("OS Architecture", cell_b), Paragraph(data.architecture, cell_n)],
            [Paragraph("CS Name", cell_b), Paragraph(data.computer_name, cell_n)],
            [Paragraph("LicenseStatus", cell_b), Paragraph(data.license_status, cell_n)],
        ]
        elements.append(build_table(os_rows))
        elements.append(Spacer(1, 12))

        # --- OS Update Details (Hotfixes) ---
        elements.append(Paragraph("OS Update Details", section_style))
        hotfix_rows = []
        if data.hotfixes:
            for idx, hf in enumerate(data.hotfixes):
                if isinstance(hf, HotfixDetail):
                    hotfix_rows.append([Paragraph(str(idx + 1), cell_b), Paragraph("", cell_n)])
                    hotfix_rows.append([Paragraph("Caption", cell_b), Paragraph(hf.caption, cell_n)])
                    hotfix_rows.append([Paragraph("CS Name", cell_b), Paragraph(hf.cs_name, cell_n)])
                    hotfix_rows.append([Paragraph("Description", cell_b), Paragraph(hf.description, cell_n)])
                    hotfix_rows.append([Paragraph("Fix ID", cell_b), Paragraph(hf.fix_id, cell_n)])
                    hotfix_rows.append([Paragraph("Installed On", cell_b), Paragraph(hf.installed_on, cell_n)])
                else:
                    hotfix_rows.append([Paragraph(f"Fix #{idx+1}", cell_b), Paragraph(str(hf), cell_n)])
        else:
            hotfix_rows.append([Paragraph("No installed hotfixes detected", cell_b), Paragraph("-", cell_n)])
        # Mac address at end of hotfix section (matching sample)
        hotfix_rows.append([Paragraph("Mac address", cell_b), Paragraph(data.mac_address, cell_n)])
        elements.append(build_table(hotfix_rows))
        elements.append(Spacer(1, 12))

        # --- Drive Details ---
        elements.append(Paragraph("Drive Details", section_style))
        elements.append(build_table([
            [Paragraph("DriveName", cell_b), Paragraph(data.drive_name, cell_n)],
        ]))
        elements.append(Spacer(1, 12))

        # --- Compression utility details ---
        elements.append(Paragraph("Compression utility details", section_style))
        elements.append(build_table([
            [Paragraph("DriveName", cell_b), Paragraph(data.drive_name, cell_n)],
        ]))
        elements.append(Spacer(1, 12))

        # --- Antivirus ---
        elements.append(Paragraph("Antivirus", section_style))
        elements.append(build_table([
            [Paragraph("DriveName", cell_b), Paragraph(av_str if av_str else data.drive_name, cell_n)],
        ]))
        elements.append(Spacer(1, 12))

        # --- Printer Details ---
        elements.append(Paragraph("Printer Details", section_style))
        printer_rows = []
        if data.printers:
            for idx, p in enumerate(data.printers):
                if isinstance(p, PrinterDetail):
                    printer_rows.append([Paragraph(str(idx + 1), cell_b), Paragraph("", cell_n)])
                    printer_rows.append([Paragraph("Name", cell_b), Paragraph(p.name, cell_n)])
                    printer_rows.append([Paragraph("SystemName", cell_b), Paragraph(p.system_name, cell_n)])
                    printer_rows.append([Paragraph("EnableBIDI", cell_b), Paragraph(p.enable_bidi, cell_n)])
                    printer_rows.append([Paragraph("ExtendedPrinterStatus", cell_b), Paragraph(p.extended_printer_status, cell_n)])
                    printer_rows.append([Paragraph("PortName", cell_b), Paragraph(p.port_name, cell_n)])
                else:
                    printer_rows.append([Paragraph(f"Printer #{idx+1}", cell_b), Paragraph(str(p), cell_n)])
            printer_rows.append([Paragraph("Total Printer connected", cell_b), Paragraph(str(len(data.printers)), cell_n)])
        else:
            printer_rows.append([Paragraph("No active printers connected", cell_b), Paragraph("-", cell_n)])
        elements.append(build_table(printer_rows))

        doc.build(elements, onFirstPage=draw_page_decorations, onLaterPages=draw_page_decorations)
        logger.info(f"PDF compliance report successfully built: {pdf_path}")
    except Exception as e:
        logger.error(f"Failed to generate NSDL PDF Report: {e}")
        generation_errors.append("PDF report generation failed")

    # Build XML compliance document
    try:
        root = ET.Element("NsdlComplianceAudit", version="2.0.0")

        meta = ET.SubElement(root, "BranchMetadata")
        ET.SubElement(meta, "BranchName").text = branch_name
        ET.SubElement(meta, "BranchCode").text = branch_code
        ET.SubElement(meta, "OfficerName").text = officer_name

        sys_xml = ET.SubElement(root, "WorkstationInventory")
        ET.SubElement(sys_xml, "ComputerName").text = data.computer_name
        ET.SubElement(sys_xml, "OSName").text = data.os_name
        ET.SubElement(sys_xml, "OSVersion").text = data.os_version
        ET.SubElement(sys_xml, "Architecture").text = data.architecture
        ET.SubElement(sys_xml, "LicenseStatus").text = data.license_status
        ET.SubElement(sys_xml, "Antivirus").text = av_str
        ET.SubElement(sys_xml, "MacAddress").text = data.mac_address
        ET.SubElement(sys_xml, "CdRomDrive").text = data.drive_name

        hf_xml = ET.SubElement(root, "Hotfixes")
        for hf in data.hotfixes:
            if isinstance(hf, HotfixDetail):
                hf_el = ET.SubElement(hf_xml, "Hotfix")
                ET.SubElement(hf_el, "Caption").text = hf.caption
                ET.SubElement(hf_el, "CSName").text = hf.cs_name
                ET.SubElement(hf_el, "Description").text = hf.description
                ET.SubElement(hf_el, "FixID").text = hf.fix_id
                ET.SubElement(hf_el, "InstalledOn").text = hf.installed_on

        pr_xml = ET.SubElement(root, "Printers")
        for p in data.printers:
            if isinstance(p, PrinterDetail):
                p_el = ET.SubElement(pr_xml, "Printer")
                ET.SubElement(p_el, "Name").text = p.name
                ET.SubElement(p_el, "SystemName").text = p.system_name
                ET.SubElement(p_el, "EnableBIDI").text = p.enable_bidi
                ET.SubElement(p_el, "ExtendedPrinterStatus").text = p.extended_printer_status
                ET.SubElement(p_el, "PortName").text = p.port_name

        tree = ET.ElementTree(root)
        tree.write(xml_path, encoding="utf-8", xml_declaration=True)
        logger.info(f"XML compliance report successfully built: {xml_path}")
    except Exception as e:
        logger.error(f"Failed to generate XML report: {e}")
        generation_errors.append("XML export failed")

    if not pdf_path.exists():
        generation_errors.append("PDF report was not created")
    if not xml_path.exists():
        generation_errors.append("XML report was not created")

    if generation_errors:
        with session_lock:
            sessions[cid] = {
                **sessions.get(cid, {}),
                "status": "failed",
                "error": "; ".join(generation_errors),
                "completed_at": datetime.now().isoformat(timespec="seconds")
            }
            save_sessions()
        raise HTTPException(status_code=500, detail="Audit report generation failed.")

    # Cache completion state and file references
    with session_lock:
        sessions[cid] = {
            **sessions.get(cid, {}),
            "status": "completed",
            "error": None,
            "branch_name": branch_name,
            "branch_code": branch_code,
            "officer_name": officer_name,
            "pdf_path": str(pdf_path),
            "xml_path": str(xml_path),
            "completed_at": datetime.now().isoformat(timespec="seconds")
        }
        save_sessions()

    return {"status": "success"}

# ------------------------------------------------------------------------------
# 5. REPORT SERVING ENDPOINTS
# ------------------------------------------------------------------------------
@app.get("/download-report")
def download_report(client_id: str = Query(...), format: str = Query("pdf"), portal_token: Optional[str] = Cookie(None)):
    cid = validate_client_id(client_id)
    session = verify_portal_token(cid, portal_token)
    if session.get("status") != "completed":
        raise HTTPException(status_code=404, detail="Audit report is not ready or has not been found.")

    if format.lower() == "pdf":
        file_value = session.get("pdf_path")
        if not file_value:
            raise HTTPException(status_code=404, detail="PDF report does not exist on disk.")
        file_path = Path(file_value)
        if not file_path.exists() or not file_path.is_file():
            raise HTTPException(status_code=404, detail="PDF report does not exist on disk.")
        return FileResponse(file_path, media_type="application/pdf", filename=os.path.basename(file_path))

    elif format.lower() == "xml":
        file_value = session.get("xml_path")
        if not file_value:
            raise HTTPException(status_code=404, detail="XML report does not exist on disk.")
        file_path = Path(file_value)
        if not file_path.exists() or not file_path.is_file():
            raise HTTPException(status_code=404, detail="XML report does not exist on disk.")
        return FileResponse(file_path, media_type="application/xml", filename=os.path.basename(file_path))

    else:
        raise HTTPException(status_code=400, detail="Invalid report format. Use 'pdf' or 'xml'.")
