# ==============================================================================
#                 InfraPulse WORKSTATION COMPLIANCE AUDIT BACKEND (FASTAPI)
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
APP_NAME = os.getenv("APP_NAME", "InfraPulse Workstation Compliance Portal")
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

class NetworkAdapter(BaseModel):
    name: str = ""
    mac_address: str = ""
    ip_address: str = ""
    subnet_mask: str = ""
    default_gateway: str = ""
    dhcp_enabled: str = "False"
    dhcp_server: str = ""
    dns_servers: str = ""

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
    network_adapters: Union[List[NetworkAdapter], List[str], str] = []
    # systeminfo fields
    system_manufacturer: str = ""
    system_model: str = ""
    processor: str = ""
    total_physical_memory: str = ""
    bios_version: str = ""
    domain: str = ""
    logon_server: str = ""
    system_boot_time: str = ""
    time_zone: str = ""
    registered_owner: str = ""
    windows_directory: str = ""

    @validator('antivirus', pre=True, allow_reuse=True)
    def coerce_antivirus(cls, v):
        if v is None: return []
        if isinstance(v, list): return v
        return [v]

    @validator('printers', pre=True, allow_reuse=True)
    def coerce_printers(cls, v):
        if v is None: return []
        if isinstance(v, list): return v
        return [v]

    @validator('hotfixes', pre=True, allow_reuse=True)
    def coerce_hotfixes(cls, v):
        if v is None: return []
        if isinstance(v, list): return v
        return [v]

    @validator('network_adapters', pre=True, allow_reuse=True)
    def coerce_network_adapters(cls, v):
        if v is None: return []
        if isinstance(v, list): return v
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

def detect_client_os(user_agent: str) -> str:
    """Returns 'windows', 'mac', or 'linux' based on User-Agent string."""
    ua = (user_agent or "").lower()
    if "mac" in ua or "darwin" in ua:
        return "mac"
    if "linux" in ua:
        return "linux"
    return "windows"


@app.get("/download-script", response_class=PlainTextResponse)
def download_script(request: Request, client_id: str = Query(...), audit_token: str = Query(...)):
    """Dynamically serves the audit script (PowerShell or Bash) baked with server URL and tokens."""
    cid = validate_client_id(client_id)
    verify_audit_token(cid, audit_token)
    base_url = str(request.base_url).rstrip('/')
    session_meta = sessions.get(cid, {})
    client_os = session_meta.get("client_os", "windows")

    if client_os in ("linux", "mac"):
        script_file = BASE_DIR / "scripts" / "audit.sh"
    else:
        script_file = BASE_DIR / "scripts" / "audit.ps1"

    try:
        with open(script_file, "r", encoding="utf-8") as f:
            script_content = f.read()
        dynamic_script = script_content.replace("API_BASE_URL_PLACEHOLDER", base_url)
        dynamic_script = dynamic_script.replace("CLIENT_ID_PLACEHOLDER", cid)
        dynamic_script = dynamic_script.replace("AUDIT_TOKEN_PLACEHOLDER", audit_token)
        return PlainTextResponse(content=dynamic_script)
    except Exception as e:
        logger.error(f"Failed to load audit script ({script_file.name}): {e}")
        raise HTTPException(status_code=500, detail="Audit script source unavailable.")

@app.get("/download-vbs")
def download_vbs(
    request: Request,
    client_id: str = Query(...),
    branch_name: Optional[str] = Query(None),
    branch_code: Optional[str] = Query(None),
    officer_name: Optional[str] = Query(None),
    os: Optional[str] = Query(None)
):
    """Generates a launcher script appropriate for the client OS:
    - Windows → .bat (runs PowerShell silently)
    - Linux/Mac → .sh (runs bash via curl)
    """
    cid = validate_client_id(client_id)
    base_url = str(request.base_url).rstrip('/')
    audit_token = secrets.token_urlsafe(32)
    portal_token = secrets.token_urlsafe(32)
    resolved_branch_name = (branch_name or DEFAULT_BRANCH_NAME).strip()
    resolved_branch_code = (branch_code or DEFAULT_BRANCH_CODE).strip()
    resolved_officer_name = (officer_name or DEFAULT_OFFICER_NAME).strip()

    user_agent = request.headers.get("user-agent", "")
    client_os = os.lower() if os else detect_client_os(user_agent)
    if client_os not in ("windows", "linux", "mac"):
        client_os = "windows"

    with session_lock:
        sessions[cid] = {
            "status": "pending",
            "client_os": client_os,
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

    if client_os in ("linux", "mac"):
        launcher_content = f"""#!/bin/bash
curl -fsSL '{script_url}' | bash
"""
        filename = f"verify_system_{cid}.sh"
        media_type = "application/x-sh"
    else:
        launcher_content = f"""@echo off
start /min powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Invoke-RestMethod -Uri '{script_url}' | Invoke-Expression"
exit
"""
        filename = f"verify_system_{cid}.bat"
        media_type = "application/octet-stream"

    headers = {
        "Content-Disposition": f"attachment; filename={filename}",
        "Cache-Control": "no-store"
    }
    response = Response(content=launcher_content, media_type=media_type, headers=headers)
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
# 3. PDF PAGE DECORATIONS (InfraPulse Style Page Border & Centered Footer)
# ------------------------------------------------------------------------------
def draw_page_decorations(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#A80000"))
    canvas.setLineWidth(1.5)
    canvas.rect(36, 36, doc.pagesize[0] - 72, doc.pagesize[1] - 72)

    canvas.setFont('Helvetica-Bold', 8)
    canvas.setFillColor(colors.HexColor("#A80000"))
    canvas.drawCentredString(doc.pagesize[0] / 2.0, 20, "INSPECTION REPORT BY InfraPulse")
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

    # Build InfraPulse Inspection Report PDF (matching sample format)
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
        consent_text = ("We provide approval to InfraPulse Infrastructure Ltd.(InfraPulse) "
                        "to capture the details regarding the System details and share the details with InfraPulse.")
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
            printer_rows.append([Paragraph("Total Printers Connected", cell_b), Paragraph(str(len(data.printers)), cell_n)])
        else:
            printer_rows.append([Paragraph("No active printers connected", cell_b), Paragraph("-", cell_n)])
        elements.append(build_table(printer_rows))
        elements.append(Spacer(1, 12))

        # --- System Information (systeminfo) ---
        elements.append(Paragraph("System Information", section_style))
        sysinfo_rows = [
            [Paragraph("System Manufacturer", cell_b), Paragraph(data.system_manufacturer or "-", cell_n)],
            [Paragraph("System Model", cell_b), Paragraph(data.system_model or "-", cell_n)],
            [Paragraph("Processor", cell_b), Paragraph(data.processor or "-", cell_n)],
            [Paragraph("Total Physical Memory", cell_b), Paragraph(data.total_physical_memory or "-", cell_n)],
            [Paragraph("BIOS Version", cell_b), Paragraph(data.bios_version or "-", cell_n)],
            [Paragraph("Domain", cell_b), Paragraph(data.domain or "-", cell_n)],
            [Paragraph("Logon Server", cell_b), Paragraph(data.logon_server or "-", cell_n)],
            [Paragraph("System Boot Time", cell_b), Paragraph(data.system_boot_time or "-", cell_n)],
            [Paragraph("Time Zone", cell_b), Paragraph(data.time_zone or "-", cell_n)],
            [Paragraph("Registered Owner", cell_b), Paragraph(data.registered_owner or "-", cell_n)],
            [Paragraph("Windows Directory", cell_b), Paragraph(data.windows_directory or "-", cell_n)],
        ]
        elements.append(build_table(sysinfo_rows))
        elements.append(Spacer(1, 12))

        # --- Network Configuration (ipconfig /all) ---
        elements.append(Paragraph("Network Configuration", section_style))
        net_rows = []
        if data.network_adapters:
            for idx, adapter in enumerate(data.network_adapters):
                if isinstance(adapter, NetworkAdapter):
                    net_rows.append([Paragraph(f"Adapter {idx + 1}", cell_b), Paragraph(adapter.name, cell_n)])
                    net_rows.append([Paragraph("Physical Address (MAC)", cell_b), Paragraph(adapter.mac_address or "-", cell_n)])
                    net_rows.append([Paragraph("IPv4 Address", cell_b), Paragraph(adapter.ip_address or "-", cell_n)])
                    net_rows.append([Paragraph("Subnet Mask", cell_b), Paragraph(adapter.subnet_mask or "-", cell_n)])
                    net_rows.append([Paragraph("Default Gateway", cell_b), Paragraph(adapter.default_gateway or "-", cell_n)])
                    net_rows.append([Paragraph("DHCP Enabled", cell_b), Paragraph(adapter.dhcp_enabled or "-", cell_n)])
                    net_rows.append([Paragraph("DHCP Server", cell_b), Paragraph(adapter.dhcp_server or "-", cell_n)])
                    net_rows.append([Paragraph("DNS Servers", cell_b), Paragraph(adapter.dns_servers or "-", cell_n)])
                else:
                    net_rows.append([Paragraph(f"Adapter #{idx+1}", cell_b), Paragraph(str(adapter), cell_n)])
        else:
            net_rows.append([Paragraph("No active network adapters found", cell_b), Paragraph("-", cell_n)])
        elements.append(build_table(net_rows))

        doc.build(elements, onFirstPage=draw_page_decorations, onLaterPages=draw_page_decorations)
        logger.info(f"PDF compliance report successfully built: {pdf_path}")
    except Exception as e:
        logger.error(f"Failed to generate InfraPulse PDF Report: {e}")
        generation_errors.append("PDF report generation failed")

    # Build XML compliance document
    try:
        root = ET.Element("InfraPulseComplianceAudit", version="2.0.0")

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

        sysinfo_xml = ET.SubElement(root, "SystemInformation")
        ET.SubElement(sysinfo_xml, "SystemManufacturer").text = data.system_manufacturer
        ET.SubElement(sysinfo_xml, "SystemModel").text = data.system_model
        ET.SubElement(sysinfo_xml, "Processor").text = data.processor
        ET.SubElement(sysinfo_xml, "TotalPhysicalMemory").text = data.total_physical_memory
        ET.SubElement(sysinfo_xml, "BIOSVersion").text = data.bios_version
        ET.SubElement(sysinfo_xml, "Domain").text = data.domain
        ET.SubElement(sysinfo_xml, "LogonServer").text = data.logon_server
        ET.SubElement(sysinfo_xml, "SystemBootTime").text = data.system_boot_time
        ET.SubElement(sysinfo_xml, "TimeZone").text = data.time_zone
        ET.SubElement(sysinfo_xml, "RegisteredOwner").text = data.registered_owner
        ET.SubElement(sysinfo_xml, "WindowsDirectory").text = data.windows_directory

        net_xml = ET.SubElement(root, "NetworkConfiguration")
        for adapter in data.network_adapters:
            if isinstance(adapter, NetworkAdapter):
                a_el = ET.SubElement(net_xml, "Adapter")
                ET.SubElement(a_el, "Name").text = adapter.name
                ET.SubElement(a_el, "PhysicalAddress").text = adapter.mac_address
                ET.SubElement(a_el, "IPv4Address").text = adapter.ip_address
                ET.SubElement(a_el, "SubnetMask").text = adapter.subnet_mask
                ET.SubElement(a_el, "DefaultGateway").text = adapter.default_gateway
                ET.SubElement(a_el, "DHCPEnabled").text = adapter.dhcp_enabled
                ET.SubElement(a_el, "DHCPServer").text = adapter.dhcp_server
                ET.SubElement(a_el, "DNSServers").text = adapter.dns_servers

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
