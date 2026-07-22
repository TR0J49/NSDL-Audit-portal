# ==============================================================================
#                 InfraPulse WORKSTATION COMPLIANCE AUDIT BACKEND (FASTAPI)
# ==============================================================================
# Version: 2.0.0

from fastapi import Cookie, FastAPI, Query, Request, HTTPException
from fastapi.responses import FileResponse, Response, PlainTextResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator
from typing import Union, List, Optional
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.pagesizes import letter
import asyncio
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


def verify_assortment_token(client_id: str, assortment_token: str) -> dict:
    session = sessions.get(client_id)
    if not session:
        with session_lock:
            load_sessions()
            session = sessions.get(client_id)
    if not session or session.get("assortment_token_hash") != hash_secret(assortment_token or ""):
        raise HTTPException(status_code=403, detail="Invalid assortment session token.")
    return session


def verify_portal_token(client_id: str, portal_token: Optional[str]) -> dict:
    session = sessions.get(client_id)
    if not session:
        with session_lock:
            load_sessions()
            session = sessions.get(client_id)
    if not session:
        raise HTTPException(status_code=404, detail="Assortment session has not been found.")
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
    ipv6_address: str = ""
    temp_ipv6_address: str = ""
    link_local_ipv6: str = ""

class DiskInfo(BaseModel):
    drive: str = ""
    total: str = ""
    used: str = ""
    free: str = ""

class InstalledApp(BaseModel):
    name: str = ""
    version: str = ""
    publisher: str = ""

class LocalUser(BaseModel):
    name: str = ""
    enabled: str = "True"
    admin: str = "False"

class RunningService(BaseModel):
    name: str = ""
    display_name: str = ""
    start_type: str = ""

class OpenPort(BaseModel):
    port: str = ""
    protocol: str = ""
    pid: str = ""

class SecurityPosture(BaseModel):
    bitlocker: str = ""
    windows_firewall: str = ""
    uac_enabled: str = ""
    filevault: str = ""
    gatekeeper: str = ""
    sip: str = ""
    apparmor: str = ""
    selinux: str = ""

class DockerInfo(BaseModel):
    version: str = ""
    running_containers: int = 0
    containers: List[str] = []

    @validator('running_containers', pre=True, allow_reuse=True)
    def coerce_containers_count(cls, v):
        try: return int(v)
        except: return 0


class RunningProcess(BaseModel):
    pid: str = ""
    name: str = ""
    parent_pid: str = ""
    user: str = ""
    path: str = ""
    cpu: str = ""
    memory: str = ""

class SslCertificate(BaseModel):
    subject: str = ""
    issuer: str = ""
    expiry: str = ""
    thumbprint: str = ""

class BrowserExtension(BaseModel):
    browser: str = ""
    name: str = ""
    version: str = ""
    extension_id: str = ""

class EventLogEntry(BaseModel):
    time: str = ""
    level: str = ""
    source: str = ""
    message: str = ""

class GpuInfo(BaseModel):
    name: str = ""
    driver_version: str = ""
    vram: str = ""

class BatteryInfo(BaseModel):
    name: str = ""
    status: str = ""
    estimated_charge: str = ""

class LocalGroup(BaseModel):
    name: str = ""
    description: str = ""
    members: str = ""

class StartupItem(BaseModel):
    name: str = ""
    command: str = ""
    location: str = ""
    user: str = ""

class NetworkConnection(BaseModel):
    protocol: str = ""
    local_address: str = ""
    local_port: str = ""
    remote_address: str = ""
    remote_port: str = ""
    state: str = ""
    pid: str = ""

class RouteEntry(BaseModel):
    destination: str = ""
    gateway: str = ""
    interface: str = ""
    metric: str = ""

class FilesystemEntry(BaseModel):
    device: str = ""
    mount_point: str = ""
    fs_type: str = ""
    total: str = ""
    used: str = ""
    free: str = ""
    use_percent: str = ""

class FileIntegrityEntry(BaseModel):
    path: str = ""
    sha256: str = ""
    size: str = ""
    modified: str = ""

class ProcessEvent(BaseModel):
    time: str = ""
    pid: str = ""
    parent_pid: str = ""
    process_name: str = ""
    command_line: str = ""
    user: str = ""

class SecurityPolicy(BaseModel):
    min_password_length: str = ""
    password_complexity: str = ""
    lockout_threshold: str = ""
    screen_lock_timeout: str = ""
    auto_updates_enabled: str = ""
    remote_login_enabled: str = ""
    antivirus_enabled: str = ""
    antivirus_definitions: str = ""

class ContainerImage(BaseModel):
    repository: str = ""
    tag: str = ""
    image_id: str = ""
    size: str = ""
    created: str = ""


class AssortmentData(BaseModel):
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
    # extended fields
    disk_info: List[DiskInfo] = []
    installed_apps: List[InstalledApp] = []
    local_users: List[LocalUser] = []
    running_services: List[RunningService] = []
    open_ports: List[OpenPort] = []
    security_posture: Optional[SecurityPosture] = None
    docker_info: Optional[DockerInfo] = None
    running_processes: List[RunningProcess] = []
    ssl_certificates: List[SslCertificate] = []
    browser_extensions: List[BrowserExtension] = []
    event_logs: List[EventLogEntry] = []
    # Hardware Inventory extensions
    gpu_info: List[GpuInfo] = []
    battery_info: Optional[BatteryInfo] = None
    # Users and Groups
    local_groups: List[LocalGroup] = []
    # Services and Startup Items
    startup_items: List[StartupItem] = []
    # Network extensions
    network_connections: List[NetworkConnection] = []
    routing_table: List[RouteEntry] = []
    # Disk filesystem extended
    filesystem_info: List[FilesystemEntry] = []
    # File-Integrity Monitoring
    file_integrity: List[FileIntegrityEntry] = []
    # Process-Event Monitoring
    process_events: List[ProcessEvent] = []
    # Security Policy
    security_policy: Optional[SecurityPolicy] = None
    # Container Images
    container_images: List[ContainerImage] = []

    @validator('antivirus', pre=True, allow_reuse=True)
    def coerce_antivirus(cls, v):
        if v is None: return []
        if isinstance(v, list): return v
        return [v]

    @validator('printers', pre=True, allow_reuse=True)
    def coerce_printers(cls, v):
        if v is None: return []
        if isinstance(v, str): return [v]
        if isinstance(v, list):
            result = []
            for item in v:
                if isinstance(item, dict):
                    result.append(PrinterDetail(**{k: str(val) for k, val in item.items() if k in PrinterDetail.__fields__}))
                else:
                    result.append(item)
            return result
        return [v]

    @validator('hotfixes', pre=True, allow_reuse=True)
    def coerce_hotfixes(cls, v):
        if v is None: return []
        if isinstance(v, str): return [v]
        if isinstance(v, list):
            result = []
            for item in v:
                if isinstance(item, dict):
                    result.append(HotfixDetail(**{k: str(val) for k, val in item.items() if k in HotfixDetail.__fields__}))
                else:
                    result.append(item)
            return result
        return [v]

    @validator('network_adapters', pre=True, allow_reuse=True)
    def coerce_network_adapters(cls, v):
        if v is None: return []
        if isinstance(v, str): return [v]
        if isinstance(v, list):
            result = []
            for item in v:
                if isinstance(item, dict):
                    result.append(NetworkAdapter(**{k: str(val) for k, val in item.items() if k in NetworkAdapter.__fields__}))
                else:
                    result.append(item)
            return result
        return [v]

    @validator('disk_info', pre=True, allow_reuse=True)
    def coerce_disk_info(cls, v):
        if not v: return []
        if isinstance(v, list):
            return [DiskInfo(**{k: str(val) for k, val in item.items() if k in DiskInfo.__fields__}) if isinstance(item, dict) else item for item in v]
        return []

    @validator('installed_apps', pre=True, allow_reuse=True)
    def coerce_installed_apps(cls, v):
        if not v: return []
        if isinstance(v, list):
            return [InstalledApp(**{k: str(val) for k, val in item.items() if k in InstalledApp.__fields__}) if isinstance(item, dict) else item for item in v]
        return []

    @validator('local_users', pre=True, allow_reuse=True)
    def coerce_local_users(cls, v):
        if not v: return []
        if isinstance(v, list):
            return [LocalUser(**{k: str(val) for k, val in item.items() if k in LocalUser.__fields__}) if isinstance(item, dict) else item for item in v]
        return []

    @validator('running_services', pre=True, allow_reuse=True)
    def coerce_running_services(cls, v):
        if not v: return []
        if isinstance(v, list):
            return [RunningService(**{k: str(val) for k, val in item.items() if k in RunningService.__fields__}) if isinstance(item, dict) else item for item in v]
        return []

    @validator('open_ports', pre=True, allow_reuse=True)
    def coerce_open_ports(cls, v):
        if not v: return []
        if isinstance(v, list):
            return [OpenPort(**{k: str(val) for k, val in item.items() if k in OpenPort.__fields__}) if isinstance(item, dict) else item for item in v]
        return []

    @validator('security_posture', pre=True, allow_reuse=True)
    def coerce_security_posture(cls, v):
        if not v: return None
        if isinstance(v, dict):
            return SecurityPosture(**{k: str(val) for k, val in v.items() if k in SecurityPosture.__fields__})
        return v

    @validator('docker_info', pre=True, allow_reuse=True)
    def coerce_docker_info(cls, v):
        if not v: return None
        if isinstance(v, dict):
            return DockerInfo(
                version=str(v.get("version", "")),
                running_containers=int(v.get("running_containers", 0)),
                containers=[str(c) for c in v.get("containers", []) if c]
            )
        return v

    @validator('running_processes', pre=True, allow_reuse=True)
    def coerce_running_processes(cls, v):
        if not v: return []
        if isinstance(v, list):
            return [RunningProcess(**{k: str(val) for k, val in item.items() if k in RunningProcess.__fields__}) if isinstance(item, dict) else item for item in v]
        return []

    @validator('ssl_certificates', pre=True, allow_reuse=True)
    def coerce_ssl_certificates(cls, v):
        if not v: return []
        if isinstance(v, list):
            return [SslCertificate(**{k: str(val) for k, val in item.items() if k in SslCertificate.__fields__}) if isinstance(item, dict) else item for item in v]
        return []

    @validator('browser_extensions', pre=True, allow_reuse=True)
    def coerce_browser_extensions(cls, v):
        if not v: return []
        if isinstance(v, list):
            return [BrowserExtension(**{k: str(val) for k, val in item.items() if k in BrowserExtension.__fields__}) if isinstance(item, dict) else item for item in v]
        return []

    @validator('event_logs', pre=True, allow_reuse=True)
    def coerce_event_logs(cls, v):
        if not v: return []
        if isinstance(v, list):
            return [EventLogEntry(**{k: str(val) for k, val in item.items() if k in EventLogEntry.__fields__}) if isinstance(item, dict) else item for item in v]
        return []

    @validator('gpu_info', pre=True, allow_reuse=True)
    def coerce_gpu_info(cls, v):
        if not v: return []
        if isinstance(v, list):
            return [GpuInfo(**{k: str(val) for k, val in item.items() if k in GpuInfo.__fields__}) if isinstance(item, dict) else item for item in v]
        return []

    @validator('battery_info', pre=True, allow_reuse=True)
    def coerce_battery_info(cls, v):
        if not v: return None
        if isinstance(v, dict):
            return BatteryInfo(**{k: str(val) for k, val in v.items() if k in BatteryInfo.__fields__})
        return v

    @validator('local_groups', pre=True, allow_reuse=True)
    def coerce_local_groups(cls, v):
        if not v: return []
        if isinstance(v, list):
            return [LocalGroup(**{k: str(val) for k, val in item.items() if k in LocalGroup.__fields__}) if isinstance(item, dict) else item for item in v]
        return []

    @validator('startup_items', pre=True, allow_reuse=True)
    def coerce_startup_items(cls, v):
        if not v: return []
        if isinstance(v, list):
            return [StartupItem(**{k: str(val) for k, val in item.items() if k in StartupItem.__fields__}) if isinstance(item, dict) else item for item in v]
        return []

    @validator('network_connections', pre=True, allow_reuse=True)
    def coerce_network_connections(cls, v):
        if not v: return []
        if isinstance(v, list):
            return [NetworkConnection(**{k: str(val) for k, val in item.items() if k in NetworkConnection.__fields__}) if isinstance(item, dict) else item for item in v]
        return []

    @validator('routing_table', pre=True, allow_reuse=True)
    def coerce_routing_table(cls, v):
        if not v: return []
        if isinstance(v, list):
            return [RouteEntry(**{k: str(val) for k, val in item.items() if k in RouteEntry.__fields__}) if isinstance(item, dict) else item for item in v]
        return []

    @validator('filesystem_info', pre=True, allow_reuse=True)
    def coerce_filesystem_info(cls, v):
        if not v: return []
        if isinstance(v, list):
            return [FilesystemEntry(**{k: str(val) for k, val in item.items() if k in FilesystemEntry.__fields__}) if isinstance(item, dict) else item for item in v]
        return []

    @validator('file_integrity', pre=True, allow_reuse=True)
    def coerce_file_integrity(cls, v):
        if not v: return []
        if isinstance(v, list):
            return [FileIntegrityEntry(**{k: str(val) for k, val in item.items() if k in FileIntegrityEntry.__fields__}) if isinstance(item, dict) else item for item in v]
        return []

    @validator('process_events', pre=True, allow_reuse=True)
    def coerce_process_events(cls, v):
        if not v: return []
        if isinstance(v, list):
            return [ProcessEvent(**{k: str(val) for k, val in item.items() if k in ProcessEvent.__fields__}) if isinstance(item, dict) else item for item in v]
        return []

    @validator('security_policy', pre=True, allow_reuse=True)
    def coerce_security_policy(cls, v):
        if not v: return None
        if isinstance(v, dict):
            return SecurityPolicy(**{k: str(val) for k, val in v.items() if k in SecurityPolicy.__fields__})
        return v

    @validator('container_images', pre=True, allow_reuse=True)
    def coerce_container_images(cls, v):
        if not v: return []
        if isinstance(v, list):
            return [ContainerImage(**{k: str(val) for k, val in item.items() if k in ContainerImage.__fields__}) if isinstance(item, dict) else item for item in v]
        return []

# ------------------------------------------------------------------------------
# 2. CORE SYSTEM ROUTING & SILENT VBS LAUNCHERS
# ------------------------------------------------------------------------------
@app.get("/")
def home():
    """Serves the premium audit portal UI."""
    return FileResponse(BASE_DIR / "frontend" / "index.html")

@app.get("/check-status")
def check_status(client_id: str = Query(...), portal_token: Optional[str] = Cookie(None)):
    """Fallback polling endpoint for clients that cannot use SSE."""
    cid = validate_client_id(client_id)
    session = verify_portal_token(cid, portal_token)
    return JSONResponse(content={
        "status": session.get("status", "pending"),
        "officer_name": session.get("officer_name", ""),
        "error": session.get("error")
    })

@app.get("/events")
async def sse_events(client_id: str = Query(...), portal_token: Optional[str] = Cookie(None)):
    """SSE endpoint — pushes status updates to the browser over a single long-lived connection."""
    cid = validate_client_id(client_id)
    verify_portal_token(cid, portal_token)

    async def event_stream():
        yield "data: {\"status\": \"connected\"}\n\n"
        last_status = None
        elapsed = 0
        timeout = 300  # 5 min max

        while elapsed < timeout:
            session = sessions.get(cid, {})
            status = session.get("status", "pending")

            if status != last_status:
                last_status = status
                payload = json.dumps({
                    "status": status,
                    "officer_name": session.get("officer_name", ""),
                    "error": session.get("error")
                })
                yield f"data: {payload}\n\n"
                if status in ("completed", "failed"):
                    return

            await asyncio.sleep(0.5)
            elapsed += 0.5

        yield "data: {\"status\": \"timeout\"}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        }
    )

def detect_client_os(user_agent: str) -> str:
    """Returns 'windows', 'mac', or 'linux' based on User-Agent string."""
    ua = (user_agent or "").lower()
    if "mac" in ua or "darwin" in ua:
        return "mac"
    if "linux" in ua:
        return "linux"
    return "windows"


@app.get("/download-script", response_class=PlainTextResponse)
def download_script(request: Request, client_id: str = Query(...), assortment_token: str = Query(...)):
    """Dynamically serves the assortment script (PowerShell or Bash) baked with server URL and tokens."""
    cid = validate_client_id(client_id)
    verify_assortment_token(cid, assortment_token)
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
        dynamic_script = dynamic_script.replace("AUDIT_TOKEN_PLACEHOLDER", assortment_token)
        return PlainTextResponse(content=dynamic_script)
    except Exception as e:
        logger.error(f"Failed to load assortment script ({script_file.name}): {e}")
        raise HTTPException(status_code=500, detail="Assortment script source unavailable.")

@app.get("/download-vbs")
def download_vbs(
    request: Request,
    client_id: str = Query(...),
    officer_name: Optional[str] = Query(None),
    os_hint: Optional[str] = Query(None, alias="os")
):
    """Generates a launcher script appropriate for the client OS:
    - Windows → .bat (runs PowerShell silently)
    - Linux/Mac → .sh (runs bash via curl)
    """
    cid = validate_client_id(client_id)
    base_url = str(request.base_url).rstrip('/')
    assortment_token = secrets.token_urlsafe(32)
    portal_token = secrets.token_urlsafe(32)
    resolved_officer_name = (officer_name or DEFAULT_OFFICER_NAME).strip()

    user_agent = request.headers.get("user-agent", "")
    client_os = os_hint.lower() if os_hint else detect_client_os(user_agent)
    if client_os not in ("windows", "linux", "mac"):
        client_os = "windows"

    with session_lock:
        sessions[cid] = {
            "status": "pending",
            "client_os": client_os,
            "officer_name": resolved_officer_name,
            "assortment_token_hash": hash_secret(assortment_token),
            "portal_token_hash": hash_secret(portal_token),
            "pdf_path": None,
            "xml_path": None,
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "completed_at": None
        }
        save_sessions()

    script_url = f"{base_url}/download-script?client_id={quote(cid)}&assortment_token={quote(assortment_token)}"

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
def build_table(rows, col_widths=None):
    if col_widths is None:
        col_widths = [180, 324]
    t = Table(rows, colWidths=col_widths)
    t.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
    ]))
    return t


def get_printer_type(port_name: str) -> str:
    port = (port_name or "").upper()
    physical_indicators = ["USB", "LPT", "COM", "IP_", "DOT4", "WSD"]
    virtual_indicators  = ["NUL", "PORTPROMPT", "SHRFAX", "MICROSOFTSHAREDPRINTER",
                           "MICROSOFT.", "AD_PORT", "TS", "XPS", "PDF", "FAX",
                           "ONENOTE", "ONENOTEIM", "CLMREDIRECTOR"]
    for ind in physical_indicators:
        if port.startswith(ind) or ind in port:
            return "Physical Printer"
    for ind in virtual_indicators:
        if ind in port:
            return "Virtual Printer"
    return "Virtual Printer"

# ------------------------------------------------------------------------------
# 4. COMPLIANCE INGESTION AND EXPORTS (PDF & XML GENERATOR)
# ------------------------------------------------------------------------------
@app.post("/upload-assortment")
def upload_assortment(data: AssortmentData, client_id: str = Query(...), assortment_token: str = Query(...)):
    cid = validate_client_id(client_id)
    verify_assortment_token(cid, assortment_token)
    logger.info(f"Uploading system assortment data for client session ID: {cid}")

    timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")

    # Load session branch info or fall back to defaults
    session_meta = sessions.get(cid, {})
    officer_name = session_meta.get("officer_name", DEFAULT_OFFICER_NAME)

    safe_officer_name = sanitize_filename_part(officer_name, fallback="assortment")
    file_prefix = USER_INFO_DIR / f"{safe_officer_name}_{timestamp}"
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

        title_style   = ParagraphStyle('TitleStyle',   fontName='Helvetica-Bold', fontSize=14, leading=18, alignment=1, spaceAfter=4)
        date_style    = ParagraphStyle('DateStyle',    fontName='Helvetica',      fontSize=9,  leading=12, alignment=1, spaceAfter=16, textColor=colors.HexColor("#555555"))
        section_style = ParagraphStyle('SectionStyle', fontName='Helvetica-Bold', fontSize=10, leading=12, spaceBefore=14, spaceAfter=6)
        cell_b = ParagraphStyle('CellBold',   fontName='Helvetica-Bold', fontSize=8, leading=10)
        cell_n = ParagraphStyle('CellNormal', fontName='Helvetica',      fontSize=8, leading=10)

        exec_dt = datetime.now().strftime("%d-%b-%Y  %H:%M:%S")

        elements = []

        # Title + real-time date
        elements.append(Paragraph("System Data Collection Report", title_style))
        elements.append(Paragraph(f"Generated on: {exec_dt}", date_style))
        elements.append(Spacer(1, 6))

        # --- 1. Collection Details (User Info) ---
        elements.append(Paragraph("Collection Details", section_style))
        consent_text = ("We provide approval to InfraPulse Infrastructure Ltd.(InfraPulse) "
                        "to capture the details regarding the System details and share the details with InfraPulse.")
        elements.append(build_table([
            [Paragraph("Collected By", cell_b),        Paragraph(officer_name, cell_n)],
            [Paragraph("Collection Date", cell_b),     Paragraph(datetime.now().strftime("%d-%b-%Y"), cell_n)],
            [Paragraph("Collection Time", cell_b),     Paragraph(datetime.now().strftime("%H:%M:%S"), cell_n)],
            [Paragraph("Consent", cell_b),             Paragraph(consent_text, cell_n)],
        ]))
        elements.append(Spacer(1, 12))

        # --- 2. Network Information ---
        elements.append(Paragraph("Network Information", section_style))
        net_rows = []
        net_rows.append([Paragraph("MAC Address", cell_b), Paragraph(data.mac_address, cell_n)])
        if data.network_adapters:
            for idx, adapter in enumerate(data.network_adapters):
                if isinstance(adapter, NetworkAdapter):
                    net_rows.append([Paragraph(f"Adapter {idx + 1}", cell_b), Paragraph(adapter.name, cell_n)])
                    net_rows.append([Paragraph("Physical Address (MAC)", cell_b), Paragraph(adapter.mac_address or "-", cell_n)])
                    net_rows.append([Paragraph("IPv4 Address", cell_b), Paragraph(adapter.ip_address or "-", cell_n)])
                    net_rows.append([Paragraph("Subnet Mask", cell_b), Paragraph(adapter.subnet_mask or "-", cell_n)])
                    net_rows.append([Paragraph("Default Gateway", cell_b), Paragraph(adapter.default_gateway or "-", cell_n)])
                    net_rows.append([Paragraph("IPv6 Address", cell_b), Paragraph(adapter.ipv6_address or "-", cell_n)])
                    net_rows.append([Paragraph("Temporary IPv6 Address", cell_b), Paragraph(adapter.temp_ipv6_address or "-", cell_n)])
                    net_rows.append([Paragraph("Link-local IPv6 Address", cell_b), Paragraph(adapter.link_local_ipv6 or "-", cell_n)])
                    net_rows.append([Paragraph("DHCP Enabled", cell_b), Paragraph(adapter.dhcp_enabled or "-", cell_n)])
                    net_rows.append([Paragraph("DHCP Server", cell_b), Paragraph(adapter.dhcp_server or "-", cell_n)])
                    net_rows.append([Paragraph("DNS Servers", cell_b), Paragraph(adapter.dns_servers or "-", cell_n)])
                else:
                    net_rows.append([Paragraph(f"Adapter #{idx+1}", cell_b), Paragraph(str(adapter), cell_n)])
        else:
            net_rows.append([Paragraph("No active network adapters found", cell_b), Paragraph("-", cell_n)])
        elements.append(build_table(net_rows))
        elements.append(Spacer(1, 12))

        # --- 3. System Information ---
        elements.append(Paragraph("System Information", section_style))
        elements.append(build_table([
            [Paragraph("Computer Name", cell_b), Paragraph(data.computer_name, cell_n)],
            [Paragraph("System Manufacturer", cell_b), Paragraph(data.system_manufacturer or "-", cell_n)],
            [Paragraph("System Model", cell_b), Paragraph(data.system_model or "-", cell_n)],
            [Paragraph("Processor", cell_b), Paragraph(data.processor or "-", cell_n)],
            [Paragraph("Total Physical Memory", cell_b), Paragraph(data.total_physical_memory or "-", cell_n)],
            [Paragraph("BIOS Version", cell_b), Paragraph(data.bios_version or "-", cell_n)],
            [Paragraph("OS Name", cell_b), Paragraph(data.os_name, cell_n)],
            [Paragraph("OS Version", cell_b), Paragraph(data.os_version, cell_n)],
            [Paragraph("OS Architecture", cell_b), Paragraph(data.architecture, cell_n)],
            [Paragraph("License Status", cell_b), Paragraph(data.license_status, cell_n)],
            [Paragraph("Windows Directory", cell_b), Paragraph(data.windows_directory or "-", cell_n)],
            [Paragraph("System Boot Time", cell_b), Paragraph(data.system_boot_time or "-", cell_n)],
            [Paragraph("Time Zone", cell_b), Paragraph(data.time_zone or "-", cell_n)],
            [Paragraph("Domain", cell_b), Paragraph(data.domain or "-", cell_n)],
            [Paragraph("Logon Server", cell_b), Paragraph(data.logon_server or "-", cell_n)],
            [Paragraph("Registered Owner", cell_b), Paragraph(data.registered_owner or "-", cell_n)],
        ]))
        elements.append(Spacer(1, 12))

        # --- 4. OS Update Details (Hotfixes) ---
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
        elements.append(build_table(hotfix_rows))
        elements.append(Spacer(1, 12))

        # --- 5. Drive Details ---
        elements.append(Paragraph("Drive Details", section_style))
        elements.append(build_table([
            [Paragraph("Drive Name", cell_b), Paragraph(data.drive_name, cell_n)],
        ]))
        elements.append(Spacer(1, 12))

        # --- 6. Antivirus ---
        elements.append(Paragraph("Antivirus", section_style))
        elements.append(build_table([
            [Paragraph("Antivirus Products", cell_b), Paragraph(av_str if av_str else "Not Detected", cell_n)],
        ]))
        elements.append(Spacer(1, 12))

        # --- 7. Printer Details ---
        elements.append(Paragraph("Printer Details", section_style))
        printer_rows = []
        if data.printers:
            for idx, p in enumerate(data.printers):
                if isinstance(p, PrinterDetail):
                    printer_type = get_printer_type(p.port_name)
                    printer_rows.append([Paragraph(str(idx + 1), cell_b), Paragraph("", cell_n)])
                    printer_rows.append([Paragraph("Name", cell_b), Paragraph(p.name, cell_n)])
                    printer_rows.append([Paragraph("Printer Type", cell_b), Paragraph(printer_type, cell_n)])
                    printer_rows.append([Paragraph("System Name", cell_b), Paragraph(p.system_name, cell_n)])
                    printer_rows.append([Paragraph("Enable BIDI", cell_b), Paragraph(p.enable_bidi, cell_n)])
                    printer_rows.append([Paragraph("Port Name", cell_b), Paragraph(p.port_name, cell_n)])
                else:
                    printer_rows.append([Paragraph(f"Printer #{idx+1}", cell_b), Paragraph(str(p), cell_n)])
            printer_rows.append([Paragraph("Total Printers Connected", cell_b), Paragraph(str(len(data.printers)), cell_n)])
        else:
            printer_rows.append([Paragraph("No active printers connected", cell_b), Paragraph("-", cell_n)])
        elements.append(build_table(printer_rows))
        elements.append(Spacer(1, 12))

        # --- 8. Disk Information ---
        elements.append(Paragraph("Disk Information", section_style))
        disk_rows = []
        if data.disk_info:
            disk_rows.append([Paragraph("Drive", cell_b), Paragraph("Total / Used / Free", cell_b)])
            for d in data.disk_info:
                disk_rows.append([Paragraph(d.drive, cell_n), Paragraph(f"{d.total} total  |  {d.used} used  |  {d.free} free", cell_n)])
        else:
            disk_rows.append([Paragraph("No disk information collected", cell_b), Paragraph("-", cell_n)])
        elements.append(build_table(disk_rows))
        elements.append(Spacer(1, 12))

        # --- 9. Local User Accounts ---
        elements.append(Paragraph("Local User Accounts", section_style))
        user_rows = [[Paragraph("Username", cell_b), Paragraph("Enabled / Admin", cell_b)]]
        if data.local_users:
            for u in data.local_users:
                user_rows.append([Paragraph(u.name, cell_n), Paragraph(f"Enabled: {u.enabled}  |  Admin: {u.admin}", cell_n)])
        else:
            user_rows = [[Paragraph("No local user data collected", cell_b), Paragraph("-", cell_n)]]
        elements.append(build_table(user_rows))
        elements.append(Spacer(1, 12))

        # --- 10. Running Services ---
        elements.append(Paragraph("Running Services", section_style))
        svc_rows = [[Paragraph("Service Name", cell_b), Paragraph("Start Type", cell_b)]]
        if data.running_services:
            for svc in data.running_services:
                label = svc.display_name if svc.display_name and svc.display_name != svc.name else svc.name
                svc_rows.append([Paragraph(label, cell_n), Paragraph(svc.start_type or "-", cell_n)])
        else:
            svc_rows = [[Paragraph("No running services collected", cell_b), Paragraph("-", cell_n)]]
        elements.append(build_table(svc_rows))
        elements.append(Spacer(1, 12))

        # --- 11. Open Ports ---
        elements.append(Paragraph("Open / Listening Ports", section_style))
        port_rows = [[Paragraph("Port", cell_b), Paragraph("Protocol", cell_b)]]
        if data.open_ports:
            for op in data.open_ports:
                port_rows.append([Paragraph(op.port, cell_n), Paragraph(op.protocol or "-", cell_n)])
        else:
            port_rows = [[Paragraph("No open port data collected", cell_b), Paragraph("-", cell_n)]]
        elements.append(build_table(port_rows))
        elements.append(Spacer(1, 12))

        # --- 12. Security Posture ---
        elements.append(Paragraph("Security Posture", section_style))
        sp = data.security_posture
        sec_rows = []
        if sp:
            if sp.bitlocker:        sec_rows.append([Paragraph("BitLocker", cell_b),        Paragraph(sp.bitlocker, cell_n)])
            if sp.windows_firewall: sec_rows.append([Paragraph("Windows Firewall", cell_b), Paragraph(sp.windows_firewall, cell_n)])
            if sp.uac_enabled:      sec_rows.append([Paragraph("UAC Enabled", cell_b),      Paragraph(sp.uac_enabled, cell_n)])
            if sp.filevault:        sec_rows.append([Paragraph("FileVault", cell_b),         Paragraph(sp.filevault, cell_n)])
            if sp.gatekeeper:       sec_rows.append([Paragraph("Gatekeeper", cell_b),        Paragraph(sp.gatekeeper, cell_n)])
            if sp.sip:              sec_rows.append([Paragraph("System Integrity Protection (SIP)", cell_b), Paragraph(sp.sip, cell_n)])
            if sp.apparmor:         sec_rows.append([Paragraph("AppArmor", cell_b),          Paragraph(sp.apparmor, cell_n)])
            if sp.selinux:          sec_rows.append([Paragraph("SELinux", cell_b),           Paragraph(sp.selinux, cell_n)])
        if not sec_rows:
            sec_rows.append([Paragraph("No security posture data collected", cell_b), Paragraph("-", cell_n)])
        elements.append(build_table(sec_rows))
        elements.append(Spacer(1, 12))

        # --- 13. Docker ---
        elements.append(Paragraph("Docker / Containers", section_style))
        di = data.docker_info
        docker_rows = []
        if di and di.version:
            docker_rows.append([Paragraph("Docker Version", cell_b), Paragraph(di.version, cell_n)])
            docker_rows.append([Paragraph("Running Containers", cell_b), Paragraph(str(di.running_containers), cell_n)])
            if di.containers:
                docker_rows.append([Paragraph("Container Names", cell_b), Paragraph(", ".join(di.containers), cell_n)])
        else:
            docker_rows.append([Paragraph("Docker not installed or not running", cell_b), Paragraph("-", cell_n)])
        elements.append(build_table(docker_rows))
        elements.append(Spacer(1, 12))

        # --- 14. Installed Applications ---
        elements.append(Paragraph("Installed Applications", section_style))
        app_rows = [[Paragraph("Application", cell_b), Paragraph("Version", cell_b)]]
        if data.installed_apps:
            for app in data.installed_apps[:100]:
                app_rows.append([Paragraph(app.name[:60], cell_n), Paragraph(app.version or "-", cell_n)])
            if len(data.installed_apps) > 100:
                app_rows.append([Paragraph(f"... and {len(data.installed_apps) - 100} more", cell_n), Paragraph("", cell_n)])
        else:
            app_rows = [[Paragraph("No installed application data collected", cell_b), Paragraph("-", cell_n)]]
        elements.append(build_table(app_rows))
        elements.append(Spacer(1, 12))

        # --- 15. Running Processes ---
        elements.append(Paragraph("Running Processes", section_style))
        proc_rows = [[Paragraph("PID", cell_b), Paragraph("Process Name", cell_b), Paragraph("User", cell_b), Paragraph("CPU%", cell_b), Paragraph("Mem%", cell_b)]]
        if data.running_processes:
            for proc in data.running_processes[:50]:
                proc_rows.append([
                    Paragraph(proc.pid, cell_n),
                    Paragraph(proc.name, cell_n),
                    Paragraph(proc.user, cell_n),
                    Paragraph(proc.cpu, cell_n),
                    Paragraph(proc.memory, cell_n),
                ])
        else:
            proc_rows = [[Paragraph("No process data collected", cell_b), Paragraph("-", cell_n)]]
        elements.append(build_table(proc_rows, col_widths=[55, 190, 100, 75, 84]))
        elements.append(Spacer(1, 12))

        # --- 16. SSL Certificates ---
        elements.append(Paragraph("SSL Certificates", section_style))
        cert_rows = [[Paragraph("Subject", cell_b), Paragraph("Expiry", cell_b)]]
        if data.ssl_certificates:
            for cert in data.ssl_certificates:
                cert_rows.append([Paragraph(cert.subject[:60], cell_n), Paragraph(cert.expiry or "-", cell_n)])
        else:
            cert_rows = [[Paragraph("No SSL certificates collected", cell_b), Paragraph("-", cell_n)]]
        elements.append(build_table(cert_rows))
        elements.append(Spacer(1, 12))

        # --- 17. Browser Extensions ---
        elements.append(Paragraph("Browser Extensions", section_style))
        ext_rows = [[Paragraph("Browser / Extension", cell_b), Paragraph("Version", cell_b)]]
        if data.browser_extensions:
            for ext in data.browser_extensions:
                ext_rows.append([Paragraph(f"{ext.browser}: {ext.name[:50]}", cell_n), Paragraph(ext.version or "-", cell_n)])
        else:
            ext_rows = [[Paragraph("No browser extensions collected", cell_b), Paragraph("-", cell_n)]]
        elements.append(build_table(ext_rows))
        elements.append(Spacer(1, 12))

        # --- 18. System Event Logs ---
        elements.append(Paragraph("System Event Logs", section_style))
        log_rows = [[Paragraph("Time / Source", cell_b), Paragraph("Level / Message", cell_b)]]
        if data.event_logs:
            for log in data.event_logs:
                log_rows.append([Paragraph(f"{log.time}\n{log.source}", cell_n), Paragraph(f"{log.level}: {log.message[:100]}", cell_n)])
        else:
            log_rows = [[Paragraph("No event log data collected", cell_b), Paragraph("-", cell_n)]]
        elements.append(build_table(log_rows))
        elements.append(Spacer(1, 12))

        # --- 19. GPU Information ---
        elements.append(Paragraph("GPU Information", section_style))
        gpu_rows = []
        if data.gpu_info:
            for gpu in data.gpu_info:
                gpu_rows.append([Paragraph("GPU Name", cell_b), Paragraph(gpu.name or "-", cell_n)])
                gpu_rows.append([Paragraph("Driver Version", cell_b), Paragraph(gpu.driver_version or "-", cell_n)])
                gpu_rows.append([Paragraph("VRAM", cell_b), Paragraph(gpu.vram or "-", cell_n)])
        else:
            gpu_rows.append([Paragraph("No GPU data collected", cell_b), Paragraph("-", cell_n)])
        elements.append(build_table(gpu_rows))
        elements.append(Spacer(1, 12))

        # --- 20. Battery Information ---
        elements.append(Paragraph("Battery Information", section_style))
        batt = data.battery_info
        if batt and batt.name:
            batt_rows = [
                [Paragraph("Battery Name", cell_b), Paragraph(batt.name or "-", cell_n)],
                [Paragraph("Status", cell_b), Paragraph(batt.status or "-", cell_n)],
                [Paragraph("Estimated Charge", cell_b), Paragraph(batt.estimated_charge or "-", cell_n)],
            ]
        else:
            batt_rows = [[Paragraph("No battery detected or not applicable", cell_b), Paragraph("-", cell_n)]]
        elements.append(build_table(batt_rows))
        elements.append(Spacer(1, 12))

        # --- 21. Local Groups ---
        elements.append(Paragraph("Local Groups", section_style))
        grp_rows = [[Paragraph("Group Name", cell_b), Paragraph("Members", cell_b)]]
        if data.local_groups:
            for grp in data.local_groups:
                grp_rows.append([Paragraph(grp.name, cell_n), Paragraph(grp.members or "-", cell_n)])
        else:
            grp_rows = [[Paragraph("No group data collected", cell_b), Paragraph("-", cell_n)]]
        elements.append(build_table(grp_rows))
        elements.append(Spacer(1, 12))

        # --- 22. Startup Items ---
        elements.append(Paragraph("Startup Items", section_style))
        si_rows = [[Paragraph("Name", cell_b), Paragraph("Command / Location", cell_b)]]
        if data.startup_items:
            for si in data.startup_items:
                si_rows.append([Paragraph(si.name[:40], cell_n), Paragraph(f"{si.command[:60]}  [{si.location}]", cell_n)])
        else:
            si_rows = [[Paragraph("No startup items collected", cell_b), Paragraph("-", cell_n)]]
        elements.append(build_table(si_rows))
        elements.append(Spacer(1, 12))

        # --- 23. Network Connections ---
        elements.append(Paragraph("Active Network Connections", section_style))
        nc_rows = [[Paragraph("Protocol / State", cell_b), Paragraph("Local → Remote", cell_b)]]
        if data.network_connections:
            for nc in data.network_connections[:60]:
                nc_rows.append([Paragraph(f"{nc.protocol} / {nc.state}", cell_n),
                                 Paragraph(f"{nc.local_address}:{nc.local_port} → {nc.remote_address}:{nc.remote_port}", cell_n)])
        else:
            nc_rows = [[Paragraph("No connection data collected", cell_b), Paragraph("-", cell_n)]]
        elements.append(build_table(nc_rows))
        elements.append(Spacer(1, 12))

        # --- 24. Routing Table ---
        elements.append(Paragraph("Routing Table", section_style))
        rt_rows = [[Paragraph("Destination", cell_b), Paragraph("Gateway / Interface / Metric", cell_b)]]
        if data.routing_table:
            for rt in data.routing_table:
                rt_rows.append([Paragraph(rt.destination, cell_n),
                                 Paragraph(f"{rt.gateway or '-'}  via {rt.interface or '-'}  metric {rt.metric or '-'}", cell_n)])
        else:
            rt_rows = [[Paragraph("No routing table data collected", cell_b), Paragraph("-", cell_n)]]
        elements.append(build_table(rt_rows))
        elements.append(Spacer(1, 12))

        # --- 25. Filesystem Info ---
        elements.append(Paragraph("Filesystem Information", section_style))
        fs_rows = [[Paragraph("Device / Type / Mount", cell_b), Paragraph("Total / Used / Free / Use%", cell_b)]]
        if data.filesystem_info:
            for fs in data.filesystem_info:
                fs_rows.append([Paragraph(f"{fs.device}\n{fs.fs_type}  →  {fs.mount_point}", cell_n),
                                 Paragraph(f"{fs.total}  |  {fs.used}  |  {fs.free}  |  {fs.use_percent}", cell_n)])
        else:
            fs_rows = [[Paragraph("No filesystem data collected", cell_b), Paragraph("-", cell_n)]]
        elements.append(build_table(fs_rows))
        elements.append(Spacer(1, 12))

        # --- 26. File Integrity ---
        elements.append(Paragraph("File Integrity (SHA-256)", section_style))
        fi_rows = [[Paragraph("File Path", cell_b), Paragraph("SHA-256 Hash / Modified", cell_b)]]
        if data.file_integrity:
            for fi in data.file_integrity:
                fi_rows.append([Paragraph(fi.path, cell_n),
                                 Paragraph(f"{fi.sha256[:32]}...\n{fi.modified}  |  {fi.size}", cell_n)])
        else:
            fi_rows = [[Paragraph("No file integrity data collected", cell_b), Paragraph("-", cell_n)]]
        elements.append(build_table(fi_rows))
        elements.append(Spacer(1, 12))

        # --- 27. Process Events ---
        elements.append(Paragraph("Process Events", section_style))
        pe_rows = [[Paragraph("Time / User", cell_b), Paragraph("Process / Command", cell_b)]]
        if data.process_events:
            for pe in data.process_events:
                pe_rows.append([Paragraph(f"{pe.time}\n{pe.user}", cell_n),
                                 Paragraph(f"{pe.process_name}  (PID {pe.pid})\n{pe.command_line[:80]}", cell_n)])
        else:
            pe_rows = [[Paragraph("No process event data collected", cell_b), Paragraph("-", cell_n)]]
        elements.append(build_table(pe_rows))
        elements.append(Spacer(1, 12))

        # --- 28. Security Policy ---
        elements.append(Paragraph("Security Policy", section_style))
        sp2 = data.security_policy
        spol_rows = []
        if sp2:
            if sp2.min_password_length:   spol_rows.append([Paragraph("Min Password Length", cell_b),    Paragraph(sp2.min_password_length, cell_n)])
            if sp2.password_complexity:   spol_rows.append([Paragraph("Password Complexity", cell_b),    Paragraph(sp2.password_complexity, cell_n)])
            if sp2.lockout_threshold:     spol_rows.append([Paragraph("Lockout Threshold", cell_b),      Paragraph(sp2.lockout_threshold, cell_n)])
            if sp2.screen_lock_timeout:   spol_rows.append([Paragraph("Screen Lock Timeout", cell_b),    Paragraph(sp2.screen_lock_timeout, cell_n)])
            if sp2.auto_updates_enabled:  spol_rows.append([Paragraph("Auto Updates", cell_b),           Paragraph(sp2.auto_updates_enabled, cell_n)])
            if sp2.remote_login_enabled:  spol_rows.append([Paragraph("Remote Login", cell_b),           Paragraph(sp2.remote_login_enabled, cell_n)])
            if sp2.antivirus_enabled:     spol_rows.append([Paragraph("Antivirus Enabled", cell_b),      Paragraph(sp2.antivirus_enabled, cell_n)])
            if sp2.antivirus_definitions: spol_rows.append([Paragraph("AV Definitions Updated", cell_b), Paragraph(sp2.antivirus_definitions, cell_n)])
        if not spol_rows:
            spol_rows.append([Paragraph("No security policy data collected", cell_b), Paragraph("-", cell_n)])
        elements.append(build_table(spol_rows))
        elements.append(Spacer(1, 12))

        # --- 29. Container Images ---
        elements.append(Paragraph("Container Images", section_style))
        ci_rows = [[Paragraph("Repository : Tag", cell_b), Paragraph("Image ID / Size / Created", cell_b)]]
        if data.container_images:
            for ci in data.container_images:
                ci_rows.append([Paragraph(f"{ci.repository}:{ci.tag}", cell_n),
                                 Paragraph(f"{ci.image_id}  |  {ci.size}  |  {ci.created}", cell_n)])
        else:
            ci_rows = [[Paragraph("No container images found", cell_b), Paragraph("-", cell_n)]]
        elements.append(build_table(ci_rows))
        elements.append(Spacer(1, 12))

        doc.build(elements, onFirstPage=draw_page_decorations, onLaterPages=draw_page_decorations)
        logger.info(f"PDF compliance report successfully built: {pdf_path}")
    except Exception as e:
        logger.error(f"Failed to generate InfraPulse PDF Report: {e}")
        generation_errors.append("PDF assortment report generation failed")

    # Build XML compliance document
    try:
        root = ET.Element("InfraPulseComplianceAudit", version="2.0.0")

        meta = ET.SubElement(root, "CollectionDetails")
        ET.SubElement(meta, "CollectedBy").text = officer_name

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
                ET.SubElement(a_el, "IPv6Address").text = adapter.ipv6_address
                ET.SubElement(a_el, "TemporaryIPv6Address").text = adapter.temp_ipv6_address
                ET.SubElement(a_el, "LinkLocalIPv6Address").text = adapter.link_local_ipv6
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

        disk_xml = ET.SubElement(root, "DiskInfo")
        for d in data.disk_info:
            d_el = ET.SubElement(disk_xml, "Disk")
            ET.SubElement(d_el, "Drive").text = d.drive
            ET.SubElement(d_el, "Total").text = d.total
            ET.SubElement(d_el, "Used").text = d.used
            ET.SubElement(d_el, "Free").text = d.free

        users_xml = ET.SubElement(root, "LocalUsers")
        for u in data.local_users:
            u_el = ET.SubElement(users_xml, "User")
            ET.SubElement(u_el, "Name").text = u.name
            ET.SubElement(u_el, "Enabled").text = u.enabled
            ET.SubElement(u_el, "Admin").text = u.admin

        svcs_xml = ET.SubElement(root, "RunningServices")
        for svc in data.running_services:
            s_el = ET.SubElement(svcs_xml, "Service")
            ET.SubElement(s_el, "Name").text = svc.name
            ET.SubElement(s_el, "DisplayName").text = svc.display_name
            ET.SubElement(s_el, "StartType").text = svc.start_type

        ports_xml = ET.SubElement(root, "OpenPorts")
        for op in data.open_ports:
            op_el = ET.SubElement(ports_xml, "Port")
            ET.SubElement(op_el, "Port").text = op.port
            ET.SubElement(op_el, "Protocol").text = op.protocol
            ET.SubElement(op_el, "PID").text = op.pid

        if data.security_posture:
            sp = data.security_posture
            sp_xml = ET.SubElement(root, "SecurityPosture")
            ET.SubElement(sp_xml, "BitLocker").text = sp.bitlocker
            ET.SubElement(sp_xml, "WindowsFirewall").text = sp.windows_firewall
            ET.SubElement(sp_xml, "UACEnabled").text = sp.uac_enabled
            ET.SubElement(sp_xml, "FileVault").text = sp.filevault
            ET.SubElement(sp_xml, "Gatekeeper").text = sp.gatekeeper
            ET.SubElement(sp_xml, "SIP").text = sp.sip
            ET.SubElement(sp_xml, "AppArmor").text = sp.apparmor
            ET.SubElement(sp_xml, "SELinux").text = sp.selinux

        if data.docker_info:
            di = data.docker_info
            docker_xml = ET.SubElement(root, "Docker")
            ET.SubElement(docker_xml, "Version").text = di.version
            ET.SubElement(docker_xml, "RunningContainers").text = str(di.running_containers)
            ctrs_xml = ET.SubElement(docker_xml, "Containers")
            for c in di.containers:
                ET.SubElement(ctrs_xml, "Container").text = c

        apps_xml = ET.SubElement(root, "InstalledApplications")
        for app in data.installed_apps:
            a_el = ET.SubElement(apps_xml, "Application")
            ET.SubElement(a_el, "Name").text = app.name
            ET.SubElement(a_el, "Version").text = app.version
            ET.SubElement(a_el, "Publisher").text = app.publisher

        procs_xml = ET.SubElement(root, "RunningProcesses")
        for proc in data.running_processes:
            p_el = ET.SubElement(procs_xml, "Process")
            ET.SubElement(p_el, "PID").text = proc.pid
            ET.SubElement(p_el, "Name").text = proc.name
            ET.SubElement(p_el, "CPU").text = proc.cpu
            ET.SubElement(p_el, "Memory").text = proc.memory

        ssl_xml = ET.SubElement(root, "SSLCertificates")
        for cert in data.ssl_certificates:
            c_el = ET.SubElement(ssl_xml, "Certificate")
            ET.SubElement(c_el, "Subject").text = cert.subject
            ET.SubElement(c_el, "Issuer").text = cert.issuer
            ET.SubElement(c_el, "Expiry").text = cert.expiry
            ET.SubElement(c_el, "Thumbprint").text = cert.thumbprint

        exts_xml = ET.SubElement(root, "BrowserExtensions")
        for ext in data.browser_extensions:
            e_el = ET.SubElement(exts_xml, "Extension")
            ET.SubElement(e_el, "Browser").text = ext.browser
            ET.SubElement(e_el, "Name").text = ext.name
            ET.SubElement(e_el, "Version").text = ext.version
            ET.SubElement(e_el, "ExtensionID").text = ext.extension_id

        logs_xml = ET.SubElement(root, "EventLogs")
        for log in data.event_logs:
            l_el = ET.SubElement(logs_xml, "Event")
            ET.SubElement(l_el, "Time").text = log.time
            ET.SubElement(l_el, "Level").text = log.level
            ET.SubElement(l_el, "Source").text = log.source
            ET.SubElement(l_el, "Message").text = log.message

        gpu_xml = ET.SubElement(root, "GPUInfo")
        for gpu in data.gpu_info:
            g_el = ET.SubElement(gpu_xml, "GPU")
            ET.SubElement(g_el, "Name").text = gpu.name
            ET.SubElement(g_el, "DriverVersion").text = gpu.driver_version
            ET.SubElement(g_el, "VRAM").text = gpu.vram

        if data.battery_info:
            batt_xml = ET.SubElement(root, "BatteryInfo")
            ET.SubElement(batt_xml, "Name").text = data.battery_info.name
            ET.SubElement(batt_xml, "Status").text = data.battery_info.status
            ET.SubElement(batt_xml, "EstimatedCharge").text = data.battery_info.estimated_charge

        grps_xml = ET.SubElement(root, "LocalGroups")
        for grp in data.local_groups:
            grp_el = ET.SubElement(grps_xml, "Group")
            ET.SubElement(grp_el, "Name").text = grp.name
            ET.SubElement(grp_el, "Description").text = grp.description
            ET.SubElement(grp_el, "Members").text = grp.members

        si_xml = ET.SubElement(root, "StartupItems")
        for si in data.startup_items:
            si_el = ET.SubElement(si_xml, "Item")
            ET.SubElement(si_el, "Name").text = si.name
            ET.SubElement(si_el, "Command").text = si.command
            ET.SubElement(si_el, "Location").text = si.location
            ET.SubElement(si_el, "User").text = si.user

        nc_xml = ET.SubElement(root, "NetworkConnections")
        for nc in data.network_connections:
            nc_el = ET.SubElement(nc_xml, "Connection")
            ET.SubElement(nc_el, "Protocol").text = nc.protocol
            ET.SubElement(nc_el, "LocalAddress").text = nc.local_address
            ET.SubElement(nc_el, "LocalPort").text = nc.local_port
            ET.SubElement(nc_el, "RemoteAddress").text = nc.remote_address
            ET.SubElement(nc_el, "RemotePort").text = nc.remote_port
            ET.SubElement(nc_el, "State").text = nc.state
            ET.SubElement(nc_el, "PID").text = nc.pid

        rt_xml = ET.SubElement(root, "RoutingTable")
        for rt in data.routing_table:
            rt_el = ET.SubElement(rt_xml, "Route")
            ET.SubElement(rt_el, "Destination").text = rt.destination
            ET.SubElement(rt_el, "Gateway").text = rt.gateway
            ET.SubElement(rt_el, "Interface").text = rt.interface
            ET.SubElement(rt_el, "Metric").text = rt.metric

        fs_xml = ET.SubElement(root, "FilesystemInfo")
        for fs in data.filesystem_info:
            fs_el = ET.SubElement(fs_xml, "Filesystem")
            ET.SubElement(fs_el, "Device").text = fs.device
            ET.SubElement(fs_el, "MountPoint").text = fs.mount_point
            ET.SubElement(fs_el, "FSType").text = fs.fs_type
            ET.SubElement(fs_el, "Total").text = fs.total
            ET.SubElement(fs_el, "Used").text = fs.used
            ET.SubElement(fs_el, "Free").text = fs.free
            ET.SubElement(fs_el, "UsePercent").text = fs.use_percent

        fi_xml = ET.SubElement(root, "FileIntegrity")
        for fi in data.file_integrity:
            fi_el = ET.SubElement(fi_xml, "File")
            ET.SubElement(fi_el, "Path").text = fi.path
            ET.SubElement(fi_el, "SHA256").text = fi.sha256
            ET.SubElement(fi_el, "Size").text = fi.size
            ET.SubElement(fi_el, "Modified").text = fi.modified

        pe_xml = ET.SubElement(root, "ProcessEvents")
        for pe in data.process_events:
            pe_el = ET.SubElement(pe_xml, "Event")
            ET.SubElement(pe_el, "Time").text = pe.time
            ET.SubElement(pe_el, "PID").text = pe.pid
            ET.SubElement(pe_el, "ParentPID").text = pe.parent_pid
            ET.SubElement(pe_el, "ProcessName").text = pe.process_name
            ET.SubElement(pe_el, "CommandLine").text = pe.command_line
            ET.SubElement(pe_el, "User").text = pe.user

        if data.security_policy:
            sp2 = data.security_policy
            sp2_xml = ET.SubElement(root, "SecurityPolicy")
            ET.SubElement(sp2_xml, "MinPasswordLength").text = sp2.min_password_length
            ET.SubElement(sp2_xml, "PasswordComplexity").text = sp2.password_complexity
            ET.SubElement(sp2_xml, "LockoutThreshold").text = sp2.lockout_threshold
            ET.SubElement(sp2_xml, "ScreenLockTimeout").text = sp2.screen_lock_timeout
            ET.SubElement(sp2_xml, "AutoUpdatesEnabled").text = sp2.auto_updates_enabled
            ET.SubElement(sp2_xml, "RemoteLoginEnabled").text = sp2.remote_login_enabled
            ET.SubElement(sp2_xml, "AntivirusEnabled").text = sp2.antivirus_enabled
            ET.SubElement(sp2_xml, "AntivirusDefinitions").text = sp2.antivirus_definitions

        ci_xml = ET.SubElement(root, "ContainerImages")
        for ci in data.container_images:
            ci_el = ET.SubElement(ci_xml, "Image")
            ET.SubElement(ci_el, "Repository").text = ci.repository
            ET.SubElement(ci_el, "Tag").text = ci.tag
            ET.SubElement(ci_el, "ImageID").text = ci.image_id
            ET.SubElement(ci_el, "Size").text = ci.size
            ET.SubElement(ci_el, "Created").text = ci.created

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
        raise HTTPException(status_code=500, detail="Assortment report generation failed.")

    # Cache completion state and file references
    with session_lock:
        sessions[cid] = {
            **sessions.get(cid, {}),
            "status": "completed",
            "error": None,
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
def download_report(client_id: str = Query(...), report_format: str = Query("pdf", alias="format"), portal_token: Optional[str] = Cookie(None)):
    cid = validate_client_id(client_id)
    session = verify_portal_token(cid, portal_token)
    if session.get("status") != "completed":
        raise HTTPException(status_code=404, detail="Assortment report is not ready or has not been found.")

    if report_format.lower() == "pdf":
        file_value = session.get("pdf_path")
        if not file_value:
            raise HTTPException(status_code=404, detail="PDF report does not exist on disk.")
        file_path = Path(file_value)
        if not file_path.exists() or not file_path.is_file():
            raise HTTPException(status_code=404, detail="PDF report does not exist on disk.")
        return FileResponse(file_path, media_type="application/pdf", filename=os.path.basename(file_path))

    elif report_format.lower() == "xml":
        file_value = session.get("xml_path")
        if not file_value:
            raise HTTPException(status_code=404, detail="XML report does not exist on disk.")
        file_path = Path(file_value)
        if not file_path.exists() or not file_path.is_file():
            raise HTTPException(status_code=404, detail="XML report does not exist on disk.")
        return FileResponse(file_path, media_type="application/xml", filename=os.path.basename(file_path))

    else:
        raise HTTPException(status_code=400, detail="Invalid report format. Use 'pdf' or 'xml'.")

