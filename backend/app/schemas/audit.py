from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class OsUpdatePayload(BaseModel):
    caption: Optional[str] = None
    cs_name: Optional[str] = None
    description: Optional[str] = None
    fix_id: Optional[str] = None
    installed_on: Optional[str] = None


class SystemInfoPayload(BaseModel):
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    os_architecture: Optional[str] = None
    os_build: Optional[str] = None
    hostname: Optional[str] = None
    cs_name: Optional[str] = None
    license_status: Optional[str] = None
    logged_in_user: Optional[str] = None
    timezone: Optional[str] = None
    installed_browsers: Optional[list] = None
    startup_programs: Optional[list] = None


class HardwareInfoPayload(BaseModel):
    cpu_name: Optional[str] = None
    cpu_cores: Optional[int] = None
    cpu_threads: Optional[int] = None
    cpu_frequency: Optional[str] = None
    ram_total: Optional[str] = None
    ram_available: Optional[str] = None
    disk_drives: Optional[list] = None
    cd_drives: Optional[list] = None
    compression_utilities: Optional[list] = None
    motherboard: Optional[str] = None
    bios_serial: Optional[str] = None
    machine_uuid: Optional[str] = None


class SoftwareEntryPayload(BaseModel):
    name: Optional[str] = None
    version: Optional[str] = None
    publisher: Optional[str] = None


class NetworkInfoPayload(BaseModel):
    mac_address: Optional[str] = None
    mac_address_formatted: Optional[str] = None
    ip_address: Optional[str] = None
    adapters: Optional[list] = None


class SecurityInfoPayload(BaseModel):
    antivirus_name: Optional[str] = None
    antivirus_status: Optional[str] = None
    antivirus_products: Optional[list] = None
    firewall_status: Optional[str] = None
    defender_status: Optional[str] = None
    uac_enabled: Optional[bool] = None


class PeripheralInfoPayload(BaseModel):
    printers: Optional[list] = None
    total_printers: Optional[int] = 0
    usb_devices: Optional[list] = None


class AuditUploadPayload(BaseModel):
    verification_token: str
    system_info: SystemInfoPayload
    hardware_info: HardwareInfoPayload
    software_entries: Optional[list[SoftwareEntryPayload]] = []
    network_info: NetworkInfoPayload
    security_info: SecurityInfoPayload
    peripheral_info: PeripheralInfoPayload
    os_updates: Optional[list[OsUpdatePayload]] = []


class AuditResponse(BaseModel):
    id: str
    verification_token: str
    hostname: Optional[str]
    username: Optional[str]
    submitted_at: datetime
    ip_address: Optional[str]
    status: str

    class Config:
        from_attributes = True


class AuditDetailResponse(AuditResponse):
    system_info: Optional[dict] = None
    hardware_info: Optional[dict] = None
    software_entries: Optional[list[dict]] = None
    network_info: Optional[dict] = None
    security_info: Optional[dict] = None
    peripheral_info: Optional[dict] = None
    os_updates: Optional[list[dict]] = None
