import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime, ForeignKey, Integer, JSON, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.database import Base


class Audit(Base):
    __tablename__ = "audits"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    verification_token = Column(String(64), unique=True, nullable=False, index=True)
    hostname = Column(String(255))
    username = Column(String(255))
    submitted_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    ip_address = Column(String(45))
    status = Column(String(20), default="pending")

    # NSDL TIN FC details (configurable per audit)
    branch_name = Column(String(500), default="")
    branch_code = Column(String(50), default="")
    branch_officer = Column(String(255), default="")

    system_info = relationship("SystemInfo", back_populates="audit", uselist=False, cascade="all, delete-orphan")
    hardware_info = relationship("HardwareInfo", back_populates="audit", uselist=False, cascade="all, delete-orphan")
    software_entries = relationship("SoftwareEntry", back_populates="audit", cascade="all, delete-orphan")
    network_info = relationship("NetworkInfo", back_populates="audit", uselist=False, cascade="all, delete-orphan")
    security_info = relationship("SecurityInfo", back_populates="audit", uselist=False, cascade="all, delete-orphan")
    peripheral_info = relationship("PeripheralInfo", back_populates="audit", uselist=False, cascade="all, delete-orphan")
    reports = relationship("GeneratedReport", back_populates="audit", cascade="all, delete-orphan")


class SystemInfo(Base):
    __tablename__ = "system_info"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    audit_id = Column(UUID(as_uuid=True), ForeignKey("audits.id", ondelete="CASCADE"), nullable=False)
    os_name = Column(String(255))
    os_version = Column(String(255))
    os_architecture = Column(String(50))
    os_build = Column(String(100))
    hostname = Column(String(255))
    cs_name = Column(String(255))
    license_status = Column(String(255))
    logged_in_user = Column(String(255))
    timezone = Column(String(100))
    installed_browsers = Column(JSON)
    startup_programs = Column(JSON)
    os_updates = Column(JSON)  # NSDL format: list of {caption, cs_name, description, fix_id, installed_on}

    audit = relationship("Audit", back_populates="system_info")


class HardwareInfo(Base):
    __tablename__ = "hardware_info"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    audit_id = Column(UUID(as_uuid=True), ForeignKey("audits.id", ondelete="CASCADE"), nullable=False)
    cpu_name = Column(String(255))
    cpu_cores = Column(Integer)
    cpu_threads = Column(Integer)
    cpu_frequency = Column(String(100))
    ram_total = Column(String(50))
    ram_available = Column(String(50))
    disk_drives = Column(JSON)
    cd_drives = Column(JSON)  # NSDL: CD/DVD drive detection
    compression_utilities = Column(JSON)  # NSDL: compression utility check
    motherboard = Column(String(255))
    bios_serial = Column(String(255))
    machine_uuid = Column(String(255))

    audit = relationship("Audit", back_populates="hardware_info")


class SoftwareEntry(Base):
    __tablename__ = "software_entries"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    audit_id = Column(UUID(as_uuid=True), ForeignKey("audits.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(500))
    version = Column(String(100))
    publisher = Column(String(255))

    audit = relationship("Audit", back_populates="software_entries")


class NetworkInfo(Base):
    __tablename__ = "network_info"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    audit_id = Column(UUID(as_uuid=True), ForeignKey("audits.id", ondelete="CASCADE"), nullable=False)
    mac_address = Column(String(50))  # Raw: E83935524931
    mac_address_formatted = Column(String(50))  # Formatted: e8:39:35:52:49:31
    ip_address = Column(String(45))
    adapters = Column(JSON)

    audit = relationship("Audit", back_populates="network_info")


class SecurityInfo(Base):
    __tablename__ = "security_info"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    audit_id = Column(UUID(as_uuid=True), ForeignKey("audits.id", ondelete="CASCADE"), nullable=False)
    antivirus_name = Column(String(255))
    antivirus_status = Column(String(100))
    antivirus_products = Column(JSON)
    firewall_status = Column(String(100))
    defender_status = Column(String(100))
    uac_enabled = Column(Boolean)

    audit = relationship("Audit", back_populates="security_info")


class PeripheralInfo(Base):
    __tablename__ = "peripheral_info"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    audit_id = Column(UUID(as_uuid=True), ForeignKey("audits.id", ondelete="CASCADE"), nullable=False)
    printers = Column(JSON)  # NSDL: {name, system_name, enable_bidi, extended_printer_status, port_name}
    total_printers = Column(Integer, default=0)
    usb_devices = Column(JSON)

    audit = relationship("Audit", back_populates="peripheral_info")


class GeneratedReport(Base):
    __tablename__ = "generated_reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    audit_id = Column(UUID(as_uuid=True), ForeignKey("audits.id", ondelete="CASCADE"), nullable=False)
    file_path = Column(String(500), nullable=False)
    generated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    audit = relationship("Audit", back_populates="reports")
