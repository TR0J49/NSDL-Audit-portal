"""
System Audit Agent - Collects comprehensive Windows system information
matching NSDL e-Governance Inspection Report format.
Uploads data to the audit platform backend.
"""

import json
import logging
import os
import platform
import socket
import subprocess
import sys
import time
import uuid
import winreg
from datetime import datetime, timezone

import psutil
import requests
import wmi

LOG_DIR = os.path.join(os.getenv("TEMP", "."), "SystemAudit")
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "audit_agent.log")),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


class SystemAuditor:
    def __init__(self):
        self.wmi_obj = wmi.WMI()
        self.data = {}

    def collect_all(self, progress_callback=None):
        steps = [
            ("Operating System", self.collect_os_info),
            ("OS Updates", self.collect_os_updates),
            ("Hardware & Drives", self.collect_hardware_info),
            ("Network", self.collect_network_info),
            ("Installed Software", self.collect_software_info),
            ("Security & Antivirus", self.collect_security_info),
            ("Printers & Peripherals", self.collect_peripheral_info),
        ]
        for i, (name, func) in enumerate(steps):
            logger.info(f"Collecting: {name}")
            if progress_callback:
                progress_callback(name, int((i / len(steps)) * 100))
            try:
                func()
            except Exception as e:
                logger.error(f"Error collecting {name}: {e}")
        if progress_callback:
            progress_callback("Complete", 100)
        return self.data

    def collect_os_info(self):
        uname = platform.uname()

        # Get full OS caption from WMI (e.g. "Microsoft Windows 10 Pro")
        os_caption = f"{uname.system} {uname.release}"
        try:
            for os_obj in self.wmi_obj.Win32_OperatingSystem():
                os_caption = os_obj.Caption.strip()
                break
        except Exception:
            pass

        # License status via slmgr
        license_status = "Unknown"
        try:
            result = subprocess.run(
                ["cscript", "//NoLogo", r"C:\Windows\System32\slmgr.vbs", "/dli"],
                capture_output=True, text=True, timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            for line in result.stdout.splitlines():
                if "license status" in line.lower():
                    license_status = line.split(":")[-1].strip()
                    break
        except Exception:
            pass

        # Browsers
        browsers = []
        browser_paths = {
            "Google Chrome": r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe",
            "Mozilla Firefox": r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe",
            "Microsoft Edge": r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe",
            "Opera": r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\opera.exe",
            "Brave": r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\brave.exe",
        }
        for name, path in browser_paths.items():
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                winreg.CloseKey(key)
                browsers.append(name)
            except OSError:
                pass

        # Startup programs
        startup_programs = []
        try:
            for item in self.wmi_obj.Win32_StartupCommand():
                startup_programs.append(item.Name or item.Command or "Unknown")
        except Exception:
            pass

        self.data["system_info"] = {
            "os_name": os_caption,
            "os_version": uname.version,
            "os_architecture": platform.architecture()[0],
            "os_build": platform.version(),
            "hostname": socket.gethostname(),
            "cs_name": socket.gethostname(),
            "license_status": license_status,
            "logged_in_user": os.getlogin(),
            "timezone": str(time.tzname),
            "installed_browsers": browsers,
            "startup_programs": startup_programs[:100],
        }

    def collect_os_updates(self):
        """Collect OS update details in NSDL format:
        Caption, CS Name, Description, Fix ID (HotFixID), Installed On
        """
        updates = []
        cs_name = socket.gethostname()
        try:
            for update in self.wmi_obj.Win32_QuickFixEngineering():
                updates.append({
                    "caption": update.Caption or "",
                    "cs_name": cs_name,
                    "description": update.Description or "",
                    "fix_id": update.HotFixID or "",
                    "installed_on": update.InstalledOn or "",
                })
        except Exception as e:
            logger.error(f"Error collecting OS updates: {e}")

        self.data["os_updates"] = updates[:300]

    def collect_hardware_info(self):
        cpu_freq = psutil.cpu_freq()
        ram = psutil.virtual_memory()

        cpu_name = "Unknown"
        try:
            for proc in self.wmi_obj.Win32_Processor():
                cpu_name = proc.Name
                break
        except Exception:
            pass

        motherboard = "Unknown"
        try:
            for board in self.wmi_obj.Win32_BaseBoard():
                motherboard = f"{board.Manufacturer} {board.Product}"
                break
        except Exception:
            pass

        bios_serial = "Unknown"
        try:
            for bios in self.wmi_obj.Win32_BIOS():
                bios_serial = bios.SerialNumber
                break
        except Exception:
            pass

        machine_uuid_val = "Unknown"
        try:
            for cs in self.wmi_obj.Win32_ComputerSystemProduct():
                machine_uuid_val = cs.UUID
                break
        except Exception:
            pass

        # Drive details - NSDL checks for CD/DVD drives
        disk_drives = []
        for part in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disk_drives.append({
                    "device": part.device,
                    "mountpoint": part.mountpoint,
                    "fstype": part.fstype,
                    "total": f"{usage.total / (1024**3):.1f} GB",
                    "used": f"{usage.used / (1024**3):.1f} GB",
                    "free": f"{usage.free / (1024**3):.1f} GB",
                    "percent": usage.percent,
                })
            except Exception:
                pass

        # CD/DVD drive detection (NSDL specific)
        cd_drives = []
        try:
            for drive in self.wmi_obj.Win32_CDROMDrive():
                cd_drives.append({
                    "name": drive.Name or "Unknown",
                    "drive_letter": drive.Drive or "",
                    "media_type": drive.MediaType or "",
                })
        except Exception:
            pass

        # Compression utility check (NSDL checks for CD burning / compression)
        compression_utilities = []
        try:
            for drive in self.wmi_obj.Win32_CDROMDrive():
                compression_utilities.append(drive.Name or "Unknown")
        except Exception:
            pass

        self.data["hardware_info"] = {
            "cpu_name": cpu_name,
            "cpu_cores": psutil.cpu_count(logical=False),
            "cpu_threads": psutil.cpu_count(logical=True),
            "cpu_frequency": f"{cpu_freq.max:.0f} MHz" if cpu_freq else "N/A",
            "ram_total": f"{ram.total / (1024**3):.1f} GB",
            "ram_available": f"{ram.available / (1024**3):.1f} GB",
            "disk_drives": disk_drives,
            "cd_drives": cd_drives,
            "compression_utilities": compression_utilities,
            "motherboard": motherboard,
            "bios_serial": bios_serial,
            "machine_uuid": machine_uuid_val,
        }

    def collect_network_info(self):
        # MAC address without separators (NSDL format: E83935524931)
        mac = uuid.getnode()
        mac_address_raw = "".join(f"{(mac >> i) & 0xFF:02X}" for i in range(40, -1, -8))
        mac_address_formatted = ":".join(f"{(mac >> i) & 0xFF:02x}" for i in range(40, -1, -8))

        ip_address = "Unknown"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
            s.close()
        except Exception:
            pass

        adapters = []
        for name, addrs in psutil.net_if_addrs().items():
            adapter = {"name": name, "mac": "", "ips": []}
            for addr in addrs:
                if addr.family == psutil.AF_LINK:
                    adapter["mac"] = addr.address
                elif addr.family == socket.AF_INET:
                    adapter["ips"].append(addr.address)
            adapters.append(adapter)

        self.data["network_info"] = {
            "mac_address": mac_address_raw,
            "mac_address_formatted": mac_address_formatted,
            "ip_address": ip_address,
            "adapters": adapters,
        }

    def collect_software_info(self):
        software = []
        reg_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]

        seen = set()
        for hive, path in reg_paths:
            try:
                key = winreg.OpenKey(hive, path)
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey = winreg.OpenKey(key, subkey_name)
                        name = self._reg_value(subkey, "DisplayName")
                        if name and name not in seen:
                            seen.add(name)
                            software.append({
                                "name": name,
                                "version": self._reg_value(subkey, "DisplayVersion") or "",
                                "publisher": self._reg_value(subkey, "Publisher") or "",
                            })
                        winreg.CloseKey(subkey)
                    except Exception:
                        continue
                winreg.CloseKey(key)
            except Exception:
                continue

        self.data["software_entries"] = sorted(software, key=lambda x: x["name"].lower())[:500]

    def collect_security_info(self):
        # Antivirus detection via SecurityCenter2
        antivirus_products = []
        try:
            wmi_sec = wmi.WMI(namespace=r"root\SecurityCenter2")
            for av in wmi_sec.AntiVirusProduct():
                state = av.productState
                enabled = "Enabled" if (state >> 12) & 0xF else "Disabled"
                antivirus_products.append({
                    "name": av.displayName,
                    "status": enabled,
                })
        except Exception:
            pass

        antivirus_name = antivirus_products[0]["name"] if antivirus_products else "No Antivirus Found"
        antivirus_status = antivirus_products[0]["status"] if antivirus_products else "N/A"

        # Firewall status
        firewall_status = "Unknown"
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            states = []
            for line in result.stdout.splitlines():
                if "State" in line:
                    states.append(line.split()[-1])
            firewall_status = ", ".join(states) if states else "Unknown"
        except Exception:
            pass

        # Windows Defender
        defender_status = "Unknown"
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-MpComputerStatus | Select-Object -Property RealTimeProtectionEnabled | Format-List"],
                capture_output=True, text=True, timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            for line in result.stdout.splitlines():
                if "RealTimeProtectionEnabled" in line:
                    val = line.split(":")[-1].strip()
                    defender_status = "Enabled" if val.lower() == "true" else "Disabled"
                    break
        except Exception:
            pass

        # UAC
        uac_enabled = True
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            )
            value, _ = winreg.QueryValueEx(key, "EnableLUA")
            uac_enabled = bool(value)
            winreg.CloseKey(key)
        except Exception:
            pass

        self.data["security_info"] = {
            "antivirus_name": antivirus_name,
            "antivirus_status": antivirus_status,
            "antivirus_products": antivirus_products,
            "firewall_status": firewall_status,
            "defender_status": defender_status,
            "uac_enabled": uac_enabled,
        }

    def collect_peripheral_info(self):
        """Collect printer details in exact NSDL format:
        Name, SystemName, EnableBIDI, ExtendedPrinterStatus, PortName
        """
        printers = []
        try:
            for printer in self.wmi_obj.Win32_Printer():
                printers.append({
                    "name": printer.Name or "",
                    "system_name": printer.SystemName or "",
                    "enable_bidi": str(printer.EnableBIDI) if printer.EnableBIDI is not None else "False",
                    "extended_printer_status": str(printer.ExtendedPrinterStatus or ""),
                    "port_name": printer.PortName or "",
                })
        except Exception as e:
            logger.error(f"Error collecting printers: {e}")

        usb_devices = []
        try:
            for device in self.wmi_obj.Win32_USBControllerDevice():
                dependent = device.Dependent
                try:
                    name = dependent.split('"')[1] if '"' in dependent else dependent
                    usb_devices.append({"name": name})
                except Exception:
                    usb_devices.append({"name": str(dependent)})
        except Exception:
            pass

        self.data["peripheral_info"] = {
            "printers": printers,
            "total_printers": len(printers),
            "usb_devices": usb_devices[:100],
        }

    @staticmethod
    def _reg_value(key, name):
        try:
            value, _ = winreg.QueryValueEx(key, name)
            return str(value)
        except Exception:
            return None


def upload_audit(server_url: str, token: str, data: dict, max_retries: int = 3) -> bool:
    payload = {"verification_token": token, **data}

    for attempt in range(1, max_retries + 1):
        try:
            logger.info(f"Upload attempt {attempt}/{max_retries}")
            response = requests.post(
                f"{server_url}/api/audit/upload",
                json=payload,
                timeout=30,
                headers={"Content-Type": "application/json"},
            )
            if response.status_code == 200:
                logger.info("Upload successful!")
                return True
            else:
                logger.warning(f"Upload failed: {response.status_code} - {response.text}")
        except requests.RequestException as e:
            logger.error(f"Upload error: {e}")

        if attempt < max_retries:
            wait = 2 ** attempt
            logger.info(f"Retrying in {wait}s...")
            time.sleep(wait)

    return False


if __name__ == "__main__":
    SERVER_URL = "http://localhost:8000"
    TOKEN = sys.argv[1] if len(sys.argv) > 1 else ""

    if not TOKEN:
        print("Usage: audit_agent.py <verification_token>")
        sys.exit(1)

    auditor = SystemAuditor()
    data = auditor.collect_all()

    # Save locally
    local_path = os.path.join(LOG_DIR, f"audit_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json")
    with open(local_path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    logger.info(f"Saved local copy: {local_path}")

    success = upload_audit(SERVER_URL, TOKEN, data)
    sys.exit(0 if success else 1)
