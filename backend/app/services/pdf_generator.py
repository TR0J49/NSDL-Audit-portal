"""
PDF Generator - Produces Inspection Reports matching NSDL e-Governance format.

Layout: A4 page, 2-column bordered table (label | value), section headers
spanning full width. Footer on each page in maroon color.
"""

import os
from datetime import datetime, timezone
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from app.config import get_settings

settings = get_settings()

PAGE_WIDTH, PAGE_HEIGHT = A4
LEFT_COL = 196
RIGHT_COL = 196
FULL_COL = LEFT_COL + RIGHT_COL
SIDE_MARGIN = 102  # matches NSDL x0=102

BORDER_COLOR = colors.black
HEADER_BG = colors.HexColor("#D9E1F2")  # Light blue header background
SECTION_BG = colors.HexColor("#B4C6E7")  # Section header background


def _cell_style():
    return ParagraphStyle("Cell", fontName="Times-Roman", fontSize=10, leading=12)


def _bold_style():
    return ParagraphStyle("CellBold", fontName="Times-Bold", fontSize=10, leading=12)


def _section_style():
    return ParagraphStyle("Section", fontName="Times-Bold", fontSize=11, leading=14)


def _footer_style():
    return ParagraphStyle(
        "Footer", fontName="Times-Roman", fontSize=9, leading=11,
        textColor=colors.HexColor("#800000"), alignment=TA_CENTER,
    )


def _make_kv_rows(pairs):
    """Create label-value row pairs for 2-column table."""
    style = _cell_style()
    bold = _bold_style()
    rows = []
    for label, value in pairs:
        rows.append([
            Paragraph(str(label), bold),
            Paragraph(str(value) if value else "N/A", style),
        ])
    return rows


def _make_section_header(title):
    """Full-width section header row (2 cells for 2-col table, spanned via style)."""
    return [Paragraph(title, _section_style()), ""]


def _build_table(data, col_widths=None, has_section_headers=None):
    """Build a table with NSDL-style borders."""
    if col_widths is None:
        col_widths = [LEFT_COL, RIGHT_COL]

    t = Table(data, colWidths=col_widths)

    style_commands = [
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("FONTNAME", (0, 0), (-1, -1), "Times-Roman"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]

    # Highlight section header rows
    if has_section_headers:
        for row_idx in has_section_headers:
            style_commands.append(("SPAN", (0, row_idx), (-1, row_idx)))
            style_commands.append(("BACKGROUND", (0, row_idx), (-1, row_idx), SECTION_BG))

    t.setStyle(TableStyle(style_commands))
    return t


def generate_audit_pdf(audit, db) -> str:
    os.makedirs(settings.REPORTS_DIR, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%d-%b-%Y_%H:%M:%S")
    filename = f"inspection_{str(audit.id)[:8]}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(settings.REPORTS_DIR, filename)

    footer_text = "INSPECTION REPORT BY NSDL E-GOVERNANCE"

    def footer_on_page(canvas, doc):
        canvas.saveState()
        canvas.setFont("Times-Roman", 9)
        canvas.setFillColor(colors.HexColor("#800000"))
        canvas.drawCentredString(PAGE_WIDTH / 2, 30, footer_text)
        canvas.restoreState()

    doc = SimpleDocTemplate(
        filepath, pagesize=A4,
        leftMargin=SIDE_MARGIN, rightMargin=SIDE_MARGIN,
        topMargin=40, bottomMargin=50,
    )

    elements = []
    cell = _cell_style()
    bold = _bold_style()

    # ================================================================
    # TITLE
    # ================================================================
    title_style = ParagraphStyle(
        "Title", fontName="Times-Bold", fontSize=14, leading=18,
        alignment=TA_CENTER, spaceAfter=10,
    )
    elements.append(Paragraph("Inspection Report", title_style))
    elements.append(Spacer(1, 6))

    # ================================================================
    # TINFC DETAILS
    # ================================================================
    tinfc_data = [
        _make_section_header("TINFC Details"),
    ]
    section_rows = {0}

    branch_name = audit.branch_name or ""
    branch_code = audit.branch_code or ""
    branch_officer = audit.branch_officer or ""

    tinfc_data += _make_kv_rows([
        ("TIN FC Branch Name", branch_name),
        ("TIN FC Branch Code", branch_code),
        ("TIN FC Branch Officer Name", branch_officer),
        ("Execution DateTime", ts),
    ])

    # Consent row
    consent_text = (
        "We provide approval to NSDL e-Governance Infrastructure Ltd.(NSDL e-Gov) "
        "to capture the details regarding the System details and share the details "
        "with NSDL e-Gov."
    )
    tinfc_data.append([
        Paragraph("Consent", bold),
        Paragraph(consent_text, cell),
    ])

    elements.append(_build_table(tinfc_data, has_section_headers=section_rows))
    elements.append(Spacer(1, 10))

    # ================================================================
    # OPERATING SYSTEM
    # ================================================================
    si = audit.system_info
    os_data = [
        _make_section_header("Operating System"),
    ]
    os_section_rows = {0}

    if si:
        os_data += _make_kv_rows([
            ("OS Name", si.os_name),
            ("OS Version", si.os_version),
            ("OS Architecture", si.os_architecture),
            ("CS Name", si.cs_name or si.hostname),
            ("LicenseStatus", si.license_status),
        ])
    else:
        os_data += _make_kv_rows([
            ("OS Name", "N/A"),
            ("OS Version", "N/A"),
            ("OS Architecture", "N/A"),
            ("CS Name", "N/A"),
            ("LicenseStatus", "N/A"),
        ])

    elements.append(_build_table(os_data, has_section_headers=os_section_rows))
    elements.append(Spacer(1, 10))

    # ================================================================
    # OS UPDATE DETAILS
    # ================================================================
    os_updates = si.os_updates if si else None
    if os_updates and len(os_updates) > 0:
        upd_data = [
            _make_section_header("OS Update Details"),
        ]
        upd_section_rows = {0}
        row_idx = 1

        for i, update in enumerate(os_updates, 1):
            if isinstance(update, dict):
                # Number header row
                upd_data.append([
                    Paragraph(str(i), _section_style()), "",
                ])
                upd_section_rows.add(row_idx)
                row_idx += 1

                upd_data += _make_kv_rows([
                    ("Caption", update.get("caption", "")),
                    ("CS Name", update.get("cs_name", "")),
                    ("Description", update.get("description", "")),
                    ("Fix ID", update.get("fix_id", "")),
                    ("Installed On", update.get("installed_on", "")),
                ])
                row_idx += 5

        elements.append(_build_table(upd_data, has_section_headers=upd_section_rows))
        elements.append(Spacer(1, 10))

    # ================================================================
    # MAC ADDRESS
    # ================================================================
    ni = audit.network_info
    mac_val = ni.mac_address if ni else "N/A"
    mac_data = _make_kv_rows([("Mac address", mac_val)])
    elements.append(_build_table(mac_data))
    elements.append(Spacer(1, 10))

    # ================================================================
    # PAGE 2 - DRIVE DETAILS, ANTIVIRUS, PRINTERS
    # ================================================================
    elements.append(PageBreak())

    # DRIVE DETAILS
    hi = audit.hardware_info
    drive_data = [
        _make_section_header("Drive Details"),
    ]
    drive_section_rows = {0}

    cd_drives = hi.cd_drives if hi else None
    if cd_drives and len(cd_drives) > 0:
        for cd in cd_drives:
            if isinstance(cd, dict):
                drive_data += _make_kv_rows([
                    ("DriveName", cd.get("name", "")),
                ])
    else:
        drive_data += _make_kv_rows([("DriveName", "No CD Unit Found")])

    elements.append(_build_table(drive_data, has_section_headers=drive_section_rows))
    elements.append(Spacer(1, 10))

    # COMPRESSION UTILITY DETAILS
    comp_data = [
        _make_section_header("Compression utility details"),
    ]
    comp_section_rows = {0}

    comp_utils = hi.compression_utilities if hi else None
    if comp_utils and len(comp_utils) > 0:
        for cu in comp_utils:
            comp_data += _make_kv_rows([("DriveName", str(cu))])
    else:
        comp_data += _make_kv_rows([("DriveName", "No CD Unit Found")])

    elements.append(_build_table(comp_data, has_section_headers=comp_section_rows))
    elements.append(Spacer(1, 10))

    # ANTIVIRUS
    sec = audit.security_info
    av_data = [
        _make_section_header("Antivirus"),
    ]
    av_section_rows = {0}

    if sec and sec.antivirus_name and sec.antivirus_name != "No Antivirus Found":
        av_data += _make_kv_rows([
            ("Name", sec.antivirus_name),
            ("Status", sec.antivirus_status),
        ])
        if sec.firewall_status:
            av_data += _make_kv_rows([("Firewall Status", sec.firewall_status)])
        if sec.defender_status:
            av_data += _make_kv_rows([("Windows Defender", sec.defender_status)])
    else:
        av_data += _make_kv_rows([("Antivirus", "No Antivirus Found")])

    elements.append(_build_table(av_data, has_section_headers=av_section_rows))
    elements.append(Spacer(1, 10))

    # PRINTER DETAILS
    pi = audit.peripheral_info
    printers = pi.printers if pi else None

    pr_data = [
        _make_section_header("Printer Details"),
    ]
    pr_section_rows = {0}
    pr_row_idx = 1

    if printers and len(printers) > 0:
        for i, printer in enumerate(printers, 1):
            if isinstance(printer, dict):
                # Number header
                pr_data.append([Paragraph(str(i), _section_style()), ""])
                pr_section_rows.add(pr_row_idx)
                pr_row_idx += 1

                pr_data += _make_kv_rows([
                    ("Name", printer.get("name", "")),
                    ("SystemName", printer.get("system_name", "")),
                    ("EnableBIDI", printer.get("enable_bidi", "False")),
                    ("ExtendedPrinterStatus", printer.get("extended_printer_status", "")),
                    ("PortName", printer.get("port_name", "")),
                ])
                pr_row_idx += 5

        # Total printers row
        total = pi.total_printers if pi else len(printers)
        pr_data += _make_kv_rows([("Total Printer connected", str(total))])
    else:
        pr_data += _make_kv_rows([("Printers", "No printers found")])

    elements.append(_build_table(pr_data, has_section_headers=pr_section_rows))
    elements.append(Spacer(1, 10))

    # ================================================================
    # PAGE 3 (optional) - DISK DRIVES, HARDWARE, SOFTWARE
    # ================================================================
    disk_drives = hi.disk_drives if hi else None
    if disk_drives and len(disk_drives) > 0:
        elements.append(PageBreak())

        hd_data = [_make_section_header("Hard Disk Details")]
        hd_section_rows = {0}
        hd_row_idx = 1

        for i, disk in enumerate(disk_drives, 1):
            if isinstance(disk, dict):
                hd_data.append([Paragraph(str(i), _section_style()), ""])
                hd_section_rows.add(hd_row_idx)
                hd_row_idx += 1

                hd_data += _make_kv_rows([
                    ("Device", disk.get("device", "")),
                    ("Mount Point", disk.get("mountpoint", "")),
                    ("File System", disk.get("fstype", "")),
                    ("Total Size", disk.get("total", "")),
                    ("Used", disk.get("used", "")),
                    ("Free", disk.get("free", "")),
                    ("Usage %", f"{disk.get('percent', '')}%"),
                ])
                hd_row_idx += 7

        elements.append(_build_table(hd_data, has_section_headers=hd_section_rows))
        elements.append(Spacer(1, 10))

    # HARDWARE DETAILS
    if hi:
        hw_data = [_make_section_header("Hardware Details")]
        hw_section_rows = {0}

        hw_data += _make_kv_rows([
            ("Processor", hi.cpu_name),
            ("Cores", str(hi.cpu_cores or "N/A")),
            ("Threads", str(hi.cpu_threads or "N/A")),
            ("CPU Frequency", hi.cpu_frequency),
            ("Total RAM", hi.ram_total),
            ("Available RAM", hi.ram_available),
            ("Motherboard", hi.motherboard),
            ("BIOS Serial", hi.bios_serial),
            ("Machine UUID", hi.machine_uuid),
        ])

        elements.append(_build_table(hw_data, has_section_headers=hw_section_rows))
        elements.append(Spacer(1, 10))

    # INSTALLED SOFTWARE
    if audit.software_entries and len(audit.software_entries) > 0:
        elements.append(PageBreak())
        sw_data = [_make_section_header("Installed Software")]
        sw_section_rows = {0}

        for i, sw in enumerate(audit.software_entries[:200], 1):
            sw_data.append([
                Paragraph(f"{i}. {sw.name or 'N/A'}", cell),
                Paragraph(f"v{sw.version}" if sw.version else "", cell),
            ])

        elements.append(_build_table(sw_data, has_section_headers=sw_section_rows))

    # BROWSERS
    if si and si.installed_browsers:
        elements.append(Spacer(1, 10))
        br_data = [_make_section_header("Installed Browsers")]
        br_section_rows = {0}
        for browser in si.installed_browsers:
            br_data += _make_kv_rows([("Browser", str(browser))])
        elements.append(_build_table(br_data, has_section_headers=br_section_rows))

    # USB DEVICES
    if pi and pi.usb_devices and len(pi.usb_devices) > 0:
        elements.append(Spacer(1, 10))
        usb_data = [_make_section_header("USB Devices")]
        usb_section_rows = {0}
        for i, device in enumerate(pi.usb_devices[:50], 1):
            name = device.get("name", "Unknown") if isinstance(device, dict) else str(device)
            usb_data += _make_kv_rows([(str(i), name)])
        elements.append(_build_table(usb_data, has_section_headers=usb_section_rows))

    # BUILD PDF
    doc.build(elements, onFirstPage=footer_on_page, onLaterPages=footer_on_page)
    return filepath
