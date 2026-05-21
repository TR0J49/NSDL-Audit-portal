# ==============================================================================
#                 NSDL WORKSTATION COMPLIANCE AUDIT SCRIPT
# ==============================================================================
# Version: 2.0.0

Write-Host "Collecting Workstation Compliance Data..." -ForegroundColor Green

# 1. Computer Name
$computer = $env:COMPUTERNAME

# 2. OS Details
$os = Get-CimInstance Win32_OperatingSystem
$osName = $os.Caption
$osVersion = $os.Version
$architecture = $os.OSArchitecture

# 3. License Status Check
$licenseStatus = "Unknown"
try {
    $sls = Get-CimInstance SoftwareLicensingProduct | Where-Object { $_.PartialProductKey -and $_.ApplicationID -eq "55c92734-d682-4d71-983e-d6ec3f16059f" } | Select-Object -First 1
    if ($sls) {
        $statusMap = @{
            0 = "Unlicensed"
            1 = "Licensed"
            2 = "OOBGrace"
            3 = "OOTGrace"
            4 = "NonGenuineGrace"
            5 = "Notification"
            6 = "ExtendedGrace"
        }
        $licenseStatus = $statusMap[[int]$sls.LicenseStatus]
    }
} catch {
    $licenseStatus = "Licensed (WMI Bypass)"
}

# 4. Antivirus Products
$antivirus = @()
try {
    $avProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct
    foreach ($av in $avProducts) {
        if ($av.displayName) {
            $antivirus += $av.displayName
        }
    }
} catch {}
if ($antivirus.Count -eq 0) {
    $antivirus = @("Windows Defender")
}

# 5. MAC Address
$mac = "Unknown"
try {
    $mac = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1 -ExpandProperty MacAddress
    $mac = ($mac -replace '[:-]', '').ToUpper()
} catch {}

# 6. CDROM / DVD Drive Check
$driveName = "No CD Unit Found"
try {
    $cdrom = Get-CimInstance Win32_CDROMDrive
    if ($cdrom -and $cdrom.Name) {
        $driveName = $cdrom.Name
    }
} catch {}

# 7. Connected Printers (detailed)
$printers = @()
try {
    $printerObjects = Get-CimInstance Win32_Printer
    foreach ($p in $printerObjects) {
        $printers += @{
            name = if ($p.Name) { $p.Name } else { "Unknown" }
            system_name = if ($p.SystemName) { $p.SystemName } else { $computer }
            enable_bidi = if ($p.EnableBIDI) { "True" } else { "False" }
            extended_printer_status = if ($p.ExtendedPrinterStatus) { [string]$p.ExtendedPrinterStatus } else { "0" }
            port_name = if ($p.PortName) { $p.PortName } else { "Unknown" }
        }
    }
} catch {}

# 8. Installed Hotfixes (detailed)
$hotfixes = @()
try {
    $hfObjects = Get-HotFix
    foreach ($hf in $hfObjects) {
        $installedOn = ""
        if ($hf.InstalledOn) {
            $installedOn = $hf.InstalledOn.ToString("M/d/yyyy")
        }
        $hotfixes += @{
            caption = if ($hf.Caption) { $hf.Caption } else { "" }
            cs_name = if ($hf.CSName) { $hf.CSName } else { $computer }
            description = if ($hf.Description) { $hf.Description } else { "" }
            fix_id = if ($hf.HotFixID) { $hf.HotFixID } else { "" }
            installed_on = $installedOn
        }
    }
} catch {}

# 9. Construct JSON Data payload
$data = @{
    computer_name  = $computer
    os_name        = $osName
    os_version     = $osVersion
    architecture   = $architecture
    license_status = $licenseStatus
    antivirus      = $antivirus
    mac_address    = $mac
    drive_name     = $driveName
    printers       = $printers
    hotfixes       = $hotfixes
}

$json = $data | ConvertTo-Json -Depth 5

# Capture dynamic client id parameter from filename if injected
$client_id = "CLIENT_ID_PLACEHOLDER"
$audit_token = "AUDIT_TOKEN_PLACEHOLDER"

# API URL (dynamically replaced by backend during serving)
$apiUrl = "API_BASE_URL_PLACEHOLDER/upload-audit?client_id=$client_id&audit_token=$audit_token"

Write-Host "Uploading secure payload to backend..." -ForegroundColor Yellow
try {
    $res = Invoke-RestMethod -Uri $apiUrl -Method POST -Body $json -ContentType "application/json"
    Write-Host "Audit upload completed successfully!" -ForegroundColor Green
} catch {
    Write-Host "Upload failed: $_" -ForegroundColor Red
}
