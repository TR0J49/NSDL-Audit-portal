# ==============================================================================
#                 InfraPulse WORKSTATION COMPLIANCE AUDIT SCRIPT
# ==============================================================================
# Version: 2.0.0

Write-Host "Collecting Workstation Compliance Data..." -ForegroundColor Green

$computer = $env:COMPUTERNAME

# 1. OS Details
$osName = ""; $osVersion = ""; $architecture = ""; $registeredOwner = ""; $windowsDirectory = ""; $systemBootTime = ""
try {
    $os = Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 8
    $osName           = $os.Caption
    $osVersion        = $os.Version
    $architecture     = $os.OSArchitecture
    $registeredOwner  = if ($os.RegisteredUser)   { $os.RegisteredUser }   else { "" }
    $windowsDirectory = if ($os.WindowsDirectory) { $os.WindowsDirectory } else { "" }
    try { $systemBootTime = $os.LastBootUpTime.ToString("dd-MMM-yyyy HH:mm:ss") } catch {}
} catch {}

# 2. License Status
$licenseStatus = "Licensed"
try {
    $sls = Get-CimInstance SoftwareLicensingProduct -OperationTimeoutSec 6 |
           Where-Object { $_.PartialProductKey -and $_.ApplicationID -eq "55c92734-d682-4d71-983e-d6ec3f16059f" } |
           Select-Object -First 1
    if ($sls) {
        $licenseStatus = @{0="Unlicensed";1="Licensed";2="OOBGrace";3="OOTGrace";4="NonGenuineGrace";5="Notification";6="ExtendedGrace"}[[int]$sls.LicenseStatus]
    }
} catch {}

# 3. Antivirus
$antivirus = @()
try {
    $avProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -OperationTimeoutSec 6
    foreach ($av in $avProducts) { if ($av.displayName) { $antivirus += $av.displayName } }
} catch {}
if ($antivirus.Count -eq 0) { $antivirus = @("Windows Defender") }

# 4. Primary MAC Address
$mac = "Unknown"
try {
    $m = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
    if ($m) { $mac = ($m.MacAddress -replace '[:-]', '').ToUpper() }
} catch {}

# 5. CDROM
$driveName = "No CD Unit Found"
try {
    $cdrom = Get-CimInstance Win32_CDROMDrive -OperationTimeoutSec 6
    if ($cdrom -and $cdrom.Name) { $driveName = $cdrom.Name }
} catch {}

# 6. Printers
$printers = @()
try {
    $printerObjects = Get-CimInstance Win32_Printer -OperationTimeoutSec 10
    foreach ($p in $printerObjects) {
        $printers += @{
            name                    = if ($p.Name)                  { $p.Name }                          else { "Unknown" }
            system_name             = if ($p.SystemName)            { $p.SystemName }                    else { $computer }
            enable_bidi             = if ($p.EnableBIDI)            { "True" }                           else { "False" }
            extended_printer_status = if ($p.ExtendedPrinterStatus) { [string]$p.ExtendedPrinterStatus } else { "0" }
            port_name               = if ($p.PortName)              { $p.PortName }                      else { "Unknown" }
        }
    }
} catch {}

# 7. Hotfixes (CimInstance is much faster than Get-HotFix)
$hotfixes = @()
try {
    $hfObjects = Get-CimInstance -ClassName Win32_QuickFixEngineering -OperationTimeoutSec 10
    foreach ($hf in $hfObjects) {
        $installedOn = ""
        if ($hf.InstalledOn) {
            try { $installedOn = ([datetime]$hf.InstalledOn).ToString("M/d/yyyy") } catch { $installedOn = [string]$hf.InstalledOn }
        }
        $hotfixes += @{
            caption      = ""
            cs_name      = if ($hf.CSName)      { $hf.CSName }      else { $computer }
            description  = if ($hf.Description) { $hf.Description } else { "" }
            fix_id       = if ($hf.HotFixID)    { $hf.HotFixID }    else { "" }
            installed_on = $installedOn
        }
    }
} catch {}

# 8. Network Adapters
$networkAdapters = @()
try {
    $netConfigs = Get-CimInstance Win32_NetworkAdapterConfiguration -OperationTimeoutSec 8 | Where-Object { $_.IPEnabled }
    foreach ($nc in $netConfigs) {
        $ipv4    = ($nc.IPAddress | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1)
        $mask    = ($nc.IPSubnet  | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1)
        $gateway = if ($nc.DefaultIPGateway)      { $nc.DefaultIPGateway[0] }          else { "" }
        $dns     = if ($nc.DNSServerSearchOrder)  { $nc.DNSServerSearchOrder -join ", " } else { "" }
        $ipv6Permanent = ""; $ipv6Temp = ""; $ipv6LinkLocal = ""
        try {
            $v6Addrs = Get-NetIPAddress -InterfaceIndex $nc.InterfaceIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue
            foreach ($addr in $v6Addrs) {
                if     ($addr.IPAddress -match '^fe80')                  { $ipv6LinkLocal = $addr.IPAddress }
                elseif ($addr.SuffixOrigin -eq 'Random')                 { $ipv6Temp      = $addr.IPAddress }
                elseif ($addr.PrefixOrigin -eq 'RouterAdvertisement')    { $ipv6Permanent = $addr.IPAddress }
                elseif ($addr.IPAddress -ne '::1')                       { $ipv6Permanent = $addr.IPAddress }
            }
        } catch {}
        $networkAdapters += @{
            name              = if ($nc.Description) { $nc.Description } else { "Unknown" }
            mac_address       = if ($nc.MACAddress)  { $nc.MACAddress }  else { "" }
            ip_address        = if ($ipv4)            { $ipv4 }           else { "" }
            subnet_mask       = if ($mask)            { $mask }           else { "" }
            default_gateway   = $gateway
            dhcp_enabled      = if ($nc.DHCPEnabled)  { "True" }          else { "False" }
            dhcp_server       = if ($nc.DHCPServer)   { $nc.DHCPServer }  else { "" }
            dns_servers       = $dns
            ipv6_address      = $ipv6Permanent
            temp_ipv6_address = $ipv6Temp
            link_local_ipv6   = $ipv6LinkLocal
        }
    }
} catch {}

# 9. System Info
$sysManufacturer = ""; $sysModel = ""; $processorName = ""; $totalRam = ""; $biosVersion = ""; $domain = ""; $logonServer = $env:LOGONSERVER; $timeZone = ""
try {
    $cs = Get-CimInstance Win32_ComputerSystem -OperationTimeoutSec 8
    $sysManufacturer = if ($cs.Manufacturer) { $cs.Manufacturer } else { "" }
    $sysModel        = if ($cs.Model)        { $cs.Model }        else { "" }
    $totalRam        = [string][math]::Round($cs.TotalPhysicalMemory / 1GB, 2) + " GB"
    $domain          = if ($cs.Domain)       { $cs.Domain }       else { "" }
} catch {}
try {
    $proc = Get-CimInstance Win32_Processor -OperationTimeoutSec 8 | Select-Object -First 1
    $processorName = if ($proc.Name) { $proc.Name.Trim() } else { "" }
} catch {}
try {
    $bios = Get-CimInstance Win32_BIOS -OperationTimeoutSec 8
    $biosVersion = if ($bios.SMBIOSBIOSVersion) { $bios.SMBIOSBIOSVersion } else { "" }
} catch {}
try { $timeZone = (Get-TimeZone).DisplayName } catch {}

# 10. Build JSON and Upload
$data = @{
    computer_name         = $computer
    os_name               = $osName
    os_version            = $osVersion
    architecture          = $architecture
    license_status        = $licenseStatus
    antivirus             = $antivirus
    mac_address           = $mac
    drive_name            = $driveName
    printers              = $printers
    hotfixes              = $hotfixes
    network_adapters      = $networkAdapters
    system_manufacturer   = $sysManufacturer
    system_model          = $sysModel
    processor             = $processorName
    total_physical_memory = $totalRam
    bios_version          = $biosVersion
    domain                = $domain
    logon_server          = $logonServer
    system_boot_time      = $systemBootTime
    time_zone             = $timeZone
    registered_owner      = $registeredOwner
    windows_directory     = $windowsDirectory
}

$json = $data | ConvertTo-Json -Depth 5

$client_id        = "CLIENT_ID_PLACEHOLDER"
$assortment_token = "AUDIT_TOKEN_PLACEHOLDER"
$apiUrl           = "API_BASE_URL_PLACEHOLDER/upload-assortment?client_id=$client_id&assortment_token=$assortment_token"

Write-Host "Uploading secure payload to backend..." -ForegroundColor Yellow
try {
    Invoke-RestMethod -Uri $apiUrl -Method POST -Body $json -ContentType "application/json" -TimeoutSec 30 | Out-Null
    Write-Host "Assortment upload completed successfully!" -ForegroundColor Green
} catch {
    Write-Host "Upload failed: $_" -ForegroundColor Red
}
