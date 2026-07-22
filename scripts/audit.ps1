# ==============================================================================
#                 InfraPulse WORKSTATION COMPLIANCE AUDIT SCRIPT
# ==============================================================================
# Version: 3.0.0

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

# 7. Hotfixes
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
        $gateway = if ($nc.DefaultIPGateway)      { $nc.DefaultIPGateway[0] }           else { "" }
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

# 10. Disk Info
$diskInfo = @()
try {
    $disks = Get-CimInstance Win32_LogicalDisk -OperationTimeoutSec 8 | Where-Object { $_.DriveType -eq 3 }
    foreach ($d in $disks) {
        $diskInfo += @{
            drive = [string]$d.DeviceID
            total = [string][math]::Round($d.Size / 1GB, 2) + " GB"
            used  = [string][math]::Round(($d.Size - $d.FreeSpace) / 1GB, 2) + " GB"
            free  = [string][math]::Round($d.FreeSpace / 1GB, 2) + " GB"
        }
    }
} catch {}

# 11. Installed Apps (from registry)
$installedApps = @()
try {
    $regPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $seen = @{}
    foreach ($path in $regPaths) {
        $items = Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName }
        foreach ($item in $items) {
            if (-not $seen.ContainsKey($item.DisplayName)) {
                $seen[$item.DisplayName] = $true
                $installedApps += @{
                    name      = [string]$item.DisplayName
                    version   = if ($item.DisplayVersion) { [string]$item.DisplayVersion } else { "" }
                    publisher = if ($item.Publisher)      { [string]$item.Publisher }      else { "" }
                }
            }
        }
    }
    $installedApps = $installedApps | Sort-Object { $_["name"] }
} catch {}

# 12. Local Users
$localUsers = @()
try {
    $adminMembers = @()
    try { $adminMembers = (Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue).Name } catch {}
    $allUsers = Get-LocalUser -ErrorAction SilentlyContinue
    foreach ($u in $allUsers) {
        $isAdmin = $adminMembers -contains "$computer\$($u.Name)"
        $localUsers += @{
            name    = [string]$u.Name
            enabled = if ($u.Enabled) { "True" } else { "False" }
            admin   = if ($isAdmin) { "True" } else { "False" }
        }
    }
} catch {}

# 13. Running Services
$runningServices = @()
try {
    $svcs = Get-CimInstance Win32_Service -OperationTimeoutSec 10 | Where-Object { $_.State -eq "Running" }
    foreach ($svc in $svcs) {
        $runningServices += @{
            name         = [string]$svc.Name
            display_name = [string]$svc.DisplayName
            start_type   = [string]$svc.StartMode
        }
    }
} catch {}

# 14. Open Ports (TCP Listening)
$openPorts = @()
try {
    $conns = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
    foreach ($c in $conns) {
        $openPorts += @{
            port     = [string]$c.LocalPort
            protocol = "TCP"
            pid      = [string]$c.OwningProcess
        }
    }
} catch {}

# 15. Security Posture
$securityPosture = @{
    bitlocker        = "Not Available"
    windows_firewall = "Unknown"
    uac_enabled      = "Unknown"
    filevault        = ""
    gatekeeper       = ""
    sip              = ""
    apparmor         = ""
    selinux          = ""
}
try {
    $bde = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
    if ($bde -and $bde.ProtectionStatus -eq "On") {
        $securityPosture["bitlocker"] = "Enabled"
    } else {
        $securityPosture["bitlocker"] = "Not Enabled"
    }
} catch { $securityPosture["bitlocker"] = "Not Available" }
try {
    $fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    $enabledProfiles = ($fwProfiles | Where-Object { $_.Enabled -eq $true }).Name -join ", "
    $securityPosture["windows_firewall"] = if ($enabledProfiles) { "Enabled ($enabledProfiles)" } else { "Disabled" }
} catch {}
try {
    $uac = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue).EnableLUA
    $securityPosture["uac_enabled"] = if ($uac -eq 1) { "True" } else { "False" }
} catch {}

# 16. Docker
$dockerInfo = @{ version = ""; running_containers = 0; containers = @() }
try {
    $dockerVer = & docker --version 2>$null
    if ($dockerVer) {
        $dockerInfo["version"] = [string]$dockerVer
        $containers = & docker ps --format "{{.Names}}" 2>$null
        if ($containers) {
            $dockerInfo["containers"] = @($containers)
            $dockerInfo["running_containers"] = @($containers).Count
        }
    }
} catch {}

# 17. Running Processes (top 50 by memory)
$runningProcesses = @()
try {
    $procs = Get-CimInstance Win32_Process -OperationTimeoutSec 10 | Sort-Object WorkingSetSize -Descending | Select-Object -First 50
    foreach ($p in $procs) {
        $owner = ""
        try { $ownerInfo = $p.GetOwner(); $owner = if ($ownerInfo.User) { [string]$ownerInfo.User } else { "" } } catch {}
        $runningProcesses += @{
            pid        = [string]$p.ProcessId
            name       = [string]$p.Name
            parent_pid = [string]$p.ParentProcessId
            user       = $owner
            path       = if ($p.ExecutablePath) { [string]$p.ExecutablePath } else { "" }
            cpu        = ""
            memory     = [string][math]::Round($p.WorkingSetSize / 1MB, 2) + " MB"
        }
    }
} catch {}

# 18. SSL Certificates (Personal store)
$sslCerts = @()
try {
    $certs = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue
    foreach ($cert in $certs) {
        $sslCerts += @{
            subject    = [string]$cert.Subject
            issuer     = [string]$cert.Issuer
            expiry     = $cert.NotAfter.ToString("dd-MMM-yyyy")
            thumbprint = [string]$cert.Thumbprint
        }
    }
} catch {}

# 19. Browser Extensions (Chrome & Edge)
$browserExtensions = @()
try {
    $extProfiles = @{
        "Chrome" = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
        "Edge"   = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
    }
    foreach ($browser in $extProfiles.Keys) {
        $extPath = $extProfiles[$browser]
        if (Test-Path $extPath) {
            Get-ChildItem $extPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $extId  = $_.Name
                $verDir = Get-ChildItem $_.FullName -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
                if ($verDir) {
                    $mPath = Join-Path $verDir.FullName "manifest.json"
                    if (Test-Path $mPath) {
                        try {
                            $m = Get-Content $mPath -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
                            $browserExtensions += @{
                                browser      = $browser
                                name         = if ($m.name)    { [string]$m.name }    else { $extId }
                                version      = if ($m.version) { [string]$m.version } else { "" }
                                extension_id = $extId
                            }
                        } catch {}
                    }
                }
            }
        }
    }
} catch {}

# 20. System Event Logs (last 20 errors/warnings)
$eventLogs = @()
try {
    $events = Get-WinEvent -LogName System -MaxEvents 50 -ErrorAction SilentlyContinue |
              Where-Object { $_.Level -in @(1, 2, 3) } | Select-Object -First 20
    foreach ($ev in $events) {
        $msg = ([string]$ev.Message) -replace "[\r\n]+", " "
        if ($msg.Length -gt 200) { $msg = $msg.Substring(0, 200) }
        $eventLogs += @{
            time    = $ev.TimeCreated.ToString("dd-MMM-yyyy HH:mm:ss")
            level   = [string]$ev.LevelDisplayName
            source  = [string]$ev.ProviderName
            message = $msg
        }
    }
} catch {}

# 21. GPU Information
$gpuInfo = @()
try {
    $gpus = Get-CimInstance Win32_VideoController -OperationTimeoutSec 8
    foreach ($gpu in $gpus) {
        $vram = if ($gpu.AdapterRAM -and $gpu.AdapterRAM -gt 0) { [string][math]::Round($gpu.AdapterRAM / 1MB, 0) + " MB" } else { "" }
        $gpuInfo += @{
            name           = if ($gpu.Name)          { [string]$gpu.Name }          else { "" }
            driver_version = if ($gpu.DriverVersion) { [string]$gpu.DriverVersion } else { "" }
            vram           = $vram
        }
    }
} catch {}

# 22. Battery Information
$batteryInfo = @{ name = ""; status = ""; estimated_charge = "" }
try {
    $batt = Get-CimInstance Win32_Battery -OperationTimeoutSec 8 | Select-Object -First 1
    if ($batt) {
        $statusMap = @{1="Other";2="Unknown";3="Fully Charged";4="Low";5="Critical";6="Charging";7="Charging and High";8="Charging and Low";9="Charging and Critical";10="Undefined";11="Partially Charged"}
        $batteryInfo = @{
            name             = if ($batt.Name)                      { [string]$batt.Name }                        else { "Battery" }
            status           = if ($statusMap[[int]$batt.BatteryStatus]) { $statusMap[[int]$batt.BatteryStatus] } else { "Unknown" }
            estimated_charge = if ($batt.EstimatedChargeRemaining)  { [string]$batt.EstimatedChargeRemaining + "%" } else { "" }
        }
    }
} catch {}

# 23. Local Groups
$localGroups = @()
try {
    $groups = Get-LocalGroup -ErrorAction SilentlyContinue
    foreach ($grp in $groups) {
        $memberNames = @()
        try {
            $members = Get-LocalGroupMember -Group $grp.Name -ErrorAction SilentlyContinue
            $memberNames = $members | ForEach-Object { ($_.Name -split "\\")[-1] }
        } catch {}
        $localGroups += @{
            name        = [string]$grp.Name
            description = if ($grp.Description) { [string]$grp.Description } else { "" }
            members     = $memberNames -join ", "
        }
    }
} catch {}

# 24. Startup Items
$startupItems = @()
try {
    $startups = Get-CimInstance Win32_StartupCommand -OperationTimeoutSec 8 -ErrorAction SilentlyContinue
    foreach ($s in $startups) {
        $startupItems += @{
            name     = if ($s.Name)     { [string]$s.Name }     else { "" }
            command  = if ($s.Command)  { [string]$s.Command }  else { "" }
            location = if ($s.Location) { [string]$s.Location } else { "" }
            user     = if ($s.User)     { [string]$s.User }     else { "" }
        }
    }
} catch {}
try {
    $runPaths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
    foreach ($path in $runPaths) {
        $loc = if ($path -like "HKLM*") { "HKLM Run" } else { "HKCU Run" }
        $entries = Get-ItemProperty $path -ErrorAction SilentlyContinue
        if ($entries) {
            $entries.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                $startupItems += @{ name = [string]$_.Name; command = [string]$_.Value; location = $loc; user = "" }
            }
        }
    }
} catch {}

# 25. Network Connections (established + listening)
$networkConnections = @()
try {
    $tcpConns = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.State -in @("Established","Listen") }
    foreach ($c in $tcpConns) {
        $networkConnections += @{
            protocol       = "TCP"
            local_address  = [string]$c.LocalAddress
            local_port     = [string]$c.LocalPort
            remote_address = [string]$c.RemoteAddress
            remote_port    = [string]$c.RemotePort
            state          = [string]$c.State
            pid            = [string]$c.OwningProcess
        }
    }
} catch {}
try {
    $udpEps = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object -First 30
    foreach ($u in $udpEps) {
        $networkConnections += @{
            protocol       = "UDP"
            local_address  = [string]$u.LocalAddress
            local_port     = [string]$u.LocalPort
            remote_address = ""
            remote_port    = ""
            state          = "Listen"
            pid            = [string]$u.OwningProcess
        }
    }
} catch {}

# 26. Routing Table
$routingTable = @()
try {
    $routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.RouteMetric -lt 9999 }
    foreach ($r in $routes) {
        $routingTable += @{
            destination = [string]$r.DestinationPrefix
            gateway     = if ($r.NextHop) { [string]$r.NextHop } else { "" }
            interface   = [string]$r.InterfaceAlias
            metric      = [string]$r.RouteMetric
        }
    }
} catch {}

# 27. Filesystem Info (type + mount)
$filesystemInfo = @()
try {
    $vols = Get-CimInstance Win32_LogicalDisk -OperationTimeoutSec 8 | Where-Object { $_.DriveType -in @(2, 3, 4) }
    foreach ($v in $vols) {
        $total = if ($v.Size)      { [string][math]::Round($v.Size / 1GB, 2) + " GB" }                             else { "" }
        $free  = if ($v.FreeSpace) { [string][math]::Round($v.FreeSpace / 1GB, 2) + " GB" }                        else { "" }
        $used  = if ($v.Size -and $v.FreeSpace) { [string][math]::Round(($v.Size - $v.FreeSpace) / 1GB, 2) + " GB" } else { "" }
        $pct   = if ($v.Size -and $v.Size -gt 0) { [string][math]::Round((($v.Size - $v.FreeSpace) / $v.Size) * 100, 1) + "%" } else { "" }
        $filesystemInfo += @{
            device      = [string]$v.DeviceID
            mount_point = [string]$v.DeviceID
            fs_type     = if ($v.FileSystem) { [string]$v.FileSystem } else { "Unknown" }
            total       = $total; used = $used; free = $free; use_percent = $pct
        }
    }
} catch {}

# 28. File Integrity (SHA-256 of critical system files)
$fileIntegrity = @()
$criticalFiles = @(
    "C:\Windows\System32\drivers\etc\hosts",
    "C:\Windows\System32\ntoskrnl.exe",
    "C:\Windows\System32\lsass.exe",
    "C:\Windows\System32\winlogon.exe",
    "C:\Windows\System32\services.exe",
    "C:\Windows\System32\cmd.exe",
    "C:\Windows\System32\powershell.exe"
)
foreach ($file in $criticalFiles) {
    try {
        if (Test-Path $file) {
            $fi   = Get-Item $file -ErrorAction SilentlyContinue
            $hash = (Get-FileHash $file -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            $fileIntegrity += @{
                path     = $file
                sha256   = if ($hash)              { [string]$hash }                                              else { "" }
                size     = if ($fi -and $fi.Length) { [string][math]::Round($fi.Length / 1KB, 2) + " KB" }       else { "" }
                modified = if ($fi -and $fi.LastWriteTime) { $fi.LastWriteTime.ToString("dd-MMM-yyyy HH:mm:ss") } else { "" }
            }
        }
    } catch {}
}

# 29. Process Events (recent process creation — Security log Event ID 4688)
$processEvents = @()
try {
    $procEvts = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 20 -ErrorAction SilentlyContinue
    foreach ($ev in $procEvts) {
        $msg       = [string]$ev.Message
        $procName  = if ($msg -match 'New Process Name:\s+(.+)')     { $matches[1].Trim() } else { "" }
        $cmdLine   = if ($msg -match 'Process Command Line:\s+(.+)') { $matches[1].Trim() } else { "" }
        $evPid     = if ($msg -match 'New Process ID:\s+(\S+)')      { $matches[1].Trim() } else { "" }
        $parentPid = if ($msg -match 'Creator Process ID:\s+(\S+)')  { $matches[1].Trim() } else { "" }
        $evUser    = if ($msg -match 'Account Name:\s+(\S+)')        { $matches[1].Trim() } else { "" }
        if ($msg.Length -gt 200) { $msg = $msg.Substring(0, 200) }
        $processEvents += @{
            time         = $ev.TimeCreated.ToString("dd-MMM-yyyy HH:mm:ss")
            pid          = $evPid
            parent_pid   = $parentPid
            process_name = $procName
            command_line = $cmdLine
            user         = $evUser
        }
    }
} catch {}

# 30. Security Policy
$securityPolicy = @{
    min_password_length  = ""
    password_complexity  = ""
    lockout_threshold    = ""
    screen_lock_timeout  = ""
    auto_updates_enabled = ""
    remote_login_enabled = ""
    antivirus_enabled    = ""
    antivirus_definitions = ""
}
try {
    $passPolicy = Get-LocalPasswordPolicy -ErrorAction SilentlyContinue
    if ($passPolicy) {
        $securityPolicy["min_password_length"] = [string]$passPolicy.MinPasswordLength
        $securityPolicy["password_complexity"] = if ($passPolicy.PasswordComplexity) { "Enabled" } else { "Disabled" }
        $securityPolicy["lockout_threshold"]   = [string]$passPolicy.LockoutThreshold
    }
} catch {}
try {
    $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($mpStatus) {
        $securityPolicy["antivirus_enabled"]     = if ($mpStatus.AntivirusEnabled) { "Enabled" } else { "Disabled" }
        $securityPolicy["antivirus_definitions"] = [string]$mpStatus.AntivirusSignatureLastUpdated
    }
} catch {}
try {
    $rdp = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue).fDenyTSConnections
    $securityPolicy["remote_login_enabled"] = if ($rdp -eq 0) { "Enabled (RDP)" } else { "Disabled (RDP)" }
} catch {}
try {
    $lockTimeout = (Get-ItemProperty "HKCU:\Control Panel\Desktop" -ErrorAction SilentlyContinue).ScreenSaveTimeOut
    $securityPolicy["screen_lock_timeout"] = if ($lockTimeout) { $lockTimeout + " sec" } else { "" }
} catch {}
try {
    $auOpt = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -ErrorAction SilentlyContinue).AUOptions
    $securityPolicy["auto_updates_enabled"] = switch ([int]$auOpt) { 2{"Notify only"} 3{"Auto download"} 4{"Auto install"} default{"Unknown"} }
} catch {}

# 31. Container Images
$containerImages = @()
try {
    if (& docker --version 2>$null) {
        $imgLines = & docker images --format "{{.Repository}}`t{{.Tag}}`t{{.ID}}`t{{.Size}}`t{{.CreatedSince}}" 2>$null
        foreach ($line in $imgLines) {
            $parts = $line -split "`t"
            if ($parts.Count -ge 5) {
                $containerImages += @{
                    repository = [string]$parts[0]
                    tag        = [string]$parts[1]
                    image_id   = [string]$parts[2]
                    size       = [string]$parts[3]
                    created    = [string]$parts[4]
                }
            }
        }
    }
} catch {}

# 32. Build JSON and Upload
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
    disk_info             = $diskInfo
    installed_apps        = $installedApps
    local_users           = $localUsers
    running_services      = $runningServices
    open_ports            = $openPorts
    security_posture      = $securityPosture
    docker_info           = $dockerInfo
    running_processes     = $runningProcesses
    ssl_certificates      = $sslCerts
    browser_extensions    = $browserExtensions
    event_logs            = $eventLogs
    gpu_info              = $gpuInfo
    battery_info          = $batteryInfo
    local_groups          = $localGroups
    startup_items         = $startupItems
    network_connections   = $networkConnections
    routing_table         = $routingTable
    filesystem_info       = $filesystemInfo
    file_integrity        = $fileIntegrity
    process_events        = $processEvents
    security_policy       = $securityPolicy
    container_images      = $containerImages
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
