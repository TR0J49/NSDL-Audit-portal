#!/bin/bash
# ==============================================================================
#                 InfraPulse WORKSTATION COMPLIANCE AUDIT SCRIPT
# ==============================================================================
# Version: 2.0.0

echo "Collecting Workstation Compliance Data..."

OS_TYPE=$(uname -s)
COMPUTER=$(hostname)

# 2. OS Details
if [ "$OS_TYPE" = "Darwin" ]; then
    OS_NAME=$(sw_vers -productName 2>/dev/null || echo "macOS")
    OS_VERSION=$(sw_vers -productVersion 2>/dev/null || uname -r)
else
    OS_NAME=$(grep -oP '(?<=^NAME=).+' /etc/os-release 2>/dev/null | tr -d '"' || uname -s)
    OS_VERSION=$(uname -r)
fi
ARCHITECTURE=$(uname -m)

# 3. License Status
if [ "$OS_TYPE" = "Darwin" ]; then
    LICENSE_STATUS="macOS Licensed"
else
    LICENSE_STATUS="Open Source"
fi

# 4. Antivirus
ANTIVIRUS="Not Detected"
if command -v clamscan &>/dev/null; then ANTIVIRUS="ClamAV"
elif [ -f "/opt/sophos-av/bin/savdstatus" ]; then ANTIVIRUS="Sophos"
elif [ -f "/opt/BitDefender-Security-Tools/bin/bd" ]; then ANTIVIRUS="Bitdefender"
elif [ "$OS_TYPE" = "Darwin" ]; then
    if [ -d "/Applications/Malwarebytes.app" ]; then ANTIVIRUS="Malwarebytes"
    elif [ -d "/Library/Application Support/com.symantec.sym.agent" ]; then ANTIVIRUS="Symantec"
    fi
fi

# 5. Primary MAC Address
MAC="Unknown"
if [ "$OS_TYPE" = "Darwin" ]; then
    MAC=$(ifconfig en0 2>/dev/null | awk '/ether/{print $2}' | tr '[:lower:]' '[:upper:]' | tr -d ':')
else
    MAC=$(ip link show 2>/dev/null | awk '/ether/{print $2}' | head -1 | tr '[:lower:]' '[:upper:]' | tr -d ':')
    [ -z "$MAC" ] && MAC=$(ifconfig 2>/dev/null | awk '/ether/{print $2}' | head -1 | tr '[:lower:]' '[:upper:]' | tr -d ':')
fi

# 6. CD/DVD Drive
DRIVE_NAME="No CD Unit Found"
if [ "$OS_TYPE" = "Darwin" ]; then
    DRIVE=$(system_profiler SPDiscBurningDataType 2>/dev/null | grep "Model:" | head -1 | awk -F': ' '{print $2}')
    [ -n "$DRIVE" ] && DRIVE_NAME="$DRIVE"
else
    DRIVE=$(lsblk -d -o NAME,TYPE 2>/dev/null | awk '$2=="rom"{print $1}' | head -1)
    [ -n "$DRIVE" ] && DRIVE_NAME="/dev/$DRIVE"
fi

# 7. Printers
PRINTERS_JSON="[]"
if command -v lpstat &>/dev/null; then
    PRINTER_LIST=$(lpstat -p 2>/dev/null | awk '/^printer/{print $2}')
    if [ -n "$PRINTER_LIST" ]; then
        PRINTERS_JSON="["
        FIRST=true
        while IFS= read -r p; do
            [ -z "$p" ] && continue
            $FIRST || PRINTERS_JSON="$PRINTERS_JSON,"
            PRINTERS_JSON="${PRINTERS_JSON}{\"name\":\"$p\",\"system_name\":\"$COMPUTER\",\"enable_bidi\":\"False\",\"extended_printer_status\":\"0\",\"port_name\":\"Unknown\"}"
            FIRST=false
        done <<< "$PRINTER_LIST"
        PRINTERS_JSON="$PRINTERS_JSON]"
    fi
fi

# 8. Recent Updates / Hotfixes (last 20)
HOTFIXES_JSON="[]"
build_hf() { echo "{\"caption\":\"\",\"cs_name\":\"$COMPUTER\",\"description\":\"$2\",\"fix_id\":\"$3\",\"installed_on\":\"$4\"}"; }

if [ "$OS_TYPE" = "Darwin" ]; then
    mapfile -t UPDATES < <(softwareupdate --history 2>/dev/null | tail -n +3 | head -20)
    if [ ${#UPDATES[@]} -gt 0 ]; then
        HOTFIXES_JSON="["; FIRST=true
        for line in "${UPDATES[@]}"; do
            [ -z "$line" ] && continue
            FIX_ID=$(echo "$line" | awk '{print $1}')
            DATE=$(echo "$line" | awk '{print $NF}')
            $FIRST || HOTFIXES_JSON="$HOTFIXES_JSON,"
            HOTFIXES_JSON="$HOTFIXES_JSON$(build_hf "$COMPUTER" "Software Update" "$FIX_ID" "$DATE")"
            FIRST=false
        done
        HOTFIXES_JSON="$HOTFIXES_JSON]"
    fi
elif command -v apt &>/dev/null && [ -f /var/log/dpkg.log ]; then
    mapfile -t UPDATES < <(grep " install " /var/log/dpkg.log 2>/dev/null | tail -20)
    if [ ${#UPDATES[@]} -gt 0 ]; then
        HOTFIXES_JSON="["; FIRST=true
        for line in "${UPDATES[@]}"; do
            [ -z "$line" ] && continue
            PKG=$(echo "$line" | awk '{print $4}')
            DATE=$(echo "$line" | awk '{print $1}')
            $FIRST || HOTFIXES_JSON="$HOTFIXES_JSON,"
            HOTFIXES_JSON="$HOTFIXES_JSON$(build_hf "$COMPUTER" "Package Install" "$PKG" "$DATE")"
            FIRST=false
        done
        HOTFIXES_JSON="$HOTFIXES_JSON]"
    fi
elif command -v rpm &>/dev/null; then
    mapfile -t UPDATES < <(rpm -qa --last 2>/dev/null | head -20)
    if [ ${#UPDATES[@]} -gt 0 ]; then
        HOTFIXES_JSON="["; FIRST=true
        for line in "${UPDATES[@]}"; do
            [ -z "$line" ] && continue
            PKG=$(echo "$line" | awk '{print $1}')
            DATE=$(echo "$line" | awk '{print $2,$3,$4}')
            $FIRST || HOTFIXES_JSON="$HOTFIXES_JSON,"
            HOTFIXES_JSON="$HOTFIXES_JSON$(build_hf "$COMPUTER" "RPM Package" "$PKG" "$DATE")"
            FIRST=false
        done
        HOTFIXES_JSON="$HOTFIXES_JSON]"
    fi
fi

# 9. Network Adapters - ipconfig equivalent
NETWORK_ADAPTERS_JSON="[]"
if [ "$OS_TYPE" = "Darwin" ]; then
    # macOS: use ifconfig + networksetup
    mapfile -t IFACES < <(ifconfig -l 2>/dev/null | tr ' ' '\n' | grep -v '^lo')
    if [ ${#IFACES[@]} -gt 0 ]; then
        NETWORK_ADAPTERS_JSON="["; FIRST=true
        for iface in "${IFACES[@]}"; do
            [ -z "$iface" ] && continue
            IP=$(ifconfig "$iface" 2>/dev/null | awk '/inet /{print $2}' | head -1)
            [ -z "$IP" ] && continue
            MASK=$(ifconfig "$iface" 2>/dev/null | awk '/inet /{print $4}' | head -1)
            MAC_A=$(ifconfig "$iface" 2>/dev/null | awk '/ether/{print $2}' | head -1)
            GW=$(route -n get default 2>/dev/null | awk '/gateway:/{print $2}')
            DNS=$(scutil --dns 2>/dev/null | awk '/nameserver/{print $3}' | sort -u | head -3 | tr '\n' ',' | sed 's/,$//')
            $FIRST || NETWORK_ADAPTERS_JSON="$NETWORK_ADAPTERS_JSON,"
            NETWORK_ADAPTERS_JSON="$NETWORK_ADAPTERS_JSON{\"name\":\"$iface\",\"mac_address\":\"${MAC_A:-}\",\"ip_address\":\"${IP:-}\",\"subnet_mask\":\"${MASK:-}\",\"default_gateway\":\"${GW:-}\",\"dhcp_enabled\":\"True\",\"dhcp_server\":\"\",\"dns_servers\":\"${DNS:-}\"}"
            FIRST=false
        done
        NETWORK_ADAPTERS_JSON="$NETWORK_ADAPTERS_JSON]"
    fi
else
    # Linux: use ip addr
    mapfile -t IFACES < <(ip -o link show 2>/dev/null | awk -F': ' '!/lo/{print $2}')
    if [ ${#IFACES[@]} -gt 0 ]; then
        NETWORK_ADAPTERS_JSON="["; FIRST=true
        for iface in "${IFACES[@]}"; do
            [ -z "$iface" ] && continue
            IP=$(ip -4 addr show "$iface" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
            [ -z "$IP" ] && continue
            PREFIX=$(ip -4 addr show "$iface" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f2 | head -1)
            MAC_A=$(ip link show "$iface" 2>/dev/null | awk '/ether/{print $2}')
            GW=$(ip route show default 2>/dev/null | awk '/default via/{print $3}' | head -1)
            DNS=$(grep nameserver /etc/resolv.conf 2>/dev/null | awk '{print $2}' | head -3 | tr '\n' ',' | sed 's/,$//')
            DHCP="False"
            command -v dhclient &>/dev/null && DHCP="True"
            $FIRST || NETWORK_ADAPTERS_JSON="$NETWORK_ADAPTERS_JSON,"
            NETWORK_ADAPTERS_JSON="$NETWORK_ADAPTERS_JSON{\"name\":\"$iface\",\"mac_address\":\"${MAC_A:-}\",\"ip_address\":\"${IP:-}\",\"subnet_mask\":\"${PREFIX:-} (prefix)\",\"default_gateway\":\"${GW:-}\",\"dhcp_enabled\":\"$DHCP\",\"dhcp_server\":\"\",\"dns_servers\":\"${DNS:-}\"}"
            FIRST=false
        done
        NETWORK_ADAPTERS_JSON="$NETWORK_ADAPTERS_JSON]"
    fi
fi

# 10. System Info - systeminfo equivalent
SYS_MANUFACTURER="Unknown"
SYS_MODEL="Unknown"
PROCESSOR="Unknown"
TOTAL_RAM="Unknown"
BIOS_VERSION="Unknown"
DOMAIN="Unknown"
LOGON_SERVER="Unknown"
BOOT_TIME="Unknown"
TIME_ZONE="Unknown"
REGISTERED_OWNER="Unknown"
WINDOWS_DIRECTORY="N/A"

if [ "$OS_TYPE" = "Darwin" ]; then
    SYS_MANUFACTURER="Apple Inc."
    SYS_MODEL=$(system_profiler SPHardwareDataType 2>/dev/null | awk -F': ' '/Model Name/{print $2}' | xargs)
    PROCESSOR=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "Unknown")
    TOTAL_RAM=$(sysctl -n hw.memsize 2>/dev/null | awk '{printf "%.2f GB", $1/1073741824}')
    BIOS_VERSION=$(system_profiler SPHardwareDataType 2>/dev/null | awk -F': ' '/Boot ROM Version/{print $2}' | xargs)
    DOMAIN=$(dsconfigad -show 2>/dev/null | awk -F'=' '/Active Directory Domain/{print $2}' | xargs || echo "WORKGROUP")
    LOGON_SERVER=$(echo "$COMPUTERNAME")
    BOOT_TIME=$(sysctl -n kern.boottime 2>/dev/null | awk -F'[=,]' '{print $2}' | xargs -I{} date -r {} "+%d-%b-%Y %H:%M:%S" 2>/dev/null || echo "Unknown")
    TIME_ZONE=$(readlink /etc/localtime 2>/dev/null | sed 's|.*zoneinfo/||')
    REGISTERED_OWNER=$(id -F 2>/dev/null || whoami)
    WINDOWS_DIRECTORY="N/A"
else
    SYS_MANUFACTURER=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || echo "Unknown")
    SYS_MODEL=$(cat /sys/class/dmi/id/product_name 2>/dev/null || echo "Unknown")
    PROCESSOR=$(grep -m1 "model name" /proc/cpuinfo 2>/dev/null | awk -F': ' '{print $2}' || echo "Unknown")
    TOTAL_RAM=$(awk '/MemTotal/{printf "%.2f GB", $2/1048576}' /proc/meminfo 2>/dev/null || echo "Unknown")
    BIOS_VERSION=$(cat /sys/class/dmi/id/bios_version 2>/dev/null || echo "Unknown")
    DOMAIN=$(hostname -d 2>/dev/null || echo "WORKGROUP")
    LOGON_SERVER=$(whoami)
    BOOT_TIME=$(who -b 2>/dev/null | awk '{print $3,$4}' || uptime -s 2>/dev/null || echo "Unknown")
    TIME_ZONE=$(timedatectl 2>/dev/null | awk '/Time zone/{print $3}' || cat /etc/timezone 2>/dev/null || echo "Unknown")
    REGISTERED_OWNER=$(getent passwd "$(whoami)" 2>/dev/null | cut -d: -f5 | cut -d, -f1 || whoami)
    WINDOWS_DIRECTORY="N/A"
fi

# 11. Build JSON payload
JSON=$(cat <<EOF
{
  "computer_name": "$COMPUTER",
  "os_name": "$OS_NAME",
  "os_version": "$OS_VERSION",
  "architecture": "$ARCHITECTURE",
  "license_status": "$LICENSE_STATUS",
  "antivirus": ["$ANTIVIRUS"],
  "mac_address": "$MAC",
  "drive_name": "$DRIVE_NAME",
  "printers": $PRINTERS_JSON,
  "hotfixes": $HOTFIXES_JSON,
  "network_adapters": $NETWORK_ADAPTERS_JSON,
  "system_manufacturer": "$SYS_MANUFACTURER",
  "system_model": "$SYS_MODEL",
  "processor": "$PROCESSOR",
  "total_physical_memory": "$TOTAL_RAM",
  "bios_version": "$BIOS_VERSION",
  "domain": "$DOMAIN",
  "logon_server": "$LOGON_SERVER",
  "system_boot_time": "$BOOT_TIME",
  "time_zone": "$TIME_ZONE",
  "registered_owner": "$REGISTERED_OWNER",
  "windows_directory": "$WINDOWS_DIRECTORY"
}
EOF
)

CLIENT_ID="CLIENT_ID_PLACEHOLDER"
AUDIT_TOKEN="AUDIT_TOKEN_PLACEHOLDER"
API_URL="API_BASE_URL_PLACEHOLDER/upload-audit?client_id=$CLIENT_ID&audit_token=$AUDIT_TOKEN"

echo "Uploading secure payload to backend..."
if curl -s -X POST "$API_URL" -H "Content-Type: application/json" -d "$JSON"; then
    echo "Audit upload completed successfully!"
else
    echo "Upload failed."
fi
