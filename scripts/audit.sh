#!/bin/bash
# ==============================================================================
#                 InfraPulse WORKSTATION COMPLIANCE AUDIT SCRIPT
# ==============================================================================
# Version: 3.0.0

echo "Collecting Workstation Compliance Data..."

OS_TYPE=$(uname -s)
COMPUTER=$(hostname)

# Helper: escape string for JSON
json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/ /g'; }

# 1. OS Details
if [ "$OS_TYPE" = "Darwin" ]; then
    OS_NAME=$(sw_vers -productName 2>/dev/null || echo "macOS")
    OS_VERSION=$(sw_vers -productVersion 2>/dev/null || uname -r)
else
    OS_NAME=$(grep -oP '(?<=^NAME=).+' /etc/os-release 2>/dev/null | tr -d '"' || uname -s)
    OS_VERSION=$(uname -r)
fi
ARCHITECTURE=$(uname -m)

# 2. License Status
if [ "$OS_TYPE" = "Darwin" ]; then
    LICENSE_STATUS="macOS Licensed"
else
    LICENSE_STATUS="Open Source"
fi

# 3. Antivirus
ANTIVIRUS="Not Detected"
if command -v clamscan &>/dev/null; then ANTIVIRUS="ClamAV"
elif [ -f "/opt/sophos-av/bin/savdstatus" ]; then ANTIVIRUS="Sophos"
elif [ -f "/opt/BitDefender-Security-Tools/bin/bd" ]; then ANTIVIRUS="Bitdefender"
elif [ "$OS_TYPE" = "Darwin" ]; then
    if [ -d "/Applications/Malwarebytes.app" ]; then ANTIVIRUS="Malwarebytes"
    elif [ -d "/Library/Application Support/com.symantec.sym.agent" ]; then ANTIVIRUS="Symantec"
    else ANTIVIRUS="XProtect (Built-in)"
    fi
fi

# 4. Primary MAC Address
MAC="Unknown"
if [ "$OS_TYPE" = "Darwin" ]; then
    MAC=$(ifconfig en0 2>/dev/null | awk '/ether/{print $2}' | tr '[:lower:]' '[:upper:]' | tr -d ':')
else
    MAC=$(ip link show 2>/dev/null | awk '/ether/{print $2}' | head -1 | tr '[:lower:]' '[:upper:]' | tr -d ':')
    [ -z "$MAC" ] && MAC=$(ifconfig 2>/dev/null | awk '/ether/{print $2}' | head -1 | tr '[:lower:]' '[:upper:]' | tr -d ':')
fi

# 5. CD/DVD Drive
DRIVE_NAME="No CD Unit Found"
if [ "$OS_TYPE" = "Darwin" ]; then
    DRIVE=$(system_profiler SPDiscBurningDataType 2>/dev/null | grep "Model:" | head -1 | awk -F': ' '{print $2}')
    [ -n "$DRIVE" ] && DRIVE_NAME="$DRIVE"
else
    DRIVE=$(lsblk -d -o NAME,TYPE 2>/dev/null | awk '$2=="rom"{print $1}' | head -1)
    [ -n "$DRIVE" ] && DRIVE_NAME="/dev/$DRIVE"
fi

# 6. Printers
PRINTERS_JSON="[]"
if command -v lpstat &>/dev/null; then
    PRINTER_LIST=$(lpstat -p 2>/dev/null | awk '/^printer/{print $2}')
    if [ -n "$PRINTER_LIST" ]; then
        PRINTERS_JSON="["; FIRST=true
        while IFS= read -r p; do
            [ -z "$p" ] && continue
            $FIRST || PRINTERS_JSON="$PRINTERS_JSON,"
            PRINTERS_JSON="${PRINTERS_JSON}{\"name\":\"$(json_escape "$p")\",\"system_name\":\"$COMPUTER\",\"enable_bidi\":\"False\",\"extended_printer_status\":\"0\",\"port_name\":\"Unknown\"}"
            FIRST=false
        done <<< "$PRINTER_LIST"
        PRINTERS_JSON="$PRINTERS_JSON]"
    fi
fi

# 7. Recent Updates / Hotfixes (last 20)
HOTFIXES_JSON="[]"
build_hf() { echo "{\"caption\":\"\",\"cs_name\":\"$COMPUTER\",\"description\":\"$2\",\"fix_id\":\"$(json_escape "$3")\",\"installed_on\":\"$4\"}"; }

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

# 8. Network Adapters
NETWORK_ADAPTERS_JSON="[]"
if [ "$OS_TYPE" = "Darwin" ]; then
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
            IPV6=$(ifconfig "$iface" 2>/dev/null | awk '/inet6 /{print $2}' | grep -v '^fe80' | grep -v '^::1' | head -1)
            IPV6_LL=$(ifconfig "$iface" 2>/dev/null | awk '/inet6.*fe80/{print $2}' | head -1)
            $FIRST || NETWORK_ADAPTERS_JSON="$NETWORK_ADAPTERS_JSON,"
            NETWORK_ADAPTERS_JSON="$NETWORK_ADAPTERS_JSON{\"name\":\"$iface\",\"mac_address\":\"${MAC_A:-}\",\"ip_address\":\"${IP:-}\",\"subnet_mask\":\"${MASK:-}\",\"default_gateway\":\"${GW:-}\",\"ipv6_address\":\"${IPV6:-}\",\"temp_ipv6_address\":\"\",\"link_local_ipv6\":\"${IPV6_LL:-}\",\"dhcp_enabled\":\"True\",\"dhcp_server\":\"\",\"dns_servers\":\"${DNS:-}\"}"
            FIRST=false
        done
        NETWORK_ADAPTERS_JSON="$NETWORK_ADAPTERS_JSON]"
    fi
else
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
            IPV6=$(ip -6 addr show "$iface" 2>/dev/null | awk '/inet6 /{print $2}' | grep -v '^fe80' | grep -v '^::1' | head -1 | cut -d/ -f1)
            IPV6_TEMP=$(ip -6 addr show "$iface" 2>/dev/null | grep 'temporary' | awk '{print $2}' | head -1 | cut -d/ -f1)
            IPV6_LL=$(ip -6 addr show "$iface" 2>/dev/null | awk '/inet6.*fe80/{print $2}' | head -1 | cut -d/ -f1)
            $FIRST || NETWORK_ADAPTERS_JSON="$NETWORK_ADAPTERS_JSON,"
            NETWORK_ADAPTERS_JSON="$NETWORK_ADAPTERS_JSON{\"name\":\"$iface\",\"mac_address\":\"${MAC_A:-}\",\"ip_address\":\"${IP:-}\",\"subnet_mask\":\"${PREFIX:-} (prefix)\",\"default_gateway\":\"${GW:-}\",\"ipv6_address\":\"${IPV6:-}\",\"temp_ipv6_address\":\"${IPV6_TEMP:-}\",\"link_local_ipv6\":\"${IPV6_LL:-}\",\"dhcp_enabled\":\"$DHCP\",\"dhcp_server\":\"\",\"dns_servers\":\"${DNS:-}\"}"
            FIRST=false
        done
        NETWORK_ADAPTERS_JSON="$NETWORK_ADAPTERS_JSON]"
    fi
fi

# 9. System Info
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

# 10. Disk Info
DISK_INFO_JSON="[]"
if [ "$OS_TYPE" = "Darwin" ]; then
    mapfile -t DISK_LINES < <(df -h 2>/dev/null | grep -E '^/dev/' | grep -v 'devfs')
else
    mapfile -t DISK_LINES < <(df -h 2>/dev/null | grep -E '^/dev/')
fi
if [ ${#DISK_LINES[@]} -gt 0 ]; then
    DISK_INFO_JSON="["; FIRST=true
    for line in "${DISK_LINES[@]}"; do
        DRIVE=$(echo "$line" | awk '{print $1}')
        TOTAL=$(echo "$line" | awk '{print $2}')
        USED=$(echo "$line" | awk '{print $3}')
        FREE=$(echo "$line" | awk '{print $4}')
        $FIRST || DISK_INFO_JSON="$DISK_INFO_JSON,"
        DISK_INFO_JSON="$DISK_INFO_JSON{\"drive\":\"$(json_escape "$DRIVE")\",\"total\":\"$TOTAL\",\"used\":\"$USED\",\"free\":\"$FREE\"}"
        FIRST=false
    done
    DISK_INFO_JSON="$DISK_INFO_JSON]"
fi

# 11. Installed Apps (capped at 100)
INSTALLED_APPS_JSON="[]"
if [ "$OS_TYPE" = "Darwin" ]; then
    mapfile -t APP_DIRS < <(ls -d /Applications/*.app 2>/dev/null | head -100)
    if [ ${#APP_DIRS[@]} -gt 0 ]; then
        INSTALLED_APPS_JSON="["; FIRST=true
        for appdir in "${APP_DIRS[@]}"; do
            APP=$(basename "$appdir" .app)
            APP_ESC=$(json_escape "$APP")
            VER=$(defaults read "${appdir}/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "")
            $FIRST || INSTALLED_APPS_JSON="$INSTALLED_APPS_JSON,"
            INSTALLED_APPS_JSON="$INSTALLED_APPS_JSON{\"name\":\"$APP_ESC\",\"version\":\"$(json_escape "$VER")\",\"publisher\":\"\"}"
            FIRST=false
        done
        INSTALLED_APPS_JSON="$INSTALLED_APPS_JSON]"
    fi
elif command -v dpkg-query &>/dev/null; then
    mapfile -t APP_LIST < <(dpkg-query -W -f='${Package}\t${Version}\t${Maintainer}\n' 2>/dev/null | head -100)
    if [ ${#APP_LIST[@]} -gt 0 ]; then
        INSTALLED_APPS_JSON="["; FIRST=true
        for line in "${APP_LIST[@]}"; do
            NAME=$(echo "$line" | awk -F'\t' '{print $1}')
            VER=$(echo "$line" | awk -F'\t' '{print $2}')
            PUB=$(echo "$line" | awk -F'\t' '{print $3}' | cut -c1-60)
            $FIRST || INSTALLED_APPS_JSON="$INSTALLED_APPS_JSON,"
            INSTALLED_APPS_JSON="$INSTALLED_APPS_JSON{\"name\":\"$(json_escape "$NAME")\",\"version\":\"$(json_escape "$VER")\",\"publisher\":\"$(json_escape "$PUB")\"}"
            FIRST=false
        done
        INSTALLED_APPS_JSON="$INSTALLED_APPS_JSON]"
    fi
elif command -v rpm &>/dev/null; then
    mapfile -t APP_LIST < <(rpm -qa --queryformat '%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n' 2>/dev/null | head -100)
    if [ ${#APP_LIST[@]} -gt 0 ]; then
        INSTALLED_APPS_JSON="["; FIRST=true
        for line in "${APP_LIST[@]}"; do
            NAME=$(echo "$line" | awk -F'\t' '{print $1}')
            VER=$(echo "$line" | awk -F'\t' '{print $2}')
            PUB=$(echo "$line" | awk -F'\t' '{print $3}' | cut -c1-60)
            $FIRST || INSTALLED_APPS_JSON="$INSTALLED_APPS_JSON,"
            INSTALLED_APPS_JSON="$INSTALLED_APPS_JSON{\"name\":\"$(json_escape "$NAME")\",\"version\":\"$(json_escape "$VER")\",\"publisher\":\"$(json_escape "$PUB")\"}"
            FIRST=false
        done
        INSTALLED_APPS_JSON="$INSTALLED_APPS_JSON]"
    fi
fi

# 12. Local Users
LOCAL_USERS_JSON="[]"
if [ "$OS_TYPE" = "Darwin" ]; then
    mapfile -t ULIST < <(dscl . list /Users 2>/dev/null | grep -v '^_' | grep -v '^root$' | grep -v '^daemon$' | grep -v '^nobody$')
    ADMIN_USERS=$(dscl . read /Groups/admin GroupMembership 2>/dev/null | sed 's/GroupMembership: //')
    if [ ${#ULIST[@]} -gt 0 ]; then
        LOCAL_USERS_JSON="["; FIRST=true
        for u in "${ULIST[@]}"; do
            [ -z "$u" ] && continue
            ISADMIN="False"
            echo "$ADMIN_USERS" | grep -qw "$u" && ISADMIN="True"
            $FIRST || LOCAL_USERS_JSON="$LOCAL_USERS_JSON,"
            LOCAL_USERS_JSON="$LOCAL_USERS_JSON{\"name\":\"$(json_escape "$u")\",\"enabled\":\"True\",\"admin\":\"$ISADMIN\"}"
            FIRST=false
        done
        LOCAL_USERS_JSON="$LOCAL_USERS_JSON]"
    fi
else
    mapfile -t ULIST < <(getent passwd 2>/dev/null | awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}')
    SUDO_USERS=$(getent group sudo 2>/dev/null | awk -F: '{print $4}' | tr ',' ' ')
    [ -z "$SUDO_USERS" ] && SUDO_USERS=$(getent group wheel 2>/dev/null | awk -F: '{print $4}' | tr ',' ' ')
    if [ ${#ULIST[@]} -gt 0 ]; then
        LOCAL_USERS_JSON="["; FIRST=true
        for u in "${ULIST[@]}"; do
            [ -z "$u" ] && continue
            ISADMIN="False"
            echo " $SUDO_USERS " | grep -qw " $u " && ISADMIN="True"
            $FIRST || LOCAL_USERS_JSON="$LOCAL_USERS_JSON,"
            LOCAL_USERS_JSON="$LOCAL_USERS_JSON{\"name\":\"$(json_escape "$u")\",\"enabled\":\"True\",\"admin\":\"$ISADMIN\"}"
            FIRST=false
        done
        LOCAL_USERS_JSON="$LOCAL_USERS_JSON]"
    fi
fi

# 13. Running Services (top 50)
RUNNING_SERVICES_JSON="[]"
if [ "$OS_TYPE" = "Darwin" ]; then
    mapfile -t SVCLIST < <(launchctl list 2>/dev/null | awk 'NR>1 && $1 != "-" {print $3}' | head -50)
    if [ ${#SVCLIST[@]} -gt 0 ]; then
        RUNNING_SERVICES_JSON="["; FIRST=true
        for svc in "${SVCLIST[@]}"; do
            [ -z "$svc" ] && continue
            $FIRST || RUNNING_SERVICES_JSON="$RUNNING_SERVICES_JSON,"
            RUNNING_SERVICES_JSON="$RUNNING_SERVICES_JSON{\"name\":\"$(json_escape "$svc")\",\"display_name\":\"$(json_escape "$svc")\",\"start_type\":\"Automatic\"}"
            FIRST=false
        done
        RUNNING_SERVICES_JSON="$RUNNING_SERVICES_JSON]"
    fi
elif command -v systemctl &>/dev/null; then
    mapfile -t SVCLIST < <(systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print $1}' | sed 's/\.service$//' | head -50)
    if [ ${#SVCLIST[@]} -gt 0 ]; then
        RUNNING_SERVICES_JSON="["; FIRST=true
        for svc in "${SVCLIST[@]}"; do
            [ -z "$svc" ] && continue
            $FIRST || RUNNING_SERVICES_JSON="$RUNNING_SERVICES_JSON,"
            RUNNING_SERVICES_JSON="$RUNNING_SERVICES_JSON{\"name\":\"$(json_escape "$svc")\",\"display_name\":\"$(json_escape "$svc")\",\"start_type\":\"Automatic\"}"
            FIRST=false
        done
        RUNNING_SERVICES_JSON="$RUNNING_SERVICES_JSON]"
    fi
fi

# 14. Open Ports (listening)
OPEN_PORTS_JSON="[]"
if [ "$OS_TYPE" = "Darwin" ]; then
    mapfile -t PORTLIST < <(netstat -an 2>/dev/null | grep -E '^(tcp|udp)' | grep 'LISTEN' | awk '{print $4}' | rev | cut -d. -f1 | rev | sort -nu | head -50)
    PORT_PROTO="TCP"
elif command -v ss &>/dev/null; then
    mapfile -t PORTLIST < <(ss -tulnp 2>/dev/null | awk 'NR>1 {print $5}' | awk -F: '{print $NF}' | grep -E '^[0-9]+$' | sort -nu | head -50)
    PORT_PROTO="TCP/UDP"
else
    mapfile -t PORTLIST < <(netstat -tulnp 2>/dev/null | awk 'NR>2 {print $4}' | awk -F: '{print $NF}' | grep -E '^[0-9]+$' | sort -nu | head -50)
    PORT_PROTO="TCP/UDP"
fi
if [ ${#PORTLIST[@]} -gt 0 ]; then
    OPEN_PORTS_JSON="["; FIRST=true
    for port in "${PORTLIST[@]}"; do
        [ -z "$port" ] && continue
        $FIRST || OPEN_PORTS_JSON="$OPEN_PORTS_JSON,"
        OPEN_PORTS_JSON="$OPEN_PORTS_JSON{\"port\":\"$port\",\"protocol\":\"$PORT_PROTO\",\"pid\":\"\"}"
        FIRST=false
    done
    OPEN_PORTS_JSON="$OPEN_PORTS_JSON]"
fi

# 15. Security Posture
SEC_BITLOCKER=""
SEC_WINDOWS_FIREWALL=""
SEC_UAC=""
SEC_FILEVAULT="Not Checked"
SEC_GATEKEEPER="Not Checked"
SEC_SIP="Not Checked"
SEC_APPARMOR="Not Checked"
SEC_SELINUX="Not Checked"

if [ "$OS_TYPE" = "Darwin" ]; then
    FV=$(fdesetup status 2>/dev/null)
    if echo "$FV" | grep -qi "FileVault is On"; then SEC_FILEVAULT="Enabled"; else SEC_FILEVAULT="Disabled"; fi
    GK=$(spctl --status 2>/dev/null)
    if echo "$GK" | grep -qi "enabled"; then SEC_GATEKEEPER="Enabled"; else SEC_GATEKEEPER="Disabled"; fi
    SIP_STATUS=$(csrutil status 2>/dev/null)
    if echo "$SIP_STATUS" | grep -qi "enabled"; then SEC_SIP="Enabled"; else SEC_SIP="Disabled"; fi
else
    if command -v aa-status &>/dev/null; then
        aa-status --enabled 2>/dev/null && SEC_APPARMOR="Enabled" || SEC_APPARMOR="Disabled"
    elif [ -d /sys/kernel/security/apparmor ]; then
        SEC_APPARMOR="Enabled"
    else
        SEC_APPARMOR="Not Installed"
    fi
    if command -v getenforce &>/dev/null; then
        SE=$(getenforce 2>/dev/null)
        SEC_SELINUX="${SE:-Not Installed}"
    else
        SEC_SELINUX="Not Installed"
    fi
fi

# 16. Docker
DOCKER_VERSION=""
DOCKER_CONTAINERS=0
DOCKER_CONTAINERS_JSON="[]"
if command -v docker &>/dev/null; then
    DOCKER_VERSION=$(docker --version 2>/dev/null || echo "")
    if [ -n "$DOCKER_VERSION" ]; then
        mapfile -t CONTAINERS < <(docker ps --format "{{.Names}}" 2>/dev/null)
        DOCKER_CONTAINERS=${#CONTAINERS[@]}
        if [ "$DOCKER_CONTAINERS" -gt 0 ]; then
            DOCKER_CONTAINERS_JSON="["; FIRST=true
            for c in "${CONTAINERS[@]}"; do
                $FIRST || DOCKER_CONTAINERS_JSON="$DOCKER_CONTAINERS_JSON,"
                DOCKER_CONTAINERS_JSON="$DOCKER_CONTAINERS_JSON\"$(json_escape "$c")\""
                FIRST=false
            done
            DOCKER_CONTAINERS_JSON="$DOCKER_CONTAINERS_JSON]"
        fi
    fi
fi

# 17. Running Processes (top 50 by memory)
RUNNING_PROCESSES_JSON="[]"
mapfile -t PROC_LINES < <(ps -eo pid,ppid,user,%cpu,%mem,comm 2>/dev/null | sort -k5 -rn | awk 'NR>1{print}' | head -50)
if [ ${#PROC_LINES[@]} -gt 0 ]; then
    RUNNING_PROCESSES_JSON="["; FIRST=true
    for line in "${PROC_LINES[@]}"; do
        [ -z "$line" ] && continue
        P_PID=$(echo "$line" | awk '{print $1}')
        P_PPID=$(echo "$line" | awk '{print $2}')
        P_USER=$(echo "$line" | awk '{print $3}')
        P_CPU=$(echo "$line" | awk '{print $4}')
        P_MEM=$(echo "$line" | awk '{print $5}')
        P_CMD=$(echo "$line" | awk '{print $6}')
        P_NAME=$(basename "$P_CMD" 2>/dev/null || echo "$P_CMD")
        [ -z "$P_NAME" ] && continue
        $FIRST || RUNNING_PROCESSES_JSON="$RUNNING_PROCESSES_JSON,"
        RUNNING_PROCESSES_JSON="$RUNNING_PROCESSES_JSON{\"pid\":\"$P_PID\",\"name\":\"$(json_escape "$P_NAME")\",\"parent_pid\":\"$P_PPID\",\"user\":\"$(json_escape "$P_USER")\",\"path\":\"$(json_escape "$P_CMD")\",\"cpu\":\"${P_CPU}%\",\"memory\":\"${P_MEM}%\"}"
        FIRST=false
    done
    RUNNING_PROCESSES_JSON="$RUNNING_PROCESSES_JSON]"
fi

# 18. SSL Certificates
SSL_CERTS_JSON="[]"
if command -v openssl &>/dev/null; then
    if [ "$OS_TYPE" = "Darwin" ]; then
        # macOS stores CAs in a single PEM bundle — split it into individual files
        TEMP_CERT_DIR=$(mktemp -d)
        BUNDLE="/etc/ssl/cert.pem"
        [ -f "$BUNDLE" ] && awk -v tmpdir="$TEMP_CERT_DIR" '
            /-----BEGIN CERTIFICATE-----/{n++; out=tmpdir"/cert"n".pem"}
            out{print > out}
            /-----END CERTIFICATE-----/{close(out); out=""}
        ' "$BUNDLE" 2>/dev/null
        mapfile -t CERT_FILES < <(ls "$TEMP_CERT_DIR"/cert*.pem 2>/dev/null | head -20)
        # fallback: try individual files in /etc/ssl
        [ ${#CERT_FILES[@]} -eq 0 ] && mapfile -t CERT_FILES < <(find /etc/ssl 2>/dev/null \( -name "*.pem" -o -name "*.crt" \) 2>/dev/null | head -20)
    else
        mapfile -t CERT_FILES < <(find /etc/ssl/certs 2>/dev/null \( -name "*.pem" -o -name "*.crt" \) 2>/dev/null | head -20)
    fi
    if [ ${#CERT_FILES[@]} -gt 0 ]; then
        SSL_CERTS_JSON="["; FIRST=true
        for cert in "${CERT_FILES[@]}"; do
            [ -f "$cert" ] || continue
            C_SUBJECT=$(openssl x509 -noout -subject -in "$cert" 2>/dev/null | sed 's/subject=//' | head -c 100)
            C_ISSUER=$(openssl x509 -noout -issuer -in "$cert" 2>/dev/null | sed 's/issuer=//' | head -c 100)
            C_EXPIRY=$(openssl x509 -noout -enddate -in "$cert" 2>/dev/null | sed 's/notAfter=//')
            [ -z "$C_SUBJECT" ] && continue
            $FIRST || SSL_CERTS_JSON="$SSL_CERTS_JSON,"
            SSL_CERTS_JSON="$SSL_CERTS_JSON{\"subject\":\"$(json_escape "$C_SUBJECT")\",\"issuer\":\"$(json_escape "$C_ISSUER")\",\"expiry\":\"$(json_escape "$C_EXPIRY")\",\"thumbprint\":\"\"}"
            FIRST=false
        done
        SSL_CERTS_JSON="$SSL_CERTS_JSON]"
    fi
    # Clean up temp dir used for macOS cert bundle splitting
    [ -n "$TEMP_CERT_DIR" ] && rm -rf "$TEMP_CERT_DIR" 2>/dev/null
fi

# 19. Browser Extensions
BROWSER_EXTENSIONS_JSON="[]"
_scan_browser_exts() {
    local ext_dir="$1" bname="$2"
    [ -d "$ext_dir" ] || return
    for ext_id_dir in "$ext_dir"/*/; do
        [ -d "$ext_id_dir" ] || continue
        local ext_id; ext_id=$(basename "$ext_id_dir")
        local ver_dir; ver_dir=$(ls -d "$ext_id_dir"/*/ 2>/dev/null | sort -V | tail -1)
        [ -d "$ver_dir" ] || continue
        local manifest="$ver_dir/manifest.json"
        [ -f "$manifest" ] || continue
        local EXT_NAME EXT_VER
        EXT_NAME=$(grep -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' "$manifest" 2>/dev/null | head -1 | sed 's/.*: *"\(.*\)"/\1/' | head -c 60)
        EXT_VER=$(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$manifest" 2>/dev/null | head -1 | sed 's/.*: *"\(.*\)"/\1/')
        [ -z "$EXT_NAME" ] && EXT_NAME="$ext_id"
        if [ "$BROWSER_EXTENSIONS_JSON" = "[]" ]; then
            BROWSER_EXTENSIONS_JSON="["
        else
            BROWSER_EXTENSIONS_JSON="${BROWSER_EXTENSIONS_JSON%]},"
        fi
        BROWSER_EXTENSIONS_JSON="$BROWSER_EXTENSIONS_JSON{\"browser\":\"$bname\",\"name\":\"$(json_escape "$EXT_NAME")\",\"version\":\"$(json_escape "$EXT_VER")\",\"extension_id\":\"$(json_escape "$ext_id")\"}"
    done
    [ "$BROWSER_EXTENSIONS_JSON" != "[]" ] && [ "${BROWSER_EXTENSIONS_JSON: -1}" != "]" ] && BROWSER_EXTENSIONS_JSON="$BROWSER_EXTENSIONS_JSON]"
}
if [ "$OS_TYPE" = "Darwin" ]; then
    _scan_browser_exts "$HOME/Library/Application Support/Google/Chrome/Default/Extensions" "Chrome"
    _scan_browser_exts "$HOME/Library/Application Support/Microsoft Edge/Default/Extensions" "Edge"
else
    _scan_browser_exts "$HOME/.config/google-chrome/Default/Extensions" "Chrome"
    _scan_browser_exts "$HOME/.config/microsoft-edge/Default/Extensions" "Edge"
fi

# 20. System Event Logs
EVENT_LOGS_JSON="[]"
if [ "$OS_TYPE" = "Darwin" ]; then
    mapfile -t LOG_LINES < <(log show --last 1h --level error --style syslog 2>/dev/null | grep -v '^Filtering\|^--' | tail -20)
    if [ ${#LOG_LINES[@]} -gt 0 ]; then
        EVENT_LOGS_JSON="["; FIRST=true
        for line in "${LOG_LINES[@]}"; do
            [ -z "$line" ] && continue
            EV_TIME=$(echo "$line" | awk '{print $1, $2}')
            EV_SRC=$(echo "$line" | awk '{print $4}' | sed 's/\[.*\]$//' | sed 's/:$//')
            EV_MSG=$(echo "$line" | cut -d' ' -f5- | head -c 200)
            $FIRST || EVENT_LOGS_JSON="$EVENT_LOGS_JSON,"
            EVENT_LOGS_JSON="$EVENT_LOGS_JSON{\"time\":\"$(json_escape "$EV_TIME")\",\"level\":\"Error\",\"source\":\"$(json_escape "$EV_SRC")\",\"message\":\"$(json_escape "$EV_MSG")\"}"
            FIRST=false
        done
        EVENT_LOGS_JSON="$EVENT_LOGS_JSON]"
    fi
elif command -v journalctl &>/dev/null; then
    mapfile -t LOG_LINES < <(journalctl -p err -n 20 --no-pager --output=short 2>/dev/null | grep -v '^--')
    if [ ${#LOG_LINES[@]} -gt 0 ]; then
        EVENT_LOGS_JSON="["; FIRST=true
        for line in "${LOG_LINES[@]}"; do
            [ -z "$line" ] && continue
            EV_TIME=$(echo "$line" | awk '{print $1, $2, $3}')
            EV_SRC=$(echo "$line" | awk '{print $5}' | sed 's/\[.*\]$//' | sed 's/:$//')
            EV_MSG=$(echo "$line" | cut -d' ' -f6- | head -c 200)
            $FIRST || EVENT_LOGS_JSON="$EVENT_LOGS_JSON,"
            EVENT_LOGS_JSON="$EVENT_LOGS_JSON{\"time\":\"$(json_escape "$EV_TIME")\",\"level\":\"Error\",\"source\":\"$(json_escape "$EV_SRC")\",\"message\":\"$(json_escape "$EV_MSG")\"}"
            FIRST=false
        done
        EVENT_LOGS_JSON="$EVENT_LOGS_JSON]"
    fi
fi

# 21. GPU Information
GPU_INFO_JSON="[]"
if [ "$OS_TYPE" = "Darwin" ]; then
    GPU_NAME=$(system_profiler SPDisplaysDataType 2>/dev/null | awk -F': ' '/Chipset Model/{print $2; exit}' | xargs)
    [ -n "$GPU_NAME" ] && GPU_INFO_JSON="[{\"name\":\"$(json_escape "$GPU_NAME")\",\"driver_version\":\"\",\"vram\":\"\"}]"
elif command -v lspci &>/dev/null; then
    mapfile -t GPU_LINES < <(lspci 2>/dev/null | grep -iE 'vga|3d|display|nvidia|amd|intel.*graphics')
    if [ ${#GPU_LINES[@]} -gt 0 ]; then
        GPU_INFO_JSON="["; FIRST=true
        for line in "${GPU_LINES[@]}"; do
            GPU_NAME=$(echo "$line" | sed 's/^[0-9a-f:.]*[[:space:]]*[^:]*:[[:space:]]*//')
            $FIRST || GPU_INFO_JSON="$GPU_INFO_JSON,"
            GPU_INFO_JSON="$GPU_INFO_JSON{\"name\":\"$(json_escape "$GPU_NAME")\",\"driver_version\":\"\",\"vram\":\"\"}"
            FIRST=false
        done
        GPU_INFO_JSON="$GPU_INFO_JSON]"
    fi
fi

# 22. Battery Information
BATTERY_NAME=""; BATTERY_STATUS=""; BATTERY_CHARGE=""
if [ "$OS_TYPE" = "Darwin" ]; then
    BATT_OUT=$(system_profiler SPPowerDataType 2>/dev/null)
    BATTERY_NAME="MacBook Battery"
    BATTERY_STATUS=$(echo "$BATT_OUT" | awk -F': ' '/Condition/{print $2; exit}' | xargs)
    BATTERY_CHARGE=$(echo "$BATT_OUT" | awk -F': ' '/State of Charge/{print $2; exit}' | xargs)
    [ -n "$BATTERY_CHARGE" ] && BATTERY_CHARGE="${BATTERY_CHARGE}%"
elif [ -d /sys/class/power_supply ]; then
    for bat_dir in /sys/class/power_supply/BAT*; do
        [ -d "$bat_dir" ] || continue
        BATTERY_NAME=$(basename "$bat_dir")
        BATTERY_STATUS=$(cat "$bat_dir/status" 2>/dev/null || echo "")
        CAP=$(cat "$bat_dir/capacity" 2>/dev/null || echo "")
        [ -n "$CAP" ] && BATTERY_CHARGE="${CAP}%"
        break
    done
fi

# 23. Local Groups
LOCAL_GROUPS_JSON="[]"
if [ "$OS_TYPE" = "Darwin" ]; then
    mapfile -t GRPLIST < <(dscl . list /Groups 2>/dev/null | grep -v '^_' | head -30)
    if [ ${#GRPLIST[@]} -gt 0 ]; then
        LOCAL_GROUPS_JSON="["; FIRST=true
        for grp in "${GRPLIST[@]}"; do
            [ -z "$grp" ] && continue
            MEMBERS=$(dscl . read "/Groups/$grp" GroupMembership 2>/dev/null | sed 's/GroupMembership: //' | tr ' ' ',')
            $FIRST || LOCAL_GROUPS_JSON="$LOCAL_GROUPS_JSON,"
            LOCAL_GROUPS_JSON="$LOCAL_GROUPS_JSON{\"name\":\"$(json_escape "$grp")\",\"description\":\"\",\"members\":\"$(json_escape "$MEMBERS")\"}"
            FIRST=false
        done
        LOCAL_GROUPS_JSON="$LOCAL_GROUPS_JSON]"
    fi
else
    mapfile -t GRPLIST < <(getent group 2>/dev/null | awk -F: '{print $1":"$4}' | head -50)
    if [ ${#GRPLIST[@]} -gt 0 ]; then
        LOCAL_GROUPS_JSON="["; FIRST=true
        for entry in "${GRPLIST[@]}"; do
            [ -z "$entry" ] && continue
            GRP_NAME=$(echo "$entry" | cut -d: -f1)
            GRP_MEMBERS=$(echo "$entry" | cut -d: -f2)
            $FIRST || LOCAL_GROUPS_JSON="$LOCAL_GROUPS_JSON,"
            LOCAL_GROUPS_JSON="$LOCAL_GROUPS_JSON{\"name\":\"$(json_escape "$GRP_NAME")\",\"description\":\"\",\"members\":\"$(json_escape "$GRP_MEMBERS")\"}"
            FIRST=false
        done
        LOCAL_GROUPS_JSON="$LOCAL_GROUPS_JSON]"
    fi
fi

# 24. Startup Items
STARTUP_ITEMS_JSON="[]"
if [ "$OS_TYPE" = "Darwin" ]; then
    mapfile -t LD_ITEMS < <(ls /Library/LaunchDaemons/ /Library/LaunchAgents/ "$HOME/Library/LaunchAgents/" 2>/dev/null | grep '\.plist$' | head -30)
    if [ ${#LD_ITEMS[@]} -gt 0 ]; then
        STARTUP_ITEMS_JSON="["; FIRST=true
        for item in "${LD_ITEMS[@]}"; do
            [ -z "$item" ] && continue
            ITEM_NAME=$(basename "$item" .plist)
            $FIRST || STARTUP_ITEMS_JSON="$STARTUP_ITEMS_JSON,"
            STARTUP_ITEMS_JSON="$STARTUP_ITEMS_JSON{\"name\":\"$(json_escape "$ITEM_NAME")\",\"command\":\"\",\"location\":\"LaunchDaemon/Agent\",\"user\":\"\"}"
            FIRST=false
        done
        STARTUP_ITEMS_JSON="$STARTUP_ITEMS_JSON]"
    fi
else
    STARTUP_ITEMS_JSON="["; SI_FIRST=true
    mapfile -t ENABLED_UNITS < <(systemctl list-unit-files --state=enabled --type=service --no-legend 2>/dev/null | awk '{print $1}' | sed 's/\.service$//' | head -30)
    for unit in "${ENABLED_UNITS[@]}"; do
        [ -z "$unit" ] && continue
        $SI_FIRST || STARTUP_ITEMS_JSON="$STARTUP_ITEMS_JSON,"
        STARTUP_ITEMS_JSON="$STARTUP_ITEMS_JSON{\"name\":\"$(json_escape "$unit")\",\"command\":\"\",\"location\":\"systemd\",\"user\":\"\"}"
        SI_FIRST=false
    done
    mapfile -t CRON_ENTRIES < <(crontab -l 2>/dev/null | grep -v '^#' | grep -v '^$' | head -10)
    for cron in "${CRON_ENTRIES[@]}"; do
        [ -z "$cron" ] && continue
        $SI_FIRST || STARTUP_ITEMS_JSON="$STARTUP_ITEMS_JSON,"
        STARTUP_ITEMS_JSON="$STARTUP_ITEMS_JSON{\"name\":\"cron\",\"command\":\"$(json_escape "$cron")\",\"location\":\"crontab\",\"user\":\"$(whoami)\"}"
        SI_FIRST=false
    done
    [ "$SI_FIRST" = true ] && STARTUP_ITEMS_JSON="[]" || STARTUP_ITEMS_JSON="$STARTUP_ITEMS_JSON]"
fi

# 25. Network Connections (established + listening)
NETWORK_CONNECTIONS_JSON="[]"
if command -v ss &>/dev/null; then
    mapfile -t CONN_LINES < <(ss -tupan 2>/dev/null | awk 'NR>1' | head -60)
    if [ ${#CONN_LINES[@]} -gt 0 ]; then
        NETWORK_CONNECTIONS_JSON="["; FIRST=true
        for line in "${CONN_LINES[@]}"; do
            [ -z "$line" ] && continue
            PROTO=$(echo "$line" | awk '{print toupper($1)}')
            STATE=$(echo "$line" | awk '{print $2}')
            L_FULL=$(echo "$line" | awk '{print $5}')
            R_FULL=$(echo "$line" | awk '{print $6}')
            L_ADDR=$(echo "$L_FULL" | sed 's/:\([^:]*\)$//' | tr -d '[]')
            L_PORT=$(echo "$L_FULL" | rev | cut -d: -f1 | rev)
            R_ADDR=$(echo "$R_FULL" | sed 's/:\([^:]*\)$//' | tr -d '[]')
            R_PORT=$(echo "$R_FULL" | rev | cut -d: -f1 | rev)
            NC_PID=$(echo "$line" | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
            $FIRST || NETWORK_CONNECTIONS_JSON="$NETWORK_CONNECTIONS_JSON,"
            NETWORK_CONNECTIONS_JSON="$NETWORK_CONNECTIONS_JSON{\"protocol\":\"$PROTO\",\"local_address\":\"$(json_escape "$L_ADDR")\",\"local_port\":\"$L_PORT\",\"remote_address\":\"$(json_escape "$R_ADDR")\",\"remote_port\":\"$R_PORT\",\"state\":\"$(json_escape "$STATE")\",\"pid\":\"$NC_PID\"}"
            FIRST=false
        done
        NETWORK_CONNECTIONS_JSON="$NETWORK_CONNECTIONS_JSON]"
    fi
elif [ "$OS_TYPE" = "Darwin" ]; then
    mapfile -t CONN_LINES < <(netstat -an 2>/dev/null | grep -E '^(tcp|udp)' | head -60)
    if [ ${#CONN_LINES[@]} -gt 0 ]; then
        NETWORK_CONNECTIONS_JSON="["; FIRST=true
        for line in "${CONN_LINES[@]}"; do
            PROTO=$(echo "$line" | awk '{print toupper($1)}')
            STATE=$(echo "$line" | awk '{print $6}')
            L_RAW=$(echo "$line" | awk '{print $4}')
            R_RAW=$(echo "$line" | awk '{print $5}')
            L_ADDR=$(echo "$L_RAW" | rev | cut -d. -f2- | rev)
            L_PORT=$(echo "$L_RAW" | rev | cut -d. -f1 | rev)
            R_ADDR=$(echo "$R_RAW" | rev | cut -d. -f2- | rev)
            R_PORT=$(echo "$R_RAW" | rev | cut -d. -f1 | rev)
            $FIRST || NETWORK_CONNECTIONS_JSON="$NETWORK_CONNECTIONS_JSON,"
            NETWORK_CONNECTIONS_JSON="$NETWORK_CONNECTIONS_JSON{\"protocol\":\"$PROTO\",\"local_address\":\"$(json_escape "$L_ADDR")\",\"local_port\":\"$L_PORT\",\"remote_address\":\"$(json_escape "$R_ADDR")\",\"remote_port\":\"$R_PORT\",\"state\":\"$(json_escape "$STATE")\",\"pid\":\"\"}"
            FIRST=false
        done
        NETWORK_CONNECTIONS_JSON="$NETWORK_CONNECTIONS_JSON]"
    fi
fi

# 26. Routing Table
ROUTING_TABLE_JSON="[]"
if command -v ip &>/dev/null; then
    mapfile -t ROUTE_LINES < <(ip route 2>/dev/null | head -20)
    if [ ${#ROUTE_LINES[@]} -gt 0 ]; then
        ROUTING_TABLE_JSON="["; FIRST=true
        for line in "${ROUTE_LINES[@]}"; do
            RT_DEST=$(echo "$line" | awk '{print $1}')
            RT_GW=$(echo "$line" | grep -o 'via [^ ]*' | awk '{print $2}')
            RT_IFACE=$(echo "$line" | grep -o 'dev [^ ]*' | awk '{print $2}')
            RT_METRIC=$(echo "$line" | grep -o 'metric [0-9]*' | awk '{print $2}')
            $FIRST || ROUTING_TABLE_JSON="$ROUTING_TABLE_JSON,"
            ROUTING_TABLE_JSON="$ROUTING_TABLE_JSON{\"destination\":\"$(json_escape "$RT_DEST")\",\"gateway\":\"$(json_escape "$RT_GW")\",\"interface\":\"$(json_escape "$RT_IFACE")\",\"metric\":\"$(json_escape "$RT_METRIC")\"}"
            FIRST=false
        done
        ROUTING_TABLE_JSON="$ROUTING_TABLE_JSON]"
    fi
elif [ "$OS_TYPE" = "Darwin" ]; then
    mapfile -t ROUTE_LINES < <(netstat -rn 2>/dev/null | awk 'NR>3 && /[0-9]/' | head -20)
    if [ ${#ROUTE_LINES[@]} -gt 0 ]; then
        ROUTING_TABLE_JSON="["; FIRST=true
        for line in "${ROUTE_LINES[@]}"; do
            RT_DEST=$(echo "$line" | awk '{print $1}')
            RT_GW=$(echo "$line" | awk '{print $2}')
            RT_IFACE=$(echo "$line" | awk '{print $NF}')
            $FIRST || ROUTING_TABLE_JSON="$ROUTING_TABLE_JSON,"
            ROUTING_TABLE_JSON="$ROUTING_TABLE_JSON{\"destination\":\"$(json_escape "$RT_DEST")\",\"gateway\":\"$(json_escape "$RT_GW")\",\"interface\":\"$(json_escape "$RT_IFACE")\",\"metric\":\"\"}"
            FIRST=false
        done
        ROUTING_TABLE_JSON="$ROUTING_TABLE_JSON]"
    fi
fi

# 27. Filesystem Info (type + mount point)
FILESYSTEM_INFO_JSON="[]"
if [ "$OS_TYPE" = "Darwin" ]; then
    # macOS df does not support -T flag; use df -h and get type from mount
    mapfile -t FS_LINES < <(df -h 2>/dev/null | grep -E '^/dev/' | grep -v 'devfs' | head -20)
else
    mapfile -t FS_LINES < <(df -Th 2>/dev/null | grep -E '^/dev/' | head -20)
fi
if [ ${#FS_LINES[@]} -gt 0 ]; then
    FILESYSTEM_INFO_JSON="["; FIRST=true
    for line in "${FS_LINES[@]}"; do
        FS_DEV=$(echo "$line" | awk '{print $1}')
        if [ "$OS_TYPE" = "Darwin" ]; then
            # macOS df -h: Filesystem Size Used Avail Capacity iused ifree %iused Mounted
            FS_TOTAL=$(echo "$line" | awk '{print $2}')
            FS_USED=$(echo "$line" | awk '{print $3}')
            FS_FREE=$(echo "$line" | awk '{print $4}')
            FS_PCT=$(echo "$line" | awk '{print $5}')
            FS_MOUNT=$(echo "$line" | awk '{print $NF}')
            # Get filesystem type from mount output
            FS_TYPE=$(mount 2>/dev/null | awk -v dev="$FS_DEV" '$1==dev{gsub(/.*\(/,""); gsub(/[,)].*/,""); print; exit}')
            [ -z "$FS_TYPE" ] && FS_TYPE="apfs"
        else
            # Linux df -Th: Filesystem Type Size Used Avail Use% Mounted
            FS_TYPE=$(echo "$line" | awk '{print $2}')
            FS_TOTAL=$(echo "$line" | awk '{print $3}')
            FS_USED=$(echo "$line" | awk '{print $4}')
            FS_FREE=$(echo "$line" | awk '{print $5}')
            FS_PCT=$(echo "$line" | awk '{print $6}')
            FS_MOUNT=$(echo "$line" | awk '{print $NF}')
        fi
        $FIRST || FILESYSTEM_INFO_JSON="$FILESYSTEM_INFO_JSON,"
        FILESYSTEM_INFO_JSON="$FILESYSTEM_INFO_JSON{\"device\":\"$(json_escape "$FS_DEV")\",\"mount_point\":\"$(json_escape "$FS_MOUNT")\",\"fs_type\":\"$(json_escape "$FS_TYPE")\",\"total\":\"$FS_TOTAL\",\"used\":\"$FS_USED\",\"free\":\"$FS_FREE\",\"use_percent\":\"$FS_PCT\"}"
        FIRST=false
    done
    FILESYSTEM_INFO_JSON="$FILESYSTEM_INFO_JSON]"
fi

# 28. File Integrity (SHA-256 of critical system files)
FILE_INTEGRITY_JSON="[]"
if [ "$OS_TYPE" = "Darwin" ]; then
    CRITICAL_FILES=("/etc/hosts" "/etc/passwd" "/etc/sudoers" "/etc/ssh/sshd_config" "/bin/sh" "/usr/bin/sudo" "/usr/bin/ssh")
else
    CRITICAL_FILES=("/etc/hosts" "/etc/passwd" "/etc/shadow" "/etc/sudoers" "/etc/ssh/sshd_config" "/bin/bash" "/usr/bin/sudo" "/usr/bin/ssh" "/etc/crontab")
fi
if command -v sha256sum &>/dev/null; then
    HASH_CMD="sha256sum"
elif command -v shasum &>/dev/null; then
    HASH_CMD="shasum -a 256"
else
    HASH_CMD=""
fi
if [ -n "$HASH_CMD" ]; then
    FILE_INTEGRITY_JSON="["; FIRST=true
    for fpath in "${CRITICAL_FILES[@]}"; do
        [ -f "$fpath" ] || continue
        FI_HASH=$(${HASH_CMD} "$fpath" 2>/dev/null | awk '{print $1}')
        FI_SIZE=$(du -sh "$fpath" 2>/dev/null | awk '{print $1}')
        FI_MOD=$(stat -c "%y" "$fpath" 2>/dev/null | cut -c1-19 || stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$fpath" 2>/dev/null)
        [ -z "$FI_HASH" ] && continue
        $FIRST || FILE_INTEGRITY_JSON="$FILE_INTEGRITY_JSON,"
        FILE_INTEGRITY_JSON="$FILE_INTEGRITY_JSON{\"path\":\"$(json_escape "$fpath")\",\"sha256\":\"$(json_escape "$FI_HASH")\",\"size\":\"$(json_escape "$FI_SIZE")\",\"modified\":\"$(json_escape "$FI_MOD")\"}"
        FIRST=false
    done
    FILE_INTEGRITY_JSON="$FILE_INTEGRITY_JSON]"
fi

# 29. Process Events
PROCESS_EVENTS_JSON="[]"
if [ "$OS_TYPE" = "Darwin" ]; then
    mapfile -t PROC_LOG < <(log show --predicate 'process == "sudo"' --last 7d --style syslog 2>/dev/null | grep -v '^Filtering\|^--' | tail -20)
    if [ ${#PROC_LOG[@]} -gt 0 ]; then
        PROCESS_EVENTS_JSON="["; FIRST=true
        for line in "${PROC_LOG[@]}"; do
            [ -z "$line" ] && continue
            PE_TIME=$(echo "$line" | awk '{print $1, $2}')
            PE_MSG=$(echo "$line" | cut -d' ' -f4- | head -c 200)
            PE_USER=$(echo "$PE_MSG" | grep -o 'by [A-Za-z0-9_.-]*(' | sed 's/by //;s/($//' | head -1)
            [ -z "$PE_USER" ] && PE_USER=$(echo "$PE_MSG" | grep -o 'for user [A-Za-z0-9_.-]*' | awk '{print $NF}' | head -1)
            [ -z "$PE_USER" ] && PE_USER=$(echo "$PE_MSG" | awk -F' : TTY=' '{print $1}' | awk '{print $NF}')
            $FIRST || PROCESS_EVENTS_JSON="$PROCESS_EVENTS_JSON,"
            PROCESS_EVENTS_JSON="$PROCESS_EVENTS_JSON{\"time\":\"$(json_escape "$PE_TIME")\",\"pid\":\"\",\"parent_pid\":\"\",\"process_name\":\"sudo\",\"command_line\":\"$(json_escape "$PE_MSG")\",\"user\":\"$(json_escape "$PE_USER")\"}"
            FIRST=false
        done
        PROCESS_EVENTS_JSON="$PROCESS_EVENTS_JSON]"
    fi
elif command -v ausearch &>/dev/null 2>&1; then
    mapfile -t AUDIT_LINES < <(ausearch -m EXECVE -i --start recent 2>/dev/null | tail -20)
    if [ ${#AUDIT_LINES[@]} -gt 0 ]; then
        PROCESS_EVENTS_JSON="["; FIRST=true
        for line in "${AUDIT_LINES[@]}"; do
            [ -z "$line" ] && continue
            PE_TIME=$(echo "$line" | grep -o 'msg=audit([^)]*)' | head -1)
            PE_CMD=$(echo "$line" | grep -o 'a0="[^"]*"' | head -1 | sed 's/a0="//' | tr -d '"')
            $FIRST || PROCESS_EVENTS_JSON="$PROCESS_EVENTS_JSON,"
            PROCESS_EVENTS_JSON="$PROCESS_EVENTS_JSON{\"time\":\"$(json_escape "$PE_TIME")\",\"pid\":\"\",\"parent_pid\":\"\",\"process_name\":\"$(json_escape "$PE_CMD")\",\"command_line\":\"\",\"user\":\"\"}"
            FIRST=false
        done
        PROCESS_EVENTS_JSON="$PROCESS_EVENTS_JSON]"
    fi
elif command -v journalctl &>/dev/null; then
    mapfile -t PROC_LOG < <(journalctl _COMM=sudo -n 20 --no-pager --output=short 2>/dev/null | grep -v '^--')
    if [ ${#PROC_LOG[@]} -gt 0 ]; then
        PROCESS_EVENTS_JSON="["; FIRST=true
        for line in "${PROC_LOG[@]}"; do
            [ -z "$line" ] && continue
            PE_TIME=$(echo "$line" | awk '{print $1, $2, $3}')
            PE_MSG=$(echo "$line" | cut -d' ' -f6- | head -c 200)
            # Extract username: sudo command lines start with "username : TTY=..."
            # pam_unix session opened lines contain "by username(uid=...)"
            # pam_unix session closed lines have no username - use hostname field as fallback
            if echo "$PE_MSG" | grep -q 'pam_unix'; then
                # session opened: "...by omi(uid=1000)" → extract before "("
                PE_USER=$(echo "$PE_MSG" | grep -o 'by [A-Za-z0-9_.-]*(' | sed 's/by //;s/($//' | head -1)
                # session closed: "...for user root" → extract last word
                [ -z "$PE_USER" ] && PE_USER=$(echo "$PE_MSG" | grep -o 'for user [A-Za-z0-9_.-]*' | awk '{print $NF}' | head -1)
            elif echo "$PE_MSG" | grep -q ' : TTY='; then
                # sudo command: "omi : TTY=pts/0 ; ..." → extract word before " : TTY="
                PE_USER=$(echo "$PE_MSG" | awk -F' : TTY=' '{print $1}' | awk '{print $NF}')
            fi
            [ -z "$PE_USER" ] && PE_USER=$(echo "$line" | awk '{print $4}' | sed 's/\[.*//;s/:$//')
            $FIRST || PROCESS_EVENTS_JSON="$PROCESS_EVENTS_JSON,"
            PROCESS_EVENTS_JSON="$PROCESS_EVENTS_JSON{\"time\":\"$(json_escape "$PE_TIME")\",\"pid\":\"\",\"parent_pid\":\"\",\"process_name\":\"sudo\",\"command_line\":\"$(json_escape "$PE_MSG")\",\"user\":\"$(json_escape "$PE_USER")\"}"
            FIRST=false
        done
        PROCESS_EVENTS_JSON="$PROCESS_EVENTS_JSON]"
    fi
fi

# 30. Security Policy
SEC_MIN_PASS_LEN=""; SEC_PASS_COMPLEXITY=""; SEC_LOCKOUT=""
SEC_SCREEN_LOCK=""; SEC_AUTO_UPDATES=""; SEC_REMOTE_LOGIN=""
SEC_AV_ENABLED=""; SEC_AV_DEFS=""
if [ "$OS_TYPE" = "Darwin" ]; then
    SEC_REMOTE_LOGIN=$(systemsetup -getremotelogin 2>/dev/null | awk -F': ' '{print $2}' | xargs)
    SEC_AUTO_UPDATES=$(softwareupdate --schedule 2>/dev/null | awk -F': ' '{print $2}' | xargs)
    SEC_SCREEN_LOCK=$(defaults read com.apple.screensaver idleTime 2>/dev/null | awk '{print $1 " sec"}')
    SEC_MIN_PASS_LEN=$(pwpolicy -getaccountpolicies 2>/dev/null | grep -o 'policyAttributePassword.*' | head -1 || echo "")
else
    SEC_MIN_PASS_LEN=$(grep -E '^PASS_MIN_LEN' /etc/login.defs 2>/dev/null | awk '{print $2}')
    [ -z "$SEC_MIN_PASS_LEN" ] && SEC_MIN_PASS_LEN=$(grep -E 'minlen=' /etc/security/pwquality.conf /etc/pam.d/common-password 2>/dev/null | grep -v '^#' | head -1 | grep -o 'minlen=[0-9]*' | cut -d= -f2)
    SEC_PASS_COMPLEXITY=$(grep -E 'pam_pwquality|pam_cracklib' /etc/pam.d/common-password 2>/dev/null | grep -v '^#' | head -1 | awk '{print "Enabled - "$0}' | head -c 80)
    SEC_LOCKOUT=$(grep -E 'deny=' /etc/pam.d/common-auth /etc/pam.d/system-auth 2>/dev/null | grep -v '^#' | head -1 | grep -o 'deny=[0-9]*')
    [ -f /etc/apt/apt.conf.d/20auto-upgrades ] && SEC_AUTO_UPDATES=$(grep 'Unattended-Upgrade' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null | head -1 | grep -o '"[01]"' | tr -d '"' | sed 's/1/Enabled/;s/0/Disabled/')
    SEC_REMOTE_LOGIN=$(grep -E '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | awk '{print "PermitRootLogin: "$2}' || echo "")
    SEC_SCREEN_LOCK=$(gsettings get org.gnome.desktop.screensaver lock-delay 2>/dev/null | sed "s/uint32 //" | tr -d "'" | awk '{print $1 " sec"}' || echo "")
fi

# 31. Container Images
CONTAINER_IMAGES_JSON="[]"
if command -v docker &>/dev/null && docker images &>/dev/null 2>&1; then
    mapfile -t IMG_LINES < <(docker images --format "{{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}\t{{.CreatedSince}}" 2>/dev/null)
    if [ ${#IMG_LINES[@]} -gt 0 ]; then
        CONTAINER_IMAGES_JSON="["; FIRST=true
        for line in "${IMG_LINES[@]}"; do
            [ -z "$line" ] && continue
            IMG_REPO=$(echo "$line" | awk -F'\t' '{print $1}')
            IMG_TAG=$(echo "$line" | awk -F'\t' '{print $2}')
            IMG_ID=$(echo "$line" | awk -F'\t' '{print $3}')
            IMG_SIZE=$(echo "$line" | awk -F'\t' '{print $4}')
            IMG_CREATED=$(echo "$line" | awk -F'\t' '{print $5}')
            $FIRST || CONTAINER_IMAGES_JSON="$CONTAINER_IMAGES_JSON,"
            CONTAINER_IMAGES_JSON="$CONTAINER_IMAGES_JSON{\"repository\":\"$(json_escape "$IMG_REPO")\",\"tag\":\"$(json_escape "$IMG_TAG")\",\"image_id\":\"$(json_escape "$IMG_ID")\",\"size\":\"$(json_escape "$IMG_SIZE")\",\"created\":\"$(json_escape "$IMG_CREATED")\"}"
            FIRST=false
        done
        CONTAINER_IMAGES_JSON="$CONTAINER_IMAGES_JSON]"
    fi
fi

# 32. Build JSON payload
JSON=$(cat <<EOF
{
  "computer_name": "$(json_escape "$COMPUTER")",
  "os_name": "$(json_escape "$OS_NAME")",
  "os_version": "$(json_escape "$OS_VERSION")",
  "architecture": "$ARCHITECTURE",
  "license_status": "$LICENSE_STATUS",
  "antivirus": ["$(json_escape "$ANTIVIRUS")"],
  "mac_address": "$MAC",
  "drive_name": "$(json_escape "$DRIVE_NAME")",
  "printers": $PRINTERS_JSON,
  "hotfixes": $HOTFIXES_JSON,
  "network_adapters": $NETWORK_ADAPTERS_JSON,
  "system_manufacturer": "$(json_escape "$SYS_MANUFACTURER")",
  "system_model": "$(json_escape "$SYS_MODEL")",
  "processor": "$(json_escape "$PROCESSOR")",
  "total_physical_memory": "$TOTAL_RAM",
  "bios_version": "$(json_escape "$BIOS_VERSION")",
  "domain": "$(json_escape "$DOMAIN")",
  "logon_server": "$(json_escape "$LOGON_SERVER")",
  "system_boot_time": "$(json_escape "$BOOT_TIME")",
  "time_zone": "$(json_escape "$TIME_ZONE")",
  "registered_owner": "$(json_escape "$REGISTERED_OWNER")",
  "windows_directory": "$WINDOWS_DIRECTORY",
  "disk_info": $DISK_INFO_JSON,
  "installed_apps": $INSTALLED_APPS_JSON,
  "local_users": $LOCAL_USERS_JSON,
  "running_services": $RUNNING_SERVICES_JSON,
  "open_ports": $OPEN_PORTS_JSON,
  "security_posture": {
    "bitlocker": "$(json_escape "$SEC_BITLOCKER")",
    "windows_firewall": "$(json_escape "$SEC_WINDOWS_FIREWALL")",
    "uac_enabled": "$(json_escape "$SEC_UAC")",
    "filevault": "$(json_escape "$SEC_FILEVAULT")",
    "gatekeeper": "$(json_escape "$SEC_GATEKEEPER")",
    "sip": "$(json_escape "$SEC_SIP")",
    "apparmor": "$(json_escape "$SEC_APPARMOR")",
    "selinux": "$(json_escape "$SEC_SELINUX")"
  },
  "docker_info": {
    "version": "$(json_escape "$DOCKER_VERSION")",
    "running_containers": $DOCKER_CONTAINERS,
    "containers": $DOCKER_CONTAINERS_JSON
  },
  "running_processes": $RUNNING_PROCESSES_JSON,
  "ssl_certificates": $SSL_CERTS_JSON,
  "browser_extensions": $BROWSER_EXTENSIONS_JSON,
  "event_logs": $EVENT_LOGS_JSON,
  "gpu_info": $GPU_INFO_JSON,
  "battery_info": {"name":"$(json_escape "$BATTERY_NAME")","status":"$(json_escape "$BATTERY_STATUS")","estimated_charge":"$(json_escape "$BATTERY_CHARGE")"},
  "local_groups": $LOCAL_GROUPS_JSON,
  "startup_items": $STARTUP_ITEMS_JSON,
  "network_connections": $NETWORK_CONNECTIONS_JSON,
  "routing_table": $ROUTING_TABLE_JSON,
  "filesystem_info": $FILESYSTEM_INFO_JSON,
  "file_integrity": $FILE_INTEGRITY_JSON,
  "process_events": $PROCESS_EVENTS_JSON,
  "security_policy": {"min_password_length":"$(json_escape "$SEC_MIN_PASS_LEN")","password_complexity":"$(json_escape "$SEC_PASS_COMPLEXITY")","lockout_threshold":"$(json_escape "$SEC_LOCKOUT")","screen_lock_timeout":"$(json_escape "$SEC_SCREEN_LOCK")","auto_updates_enabled":"$(json_escape "$SEC_AUTO_UPDATES")","remote_login_enabled":"$(json_escape "$SEC_REMOTE_LOGIN")","antivirus_enabled":"$(json_escape "$SEC_AV_ENABLED")","antivirus_definitions":"$(json_escape "$SEC_AV_DEFS")"},
  "container_images": $CONTAINER_IMAGES_JSON
}
EOF
)

CLIENT_ID="CLIENT_ID_PLACEHOLDER"
ASSORTMENT_TOKEN="AUDIT_TOKEN_PLACEHOLDER"
API_URL="API_BASE_URL_PLACEHOLDER/upload-assortment?client_id=$CLIENT_ID&assortment_token=$ASSORTMENT_TOKEN"

echo "Uploading secure payload to backend..."
if curl -s -X POST "$API_URL" -H "Content-Type: application/json" -d "$JSON"; then
    echo "Audit upload completed successfully!"
else
    echo "Upload failed."
fi
