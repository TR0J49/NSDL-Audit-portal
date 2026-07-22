# InfraPulse vs osquery — Data Collection Capability Comparison

**Report Date:** 22-Jul-2026
**Sample System:** Ubuntu 22.04 — omi-Lenovo-IdeaPad-S145-15IWL

---

## Summary

| | InfraPulse | osquery |
|--|-----------|---------|
| Type | Custom lightweight web-based collector | Open-source SQL-based endpoint agent |
| Deployment | Browser + one-click script | Agent installed on each machine |
| Output | PDF + XML report | SQL query results / JSON |
| Real-time monitoring | No | Yes |
| Cross-platform | Windows, Mac, Linux | Windows, Mac, Linux |
| Data scope | System snapshot | Deep endpoint visibility |

---

## Capability Match Analysis

### Fully Matched — InfraPulse collects what osquery covers

| Capability | osquery | InfraPulse | Evidence from Report |
|-----------|---------|-----------|----------------------|
| Device and OS inventory | Strong | Strong | OS Name: Ubuntu, Version: 6.17.0-40-generic, Architecture: x86\_64, Computer Name: omi-Lenovo-IdeaPad-S145-15IWL |
| Hardware inventory | Strong | Strong | Manufacturer: LENOVO, Model: 81MV, Processor: Intel Core i5-8265U, RAM: 7.64 GB, BIOS: ASCN51WW |
| Network interfaces and connections | Strong | Strong | Adapter: wlp0s20f3, IPv4: 192.168.1.139, IPv6 with Temp and Link-local addresses, DNS: 127.0.0.53, Gateway: 192.168.1.1 |
| Package-management visibility | Strong | Partial | 20 installed packages collected with Fix ID, Description, and Install Date |

---

### Partially Matched — InfraPulse covers some but not all

| Capability | osquery Coverage | InfraPulse Coverage | What InfraPulse Misses |
|-----------|-----------------|--------------------|-----------------------|
| OS-native security posture | BitLocker, FileVault, SIP, Gatekeeper, SELinux, AppArmor, keychain, registry | License Status, Antivirus product names | SELinux/AppArmor status, Gatekeeper, SIP, FileVault encryption status, Firewall status |
| Disk and filesystem inventory | Full disk info, partitions, filesystem types, mount points, free space | CD/ROM Drive name only | Disk size, used/free space, partition table, filesystem type, mount points |
| Installed software | All installed apps, version, install date | OS hotfixes and packages only | Full application list (e.g. Chrome, Office, VS Code), version numbers |

---

### Not Collected — osquery has it, InfraPulse does not collect

| Capability | osquery | InfraPulse | Impact |
|-----------|---------|-----------|--------|
| Users and groups | Strong on all OS | Not collected | Cannot audit local accounts, admin groups, guest accounts |
| Running processes | Strong on all OS | Not collected | Cannot detect suspicious processes at time of scan |
| Services and startup items | Strong on all OS | Not collected | Cannot audit auto-start services or persistence mechanisms |
| Certificates and browser extensions | Strong on all OS | Not collected | Cannot audit SSL certs, expired certs, rogue browser extensions |
| File-integrity monitoring | NTFS Journal / FSEvents / inotify | Not collected | No file change detection |
| Process-event monitoring | ETW / Endpoint Security / Linux Audit | Not collected | No process launch or kill tracking |
| Container visibility | Strongest on Linux | Not collected | Cannot detect running Docker or K8s containers |
| OS event-log access | Windows Event Log / Unified logs / journald | Not collected | Cannot read system event logs for audit trail |

---

## Detailed Gap Analysis from Sample Report

Based on the actual PDF generated from the Ubuntu system on 22-Jul-2026:

### What InfraPulse collected correctly

1. Full network adapter info including IPv6, Temporary IPv6, and Link-local IPv6 addresses
2. Hardware details — Lenovo IdeaPad S145, Core i5-8265U, 7.64 GB RAM
3. BIOS version ASCN51WW
4. 20 OS package installs with dates (July 9 and July 17 and July 22 packages)
5. System boot time, timezone (Asia/Kolkata), registered owner
6. OS version correctly identified as Ubuntu with kernel 6.17.0-40-generic

### What InfraPulse missed or showed as Not Detected

| Field | Value in Report | Gap |
|-------|----------------|-----|
| Antivirus | Not Detected | Linux uses ClamAV or rkhunter — script should check these |
| Drive Details | No CD Unit Found | Correct but no disk/SSD info collected |
| Printer Details | No active printers | Correct but no USB device list |
| Windows Directory | N/A | Correct for Linux but no Linux equivalent path shown |
| License Status | Open Source | Correct but no distro license detail |
| Users and groups | Not collected | Local users on this Ubuntu machine not listed |
| Running processes | Not collected | Process list at time of scan missing |
| Installed apps | Not collected | Only OS packages shown, not all installed software |
| Disk space | Not collected | No storage usage data in report |
| SELinux or AppArmor | Not collected | Ubuntu uses AppArmor by default — status not collected |

---

## Side-by-Side Comparison Table

| Capability | osquery (Windows) | osquery (macOS) | osquery (Linux) | InfraPulse (Windows) | InfraPulse (macOS) | InfraPulse (Linux) |
|-----------|------------------|-----------------|-----------------|---------------------|-------------------|-------------------|
| Device and OS inventory | Strong | Strong | Strong | Strong | Strong | Strong |
| Hardware inventory | Strong | Strong | Strong | Strong | Strong | Strong |
| Network interfaces | Strong | Strong | Strong | Strong | Strong | Strong |
| Package / update visibility | Strong | Strong | Strong | Partial | Partial | Partial |
| Installed software (all apps) | Strong | Strong | Strong | Not collected | Not collected | Not collected |
| Users and groups | Strong | Strong | Strong | Not collected | Not collected | Not collected |
| Running processes | Strong | Strong | Strong | Not collected | Not collected | Not collected |
| Services and startup items | Strong | Strong | Strong | Not collected | Not collected | Not collected |
| Disk and filesystem | Strong | Strong | Strong | Weak (CD only) | Weak (CD only) | Weak (CD only) |
| Antivirus and security posture | Strong | Strong | Strong | Partial | Partial | Partial |
| Certificates and extensions | Strong | Strong | Strong | Not collected | Not collected | Not collected |
| File-integrity monitoring | Strong | Strong | Strong | Not collected | Not collected | Not collected |
| Container visibility | Limited | Limited | Strongest | Not collected | Not collected | Not collected |
| OS event-log access | Strong | Strong | Strong | Not collected | Not collected | Not collected |
| PDF report output | No | No | No | Yes | Yes | Yes |
| Web-based collection portal | No | No | No | Yes | Yes | Yes |
| No agent install needed | No | No | No | Yes | Yes | Yes |

---

## What InfraPulse Does Better Than osquery

1. No agent installation required — runs via a one-click browser download
2. Generates a formatted PDF report instantly — osquery returns raw SQL data
3. Web-based portal with real-time SSE status updates
4. Consent and officer name captured for compliance audit trail
5. Suitable for non-technical end users — no SQL knowledge needed
6. XML export for integration with other systems

---

## Recommended Fields to Add to InfraPulse

The following fields would close the gap significantly without making the script complex:

**High Priority**

1. Disk information — total size, used space, free space, filesystem type
2. List of all installed applications with version numbers
3. Local user accounts — username, admin status, last login
4. AppArmor or SELinux status (Linux), FileVault status (Mac), BitLocker status (Windows)
5. Antivirus for Linux — check for ClamAV, rkhunter, chkrootkit

**Medium Priority**

6. Active services list — top running system services
7. Open network ports and listening services
8. Startup items and scheduled tasks
9. Last login time and active sessions

**Low Priority**

10. Browser extensions list
11. Docker or container runtime status
12. Installed certificates

---

## Conclusion

InfraPulse currently covers approximately 4 out of 15 osquery capability areas fully, with 3 areas partially covered and 8 areas not collected at all.

For a basic system inventory and compliance snapshot, InfraPulse is effective and significantly easier to deploy than osquery. For deep endpoint security monitoring, real-time process tracking, and security posture assessment, osquery provides far greater depth.

The two tools serve different purposes and can be complementary — InfraPulse for quick no-install compliance snapshots, osquery for continuous deep endpoint monitoring.
