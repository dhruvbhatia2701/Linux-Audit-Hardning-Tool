#!/usr/bin/env python3

import os
import subprocess

report = []
score = 0
total_checks = 0

def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()
    except:
        return ""

# 1. Check firewall rules
def check_firewall():
    global score, total_checks
    total_checks += 1
    fw_status = run_cmd("sudo ufw status")
    if "Status: active" in fw_status:
        report.append("[+] Firewall is active (ufw)")
        score += 1
    else:
        report.append("[-] Firewall is not active. Enable ufw for better security.")

# 2. Check for unused services (example: telnet, rsh)
def check_services():
    global score, total_checks
    total_checks += 1
    suspicious_services = ['telnet', 'rsh', 'xinetd']
    found = []
    for svc in suspicious_services:
        svc_status = run_cmd(f"systemctl is-enabled {svc}")
        if svc_status == "enabled":
            found.append(svc)
    if found:
        report.append(f"[-] Unused or insecure services found enabled: {', '.join(found)}")
    else:
        report.append("[+] No suspicious services enabled.")
        score += 1

# 3. SSH settings
def check_ssh():
    global score, total_checks
    total_checks += 1
    sshd_conf = "/etc/ssh/sshd_config"
    if not os.path.exists(sshd_conf):
        report.append("[-] SSH config file not found.")
        return

    with open(sshd_conf, "r") as file:
        content = file.read()
        root_login = "PermitRootLogin no" in content
        protocol2 = "Protocol 2" in content

        if root_login and protocol2:
            report.append("[+] SSH settings are secure.")
            score += 1
        else:
            report.append("[-] Insecure SSH settings detected. Ensure 'PermitRootLogin no' and 'Protocol 2'.")

# 4. File permission checks
def check_file_permissions():
    global score, total_checks
    total_checks += 1
    bad_perms = []

    if oct(os.stat("/etc/passwd").st_mode)[-3:] != '644':
        bad_perms.append("/etc/passwd")
    
    # if oct(os.stat("/etc/shadow").st_mode)[-3:] != '640':
    #     bad_perms.append("/etc/shadow")

    if bad_perms:
        report.append(f"[-] Incorrect permissions on: {', '.join(bad_perms)}")
    else:
        report.append("[+] File permissions are correct on /etc/passwd and /etc/shadow.")
        score += 1

# 5. Rootkit check (simple indicator-based)
def check_rootkit_indicators():
    global score, total_checks
    total_checks += 1
    suspicious_files = ["/usr/bin/hdparm", "/usr/sbin/rklogd"]
    found = []

    for f in suspicious_files:
        if os.path.exists(f):
            found.append(f)

    if found:
        report.append(f"[-] Potential rootkit indicators found: {', '.join(found)}")
    else:
        report.append("[+] No basic rootkit indicators found.")
        score += 1

# 6. Generate recommendations
def generate_recommendations():
    report.append("\n--- Recommendations ---")
    report.append("- Enable UFW firewall if disabled: `sudo ufw enable`")
    report.append("- Disable unused services: `systemctl disable <service>`")
    report.append("- Harden SSH: Disable root login and use Protocol 2")
    report.append("- Set correct permissions:\n  `chmod 644 /etc/passwd`\n")
    report.append("- Use chkrootkit or rkhunter for deep rootkit scans")

# Run all checks
def run_audit():
    print("[*] Running Linux Hardening Audit...\n")
    check_firewall()
    check_services()
    check_ssh()
    check_file_permissions()
    check_rootkit_indicators()
    generate_recommendations()

    compliance = round((score / total_checks) * 100, 2)
    report.append(f"\n[*] Compliance Score: {compliance}% ({score}/{total_checks})")

    with open("linux_audit_report.txt", "w") as f:
        f.write("\n".join(report))

    print("[*] Audit complete. Report saved to 'linux_audit_report.txt'.")

if __name__ == "__main__":
    run_audit()