# WebGate FW3.7 — Domain Security Auditor

<p align="center">
  <img src="https://img.shields.io/badge/version-FW3.7-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/python-3.8%2B-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/license-PENTEST_ONLY-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey?style=for-the-badge" />
</p>

> **FOR AUTHORIZED SECURITY TESTING ONLY.**
> Unauthorized use is a criminal offense under CFAA, CMA, and equivalent laws worldwide.

---

## What is WebGate?

WebGate is a professional-grade **domain security auditor and penetration testing framework** for authorized security assessments. It combines passive reconnaissance, vulnerability scanning, and (with written scope agreement) active exploitation into a single beautiful GUI and CLI.

---

## Features

### Surface Scan
- DNS resolution (A, AAAA, MX, NS, TXT, CNAME, SOA)
- WHOIS (registrar, expiry, org, country)
- HTTP headers + security score (CSP, HSTS, X-Frame-Options...)
- SSL/TLS analysis (version, cipher, expiry, weak ciphers)
- Port scanning with banner grabbing + CVE matching
- WAF/CDN detection (Cloudflare, Akamai, Sucuri, AWS, Incapsula...)
- Subdomain enumeration (80+ prefixes)
- OS/device/CMS fingerprinting

### Deep Scan (30+ tools)
| Category | Tools |
|---|---|
| Recon | Nmap, Gobuster, Deep Port Scan, Cloudflare Bypass |
| CMS | WPScan, WP Exploit, WP Plugins, CMSeek, Droopescan, GravityForms |
| SQL | SQLMap (interactive dump), SQLi Scanner |
| XSS | XSStrike (simplified output), DOM XSS indicators |
| RCE | Commix, Joomla RCE, vBulletin RCE |
| SSL | Full SSL/TLS audit |
| Web | File upload check, Shell finder, POET enumeration |
| OSINT | Inurlbr dorks, CUPP wordlist |
| Brute | Login brute force, SSH default credentials |

### Exploit Framework (Scope Agreement required)
- SQL Injection — error-based, time-based, UNION, blind
- XSS — reflected, stored, DOM
- Command Injection — all major vectors
- LFI/RFI — path traversal, PHP wrappers
- File Upload — webshell detection + upload
- Brute Force — login forms, SSH
- **SSH Backdoor via RCE CVE** — with `I accept` scope agreement
  - TOR routing via bridge (obfs4 / webtunnel / snowflake)
  - Paramiko-based SSH verification
  - sudo privilege escalation check

### SQLMap Interactive Dump
When injection is confirmed:
1. Databases listed in GUI — select target DB
2. Fetch tables — click to enumerate
3. Select table → dump → saved to file
All protected by Scope Agreement.

### CVE Exploit Flow
After surface scan, if RCE CVE detected:
1. **Dialog**: "Exploit found: CVE-XXXX — Try SSH access?"
2. **Scope Agreement**: type exactly `I accept`
3. **SSH Config**: username, password to create, TOR bridge (optional)
4. Exploit attempt via CVE-specific vector + SSH verification

### GUI
- 5 themes: **Dark**, **Mono**, **Light**, **Midnight**, **Hacker** + Custom
- EN/RU live toggle
- Logo glitch animation (random interval)
- Particle burst on scan start
- Gradient + shimmer progress bar with % overlay
- Typewriter log output
- Live step indicators

### Simplified Reports
Not raw tool noise — clean findings:
```
SQL INJECTION:
  FOUND — SQL Injection detected
    Vulnerable parameter: GET ?id (MySQL)
    Payload: 1 AND SLEEP(5)--
    Databases: information_schema, users_db, shop

XSS:
  FOUND — XSS vulnerability detected
    Reflected XSS: param=q

CRITICAL CVEs:
  CVE-2021-41773 on port 80/HTTP
    Path traversal + RCE on Apache 2.4.49 — CVSS 9.8
```

---

## Installation

### Arch Linux
```bash
sudo pacman -S python python-pip tk nmap
pip install -r requirements.txt
```

### Debian / Ubuntu / Kali
```bash
sudo apt install python3 python3-pip python3-tk nmap
pip3 install -r requirements.txt
```

### Fedora / RHEL
```bash
sudo dnf install python3 python3-pip python3-tkinter nmap
pip3 install -r requirements.txt
```

### Termux (Android)
```bash
pkg install python nmap
pip install -r requirements.txt
```

Or use the auto-installer:
```bash
chmod +x install.sh && sudo ./install.sh
```

---

## Usage

```bash
# GUI (recommended)
python webgate.py --gui

# CLI interactive shell
python webgate.py

# Quick surface scan
python webgate.py -d example.com

# Deep scan
python webgate.py deep example.com

# Full scan (all phases)
python webgate.py full example.com

# Network agent (local network scan)
python webgate.py agent

# Exploit mode (Scope Agreement required)
python webgate.py exploit example.com

# Fingerprint device/OS/CMS
python webgate.py finger example.com
```

---

## CVE Database

200+ CVEs covering: nginx, Apache, IIS, PHP, MySQL, PostgreSQL, MongoDB, Redis, SSH, FTP, SMB, RDP, WordPress, Joomla, Drupal, Log4j (Log4Shell), Spring (Spring4Shell), Apache Struts (Equifax), Cisco, Fortinet, MikroTik, GitLab, Jenkins, Confluence, Docker, Kubernetes, and more.

---

## Legal

**USE ONLY ON SYSTEMS YOU OWN OR HAVE EXPLICIT WRITTEN AUTHORIZATION TO TEST.**

See [LICENSE](LICENSE) for full terms.

---

## Author

**c3less**
Telegram: [@c3less](https://t.me/c3less)
GitHub: [github.com/c3less/webgate](https://github.com/c3less/webgate)

---

## Changelog

### FW3.7
- NEW: SSH backdoor via RCE CVE (Scope Agreement + typed "I accept")
- NEW: TOR routing via bridge (obfs4/webtunnel/snowflake)
- NEW: SQLMap interactive dump — pick DB → table → dump in GUI
- NEW: CVEExploitOfferDialog — auto-prompt when RCE CVE detected
- NEW: ScopeAgreementDialog with typed confirmation
- NEW: Simplified reports — injection Y/N + vulnerable param/payload
- IMPROVED: SQLMap output shows only key findings (no raw noise)
- IMPROVED: XSStrike output simplified to injection Y/N + URL
- IMPROVED: Progress bar with gradient, % overlay, bright pulse edge
- IMPROVED: Logo glitch animation
- IMPROVED: Particle burst animation on scan start
- FIXED: Removed COPY button (was causing GUI freeze/lag on Wayland)
- FIXED: All version strings updated to FW3.7
