# WebGate — Domain Security Auditor

> **For educational and authorized security testing only.**

```
██╗    ██╗███████╗██████╗  ██████╗  █████╗ ████████╗███████╗
██║    ██║██╔════╝██╔══██╗██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝
██║ █╗ ██║█████╗  ██████╔╝██║  ███╗███████║   ██║   █████╗
██║███╗██║██╔══╝  ██╔══██╗██║   ██║██╔══██║   ██║   ██╔══╝
╚███╔███╔╝███████╗██████╔╝╚██████╔╝██║  ██║   ██║   ███████╗
 ╚══╝╚══╝ ╚══════╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝
```

**WebGate** is an all-in-one domain security auditor with a sleek black-and-white GUI inspired by eDEX-UI and a sqlmap-style interactive CLI. Built for security professionals, students, and CTF participants.

---

## Features

### Standard Scan
| Module | What it does |
|---|---|
| DNS Resolution | IPv4 / IPv6 lookup, reverse DNS |
| DNS Records | A, AAAA, MX, NS, TXT, CNAME, SOA via dnspython |
| WHOIS | Registrar, dates, expiry warning, DNSSEC |
| HTTP Headers | Status, server, redirect chain, 7-header security audit |
| SSL / TLS | Version, cipher, SANs, expiry countdown, self-signed detection |
| Port Scan | 21 common ports with banner grabbing |
| Risk Report | Severity-rated risk summary + full report saved to `.txt` |

### Deep Scan *(requires user authorization confirmation)*
| Module | What it does |
|---|---|
| Web Crawl | Discovers URLs and forms on the target |
| XSS Probe | Reflection test with basic payloads |
| SQLi Surface | Error-based SQL injection indicator detection |
| Dir Enumeration | Common path/file accessibility check |
| WhatWeb | Technology fingerprinting (if installed) |
| SQLMap Light | Automated surface SQLi scan, level=1 crawl=2 (if installed) |

### GUI Highlights
- **Splash screen** with animated logo and typewriter effect
- **eDEX-UI aesthetic** — pure black/white/grey palette
- **Resizable window** (min 700×480)
- **Typing sound** per character (toggleable)
- **Smooth progress bar** animation
- **Step indicator** panel with live status
- **Summary popup** after scan with risk severity
- **Desktop notification** on scan completion
- **Language toggle** — English / Russian
- **Theme toggle** — Dark / Light / Midnight / Custom
- **Adjustable transparency**
- **Deep Scan disclaimer** dialog (educational use acknowledgement)

---

## Installation

```bash
git clone https://github.com/c3less/webgate.git
cd webgate
chmod +x install.sh
./install.sh
```

Or install Python deps manually:

```bash
pip install dnspython python-whois pyOpenSSL
```

For full Deep Scan support:

```bash
# Debian/Ubuntu
sudo apt install python3-tk alsa-utils whatweb libnotify-bin

# Arch
sudo pacman -S python-tkinter alsa-utils whatweb libnotify

# SQLMap
pip install sqlmap
```

---

## Usage

```bash
# Interactive CLI shell (sqlmap-style)
python webgate.py

# Graphical interface
python webgate.py --gui

# Quick one-shot scan
python webgate.py -d example.com

# GUI pre-loaded with domain
python webgate.py --gui -d example.com
```

### CLI shell commands
```
webgate › scan example.com   — run full audit
webgate › gui                — launch graphical interface
webgate › help               — show usage
webgate › exit               — quit
```

---

## Screenshots

> *CLI mode — sqlmap-inspired interactive shell*

```
  ════════════════════════════════════════════════════════════════
  TARGET   : github.com
  STARTED  : 2026-03-05 12:00:00
  ════════════════════════════════════════════════════════════════

  [»] Resolving domain to IP address...
  [+]   IPv4            : 140.82.121.4
  [»] Checking SSL/TLS certificate...
  [+]   TLS version     : TLSv1.3
  [+]   Cipher          : TLS_AES_128_GCM_SHA256 (128 bits)
  [✓] SCAN COMPLETE  [18.3s]
```

> *GUI mode — eDEX-UI B&W aesthetic with animated panels*

---

## Report Output

Reports are automatically saved as:
```
audit_<domain>_<YYYYMMDD_HHMMSS>.txt
```

Containing: DNS, WHOIS, HTTP headers, SSL details, open ports, security header audit, risk summary, and full timestamped scan log.

---

## Optional Dependencies

| Package | Purpose | Install |
|---|---|---|
| `dnspython` | Full DNS record analysis | `pip install dnspython` |
| `python-whois` | WHOIS lookups | `pip install python-whois` |
| `pyOpenSSL` | Advanced SSL parsing | `pip install pyOpenSSL` |
| `whatweb` | Technology fingerprinting | `apt install whatweb` |
| `sqlmap` | SQLi surface scanning | `pip install sqlmap` |

All are optional — the tool works without them but with reduced functionality.

---

## Legal Notice

This tool is provided for **educational purposes** and **authorized security testing only**.

- Only scan domains you **own** or have **written permission** to test
- Unauthorized scanning may violate computer fraud laws in your jurisdiction
- The Deep Scan feature includes a mandatory disclaimer that must be acknowledged before use
- The authors accept **no responsibility** for misuse

---

## Requirements

- Python 3.10+
- `tkinter` (for GUI)

---

## License

MIT License — see [LICENSE](LICENSE)

---

*Created by c3less — WebGate v2.0*
