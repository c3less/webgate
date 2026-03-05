#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  WebGate v3.0 — Installer
#  Arch Linux + generic Linux support
#  Created by c3less  |  github.com/c3less/webgate
# ═══════════════════════════════════════════════════════════════

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;96m'; WHITE='\033[0;97m'; DIM='\033[2m'; RST='\033[0m'

log()  { echo -e "  ${WHITE}[+]${RST} $1"; }
warn() { echo -e "  ${YELLOW}[!]${RST} $1"; }
err()  { echo -e "  ${RED}[-]${RST} $1"; }
ok()   { echo -e "  ${GREEN}[✓]${RST} $1"; }
dim()  { echo -e "  ${DIM}$1${RST}"; }
hdr()  { echo -e "\n${CYAN}  ── $1 ──${RST}"; }

banner() {
cat << 'EOF'

██╗    ██╗███████╗██████╗  ██████╗  █████╗ ████████╗███████╗
██║    ██║██╔════╝██╔══██╗██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝
██║ █╗ ██║█████╗  ██████╔╝██║  ███╗███████║   ██║   █████╗
██║███╗██║██╔══╝  ██╔══██╗██║   ██║██╔══██║   ██║   ██╔══╝
╚███╔███╔╝███████╗██████╔╝╚██████╔╝██║  ██║   ██║   ███████╗
 ╚══╝╚══╝ ╚══════╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝
EOF
echo -e "  ${WHITE}WebGate Installer v3.0  ·  by c3less${RST}"
echo -e "  ${DIM}200+ CVE database  ·  30 security tools${RST}\n"
}

banner

# ── Detect OS ─────────────────────────────────────────────────
IS_ARCH=false; IS_DEBIAN=false; IS_FEDORA=false
if [[ -f /etc/arch-release ]];   then IS_ARCH=true;   ok "Arch Linux detected"
elif [[ -f /etc/debian_version ]]; then IS_DEBIAN=true; ok "Debian/Ubuntu detected"
elif [[ -f /etc/fedora-release ]]; then IS_FEDORA=true; ok "Fedora detected"
else warn "Unknown distro — some packages may not install automatically"; fi

install_pkg() {
    local pkg="$1"
    if $IS_ARCH;   then sudo pacman -S --noconfirm --needed "$pkg" 2>/dev/null; return; fi
    if $IS_DEBIAN; then sudo apt-get install -y "$pkg" 2>/dev/null;             return; fi
    if $IS_FEDORA; then sudo dnf install -y "$pkg" 2>/dev/null;                 return; fi
}

pkg_installed() { command -v "$1" &>/dev/null || python3 -c "import $1" 2>/dev/null; }

# ── Core system deps ───────────────────────────────────────────
hdr "System dependencies"
CORE_PKGS=("python" "python-pip" "git" "sqlite" "tk" "alsa-utils" "libnotify" "curl")

for pkg in "${CORE_PKGS[@]}"; do
    DPKG="$pkg"
    if $IS_DEBIAN; then
        case $pkg in
            python)      DPKG="python3" ;;
            python-pip)  DPKG="python3-pip" ;;
            tk)          DPKG="python3-tk" ;;
            alsa-utils)  DPKG="alsa-utils" ;;
            libnotify)   DPKG="libnotify-bin" ;;
        esac
    fi
    if $IS_FEDORA; then
        case $pkg in
            python)     DPKG="python3" ;;
            python-pip) DPKG="python3-pip" ;;
            tk)         DPKG="python3-tkinter" ;;
            libnotify)  DPKG="libnotify" ;;
        esac
    fi
    if ! install_pkg "$DPKG" 2>/dev/null; then
        warn "Could not install $pkg — try manually"
    else
        ok "$pkg installed/available"
    fi
done

# ── Python packages ────────────────────────────────────────────
hdr "Python packages"
PY_DEPS=("dnspython" "python-whois" "pyOpenSSL" "requests" "colorama" "beautifulsoup4")
for dep in "${PY_DEPS[@]}"; do
    if pip3 install --quiet --break-system-packages "$dep" 2>/dev/null \
       || pip3 install --quiet "$dep" 2>/dev/null; then
        ok "pip: $dep"
    else
        warn "pip: $dep failed — optional"
    fi
done

# ── External security tools ────────────────────────────────────
hdr "Security tools"

install_tool() {
    local name="$1"; local cmd="$2"; local install_cmd="$3"
    if command -v "$cmd" &>/dev/null; then
        ok "$name already installed ($(command -v $cmd))"
        return
    fi
    log "Installing $name..."
    eval "$install_cmd" 2>/dev/null && ok "$name installed" || warn "$name failed — install manually"
}

# Nmap
install_tool "Nmap" "nmap" "install_pkg nmap"

# SQLMap
install_tool "SQLMap" "sqlmap" "pip3 install --quiet --break-system-packages sqlmap 2>/dev/null || install_pkg sqlmap"

# WPScan (requires Ruby)
if ! command -v wpscan &>/dev/null; then
    log "Installing WPScan (Ruby gem)..."
    install_pkg ruby 2>/dev/null || true
    gem install wpscan 2>/dev/null && ok "WPScan installed" || warn "WPScan failed — install: gem install wpscan"
else
    ok "WPScan already installed"
fi

# Gobuster
install_tool "Gobuster" "gobuster" "install_pkg gobuster"

# XSStrike
if ! command -v xsstrike &>/dev/null; then
    log "Installing XSStrike..."
    if pip3 install --quiet --break-system-packages xsstrike 2>/dev/null; then
        ok "XSStrike installed"
    elif [[ -d /opt/XSStrike ]]; then
        ok "XSStrike already at /opt/XSStrike"
    else
        git clone https://github.com/s0md3v/XSStrike /opt/XSStrike --quiet 2>/dev/null \
            && ln -sf /opt/XSStrike/xsstrike.py /usr/local/bin/xsstrike 2>/dev/null \
            && ok "XSStrike cloned to /opt/XSStrike" \
            || warn "XSStrike failed — clone manually: git clone https://github.com/s0md3v/XSStrike"
    fi
else
    ok "XSStrike already installed"
fi

# Commix
if ! command -v commix &>/dev/null; then
    log "Installing Commix..."
    if [[ -d /opt/commix ]]; then
        ok "Commix already at /opt/commix"
        ln -sf /opt/commix/commix.py /usr/local/bin/commix 2>/dev/null || true
    else
        git clone --depth=1 https://github.com/commixproject/commix.git /opt/commix 2>/dev/null \
            && chmod +x /opt/commix/commix.py \
            && ln -sf /opt/commix/commix.py /usr/local/bin/commix 2>/dev/null \
            && ok "Commix installed" || warn "Commix: git clone failed — try manually"
    fi
else
    ok "Commix already installed"
fi

# Droopescan (Drupal)
install_tool "Droopescan" "droopescan" "pip3 install --quiet --break-system-packages droopescan 2>/dev/null"

# CMSeek
if ! command -v cmseek &>/dev/null; then
    log "Installing CMSeek..."
    if [[ -d /opt/CMSeeK ]]; then
        ok "CMSeek already at /opt/CMSeeK"
        ln -sf /opt/CMSeeK/cmseek.py /usr/local/bin/cmseek 2>/dev/null || true
    else
        git clone --depth=1 https://github.com/Tuhinshubhra/CMSeeK.git /opt/CMSeeK 2>/dev/null \
            && chmod +x /opt/CMSeeK/cmseek.py \
            && ln -sf /opt/CMSeeK/cmseek.py /usr/local/bin/cmseek 2>/dev/null \
            && pip3 install --quiet --break-system-packages requests 2>/dev/null \
            && ok "CMSeek installed" || warn "CMSeek: git clone failed — try manually"
    fi
else
    ok "CMSeek already installed"
fi

# Arachni (web)
if ! command -v arachni &>/dev/null; then
    warn "Arachni: download from https://www.arachni-scanner.com/download/"
else
    ok "Arachni already installed"
fi

# BruteX
if ! command -v brutex &>/dev/null; then
    log "BruteX: requires manual setup at https://github.com/1N3/BruteX"
    warn "BruteX: skipping auto-install"
else
    ok "BruteX already installed"
fi

# Reaver + Pixiewps (wifi)
for tool in reaver pixiewps; do
    install_tool "$tool" "$tool" "install_pkg $tool"
done

# SSLstrip
if ! command -v sslstrip &>/dev/null; then
    log "Installing SSLstrip..."
    pip3 install --quiet --break-system-packages sslstrip 2>/dev/null \
        || pip3 install --quiet sslstrip 2>/dev/null \
        || install_pkg sslstrip 2>/dev/null \
        && ok "SSLstrip installed" || warn "SSLstrip: try: pip install sslstrip"
else
    ok "SSLstrip already installed"
fi

# Cupp
install_tool "Cupp" "cupp" "pip3 install --quiet --break-system-packages cupp 2>/dev/null || pip3 install --quiet cupp"

# Weeman
if ! command -v weeman &>/dev/null; then
    if [[ ! -d /opt/weeman ]]; then
        log "Installing Weeman..."
        git clone --depth=1 https://github.com/evait-security/weeman.git /opt/weeman 2>/dev/null \
            && chmod +x /opt/weeman/weeman.py \
            && ln -sf /opt/weeman/weeman.py /usr/local/bin/weeman 2>/dev/null \
            && ok "Weeman installed" || warn "Weeman: git clone failed"
    else
        ok "Weeman at /opt/weeman"
        ln -sf /opt/weeman/weeman.py /usr/local/bin/weeman 2>/dev/null || true
    fi
else
    ok "Weeman already installed"
fi

# Wordlists
hdr "Wordlists"
WLIST_OK=false
for wlist_path in /usr/share/wordlists/dirb/common.txt \
                  /usr/share/dirb/wordlists/common.txt \
                  /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt; do
    if [[ -f "$wlist_path" ]]; then
        ok "Wordlist found: $wlist_path"; WLIST_OK=true; break
    fi
done
if ! $WLIST_OK; then
    log "Installing wordlists..."
    install_pkg wordlists 2>/dev/null \
        || install_pkg dirb 2>/dev/null \
        || install_pkg dirbuster 2>/dev/null \
        || {
            # Download minimal wordlist
            mkdir -p /usr/share/wordlists/dirb
            curl -sL "https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt" \
                -o /usr/share/wordlists/dirb/common.txt 2>/dev/null \
            && ok "Wordlist downloaded to /usr/share/wordlists/dirb/common.txt" \
            || warn "Wordlists not found — gobuster needs: -w /path/to/wordlist.txt"
        }
fi
if [[ -f /usr/share/wordlists/dirb/common.txt ]]; then
    ok "dirb wordlists present"
fi

# ── CVE Database ───────────────────────────────────────────────
hdr "CVE Database"
DB_PATH="$(cd "$(dirname "$0")" && pwd)/cve.db"
if [[ ! -f "$DB_PATH" ]]; then
    log "Creating CVE SQLite database..."
    python3 -c "
import sys, os
sys.path.insert(0, os.path.dirname('$DB_PATH'))
os.chdir(os.path.dirname('$DB_PATH'))
exec(open('webgate.py').read().split('def main()')[0])
init_cve_db()
print('CVE DB created with', get_all_cve_count(), 'entries')
"
    ok "CVE database created: $DB_PATH"
else
    COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM services;" 2>/dev/null || echo "?")
    ok "CVE database exists ($COUNT entries)"
fi

# ── Permissions ─────────────────────────────────────────────────
hdr "Finishing up"
chmod +x "$(dirname "$0")/webgate.py"
ok "webgate.py marked executable"

# ── symlink ────────────────────────────────────────────────────
SCRIPT_PATH="$(cd "$(dirname "$0")" && pwd)/webgate.py"
if [[ ! -L /usr/local/bin/webgate ]]; then
    sudo ln -sf "$SCRIPT_PATH" /usr/local/bin/webgate 2>/dev/null \
        && ok "Symlink created: /usr/local/bin/webgate" \
        || warn "Could not create symlink — run as: python3 $SCRIPT_PATH"
else
    ok "Symlink exists: /usr/local/bin/webgate"
fi

# ── Summary ────────────────────────────────────────────────────
echo ""
echo -e "  ${GREEN}╔════════════════════════════════════════════╗${RST}"
echo -e "  ${GREEN}║  WebGate v3.0 installation complete!       ║${RST}"
echo -e "  ${GREEN}╚════════════════════════════════════════════╝${RST}"
echo ""
dim "  Usage:"
dim "    webgate                  →  interactive CLI"
dim "    webgate --gui            →  launch GUI"
dim "    webgate -d example.com   →  quick scan"
dim "    webgate --gui -d target  →  GUI with prefill"
echo ""
