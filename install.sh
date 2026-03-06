#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  WebGate v4.0 — Universal Installer
#  Supports: Arch/Manjaro, Debian/Ubuntu/Kali/Mint, Fedora/RHEL/CentOS,
#            openSUSE, Void, Alpine, NixOS, Termux (Android), iSH (iOS)
#  Created by c3less  |  github.com/c3less/webgate
# ═══════════════════════════════════════════════════════════════

# Do NOT use set -e — we want to continue past failed optional installs
set +e
ERRORS=0

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
echo -e "  ${WHITE}WebGate Installer v4.0  ·  by c3less${RST}"
echo -e "  ${DIM}CVE database · 30+ security tools · Agent mode${RST}\n"
}

banner

# ── Detect environment ─────────────────────────────────────────
IS_ARCH=false; IS_DEBIAN=false; IS_FEDORA=false; IS_OPENSUSE=false
IS_VOID=false; IS_ALPINE=false; IS_NIXOS=false
IS_TERMUX=false; IS_ISH=false; IS_MACOS=false
USE_SUDO="sudo"

# Check if sudo is available; fall back to doas or empty
if ! command -v sudo &>/dev/null; then
    if command -v doas &>/dev/null; then
        USE_SUDO="doas"
    else
        USE_SUDO=""
        warn "No sudo/doas found — running as current user"
    fi
fi

# Termux detection
if [[ -n "$TERMUX_VERSION" ]] || [[ -d "/data/data/com.termux" ]]; then
    IS_TERMUX=true; USE_SUDO=""
    ok "Termux (Android) detected"
# iSH / Alpine detection
elif [[ -f /proc/ish/version ]] || uname -r 2>/dev/null | grep -qi "ish"; then
    IS_ISH=true; IS_ALPINE=true
    ok "iSH (iOS) detected"
elif [[ -f /etc/alpine-release ]]; then
    IS_ALPINE=true; ok "Alpine Linux detected"
elif [[ "$(uname)" == "Darwin" ]]; then
    IS_MACOS=true; ok "macOS detected"
elif [[ -f /etc/arch-release ]] || [[ -f /etc/manjaro-release ]]; then
    IS_ARCH=true; ok "Arch/Manjaro detected"
elif [[ -f /etc/debian_version ]]; then
    IS_DEBIAN=true
    DISTRO=$(lsb_release -is 2>/dev/null || cat /etc/os-release 2>/dev/null | grep ^ID= | cut -d= -f2)
    ok "Debian-family ($DISTRO) detected"
elif [[ -f /etc/fedora-release ]] || grep -qi "rhel\|centos\|rocky\|alma" /etc/os-release 2>/dev/null; then
    IS_FEDORA=true
    DISTRO=$(cat /etc/os-release 2>/dev/null | grep ^ID= | cut -d= -f2)
    ok "RHEL-family ($DISTRO) detected"
elif [[ -f /etc/SuSE-release ]] || [[ -f /etc/opensuse-release ]] || grep -qi "suse" /etc/os-release 2>/dev/null; then
    IS_OPENSUSE=true; ok "openSUSE detected"
elif [[ -f /etc/void-release ]] || grep -qi "void" /etc/os-release 2>/dev/null; then
    IS_VOID=true; ok "Void Linux detected"
elif [[ -f /etc/nixos/configuration.nix ]] || command -v nix-env &>/dev/null; then
    IS_NIXOS=true; ok "NixOS detected"
    warn "NixOS: use nix-env or home-manager for system packages"
else
    # Fallback: try to detect via package manager
    if command -v pacman &>/dev/null; then
        IS_ARCH=true; warn "Unknown distro — using pacman (Arch-style)"
    elif command -v apt-get &>/dev/null; then
        IS_DEBIAN=true; warn "Unknown distro — using apt-get (Debian-style)"
    elif command -v dnf &>/dev/null; then
        IS_FEDORA=true; warn "Unknown distro — using dnf (Fedora-style)"
    elif command -v zypper &>/dev/null; then
        IS_OPENSUSE=true; warn "Unknown distro — using zypper (SUSE-style)"
    elif command -v xbps-install &>/dev/null; then
        IS_VOID=true; warn "Unknown distro — using xbps (Void-style)"
    elif command -v apk &>/dev/null; then
        IS_ALPINE=true; warn "Unknown distro — using apk (Alpine-style)"
    else
        IS_DEBIAN=true; warn "Cannot detect distro — attempting Debian-style"
    fi
fi

install_pkg() {
    local pkg="$1"
    if $IS_TERMUX;   then pkg install -y "$pkg" 2>/dev/null; return $?; fi
    if $IS_ALPINE;   then $USE_SUDO apk add --no-cache "$pkg" 2>/dev/null; return $?; fi
    if $IS_MACOS;    then brew install "$pkg" 2>/dev/null; return $?; fi
    if $IS_ARCH;     then $USE_SUDO pacman -S --noconfirm --needed "$pkg" 2>/dev/null; return $?; fi
    if $IS_DEBIAN;   then DEBIAN_FRONTEND=noninteractive $USE_SUDO apt-get install -y -qq "$pkg" 2>/dev/null; return $?; fi
    if $IS_FEDORA;   then $USE_SUDO dnf install -y -q "$pkg" 2>/dev/null; return $?; fi
    if $IS_OPENSUSE; then $USE_SUDO zypper install -y --quiet "$pkg" 2>/dev/null; return $?; fi
    if $IS_VOID;     then $USE_SUDO xbps-install -y "$pkg" 2>/dev/null; return $?; fi
    if $IS_NIXOS;    then nix-env -iA nixpkgs."$pkg" 2>/dev/null; return $?; fi
    return 1
}

pkg_installed() { command -v "$1" &>/dev/null; }

pip_find() {
    # Find the best available pip
    for p in pip3 pip python3 -m pip python -m pip; do
        if command -v "${p%% *}" &>/dev/null; then
            echo "$p"; return 0
        fi
    done
    echo "pip3"
}

pip_install() {
    local pkg="$1"
    local _pip; _pip="$(pip_find)"
    if $IS_TERMUX; then
        $_pip install "$pkg" 2>/dev/null && return 0
    fi
    if $IS_NIXOS; then
        warn "NixOS: install python packages via nix-env -iA nixpkgs.python3Packages.$pkg"
        return 1
    fi
    # Try multiple install modes in order
    $_pip install --quiet --break-system-packages "$pkg" 2>/dev/null && return 0
    $_pip install --quiet --user "$pkg" 2>/dev/null && return 0
    $_pip install --quiet "$pkg" 2>/dev/null && return 0
    # Last resort: pip2
    pip install --quiet "$pkg" 2>/dev/null && return 0
    return 1
}

# ── Check Python version ───────────────────────────────────────
PY_CMD=""
for c in python3 python3.12 python3.11 python3.10 python python; do
    if command -v "$c" &>/dev/null; then
        PY_VER=$("$c" -c "import sys; print(sys.version_info[:2])" 2>/dev/null)
        if "$c" -c "import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)" 2>/dev/null; then
            PY_CMD="$c"; break
        fi
    fi
done
if [[ -z "$PY_CMD" ]]; then
    warn "Python 3.8+ not found — installing..."
    if $IS_ARCH;   then install_pkg python
    elif $IS_DEBIAN; then install_pkg python3
    elif $IS_FEDORA; then install_pkg python3
    elif $IS_ALPINE; then install_pkg python3
    fi
    PY_CMD="python3"
fi
ok "Python: $PY_CMD"

# ── Update package manager ─────────────────────────────────────
hdr "Updating package manager"
if $IS_TERMUX; then
    pkg update -y 2>/dev/null && ok "Termux updated" || warn "Update failed (offline?)"
elif $IS_ALPINE || $IS_ISH; then
    $USE_SUDO apk update 2>/dev/null && ok "apk updated" || warn "apk update failed"
elif $IS_MACOS; then
    brew update 2>/dev/null && ok "Homebrew updated" || warn "brew update failed"
elif $IS_ARCH; then
    $USE_SUDO pacman -Sy --noconfirm 2>/dev/null && ok "pacman synced" || warn "pacman sync failed"
elif $IS_DEBIAN; then
    $USE_SUDO apt-get update -qq 2>/dev/null && ok "apt updated" || warn "apt update failed (check /etc/apt/sources.list)"
elif $IS_FEDORA; then
    $USE_SUDO dnf check-update -q 2>/dev/null || true; ok "dnf ready"
elif $IS_OPENSUSE; then
    $USE_SUDO zypper refresh 2>/dev/null && ok "zypper refreshed" || warn "zypper refresh failed"
elif $IS_VOID; then
    $USE_SUDO xbps-install -Su 2>/dev/null && ok "xbps updated" || warn "xbps update failed"
fi

# ── Core system dependencies ───────────────────────────────────
hdr "System dependencies"

install_pkg_safe() {
    local name="$1"; local pkg="$2"
    if install_pkg "$pkg" 2>/dev/null; then
        ok "$name"
    else
        warn "$name — not installed (try: install_pkg $pkg manually)"
        ERRORS=$((ERRORS+1))
    fi
}

if $IS_TERMUX; then
    for p in python git openssl nmap curl sqlite alsa-utils; do
        install_pkg_safe "$p" "$p"
    done
elif $IS_ALPINE || $IS_ISH; then
    for p in python3 py3-pip git openssl nmap curl sqlite; do
        install_pkg_safe "$p" "$p"
    done
elif $IS_MACOS; then
    for p in python3 git openssl nmap curl sqlite3; do
        install_pkg_safe "$p" "$p"
    done
else
    # Generic Linux — map to distro-specific names
    declare -A PKG_MAP
    if $IS_ARCH; then
        PKG_MAP=([python]=python [pip]=python-pip [git]=git [sqlite]=sqlite
                 [curl]=curl [nmap]=nmap [net-tools]=net-tools [alsa]=alsa-utils
                 [tk]=tk [aplay]=alsa-utils)
    elif $IS_DEBIAN; then
        PKG_MAP=([python]=python3 [pip]=python3-pip [git]=git [sqlite]=sqlite3
                 [curl]=curl [nmap]=nmap [net-tools]=net-tools [alsa]=alsa-utils
                 [tk]=python3-tk [aplay]=alsa-utils [xclip]=xclip [wl-copy]=wl-clipboard)
    elif $IS_FEDORA; then
        PKG_MAP=([python]=python3 [pip]=python3-pip [git]=git [sqlite]=sqlite
                 [curl]=curl [nmap]=nmap [net-tools]=net-tools [alsa]=alsa-utils
                 [tk]=python3-tkinter [aplay]=alsa-utils)
    elif $IS_OPENSUSE; then
        PKG_MAP=([python]=python3 [pip]=python3-pip [git]=git [sqlite]=sqlite3
                 [curl]=curl [nmap]=nmap [alsa]=alsa-utils
                 [tk]=python3-tk [aplay]=alsa-utils)
    elif $IS_VOID; then
        PKG_MAP=([python]=python3 [pip]=python3-pip [git]=git [sqlite]=sqlite
                 [curl]=curl [nmap]=nmap [alsa]=alsa-utils [aplay]=alsa-utils)
    fi

    for key in python pip git sqlite curl nmap net-tools alsa tk aplay; do
        pkg="${PKG_MAP[$key]:-}"
        [[ -z "$pkg" ]] && continue
        install_pkg_safe "$key" "$pkg"
    done

    # Also install clipboard utilities for sound/clipboard support
    if $IS_DEBIAN; then
        install_pkg_safe "xclip"      "xclip"      2>/dev/null || true
        install_pkg_safe "wl-copy"    "wl-clipboard" 2>/dev/null || true
        install_pkg_safe "xsel"       "xsel"       2>/dev/null || true
    fi
fi

# ── Python packages ────────────────────────────────────────────
hdr "Python packages"
PY_DEPS=(
    "dnspython"
    "python-whois"
    "pyOpenSSL"
    "requests"
    "colorama"
    "beautifulsoup4"
    "netifaces"
    "scapy"
    "paramiko"
)

for dep in "${PY_DEPS[@]}"; do
    if pip_install "$dep"; then
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
        ok "$name already installed"
        return
    fi
    log "Installing $name..."
    eval "$install_cmd" 2>/dev/null && ok "$name installed" || warn "$name failed — install manually"
}

# Nmap (already installed in core deps for most)
pkg_installed nmap && ok "Nmap ready" || install_tool "Nmap" "nmap" "install_pkg nmap"

# SQLMap
if ! pkg_installed sqlmap; then
    install_tool "SQLMap" "sqlmap" "pip_install sqlmap"
fi

# Gobuster (not available on Termux/iSH — skip gracefully)
if ! $IS_TERMUX && ! $IS_ISH; then
    install_tool "Gobuster" "gobuster" "install_pkg gobuster"
else
    dim "Gobuster: skipped (not available on mobile platforms)"
fi

# Hydra
install_tool "Hydra" "hydra" "install_pkg hydra"

# Nikto
if ! pkg_installed nikto; then
    if $IS_TERMUX; then
        dim "Nikto: install via git clone on Termux"
    else
        install_tool "Nikto" "nikto" "install_pkg nikto"
    fi
fi

# WPScan (Ruby-based — skip on limited platforms)
if ! $IS_TERMUX && ! $IS_ISH; then
    if ! pkg_installed wpscan; then
        log "Installing WPScan (Ruby gem)..."
        install_pkg ruby 2>/dev/null || true
        gem install wpscan 2>/dev/null && ok "WPScan installed" || warn "WPScan failed — gem install wpscan"
    else
        ok "WPScan already installed"
    fi
else
    dim "WPScan: skipped (not available on mobile)"
fi

# XSStrike
if ! pkg_installed xsstrike; then
    log "Installing XSStrike..."
    pip_install xsstrike 2>/dev/null && ok "XSStrike" || {
        XSDIR="${PREFIX:-/opt}/XSStrike"
        if [[ ! -d "$XSDIR" ]]; then
            git clone --depth=1 https://github.com/s0md3v/XSStrike "$XSDIR" --quiet 2>/dev/null \
                && ok "XSStrike cloned to $XSDIR" || warn "XSStrike failed"
        else
            ok "XSStrike already at $XSDIR"
        fi
    }
else
    ok "XSStrike already installed"
fi

# Commix
if ! pkg_installed commix; then
    CXDIR="${PREFIX:-/opt}/commix"
    if [[ ! -d "$CXDIR" ]]; then
        log "Installing Commix..."
        git clone --depth=1 https://github.com/commixproject/commix.git "$CXDIR" 2>/dev/null \
            && chmod +x "$CXDIR/commix.py" \
            && ok "Commix installed" || warn "Commix failed"
    else
        ok "Commix already at $CXDIR"
    fi
else
    ok "Commix already installed"
fi

# Wordlists
hdr "Wordlists"
WLIST_OK=false
for wlist_path in /usr/share/wordlists/dirb/common.txt \
                  /usr/share/dirb/wordlists/common.txt \
                  "${PREFIX}/share/wordlists/common.txt" \
                  "${HOME}/.webgate/wordlists/common.txt"; do
    if [[ -f "$wlist_path" ]]; then
        ok "Wordlist found: $wlist_path"; WLIST_OK=true; break
    fi
done
if ! $WLIST_OK; then
    log "Downloading minimal wordlist..."
    WL_DIR="${HOME}/.webgate/wordlists"
    mkdir -p "$WL_DIR"
    curl -sL "https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt" \
        -o "$WL_DIR/common.txt" 2>/dev/null \
    && ok "Wordlist downloaded to $WL_DIR/common.txt" \
    || warn "Wordlist download failed — gobuster needs -w /path/to/wordlist.txt"
fi

# ── CVE Database ───────────────────────────────────────────────
hdr "CVE Database"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DB_PATH="$SCRIPT_DIR/cve.db"
if [[ ! -f "$DB_PATH" ]]; then
    log "Creating CVE SQLite database..."
    python3 "$SCRIPT_DIR/webgate.py" --init-db 2>/dev/null \
        && ok "CVE database created: $DB_PATH" \
        || warn "CVE DB creation failed — will auto-create on first run"
else
    COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM services;" 2>/dev/null || echo "?")
    ok "CVE database exists ($COUNT entries)"
fi

# ── Permissions & symlink ──────────────────────────────────────
hdr "Finishing up"
chmod +x "$SCRIPT_DIR/webgate.py"
ok "webgate.py marked executable"

# Create symlink (not on Termux/iSH — use alias instead)
if $IS_TERMUX; then
    BINDIR="$PREFIX/bin"
    ln -sf "$SCRIPT_DIR/webgate.py" "$BINDIR/webgate" 2>/dev/null \
        && ok "Symlink: $BINDIR/webgate" \
        || warn "Add alias: alias webgate='python3 $SCRIPT_DIR/webgate.py'"
elif $IS_ISH; then
    ln -sf "$SCRIPT_DIR/webgate.py" /usr/local/bin/webgate 2>/dev/null \
        && ok "Symlink: /usr/local/bin/webgate" \
        || warn "Add alias: alias webgate='python3 $SCRIPT_DIR/webgate.py'"
else
    # Try /usr/local/bin first, then ~/.local/bin as fallback
    if $USE_SUDO ln -sf "$SCRIPT_DIR/webgate.py" /usr/local/bin/webgate 2>/dev/null; then
        ok "Symlink: /usr/local/bin/webgate"
    else
        LOCAL_BIN="$HOME/.local/bin"
        mkdir -p "$LOCAL_BIN"
        ln -sf "$SCRIPT_DIR/webgate.py" "$LOCAL_BIN/webgate" 2>/dev/null \
            && ok "Symlink: $LOCAL_BIN/webgate (add to PATH if needed)" \
            || warn "Symlink failed — run manually: $PY_CMD $SCRIPT_DIR/webgate.py"
    fi
fi

# ── Summary ────────────────────────────────────────────────────
echo ""
if [[ $ERRORS -eq 0 ]]; then
    echo -e "  ${GREEN}╔══════════════════════════════════════════════════╗${RST}"
    echo -e "  ${GREEN}║  WebGate v4.0 installation complete!   ✓        ║${RST}"
    echo -e "  ${GREEN}╚══════════════════════════════════════════════════╝${RST}"
else
    echo -e "  ${YELLOW}╔══════════════════════════════════════════════════╗${RST}"
    echo -e "  ${YELLOW}║  WebGate installed with $ERRORS warning(s)             ║${RST}"
    echo -e "  ${YELLOW}║  Optional tools may be missing — see above       ║${RST}"
    echo -e "  ${YELLOW}╚══════════════════════════════════════════════════╝${RST}"
fi
echo ""

if $IS_TERMUX; then
    dim "  Termux notes:"
    dim "    • termux-setup-storage for file access"
    dim "    • GUI mode not available — use CLI"
    dim "    • For sound: pkg install termux-api && termux-media-player"
    echo ""
elif $IS_NIXOS; then
    dim "  NixOS notes:"
    dim "    • Add to nix-env or use nix-shell for Python packages"
    dim "    • Run: nix-shell -p python3 python3Packages.dnspython ..."
    echo ""
elif $IS_ISH; then
    dim "  iSH notes:"
    dim "    • Limited networking on iOS"
    dim "    • GUI not available — use CLI"
    echo ""
fi

if $IS_DEBIAN || $IS_ARCH; then
    if ! command -v xclip &>/dev/null && ! command -v wl-copy &>/dev/null; then
        warn "Clipboard copy: install xclip (X11) or wl-clipboard (Wayland)"
        dim "    apt install xclip  OR  pacman -S xclip"
    fi
    if ! command -v aplay &>/dev/null && ! command -v paplay &>/dev/null && ! command -v pw-play &>/dev/null; then
        warn "Sound: install alsa-utils or pipewire for typing sounds"
        dim "    apt install alsa-utils  OR  pacman -S alsa-utils"
    fi
fi

dim "  Usage:"
dim "    webgate                      →  interactive CLI"
dim "    webgate -d example.com       →  quick scan"
dim "    webgate agent                →  network agent mode"
dim "    webgate exploit example.com  →  exploit mode (with agreement)"
dim "    webgate --gui                →  GUI (desktop only)"
echo ""
