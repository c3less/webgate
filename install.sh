#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  WebGate v2.0 — Auto-Installer
#  Created by c3less
# ═══════════════════════════════════════════════════════════════

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
WHITE='\033[1;37m'; DIM='\033[2m'; RST='\033[0m'

banner() {
cat << 'EOF'

██╗    ██╗███████╗██████╗  ██████╗  █████╗ ████████╗███████╗
██║    ██║██╔════╝██╔══██╗██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝
██║ █╗ ██║█████╗  ██████╔╝██║  ███╗███████║   ██║   █████╗
██║███╗██║██╔══╝  ██╔══██╗██║   ██║██╔══██║   ██║   ██╔══╝
╚███╔███╔╝███████╗██████╔╝╚██████╔╝██║  ██║   ██║   ███████╗
 ╚══╝╚══╝ ╚══════╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝

  WebGate Installer v2.0  ·  by c3less
  ──────────────────────────────────────────────────────────────
EOF
}

log()  { echo -e "  ${WHITE}[+]${RST} $1"; }
warn() { echo -e "  ${YELLOW}[!]${RST} $1"; }
err()  { echo -e "  ${RED}[-]${RST} $1"; }
ok()   { echo -e "  ${GREEN}[✓]${RST} $1"; }
dim()  { echo -e "  ${DIM}$1${RST}"; }

banner

# ── Detect OS ──────────────────────────────────────────────────
OS="unknown"
if   [[ -f /etc/debian_version ]]; then OS="debian"
elif [[ -f /etc/arch-release ]];   then OS="arch"
elif [[ -f /etc/fedora-release ]]; then OS="fedora"
elif [[ "$OSTYPE" == "darwin"* ]]; then OS="macos"
fi
log "Detected OS: $OS"

# ── Check Python ───────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    err "Python 3 not found. Please install Python 3.10+"
    exit 1
fi
PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
log "Python version: $PY_VER"

# ── Check pip ──────────────────────────────────────────────────
if ! command -v pip3 &>/dev/null; then
    warn "pip3 not found — attempting to install..."
    case $OS in
        debian) sudo apt-get install -y python3-pip ;;
        arch)   sudo pacman -Sy --noconfirm python-pip ;;
        fedora) sudo dnf install -y python3-pip ;;
        macos)  python3 -m ensurepip --upgrade ;;
        *)      err "Cannot install pip automatically. Please install pip3 manually."; exit 1 ;;
    esac
fi
ok "pip3 found"

# ── Python dependencies ────────────────────────────────────────
log "Installing Python dependencies..."
pip3 install --quiet --upgrade pip

DEPS=("dnspython" "python-whois" "pyOpenSSL" "colorama")
for dep in "${DEPS[@]}"; do
    echo -n "  Installing $dep... "
    if pip3 install --quiet "$dep"; then
        echo -e "${GREEN}done${RST}"
    else
        echo -e "${YELLOW}failed (optional)${RST}"
    fi
done

# ── tkinter ────────────────────────────────────────────────────
log "Checking tkinter (GUI support)..."
if python3 -c "import tkinter" 2>/dev/null; then
    ok "tkinter available"
else
    warn "tkinter not found — installing..."
    case $OS in
        debian) sudo apt-get install -y python3-tk ;;
        arch)   sudo pacman -Sy --noconfirm tk ;;
        fedora) sudo dnf install -y python3-tkinter ;;
        macos)  warn "On macOS install Homebrew Python: brew install python-tk@3.12" ;;
        *)      warn "Install python3-tk via your package manager" ;;
    esac
fi

# ── aplay (sound on Linux) ─────────────────────────────────────
if [[ "$OS" != "macos" ]]; then
    if ! command -v aplay &>/dev/null; then
        log "Installing alsa-utils (sound support)..."
        case $OS in
            debian) sudo apt-get install -y alsa-utils ;;
            arch)   sudo pacman -Sy --noconfirm alsa-utils ;;
            fedora) sudo dnf install -y alsa-utils ;;
        esac
    else
        ok "aplay found (sound support)"
    fi
fi

# ── notify-send (notifications on Linux) ──────────────────────
if [[ "$OS" != "macos" ]] && ! command -v notify-send &>/dev/null; then
    log "Installing libnotify (desktop notifications)..."
    case $OS in
        debian) sudo apt-get install -y libnotify-bin ;;
        arch)   sudo pacman -Sy --noconfirm libnotify ;;
        fedora) sudo dnf install -y libnotify ;;
    esac
fi

# ── Optional external tools ────────────────────────────────────
echo ""
log "Checking optional external tools (Deep Scan features):"

# WhatWeb
if command -v whatweb &>/dev/null; then
    ok "WhatWeb: $(whatweb --version 2>&1 | head -1)"
else
    warn "WhatWeb not found"
    read -p "  Install WhatWeb? [y/N] " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        case $OS in
            debian) sudo apt-get install -y whatweb ;;
            arch)
                # whatweb is in AUR, not official repos
                if command -v yay &>/dev/null; then
                    yay -Sy --noconfirm whatweb
                elif command -v paru &>/dev/null; then
                    paru -Sy --noconfirm whatweb
                else
                    # Fallback: install from git directly
                    log "AUR helper not found — installing WhatWeb from source..."
                    TMPDIR=$(mktemp -d)
                    git clone --depth=1 https://github.com/urbanadventurer/WhatWeb.git "$TMPDIR/whatweb"
                    sudo install -Dm755 "$TMPDIR/whatweb/whatweb" /usr/local/bin/whatweb
                    sudo cp -r "$TMPDIR/whatweb/plugins" /usr/local/share/whatweb-plugins 2>/dev/null || true
                    rm -rf "$TMPDIR"
                    # WhatWeb needs ruby
                    if ! command -v ruby &>/dev/null; then
                        sudo pacman -Sy --noconfirm ruby
                    fi
                    ok "WhatWeb installed from source"
                fi ;;
            fedora) sudo dnf install -y whatweb ;;
            *)      warn "Install manually: https://github.com/urbanadventurer/WhatWeb" ;;
        esac
    fi
fi

# SQLMap
if command -v sqlmap &>/dev/null; then
    ok "SQLMap: found"
else
    warn "SQLMap not found"
    read -p "  Install SQLMap via pip? [y/N] " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        pip3 install --quiet sqlmap && ok "SQLMap installed"
    fi
fi

# ── Make webgate executable ────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chmod +x "$SCRIPT_DIR/webgate.py"

# ── Optional: create symlink ───────────────────────────────────
echo ""
read -p "  Create 'webgate' command in /usr/local/bin? [y/N] " ans
if [[ "$ans" =~ ^[Yy]$ ]]; then
    sudo ln -sf "$SCRIPT_DIR/webgate.py" /usr/local/bin/webgate
    ok "Symlink created → /usr/local/bin/webgate"
fi

# ── Done ───────────────────────────────────────────────────────
echo ""
echo -e "  ════════════════════════════════════════════════════"
ok "WebGate installation complete!"
echo ""
dim "  Run CLI:  python3 webgate.py"
dim "  Run GUI:  python3 webgate.py --gui"
dim "  Quick:    python3 webgate.py -d example.com"
echo -e "  ════════════════════════════════════════════════════"
echo ""
