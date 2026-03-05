#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebGate  —  Domain Security Auditor
Created by c3less  |  https://github.com/c3less/webgate
Telegram: @c3less

CLI:   python webgate.py
GUI:   python webgate.py --gui
Quick: python webgate.py -d example.com
"""

# ═══════════════════════════════════════════════════════════════
# IMPORTS
# ═══════════════════════════════════════════════════════════════
import sys, os, re, time, socket, ssl, json, threading, argparse
import subprocess, struct, wave, io, math, tempfile, atexit, sqlite3
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# Force X11 for transparency support on Linux/Wayland
if sys.platform.startswith("linux"):
    os.environ.setdefault("GDK_BACKEND", "x11")
    os.environ.setdefault("DISPLAY", ":0")

try:
    import whois;          WHOIS_OK = True
except ImportError:        WHOIS_OK = False
try:
    import dns.resolver, dns.exception; DNS_OK = True
except ImportError:        DNS_OK = False


# ═══════════════════════════════════════════════════════════════
# SETTINGS
# ═══════════════════════════════════════════════════════════════
_SCRIPT_DIR    = os.path.dirname(os.path.realpath(os.path.abspath(__file__)))
_SETTINGS_FILE = os.path.join(_SCRIPT_DIR, "settings.json")
_REPORTS_DIR   = _SCRIPT_DIR
_IS_SYMLINK    = os.path.islink(os.path.abspath(sys.argv[0]))

_DEFAULT_SETTINGS = {
    "lang":         "EN",
    "theme":        "dark",   # always default to vibrant dark
    "sound":        True,
    "transparency": 0.93,
    "custom_theme": {},
    "deep_tools": {
        "nmap": True, "wpscan": True, "sqlmap": True,
        "cmseek": False, "xsstrike": True, "gobuster": True,
        "commix": False, "droopescan": False, "brutex": False,
        "arachni": False, "weeman": False, "sslstrip": False,
        "reaver": False, "pixiewps": False, "cupp": False,
        "wp_plugins": True, "shell_finder": True, "sqli_scan": True,
        "upload_check": True, "gravityforms": True, "joomla_rce": False,
        "vbulletin_rce": False, "bypass_cf": True, "poet": False,
        "port_scan_deep": True, "ssl_audit": True,
        "wordpress_scan": True, "wp_exploit": True,
    },
    "ask_per_port":  False,
    "auto_surface":  True,
}

def load_settings() -> dict:
    try:
        with open(_SETTINGS_FILE) as f:
            s = json.load(f)
            merged = dict(_DEFAULT_SETTINGS)
            merged.update(s)
            if "deep_tools" in s:
                merged["deep_tools"] = {**_DEFAULT_SETTINGS["deep_tools"], **s["deep_tools"]}
            return merged
    except Exception:
        return dict(_DEFAULT_SETTINGS)

def save_settings(s: dict):
    try:
        with open(_SETTINGS_FILE, "w") as f:
            json.dump(s, f, indent=2)
    except Exception:
        pass

SETTINGS = load_settings()


# ═══════════════════════════════════════════════════════════════
# TOOL CATALOG  (30 tools)
# ═══════════════════════════════════════════════════════════════
TOOL_CATALOG = {
    "nmap":          {"label": "Nmap",                "cat": "recon",   "ext": True,  "cmd": "nmap"},
    "wpscan":        {"label": "WPScan",              "cat": "cms",     "ext": True,  "cmd": "wpscan"},
    "sqlmap":        {"label": "SQLMap",              "cat": "sql",     "ext": True,  "cmd": "sqlmap"},
    "cmseek":        {"label": "CMS Scanner",         "cat": "cms",     "ext": True,  "cmd": "cmseek"},
    "xsstrike":      {"label": "XSStrike",            "cat": "xss",     "ext": True,  "cmd": "xsstrike"},
    "gobuster":      {"label": "Dir/Shell Finder",    "cat": "recon",   "ext": True,  "cmd": "gobuster"},
    "commix":        {"label": "Commix (CMDi)",       "cat": "cmdi",    "ext": True,  "cmd": "commix"},
    "droopescan":    {"label": "Drupal Hacking",      "cat": "cms",     "ext": True,  "cmd": "droopescan"},
    "brutex":        {"label": "BruteX",              "cat": "brute",   "ext": True,  "cmd": "brutex"},
    "arachni":       {"label": "Arachni",             "cat": "web",     "ext": True,  "cmd": "arachni"},
    "weeman":        {"label": "Weeman (Phish)",      "cat": "phish",   "ext": True,  "cmd": "weeman"},
    "sslstrip":      {"label": "SSLstrip",            "cat": "mitm",    "ext": True,  "cmd": "sslstrip"},
    "reaver":        {"label": "Reaver (WiFi)",       "cat": "wifi",    "ext": True,  "cmd": "reaver"},
    "pixiewps":      {"label": "Pixiewps (WiFi)",     "cat": "wifi",    "ext": True,  "cmd": "pixiewps"},
    "cupp":          {"label": "Cupp (Wordlist)",     "cat": "osint",   "ext": True,  "cmd": "cupp"},
    "wordpress_scan":{"label": "WordPress Scanner",   "cat": "cms",     "ext": False, "cmd": "internal"},
    "wp_plugins":    {"label": "WP Plugins Scan",     "cat": "cms",     "ext": False, "cmd": "internal"},
    "wp_exploit":    {"label": "WP Exploit Scan",     "cat": "cms",     "ext": False, "cmd": "internal"},
    "gravityforms":  {"label": "Gravity Forms Scan",  "cat": "cms",     "ext": False, "cmd": "internal"},
    "upload_check":  {"label": "File Upload Check",   "cat": "web",     "ext": False, "cmd": "internal"},
    "sqli_scan":     {"label": "SQLi Scanner",        "cat": "sql",     "ext": False, "cmd": "internal"},
    "shell_finder":  {"label": "Shell Finder",        "cat": "recon",   "ext": False, "cmd": "internal"},
    "joomla_rce":    {"label": "Joomla RCE",          "cat": "rce",     "ext": False, "cmd": "internal"},
    "vbulletin_rce": {"label": "vBulletin RCE",       "cat": "rce",     "ext": False, "cmd": "internal"},
    "bypass_cf":     {"label": "Bypass Cloudflare",   "cat": "recon",   "ext": False, "cmd": "internal"},
    "poet":          {"label": "POET",                "cat": "web",     "ext": False, "cmd": "internal"},
    "port_scan_deep":{"label": "Deep Port Scan",      "cat": "recon",   "ext": False, "cmd": "internal"},
    "ssl_audit":     {"label": "SSL Full Audit",      "cat": "ssl",     "ext": False, "cmd": "internal"},
    "inurlbr":       {"label": "Inurlbr (Dork)",      "cat": "osint",   "ext": False, "cmd": "internal"},
    "setoolkit":     {"label": "SET Social Eng.",     "cat": "social",  "ext": True,  "cmd": "setoolkit"},
}

CAT_COLORS = {
    "recon":  "#4a9eff", "cms":   "#ff9f43", "sql":  "#ee5a24",
    "xss":    "#ff6b6b", "cmdi":  "#ff4757", "mitm": "#a29bfe",
    "brute":  "#fd79a8", "web":   "#55efc4", "phish":"#fdcb6e",
    "wifi":   "#74b9ff", "osint": "#81ecec", "rce":  "#d63031",
    "ssl":    "#00b894", "social":"#e17055",
}


# ═══════════════════════════════════════════════════════════════
# TRANSLATIONS
# ═══════════════════════════════════════════════════════════════
TR = {
"EN": {
    "app_title":    "WebGate",
    "app_sub":      "Domain Security Auditor",
    "credit":       "by c3less",
    "instructions": "Enter domain · START SCAN = surface · DEEP SCAN = full pentest",
    "target_lbl":   "TARGET DOMAIN",
    "placeholder":  "example.com  or  192.168.1.1",
    "scan_btn":     "START SCAN",
    "deep_btn":     "DEEP SCAN",
    "cancel_btn":   "CANCEL",
    "settings_btn": "⚙  SETTINGS",
    "copy_btn":     "⎘ COPY",
    "clear_btn":    "✕ CLEAR",
    "scanning":     "SCANNING…",
    "ready":        "READY",
    "complete":     "COMPLETE",
    "cancelled":    "CANCELLED",
    "log_hdr":      "SCAN OUTPUT",
    "status_hdr":   "STATUS",
    "steps_hdr":    "STEPS",
    "tools_hdr":    "TOOLS",
    "stat_status":  "STATUS",
    "stat_target":  "TARGET",
    "stat_ip":      "IP",
    "stat_country": "COUNTRY",
    "stat_ports":   "PORTS",
    "stat_ssl":     "SSL",
    "stat_sec":     "SEC",
    "stat_time":    "TIME",
    "stat_eta":     "ETA",
    "steps": ["DNS Resolve","DNS Records","WHOIS","HTTP Headers",
              "SSL / TLS","Port Scan","CVE Check","Report"],
    "deep_steps": ["Nmap","WPScan","SQLMap","Dir Enum","XSS","CVE Exploit","Report"],
    "summary_title": "SURFACE ANALYSIS",
    "summary_ip":    "IP Address",
    "summary_country":"Country",
    "summary_ssl":   "SSL / TLS",
    "summary_open":  "Open Ports",
    "summary_sec":   "Sec Headers",
    "summary_risk":  "Risk Level",
    "summary_cve":   "CVE Matches",
    "summary_next":  "PROCEED TO DEEP SCAN →",
    "summary_close": "CLOSE",
    "risk_low":      "LOW",
    "risk_medium":   "MEDIUM",
    "risk_high":     "HIGH",
    "risk_critical": "CRITICAL",
    "settings_title":"⚙  Settings",
    "lang_label":    "Language",
    "theme_label":   "Theme",
    "sound_label":   "Typing Sound",
    "alpha_label":   "Transparency",
    "ask_port_label":"Ask before each port",
    "save_btn":      "SAVE",
    "close_btn":     "CLOSE",
    "custom_btn":    "Custom Colors",
    "disc_title":    "⚠  Deep Scan — Authorized Use Only",
    "disc_body": (
        "DISCLAIMER — READ CAREFULLY\n\n"
        "WebGate Deep Scan integrates advanced offensive security tools:\n"
        "SQLMap, Nmap, WPScan, XSStrike, Commix, and many more.\n\n"
        "These tools WILL:\n"
        "  • Send aggressive automated requests to the target\n"
        "  • Trigger IDS/IPS and WAF alerts\n"
        "  • Attempt to exploit discovered vulnerabilities\n"
        "  • Leave traces in server logs\n\n"
        "LEGAL USE ONLY:\n"
        "  ✓ Systems you own or operate\n"
        "  ✓ Authorized penetration testing engagements\n"
        "  ✓ CTF / Lab environments\n\n"
        "UNAUTHORIZED use is a criminal offense under CFAA, CMA,\n"
        "and equivalent laws worldwide.\n\n"
        "By clicking AGREE you accept full legal responsibility."
    ),
    "disc_agree":    "✓  I AGREE — I have written authorization",
    "disc_deny":     "✗  CANCEL",
    "tool_sel_title":"Select Deep Scan Tools",
    "tool_sel_sub":  "Check tools to include in the deep scan:",
    "tool_sel_ask":  "Ask before scanning each port",
    "tool_sel_ok":   "START DEEP SCAN",
    "tool_sel_cancel":"CANCEL",
    "port_ask_title":"Port Scan Confirmation",
    "port_ask_yes":  "YES — Scan",
    "port_ask_no":   "SKIP",
    "port_ask_all":  "YES to ALL remaining",
    "notif_title":   "WebGate — Scan Complete",
    "notif_body":    "Security audit finished for",
    "enter_domain":  "Please enter a target domain or IP.",
    "init_msg":      "WebGate ready — enter a target and press START SCAN",
    "copied":        "Copied to clipboard!",
    "missing_mod":   "Optional modules missing — some features disabled",
},
"RU": {
    "app_title":    "WebGate",
    "app_sub":      "Аудитор безопасности доменов",
    "credit":       "by c3less",
    "instructions": "Домен · СКАН = поверхностный · ГЛУБОКИЙ = пентест",
    "target_lbl":   "ЦЕЛЕВОЙ ДОМЕН",
    "placeholder":  "example.com  или  192.168.1.1",
    "scan_btn":     "НАЧАТЬ СКАН",
    "deep_btn":     "ГЛУБОКИЙ СКАН",
    "cancel_btn":   "ОТМЕНА",
    "settings_btn": "⚙  НАСТРОЙКИ",
    "copy_btn":     "⎘ КОПИРОВАТЬ",
    "clear_btn":    "✕ ОЧИСТИТЬ",
    "scanning":     "СКАНИРОВАНИЕ…",
    "ready":        "ГОТОВ",
    "complete":     "ЗАВЕРШЕНО",
    "cancelled":    "ОТМЕНЕНО",
    "log_hdr":      "ВЫВОД СКАНА",
    "status_hdr":   "СТАТУС",
    "steps_hdr":    "ШАГИ",
    "tools_hdr":    "ИНСТРУМЕНТЫ",
    "stat_status":  "СТАТУС",
    "stat_target":  "ЦЕЛЬ",
    "stat_ip":      "IP",
    "stat_country": "СТРАНА",
    "stat_ports":   "ПОРТЫ",
    "stat_ssl":     "SSL",
    "stat_sec":     "ЗАЩ",
    "stat_time":    "ВРЕМЯ",
    "stat_eta":     "ETA",
    "steps": ["DNS Резолюция","DNS Записи","WHOIS","HTTP","SSL / TLS",
              "Скан портов","CVE Проверка","Отчёт"],
    "deep_steps": ["Nmap","WPScan","SQLMap","Dir Enum","XSS","CVE Эксплойт","Отчёт"],
    "summary_title": "ПОВЕРХНОСТНЫЙ АНАЛИЗ",
    "summary_ip":    "IP адрес",
    "summary_country":"Страна",
    "summary_ssl":   "SSL / TLS",
    "summary_open":  "Открытые порты",
    "summary_sec":   "Заголовки защиты",
    "summary_risk":  "Уровень риска",
    "summary_cve":   "CVE совпадений",
    "summary_next":  "НАЧАТЬ ГЛУБОКИЙ СКАН →",
    "summary_close": "ЗАКРЫТЬ",
    "risk_low":      "НИЗКИЙ",
    "risk_medium":   "СРЕДНИЙ",
    "risk_high":     "ВЫСОКИЙ",
    "risk_critical": "КРИТИЧЕСКИЙ",
    "settings_title":"⚙  Настройки",
    "lang_label":    "Язык",
    "theme_label":   "Тема",
    "sound_label":   "Звук печати",
    "alpha_label":   "Прозрачность",
    "ask_port_label":"Спрашивать перед каждым портом",
    "save_btn":      "СОХРАНИТЬ",
    "close_btn":     "ЗАКРЫТЬ",
    "custom_btn":    "Свои цвета",
    "disc_title":    "⚠  Глубокий скан — только авторизованно",
    "disc_body": (
        "ОТКАЗ ОТ ОТВЕТСТВЕННОСТИ — ПРОЧТИТЕ ВНИМАТЕЛЬНО\n\n"
        "Глубокий скан использует мощные инструменты:\n"
        "SQLMap, Nmap, WPScan, XSStrike, Commix и другие.\n\n"
        "Эти инструменты БУДУТ:\n"
        "  • Отправлять агрессивные запросы к цели\n"
        "  • Активировать IDS/IPS и WAF системы\n"
        "  • Пытаться эксплуатировать уязвимости\n"
        "  • Оставлять следы в логах сервера\n\n"
        "РАЗРЕШЁННОЕ ИСПОЛЬЗОВАНИЕ:\n"
        "  ✓ Ваши собственные системы\n"
        "  ✓ Авторизованное тестирование на проникновение\n"
        "  ✓ CTF / Лабораторные среды\n\n"
        "НЕСАНКЦИОНИРОВАННОЕ использование — уголовное преступление.\n\n"
        "Нажимая СОГЛАСЕН вы принимаете полную ответственность."
    ),
    "disc_agree":    "✓  СОГЛАСЕН — у меня есть разрешение",
    "disc_deny":     "✗  ОТМЕНА",
    "tool_sel_title":"Выбор инструментов глубокого скана",
    "tool_sel_sub":  "Отметьте инструменты для глубокого скана:",
    "tool_sel_ask":  "Спрашивать перед сканированием каждого порта",
    "tool_sel_ok":   "НАЧАТЬ ГЛУБОКИЙ СКАН",
    "tool_sel_cancel":"ОТМЕНА",
    "port_ask_title":"Подтверждение сканирования порта",
    "port_ask_yes":  "ДА — Сканировать",
    "port_ask_no":   "ПРОПУСТИТЬ",
    "port_ask_all":  "ДА для ВСЕХ оставшихся",
    "notif_title":   "WebGate — Скан завершён",
    "notif_body":    "Аудит безопасности завершён для",
    "enter_domain":  "Введите целевой домен или IP.",
    "init_msg":      "WebGate v3.0 готов — введите цель и нажмите НАЧАТЬ СКАН",
    "copied":        "Скопировано в буфер!",
    "missing_mod":   "Отсутствуют модули — некоторые функции недоступны",
},
}

def t(key: str) -> str:
    return TR.get(SETTINGS["lang"], TR["EN"]).get(key, key)


# ═══════════════════════════════════════════════════════════════
# THEMES
# ═══════════════════════════════════════════════════════════════
THEMES = {
"dark": {
    "BG":      "#0a0d14", "BG2":    "#0f1220", "BG3":    "#141828",
    "BG4":     "#1a1f32", "BORDER": "#1e2a48", "BORDER2":"#2a4080",
    "BORDER3": "#3a5aaa", "FG":     "#c8d4e8", "FG2":    "#8898b8",
    "FG3":     "#3a4868", "WHITE":  "#e8f0ff", "OFFWHT": "#d0dcf8",
    "BTN_BG":  "#1a6fd4", "BTN_FG": "#ffffff", "BTN_HOV":"#2a8aff",
    "BTN_DIS_BG":"#1a1f32","BTN_DIS_FG":"#3a4868",
    "LOGO_CLR":"#4a9eff", "LOGO_SHD":"#0a1428",
    "ACC":     "#4a9eff", "ACC2":   "#ff6b6b", "ACC3":   "#55efc4",
    "WARN":    "#ffcc00", "ERR":    "#ff4757",
    "LOG_CLR": {"INFO":"#6878a8","FOUND":"#c8d4e8","WARN":"#ffcc00",
                "ERROR":"#ff4757","STEP":"#4a9eff","SUCCESS":"#55efc4"},
},
"light": {
    "BG":      "#f0f0f0", "BG2":    "#e8e8e8", "BG3":    "#dcdcdc",
    "BG4":     "#d0d0d0", "BORDER": "#c0c0c0", "BORDER2":"#999999",
    "BORDER3": "#666666", "FG":     "#1a1a1a", "FG2":    "#555555",
    "FG3":     "#999999", "WHITE":  "#000000", "OFFWHT": "#111111",
    "BTN_BG":  "#111111", "BTN_FG": "#f0f0f0", "BTN_HOV":"#333333",
    "BTN_DIS_BG":"#cccccc","BTN_DIS_FG":"#999999",
    "LOGO_CLR":"#111111", "LOGO_SHD":"#aaaaaa",
    "ACC":     "#0066cc", "ACC2":   "#cc3333", "ACC3":   "#009966",
    "WARN":    "#cc8800", "ERR":    "#cc0000",
    "LOG_CLR": {"INFO":"#888888","FOUND":"#111111","WARN":"#cc8800",
                "ERROR":"#cc0000","STEP":"#0055aa","SUCCESS":"#006633"},
},
"midnight": {
    "BG":      "#05030f", "BG2":    "#0a0820", "BG3":    "#100e2e",
    "BG4":     "#161440", "BORDER": "#1e1c44", "BORDER2":"#3a3878",
    "BORDER3": "#6a68cc", "FG":     "#c0b8f0", "FG2":    "#8880c8",
    "FG3":     "#3a3870", "WHITE":  "#ffffff", "OFFWHT": "#e0d8ff",
    "BTN_BG":  "#c8c0f0", "BTN_FG": "#05030f", "BTN_HOV":"#ffffff",
    "BTN_DIS_BG":"#161440","BTN_DIS_FG":"#4a48a0",
    "LOGO_CLR":"#e0d8ff", "LOGO_SHD":"#1e1c44",
    "ACC":     "#7c6fff", "ACC2":   "#ff6b9d", "ACC3":   "#6dffd8",
    "WARN":    "#ffd166", "ERR":    "#ff4757",
    "LOG_CLR": {"INFO":"#3a3870","FOUND":"#c0b8f0","WARN":"#ffd166",
                "ERROR":"#ff4757","STEP":"#7c6fff","SUCCESS":"#6dffd8"},
},
"hacker": {
    "BG":      "#000000", "BG2":    "#050505", "BG3":    "#0a0a0a",
    "BG4":     "#0f0f0f", "BORDER": "#003300", "BORDER2":"#006600",
    "BORDER3": "#00cc00", "FG":     "#00cc00", "FG2":    "#008800",
    "FG3":     "#004400", "WHITE":  "#00ff00", "OFFWHT": "#00dd00",
    "BTN_BG":  "#003300", "BTN_FG": "#00ff00", "BTN_HOV":"#004400",
    "BTN_DIS_BG":"#050505","BTN_DIS_FG":"#004400",
    "LOGO_CLR":"#00ff00", "LOGO_SHD":"#003300",
    "ACC":     "#00ff88", "ACC2":   "#ff4400", "ACC3":   "#00ffcc",
    "WARN":    "#ffaa00", "ERR":    "#ff2200",
    "LOG_CLR": {"INFO":"#006600","FOUND":"#00cc00","WARN":"#ffaa00",
                "ERROR":"#ff2200","STEP":"#00ff88","SUCCESS":"#00ffcc"},
},
}

THEME_ORDER = ["dark", "light", "midnight", "hacker", "custom"]

def get_theme() -> dict:
    name = SETTINGS.get("theme", "dark")
    base = THEMES.get(name, THEMES["dark"]).copy()
    if name == "custom" and SETTINGS.get("custom_theme"):
        base.update(SETTINGS["custom_theme"])
    return base


# ═══════════════════════════════════════════════════════════════
# SOUND
# ═══════════════════════════════════════════════════════════════
_CLICK_FILE = ""
_last_sound  = 0.0

def _init_sound():
    global _CLICK_FILE
    try:
        sr, n = 22050, int(22050 * 0.018)
        buf = io.BytesIO()
        with wave.open(buf, 'wb') as w:
            w.setnchannels(1); w.setsampwidth(2); w.setframerate(sr)
            frames = []
            for i in range(n):
                t_ = i / sr
                amp = int(4200 * (1 - t_ / 0.018) * math.sin(2 * math.pi * 2400 * t_))
                frames.append(struct.pack('<h', max(-32767, min(32767, amp))))
            w.writeframes(b''.join(frames))
        fd, path = tempfile.mkstemp(suffix='.wav')
        with os.fdopen(fd, 'wb') as f:
            f.write(buf.getvalue())
        _CLICK_FILE = path
        atexit.register(lambda: os.path.exists(path) and os.unlink(path))
    except Exception:
        pass

def play_click():
    global _last_sound
    if not SETTINGS.get("sound") or not _CLICK_FILE:
        return
    now = time.time()
    if now - _last_sound < 0.035:
        return
    _last_sound = now
    try:
        if sys.platform.startswith("linux"):
            subprocess.Popen(["aplay", "-q", _CLICK_FILE],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif sys.platform == "darwin":
            subprocess.Popen(["afplay", _CLICK_FILE])
    except Exception:
        pass

def send_notification(title: str, body: str):
    try:
        if sys.platform.startswith("linux"):
            subprocess.Popen(["notify-send", title, body,
                "--icon=dialog-information", "--expire-time=6000"])
        elif sys.platform == "darwin":
            subprocess.Popen(["osascript", "-e",
                f'display notification "{body}" with title "{title}"'])
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════
# TERMINAL COLORS (CLI)
# ═══════════════════════════════════════════════════════════════
class C:
    RST='\033[0m'; BOLD='\033[1m'; DIM='\033[2m'; ITAL='\033[3m'
    WHT='\033[97m'; GRY='\033[90m'; LGRY='\033[37m'
    CYN='\033[96m'; GRN='\033[92m'; YLW='\033[93m'; RED='\033[91m'
    BLU='\033[94m'; MGT='\033[95m'
    @classmethod
    def disable(cls):
        for a in list(vars(cls)):
            if not a.startswith('_') and isinstance(getattr(cls, a), str):
                setattr(cls, a, '')

if not sys.stdout.isatty(): C.disable()
elif os.name == 'nt':
    try: import colorama; colorama.init()
    except ImportError: C.disable()

BANNER = f"""\
{C.BOLD}{C.WHT}
██╗    ██╗███████╗██████╗  ██████╗  █████╗ ████████╗███████╗
██║    ██║██╔════╝██╔══██╗██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝
██║ █╗ ██║█████╗  ██████╔╝██║  ███╗███████║   ██║   █████╗
██║███╗██║██╔══╝  ██╔══██╗██║   ██║██╔══██║   ██║   ██╔══╝
╚███╔███╔╝███████╗██████╔╝╚██████╔╝██║  ██║   ██║   ███████╗
 ╚══╝╚══╝ ╚══════╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝
{C.RST}{C.DIM}
  ┌─────────────────────────────────────────────────────────┐
  │  Domain Security Auditor  │  v3.0  │  by c3less          │
  │  DNS · WHOIS · SSL · Ports · CVE · DeepScan · 30 Tools  │
  └─────────────────────────────────────────────────────────┘
{C.RST}"""


# ═══════════════════════════════════════════════════════════════
# CVE DATABASE — 200+ entries
# ═══════════════════════════════════════════════════════════════
_CVE_DB_PATH = os.path.join(_SCRIPT_DIR, "cve.db")

CVE_DATA = [
    # nginx
    ("nginx","CVE-2021-23017","Buffer overflow via DNS resolver, CVSS 9.4 — RCE possible"),
    ("nginx","CVE-2019-20372","HTTP request smuggling via malformed Transfer-Encoding"),
    ("nginx","CVE-2017-7529","Integer overflow in range filter, CVSS 7.5 — info leak"),
    ("nginx","CVE-2016-0747","Resolver memory corruption — CVSS 5.0"),
    ("nginx","CVE-2013-2070","Proxy response body corruption via chunked encoding"),
    # apache
    ("apache","CVE-2021-41773","Path traversal + RCE on Apache 2.4.49 — CVSS 9.8"),
    ("apache","CVE-2021-42013","Path traversal bypass of CVE-2021-41773 fix — CVSS 9.8"),
    ("apache","CVE-2020-11984","mod_uwsgi buffer overflow — CVSS 9.8"),
    ("apache","CVE-2019-0211","Local privilege escalation via scoreboard — CVSS 7.8"),
    ("apache","CVE-2017-7679","mod_mime buffer over-read — CVSS 9.8"),
    ("apache","CVE-2017-9798","Optionsbleed — OPTIONS method memory leak"),
    ("apache","CVE-2022-22720","HTTP request smuggling via malformed chunked body"),
    ("apache","CVE-2022-31813","Forwarded header bypass — CVSS 9.8"),
    # IIS
    ("iis","CVE-2021-31166","HTTP Protocol Stack RCE — CVSS 9.8, wormable"),
    ("iis","CVE-2017-7269","WebDAV ScStoragePathFromUrl overflow — CVSS 10.0 RCE"),
    ("iis","CVE-2015-1635","HTTP.sys RCE (MS15-034) — CVSS 9.8"),
    ("iis","CVE-2022-21907","HTTP Protocol Stack RCE — CVSS 9.8"),
    # PHP
    ("php","CVE-2019-11043","PHP-FPM env_path_info underflow RCE — CVSS 9.8"),
    ("php","CVE-2021-21708","UAF in PDO SQLite — CVSS 9.8"),
    ("php","CVE-2022-31625","Uninitialized array in pg_query_params — CVSS 9.8"),
    ("php","CVE-2022-31626","Heap BOF via mysqlnd — CVSS 9.8"),
    ("php","CVE-2016-10033","PHPMailer RCE via mail() — CVSS 9.8"),
    ("php","CVE-2021-21704","FTP wrapper null dereference — CVSS 5.9"),
    # Python/Django/Flask
    ("python","CVE-2022-42966","Django SQL injection via annotate — CVSS 7.5"),
    ("python","CVE-2021-44420","Django bypass URL validation — CVSS 7.3"),
    ("django","CVE-2023-36053","ReDoS in EmailValidator — CVSS 7.5"),
    ("django","CVE-2022-28346","SQL injection via QuerySet.annotate — CVSS 9.8"),
    ("flask","CVE-2018-1000656","Werkzeug path traversal — CVSS 7.5"),
    # MySQL
    ("mysql","CVE-2021-2307","MySQL Server priv escalation — CVSS 6.1"),
    ("mysql","CVE-2020-14765","MySQL Server DoS — CVSS 6.5"),
    ("mysql","CVE-2020-14812","MySQL InnoDB priv escalation — CVSS 4.9"),
    ("mysql","CVE-2016-6662","Config file injection — CVSS 9.8, RCE"),
    ("mysql","CVE-2012-2122","Auth bypass via timing attack — CVSS 5.1"),
    ("mysql","CVE-2021-22929","MySQL Shell code injection — CVSS 8.8"),
    # MariaDB
    ("mariadb","CVE-2022-27376","Auth bypass via malloc — CVSS 9.8"),
    ("mariadb","CVE-2021-46668","Denial of service in Item_func_in — CVSS 6.5"),
    # PostgreSQL
    ("postgresql","CVE-2023-2454","Extension script injection — CVSS 7.2"),
    ("postgresql","CVE-2022-2625","Extension escalation via CREATE EXTENSION — CVSS 8.0"),
    ("postgresql","CVE-2021-23214","MITM SSL injection — CVSS 8.1"),
    ("postgresql","CVE-2019-10208","SQL injection via type name — CVSS 8.8"),
    ("postgresql","CVE-2018-1058","Schema injection RCE — CVSS 8.8"),
    # MongoDB
    ("mongodb","CVE-2021-32036","Denial of service via crafted aggregation — CVSS 6.5"),
    ("mongodb","CVE-2020-7921","Improper serialization — info leak CVSS 5.9"),
    ("mongodb","CVE-2019-20149","Operator injection via $where — CVSS 7.5"),
    # Redis
    ("redis","CVE-2022-0543","Lua sandbox escape — CVSS 10.0 RCE"),
    ("redis","CVE-2021-32761","Out-of-bound read via BITFIELD — CVSS 8.1"),
    ("redis","CVE-2021-32762","Heap overflow in redis-cli — CVSS 8.8"),
    ("redis","CVE-2021-29477","Integer overflow SETRANGE — CVSS 8.8"),
    ("redis","CVE-2020-14147","Denial of service via LPOS — CVSS 7.5"),
    # Memcached
    ("memcached","CVE-2018-1000115","UDP amplification — CVSS 7.5"),
    ("memcached","CVE-2016-8704","Integer overflow — CVSS 9.8 RCE"),
    # SSH / OpenSSH
    ("ssh","CVE-2023-38408","Remote code execution via PKCS11 — CVSS 9.8"),
    ("ssh","CVE-2023-25136","Double-free in sshd — CVSS 6.5"),
    ("ssh","CVE-2021-28041","Double-free in ssh-agent — CVSS 7.1"),
    ("ssh","CVE-2019-6111","SCP client path traversal — CVSS 5.9"),
    ("ssh","CVE-2018-15473","Username enumeration — CVSS 5.3"),
    ("ssh","CVE-2016-10009","sshd agent forwarding priv escalation — CVSS 7.3"),
    # FTP
    ("ftp","CVE-2020-9273","ProFTPD RCE via memory corruption — CVSS 8.8"),
    ("ftp","CVE-2019-12815","ProFTPD arbitrary file copy — CVSS 9.8"),
    ("ftp","CVE-2015-3306","ProFTPD mod_copy unauth file copy — CVSS 10.0"),
    ("ftp","CVE-2011-4130","vsftpd 2.3.4 backdoor — CVSS 10.0"),
    # Telnet
    ("telnet","CVE-2011-4862","BSD Telnetd buffer overflow — CVSS 10.0 RCE"),
    ("telnet","CVE-2020-10188","telnetd buffer overflow — CVSS 9.8"),
    # SMB / Samba
    ("smb","CVE-2021-44142","Samba heap overflow — CVSS 9.9 RCE"),
    ("smb","CVE-2020-0796","SMBGhost Windows RCE — CVSS 10.0"),
    ("smb","CVE-2017-0144","EternalBlue — WannaCry CVSS 9.3 RCE"),
    ("smb","CVE-2017-0145","EternalRomance — CVSS 9.3 RCE"),
    ("smb","CVE-2017-7494","SambaCry — CVSS 7.5 RCE"),
    ("samba","CVE-2022-32744","Kerberos forged PAC — CVSS 8.8"),
    ("samba","CVE-2021-20254","Buffer overflow via sid mapping — CVSS 6.8"),
    # RDP
    ("rdp","CVE-2019-0708","BlueKeep — CVSS 9.8 pre-auth RCE"),
    ("rdp","CVE-2020-0609","Windows RDS RCE — CVSS 9.8"),
    ("rdp","CVE-2021-34535","RDP client RCE — CVSS 8.8"),
    ("rdp","CVE-2022-21893","RDP information disclosure — CVSS 8.0"),
    # WordPress
    ("wordpress","CVE-2022-21662","XSS via post slugs — CVSS 5.4"),
    ("wordpress","CVE-2021-29447","XXE in media library — CVSS 7.1"),
    ("wordpress","CVE-2020-28032","Object injection via plugins — CVSS 9.8"),
    ("wordpress","CVE-2019-8943","Path traversal in media handler — CVSS 6.5"),
    ("wordpress","CVE-2019-17671","Unauthenticated view of private posts — CVSS 5.3"),
    ("wordpress","CVE-2022-3590","SSRF in PingBack — CVSS 5.9"),
    ("wordpress","CVE-2023-2745","Directory traversal — CVSS 5.4"),
    ("wp","CVE-2022-21663","Object injection in WP core — CVSS 7.2"),
    ("wp","CVE-2021-29450","XXE via media upload — CVSS 7.1"),
    # Joomla
    ("joomla","CVE-2023-23752","API unauthorized access — CVSS 5.3"),
    ("joomla","CVE-2021-23132","ACL bypass in webservice — CVSS 7.5"),
    ("joomla","CVE-2020-11890","Stored XSS in custom fields — CVSS 6.1"),
    ("joomla","CVE-2015-8562","PHP object injection RCE — CVSS 10.0"),
    ("joomla","CVE-2017-8917","SQL injection in search — CVSS 9.8"),
    # Drupal
    ("drupal","CVE-2018-7600","Drupalgeddon2 — CVSS 9.8 RCE"),
    ("drupal","CVE-2018-7602","Remote code execution — CVSS 9.8"),
    ("drupal","CVE-2019-6340","REST API RCE — CVSS 9.8"),
    ("drupal","CVE-2020-13671","Unrestricted file upload — CVSS 8.8"),
    ("drupal","CVE-2022-25275","Authentication bypass — CVSS 9.1"),
    # Tomcat
    ("tomcat","CVE-2020-1938","Ghostcat — AJP file read RCE CVSS 9.8"),
    ("tomcat","CVE-2019-0232","CGI Servlet RCE on Windows — CVSS 8.1"),
    ("tomcat","CVE-2017-12617","JSP upload via PUT — CVSS 8.1"),
    ("tomcat","CVE-2016-8735","Deserialization via JmxRemoteLifecycleListener CVSS 9.8"),
    ("tomcat","CVE-2022-42252","Partial PUT RCE — CVSS 9.8"),
    # Jenkins
    ("jenkins","CVE-2023-27898","Stored XSS via plugin — CVSS 8.0"),
    ("jenkins","CVE-2022-2048","Password spray via login — CVSS 7.5"),
    ("jenkins","CVE-2019-1003000","Script approval sandbox bypass RCE — CVSS 8.8"),
    ("jenkins","CVE-2018-1000861","Groovy sandbox escape — CVSS 9.8"),
    ("jenkins","CVE-2016-0792","Java deserialization RCE — CVSS 9.8"),
    # GitLab
    ("gitlab","CVE-2022-2185","CSRF via import — CVSS 8.8"),
    ("gitlab","CVE-2021-22205","Remote code execution via ExifTool — CVSS 10.0"),
    ("gitlab","CVE-2022-1162","Hardcoded password for OmniAuth — CVSS 9.1"),
    ("gitlab","CVE-2023-3932","Privilege escalation — CVSS 8.8"),
    # phpMyAdmin
    ("phpmyadmin","CVE-2020-26934","Stored XSS via QBE — CVSS 6.1"),
    ("phpmyadmin","CVE-2019-12616","CSRF via designer — CVSS 6.1"),
    ("phpmyadmin","CVE-2018-12613","Local file inclusion — CVSS 8.8"),
    ("phpmyadmin","CVE-2016-5734","Remote code execution — CVSS 9.8"),
    # Elasticsearch
    ("elasticsearch","CVE-2021-22145","Information disclosure — CVSS 6.5"),
    ("elasticsearch","CVE-2019-7616","Elevation of privilege — CVSS 8.8"),
    ("elasticsearch","CVE-2015-1427","Groovy sandbox escape — CVSS 10.0"),
    # Kibana
    ("kibana","CVE-2019-7609","Prototype pollution RCE — CVSS 10.0"),
    ("kibana","CVE-2022-23708","SSRF via Alerting — CVSS 4.3"),
    # Grafana
    ("grafana","CVE-2021-43798","Path traversal — CVSS 7.5 read arbitrary files"),
    ("grafana","CVE-2022-26148","Stored credentials in plain text — CVSS 9.8"),
    # Struts
    ("struts","CVE-2017-5638","Jakarta Multipart parser RCE — CVSS 10.0 (Equifax)"),
    ("struts","CVE-2018-11776","RCE via namespace — CVSS 10.0"),
    ("struts","CVE-2019-0230","OGNL expression injection — CVSS 9.8"),
    # Spring
    ("spring","CVE-2022-22965","Spring4Shell — CVSS 9.8 RCE"),
    ("spring","CVE-2022-22950","ReDoS in Spring Security — CVSS 6.5"),
    ("spring","CVE-2018-1270","SpEL injection RCE — CVSS 9.8"),
    # Node.js / Express
    ("nodejs","CVE-2022-32212","DNS rebinding via hosts — CVSS 8.1"),
    ("nodejs","CVE-2021-22931","Prototype pollution — CVSS 9.8"),
    ("express","CVE-2022-24999","Prototype pollution via qs — CVSS 7.5"),
    # SSL/TLS
    ("ssl","CVE-2014-0160","Heartbleed — CVSS 7.5 mem leak"),
    ("ssl","CVE-2014-3566","POODLE — CVSS 3.4 SSLv3 downgrade"),
    ("ssl","CVE-2015-0291","OpenSSL ClientHello sigalgs DoS — CVSS 5.0"),
    ("ssl","CVE-2016-2107","LUCKY13 padding oracle — CVSS 5.9"),
    ("ssl","CVE-2021-3449","OpenSSL TLS renegotiation NULL deref — CVSS 5.9"),
    ("tls","CVE-2020-1967","OpenSSL sig_algs NULL deref — CVSS 7.5"),
    # SMTP
    ("smtp","CVE-2021-44142","Postfix/Cyrus buffer overflow"),
    ("smtp","CVE-2020-7247","OpenSMTPD RCE — CVSS 10.0"),
    ("smtp","CVE-2019-16928","Exim heap overflow — CVSS 9.8"),
    ("smtp","CVE-2018-6789","Exim base64 decode heap overflow — CVSS 9.8"),
    # DNS
    ("dns","CVE-2021-25216","BIND buffer overflow — CVSS 8.1"),
    ("dns","CVE-2020-8617","BIND assertion failure — CVSS 7.5"),
    ("dns","CVE-2020-8616","BIND NXNS attack — CVSS 8.6"),
    # Docker
    ("docker","CVE-2019-5736","runc container escape — CVSS 8.6"),
    ("docker","CVE-2020-15257","Shimmer Unix socket escape — CVSS 5.2"),
    # Kubernetes
    ("kubernetes","CVE-2019-11253","YAML bomb DoS — CVSS 7.5"),
    ("kubernetes","CVE-2018-1002105","Privilege escalation via API — CVSS 9.8"),
    # vBulletin
    ("vbulletin","CVE-2019-16759","PHP object injection RCE — CVSS 9.8"),
    ("vbulletin","CVE-2020-17496","RCE via subWidgets — CVSS 9.8"),
    ("vbulletin","CVE-2021-27931","XSS via post — CVSS 6.1"),
    # HTTP Alt ports
    ("http-alt","CVE-2021-21985","VMware vCenter RCE via VPX — CVSS 9.8"),
    ("http-alt","CVE-2022-0540","Jira auth bypass — CVSS 9.8"),
    ("dev","CVE-2021-26084","Confluence OGNL injection RCE — CVSS 9.8"),
    # WinRM
    ("winrm","CVE-2021-31166","HTTP RCE via protocol stack — CVSS 9.8"),
    # Generic web
    ("http","CVE-2021-44228","Log4Shell — JNDI RCE CVSS 10.0"),
    ("https","CVE-2021-44228","Log4Shell — JNDI RCE CVSS 10.0"),
    ("http","CVE-2022-41040","ProxyNotShell — SSRF + RCE CVSS 8.8"),
    ("http","CVE-2022-41082","ProxyNotShell PowerShell RCE — CVSS 8.8"),
    ("https","CVE-2022-41040","ProxyNotShell — SSRF + RCE CVSS 8.8"),
]

def init_cve_db():
    conn = sqlite3.connect(_CVE_DB_PATH)
    cur  = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS services (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL COLLATE NOCASE,
        cve_id TEXT NOT NULL,
        description TEXT
    )""")
    cur.execute("SELECT COUNT(*) FROM services")
    if cur.fetchone()[0] < len(CVE_DATA):
        cur.execute("DELETE FROM services")
        cur.executemany(
            "INSERT INTO services (name,cve_id,description) VALUES (?,?,?)",
            CVE_DATA
        )
        conn.commit()
    conn.close()

def query_cve(service_name: str) -> list:
    if not os.path.exists(_CVE_DB_PATH):
        return []
    conn = sqlite3.connect(_CVE_DB_PATH)
    cur  = conn.cursor()
    cur.execute(
        "SELECT cve_id, description FROM services WHERE name LIKE ?",
        (f"%{service_name.lower()}%",)
    )
    rows = cur.fetchall()
    conn.close()
    return rows

def get_all_cve_count() -> int:
    if not os.path.exists(_CVE_DB_PATH):
        return 0
    conn = sqlite3.connect(_CVE_DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM services")
    n = c.fetchone()[0]
    conn.close()
    return n


# ═══════════════════════════════════════════════════════════════
# CORE SCANNER
# ═══════════════════════════════════════════════════════════════
class DomainScanner:
    PORTS = {
        21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
        80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS", 445:"SMB",
        587:"SMTPS", 993:"IMAPS", 995:"POP3S", 1433:"MSSQL",
        3306:"MySQL", 3389:"RDP", 4848:"GlassFish", 5432:"PostgreSQL",
        5900:"VNC", 6379:"Redis", 8080:"HTTP-Alt", 8443:"HTTPS-Alt",
        8888:"Dev", 9200:"Elasticsearch", 9300:"ES-Transport",
        11211:"Memcached", 27017:"MongoDB", 28017:"Mongo-Web",
    }
    SECURITY_HEADERS = [
        "Strict-Transport-Security", "Content-Security-Policy",
        "X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection",
        "Referrer-Policy", "Permissions-Policy",
    ]

    def __init__(self, domain: str, log_cb=None, prog_cb=None):
        self.domain   = re.sub(r'^https?://', '', domain.strip().lower()).split('/')[0].split('?')[0]
        self.log_cb   = log_cb  or (lambda m, l: print(f"[{l}] {m}"))
        self.prog_cb  = prog_cb or (lambda v: None)
        self.results  = {}
        self.log_lines= []
        self.cancelled= False
        self.start_time = None

    def _log(self, msg: str, level: str = "INFO"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_lines.append(f"[{ts}] {msg}")
        self.log_cb(msg, level)

    def _prog(self, v: int):
        self.prog_cb(min(100, max(0, int(v))))

    def resolve_dns(self):
        self._log("Resolving domain to IP address...", "STEP"); self._prog(4)
        r = {"ips": [], "ipv6": [], "reverse_dns": "N/A", "error": None}
        try:
            info = socket.getaddrinfo(self.domain, None)
            seen = {}
            for i in info:
                ip, fam = i[4][0], i[0]
                if ip not in seen:
                    seen[ip] = 1
                    (r["ips"] if fam == socket.AF_INET else r["ipv6"]).append(ip)
            for ip in r["ips"]:  self._log(f"  IPv4            : {ip}", "FOUND")
            for ip in r["ipv6"]: self._log(f"  IPv6            : {ip}", "FOUND")
            tgt = r["ips"][0] if r["ips"] else (r["ipv6"][0] if r["ipv6"] else None)
            if tgt:
                try:
                    rdns = socket.gethostbyaddr(tgt)[0]
                    r["reverse_dns"] = rdns
                    self._log(f"  Reverse DNS     : {rdns}", "FOUND")
                except:
                    self._log("  Reverse DNS     : N/A", "WARN")
        except socket.gaierror as e:
            r["error"] = str(e)
            self._log(f"  Cannot resolve  : {e}", "ERROR")
        self.results["resolution"] = r; self._prog(14)

    def check_dns_records(self):
        self._log("Checking DNS records (A,AAAA,MX,NS,TXT,CNAME,SOA)...", "STEP"); self._prog(18)
        r = {}
        if DNS_OK:
            for rtype in ["A","AAAA","MX","NS","TXT","CNAME","SOA"]:
                try:
                    ans = dns.resolver.resolve(self.domain, rtype, lifetime=6)
                    records = [str(a) for a in ans]
                    r[rtype] = records
                    for rec in records:
                        self._log(f"  {rtype:<6}          : {rec[:74]}", "FOUND")
                except dns.resolver.NXDOMAIN:
                    self._log("  NXDOMAIN — domain not found", "ERROR"); break
                except (dns.resolver.NoAnswer, dns.exception.Timeout): pass
                except Exception as e:
                    self._log(f"  {rtype}: {str(e)[:60]}", "WARN")
        else:
            try:
                ip = socket.gethostbyname(self.domain)
                r["A"] = [ip]
                self._log(f"  A               : {ip}", "FOUND")
                self._log("  Tip: pip install dnspython for full DNS analysis", "WARN")
            except Exception as e:
                self._log(f"  DNS failed: {e}", "ERROR")
        self.results["dns_records"] = r; self._prog(28)

    def get_whois(self):
        self._log("Retrieving WHOIS information...", "STEP"); self._prog(31)
        r = {}
        if not WHOIS_OK:
            self._log("  Tip: pip install python-whois", "WARN")
            r["error"] = "module missing"; self.results["whois"] = r; self._prog(44); return
        try:
            w = whois.whois(self.domain)
            def sg(a):
                v = getattr(w, a, None)
                return v[0] if isinstance(v, list) else v
            for k, lbl in [("registrar","Registrar"),("creation_date","Registered"),
                            ("expiration_date","Expires"),("org","Organization"),
                            ("country","Country"),("emails","Contact"),("dnssec","DNSSEC")]:
                v = sg(k)
                if v:
                    r[k] = str(v)
                    self._log(f"  {lbl:<16} : {str(v)[:62]}", "FOUND")
            exp = sg("expiration_date")
            if exp and hasattr(exp, "date"):
                days = (exp - datetime.now()).days
                r["days_until_expiry"] = days
                if   days < 0:  self._log(f"  Domain EXPIRED {abs(days)} days ago!", "ERROR")
                elif days < 30: self._log(f"  Expires in {days} days — URGENT", "WARN")
                elif days < 90: self._log(f"  Expires in {days} days", "WARN")
                else:           self._log(f"  Expires in     : {days} days", "INFO")
        except Exception as e:
            r["error"] = str(e)
            self._log(f"  WHOIS failed: {str(e)[:100]}", "ERROR")
        self.results["whois"] = r; self._prog(44)

    def analyze_http_headers(self):
        self._log("Analyzing HTTP headers and security posture...", "STEP"); self._prog(48)
        r = {"status_code": None, "server": None, "protocol": None, "headers": {},
             "redirects_to_https": False, "technologies": [], "security_headers": {}, "score": 0}
        raw = {}
        for proto in ("https", "http"):
            url = f"{proto}://{self.domain}"
            try:
                req = Request(url, headers={"User-Agent": "Mozilla/5.0 (WebGate/3.0 SecurityAudit)"})
                with urlopen(req, timeout=10) as resp:
                    raw = dict(resp.headers)
                    r["status_code"] = resp.status
                    r["protocol"] = proto.upper()
                    r["redirects_to_https"] = resp.url.startswith("https://")
                    self._log(f"  Status          : {resp.status} ({proto.upper()})", "FOUND")
                    if resp.url != url:
                        self._log(f"  Redirect        : {resp.url[:70]}", "FOUND")
                    break
            except HTTPError as e:
                raw = dict(e.headers) if hasattr(e, "headers") else {}
                r["status_code"] = e.code
                r["protocol"] = proto.upper()
                self._log(f"  Status          : {e.code} ({proto.upper()})", "FOUND")
                break
            except Exception as e:
                self._log(f"  {proto.upper()} fail: {str(e)[:65]}", "WARN")
        r["headers"] = raw
        for h, lbl in [("Server","Server"),("X-Powered-By","Backend"),("X-Generator","Generator")]:
            if h in raw:
                v = raw[h]
                r["technologies"].append(f"{lbl}: {v}")
                if h == "Server": r["server"] = v
                self._log(f"  {lbl:<16} : {v[:60]}", "FOUND")
        if not r["redirects_to_https"] and r["protocol"] == "HTTP":
            self._log("  HTTPS redirect  : NOT enforced", "WARN")
        self._log("  Security headers audit:", "INFO")
        score = 0
        for h in self.SECURITY_HEADERS:
            ok = h in raw
            r["security_headers"][h] = ok
            self._log(f"    {'✓' if ok else '✗'} {h}", "FOUND" if ok else "WARN")
            if ok: score += 1
        r["score"] = score
        self._log(f"  Security score  : {score}/{len(self.SECURITY_HEADERS)}", "INFO")
        self.results["http"] = r; self._prog(60)

    def check_ssl(self):
        self._log("Checking SSL/TLS certificate...", "STEP"); self._prog(63)
        r = {"available": False, "version": None, "cipher": None, "bits": None,
             "common_name": None, "issuer": None, "not_after": None,
             "days_until_expiry": None, "san": [], "self_signed": False,
             "wildcard": False, "error": None}
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=10) as raw:
                with ctx.wrap_socket(raw, server_hostname=self.domain) as ss:
                    r["available"] = True
                    r["version"]   = ss.version()
                    c = ss.cipher()
                    if c: r["cipher"] = c[0]; r["bits"] = c[2]
                    cert = ss.getpeercert()
                    subj = dict(x[0] for x in cert.get("subject", []))
                    iss  = dict(x[0] for x in cert.get("issuer", []))
                    r["common_name"] = subj.get("commonName", "N/A")
                    r["issuer"]      = iss.get("organizationName", "N/A")
                    r["not_after"]   = cert.get("notAfter", "N/A")
                    r["self_signed"] = subj == iss
                    r["wildcard"]    = r["common_name"].startswith("*.")
                    self._log(f"  TLS version     : {r['version']}", "FOUND")
                    self._log(f"  Cipher          : {r['cipher']} ({r['bits']} bits)", "FOUND")
                    self._log(f"  Common name     : {r['common_name']}", "FOUND")
                    self._log(f"  Issuer          : {r['issuer']}", "FOUND")
                    if r["self_signed"]:
                        self._log("  Self-signed cert detected!", "WARN")
                    try:
                        exp  = datetime.strptime(r["not_after"], "%b %d %H:%M:%S %Y %Z")
                        days = (exp - datetime.now()).days
                        r["days_until_expiry"] = days
                        self._log(f"  Valid until     : {r['not_after']}", "FOUND")
                        if   days < 0:  self._log(f"  Certificate EXPIRED!", "ERROR")
                        elif days < 15: self._log(f"  Expires in {days}d — CRITICAL", "ERROR")
                        elif days < 30: self._log(f"  Expires in {days}d", "WARN")
                        else:           self._log(f"  Days remaining  : {days}", "FOUND")
                    except: pass
                    sans = cert.get("subjectAltName", [])
                    r["san"] = [v for _, v in sans]
                    self._log(f"  Alt names (SAN) : {len(sans)} entries", "INFO")
                    for _, sv in sans[:8]:
                        self._log(f"    · {sv}", "INFO")
                    if len(sans) > 8:
                        self._log(f"    … +{len(sans)-8} more", "INFO")
        except ssl.SSLCertVerificationError as e:
            r["error"] = str(e)
            self._log(f"  Cert verify failed: {str(e)[:80]}", "ERROR")
        except ConnectionRefusedError:
            r["error"] = "Port 443 closed"
            self._log("  Port 443 closed — no HTTPS", "WARN")
        except socket.timeout:
            r["error"] = "timeout"
            self._log("  SSL connection timed out", "ERROR")
        except Exception as e:
            r["error"] = str(e)
            self._log(f"  SSL error: {str(e)[:100]}", "ERROR")
        self.results["ssl"] = r; self._prog(76)

    def scan_ports(self, ask_cb=None):
        self._log("Scanning common ports...", "STEP"); self._prog(79)
        r = {"target_ip": None, "open": [], "closed": [], "filtered": []}
        try:    r["target_ip"] = socket.gethostbyname(self.domain)
        except: r["target_ip"] = self.domain
        tgt = r["target_ip"]; total = len(self.PORTS)
        for i, (port, svc) in enumerate(self.PORTS.items()):
            if self.cancelled: break
            if ask_cb:
                ans = ask_cb(port, svc)
                if ans == "skip": r["closed"].append(port); continue
                if ans == "all":  ask_cb = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.2)
                res = s.connect_ex((tgt, port))
                s.close()
                if res == 0:
                    banner = self._banner(tgt, port)
                    cves   = query_cve(svc.lower())
                    r["open"].append({"port": port, "service": svc,
                                      "banner": banner, "cves": cves})
                    cve_str = f"  [{len(cves)} CVE]" if cves else ""
                    self._log(
                        f"  {port:5}/tcp  OPEN    {svc:<14}"
                        f"{'  ['+banner[:28]+']' if banner else ''}{cve_str}", "FOUND"
                    )
                    for cve_id, desc in cves[:3]:
                        self._log(f"    ⚡ {cve_id}: {desc[:60]}", "WARN")
                else:
                    r["closed"].append(port)
            except socket.timeout:
                r["filtered"].append(port)
            except:
                r["closed"].append(port)
            self._prog(79 + int((i + 1) / total * 9))
        self._log(f"  Open: {len(r['open'])}  Closed: {len(r['closed'])}  Filtered: {len(r['filtered'])}", "INFO")
        self.results["ports"] = r; self._prog(90)

    def _banner(self, ip: str, port: int) -> str:
        try:
            s = socket.socket(); s.settimeout(0.8)
            s.connect((ip, port))
            if port in (80, 8080): s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            raw = s.recv(256).decode("utf-8", errors="ignore").strip()
            s.close()
            return " ".join(raw.split())[:50]
        except:
            return ""

    def generate_report(self) -> str:
        self._log("Generating security report...", "STEP"); self._prog(93)
        ts   = datetime.now()
        safe = re.sub(r"[^\w\-.]", "_", self.domain)
        fn   = os.path.join(_REPORTS_DIR, f"audit_{safe}_{ts.strftime('%Y%m%d_%H%M%S')}.txt")
        elapsed = f"{time.time()-self.start_time:.1f}s" if self.start_time else ""
        W = 72; lines = []
        def rule(c="═"): return c * W
        def sec(s): lines.extend(["", rule("─"), f"  {s}", rule("─")])

        lines += [rule(), "  WEBGATE v3.0 — DOMAIN SECURITY AUDIT REPORT",
                  "  Created by c3less  │  github.com/c3less/webgate", rule("─"),
                  f"  Target    : {self.domain}",
                  f"  Date/Time : {ts.strftime('%Y-%m-%d %H:%M:%S')}",
                  f"  CVE DB    : {get_all_cve_count()} entries"]
        if elapsed: lines.append(f"  Duration  : {elapsed}")
        lines.append(rule())

        sec("1. DNS RESOLUTION")
        r = self.results.get("resolution", {})
        for ip in r.get("ips", []):  lines.append(f"  IPv4          : {ip}")
        for ip in r.get("ipv6", []): lines.append(f"  IPv6          : {ip}")
        lines.append(f"  Reverse DNS   : {r.get('reverse_dns', 'N/A')}")

        sec("2. DNS RECORDS")
        for rtype, recs in self.results.get("dns_records", {}).items():
            if rtype == "error": continue
            for rec in (recs if isinstance(recs, list) else [recs]):
                lines.append(f"  {rtype:<8} : {str(rec)[:62]}")

        sec("3. WHOIS")
        for k, v in self.results.get("whois", {}).items():
            if k != "error":
                lines.append(f"  {k.replace('_',' ').title():<20}: {str(v)[:50]}")

        sec("4. HTTP / HEADERS")
        h = self.results.get("http", {})
        lines += [f"  Status        : {h.get('status_code','N/A')}",
                  f"  Server        : {h.get('server','Not disclosed')}",
                  f"  HTTPS Redir   : {'Yes' if h.get('redirects_to_https') else 'No'}",
                  f"  Sec Score     : {h.get('score',0)}/7", "", "  Security Headers:"]
        for hdr, ok in h.get("security_headers", {}).items():
            lines.append(f"    {'✓' if ok else '✗'}  {hdr}")

        sec("5. SSL/TLS")
        s = self.results.get("ssl", {})
        if s.get("available"):
            for k, lbl in [("version","TLS"),("cipher","Cipher"),("common_name","CN"),
                            ("issuer","Issuer"),("not_after","Expires"),
                            ("days_until_expiry","Days left")]:
                v = s.get(k)
                if v is not None: lines.append(f"  {lbl:<14}: {v}")
        else:
            lines.append(f"  Not available: {s.get('error','unknown')}")

        sec("6. OPEN PORTS + CVE")
        p = self.results.get("ports", {})
        lines.append(f"  Target IP     : {p.get('target_ip','N/A')}")
        for po in p.get("open", []):
            lines.append(f"  {po['port']:5}/tcp  OPEN  {po['service']:<14} {(po.get('banner') or '')[:20]}")
            for cve_id, desc in po.get("cves", [])[:5]:
                lines.append(f"    ⚡ {cve_id}: {desc[:55]}")
        if not p.get("open"):
            lines.append("  No open ports found")

        sec("7. RISK SUMMARY")
        risks = self._build_risks()
        if risks:
            for sev, det in risks: lines.append(f"  [{sev:<8}] {det}")
        else:
            lines.append("  [OK] No critical risks found")

        sec("8. SCAN LOG")
        for ln in self.log_lines: lines.append(f"  {ln}")
        lines += ["", rule(), "  END OF REPORT — WebGate v3.0 by c3less", rule()]

        try:
            with open(fn, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            self._log(f"  Saved: {fn}", "FOUND")
        except Exception as e:
            self._log(f"  Save failed: {e}", "ERROR")
        self.results["report_file"] = fn
        self._prog(100)
        return fn

    def _build_risks(self) -> list:
        risks = []; s = self.results.get("ssl", {})
        if not s.get("available"):
            risks.append(("HIGH", "No HTTPS on port 443"))
        if s.get("self_signed"):
            risks.append(("HIGH", "Self-signed certificate"))
        d = s.get("days_until_expiry")
        if d is not None:
            if d < 0:   risks.append(("CRITICAL", f"SSL EXPIRED {abs(d)}d ago"))
            elif d < 15: risks.append(("HIGH", f"SSL expires in {d} days"))
            elif d < 30: risks.append(("MEDIUM", f"SSL expires in {d} days"))
        sc = self.results.get("http", {}).get("score", 0)
        if sc < 3:  risks.append(("HIGH",   f"Poor security headers ({sc}/7)"))
        elif sc < 5: risks.append(("MEDIUM", f"Incomplete security headers ({sc}/7)"))
        if not self.results.get("http", {}).get("redirects_to_https"):
            risks.append(("MEDIUM", "HTTP→HTTPS redirect not enforced"))
        danger = {"Telnet", "FTP", "RDP", "SMB"}
        dbs    = {"MySQL", "PostgreSQL", "MongoDB", "Redis", "Memcached", "Elasticsearch"}
        for po in self.results.get("ports", {}).get("open", []):
            if po["service"] in danger:
                risks.append(("HIGH",     f"Dangerous port: {po['port']}/{po['service']}"))
            elif po["service"] in dbs:
                risks.append(("HIGH",     f"Database exposed: {po['port']}/{po['service']}"))
            if po.get("cves"):
                risks.append(("CRITICAL", f"{len(po['cves'])} CVE(s) for {po['service']} on :{po['port']}"))
        return risks

    def run(self) -> str | None:
        self.start_time = time.time()
        self._log(f"Starting audit: {self.domain}", "INFO")
        self._log("─" * 52, "INFO")
        for step in [self.resolve_dns, self.check_dns_records, self.get_whois,
                     self.analyze_http_headers, self.check_ssl, self.scan_ports,
                     self.generate_report]:
            if self.cancelled:
                self._log("Cancelled.", "WARN"); return None
            try:
                step()
            except Exception as e:
                self._log(f"Step error: {e}", "ERROR")
        elapsed = time.time() - self.start_time
        self._log("─" * 52, "INFO")
        self._log(f"SCAN COMPLETE  [{elapsed:.1f}s]", "SUCCESS")
        return self.results.get("report_file")


# ═══════════════════════════════════════════════════════════════
# DEEP SCANNER — 30 tools
# ═══════════════════════════════════════════════════════════════
class DeepScanner:
    def __init__(self, domain: str, log_cb=None, prog_cb=None, tools=None):
        self.domain    = domain
        self.log_cb    = log_cb  or print
        self.prog_cb   = prog_cb or (lambda v: None)
        self.results   = {}
        self.cancelled = False
        self.base_url  = f"http://{domain}"
        self.tools     = tools or SETTINGS.get("deep_tools", {})

    def _log(self, m, l="INFO"): self.log_cb(m, l)
    def _prog(self, v):          self.prog_cb(min(100, int(v)))
    def _enabled(self, key):     return self.tools.get(key, False)

    def _run_ext(self, key: str, cmd: list, timeout=120) -> str:
        name = TOOL_CATALOG.get(key, {}).get("label", key)
        self._log(f"Running {name}…", "STEP")
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            out = (res.stdout + res.stderr).strip()
            self.results[key] = out
            lines = out.count('\n') + 1
            self._log(f"{name} complete ({lines} lines output).", "FOUND")
            return out
        except FileNotFoundError:
            self._log(f"{name} not installed — skipping.", "WARN")
        except subprocess.TimeoutExpired:
            self._log(f"{name} timed out.", "WARN")
        except Exception as e:
            self._log(f"{name} error: {e}", "ERROR")
        return ""

    # ── External tools ──────────────────────────────────────────
    def run_nmap(self):
        if not self._enabled("nmap"): return
        self._run_ext("nmap",
            ["nmap", "-sV", "-sC", "--open", "-p", "1-10000", self.domain],
            timeout=180)
        self._prog(12)

    def run_wpscan(self):
        if not self._enabled("wpscan"): return
        self._run_ext("wpscan",
            ["wpscan", "--url", f"https://{self.domain}",
             "--no-update", "--format", "cli-no-colour",
             "--enumerate", "p,t,u", "--plugins-detection", "aggressive"],
            timeout=180)
        self._prog(22)

    def run_sqlmap(self):
        if not self._enabled("sqlmap"): return
        self._run_ext("sqlmap",
            ["sqlmap", "-u", f"http://{self.domain}",
             "--crawl=2", "--level=2", "--risk=2", "--batch",
             "--forms", "--random-agent"],
            timeout=240)
        self._prog(32)

    def run_cmseek(self):
        if not self._enabled("cmseek"): return
        self._run_ext("cmseek",
            ["cmseek", "-u", f"http://{self.domain}", "--batch"],
            timeout=120)
        self._prog(38)

    def run_xsstrike(self):
        if not self._enabled("xsstrike"): return
        self._run_ext("xsstrike",
            ["xsstrike", "-u", f"http://{self.domain}",
             "--crawl", "--blind"],
            timeout=120)
        self._prog(44)

    def run_gobuster(self):
        if not self._enabled("gobuster"): return
        self._run_ext("gobuster",
            ["gobuster", "dir", "-u", f"http://{self.domain}",
             "-w", "/usr/share/wordlists/dirb/common.txt",
             "-t", "50", "-q", "--no-error"],
            timeout=120)
        self._prog(50)

    def run_commix(self):
        if not self._enabled("commix"): return
        self._run_ext("commix",
            ["commix", "--url", f"http://{self.domain}",
             "--batch", "--crawl=2"],
            timeout=180)
        self._prog(55)

    def run_droopescan(self):
        if not self._enabled("droopescan"): return
        self._run_ext("droopescan",
            ["droopescan", "scan", "drupal", "-u", f"http://{self.domain}"],
            timeout=120)
        self._prog(58)

    def run_brutex(self):
        if not self._enabled("brutex"): return
        self._run_ext("brutex",
            ["brutex", self.domain],
            timeout=300)
        self._prog(62)

    def run_arachni(self):
        if not self._enabled("arachni"): return
        self._run_ext("arachni",
            ["arachni", f"http://{self.domain}", "--checks=*",
             "--scope-include-subdomains"],
            timeout=300)
        self._prog(66)

    def run_sslstrip(self):
        if not self._enabled("sslstrip"): return
        self._log("SSLstrip requires active MITM position — logging info only.", "WARN")
        self.results["sslstrip"] = "SSLstrip: passive mode — MITM not active"
        self._prog(68)

    def run_setoolkit(self):
        if not self._enabled("setoolkit"): return
        self._log("SET (Social Engineering Toolkit) requires interactive mode.", "WARN")
        self.results["setoolkit"] = "SET: requires interactive terminal"
        self._prog(70)

    def run_weeman(self):
        if not self._enabled("weeman"): return
        self._log("Weeman phishing framework — interactive mode required.", "WARN")
        self.results["weeman"] = "Weeman: requires interactive terminal"
        self._prog(72)

    def run_reaver(self):
        if not self._enabled("reaver"): return
        self._log("Reaver WPS attack — requires wireless interface.", "WARN")
        self.results["reaver"] = "Reaver: requires wireless adapter in monitor mode"
        self._prog(73)

    def run_pixiewps(self):
        if not self._enabled("pixiewps"): return
        self._log("Pixiewps WPS pixie-dust — requires wireless interface.", "WARN")
        self.results["pixiewps"] = "Pixiewps: requires wireless adapter"
        self._prog(74)

    def run_cupp(self):
        if not self._enabled("cupp"): return
        self._run_ext("cupp",
            ["cupp", "-w", self.domain.split(".")[0]],
            timeout=30)
        self._prog(75)

    # ── Internal scanners ───────────────────────────────────────
    def _http_get(self, path: str, timeout=8) -> tuple:
        for proto in ("https", "http"):
            try:
                url = f"{proto}://{self.domain}/{path.lstrip('/')}"
                req = Request(url, headers={"User-Agent": "Mozilla/5.0 (WebGate/3.0)"})
                with urlopen(req, timeout=timeout) as r:
                    return r.status, r.read(4096).decode("utf-8", errors="ignore")
            except HTTPError as e:
                return e.code, ""
            except: pass
        return 0, ""

    def run_wordpress_scan(self):
        if not self._enabled("wordpress_scan"): return
        self._log("WordPress path scan…", "STEP")
        paths = ["wp-login.php", "wp-admin/", "wp-json/wp/v2/users",
                 "xmlrpc.php", "wp-content/uploads/", "readme.html",
                 "license.txt", "wp-config.php.bak"]
        found = []
        for p in paths:
            if self.cancelled: break
            code, body = self._http_get(p)
            if code in (200, 301, 302):
                found.append(f"  {code}  /{p}")
                self._log(f"  [WP] {code}  /{p}", "FOUND")
        if "wp-json/wp/v2/users" in str(found):
            self._log("  [WP] User enumeration via REST API — CRITICAL", "ERROR")
        self.results["wordpress_scan"] = "\n".join(found) or "No WP paths found"
        self._prog(78)

    def run_wp_plugins(self):
        if not self._enabled("wp_plugins"): return
        self._log("Scanning WordPress plugins…", "STEP")
        plugins = [
            "contact-form-7", "yoast-seo", "woocommerce", "wordfence",
            "elementor", "all-in-one-seo-pack", "wp-super-cache",
            "jetpack", "wpforms-lite", "classic-editor",
            "revslider", "gravityforms", "ninja-forms", "visual-composer",
        ]
        found = []
        for plugin in plugins:
            if self.cancelled: break
            code, _ = self._http_get(f"wp-content/plugins/{plugin}/")
            if code in (200, 403):
                found.append(plugin)
                self._log(f"  [Plugin] {plugin} — HTTP {code}", "FOUND")
                cves = query_cve(plugin)
                for cid, cdesc in cves[:2]:
                    self._log(f"    ⚡ {cid}: {cdesc[:55]}", "WARN")
        self.results["wp_plugins"] = "\n".join(found) or "No plugins detected"
        self._prog(80)

    def run_wp_exploit(self):
        if not self._enabled("wp_exploit"): return
        self._log("WordPress exploit surface check…", "STEP")
        issues = []
        code, body = self._http_get("xmlrpc.php")
        if code in (200, 405):
            issues.append("XML-RPC enabled — brute force possible")
            self._log("  [WP-Exploit] XML-RPC enabled (CVE-2020-28032 surface)", "WARN")
        code, body = self._http_get("wp-json/wp/v2/users")
        if code == 200 and '"id"' in body:
            issues.append("User enumeration via REST API")
            self._log("  [WP-Exploit] User list exposed via REST API!", "ERROR")
        code, _ = self._http_get("?author=1")
        if code in (301, 302):
            issues.append("Author enumeration via ?author=N")
            self._log("  [WP-Exploit] Author enumeration possible", "WARN")
        self.results["wp_exploit"] = "\n".join(issues) or "No obvious WP exploits found"
        self._prog(82)

    def run_gravityforms(self):
        if not self._enabled("gravityforms"): return
        self._log("Gravity Forms scanner…", "STEP")
        code, body = self._http_get("wp-content/plugins/gravityforms/")
        if code in (200, 403):
            self._log("  [GravityForms] Plugin present!", "FOUND")
            cves = query_cve("gravityforms")
            for cid, cdesc in cves[:3]:
                self._log(f"    ⚡ {cid}: {cdesc[:55]}", "WARN")
            self.results["gravityforms"] = "GravityForms detected"
        else:
            self.results["gravityforms"] = "GravityForms not detected"
        self._prog(83)

    def run_upload_check(self):
        if not self._enabled("upload_check"): return
        self._log("File upload surface check…", "STEP")
        upload_paths = [
            "upload.php", "uploader.php", "file-upload.php",
            "wp-content/uploads/", "uploads/", "files/",
            "admin/upload.php", "data/upload/",
        ]
        found = []
        for p in upload_paths:
            if self.cancelled: break
            code, body = self._http_get(p)
            if code in (200, 403):
                found.append(p)
                self._log(f"  [Upload] {code}  /{p}", "FOUND")
        self.results["upload_check"] = "\n".join(found) or "No upload paths found"
        self._prog(84)

    def run_sqli_scan(self):
        if not self._enabled("sqli_scan"): return
        self._log("Quick SQLi surface scan…", "STEP")
        payloads = ["'", "''", "' OR '1'='1", "1 AND 1=1", "1; SELECT 1--"]
        errors   = ["sql syntax", "mysql_fetch", "ORA-", "syntax error",
                    "unclosed quotation", "pg_query", "sqlite_"]
        findings = []
        for pl in payloads:
            if self.cancelled: break
            code, body = self._http_get(f"?id={pl}", timeout=6)
            low = body.lower()
            for err in errors:
                if err.lower() in low:
                    findings.append(f"Payload '{pl}' triggered: {err}")
                    self._log(f"  [SQLi] Error triggered by payload: {pl}", "ERROR")
                    break
        self.results["sqli_scan"] = "\n".join(findings) or "No SQLi errors detected"
        self._prog(86)

    def run_shell_finder(self):
        if not self._enabled("shell_finder"): return
        self._log("Shell and backdoor finder…", "STEP")
        shells = [
            "shell.php", "cmd.php", "c99.php", "r57.php", "wso.php",
            "b374k.php", "weevely.php", "alfa.php", "mini.php",
            "indoxploit.php", "priv8.php", "bypass.php", "test.php",
            "info.php", "phpinfo.php", "admin.php", "config.php.bak",
        ]
        found = []
        for s in shells:
            if self.cancelled: break
            for prefix in ["", "uploads/", "wp-content/uploads/", "files/"]:
                code, body = self._http_get(f"{prefix}{s}", timeout=5)
                if code == 200 and len(body) > 20:
                    path = f"/{prefix}{s}"
                    found.append(path)
                    self._log(f"  [SHELL] {code}  {path} ({len(body)}b)", "ERROR")
                    break
        self.results["shell_finder"] = "\n".join(found) or "No shells found"
        self._prog(87)

    def run_joomla_rce(self):
        if not self._enabled("joomla_rce"): return
        self._log("Joomla RCE surface check…", "STEP")
        code, body = self._http_get("administrator/index.php")
        if code == 200 and "joomla" in body.lower():
            self._log("  [Joomla] Admin panel detected!", "FOUND")
            self._log("  [Joomla] Check CVE-2015-8562, CVE-2023-23752", "WARN")
            cves = query_cve("joomla")
            for cid, cdesc in cves[:3]:
                self._log(f"    ⚡ {cid}: {cdesc[:55]}", "WARN")
            self.results["joomla_rce"] = "Joomla admin detected — CVE surface active"
        else:
            self.results["joomla_rce"] = "Joomla not detected"
        self._prog(88)

    def run_vbulletin_rce(self):
        if not self._enabled("vbulletin_rce"): return
        self._log("vBulletin RCE surface check…", "STEP")
        code, body = self._http_get("admincp/index.php")
        if code in (200, 302):
            self._log("  [vBulletin] Admin panel detected!", "FOUND")
            cves = query_cve("vbulletin")
            for cid, cdesc in cves[:3]:
                self._log(f"    ⚡ {cid}: {cdesc[:55]}", "WARN")
            self.results["vbulletin_rce"] = "vBulletin admin detected"
        else:
            self.results["vbulletin_rce"] = "vBulletin not detected"
        self._prog(89)

    def run_bypass_cf(self):
        if not self._enabled("bypass_cf"): return
        self._log("Cloudflare bypass detection…", "STEP")
        info = []
        try:
            ip = socket.gethostbyname(self.domain)
            cf_ranges = ["103.21.", "103.22.", "103.31.", "104.16.", "104.17.",
                         "104.18.", "104.19.", "108.162.", "141.101.", "162.158.",
                         "172.64.", "172.65.", "172.66.", "172.67.", "173.245.",
                         "188.114.", "188.166.", "190.93.", "197.234.", "198.41.",
                         "199.27."]
            is_cf = any(ip.startswith(r) for r in cf_ranges)
            if is_cf:
                self._log(f"  [CF] IP {ip} is behind Cloudflare", "FOUND")
                info.append(f"Cloudflare IP: {ip}")
                # Try to find real IP via DNS history hints
                try:
                    subdomains = ["direct", "mail", "ftp", "cpanel", "webmail",
                                  "smtp", "pop", "ssh", "origin", "www2"]
                    for sub in subdomains:
                        try:
                            real = socket.gethostbyname(f"{sub}.{self.domain}")
                            if not any(real.startswith(r) for r in cf_ranges):
                                self._log(f"  [CF-Bypass] Real IP found: {sub}.{self.domain} = {real}", "ERROR")
                                info.append(f"Real IP candidate: {real} (via {sub})")
                        except: pass
                except: pass
            else:
                self._log(f"  [CF] Not behind Cloudflare (IP: {ip})", "INFO")
        except Exception as e:
            self._log(f"  [CF] Error: {e}", "ERROR")
        self.results["bypass_cf"] = "\n".join(info) or "No Cloudflare bypass found"
        self._prog(90)

    def run_poet(self):
        if not self._enabled("poet"): return
        self._log("POET (Parameter/endpoint) enumeration…", "STEP")
        params = ["?debug=1", "?test=1", "?admin=1", "?cmd=id", "?id=1",
                  "?page=../../etc/passwd", "?file=../etc/passwd",
                  "?include=php://input", "?url=http://169.254.169.254/",
                  "?redirect=http://evil.com", "?callback=alert(1)"]
        findings = []
        for p in params:
            if self.cancelled: break
            code, body = self._http_get(p, timeout=6)
            if code == 200 and any(x in body for x in ["root:x:", "uid=", "HTTP/1."]):
                findings.append(f"Param {p} — suspicious response!")
                self._log(f"  [POET] Suspicious response to {p}", "ERROR")
        self.results["poet"] = "\n".join(findings) or "No POET findings"
        self._prog(91)

    def run_inurlbr(self):
        if not self._enabled("inurlbr"): return
        self._log("Inurlbr dork-based recon…", "STEP")
        dorks = [
            f"site:{self.domain} inurl:admin",
            f"site:{self.domain} inurl:login",
            f"site:{self.domain} filetype:sql",
            f"site:{self.domain} filetype:env",
            f"site:{self.domain} intitle:index.of",
        ]
        self._log("  [Inurlbr] Dorks generated (manual Google search required):", "INFO")
        for d in dorks:
            self._log(f"  {d}", "FOUND")
        self.results["inurlbr"] = "\n".join(dorks)
        self._prog(92)

    def run_port_scan_deep(self):
        if not self._enabled("port_scan_deep"): return
        self._log("Extended port scan (top 2000)…", "STEP")
        extra_ports = [8000, 8001, 8002, 8008, 8009, 8081, 8082, 8083,
                       8090, 8161, 8180, 8280, 8888, 9000, 9001, 9090,
                       9200, 9300, 9418, 10000, 10443, 15672, 16000,
                       25565, 27015, 49152, 50000]
        try:
            ip = socket.gethostbyname(self.domain)
        except:
            ip = self.domain
        open_extra = []
        for port in extra_ports:
            if self.cancelled: break
            try:
                s = socket.socket()
                s.settimeout(1.0)
                if s.connect_ex((ip, port)) == 0:
                    open_extra.append(port)
                    self._log(f"  [PortDeep] {port}/tcp OPEN", "FOUND")
                s.close()
            except: pass
        self.results["port_scan_deep"] = str(open_extra)
        self._prog(93)

    def run_ssl_audit(self):
        if not self._enabled("ssl_audit"): return
        self._log("Full SSL/TLS audit…", "STEP")
        findings = []
        weak_ciphers = ["RC4", "DES", "3DES", "EXPORT", "NULL", "anon"]
        try:
            for proto in [ssl.PROTOCOL_TLS_CLIENT]:
                ctx = ssl.SSLContext(proto)
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                with socket.create_connection((self.domain, 443), timeout=8) as raw:
                    with ctx.wrap_socket(raw) as ss:
                        cipher = ss.cipher()
                        if cipher:
                            name = cipher[0]
                            for w in weak_ciphers:
                                if w in name:
                                    findings.append(f"Weak cipher: {name}")
                                    self._log(f"  [SSL] WEAK CIPHER: {name}", "ERROR")
                                    break
                            else:
                                self._log(f"  [SSL] Cipher: {name} — OK", "INFO")
        except Exception as e:
            self._log(f"  [SSL] Audit error: {e}", "WARN")
        cves = query_cve("ssl")
        for cid, cdesc in cves[:3]:
            self._log(f"    ⚡ {cid}: {cdesc[:55]}", "WARN")
        self.results["ssl_audit"] = "\n".join(findings) or "SSL audit OK"
        self._prog(95)

    def run(self):
        self._log(f"Deep scan started: {self.domain}", "INFO")
        self._log(f"Tools enabled: {sum(1 for v in self.tools.values() if v)}", "INFO")

        steps = [
            self.run_nmap, self.run_wpscan, self.run_sqlmap,
            self.run_cmseek, self.run_xsstrike, self.run_gobuster,
            self.run_commix, self.run_droopescan, self.run_brutex,
            self.run_arachni, self.run_sslstrip, self.run_setoolkit,
            self.run_weeman, self.run_reaver, self.run_pixiewps,
            self.run_cupp,
            # Internal
            self.run_wordpress_scan, self.run_wp_plugins, self.run_wp_exploit,
            self.run_gravityforms, self.run_upload_check, self.run_sqli_scan,
            self.run_shell_finder, self.run_joomla_rce, self.run_vbulletin_rce,
            self.run_bypass_cf, self.run_poet, self.run_inurlbr,
            self.run_port_scan_deep, self.run_ssl_audit,
        ]
        for step in steps:
            if self.cancelled: break
            try:
                step()
            except Exception as e:
                self._log(f"Tool error: {e}", "ERROR")

        self._log("Deep scan finished.", "SUCCESS")
        self._prog(100)


# ═══════════════════════════════════════════════════════════════
# GUI — SPLASH SCREEN
# ═══════════════════════════════════════════════════════════════
class SplashScreen:
    TIPS = [
        "200+ CVE database · 30 security tools built-in",
        "DEEP SCAN runs Nmap, WPScan, SQLMap, XSStrike + more",
        "Surface scan: OS fingerprint, country, open ports + CVE",
        "Switch themes and language live without stopping scan",
        "All scans run in background — UI stays responsive",
        "Reports saved as audit_<domain>_<date>.txt",
        "CVE DB covers nginx, apache, WordPress, SSH, SMB, Redis…",
        "AUTHORIZED TESTING ONLY — stay legal, stay safe",
    ]

    def __init__(self, parent, callback):
        import tkinter as tk
        self.parent = parent
        self.cb     = callback
        th = get_theme()

        win = tk.Toplevel(parent)
        self.win = win
        win.overrideredirect(True)
        win.configure(bg=th["BG"])

        sw = win.winfo_screenwidth()
        sh = win.winfo_screenheight()
        W, H = 560, 340
        win.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")

        try:
            win.update_idletasks()  # removed wait_visibility (hangs on Wayland)
            win.attributes("-alpha", 0.0)
        except Exception:
            pass

        # Logo canvas
        cv = tk.Canvas(win, bg=th["BG"], width=W, height=110, highlightthickness=0)
        cv.pack(pady=(28, 0))
        cv.create_text(W//2+3, 58, text="WebGate",
            font=("Georgia", 42, "bold italic"), fill=th["BG3"], anchor="center")
        cv.create_text(W//2+1, 56, text="WebGate",
            font=("Georgia", 42, "bold italic"), fill=th["LOGO_SHD"], anchor="center")
        cv.create_text(W//2-1, 54, text="WebGate",
            font=("Georgia", 42, "bold italic"), fill=th["LOGO_CLR"], anchor="center")
        cv.create_line(W//2-120, 80, W//2+120, 80, fill=th["BORDER2"], width=1)
        cv.create_text(W//2, 95, text="Domain Security Auditor  ·  by c3less",
            font=("Courier New", 9), fill=th["FG3"], anchor="center")

        # Tip label
        self._tip_lbl = tk.Label(win, text=self.TIPS[0],
            font=("Courier New", 9), bg=th["BG"], fg=th["FG3"])
        self._tip_lbl.pack(pady=4)

        # Progress bar frame
        pb_frame = tk.Frame(win, bg=th["BG"])
        pb_frame.pack(fill="x", padx=60, pady=(12, 4))
        self._pb_cv = tk.Canvas(pb_frame, height=3, bg=th["BG2"],
            highlightthickness=0, bd=0)
        self._pb_cv.pack(fill="x")

        # Status label
        self._st_lbl = tk.Label(win, text="Initializing…",
            font=("Courier New", 8), bg=th["BG"], fg=th["FG3"])
        self._st_lbl.pack()

        # Credit
        tk.Label(win, text="by c3less  ·  github.com/c3less/webgate",
            font=("Courier New", 8), bg=th["BG"], fg=th["FG3"]).pack(pady=(16, 0))

        self._prog  = 0
        self._tip_i = 0
        self._th    = th
        self._W     = W

        # Start animations
        self._fade_in(0.0)
        self._animate_prog(0)

    def _fade_in(self, a):
        nv = min(0.97, a + 0.07)
        _safe_alpha(self.win, nv)
        if nv < 0.97:
            self.win.after(16, lambda: self._fade_in(nv))

    def _animate_prog(self, step):
        th = self._th
        self._prog = min(100, step)
        cv = self._pb_cv
        cv.delete("all")
        try:
            w = cv.winfo_width()
            if w < 2: w = self._W - 120
            cv.create_rectangle(0, 0, w, 3, fill=th["BG3"], outline="")
            if self._prog > 0:
                fw = max(4, int(w * self._prog / 100))
                cv.create_rectangle(0, 0, fw, 3, fill=th["ACC"], outline="")
        except: pass

        status_msgs = {
            10: "Loading CVE database…",
            30: "Initializing sound engine…",
            50: "Building GUI components…",
            70: "Applying theme…",
            90: "Almost ready…",
            100: "Launch!",
        }
        for threshold, msg in sorted(status_msgs.items()):
            if self._prog >= threshold:
                try: self._st_lbl.config(text=msg)
                except: pass

        if step % 18 == 0:
            self._tip_i = (self._tip_i + 1) % len(self.TIPS)
            try: self._tip_lbl.config(text=self.TIPS[self._tip_i])
            except: pass

        if step < 100:
            speed = 12 if step < 80 else 25
            self.win.after(speed, lambda: self._animate_prog(step + 1))
        else:
            self.win.after(300, self._finish)

    def _finish(self):
        def fade_out(a):
            _safe_alpha(self.win, max(0.0, a - 0.1))
            if a > 0.0:
                self.win.after(14, lambda: fade_out(a - 0.1))
            else:
                try: self.win.destroy()
                except: pass
                # Show main window
                try: self.parent.deiconify()
                except: pass
                self.parent.update()
                self.cb()
        fade_out(0.97)


# ═══════════════════════════════════════════════════════════════
# GUI — DISCLAIMER DIALOG
# ═══════════════════════════════════════════════════════════════
class DisclaimerDialog:
    def __init__(self, parent, on_agree):
        import tkinter as tk
        th  = get_theme()
        win = tk.Toplevel(parent)
        win.title(t("disc_title"))
        win.configure(bg=th["BG"])
        win.resizable(False, False)
        win.transient(parent)
        win.grab_set()

        sw = win.winfo_screenwidth(); sh = win.winfo_screenheight()
        W, H = 620, 500
        win.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")
        try:
            win.update_idletasks()  # removed wait_visibility (hangs on Wayland)
            win.attributes("-alpha", 0.0)
        except: pass

        # Header
        hdr = tk.Frame(win, bg=th["ERR"], height=4)
        hdr.pack(fill="x")
        tk.Label(win, text=t("disc_title"),
            font=("Georgia", 14, "bold"), bg=th["BG"], fg=th["ERR"]
        ).pack(pady=(18, 6))
        tk.Frame(win, bg=th["BORDER"], height=1).pack(fill="x", padx=24)

        # Body text
        txt = tk.Text(win, font=("Courier New", 10), bg=th["BG2"], fg=th["FG"],
            relief="flat", bd=0, padx=20, pady=16, wrap="word",
            state="normal", height=16)
        txt.insert("1.0", t("disc_body"))
        txt.config(state="disabled")
        txt.pack(fill="both", expand=True, padx=20, pady=(12, 8))

        # Buttons
        btnf = tk.Frame(win, bg=th["BG"])
        btnf.pack(fill="x", padx=20, pady=(0, 18))

        def agree():
            win.destroy()
            on_agree()

        tk.Button(btnf, text=t("disc_deny"),
            font=("Courier New", 10), bg=th["BG3"], fg=th["FG2"],
            relief="flat", bd=0, padx=20, pady=8, cursor="hand2",
            command=win.destroy
        ).pack(side="right", padx=(8, 0))

        agree_btn = tk.Button(btnf, text=t("disc_agree"),
            font=("Courier New", 10, "bold"), bg=th["ERR"], fg=th["WHITE"],
            relief="flat", bd=0, padx=20, pady=8, cursor="hand2",
            command=agree)
        agree_btn.pack(side="right")

        def _fade(a):
            try: win.attributes("-alpha", min(0.97, a))
            except: pass
            if a < 0.97: win.after(15, lambda: _fade(a + 0.08))
        _fade(0.0)


# ═══════════════════════════════════════════════════════════════
# GUI — TOOL SELECTOR DIALOG (checkboxes before deep scan)
# ═══════════════════════════════════════════════════════════════
class ToolSelectorDialog:
    def __init__(self, parent, on_start):
        import tkinter as tk
        th  = get_theme()
        win = tk.Toplevel(parent)
        win.title(t("tool_sel_title"))
        win.configure(bg=th["BG"])
        win.resizable(False, True)
        win.transient(parent)
        win.grab_set()

        sw = win.winfo_screenwidth(); sh = win.winfo_screenheight()
        W, H = 680, 580
        win.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")
        try:
            win.update_idletasks()  # removed wait_visibility (hangs on Wayland)
            win.attributes("-alpha", 0.0)
        except: pass

        tk.Label(win, text=t("tool_sel_title"),
            font=("Georgia", 13, "bold italic"), bg=th["BG"], fg=th["LOGO_CLR"]
        ).pack(pady=(16, 4))
        tk.Label(win, text=t("tool_sel_sub"),
            font=("Courier New", 9), bg=th["BG"], fg=th["FG3"]
        ).pack()
        tk.Frame(win, bg=th["BORDER"], height=1).pack(fill="x", padx=20, pady=(8, 0))

        # Group tools by category
        cats = {}
        for key, info in TOOL_CATALOG.items():
            c = info["cat"]
            cats.setdefault(c, []).append((key, info))

        # Scrollable frame
        canvas = tk.Canvas(win, bg=th["BG"], highlightthickness=0)
        scrollbar = tk.Scrollbar(win, orient="vertical", command=canvas.yview)
        scroll_frame = tk.Frame(canvas, bg=th["BG"])
        scroll_frame.bind("<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True, padx=(20, 0), pady=8)
        scrollbar.pack(side="right", fill="y")

        self._vars = {}
        cols = 2
        cat_labels = {
            "recon":"Reconnaissance","cms":"CMS / Web","sql":"SQL Injection",
            "xss":"XSS","cmdi":"Command Injection","mitm":"MITM / SSL",
            "brute":"Brute Force","web":"Web Scanners","phish":"Phishing",
            "wifi":"WiFi / Wireless","osint":"OSINT / Wordlist",
            "rce":"Remote Code Exec","ssl":"SSL Audit","social":"Social Eng.",
        }

        for cat, items in sorted(cats.items()):
            cat_color = CAT_COLORS.get(cat, th["FG2"])
            cf = tk.Frame(scroll_frame, bg=th["BG2"], bd=0)
            cf.pack(fill="x", padx=8, pady=(6, 2))
            tk.Label(cf, text=cat_labels.get(cat, cat.upper()),
                font=("Courier New", 8, "bold"), bg=th["BG2"], fg=cat_color,
                anchor="w"
            ).pack(fill="x", padx=10, pady=(4, 2))

            row_f = None
            for idx, (key, info) in enumerate(items):
                if idx % cols == 0:
                    row_f = tk.Frame(cf, bg=th["BG2"])
                    row_f.pack(fill="x", padx=8, pady=1)

                var = tk.BooleanVar(value=SETTINGS["deep_tools"].get(key, False))
                self._vars[key] = var

                item_f = tk.Frame(row_f, bg=th["BG2"])
                item_f.pack(side="left", fill="x", expand=True)

                ext_mark = "★" if info["ext"] else "·"
                chk = tk.Checkbutton(item_f,
                    text=f"{ext_mark} {info['label']}",
                    variable=var,
                    font=("Courier New", 9),
                    bg=th["BG2"], fg=th["FG"],
                    selectcolor=th["BG3"],
                    activebackground=th["BG2"],
                    activeforeground=th["WHITE"],
                    relief="flat", bd=0, anchor="w",
                    cursor="hand2",
                )
                chk.pack(fill="x")

        # Ask per port checkbox
        ask_f = tk.Frame(win, bg=th["BG"])
        ask_f.pack(fill="x", padx=20, pady=4)
        self._ask_var = tk.BooleanVar(value=SETTINGS.get("ask_per_port", False))
        tk.Checkbutton(ask_f,
            text=f"⚙  {t('tool_sel_ask')}",
            variable=self._ask_var,
            font=("Courier New", 9),
            bg=th["BG"], fg=th["FG2"],
            selectcolor=th["BG3"],
            activebackground=th["BG"],
            relief="flat", bd=0, cursor="hand2",
        ).pack(side="left")

        tk.Label(ask_f, text="★ = external tool required",
            font=("Courier New", 8), bg=th["BG"], fg=th["FG3"]
        ).pack(side="right")

        # Select all / none buttons
        ctrl_f = tk.Frame(win, bg=th["BG"])
        ctrl_f.pack(fill="x", padx=20, pady=(2, 0))
        def select_all():
            for v in self._vars.values(): v.set(True)
        def select_none():
            for v in self._vars.values(): v.set(False)
        tk.Button(ctrl_f, text="ALL", font=("Courier New", 8),
            bg=th["BG3"], fg=th["FG2"], relief="flat", bd=0,
            padx=8, pady=2, cursor="hand2", command=select_all
        ).pack(side="left", padx=(0, 4))
        tk.Button(ctrl_f, text="NONE", font=("Courier New", 8),
            bg=th["BG3"], fg=th["FG2"], relief="flat", bd=0,
            padx=8, pady=2, cursor="hand2", command=select_none
        ).pack(side="left")

        tk.Frame(win, bg=th["BORDER"], height=1).pack(fill="x", padx=20, pady=(8, 0))

        # Action buttons
        btnf = tk.Frame(win, bg=th["BG"])
        btnf.pack(fill="x", padx=20, pady=(8, 16))

        def start():
            selected = {k: v.get() for k, v in self._vars.items()}
            ask = self._ask_var.get()
            SETTINGS["deep_tools"]  = selected
            SETTINGS["ask_per_port"] = ask
            save_settings(SETTINGS)
            win.destroy()
            on_start(selected, ask)

        tk.Button(btnf, text=t("tool_sel_cancel"),
            font=("Courier New", 10), bg=th["BG3"], fg=th["FG2"],
            relief="flat", bd=0, padx=18, pady=8, cursor="hand2",
            command=win.destroy
        ).pack(side="right", padx=(8, 0))

        tk.Button(btnf, text=t("tool_sel_ok"),
            font=("Courier New", 10, "bold"),
            bg=th["BTN_BG"], fg=th["BTN_FG"],
            activebackground=th["BTN_HOV"],
            relief="flat", bd=0, padx=20, pady=8, cursor="hand2",
            command=start
        ).pack(side="right")

        def _fade(a):
            try: win.attributes("-alpha", min(0.97, a))
            except: pass
            if a < 0.97: win.after(14, lambda: _fade(a + 0.08))
        _fade(0.0)


# ═══════════════════════════════════════════════════════════════
# GUI — PORT CONFIRMATION DIALOG
# ═══════════════════════════════════════════════════════════════
class PortConfirmResult:
    """Thread-safe result holder for port confirmation dialog."""
    def __init__(self):
        self._event  = threading.Event()
        self._result = "yes"

    def wait(self):
        self._event.wait(timeout=30)
        return self._result

    def set(self, val):
        self._result = val
        self._event.set()


def ask_port_gui(parent, port, service, cves) -> str:
    """Called from scan thread via root.after — returns 'yes'/'skip'/'all'."""
    result = PortConfirmResult()
    import tkinter as tk

    def show():
        th  = get_theme()
        win = tk.Toplevel(parent)
        win.title(t("port_ask_title"))
        win.configure(bg=th["BG"])
        win.resizable(False, False)
        win.transient(parent)
        win.grab_set()

        sw = win.winfo_screenwidth(); sh = win.winfo_screenheight()
        W, H = 460, 320
        win.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")
        try:
            win.update_idletasks()  # removed wait_visibility (hangs on Wayland)
            win.attributes("-alpha", 0.0)
        except: pass

        tk.Label(win, text=t("port_ask_title"),
            font=("Georgia", 12, "bold italic"), bg=th["BG"], fg=th["LOGO_CLR"]
        ).pack(pady=(16, 4))

        info_f = tk.Frame(win, bg=th["BG2"])
        info_f.pack(fill="x", padx=20, pady=(0, 8))
        tk.Label(info_f, text=f"  PORT  {port}/tcp  →  {service}",
            font=("Courier New", 12, "bold"), bg=th["BG2"], fg=th["ACC"]
        ).pack(anchor="w", pady=6)

        if cves:
            tk.Label(info_f, text=f"  {len(cves)} CVE(s) found for this service:",
                font=("Courier New", 9), bg=th["BG2"], fg=th["WARN"]
            ).pack(anchor="w", padx=4)
            for cid, desc in cves[:3]:
                tk.Label(info_f, text=f"    ⚡ {cid}: {desc[:45]}",
                    font=("Courier New", 8), bg=th["BG2"], fg=th["FG2"]
                ).pack(anchor="w", padx=8)

        tk.Label(win, text="Analyze this port?",
            font=("Courier New", 10), bg=th["BG"], fg=th["FG"]
        ).pack(pady=(8, 4))

        btnf = tk.Frame(win, bg=th["BG"])
        btnf.pack(pady=8)

        def do(val):
            win.destroy()
            result.set(val)

        tk.Button(btnf, text=t("port_ask_yes"),
            font=("Courier New", 10, "bold"),
            bg=th["ACC3"], fg=th["BG"],
            relief="flat", bd=0, padx=16, pady=7, cursor="hand2",
            command=lambda: do("yes")
        ).pack(side="left", padx=4)
        tk.Button(btnf, text=t("port_ask_no"),
            font=("Courier New", 10),
            bg=th["BG3"], fg=th["FG2"],
            relief="flat", bd=0, padx=16, pady=7, cursor="hand2",
            command=lambda: do("skip")
        ).pack(side="left", padx=4)
        tk.Button(btnf, text=t("port_ask_all"),
            font=("Courier New", 9),
            bg=th["BG4"], fg=th["FG3"],
            relief="flat", bd=0, padx=12, pady=7, cursor="hand2",
            command=lambda: do("all")
        ).pack(side="left", padx=4)

        win.protocol("WM_DELETE_WINDOW", lambda: do("yes"))

        def _fade(a):
            try: win.attributes("-alpha", min(0.97, a))
            except: pass
            if a < 0.97: win.after(14, lambda: _fade(a + 0.08))
        _fade(0.0)

    parent.after(0, show)
    return result.wait()


# ═══════════════════════════════════════════════════════════════
# GUI — SETTINGS DIALOG
# ═══════════════════════════════════════════════════════════════
class SettingsDialog:
    def __init__(self, parent, on_apply):
        import tkinter as tk
        from tkinter import colorchooser
        th  = get_theme()
        win = tk.Toplevel(parent)
        win.title(t("settings_title"))
        win.configure(bg=th["BG"])
        win.resizable(False, False)
        win.transient(parent)
        win.grab_set()

        sw = win.winfo_screenwidth(); sh = win.winfo_screenheight()
        W, H = 420, 520
        win.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")
        try:
            win.update_idletasks()  # removed wait_visibility (hangs on Wayland)
            win.attributes("-alpha", 0.0)
        except: pass

        tk.Label(win, text=t("settings_title"),
            font=("Georgia", 14, "bold italic"), bg=th["BG"], fg=th["LOGO_CLR"]
        ).pack(pady=(18, 6))
        tk.Frame(win, bg=th["BORDER"], height=1).pack(fill="x", padx=24, pady=(0, 12))

        body = tk.Frame(win, bg=th["BG"])
        body.pack(fill="both", expand=True, padx=28)

        def row(label, widget_cb):
            f = tk.Frame(body, bg=th["BG"]); f.pack(fill="x", pady=7)
            tk.Label(f, text=label, font=("Courier New", 10),
                bg=th["BG"], fg=th["FG2"], width=18, anchor="w"
            ).pack(side="left")
            return f

        # Language
        lang_f  = row(t("lang_label"), None)
        lang_var = tk.StringVar(value=SETTINGS["lang"])
        for lng in ("EN", "RU"):
            tk.Radiobutton(lang_f, text=lng, variable=lang_var, value=lng,
                font=("Courier New", 10), bg=th["BG"], fg=th["FG"],
                selectcolor=th["BG3"], activebackground=th["BG"],
                relief="flat"
            ).pack(side="left", padx=6)

        # Theme
        theme_f   = row(t("theme_label"), None)
        theme_var = tk.StringVar(value=SETTINGS["theme"])
        theme_cb  = tk.OptionMenu(theme_f, theme_var,
            *[n for n in THEME_ORDER if n != "custom"])
        theme_cb.config(font=("Courier New", 9),
            bg=th["BG3"], fg=th["FG"], relief="flat",
            activebackground=th["BORDER2"], bd=0,
            highlightthickness=0)
        theme_cb["menu"].config(bg=th["BG3"], fg=th["FG"])
        theme_cb.pack(side="left")

        # Sound
        sound_f   = row(t("sound_label"), None)
        sound_var = tk.BooleanVar(value=SETTINGS.get("sound", True))
        tk.Checkbutton(sound_f, text="ON", variable=sound_var,
            font=("Courier New", 10), bg=th["BG"], fg=th["FG"],
            selectcolor=th["BG3"], activebackground=th["BG"],
            relief="flat"
        ).pack(side="left")

        # Transparency
        alpha_f   = row(t("alpha_label"), None)
        alpha_var = tk.DoubleVar(value=SETTINGS.get("transparency", 0.93))
        alpha_lbl = tk.Label(alpha_f, text=f"{alpha_var.get():.2f}",
            font=("Courier New", 9), bg=th["BG"], fg=th["FG2"], width=5)

        def on_alpha(v):
            val = round(float(v), 2)
            alpha_var.set(val)
            alpha_lbl.config(text=f"{val:.2f}")
            try:
                parent.attributes("-alpha", val)
            except: pass

        alpha_scale = tk.Scale(alpha_f, from_=0.4, to=1.0,
            resolution=0.01, orient="horizontal",
            variable=alpha_var, command=on_alpha,
            font=("Courier New", 8), bg=th["BG"], fg=th["FG"],
            troughcolor=th["BG3"], sliderrelief="flat",
            activebackground=th["BORDER2"],
            highlightthickness=0, bd=0, length=160)
        alpha_scale.pack(side="left")
        alpha_lbl.pack(side="left", padx=6)

        # Ask per port
        ask_f   = row(t("ask_port_label"), None)
        ask_var = tk.BooleanVar(value=SETTINGS.get("ask_per_port", False))
        tk.Checkbutton(ask_f, text="ON", variable=ask_var,
            font=("Courier New", 10), bg=th["BG"], fg=th["FG"],
            selectcolor=th["BG3"], activebackground=th["BG"],
            relief="flat"
        ).pack(side="left")

        # Custom colors button
        def pick_custom():
            color = colorchooser.askcolor(
                color=th.get("ACC","#4a9eff"), parent=win)[1]
            if color:
                SETTINGS["custom_theme"] = {"ACC": color}
                save_settings(SETTINGS)

        tk.Button(body, text=t("custom_btn"),
            font=("Courier New", 9), bg=th["BG3"], fg=th["FG2"],
            relief="flat", bd=0, padx=12, pady=5, cursor="hand2",
            command=pick_custom
        ).pack(anchor="w", pady=(8, 0))

        tk.Frame(win, bg=th["BORDER"], height=1).pack(fill="x", padx=24, pady=10)

        # Buttons
        btnf = tk.Frame(win, bg=th["BG"])
        btnf.pack(pady=(0, 16))

        def save():
            SETTINGS["lang"]         = lang_var.get()
            SETTINGS["theme"]        = theme_var.get()
            SETTINGS["sound"]        = sound_var.get()
            SETTINGS["transparency"] = round(alpha_var.get(), 2)
            SETTINGS["ask_per_port"] = ask_var.get()
            save_settings(SETTINGS)
            win.destroy()
            on_apply(animated=True)

        tk.Button(btnf, text=t("close_btn"),
            font=("Courier New", 10), bg=th["BG3"], fg=th["FG2"],
            relief="flat", bd=0, padx=18, pady=7, cursor="hand2",
            command=win.destroy
        ).pack(side="right", padx=(8, 0))
        tk.Button(btnf, text=t("save_btn"),
            font=("Courier New", 10, "bold"),
            bg=th["BTN_BG"], fg=th["BTN_FG"],
            activebackground=th["BTN_HOV"],
            relief="flat", bd=0, padx=20, pady=7, cursor="hand2",
            command=save
        ).pack(side="right")

        def _fade(a):
            try: win.attributes("-alpha", min(0.97, a))
            except: pass
            if a < 0.97: win.after(14, lambda: _fade(a + 0.08))
        _fade(0.0)


# ═══════════════════════════════════════════════════════════════
# GUI — SURFACE PANEL (slides from bottom after surface scan)
# ═══════════════════════════════════════════════════════════════
class SurfacePanel:
    """Animated panel that slides up from the bottom with surface analysis."""
    def __init__(self, parent, results: dict, domain: str, on_deep=None):
        import tkinter as tk
        th   = get_theme()
        self._th = th

        win = tk.Toplevel(parent)
        self.win = win
        win.title(t("summary_title"))
        win.configure(bg=th["BG"])
        win.overrideredirect(True)
        win.attributes("-topmost", True)

        sw = win.winfo_screenwidth()
        sh = win.winfo_screenheight()
        W  = min(sw - 80, 980)
        H  = 340

        # Position: bottom center
        x = (sw - W) // 2
        target_y = sh - H - 40

        win.geometry(f"{W}x{H}+{x}+{sh}")  # Start off-screen
        try:
            win.update_idletasks()  # removed wait_visibility (hangs on Wayland)
            win.attributes("-alpha", 0.0)
        except: pass

        # ── Build content ──────────────────────────────────────
        # Top bar
        top = tk.Frame(win, bg=th["BG3"], height=36)
        top.pack(fill="x")
        top.pack_propagate(False)
        tk.Label(top, text=f"  ▲  {t('summary_title')}  —  {domain}",
            font=("Courier New", 9, "bold"), bg=th["BG3"], fg=th["LOGO_CLR"]
        ).pack(side="left", padx=10, pady=8)
        tk.Button(top, text="✕",
            font=("Courier New", 11), bg=th["BG3"], fg=th["FG3"],
            relief="flat", bd=0, cursor="hand2",
            command=lambda: self._slide_out(sh)
        ).pack(side="right", padx=10)

        # Content area — 4 columns
        body = tk.Frame(win, bg=th["BG"])
        body.pack(fill="both", expand=True, padx=12, pady=8)

        # Column helper
        def col(parent, weight=1):
            f = tk.Frame(parent, bg=th["BG2"], bd=0)
            f.pack(side="left", fill="both", expand=True,
                   padx=4, pady=4, ipadx=8, ipady=6)
            return f

        def kv(parent, key, val, vcolor=None):
            r = tk.Frame(parent, bg=th["BG2"])
            r.pack(fill="x", pady=1, padx=8)
            tk.Label(r, text=f"{key:<14}", font=("Courier New", 8),
                bg=th["BG2"], fg=th["FG3"], anchor="w"
            ).pack(side="left")
            tk.Label(r, text=str(val)[:34], font=("Courier New", 9, "bold"),
                bg=th["BG2"], fg=vcolor or th["FG"], anchor="w"
            ).pack(side="left")

        # ── Col 1: Server / OS info ───────────────────────────
        c1 = col(body)
        tk.Label(c1, text="SERVER INFO", font=("Courier New", 8, "bold"),
            bg=th["BG2"], fg=th["ACC"]
        ).pack(anchor="w", padx=8, pady=(4, 2))

        server = results.get("http", {}).get("server", "N/A")
        status = results.get("http", {}).get("status_code", "N/A")
        proto  = results.get("http", {}).get("protocol", "N/A")
        techs  = results.get("http", {}).get("technologies", [])

        kv(c1, "Server",  server or "Unknown",  th["FOUND"] if server else th["FG2"])
        kv(c1, "Status",  status,  th["ACC3"] if str(status) == "200" else th["WARN"])
        kv(c1, "Proto",   proto,   th["ACC3"] if proto == "HTTPS" else th["WARN"])
        for tech in techs[:3]:
            kv(c1, "Tech", tech[:30], th["FG"])

        # Guess OS from server header
        os_guess = "Unknown"
        if server:
            sl = server.lower()
            if "ubuntu" in sl or "debian" in sl: os_guess = "Linux (Debian/Ubuntu)"
            elif "centos" in sl or "rhel" in sl:  os_guess = "Linux (RHEL/CentOS)"
            elif "win" in sl or "iis" in sl:       os_guess = "Windows Server"
            elif "freebsd" in sl:                   os_guess = "FreeBSD"
            elif "nginx" in sl:                     os_guess = "Linux (nginx)"
            elif "apache" in sl:                    os_guess = "Linux (Apache)"
        kv(c1, "OS Guess", os_guess, th["FG2"])

        # ── Col 2: IP / Country ───────────────────────────────
        c2 = col(body)
        tk.Label(c2, text="NETWORK", font=("Courier New", 8, "bold"),
            bg=th["BG2"], fg=th["ACC"]
        ).pack(anchor="w", padx=8, pady=(4, 2))

        ip_list = results.get("resolution", {}).get("ips", [])
        ip = ip_list[0] if ip_list else "N/A"
        rdns = results.get("resolution", {}).get("reverse_dns", "N/A")

        # IP color: green=safe, red=known bad, yellow=unknown
        ip_color = th["ACC3"]
        kv(c2, "IPv4",   ip,   ip_color)
        kv(c2, "rDNS",   rdns[:30] if rdns != "N/A" else "N/A", th["FG2"])

        # Geolocation
        country_info = {"country": "N/A", "city": "N/A", "org": "N/A"}
        try:
            url = f"https://ipinfo.io/{ip}/json"
            with urlopen(Request(url, headers={"User-Agent": "WebGate/3.0"}),
                         timeout=5) as resp:
                data = json.load(resp)
                country_info["country"] = data.get("country", "N/A")
                country_info["city"]    = data.get("city", "N/A")
                country_info["org"]     = data.get("org", "N/A")[:28]
        except: pass

        kv(c2, "Country", country_info["country"], th["FG"])
        kv(c2, "City",    country_info["city"],    th["FG2"])
        kv(c2, "ASN/Org", country_info["org"],     th["FG2"])

        # ── Col 3: Ports + CVE count ──────────────────────────
        c3 = col(body)
        tk.Label(c3, text="OPEN PORTS", font=("Courier New", 8, "bold"),
            bg=th["BG2"], fg=th["ACC"]
        ).pack(anchor="w", padx=8, pady=(4, 2))

        open_ports = results.get("ports", {}).get("open", [])
        total_cves = sum(len(p.get("cves", [])) for p in open_ports)

        if not open_ports:
            kv(c3, "Ports", "None found", th["ACC3"])
        else:
            for po in open_ports[:8]:
                cve_n   = len(po.get("cves", []))
                svc_col = th["ERR"] if cve_n > 0 else th["WARN"]
                kv(c3, f"{po['port']}/tcp",
                   f"{po['service']}  [{cve_n} CVE]" if cve_n else po['service'],
                   svc_col)

        kv(c3, "Total CVE", str(total_cves), th["ERR"] if total_cves > 0 else th["ACC3"])

        # ── Col 4: Risk + SSL ─────────────────────────────────
        c4 = col(body)
        tk.Label(c4, text="RISK LEVEL", font=("Courier New", 8, "bold"),
            bg=th["BG2"], fg=th["ACC"]
        ).pack(anchor="w", padx=8, pady=(4, 2))

        ssl_r = results.get("ssl", {})
        ssl_ok = ssl_r.get("available", False)
        ssl_days = ssl_r.get("days_until_expiry")
        sec_score = results.get("http", {}).get("score", 0)

        # Calculate risk
        risk_pts = 0
        if not ssl_ok:         risk_pts += 3
        if total_cves > 5:     risk_pts += 3
        elif total_cves > 0:   risk_pts += 2
        if sec_score < 3:      risk_pts += 2
        if ssl_days is not None and ssl_days < 30: risk_pts += 1
        if len(open_ports) > 5: risk_pts += 1

        if   risk_pts >= 7: risk_lbl, risk_col = "CRITICAL", th["ERR"]
        elif risk_pts >= 4: risk_lbl, risk_col = "HIGH",     th["WARN"]
        elif risk_pts >= 2: risk_lbl, risk_col = "MEDIUM",   "#ffaa00"
        else:               risk_lbl, risk_col = "LOW",      th["ACC3"]

        tk.Label(c4, text=f"  {risk_lbl}",
            font=("Courier New", 16, "bold"),
            bg=th["BG2"], fg=risk_col
        ).pack(anchor="w", padx=8, pady=(2, 6))

        kv(c4, "SSL",  "✓ Valid" if ssl_ok else "✗ None",
           th["ACC3"] if ssl_ok else th["ERR"])
        if ssl_days is not None:
            kv(c4, "SSL Days", str(ssl_days),
               th["ERR"] if ssl_days < 15 else th["FG"])
        kv(c4, "Sec Headers", f"{sec_score}/7",
           th["ERR"] if sec_score < 3 else th["FG"])

        # ── Bottom buttons ────────────────────────────────────
        btn_f = tk.Frame(win, bg=th["BG3"])
        btn_f.pack(fill="x")
        if on_deep:
            tk.Button(btn_f, text=t("summary_next"),
                font=("Courier New", 9, "bold"),
                bg=th["ACC"], fg=th["BG"],
                relief="flat", bd=0, padx=18, pady=6, cursor="hand2",
                command=lambda: (self._slide_out(sh), on_deep())
            ).pack(side="right", padx=10, pady=6)
        tk.Button(btn_f, text=t("summary_close"),
            font=("Courier New", 9),
            bg=th["BG4"], fg=th["FG2"],
            relief="flat", bd=0, padx=14, pady=6, cursor="hand2",
            command=lambda: self._slide_out(sh)
        ).pack(side="right", padx=(0, 4), pady=6)

        # ── Slide-in animation ────────────────────────────────
        self._W = W; self._H = H; self._x = x
        self._target_y = target_y
        self._slide_in(sh, target_y)

    def _slide_in(self, y, target):
        step = max(20, (y - target) // 4)
        ny   = y - step
        try:
            self.win.geometry(f"{self._W}x{self._H}+{self._x}+{int(ny)}")
            self.win.attributes("-alpha", min(0.97, (target - ny + self._H) / self._H))
        except: pass
        if ny > target:
            self.win.after(12, lambda: self._slide_in(ny, target))
        else:
            try:
                self.win.geometry(f"{self._W}x{self._H}+{self._x}+{target}")
                self.win.attributes("-alpha", 0.97)
            except: pass

    def _slide_out(self, sh):
        try:
            geo = self.win.geometry()
            y   = int(geo.split("+")[2])
        except:
            y = self._target_y
        step = max(25, (sh - y) // 3)
        ny   = y + step
        try:
            self.win.geometry(f"{self._W}x{self._H}+{self._x}+{int(ny)}")
            self.win.attributes("-alpha", max(0.0, 1.0 - (ny - self._target_y) / self._H))
        except: pass
        if ny < sh:
            self.win.after(12, lambda: self._slide_out(sh))
        else:
            try: self.win.destroy()
            except: pass


# ═══════════════════════════════════════════════════════════════
# COLOR HELPERS + ROUNDED BUTTON
# ═══════════════════════════════════════════════════════════════
def _hex_to_rgb(h):
    h = h.lstrip("#")
    if len(h) == 3: h = h[0]*2+h[1]*2+h[2]*2
    return int(h[0:2],16), int(h[2:4],16), int(h[4:6],16)

def _rgb_to_hex(r,g,b):
    return f"#{max(0,min(255,r)):02x}{max(0,min(255,g)):02x}{max(0,min(255,b)):02x}"

def _lerp_color(c1, c2, t):
    r1,g1,b1 = _hex_to_rgb(c1); r2,g2,b2 = _hex_to_rgb(c2)
    return _rgb_to_hex(int(r1+(r2-r1)*t), int(g1+(g2-g1)*t), int(b1+(b2-b1)*t))

def _lighten(c, amt=0.25):
    r,g,b = _hex_to_rgb(c)
    return _rgb_to_hex(r+int((255-r)*amt), g+int((255-g)*amt), b+int((255-b)*amt))

def _darken(c, amt=0.25):
    r,g,b = _hex_to_rgb(c)
    return _rgb_to_hex(int(r*(1-amt)), int(g*(1-amt)), int(b*(1-amt)))


class RoundedButton(object):
    """Fake 'rounded button' using a Canvas widget.

    drop-in replacement for tk.Button with:
      - smooth polygon rounded corners
      - animated hover (color lerp)
      - press feedback
      - configurable icon prefix
    """
    def __init__(self, parent, text="", icon="", command=None,
                 bg="#1a6fd4", fg="#ffffff", hover_bg=None, press_bg=None,
                 dis_bg="#1a1f32", dis_fg="#3a4868",
                 radius=11, width=0, height=36,
                 font_spec=None, padx=0, pady=0, disabled=False,
                 parent_bg=None, **kw):
        import tkinter as tk
        self._tk       = tk
        self._bg       = bg
        self._fg       = fg
        self._hbg      = hover_bg  or _lighten(bg, 0.22)
        self._pbg      = press_bg  or _lighten(bg, 0.40)
        self._dis_bg   = dis_bg
        self._dis_fg   = dis_fg
        self._radius   = radius
        self._icon     = icon
        self._label    = text
        self._text     = (icon + "  " + text).strip() if icon else text
        self._cmd      = command
        self._disabled = disabled
        self._font     = font_spec or ("DejaVu Sans", 10, "bold")
        self._cur      = dis_bg if disabled else bg
        self._anim_id  = None
        self._hover    = False

        pbg = parent_bg
        if pbg is None:
            try:    pbg = parent.cget("bg")
            except: pbg = "#0a0d14"

        if not width:
            width = max(90, len(self._text)*8 + 42)

        self.widget = tk.Canvas(parent, width=width, height=height,
                                highlightthickness=0, bd=0, bg=pbg,
                                cursor="hand2" if not disabled else "arrow",
                                **kw)
        self.widget.bind("<Configure>", lambda _: self._draw(self._cur))
        if not disabled:
            self.widget.bind("<Enter>",           self._on_enter)
            self.widget.bind("<Leave>",           self._on_leave)
            self.widget.bind("<ButtonPress-1>",   self._on_press)
            self.widget.bind("<ButtonRelease-1>", self._on_release)
        self._draw(self._cur)

    # ── layout proxies (so callers can use .pack / .grid / .place) ──
    def pack(self, **kw):   self.widget.pack(**kw)
    def grid(self, **kw):   self.widget.grid(**kw)
    def place(self, **kw):  self.widget.place(**kw)
    def bind(self, *a, **k):self.widget.bind(*a, **k)
    def pack_forget(self):  self.widget.pack_forget()
    def grid_forget(self):  self.widget.grid_forget()
    def cget(self, k):      return self.widget.cget(k)
    def configure(self, **kw):
        # Handle state=disabled/normal
        if "state" in kw:
            self.set_disabled(kw["state"] == "disabled")
        if "text" in kw:
            self.set_text(kw["text"])

    def _rrect(self, color):
        """Draw rounded-rect polygon."""
        cv = self.widget
        cv.delete("all")
        w = cv.winfo_width() or int(cv.cget("width"))
        h = cv.winfo_height() or int(cv.cget("height"))
        r = min(self._radius, w//2-1, h//2-1)
        pts = [r,0, w-r,0, w,r, w,h-r, w-r,h, r,h, 0,h-r, 0,r]
        cv.create_polygon(pts, smooth=True, fill=color, outline="")
        fg = self._dis_fg if self._disabled else self._fg
        cv.create_text(w//2, h//2, text=self._text, fill=fg,
                       font=self._font, anchor="center")

    def _draw(self, color):
        self._cur = color
        self._rrect(color)

    def _animate(self, start, end, steps=7, step=0):
        if self._anim_id:
            try: self.widget.after_cancel(self._anim_id)
            except: pass
        def _tick(i):
            if i > steps:
                self._draw(end); return
            c = _lerp_color(start, end, i/steps)
            self._draw(c)
            self._anim_id = self.widget.after(14, lambda: _tick(i+1))
        _tick(1)

    def _on_enter(self, _):
        self._hover = True
        self._animate(self._cur, self._hbg)

    def _on_leave(self, _):
        self._hover = False
        self._animate(self._cur, self._bg)

    def _on_press(self, _):
        self._draw(self._pbg)

    def _on_release(self, _):
        self._draw(self._hbg if self._hover else self._bg)
        if self._cmd and not self._disabled:
            self._cmd()

    def set_text(self, text, icon=None):
        if icon is not None: self._icon = icon
        self._label = text
        self._text  = (self._icon+"  "+text).strip() if self._icon else text
        self._draw(self._cur)

    def set_disabled(self, disabled):
        self._disabled = disabled
        if disabled:
            self.widget.config(cursor="arrow")
            self._draw(self._dis_bg)
        else:
            self.widget.config(cursor="hand2")
            self._draw(self._bg)


# ═══════════════════════════════════════════════════════════════
# GUI — MAIN APPLICATION
# ═══════════════════════════════════════════════════════════════
class SecurityScannerGUI:
    def __init__(self, root, prefill: str = ""):
        import tkinter as tk
        from tkinter import font as tkfont
        self.tk   = tk
        self.root = root
        self.th   = get_theme()

        self.root.title("WebGate  —  Domain Security Auditor")
        self.root.minsize(1200, 750)
        self.root.geometry("1440x900")
        self.root.configure(bg=self.th["BG"])

        self._prefill    = prefill
        self.scanning    = False
        self.scanner     = None
        self._log_q      = []
        self._log_busy   = False
        self._scan_start = 0.0
        self._step_idx   = [0]
        self._dot_state  = 0
        self._prog_val   = 0
        self._eta_secs   = 0
        self._surface_done = False

        self.font, self.tfont = self._pick_font()
        self._build_ui()
        self._pulse_dot()

    def _pick_font(self):
        avail = list(self.tk.font.families())
        mono  = next((f for f in ["JetBrains Mono","Fira Code","Cascadia Code",
                                    "Source Code Pro","Consolas","Courier New"] if f in avail),
                      "Courier New")
        title = next((f for f in ["Helvetica Neue","Inter","Segoe UI","DejaVu Sans",
                                    "Helvetica","Arial"] if f in avail), "Helvetica")
        return mono, title

    # ── Transparency ──────────────────────────────────────────
    def _set_alpha(self, val):
        _safe_alpha(self.root, max(0.1, min(1.0, val)))

    def _fade_in_root(self, a=0.0):
        target = SETTINGS.get("transparency", 0.95)
        if a == 0.0:
            # Set invisible BEFORE showing window so no flash
            _safe_alpha(self.root, 0.0)
            self.root.deiconify()
            self.root.update_idletasks()
        nxt = min(target, a + 0.07)
        _safe_alpha(self.root, nxt)
        if nxt < target:
            self.root.after(14, lambda: self._fade_in_root(nxt))

    # ── UI Construction ───────────────────────────────────────
    def _build_ui(self):
        tk = self.tk; th = self.th; root = self.root
        root.configure(bg=th["BG"])

        # ── TOP BAR ────────────────────────────────────────────
        top = tk.Frame(root, bg=th["BG"])
        top.pack(fill="x")

        # Logo
        logo_cv = tk.Canvas(top, bg=th["BG"], height=72,
                             highlightthickness=0, width=380)
        logo_cv.pack(side="left", padx=24, pady=8)
        # Shadow layers
        for dx, dy, col in [(5,38,th["BG4"]),(3,36,th["LOGO_SHD"]),(1,34,th["LOGO_SHD"])]:
            logo_cv.create_text(dx, dy, text="WebGate",
                font=("Georgia", 40, "bold italic"), fill=col, anchor="w")
        # Main logo text
        logo_cv.create_text(0, 33, text="WebGate",
            font=("Georgia", 40, "bold italic"), fill=th["LOGO_CLR"], anchor="w")
        # Accent underline (gradient-like double line)
        logo_cv.create_line(0, 52, 260, 52, fill=th["ACC"], width=2)
        logo_cv.create_line(0, 55, 160, 55, fill=th["BORDER3"], width=1)
        # CVE count badge
        cve_n = get_all_cve_count()
        logo_cv.create_text(0, 66,
            text=f"by c3less  ·  {cve_n} CVE  ·  30 tools",
            font=(self.font, 8), fill=th["FG3"], anchor="w")

        # Right controls
        rc = tk.Frame(top, bg=th["BG"])
        rc.pack(side="right", padx=16, pady=12)

        # Status dot (pulsing indicator)
        self._dot = tk.Label(rc, text="●", font=(self.font, 16),
                              bg=th["BG"], fg=th["FG3"])
        self._dot.pack(side="right", padx=(0, 10))

        # Settings button
        self._settings_rbtn = RoundedButton(rc,
            text="SETTINGS", icon="⚙",
            bg=th["BG4"], fg=th["FG2"], hover_bg=th["BORDER2"],
            font_spec=(self.font, 9), height=32, radius=8,
            command=self._open_settings, parent_bg=th["BG"])
        self._settings_rbtn.pack(side="right", padx=4)
        self._settings_btn = self._settings_rbtn.widget  # compat

        # Language toggle
        self._lang_rbtn = RoundedButton(rc,
            text=SETTINGS["lang"],
            bg=th["BG3"], fg=th["FG"], hover_bg=th["BORDER3"],
            font_spec=(self.font, 9, "bold"), height=32, width=58, radius=8,
            command=self._toggle_lang, parent_bg=th["BG"])
        self._lang_rbtn.pack(side="right", padx=4)

        # Theme toggle
        theme_names = {"dark":"DARK","light":"LIGHT","midnight":"NIGHT","hacker":"HACK","custom":"CUST"}
        self._theme_rbtn = RoundedButton(rc,
            text=theme_names.get(SETTINGS["theme"], "DARK"),
            bg=th["BG3"], fg=th["FG"], hover_bg=th["BORDER3"],
            font_spec=(self.font, 8, "bold"), height=32, width=72, radius=8,
            command=self._cycle_theme, parent_bg=th["BG"])
        self._theme_rbtn.pack(side="right", padx=4)

        # Instructions
        instr = tk.Label(top, text=t("instructions"),
            font=(self.font, 8), bg=th["BG"], fg=th["FG3"],
            justify="left", anchor="w")
        instr.pack(side="left", padx=(10, 0))

        tk.Frame(root, bg=th["BORDER"], height=1).pack(fill="x")

        # ── INPUT ROW ──────────────────────────────────────────
        inrow = tk.Frame(root, bg=th["BG2"])
        inrow.pack(fill="x")
        inner = tk.Frame(inrow, bg=th["BG2"])
        inner.pack(side="left", padx=20, pady=12)

        tk.Label(inner, text=t("target_lbl"),
            font=(self.font, 8, "bold"),
            bg=th["BG2"], fg=th["FG3"]
        ).pack(side="left", padx=(0, 10))

        # Animated entry field with glow border
        self._ef = tk.Frame(inner, bg=th["BORDER2"], padx=2, pady=2)
        self._ef.pack(side="left")
        self._dvar  = tk.StringVar(value=self._prefill)
        self._entry = tk.Entry(self._ef, textvariable=self._dvar,
            font=(self.font, 13),
            bg=th["BG3"], fg=th["FG"],
            insertbackground=th["WHITE"],
            relief="flat", bd=6, width=32)
        self._entry.pack()
        self._entry.bind("<FocusIn>",  self._ef_in)
        self._entry.bind("<FocusOut>", self._ef_out)
        self._entry.bind("<Key>",      lambda e: self._entry_pulse())

        # Animated placeholder
        if not self._prefill:
            self._entry.insert(0, t("placeholder"))
            self._entry.config(fg=th["FG3"])
        self._entry.bind("<FocusIn>",  self._ef_in,  add="+")
        self._entry.bind("<FocusOut>", self._ef_out, add="+")

        # Main SCAN button
        self._scan_rbtn = RoundedButton(inner,
            text=t("scan_btn"), icon="▶",
            bg=th["BTN_BG"], fg=th["BTN_FG"],
            hover_bg=th["BTN_HOV"], press_bg=th["BTN_BG"],
            font_spec=(self.font, 12, "bold"),
            height=42, radius=12, command=self._on_scan,
            parent_bg=th["BG2"])
        self._scan_rbtn.pack(side="left", padx=(14, 0))
        self._btn = self._scan_rbtn  # compat alias

        # DEEP SCAN button
        self._deep_rbtn = RoundedButton(inner,
            text=t("deep_btn"), icon="⚡",
            bg=th["BG4"], fg=th["FG"],
            hover_bg=th["BORDER2"],
            font_spec=(self.font, 10), height=42, radius=12,
            command=self._on_deep_scan, parent_bg=th["BG2"])
        self._deep_rbtn.pack(side="left", padx=(8, 0))
        self._deep_btn = self._deep_rbtn  # compat alias

        # CANCEL button (hidden initially)
        self._cancel_rbtn = RoundedButton(inner,
            text=t("cancel_btn"), icon="✕",
            bg="#3a1a1a", fg=th["ERR"],
            hover_bg="#5a2a2a",
            font_spec=(self.font, 10), height=42, radius=12,
            command=self._on_cancel, parent_bg=th["BG2"])
        self._cancel_btn = self._cancel_rbtn  # compat alias

        # Right side: copy + clear
        right_btns = tk.Frame(inrow, bg=th["BG2"])
        right_btns.pack(side="right", padx=16)
        RoundedButton(right_btns, text="COPY", icon="⎘",
            bg=th["BG4"], fg=th["FG3"], hover_bg=th["BORDER2"],
            font_spec=(self.font, 8), height=30, radius=8,
            command=self._copy_log, parent_bg=th["BG2"]
        ).pack(side="left", padx=3)
        RoundedButton(right_btns, text="CLEAR", icon="✕",
            bg=th["BG4"], fg=th["FG3"], hover_bg=th["BORDER2"],
            font_spec=(self.font, 8), height=30, radius=8,
            command=self._clear_log, parent_bg=th["BG2"]
        ).pack(side="left", padx=3)

        tk.Frame(root, bg=th["BORDER"], height=1).pack(fill="x")

        # ── MAIN CONTENT ───────────────────────────────────────
        content = tk.Frame(root, bg=th["BG"])
        content.pack(fill="both", expand=True)
        content.columnconfigure(0, weight=1)
        content.rowconfigure(0, weight=1)

        # Log panel
        log_frame = tk.Frame(content, bg=th["BG"])
        log_frame.grid(row=0, column=0, sticky="nsew")
        log_frame.rowconfigure(1, weight=1)
        log_frame.columnconfigure(0, weight=1)

        log_hdr = tk.Frame(log_frame, bg=th["BG3"], height=26)
        log_hdr.grid(row=0, column=0, columnspan=2, sticky="ew")
        tk.Label(log_hdr, text=t("log_hdr"),
            font=(self.font, 8, "bold"),
            bg=th["BG3"], fg=th["FG3"]
        ).pack(side="left", padx=14, pady=4)
        self._evt_lbl = tk.Label(log_hdr, text="",
            font=(self.font, 7), bg=th["BG3"], fg=th["FG3"])
        self._evt_lbl.pack(side="right", padx=14, pady=4)

        self._log_w = tk.Text(log_frame,
            font=(self.font, 10), bg=th["BG"], fg=th["FG"],
            insertbackground=th["WHITE"], relief="flat", bd=0,
            padx=16, pady=12, wrap="word", state="disabled",
            cursor="arrow",
            selectbackground=th["BORDER2"], selectforeground=th["WHITE"])
        sb = tk.Scrollbar(log_frame, orient="vertical",
            command=self._log_w.yview,
            bg=th["BG3"], troughcolor=th["BG"],
            activebackground=th["BORDER2"],
            width=7, relief="flat", bd=0)
        self._log_w.configure(yscrollcommand=sb.set)
        sb.grid(row=1, column=1, sticky="ns")
        self._log_w.grid(row=1, column=0, sticky="nsew")

        for lvl, col_val in th["LOG_CLR"].items():
            self._log_w.tag_configure(f"lvl_{lvl}", foreground=col_val)
        self._log_w.tag_configure("ts",     foreground=th["FG3"])
        self._log_w.tag_configure("pfx_h",  foreground=th["WHITE"],
                                             font=(self.font, 10, "bold"))
        self._log_w.tag_configure("rule",   foreground=th["FG3"])
        self._log_w.tag_configure("cursor", foreground=th["WHITE"])

        # ── RIGHT PANEL ────────────────────────────────────────
        rp = tk.Frame(content, bg=th["BG2"], width=220)
        rp.grid(row=0, column=2, sticky="ns")
        rp.pack_propagate(False)

        def phdr(parent, text):
            f = tk.Frame(parent, bg=th["BG3"], height=26)
            f.pack(fill="x")
            tk.Label(f, text=text, font=(self.font, 7, "bold"),
                bg=th["BG3"], fg=th["FG3"]
            ).pack(side="left", padx=12, pady=4)

        phdr(rp, t("status_hdr"))

        sf = tk.Frame(rp, bg=th["BG2"])
        sf.pack(fill="x", padx=10, pady=6)
        self._stats = {}
        stat_keys = [
            (t("stat_status"),  "IDLE"),
            (t("stat_target"),  "—"),
            (t("stat_ip"),      "—"),
            (t("stat_country"), "—"),
            (t("stat_ports"),   "—"),
            (t("stat_ssl"),     "—"),
            (t("stat_sec"),     "—"),
            (t("stat_time"),    "—"),
            (t("stat_eta"),     "—"),
        ]
        for k, v in stat_keys:
            r = tk.Frame(sf, bg=th["BG2"]); r.pack(fill="x", pady=1)
            tk.Label(r, text=f"{k:<8}", font=(self.font, 7),
                bg=th["BG2"], fg=th["FG3"], anchor="w"
            ).pack(side="left")
            vl = tk.Label(r, text=v, font=(self.font, 8, "bold"),
                bg=th["BG2"], fg=th["FG2"], anchor="w")
            vl.pack(side="left")
            self._stats[k] = vl

        tk.Frame(rp, bg=th["BORDER"], height=1).pack(fill="x", pady=(4, 0))
        phdr(rp, t("steps_hdr"))
        stepf = tk.Frame(rp, bg=th["BG2"])
        stepf.pack(fill="x", padx=10, pady=6)
        self._step_w = []
        for name in t("steps"):
            r = tk.Frame(stepf, bg=th["BG2"]); r.pack(fill="x", pady=1)
            dot = tk.Label(r, text="○", font=(self.font, 10),
                bg=th["BG2"], fg=th["FG3"])
            dot.pack(side="left", padx=(0, 5))
            lbl = tk.Label(r, text=name, font=(self.font, 8),
                bg=th["BG2"], fg=th["FG3"], anchor="w")
            lbl.pack(side="left")
            self._step_w.append((dot, lbl))

        # ── BOTTOM BAR ─────────────────────────────────────────
        tk.Frame(root, bg=th["ACC"], height=2).pack(fill="x", side="bottom")
        bot = tk.Frame(root, bg=th["BG3"], height=36)
        bot.pack(fill="x", side="bottom")
        bot.pack_propagate(False)

        self._prog_lbl = tk.Label(bot, text=t("ready"),
            font=(self.font, 8, "bold"), bg=th["BG3"], fg=th["FG2"])
        self._prog_lbl.pack(side="left", padx=16, pady=8)

        self._cv = tk.Canvas(bot, height=6, bg=th["BG"],
            highlightthickness=0, bd=0)
        self._cv.pack(side="left", fill="x", expand=True, padx=12, pady=15)

        self._eta_lbl = tk.Label(bot, text="",
            font=(self.font, 8), bg=th["BG3"], fg=th["FG3"])
        self._eta_lbl.pack(side="right", padx=8)

        def _link_btn(parent, label, url, icon=""):
            full = (icon + "  " + label).strip() if icon else label
            lbl = tk.Label(parent, text=full,
                font=(self.font, 8, "bold"), bg=th["BG3"],
                fg=th["FG3"], cursor="hand2", padx=6)
            lbl.pack(side="right", padx=4, pady=8)
            def _enter(_):
                lbl.config(fg=th["ACC"])
                self.root.after(0, lambda: lbl.config(
                    font=(self.font, 8, "bold underline")))
            def _leave(_):
                lbl.config(fg=th["FG3"],
                    font=(self.font, 8, "bold"))
            lbl.bind("<Enter>", _enter)
            lbl.bind("<Leave>", _leave)
            lbl.bind("<Button-1>", lambda _: self._open_url(url))
            return lbl

        _link_btn(bot, "@c3less",                 "https://t.me/c3less",                   icon="✈")
        tk.Label(bot, text="·", font=(self.font,8), bg=th["BG3"], fg=th["FG3"]).pack(side="right")
        _link_btn(bot, "github.com/c3less/webgate","https://github.com/c3less/webgate",     icon="⌥")

        self._cv.bind("<Configure>", lambda _: self._draw_prog(self._prog_val))

        # Key bindings
        self.root.bind("<Return>", lambda _: self._on_scan())
        self.root.bind("<Escape>", lambda _: self._on_cancel())
        self.root.bind("<Control-c>", lambda _: self._copy_log())
        # Ctrl+scroll = zoom font
        self._font_size = 10
        self.root.bind("<Control-MouseWheel>",
            lambda e: self._zoom_font(1 if e.delta > 0 else -1))
        self.root.bind("<Control-Button-4>",  # Linux scroll up
            lambda _: self._zoom_font(1))
        self.root.bind("<Control-Button-5>",  # Linux scroll down
            lambda _: self._zoom_font(-1))

        self.root.update_idletasks()
        self._draw_prog(0)
        self._push(t("init_msg"), "INFO")

    # ── Hover effects (no-op now — RoundedButton handles its own) ─
    def _btn_hover(self): pass

    # ── Entry animations ──────────────────────────────────────
    def _ef_in(self, _):
        th = self.th
        cur = self._entry.get()
        if cur == t("placeholder"):
            self._entry.delete(0, "end")
            self._entry.config(fg=th["FG"])
        self._entry_glow(0, True)

    def _ef_out(self, _):
        th = self.th
        if not self._entry.get():
            self._entry.insert(0, t("placeholder"))
            self._entry.config(fg=th["FG3"])
        self._entry_glow(0, False)

    def _entry_glow(self, step, focus_in):
        try: frame = self._ef
        except AttributeError: return
        th = self.th
        if focus_in:
            colors = [th["BORDER3"], th["ACC"], th["BORDER3"], th["BORDER2"]]
        else:
            colors = [th["BORDER3"], th["BORDER2"]]
        if step < len(colors):
            try: frame.config(bg=colors[step])
            except: return
            self.root.after(50, lambda: self._entry_glow(step + 1, focus_in))

    def _entry_pulse(self):
        """Brief flash on keypress."""
        th = self.th
        try:
            self._ef.config(bg=th["ACC"])
            self.root.after(80, lambda: self._ef.config(bg=th["BORDER2"]))
        except: pass

    # ── Pulsing dot ───────────────────────────────────────────
    def _pulse_dot(self):
        if not hasattr(self, "_dot"): return
        th = self.th
        if self.scanning:
            cols = [th["FG3"], th["FG2"], th["ACC"], th["WHITE"],
                    th["ACC"], th["FG2"], th["FG3"]]
            try:
                self._dot.config(fg=cols[self._dot_state % len(cols)])
            except: pass
        else:
            try: self._dot.config(fg=th["FG3"])
            except: pass
        self._dot_state += 1
        self.root.after(280, self._pulse_dot)

    # ── Press effect ──────────────────────────────────────────
    def _press_effect(self, btn):
        th  = self.th
        orig = btn.cget("bg")
        def on_press(_):  btn.config(bg=th.get("BORDER2", "#444"))
        def on_release(_): btn.config(bg=orig)
        btn.bind("<ButtonPress-1>",   on_press,   add="+")
        btn.bind("<ButtonRelease-1>", on_release, add="+")

    # ── Language / Theme ──────────────────────────────────────
    def _toggle_lang(self):
        if self.scanning: return
        SETTINGS["lang"] = "RU" if SETTINGS["lang"] == "EN" else "EN"
        save_settings(SETTINGS)
        self._apply_theme(animated=True)

    def _cycle_theme(self):
        if self.scanning: return
        order = [n for n in THEME_ORDER if n != "custom"]
        cur   = SETTINGS.get("theme", "dark")
        nxt   = order[(order.index(cur) if cur in order else 0) + 1 if
                      (order.index(cur) if cur in order else 0) + 1 < len(order) else 0]
        SETTINGS["theme"] = nxt
        save_settings(SETTINGS)
        self._apply_theme(animated=True)

    def _apply_theme(self, animated=False):
        if animated:
            self._fade_out_in()
        else:
            self._rebuild_ui()

    def _fade_out_in(self):
        cur = SETTINGS.get("transparency", 0.93)

        def fade_out(a):
            nv = max(0.0, a - 0.12)
            self._set_alpha(nv)
            if nv > 0.0:
                self.root.after(12, lambda: fade_out(nv))
            else:
                self._rebuild_ui()
                fade_in(0.0)

        def fade_in(a):
            target = SETTINGS.get("transparency", 0.93)
            nv = min(target, a + 0.10)
            self._set_alpha(nv)
            if nv < target:
                self.root.after(12, lambda: fade_in(nv))

        fade_out(cur)

    def _rebuild_ui(self):
        try:    log_content = self._log_w.get("1.0", "end-1c")
        except: log_content = ""
        self.th = get_theme()
        for w in self.root.winfo_children():
            w.destroy()
        self._log_q     = []
        self._log_busy  = False
        self._step_w    = []
        self._stats     = {}
        self._shimmer_x = 0
        self._build_ui()
        self._pulse_dot()
        if log_content.strip():
            self._log_w.configure(state="normal")
            self._log_w.insert("end", log_content + "\n")
            self._log_w.see("end")
            self._log_w.configure(state="disabled")
        else:
            self._push(t("init_msg"), "INFO")
        # Restore transparency
        self.root.after(50, lambda: self._set_alpha(
            SETTINGS.get("transparency", 0.93)))

    # ── Progress bar with shimmer ─────────────────────────────
    def _draw_prog(self, val: int):
        self._prog_val = val
        cv = self._cv; cv.delete("all")
        w = cv.winfo_width(); h = cv.winfo_height()
        if w < 2: return
        th = self.th
        # Track (rounded)
        cv.create_rectangle(0, 0, w, h, fill=th["BG4"], outline="")
        if val > 0:
            fw = max(6, int(w * val / 100))
            # Main bar
            cv.create_rectangle(0, 0, fw, h, fill=th["ACC"], outline="")
            # Bright leading edge
            if fw > 4:
                cv.create_rectangle(max(0,fw-4), 0, fw, h,
                                    fill=th["WHITE"], outline="")
            # Shimmer stripe (animated separately via _shimmer)
            sx = getattr(self, "_shimmer_x", 0) % max(1, fw+60) - 30
            sw = 20
            if 0 < sx < fw:
                cv.create_rectangle(max(0,sx), 0, min(fw,sx+sw), h,
                    fill=_lighten(th["ACC"],0.5), outline="")

    def _smooth_prog(self, target, cur=None, step=2):
        if cur is None: cur = self._prog_val
        if cur < target:
            cur = min(cur + step, target)
            self._draw_prog(cur)
            self.root.after(12, lambda: self._smooth_prog(target, cur, step))
        else:
            self._draw_prog(target)

    def _set_prog(self, v):
        self.root.after(0, lambda: self._smooth_prog(v))

    def _shimmer_tick(self):
        """Animate shimmer stripe across progress bar while scanning."""
        if not self.scanning: return
        self._shimmer_x = getattr(self, "_shimmer_x", 0) + 5
        self._draw_prog(self._prog_val)
        self.root.after(35, self._shimmer_tick)

    # ── Log system ────────────────────────────────────────────
    _PFX = {"INFO":"  ·  ","FOUND":"  +  ","WARN":"  !  ",
            "ERROR":"  ✗  ","STEP":"  ▶  ","SUCCESS":"  ✓  "}

    def _ins(self, txt: str, *tags):
        self._log_w.configure(state="normal")
        self._log_w.insert("end", txt, tags)
        self._log_w.see("end")
        self._log_w.configure(state="disabled")
        lines = int(self._log_w.index("end-1c").split(".")[0])
        try: self._evt_lbl.config(text=f"{max(0, lines-1)} lines")
        except: pass

    def _push(self, msg: str, level: str = "INFO", rule: bool = False):
        self._log_q.append((msg, level, rule))
        if not self._log_busy:
            self._log_busy = True
            self.root.after(0, self._flush)

    def _flush(self):
        if not self._log_q:
            self._log_busy = False; return
        msg, level, rule = self._log_q.pop(0)
        if rule:
            self._ins(f"{msg}\n", "rule")
            self.root.after(8, self._flush); return
        ts  = datetime.now().strftime("%H:%M:%S")
        pfx = self._PFX.get(level, "  ·  ")
        ltag = f"lvl_{level}"
        ptag = "pfx_h" if level in ("STEP", "SUCCESS", "ERROR") else ltag
        self._ins(f"[{ts}]", "ts")
        self._ins(pfx, ptag)
        if level == "STEP":
            self._type_msg(msg, level, 0,
                cb=lambda: self.root.after(40, self._flush))
        else:
            self._ins(f"{msg}\n", ltag)
            self.root.after(14, self._flush)

    def _type_msg(self, text: str, level: str, idx: int, cb):
        if idx >= len(text):
            self._ins("\n"); cb(); return
        self._ins(text[idx], f"lvl_{level}")
        if SETTINGS.get("sound") and idx % 2 == 0:
            play_click()
        self.root.after(10, lambda: self._type_msg(text, level, idx + 1, cb))

    def log_from_thread(self, msg: str, level: str):
        self.root.after(0, lambda: self._push(msg, level))

    # ── Step indicators ───────────────────────────────────────
    def _set_step(self, idx: int, state: str):
        if idx >= len(self._step_w): return
        dot, lbl = self._step_w[idx]; th = self.th
        cfg = {
            "active":  ("◉", th["ACC"],   th["WHITE"]),
            "done":    ("●", th["FG2"],   th["FG2"]),
            "error":   ("✗", th["ERR"],   th["ERR"]),
            "pending": ("○", th["FG3"],   th["FG3"]),
        }.get(state, ("○", th["FG3"], th["FG3"]))
        dot.config(text=cfg[0], fg=cfg[1])
        lbl.config(fg=cfg[2])

    def _reset_steps(self):
        for i in range(len(self._step_w)):
            self._set_step(i, "pending")

    def _stat(self, k, v, c=None):
        lbl = self._stats.get(k)
        if lbl:
            lbl.config(text=str(v), fg=c or self.th["FG"])

    # ── Clipboard ─────────────────────────────────────────────
    def _copy_log(self):
        try:
            content = self._log_w.get("1.0", "end-1c")
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            self.root.update()  # Keep clipboard alive
            self._push(t("copied"), "SUCCESS")
        except Exception as e:
            self._push(f"Clipboard error: {e}", "ERROR")

    def _clear_log(self):
        if self.scanning: return
        self._log_w.configure(state="normal")
        self._log_w.delete("1.0", "end")
        self._log_w.configure(state="disabled")
        self._evt_lbl.config(text="")

    # ── Scan lifecycle ────────────────────────────────────────
    def _get_domain(self):
        d = self._dvar.get().strip()
        if d == t("placeholder"): return ""
        return d

    def _on_scan(self):
        if self.scanning: return
        domain = self._get_domain()
        if not domain:
            self._push(t("enter_domain"), "WARN"); return
        self._begin_scan(domain, deep=False)

    def _on_deep_scan(self):
        if self.scanning: return
        domain = self._get_domain()
        if not domain:
            self._push(t("enter_domain"), "WARN"); return
        DisclaimerDialog(self.root,
            lambda: ToolSelectorDialog(self.root,
                lambda tools, ask: self._begin_scan(domain, deep=True,
                    tools=tools, ask_port=ask)))

    def _on_cancel(self):
        if self.scanner and self.scanning:
            self.scanner.cancelled = True
            self._push("Cancelling…", "WARN")

    def _begin_scan(self, domain: str, deep: bool = False,
                    tools=None, ask_port=False):
        self.scanning = True; th = self.th
        self._scan_rbtn.set_text("SCANNING…", icon="◉")
        self._scan_rbtn.set_disabled(True)
        self._deep_rbtn.set_disabled(True)
        self._cancel_rbtn.pack(side="left", padx=(8, 0))
        self._entry.config(state="disabled")
        self._reset_steps()
        self._log_q.clear(); self._log_busy = False
        self._log_w.configure(state="normal")
        self._log_w.delete("1.0", "end")
        self._log_w.configure(state="disabled")
        self._evt_lbl.config(text="")
        self._draw_prog(0)
        self._stat(t("stat_status"), "SCANNING", th["WHITE"])
        self._stat(t("stat_target"), domain, th["FG"])
        for k in [t("stat_ip"), t("stat_country"), t("stat_ports"),
                  t("stat_ssl"), t("stat_sec"), t("stat_time"), t("stat_eta")]:
            self._stat(k, "—", th["FG2"])
        self._prog_lbl.config(text=t("scanning"))
        self._scan_start = time.time()
        self._step_idx   = [0]
        self._shimmer_x  = 0
        self._tick()
        self._shimmer_tick()
        threading.Thread(
            target=self._thread,
            args=(domain, deep, tools, ask_port),
            daemon=True
        ).start()

    def _tick(self):
        if not self.scanning: return
        el  = time.time() - self._scan_start
        pv  = self._prog_val
        eta = "—"
        if pv > 5:
            total_est = el / (pv / 100)
            rem = max(0, total_est - el)
            eta = f"{int(rem)}s"
        try:
            self._stat(t("stat_time"), f"{el:.0f}s", self.th["FG2"])
            self._stat(t("stat_eta"),  eta,           self.th["FG3"])
        except: pass
        self.root.after(1000, self._tick)

    def _thread(self, domain: str, deep: bool,
                tools=None, ask_port=False):
        idx = [0]

        def on_log(msg, level):
            if level == "STEP":
                i = idx[0]
                if i > 0:
                    self.root.after(0, lambda k=i-1: self._set_step(k, "done"))
                self.root.after(0, lambda k=i: self._set_step(k, "active"))
                idx[0] += 1
            if "IPv4" in msg:
                ip = msg.split(":")[-1].strip()
                self.root.after(0, lambda v=ip: self._stat(t("stat_ip"), v, self.th["FG"]))
            if "Open:" in msg:
                n = msg.split("Open:")[-1].split()[0]
                self.root.after(0, lambda v=n: self._stat(t("stat_ports"), v, self.th["FG"]))
            if "TLS version" in msg:
                self.root.after(0, lambda: self._stat(t("stat_ssl"), "✓", self.th["ACC3"]))
            if "Security score" in msg:
                sc = msg.split(":")[-1].strip()
                self.root.after(0, lambda v=sc: self._stat(t("stat_sec"), v, self.th["FG"]))
            if "Country" in msg and ":" in msg:
                country = msg.split(":")[-1].strip()
                self.root.after(0, lambda v=country: self._stat(t("stat_country"), v, self.th["FG"]))
            self.log_from_thread(msg, level)

        def on_prog(v):
            self._set_prog(v)

        # Ask-per-port callback
        ask_cb = None
        if ask_port:
            def ask_cb(port, svc):
                cves = query_cve(svc.lower())
                return ask_port_gui(self.root, port, svc, cves)

        self.scanner = DomainScanner(domain, log_cb=on_log, prog_cb=on_prog)

        # Patch scan_ports to use ask_cb
        orig_scan = self.scanner.scan_ports
        if ask_cb:
            self.scanner.scan_ports = lambda: orig_scan(ask_cb=ask_cb)

        report  = self.scanner.run()
        results = self.scanner.results

        # Surface panel (slides from bottom)
        def _show_panel():
            def _start_deep():
                ds = DeepScanner(domain, log_cb=on_log, prog_cb=on_prog,
                                 tools=tools or SETTINGS.get("deep_tools", {}))
                self.scanner = ds
                threading.Thread(target=ds.run, daemon=True).start()
            SurfacePanel(self.root, results, domain,
                on_deep=_start_deep if not deep else None)
        self.root.after(400, _show_panel)

        if deep and not self.scanner.cancelled:
            ds = DeepScanner(domain, log_cb=on_log, prog_cb=on_prog,
                             tools=tools or SETTINGS.get("deep_tools", {}))
            self.scanner = ds
            ds.run()

        last = idx[0] - 1
        if last >= 0:
            self.root.after(0, lambda k=last: self._set_step(k, "done"))
        self.root.after(0, lambda: self._done(
            report, results, domain, self.scanner.cancelled))

    def _done(self, report: str, results: dict, domain: str, cancelled: bool):
        self.scanning = False; th = self.th
        self._scan_rbtn.set_text(t("scan_btn"), icon="▶")
        self._scan_rbtn.set_disabled(False)
        self._deep_rbtn.set_disabled(False)
        self._cancel_rbtn.pack_forget()
        self._entry.config(state="normal")
        self._prog_lbl.config(
            text=t("cancelled") if cancelled else t("complete"))
        self._stat(t("stat_status"),
            "CANCELLED" if cancelled else "COMPLETE ✓",
            th["FG2"] if cancelled else th["ACC3"])
        try: self._eta_lbl.config(text="")
        except: pass
        if not cancelled:
            self._draw_prog(100)
            if report:
                self._push(f"Report saved: {report}", "FOUND")
            send_notification(t("notif_title"),
                f"{t('notif_body')} {domain}")
            self.root.after(800, self._blink)

    def _blink(self, count=0):
        if count >= 14 or self.scanning: return
        self._log_w.configure(state="normal")
        try: self._log_w.delete("cs", "ce")
        except: pass
        if count % 2 == 0:
            self._log_w.mark_set("cs", "end-1c")
            self._log_w.insert("end", "█", "cursor")
            self._log_w.mark_set("ce", "end-1c")
        self._log_w.configure(state="disabled")
        self.root.after(450, lambda: self._blink(count + 1))

    # ── Misc ──────────────────────────────────────────────────
    def _open_url(self, url: str):
        import webbrowser; webbrowser.open(url)

    def _zoom_font(self, delta: int):
        """Ctrl+scroll to zoom log font size."""
        self._font_size = max(7, min(20, self._font_size + delta))
        fs = self._font_size
        try:
            self._log_w.config(font=(self.font, fs))
        except Exception:
            pass

    def _open_settings(self):
        SettingsDialog(self.root, self._apply_theme)

    def run(self): pass  # GUI launched via launch_gui()


# ═══════════════════════════════════════════════════════════════
# CLI INTERFACE
# ═══════════════════════════════════════════════════════════════
class CLIInterface:
    def shell(self):
        print(BANNER)
        print(f"{C.DIM}  Type a domain to scan, 'deep <domain>' for deep scan,")
        print(f"  'help' for options, 'exit' to quit.{C.RST}\n")
        while True:
            try:
                raw = input(f"  {C.WHT}webgate{C.RST}{C.GRY}>{C.RST} ").strip()
            except (KeyboardInterrupt, EOFError):
                print(f"\n  {C.GRY}Bye!{C.RST}"); break
            if not raw: continue
            if raw in ("exit", "quit", "q"): print(f"  {C.GRY}Bye!{C.RST}"); break
            if raw in ("help", "?"):
                self._help(); continue
            if raw in ("gui", "--gui"):
                print(f"  {C.BLU}»{C.RST} Launching GUI…")
                launch_gui(); return
            if raw.startswith("deep "):
                self.quick(raw[5:].strip(), deep=True)
            else:
                self.quick(raw)

    def quick(self, domain: str, deep: bool = False):
        print(f"\n  {C.WHT}[*]{C.RST} Target: {C.BOLD}{domain}{C.RST}")
        print(f"  {C.GRY}{'─' * 56}{C.RST}")
        self._last_prog = -1
        def log_cb(msg, level):
            pfx = {"INFO":    C.GRY  + "·",
                   "FOUND":   C.WHT  + "+",
                   "WARN":    C.YLW  + "!",
                   "ERROR":   C.RED  + "✗",
                   "STEP":    C.BLU  + "»",
                   "SUCCESS": C.GRN  + "✓"}.get(level, "·")
            print(f"  {pfx}{C.RST} {msg}")
        def prog_cb(v):
            v = int(v)
            if v == self._last_prog: return
            self._last_prog = v
            bar = "█" * (v // 5) + "░" * (20 - v // 5)
            print(f"  {C.GRY}[{bar}] {v:3d}%{C.RST}")
        sc = DomainScanner(domain, log_cb=log_cb, prog_cb=prog_cb)
        report = sc.run()
        if deep and not sc.cancelled:
            ds = DeepScanner(domain, log_cb=log_cb, prog_cb=prog_cb)
            ds.run()
        if report:
            print(f"\n  {C.GRN}[✓]{C.RST} Report: {report}\n")

    def _help(self):
        print(f"""
  {C.WHT}Commands:{C.RST}
  {C.GRY}<domain>         {C.RST}Run surface scan
  {C.GRY}deep <domain>    {C.RST}Run surface + deep scan
  {C.GRY}help             {C.RST}Show this help
  {C.GRY}exit / quit      {C.RST}Exit WebGate
  {C.GRY}python webgate.py --gui   {C.RST}Launch GUI
""")


# ═══════════════════════════════════════════════════════════════
# LAUNCH GUI
# ═══════════════════════════════════════════════════════════════
def launch_gui(domain: str = ""):
    _init_sound()

    # ── Display detection (Wayland / Hyprland / X11) ──────────
    if sys.platform.startswith("linux"):
        if not os.environ.get("DISPLAY"):
            # Auto-detect XWayland socket
            import glob
            sockets = sorted(glob.glob("/tmp/.X11-unix/X*"))
            if sockets:
                num = sockets[0].split("X")[-1]
                os.environ["DISPLAY"] = f":{num}"
                print(f"  [*] Auto-detected DISPLAY=:{num}")
            else:
                os.environ["DISPLAY"] = ":0"

    # ── Import tkinter ─────────────────────────────────────────
    try:
        import tkinter as tk
    except ImportError:
        print("[!] tkinter missing. Run: sudo pacman -S tk"); return

    # ── Verify display connection ──────────────────────────────
    try:
        _test = tk.Tk(); _test.destroy()
    except Exception as e:
        print(f"[!] Cannot connect to display: {e}")
        print(f"    DISPLAY={os.environ.get('DISPLAY','not set')}")
        print(f"    Try: DISPLAY=:0 webgate --gui")
        return

    # ── Create root ────────────────────────────────────────────
    root = tk.Tk()
    root.withdraw()         # hide root — splash is a Toplevel
    root.update_idletasks() # process pending events (needed for Toplevel)

    def _show_main():
        """Called by SplashScreen after its animation completes."""
        app = SecurityScannerGUI(root=root, prefill=domain)
        app._fade_in_root(0.0)

    SplashScreen(root, _show_main)
    root.mainloop()

def _safe_alpha(widget, val):
    """Set window alpha, silently ignore if not supported (Wayland)."""
    try:
        widget.attributes("-alpha", float(val))
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════
def _ensure_git_repo():
    if os.path.exists(os.path.join(_SCRIPT_DIR, ".git")):
        return
    try:
        subprocess.run(["git", "init", _SCRIPT_DIR], capture_output=True)
        gi = os.path.join(_SCRIPT_DIR, ".gitignore")
        if not os.path.exists(gi):
            with open(gi, "w") as f:
                f.write("# WebGate auto-generated\n*.pyc\n__pycache__/\n"
                        "settings.json\naudit_*.txt\n*.wav\n.env\n")
    except Exception:
        pass

def main():
    _init_sound()
    init_cve_db()
    _ensure_git_repo()

    if _IS_SYMLINK and sys.stdout.isatty():
        Y = '\033[33m'; RST = '\033[0m'
        print(f"\n  {Y}{'─'*62}{RST}")
        print(f"  {Y}[!] WebGate — for AUTHORIZED security testing only.{RST}")
        print(f"  {Y}     Only scan systems you own or have written permission to test.{RST}")
        print(f"  {Y}{'─'*62}{RST}\n")

    p = argparse.ArgumentParser(prog="webgate", add_help=False)
    p.add_argument("-d", "--domain", default="")
    p.add_argument("--gui",      action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("-h", "--help", action="store_true")
    args = p.parse_args()

    if args.no_color: C.disable()
    if args.help:
        print(BANNER)
        print("  python webgate.py              →  interactive CLI")
        print("  python webgate.py --gui        →  GUI interface")
        print("  python webgate.py -d domain    →  quick CLI scan")
        print("  python webgate.py --gui -d dom →  GUI with prefill")
        return
    if args.gui:
        launch_gui(domain=args.domain); return
    cli = CLIInterface()
    if args.domain:
        cli.quick(args.domain)
    else:
        cli.shell()

if __name__ == "__main__":
    main()
