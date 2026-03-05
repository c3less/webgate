#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebGate v2.0  —  Domain Security Auditor
Created by c3less
https://github.com/c3less/webgate

CLI (default):  python webgate.py
GUI:            python webgate.py --gui
Quick scan:     python webgate.py -d example.com
"""

# ═══════════════════════════════════════════════════════════════
# IMPORTS
# ═══════════════════════════════════════════════════════════════

import sys, os, re, time, socket, ssl, json, threading, argparse
import subprocess, struct, wave, io, math, tempfile, atexit
import http.client
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

try:
    import whois;      WHOIS_OK = True
except ImportError:    WHOIS_OK = False
try:
    import dns.resolver, dns.exception; DNS_OK = True
except ImportError:    DNS_OK = False


# ═══════════════════════════════════════════════════════════════
# SETTINGS  (persisted to settings.json)
# ═══════════════════════════════════════════════════════════════

# All paths relative to script location, not CWD
_SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
_SETTINGS_FILE = os.path.join(_SCRIPT_DIR, "settings.json")
_REPORTS_DIR   = _SCRIPT_DIR   # reports saved alongside script
_IS_SYMLINK    = os.path.islink(os.path.abspath(sys.argv[0]))
_DEFAULT_SETTINGS = {
    "lang":         "EN",
    "theme":        "dark",
    "sound":        True,
    "transparency": 0.94,
    "custom_theme": {}
}

def load_settings() -> dict:
    try:
        with open(_SETTINGS_FILE) as f:
            s = json.load(f)
            return {**_DEFAULT_SETTINGS, **s}
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
# TRANSLATIONS
# ═══════════════════════════════════════════════════════════════

TR = {
"EN": {
    "app_sub":      "Domain Security Auditor",
    "credit":       "Created by c3less",
    "target_lbl":   "TARGET DOMAIN",
    "scan_btn":     "START SCAN",
    "deep_btn":     "DEEP SCAN",
    "cancel_btn":   "CANCEL",
    "settings_btn": "⚙",
    "scanning":     "SCANNING...",
    "ready":        "READY",
    "complete":     "COMPLETE",
    "cancelled":    "CANCELLED",
    "log_hdr":      "SCAN OUTPUT",
    "status_hdr":   "SCAN STATUS",
    "steps_hdr":    "STEPS",
    "stat_status":  "STATUS",
    "stat_target":  "TARGET",
    "stat_ip":      "IP",
    "stat_ports":   "PORTS",
    "stat_ssl":     "SSL",
    "stat_sec":     "SEC",
    "stat_time":    "TIME",
    "steps": ["DNS Resolution","DNS Records","WHOIS","HTTP Headers",
               "SSL / TLS","Port Scan","Report"],
    "deep_steps": ["Web Crawl","XSS Check","SQLi Surface","Dir Enum","WhatWeb"],
    "summary_title":"SCAN SUMMARY",
    "summary_ip":   "IP Address",
    "summary_ssl":  "SSL / TLS",
    "summary_open": "Open Ports",
    "summary_sec":  "Sec Headers",
    "summary_risk": "Risk Level",
    "risk_low":     "LOW",
    "risk_medium":  "MEDIUM",
    "risk_high":    "HIGH",
    "risk_critical":"CRITICAL",
    "settings_title":"Settings",
    "lang_label":   "Language",
    "theme_label":  "Theme",
    "sound_label":  "Typing Sound",
    "alpha_label":  "Transparency",
    "save_btn":     "Save",
    "close_btn":    "Close",
    "custom_btn":   "Custom Colors",
    "disc_title":   "Deep Scan — Educational Use Only",
    "disc_body":    (
        "DISCLAIMER — READ CAREFULLY\n\n"
        "WebGate Deep Scan integrates advanced reconnaissance tools "
        "(SQLMap, WhatWeb, custom XSS probes). These tools may:\n\n"
        "  • Send multiple automated requests to the target server\n"
        "  • Trigger web application firewalls (WAF)\n"
        "  • Leave traces in server access logs\n"
        "  • Violate terms of service of the target\n\n"
        "This tool is provided STRICTLY for:\n"
        "  ✓ Educational and research purposes\n"
        "  ✓ Authorized penetration testing\n"
        "  ✓ Testing systems you own or have written permission to test\n\n"
        "UNAUTHORIZED use against systems you do not own or have "
        "explicit permission to test is ILLEGAL and may result in "
        "criminal prosecution under computer fraud laws worldwide.\n\n"
        "By clicking 'I AGREE' you accept full legal responsibility "
        "for your actions and confirm you have proper authorization."
    ),
    "disc_agree":   "I AGREE — I have authorization to test this target",
    "disc_deny":    "CANCEL",
    "notif_title":  "WebGate — Scan Complete",
    "notif_body":   "Security audit finished for",
    "enter_domain": "Please enter a target domain.",
    "placeholder":  "example.com",
    "init_msg":     "WebGate initialized — enter a domain and press START SCAN",
    "missing":      "Missing optional modules",
    "install_hint": "Run: pip install",
},
"RU": {
    "app_sub":      "Аудитор безопасности доменов",
    "credit":       "Создано c3less",
    "target_lbl":   "ЦЕЛЕВОЙ ДОМЕН",
    "scan_btn":     "НАЧАТЬ СКАН",
    "deep_btn":     "ГЛУБОКИЙ СКАН",
    "cancel_btn":   "ОТМЕНА",
    "settings_btn": "⚙",
    "scanning":     "СКАНИРОВАНИЕ...",
    "ready":        "ГОТОВ",
    "complete":     "ЗАВЕРШЕНО",
    "cancelled":    "ОТМЕНЕНО",
    "log_hdr":      "ВЫВОД СКАНА",
    "status_hdr":   "СТАТУС СКАНА",
    "steps_hdr":    "ШАГИ",
    "stat_status":  "СТАТУС",
    "stat_target":  "ЦЕЛЬ",
    "stat_ip":      "IP",
    "stat_ports":   "ПОРТЫ",
    "stat_ssl":     "SSL",
    "stat_sec":     "ЗАЩ",
    "stat_time":    "ВРЕМЯ",
    "steps": ["DNS Резолюция","DNS Записи","WHOIS","HTTP Заголовки",
               "SSL / TLS","Скан портов","Отчёт"],
    "deep_steps": ["Краулинг","Проверка XSS","SQLi поверх.","Перебор директорий","WhatWeb"],
    "summary_title":"СВОДКА СКАНА",
    "summary_ip":   "IP адрес",
    "summary_ssl":  "SSL / TLS",
    "summary_open": "Открытые порты",
    "summary_sec":  "Заголовки безопасности",
    "summary_risk": "Уровень риска",
    "risk_low":     "НИЗКИЙ",
    "risk_medium":  "СРЕДНИЙ",
    "risk_high":    "ВЫСОКИЙ",
    "risk_critical":"КРИТИЧЕСКИЙ",
    "settings_title":"Настройки",
    "lang_label":   "Язык",
    "theme_label":  "Тема",
    "sound_label":  "Звук печати",
    "alpha_label":  "Прозрачность",
    "save_btn":     "Сохранить",
    "close_btn":    "Закрыть",
    "custom_btn":   "Свои цвета",
    "disc_title":   "Глубокий скан — только для обучения",
    "disc_body":    (
        "ОТКАЗ ОТ ОТВЕТСТВЕННОСТИ — ПРОЧТИТЕ ВНИМАТЕЛЬНО\n\n"
        "Глубокий скан WebGate использует продвинутые инструменты "
        "(SQLMap, WhatWeb, XSS-зонды). Эти инструменты могут:\n\n"
        "  • Отправлять множество автоматических запросов к серверу\n"
        "  • Активировать файрволы веб-приложений (WAF)\n"
        "  • Оставлять следы в логах сервера\n"
        "  • Нарушать условия использования сервиса\n\n"
        "Инструмент предназначен ИСКЛЮЧИТЕЛЬНО для:\n"
        "  ✓ Образовательных и исследовательских целей\n"
        "  ✓ Авторизованного тестирования на проникновение\n"
        "  ✓ Тестирования систем, которыми вы владеете\n\n"
        "НЕСАНКЦИОНИРОВАННОЕ использование против систем, на тестирование "
        "которых у вас нет разрешения, является НЕЗАКОННЫМ и может повлечь "
        "уголовную ответственность.\n\n"
        "Нажимая 'Я СОГЛАСЕН' вы принимаете полную юридическую "
        "ответственность и подтверждаете наличие разрешения."
    ),
    "disc_agree":   "Я СОГЛАСЕН — у меня есть разрешение на тестирование",
    "disc_deny":    "ОТМЕНА",
    "notif_title":  "WebGate — Скан завершён",
    "notif_body":   "Аудит безопасности завершён для",
    "enter_domain": "Введите целевой домен.",
    "placeholder":  "example.com",
    "init_msg":     "WebGate инициализирован — введите домен и нажмите НАЧАТЬ СКАН",
    "missing":      "Отсутствуют модули",
    "install_hint": "Установите: pip install",
},
}

def t(key: str) -> str:
    return TR.get(SETTINGS["lang"], TR["EN"]).get(key, key)


# ═══════════════════════════════════════════════════════════════
# THEMES
# ═══════════════════════════════════════════════════════════════

THEMES = {
"dark": {
    "BG":       "#080808", "BG2":     "#101010", "BG3":     "#181818",
    "BORDER":   "#2a2a2a", "BORDER2": "#444444", "BORDER3": "#666666",
    "FG":       "#d0d0d0", "FG2":     "#888888", "FG3":     "#444444",
    "WHITE":    "#ffffff", "OFFWHT":  "#eeeeee",
    "BTN_BG":   "#d8d8d8", "BTN_FG":  "#080808",
    "BTN_HOV":  "#ffffff", "BTN_DIS_BG": "#282828", "BTN_DIS_FG": "#555555",
    "LOGO_CLR": "#ffffff", "LOGO_SHD": "#333333",
    "LOG_CLR": {"INFO":"#666666","FOUND":"#cccccc","WARN":"#aaaaaa",
                "ERROR":"#ffffff","STEP":"#ffffff","SUCCESS":"#ffffff"},
},
"light": {
    "BG":       "#f4f4f4", "BG2":     "#ececec", "BG3":     "#e0e0e0",
    "BORDER":   "#cccccc", "BORDER2": "#999999", "BORDER3": "#666666",
    "FG":       "#1a1a1a", "FG2":     "#555555", "FG3":     "#aaaaaa",
    "WHITE":    "#000000", "OFFWHT":  "#1a1a1a",
    "BTN_BG":   "#1a1a1a", "BTN_FG":  "#f4f4f4",
    "BTN_HOV":  "#333333", "BTN_DIS_BG": "#cccccc", "BTN_DIS_FG": "#999999",
    "LOGO_CLR": "#111111", "LOGO_SHD": "#aaaaaa",
    "LOG_CLR": {"INFO":"#888888","FOUND":"#111111","WARN":"#555555",
                "ERROR":"#000000","STEP":"#000000","SUCCESS":"#000000"},
},
"midnight": {
    "BG":       "#0a0818", "BG2":     "#110d22", "BG3":     "#18142e",
    "BORDER":   "#2a2240", "BORDER2": "#4a3880", "BORDER3": "#7a60cc",
    "FG":       "#c8c0e8", "FG2":     "#8878b8", "FG3":     "#443860",
    "WHITE":    "#ffffff", "OFFWHT":  "#e0d8ff",
    "BTN_BG":   "#d0c8f0", "BTN_FG":  "#0a0818",
    "BTN_HOV":  "#ffffff", "BTN_DIS_BG": "#1e1838", "BTN_DIS_FG": "#5a4888",
    "LOGO_CLR": "#e0d8ff", "LOGO_SHD": "#2a2050",
    "LOG_CLR": {"INFO":"#5a4888","FOUND":"#c0b8e8","WARN":"#9888c8",
                "ERROR":"#ffffff","STEP":"#e0d8ff","SUCCESS":"#c0f0c8"},
},
}

def get_theme() -> dict:
    name = SETTINGS.get("theme", "dark")
    base = THEMES.get(name, THEMES["dark"]).copy()
    if name == "custom" and SETTINGS.get("custom_theme"):
        base.update(SETTINGS["custom_theme"])
    return base


# ═══════════════════════════════════════════════════════════════
# SOUND  (short typing click via WAV + aplay/afplay/winsound)
# ═══════════════════════════════════════════════════════════════

_CLICK_FILE: str = ""
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
                amp = int(4500 * (1 - t_ / 0.018) * math.sin(2 * math.pi * 2200 * t_))
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
    if now - _last_sound < 0.04:   # throttle — max 25/s
        return
    _last_sound = now
    try:
        if sys.platform.startswith("linux"):
            subprocess.Popen(["aplay", "-q", _CLICK_FILE],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif sys.platform == "darwin":
            subprocess.Popen(["afplay", _CLICK_FILE])
        elif sys.platform == "win32":
            import winsound
            threading.Thread(target=winsound.PlaySound,
                args=(_CLICK_FILE, winsound.SND_FILENAME | winsound.SND_ASYNC),
                daemon=True).start()
    except Exception:
        pass

def send_notification(title: str, body: str):
    try:
        if sys.platform.startswith("linux"):
            subprocess.Popen(["notify-send", title, body,
                "--icon=dialog-information", "--expire-time=6000"])
        elif sys.platform == "darwin":
            script = f'display notification "{body}" with title "{title}"'
            subprocess.Popen(["osascript", "-e", script])
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════
# TERMINAL COLORS (CLI)
# ═══════════════════════════════════════════════════════════════

class C:
    RST='\033[0m'; BOLD='\033[1m'; DIM='\033[2m'
    WHT='\033[97m'; GRY='\033[90m'; LGRY='\033[37m'
    @classmethod
    def disable(cls):
        for a in list(vars(cls)):
            if not a.startswith('_') and isinstance(getattr(cls,a),str):
                setattr(cls,a,'')

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
  │  Domain Security Auditor    │   v2.0   │   by c3less    │
  │  DNS · WHOIS · HTTP · SSL · Ports · DeepScan · Reports  │
  └─────────────────────────────────────────────────────────┘
  python webgate.py --gui   →  launch graphical interface
{C.RST}"""


# ═══════════════════════════════════════════════════════════════
# CORE SCANNER
# ═══════════════════════════════════════════════════════════════

class DomainScanner:
    PORTS = {
        21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
        110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",587:"SMTPS",
        993:"IMAPS",995:"POP3S",3306:"MySQL",3389:"RDP",
        5432:"PostgreSQL",6379:"Redis",8080:"HTTP-Alt",
        8443:"HTTPS-Alt",8888:"Dev",27017:"MongoDB",
    }
    SECURITY_HEADERS = [
        "Strict-Transport-Security","Content-Security-Policy",
        "X-Frame-Options","X-Content-Type-Options","X-XSS-Protection",
        "Referrer-Policy","Permissions-Policy",
    ]

    def __init__(self, domain:str, log_cb=None, prog_cb=None):
        self.domain    = re.sub(r'^https?://','',domain.strip().lower()).split('/')[0].split('?')[0]
        self.log_cb    = log_cb  or (lambda m,l: print(f"[{l}] {m}"))
        self.prog_cb   = prog_cb or (lambda v: None)
        self.results   = {}
        self.log_lines = []
        self.cancelled = False
        self.start_time= None

    def _log(self, msg:str, level:str="INFO"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_lines.append(f"[{ts}] {msg}")
        self.log_cb(msg, level)

    def _prog(self, v:int): self.prog_cb(min(100, max(0, int(v))))

    # ── Step 1: DNS Resolution ──────────────────────────────────
    def resolve_dns(self):
        self._log("Resolving domain to IP address...", "STEP"); self._prog(4)
        r = {"ips":[], "ipv6":[], "reverse_dns":"N/A", "error":None}
        try:
            info = socket.getaddrinfo(self.domain, None)
            seen = {}
            for i in info:
                ip, fam = i[4][0], i[0]
                if ip not in seen:
                    seen[ip]=1
                    (r["ips"] if fam==socket.AF_INET else r["ipv6"]).append(ip)
            for ip in r["ips"]:  self._log(f"  IPv4            : {ip}", "FOUND")
            for ip in r["ipv6"]: self._log(f"  IPv6            : {ip}", "FOUND")
            tgt = r["ips"][0] if r["ips"] else (r["ipv6"][0] if r["ipv6"] else None)
            if tgt:
                try:
                    rdns = socket.gethostbyaddr(tgt)[0]
                    r["reverse_dns"] = rdns
                    self._log(f"  Reverse DNS     : {rdns}", "FOUND")
                except: self._log("  Reverse DNS     : N/A", "WARN")
        except socket.gaierror as e:
            r["error"] = str(e)
            self._log(f"  Cannot resolve: {e}", "ERROR")
        self.results["resolution"] = r; self._prog(14)

    # ── Step 2: DNS Records ─────────────────────────────────────
    def check_dns_records(self):
        self._log("Checking DNS records (A,AAAA,MX,NS,TXT,CNAME,SOA)...", "STEP"); self._prog(18)
        r = {}
        if DNS_OK:
            for rtype in ["A","AAAA","MX","NS","TXT","CNAME","SOA"]:
                try:
                    ans = dns.resolver.resolve(self.domain, rtype, lifetime=6)
                    records = [str(a) for a in ans]
                    r[rtype] = records
                    for rec in records: self._log(f"  {rtype:<6}          : {rec[:74]}", "FOUND")
                except dns.resolver.NXDOMAIN:
                    self._log("  NXDOMAIN — domain not found", "ERROR"); break
                except (dns.resolver.NoAnswer, dns.exception.Timeout): pass
                except Exception as e: self._log(f"  {rtype}: {str(e)[:60]}", "WARN")
        else:
            try:
                ip = socket.gethostbyname(self.domain)
                r["A"]=[ip]; self._log(f"  A               : {ip}", "FOUND")
                self._log("  Tip: pip install dnspython for full DNS analysis", "WARN")
            except Exception as e: self._log(f"  DNS failed: {e}", "ERROR")
        self.results["dns_records"] = r; self._prog(28)

    # ── Step 3: WHOIS ───────────────────────────────────────────
    def get_whois(self):
        self._log("Retrieving WHOIS information...", "STEP"); self._prog(31)
        r = {}
        if not WHOIS_OK:
            self._log("  Tip: pip install python-whois", "WARN")
            r["error"]="module missing"; self.results["whois"]=r; self._prog(44); return
        try:
            w = whois.whois(self.domain)
            def sg(a):
                v=getattr(w,a,None); return v[0] if isinstance(v,list) else v
            for k,lbl in [("registrar","Registrar"),("creation_date","Registered"),
                          ("expiration_date","Expires"),("org","Organization"),
                          ("country","Country"),("emails","Contact"),("dnssec","DNSSEC")]:
                v=sg(k)
                if v: r[k]=str(v); self._log(f"  {lbl:<16} : {str(v)[:62]}", "FOUND")
            exp=sg("expiration_date")
            if exp and hasattr(exp,"date"):
                days=(exp-datetime.now()).days; r["days_until_expiry"]=days
                if   days<0:   self._log(f"  Domain EXPIRED {abs(days)} days ago!", "ERROR")
                elif days<30:  self._log(f"  Expires in {days} days — URGENT", "WARN")
                elif days<90:  self._log(f"  Expires in {days} days", "WARN")
                else:          self._log(f"  Expires in     : {days} days", "INFO")
        except Exception as e:
            r["error"]=str(e); self._log(f"  WHOIS failed: {str(e)[:100]}", "ERROR")
        self.results["whois"]=r; self._prog(44)

    # ── Step 4: HTTP Headers ────────────────────────────────────
    def analyze_http_headers(self):
        self._log("Analyzing HTTP headers and security posture...", "STEP"); self._prog(48)
        r={"status_code":None,"server":None,"protocol":None,"headers":{},
           "redirects_to_https":False,"technologies":[],"security_headers":{},"score":0}
        raw={}
        for proto in ("https","http"):
            url=f"{proto}://{self.domain}"
            try:
                req=Request(url,headers={"User-Agent":"Mozilla/5.0 (webgate/2.0 SecurityAudit)"})
                with urlopen(req,timeout=10) as resp:
                    raw=dict(resp.headers); r["status_code"]=resp.status
                    r["protocol"]=proto.upper()
                    r["redirects_to_https"]=resp.url.startswith("https://")
                    self._log(f"  Status          : {resp.status} ({proto.upper()})", "FOUND")
                    if resp.url!=url: self._log(f"  Redirect        : {resp.url[:70]}", "FOUND")
                    break
            except HTTPError as e:
                raw=dict(e.headers) if hasattr(e,"headers") else {}
                r["status_code"]=e.code; r["protocol"]=proto.upper()
                self._log(f"  Status          : {e.code} ({proto.upper()})", "FOUND"); break
            except Exception as e: self._log(f"  {proto.upper()} fail: {str(e)[:65]}", "WARN")
        r["headers"]=raw
        for h,lbl in [("Server","Server"),("X-Powered-By","Backend"),
                      ("X-Generator","Generator")]:
            if h in raw:
                v=raw[h]; r["technologies"].append(f"{lbl}: {v}")
                if h=="Server": r["server"]=v
                self._log(f"  {lbl:<16} : {v[:60]}", "FOUND")
        if not r["redirects_to_https"] and r["protocol"]=="HTTP":
            self._log("  HTTPS redirect  : NOT enforced", "WARN")
        self._log("  Security headers audit:", "INFO")
        score=0
        for h in self.SECURITY_HEADERS:
            ok=h in raw; r["security_headers"][h]=ok
            self._log(f"    {'✓' if ok else '✗'} {h}", "FOUND" if ok else "WARN")
            if ok: score+=1
        r["score"]=score
        self._log(f"  Security score  : {score}/{len(self.SECURITY_HEADERS)}", "INFO")
        self.results["http"]=r; self._prog(60)

    # ── Step 5: SSL ─────────────────────────────────────────────
    def check_ssl(self):
        self._log("Checking SSL/TLS certificate...", "STEP"); self._prog(63)
        r={"available":False,"version":None,"cipher":None,"bits":None,
           "common_name":None,"issuer":None,"not_after":None,
           "days_until_expiry":None,"san":[],"self_signed":False,"wildcard":False,"error":None}
        try:
            ctx=ssl.create_default_context()
            with socket.create_connection((self.domain,443),timeout=10) as raw:
                with ctx.wrap_socket(raw,server_hostname=self.domain) as ss:
                    r["available"]=True; r["version"]=ss.version()
                    c=ss.cipher()
                    if c: r["cipher"]=c[0]; r["bits"]=c[2]
                    cert=ss.getpeercert()
                    subj=dict(x[0] for x in cert.get("subject",[]))
                    iss =dict(x[0] for x in cert.get("issuer",[]))
                    r["common_name"]=subj.get("commonName","N/A")
                    r["issuer"]=iss.get("organizationName","N/A")
                    r["not_after"]=cert.get("notAfter","N/A")
                    r["self_signed"]=subj==iss
                    r["wildcard"]=r["common_name"].startswith("*.")
                    self._log(f"  TLS version     : {r['version']}", "FOUND")
                    self._log(f"  Cipher          : {r['cipher']} ({r['bits']} bits)", "FOUND")
                    self._log(f"  Common name     : {r['common_name']}", "FOUND")
                    self._log(f"  Issuer          : {r['issuer']}", "FOUND")
                    if r["self_signed"]: self._log("  Self-signed cert detected!", "WARN")
                    try:
                        exp=datetime.strptime(r["not_after"],"%b %d %H:%M:%S %Y %Z")
                        days=(exp-datetime.now()).days; r["days_until_expiry"]=days
                        self._log(f"  Valid until     : {r['not_after']}", "FOUND")
                        if   days<0:  self._log(f"  Certificate EXPIRED!", "ERROR")
                        elif days<15: self._log(f"  Expires in {days}d — CRITICAL", "ERROR")
                        elif days<30: self._log(f"  Expires in {days}d", "WARN")
                        else:         self._log(f"  Days remaining  : {days}", "FOUND")
                    except: pass
                    sans=cert.get("subjectAltName",[])
                    r["san"]=[v for _,v in sans]
                    self._log(f"  Alt names (SAN) : {len(sans)} entries", "INFO")
                    for _,sv in sans[:8]: self._log(f"    · {sv}", "INFO")
                    if len(sans)>8: self._log(f"    ... +{len(sans)-8} more","INFO")
        except ssl.SSLCertVerificationError as e:
            r["error"]=str(e); self._log(f"  Cert verify failed: {str(e)[:80]}", "ERROR")
        except ConnectionRefusedError:
            r["error"]="Port 443 closed"; self._log("  Port 443 closed — no HTTPS", "WARN")
        except socket.timeout:
            r["error"]="timeout"; self._log("  SSL connection timed out", "ERROR")
        except Exception as e:
            r["error"]=str(e); self._log(f"  SSL error: {str(e)[:100]}", "ERROR")
        self.results["ssl"]=r; self._prog(76)

    # ── Step 6: Port Scan ───────────────────────────────────────
    def scan_ports(self):
        self._log("Scanning common ports...", "STEP"); self._prog(79)
        r={"target_ip":None,"open":[],"closed":[],"filtered":[]}
        try:    r["target_ip"]=socket.gethostbyname(self.domain)
        except: r["target_ip"]=self.domain
        tgt=r["target_ip"]; total=len(self.PORTS)
        for i,(port,svc) in enumerate(self.PORTS.items()):
            if self.cancelled: break
            try:
                s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                s.settimeout(1.2); res=s.connect_ex((tgt,port)); s.close()
                if res==0:
                    banner=self._banner(tgt,port)
                    r["open"].append({"port":port,"service":svc,"banner":banner})
                    self._log(f"  {port:5}/tcp  OPEN    {svc:<14}{'  ['+banner[:28]+']' if banner else ''}", "FOUND")
                else: r["closed"].append(port)
            except socket.timeout: r["filtered"].append(port)
            except: r["closed"].append(port)
            self._prog(79+int((i+1)/total*11))
        self._log(f"  Open: {len(r['open'])}  Closed: {len(r['closed'])}  Filtered: {len(r['filtered'])}", "INFO")
        self.results["ports"]=r; self._prog(90)

    def _banner(self, ip:str, port:int) -> str:
        try:
            s=socket.socket(); s.settimeout(0.8); s.connect((ip,port))
            if port in (80,8080): s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            raw=s.recv(256).decode("utf-8",errors="ignore").strip(); s.close()
            return " ".join(raw.split())[:50]
        except: return ""

    # ── Step 7: Report ──────────────────────────────────────────
    def generate_report(self) -> str:
        self._log("Generating security report...", "STEP"); self._prog(93)
        ts=datetime.now(); safe=re.sub(r"[^\w\-.]","_",self.domain)
        fn=os.path.join(_REPORTS_DIR, f"audit_{safe}_{ts.strftime('%Y%m%d_%H%M%S')}.txt")
        elapsed=f"{time.time()-self.start_time:.1f}s" if self.start_time else ""
        W=72; lines=[]
        def rule(c="═"): return c*W
        def sec(s): lines.extend(["",rule("─"),f"  {s}",rule("─")])

        lines+=[rule("═"),"  WEBGATE — DOMAIN SECURITY AUDIT REPORT",
                "  Created by c3less  │  webgate v2.0",rule("─"),
                f"  Target    : {self.domain}",
                f"  Date/Time : {ts.strftime('%Y-%m-%d %H:%M:%S')}"]
        if elapsed: lines.append(f"  Duration  : {elapsed}")
        lines.append(rule("═"))

        sec("1. DNS RESOLUTION")
        r=self.results.get("resolution",{})
        for ip in r.get("ips",[]): lines.append(f"  IPv4          : {ip}")
        for ip in r.get("ipv6",[]): lines.append(f"  IPv6          : {ip}")
        lines.append(f"  Reverse DNS   : {r.get('reverse_dns','N/A')}")

        sec("2. DNS RECORDS")
        for rtype,recs in self.results.get("dns_records",{}).items():
            if rtype=="error": continue
            for rec in (recs if isinstance(recs,list) else [recs]):
                lines.append(f"  {rtype:<8} : {str(rec)[:62]}")

        sec("3. WHOIS")
        for k,v in self.results.get("whois",{}).items():
            if k!="error": lines.append(f"  {k.replace('_',' ').title():<20}: {str(v)[:50]}")

        sec("4. HTTP")
        h=self.results.get("http",{})
        lines+=[f"  Status        : {h.get('status_code','N/A')}",
                f"  Server        : {h.get('server','Not disclosed')}",
                f"  HTTPS Redir   : {'Yes' if h.get('redirects_to_https') else 'No'}",
                f"  Sec Score     : {h.get('score',0)}/7","","  Security Headers:"]
        for hdr,ok in h.get("security_headers",{}).items():
            lines.append(f"    {'✓' if ok else '✗'}  {hdr}")

        sec("5. SSL/TLS")
        s=self.results.get("ssl",{})
        if s.get("available"):
            for k,lbl in [("version","TLS"),("cipher","Cipher"),("common_name","CN"),
                          ("issuer","Issuer"),("not_after","Expires"),("days_until_expiry","Days left")]:
                v=s.get(k)
                if v is not None: lines.append(f"  {lbl:<14}: {v}")
        else: lines.append(f"  Not available: {s.get('error','unknown')}")

        sec("6. PORTS")
        p=self.results.get("ports",{})
        lines.append(f"  Target IP     : {p.get('target_ip','N/A')}")
        for po in p.get("open",[]):
            lines.append(f"  {po['port']:5}/tcp  OPEN  {po['service']:<14} {(po.get('banner') or '')[:20]}")
        if not p.get("open"): lines.append("  No open ports found")

        sec("7. RISK SUMMARY")
        risks=self._build_risks()
        if risks:
            for sev,det in risks: lines.append(f"  [{sev:<8}] {det}")
        else: lines.append("  [OK] No critical risks found")

        sec("8. SCAN LOG")
        for l in self.log_lines: lines.append(f"  {l}")
        lines+=["",rule("═"),"  END OF REPORT — webgate by c3less",rule("═")]

        try:
            with open(fn,"w",encoding="utf-8") as f: f.write("\n".join(lines))
            self._log(f"  Saved: {fn}", "FOUND")
        except Exception as e: self._log(f"  Save failed: {e}", "ERROR")
        self.results["report_file"]=fn; self._prog(100); return fn

    def _build_risks(self) -> list:
        risks=[]; s=self.results.get("ssl",{})
        if not s.get("available"):  risks.append(("HIGH","No HTTPS on port 443"))
        if s.get("self_signed"):    risks.append(("HIGH","Self-signed certificate"))
        d=s.get("days_until_expiry")
        if d is not None:
            if d<0:   risks.append(("CRITICAL",f"SSL EXPIRED {abs(d)}d ago"))
            elif d<15:risks.append(("HIGH",f"SSL expires in {d} days"))
            elif d<30:risks.append(("MEDIUM",f"SSL expires in {d} days"))
        sc=self.results.get("http",{}).get("score",0)
        if sc<3: risks.append(("HIGH",f"Poor security headers ({sc}/7)"))
        elif sc<5: risks.append(("MEDIUM",f"Incomplete security headers ({sc}/7)"))
        if not self.results.get("http",{}).get("redirects_to_https"):
            risks.append(("MEDIUM","HTTP→HTTPS redirect not enforced"))
        danger={"Telnet","FTP","RDP","SMB"}; dbs={"MySQL","PostgreSQL","MongoDB","Redis"}
        for po in self.results.get("ports",{}).get("open",[]):
            if po["service"] in danger: risks.append(("HIGH",f"Dangerous port: {po['port']}/{po['service']}"))
            elif po["service"] in dbs:  risks.append(("HIGH",f"Database exposed: {po['port']}/{po['service']}"))
        return risks

    def run(self) -> str | None:
        self.start_time=time.time()
        self._log(f"Starting audit: {self.domain}", "INFO")
        self._log("─"*52,"INFO")
        for step in [self.resolve_dns,self.check_dns_records,self.get_whois,
                     self.analyze_http_headers,self.check_ssl,self.scan_ports,self.generate_report]:
            if self.cancelled: self._log("Cancelled.","WARN"); return None
            try: step()
            except Exception as e: self._log(f"Step error: {e}","ERROR")
        elapsed=time.time()-self.start_time
        self._log("─"*52,"INFO"); self._log(f"SCAN COMPLETE  [{elapsed:.1f}s]","SUCCESS")
        return self.results.get("report_file")


# ═══════════════════════════════════════════════════════════════
# DEEP SCANNER  (educational / authorized use only)
# ═══════════════════════════════════════════════════════════════

class DeepScanner:
    """
    Surface-level deep scan: web crawl, XSS probe, SQLi detect,
    directory enum, WhatWeb fingerprinting, SQLMap light.
    All external tools are optional — graceful fallback if absent.
    """
    XSS_PAYLOADS = [
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        "';alert(String.fromCharCode(88,83,83))//",
        '<svg onload=alert(1)>',
    ]
    COMMON_DIRS = [
        "admin","login","wp-admin","phpmyadmin","dashboard","api",
        "backup","config","uploads","files","static","assets",
        ".env","robots.txt","sitemap.xml","server-status",
    ]
    SQLI_PAYLOADS = ["'","\"","' OR '1'='1","1; DROP TABLE users--"]

    def __init__(self, domain:str, log_cb=None, prog_cb=None):
        self.domain  = domain
        self.log_cb  = log_cb  or print
        self.prog_cb = prog_cb or (lambda v: None)
        self.results = {"xss":[],"sqli":[],"dirs":[],"whatweb":None,"sqlmap":None}
        self.cancelled = False
        self.base_url = f"http://{domain}"

    def _log(self, m, l="INFO"): self.log_cb(m, l)
    def _prog(self, v):          self.prog_cb(min(100, int(v)))

    # ── 1: Crawl & collect URLs/forms ──────────────────────────
    def crawl(self) -> list:
        self._log("Web crawl — collecting URLs and forms...", "STEP"); self._prog(5)
        urls=[self.base_url]
        found=[]
        try:
            req=Request(self.base_url, headers={"User-Agent":"Mozilla/5.0 (webgate)"})
            with urlopen(req, timeout=10) as resp:
                body=resp.read().decode("utf-8","ignore")
            # Extract href links
            for m in re.finditer(r'href=["\']([^"\']+)["\']', body, re.I):
                href=m.group(1)
                if href.startswith("http"):
                    if self.domain in href: urls.append(href)
                elif href.startswith("/"):
                    urls.append(f"{self.base_url}{href}")
            # Extract forms + action URLs
            for m in re.finditer(r'<form[^>]*action=["\']([^"\']+)["\']', body, re.I):
                action=m.group(1)
                if not action.startswith("http"):
                    action=f"{self.base_url}/{action.lstrip('/')}"
                found.append(action)
            urls=list(dict.fromkeys(urls))[:20]  # dedupe, cap at 20
            self._log(f"  Found {len(urls)} URLs, {len(found)} forms", "FOUND")
        except Exception as e: self._log(f"  Crawl error: {e}", "WARN")
        self._prog(18)
        return list(dict.fromkeys(urls+found))

    # ── 2: XSS probe ───────────────────────────────────────────
    def check_xss(self, urls:list):
        self._log("XSS reflection check — probing URLs with payloads...", "STEP"); self._prog(22)
        vuln=[]
        for url in urls[:8]:
            for payload in self.XSS_PAYLOADS[:2]:
                if self.cancelled: return
                test_url=f"{url}{'&' if '?' in url else '?'}q={payload}"
                try:
                    req=Request(test_url, headers={"User-Agent":"Mozilla/5.0"})
                    with urlopen(req, timeout=6) as r:
                        body=r.read().decode("utf-8","ignore")
                    if payload.lower() in body.lower():
                        vuln.append({"url":url,"payload":payload,"type":"Reflected XSS"})
                        self._log(f"  [!!] XSS reflected: {url[:60]}", "ERROR")
                    else: self._log(f"  OK  {url[:55]}", "INFO")
                except: pass
        if not vuln: self._log("  No reflected XSS found in probed URLs", "FOUND")
        self.results["xss"]=vuln; self._prog(38)

    # ── 3: SQLi surface detection ───────────────────────────────
    def check_sqli(self, urls:list):
        self._log("SQLi surface detection — error-based probe...", "STEP"); self._prog(42)
        errors=["sql syntax","mysql_fetch","ORA-","PG::","sqlite3","ODBC Driver","Unclosed"]
        vuln=[]
        for url in urls[:6]:
            if "?" not in url: continue
            if self.cancelled: return
            for p in self.SQLI_PAYLOADS[:2]:
                test=re.sub(r'=([^&]*)',f'={p}',url,count=1)
                try:
                    req=Request(test, headers={"User-Agent":"Mozilla/5.0"})
                    with urlopen(req, timeout=6) as r:
                        body=r.read().decode("utf-8","ignore")
                    for err in errors:
                        if err.lower() in body.lower():
                            vuln.append({"url":url,"indicator":err})
                            self._log(f"  [!!] SQLi indicator '{err}': {url[:50]}", "ERROR")
                except: pass
        if not vuln: self._log("  No SQLi errors detected on surface", "FOUND")
        self.results["sqli"]=vuln; self._prog(55)

    # ── 4: Directory enumeration ────────────────────────────────
    def dir_enum(self):
        self._log("Directory/file enumeration (common paths)...", "STEP"); self._prog(58)
        found=[]
        total=len(self.COMMON_DIRS)
        for i,d in enumerate(self.COMMON_DIRS):
            if self.cancelled: break
            url=f"{self.base_url}/{d}"
            try:
                req=Request(url, headers={"User-Agent":"Mozilla/5.0"})
                with urlopen(req, timeout=5) as r:
                    status=r.status
            except HTTPError as e: status=e.code
            except: status=0
            if status in (200,301,302,403):
                found.append({"path":d,"status":status})
                self._log(f"  {status}  /{d}", "FOUND" if status==200 else "WARN")
            self._prog(58+int((i+1)/total*12))
        self._log(f"  Found {len(found)} accessible paths", "INFO")
        self.results["dirs"]=found; self._prog(72)

    # ── 5: WhatWeb fingerprint ──────────────────────────────────
    def run_whatweb(self):
        self._log("WhatWeb fingerprinting...", "STEP"); self._prog(74)
        try:
            res=subprocess.run(
                ["whatweb", f"http://{self.domain}"],
                capture_output=True, text=True, timeout=30
            )
            # Filter out Ruby internal warnings/tracebacks
            out_lines = [
                l for l in (res.stdout+res.stderr).splitlines()
                if l.strip() and not any(x in l for x in
                   ["warning:", "from /usr", "from /var", "from internal:", "in `<", "in `top"])
            ]
            out = "\n".join(out_lines).strip()
            if out:
                self.results["whatweb"] = out
                for line in out_lines[:12]:
                    self._log(f"  {line[:82]}", "FOUND")
            else:
                self._log("  WhatWeb returned no output", "WARN")
        except FileNotFoundError:
            self._log("  WhatWeb not found — install: sudo pacman -S ruby && gem install whatweb", "WARN")
        except Exception as e:
            self._log(f"  WhatWeb error: {e}", "WARN")
        self._prog(84)

    # ── 6: SQLMap light (if installed) ──────────────────────────
    def run_sqlmap(self):
        self._log("SQLMap surface scan (level=1, crawl=2)...", "STEP"); self._prog(86)
        out_dir=tempfile.mkdtemp(prefix="webgate_sqlmap_")
        try:
            cmd=["sqlmap","-u",f"http://{self.domain}",
                 "--crawl=2","--level=1","--risk=1","--batch",
                 "--output-dir="+out_dir]
            res=subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            out=(res.stdout+res.stderr)
            # Parse key findings
            for line in out.splitlines():
                if any(k in line.lower() for k in ["vulnerable","injection","found","error"]):
                    self._log(f"  {line[:80]}", "FOUND")
            self.results["sqlmap"]=out[:2000]
            self._log(f"  SQLMap output dir: {out_dir}", "INFO")
        except FileNotFoundError:
            self._log("  SQLMap not installed (pip install sqlmap)", "WARN")
        except subprocess.TimeoutExpired:
            self._log("  SQLMap timed out (120s)", "WARN")
        except Exception as e:
            self._log(f"  SQLMap error: {e}", "WARN")
        self._prog(96)

    def run(self):
        self._log(f"Deep scan started: {self.domain}", "INFO")
        self._log("─"*52, "INFO")
        urls=self.crawl()
        if not self.cancelled: self.check_xss(urls)
        if not self.cancelled: self.check_sqli(urls)
        if not self.cancelled: self.dir_enum()
        if not self.cancelled: self.run_whatweb()
        if not self.cancelled: self.run_sqlmap()
        # Extra tools: nmap (always useful), nikto, gobuster if installed
        if not self.cancelled:
            ts = ToolScanner(self.domain,
                             ["nmap", "nikto", "gobuster", "theHarv"],
                             self.log_cb, self.prog_cb)
            ts.run()
        self._prog(100)
        self._log("─"*52, "INFO")
        self._log("DEEP SCAN COMPLETE", "SUCCESS")


# ═══════════════════════════════════════════════════════════════
# TOOL REGISTRY  (all requested tools — 30 entries)
# ═══════════════════════════════════════════════════════════════

TOOL_REGISTRY = {
    # ─── Recon / fingerprinting ────────────────────────────────
    "nmap":       {"name":"Nmap",                   "cmd":"nmap",          "cat":"recon",
                   "desc":"Port scan + service/version detection",
                   "passive": False},
    "rustscan":   {"name":"RustScan",               "cmd":"rustscan",      "cat":"recon",
                   "desc":"Ultra-fast port scanner"},
    "nikto":      {"name":"Nikto",                  "cmd":"nikto",         "cat":"recon",
                   "desc":"Web server vulnerability scanner"},
    "whatweb2":   {"name":"WhatWeb (deep)",         "cmd":"whatweb",       "cat":"recon",
                   "desc":"Technology fingerprinting (aggressive mode)"},
    "theHarv":    {"name":"theHarvester",           "cmd":"theHarvester",  "cat":"recon",
                   "desc":"Email / subdomain OSINT"},
    "cloudfail":  {"name":"CloudFail",              "cmd":"cloudfail",     "cat":"recon",
                   "desc":"Bypass Cloudflare — real-IP discovery"},
    "inurlbr":    {"name":"Inurlbr",               "cmd":"inurlbr",       "cat":"recon",
                   "desc":"Google dork / URL brute scanner"},
    # ─── Web vulnerability scanning ───────────────────────────
    "xsstrike":   {"name":"XSStrike",               "cmd":"xsstrike",      "cat":"web",
                   "desc":"Advanced XSS detection & crawl"},
    "commix":     {"name":"Commix",                 "cmd":"commix",        "cat":"web",
                   "desc":"Command injection tester"},
    "ghauri":     {"name":"Ghauri (SQLi)",          "cmd":"ghauri",        "cat":"web",
                   "desc":"Advanced SQL injection scanner"},
    "arachni":    {"name":"Arachni",                "cmd":"arachni",       "cat":"web",
                   "desc":"Full web application security scanner"},
    # ─── Directory enumeration ─────────────────────────────────
    "gobuster":   {"name":"Gobuster",               "cmd":"gobuster",      "cat":"enum",
                   "desc":"Dir / DNS / vhost brute-forcer"},
    "dirsearch":  {"name":"DirSearch",              "cmd":"dirsearch",     "cat":"enum",
                   "desc":"Web path brute-force"},
    # ─── CMS scanners ──────────────────────────────────────────
    "wpscan":     {"name":"WPScan",                 "cmd":"wpscan",        "cat":"cms",
                   "desc":"WordPress vulnerability scanner"},
    "wpscan_pl":  {"name":"WP Plugins Scanner",     "cmd":"wpscan",        "cat":"cms",
                   "desc":"Enumerate installed WordPress plugins"},
    "wpscan_gf":  {"name":"Gravity Form Scanner",   "cmd":"wpscan",        "cat":"cms",
                   "desc":"Gravity Forms plugin vulnerability check"},
    "wpscan_xe":  {"name":"WP Exploit Scanner",     "cmd":"wpscan",        "cat":"cms",
                   "desc":"WordPress exploit fingerprinting"},
    "cmsmap":     {"name":"CMSMap",                 "cmd":"cmsmap",        "cat":"cms",
                   "desc":"Multi-CMS scanner (WP/Joomla/Drupal)"},
    "droopescan": {"name":"Droopescan",             "cmd":"droopescan",    "cat":"cms",
                   "desc":"Drupal & Silverstripe scanner"},
    "joomscan":   {"name":"JoomScan",               "cmd":"joomscan",      "cat":"cms",
                   "desc":"Joomla RCE / vuln scanner"},
    "vbscan":     {"name":"VBScan",                 "cmd":"vbscan",        "cat":"cms",
                   "desc":"vBulletin RCE / vuln scanner"},
    # ─── Upload / file checkers ────────────────────────────────
    "fupchecker": {"name":"File Upload Checker",    "cmd":"python3",       "cat":"web",
                   "desc":"Unrestricted file upload surface test"},
    "shellnoob":  {"name":"Shellnoob",              "cmd":"shellnoob",     "cat":"web",
                   "desc":"Shellcode generation helper"},
    # ─── Tools requiring explicit physical / auth setup ────────
    "sslstrip":   {"name":"SSLstrip",               "cmd":"sslstrip",      "cat":"mitm",
                   "desc":"HTTPS downgrade (requires ARP / active MitM)"},
    "reaver":     {"name":"Reaver",                 "cmd":"reaver",        "cat":"wifi",
                   "desc":"WPS brute-force (requires physical Wi-Fi access)"},
    "pixiewps":   {"name":"Pixiewps",               "cmd":"pixiewps",      "cat":"wifi",
                   "desc":"WPS Pixie Dust (requires physical Wi-Fi access)"},
    "setoolkit":  {"name":"SET",                    "cmd":"setoolkit",     "cat":"se",
                   "desc":"Social Engineering Toolkit (requires explicit auth)"},
    "cupp":       {"name":"CUPP",                   "cmd":"cupp",          "cat":"wordlist",
                   "desc":"Password profiler / wordlist generator"},
    "brutex":     {"name":"BruteX",                 "cmd":"brutex",        "cat":"brute",
                   "desc":"Auto brute-force SSH/FTP/HTTP (requires auth)"},
    "poet":       {"name":"POET",                   "cmd":"poet",          "cat":"post",
                   "desc":"Post-exploitation toolkit (use after gaining access)"},
    "weeman":     {"name":"Weeman",                 "cmd":"weeman",        "cat":"se",
                   "desc":"HTTP phishing server emulator (requires auth)"},
}

# Categories that need special authorization / physical access (not auto-run)
_TOOL_SKIP_AUTO = {"mitm", "wifi", "se", "post"}


def check_tool_availability() -> dict:
    """Returns {key: bool} — True if tool binary is found in PATH."""
    avail = {}
    for key, info in TOOL_REGISTRY.items():
        try:
            r = subprocess.run(["which", info["cmd"]], capture_output=True, timeout=3)
            avail[key] = (r.returncode == 0)
        except Exception:
            avail[key] = False
    return avail


class ToolScanner:
    """
    Runs a selected subset of TOOL_REGISTRY tools against a domain.
    Tools in _TOOL_SKIP_AUTO categories are warned about but never
    launched automatically — they require explicit interactive setup.
    """

    def __init__(self, domain: str, tools: list, log_cb=None, prog_cb=None):
        self.domain    = domain
        self.tools     = tools
        self.log_cb    = log_cb  or (lambda m, l: print(f"[{l}] {m}"))
        self.prog_cb   = prog_cb or (lambda v: None)
        self.cancelled = False
        self.results   = {}

    def _log(self, m, l="INFO"): self.log_cb(m, l)
    def _prog(self, v):          self.prog_cb(min(100, int(v)))

    def run(self):
        avail  = check_tool_availability()
        total  = max(len(self.tools), 1)
        for i, key in enumerate(self.tools):
            if self.cancelled: break
            info = TOOL_REGISTRY.get(key)
            if not info:
                continue
            self._prog(int(i / total * 100))
            cat = info.get("cat", "")
            if cat in _TOOL_SKIP_AUTO:
                self._log(f"  {info['name']} — requires manual auth/physical access (skip auto)", "WARN")
                continue
            if not avail.get(key, False):
                self._log(f"  {info['name']} not installed — skip", "WARN")
                continue
            self._log(f"{info['name']} — {info['desc']}", "STEP")
            self._run_tool(key, info)
            self._prog(int((i + 1) / total * 100))
        self._prog(100)

    def _run_tool(self, key: str, info: dict):
        domain  = self.domain
        cmd     = None
        timeout = 60

        if key == "nmap":
            cmd = ["nmap", "-sV", "--open", "-T4",
                   "-p", "21,22,23,25,53,80,110,143,443,445,587,993,"
                         "995,3306,3389,5432,6379,8080,8443,27017",
                   domain]
            timeout = 90
        elif key in ("wpscan", "wpscan_pl", "wpscan_gf", "wpscan_xe"):
            enum = {"wpscan_pl": "p", "wpscan_gf": "p",
                    "wpscan_xe": "vp", "wpscan": "vp,u"}.get(key, "vp,u")
            cmd = ["wpscan", "--url", f"https://{domain}", "--no-update",
                   "--enumerate", enum, "--format", "cli-no-colour"]
            timeout = 120
        elif key == "xsstrike":
            cmd = ["xsstrike", "-u", f"http://{domain}", "--crawl"]
        elif key == "commix":
            cmd = ["commix", "--url", f"http://{domain}/", "--batch"]
        elif key == "droopescan":
            cmd = ["droopescan", "scan", "drupal", "-u", f"http://{domain}"]
        elif key == "joomscan":
            cmd = ["joomscan", "-u", f"http://{domain}"]
        elif key == "vbscan":
            cmd = ["vbscan", "-u", f"http://{domain}"]
        elif key == "cmsmap":
            cmd = ["cmsmap", f"http://{domain}"]
        elif key == "nikto":
            cmd = ["nikto", "-h", f"http://{domain}", "-nointeractive"]
            timeout = 120
        elif key == "gobuster":
            for wl in ("/usr/share/wordlists/dirb/common.txt",
                       "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
                       "/usr/share/dirb/wordlists/common.txt"):
                if os.path.exists(wl):
                    break
            else:
                self._log("  Gobuster wordlist not found — skip", "WARN"); return
            cmd = ["gobuster", "dir", "-u", f"http://{domain}",
                   "-w", wl, "-q", "-t", "20"]
        elif key == "dirsearch":
            cmd = ["dirsearch", "-u", f"http://{domain}", "-q"]
        elif key == "arachni":
            cmd = ["arachni", f"http://{domain}"]
            timeout = 180
        elif key == "rustscan":
            cmd = ["rustscan", "-a", domain, "--", "-sV"]
        elif key == "cloudfail":
            cmd = ["cloudfail", "-t", domain]
        elif key == "ghauri":
            cmd = ["ghauri", "-u", f"http://{domain}/?id=1", "--batch"]
        elif key == "theHarv":
            cmd = ["theHarvester", "-d", domain, "-b", "bing,google"]
            timeout = 90
        elif key == "whatweb2":
            cmd = ["whatweb", "--aggression=3", f"http://{domain}"]
        elif key == "inurlbr":
            cmd = ["inurlbr", "--dork", f"site:{domain}",
                   "--save", f"/tmp/wg_inurlbr_{domain}.txt"]
        elif key == "cupp":
            self._log("  CUPP runs interactively — generate wordlist manually", "WARN")
            return
        elif key in ("shellnoob", "fupchecker"):
            self._log(f"  {info['name']} requires interactive use", "WARN")
            return
        else:
            self._log(f"  No runner configured for {info['name']}", "WARN")
            return

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            out = (res.stdout + res.stderr).strip()
            shown = 0
            for line in out.splitlines():
                line = line.strip()
                if not line or shown >= 30:
                    continue
                lvl = "FOUND" if any(k in line.lower() for k in
                    ["found", "vuln", "open", "error", "inject",
                     "alert", "critical", "warning"]) else "INFO"
                self._log(f"  {line[:90]}", lvl)
                shown += 1
            self.results[key] = out[:4000]
        except FileNotFoundError:
            self._log(f"  {info['name']}: not in PATH", "WARN")
        except subprocess.TimeoutExpired:
            self._log(f"  {info['name']}: timed out ({timeout}s)", "WARN")
        except Exception as e:
            self._log(f"  {info['name']}: {e}", "WARN")


# ═══════════════════════════════════════════════════════════════
# CLI INTERFACE
# ═══════════════════════════════════════════════════════════════

class CLIInterface:
    # ANSI color shortcuts
    _Y  = '\033[33m'   # yellow for warnings
    _R  = '\033[31m'   # red
    _G  = '\033[32m'   # green (not used in B&W theme but for disclaimer)
    _PFX= {"INFO":f"{C.GRY}  [*]{C.RST}","FOUND":f"{C.BOLD}  [+]{C.RST}",
           "WARN":f"{C.GRY}  [!]{C.RST}","ERROR":f"{C.BOLD}  [-]{C.RST}",
           "STEP":f"{C.BOLD}{C.WHT}  [»]{C.RST}","SUCCESS":f"{C.BOLD}  [✓]{C.RST}"}

    def __init__(self): self._pv=0

    def log(self,m,l="INFO"):
        if self._pv>0: print(f"\r{' '*66}\r",end="")
        print(f"{self._PFX.get(l,'  [*]')} {m}")

    def progress(self,v,w=46):
        self._pv=v; bar="█"*int(w*v/100)+"░"*(w-int(w*v/100))
        print(f"\r  [{bar}] {v:3d}%",end="",flush=True)
        if v>=100: print(); self._pv=0

    def _header(self, domain, mode="SCAN"):
        print(f"\n  {'═'*66}")
        print(f"  {C.BOLD}MODE{C.RST}     : {mode}")
        print(f"  {C.BOLD}TARGET{C.RST}   : {domain}")
        print(f"  {C.BOLD}STARTED{C.RST}  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  {'═'*66}\n")

    def _footer(self, t0, rep):
        print(f"\n  {'═'*66}")
        print(f"  Completed in {time.time()-t0:.1f}s")
        if rep: print(f"  Report saved : {rep}")
        print(f"  {'═'*66}\n")

    def scan(self, domain):
        self._header(domain, "STANDARD SCAN")
        t0=time.time()
        sc=DomainScanner(domain,log_cb=self.log,prog_cb=self.progress)
        rep=sc.run()
        self._footer(t0, rep)

    def deep_scan(self, domain):
        # Show disclaimer in yellow first
        print(f"\n  {self._Y}{'─'*66}{C.RST}")
        print(f"  {self._Y}[!] DEEP SCAN — EDUCATIONAL USE ONLY{C.RST}")
        print(f"  {self._Y}    Only scan systems you own or have written permission to test.{C.RST}")
        print(f"  {self._Y}    Unauthorized scanning may be illegal in your jurisdiction.{C.RST}")
        print(f"  {self._Y}{'─'*66}{C.RST}")
        try:
            ans=input(f"\n  Type {C.BOLD}AGREE{C.RST} to continue or press Enter to cancel: ").strip()
        except (KeyboardInterrupt, EOFError):
            print(); return
        if ans.upper() != "AGREE":
            print(f"  {C.GRY}Cancelled.{C.RST}\n"); return

        # Standard scan first, then deep
        self._header(domain, "STANDARD SCAN → DEEP SCAN")
        t0=time.time()
        sc=DomainScanner(domain,log_cb=self.log,prog_cb=self.progress)
        rep=sc.run()
        print(f"\n  {C.BOLD}{'─'*66}{C.RST}")
        print(f"  {C.BOLD}[DEEP SCAN] Starting extended analysis...{C.RST}\n")
        ds=DeepScanner(domain,log_cb=self.log,prog_cb=self.progress)
        ds.run()
        self._footer(t0, rep)

    def history(self):
        """List and optionally view saved audit reports."""
        reports = sorted(
            [f for f in os.listdir(_REPORTS_DIR) if f.startswith("audit_") and f.endswith(".txt")],
            reverse=True
        )
        if not reports:
            print(f"  {C.GRY}No saved reports found.{C.RST}\n"); return
        print(f"\n  {'─'*66}")
        print(f"  {C.BOLD}SCAN HISTORY{C.RST}  ({len(reports)} reports)")
        print(f"  {'─'*66}")
        for i,r in enumerate(reports[:20]):
            # Parse domain + date from filename
            parts=r.replace("audit_","").replace(".txt","").rsplit("_",2)
            domain_part = parts[0] if parts else r
            date_part   = f"{parts[1][0:4]}-{parts[1][4:6]}-{parts[1][6:8]}" if len(parts)>1 else ""
            time_part   = f"{parts[2][0:2]}:{parts[2][2:4]}:{parts[2][4:6]}" if len(parts)>2 else ""
            size_kb     = os.path.getsize(os.path.join(_REPORTS_DIR,r))//1024
            print(f"  {C.BOLD}[{i+1:2d}]{C.RST}  {domain_part:<30} {date_part} {time_part}  {size_kb}KB")
        print(f"  {'─'*66}")
        try:
            sel=input(f"  Open report [1-{min(len(reports),20)}, Enter=cancel]: ").strip()
        except (KeyboardInterrupt, EOFError): print(); return
        if sel.isdigit():
            idx=int(sel)-1
            if 0<=idx<len(reports):
                path=os.path.join(_REPORTS_DIR,reports[idx])
                # Use pager if available
                pager=os.environ.get("PAGER","less")
                try: subprocess.run([pager,path])
                except: subprocess.run(["cat",path])

    def shell(self):
        print(BANNER)
        print(f"  {C.GRY}github.com/c3less  ·  t.me/c3less{C.RST}\n")
        HELP = f"""
  {C.BOLD}Commands:{C.RST}
  scan <domain>        Standard security audit
  deep <domain>        Deep scan (XSS, SQLi, ports, WhatWeb, SQLMap)
  history              Browse saved scan reports
  gui                  Launch graphical interface
  clear                Clear screen
  exit                 Quit

  {C.GRY}Or just type a domain: example.com{C.RST}
"""
        while True:
            try: raw=input(f"  {C.BOLD}webgate{C.RST} {C.GRY}›{C.RST} ").strip()
            except (KeyboardInterrupt,EOFError): print(f"\n\n  {C.GRY}Goodbye.{C.RST}\n"); break
            if not raw: continue
            p=raw.split(); cmd=p[0].lower()
            if cmd in ("exit","quit","q"): print(f"\n  {C.GRY}Goodbye.{C.RST}\n"); break
            elif cmd=="help":    print(HELP)
            elif cmd=="gui":     launch_gui()
            elif cmd=="clear":   os.system("clear")
            elif cmd=="history": self.history()
            elif cmd=="scan" and len(p)>1: self.scan(p[1])
            elif cmd=="deep" and len(p)>1: self.deep_scan(p[1])
            elif "." in raw or raw.startswith("http"): self.scan(p[0])
            else: print(f"  {C.GRY}Unknown command. Type 'help'.{C.RST}")

    def quick(self,domain): print(BANNER); self.scan(domain)


# ═══════════════════════════════════════════════════════════════
# GUI — SPLASH SCREEN
# ═══════════════════════════════════════════════════════════════

class SplashScreen:
    """
    Splash window shown before the main UI.
    Takes an existing Tk() root and an on_done callback.
    Does NOT create its own Tk() — avoids multiple-root issues.
    """
    def __init__(self, root, on_done):
        import tkinter as tk
        self._root   = root
        self._done   = on_done
        th = get_theme()
        w, h = 520, 300

        win = tk.Toplevel(root)
        self.win = win
        win.overrideredirect(True)
        win.attributes("-alpha", 0.0)
        try: win.attributes("-topmost", True)
        except: pass
        scrw = win.winfo_screenwidth()
        scrh = win.winfo_screenheight()
        win.geometry(f"{w}x{h}+{(scrw-w)//2}+{(scrh-h)//2}")
        win.configure(bg=th["BG"])

        cv = tk.Canvas(win, bg=th["BG"], highlightthickness=0)
        cv.pack(fill="both", expand=True)

        # Grid background
        for x in range(0, w, 40): cv.create_line(x, 0, x, h, fill=th["BORDER"], width=1)
        for y in range(0, h, 40): cv.create_line(0, y, w, y, fill=th["BORDER"], width=1)

        cx = w // 2
        # Logo — shadow then main text
        cv.create_text(cx+3, 103, text="WebGate",
            font=("Georgia", 44, "bold italic"), fill=th["LOGO_SHD"], anchor="center")
        cv.create_text(cx, 100, text="WebGate",
            font=("Georgia", 44, "bold italic"), fill=th["LOGO_CLR"], anchor="center")

        self._cv     = cv
        self._cx     = cx
        self._sub_id = cv.create_text(cx, 155, text="",
            font=("Georgia", 11, "italic"), fill=th["FG2"], anchor="center")
        self._ver_id = cv.create_text(cx, 180, text="",
            font=("Courier New", 9), fill=th["FG3"], anchor="center")
        cv.create_rectangle(cx-160, 235, cx+160, 239, fill=th["BORDER"], outline="")
        self._bar    = cv.create_rectangle(cx-160, 235, cx-160, 239, fill=th["WHITE"], outline="")

        self._sub_text = "Domain Security Auditor"
        self._ver_text = "v2.0  ·  by c3less"
        self._si = 0

        win.after(60, self._fade_in)

    def _fade_in(self, a=0.0):
        a = min(1.0, a + 0.07)
        self.win.attributes("-alpha", a)
        if a < 1.0: self.win.after(22, lambda: self._fade_in(a))
        else:        self.win.after(120, self._type_sub)

    def _type_sub(self):
        i = self._si
        self._cv.itemconfig(self._sub_id,
            text=self._sub_text[:i] + ("▌" if i < len(self._sub_text) else ""))
        if SETTINGS.get("sound"): play_click()
        if i < len(self._sub_text):
            self._si += 1
            self.win.after(42, self._type_sub)
        else:
            self.win.after(220, lambda: self._type_ver(0))

    def _type_ver(self, i=0):
        self._cv.itemconfig(self._ver_id, text=self._ver_text[:i])
        if i < len(self._ver_text):
            self.win.after(32, lambda: self._type_ver(i + 1))
        else:
            self.win.after(320, lambda: self._animate_bar(0))

    def _animate_bar(self, pct=0):
        cx = self._cx; bx = cx - 160; bw = 320
        self._cv.coords(self._bar, bx, 235, bx + int(bw * pct / 100), 239)
        if pct < 100: self.win.after(13, lambda: self._animate_bar(pct + 2))
        else:          self.win.after(280, lambda: self._fade_out(1.0))

    def _fade_out(self, a=1.0):
        a = max(0.0, a - 0.09)
        self.win.attributes("-alpha", a)
        if a > 0: self.win.after(18, lambda: self._fade_out(a))
        else:
            self.win.destroy()
            self._done()   # show main window


# ═══════════════════════════════════════════════════════════════
# GUI — SETTINGS DIALOG
# ═══════════════════════════════════════════════════════════════

class SettingsDialog:
    def __init__(self, parent, on_apply):
        import tkinter as tk
        from tkinter import ttk, colorchooser
        self.tk=tk; self.cc=colorchooser; self.on_apply=on_apply
        th=get_theme()
        win=tk.Toplevel(parent)
        self.win=win; win.title(t("settings_title"))
        win.geometry("380x340"); win.resizable(False,False)
        win.configure(bg=th["BG"])
        try: win.attributes("-topmost",True)
        except: pass
        win.attributes("-alpha",0.0)
        win.after(10,lambda: self._fade_in(win))
        self._build(win, th)

    def _fade_in(self, win, a=0.0):
        a=min(1.0,a+0.1); win.attributes("-alpha",a)
        if a<1.0: win.after(20, lambda: self._fade_in(win,a))

    def _build(self, win, th):
        tk=self.tk
        pad=dict(padx=20,pady=8)
        def lbl(txt, row, col=0):
            tk.Label(win,text=txt,font=("Courier New",9),bg=th["BG"],fg=th["FG2"]).grid(
                row=row,column=col,sticky="w",**pad)

        win.columnconfigure(1,weight=1)
        # Title
        tk.Label(win,text=t("settings_title"),font=("Georgia",14,"bold italic"),
                 bg=th["BG"],fg=th["WHITE"]).grid(row=0,column=0,columnspan=2,pady=(16,4))

        # Language
        lbl(t("lang_label"),1)
        self._lang=tk.StringVar(value=SETTINGS["lang"])
        fr=tk.Frame(win,bg=th["BG"]); fr.grid(row=1,column=1,sticky="w",padx=12)
        for lang in ("EN","RU"):
            tk.Radiobutton(fr,text=lang,variable=self._lang,value=lang,
                bg=th["BG"],fg=th["FG"],selectcolor=th["BG3"],
                activebackground=th["BG"],font=("Courier New",9)).pack(side="left",padx=6)

        # Theme
        lbl(t("theme_label"),2)
        self._theme=tk.StringVar(value=SETTINGS["theme"])
        fr2=tk.Frame(win,bg=th["BG"]); fr2.grid(row=2,column=1,sticky="w",padx=12)
        for name in ("dark","light","midnight","custom"):
            tk.Radiobutton(fr2,text=name.capitalize(),variable=self._theme,value=name,
                bg=th["BG"],fg=th["FG"],selectcolor=th["BG3"],
                activebackground=th["BG"],font=("Courier New",8)).pack(side="left",padx=4)

        # Sound
        lbl(t("sound_label"),3)
        self._sound=tk.BooleanVar(value=SETTINGS["sound"])
        tk.Checkbutton(win,variable=self._sound,bg=th["BG"],fg=th["FG"],
            selectcolor=th["BG3"],activebackground=th["BG"],
            text="Enable").grid(row=3,column=1,sticky="w",padx=12)

        # Transparency
        lbl(t("alpha_label"),4)
        self._alpha=tk.DoubleVar(value=SETTINGS["transparency"])
        sl=tk.Scale(win,from_=0.5,to=1.0,resolution=0.01,orient="horizontal",
            variable=self._alpha,bg=th["BG"],fg=th["FG"],
            troughcolor=th["BG3"],highlightthickness=0,length=180)
        sl.grid(row=4,column=1,sticky="w",padx=12)

        # Custom theme button
        tk.Button(win,text=t("custom_btn"),font=("Courier New",8),
            bg=th["BG3"],fg=th["FG"],relief="flat",padx=10,pady=4,
            command=self._pick_custom).grid(row=5,column=1,sticky="w",padx=12,pady=4)

        # Buttons
        bf=tk.Frame(win,bg=th["BG"]); bf.grid(row=6,column=0,columnspan=2,pady=16)
        tk.Button(bf,text=t("save_btn"),font=("Courier New",9,"bold"),
            bg=th["BTN_BG"],fg=th["BTN_FG"],relief="flat",padx=20,pady=6,
            command=self._save).pack(side="left",padx=8)
        tk.Button(bf,text=t("close_btn"),font=("Courier New",9),
            bg=th["BG3"],fg=th["FG"],relief="flat",padx=16,pady=6,
            command=self.win.destroy).pack(side="left",padx=8)

    def _pick_custom(self):
        th=get_theme()
        colors={}
        for key,lbl_txt in [("BG","Background"),("FG","Text"),
                             ("WHITE","Accent"),("BTN_BG","Button")]:
            col=self.cc.askcolor(color=th.get(key,"#ffffff"),title=f"Pick {lbl_txt}")
            if col and col[1]: colors[key]=col[1]
        if colors:
            SETTINGS["custom_theme"].update(colors)
            self._theme.set("custom")

    def _save(self):
        old_lang  = SETTINGS["lang"]
        old_theme = SETTINGS["theme"]
        SETTINGS["lang"]         = self._lang.get()
        SETTINGS["theme"]        = self._theme.get()
        SETTINGS["sound"]        = self._sound.get()
        SETTINGS["transparency"] = self._alpha.get()
        save_settings(SETTINGS)
        # Apply transparency immediately to parent window
        try:
            self.win.master.attributes("-alpha", SETTINGS["transparency"])
        except Exception:
            pass
        # Only rebuild UI if theme or lang actually changed
        if SETTINGS["lang"] != old_lang or SETTINGS["theme"] != old_theme:
            self.on_apply()
        self.win.destroy()


# ═══════════════════════════════════════════════════════════════
# GUI — DISCLAIMER DIALOG
# ═══════════════════════════════════════════════════════════════

class DisclaimerDialog:
    def __init__(self, parent, on_agree):
        import tkinter as tk
        self.on_agree=on_agree; th=get_theme()
        win=tk.Toplevel(parent); self.win=win
        win.title(t("disc_title"))
        win.geometry("560x480"); win.resizable(False,False)
        win.configure(bg=th["BG"])
        try: win.attributes("-topmost",True)
        except: pass
        win.attributes("-alpha",0.0)
        win.after(10, lambda: self._fade(win))

        tk.Label(win,text="⚠  "+t("disc_title"),font=("Georgia",12,"bold italic"),
            bg=th["BG"],fg=th["WHITE"]).pack(pady=(16,8))
        tk.Frame(win,bg=th["BORDER"],height=1).pack(fill="x",padx=20)

        body=tk.Text(win,font=("Courier New",9),bg=th["BG2"],fg=th["FG"],
            relief="flat",bd=0,padx=14,pady=10,wrap="word",state="normal",
            highlightthickness=0)
        body.insert("1.0", t("disc_body"))
        body.configure(state="disabled")
        body.pack(fill="both",expand=True,padx=20,pady=12)

        bf=tk.Frame(win,bg=th["BG"]); bf.pack(pady=14)
        tk.Button(bf,text=t("disc_agree"),font=("Courier New",9,"bold"),
            bg=th["BTN_BG"],fg=th["BTN_FG"],relief="flat",padx=14,pady=7,
            command=self._agree).pack(side="left",padx=10)
        tk.Button(bf,text=t("disc_deny"),font=("Courier New",9),
            bg=th["BG3"],fg=th["FG"],relief="flat",padx=14,pady=7,
            command=win.destroy).pack(side="left",padx=10)

    def _fade(self, win, a=0.0):
        a=min(1.0,a+0.1); win.attributes("-alpha",a)
        if a<1.0: win.after(20, lambda: self._fade(win,a))

    def _agree(self):
        self.win.destroy(); self.on_agree()


# ═══════════════════════════════════════════════════════════════
# GUI — SUMMARY POPUP
# ═══════════════════════════════════════════════════════════════

class SummaryPopup:
    RISK_COLORS={"LOW":"#88ff88","MEDIUM":"#ffcc44","HIGH":"#ff8844","CRITICAL":"#ff4444"}

    def __init__(self, parent, results:dict, domain:str):
        import tkinter as tk
        th=get_theme()
        win=tk.Toplevel(parent); self.win=win
        win.title(t("summary_title"))
        win.geometry("480x400"); win.resizable(False,False)
        win.configure(bg=th["BG"])
        try: win.attributes("-topmost",True)
        except: pass
        win.attributes("-alpha",0.0)
        win.after(10, lambda: self._fade(win))

        # Title
        tk.Label(win,text=t("summary_title"),font=("Georgia",14,"bold italic"),
            bg=th["BG"],fg=th["WHITE"]).pack(pady=(16,4))
        tk.Label(win,text=domain,font=("Courier New",10),
            bg=th["BG"],fg=th["FG2"]).pack()
        tk.Frame(win,bg=th["BORDER"],height=1).pack(fill="x",padx=20,pady=8)

        # Stats grid
        fr=tk.Frame(win,bg=th["BG"]); fr.pack(padx=28,pady=4,fill="x")

        res_res = results.get("resolution",{})
        ssl_res = results.get("ssl",{})
        http_res= results.get("http",{})
        port_res= results.get("ports",{})

        ip_val  = ", ".join(res_res.get("ips",["N/A"])[:2])
        ssl_val = ssl_res.get("version","N/A") if ssl_res.get("available") else "Not available"
        port_val= str(len(port_res.get("open",[])))
        sec_val = f"{http_res.get('score',0)}/{len(DomainScanner.SECURITY_HEADERS)}"

        # Build risk level
        s=DomainScanner.__new__(DomainScanner)
        s.results=results
        risks=s._build_risks()
        if   any(r[0]=="CRITICAL" for r in risks): rlbl="CRITICAL"; rc=self.RISK_COLORS["CRITICAL"]
        elif any(r[0]=="HIGH"     for r in risks): rlbl="HIGH";     rc=self.RISK_COLORS["HIGH"]
        elif any(r[0]=="MEDIUM"   for r in risks): rlbl="MEDIUM";   rc=self.RISK_COLORS["MEDIUM"]
        else:                                       rlbl="LOW";      rc=self.RISK_COLORS["LOW"]

        rows=[
            (t("summary_ip"),  ip_val,  th["FG"]),
            (t("summary_ssl"), ssl_val, th["FG"] if ssl_res.get("available") else th["FG2"]),
            (t("summary_open"),port_val,th["WHITE"] if int(port_val)>3 else th["FG"]),
            (t("summary_sec"), sec_val, th["FG"]),
            (t("summary_risk"),rlbl,    rc),
        ]
        for i,(lbl_txt,val,clr) in enumerate(rows):
            tk.Label(fr,text=lbl_txt,font=("Courier New",9),bg=th["BG"],
                fg=th["FG2"],anchor="w",width=18).grid(row=i,column=0,sticky="w",pady=4)
            tk.Label(fr,text=val,font=("Courier New",10,"bold"),bg=th["BG"],
                fg=clr,anchor="w").grid(row=i,column=1,sticky="w",padx=10)

        tk.Frame(win,bg=th["BORDER"],height=1).pack(fill="x",padx=20,pady=8)

        # Risk list
        if risks:
            rf=tk.Frame(win,bg=th["BG2"]); rf.pack(fill="x",padx=20,pady=4)
            for sev,det in risks[:6]:
                c=self.RISK_COLORS.get(sev,th["FG2"])
                tk.Label(rf,text=f"  [{sev:<8}] {det[:55]}",
                    font=("Courier New",8),bg=th["BG2"],fg=c,anchor="w"
                ).pack(fill="x",pady=1)

        tk.Button(win,text=t("close_btn"),font=("Courier New",9),
            bg=th["BG3"],fg=th["FG"],relief="flat",padx=16,pady=6,
            command=win.destroy).pack(pady=12)

    def _fade(self, win, a=0.0):
        a=min(1.0,a+0.1); win.attributes("-alpha",a)
        if a<1.0: win.after(20, lambda: self._fade(win,a))


# ═══════════════════════════════════════════════════════════════
# GUI — MAIN APPLICATION
# ═══════════════════════════════════════════════════════════════

class SecurityScannerGUI:
    def __init__(self, root, prefill:str=""):
        import tkinter as tk
        from tkinter import font as tkfont
        self.tk = tk; self._tkfont = tkfont
        self.th  = get_theme()

        # Reuse the single Tk() root passed in from launch_gui
        self.root = root
        self.root.title("WebGate")
        self.root.minsize(700, 480)
        self.root.geometry("900x620")
        self.root.resizable(True, True)
        self.root.configure(bg=self.th["BG"])
        try: self.root.attributes("-alpha", SETTINGS.get("transparency", 0.94))
        except: pass
        self.root.deiconify()   # make visible (was withdrawn during splash)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self._prefill   = prefill
        self.scanning   = False
        self.scanner    = None
        self._log_q     = []
        self._log_busy  = False
        self._scan_start= 0.0
        self._step_idx  = [0]
        self._dot_state = 0
        self._prog_val  = 0

        self.font, self.tfont = self._pick_font()
        self._build_ui()
        self._pulse_dot()
        # Fade-in
        self.root.attributes("-alpha", 0.0)
        self.root.after(50, self._fade_in)

    def _pick_font(self) -> tuple:
        """Returns (mono_font, title_font) tuple."""
        avail = self._tkfont.families()
        mono_prefer  = ["JetBrains Mono","Cascadia Code","Fira Code",
                        "Iosevka","Source Code Pro","Consolas","Courier New","Courier"]
        title_prefer = ["Helvetica Neue","Inter","Segoe UI","Ubuntu","DejaVu Sans","Helvetica","Arial"]
        mono  = next((f for f in mono_prefer  if f in avail), "Courier New")
        title = next((f for f in title_prefer if f in avail), "Helvetica")
        return mono, title

    def _apply_theme(self, animated=True):
        if animated:
            self._fade_then_rebuild()
        else:
            self._rebuild_ui()

    def _fade_then_rebuild(self):
        """Fade out → rebuild → fade in (water-drop transition)."""
        cur = SETTINGS.get("transparency", 0.94)
        def fade_out(a):
            a = max(0.0, a - 0.15)
            try: self.root.attributes("-alpha", a)
            except: pass
            if a > 0.0:
                self.root.after(11, lambda: fade_out(a))
            else:
                self._rebuild_ui()
                fade_in(0.0)
        def fade_in(a):
            target = SETTINGS.get("transparency", 0.94)
            a = min(target, a + 0.11)
            try: self.root.attributes("-alpha", a)
            except: pass
            if a < target:
                self.root.after(11, lambda: fade_in(a))
        fade_out(cur)

    def _rebuild_ui(self):
        """Core UI rebuild — preserves log content and scanning state."""
        try:
            log_content = self._log_w.get("1.0", "end-1c")
        except Exception:
            log_content = ""
        self.th = get_theme()
        for w in self.root.winfo_children(): w.destroy()
        self._log_q = []; self._log_busy = False
        self._build_ui()
        self._pulse_dot()
        if log_content.strip():
            self._log_w.configure(state="normal")
            self._log_w.insert("end", log_content + "\n")
            self._log_w.see("end")
            self._log_w.configure(state="disabled")
        else:
            self._push(t("init_msg"), "INFO")

    # ── Fade in/out ────────────────────────────────────────────
    def _fade_in(self, a=0.0):
        target=SETTINGS.get("transparency",0.94)
        a=min(target, a+0.06)
        self.root.attributes("-alpha", a)
        if a < target: self.root.after(20, lambda: self._fade_in(a))

    # ── Build UI ───────────────────────────────────────────────
    def _build_ui(self):
        tk=self.tk; th=self.th; root=self.root
        root.configure(bg=th["BG"])

        # ─ Top bar ──────────────────────────────────────────────
        top=tk.Frame(root,bg=th["BG"]); top.pack(fill="x")

        # Logo canvas — Georgia italic, clean, no subtitle clutter
        logo_cv=tk.Canvas(top,bg=th["BG"],height=48,highlightthickness=0,width=280)
        logo_cv.pack(side="left",padx=18,pady=8)
        # Deep shadow for depth
        logo_cv.create_text(5,27,text="WebGate",
            font=("Georgia",26,"bold italic"),fill=th["BG3"],anchor="w")
        logo_cv.create_text(3,26,text="WebGate",
            font=("Georgia",26,"bold italic"),fill=th["LOGO_SHD"],anchor="w")
        # Main text
        logo_cv.create_text(2,24,text="WebGate",
            font=("Georgia",26,"bold italic"),fill=th["LOGO_CLR"],anchor="w")
        # Thin accent line below — adds logo feel
        logo_cv.create_line(2,42,180,42,fill=th["BORDER2"],width=1)

        # Right controls
        rc=tk.Frame(top,bg=th["BG"]); rc.pack(side="right",padx=16,pady=10)
        tk.Label(rc,text=t("credit"),font=(self.font,7),
            bg=th["BG"],fg=th["FG3"]).pack(side="right",padx=(8,0))
        # Settings button
        tk.Button(rc,text=t("settings_btn"),font=(self.font,12),
            bg=th["BG"],fg=th["FG2"],relief="flat",bd=0,cursor="hand2",
            activebackground=th["BG"],activeforeground=th["WHITE"],
            command=self._open_settings).pack(side="right",padx=4)
        # Lang toggle — clean text, no icons
        self._lang_btn=tk.Button(rc,text=SETTINGS["lang"],
            font=(self.font,8,"bold"),bg=th["BG3"],fg=th["FG"],
            relief="flat",bd=0,padx=8,pady=3,cursor="hand2",
            command=self._toggle_lang)
        self._lang_btn.pack(side="right",padx=4)
        self._press_effect(self._lang_btn)
        # Theme toggle — text only
        theme_names={"dark":"DARK","light":"LIGHT","midnight":"NIGHT","custom":"CUSTOM"}
        self._theme_btn=tk.Button(rc,
            text=theme_names.get(SETTINGS["theme"],"DARK"),
            font=(self.font,7,"bold"),bg=th["BG3"],fg=th["FG"],
            relief="flat",bd=0,padx=8,pady=3,cursor="hand2",
            command=self._cycle_theme)
        self._theme_btn.pack(side="right",padx=4)
        self._press_effect(self._theme_btn)
        # Status dot
        self._dot=tk.Label(rc,text="●",font=(self.font,12),
            bg=th["BG"],fg=th["FG3"])
        self._dot.pack(side="right",padx=(0,6))

        # ─ Separator ────────────────────────────────────────────
        tk.Frame(root,bg=th["BORDER"],height=1).pack(fill="x")

        # ─ Input row ────────────────────────────────────────────
        inrow=tk.Frame(root,bg=th["BG2"]); inrow.pack(fill="x")
        inner=tk.Frame(inrow,bg=th["BG2"]); inner.pack(side="left",padx=18,pady=10)

        tk.Label(inner,text=t("target_lbl"),font=(self.font,7,"bold"),
            bg=th["BG2"],fg=th["FG3"]).pack(side="left",padx=(0,8))

        ef=tk.Frame(inner,bg=th["BORDER2"],padx=1,pady=1); ef.pack(side="left")
        self._entry_frame = ef
        self._dvar=tk.StringVar(value=self._prefill)
        self._entry=tk.Entry(ef,textvariable=self._dvar,font=(self.font,12),
            bg=th["BG3"],fg=th["FG"],insertbackground=th["WHITE"],
            relief="flat",bd=5,width=28)
        self._entry.pack()
        self._entry.bind("<FocusIn>",  self._ef_in)
        self._entry.bind("<FocusOut>", self._ef_out)

        self._btn=tk.Button(inner,text=t("scan_btn"),font=(self.font,11,"bold"),
            bg=th["BTN_BG"],fg=th["BTN_FG"],activebackground=th["BTN_HOV"],
            activeforeground=th["BTN_FG"],relief="flat",bd=0,
            padx=18,pady=5,cursor="hand2",command=self._on_scan)
        self._btn.pack(side="left",padx=(10,0))
        self._btn_hover()

        self._deep_btn=tk.Button(inner,text=t("deep_btn"),
            font=(self.font,9),bg=th["BG3"],fg=th["FG2"],
            activebackground=th["BORDER2"],activeforeground=th["FG"],
            relief="flat",bd=0,padx=14,pady=5,cursor="hand2",
            command=self._on_deep_scan)
        self._deep_btn.pack(side="left",padx=(6,0))

        self._cancel_btn=tk.Button(inner,text=t("cancel_btn"),
            font=(self.font,9),bg=th["BG3"],fg=th["FG2"],
            activebackground=th["BORDER"],activeforeground=th["FG"],
            relief="flat",bd=0,padx=12,pady=5,cursor="hand2",
            command=self._on_cancel)

        # ─ Separator ────────────────────────────────────────────
        tk.Frame(root,bg=th["BORDER"],height=1).pack(fill="x")

        # ─ Content ──────────────────────────────────────────────
        content=tk.Frame(root,bg=th["BG"]); content.pack(fill="both",expand=True)
        content.columnconfigure(0,weight=1); content.rowconfigure(0,weight=1)

        # Log panel
        log_frame=tk.Frame(content,bg=th["BG2"]); log_frame.grid(row=0,column=0,sticky="nsew")
        log_frame.rowconfigure(1,weight=1); log_frame.columnconfigure(0,weight=1)

        log_hdr=tk.Frame(log_frame,bg=th["BG3"],height=22)
        log_hdr.grid(row=0,column=0,columnspan=2,sticky="ew")
        tk.Label(log_hdr,text=t("log_hdr"),font=(self.font,7,"bold"),
            bg=th["BG3"],fg=th["FG3"]).pack(side="left",padx=12,pady=3)
        self._evt_lbl=tk.Label(log_hdr,text="",font=(self.font,7),
            bg=th["BG3"],fg=th["FG3"])
        self._evt_lbl.pack(side="right",padx=12,pady=3)

        self._log_w=tk.Text(log_frame,font=(self.font,10),bg=th["BG"],fg=th["FG"],
            insertbackground=th["WHITE"],relief="flat",bd=0,padx=14,pady=10,
            wrap="word",state="disabled",cursor="arrow",
            selectbackground=th["BORDER2"],selectforeground=th["WHITE"])
        sb=tk.Scrollbar(log_frame,orient="vertical",command=self._log_w.yview,
            bg=th["BG3"],troughcolor=th["BG"],activebackground=th["BORDER2"],
            width=7,relief="flat",bd=0)
        self._log_w.configure(yscrollcommand=sb.set)
        sb.grid(row=1,column=1,sticky="ns")
        self._log_w.grid(row=1,column=0,sticky="nsew")

        for lvl,col in th["LOG_CLR"].items():
            self._log_w.tag_configure(f"lvl_{lvl}", foreground=col)
        self._log_w.tag_configure("ts",    foreground=th["FG3"])
        self._log_w.tag_configure("pfx_h", foreground=th["WHITE"],font=(self.font,10,"bold"))
        self._log_w.tag_configure("rule",  foreground=th["FG3"])
        self._log_w.tag_configure("cursor",foreground=th["WHITE"])

        # Ctrl+scroll → font resize
        def _ctrl_scroll(event):
            delta = 1 if (event.delta > 0 or event.num == 4) else -1
            sz = getattr(self, "_log_font_size", 9) + delta
            sz = max(6, min(sz, 22))
            self._log_font_size = sz
            self._log_w.configure(font=(self.font, sz))
            self._log_w.tag_configure("pfx_h", font=(self.font, sz, "bold"))
        self._log_w.bind("<Control-MouseWheel>", _ctrl_scroll)
        self._log_w.bind("<Control-Button-4>",   _ctrl_scroll)
        self._log_w.bind("<Control-Button-5>",   _ctrl_scroll)

        # Right-click → copy context menu
        def _show_copy_menu(event):
            menu = tk.Menu(self._log_w, tearoff=0, bg=th["BG3"], fg=th["FG"],
                           activebackground=th["BORDER2"], activeforeground=th["WHITE"],
                           font=(self.font, 9), bd=0, relief="flat")
            def _copy():
                try:
                    sel = self._log_w.get(tk.SEL_FIRST, tk.SEL_LAST)
                    self.root.clipboard_clear()
                    self.root.clipboard_append(sel)
                except tk.TclError:
                    pass
            menu.add_command(label="  Copy  ", command=_copy)
            menu.add_separator()
            menu.add_command(label="  Select All  ",
                command=lambda: self._log_w.tag_add(tk.SEL, "1.0", "end"))
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()
        self._log_w.bind("<Button-3>", _show_copy_menu)

        # Ctrl+C and middle-click — explicit bindings (disabled state blocks defaults)
        def _do_copy(event=None):
            try:
                sel = self._log_w.get(tk.SEL_FIRST, tk.SEL_LAST)
                self.root.clipboard_clear()
                self.root.clipboard_append(sel)
                self._copy_flash()
            except tk.TclError:
                pass
            return "break"
        self._log_w.bind("<Control-c>", _do_copy)
        self._log_w.bind("<Control-C>", _do_copy)
        self._log_w.bind("<Button-2>",  lambda e: _do_copy())

        # Divider
        tk.Frame(content,bg=th["BORDER"],width=1).grid(row=0,column=1,sticky="ns")

        # Right panel
        rp=tk.Frame(content,bg=th["BG2"],width=200)
        rp.grid(row=0,column=2,sticky="ns"); rp.pack_propagate(False)

        def phdr(p,txt):
            f=tk.Frame(p,bg=th["BG3"],height=22); f.pack(fill="x"); f.pack_propagate(False)
            tk.Label(f,text=txt,font=(self.font,7,"bold"),bg=th["BG3"],fg=th["FG3"]
                ).pack(side="left",padx=10,pady=3)
        phdr(rp, t("status_hdr"))

        sf=tk.Frame(rp,bg=th["BG2"]); sf.pack(fill="x",padx=10,pady=6)
        self._stats={}
        for k,v in [(t("stat_status"),"IDLE"),(t("stat_target"),"—"),
                    (t("stat_ip"),"—"),(t("stat_ports"),"—"),
                    (t("stat_ssl"),"—"),(t("stat_sec"),"—"),(t("stat_time"),"—")]:
            r=tk.Frame(sf,bg=th["BG2"]); r.pack(fill="x",pady=1)
            tk.Label(r,text=f"{k:<8}",font=(self.font,8),bg=th["BG2"],fg=th["FG3"],anchor="w").pack(side="left")
            vl=tk.Label(r,text=v,font=(self.font,9,"bold"),bg=th["BG2"],fg=th["FG2"],anchor="w")
            vl.pack(side="left"); self._stats[k]=vl

        tk.Frame(rp,bg=th["BORDER"],height=1).pack(fill="x",pady=(4,0))
        phdr(rp, t("steps_hdr"))
        stepf=tk.Frame(rp,bg=th["BG2"]); stepf.pack(fill="x",padx=10,pady=6)
        self._step_w=[]
        for name in t("steps"):
            r=tk.Frame(stepf,bg=th["BG2"]); r.pack(fill="x",pady=1)
            dot=tk.Label(r,text="○",font=(self.font,10),bg=th["BG2"],fg=th["FG3"])
            dot.pack(side="left",padx=(0,5))
            lbl=tk.Label(r,text=name,font=(self.font,9),bg=th["BG2"],fg=th["FG3"],anchor="w")
            lbl.pack(side="left"); self._step_w.append((dot,lbl))

        # ─ Bottom bar ───────────────────────────────────────────
        tk.Frame(root,bg=th["BORDER"],height=1).pack(fill="x",side="bottom")
        bot=tk.Frame(root,bg=th["BG3"],height=26); bot.pack(fill="x",side="bottom")
        bot.pack_propagate(False)
        self._prog_lbl=tk.Label(bot,text=t("ready"),font=(self.font,7,"bold"),
            bg=th["BG3"],fg=th["FG3"])
        self._prog_lbl.pack(side="left",padx=12,pady=5)
        self._cv=tk.Canvas(bot,height=4,bg=th["BG"],highlightthickness=0,bd=0)
        self._cv.pack(side="left",fill="x",expand=True,padx=10,pady=11)
        # GitHub link
        gh=tk.Label(bot,text="github.com/c3less",font=(self.font,7),
            bg=th["BG3"],fg=th["FG3"],cursor="hand2")
        gh.pack(side="right",padx=6)
        gh.bind("<Button-1>",lambda _: self._open_url("https://github.com/c3less"))
        gh.bind("<Enter>",lambda _: gh.config(fg=th["FG"]))
        gh.bind("<Leave>",lambda _: gh.config(fg=th["FG3"]))
        tk.Label(bot,text="·",font=(self.font,7),bg=th["BG3"],fg=th["FG3"]).pack(side="right")
        # Telegram link
        tg=tk.Label(bot,text="t.me/c3less",font=(self.font,7),
            bg=th["BG3"],fg=th["FG3"],cursor="hand2")
        tg.pack(side="right",padx=6)
        tg.bind("<Button-1>",lambda _: self._open_url("https://t.me/c3less"))
        tg.bind("<Enter>",lambda _: tg.config(fg=th["FG"]))
        tg.bind("<Leave>",lambda _: tg.config(fg=th["FG3"]))
        tk.Label(bot,text="·",font=(self.font,7),bg=th["BG3"],fg=th["FG3"]).pack(side="right")
        tk.Label(bot,text="v2.0",font=(self.font,7),
            bg=th["BG3"],fg=th["FG3"]).pack(side="right",padx=6)

        # Bind resize to redraw progress
        self._cv.bind("<Configure>", lambda _: self._draw_prog(self._prog_val))

        # Key bindings
        self.root.bind("<Return>", lambda _: self._on_scan())
        self.root.bind("<Escape>", lambda _: self._on_cancel())

        # Initial message
        self.root.update_idletasks()
        self._draw_prog(0)
        self._push(t("init_msg"), "INFO")

    # ── Hover effects ──────────────────────────────────────────
    def _btn_hover(self):
        th=self.th; b=self._btn
        def e(_): b.config(bg=th["BTN_HOV"]) if not self.scanning else None
        def l(_): b.config(bg=th["BTN_BG"])  if not self.scanning else None
        b.bind("<Enter>",e); b.bind("<Leave>",l)

    def _ef_in(self, _):
        if not self._dvar.get(): self._entry.config(fg=self.th["FG"])
        self._entry_glow(0, True)

    def _ef_out(self, _):
        self._entry_glow(0, False)

    def _entry_glow(self, step, focus_in):
        """Pulse the entry border on focus in/out."""
        try: frame = self._entry_frame
        except AttributeError: return
        th = self.th
        if focus_in:
            steps = [th["BORDER3"], th["WHITE"], th["BORDER3"], th["BORDER2"]]
        else:
            steps = [th["BORDER3"], th["BORDER2"]]
        if step < len(steps):
            try: frame.config(bg=steps[step])
            except: return
            self.root.after(55, lambda: self._entry_glow(step + 1, focus_in))

    # ── Pulsing dot animation ──────────────────────────────────
    def _pulse_dot(self):
        if not hasattr(self,"_dot"): return
        th=self.th
        colors=[th["FG3"],th["FG2"],th["FG"],th["WHITE"],th["FG"],th["FG2"]]
        try:
            if self.scanning:
                self._dot.config(fg=colors[self._dot_state%len(colors)])
            else:
                self._dot.config(fg=th["FG3"])
            self._dot_state+=1
        except: pass
        self.root.after(350, self._pulse_dot)

    # ── Controls ───────────────────────────────────────────────
    def _toggle_lang(self):
        SETTINGS["lang"]="RU" if SETTINGS["lang"]=="EN" else "EN"
        save_settings(SETTINGS); self._apply_theme()

    def _cycle_theme(self):
        order=["dark","light","midnight","custom"]
        cur=SETTINGS.get("theme","dark")
        nxt=order[(order.index(cur)+1)%len(order)]
        SETTINGS["theme"]=nxt; save_settings(SETTINGS); self._apply_theme()

    def _open_settings(self):
        SettingsDialog(self.root, self._apply_theme)

    def _copy_flash(self):
        """Brief highlight flash on the log widget when text is copied."""
        try:
            orig  = self._log_w.cget("bg")
            flash = self.th.get("BORDER2", "#444444")
            self._log_w.configure(bg=flash)
            self.root.after(140, lambda: self._log_w.configure(bg=orig))
        except Exception:
            pass

    def _open_url(self, url: str):
        import webbrowser
        webbrowser.open(url)

    def _press_effect(self, btn):
        """Subtle visual depress: darken on click, restore on release."""
        th = self.th
        orig = btn.cget("bg")
        def on_press(_):  btn.config(bg=th.get("BORDER2", "#444"))
        def on_release(_): btn.config(bg=orig)
        btn.bind("<ButtonPress-1>",   on_press,   add="+")
        btn.bind("<ButtonRelease-1>", on_release, add="+")

    def _on_close(self):
        if self.scanning:
            import tkinter.messagebox as mb
            ans = mb.askyesnocancel(
                "WebGate — Scan in progress",
                "A scan is currently running.\n\n"
                "• Yes  — continue in background (window closes, scan finishes, report saved)\n"
                "• No   — stop scan and close\n"
                "• Cancel — go back",
                icon="warning"
            )
            if ans is None:    # Cancel
                return
            elif ans is True:  # Yes — background
                self.root.withdraw()
                def _wait_and_quit():
                    while self.scanning:
                        time.sleep(0.5)
                    self.root.after(0, self.root.destroy)
                threading.Thread(target=_wait_and_quit, daemon=True).start()
                return
            else:              # No — stop
                if self.scanner:
                    self.scanner.cancelled = True
        self.root.destroy()

    # ── Progress bar ───────────────────────────────────────────
    def _draw_prog(self, val:int):
        self._prog_val=val; cv=self._cv; cv.delete("all")
        w=cv.winfo_width(); h=cv.winfo_height()
        if w<2: return
        cv.create_rectangle(0,0,w,h,fill=self.th["BG3"],outline="")
        if val>0:
            fw=max(4,int(w*val/100))
            cv.create_rectangle(0,0,fw,h,fill=self.th["WHITE"],outline="")

    def _smooth_prog(self,target,cur=None,step=2):
        if cur is None: cur=self._prog_val
        if cur<target:
            cur=min(cur+step,target); self._draw_prog(cur)
            self.root.after(14,lambda: self._smooth_prog(target,cur,step))
        else: self._draw_prog(target)

    def _set_prog(self,v): self.root.after(0,lambda: self._smooth_prog(v))

    # ── Log system ─────────────────────────────────────────────
    _PFX={"INFO":"  ·  ","FOUND":"  +  ","WARN":"  !  ",
          "ERROR":"  ✗  ","STEP":"  »  ","SUCCESS":"  ✓  "}

    def _ins(self, txt:str, *tags):
        self._log_w.configure(state="normal")
        self._log_w.insert("end", txt, tags)
        self._log_w.see("end")
        self._log_w.configure(state="disabled")
        lines=int(self._log_w.index("end-1c").split(".")[0])
        try: self._evt_lbl.config(text=f"{max(0,lines-1)} lines")
        except: pass

    def _push(self, msg:str, level:str="INFO", rule:bool=False):
        self._log_q.append((msg,level,rule))
        if not self._log_busy:
            self._log_busy=True; self.root.after(0,self._flush)

    def _flush(self):
        if not self._log_q: self._log_busy=False; return
        msg,level,rule=self._log_q.pop(0)
        if rule:
            self._ins(f"{msg}\n","rule")
            self.root.after(10,self._flush); return
        ts=datetime.now().strftime("%H:%M:%S")
        pfx=self._PFX.get(level,"  ·  ")
        ltag=f"lvl_{level}"
        ptag="pfx_h" if level in ("STEP","SUCCESS","ERROR") else ltag
        self._ins(f"[{ts}]","ts"); self._ins(pfx,ptag)
        if level=="STEP":
            self._type_msg(msg,level,0, cb=lambda: self.root.after(50,self._flush))
        else:
            self._ins(f"{msg}\n",ltag)
            self.root.after(18,self._flush)

    def _type_msg(self, text:str, level:str, idx:int, cb):
        if idx>=len(text):
            self._ins("\n"); cb(); return
        self._ins(text[idx],f"lvl_{level}")
        if SETTINGS.get("sound") and idx%2==0: play_click()
        self.root.after(12, lambda: self._type_msg(text,level,idx+1,cb))

    def log_from_thread(self, msg:str, level:str):
        self.root.after(0, lambda: self._push(msg,level))

    # ── Step indicators ────────────────────────────────────────
    def _set_step(self, idx:int, state:str):
        if idx>=len(self._step_w): return
        dot,lbl=self._step_w[idx]; th=self.th
        cfg={"active":("◉",th["WHITE"],th["WHITE"]),
             "done":  ("●",th["FG2"],  th["FG2"]),
             "error": ("✗",th["BORDER3"],th["BORDER3"]),
             "pending":("○",th["FG3"],th["FG3"])}.get(state,("○",th["FG3"],th["FG3"]))
        dot.config(text=cfg[0],fg=cfg[1]); lbl.config(fg=cfg[2])

    def _reset_steps(self):
        for i in range(len(self._step_w)): self._set_step(i,"pending")

    def _stat(self,k,v,c=None):
        lbl=self._stats.get(k)
        if lbl: lbl.config(text=str(v),fg=c or self.th["FG"])

    # ── Scan lifecycle ─────────────────────────────────────────
    def _on_scan(self):
        if self.scanning: return
        domain=self._dvar.get().strip()
        if not domain: self._push(t("enter_domain"),"WARN"); return
        self._begin_scan(domain)

    def _on_deep_scan(self):
        if self.scanning: return
        domain=self._dvar.get().strip()
        if not domain: self._push(t("enter_domain"),"WARN"); return
        DisclaimerDialog(self.root, lambda: self._begin_scan(domain, deep=True))

    def _on_cancel(self):
        if self.scanner and self.scanning:
            self.scanner.cancelled=True
            self._push("Cancelling...","WARN")

    def _begin_scan(self, domain:str, deep:bool=False):
        self.scanning=True; th=self.th
        self._btn.config(text=t("scanning"),state="disabled",
            bg=th["BTN_DIS_BG"],fg=th["BTN_DIS_FG"])
        self._deep_btn.config(state="disabled")
        self._cancel_btn.pack(side="left",padx=(6,0))
        self._entry.config(state="disabled")
        self._reset_steps()
        self._log_q.clear(); self._log_busy=False
        self._log_w.configure(state="normal"); self._log_w.delete("1.0","end")
        self._log_w.configure(state="disabled"); self._evt_lbl.config(text="")
        self._draw_prog(0)
        # Stats reset
        tk=self.tk; th=self.th
        self._stat(t("stat_status"),"SCANNING",th["WHITE"])
        self._stat(t("stat_target"),domain,th["FG"])
        for k in [t("stat_ip"),t("stat_ports"),t("stat_ssl"),t("stat_sec"),t("stat_time")]:
            self._stat(k,"—",th["FG2"])
        self._prog_lbl.config(text=t("scanning"))
        self._scan_start=time.time(); self._tick()
        self._step_idx=[0]
        threading.Thread(target=self._thread,args=(domain,deep),daemon=True).start()

    def _tick(self):
        if self.scanning:
            el=time.time()-self._scan_start
            self._stat(t("stat_time"),f"{el:.0f}s",self.th["FG2"])
            self.root.after(1000,self._tick)

    def _thread(self, domain:str, deep:bool):
        idx=[0]
        def on_log(msg,level):
            if level=="STEP":
                i=idx[0]
                if i>0: self.root.after(0,lambda k=i-1: self._set_step(k,"done"))
                self.root.after(0,lambda k=i: self._set_step(k,"active"))
                idx[0]+=1
            th=self.th
            if "IPv4"        in msg: self.root.after(0,lambda v=msg.split(":")[-1].strip(): self._stat(t("stat_ip"),v,th["FG"]))
            if "Open:"       in msg: self.root.after(0,lambda v=msg.split("Open:")[-1].split()[0]: self._stat(t("stat_ports"),v,th["FG"]))
            if "Security score" in msg: self.root.after(0,lambda v=msg.split(":")[-1].strip(): self._stat(t("stat_sec"),v,th["FG"]))
            if "TLS version" in msg: self.root.after(0,lambda: self._stat(t("stat_ssl"),"✓ OK",th["FG"]))
            if "Port 443 closed" in msg or "no HTTPS" in msg: self.root.after(0,lambda: self._stat(t("stat_ssl"),"✗",th["FG2"]))
            self.log_from_thread(msg,level)
        def on_prog(v): self._set_prog(v)

        self.scanner=DomainScanner(domain,log_cb=on_log,prog_cb=on_prog)
        report=self.scanner.run()
        results=self.scanner.results

        if deep and not self.scanner.cancelled:
            # Switch step list display
            ds=DeepScanner(domain,log_cb=on_log,prog_cb=on_prog)
            self.scanner=ds  # for cancel support
            ds.run()

        last=idx[0]-1
        if last>=0: self.root.after(0,lambda k=last: self._set_step(k,"done"))
        self.root.after(0,lambda: self._done(report, results, domain, self.scanner.cancelled))

    def _done(self, report:str, results:dict, domain:str, cancelled:bool):
        self.scanning=False; th=self.th
        self._btn.config(text=t("scan_btn"),state="normal",
            bg=th["BTN_BG"],fg=th["BTN_FG"])
        self._deep_btn.config(state="normal")
        self._cancel_btn.pack_forget()
        self._entry.config(state="normal")
        self._prog_lbl.config(text=t("cancelled") if cancelled else t("complete"))
        self._stat(t("stat_status"),"CANCELLED" if cancelled else "COMPLETE ✓",
            th["FG2"] if cancelled else th["WHITE"])
        if not cancelled:
            self._draw_prog(100)
            if report: self._push(f"Report: {report}","FOUND")
            # Notification
            send_notification(t("notif_title"),f"{t('notif_body')} {domain}")
            # Summary popup
            self.root.after(500, lambda: SummaryPopup(self.root,results,domain))
            # Blinking cursor
            self.root.after(800, self._blink)

    def _blink(self, count=0):
        if count>=14 or self.scanning: return
        self._log_w.configure(state="normal")
        try: self._log_w.delete("cs","ce")
        except: pass
        if count%2==0:
            self._log_w.mark_set("cs","end-1c")
            self._log_w.insert("end","█","cursor")
            self._log_w.mark_set("ce","end-1c")
        self._log_w.configure(state="disabled")
        self.root.after(450, lambda: self._blink(count+1))

    def run(self): pass  # mainloop runs in launch_gui


# ═══════════════════════════════════════════════════════════════
# LAUNCH GUI
# ═══════════════════════════════════════════════════════════════

def launch_gui(domain:str=""):
    _init_sound()

    # ── Wayland / Hyprland compatibility ──────────────────────
    # tkinter uses X11 backend; on Wayland we need XWayland.
    # Set DISPLAY if not set (Hyprland usually exposes :0 or :1).
    if sys.platform.startswith("linux"):
        if not os.environ.get("DISPLAY"):
            # Try common display values
            for d in (":0", ":1", ":10"):
                os.environ["DISPLAY"] = d
                try:
                    import tkinter as _tk_test
                    _r = _tk_test.Tk(); _r.destroy()
                    break
                except Exception:
                    continue
        # Force X11 backend for Wayland compositors (Hyprland, Sway, etc.)
        os.environ.setdefault("GDK_BACKEND", "x11")
        os.environ.setdefault("QT_QPA_PLATFORM", "xcb")

    try:
        import tkinter as tk
    except ImportError:
        print("tkinter not available. Install python-tk."); return

    # Single Tk() root for the entire app lifetime
    root = tk.Tk()
    root.withdraw()   # hidden until splash completes

    def _show_main():
        app = SecurityScannerGUI(root=root, prefill=domain)
        # fade in the main window
        root.attributes("-alpha", 0.0)
        _fade_in_root(root)

    def _fade_in_root(r, a=0.0):
        target = SETTINGS.get("transparency", 0.94)
        a = min(target, a + 0.07)
        try: r.attributes("-alpha", a)
        except: pass
        if a < target: r.after(18, lambda: _fade_in_root(r, a))

    SplashScreen(root, _show_main)
    root.mainloop()


# ═══════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════

def _ensure_git_repo():
    """Create git repo + .gitignore in script dir if not already initialised."""
    if os.path.exists(os.path.join(_SCRIPT_DIR, ".git")):
        return
    try:
        subprocess.run(["git", "init", _SCRIPT_DIR], capture_output=True)
        gi = os.path.join(_SCRIPT_DIR, ".gitignore")
        if not os.path.exists(gi):
            with open(gi, "w") as f:
                f.write("# WebGate — auto-generated\n"
                        "*.pyc\n__pycache__/\nsettings.json\n"
                        "audit_*.txt\n*.wav\n.env\n")
    except Exception:
        pass


def main():
    _init_sound()
    _ensure_git_repo()
    # Brief disclaimer when launched via symlink (e.g. /usr/local/bin/webgate)
    if _IS_SYMLINK and sys.stdout.isatty():
        _Y = '\033[33m'; _RST = '\033[0m'
        print(f"\n  {_Y}{'─'*62}{_RST}")
        print(f"  {_Y}[!]  WebGate — for AUTHORIZED security testing only.{_RST}")
        print(f"  {_Y}     Only scan systems you own or have written permission to test.{_RST}")
        print(f"  {_Y}{'─'*62}{_RST}\n")
    p=argparse.ArgumentParser(prog="webgate",add_help=False)
    p.add_argument("-d","--domain",default="")
    p.add_argument("--gui",action="store_true")
    p.add_argument("--no-color",action="store_true")
    p.add_argument("-h","--help",action="store_true")
    args=p.parse_args()

    if args.no_color: C.disable()
    if args.help:
        print(BANNER)
        print("  python webgate.py              →  CLI shell")
        print("  python webgate.py --gui        →  GUI")
        print("  python webgate.py -d domain    →  Quick scan")
        return
    if args.gui:
        launch_gui(domain=args.domain); return
    cli=CLIInterface()
    if args.domain: cli.quick(args.domain)
    else: cli.shell()

if __name__=="__main__":
    main()
