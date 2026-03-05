# WebGate v3.0 — Roadmap & Improvement Plan

## Текущее состояние (v3.0 — STABLE)
- ✅ 3403 строки кода
- ✅ 200+ CVE в SQLite базе (nginx, apache, PHP, WP, Joomla, Drupal, MySQL, SSH, SMB, RDP…)
- ✅ 30 инструментов (Nmap, WPScan, SQLMap, XSStrike, Gobuster, Commix + 24 внутренних)
- ✅ SplashScreen с анимацией и progress bar
- ✅ Прозрачность исправлена (wait_visibility + update_idletasks)
- ✅ Буфер обмена исправлен (clipboard_clear + clipboard_append + update)
- ✅ Чекбоксы перед Deep Scan (ToolSelectorDialog)
- ✅ SurfacePanel — выдвижная панель снизу с результатами поверхностного скана
- ✅ PortConfirmDialog — спрашивать ли по каждому порту
- ✅ ETA (приблизительное время до конца скана)
- ✅ Анимации: fade-in/out при смене темы/языка, glow entry, pulse dot, typed log
- ✅ Тема hacker (зелёный на чёрном)
- ✅ Скан не останавливается при смене темы/настроек
- ✅ install.sh для Arch/Debian/Fedora
- ✅ CLI с интерактивным shell

---

## v3.1 — Ближайшие улучшения

### UI/UX
- [ ] Gradient прогресс-бар (анимированный shimmer)
- [ ] Toast-уведомления внутри окна (popup снизу справа)
- [ ] Tabs: Basic | Advanced | Reports | Settings
- [ ] Drag & drop цели на поле ввода
- [ ] История сканирований (список последних целей)
- [ ] Dark/light mode keyboard shortcut (Ctrl+T)

### Сканер
- [ ] Параллельное сканирование портов (threading pool)
- [ ] Сохранение состояния скана (resume после обрыва)
- [ ] Скриншот страницы цели (selenium/playwright)
- [ ] WAF detection (обнаружение Cloudflare/Akamai/AWS Shield)
- [ ] CMS fingerprint (WhatWeb API)
- [ ] Технологии стека (Wappalyzer-style fingerprint)

### CVE / Intelligence
- [ ] Автообновление CVE базы из NVD API
- [ ] CVSS score отображение (цветовое)
- [ ] Exploit-DB lookup по CVE
- [ ] Severity badges (критично/высокий/средний/низкий)
- [ ] Export CVE отчёта в JSON/CSV

### Tools
- [ ] Nikto web scanner интеграция
- [ ] Metasploit module suggester по CVE
- [ ] Nuclei templates runner
- [ ] FFUF (fuzzing) интеграция
- [ ] Hydra brute force для найденных сервисов

---

## v3.2 — Средний срок

### Network
- [ ] Поддержка CIDR нотации (192.168.1.0/24)
- [ ] Bulk scan из файла с целями
- [ ] Subdomain enumeration (amass, subfinder)
- [ ] OSINT модуль (theHarvester, Shodan API)
- [ ] Traceroute визуализация

### Reporting
- [ ] HTML отчёт с CSS и графиками
- [ ] PDF экспорт (reportlab)
- [ ] Сравнение с предыдущим сканом (diff)
- [ ] Email отправка отчёта

### Auth & Config
- [ ] API ключи (Shodan, VirusTotal, IPInfo)
- [ ] Proxy поддержка (HTTP/SOCKS5)
- [ ] Rate limiting настройка
- [ ] User-Agent рандомизация

---

## v4.0 — Долгосрочно

### AI Integration
- [ ] LLM анализ уязвимостей (локальный ollama)
- [ ] Автоматические рекомендации по защите
- [ ] Smart scan: автовыбор инструментов по результатам поверхностного скана
- [ ] NLP парсинг вывода инструментов

### Architecture
- [ ] Plugin система (custom Python scanners)
- [ ] WebSocket real-time API
- [ ] Docker container с всеми инструментами
- [ ] CI/CD integration (GitHub Actions module)

---

## Известные ограничения v3.0
- Transparency работает только с X11 compositor (picom/compton)
- На чистом Wayland alpha может не работать (ограничение tkinter)
- WiFi tools (Reaver/Pixiewps) требуют wireless адаптер
- SET/Weeman требуют интерактивный terminal
- Arachni требует ручной установки

## Как запустить
```bash
bash install.sh          # установка
python3 webgate.py --gui # GUI
python3 webgate.py       # CLI
webgate                  # если создан symlink
```
