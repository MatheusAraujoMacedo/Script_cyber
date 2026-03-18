#!/usr/bin/env python3
"""
VulnRecon — Interactive CLI Security Auditing Tool
A polished, menu-driven vulnerability scanner with styled terminal UI.
Modules: Port Scanner | HTTP Headers | Dir Fuzzer | Admin Hunter | CVE Scanner | Cloud Buckets
"""

import os
import platform
import re
import socket
import sys
import threading
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

try:
    import requests
    from requests.exceptions import ConnectionError, Timeout, RequestException
except ImportError:
    print("\n  [!] Dependencia ausente: 'requests'")
    print("      Instale com: pip install requests\n")
    sys.exit(1)


# ─────────────────────────────────────────────────────
#  Console Setup
# ─────────────────────────────────────────────────────

def setup_console():
    """Configure console for UTF-8 output and ANSI escape code support."""
    if platform.system() == "Windows":
        os.system("chcp 65001 >nul 2>&1")
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def clear_screen():
    """Clear the terminal screen."""
    os.system("cls" if platform.system() == "Windows" else "clear")


def get_panel_width():
    """Calculate optimal panel width based on terminal size."""
    try:
        cols = os.get_terminal_size().columns
    except (ValueError, OSError):
        cols = 80
    return min(cols - 4, 68)


# ─────────────────────────────────────────────────────
#  ANSI Color Codes
# ─────────────────────────────────────────────────────

class C:
    """Compact ANSI escape codes."""
    R    = "\033[91m"
    G    = "\033[92m"
    Y    = "\033[93m"
    M    = "\033[95m"
    CY   = "\033[96m"
    W    = "\033[97m"
    BLD  = "\033[1m"
    DIM  = "\033[2m"
    RST  = "\033[0m"


# ─────────────────────────────────────────────────────
#  UI Drawing Utilities
# ─────────────────────────────────────────────────────

def _vlen(text):
    """Visible length of text (strips ANSI codes)."""
    return len(re.sub(r'\033\[[0-9;]*m', '', text))


def draw_box(lines, width=60, title="", bc=None):
    """Draw a Unicode-bordered box around content lines."""
    if bc is None:
        bc = C.CY
    r = C.RST
    iw = width - 2

    if title:
        tl = _vlen(title)
        rpad = max(iw - tl - 4, 0)
        print(f"  {bc}┌── {r}{title} {bc}{'─' * rpad}┐{r}")
    else:
        print(f"  {bc}┌{'─' * iw}┐{r}")

    print(f"  {bc}│{r}{' ' * iw}{bc}│{r}")
    for line in lines:
        pad = max(iw - _vlen(line), 0)
        print(f"  {bc}│{r}{line}{' ' * pad}{bc}│{r}")
    print(f"  {bc}│{r}{' ' * iw}{bc}│{r}")
    print(f"  {bc}└{'─' * iw}┘{r}")


def draw_table(headers, rows, bc=None):
    """Draw a styled table with box-drawing characters."""
    if bc is None:
        bc = C.CY
    r = C.RST
    cw = [h[1] for h in headers]

    # Top
    print(f"  {bc}┌" + "┬".join("─" * (w + 2) for w in cw) + f"┐{r}")
    # Header
    line = f"  {bc}│{r}"
    for (label, w) in headers:
        pad = max(w - _vlen(label), 0)
        line += f" {C.BLD}{C.W}{label}{r}{' ' * (pad + 1)}{bc}│{r}"
    print(line)
    # Sep
    print(f"  {bc}├" + "┼".join("─" * (w + 2) for w in cw) + f"┤{r}")
    # Rows
    for row in rows:
        line = f"  {bc}│{r}"
        for i, cell in enumerate(row):
            pad = max(cw[i] - _vlen(cell), 0)
            line += f" {cell}{' ' * (pad + 1)}{bc}│{r}"
        print(line)
    # Bottom
    print(f"  {bc}└" + "┴".join("─" * (w + 2) for w in cw) + f"┘{r}")


# ─────────────────────────────────────────────────────
#  Loading Spinner
# ─────────────────────────────────────────────────────

class Spinner:
    """Animated loading spinner for long-running operations."""
    FRAMES = ["|", "/", "-", "\\"]

    def __init__(self, msg="Processando..."):
        self.msg = msg
        self._on = False
        self._t = None

    def start(self):
        self._on = True
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def stop(self, done=None):
        self._on = False
        if self._t:
            self._t.join()
        if done:
            print(f"\r  {C.G}✓{C.RST} {done}{' ' * 30}")
        else:
            print(f"\r{' ' * 60}\r", end="")

    def _run(self):
        i = 0
        while self._on:
            f = self.FRAMES[i % len(self.FRAMES)]
            print(f"\r  {C.CY}{f}{C.RST} {self.msg}", end="", flush=True)
            time.sleep(0.12)
            i += 1


# ─────────────────────────────────────────────────────
#  Banners
# ─────────────────────────────────────────────────────

BANNER = f"""
{C.CY}{C.BLD}  ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗
  ██║   ██║██║   ██║██║     ████╗  ██║
  ██║   ██║██║   ██║██║     ██╔██╗ ██║
  ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║
   ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║
    ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝{C.RST}
{C.W}{C.BLD}           R  E  C  O  N{C.RST}
{C.DIM}  ──────────────────────────────────────
{C.W}   Security Auditing Tool  {C.DIM}v3.0
  ──────────────────────────────────────{C.RST}
"""

BANNER_MINI = f"\n{C.CY}{C.BLD}  ▸ VULNRECON{C.RST} {C.DIM}v3.0{C.RST}\n{C.DIM}  ──────────────────────────────────────{C.RST}\n"


# ─────────────────────────────────────────────────────
#  Target Resolution
# ─────────────────────────────────────────────────────

def resolve_target(raw):
    """Parse and validate target. Returns dict or None."""
    raw = raw.strip()
    if not raw:
        return None
    if not raw.startswith(("http://", "https://")):
        url = f"http://{raw}"
    else:
        url = raw
    hostname = urlparse(url).hostname
    if not hostname:
        return None
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        return None
    return {"hostname": hostname, "ip": ip, "url": url}


def prompt_target():
    """Interactively prompt for a target with validation. Returns dict or None."""
    w = get_panel_width()
    while True:
        print()
        draw_box([
            f"  {C.W}{C.BLD}Digite o alvo para escanear{C.RST}",
            f"  {C.DIM}Hostname, IP ou URL (ex: scanme.nmap.org){C.RST}",
            f"  {C.Y}Digite 0 para voltar ao menu{C.RST}",
        ], width=w, title=f"{C.CY}{C.BLD}ALVO{C.RST}")
        print()
        try:
            user_input = input(f"  {C.CY}▸{C.RST} ").strip()
        except (KeyboardInterrupt, EOFError):
            return None
        if user_input in ("0", ""):
            return None

        spinner = Spinner("Resolvendo alvo...")
        spinner.start()
        target = resolve_target(user_input)
        spinner.stop()

        if target is None:
            print()
            draw_box([
                f"  {C.R}Nao foi possivel resolver '{user_input}'{C.RST}",
                f"  {C.DIM}Verifique o hostname/IP e sua conexao.{C.RST}",
            ], width=w, title=f"{C.R}{C.BLD}ERRO{C.RST}", bc=C.R)
            continue

        print()
        draw_box([
            f"  {C.G}Alvo resolvido com sucesso!{C.RST}",
            f"  {C.W}Host: {C.BLD}{target['hostname']}{C.RST}",
            f"  {C.W}IP:   {C.BLD}{target['ip']}{C.RST}",
        ], width=w, title=f"{C.G}{C.BLD}OK{C.RST}", bc=C.G)
        return target


# ─────────────────────────────────────────────────────
#  Module 1: Port Scanner
# ─────────────────────────────────────────────────────

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}


def _scan_port(ip, port, timeout):
    svc = COMMON_PORTS.get(port, "?")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return {"port": port, "service": svc, "is_open": s.connect_ex((ip, port)) == 0}
    except (socket.timeout, OSError):
        return {"port": port, "service": svc, "is_open": False}


def run_port_scanner(target, timeout=1.5, threads=20):
    w = get_panel_width()
    print(BANNER_MINI)
    draw_box([
        f"  {C.W}Alvo:    {C.BLD}{target['hostname']}{C.RST} ({target['ip']})",
        f"  {C.W}Portas:  {C.BLD}{len(COMMON_PORTS)}{C.RST} | Timeout: {C.BLD}{timeout}s{C.RST} | Threads: {C.BLD}{threads}{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}SCANNER DE PORTAS{C.RST}")

    print()
    sp = Spinner("Escaneando portas...")
    sp.start()
    t0 = time.time()
    results = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_scan_port, target["ip"], p, timeout): p for p in COMMON_PORTS}
        for f in as_completed(futs):
            try:
                results.append(f.result())
            except Exception:
                p = futs[f]
                results.append({"port": p, "service": COMMON_PORTS.get(p, "?"), "is_open": False})
    elapsed = time.time() - t0
    sp.stop(f"Scan concluido em {elapsed:.2f}s")

    results.sort(key=lambda r: r["port"])
    hdr = [("Porta", 8), ("Servico", 14), ("Status", 16)]
    rows = []
    open_n = 0
    for r in results:
        if r["is_open"]:
            open_n += 1
            rows.append([f"{r['port']}/tcp", r["service"], f"{C.R}{C.BLD}● ABERTA{C.RST}"])
        else:
            rows.append([f"{r['port']}/tcp", r["service"], f"{C.G}○ FECHADA{C.RST}"])

    print()
    draw_table(hdr, rows)
    closed_n = len(results) - open_n
    print()
    if open_n:
        draw_box([
            f"  {C.R}{C.BLD}{open_n} aberta(s){C.RST} {C.DIM}|{C.RST} {C.G}{closed_n} fechada(s){C.RST}",
            f"  {C.Y}Portas abertas podem indicar servicos expostos!{C.RST}",
        ], width=w, title=f"{C.Y}{C.BLD}RESULTADO{C.RST}", bc=C.Y)
    else:
        draw_box([
            f"  {C.G}{C.BLD}Todas as {len(results)} portas estao fechadas.{C.RST}",
        ], width=w, title=f"{C.G}{C.BLD}RESULTADO{C.RST}", bc=C.G)
    return results


# ─────────────────────────────────────────────────────
#  Module 2: HTTP Security Headers
# ─────────────────────────────────────────────────────

SECURITY_HEADERS = {
    "Strict-Transport-Security": ("ALTA",  "Protege contra SSL-stripping."),
    "X-Frame-Options":          ("MEDIA", "Previne clickjacking (iframe)."),
    "X-Content-Type-Options":   ("MEDIA", "Previne MIME-type sniffing."),
    "Content-Security-Policy":  ("ALTA",  "Controla recursos, mitiga XSS."),
    "X-XSS-Protection":         ("BAIXA", "Filtro XSS legado (fallback)."),
    "Referrer-Policy":           ("BAIXA", "Controla info de referrer."),
    "Permissions-Policy":        ("MEDIA", "Restringe camera, mic, geoloc."),
}
SEV_C = {"ALTA": C.R, "MEDIA": C.Y, "BAIXA": C.DIM}


def run_header_analysis(target, timeout=10):
    w = get_panel_width()
    print(BANNER_MINI)
    draw_box([
        f"  {C.W}Alvo: {C.BLD}{target['url']}{C.RST}",
        f"  {C.W}Headers analisados: {C.BLD}{len(SECURITY_HEADERS)}{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}CABECALHOS DE SEGURANCA{C.RST}")

    print()
    sp = Spinner("Requisitando cabecalhos...")
    sp.start()
    try:
        resp = requests.get(target["url"], timeout=timeout, allow_redirects=True, verify=False)
    except (Timeout, ConnectionError, RequestException) as e:
        sp.stop()
        print()
        draw_box([f"  {C.R}Falha na conexao: {e}{C.RST}"], width=w, title=f"{C.R}{C.BLD}ERRO{C.RST}", bc=C.R)
        return {"present": [], "missing": list(SECURITY_HEADERS.keys()), "error": True}

    sp.stop(f"HTTP {resp.status_code} — {len(resp.headers)} headers recebidos")

    present, missing, lines = [], [], []
    for h, (sev, desc) in SECURITY_HEADERS.items():
        sc = SEV_C.get(sev, C.W)
        val = resp.headers.get(h)
        if val:
            present.append(h)
            v = (val[:38] + "...") if len(val) > 38 else val
            lines.append(f"  {C.G}✓{C.RST} {C.W}{h}{C.RST}")
            lines.append(f"    {C.DIM}{v}{C.RST}")
        else:
            missing.append(h)
            lines.append(f"  {C.R}✗{C.RST} {C.W}{h}{C.RST} {sc}[{sev}]{C.RST}")
            lines.append(f"    {C.DIM}{desc}{C.RST}")

    print()
    draw_box(lines, width=w, title=f"{C.CY}{C.BLD}ANALISE{C.RST}")

    score = len(present) / len(SECURITY_HEADERS) * 100
    sc = C.G if score >= 70 else (C.Y if score >= 40 else C.R)
    print()
    draw_box([
        f"  {C.W}Score: {sc}{C.BLD}{score:.0f}%{C.RST} ({len(present)}/{len(SECURITY_HEADERS)})",
        f"  {C.G}{C.BLD}{len(present)} presente(s){C.RST} {C.DIM}|{C.RST} {C.R}{C.BLD}{len(missing)} ausente(s){C.RST}",
    ], width=w, title=f"{C.Y}{C.BLD}RESULTADO{C.RST}", bc=sc)
    return {"present": present, "missing": missing, "error": False}


# ─────────────────────────────────────────────────────
#  Module 3: Directory Fuzzer
# ─────────────────────────────────────────────────────

FUZZ_PATHS = [
    "/.git/", "/.git/config", "/.gitignore", "/.svn/", "/.hg/",
    "/.env", "/.env.bak", "/config.php", "/config.yml",
    "/wp-config.php", "/web.config",
    "/admin", "/admin/", "/administrator/", "/wp-admin/",
    "/wp-login.php", "/phpmyadmin/", "/cpanel", "/webmail",
    "/backup.zip", "/backup.tar.gz", "/database.sql",
    "/db.sql", "/dump.sql", "/.htaccess", "/.htpasswd",
    "/server-status", "/server-info", "/phpinfo.php", "/info.php",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/humans.txt", "/security.txt", "/.well-known/security.txt",
    "/api/", "/api/v1/", "/swagger.json", "/openapi.json", "/graphql",
]
INTERESTING = {200, 201, 301, 302, 307, 308, 401, 403, 500}
STATUS_LBL = {
    200: ("ENCONTRADO", C.R), 201: ("ENCONTRADO", C.R),
    301: ("REDIRECT", C.Y), 302: ("REDIRECT", C.Y),
    307: ("REDIRECT", C.Y), 308: ("REDIRECT", C.Y),
    401: ("PROTEGIDO", C.M), 403: ("PROIBIDO", C.M),
    500: ("ERRO SVR", C.Y),
}


def _fuzz_path(base, path, timeout):
    try:
        r = requests.get(base.rstrip("/") + path, timeout=timeout,
                         allow_redirects=False, verify=False,
                         headers={"User-Agent": "VulnRecon/2.0"})
        return {"path": path, "code": r.status_code, "hit": r.status_code in INTERESTING}
    except (Timeout, ConnectionError, RequestException):
        return {"path": path, "code": None, "hit": False}


def run_directory_fuzzer(target, timeout=5, threads=10):
    w = get_panel_width()
    print(BANNER_MINI)
    draw_box([
        f"  {C.W}Alvo:     {C.BLD}{target['url']}{C.RST}",
        f"  {C.W}Wordlist: {C.BLD}{len(FUZZ_PATHS)}{C.RST} rotas | Threads: {C.BLD}{threads}{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}CACA-DIRETORIOS{C.RST}")

    print()
    sp = Spinner("Fuzzing em andamento...")
    sp.start()
    t0 = time.time()
    results = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_fuzz_path, target["url"], p, timeout): p for p in FUZZ_PATHS}
        for f in as_completed(futs):
            try:
                results.append(f.result())
            except Exception:
                results.append({"path": futs[f], "code": None, "hit": False})
    elapsed = time.time() - t0
    sp.stop(f"Fuzzing concluido em {elapsed:.2f}s")

    results.sort(key=lambda r: (not r["hit"], r["path"]))
    hdr = [("Rota", 30), ("HTTP", 6), ("Veredicto", 14)]
    rows = []
    hit_n = 0
    for r in results:
        p = r["path"][:28] + ".." if len(r["path"]) > 30 else r["path"]
        if r["code"] is None:
            rows.append([f"{C.DIM}{p}{C.RST}", f"{C.DIM}---{C.RST}", f"{C.DIM}TIMEOUT{C.RST}"])
        elif r["hit"]:
            hit_n += 1
            lbl, clr = STATUS_LBL.get(r["code"], ("FOUND", C.Y))
            rows.append([p, f"{clr}{r['code']}{C.RST}", f"{clr}{C.BLD}{lbl}{C.RST}"])
        else:
            rows.append([f"{C.DIM}{p}{C.RST}", f"{C.DIM}{r['code']}{C.RST}", f"{C.G}OK{C.RST}"])

    print()
    draw_table(hdr, rows)
    safe_n = len(results) - hit_n
    print()
    if hit_n:
        draw_box([
            f"  {C.R}{C.BLD}{hit_n} exposta(s){C.RST} {C.DIM}|{C.RST} {C.G}{safe_n} segura(s){C.RST}",
            f"  {C.Y}Rotas expostas podem vazar informacoes sensiveis!{C.RST}",
        ], width=w, title=f"{C.Y}{C.BLD}RESULTADO{C.RST}", bc=C.Y)
    else:
        draw_box([
            f"  {C.G}{C.BLD}Nenhuma rota sensivel exposta.{C.RST}",
        ], width=w, title=f"{C.G}{C.BLD}RESULTADO{C.RST}", bc=C.G)
    return results


# ─────────────────────────────────────────────────────
#  Module 4: Advanced Admin Panel Hunter
# ─────────────────────────────────────────────────────

ADMIN_PATHS = [
    # WordPress
    ("/wp-login.php", "WordPress"),
    ("/wp-admin/", "WordPress"),
    ("/wp-admin/install.php", "WordPress"),
    # Joomla
    ("/administrator/", "Joomla"),
    ("/administrator/index.php", "Joomla"),
    # Drupal
    ("/user/login", "Drupal"),
    ("/admin/", "Drupal/Generic"),
    # Magento
    ("/admin", "Magento/Generic"),
    ("/index.php/admin/", "Magento"),
    # phpMyAdmin
    ("/phpmyadmin/", "phpMyAdmin"),
    ("/pma/", "phpMyAdmin"),
    ("/myadmin/", "phpMyAdmin"),
    ("/phpmyadmin/index.php", "phpMyAdmin"),
    # Tomcat
    ("/manager/html", "Apache Tomcat"),
    ("/manager/status", "Apache Tomcat"),
    ("/host-manager/html", "Apache Tomcat"),
    # cPanel / Plesk / Webmin
    ("/cpanel", "cPanel"),
    ("/webmail", "cPanel Webmail"),
    ("/whm/", "WHM (cPanel)"),
    ("/plesk/", "Plesk"),
    ("/webmin/", "Webmin"),
    # Generic
    ("/admin/login", "Generic"),
    ("/admin/login.php", "Generic PHP"),
    ("/login", "Generic"),
    ("/login.php", "Generic PHP"),
    ("/panel/", "Generic Panel"),
    ("/dashboard/", "Generic Dashboard"),
    ("/controlpanel/", "Generic"),
    ("/adminpanel/", "Generic"),
    ("/cms/", "Generic CMS"),
    ("/cms/admin/", "Generic CMS"),
    # Django / Laravel / Rails
    ("/admin/login/?next=/admin/", "Django"),
    ("/nova/login", "Laravel Nova"),
    ("/rails/info", "Ruby on Rails"),
]

# Fingerprint patterns: (substring_in_html, technology_name)
CMS_FINGERPRINTS = [
    ("wp-content", "WordPress"),
    ("wp-includes", "WordPress"),
    ("Joomla", "Joomla"),
    ("/media/jui/", "Joomla"),
    ("Drupal", "Drupal"),
    ("drupal.js", "Drupal"),
    ("Magento", "Magento"),
    ("phpMyAdmin", "phpMyAdmin"),
    ("Apache Tomcat", "Apache Tomcat"),
    ("cPanel", "cPanel"),
    ("Plesk", "Plesk"),
    ("django", "Django"),
    ("csrfmiddlewaretoken", "Django"),
    ("laravel", "Laravel"),
    ("rails", "Ruby on Rails"),
]


def _probe_admin_path(base_url, path, expected_cms, timeout):
    """Send GET to an admin path; return result with optional CMS fingerprint."""
    full_url = base_url.rstrip("/") + path
    try:
        resp = requests.get(
            full_url, timeout=timeout, allow_redirects=True, verify=False,
            headers={"User-Agent": "VulnRecon/3.0 (Security Audit)"}
        )
        code = resp.status_code
        detected_cms = None

        # Only fingerprint on 200/401/403 responses (page exists)
        if code in (200, 401, 403):
            body = resp.text[:5000].lower()  # Read first 5KB only
            for pattern, cms_name in CMS_FINGERPRINTS:
                if pattern.lower() in body:
                    detected_cms = cms_name
                    break
            if detected_cms is None:
                detected_cms = expected_cms

        return {
            "path": path,
            "code": code,
            "cms": detected_cms,
            "found": code in (200, 301, 302, 401, 403),
        }
    except (Timeout, ConnectionError, RequestException):
        return {"path": path, "code": None, "cms": None, "found": False}


def run_admin_hunter(target, timeout=5, threads=10):
    """Run the Advanced Admin Panel Hunter module."""
    w = get_panel_width()
    print(BANNER_MINI)
    draw_box([
        f"  {C.W}Alvo:     {C.BLD}{target['url']}{C.RST}",
        f"  {C.W}Wordlist: {C.BLD}{len(ADMIN_PATHS)}{C.RST} rotas de admin | Threads: {C.BLD}{threads}{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}CACA-PAINEIS DE ADMIN{C.RST}")

    print()
    sp = Spinner("Buscando paineis de administracao...")
    sp.start()
    t0 = time.time()
    results = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {
            ex.submit(_probe_admin_path, target["url"], path, cms, timeout): path
            for path, cms in ADMIN_PATHS
        }
        for f in as_completed(futs):
            try:
                results.append(f.result())
            except Exception:
                results.append({"path": futs[f], "code": None, "cms": None, "found": False})
    elapsed = time.time() - t0
    sp.stop(f"Busca concluida em {elapsed:.2f}s")

    # Sort: found first
    results.sort(key=lambda r: (not r["found"], r["path"]))

    hdr = [("Rota", 28), ("HTTP", 6), ("CMS/Tech", 16), ("Status", 12)]
    rows = []
    found_n = 0
    for r in results:
        p = r["path"][:26] + ".." if len(r["path"]) > 28 else r["path"]
        cms = r["cms"] or "-"
        if len(cms) > 16:
            cms = cms[:14] + ".."
        if r["code"] is None:
            rows.append([f"{C.DIM}{p}{C.RST}", f"{C.DIM}---{C.RST}",
                         f"{C.DIM}-{C.RST}", f"{C.DIM}TIMEOUT{C.RST}"])
        elif r["found"]:
            found_n += 1
            clr = C.R if r["code"] == 200 else C.M
            lbl = "ABERTO" if r["code"] == 200 else ("PROTEGIDO" if r["code"] in (401, 403) else "REDIRECT")
            rows.append([p, f"{clr}{r['code']}{C.RST}",
                         f"{C.Y}{C.BLD}{cms}{C.RST}", f"{clr}{C.BLD}{lbl}{C.RST}"])
        else:
            rows.append([f"{C.DIM}{p}{C.RST}", f"{C.DIM}{r['code']}{C.RST}",
                         f"{C.DIM}-{C.RST}", f"{C.G}N/A{C.RST}"])

    print()
    draw_table(hdr, rows)
    safe_n = len(results) - found_n
    print()
    if found_n:
        # Collect unique CMS detected
        detected = set(r["cms"] for r in results if r["found"] and r["cms"])
        cms_str = ", ".join(sorted(detected)) if detected else "Nao identificado"
        draw_box([
            f"  {C.R}{C.BLD}{found_n} painel(is) encontrado(s){C.RST} {C.DIM}|{C.RST} {C.G}{safe_n} nao encontrado(s){C.RST}",
            f"  {C.W}Tecnologia detectada: {C.Y}{C.BLD}{cms_str}{C.RST}",
            f"  {C.Y}Paineis expostos sao alvos de brute-force!{C.RST}",
        ], width=w, title=f"{C.Y}{C.BLD}RESULTADO{C.RST}", bc=C.Y)
    else:
        draw_box([
            f"  {C.G}{C.BLD}Nenhum painel de admin encontrado.{C.RST}",
        ], width=w, title=f"{C.G}{C.BLD}RESULTADO{C.RST}", bc=C.G)
    return results


# ─────────────────────────────────────────────────────
#  Module 5: Public Vulnerability Scanner (CVE Lookup)
# ─────────────────────────────────────────────────────

def _extract_software_versions(headers):
    """
    Extract software names and versions from HTTP response headers.
    Returns a list of (software_name, version_string) tuples.
    """
    software = []
    # Server header (e.g., "Apache/2.4.41 (Ubuntu)")
    server = headers.get("Server", "")
    if server:
        # Parse tokens like "Apache/2.4.41" or "nginx/1.18.0"
        for token in server.replace(",", " ").split():
            if "/" in token:
                parts = token.split("/", 1)
                name = parts[0].strip("()").strip()
                ver = parts[1].strip("()").strip()
                if name and ver and any(c.isdigit() for c in ver):
                    software.append((name, ver))
            elif token.lower() not in ("(ubuntu)", "(debian)", "(centos)", "(win64)", "(win32)"):
                # Standalone server name without version
                if any(c.isalpha() for c in token) and token not in ("(", ")"):
                    pass  # Skip tokens without version info

    # X-Powered-By header (e.g., "PHP/7.4.3")
    powered = headers.get("X-Powered-By", "")
    if powered:
        for token in powered.replace(",", " ").split():
            if "/" in token:
                parts = token.split("/", 1)
                name = parts[0].strip()
                ver = parts[1].strip()
                if name and ver and any(c.isdigit() for c in ver):
                    software.append((name, ver))

    # X-AspNet-Version
    aspnet = headers.get("X-AspNet-Version", "")
    if aspnet:
        software.append(("ASP.NET", aspnet.strip()))

    # X-AspNetMvc-Version
    mvc = headers.get("X-AspNetMvc-Version", "")
    if mvc:
        software.append(("ASP.NET MVC", mvc.strip()))

    return software


def _query_nvd_cves(keyword, max_results=5, timeout=15):
    """
    Query the NIST NVD API for CVEs matching a keyword.
    Returns a list of dicts: {cve_id, severity, description}.
    Uses the public API (no API key required, rate-limited).
    """
    api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
    }
    try:
        resp = requests.get(api_url, params=params, timeout=timeout, verify=True)
        if resp.status_code != 200:
            return []
        data = resp.json()
    except (Timeout, ConnectionError, RequestException, json.JSONDecodeError):
        return []

    cves = []
    for vuln in data.get("vulnerabilities", []):
        cve_data = vuln.get("cve", {})
        cve_id = cve_data.get("id", "N/A")

        # Extract severity from CVSS v3.1 or v3.0 or v2.0
        severity = "N/A"
        metrics = cve_data.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(key, [])
            if metric_list:
                cvss = metric_list[0].get("cvssData", {})
                score = cvss.get("baseScore", "N/A")
                sev_label = metric_list[0].get("baseSeverity",
                            cvss.get("baseSeverity", "N/A"))
                severity = f"{score} ({sev_label})"
                break

        # Extract description (English)
        desc = "Sem descricao disponivel."
        for d in cve_data.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", desc)[:80]
                break

        cves.append({"cve_id": cve_id, "severity": severity, "description": desc})

    return cves


def run_cve_scanner(target, timeout=10):
    """Run the CVE Lookup module based on HTTP header fingerprinting."""
    w = get_panel_width()
    print(BANNER_MINI)
    draw_box([
        f"  {C.W}Alvo: {C.BLD}{target['url']}{C.RST}",
        f"  {C.DIM}Coleta versoes dos headers HTTP e consulta{C.RST}",
        f"  {C.DIM}a API publica do NIST NVD por CVEs conhecidas.{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}SCANNER DE CVEs{C.RST}")

    # Step 1: Fetch headers
    print()
    sp = Spinner("Coletando headers do servidor...")
    sp.start()
    try:
        resp = requests.get(target["url"], timeout=timeout, allow_redirects=True, verify=False)
    except (Timeout, ConnectionError, RequestException) as e:
        sp.stop()
        print()
        draw_box([f"  {C.R}Falha na conexao: {e}{C.RST}"], width=w,
                 title=f"{C.R}{C.BLD}ERRO{C.RST}", bc=C.R)
        return []
    sp.stop(f"HTTP {resp.status_code} — Headers coletados")

    # Step 2: Extract software versions
    software = _extract_software_versions(resp.headers)

    if not software:
        print()
        draw_box([
            f"  {C.G}Nenhum software com versao exposta nos headers.{C.RST}",
            f"  {C.DIM}O servidor nao revelou versoes em Server,{C.RST}",
            f"  {C.DIM}X-Powered-By ou outros headers comuns.{C.RST}",
        ], width=w, title=f"{C.G}{C.BLD}RESULTADO{C.RST}", bc=C.G)
        return []

    # Show detected software
    sw_lines = []
    for name, ver in software:
        sw_lines.append(f"  {C.Y}▸{C.RST} {C.W}{C.BLD}{name}{C.RST} {C.DIM}v{ver}{C.RST}")
    print()
    draw_box(sw_lines, width=w, title=f"{C.CY}{C.BLD}SOFTWARE DETECTADO{C.RST}")

    # Step 3: Query NVD for each software
    all_cves = []
    for name, ver in software:
        keyword = f"{name} {ver}"
        print()
        sp = Spinner(f"Consultando NVD para {name} {ver}...")
        sp.start()
        cves = _query_nvd_cves(keyword)
        sp.stop(f"{len(cves)} CVE(s) encontrada(s) para {name} {ver}")

        if cves:
            hdr_def = [("CVE ID", 18), ("Severidade", 16), ("Descricao", 28)]
            rows = []
            for c in cves:
                sev = c["severity"]
                # Color based on severity
                if "CRITICAL" in sev.upper():
                    sev_display = f"{C.R}{C.BLD}{sev}{C.RST}"
                elif "HIGH" in sev.upper():
                    sev_display = f"{C.R}{sev}{C.RST}"
                elif "MEDIUM" in sev.upper():
                    sev_display = f"{C.Y}{sev}{C.RST}"
                else:
                    sev_display = f"{C.DIM}{sev}{C.RST}"

                desc = c["description"][:26] + ".." if len(c["description"]) > 28 else c["description"]
                rows.append([c["cve_id"], sev_display, desc])
            all_cves.extend(cves)

            print()
            draw_table(hdr_def, rows)

        # NVD rate limit: be nice (6 sec between calls without API key)
        if len(software) > 1:
            time.sleep(2)

    # Final summary
    total = len(all_cves)
    print()
    if total:
        draw_box([
            f"  {C.R}{C.BLD}{total} CVE(s) publica(s) encontrada(s){C.RST}",
            f"  {C.W}Software:  {C.Y}{', '.join(f'{n} {v}' for n, v in software)}{C.RST}",
            f"  {C.Y}Versoes expostas facilitam ataques direcionados!{C.RST}",
        ], width=w, title=f"{C.Y}{C.BLD}RESULTADO{C.RST}", bc=C.Y)
    else:
        draw_box([
            f"  {C.G}{C.BLD}Nenhuma CVE publica encontrada.{C.RST}",
            f"  {C.DIM}Isso nao garante seguranca total.{C.RST}",
        ], width=w, title=f"{C.G}{C.BLD}RESULTADO{C.RST}", bc=C.G)
    return all_cves


# ─────────────────────────────────────────────────────
#  Module 6: Exposed Cloud Bucket Checker
# ─────────────────────────────────────────────────────

# Common bucket URL patterns to test
def _generate_bucket_urls(hostname):
    """
    Generate potential cloud bucket URLs based on the target hostname.
    Tests common naming conventions for S3, Azure Blob, and GCS.
    """
    # Strip common prefixes to get the base domain name
    base = hostname.replace("www.", "").split(".")[0]
    buckets = []

    # Amazon S3 patterns
    s3_names = [base, f"{base}-backup", f"{base}-assets", f"{base}-static",
                f"{base}-media", f"{base}-uploads", f"{base}-data",
                f"{base}-dev", f"{base}-staging", f"{base}-prod",
                f"{base}-public", f"{base}-private", f"{base}-logs"]
    for name in s3_names:
        buckets.append({
            "url": f"https://{name}.s3.amazonaws.com",
            "provider": "AWS S3",
            "bucket": name,
        })

    # Azure Blob Storage patterns
    azure_names = [base, f"{base}storage", f"{base}data"]
    for name in azure_names:
        buckets.append({
            "url": f"https://{name}.blob.core.windows.net",
            "provider": "Azure Blob",
            "bucket": name,
        })

    # Google Cloud Storage patterns
    gcs_names = [base, f"{base}-public", f"{base}-assets"]
    for name in gcs_names:
        buckets.append({
            "url": f"https://storage.googleapis.com/{name}",
            "provider": "Google GCS",
            "bucket": name,
        })

    return buckets


def _check_single_bucket(bucket_info, timeout):
    """
    Check if a cloud bucket exists and is publicly accessible.
    Returns the bucket_info dict augmented with 'status' and 'public' fields.
    """
    url = bucket_info["url"]
    try:
        resp = requests.get(
            url, timeout=timeout, allow_redirects=True, verify=True,
            headers={"User-Agent": "VulnRecon/3.0 (Security Audit)"}
        )
        code = resp.status_code
        body = resp.text[:2000].lower()

        # Determine status
        if code == 200:
            # Check if it's actually listing contents (public read)
            is_listing = any(marker in body for marker in [
                "<listbucketresult",   # S3 XML listing
                "<enumerationresults",  # Azure XML listing
                "<listresult",          # GCS listing
                "<contents>",           # S3 contents
                "\"items\":",           # GCS JSON
            ])
            bucket_info["status"] = "PUBLICO" if is_listing else "EXISTE"
            bucket_info["public"] = is_listing
            bucket_info["code"] = code
        elif code == 403:
            bucket_info["status"] = "PRIVADO"
            bucket_info["public"] = False
            bucket_info["code"] = code
        elif code == 404:
            bucket_info["status"] = "NAO EXISTE"
            bucket_info["public"] = False
            bucket_info["code"] = code
        else:
            bucket_info["status"] = f"HTTP {code}"
            bucket_info["public"] = False
            bucket_info["code"] = code

    except (Timeout, ConnectionError, RequestException):
        bucket_info["status"] = "TIMEOUT"
        bucket_info["public"] = False
        bucket_info["code"] = None

    return bucket_info


def run_cloud_checker(target, timeout=5, threads=10):
    """Run the Exposed Cloud Bucket Checker module."""
    w = get_panel_width()
    print(BANNER_MINI)

    buckets = _generate_bucket_urls(target["hostname"])
    draw_box([
        f"  {C.W}Alvo:      {C.BLD}{target['hostname']}{C.RST}",
        f"  {C.W}Buckets:   {C.BLD}{len(buckets)}{C.RST} combinacoes testadas",
        f"  {C.W}Providers: {C.BLD}AWS S3, Azure Blob, Google GCS{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}VERIFICADOR DE BUCKETS NA NUVEM{C.RST}")

    print()
    sp = Spinner("Verificando buckets na nuvem...")
    sp.start()
    t0 = time.time()
    results = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_check_single_bucket, b, timeout): b["url"] for b in buckets}
        for f in as_completed(futs):
            try:
                results.append(f.result())
            except Exception:
                pass
    elapsed = time.time() - t0
    sp.stop(f"Verificacao concluida em {elapsed:.2f}s")

    # Sort: public first, then exists, then rest
    priority = {"PUBLICO": 0, "EXISTE": 1, "PRIVADO": 2}
    results.sort(key=lambda r: (priority.get(r["status"], 9), r["provider"], r["bucket"]))

    hdr = [("Provider", 12), ("Bucket", 20), ("Status", 12), ("Risco", 10)]
    rows = []
    public_n = 0
    exists_n = 0
    for r in results:
        bname = r["bucket"][:18] + ".." if len(r["bucket"]) > 20 else r["bucket"]
        st = r["status"]
        if st == "PUBLICO":
            public_n += 1
            exists_n += 1
            rows.append([r["provider"], bname,
                         f"{C.R}{C.BLD}{st}{C.RST}", f"{C.R}{C.BLD}CRITICO{C.RST}"])
        elif st == "EXISTE":
            exists_n += 1
            rows.append([r["provider"], bname,
                         f"{C.Y}{st}{C.RST}", f"{C.Y}MEDIO{C.RST}"])
        elif st == "PRIVADO":
            exists_n += 1
            rows.append([r["provider"], bname,
                         f"{C.G}{st}{C.RST}", f"{C.G}BAIXO{C.RST}"])
        elif st == "NAO EXISTE":
            rows.append([f"{C.DIM}{r['provider']}{C.RST}", f"{C.DIM}{bname}{C.RST}",
                         f"{C.DIM}{st}{C.RST}", f"{C.DIM}-{C.RST}"])
        else:
            rows.append([f"{C.DIM}{r['provider']}{C.RST}", f"{C.DIM}{bname}{C.RST}",
                         f"{C.DIM}{st}{C.RST}", f"{C.DIM}-{C.RST}"])

    print()
    draw_table(hdr, rows)
    print()

    if public_n:
        draw_box([
            f"  {C.R}{C.BLD}{public_n} bucket(s) PUBLICO(S) encontrado(s)!{C.RST}",
            f"  {C.Y}Buckets publicos podem vazar dados sensiveis,{C.RST}",
            f"  {C.Y}backups e credenciais. Risco CRITICO!{C.RST}",
        ], width=w, title=f"{C.R}{C.BLD}RESULTADO{C.RST}", bc=C.R)
    elif exists_n:
        draw_box([
            f"  {C.Y}{C.BLD}{exists_n} bucket(s) encontrado(s), nenhum publico.{C.RST}",
            f"  {C.DIM}Buckets existem mas requerem autenticacao.{C.RST}",
        ], width=w, title=f"{C.Y}{C.BLD}RESULTADO{C.RST}", bc=C.Y)
    else:
        draw_box([
            f"  {C.G}{C.BLD}Nenhum bucket na nuvem encontrado.{C.RST}",
        ], width=w, title=f"{C.G}{C.BLD}RESULTADO{C.RST}", bc=C.G)
    return results


# ─────────────────────────────────────────────────────
#  Full Audit
# ─────────────────────────────────────────────────────

def _pause_and_clear():
    """Pause for user input and clear screen."""
    print()
    input(f"  {C.DIM}Pressione Enter para continuar...{C.RST}")
    clear_screen()


def run_full_audit(target):
    """Run all 6 modules sequentially with pauses between them."""
    w = get_panel_width()

    port_res = run_port_scanner(target)
    _pause_and_clear()

    hdr_res = run_header_analysis(target)
    _pause_and_clear()

    fuzz_res = run_directory_fuzzer(target)
    _pause_and_clear()

    admin_res = run_admin_hunter(target)
    _pause_and_clear()

    cve_res = run_cve_scanner(target)
    _pause_and_clear()

    cloud_res = run_cloud_checker(target)

    # Summary
    op = len([r for r in port_res if r["is_open"]])
    mh = len(hdr_res.get("missing", []))
    ed = len([r for r in fuzz_res if r["hit"]])
    ap = len([r for r in admin_res if r["found"]])
    cv = len(cve_res)
    pb = len([r for r in cloud_res if r.get("public")])
    total = op + mh + ed + ap + cv + pb

    if total == 0:
        risk, rc = "BAIXO", C.G
    elif total < 5:
        risk, rc = "MEDIO", C.Y
    elif total < 10:
        risk, rc = "ALTO", C.R
    else:
        risk, rc = "CRITICO", C.R

    print()
    draw_box([
        f"  {C.W}{C.BLD}Alvo: {target['hostname']}{C.RST} ({target['ip']})",
        "",
        f"  {C.CY}Portas abertas:      {C.R if op else C.G}{C.BLD}{op}{C.RST}",
        f"  {C.CY}Headers ausentes:    {C.R if mh else C.G}{C.BLD}{mh}{C.RST}",
        f"  {C.CY}Diretorios expostos: {C.R if ed else C.G}{C.BLD}{ed}{C.RST}",
        f"  {C.CY}Paineis de admin:    {C.R if ap else C.G}{C.BLD}{ap}{C.RST}",
        f"  {C.CY}CVEs encontradas:    {C.R if cv else C.G}{C.BLD}{cv}{C.RST}",
        f"  {C.CY}Buckets publicos:    {C.R if pb else C.G}{C.BLD}{pb}{C.RST}",
        "",
        f"  {C.W}Total de achados: {rc}{C.BLD}{total}{C.RST}",
        f"  {C.W}Nivel de risco:   {rc}{C.BLD}{risk}{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}RESUMO DA AUDITORIA{C.RST}")


# ─────────────────────────────────────────────────────
#  Help / About Page
# ─────────────────────────────────────────────────────

def show_help():
    """Display help page with explanations in Portuguese."""
    w = get_panel_width()
    print(BANNER_MINI)

    draw_box([
        f"  {C.CY}{C.BLD}VulnRecon{C.RST} e uma ferramenta de auditoria",
        f"  de seguranca que roda no terminal.",
        f"  Identifica vulnerabilidades em servidores.",
    ], width=w, title=f"{C.CY}{C.BLD}O QUE E?{C.RST}")

    print()
    draw_box([
        f"  {C.W}{C.BLD}[1] Scanner de Portas{C.RST}",
        f"  {C.DIM}Testa conexoes TCP em 20 portas criticas.{C.RST}",
        "",
        f"  {C.W}{C.BLD}[2] Cabecalhos de Seguranca{C.RST}",
        f"  {C.DIM}Analisa 7 headers HTTP de protecao.{C.RST}",
        "",
        f"  {C.W}{C.BLD}[3] Caca-Diretorios{C.RST}",
        f"  {C.DIM}Fuzzing em rotas sensiveis.{C.RST}",
        "",
        f"  {C.W}{C.BLD}[4] Caca-Paineis de Admin{C.RST}",
        f"  {C.DIM}Busca paineis + fingerprint de CMS.{C.RST}",
        "",
        f"  {C.W}{C.BLD}[5] Scanner de CVEs{C.RST}",
        f"  {C.DIM}Consulta CVEs via API do NIST NVD.{C.RST}",
        "",
        f"  {C.W}{C.BLD}[6] Verificador de Buckets{C.RST}",
        f"  {C.DIM}Checa buckets S3, Azure, GCS expostos.{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}MODULOS{C.RST}")

    print()
    draw_box([
        f"  {C.R}{C.BLD}AVISO LEGAL{C.RST}",
        "",
        f"  {C.W}Use SOMENTE em alvos com autorizacao.{C.RST}",
        f"  {C.W}Para testes, use:{C.RST}",
        f"  {C.G}{C.BLD}scanme.nmap.org{C.RST} {C.DIM}(autorizado pelo Nmap){C.RST}",
        "",
        f"  {C.DIM}Escanear sem permissao e ILEGAL e pode{C.RST}",
        f"  {C.DIM}resultar em consequencias juridicas.{C.RST}",
    ], width=w, title=f"{C.R}{C.BLD}USO LEGAL{C.RST}", bc=C.R)


# ─────────────────────────────────────────────────────
#  Interactive Menu
# ─────────────────────────────────────────────────────

def show_menu():
    """Display the main interactive menu."""
    w = get_panel_width()
    draw_box([
        f"  {C.CY}{C.BLD}[1]{C.RST}  {C.W}{C.BLD}Auditoria Completa{C.RST}",
        f"       {C.DIM}Todos os 6 modulos de uma vez{C.RST}",
        "",
        f"  {C.CY}{C.BLD}[2]{C.RST}  {C.W}{C.BLD}Escanear Portas{C.RST}",
        f"       {C.DIM}Testa conexoes TCP nas portas criticas{C.RST}",
        "",
        f"  {C.CY}{C.BLD}[3]{C.RST}  {C.W}{C.BLD}Verificar Cabecalhos HTTP{C.RST}",
        f"       {C.DIM}Analisa headers de seguranca do servidor{C.RST}",
        "",
        f"  {C.CY}{C.BLD}[4]{C.RST}  {C.W}{C.BLD}Cacar Diretorios Ocultos{C.RST}",
        f"       {C.DIM}Fuzzing em rotas sensiveis{C.RST}",
        "",
        f"  {C.CY}{C.BLD}[5]{C.RST}  {C.W}{C.BLD}Cacar Paineis de Admin{C.RST}",
        f"       {C.DIM}Detecta paineis + fingerprint de CMS{C.RST}",
        "",
        f"  {C.CY}{C.BLD}[6]{C.RST}  {C.W}{C.BLD}Scanner de CVEs{C.RST}",
        f"       {C.DIM}Consulta vulnerabilidades publicas (NVD){C.RST}",
        "",
        f"  {C.CY}{C.BLD}[7]{C.RST}  {C.W}{C.BLD}Verificador de Buckets na Nuvem{C.RST}",
        f"       {C.DIM}Checa S3, Azure Blob, Google GCS{C.RST}",
        "",
        f"  {C.CY}{C.BLD}[8]{C.RST}  {C.W}{C.BLD}Ajuda / Sobre{C.RST}",
        f"       {C.DIM}Conceitos e uso legal{C.RST}",
        "",
        f"  {C.R}{C.BLD}[0]{C.RST}  {C.DIM}Sair{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}MENU PRINCIPAL{C.RST}")


def run_scan_module(choice, target):
    """Execute the selected scan module."""
    clear_screen()
    if choice == "1":
        run_full_audit(target)
    elif choice == "2":
        run_port_scanner(target)
    elif choice == "3":
        run_header_analysis(target)
    elif choice == "4":
        run_directory_fuzzer(target)
    elif choice == "5":
        run_admin_hunter(target)
    elif choice == "6":
        run_cve_scanner(target)
    elif choice == "7":
        run_cloud_checker(target)


# ─────────────────────────────────────────────────────
#  Main Entry Point
# ─────────────────────────────────────────────────────

def main():
    """Main interactive loop."""
    setup_console()

    while True:
        clear_screen()
        print(BANNER)
        show_menu()
        print()

        try:
            choice = input(f"  {C.CY}▸ Escolha uma opcao:{C.RST} ").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n\n  {C.DIM}Ate logo!{C.RST}\n")
            break

        if choice == "0":
            clear_screen()
            print(BANNER)
            draw_box([
                f"  {C.G}Obrigado por usar o VulnRecon!{C.RST}",
                f"  {C.DIM}Fique seguro. Hackeie com responsabilidade.{C.RST}",
            ], width=get_panel_width(), title=f"{C.G}{C.BLD}ATE LOGO{C.RST}", bc=C.G)
            print()
            break

        elif choice == "8":
            clear_screen()
            show_help()
            print()
            input(f"  {C.DIM}Pressione Enter para voltar ao menu...{C.RST}")
            continue

        elif choice in ("1", "2", "3", "4", "5", "6", "7"):
            clear_screen()
            print(BANNER_MINI)
            target = prompt_target()
            if target is None:
                continue
            print()
            input(f"  {C.DIM}Pressione Enter para iniciar o scan...{C.RST}")
            run_scan_module(choice, target)
            print()
            input(f"  {C.DIM}Pressione Enter para voltar ao menu...{C.RST}")
            continue

        else:
            # Invalid input — show styled error
            print()
            draw_box([
                f"  {C.R}Opcao '{choice}' invalida.{C.RST}",
                f"  {C.DIM}Digite um numero de 0 a 8.{C.RST}",
            ], width=get_panel_width(), title=f"{C.R}{C.BLD}ERRO{C.RST}", bc=C.R)
            time.sleep(1.5)


if __name__ == "__main__":
    main()
