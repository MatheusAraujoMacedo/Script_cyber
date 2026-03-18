#!/usr/bin/env python3
"""
VulnRecon — Interactive CLI Security Auditing Tool
A polished, menu-driven vulnerability scanner with styled terminal UI.
Modules: Port Scanner | HTTP Headers | Dir Fuzzer | Admin Hunter | CVE Scanner | Cloud Buckets
"""

# ─────────────────────────────────────────────────────
#  VirusTotal API Key (insert yours below)
# ─────────────────────────────────────────────────────
VIRUSTOTAL_API_KEY = "d3907ef31017f69d9473428ea32aeb232dfa820ca70479c3377e8d02d77eab73"  

import os
import platform
import re
import socket
import sys
import threading
import time
import json
import random
import string
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import argparse

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
#  Stealth & Request Utilities
# ─────────────────────────────────────────────────────

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.0; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
]

# Global throttle delay (seconds) between requests per thread
THROTTLE_DELAY = 0.15


def _random_ua():
    """Return a random legitimate browser User-Agent string."""
    return random.choice(_USER_AGENTS)


def _vr_get(url, timeout=5, **kwargs):
    """
    VulnRecon GET wrapper with random User-Agent and throttle.
    Thread-safe; applies a small delay to avoid target overload.
    """
    time.sleep(random.uniform(THROTTLE_DELAY * 0.5, THROTTLE_DELAY * 1.5))
    headers = kwargs.pop("headers", {})
    headers.setdefault("User-Agent", _random_ua())
    return requests.get(
        url, timeout=timeout, verify=kwargs.pop("verify", False),
        allow_redirects=kwargs.pop("allow_redirects", True),
        headers=headers, **kwargs
    )


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
        r = _vr_get(base.rstrip("/") + path, timeout=timeout, allow_redirects=False)
        clen = len(r.content)
        return {"path": path, "code": r.status_code, "hit": r.status_code in INTERESTING, "clen": clen}
    except (Timeout, ConnectionError, RequestException):
        return {"path": path, "code": None, "hit": False, "clen": 0}


def run_directory_fuzzer(target, timeout=5, threads=10, wordlist_path=None):
    w = get_panel_width()
    print(BANNER_MINI)

    # Load wordlist: external file or built-in
    if wordlist_path and os.path.isfile(wordlist_path):
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            paths = [line.strip() for line in f if line.strip()]
            paths = [p if p.startswith("/") else "/" + p for p in paths]
        draw_box([
            f"  {C.W}Alvo:     {C.BLD}{target['url']}{C.RST}",
            f"  {C.W}Wordlist: {C.BLD}{wordlist_path}{C.RST} ({len(paths)} rotas)",
            f"  {C.W}Threads:  {C.BLD}{threads}{C.RST}",
        ], width=w, title=f"{C.CY}{C.BLD}CACA-DIRETORIOS{C.RST}")
    else:
        paths = FUZZ_PATHS
        draw_box([
            f"  {C.W}Alvo:     {C.BLD}{target['url']}{C.RST}",
            f"  {C.W}Wordlist: {C.BLD}{len(paths)}{C.RST} rotas (embutida) | Threads: {C.BLD}{threads}{C.RST}",
        ], width=w, title=f"{C.CY}{C.BLD}CACA-DIRETORIOS{C.RST}")

    # Baseline calibration: detect soft-404 / catch-all pages
    print()
    rand_slug = "/" + "".join(random.choices(string.ascii_lowercase, k=16))
    baseline_clen = None
    try:
        bl_resp = _vr_get(target["url"].rstrip("/") + rand_slug, timeout=timeout, allow_redirects=False)
        if bl_resp.status_code == 200:
            baseline_clen = len(bl_resp.content)
            draw_box([
                f"  {C.Y}Soft-404 detectado (catch-all page){C.RST}",
                f"  {C.DIM}Baseline: {baseline_clen} bytes — filtrando falsos positivos{C.RST}",
            ], width=w, title=f"{C.Y}{C.BLD}CALIBRACAO{C.RST}", bc=C.Y)
            print()
    except (Timeout, ConnectionError, RequestException):
        pass

    sp = Spinner("Fuzzing em andamento...")
    sp.start()
    t0 = time.time()
    results = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_fuzz_path, target["url"], p, timeout): p for p in paths}
        for f in as_completed(futs):
            try:
                results.append(f.result())
            except Exception:
                results.append({"path": futs[f], "code": None, "hit": False, "clen": 0})
    elapsed = time.time() - t0
    sp.stop(f"Fuzzing concluido em {elapsed:.2f}s")

    # Filter out soft-404 false positives
    if baseline_clen is not None:
        fp_count = 0
        for r in results:
            if r["hit"] and r["code"] == 200 and r["clen"] == baseline_clen:
                r["hit"] = False
                r["code_note"] = "SOFT-404"
                fp_count += 1
        if fp_count:
            draw_box([
                f"  {C.G}{fp_count} falso(s) positivo(s) filtrado(s) pelo baseline.{C.RST}",
            ], width=w, title=f"{C.G}{C.BLD}FILTRO{C.RST}", bc=C.G)
            print()

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
#  Module 7: WAF Detection (Pre-Scan)
# ─────────────────────────────────────────────────────

WAF_SIGNATURES = {
    "Cloudflare":  ["cloudflare", "cf-ray", "cf-cache-status", "__cfduid"],
    "Akamai":      ["akamai", "x-akamai", "akamaighost"],
    "Sucuri":      ["sucuri", "x-sucuri"],
    "AWS WAF":     ["awselb", "x-amzn", "x-amz-cf"],
    "Imperva":     ["imperva", "incapsula", "x-iinfo"],
    "F5 BIG-IP":   ["bigip", "f5", "x-wa-info"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "Barracuda":   ["barracuda", "barra_counter"],
    "Fortinet":    ["fortigate", "fortiWeb"],
    "Wordfence":   ["wordfence"],
}


def run_waf_detector(target, timeout=10):
    """Detect Web Application Firewalls via header analysis and probe."""
    w = get_panel_width()
    print(BANNER_MINI)
    draw_box([
        f"  {C.W}Alvo: {C.BLD}{target['url']}{C.RST}",
        f"  {C.DIM}Analise passiva de headers + probe inofensivo.{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}DETETOR DE WAF{C.RST}")

    detected = []

    # Phase 1: Normal request header analysis
    print()
    sp = Spinner("Analisando headers do servidor...")
    sp.start()
    try:
        resp = _vr_get(target["url"], timeout=timeout)
        all_headers = str(resp.headers).lower()
        server = resp.headers.get("Server", "").lower()

        for waf_name, patterns in WAF_SIGNATURES.items():
            for p in patterns:
                if p.lower() in all_headers or p.lower() in server:
                    detected.append({"waf": waf_name, "evidence": p, "method": "Headers"})
                    break
    except (Timeout, ConnectionError, RequestException):
        sp.stop()
        draw_box([f"  {C.R}Falha na conexao.{C.RST}"], width=w, bc=C.R,
                 title=f"{C.R}{C.BLD}ERRO{C.RST}")
        return detected
    sp.stop(f"Headers analisados")

    # Phase 2: Probe with blockable (but harmless) payload
    print()
    sp = Spinner("Enviando probe inofensivo para detecao de WAF...")
    sp.start()
    probe_url = target["url"].rstrip("/") + "/?id=<script>alert(1)</script>"
    try:
        probe_resp = _vr_get(probe_url, timeout=timeout)
        probe_headers = str(probe_resp.headers).lower()
        probe_body = probe_resp.text[:3000].lower()

        # Check if probe triggered WAF
        for waf_name, patterns in WAF_SIGNATURES.items():
            for p in patterns:
                if p.lower() in probe_headers or p.lower() in probe_body:
                    if not any(d["waf"] == waf_name for d in detected):
                        detected.append({"waf": waf_name, "evidence": p, "method": "Probe"})
                    break

        # Check for WAF-like blocking behavior
        if probe_resp.status_code in (403, 406, 429, 503):
            if not detected:
                detected.append({"waf": "Desconhecido", "evidence": f"HTTP {probe_resp.status_code} no probe", "method": "Probe"})

    except (Timeout, ConnectionError, RequestException):
        pass
    sp.stop(f"Probe concluido")

    # Display results
    print()
    if detected:
        hdr = [("WAF", 16), ("Evidencia", 24), ("Metodo", 10)]
        rows = [[d["waf"], d["evidence"], d["method"]] for d in detected]
        draw_table(hdr, rows)
        unique_wafs = set(d["waf"] for d in detected)
        print()
        draw_box([
            f"  {C.R}{C.BLD}{len(unique_wafs)} WAF(s) detectado(s)!{C.RST}",
            f"  {C.W}Identificados: {C.Y}{C.BLD}{', '.join(unique_wafs)}{C.RST}",
            f"  {C.Y}O WAF pode bloquear scans e alterar resultados.{C.RST}",
        ], width=w, title=f"{C.R}{C.BLD}ALERTA{C.RST}", bc=C.R)
    else:
        draw_box([
            f"  {C.G}{C.BLD}Nenhum WAF detectado.{C.RST}",
            f"  {C.DIM}O alvo nao parece ter firewall de aplicacao.{C.RST}",
        ], width=w, title=f"{C.G}{C.BLD}RESULTADO{C.RST}", bc=C.G)
    return detected


# ─────────────────────────────────────────────────────
#  Module 8: Passive Error-Based DB Scanner
# ─────────────────────────────────────────────────────

# Syntax-breaking chars (NOT exploitation payloads — just syntax probes)
_SYNTAX_PROBES = ["'", '"', "%00", "\\", ";", ")", "{{"]

# DB error signatures to detect in response body
_DB_ERROR_SIGS = [
    ("SQL syntax", "MySQL"),
    ("mysql_fetch", "MySQL"),
    ("mysql_num_rows", "MySQL"),
    ("You have an error in your SQL", "MySQL"),
    ("pg_query", "PostgreSQL"),
    ("pg_exec", "PostgreSQL"),
    ("PSQLException", "PostgreSQL"),
    ("unterminated quoted string", "PostgreSQL"),
    ("ORA-", "Oracle"),
    ("ODBC SQL Server", "MSSQL"),
    ("SQLServer JDBC", "MSSQL"),
    ("java.sql.SQLException", "Java/JDBC"),
    ("sqlite3.OperationalError", "SQLite"),
    ("near \":\": syntax error", "SQLite"),
    ("PDOException", "PHP PDO"),
    ("MongoError", "MongoDB"),
]


def _probe_param_for_errors(url, param, timeout):
    """
    Append a syntax-breaking character to a URL parameter
    and check if the response leaks database error messages.
    Does NOT exploit — only detects information disclosure.
    """
    findings = []
    for probe in _SYNTAX_PROBES:
        test_url = re.sub(
            f"({re.escape(param)}=)[^&]*",
            f"\\g<1>{probe}",
            url
        )
        try:
            resp = _vr_get(test_url, timeout=timeout, allow_redirects=True)
            body = resp.text[:8000]
            for sig, db_type in _DB_ERROR_SIGS:
                if sig.lower() in body.lower():
                    findings.append({
                        "param": param,
                        "probe": probe,
                        "db_type": db_type,
                        "signature": sig,
                        "url": test_url,
                    })
                    return findings  # One finding per param is enough
        except (Timeout, ConnectionError, RequestException):
            continue
    return findings


def run_error_db_scanner(target, timeout=8):
    """Run passive error-based DB scanner on discovered URL parameters."""
    w = get_panel_width()
    print(BANNER_MINI)
    draw_box([
        f"  {C.W}Alvo: {C.BLD}{target['url']}{C.RST}",
        f"  {C.DIM}Detecta divulgacao de erros de BD via{C.RST}",
        f"  {C.DIM}caracteres de quebra de sintaxe (passivo).{C.RST}",
        "",
        f"  {C.Y}Nao explora falhas — apenas detecta e reporta.{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}SCANNER DE ERROS DE BD{C.RST}")

    # Step 1: Extract parameterized URLs from page
    print()
    sp = Spinner("Extraindo URLs com parametros...")
    sp.start()
    param_urls = _extract_links_and_params(target["url"], timeout)
    sp.stop(f"{len(param_urls)} URL(s) com parametros encontrada(s)")

    if not param_urls:
        print()
        draw_box([
            f"  {C.G}Nenhum parametro encontrado para testar.{C.RST}",
            f"  {C.DIM}O alvo nao expoe URLs com parametros.{C.RST}",
        ], width=w, title=f"{C.G}{C.BLD}RESULTADO{C.RST}", bc=C.G)
        return []

    # Step 2: Test each parameterized URL
    all_findings = []
    tested = 0
    for item in param_urls[:15]:  # Limit to 15 URLs to avoid flooding
        for param in item["params"][:3]:  # Max 3 params per URL
            tested += 1
            print()
            sp = Spinner(f"Testando {param}=... ({tested})")
            sp.start()
            findings = _probe_param_for_errors(item["full_url"], param, timeout)
            if findings:
                sp.stop(f"Erro de BD detectado em '{param}'!")
                all_findings.extend(findings)
            else:
                sp.stop(f"'{param}' — sem divulgacao")

    # Display results
    print()
    if all_findings:
        hdr = [("Parametro", 12), ("Banco", 12), ("Assinatura", 26), ("Probe", 6)]
        rows = []
        for f in all_findings:
            sig = f["signature"][:24] + ".." if len(f["signature"]) > 26 else f["signature"]
            rows.append([f["param"], f"{C.R}{C.BLD}{f['db_type']}{C.RST}",
                         sig, f"{C.R}{f['probe']}{C.RST}"])
        draw_table(hdr, rows)
        print()
        draw_box([
            f"  {C.R}{C.BLD}{len(all_findings)} divulgacao(oes) de erro de BD!{C.RST}",
            f"  {C.Y}Erros de BD expostos revelam tecnologia interna{C.RST}",
            f"  {C.Y}e podem indicar vulnerabilidades de injection.{C.RST}",
            "",
            f"  {C.DIM}Reporte ao responsavel do sistema para correcao.{C.RST}",
        ], width=w, title=f"{C.R}{C.BLD}RESULTADO CRITICO{C.RST}", bc=C.R)
    else:
        draw_box([
            f"  {C.G}{C.BLD}Nenhum erro de BD detectado.{C.RST}",
            f"  {C.DIM}Testados {tested} parametro(s) sem divulgacao.{C.RST}",
        ], width=w, title=f"{C.G}{C.BLD}RESULTADO{C.RST}", bc=C.G)
    return all_findings


# ─────────────────────────────────────────────────────
#  Report Export
# ─────────────────────────────────────────────────────

def export_report(target, results_dict, output_path="report_vulnrecon.json"):
    """Export all scan results to a structured JSON report file."""
    w = get_panel_width()
    report = {
        "tool": "VulnRecon",
        "version": "3.0",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "target": {
            "hostname": target["hostname"],
            "ip": target["ip"],
            "url": target["url"],
        },
        "results": {},
    }

    # Serialize each module's results (filter non-serializable data)
    for module_name, data in results_dict.items():
        try:
            json.dumps(data)  # Test serializability
            report["results"][module_name] = data
        except (TypeError, ValueError):
            report["results"][module_name] = str(data)

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        draw_box([
            f"  {C.G}{C.BLD}Relatorio exportado com sucesso!{C.RST}",
            f"  {C.W}Arquivo: {C.BLD}{output_path}{C.RST}",
            f"  {C.DIM}{time.strftime('%Y-%m-%d %H:%M:%S')}{C.RST}",
        ], width=w, title=f"{C.G}{C.BLD}EXPORTACAO{C.RST}", bc=C.G)
    except (IOError, OSError) as e:
        draw_box([
            f"  {C.R}Falha ao salvar relatorio: {e}{C.RST}",
        ], width=w, title=f"{C.R}{C.BLD}ERRO{C.RST}", bc=C.R)


# ─────────────────────────────────────────────────────
#  Module 9: Passive Attack Surface Mapper
# ─────────────────────────────────────────────────────

# Database management panels to probe (passive — just check if they exist)
DB_PANEL_PATHS = [
    ("/adminer.php", "Adminer"),
    ("/adminer/", "Adminer"),
    ("/phpmyadmin/", "phpMyAdmin"),
    ("/pma/", "phpMyAdmin"),
    ("/myadmin/", "phpMyAdmin"),
    ("/phppgadmin/", "phpPgAdmin"),
    ("/pgadmin/", "pgAdmin"),
    ("/dbadmin/", "DB Admin"),
    ("/mysql/", "MySQL Panel"),
    ("/mongo-express/", "Mongo Express"),
    ("/rockmongo/", "RockMongo"),
    ("/redis-commander/", "Redis Commander"),
    ("/elasticsearch/", "Elasticsearch"),
    ("/_cat/indices", "Elasticsearch API"),
    ("/_cluster/health", "Elasticsearch API"),
    ("/solr/", "Apache Solr"),
    ("/couchdb/", "CouchDB"),
    ("/_utils/", "CouchDB Fauxton"),
    ("/_all_dbs", "CouchDB API"),
    ("/neo4j/", "Neo4j"),
]

# Patterns in HTML that indicate error/debug info disclosure
ERROR_PATTERNS = [
    ("SQL syntax", "ALTA", "Mensagem de erro SQL exposta"),
    ("mysql_fetch", "ALTA", "Funcao MySQL exposta no output"),
    ("pg_query", "ALTA", "Funcao PostgreSQL exposta"),
    ("ORA-", "ALTA", "Erro Oracle Database exposto"),
    ("ODBC SQL Server", "ALTA", "Erro MSSQL/ODBC exposto"),
    ("Traceback (most recent call last)", "ALTA", "Stack trace Python exposto"),
    ("at java.", "MEDIA", "Stack trace Java exposto"),
    ("at org.", "MEDIA", "Stack trace Java/Spring exposto"),
    ("Exception in thread", "MEDIA", "Excecao Java nao tratada"),
    ("Warning: ", "MEDIA", "Warning PHP exposto"),
    ("Fatal error", "ALTA", "Erro fatal PHP exposto"),
    ("Notice: ", "BAIXA", "Notice PHP exposto"),
    ("Parse error", "ALTA", "Erro de parse PHP exposto"),
    ("Stack Trace:", "MEDIA", "Stack trace .NET exposto"),
    ("Server Error in", "MEDIA", "Erro de servidor ASP.NET"),
    ("X-Debug-Token", "MEDIA", "Symfony debug token exposto"),
    ("DJANGO_SETTINGS_MODULE", "ALTA", "Config Django exposta"),
    ("DEBUG = True", "ALTA", "Modo debug Django ativo"),
    ("Laravel", "BAIXA", "Framework Laravel identificado"),
    ("APP_DEBUG", "ALTA", "Debug mode Laravel exposto"),
]


def _probe_db_panel(base_url, path, panel_name, timeout):
    """Check if a database management panel exists at the given path."""
    full_url = base_url.rstrip("/") + path
    try:
        resp = requests.get(
            full_url, timeout=timeout, allow_redirects=True, verify=False,
            headers={"User-Agent": "VulnRecon/3.0 (Security Audit)"}
        )
        code = resp.status_code
        found = code in (200, 301, 302, 401, 403)
        return {"path": path, "panel": panel_name, "code": code, "found": found}
    except (Timeout, ConnectionError, RequestException):
        return {"path": path, "panel": panel_name, "code": None, "found": False}


def _extract_links_and_params(url, timeout):
    """
    Fetch a page and extract all links with URL parameters.
    Returns a list of dicts: {url, params: [list of param names]}.
    This is purely passive — only reads the HTML, no injection.
    """
    found_params = []
    try:
        resp = requests.get(
            url, timeout=timeout, allow_redirects=True, verify=False,
            headers={"User-Agent": "VulnRecon/3.0 (Security Audit)"}
        )
        body = resp.text
    except (Timeout, ConnectionError, RequestException):
        return found_params

    # Extract href values from HTML
    href_pattern = re.compile(r'href=["\']([^"\'>]+)["\']', re.IGNORECASE)
    action_pattern = re.compile(r'action=["\']([^"\'>]+)["\']', re.IGNORECASE)

    all_urls = set()
    for pattern in (href_pattern, action_pattern):
        all_urls.update(pattern.findall(body))

    # Parse each URL for query parameters
    base_parsed = urlparse(url)
    for raw_link in all_urls:
        # Resolve relative URLs
        if raw_link.startswith("/"):
            full = f"{base_parsed.scheme}://{base_parsed.netloc}{raw_link}"
        elif raw_link.startswith("http"):
            full = raw_link
        elif raw_link.startswith("?"):
            full = f"{url.split('?')[0]}{raw_link}"
        else:
            continue

        parsed = urlparse(full)
        if parsed.query:
            # Extract parameter names from query string
            param_names = []
            for part in parsed.query.split("&"):
                if "=" in part:
                    param_names.append(part.split("=", 1)[0])
            if param_names:
                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                found_params.append({
                    "url": clean_url,
                    "params": param_names,
                    "full_url": full,
                })

    # Deduplicate by URL
    seen = set()
    unique = []
    for item in found_params:
        key = item["url"]
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def _check_error_disclosure(url, timeout):
    """
    Fetch the target page and scan for error/debug disclosure patterns.
    This is passive — only reads the normal response, no payloads sent.
    Returns a list of dicts: {pattern, severity, description}.
    """
    findings = []
    try:
        resp = requests.get(
            url, timeout=timeout, allow_redirects=True, verify=False,
            headers={"User-Agent": "VulnRecon/3.0 (Security Audit)"}
        )
        body = resp.text
        headers_str = str(resp.headers)
    except (Timeout, ConnectionError, RequestException):
        return findings

    search_text = body + headers_str
    for pattern, severity, description in ERROR_PATTERNS:
        if pattern.lower() in search_text.lower():
            findings.append({
                "pattern": pattern,
                "severity": severity,
                "description": description,
            })
    return findings


def run_surface_mapper(target, timeout=5, threads=10):
    """Run the Passive Attack Surface Mapper module."""
    w = get_panel_width()
    print(BANNER_MINI)
    draw_box([
        f"  {C.W}Alvo: {C.BLD}{target['url']}{C.RST}",
        f"  {C.DIM}Mapeamento passivo de superficie de ataque.{C.RST}",
        f"  {C.DIM}Nenhum payload e enviado — apenas observacao.{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}MAPEADOR DE SUPERFICIE DE ATAQUE{C.RST}")

    total_findings = 0

    # ── Phase 1: Database Panel Discovery ──
    print()
    sp = Spinner("Buscando paineis de banco de dados...")
    sp.start()
    t0 = time.time()
    db_results = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {
            ex.submit(_probe_db_panel, target["url"], path, name, timeout): path
            for path, name in DB_PANEL_PATHS
        }
        for f in as_completed(futs):
            try:
                db_results.append(f.result())
            except Exception:
                db_results.append({"path": futs[f], "panel": "?", "code": None, "found": False})
    elapsed = time.time() - t0
    sp.stop(f"Busca concluida em {elapsed:.2f}s")

    db_results.sort(key=lambda r: (not r["found"], r["path"]))
    db_found = [r for r in db_results if r["found"]]

    hdr = [("Rota", 24), ("Painel", 18), ("HTTP", 6), ("Status", 12)]
    rows = []
    for r in db_results:
        p = r["path"][:22] + ".." if len(r["path"]) > 24 else r["path"]
        if r["code"] is None:
            rows.append([f"{C.DIM}{p}{C.RST}", f"{C.DIM}{r['panel']}{C.RST}",
                         f"{C.DIM}---{C.RST}", f"{C.DIM}TIMEOUT{C.RST}"])
        elif r["found"]:
            clr = C.R if r["code"] == 200 else C.M
            lbl = "EXPOSTO" if r["code"] == 200 else "EXISTE"
            rows.append([p, f"{C.Y}{C.BLD}{r['panel']}{C.RST}",
                         f"{clr}{r['code']}{C.RST}", f"{clr}{C.BLD}{lbl}{C.RST}"])
        else:
            rows.append([f"{C.DIM}{p}{C.RST}", f"{C.DIM}{r['panel']}{C.RST}",
                         f"{C.DIM}{r['code']}{C.RST}", f"{C.G}N/A{C.RST}"])

    print()
    draw_table(hdr, rows)
    total_findings += len(db_found)

    if db_found:
        panels_str = ", ".join(set(r["panel"] for r in db_found))
        print()
        draw_box([
            f"  {C.R}{C.BLD}{len(db_found)} painel(is) de BD encontrado(s)!{C.RST}",
            f"  {C.W}Tecnologias: {C.Y}{C.BLD}{panels_str}{C.RST}",
        ], width=w, title=f"{C.R}{C.BLD}ALERTA{C.RST}", bc=C.R)

    # ── Phase 2: URL Parameter Discovery ──
    print()
    sp = Spinner("Extraindo parametros de URLs da pagina...")
    sp.start()
    params = _extract_links_and_params(target["url"], timeout)
    sp.stop(f"{len(params)} URL(s) com parametros encontrada(s)")

    if params:
        hdr2 = [("URL", 32), ("Parametros", 28)]
        rows2 = []
        for item in params[:20]:  # Limit display to 20 entries
            url_display = item["url"]
            if len(url_display) > 32:
                url_display = url_display[:30] + ".."
            p_str = ", ".join(item["params"][:5])  # Max 5 params shown
            if len(item["params"]) > 5:
                p_str += f" (+{len(item['params']) - 5})"
            rows2.append([url_display, f"{C.Y}{p_str}{C.RST}"])
        total_findings += len(params)

        print()
        draw_table(hdr2, rows2)
        print()
        draw_box([
            f"  {C.Y}{C.BLD}{len(params)} endpoint(s) com parametros{C.RST}",
            f"  {C.DIM}Parametros em URLs sao potenciais pontos{C.RST}",
            f"  {C.DIM}de entrada para ataques de injection.{C.RST}",
        ], width=w, title=f"{C.Y}{C.BLD}SUPERFICIE DE ATAQUE{C.RST}", bc=C.Y)
    else:
        print()
        draw_box([
            f"  {C.G}Nenhum parametro de URL encontrado na pagina.{C.RST}",
        ], width=w, title=f"{C.G}{C.BLD}PARAMETROS{C.RST}", bc=C.G)

    # ── Phase 3: Error/Debug Disclosure ──
    print()
    sp = Spinner("Analisando divulgacao de erros e debug...")
    sp.start()
    errors = _check_error_disclosure(target["url"], timeout)
    sp.stop(f"{len(errors)} indicador(es) de divulgacao encontrado(s)")

    if errors:
        err_lines = []
        for e in errors:
            sc = SEV_C.get(e["severity"], C.W)
            err_lines.append(f"  {C.R}!{C.RST} {C.W}{e['pattern']}{C.RST} {sc}[{e['severity']}]{C.RST}")
            err_lines.append(f"    {C.DIM}{e['description']}{C.RST}")
        total_findings += len(errors)

        print()
        draw_box(err_lines, width=w, title=f"{C.R}{C.BLD}DIVULGACAO DE ERROS{C.RST}", bc=C.R)
    else:
        print()
        draw_box([
            f"  {C.G}Nenhum vazamento de erro/debug detectado.{C.RST}",
        ], width=w, title=f"{C.G}{C.BLD}ERROR DISCLOSURE{C.RST}", bc=C.G)

    # ── Final Report ──
    print()
    if total_findings:
        risk_clr = C.R if total_findings >= 5 else C.Y
        draw_box([
            f"  {C.W}{C.BLD}Relatorio de Superficie de Ataque{C.RST}",
            "",
            f"  {C.CY}Paineis de BD expostos: {C.R if db_found else C.G}{C.BLD}{len(db_found)}{C.RST}",
            f"  {C.CY}URLs com parametros:    {C.Y if params else C.G}{C.BLD}{len(params)}{C.RST}",
            f"  {C.CY}Vazamentos de erro:     {C.R if errors else C.G}{C.BLD}{len(errors)}{C.RST}",
            "",
            f"  {C.W}Total de pontos de atencao: {risk_clr}{C.BLD}{total_findings}{C.RST}",
            "",
            f"  {C.DIM}Este relatorio nao executa nenhum ataque.{C.RST}",
            f"  {C.DIM}Use-o para documentar e reportar falhas{C.RST}",
            f"  {C.DIM}ao responsavel pelo sistema.{C.RST}",
        ], width=w, title=f"{C.CY}{C.BLD}RESULTADO FINAL{C.RST}")
    else:
        draw_box([
            f"  {C.G}{C.BLD}Superficie de ataque minima detectada.{C.RST}",
            f"  {C.DIM}Nenhum painel, parametro ou erro exposto.{C.RST}",
        ], width=w, title=f"{C.G}{C.BLD}RESULTADO{C.RST}", bc=C.G)

    return {
        "db_panels": db_found,
        "url_params": params,
        "error_disclosures": errors,
        "total": total_findings,
    }


# ─────────────────────────────────────────────────────
#  Module 10: Passive Subdomain Enumeration (crt.sh)
# ─────────────────────────────────────────────────────

def run_subdomain_enum(target, timeout=15):
    """Enumerate subdomains passively via crt.sh Certificate Transparency."""
    w = get_panel_width()
    print(BANNER_MINI)
    domain = target["hostname"]
    draw_box([
        f"  {C.W}Dominio: {C.BLD}{domain}{C.RST}",
        f"  {C.DIM}Consulta passiva ao crt.sh (Certificate Transparency).{C.RST}",
        f"  {C.DIM}Nao toca no servidor alvo — apenas OSINT publico.{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}ENUMERACAO DE SUBDOMINIOS{C.RST}")

    print()
    sp = Spinner("Consultando crt.sh...")
    sp.start()
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=timeout, headers={"User-Agent": _random_ua()}
        )
    except (Timeout, ConnectionError, RequestException) as e:
        sp.stop()
        draw_box([f"  {C.R}Falha na conexao com crt.sh: {e}{C.RST}"],
                 width=w, title=f"{C.R}{C.BLD}ERRO{C.RST}", bc=C.R)
        return []
    sp.stop(f"Resposta: HTTP {resp.status_code}")

    if resp.status_code != 200:
        print()
        draw_box([f"  {C.R}crt.sh retornou HTTP {resp.status_code}{C.RST}"],
                 width=w, title=f"{C.R}{C.BLD}ERRO{C.RST}", bc=C.R)
        return []

    # Parse and deduplicate subdomains
    try:
        entries = resp.json()
    except (json.JSONDecodeError, ValueError):
        print()
        draw_box([f"  {C.R}Resposta invalida do crt.sh.{C.RST}"],
                 width=w, title=f"{C.R}{C.BLD}ERRO{C.RST}", bc=C.R)
        return []

    subdomains = set()
    for entry in entries:
        name = entry.get("name_value", "")
        for sub in name.split("\n"):
            sub = sub.strip().lower()
            if sub and "*" not in sub and sub.endswith(domain):
                subdomains.add(sub)

    subdomains = sorted(subdomains)

    # Display results
    print()
    if subdomains:
        hdr = [("Subdominio", 44), ("Status", 10)]
        rows = []
        for sd in subdomains:
            if sd == domain:
                rows.append([f"{C.W}{sd}{C.RST}", f"{C.DIM}principal{C.RST}"])
            else:
                rows.append([f"{C.CY}{sd}{C.RST}", f"{C.G}encontrado{C.RST}"])
        draw_table(hdr, rows)
        print()
        draw_box([
            f"  {C.CY}{C.BLD}{len(subdomains)} subdominio(s) encontrado(s){C.RST}",
            f"  {C.DIM}Fonte: Certificate Transparency (crt.sh){C.RST}",
        ], width=w, title=f"{C.CY}{C.BLD}RESULTADO{C.RST}")
    else:
        draw_box([
            f"  {C.G}Nenhum subdominio encontrado para {domain}.{C.RST}",
        ], width=w, title=f"{C.G}{C.BLD}RESULTADO{C.RST}", bc=C.G)

    return subdomains


# ─────────────────────────────────────────────────────
#  Module 11: Technology / CMS Fingerprinting
# ─────────────────────────────────────────────────────

_TECH_PATTERNS = [
    # (pattern_in_body_or_headers, tech_name, category)
    ("wp-content", "WordPress", "CMS"),
    ("wp-includes", "WordPress", "CMS"),
    ("wp-json", "WordPress", "CMS"),
    ("/joomla", "Joomla", "CMS"),
    ("Drupal", "Drupal", "CMS"),
    ("Magento", "Magento", "CMS"),
    ("Shopify", "Shopify", "CMS/E-commerce"),
    ("Wix.com", "Wix", "CMS"),
    ("squarespace", "Squarespace", "CMS"),
    ("react", "React", "Frontend"),
    ("__next", "Next.js", "Frontend"),
    ("_nuxt", "Nuxt.js", "Frontend"),
    ("ng-version", "Angular", "Frontend"),
    ("vue.js", "Vue.js", "Frontend"),
    ("jquery", "jQuery", "Frontend"),
    ("bootstrap", "Bootstrap", "CSS"),
    ("tailwindcss", "TailwindCSS", "CSS"),
    ("laravel", "Laravel", "Backend"),
    ("csrfmiddlewaretoken", "Django", "Backend"),
    ("__rails", "Ruby on Rails", "Backend"),
    ("express", "Express.js", "Backend"),
    ("phpmyadmin", "phpMyAdmin", "Database"),
    ("google-analytics", "Google Analytics", "Analytics"),
    ("gtag", "Google Tag Manager", "Analytics"),
    ("cloudflare", "Cloudflare", "CDN/WAF"),
    ("recaptcha", "reCAPTCHA", "Security"),
]


def run_tech_fingerprint(target, timeout=10):
    """Fingerprint technologies by analyzing headers and HTML body."""
    w = get_panel_width()
    print(BANNER_MINI)
    draw_box([
        f"  {C.W}Alvo: {C.BLD}{target['url']}{C.RST}",
        f"  {C.DIM}Analisa headers e HTML para identificar tecnologias.{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}FINGERPRINTING DE TECNOLOGIAS{C.RST}")

    print()
    sp = Spinner("Analisando tecnologias...")
    sp.start()
    try:
        resp = _vr_get(target["url"], timeout=timeout)
        body = resp.text[:30000].lower()
        raw_headers = str(resp.headers).lower()
    except (Timeout, ConnectionError, RequestException) as e:
        sp.stop()
        draw_box([f"  {C.R}Falha na conexao: {e}{C.RST}"],
                 width=w, title=f"{C.R}{C.BLD}ERRO{C.RST}", bc=C.R)
        return []
    sp.stop("Pagina analisada")

    detected = []

    # Check Server header
    server = resp.headers.get("Server", "")
    if server:
        detected.append({"tech": server, "category": "Servidor", "source": "Header: Server"})

    # Check X-Powered-By
    powered = resp.headers.get("X-Powered-By", "")
    if powered:
        detected.append({"tech": powered, "category": "Backend", "source": "Header: X-Powered-By"})

    # Check meta generator tag
    gen_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\'>]+)', body)
    if gen_match:
        detected.append({"tech": gen_match.group(1), "category": "CMS", "source": "Meta: generator"})

    # Check body and headers against known patterns
    search_text = body + raw_headers
    seen = set()
    for pattern, tech_name, category in _TECH_PATTERNS:
        if pattern.lower() in search_text and tech_name not in seen:
            seen.add(tech_name)
            detected.append({"tech": tech_name, "category": category, "source": "HTML/Headers"})

    # Display results
    print()
    if detected:
        hdr = [("Tecnologia", 22), ("Categoria", 16), ("Fonte", 18)]
        rows = []
        for d in detected:
            t = d["tech"][:20] + ".." if len(d["tech"]) > 22 else d["tech"]
            rows.append([f"{C.CY}{C.BLD}{t}{C.RST}", d["category"], f"{C.DIM}{d['source']}{C.RST}"])
        draw_table(hdr, rows)
        print()
        draw_box([
            f"  {C.CY}{C.BLD}{len(detected)} tecnologia(s) identificada(s){C.RST}",
        ], width=w, title=f"{C.CY}{C.BLD}RESULTADO{C.RST}")
    else:
        draw_box([
            f"  {C.G}Nenhuma tecnologia identificada.{C.RST}",
        ], width=w, title=f"{C.G}{C.BLD}RESULTADO{C.RST}", bc=C.G)

    return detected


# ─────────────────────────────────────────────────────
#  Module 12: File Malware Scanner (VirusTotal)
# ─────────────────────────────────────────────────────

def _calculate_sha256(filepath, chunk_size=65536):
    """Calculate SHA-256 hash of a file using chunked reads."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            sha256.update(data)
    return sha256.hexdigest()


def _prompt_file_path():
    """Ask the user for a local file path with validation."""
    w = get_panel_width()
    while True:
        print()
        try:
            path = input(f"  {C.CY}▸ Caminho do ficheiro{C.RST} {C.DIM}(ou 'v' para voltar):{C.RST} ").strip()
        except (KeyboardInterrupt, EOFError):
            return None

        if path.lower() == "v":
            return None

        # Remove surrounding quotes if any
        path = path.strip('"').strip("'")

        if not os.path.isfile(path):
            draw_box([
                f"  {C.R}Ficheiro nao encontrado:{C.RST}",
                f"  {C.DIM}{path}{C.RST}",
            ], width=w, title=f"{C.R}{C.BLD}ERRO{C.RST}", bc=C.R)
            continue

        return path


def run_file_scanner():
    """Scan a local file for malware using VirusTotal API."""
    w = get_panel_width()
    clear_screen()
    print(BANNER_MINI)
    draw_box([
        f"  {C.W}{C.BLD}Scanner de Malware via VirusTotal{C.RST}",
        f"  {C.DIM}Calcula o SHA-256 do ficheiro e consulta{C.RST}",
        f"  {C.DIM}a base de dados do VirusTotal (API v3).{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}FILE MALWARE SCANNER{C.RST}")

    # Check API key
    if not VIRUSTOTAL_API_KEY:
        print()
        draw_box([
            f"  {C.R}{C.BLD}API Key do VirusTotal nao configurada!{C.RST}",
            "",
            f"  {C.W}Abra o ficheiro vulnrecon.py e insira sua{C.RST}",
            f"  {C.W}chave na constante {C.BLD}VIRUSTOTAL_API_KEY{C.RST}",
            "",
            f"  {C.DIM}Obtenha gratis em: virustotal.com/gui/join-us{C.RST}",
        ], width=w, title=f"{C.R}{C.BLD}CONFIGURACAO{C.RST}", bc=C.R)
        return None

    # Get file path from user
    filepath = _prompt_file_path()
    if filepath is None:
        return None

    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)

    # Format file size
    if filesize >= 1_073_741_824:
        size_str = f"{filesize / 1_073_741_824:.2f} GB"
    elif filesize >= 1_048_576:
        size_str = f"{filesize / 1_048_576:.2f} MB"
    elif filesize >= 1024:
        size_str = f"{filesize / 1024:.2f} KB"
    else:
        size_str = f"{filesize} bytes"

    print()
    draw_box([
        f"  {C.W}Ficheiro: {C.BLD}{filename}{C.RST}",
        f"  {C.W}Tamanho:  {C.BLD}{size_str}{C.RST}",
        f"  {C.DIM}{filepath}{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}FICHEIRO SELECIONADO{C.RST}")

    # Step 1: Calculate SHA-256
    print()
    sp = Spinner("Calculando SHA-256 (chunked)...")
    sp.start()
    t0 = time.time()
    try:
        file_hash = _calculate_sha256(filepath)
    except (IOError, OSError, PermissionError) as e:
        sp.stop()
        draw_box([
            f"  {C.R}Erro ao ler ficheiro: {e}{C.RST}",
        ], width=w, title=f"{C.R}{C.BLD}ERRO{C.RST}", bc=C.R)
        return None
    elapsed = time.time() - t0
    sp.stop(f"Hash calculado em {elapsed:.2f}s")

    print()
    draw_box([
        f"  {C.W}SHA-256:{C.RST}",
        f"  {C.G}{C.BLD}{file_hash}{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}HASH{C.RST}")

    # Step 2: Query VirusTotal API
    print()
    sp = Spinner("Consultando VirusTotal...")
    sp.start()
    vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    try:
        resp = requests.get(
            vt_url, timeout=15,
            headers={"x-apikey": VIRUSTOTAL_API_KEY, "User-Agent": _random_ua()}
        )
    except (Timeout, ConnectionError, RequestException) as e:
        sp.stop()
        draw_box([
            f"  {C.R}Falha na conexao com VirusTotal: {e}{C.RST}",
        ], width=w, title=f"{C.R}{C.BLD}ERRO{C.RST}", bc=C.R)
        return None
    sp.stop(f"Resposta: HTTP {resp.status_code}")

    # Step 3: Parse response
    print()
    if resp.status_code == 404:
        draw_box([
            f"  {C.Y}{C.BLD}Hash nao encontrado na base do VirusTotal.{C.RST}",
            "",
            f"  {C.DIM}O ficheiro nunca foi submetido para analise.{C.RST}",
            f"  {C.DIM}Isso nao significa que e seguro ou malicioso.{C.RST}",
        ], width=w, title=f"{C.Y}{C.BLD}DESCONHECIDO{C.RST}", bc=C.Y)
        return {"hash": file_hash, "status": "unknown", "file": filename}

    if resp.status_code == 401:
        draw_box([
            f"  {C.R}{C.BLD}API Key invalida ou expirada.{C.RST}",
            f"  {C.DIM}Verifique a constante VIRUSTOTAL_API_KEY.{C.RST}",
        ], width=w, title=f"{C.R}{C.BLD}ERRO DE AUTH{C.RST}", bc=C.R)
        return None

    if resp.status_code != 200:
        draw_box([
            f"  {C.R}Erro inesperado: HTTP {resp.status_code}{C.RST}",
        ], width=w, title=f"{C.R}{C.BLD}ERRO{C.RST}", bc=C.R)
        return None

    try:
        data = resp.json()
        attrs = data["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
    except (json.JSONDecodeError, KeyError):
        draw_box([
            f"  {C.R}Erro ao interpretar resposta do VirusTotal.{C.RST}",
        ], width=w, title=f"{C.R}{C.BLD}ERRO{C.RST}", bc=C.R)
        return None

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total_engines = malicious + suspicious + harmless + undetected
    threats = malicious + suspicious

    # Results table
    hdr = [("Metrica", 24), ("Valor", 12)]
    rows = [
        [f"{C.R}Malicioso{C.RST}", f"{C.R}{C.BLD}{malicious}{C.RST}"],
        [f"{C.Y}Suspeito{C.RST}", f"{C.Y}{C.BLD}{suspicious}{C.RST}"],
        [f"{C.G}Limpo{C.RST}", f"{C.G}{C.BLD}{harmless}{C.RST}"],
        [f"{C.DIM}Nao detetado{C.RST}", f"{C.DIM}{undetected}{C.RST}"],
        ["", ""],
        [f"{C.W}{C.BLD}Total de motores{C.RST}", f"{C.W}{C.BLD}{total_engines}{C.RST}"],
    ]
    draw_table(hdr, rows)

    # Verdict
    print()
    if threats == 0:
        draw_box([
            f"  {C.G}{C.BLD}FICHEIRO LIMPO{C.RST}",
            "",
            f"  {C.G}0/{total_engines} motores detetaram ameacas.{C.RST}",
            f"  {C.DIM}Nenhuma deteção de malware registrada.{C.RST}",
        ], width=w, title=f"{C.G}{C.BLD}VEREDICTO{C.RST}", bc=C.G)
    elif threats <= 3:
        draw_box([
            f"  {C.Y}{C.BLD}FICHEIRO SUSPEITO{C.RST}",
            "",
            f"  {C.Y}{threats}/{total_engines} motores detetaram ameacas.{C.RST}",
            f"  {C.DIM}Pode ser um falso positivo, mas tenha cuidado.{C.RST}",
        ], width=w, title=f"{C.Y}{C.BLD}VEREDICTO{C.RST}", bc=C.Y)
    else:
        popular_threat = attrs.get("popular_threat_classification", {})
        threat_label = popular_threat.get("suggested_threat_label", "Desconhecido")
        draw_box([
            f"  {C.R}{C.BLD}MALWARE DETETADO!{C.RST}",
            "",
            f"  {C.R}{threats}/{total_engines} motores detetaram ameacas!{C.RST}",
            f"  {C.W}Classificacao: {C.R}{C.BLD}{threat_label}{C.RST}",
            "",
            f"  {C.Y}NAO execute este ficheiro!{C.RST}",
        ], width=w, title=f"{C.R}{C.BLD}VEREDICTO{C.RST}", bc=C.R)

    return {
        "hash": file_hash, "file": filename, "size": filesize,
        "malicious": malicious, "suspicious": suspicious,
        "harmless": harmless, "undetected": undetected,
        "threats": threats, "total_engines": total_engines,
    }


# ─────────────────────────────────────────────────────
#  Full Audit
# ─────────────────────────────────────────────────────

def _pause_and_clear():
    """Pause for user input and clear screen."""
    print()
    input(f"  {C.DIM}Pressione Enter para continuar...{C.RST}")
    clear_screen()


def run_full_audit(target):
    """Run all modules sequentially with pauses, then export report."""
    w = get_panel_width()
    all_results = {}

    waf_res = run_waf_detector(target)
    all_results["waf"] = waf_res
    _pause_and_clear()

    port_res = run_port_scanner(target)
    all_results["ports"] = port_res
    _pause_and_clear()

    hdr_res = run_header_analysis(target)
    all_results["headers"] = hdr_res
    _pause_and_clear()

    fuzz_res = run_directory_fuzzer(target)
    all_results["directories"] = fuzz_res
    _pause_and_clear()

    admin_res = run_admin_hunter(target)
    all_results["admin_panels"] = admin_res
    _pause_and_clear()

    cve_res = run_cve_scanner(target)
    all_results["cves"] = cve_res
    _pause_and_clear()

    cloud_res = run_cloud_checker(target)
    all_results["cloud_buckets"] = cloud_res
    _pause_and_clear()

    surface_res = run_surface_mapper(target)
    all_results["surface"] = surface_res
    _pause_and_clear()

    err_res = run_error_db_scanner(target)
    all_results["error_db"] = err_res

    # Summary
    wf = len(waf_res)
    op = len([r for r in port_res if r["is_open"]])
    mh = len(hdr_res.get("missing", []))
    ed = len([r for r in fuzz_res if r["hit"]])
    ap = len([r for r in admin_res if r["found"]])
    cv = len(cve_res)
    pb = len([r for r in cloud_res if r.get("public")])
    sf = surface_res.get("total", 0)
    er = len(err_res)
    total = wf + op + mh + ed + ap + cv + pb + sf + er

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
        f"  {C.CY}WAFs detectados:     {C.R if wf else C.G}{C.BLD}{wf}{C.RST}",
        f"  {C.CY}Portas abertas:      {C.R if op else C.G}{C.BLD}{op}{C.RST}",
        f"  {C.CY}Headers ausentes:    {C.R if mh else C.G}{C.BLD}{mh}{C.RST}",
        f"  {C.CY}Diretorios expostos: {C.R if ed else C.G}{C.BLD}{ed}{C.RST}",
        f"  {C.CY}Paineis de admin:    {C.R if ap else C.G}{C.BLD}{ap}{C.RST}",
        f"  {C.CY}CVEs encontradas:    {C.R if cv else C.G}{C.BLD}{cv}{C.RST}",
        f"  {C.CY}Buckets publicos:    {C.R if pb else C.G}{C.BLD}{pb}{C.RST}",
        f"  {C.CY}Superficie ataque:   {C.R if sf else C.G}{C.BLD}{sf}{C.RST}",
        f"  {C.CY}Erros de BD:         {C.R if er else C.G}{C.BLD}{er}{C.RST}",
        "",
        f"  {C.W}Total de achados: {rc}{C.BLD}{total}{C.RST}",
        f"  {C.W}Nivel de risco:   {rc}{C.BLD}{risk}{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}RESUMO DA AUDITORIA{C.RST}")

    # Export JSON report
    print()
    export_report(target, all_results)


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
        "",
        f"  {C.W}{C.BLD}[7] Detetor de WAF{C.RST}",
        f"  {C.DIM}Analisa firewalls de aplicacao web.{C.RST}",
        "",
        f"  {C.W}{C.BLD}[8] Scanner de Erros de BD{C.RST}",
        f"  {C.DIM}Detecta divulgacao de erros de banco de dados.{C.RST}",
        "",
        f"  {C.W}{C.BLD}[9] Mapeador de Superficie de Ataque{C.RST}",
        f"  {C.DIM}Paineis de BD, parametros e erros expostos.{C.RST}",
        "",
        f"  {C.W}{C.BLD}[10] Scanner de Malware (Local){C.RST}",
        f"  {C.DIM}Analisa ficheiros via SHA-256 + VirusTotal.{C.RST}",
        "",
        f"  {C.W}{C.BLD}[11] Enumeracao de Subdominios{C.RST}",
        f"  {C.DIM}OSINT passivo via crt.sh (Certificate Transparency).{C.RST}",
        "",
        f"  {C.W}{C.BLD}[12] Fingerprinting de Tecnologias{C.RST}",
        f"  {C.DIM}Identifica CMS, frameworks e servidores.{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}MODULOS{C.RST}")

    print()
    draw_box([
        f"  {C.W}{C.BLD}Modo Headless (CLI):{C.RST}",
        f"  {C.DIM}python vulnrecon.py alvo.com --all{C.RST}",
        f"  {C.DIM}python vulnrecon.py alvo.com --ports --headers{C.RST}",
        f"  {C.DIM}python vulnrecon.py alvo.com --export relatorio.json{C.RST}",
        f"  {C.DIM}Use --help para ver todas as flags.{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}USO VIA TERMINAL{C.RST}")

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
        f"       {C.DIM}Todos os modulos + relatorio JSON{C.RST}",
        "",
        f"  {C.CY}{C.BLD}[2]{C.RST}  {C.W}{C.BLD}Escanear Portas{C.RST}",
        f"       {C.DIM}Testa conexoes TCP nas portas criticas{C.RST}",
        "",
        f"  {C.CY}{C.BLD}[3]{C.RST}  {C.W}{C.BLD}Verificar Cabecalhos HTTP{C.RST}",
        f"       {C.DIM}Analisa headers de seguranca do servidor{C.RST}",
        "",
        f"  {C.CY}{C.BLD}[4]{C.RST}  {C.W}{C.BLD}Cacar Diretorios Ocultos{C.RST}",
        f"       {C.DIM}Fuzzing + calibracao soft-404{C.RST}",
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
        f"  {C.CY}{C.BLD}[8]{C.RST}  {C.W}{C.BLD}Detetor de WAF{C.RST}",
        f"       {C.DIM}Identifica firewalls de aplicacao{C.RST}",
        "",
        f"  {C.CY}{C.BLD}[9]{C.RST}  {C.W}{C.BLD}Scanner de Erros de BD{C.RST}",
        f"       {C.DIM}Detecta divulgacao de erros de BD{C.RST}",
        "",
        f"  {C.CY}{C.BLD}[10]{C.RST} {C.W}{C.BLD}Mapeador de Superficie{C.RST}",
        f"       {C.DIM}Paineis de BD + parametros + erros{C.RST}",
        "",
        f"  {C.CY}{C.BLD}[11]{C.RST} {C.W}{C.BLD}Scanner de Malware (Local){C.RST}",
        f"       {C.DIM}Analisa ficheiros via VirusTotal{C.RST}",
        "",
        f"  {C.CY}{C.BLD}[12]{C.RST} {C.W}{C.BLD}Enumeracao de Subdominios{C.RST}",
        f"       {C.DIM}OSINT passivo via crt.sh{C.RST}",
        "",
        f"  {C.CY}{C.BLD}[13]{C.RST} {C.W}{C.BLD}Fingerprinting de Tecnologias{C.RST}",
        f"       {C.DIM}Identifica CMS, frameworks e servidores{C.RST}",
        "",
        f"  {C.CY}{C.BLD}[14]{C.RST} {C.W}{C.BLD}Ajuda / Sobre{C.RST}",
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
    elif choice == "8":
        run_waf_detector(target)
    elif choice == "9":
        run_error_db_scanner(target)
    elif choice == "10":
        run_surface_mapper(target)
    elif choice == "12":
        run_subdomain_enum(target)
    elif choice == "13":
        run_tech_fingerprint(target)


# ─────────────────────────────────────────────────────
#  Argparse (Headless CLI Mode)
# ─────────────────────────────────────────────────────

def build_parser():
    """Build the argparse parser for headless CLI mode."""
    parser = argparse.ArgumentParser(
        prog="vulnrecon",
        description="VulnRecon — Ferramenta de Auditoria de Seguranca CLI",
        epilog="Exemplo: python vulnrecon.py scanme.nmap.org --all --export relatorio.json",
    )
    parser.add_argument("target", nargs="?", default=None,
                        help="URL ou IP do alvo (ex: scanme.nmap.org)")

    # Scan module flags
    scan = parser.add_argument_group("Modulos de Scan")
    scan.add_argument("--all", action="store_true", help="Executa todos os modulos")
    scan.add_argument("--ports", action="store_true", help="Scanner de portas TCP")
    scan.add_argument("--headers", action="store_true", help="Analise de cabecalhos HTTP")
    scan.add_argument("--fuzz", action="store_true", help="Fuzzing de diretorios")
    scan.add_argument("--admin", action="store_true", help="Caca-paineis de admin")
    scan.add_argument("--cves", action="store_true", help="Scanner de CVEs (NVD)")
    scan.add_argument("--buckets", action="store_true", help="Verificador de cloud buckets")
    scan.add_argument("--waf", action="store_true", help="Detetor de WAF")
    scan.add_argument("--errors", action="store_true", help="Scanner de erros de BD")
    scan.add_argument("--surface", action="store_true", help="Mapeador de superficie de ataque")
    scan.add_argument("--subdomains", action="store_true", help="Enumeracao de subdominios (crt.sh)")
    scan.add_argument("--tech", action="store_true", help="Fingerprinting de tecnologias")

    # Configuration flags
    config = parser.add_argument_group("Configuracao")
    config.add_argument("--threads", type=int, default=10, help="Numero de threads (default: 10)")
    config.add_argument("--timeout", type=int, default=5, help="Timeout em segundos (default: 5)")
    config.add_argument("--delay", type=float, default=None, help="Delay entre requests em segundos")
    config.add_argument("--wordlist", type=str, default=None, help="Wordlist externa para fuzzing (.txt)")
    config.add_argument("--export", type=str, default=None, help="Exportar relatorio JSON (ex: report.json)")

    return parser


def run_headless(args):
    """Run VulnRecon in headless (CLI) mode based on argparse flags."""
    global THROTTLE_DELAY
    setup_console()

    # Apply delay if specified
    if args.delay is not None:
        THROTTLE_DELAY = args.delay

    # Resolve target
    print(BANNER_MINI)
    target = resolve_target(args.target)
    if target is None:
        print(f"  {C.R}Erro: nao foi possivel resolver '{args.target}'{C.RST}")
        sys.exit(1)

    draw_box([
        f"  {C.W}Alvo: {C.BLD}{target['url']}{C.RST}",
        f"  {C.W}IP:   {C.BLD}{target['ip']}{C.RST}",
        f"  {C.DIM}Threads: {args.threads} | Timeout: {args.timeout}s{C.RST}",
    ], width=get_panel_width(), title=f"{C.CY}{C.BLD}VULNRECON HEADLESS{C.RST}")

    all_results = {}
    run_all = args.all

    if run_all or args.waf:
        print()
        res = run_waf_detector(target, timeout=args.timeout)
        all_results["waf"] = res

    if run_all or args.ports:
        print()
        res = run_port_scanner(target, timeout=args.timeout, threads=args.threads)
        all_results["ports"] = res

    if run_all or args.headers:
        print()
        res = run_header_analysis(target, timeout=args.timeout)
        all_results["headers"] = res

    if run_all or args.fuzz:
        print()
        res = run_directory_fuzzer(target, timeout=args.timeout, threads=args.threads,
                                  wordlist_path=args.wordlist)
        all_results["directories"] = res

    if run_all or args.admin:
        print()
        res = run_admin_hunter(target, timeout=args.timeout, threads=args.threads)
        all_results["admin_panels"] = res

    if run_all or args.cves:
        print()
        res = run_cve_scanner(target, timeout=args.timeout)
        all_results["cves"] = res

    if run_all or args.buckets:
        print()
        res = run_cloud_checker(target, timeout=args.timeout, threads=args.threads)
        all_results["cloud_buckets"] = res

    if run_all or args.surface:
        print()
        res = run_surface_mapper(target, timeout=args.timeout)
        all_results["surface"] = res

    if run_all or args.errors:
        print()
        res = run_error_db_scanner(target, timeout=args.timeout)
        all_results["error_db"] = res

    if run_all or args.subdomains:
        print()
        res = run_subdomain_enum(target, timeout=args.timeout)
        all_results["subdomains"] = [s for s in res] if res else []

    if run_all or args.tech:
        print()
        res = run_tech_fingerprint(target, timeout=args.timeout)
        all_results["technologies"] = res

    # Export report if --export flag is set
    export_path = args.export
    if export_path:
        print()
        export_report(target, all_results, output_path=export_path)
    elif run_all:
        print()
        export_report(target, all_results)

    print()


# ─────────────────────────────────────────────────────
#  Interactive Mode
# ─────────────────────────────────────────────────────

def run_interactive():
    """Main interactive menu loop."""
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

        elif choice == "11":
            # File Malware Scanner — dedicated flow (no network target)
            clear_screen()
            run_file_scanner()
            print()
            input(f"  {C.DIM}Pressione Enter para voltar ao menu...{C.RST}")
            continue

        elif choice == "14":
            clear_screen()
            show_help()
            print()
            input(f"  {C.DIM}Pressione Enter para voltar ao menu...{C.RST}")
            continue

        elif choice in ("1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "12", "13"):
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
            # Invalid input
            print()
            draw_box([
                f"  {C.R}Opcao '{choice}' invalida.{C.RST}",
                f"  {C.DIM}Digite um numero de 0 a 14.{C.RST}",
            ], width=get_panel_width(), title=f"{C.R}{C.BLD}ERRO{C.RST}", bc=C.R)
            time.sleep(1.5)


# ─────────────────────────────────────────────────────
#  Main Entry Point
# ─────────────────────────────────────────────────────

def main():
    """Hybrid entry point: headless if CLI args provided, interactive otherwise."""
    setup_console()

    parser = build_parser()

    # If no arguments at all → interactive mode
    if len(sys.argv) == 1:
        run_interactive()
    else:
        args = parser.parse_args()
        if args.target:
            run_headless(args)
        else:
            parser.print_help()


if __name__ == "__main__":
    main()

