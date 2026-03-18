#!/usr/bin/env python3
"""
VulnRecon — Interactive CLI Security Auditing Tool
A polished, menu-driven vulnerability scanner with styled terminal UI.
Modules: Port Scanner | HTTP Security Headers | Directory Fuzzer
"""

import os
import platform
import re
import socket
import sys
import threading
import time
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
{C.W}   Security Auditing Tool  {C.DIM}v2.0
  ──────────────────────────────────────{C.RST}
"""

BANNER_MINI = f"\n{C.CY}{C.BLD}  ▸ VULNRECON{C.RST} {C.DIM}v2.0{C.RST}\n{C.DIM}  ──────────────────────────────────────{C.RST}\n"


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
#  Full Audit
# ─────────────────────────────────────────────────────

def run_full_audit(target):
    """Run all modules sequentially with pauses between them."""
    w = get_panel_width()
    port_res = run_port_scanner(target)
    print()
    input(f"  {C.DIM}Pressione Enter para continuar...{C.RST}")
    clear_screen()

    hdr_res = run_header_analysis(target)
    print()
    input(f"  {C.DIM}Pressione Enter para continuar...{C.RST}")
    clear_screen()

    fuzz_res = run_directory_fuzzer(target)

    # Summary
    op = len([r for r in port_res if r["is_open"]])
    mh = len(hdr_res.get("missing", []))
    ed = len([r for r in fuzz_res if r["hit"]])
    total = op + mh + ed

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
        f"  {C.DIM}Portas abertas = servicos expostos.{C.RST}",
        "",
        f"  {C.W}{C.BLD}[2] Cabecalhos de Seguranca{C.RST}",
        f"  {C.DIM}Analisa 7 headers HTTP essenciais que{C.RST}",
        f"  {C.DIM}protegem contra XSS, clickjacking, etc.{C.RST}",
        "",
        f"  {C.W}{C.BLD}[3] Caca-Diretorios{C.RST}",
        f"  {C.DIM}Busca rotas sensiveis (.git, .env, /admin){C.RST}",
        f"  {C.DIM}que podem vazar dados criticos.{C.RST}",
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
        f"       {C.DIM}Portas + Headers + Diretorios{C.RST}",
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
        f"  {C.CY}{C.BLD}[5]{C.RST}  {C.W}{C.BLD}Ajuda / Sobre{C.RST}",
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

        elif choice == "5":
            clear_screen()
            show_help()
            print()
            input(f"  {C.DIM}Pressione Enter para voltar ao menu...{C.RST}")
            continue

        elif choice in ("1", "2", "3", "4"):
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
                f"  {C.DIM}Digite um numero de 0 a 5.{C.RST}",
            ], width=get_panel_width(), title=f"{C.R}{C.BLD}ERRO{C.RST}", bc=C.R)
            time.sleep(1.5)


if __name__ == "__main__":
    main()
