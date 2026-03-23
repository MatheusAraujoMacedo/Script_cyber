#!/usr/bin/env python3
"""
VulnRecon v4.0 — Enterprise CLI Security Auditing Tool
Async-powered (aiohttp + asyncio) vulnerability scanner with styled terminal UI.
Modules: Port Scanner | HTTP Headers | Dir Fuzzer | Admin Hunter | CVE Scanner
         Cloud Buckets | WAF Detector | DB Error Scanner | Surface Mapper
         File Malware Scanner | Subdomain Enum | Tech Fingerprinting
Enterprise: Proxy Rotation | Auth Sessions | CI/CD | HTML Reports | OAST Stub
"""

# ─────────────────────────────────────────────────────
#  API Keys
# ─────────────────────────────────────────────────────
VIRUSTOTAL_API_KEY = ""

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
import asyncio
import ssl
import html as html_mod
from urllib.parse import urlparse, urlencode, urljoin, parse_qs
import argparse

try:
    import aiohttp
    from aiohttp import ClientConnectorError, ServerDisconnectedError, ClientResponseError
except ImportError:
    print("\n  [!] Dependencia ausente: 'aiohttp'")
    print("      Instale com: pip install aiohttp\n")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("\n  [!] Dependencia ausente: 'beautifulsoup4'")
    print("      Instale com: pip install beautifulsoup4\n")
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
    import warnings
    warnings.filterwarnings("ignore")


def clear_screen():
    os.system("cls" if platform.system() == "Windows" else "clear")


def get_panel_width():
    try:
        cols = os.get_terminal_size().columns
    except (ValueError, OSError):
        cols = 80
    return min(cols - 4, 68)


# ─────────────────────────────────────────────────────
#  ANSI Color Codes
# ─────────────────────────────────────────────────────

class C:
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
#  Configuration Registry (Dynamic Signatures)
# ─────────────────────────────────────────────────────

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.0; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
]

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

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
INTERESTING_CODES = {200, 201, 301, 302, 307, 308, 401, 403, 500}
STATUS_LBL = {
    200: ("ENCONTRADO", C.R), 201: ("ENCONTRADO", C.R),
    301: ("REDIRECT", C.Y), 302: ("REDIRECT", C.Y),
    307: ("REDIRECT", C.Y), 308: ("REDIRECT", C.Y),
    401: ("PROTEGIDO", C.M), 403: ("PROIBIDO", C.M),
    500: ("ERRO SVR", C.Y),
}

ADMIN_PATHS = [
    ("/wp-login.php", "WordPress"), ("/wp-admin/", "WordPress"),
    ("/wp-admin/install.php", "WordPress"),
    ("/administrator/", "Joomla"), ("/administrator/index.php", "Joomla"),
    ("/user/login", "Drupal"), ("/admin/", "Drupal/Generic"),
    ("/admin", "Magento/Generic"), ("/index.php/admin/", "Magento"),
    ("/phpmyadmin/", "phpMyAdmin"), ("/pma/", "phpMyAdmin"),
    ("/myadmin/", "phpMyAdmin"), ("/phpmyadmin/index.php", "phpMyAdmin"),
    ("/manager/html", "Apache Tomcat"), ("/manager/status", "Apache Tomcat"),
    ("/host-manager/html", "Apache Tomcat"),
    ("/cpanel", "cPanel"), ("/webmail", "cPanel Webmail"),
    ("/whm/", "WHM (cPanel)"), ("/plesk/", "Plesk"), ("/webmin/", "Webmin"),
    ("/admin/login", "Generic"), ("/admin/login.php", "Generic PHP"),
    ("/login", "Generic"), ("/login.php", "Generic PHP"),
    ("/panel/", "Generic Panel"), ("/dashboard/", "Generic Dashboard"),
    ("/controlpanel/", "Generic"), ("/adminpanel/", "Generic"),
    ("/cms/", "Generic CMS"), ("/cms/admin/", "Generic CMS"),
    ("/admin/login/?next=/admin/", "Django"),
    ("/nova/login", "Laravel Nova"), ("/rails/info", "Ruby on Rails"),
]

CMS_FINGERPRINTS = [
    ("wp-content", "WordPress"), ("wp-includes", "WordPress"),
    ("Joomla", "Joomla"), ("/media/jui/", "Joomla"),
    ("Drupal", "Drupal"), ("drupal.js", "Drupal"),
    ("Magento", "Magento"), ("phpMyAdmin", "phpMyAdmin"),
    ("Apache Tomcat", "Apache Tomcat"), ("cPanel", "cPanel"),
    ("Plesk", "Plesk"), ("django", "Django"),
    ("csrfmiddlewaretoken", "Django"), ("laravel", "Laravel"),
    ("rails", "Ruby on Rails"),
]

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

SYNTAX_PROBES = ["'", '"', "%00", "\\", ";", ")", "{{"]

DB_ERROR_SIGS = [
    ("SQL syntax", "MySQL"), ("mysql_fetch", "MySQL"),
    ("mysql_num_rows", "MySQL"), ("You have an error in your SQL", "MySQL"),
    ("pg_query", "PostgreSQL"), ("pg_exec", "PostgreSQL"),
    ("PSQLException", "PostgreSQL"), ("unterminated quoted string", "PostgreSQL"),
    ("ORA-", "Oracle"), ("ODBC SQL Server", "MSSQL"),
    ("SQLServer JDBC", "MSSQL"), ("java.sql.SQLException", "Java/JDBC"),
    ("sqlite3.OperationalError", "SQLite"),
    ("near \":\": syntax error", "SQLite"),
    ("PDOException", "PHP PDO"), ("MongoError", "MongoDB"),
]

DB_PANEL_PATHS = [
    ("/adminer.php", "Adminer"), ("/adminer/", "Adminer"),
    ("/phpmyadmin/", "phpMyAdmin"), ("/pma/", "phpMyAdmin"),
    ("/myadmin/", "phpMyAdmin"), ("/phppgadmin/", "phpPgAdmin"),
    ("/pgadmin/", "pgAdmin"), ("/dbadmin/", "DB Admin"),
    ("/mysql/", "MySQL Panel"), ("/mongo-express/", "Mongo Express"),
    ("/rockmongo/", "RockMongo"), ("/redis-commander/", "Redis Commander"),
    ("/elasticsearch/", "Elasticsearch"), ("/_cat/indices", "Elasticsearch API"),
    ("/_cluster/health", "Elasticsearch API"), ("/solr/", "Apache Solr"),
    ("/couchdb/", "CouchDB"), ("/_utils/", "CouchDB Fauxton"),
    ("/_all_dbs", "CouchDB API"), ("/neo4j/", "Neo4j"),
]

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

TECH_PATTERNS = [
    ("wp-content", "WordPress", "CMS"), ("wp-includes", "WordPress", "CMS"),
    ("wp-json", "WordPress", "CMS"), ("/joomla", "Joomla", "CMS"),
    ("Drupal", "Drupal", "CMS"), ("Magento", "Magento", "CMS"),
    ("Shopify", "Shopify", "CMS/E-commerce"), ("Wix.com", "Wix", "CMS"),
    ("squarespace", "Squarespace", "CMS"), ("react", "React", "Frontend"),
    ("__next", "Next.js", "Frontend"), ("_nuxt", "Nuxt.js", "Frontend"),
    ("ng-version", "Angular", "Frontend"), ("vue.js", "Vue.js", "Frontend"),
    ("jquery", "jQuery", "Frontend"), ("bootstrap", "Bootstrap", "CSS"),
    ("tailwindcss", "TailwindCSS", "CSS"), ("laravel", "Laravel", "Backend"),
    ("csrfmiddlewaretoken", "Django", "Backend"),
    ("__rails", "Ruby on Rails", "Backend"),
    ("express", "Express.js", "Backend"),
    ("phpmyadmin", "phpMyAdmin", "Database"),
    ("google-analytics", "Google Analytics", "Analytics"),
    ("gtag", "Google Tag Manager", "Analytics"),
    ("cloudflare", "Cloudflare", "CDN/WAF"),
    ("recaptcha", "reCAPTCHA", "Security"),
]

# Global throttle
THROTTLE_DELAY = 0.15

# Adaptive HTTP behavior and advanced DAST settings
HTTP_MAX_RETRIES = 3
HTTP_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
DEFAULT_CRAWL_MAX_PAGES = 25
DEFAULT_EVIDENCE_BODY_MAX = 2000


# ─────────────────────────────────────────────────────
#  UI Drawing Utilities
# ─────────────────────────────────────────────────────

def _vlen(text):
    return len(re.sub(r'\033\[[0-9;]*m', '', text))


def draw_box(lines, width=60, title="", bc=None):
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
    if bc is None:
        bc = C.CY
    r = C.RST
    cw = [h[1] for h in headers]
    print(f"  {bc}┌" + "┬".join("─" * (w + 2) for w in cw) + f"┐{r}")
    line = f"  {bc}│{r}"
    for (label, w) in headers:
        pad = max(w - _vlen(label), 0)
        line += f" {C.BLD}{C.W}{label}{r}{' ' * (pad + 1)}{bc}│{r}"
    print(line)
    print(f"  {bc}├" + "┼".join("─" * (w + 2) for w in cw) + f"┤{r}")
    for row in rows:
        line = f"  {bc}│{r}"
        for i, cell in enumerate(row):
            pad = max(cw[i] - _vlen(str(cell)), 0)
            line += f" {cell}{' ' * (pad + 1)}{bc}│{r}"
        print(line)
    print(f"  {bc}└" + "┴".join("─" * (w + 2) for w in cw) + f"┘{r}")


# ─────────────────────────────────────────────────────
#  Loading Spinner (Thread-based, asyncio-compatible)
# ─────────────────────────────────────────────────────

class Spinner:
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
{C.W}   Security Auditing Tool  {C.DIM}v4.0 Enterprise
  ──────────────────────────────────────{C.RST}
"""

BANNER_MINI = f"\n{C.CY}{C.BLD}  ▸ VULNRECON{C.RST} {C.DIM}v4.0{C.RST}\n{C.DIM}  ──────────────────────────────────────{C.RST}\n"


# ─────────────────────────────────────────────────────
#  Async HTTP Engine
# ─────────────────────────────────────────────────────

class AsyncHttpClient:
    """Central async HTTP client with stealth, proxy rotation, and auth support."""

    def __init__(self, timeout=5, delay=0.15, proxy_list=None, cookie=None, token=None):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.delay = delay
        self.proxies = []
        if proxy_list and os.path.isfile(proxy_list):
            with open(proxy_list, "r") as f:
                self.proxies = [l.strip() for l in f if l.strip()]
        self.cookie = cookie
        self.token = token
        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE

    def _build_headers(self, extra=None):
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        if self.cookie:
            headers["Cookie"] = self.cookie
        if self.token:
            headers["Authorization"] = self.token
        if extra:
            headers.update(extra)
        return headers

    def _pick_proxy(self):
        return random.choice(self.proxies) if self.proxies else None

    async def request(self, session, method, url, data=None, json_data=None, allow_redirects=True,
                      extra_headers=None, verify_ssl=False, retries=HTTP_MAX_RETRIES):
        """Perform async request with adaptive retries, jitter, and proxy rotation."""
        last_error = None
        for attempt in range(1, retries + 1):
            jitter = random.uniform(self.delay * 0.5, self.delay * 1.5) if self.delay > 0 else 0
            if jitter > 0:
                await asyncio.sleep(jitter)
            headers = self._build_headers(extra_headers)
            proxy = self._pick_proxy()
            ssl_ctx = None if verify_ssl else self._ssl_ctx
            try:
                async with session.request(
                    method, url, headers=headers, data=data, json=json_data,
                    allow_redirects=allow_redirects, proxy=proxy, ssl=ssl_ctx, timeout=self.timeout
                ) as resp:
                    body = await resp.text(errors="replace")
                    if resp.status in HTTP_RETRYABLE_STATUS and attempt < retries:
                        await asyncio.sleep(min(0.5 * (2 ** (attempt - 1)), 3.0))
                        continue
                    return AsyncResponse(resp.status, dict(resp.headers), body)
            except (ClientConnectorError, ServerDisconnectedError, asyncio.TimeoutError,
                    ClientResponseError, aiohttp.ClientError, OSError) as e:
                last_error = e
                if attempt < retries:
                    await asyncio.sleep(min(0.5 * (2 ** (attempt - 1)), 3.0))
                    continue
                break
        raise NetworkError(str(last_error) if last_error else "Network request failed")

    async def get(self, session, url, allow_redirects=True, extra_headers=None, verify_ssl=False, retries=HTTP_MAX_RETRIES):
        return await self.request(
            session, "GET", url, allow_redirects=allow_redirects,
            extra_headers=extra_headers, verify_ssl=verify_ssl, retries=retries
        )

    async def post(self, session, url, data=None, json_data=None, allow_redirects=True,
                   extra_headers=None, verify_ssl=False, retries=HTTP_MAX_RETRIES):
        return await self.request(
            session, "POST", url, data=data, json_data=json_data, allow_redirects=allow_redirects,
            extra_headers=extra_headers, verify_ssl=verify_ssl, retries=retries
        )


class AsyncResponse:
    """Lightweight container for async HTTP response data."""
    def __init__(self, status, headers, text):
        self.status_code = status
        self.headers = headers
        self.text = text
        self.content_length = len(text.encode("utf-8", errors="replace"))


class NetworkError(Exception):
    """Custom exception for network failures."""
    pass


# ─────────────────────────────────────────────────────
#  Target Resolution
# ─────────────────────────────────────────────────────

def resolve_target(raw):
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
#  OAST Stub (Out-of-Band Application Security Testing)
# ─────────────────────────────────────────────────────

class InteractshClient:
    """Placeholder for future Interactsh/OAST integration.
    Generates unique callback URLs for detecting blind vulnerabilities
    such as SSRF, Blind XSS, and Log4Shell.
    """

    def __init__(self, server="oast.live"):
        self.server = server
        self.correlation_id = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        self._interactions = []

    def generate_url(self, label="test"):
        """Generate a unique OAST callback URL."""
        return f"https://{label}-{self.correlation_id}.{self.server}"

    def poll_interactions(self):
        """Poll for received interactions (stub — returns empty list)."""
        # Future: implement actual Interactsh API polling
        return self._interactions

    def get_status(self):
        return {
            "server": self.server,
            "correlation_id": self.correlation_id,
            "interactions": len(self._interactions),
            "status": "stub — nao implementado",
        }


# ─────────────────────────────────────────────────────
#  Advanced DAST Utilities (Auth, Evidence, Recon, Active Tests)
# ─────────────────────────────────────────────────────

def _mk_evidence(method, url, payload, status, response_text, headers=None):
    return {
        "request": {"method": method, "url": url, "payload": payload or {}, "headers": headers or {}},
        "response": {"status_code": status, "snippet": (response_text or "")[:DEFAULT_EVIDENCE_BODY_MAX]},
    }


def _extract_version_hint(text):
    m = re.search(r"(\d+\.\d+(?:\.\d+)?)", text or "")
    return m.group(1) if m else None


async def run_stateful_auth_crawler(target, http_client=None, timeout=10, login_profile=None, max_pages=DEFAULT_CRAWL_MAX_PAGES):
    """Stateful authenticated crawler with optional login form submission."""
    client = http_client or AsyncHttpClient(timeout=timeout)
    visited = set()
    to_visit = [target["url"]]
    queued = {target["url"]}
    auth_info = {"attempted": False, "authenticated": False, "login_url": None}
    pages = []

    async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as session:
        if login_profile and login_profile.get("url") and login_profile.get("username") and login_profile.get("password"):
            auth_info["attempted"] = True
            auth_info["login_url"] = login_profile["url"]
            try:
                login_page = await client.get(session, login_profile["url"])
                soup = BeautifulSoup(login_page.text[:60000], "html.parser")
                form = soup.find("form")
                if form:
                    action = form.get("action") or login_profile["url"]
                    post_url = urljoin(login_profile["url"], action)
                    data = {}
                    for inp in form.find_all("input"):
                        name = inp.get("name")
                        if not name:
                            continue
                        value = inp.get("value", "")
                        data[name] = value
                    user_key = login_profile.get("user_field", "username")
                    pass_key = login_profile.get("pass_field", "password")
                    data[user_key] = login_profile["username"]
                    data[pass_key] = login_profile["password"]
                    if login_profile.get("extra_fields"):
                        data.update(login_profile["extra_fields"])
                    login_resp = await client.post(session, post_url, data=data)
                    auth_info["authenticated"] = login_resp.status_code in (200, 302, 303)
            except NetworkError:
                auth_info["authenticated"] = False

        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            queued.discard(url)
            if url in visited:
                continue
            visited.add(url)
            try:
                resp = await client.get(session, url)
            except NetworkError:
                continue
            pages.append({"url": url, "status": resp.status_code, "title": ""})
            soup = BeautifulSoup(resp.text[:100000], "html.parser")
            if soup.title and soup.title.string:
                pages[-1]["title"] = soup.title.string.strip()[:100]
            for tag in soup.find_all("a", href=True):
                nxt = urljoin(url, tag["href"])
                if urlparse(nxt).netloc == target["hostname"] and nxt not in visited and nxt not in queued:
                    to_visit.append(nxt)
                    queued.add(nxt)
            for form in soup.find_all("form"):
                action = form.get("action") or url
                nxt = urljoin(url, action)
                if urlparse(nxt).netloc == target["hostname"] and nxt not in visited and nxt not in queued:
                    to_visit.append(nxt)
                    queued.add(nxt)

    return {"auth": auth_info, "pages": pages, "total_pages": len(pages)}


async def run_recon_discovery(target, http_client=None, timeout=10):
    """Extract parameters, JS hints, robots/sitemap, and API surface."""
    client = http_client or AsyncHttpClient(timeout=timeout)
    base = target["url"].rstrip("/")
    out = {"robots": [], "sitemap": [], "params": [], "openapi": [], "graphql": []}
    async with aiohttp.ClientSession() as session:
        for endpoint in ("/robots.txt", "/sitemap.xml"):
            try:
                resp = await client.get(session, base + endpoint)
            except NetworkError:
                continue
            if resp.status_code != 200:
                continue
            lines = [l.strip() for l in resp.text.splitlines() if l.strip()]
            if endpoint == "/robots.txt":
                out["robots"] = lines[:200]
            else:
                out["sitemap"] = lines[:300]

        try:
            home = await client.get(session, target["url"])
        except NetworkError:
            return out
        soup = BeautifulSoup(home.text[:120000], "html.parser")

        for a in soup.find_all("a", href=True):
            href = urljoin(target["url"], a["href"])
            p = urlparse(href)
            if p.query:
                out["params"].append({"url": f"{p.scheme}://{p.netloc}{p.path}", "params": list(parse_qs(p.query).keys())})

        for script in soup.find_all("script"):
            src = script.get("src", "")
            body = script.text or ""
            blob = f"{src}\n{body[:20000]}"
            for m in re.findall(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*['\"]?[^'\"\s&]+", blob):
                if m.lower() not in ("var", "let", "const", "function"):
                    out["params"].append({"url": target["url"], "params": [m], "source": "js"})

        for api_path in ("/openapi.json", "/swagger.json", "/v3/api-docs"):
            try:
                api_resp = await client.get(session, base + api_path)
                if api_resp.status_code == 200 and ("openapi" in api_resp.text.lower() or "swagger" in api_resp.text.lower()):
                    out["openapi"].append(base + api_path)
            except NetworkError:
                pass

        for gql_path in ("/graphql", "/api/graphql"):
            try:
                gql = await client.post(session, base + gql_path, json_data={"query": "{ __typename }"})
                if gql.status_code in (200, 400) and ("errors" in gql.text.lower() or "data" in gql.text.lower()):
                    out["graphql"].append(base + gql_path)
            except NetworkError:
                pass

    uniq = {}
    for item in out["params"]:
        key = (item.get("url"), tuple(sorted(item.get("params", []))))
        uniq[key] = item
    out["params"] = list(uniq.values())[:400]
    return out


async def run_active_owasp_checks(target, recon_data=None, http_client=None, timeout=10, oast_client=None):
    """Active (safe) probes for common OWASP classes with evidence."""
    client = http_client or AsyncHttpClient(timeout=timeout)
    oast = oast_client or InteractshClient()
    findings = []
    seen_findings = set()
    params = (recon_data or {}).get("params", [])
    if not params:
        params = [{"url": target["url"], "params": ["q", "id", "url", "redirect", "file"]}]

    payloads = {
        "SQLi": "' OR '1'='1",
        "XSS-Reflected": "<svg/onload=alert(1)>",
        "Path-Traversal": "../../../../etc/passwd",
        "Command-Injection": ";id",
        "Open-Redirect": "https://example.org",
        "IDOR": "999999",
        "SSRF": oast.generate_url("ssrf"),
        "Blind-XSS": f"<img src='{oast.generate_url('bxss')}'>",
    }

    async with aiohttp.ClientSession() as session:
        for item in params[:30]:
            base_url = item.get("url") or target["url"]
            pnames = list(dict.fromkeys(item.get("params", [])))[:4]
            for p in pnames:
                for vuln_type, payload in payloads.items():
                    q = {p: payload}
                    test_url = f"{base_url}?{urlencode(q)}"
                    try:
                        resp = await client.get(session, test_url, allow_redirects=False)
                    except NetworkError:
                        continue
                    text_low = resp.text.lower()
                    hit = False
                    if vuln_type == "SQLi" and any(s in text_low for s in ("sql syntax", "mysql", "psqlexception", "sqlite")):
                        hit = True
                    elif vuln_type.startswith("XSS") and payload.lower() in text_low:
                        hit = True
                    elif vuln_type == "Path-Traversal" and ("root:x:" in text_low or "[boot loader]" in text_low):
                        hit = True
                    elif vuln_type == "Command-Injection" and ("uid=" in text_low or "gid=" in text_low):
                        hit = True
                    elif vuln_type == "Open-Redirect" and resp.status_code in (301, 302, 303, 307, 308) and payload in (resp.headers.get("Location", "")):
                        hit = True
                    elif vuln_type == "IDOR" and resp.status_code == 200 and "forbidden" not in text_low and "unauthorized" not in text_low:
                        hit = True
                    elif vuln_type in ("SSRF", "Blind-XSS"):
                        hit = False
                    if hit:
                        sig = (vuln_type, test_url, p, resp.status_code)
                        if sig in seen_findings:
                            continue
                        seen_findings.add(sig)
                        findings.append({
                            "type": vuln_type,
                            "severity": "ALTA" if vuln_type in ("SQLi", "Command-Injection", "SSRF", "IDOR") else "MEDIA",
                            "url": test_url,
                            "param": p,
                            "evidence": _mk_evidence("GET", test_url, q, resp.status_code, resp.text),
                        })

        # OAST validation from stub/client state
        interactions = oast.poll_interactions()
        if interactions:
            findings.append({
                "type": "OAST-Confirmed",
                "severity": "CRITICA",
                "url": target["url"],
                "interaction_count": len(interactions),
                "evidence": {"oast": interactions},
            })
    findings.sort(key=lambda f: (f.get("type", ""), f.get("url", ""), f.get("param", "")))
    return findings


async def run_contextual_fingerprint_and_cve(target, tech_data=None, http_client=None, timeout=10):
    """Extract version hints and map to contextual CVE lookups (safe PoC mode)."""
    tech_data = tech_data or []
    versioned = []
    cve_queries = []
    for t in tech_data:
        tech_name = t.get("tech", "")
        version = _extract_version_hint(tech_name)
        if version:
            versioned.append({"tech": tech_name, "version": version, "source": t.get("source", "")})
            cve_queries.append(f"{tech_name} {version}")
    return {"versioned_tech": versioned, "cve_queries": cve_queries[:20], "mode": "safe-poc"}


def run_tls_dns_audit(target, timeout=6):
    """TLS/DNS checks: cert metadata, CAA, weak TLS support hint."""
    host = target["hostname"]
    result = {"host": host, "tls": {}, "dns": {}, "risks": []}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                result["tls"]["version"] = ssock.version()
                result["tls"]["cipher"] = cipher[0] if cipher else None
                result["tls"]["subject"] = cert.get("subject", [])
                result["tls"]["notAfter"] = cert.get("notAfter")
                if result["tls"]["version"] in ("TLSv1", "TLSv1.1"):
                    result["risks"].append("TLS legado habilitado")
    except Exception as e:
        result["tls"]["error"] = str(e)
        result["risks"].append("Falha ao validar TLS")

    try:
        caa = socket.getaddrinfo(f"caa.{host}", None)
        result["dns"]["caa_lookup"] = bool(caa)
    except Exception:
        result["dns"]["caa_lookup"] = False
        result["risks"].append("CAA nao identificado (verificar via DNS autoritativo)")
    return result

# ─────────────────────────────────────────────────────
#  Module 1: Async Port Scanner
# ─────────────────────────────────────────────────────

async def _scan_single_port(ip, port, timeout):
    svc = COMMON_PORTS.get(port, "?")
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return {"port": port, "service": svc, "is_open": True}
    except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
        return {"port": port, "service": svc, "is_open": False}


async def run_port_scanner(target, http_client=None, timeout=1.5, concurrency=30):
    w = get_panel_width()
    print(BANNER_MINI)
    draw_box([
        f"  {C.W}Alvo:    {C.BLD}{target['hostname']}{C.RST} ({target['ip']})",
        f"  {C.W}Portas:  {C.BLD}{len(COMMON_PORTS)}{C.RST} | Timeout: {C.BLD}{timeout}s{C.RST} | Async",
    ], width=w, title=f"{C.CY}{C.BLD}SCANNER DE PORTAS{C.RST}")

    print()
    sp = Spinner("Escaneando portas...")
    sp.start()
    t0 = time.time()
    sem = asyncio.Semaphore(concurrency)

    async def _guarded(ip, port):
        async with sem:
            return await _scan_single_port(ip, port, timeout)

    tasks = [_guarded(target["ip"], p) for p in COMMON_PORTS]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    results = [r if isinstance(r, dict) else {"port": 0, "service": "?", "is_open": False} for r in results]
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
#  Module 2: HTTP Security Headers (Async)
# ─────────────────────────────────────────────────────

async def run_header_analysis(target, http_client=None, timeout=10):
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
        resp = await http_client.get(
            aiohttp.ClientSession(), target["url"]
        ) if http_client else None
        if resp is None:
            async with aiohttp.ClientSession() as session:
                client = AsyncHttpClient(timeout=timeout)
                resp = await client.get(session, target["url"])
    except NetworkError as e:
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
#  Module 3: Async Directory Fuzzer
# ─────────────────────────────────────────────────────

async def _fuzz_single_path(session, client, base, path):
    try:
        resp = await client.get(session, base.rstrip("/") + path, allow_redirects=False)
        return {"path": path, "code": resp.status_code, "hit": resp.status_code in INTERESTING_CODES, "clen": resp.content_length}
    except NetworkError:
        return {"path": path, "code": None, "hit": False, "clen": 0}


async def run_directory_fuzzer(target, http_client=None, timeout=5, concurrency=15, wordlist_path=None):
    w = get_panel_width()
    print(BANNER_MINI)
    client = http_client or AsyncHttpClient(timeout=timeout)

    if wordlist_path and os.path.isfile(wordlist_path):
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            paths = [l.strip() for l in f if l.strip()]
            paths = [p if p.startswith("/") else "/" + p for p in paths]
        draw_box([
            f"  {C.W}Alvo:     {C.BLD}{target['url']}{C.RST}",
            f"  {C.W}Wordlist: {C.BLD}{wordlist_path}{C.RST} ({len(paths)} rotas)",
        ], width=w, title=f"{C.CY}{C.BLD}CACA-DIRETORIOS{C.RST}")
    else:
        paths = FUZZ_PATHS
        draw_box([
            f"  {C.W}Alvo:     {C.BLD}{target['url']}{C.RST}",
            f"  {C.W}Wordlist: {C.BLD}{len(paths)}{C.RST} rotas (embutida) | Async",
        ], width=w, title=f"{C.CY}{C.BLD}CACA-DIRETORIOS{C.RST}")

    # Soft-404 calibration
    print()
    rand_slug = "/" + "".join(random.choices(string.ascii_lowercase, k=16))
    baseline_clen = None
    async with aiohttp.ClientSession() as session:
        try:
            bl_resp = await client.get(session, target["url"].rstrip("/") + rand_slug, allow_redirects=False)
            if bl_resp.status_code == 200:
                baseline_clen = bl_resp.content_length
                draw_box([
                    f"  {C.Y}Soft-404 detectado (catch-all page){C.RST}",
                    f"  {C.DIM}Baseline: {baseline_clen} bytes — filtrando falsos positivos{C.RST}",
                ], width=w, title=f"{C.Y}{C.BLD}CALIBRACAO{C.RST}", bc=C.Y)
                print()
        except NetworkError:
            pass

        sp = Spinner("Fuzzing em andamento...")
        sp.start()
        t0 = time.time()
        sem = asyncio.Semaphore(concurrency)

        async def _guarded(path):
            async with sem:
                return await _fuzz_single_path(session, client, target["url"], path)

        results = await asyncio.gather(*[_guarded(p) for p in paths], return_exceptions=True)
        results = [r if isinstance(r, dict) else {"path": "?", "code": None, "hit": False, "clen": 0} for r in results]
        elapsed = time.time() - t0
        sp.stop(f"Fuzzing concluido em {elapsed:.2f}s")

    if baseline_clen is not None:
        fp_count = 0
        for r in results:
            if r["hit"] and r["code"] == 200 and r["clen"] == baseline_clen:
                r["hit"] = False
                r["code_note"] = "SOFT-404"
                fp_count += 1
        if fp_count:
            draw_box([f"  {C.G}{fp_count} falso(s) positivo(s) filtrado(s).{C.RST}"],
                     width=w, title=f"{C.G}{C.BLD}FILTRO{C.RST}", bc=C.G)
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
    print()
    if hit_n:
        draw_box([
            f"  {C.R}{C.BLD}{hit_n} exposta(s){C.RST} {C.DIM}|{C.RST} {C.G}{len(results) - hit_n} segura(s){C.RST}",
            f"  {C.Y}Rotas expostas podem vazar informacoes sensiveis!{C.RST}",
        ], width=w, title=f"{C.Y}{C.BLD}RESULTADO{C.RST}", bc=C.Y)
    else:
        draw_box([f"  {C.G}{C.BLD}Nenhuma rota sensivel exposta.{C.RST}"],
                 width=w, title=f"{C.G}{C.BLD}RESULTADO{C.RST}", bc=C.G)
    return results


# ─────────────────────────────────────────────────────
#  Module 4: Async Admin Panel Hunter
# ─────────────────────────────────────────────────────

async def _probe_admin(session, client, base_url, path, expected_cms):
    full_url = base_url.rstrip("/") + path
    try:
        resp = await client.get(session, full_url)
        code = resp.status_code
        detected_cms = None
        if code in (200, 401, 403):
            body = resp.text[:5000].lower()
            for pattern, cms_name in CMS_FINGERPRINTS:
                if pattern.lower() in body:
                    detected_cms = cms_name
                    break
            if detected_cms is None:
                detected_cms = expected_cms
        return {"path": path, "code": code, "cms": detected_cms, "found": code in (200, 301, 302, 401, 403)}
    except NetworkError:
        return {"path": path, "code": None, "cms": None, "found": False}


async def run_admin_hunter(target, http_client=None, timeout=5, concurrency=15):
    w = get_panel_width()
    print(BANNER_MINI)
    client = http_client or AsyncHttpClient(timeout=timeout)
    draw_box([
        f"  {C.W}Alvo:     {C.BLD}{target['url']}{C.RST}",
        f"  {C.W}Wordlist: {C.BLD}{len(ADMIN_PATHS)}{C.RST} rotas de admin | Async",
    ], width=w, title=f"{C.CY}{C.BLD}CACA-PAINEIS DE ADMIN{C.RST}")

    print()
    sp = Spinner("Buscando paineis de administracao...")
    sp.start()
    t0 = time.time()
    sem = asyncio.Semaphore(concurrency)
    async with aiohttp.ClientSession() as session:
        async def _guarded(path, cms):
            async with sem:
                return await _probe_admin(session, client, target["url"], path, cms)
        results = await asyncio.gather(*[_guarded(p, c) for p, c in ADMIN_PATHS], return_exceptions=True)
    results = [r if isinstance(r, dict) else {"path": "?", "code": None, "cms": None, "found": False} for r in results]
    elapsed = time.time() - t0
    sp.stop(f"Busca concluida em {elapsed:.2f}s")

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
            rows.append([f"{C.DIM}{p}{C.RST}", f"{C.DIM}---{C.RST}", f"{C.DIM}-{C.RST}", f"{C.DIM}TIMEOUT{C.RST}"])
        elif r["found"]:
            found_n += 1
            clr = C.R if r["code"] == 200 else C.M
            lbl = "ABERTO" if r["code"] == 200 else ("PROTEGIDO" if r["code"] in (401, 403) else "REDIRECT")
            rows.append([p, f"{clr}{r['code']}{C.RST}", f"{C.Y}{C.BLD}{cms}{C.RST}", f"{clr}{C.BLD}{lbl}{C.RST}"])
        else:
            rows.append([f"{C.DIM}{p}{C.RST}", f"{C.DIM}{r['code']}{C.RST}", f"{C.DIM}-{C.RST}", f"{C.G}N/A{C.RST}"])

    print()
    draw_table(hdr, rows)
    print()
    if found_n:
        detected = set(r["cms"] for r in results if r["found"] and r["cms"])
        cms_str = ", ".join(sorted(detected)) if detected else "Nao identificado"
        draw_box([
            f"  {C.R}{C.BLD}{found_n} painel(is) encontrado(s){C.RST} {C.DIM}|{C.RST} {C.G}{len(results) - found_n} nao encontrado(s){C.RST}",
            f"  {C.W}Tecnologia detectada: {C.Y}{C.BLD}{cms_str}{C.RST}",
        ], width=w, title=f"{C.Y}{C.BLD}RESULTADO{C.RST}", bc=C.Y)
    else:
        draw_box([f"  {C.G}{C.BLD}Nenhum painel de admin encontrado.{C.RST}"],
                 width=w, title=f"{C.G}{C.BLD}RESULTADO{C.RST}", bc=C.G)
    return results


# ─────────────────────────────────────────────────────
#  Module 5: Async CVE Scanner
# ─────────────────────────────────────────────────────

def _extract_software_versions(headers):
    software = []
    server = headers.get("Server", "")
    if server:
        for token in server.replace(",", " ").split():
            if "/" in token:
                parts = token.split("/", 1)
                name, ver = parts[0].strip("()").strip(), parts[1].strip("()").strip()
                if name and ver and any(c.isdigit() for c in ver):
                    software.append((name, ver))
    powered = headers.get("X-Powered-By", "")
    if powered:
        for token in powered.replace(",", " ").split():
            if "/" in token:
                parts = token.split("/", 1)
                name, ver = parts[0].strip(), parts[1].strip()
                if name and ver and any(c.isdigit() for c in ver):
                    software.append((name, ver))
    aspnet = headers.get("X-AspNet-Version", "")
    if aspnet:
        software.append(("ASP.NET", aspnet.strip()))
    mvc = headers.get("X-AspNetMvc-Version", "")
    if mvc:
        software.append(("ASP.NET MVC", mvc.strip()))
    return software


async def _query_nvd_cves(session, keyword, max_results=5, timeout=15):
    api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": keyword, "resultsPerPage": max_results}
    url = f"{api_url}?{urlencode(params)}"
    try:
        ctx = ssl.create_default_context()
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout), ssl=ctx,
                               headers={"User-Agent": random.choice(USER_AGENTS)}) as resp:
            if resp.status != 200:
                return []
            data = await resp.json()
    except (asyncio.TimeoutError, aiohttp.ClientError, json.JSONDecodeError, Exception):
        return []

    cves = []
    for vuln in data.get("vulnerabilities", []):
        cve_data = vuln.get("cve", {})
        cve_id = cve_data.get("id", "N/A")
        severity = "N/A"
        metrics = cve_data.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(key, [])
            if metric_list:
                cvss = metric_list[0].get("cvssData", {})
                score = cvss.get("baseScore", "N/A")
                sev_label = metric_list[0].get("baseSeverity", cvss.get("baseSeverity", "N/A"))
                severity = f"{score} ({sev_label})"
                break
        desc = "Sem descricao disponivel."
        for d in cve_data.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", desc)[:80]
                break
        cves.append({"cve_id": cve_id, "severity": severity, "description": desc})
    return cves


async def run_cve_scanner(target, http_client=None, timeout=10):
    w = get_panel_width()
    print(BANNER_MINI)
    client = http_client or AsyncHttpClient(timeout=timeout)
    draw_box([
        f"  {C.W}Alvo: {C.BLD}{target['url']}{C.RST}",
        f"  {C.DIM}Coleta versoes dos headers HTTP e consulta{C.RST}",
        f"  {C.DIM}a API publica do NIST NVD por CVEs conhecidas.{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}SCANNER DE CVEs{C.RST}")

    print()
    sp = Spinner("Coletando headers do servidor...")
    sp.start()
    try:
        async with aiohttp.ClientSession() as session:
            resp = await client.get(session, target["url"])
    except NetworkError as e:
        sp.stop()
        draw_box([f"  {C.R}Falha na conexao: {e}{C.RST}"], width=w, title=f"{C.R}{C.BLD}ERRO{C.RST}", bc=C.R)
        return []
    sp.stop(f"HTTP {resp.status_code} — Headers coletados")

    software = _extract_software_versions(resp.headers)
    if not software:
        print()
        draw_box([
            f"  {C.G}Nenhum software com versao exposta nos headers.{C.RST}",
        ], width=w, title=f"{C.G}{C.BLD}RESULTADO{C.RST}", bc=C.G)
        return []

    sw_lines = [f"  {C.Y}▸{C.RST} {C.W}{C.BLD}{n}{C.RST} {C.DIM}v{v}{C.RST}" for n, v in software]
    print()
    draw_box(sw_lines, width=w, title=f"{C.CY}{C.BLD}SOFTWARE DETECTADO{C.RST}")

    all_cves = []
    async with aiohttp.ClientSession() as session:
        for name, ver in software:
            keyword = f"{name} {ver}"
            print()
            sp = Spinner(f"Consultando NVD para {name} {ver}...")
            sp.start()
            cves = await _query_nvd_cves(session, keyword)
            sp.stop(f"{len(cves)} CVE(s) encontrada(s) para {name} {ver}")
            if cves:
                hdr_def = [("CVE ID", 18), ("Severidade", 16), ("Descricao", 28)]
                rows = []
                for c in cves:
                    sev = c["severity"]
                    if "CRITICAL" in sev.upper():
                        sd = f"{C.R}{C.BLD}{sev}{C.RST}"
                    elif "HIGH" in sev.upper():
                        sd = f"{C.R}{sev}{C.RST}"
                    elif "MEDIUM" in sev.upper():
                        sd = f"{C.Y}{sev}{C.RST}"
                    else:
                        sd = f"{C.DIM}{sev}{C.RST}"
                    desc = c["description"][:26] + ".." if len(c["description"]) > 28 else c["description"]
                    rows.append([c["cve_id"], sd, desc])
                all_cves.extend(cves)
                print()
                draw_table(hdr_def, rows)
            if len(software) > 1:
                await asyncio.sleep(2)

    print()
    if all_cves:
        draw_box([
            f"  {C.R}{C.BLD}{len(all_cves)} CVE(s) publica(s) encontrada(s){C.RST}",
            f"  {C.W}Software:  {C.Y}{', '.join(f'{n} {v}' for n, v in software)}{C.RST}",
        ], width=w, title=f"{C.Y}{C.BLD}RESULTADO{C.RST}", bc=C.Y)
    else:
        draw_box([f"  {C.G}{C.BLD}Nenhuma CVE publica encontrada.{C.RST}"],
                 width=w, title=f"{C.G}{C.BLD}RESULTADO{C.RST}", bc=C.G)
    return all_cves


# ─────────────────────────────────────────────────────
#  Module 6: Async Cloud Bucket Checker
# ─────────────────────────────────────────────────────

def _generate_bucket_urls(hostname):
    base = hostname.replace("www.", "").split(".")[0]
    buckets = []
    s3_names = [base, f"{base}-backup", f"{base}-assets", f"{base}-static",
                f"{base}-media", f"{base}-uploads", f"{base}-data",
                f"{base}-dev", f"{base}-staging", f"{base}-prod",
                f"{base}-public", f"{base}-private", f"{base}-logs"]
    for name in s3_names:
        buckets.append({"url": f"https://{name}.s3.amazonaws.com", "provider": "AWS S3", "bucket": name})
    for name in [base, f"{base}storage", f"{base}data"]:
        buckets.append({"url": f"https://{name}.blob.core.windows.net", "provider": "Azure Blob", "bucket": name})
    for name in [base, f"{base}-public", f"{base}-assets"]:
        buckets.append({"url": f"https://storage.googleapis.com/{name}", "provider": "Google GCS", "bucket": name})
    return buckets


async def _check_bucket(session, bucket_info, timeout):
    url = bucket_info["url"]
    try:
        ctx = ssl.create_default_context()
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout), ssl=ctx,
                               headers={"User-Agent": random.choice(USER_AGENTS)}) as resp:
            code = resp.status
            body = (await resp.text(errors="replace"))[:2000].lower()
            if code == 200:
                is_listing = any(m in body for m in ["<listbucketresult", "<enumerationresults", "<listresult", "<contents>", '"items":'])
                bucket_info["status"] = "PUBLICO" if is_listing else "EXISTE"
                bucket_info["public"] = is_listing
            elif code == 403:
                bucket_info["status"] = "PRIVADO"
                bucket_info["public"] = False
            elif code == 404:
                bucket_info["status"] = "NAO EXISTE"
                bucket_info["public"] = False
            else:
                bucket_info["status"] = f"HTTP {code}"
                bucket_info["public"] = False
            bucket_info["code"] = code
    except (asyncio.TimeoutError, aiohttp.ClientError, OSError):
        bucket_info["status"] = "TIMEOUT"
        bucket_info["public"] = False
        bucket_info["code"] = None
    return bucket_info


async def run_cloud_checker(target, http_client=None, timeout=5, concurrency=15):
    w = get_panel_width()
    print(BANNER_MINI)
    buckets = _generate_bucket_urls(target["hostname"])
    draw_box([
        f"  {C.W}Alvo:      {C.BLD}{target['hostname']}{C.RST}",
        f"  {C.W}Buckets:   {C.BLD}{len(buckets)}{C.RST} combinacoes | Async",
        f"  {C.W}Providers: {C.BLD}AWS S3, Azure Blob, Google GCS{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}VERIFICADOR DE BUCKETS NA NUVEM{C.RST}")

    print()
    sp = Spinner("Verificando buckets na nuvem...")
    sp.start()
    t0 = time.time()
    sem = asyncio.Semaphore(concurrency)
    async with aiohttp.ClientSession() as session:
        async def _guarded(b):
            async with sem:
                return await _check_bucket(session, b, timeout)
        results = await asyncio.gather(*[_guarded(b) for b in buckets], return_exceptions=True)
    results = [r if isinstance(r, dict) else {"status": "ERRO", "public": False, "provider": "?", "bucket": "?"} for r in results]
    elapsed = time.time() - t0
    sp.stop(f"Verificacao concluida em {elapsed:.2f}s")

    priority = {"PUBLICO": 0, "EXISTE": 1, "PRIVADO": 2}
    results.sort(key=lambda r: (priority.get(r.get("status", ""), 9), r.get("provider", ""), r.get("bucket", "")))
    hdr = [("Provider", 12), ("Bucket", 20), ("Status", 12), ("Risco", 10)]
    rows = []
    public_n = exists_n = 0
    for r in results:
        bname = r.get("bucket", "?")
        bname = bname[:18] + ".." if len(bname) > 20 else bname
        st = r.get("status", "?")
        if st == "PUBLICO":
            public_n += 1; exists_n += 1
            rows.append([r.get("provider","?"), bname, f"{C.R}{C.BLD}{st}{C.RST}", f"{C.R}{C.BLD}CRITICO{C.RST}"])
        elif st == "EXISTE":
            exists_n += 1
            rows.append([r.get("provider","?"), bname, f"{C.Y}{st}{C.RST}", f"{C.Y}MEDIO{C.RST}"])
        elif st == "PRIVADO":
            exists_n += 1
            rows.append([r.get("provider","?"), bname, f"{C.G}{st}{C.RST}", f"{C.G}BAIXO{C.RST}"])
        else:
            rows.append([f"{C.DIM}{r.get('provider','?')}{C.RST}", f"{C.DIM}{bname}{C.RST}", f"{C.DIM}{st}{C.RST}", f"{C.DIM}-{C.RST}"])

    print()
    draw_table(hdr, rows)
    print()
    if public_n:
        draw_box([f"  {C.R}{C.BLD}{public_n} bucket(s) PUBLICO(S)! Risco CRITICO!{C.RST}"],
                 width=w, title=f"{C.R}{C.BLD}RESULTADO{C.RST}", bc=C.R)
    elif exists_n:
        draw_box([f"  {C.Y}{C.BLD}{exists_n} bucket(s) encontrado(s), nenhum publico.{C.RST}"],
                 width=w, title=f"{C.Y}{C.BLD}RESULTADO{C.RST}", bc=C.Y)
    else:
        draw_box([f"  {C.G}{C.BLD}Nenhum bucket na nuvem encontrado.{C.RST}"],
                 width=w, title=f"{C.G}{C.BLD}RESULTADO{C.RST}", bc=C.G)
    return results


# ─────────────────────────────────────────────────────
#  Module 7: Async WAF Detector
# ─────────────────────────────────────────────────────

async def run_waf_detector(target, http_client=None, timeout=10):
    w = get_panel_width()
    print(BANNER_MINI)
    client = http_client or AsyncHttpClient(timeout=timeout)
    draw_box([
        f"  {C.W}Alvo: {C.BLD}{target['url']}{C.RST}",
        f"  {C.DIM}Analise passiva de headers + probe inofensivo.{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}DETETOR DE WAF{C.RST}")
    detected = []

    print()
    sp = Spinner("Analisando headers do servidor...")
    sp.start()
    try:
        async with aiohttp.ClientSession() as session:
            resp = await client.get(session, target["url"])
            all_headers = str(resp.headers).lower()
            for waf_name, patterns in WAF_SIGNATURES.items():
                for p in patterns:
                    if p.lower() in all_headers:
                        detected.append({"waf": waf_name, "evidence": p, "method": "Headers"})
                        break
    except NetworkError:
        sp.stop()
        draw_box([f"  {C.R}Falha na conexao.{C.RST}"], width=w, bc=C.R, title=f"{C.R}{C.BLD}ERRO{C.RST}")
        return detected
    sp.stop("Headers analisados")

    print()
    sp = Spinner("Enviando probe inofensivo para detecao de WAF...")
    sp.start()
    probe_url = target["url"].rstrip("/") + "/?id=<script>alert(1)</script>"
    try:
        async with aiohttp.ClientSession() as session:
            probe_resp = await client.get(session, probe_url)
            probe_hdrs = str(probe_resp.headers).lower()
            probe_body = probe_resp.text[:3000].lower()
            for waf_name, patterns in WAF_SIGNATURES.items():
                for p in patterns:
                    if p.lower() in probe_hdrs or p.lower() in probe_body:
                        if not any(d["waf"] == waf_name for d in detected):
                            detected.append({"waf": waf_name, "evidence": p, "method": "Probe"})
                        break
            if probe_resp.status_code in (403, 406, 429, 503) and not detected:
                detected.append({"waf": "Desconhecido", "evidence": f"HTTP {probe_resp.status_code}", "method": "Probe"})
    except NetworkError:
        pass
    sp.stop("Probe concluido")

    print()
    if detected:
        hdr = [("WAF", 16), ("Evidencia", 24), ("Metodo", 10)]
        rows = [[d["waf"], d["evidence"], d["method"]] for d in detected]
        draw_table(hdr, rows)
        print()
        draw_box([
            f"  {C.R}{C.BLD}{len(set(d['waf'] for d in detected))} WAF(s) detectado(s)!{C.RST}",
            f"  {C.Y}O WAF pode bloquear scans e alterar resultados.{C.RST}",
        ], width=w, title=f"{C.R}{C.BLD}ALERTA{C.RST}", bc=C.R)
    else:
        draw_box([f"  {C.G}{C.BLD}Nenhum WAF detectado.{C.RST}"],
                 width=w, title=f"{C.G}{C.BLD}RESULTADO{C.RST}", bc=C.G)
    return detected


# ─────────────────────────────────────────────────────
#  Module 8: Async DB Error Scanner (BeautifulSoup)
# ─────────────────────────────────────────────────────

async def _extract_links_bs4(session, client, url):
    """Extract all parameterized URLs from target page using BeautifulSoup."""
    found_params = []
    try:
        resp = await client.get(session, url)
        soup = BeautifulSoup(resp.text, "html.parser")
    except NetworkError:
        return found_params

    base_parsed = urlparse(url)
    raw_links = set()
    for tag in soup.find_all("a", href=True):
        raw_links.add(tag["href"])
    for tag in soup.find_all("form", action=True):
        raw_links.add(tag["action"])

    for raw_link in raw_links:
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
            param_names = [p.split("=", 1)[0] for p in parsed.query.split("&") if "=" in p]
            if param_names:
                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                found_params.append({"url": clean_url, "params": param_names, "full_url": full})

    seen = set()
    unique = []
    for item in found_params:
        if item["url"] not in seen:
            seen.add(item["url"])
            unique.append(item)
    return unique


async def _probe_param_errors(session, client, url, param):
    findings = []
    for probe in SYNTAX_PROBES:
        test_url = re.sub(f"({re.escape(param)}=)[^&]*", lambda m: f"{m.group(1)}{probe}", url)
        try:
            resp = await client.get(session, test_url)
            body = resp.text[:8000]
            for sig, db_type in DB_ERROR_SIGS:
                if sig.lower() in body.lower():
                    findings.append({"param": param, "probe": probe, "db_type": db_type, "signature": sig, "url": test_url})
                    return findings
        except NetworkError:
            continue
    return findings


async def run_error_db_scanner(target, http_client=None, timeout=8):
    w = get_panel_width()
    print(BANNER_MINI)
    client = http_client or AsyncHttpClient(timeout=timeout)
    draw_box([
        f"  {C.W}Alvo: {C.BLD}{target['url']}{C.RST}",
        f"  {C.DIM}Detecta divulgacao de erros de BD via{C.RST}",
        f"  {C.DIM}caracteres de quebra de sintaxe (passivo).{C.RST}",
        "",
        f"  {C.Y}Nao explora falhas — apenas detecta e reporta.{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}SCANNER DE ERROS DE BD{C.RST}")

    print()
    sp = Spinner("Extraindo URLs com parametros (BeautifulSoup)...")
    sp.start()
    async with aiohttp.ClientSession() as session:
        param_urls = await _extract_links_bs4(session, client, target["url"])
    sp.stop(f"{len(param_urls)} URL(s) com parametros encontrada(s)")

    if not param_urls:
        print()
        draw_box([f"  {C.G}Nenhum parametro encontrado para testar.{C.RST}"],
                 width=w, title=f"{C.G}{C.BLD}RESULTADO{C.RST}", bc=C.G)
        return []

    all_findings = []
    tested = 0
    async with aiohttp.ClientSession() as session:
        for item in param_urls[:15]:
            for param in item["params"][:3]:
                tested += 1
                print()
                sp = Spinner(f"Testando {param}=... ({tested})")
                sp.start()
                findings = await _probe_param_errors(session, client, item["full_url"], param)
                if findings:
                    sp.stop(f"Erro de BD detectado em '{param}'!")
                    all_findings.extend(findings)
                else:
                    sp.stop(f"'{param}' — sem divulgacao")

    print()
    if all_findings:
        hdr = [("Parametro", 12), ("Banco", 12), ("Assinatura", 26), ("Probe", 6)]
        rows = []
        for f in all_findings:
            sig = f["signature"][:24] + ".." if len(f["signature"]) > 26 else f["signature"]
            rows.append([f["param"], f"{C.R}{C.BLD}{f['db_type']}{C.RST}", sig, f"{C.R}{f['probe']}{C.RST}"])
        draw_table(hdr, rows)
        print()
        draw_box([
            f"  {C.R}{C.BLD}{len(all_findings)} divulgacao(oes) de erro de BD!{C.RST}",
            f"  {C.Y}Erros de BD expostos revelam tecnologia interna.{C.RST}",
        ], width=w, title=f"{C.R}{C.BLD}RESULTADO CRITICO{C.RST}", bc=C.R)
    else:
        draw_box([
            f"  {C.G}{C.BLD}Nenhum erro de BD detectado.{C.RST}",
            f"  {C.DIM}Testados {tested} parametro(s) sem divulgacao.{C.RST}",
        ], width=w, title=f"{C.G}{C.BLD}RESULTADO{C.RST}", bc=C.G)
    return all_findings


# ─────────────────────────────────────────────────────
#  Module 9: Async Surface Mapper
# ─────────────────────────────────────────────────────

async def _probe_db_panel(session, client, base_url, path, panel_name):
    full_url = base_url.rstrip("/") + path
    try:
        resp = await client.get(session, full_url)
        code = resp.status_code
        return {"path": path, "panel": panel_name, "code": code, "found": code in (200, 301, 302, 401, 403)}
    except NetworkError:
        return {"path": path, "panel": panel_name, "code": None, "found": False}


async def _check_error_disclosure(session, client, url):
    findings = []
    try:
        resp = await client.get(session, url)
        search_text = (resp.text + str(resp.headers)).lower()
    except NetworkError:
        return findings
    for pattern, severity, description in ERROR_PATTERNS:
        if pattern.lower() in search_text:
            findings.append({"pattern": pattern, "severity": severity, "description": description})
    return findings


async def run_surface_mapper(target, http_client=None, timeout=5, concurrency=15):
    w = get_panel_width()
    print(BANNER_MINI)
    client = http_client or AsyncHttpClient(timeout=timeout)
    draw_box([
        f"  {C.W}Alvo: {C.BLD}{target['url']}{C.RST}",
        f"  {C.DIM}Mapeamento passivo de superficie de ataque.{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}MAPEADOR DE SUPERFICIE DE ATAQUE{C.RST}")
    total_findings = 0

    # Phase 1: DB Panels
    print()
    sp = Spinner("Buscando paineis de banco de dados...")
    sp.start()
    t0 = time.time()
    sem = asyncio.Semaphore(concurrency)
    async with aiohttp.ClientSession() as session:
        async def _g1(path, name):
            async with sem:
                return await _probe_db_panel(session, client, target["url"], path, name)
        db_results = await asyncio.gather(*[_g1(p, n) for p, n in DB_PANEL_PATHS], return_exceptions=True)
    db_results = [r if isinstance(r, dict) else {"path": "?", "panel": "?", "code": None, "found": False} for r in db_results]
    sp.stop(f"Busca concluida em {time.time() - t0:.2f}s")
    db_found = [r for r in db_results if r["found"]]
    total_findings += len(db_found)

    hdr = [("Rota", 24), ("Painel", 18), ("HTTP", 6), ("Status", 12)]
    rows = []
    for r in sorted(db_results, key=lambda x: (not x["found"], x["path"])):
        p = r["path"][:22] + ".." if len(r["path"]) > 24 else r["path"]
        if r["code"] is None:
            rows.append([f"{C.DIM}{p}{C.RST}", f"{C.DIM}{r['panel']}{C.RST}", f"{C.DIM}---{C.RST}", f"{C.DIM}TIMEOUT{C.RST}"])
        elif r["found"]:
            clr = C.R if r["code"] == 200 else C.M
            lbl = "EXPOSTO" if r["code"] == 200 else "EXISTE"
            rows.append([p, f"{C.Y}{C.BLD}{r['panel']}{C.RST}", f"{clr}{r['code']}{C.RST}", f"{clr}{C.BLD}{lbl}{C.RST}"])
        else:
            rows.append([f"{C.DIM}{p}{C.RST}", f"{C.DIM}{r['panel']}{C.RST}", f"{C.DIM}{r['code']}{C.RST}", f"{C.G}N/A{C.RST}"])
    print()
    draw_table(hdr, rows)

    # Phase 2: URL params
    print()
    sp = Spinner("Extraindo parametros de URLs (BeautifulSoup)...")
    sp.start()
    async with aiohttp.ClientSession() as session:
        params = await _extract_links_bs4(session, client, target["url"])
    sp.stop(f"{len(params)} URL(s) com parametros encontrada(s)")
    total_findings += len(params)

    # Phase 3: Error disclosure
    print()
    sp = Spinner("Analisando divulgacao de erros e debug...")
    sp.start()
    async with aiohttp.ClientSession() as session:
        errors = await _check_error_disclosure(session, client, target["url"])
    sp.stop(f"{len(errors)} indicador(es) de divulgacao encontrado(s)")
    total_findings += len(errors)

    # Final
    print()
    if total_findings:
        draw_box([
            f"  {C.CY}Paineis de BD expostos: {C.R if db_found else C.G}{C.BLD}{len(db_found)}{C.RST}",
            f"  {C.CY}URLs com parametros:    {C.Y if params else C.G}{C.BLD}{len(params)}{C.RST}",
            f"  {C.CY}Vazamentos de erro:     {C.R if errors else C.G}{C.BLD}{len(errors)}{C.RST}",
            f"  {C.W}Total de pontos de atencao: {C.R}{C.BLD}{total_findings}{C.RST}",
        ], width=w, title=f"{C.CY}{C.BLD}RESULTADO FINAL{C.RST}")
    else:
        draw_box([f"  {C.G}{C.BLD}Superficie de ataque minima detectada.{C.RST}"],
                 width=w, title=f"{C.G}{C.BLD}RESULTADO{C.RST}", bc=C.G)
    return {"db_panels": db_found, "url_params": params, "error_disclosures": errors, "total": total_findings}


# ─────────────────────────────────────────────────────
#  Module 10: Async Subdomain Enumeration (crt.sh)
# ─────────────────────────────────────────────────────

async def run_subdomain_enum(target, http_client=None, timeout=15):
    w = get_panel_width()
    print(BANNER_MINI)
    domain = target["hostname"]
    draw_box([
        f"  {C.W}Dominio: {C.BLD}{domain}{C.RST}",
        f"  {C.DIM}Consulta passiva ao crt.sh (Certificate Transparency).{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}ENUMERACAO DE SUBDOMINIOS{C.RST}")

    print()
    sp = Spinner("Consultando crt.sh...")
    sp.start()
    subdomains = set()
    try:
        ctx = ssl.create_default_context()
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=aiohttp.ClientTimeout(total=timeout), ssl=ctx,
                headers={"User-Agent": random.choice(USER_AGENTS)}
            ) as resp:
                if resp.status != 200:
                    sp.stop()
                    draw_box([f"  {C.R}crt.sh retornou HTTP {resp.status}{C.RST}"],
                             width=w, title=f"{C.R}{C.BLD}ERRO{C.RST}", bc=C.R)
                    return []
                entries = await resp.json(content_type=None)
    except (asyncio.TimeoutError, aiohttp.ClientError, json.JSONDecodeError) as e:
        sp.stop()
        draw_box([f"  {C.R}Falha na conexao com crt.sh: {e}{C.RST}"],
                 width=w, title=f"{C.R}{C.BLD}ERRO{C.RST}", bc=C.R)
        return []
    sp.stop(f"Resposta: HTTP 200")

    for entry in entries:
        name = entry.get("name_value", "")
        for sub in name.split("\n"):
            sub = sub.strip().lower()
            if sub and "*" not in sub and sub.endswith(domain):
                subdomains.add(sub)
    subdomains = sorted(subdomains)

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
        draw_box([f"  {C.CY}{C.BLD}{len(subdomains)} subdominio(s) encontrado(s){C.RST}"],
                 width=w, title=f"{C.CY}{C.BLD}RESULTADO{C.RST}")
    else:
        draw_box([f"  {C.G}Nenhum subdominio encontrado para {domain}.{C.RST}"],
                 width=w, title=f"{C.G}{C.BLD}RESULTADO{C.RST}", bc=C.G)
    return subdomains


# ─────────────────────────────────────────────────────
#  Module 11: Async Tech Fingerprinting (BeautifulSoup)
# ─────────────────────────────────────────────────────

async def run_tech_fingerprint(target, http_client=None, timeout=10):
    w = get_panel_width()
    print(BANNER_MINI)
    client = http_client or AsyncHttpClient(timeout=timeout)
    draw_box([
        f"  {C.W}Alvo: {C.BLD}{target['url']}{C.RST}",
        f"  {C.DIM}Analisa headers e HTML para identificar tecnologias.{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}FINGERPRINTING DE TECNOLOGIAS{C.RST}")

    print()
    sp = Spinner("Analisando tecnologias...")
    sp.start()
    try:
        async with aiohttp.ClientSession() as session:
            resp = await client.get(session, target["url"])
    except NetworkError as e:
        sp.stop()
        draw_box([f"  {C.R}Falha na conexao: {e}{C.RST}"], width=w, title=f"{C.R}{C.BLD}ERRO{C.RST}", bc=C.R)
        return []
    sp.stop("Pagina analisada")

    detected = []
    server = resp.headers.get("Server", "")
    if server:
        detected.append({"tech": server, "category": "Servidor", "source": "Header: Server"})
    powered = resp.headers.get("X-Powered-By", "")
    if powered:
        detected.append({"tech": powered, "category": "Backend", "source": "Header: X-Powered-By"})

    # BeautifulSoup for meta generator
    soup = BeautifulSoup(resp.text[:30000], "html.parser")
    gen_tag = soup.find("meta", attrs={"name": "generator"})
    if gen_tag and gen_tag.get("content"):
        detected.append({"tech": gen_tag["content"], "category": "CMS", "source": "Meta: generator"})

    search_text = (resp.text[:30000] + str(resp.headers)).lower()
    seen = set()
    for pattern, tech_name, category in TECH_PATTERNS:
        if pattern.lower() in search_text and tech_name not in seen:
            seen.add(tech_name)
            detected.append({"tech": tech_name, "category": category, "source": "HTML/Headers"})

    print()
    if detected:
        hdr = [("Tecnologia", 22), ("Categoria", 16), ("Fonte", 18)]
        rows = []
        for d in detected:
            t = d["tech"][:20] + ".." if len(d["tech"]) > 22 else d["tech"]
            rows.append([f"{C.CY}{C.BLD}{t}{C.RST}", d["category"], f"{C.DIM}{d['source']}{C.RST}"])
        draw_table(hdr, rows)
        print()
        draw_box([f"  {C.CY}{C.BLD}{len(detected)} tecnologia(s) identificada(s){C.RST}"],
                 width=w, title=f"{C.CY}{C.BLD}RESULTADO{C.RST}")
    else:
        draw_box([f"  {C.G}Nenhuma tecnologia identificada.{C.RST}"],
                 width=w, title=f"{C.G}{C.BLD}RESULTADO{C.RST}", bc=C.G)
    return detected


# ─────────────────────────────────────────────────────
#  Module 12: File Malware Scanner (VirusTotal) — sync
# ─────────────────────────────────────────────────────

def _calculate_sha256(filepath, chunk_size=65536):
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            sha.update(data)
    return sha.hexdigest()


def run_file_scanner():
    """Scan a local file for malware using VirusTotal API (sync — no target needed)."""
    import urllib.request
    w = get_panel_width()
    clear_screen()
    print(BANNER_MINI)
    draw_box([
        f"  {C.W}{C.BLD}Scanner de Malware via VirusTotal{C.RST}",
        f"  {C.DIM}Calcula o SHA-256 e consulta a base do VirusTotal.{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}FILE MALWARE SCANNER{C.RST}")

    if not VIRUSTOTAL_API_KEY:
        print()
        draw_box([
            f"  {C.R}{C.BLD}API Key do VirusTotal nao configurada!{C.RST}",
            f"  {C.DIM}Insira sua chave na constante VIRUSTOTAL_API_KEY{C.RST}",
        ], width=w, title=f"{C.R}{C.BLD}CONFIGURACAO{C.RST}", bc=C.R)
        return None

    print()
    try:
        path = input(f"  {C.CY}▸ Caminho do ficheiro{C.RST} {C.DIM}(ou 'v' para voltar):{C.RST} ").strip().strip('"').strip("'")
    except (KeyboardInterrupt, EOFError):
        return None
    if path.lower() == "v" or not os.path.isfile(path):
        return None

    filename = os.path.basename(path)
    filesize = os.path.getsize(path)
    size_str = f"{filesize / 1_048_576:.2f} MB" if filesize >= 1_048_576 else f"{filesize / 1024:.2f} KB" if filesize >= 1024 else f"{filesize} bytes"

    print()
    sp = Spinner("Calculando SHA-256...")
    sp.start()
    try:
        file_hash = _calculate_sha256(path)
    except (IOError, OSError) as e:
        sp.stop()
        draw_box([f"  {C.R}Erro ao ler ficheiro: {e}{C.RST}"], width=w, title=f"{C.R}{C.BLD}ERRO{C.RST}", bc=C.R)
        return None
    sp.stop(f"Hash: {file_hash[:16]}...")

    print()
    sp = Spinner("Consultando VirusTotal...")
    sp.start()
    vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    req = urllib.request.Request(vt_url, headers={"x-apikey": VIRUSTOTAL_API_KEY, "User-Agent": random.choice(USER_AGENTS)})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        sp.stop()
        if e.code == 404:
            draw_box([f"  {C.Y}{C.BLD}Hash nao encontrado na base do VirusTotal.{C.RST}"],
                     width=w, title=f"{C.Y}{C.BLD}DESCONHECIDO{C.RST}", bc=C.Y)
        else:
            draw_box([f"  {C.R}Erro HTTP {e.code}{C.RST}"], width=w, title=f"{C.R}{C.BLD}ERRO{C.RST}", bc=C.R)
        return {"hash": file_hash, "status": "unknown", "file": filename}
    except Exception as e:
        sp.stop()
        draw_box([f"  {C.R}Falha: {e}{C.RST}"], width=w, title=f"{C.R}{C.BLD}ERRO{C.RST}", bc=C.R)
        return None
    sp.stop(f"Resposta recebida")

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total_engines = malicious + suspicious + harmless + undetected
    threats = malicious + suspicious

    print()
    if threats == 0:
        draw_box([f"  {C.G}{C.BLD}FICHEIRO LIMPO — 0/{total_engines} ameacas.{C.RST}"],
                 width=w, title=f"{C.G}{C.BLD}VEREDICTO{C.RST}", bc=C.G)
    elif threats <= 3:
        draw_box([f"  {C.Y}{C.BLD}FICHEIRO SUSPEITO — {threats}/{total_engines} ameacas.{C.RST}"],
                 width=w, title=f"{C.Y}{C.BLD}VEREDICTO{C.RST}", bc=C.Y)
    else:
        draw_box([f"  {C.R}{C.BLD}MALWARE DETETADO! — {threats}/{total_engines} ameacas!{C.RST}"],
                 width=w, title=f"{C.R}{C.BLD}VEREDICTO{C.RST}", bc=C.R)
    return {"hash": file_hash, "file": filename, "threats": threats, "total_engines": total_engines}


# ─────────────────────────────────────────────────────
#  Report Export: JSON
# ─────────────────────────────────────────────────────

def export_report(target, results_dict, output_path="report_vulnrecon.json"):
    w = get_panel_width()
    report = {
        "tool": "VulnRecon", "version": "4.0",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "target": {"hostname": target["hostname"], "ip": target["ip"], "url": target["url"]},
        "results": {},
    }
    for module_name, data in results_dict.items():
        try:
            json.dumps(data)
            report["results"][module_name] = data
        except (TypeError, ValueError):
            report["results"][module_name] = str(data)
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        draw_box([
            f"  {C.G}{C.BLD}Relatorio JSON exportado!{C.RST}",
            f"  {C.W}Arquivo: {C.BLD}{output_path}{C.RST}",
        ], width=w, title=f"{C.G}{C.BLD}EXPORTACAO{C.RST}", bc=C.G)
    except (IOError, OSError) as e:
        draw_box([f"  {C.R}Falha ao salvar: {e}{C.RST}"], width=w, title=f"{C.R}{C.BLD}ERRO{C.RST}", bc=C.R)


# ─────────────────────────────────────────────────────
#  Report Export: HTML (Enterprise)
# ─────────────────────────────────────────────────────

def export_html_report(target, results_dict, output_path="report_vulnrecon.html"):
    w = get_panel_width()
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    findings_summary = []
    total_critical = 0

    for mod, data in results_dict.items():
        count = 0
        severity = "BAIXO"
        if isinstance(data, list):
            count = len(data)
            if mod in ("waf",) and count > 0:
                severity = "MEDIO"
            elif mod in ("cves", "error_db") and count > 0:
                severity = "ALTO"
            elif mod == "cloud_buckets":
                pub = sum(1 for r in data if isinstance(r, dict) and r.get("public"))
                if pub > 0:
                    severity = "CRITICO"
                    total_critical += pub
        elif isinstance(data, dict):
            if mod == "headers":
                missing = len(data.get("missing", []))
                count = missing
                severity = "ALTO" if missing >= 4 else "MEDIO" if missing >= 2 else "BAIXO"
            elif mod == "surface":
                count = data.get("total", 0)
                severity = "ALTO" if count >= 5 else "MEDIO" if count >= 1 else "BAIXO"
        findings_summary.append({"module": mod, "count": count, "severity": severity})
        if severity in ("ALTO", "CRITICO"):
            total_critical += 1

    sev_colors = {"CRITICO": "#e74c3c", "ALTO": "#e67e22", "MEDIO": "#f1c40f", "BAIXO": "#2ecc71"}

    rows_html = ""
    for f in findings_summary:
        color = sev_colors.get(f["severity"], "#95a5a6")
        rows_html += f'<tr><td>{html_mod.escape(f["module"])}</td><td>{f["count"]}</td><td style="color:{color};font-weight:bold">{f["severity"]}</td></tr>\n'

    html_content = f"""<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VulnRecon Report — {html_mod.escape(target['hostname'])}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#c9d1d9;padding:2rem}}
.container{{max-width:900px;margin:0 auto}}.header{{text-align:center;border-bottom:1px solid #30363d;padding-bottom:1.5rem;margin-bottom:2rem}}
h1{{color:#58a6ff;font-size:2rem}}h2{{color:#79c0ff;margin:1.5rem 0 0.75rem;font-size:1.2rem}}
.meta{{color:#8b949e;font-size:0.9rem;margin-top:0.5rem}}
table{{width:100%;border-collapse:collapse;margin:1rem 0}}th,td{{padding:0.6rem 1rem;text-align:left;border-bottom:1px solid #21262d}}
th{{background:#161b22;color:#58a6ff;font-weight:600}}tr:hover{{background:#161b22}}
.risk-badge{{display:inline-block;padding:0.3rem 0.8rem;border-radius:4px;font-weight:bold;font-size:0.85rem}}
.footer{{text-align:center;color:#484f58;margin-top:3rem;padding-top:1rem;border-top:1px solid #21262d;font-size:0.8rem}}
</style></head><body><div class="container">
<div class="header"><h1>🛡️ VulnRecon v4.0 — Relatorio de Auditoria</h1>
<p class="meta">Alvo: <strong>{html_mod.escape(target['hostname'])}</strong> ({html_mod.escape(target['ip'])}) | Gerado em: {ts}</p></div>
<h2>Matriz de Risco</h2>
<table><thead><tr><th>Modulo</th><th>Achados</th><th>Severidade</th></tr></thead><tbody>{rows_html}</tbody></table>
<div class="footer">Gerado automaticamente por VulnRecon v4.0 Enterprise. Use somente com autorizacao.</div>
</div></body></html>"""

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        draw_box([
            f"  {C.G}{C.BLD}Relatorio HTML exportado!{C.RST}",
            f"  {C.W}Arquivo: {C.BLD}{output_path}{C.RST}",
        ], width=w, title=f"{C.G}{C.BLD}EXPORTACAO HTML{C.RST}", bc=C.G)
    except (IOError, OSError) as e:
        draw_box([f"  {C.R}Falha ao salvar HTML: {e}{C.RST}"], width=w, title=f"{C.R}{C.BLD}ERRO{C.RST}", bc=C.R)
    return total_critical


# ─────────────────────────────────────────────────────
#  Full Audit (Async)
# ─────────────────────────────────────────────────────

async def run_full_audit(target, http_client=None, timeout=5, concurrency=15, login_profile=None):
    w = get_panel_width()
    all_results = {}

    all_results["waf"] = await run_waf_detector(target, http_client, timeout)
    all_results["ports"] = await run_port_scanner(target, http_client, timeout=1.5, concurrency=concurrency)
    all_results["headers"] = await run_header_analysis(target, http_client, timeout)
    all_results["directories"] = await run_directory_fuzzer(target, http_client, timeout, concurrency)
    all_results["admin_panels"] = await run_admin_hunter(target, http_client, timeout, concurrency)
    all_results["cves"] = await run_cve_scanner(target, http_client, timeout)
    all_results["cloud_buckets"] = await run_cloud_checker(target, http_client, timeout, concurrency)
    all_results["surface"] = await run_surface_mapper(target, http_client, timeout, concurrency)
    all_results["error_db"] = await run_error_db_scanner(target, http_client, timeout)
    all_results["subdomains"] = list(await run_subdomain_enum(target, http_client, timeout))
    all_results["technologies"] = await run_tech_fingerprint(target, http_client, timeout)
    all_results["auth_crawl"] = await run_stateful_auth_crawler(
        target, http_client=http_client, timeout=timeout, login_profile=login_profile
    )
    all_results["recon_plus"] = await run_recon_discovery(target, http_client=http_client, timeout=timeout)
    all_results["active_owasp"] = await run_active_owasp_checks(
        target, recon_data=all_results["recon_plus"], http_client=http_client, timeout=timeout
    )
    all_results["contextual_intel"] = await run_contextual_fingerprint_and_cve(
        target, tech_data=all_results["technologies"], http_client=http_client, timeout=timeout
    )
    all_results["tls_dns"] = run_tls_dns_audit(target, timeout=timeout)

    print()
    export_report(target, all_results)
    return all_results


# ─────────────────────────────────────────────────────
#  Help / About
# ─────────────────────────────────────────────────────

def show_help():
    w = get_panel_width()
    print(BANNER_MINI)
    draw_box([
        f"  {C.CY}{C.BLD}VulnRecon v4.0 Enterprise{C.RST}",
        f"  {C.DIM}Ferramenta de auditoria de seguranca async.{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}SOBRE{C.RST}")
    print()
    draw_box([
        f"  {C.W}{C.BLD}Modo Headless (CLI):{C.RST}",
        f"  {C.DIM}python vulnrecon.py alvo.com --all{C.RST}",
        f"  {C.DIM}python vulnrecon.py alvo.com --ports --headers{C.RST}",
        f"  {C.DIM}python vulnrecon.py alvo.com --all --export r.json{C.RST}",
        f"  {C.DIM}python vulnrecon.py alvo.com --all --export-html r.html{C.RST}",
        f"  {C.DIM}python vulnrecon.py alvo.com --all --ci{C.RST}",
        f"  {C.DIM}python vulnrecon.py alvo.com --all --proxy-list p.txt{C.RST}",
        f"  {C.DIM}python vulnrecon.py alvo.com --all --cookie 'sess=x'{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}USO VIA TERMINAL{C.RST}")
    print()
    draw_box([
        f"  {C.R}{C.BLD}AVISO LEGAL{C.RST}",
        f"  {C.W}Use SOMENTE em alvos com autorizacao.{C.RST}",
        f"  {C.G}{C.BLD}scanme.nmap.org{C.RST} {C.DIM}(autorizado pelo Nmap){C.RST}",
    ], width=w, title=f"{C.R}{C.BLD}USO LEGAL{C.RST}", bc=C.R)


# ─────────────────────────────────────────────────────
#  Interactive Menu
# ─────────────────────────────────────────────────────

def show_menu():
    w = get_panel_width()
    draw_box([
        f"  {C.CY}{C.BLD}[1]{C.RST}  {C.W}{C.BLD}Auditoria Completa{C.RST}",
        f"       {C.DIM}Todos os modulos + relatorio JSON{C.RST}",
        "",
        f"  {C.CY}{C.BLD}[2]{C.RST}  {C.W}{C.BLD}Escanear Portas{C.RST}",
        f"  {C.CY}{C.BLD}[3]{C.RST}  {C.W}{C.BLD}Verificar Cabecalhos HTTP{C.RST}",
        f"  {C.CY}{C.BLD}[4]{C.RST}  {C.W}{C.BLD}Cacar Diretorios Ocultos{C.RST}",
        f"  {C.CY}{C.BLD}[5]{C.RST}  {C.W}{C.BLD}Cacar Paineis de Admin{C.RST}",
        f"  {C.CY}{C.BLD}[6]{C.RST}  {C.W}{C.BLD}Scanner de CVEs{C.RST}",
        f"  {C.CY}{C.BLD}[7]{C.RST}  {C.W}{C.BLD}Verificador de Buckets{C.RST}",
        f"  {C.CY}{C.BLD}[8]{C.RST}  {C.W}{C.BLD}Detetor de WAF{C.RST}",
        f"  {C.CY}{C.BLD}[9]{C.RST}  {C.W}{C.BLD}Scanner de Erros de BD{C.RST}",
        f"  {C.CY}{C.BLD}[10]{C.RST} {C.W}{C.BLD}Mapeador de Superficie{C.RST}",
        f"  {C.CY}{C.BLD}[11]{C.RST} {C.W}{C.BLD}Scanner de Malware (Local){C.RST}",
        f"  {C.CY}{C.BLD}[12]{C.RST} {C.W}{C.BLD}Enumeracao de Subdominios{C.RST}",
        f"  {C.CY}{C.BLD}[13]{C.RST} {C.W}{C.BLD}Fingerprinting de Tecnologias{C.RST}",
        f"  {C.CY}{C.BLD}[14]{C.RST} {C.W}{C.BLD}Ajuda / Sobre{C.RST}",
        "",
        f"  {C.R}{C.BLD}[0]{C.RST}  {C.DIM}Sair{C.RST}",
    ], width=w, title=f"{C.CY}{C.BLD}MENU PRINCIPAL{C.RST}")


SCAN_MAP = {
    "1": "full", "2": "ports", "3": "headers", "4": "fuzz",
    "5": "admin", "6": "cves", "7": "buckets", "8": "waf",
    "9": "errors", "10": "surface", "12": "subdomains", "13": "tech",
}


async def run_scan_module(choice, target):
    client = AsyncHttpClient()
    if choice == "1":
        await run_full_audit(target, client)
    elif choice == "2":
        await run_port_scanner(target, client)
    elif choice == "3":
        await run_header_analysis(target, client)
    elif choice == "4":
        await run_directory_fuzzer(target, client)
    elif choice == "5":
        await run_admin_hunter(target, client)
    elif choice == "6":
        await run_cve_scanner(target, client)
    elif choice == "7":
        await run_cloud_checker(target, client)
    elif choice == "8":
        await run_waf_detector(target, client)
    elif choice == "9":
        await run_error_db_scanner(target, client)
    elif choice == "10":
        await run_surface_mapper(target, client)
    elif choice == "12":
        await run_subdomain_enum(target, client)
    elif choice == "13":
        await run_tech_fingerprint(target, client)


def run_interactive():
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
        elif choice in SCAN_MAP:
            clear_screen()
            print(BANNER_MINI)
            target = prompt_target()
            if target is None:
                continue
            print()
            input(f"  {C.DIM}Pressione Enter para iniciar o scan...{C.RST}")
            clear_screen()
            asyncio.run(run_scan_module(choice, target))
            print()
            input(f"  {C.DIM}Pressione Enter para voltar ao menu...{C.RST}")
        else:
            draw_box([f"  {C.R}Opcao '{choice}' invalida.{C.RST}"],
                     width=get_panel_width(), title=f"{C.R}{C.BLD}ERRO{C.RST}", bc=C.R)
            time.sleep(1.5)


# ─────────────────────────────────────────────────────
#  Argparse (Headless CLI Mode) — Enterprise Flags
# ─────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog="vulnrecon",
        description="VulnRecon v4.0 — Ferramenta Enterprise de Auditoria de Seguranca",
        epilog="Exemplo: python vulnrecon.py scanme.nmap.org --all --export-html relatorio.html --ci",
    )
    parser.add_argument("target", nargs="?", default=None, help="URL ou IP do alvo")

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
    scan.add_argument("--surface", action="store_true", help="Mapeador de superficie")
    scan.add_argument("--subdomains", action="store_true", help="Enumeracao de subdominios")
    scan.add_argument("--tech", action="store_true", help="Fingerprinting de tecnologias")
    scan.add_argument("--auth-crawl", action="store_true", dest="auth_crawl", help="Crawler autenticado stateful")
    scan.add_argument("--active", action="store_true", help="Testes ativos OWASP com evidencia")
    scan.add_argument("--recon-plus", action="store_true", dest="recon_plus", help="Recon avancado (robots/sitemap/OpenAPI/GraphQL)")
    scan.add_argument("--tlsdns", action="store_true", help="Auditoria TLS/DNS")

    config = parser.add_argument_group("Configuracao")
    config.add_argument("--threads", type=int, default=15, help="Concorrencia async (default: 15)")
    config.add_argument("--timeout", type=int, default=5, help="Timeout em segundos (default: 5)")
    config.add_argument("--delay", type=float, default=None, help="Delay base entre requests")
    config.add_argument("--wordlist", type=str, default=None, help="Wordlist externa para fuzzing")
    config.add_argument("--export", type=str, default=None, help="Exportar relatorio JSON")
    config.add_argument("--export-html", type=str, default=None, dest="export_html", help="Exportar relatorio HTML")

    enterprise = parser.add_argument_group("Enterprise")
    enterprise.add_argument("--proxy-list", type=str, default=None, dest="proxy_list", help="Arquivo com lista de proxies")
    enterprise.add_argument("--cookie", type=str, default=None, help="Cookie header para scan autenticado")
    enterprise.add_argument("--token", type=str, default=None, help="Authorization Bearer token")
    enterprise.add_argument("--login-url", type=str, default=None, help="URL de login para crawler autenticado stateful")
    enterprise.add_argument("--login-user", type=str, default=None, help="Usuario de login")
    enterprise.add_argument("--login-pass", type=str, default=None, help="Senha de login")
    enterprise.add_argument("--login-user-field", type=str, default="username", help="Campo de usuario no form")
    enterprise.add_argument("--login-pass-field", type=str, default="password", help="Campo de senha no form")
    enterprise.add_argument("--ci", action="store_true", help="Modo CI/CD: exit(1) se achados criticos")

    return parser


async def run_headless(args):
    global THROTTLE_DELAY
    setup_console()
    if args.delay is not None:
        THROTTLE_DELAY = args.delay

    print(BANNER_MINI)
    target = resolve_target(args.target)
    if target is None:
        print(f"  {C.R}Erro: nao foi possivel resolver '{args.target}'{C.RST}")
        sys.exit(1)

    draw_box([
        f"  {C.W}Alvo: {C.BLD}{target['url']}{C.RST}",
        f"  {C.W}IP:   {C.BLD}{target['ip']}{C.RST}",
        f"  {C.DIM}Concorrencia: {args.threads} | Timeout: {args.timeout}s{C.RST}",
    ], width=get_panel_width(), title=f"{C.CY}{C.BLD}VULNRECON HEADLESS{C.RST}")

    client = AsyncHttpClient(
        timeout=args.timeout, delay=THROTTLE_DELAY,
        proxy_list=args.proxy_list, cookie=args.cookie, token=args.token
    )
    login_profile = None
    if args.login_url and args.login_user and args.login_pass:
        login_profile = {
            "url": args.login_url,
            "username": args.login_user,
            "password": args.login_pass,
            "user_field": args.login_user_field,
            "pass_field": args.login_pass_field,
        }
    all_results = {}
    run_all = args.all

    if run_all or args.waf:
        print()
        all_results["waf"] = await run_waf_detector(target, client, args.timeout)
    if run_all or args.ports:
        print()
        all_results["ports"] = await run_port_scanner(target, client, timeout=args.timeout, concurrency=args.threads)
    if run_all or args.headers:
        print()
        all_results["headers"] = await run_header_analysis(target, client, args.timeout)
    if run_all or args.fuzz:
        print()
        all_results["directories"] = await run_directory_fuzzer(target, client, args.timeout, args.threads, args.wordlist)
    if run_all or args.admin:
        print()
        all_results["admin_panels"] = await run_admin_hunter(target, client, args.timeout, args.threads)
    if run_all or args.cves:
        print()
        all_results["cves"] = await run_cve_scanner(target, client, args.timeout)
    if run_all or args.buckets:
        print()
        all_results["cloud_buckets"] = await run_cloud_checker(target, client, args.timeout, args.threads)
    if run_all or args.surface:
        print()
        all_results["surface"] = await run_surface_mapper(target, client, args.timeout, args.threads)
    if run_all or args.errors:
        print()
        all_results["error_db"] = await run_error_db_scanner(target, client, args.timeout)
    if run_all or args.subdomains:
        print()
        subs = await run_subdomain_enum(target, client, args.timeout)
        all_results["subdomains"] = list(subs) if subs else []
    if run_all or args.tech:
        print()
        all_results["technologies"] = await run_tech_fingerprint(target, client, args.timeout)
    if run_all or args.auth_crawl:
        print()
        all_results["auth_crawl"] = await run_stateful_auth_crawler(
            target, client, args.timeout, login_profile=login_profile
        )
    if run_all or args.recon_plus:
        print()
        all_results["recon_plus"] = await run_recon_discovery(target, client, args.timeout)
    if run_all or args.active:
        print()
        recon_data = all_results.get("recon_plus")
        if recon_data is None:
            recon_data = await run_recon_discovery(target, client, args.timeout)
            all_results["recon_plus"] = recon_data
        all_results["active_owasp"] = await run_active_owasp_checks(
            target, recon_data=recon_data, http_client=client, timeout=args.timeout
        )
    if run_all:
        all_results["contextual_intel"] = await run_contextual_fingerprint_and_cve(
            target, tech_data=all_results.get("technologies", []), http_client=client, timeout=args.timeout
        )
    if run_all or args.tlsdns:
        print()
        all_results["tls_dns"] = run_tls_dns_audit(target, timeout=args.timeout)

    # Export reports
    if args.export:
        print()
        export_report(target, all_results, output_path=args.export)
    elif run_all:
        print()
        export_report(target, all_results)

    critical_count = 0
    if args.export_html:
        print()
        critical_count = export_html_report(target, all_results, output_path=args.export_html)

    # CI/CD: exit(1) on critical findings
    if args.ci:
        has_critical = critical_count > 0
        # Also check individual modules
        for mod, data in all_results.items():
            if isinstance(data, list) and len(data) > 0:
                if mod in ("cves", "error_db"):
                    has_critical = True
                elif mod == "cloud_buckets":
                    if any(isinstance(r, dict) and r.get("public") for r in data):
                        has_critical = True
        if has_critical:
            print()
            draw_box([
                f"  {C.R}{C.BLD}CI/CD: Achados criticos detectados!{C.RST}",
                f"  {C.Y}Saindo com exit code 1 para quebrar a pipeline.{C.RST}",
            ], width=get_panel_width(), title=f"{C.R}{C.BLD}CI/CD MODE{C.RST}", bc=C.R)
            sys.exit(1)
        else:
            print()
            draw_box([f"  {C.G}{C.BLD}CI/CD: Nenhum achado critico. Pipeline OK.{C.RST}"],
                     width=get_panel_width(), title=f"{C.G}{C.BLD}CI/CD MODE{C.RST}", bc=C.G)

    print()


# ─────────────────────────────────────────────────────
#  Main Entry Point
# ─────────────────────────────────────────────────────

def main():
    setup_console()
    parser = build_parser()
    if len(sys.argv) == 1:
        run_interactive()
    else:
        args = parser.parse_args()
        if args.target:
            asyncio.run(run_headless(args))
        else:
            parser.print_help()


if __name__ == "__main__":
    main()
