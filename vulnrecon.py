#!/usr/bin/env python3
"""
VulnRecon — CLI Security Auditing Tool
A lightweight vulnerability scanner for security auditing.
Modules: Port Scanner | HTTP Security Headers | Directory Fuzzer
"""

import argparse
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

try:
    import requests
    from requests.exceptions import ConnectionError, Timeout, RequestException
except ImportError:
    print("\n[!] Missing dependency: 'requests'")
    print("    Install it with: pip install requests\n")
    sys.exit(1)


# ──────────────────────────────────────────────
#  ANSI Color Codes & Styling
# ──────────────────────────────────────────────

class Colors:
    """ANSI escape codes for terminal styling."""
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"


def print_colored(text: str, color: str = Colors.WHITE) -> None:
    """Print a line with the specified ANSI color."""
    print(f"{color}{text}{Colors.RESET}")


def print_status(symbol: str, message: str, color: str) -> None:
    """Print a formatted status line: [symbol] message."""
    print(f"  {color}{Colors.BOLD}[{symbol}]{Colors.RESET} {color}{message}{Colors.RESET}")


def print_section_header(title: str) -> None:
    """Print a styled section header."""
    width = 56
    print()
    print_colored("─" * width, Colors.DIM)
    print_colored(f"  ▸ {title}", Colors.CYAN + Colors.BOLD)
    print_colored("─" * width, Colors.DIM)


# ──────────────────────────────────────────────
#  ASCII Art Banner
# ──────────────────────────────────────────────

BANNER = f"""
{Colors.CYAN}{Colors.BOLD}
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗
 ██║   ██║██║   ██║██║     ████╗  ██║
 ██║   ██║██║   ██║██║     ██╔██╗ ██║
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝
         {Colors.WHITE}{Colors.BOLD}R  E  C  O  N{Colors.RESET}
{Colors.DIM}  ──────────────────────────────────────
{Colors.WHITE}   Security Auditing Tool  {Colors.DIM}v1.0.0
   github.com/your-handle/vulnrecon
  ──────────────────────────────────────{Colors.RESET}
"""


# ──────────────────────────────────────────────
#  Target Resolution & Validation
# ──────────────────────────────────────────────

def resolve_target(raw_target: str) -> dict:
    """
    Parse and validate the user-provided target.
    Returns a dict with 'hostname', 'ip', and 'url' keys.
    """
    raw_target = raw_target.strip()

    # If no scheme is present, prepend http:// for urlparse to work
    if not raw_target.startswith(("http://", "https://")):
        url_for_parse = f"http://{raw_target}"
    else:
        url_for_parse = raw_target

    parsed = urlparse(url_for_parse)
    hostname = parsed.hostname

    if not hostname:
        return None

    try:
        ip_address = socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

    return {
        "hostname": hostname,
        "ip": ip_address,
        "url": url_for_parse,
    }


# ──────────────────────────────────────────────
#  Module 1: Port Scanner
# ──────────────────────────────────────────────

# Common ports with service descriptions
COMMON_PORTS = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    993:   "IMAPS",
    995:   "POP3S",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    27017: "MongoDB",
}


def scan_single_port(ip: str, port: int, timeout: float) -> dict:
    """
    Attempt a TCP connection to a single port.
    Returns a dict with 'port', 'service', and 'is_open'.
    """
    service = COMMON_PORTS.get(port, "Unknown")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            return {"port": port, "service": service, "is_open": result == 0}
    except (socket.timeout, OSError):
        return {"port": port, "service": service, "is_open": False}


def run_port_scanner(target: dict, timeout: float = 1.5, threads: int = 20) -> list:
    """
    Scan all common ports using a thread pool for concurrency.
    Returns a sorted list of result dicts.
    """
    print_section_header("PORT SCANNER")
    print_colored(f"  Target: {target['hostname']} ({target['ip']})", Colors.WHITE)
    print_colored(f"  Ports:  {len(COMMON_PORTS)} | Timeout: {timeout}s | Threads: {threads}", Colors.DIM)
    print()

    results = []
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_single_port, target["ip"], port, timeout): port
            for port in COMMON_PORTS
        }
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception:
                port = futures[future]
                results.append({"port": port, "service": COMMON_PORTS.get(port, "?"), "is_open": False})

    elapsed = time.time() - start_time
    results.sort(key=lambda r: r["port"])

    open_ports = []
    closed_ports = []

    for r in results:
        port_str = f"{r['port']}/tcp"
        service_str = r["service"]
        if r["is_open"]:
            print_status("OPEN", f"{port_str:<12} {service_str}", Colors.RED)
            open_ports.append(r)
        else:
            print_status("CLOSED", f"{port_str:<12} {service_str}", Colors.GREEN)
            closed_ports.append(r)

    print()
    print_colored(f"  Scan completed in {elapsed:.2f}s", Colors.DIM)
    print_colored(
        f"  Results: {Colors.RED}{Colors.BOLD}{len(open_ports)} open{Colors.RESET}"
        f"{Colors.DIM} · {Colors.GREEN}{len(closed_ports)} closed{Colors.RESET}",
        ""
    )

    return results


# ──────────────────────────────────────────────
#  Module 2: HTTP Security Headers Analyzer
# ──────────────────────────────────────────────

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "Enforces HTTPS connections, prevents SSL-stripping attacks.",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "Prevents clickjacking by disallowing iframe embedding.",
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "Prevents MIME-type sniffing attacks.",
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "Controls resource loading, mitigates XSS and injection attacks.",
    },
    "X-XSS-Protection": {
        "severity": "LOW",
        "description": "Legacy XSS filter (deprecated but still recommended as fallback).",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Controls how much referrer info is sent with requests.",
    },
    "Permissions-Policy": {
        "severity": "MEDIUM",
        "description": "Restricts browser features like camera, microphone, geolocation.",
    },
}

SEVERITY_COLORS = {
    "HIGH": Colors.RED,
    "MEDIUM": Colors.YELLOW,
    "LOW": Colors.DIM,
}


def run_header_analysis(target: dict, timeout: float = 10) -> dict:
    """
    Fetch response headers from the target and check for
    the presence of essential security headers.
    Returns a dict with 'present' and 'missing' lists.
    """
    print_section_header("HTTP SECURITY HEADERS")

    url = target["url"]
    print_colored(f"  Target: {url}", Colors.WHITE)
    print()

    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
    except Timeout:
        print_status("!", "Connection timed out. Skipping header analysis.", Colors.YELLOW)
        return {"present": [], "missing": list(SECURITY_HEADERS.keys()), "error": True}
    except ConnectionError:
        print_status("!", "Connection refused. Skipping header analysis.", Colors.YELLOW)
        return {"present": [], "missing": list(SECURITY_HEADERS.keys()), "error": True}
    except RequestException as e:
        print_status("!", f"Request failed: {e}", Colors.YELLOW)
        return {"present": [], "missing": list(SECURITY_HEADERS.keys()), "error": True}

    # Suppress urllib3 InsecureRequestWarning globally
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print_colored(f"  HTTP {response.status_code} — {len(response.headers)} headers received", Colors.DIM)
    print()

    present = []
    missing = []

    for header, info in SECURITY_HEADERS.items():
        value = response.headers.get(header)
        severity = info["severity"]
        sev_color = SEVERITY_COLORS.get(severity, Colors.WHITE)

        if value:
            present.append(header)
            truncated_value = (value[:50] + "…") if len(value) > 50 else value
            print_status("✓", f"{header}", Colors.GREEN)
            print_colored(f"        Value: {truncated_value}", Colors.DIM)
        else:
            missing.append(header)
            print_status("✗", f"{header}  {sev_color}[{severity}]{Colors.RESET}", Colors.RED)
            print_colored(f"        {info['description']}", Colors.DIM)

    print()
    score = len(present) / len(SECURITY_HEADERS) * 100
    score_color = Colors.GREEN if score >= 70 else (Colors.YELLOW if score >= 40 else Colors.RED)
    print_colored(
        f"  Header Score: {score_color}{Colors.BOLD}{score:.0f}%{Colors.RESET}"
        f"{Colors.DIM} ({len(present)}/{len(SECURITY_HEADERS)} headers present){Colors.RESET}",
        ""
    )

    return {"present": present, "missing": missing, "error": False}


# ──────────────────────────────────────────────
#  Module 3: Directory Fuzzer
# ──────────────────────────────────────────────

FUZZ_PATHS = [
    # Version Control & CI/CD
    "/.git/",
    "/.git/config",
    "/.gitignore",
    "/.svn/",
    "/.hg/",
    # Environment & Configuration
    "/.env",
    "/.env.bak",
    "/config.php",
    "/config.yml",
    "/wp-config.php",
    "/web.config",
    # Admin Panels
    "/admin",
    "/admin/",
    "/administrator/",
    "/wp-admin/",
    "/wp-login.php",
    "/phpmyadmin/",
    "/cpanel",
    "/webmail",
    # Backups & Sensitive Files
    "/backup.zip",
    "/backup.tar.gz",
    "/database.sql",
    "/db.sql",
    "/dump.sql",
    "/.htaccess",
    "/.htpasswd",
    # Server Information
    "/server-status",
    "/server-info",
    "/phpinfo.php",
    "/info.php",
    # Common Discovery
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/humans.txt",
    "/security.txt",
    "/.well-known/security.txt",
    # API Endpoints
    "/api/",
    "/api/v1/",
    "/swagger.json",
    "/openapi.json",
    "/graphql",
]

# HTTP Status codes considered "interesting" (not 404)
INTERESTING_CODES = {200, 201, 301, 302, 307, 308, 401, 403, 500}

STATUS_COLOR_MAP = {
    200: Colors.RED,      # Found — potential exposure
    201: Colors.RED,
    301: Colors.YELLOW,   # Redirect
    302: Colors.YELLOW,
    307: Colors.YELLOW,
    308: Colors.YELLOW,
    401: Colors.MAGENTA,  # Auth required — exists but protected
    403: Colors.MAGENTA,  # Forbidden — exists but restricted
    500: Colors.YELLOW,   # Server error — might reveal info
}


def fuzz_single_path(base_url: str, path: str, timeout: float) -> dict:
    """
    Send a GET request to base_url + path and return the result.
    Returns dict with 'path', 'status_code', and 'interesting' flag.
    """
    full_url = base_url.rstrip("/") + path
    try:
        response = requests.get(
            full_url,
            timeout=timeout,
            allow_redirects=False,
            verify=False,
            headers={"User-Agent": "VulnRecon/1.0 (Security Audit)"}
        )
        status = response.status_code
        return {
            "path": path,
            "status_code": status,
            "interesting": status in INTERESTING_CODES,
        }
    except (Timeout, ConnectionError):
        return {"path": path, "status_code": None, "interesting": False}
    except RequestException:
        return {"path": path, "status_code": None, "interesting": False}


def run_directory_fuzzer(target: dict, timeout: float = 5, threads: int = 10) -> list:
    """
    Fuzz the target for common sensitive paths using a thread pool.
    Returns a list of result dicts.
    """
    print_section_header("DIRECTORY FUZZER")

    base_url = target["url"]
    print_colored(f"  Target:    {base_url}", Colors.WHITE)
    print_colored(f"  Wordlist:  {len(FUZZ_PATHS)} paths | Threads: {threads}", Colors.DIM)
    print()

    results = []
    start_time = time.time()

    # Suppress InsecureRequestWarning
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(fuzz_single_path, base_url, path, timeout): path
            for path in FUZZ_PATHS
        }
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception:
                path = futures[future]
                results.append({"path": path, "status_code": None, "interesting": False})

    elapsed = time.time() - start_time

    # Sort: interesting first, then by path
    results.sort(key=lambda r: (not r["interesting"], r["path"]))

    interesting_count = 0
    not_found_count = 0

    for r in results:
        path = r["path"]
        code = r["status_code"]

        if code is None:
            # Connection failed for this path
            print_status("—", f"{path:<35} {'TIMEOUT':>10}", Colors.DIM)
            not_found_count += 1
        elif r["interesting"]:
            color = STATUS_COLOR_MAP.get(code, Colors.YELLOW)
            print_status("!", f"{path:<35} {f'HTTP {code}':>10}", color)
            interesting_count += 1
        else:
            print_status("·", f"{path:<35} {f'HTTP {code}':>10}", Colors.GREEN)
            not_found_count += 1

    print()
    print_colored(f"  Fuzzing completed in {elapsed:.2f}s", Colors.DIM)
    print_colored(
        f"  Results: {Colors.RED}{Colors.BOLD}{interesting_count} found{Colors.RESET}"
        f"{Colors.DIM} · {Colors.GREEN}{not_found_count} not found{Colors.RESET}",
        ""
    )

    return results


# ──────────────────────────────────────────────
#  Report Summary
# ──────────────────────────────────────────────

def print_summary(target: dict, port_results: list, header_results: dict, fuzz_results: list) -> None:
    """Print a consolidated summary of all scan results."""
    print_section_header("AUDIT SUMMARY")
    print_colored(f"  Target: {target['hostname']} ({target['ip']})", Colors.WHITE)
    print()

    findings = 0

    # Port scan summary
    if port_results:
        open_ports = [r for r in port_results if r["is_open"]]
        if open_ports:
            findings += len(open_ports)
            ports_str = ", ".join(f"{r['port']}/{r['service']}" for r in open_ports)
            print_status("⚠", f"Open ports detected: {ports_str}", Colors.RED)
        else:
            print_status("✓", "No open ports detected on common services.", Colors.GREEN)

    # Header analysis summary
    if header_results and not header_results.get("error"):
        missing = header_results.get("missing", [])
        if missing:
            findings += len(missing)
            print_status("⚠", f"Missing security headers: {len(missing)}/{len(SECURITY_HEADERS)}", Colors.RED)
            for h in missing:
                sev = SECURITY_HEADERS[h]["severity"]
                sev_color = SEVERITY_COLORS.get(sev, Colors.WHITE)
                print_colored(f"        → {h} {sev_color}[{sev}]{Colors.RESET}", Colors.DIM)
        else:
            print_status("✓", "All security headers are present.", Colors.GREEN)

    # Directory fuzzer summary
    if fuzz_results:
        exposed = [r for r in fuzz_results if r["interesting"]]
        if exposed:
            findings += len(exposed)
            print_status("⚠", f"Exposed paths found: {len(exposed)}", Colors.RED)
            for r in exposed:
                code_color = STATUS_COLOR_MAP.get(r["status_code"], Colors.YELLOW)
                print_colored(
                    f"        → {r['path']} {code_color}[HTTP {r['status_code']}]{Colors.RESET}",
                    Colors.DIM
                )
        else:
            print_status("✓", "No sensitive paths exposed.", Colors.GREEN)

    # Final verdict
    print()
    if findings == 0:
        print_colored(
            f"  {Colors.GREEN}{Colors.BOLD}▸ No findings. Target appears well-configured.{Colors.RESET}", ""
        )
    else:
        risk = "CRITICAL" if findings >= 10 else ("HIGH" if findings >= 5 else "MEDIUM")
        risk_color = Colors.RED if risk == "CRITICAL" else (Colors.RED if risk == "HIGH" else Colors.YELLOW)
        print_colored(
            f"  {risk_color}{Colors.BOLD}▸ {findings} finding(s) detected — Risk Level: {risk}{Colors.RESET}", ""
        )

    print()
    print_colored("  Disclaimer: This tool is intended for authorized security", Colors.DIM)
    print_colored("  auditing only. Always obtain proper permission before scanning.", Colors.DIM)
    print()


# ──────────────────────────────────────────────
#  CLI Argument Parser
# ──────────────────────────────────────────────

def build_argument_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="vulnrecon",
        description="VulnRecon — CLI Security Auditing Tool",
        epilog="Example: python vulnrecon.py scanme.nmap.org --all",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "target",
        help="Target hostname, IP address, or URL to scan (e.g., scanme.nmap.org)"
    )

    # Module selection
    module_group = parser.add_argument_group("modules")
    module_group.add_argument(
        "-p", "--ports",
        action="store_true",
        help="Run the TCP port scanner"
    )
    module_group.add_argument(
        "-H", "--headers",
        action="store_true",
        help="Run the HTTP security headers analyzer"
    )
    module_group.add_argument(
        "-f", "--fuzz",
        action="store_true",
        help="Run the directory fuzzer"
    )
    module_group.add_argument(
        "-A", "--all",
        action="store_true",
        help="Run all modules (ports + headers + fuzz)"
    )

    # Configuration
    config_group = parser.add_argument_group("configuration")
    config_group.add_argument(
        "-t", "--timeout",
        type=float,
        default=1.5,
        help="Connection timeout in seconds (default: 1.5)"
    )
    config_group.add_argument(
        "--threads",
        type=int,
        default=20,
        help="Number of concurrent threads (default: 20)"
    )

    return parser


# ──────────────────────────────────────────────
#  Main Entry Point
# ──────────────────────────────────────────────

def main() -> None:
    """Main execution flow for VulnRecon."""
    parser = build_argument_parser()
    args = parser.parse_args()

    # Print banner
    print(BANNER)

    # If no module flag is set, default to --all
    if not (args.ports or args.headers or args.fuzz or args.all):
        args.all = True

    # Resolve target
    print_colored(f"  Resolving target: {args.target} …", Colors.DIM)
    target = resolve_target(args.target)

    if target is None:
        print()
        print_status("✗", f"Could not resolve target '{args.target}'.", Colors.RED)
        print_colored("    Please check the hostname/IP and your network connection.", Colors.DIM)
        print()
        sys.exit(1)

    print_status("✓", f"Resolved to {target['ip']} ({target['hostname']})", Colors.GREEN)

    # Execution timestamp
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S %Z")
    print_colored(f"  Started at: {timestamp}", Colors.DIM)

    # Initialize result containers
    port_results = []
    header_results = {}
    fuzz_results = []

    # Run selected modules
    try:
        if args.all or args.ports:
            port_results = run_port_scanner(target, timeout=args.timeout, threads=args.threads)

        if args.all or args.headers:
            header_results = run_header_analysis(target)

        if args.all or args.fuzz:
            fuzz_results = run_directory_fuzzer(target, threads=args.threads)

        # Print summary if more than one module ran
        modules_ran = sum([bool(port_results), bool(header_results), bool(fuzz_results)])
        if modules_ran >= 1:
            print_summary(target, port_results, header_results, fuzz_results)

    except KeyboardInterrupt:
        print()
        print_colored("\n  [!] Scan interrupted by user. Exiting…", Colors.YELLOW)
        print()
        sys.exit(130)


if __name__ == "__main__":
    main()
