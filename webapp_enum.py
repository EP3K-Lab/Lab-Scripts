#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web App Pentesting Enumeration Script
Usage: python webapp_enum.py -u https://target.com [options]

For authorized testing only.

---------------------------------------------------------------------------
WHAT THIS SCRIPT DOES (high-level overview for new team members):
---------------------------------------------------------------------------
This tool automates the first stage of web application security testing:
reconnaissance and enumeration. It does NOT exploit anything — it simply
gathers information that a tester would otherwise collect manually.

It has five main modules:
  1. HTTP Header Analysis  – Checks what technology the server is running
                             and whether key security headers are present.
  2. robots.txt Analysis   – Reads the site's robots.txt to find paths the
                             site owner tried to hide from search engines.
  3. Path Enumeration      – Uses ffuf (fast fuzzer) with a wordlist to discover
                             exposed endpoints. Falls back to a built-in list if
                             ffuf is not installed.
  4. DNS Enumeration       – Looks up DNS records and uses subfinder for passive
                             subdomain discovery. Falls back to a small built-in
                             wordlist if subfinder is not installed.
  5. Port Scanning         – Uses RustScan to rapidly find open ports, then hands
                             off to Nmap for service/version fingerprinting.

Run it with -h / --help to see all available flags.
---------------------------------------------------------------------------
"""

import argparse   # Handles command-line argument parsing (flags like -u, --no-dns)
import os         # Used for checking default wordlist file paths
import shutil     # Used to check whether external tools exist in PATH
import subprocess # Used to call external tools (rustscan, ffuf, subfinder)
import sys        # Used to exit the script early if dependencies are missing
import urllib.parse  # Used to break a URL into parts (scheme, hostname, path, etc.)
from concurrent.futures import ThreadPoolExecutor, as_completed
# ThreadPoolExecutor lets us send many requests at the same time (multi-threading)
# instead of waiting for each one to finish before starting the next.

# These are third-party libraries that must be installed via pip.
# 'requests'   – makes HTTP requests (GET, POST, etc.)
# 'dnspython'  – performs DNS lookups
try:
    import requests
    import dns.resolver
    import dns.exception
except ImportError:
    print("[!] Missing dependencies. Run: pip install requests dnspython")
    sys.exit(1)

# Suppress SSL certificate warnings. During pentests we often hit targets
# with self-signed or expired certs, so we silence the noise here.
requests.packages.urllib3.disable_warnings()

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                        !! USER CONFIG — EDIT HERE !!                        ║
# ║  Set your personal defaults below. These are used when you don't pass       ║
# ║  the equivalent CLI flag. The CLI flag always takes priority if provided.   ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

# Path to your preferred ffuf wordlist.
# If you always use the same one, set it here so you don't need --wordlist each run.
# Common options:
#   Kali/Parrot : /usr/share/seclists/Discovery/Web-Content/common.txt
#   Kali/Parrot : /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
#   Windows     : C:/tools/SecLists/Discovery/Web-Content/common.txt
#   Leave as None to rely on auto-detection or --wordlist flag.
DEFAULT_WORDLIST = None

# RustScan batch size — how many ports to probe per round.
# Higher = faster, but may trigger IDS/rate-limiting on sensitive targets.
# Recommended: 1000 for normal use, 500 for noisy/sensitive targets.
RUSTSCAN_BATCH = 1000

# ─── Config ───────────────────────────────────────────────────────────────────
# These constants control the script's behaviour. Adjust them as needed for
# your engagement (e.g. increase TIMEOUT on slow networks, lower MAX_THREADS
# if the target rate-limits you).

TIMEOUT = 8       # Seconds to wait for a server response before giving up
MAX_THREADS = 20  # How many requests to send simultaneously
USER_AGENT = "Mozilla/5.0 (compatible; PentestEnum/1.0)"  # Browser identity we advertise

# A Session keeps settings (headers, SSL config) shared across all requests
# so we don't have to repeat ourselves on every call.
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": USER_AGENT})
SESSION.verify = False  # Don't validate SSL certificates (common on internal/test targets)

# Security headers we CHECK FOR on the target. Missing ones are a finding.
# Each header, when present, defends against a specific attack class:
#   Strict-Transport-Security  – forces HTTPS, prevents SSL stripping
#   Content-Security-Policy    – mitigates XSS by whitelisting content sources
#   X-Frame-Options            – prevents clickjacking (iframe embedding)
#   X-Content-Type-Options     – stops MIME-type sniffing attacks
#   Referrer-Policy            – controls how much URL info is sent in Referer header
#   Permissions-Policy         – restricts browser features (camera, mic, etc.)
#   X-XSS-Protection           – legacy XSS filter (old browsers)
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]

# Technology headers we LOOK FOR on the target. Presence reveals the stack.
# Knowing the server software and version helps us look up known CVEs.
#   Server           – e.g. "Apache/2.4.51" or "nginx/1.18"
#   X-Powered-By     – e.g. "PHP/7.4.3" or "ASP.NET"
#   X-Generator      – sometimes set by CMSs like WordPress or Drupal
#   X-AspNet-Version – reveals .NET framework version
TECH_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Varnish",
    "Via",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
]

# DNS record types to query. Each tells us something different:
#   A     – IPv4 address the domain points to
#   AAAA  – IPv6 address
#   MX    – mail servers (useful for phishing/email security checks)
#   NS    – authoritative name servers
#   TXT   – often contains SPF, DKIM, DMARC, or verification tokens
#   CNAME – canonical name alias (can reveal internal hostnames)
#   SOA   – start of authority (admin email, serial number, TTLs)
DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

# Paths to probe on the target web server. These are commonly exposed
# by misconfigured or default installations. Finding them is a sign
# that the server hasn't been hardened. Grouped by category for clarity.
COMMON_PATHS = [
    # Info files – publicly accessible but may reveal structure or contacts
    "robots.txt", "sitemap.xml", "sitemap_index.xml", ".well-known/security.txt",
    "humans.txt", "crossdomain.xml", "clientaccesspolicy.xml",
    # Admin / login panels – should never be publicly reachable
    "admin", "admin/", "administrator", "login", "wp-admin", "wp-login.php",
    "phpmyadmin", "cpanel", "panel", "dashboard", "manager",
    # Config / backup leaks – high severity if found; can contain credentials
    ".env", ".env.local", ".env.backup", "config.php", "wp-config.php",
    "web.config", "settings.py", "config.yml", "config.json",
    ".git/config", ".git/HEAD", ".svn/entries", ".DS_Store",
    "backup.zip", "backup.tar.gz", "db.sql", "dump.sql",
    # API / docs – Swagger/OpenAPI docs list every endpoint and parameter
    "api", "api/v1", "api/v2", "swagger", "swagger-ui.html",
    "swagger/index.html", "api-docs", "openapi.json", "graphql",
    # Server info pages – expose version info and configuration details
    "server-status", "server-info", "phpinfo.php", "_profiler",
    "actuator", "actuator/health", "actuator/env", "actuator/mappings",
    # CMS-specific paths – WordPress and Joomla leave predictable fingerprints
    "wp-json/wp/v2/users", "xmlrpc.php", "feed", "?rest_route=/",
    "joomla.xml", "administrator/manifests/files/joomla.xml",
]

# Common subdomain prefixes to brute-force. We prepend each to the base
# domain (e.g. "dev" + "target.com" = "dev.target.com") and check if it
# resolves. Real engagements use larger wordlists (e.g. SecLists).
SUBDOMAIN_WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "api", "dev", "staging", "test", "portal",
    "admin", "m", "cdn", "shop", "app", "ftp", "git", "gitlab", "jira",
    "confluence", "jenkins", "monitor", "status", "beta", "demo", "auth",
    "sso", "id", "accounts", "help", "support", "docs", "internal",
]

# ─── Helpers ──────────────────────────────────────────────────────────────────
# Small utility functions used throughout the script for output formatting
# and making HTTP requests. Keeping these separate makes the module functions
# below easier to read.

def banner():
    """Print the tool header when the script starts."""
    print("""
╔══════════════════════════════════════╗
║      Web App Enumeration Script      ║
║      For authorized testing only     ║
╚══════════════════════════════════════╝
""")

def section(title):
    """Print a visual separator with a title to break up output into sections."""
    print(f"\n{'─' * 50}")
    print(f"  {title}")
    print('─' * 50)

# Shorthand print helpers — the prefix character signals the type of finding:
#   [+] Good / found something interesting
#   [!] Warning / potential issue
#   [*] Neutral information
#   [-] Not found / nothing notable
def ok(msg):   print(f"  [+] {msg}")
def warn(msg): print(f"  [!] {msg}")
def info(msg): print(f"  [*] {msg}")
def miss(msg): print(f"  [-] {msg}")

def get(url, allow_redirects=True):
    """
    Wrapper around requests.get() that swallows network errors.
    Returns the Response object on success, or None if the request failed
    (e.g. connection refused, DNS failure, timeout). This lets callers
    do a simple `if not r:` check instead of try/except everywhere.
    """
    try:
        return SESSION.get(url, timeout=TIMEOUT, allow_redirects=allow_redirects)
    except requests.exceptions.RequestException:
        return None

def check_tool(name):
    """
    Check whether an external tool is available on the system PATH.
    Uses shutil.which(), which searches PATH the same way the shell does.
    Returns True if found, False if not installed or not in PATH.

    Example: check_tool("ffuf") → True if ffuf is installed
    """
    return shutil.which(name) is not None

# ─── Modules ──────────────────────────────────────────────────────────────────
# Each function below is an independent enumeration module. They can be
# run together (default) or individually via CLI flags (--no-headers, etc.).

def enum_headers(base_url):
    """
    MODULE 1 – HTTP Header Analysis & Technology Fingerprinting

    Makes a single GET request to the target and inspects the response for:
      - Technology headers: reveal server software, language, and framework
      - Security headers:   reveal which protections are (or aren't) in place
      - Cookies:            checks for missing Secure / HttpOnly flags
      - Redirect chain:     shows every hop from the initial URL to the final destination

    WHY IT MATTERS: Missing security headers and cookie flags are low-effort
    findings that are always worth noting in a report.
    """
    section("HTTP Headers & Technology Fingerprinting")
    r = get(base_url, allow_redirects=True)
    if not r:
        warn("Could not reach target.")
        return

    info(f"Status: {r.status_code}  |  Final URL: {r.url}")
    info(f"Response time: {r.elapsed.total_seconds():.2f}s")

    print("\n  [Technology Headers]")
    found_tech = False
    for h in TECH_HEADERS:
        val = r.headers.get(h)  # Returns None if the header isn't present
        if val:
            ok(f"{h}: {val}")
            found_tech = True
    if not found_tech:
        miss("No common technology headers found.")

    print("\n  [Security Headers]")
    for h in SECURITY_HEADERS:
        val = r.headers.get(h)
        if val:
            ok(f"{h}: {val}")
        else:
            # Missing security headers are reported as warnings — always a finding
            warn(f"MISSING: {h}")

    print("\n  [Cookies]")
    if not r.cookies:
        miss("No cookies set.")
    for cookie in r.cookies:
        flags = []
        # 'Secure' flag: ensures the cookie is only sent over HTTPS
        if not cookie.secure:
            flags.append("NO Secure flag")
        # 'HttpOnly' flag: prevents JavaScript from reading the cookie (XSS mitigation)
        if not cookie.has_nonstandard_attr("HttpOnly"):
            flags.append("NO HttpOnly flag")
        flag_str = f"  <- {', '.join(flags)}" if flags else ""
        # Truncate long cookie values so output stays readable
        name_val = f"{cookie.name} = {cookie.value[:40]}..." if len(cookie.value) > 40 else f"{cookie.name} = {cookie.value}"
        ok(f"{name_val}{flag_str}")

    if r.history:
        # A redirect chain can reveal internal hostnames or HTTP→HTTPS issues
        print("\n  [Redirect Chain]")
        for resp in r.history:
            info(f"  {resp.status_code} -> {resp.headers.get('Location', '?')}")


def enum_robots(base_url):
    """
    MODULE 2 – robots.txt Analysis

    robots.txt is a plain-text file that tells search engine crawlers which
    paths NOT to index. It's public by design, but site owners sometimes use
    it to hide sensitive paths — which ironically makes them easy to find.

    We parse it for:
      - Disallow entries: paths the owner wants hidden (admin panels, APIs, etc.)
      - Sitemap entries:  links to XML sitemaps that list every page on the site

    Returns a list of disallowed paths so they can be fed into further testing.
    """
    section("robots.txt Analysis")
    r = get(f"{base_url.rstrip('/')}/robots.txt")
    if not r or r.status_code != 200:
        miss("robots.txt not found.")
        return []

    disallowed = []
    for line in r.text.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            # Extract just the path part after "Disallow:"
            path = line.split(":", 1)[1].strip()
            # Skip empty entries and "Disallow: /" (blocks everything — not a specific path)
            if path and path != "/":
                disallowed.append(path)
                warn(f"Disallow: {path}")
        elif line.lower().startswith("sitemap:"):
            ok(f"Sitemap: {line.split(':', 1)[1].strip()}")

    if not disallowed:
        miss("No interesting Disallow entries.")
    return disallowed


def enum_paths(base_url, wordlist=None):
    """
    MODULE 3 – Directory/Path Enumeration (Content Discovery)

    Tries to use ffuf first (much faster, larger wordlists). Falls back to the
    built-in Python implementation if ffuf is not installed or no wordlist
    is available.

    --- ffuf path (preferred) ---
    ffuf (Fuzz Faster U Fool) is purpose-built for web fuzzing and can test
    tens of thousands of paths per second. Key flags used:
      -u <url>/FUZZ  : FUZZ is the placeholder ffuf replaces with each word
      -w <wordlist>  : path to a newline-separated wordlist file
      -mc 200,204,...: only report responses with these status codes
                       We only show: 200/204 (success) and 401/403 (path exists
                       but protected). Redirects and 405s are hidden — too noisy.
      -ac            : auto-calibrate — silently filters out false positives
                       by learning what a "not found" response looks like
      -t 100         : 100 concurrent threads for speed

    Recommended wordlists (from SecLists):
      Discovery/Web-Content/common.txt          (~5k words, fast)
      Discovery/Web-Content/raft-medium-words.txt (~63k words, thorough)

    --- Fallback path (built-in) ---
    If ffuf isn't available, probes the ~50 paths in COMMON_PATHS using
    Python's requests library with threading. Slower and less thorough but
    requires no extra tools.

    Status code meanings reported:
      200/204 – Publicly accessible          [HIGH priority]
      401     – Auth required but path EXISTS [worth investigating]
      403     – Forbidden but path EXISTS     [worth investigating]
    """
    section("Directory / Path Enumeration")
    base_url = base_url.rstrip("/")

    # ── ffuf branch ──────────────────────────────────────────────────────────
    if check_tool("ffuf") and wordlist:
        info(f"ffuf found — using wordlist: {wordlist}")
        cmd = [
            "ffuf",
            "-u", f"{base_url}/FUZZ",
            "-w", wordlist,
            "-mc", "200,204,401,403",  # only show successes + protected paths (no noisy redirects)
            "-ac",       # auto-calibrate to suppress false positives
            "-t", "100", # threads
        ]
        subprocess.run(cmd)
        return

    if check_tool("ffuf") and not wordlist:
        # ffuf is installed but we have no wordlist — try common default locations
        defaults = [
            # Kali / Parrot Linux (SecLists package)
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            # Kali default dirb wordlist (smaller but always present)
            "/usr/share/wordlists/dirb/common.txt",
            # Common Windows install paths
            "C:/tools/SecLists/Discovery/Web-Content/common.txt",
        ]
        for path in defaults:
            if os.path.isfile(path):
                info(f"ffuf found — auto-detected wordlist: {path}")
                cmd = [
                    "ffuf",
                    "-u", f"{base_url}/FUZZ",
                    "-w", path,
                    "-mc", "200,204,401,403",  # only show successes + protected paths (no noisy redirects)
                    "-ac",
                    "-t", "100",
                ]
                subprocess.run(cmd)
                return
        warn("ffuf is installed but no wordlist found.")
        warn("Provide one with --wordlist /path/to/list.txt")
        warn("Falling back to built-in path list...")

    # ── built-in fallback ────────────────────────────────────────────────────
    if not check_tool("ffuf"):
        info("ffuf not found — using built-in path list (install ffuf for better results).")

    def check_path(path):
        """Check a single path and return (status_code, full_url, body_size) or None."""
        url = f"{base_url}/{path}"
        r = get(url, allow_redirects=False)
        if r is None:
            return None  # Network error — skip this path
        return (r.status_code, url, len(r.content))

    found = []
    # ThreadPoolExecutor spins up MAX_THREADS workers that each call check_path().
    # as_completed() yields results as they finish (not in submission order).
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
        futures = {ex.submit(check_path, p): p for p in COMMON_PATHS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                code, url, size = result
                if code in (200, 201, 204):
                    ok(f"{code}  {url}  [{size}b]")
                    found.append(url)
                elif code in (301, 302, 307, 308):
                    info(f"{code}  {url}  [redirect]")
                elif code == 401:
                    # Auth-required means the endpoint exists — worth noting
                    warn(f"{code}  {url}  [auth required — exists]")
                    found.append(url)
                elif code == 403:
                    # Forbidden means the endpoint exists — server just won't serve it
                    warn(f"{code}  {url}  [forbidden — exists]")
                    found.append(url)

    if not found:
        miss("No interesting paths discovered.")
    return found


def enum_dns(domain):
    """
    MODULE 4 – DNS Enumeration & Subdomain Brute-force

    Two-part module:

    Part A – DNS Record Lookup:
      Queries several DNS record types for the base domain. Results give us
      IP addresses, mail servers, name servers, and TXT records (which often
      contain SPF/DKIM/DMARC policy details relevant to email security testing).

    Part B – Subdomain Brute-force:
      Constructs FQDNs by prepending each word from SUBDOMAIN_WORDLIST to the
      base domain and checking if the result resolves to an IP. A successful
      lookup means the subdomain exists and might be reachable.
      Example: "dev" + "example.com" → checks "dev.example.com" for an A record.

      NOTE: This is DNS-based brute-forcing — it only finds subdomains that are
      in DNS. It won't find ones hidden behind a WAF or only on internal DNS.
      For real engagements, use a larger wordlist and consider tools like
      Amass or Subfinder.
    """
    section("DNS Enumeration")
    resolver = dns.resolver.Resolver()
    resolver.timeout = 4   # Seconds to wait for a single DNS query
    resolver.lifetime = 4  # Total time allowed for all retries on one query

    print("\n  [DNS Records]")
    for rtype in DNS_RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            for rdata in answers:
                # :<6 left-aligns the record type in a 6-char field for clean columns
                ok(f"{rtype:<6}  {rdata}")
        except (dns.exception.DNSException, Exception):
            # NXDOMAIN, NoAnswer, Timeout — all mean the record type doesn't exist;
            # silence these and move on
            pass

    # ── Subdomain Discovery ───────────────────────────────────────────────────
    print("\n  [Subdomain Discovery]")
    found_subs = []

    if check_tool("subfinder"):
        # subfinder uses passive sources (certificate transparency logs, DNS datasets,
        # APIs, etc.) to find subdomains WITHOUT sending any requests to the target.
        # This makes it very fast and stealthy compared to active brute-forcing.
        # -d <domain>  : target domain
        # -silent      : suppress the banner/status so output is clean subdomains only
        info("subfinder found — running passive subdomain discovery ...")
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True,  # capture stdout/stderr rather than printing directly
            text=True,            # return output as a string (not raw bytes)
        )
        found_subs = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        for sub in found_subs:
            ok(sub)
        if not found_subs:
            miss("subfinder found no subdomains.")
    else:
        # Fallback: DNS brute-force using the built-in wordlist.
        # Less thorough than subfinder's passive enumeration but needs no extra tools.
        info("subfinder not found — falling back to DNS brute-force wordlist.")
        info("Install subfinder for much better subdomain coverage: https://github.com/projectdiscovery/subfinder")

        def check_sub(sub):
            """Try to resolve a subdomain. Returns (fqdn, [ips]) on success, None otherwise."""
            fqdn = f"{sub}.{domain}"
            try:
                answers = resolver.resolve(fqdn, "A")
                ips = [str(r) for r in answers]
                return (fqdn, ips)
            except Exception:
                return None  # Subdomain doesn't exist or didn't resolve

        with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
            futures = {ex.submit(check_sub, s): s for s in SUBDOMAIN_WORDLIST}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    fqdn, ips = result
                    ok(f"{fqdn}  ->  {', '.join(ips)}")
                    found_subs.append(fqdn)

        if not found_subs:
            miss("No subdomains found from wordlist.")

    return found_subs


def enum_ports(host):
    """
    MODULE 5 – Port Scanning (RustScan → Nmap)

    Two-stage process optimised for speed:

    Stage 1 – RustScan:
      Scans all 65,535 TCP ports as fast as possible. RustScan is written in
      Rust and can finish a full port scan in seconds. Key flags used:
        -a <host>        : target address
        -b 1000          : batch size — ports checked per round (higher = faster,
                           but may trigger rate-limiting; lower if needed)
        --ulimit 5000    : raise the open file descriptor limit so we can hold
                           many connections open simultaneously
        --range 1-65535  : scan every port (not just the top 1000)

    Stage 2 – Nmap (via RustScan's -- passthrough):
      Everything after '--' is passed directly to Nmap, which runs only against
      the open ports RustScan found. This is much faster than letting Nmap scan
      all ports itself.
        -sV   : probe open ports to determine service/version info
        -sC   : run Nmap's default scripts (safe, useful fingerprinting)
        --open: only display open ports in output

    WHY THIS COMBO: RustScan finds what's open quickly; Nmap then does the deep
    service fingerprinting. You get the best of both tools.

    Requires: rustscan and nmap both installed and in PATH.
    """
    section("Port Scanning (RustScan → Nmap)")

    # On Linux/macOS, nmap's -sV (version detection) and -sC (default scripts)
    # use raw sockets which require root privileges. Without sudo, nmap will
    # silently produce no output or fall back to a degraded scan.
    # Run the whole script with: sudo python3 webapp_enum.py ...
    if sys.platform != "win32" and os.geteuid() != 0:
        warn("Port scanning requires root on Linux — no output will appear without it.")
        warn("Re-run with: sudo python3 webapp_enum.py ...")
        warn("Attempting anyway in case your setup allows it...")

    # Check both tools up front and report clearly which one is missing
    rs_ok  = check_tool("rustscan")
    nm_ok  = check_tool("nmap")

    if not rs_ok:
        warn("rustscan not found in PATH — skipping port scan.")
        warn("  Verify it's installed: rustscan --version")
        warn("  Install from        : https://github.com/RustScan/RustScan")
        return

    if not nm_ok:
        warn("nmap not found in PATH — rustscan requires nmap for service fingerprinting.")
        warn("  Verify it's installed: nmap --version")
        warn("  Install from        : https://nmap.org/download.html")
        return

    cmd = [
        "rustscan",
        "-a", host,
        "-b", str(RUSTSCAN_BATCH),  # batch size (set in USER CONFIG at top of file)
        "--range", "1-65535",
        "--",               # everything after this is passed to nmap
        "-sV",              # service version detection
        "-sC",              # default nmap scripts
        "--open",           # only show open ports
    ]

    # --ulimit raises the open file descriptor limit on Linux/macOS so rustscan
    # can hold thousands of connections open simultaneously. It is not supported
    # on Windows and will cause rustscan to exit immediately if included.
    if sys.platform != "win32":
        cmd.insert(3, "5000")
        cmd.insert(3, "--ulimit")

    # Print the exact command being run — useful for debugging and for juniors
    # learning what flags are being passed to each tool
    info(f"Running: {' '.join(cmd)}")
    info("RustScan output appears below (may take a moment)...")
    print()

    # Run with output streaming directly to the terminal (no capture_output)
    # so results appear in real time as rustscan finds open ports
    result = subprocess.run(cmd)

    if result.returncode != 0:
        warn(f"RustScan exited with code {result.returncode} — scan may be incomplete.")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    """
    Entry point — parses CLI arguments and calls each module in order.

    Using argparse gives us a free --help page and clean argument handling.
    The --no-* flags let you skip modules you don't need, which is useful
    when you only want DNS info, or the target blocks path probing.

    Example usage:
      # Full scan with ffuf wordlist:
      python webapp_enum.py -u https://example.com --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt

      # Skip port scanning (e.g. already done separately):
      python webapp_enum.py -u https://example.com --no-ports

      # Headers and DNS only:
      python webapp_enum.py -u https://example.com --no-paths --no-ports
    """
    parser = argparse.ArgumentParser(
        description="Web app pentesting enumeration — authorized use only"
    )
    parser.add_argument("-u", "--url", required=True,
                        help="Target URL (e.g. https://target.com)")
    parser.add_argument("--wordlist", default=None,
                        help="Path to wordlist for ffuf (e.g. /usr/share/seclists/Discovery/Web-Content/common.txt)")
    parser.add_argument("--no-dns",     action="store_true", help="Skip DNS enumeration and subdomain discovery")
    parser.add_argument("--no-paths",   action="store_true", help="Skip path/directory enumeration")
    parser.add_argument("--no-headers", action="store_true", help="Skip header analysis and robots.txt")
    parser.add_argument("--no-ports",   action="store_true", help="Skip port scanning (RustScan → Nmap)")
    args = parser.parse_args()

    banner()

    # Normalise the URL (strip trailing slash) and extract the bare hostname
    # e.g. "https://www.example.com/path" → hostname = "www.example.com"
    url = args.url.rstrip("/")
    parsed = urllib.parse.urlparse(url)
    domain = parsed.hostname
    host = domain  # alias used by enum_ports (could be IP or hostname)

    print(f"  Target : {url}")
    print(f"  Domain : {domain}")

    # Run each module unless the user opted out via a --no-* flag.
    # Order: headers first (fast, passive), then paths/ports (active/loud).
    if not args.no_headers:
        enum_headers(url)
        enum_robots(url)   # robots.txt is logically grouped with header recon

    if not args.no_paths:
        # CLI flag takes priority; fall back to DEFAULT_WORDLIST from user config
        enum_paths(url, wordlist=args.wordlist or DEFAULT_WORDLIST)

    if not args.no_dns:
        enum_dns(domain)

    if not args.no_ports:
        enum_ports(host)

    section("Done")
    print("  Review findings above. Always stay in scope.\n")


# This block ensures main() only runs when the script is executed directly,
# not when it's imported as a module by another Python script.
if __name__ == "__main__":
    main()
