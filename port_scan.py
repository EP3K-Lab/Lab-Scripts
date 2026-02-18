#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Standalone Port Scanner: RustScan → Nmap
Usage: python port_scan.py -t <target> [options]

For authorized testing only.

---------------------------------------------------------------------------
HOW IT WORKS:
  Stage 1 – RustScan scans all 65,535 TCP ports as fast as possible and
             prints open port results to stdout.
  Stage 2 – This script parses RustScan's output to extract the open port
             numbers, then calls Nmap directly against only those ports for
             deep service/version/script fingerprinting.

This two-stage approach is much faster than running Nmap alone, because
Nmap is only doing heavy lifting on ports that are confirmed open.

SCAN PROFILES (--profile):
  default    – Service version + default scripts (-sV -sC)
  aggressive – + OS detection, traceroute, script intensity (-A)
  stealth    – SYN scan only, slower timing, no scripts (-sS -T2)
  vuln       – Runs Nmap's vuln script category to find known CVEs
  udp        – UDP scan on top-100 common UDP ports (requires root)

OUTPUT:
  Results are printed to the terminal in real time.
  Use --output <dir> to also save timestamped .txt files per target.
---------------------------------------------------------------------------
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                        !! USER CONFIG — EDIT HERE !!                        ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

# RustScan batch size — ports probed per round.
# 1000 is a good default. Lower to 500 if the target rate-limits you.
RUSTSCAN_BATCH = 1000

# RustScan timeout per port in milliseconds.
# Increase on high-latency/slow networks (e.g. 3000 for VPN targets).
RUSTSCAN_TIMEOUT = 1500


# ─── Helpers ──────────────────────────────────────────────────────────────────

def banner():
    print("""
╔══════════════════════════════════════╗
║     RustScan → Nmap Port Scanner     ║
║     For authorized testing only      ║
╚══════════════════════════════════════╝
""")


def section(title):
    print(f"\n{'─' * 55}")
    print(f"  {title}")
    print('─' * 55)


def ok(msg):   print(f"  [+] {msg}")
def warn(msg): print(f"  [!] {msg}")
def info(msg): print(f"  [*] {msg}")
def miss(msg): print(f"  [-] {msg}")


def check_tool(name):
    """
    Return the full path to an external tool if it can be found, or None.

    Checks PATH first, then falls back to common installation directories
    that are often missing from PATH when running under sudo (e.g. ~/.cargo/bin
    for RustScan installed via cargo).
    """
    found = shutil.which(name)
    if found:
        return found

    # Resolve the real user's home directory even when running under sudo.
    # sudo resets HOME to /root, so shutil.which() misses ~/.cargo/bin etc.
    user_home = None
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd
            user_home = pwd.getpwnam(sudo_user).pw_dir
        except Exception:
            pass

    if not user_home:
        user_home = os.path.expanduser("~")

    extra_dirs = [
        os.path.join(user_home, ".cargo", "bin"),  # cargo install rustscan
        os.path.join(user_home, ".local", "bin"),  # pipx / manual installs
        os.path.join(user_home, "go", "bin"),      # go install ...
        "/usr/local/bin",
        "/usr/local/sbin",
        "/snap/bin",
        "/root/.cargo/bin",
        "/root/go/bin",
    ]

    for directory in extra_dirs:
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate

    return None


# ─── RustScan ────────────────────────────────────────────────────────────────

def run_rustscan(host, batch=RUSTSCAN_BATCH, timeout=RUSTSCAN_TIMEOUT):
    """
    Run RustScan against all 65,535 TCP ports on the given host.

    RustScan is intentionally run WITHOUT its built-in Nmap passthrough
    (i.e. no '--' at the end of the command). This lets us capture its
    output cleanly, parse the open ports ourselves, and then invoke Nmap
    with the exact flags we want.

    Key RustScan flags used:
      -a <host>        Target IP address or hostname
      -b <n>           Batch size: how many ports to probe per round
      --timeout <ms>   Per-port connection timeout in milliseconds
      --range 1-65535  Scan every TCP port
      --no-config      Ignore ~/.rustscan.toml so our flags always take effect
      --greppable      Machine-friendly output: "Host: <ip>  Ports: 22,80,443"
                       Makes it easy to parse with a simple regex

    Returns a sorted list of integer port numbers, e.g. [22, 80, 443].
    Returns an empty list if RustScan found nothing or failed.
    """
    cmd = [
        "rustscan",
        "-a", host,
        "-b", str(batch),
        "--timeout", str(timeout),
        "--range", "1-65535",
        "--no-config",
        "--greppable",   # output: "Host: x.x.x.x  Ports: 22/open/tcp,,80/open/tcp,,"
    ]

    # --ulimit is Linux/macOS-only; it raises the open-file-descriptor limit
    # so RustScan can hold many parallel connections without hitting OS limits.
    if sys.platform != "win32":
        cmd += ["--ulimit", "5000"]

    info(f"Running: {' '.join(cmd)}")
    info("Scanning all 65,535 TCP ports — this may take a few seconds...\n")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,   # grab stdout/stderr; we need stdout to parse ports
            text=True,             # decode bytes → str automatically
        )
    except FileNotFoundError:
        warn("rustscan binary not found. Is it installed and on PATH?")
        return []

    if result.returncode != 0:
        warn(f"RustScan exited with code {result.returncode}.")
        if result.stderr.strip():
            warn(f"stderr: {result.stderr.strip()}")

    # ── Parse open ports from greppable output ───────────────────────────────
    # Greppable format looks like:
    #   Host: 10.10.10.5 ()    Ports: 22/open/tcp//ssh///, 80/open/tcp//http///, 443/open/tcp//https///
    #
    # We extract everything after "Ports:" and pull out the port numbers.
    ports = []
    for line in result.stdout.splitlines():
        # Handle new format: "10.0.0.108 -> [445,135,139]"
        if "->" in line and "[" in line:
            ports_section = line.split("[")[1].split("]")[0]
            for port in ports_section.split(","):
                port = port.strip()
                if port.isdigit():
                    ports.append(int(port))
        # Handle old greppable format
        elif "Ports:" in line:
            ports_section = line.split("Ports:", 1)[1]
            for entry in ports_section.split(","):
                entry = entry.strip()
                match = re.match(r"^(\d+)/open/", entry)
                if match:
                    ports.append(int(match.group(1)))

    ports = sorted(set(ports))  # deduplicate and sort numerically

    # Echo the full RustScan stdout so the user can see what it reported
    if result.stdout.strip():
        print(result.stdout)

    return ports


# ─── Nmap profiles ────────────────────────────────────────────────────────────

# Each profile is a list of extra Nmap flags appended after the base command.
# The base command always includes: -p <ports> --open
NMAP_PROFILES = {
    "default": [
        "-sV",        # Probe open ports to determine service and version info
        "-sC",        # Run Nmap's default safe scripts (banner grabs, auth checks, etc.)
    ],
    "aggressive": [
        "-A",         # Enables -sV, -sC, OS detection (-O), and traceroute
        "-T4",        # Aggressive timing (faster on reliable networks)
    ],
    "stealth": [
        "-sS",        # TCP SYN scan (half-open; less likely to be logged)
        "-T2",        # Polite timing (slower, but quieter)
        "--max-retries", "1",
    ],
    "vuln": [
        "-sV",        # Version detection needed so vuln scripts know what to test
        "--script", "vuln",   # Run the entire 'vuln' NSE script category
    ],
    "udp": [
        # NOTE: udp profile ignores the RustScan port list (UDP scan is separate).
        # It scans the top-100 most common UDP ports instead.
        "-sU",        # UDP scan (requires root / Administrator)
        "--top-ports", "100",
        "-sV",
        "--version-intensity", "0",  # Light version detection to keep UDP scan fast
    ],
}


# ─── Nmap ─────────────────────────────────────────────────────────────────────

def run_nmap(host, ports, profile="default", output_file=None):
    """
    Run Nmap against a specific list of open ports discovered by RustScan.

    By scanning only known-open ports (instead of all 65,535), Nmap can
    focus its slower, more thorough analysis where it actually matters.

    Args:
        host        : Target IP or hostname
        ports       : List of integer port numbers from RustScan
        profile     : Key from NMAP_PROFILES controlling which flags to use
        output_file : If given, also write results to this file path (-oN flag)
    """
    if not ports and profile != "udp":
        miss("No open TCP ports found — skipping Nmap.")
        return

    profile_flags = NMAP_PROFILES.get(profile, NMAP_PROFILES["default"])

    # Base Nmap command
    cmd = ["nmap"]

    if profile == "udp":
        # UDP scan ignores RustScan results — it always scans top-100 UDP ports
        cmd += profile_flags
        cmd += [host]
    else:
        port_str = ",".join(str(p) for p in ports)
        cmd += [
            "-p", port_str,   # Only scan the ports RustScan confirmed are open
            "--open",         # Only display open ports in output (skip closed/filtered)
        ]
        cmd += profile_flags
        cmd += [host]

    # Save output to a file in addition to terminal display
    if output_file:
        cmd += ["-oN", output_file]

    info(f"Running: {' '.join(cmd)}")
    if profile == "vuln":
        info("Running vuln scripts — this can take several minutes per port.")
    print()

    # Run without capturing output so results stream to the terminal in real time.
    result = subprocess.run(cmd)

    if result.returncode != 0:
        warn(f"Nmap exited with code {result.returncode} — scan may be incomplete.")

    if output_file and os.path.isfile(output_file):
        ok(f"Results saved to: {output_file}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="RustScan → Nmap port scanner — authorized use only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scan profiles:
  default    Service version + default scripts     (-sV -sC)
  aggressive OS detection + traceroute + scripts   (-A -T4)
  stealth    SYN scan, slow timing, no scripts     (-sS -T2)
  vuln       Run Nmap vuln scripts (CVE checks)    (-sV --script vuln)
  udp        Top-100 UDP ports (requires root)     (-sU --top-ports 100)

Examples:
  python port_scan.py -t 10.10.10.5
  python port_scan.py -t 10.10.10.5 --profile aggressive
  python port_scan.py -t 10.10.10.5 --profile vuln --output ./results
  python port_scan.py -t 10.10.10.5 --batch 500 --timeout 3000
  sudo python port_scan.py -t 10.10.10.5 --profile stealth
        """,
    )
    parser.add_argument(
        "-t", "--target", required=True,
        help="Target IP address or hostname (e.g. 10.10.10.5 or target.htb)"
    )
    parser.add_argument(
        "--profile", default="default",
        choices=list(NMAP_PROFILES.keys()),
        help="Nmap scan profile to use (default: default)"
    )
    parser.add_argument(
        "--batch", type=int, default=RUSTSCAN_BATCH,
        help=f"RustScan batch size — ports per round (default: {RUSTSCAN_BATCH})"
    )
    parser.add_argument(
        "--timeout", type=int, default=RUSTSCAN_TIMEOUT,
        help=f"RustScan per-port timeout in ms (default: {RUSTSCAN_TIMEOUT})"
    )
    parser.add_argument(
        "--output", metavar="DIR",
        help="Directory to save Nmap results (timestamped .txt file per target)"
    )
    parser.add_argument(
        "--rustscan-only", action="store_true",
        help="Run RustScan only — skip the Nmap deep scan"
    )
    parser.add_argument(
        "--nmap-only", metavar="PORTS",
        help="Skip RustScan and run Nmap directly on these ports (e.g. '22,80,443')"
    )
    args = parser.parse_args()

    banner()

    # ── Pre-flight checks ─────────────────────────────────────────────────────
    # Warn early about missing tools so the user isn't left wondering why
    # nothing happens after a long wait.
    rs_path = check_tool("rustscan")
    nm_path = check_tool("nmap")

    if not args.nmap_only and not rs_path:
        warn("rustscan not found in PATH or common install locations.")
        warn("Install from: https://github.com/RustScan/RustScan")
        warn("  cargo install rustscan   (via Rust/cargo)")
        warn("  or download a binary from the GitHub releases page")
        sys.exit(1)

    if not nm_path:
        warn("nmap not found in PATH.")
        warn("Install from: https://nmap.org/download.html")
        if args.rustscan_only:
            warn("--rustscan-only flag set; continuing without Nmap check.")
        else:
            sys.exit(1)

    # On Linux/macOS, -sV, -sS, and -sU require raw socket access (root).
    # Without it, Nmap silently falls back to connect() scans or produces no output.
    if sys.platform != "win32" and os.geteuid() != 0:
        if args.profile in ("stealth", "udp"):
            warn(f"Profile '{args.profile}' requires root (raw socket access).")
            warn("Re-run with: sudo python3 port_scan.py ...")
            sys.exit(1)
        else:
            warn("Running without root — version detection (-sV) may be limited.")
            warn("Re-run with sudo for best results.")

    target = args.target
    info(f"Target  : {target}")
    info(f"Profile : {args.profile}")

    # ── Resolve output file path ───────────────────────────────────────────────
    output_file = None
    if args.output:
        os.makedirs(args.output, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = re.sub(r"[^\w\-.]", "_", target)
        output_file = os.path.join(args.output, f"{safe_target}_{args.profile}_{timestamp}.txt")

    # ── Stage 1: RustScan ─────────────────────────────────────────────────────
    open_ports = []

    if args.nmap_only:
        # User supplied ports directly — skip RustScan entirely
        try:
            open_ports = sorted(int(p.strip()) for p in args.nmap_only.split(",") if p.strip())
        except ValueError:
            warn("--nmap-only: invalid port list. Use comma-separated integers, e.g. '22,80,443'.")
            sys.exit(1)
        info(f"Using user-supplied ports: {', '.join(str(p) for p in open_ports)}")
    else:
        section("Stage 1 — RustScan (Full TCP Port Discovery)")
        open_ports = run_rustscan(target, batch=args.batch, timeout=args.timeout)

        if open_ports:
            ok(f"Open ports found ({len(open_ports)}): {', '.join(str(p) for p in open_ports)}")
        else:
            miss("RustScan found no open TCP ports.")

    if args.rustscan_only:
        section("Done (RustScan only)")
        print("  Skipped Nmap (--rustscan-only flag set).\n")
        return

    # ── Stage 2: Nmap ─────────────────────────────────────────────────────────
    section(f"Stage 2 — Nmap Deep Scan (profile: {args.profile})")
    run_nmap(target, open_ports, profile=args.profile, output_file=output_file)

    section("Done")
    if open_ports:
        ok(f"Scanned {len(open_ports)} open port(s) on {target}")
    print("  Always stay within scope.\n")


if __name__ == "__main__":
    main()
