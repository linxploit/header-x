#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
██╗  ██╗███████╗ █████╗ ██████╗ ███████╗██████╗ ██╗  ██╗
██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗╚██╗██╔╝
███████║█████╗  ███████║██║  ██║█████╗  ██████╔╝ ╚███╔╝
██╔══██║██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗ ██╔██╗
██║  ██║███████╗██║  ██║██████╔╝███████╗██║  ██║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝

HeaderX — HTTP Security Header Analyzer & Grader
Made by Mindless — Founder & CEO of Linxploit
https://linxploit.com | https://linxploit.com/founder

DISCLAIMER:
    HeaderX only performs a single passive HTTP GET request per target —
    the same request any browser makes when visiting a page — and reads
    the response headers. It sends no attack payloads and modifies no
    server state. A low grade indicates hardening opportunities, not a
    confirmed exploitable vulnerability.


"""

import argparse
import concurrent.futures
import csv
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import requests
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

TOOL_NAME = "HeaderX"
VERSION = "2.0.0"
AUTHOR = "Mindless"
ORG = "Linxploit"
SITE = "https://linxploit.com"
PORTFOLIO = "https://linxploit.com/founder"

requests.packages.urllib3.disable_warnings()  # noqa


GRADIENT = [
    "\033[38;5;46m",   # green
    "\033[38;5;83m",
    "\033[38;5;120m",
    "\033[38;5;157m",
    "\033[38;5;51m",
    "\033[38;5;45m",
    "\033[38;5;39m",
    "\033[38;5;33m",
    "\033[38;5;27m",
    "\033[38;5;21m",
]
RESET = Style.RESET_ALL
DIM = Style.DIM
BOLD = Style.BRIGHT

C_OK = Fore.GREEN + BOLD
C_WARN = Fore.YELLOW + BOLD
C_BAD = Fore.RED + BOLD
C_INFO = Fore.CYAN
C_MUTE = Fore.WHITE + DIM
C_ACC = "\033[38;5;213m" + BOLD  # pink accent
C_GOLD = "\033[38;5;220m" + BOLD


def gradient_line(text: str) -> str:
    out = []
    n = max(len(GRADIENT) - 1, 1)
    for i, ch in enumerate(text):
        color = GRADIENT[int((i / max(len(text) - 1, 1)) * n)]
        out.append(color + ch)
    return "".join(out) + RESET


def supports_unicode() -> bool:
    enc = (sys.stdout.encoding or "").lower()
    return "utf" in enc


UNICODE_OK = supports_unicode()

BOX = {
    "tl": "╔" if UNICODE_OK else "+",
    "tr": "╗" if UNICODE_OK else "+",
    "bl": "╚" if UNICODE_OK else "+",
    "br": "╝" if UNICODE_OK else "+",
    "h": "═" if UNICODE_OK else "-",
    "v": "║" if UNICODE_OK else "|",
    "lt": "╠" if UNICODE_OK else "+",
    "rt": "╣" if UNICODE_OK else "+",
    "arrow": "➤" if UNICODE_OK else ">",
    "bullet": "●" if UNICODE_OK else "*",
    "check": "✔" if UNICODE_OK else "OK",
    "cross": "✘" if UNICODE_OK else "X",
    "warn": "⚠" if UNICODE_OK else "!",
    "spark": "✦" if UNICODE_OK else "*",
    "shield": "🛡" if UNICODE_OK else "[#]",
    "lock": "🔒" if UNICODE_OK else "[L]",
}

BANNER_ART = r"""
██╗  ██╗███████╗ █████╗ ██████╗ ███████╗██████╗ ██╗  ██╗
██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗╚██╗██╔╝
███████║█████╗  ███████║██║  ██║█████╗  ██████╔╝ ╚███╔╝
██╔══██║██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗ ██╔██╗
██║  ██║███████╗██║  ██║██████╔╝███████╗██║  ██║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
""".rstrip("\n")

BANNER_ART_ASCII = r"""
 _  _  ____   __    ___  ____  ____  _  _
/ )( \(  __) / _\  / __)(  __)(  _ \( \/ )
) __ ( ) _) /    \( (__  ) _)  )   / )  (
\_)(_/(____)\_/\_/ \___)(____)(__\_)(_/\_)
""".rstrip("\n")

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


def render_banner():
    art = BANNER_ART if UNICODE_OK else BANNER_ART_ASCII
    width = max(len(line) for line in art.splitlines()) + 4

    print()
    for line in art.splitlines():
        print(gradient_line(line))

    tagline = f"{BOX['spark']} HTTP Security Header Analyzer & Grader {BOX['spark']}"
    print()
    print(C_ACC + tagline.center(width) + RESET)
    sub = f"v{VERSION} · One passive request. No exploitation. Posture, not proof."
    print(C_MUTE + sub.center(width) + RESET)
    print()

    info_box(
        [
            f"{BOX['bullet']} Author   : {AUTHOR}  ({ORG} — Founder & CEO)",
            f"{BOX['bullet']} Website  : {SITE}",
            f"{BOX['bullet']} Portfolio: {PORTFOLIO}",
        ],
        title="ABOUT",
        color=Fore.MAGENTA,
    )


def info_box(lines: List[str], title: str = "", color: str = Fore.CYAN, width: Optional[int] = None):
    content_width = width or (max((len(strip_ansi(l)) for l in lines), default=20) + 4)
    top = f"{color}{BOX['tl']}{BOX['h'] * content_width}{BOX['tr']}{RESET}"
    bot = f"{color}{BOX['bl']}{BOX['h'] * content_width}{BOX['br']}{RESET}"
    print(top)
    if title:
        pad = content_width - len(title) - 2
        left = pad // 2
        right = pad - left
        print(f"{color}{BOX['v']}{RESET} {' ' * left}{BOLD}{title}{RESET}{' ' * right} {color}{BOX['v']}{RESET}")
        print(f"{color}{BOX['lt']}{BOX['h'] * content_width}{BOX['rt']}{RESET}")
    for line in lines:
        pad = max(content_width - len(strip_ansi(line)) - 1, 0)
        print(f"{color}{BOX['v']}{RESET} {Fore.WHITE}{line}{RESET}{' ' * pad}{color}{BOX['v']}{RESET}")
    print(bot)


def section_header(title: str, color: str = Fore.CYAN, icon: str = None):
    icon = icon or BOX["arrow"]
    print()
    print(color + BOLD + f"{BOX['h'] * 3} {icon} {title} " + BOX['h'] * max(0, 50 - len(title)) + RESET)


def hr(color=C_MUTE, width=62):
    print(color + BOX["h"] * width + RESET)


def grade_color(grade: str) -> str:
    return {
        "A+": C_OK, "A": C_OK,
        "B": C_INFO,
        "C": C_WARN,
        "D": C_WARN,
        "F": C_BAD,
    }.get(grade, C_MUTE)


def grade_bar(score: int, width: int = 30) -> str:
    filled = int(width * score / 100)
    bar_char = "█" if UNICODE_OK else "#"
    empty_char = "░" if UNICODE_OK else "-"
    color = C_OK if score >= 80 else C_INFO if score >= 60 else C_WARN if score >= 40 else C_BAD
    return f"{color}[{bar_char * filled}{empty_char * (width - filled)}]{RESET} {color}{score:>3}/100{RESET}"


@dataclass
class HeaderCheck:
    name: str
    present: bool
    value: Optional[str] = None
    grade_points: int = 0
    max_points: int = 0
    notes: List[str] = field(default_factory=list)


SECURITY_HEADERS_MAX_POINTS = {
    "Content-Security-Policy": 20,
    "Strict-Transport-Security": 15,
    "X-Frame-Options": 10,
    "X-Content-Type-Options": 10,
    "Referrer-Policy": 10,
    "Permissions-Policy": 10,
    "Cross-Origin-Opener-Policy": 5,
    "Cross-Origin-Resource-Policy": 5,
    "Cross-Origin-Embedder-Policy": 5,
}
COOKIE_MAX_POINTS = 10
DISCLOSURE_MAX_POINTS = 5

TOTAL_MAX_POINTS = sum(SECURITY_HEADERS_MAX_POINTS.values()) + COOKIE_MAX_POINTS + DISCLOSURE_MAX_POINTS  # 100

INFO_DISCLOSURE_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Runtime",
]

UNSAFE_CSP_TOKENS = ["unsafe-inline", "unsafe-eval", "data:", "*"]


def check_csp(value: Optional[str]) -> HeaderCheck:
    max_pts = SECURITY_HEADERS_MAX_POINTS["Content-Security-Policy"]
    if not value:
        return HeaderCheck("Content-Security-Policy", False, None, 0, max_pts,
                            ["No CSP — browser applies no restrictions on script/style/frame sources."])
    notes = []
    pts = max_pts
    lowered = value.lower()
    if "unsafe-inline" in lowered:
        notes.append("Contains 'unsafe-inline' — inline scripts/styles are not blocked by CSP.")
        pts -= 6
    if "unsafe-eval" in lowered:
        notes.append("Contains 'unsafe-eval' — eval()-based script injection is not blocked.")
        pts -= 6
    if "default-src *" in lowered or "script-src *" in lowered:
        notes.append("Wildcard '*' source allows scripts/content from any origin.")
        pts -= 4
    if "frame-ancestors" not in lowered:
        notes.append("No 'frame-ancestors' directive — consider adding clickjacking protection here too.")
        pts -= 2
    pts = max(pts, 2)  # presence alone is still worth something
    if not notes:
        notes.append("Looks reasonably strict.")
    return HeaderCheck("Content-Security-Policy", True, value, pts, max_pts, notes)


def check_hsts(value: Optional[str]) -> HeaderCheck:
    max_pts = SECURITY_HEADERS_MAX_POINTS["Strict-Transport-Security"]
    if not value:
        return HeaderCheck("Strict-Transport-Security", False, None, 0, max_pts,
                            ["Site does not instruct browsers to enforce HTTPS via HSTS."])
    notes = []
    pts = max_pts
    match = re.search(r"max-age=(\d+)", value, re.IGNORECASE)
    max_age = int(match.group(1)) if match else 0
    if max_age < 15552000:  # 180 days
        notes.append(f"max-age={max_age} is below the recommended 180 days (15552000s).")
        pts -= 6
    if "includesubdomains" not in value.lower():
        notes.append("Missing 'includeSubDomains' — subdomains are not covered.")
        pts -= 3
    if "preload" not in value.lower():
        notes.append("Missing 'preload' — not eligible for browser HSTS preload lists.")
        pts -= 2
    pts = max(pts, 3)
    if not notes:
        notes.append("Strong HSTS configuration.")
    return HeaderCheck("Strict-Transport-Security", True, value, pts, max_pts, notes)


def check_simple(name: str, value: Optional[str], good_values: Optional[List[str]] = None) -> HeaderCheck:
    max_pts = SECURITY_HEADERS_MAX_POINTS[name]
    if not value:
        return HeaderCheck(name, False, None, 0, max_pts, ["Header not sent."])
    notes = []
    pts = max_pts
    if good_values and value.strip().lower() not in [g.lower() for g in good_values]:
        notes.append(f"Present but value '{value}' is non-standard; expected one of {good_values}.")
        pts = int(max_pts * 0.6)
    else:
        notes.append("Present with a recommended value.")
    return HeaderCheck(name, True, value, pts, max_pts, notes)


def check_referrer_policy(value: Optional[str]) -> HeaderCheck:
    max_pts = SECURITY_HEADERS_MAX_POINTS["Referrer-Policy"]
    strict_values = {
        "no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin",
    }
    if not value:
        return HeaderCheck("Referrer-Policy", False, None, 0, max_pts, ["Header not sent."])
    notes = []
    if value.strip().lower() in strict_values:
        pts = max_pts
        notes.append("Uses a privacy-conscious policy.")
    else:
        pts = int(max_pts * 0.5)
        notes.append(f"Value '{value}' leaks more referrer data than the strict presets.")
    return HeaderCheck("Referrer-Policy", True, value, pts, max_pts, notes)


def check_permissions_policy(value: Optional[str]) -> HeaderCheck:
    max_pts = SECURITY_HEADERS_MAX_POINTS["Permissions-Policy"]
    if not value:
        return HeaderCheck("Permissions-Policy", False, None, 0, max_pts,
                            ["No explicit control over browser features (camera, mic, geolocation, etc.)."])
    return HeaderCheck("Permissions-Policy", True, value, max_pts, max_pts,
                        ["Present — browser feature access is explicitly scoped."])


def check_cookies(set_cookie_headers: List[str]) -> HeaderCheck:
    if not set_cookie_headers:
        return HeaderCheck("Cookie flags", False, None, COOKIE_MAX_POINTS, COOKIE_MAX_POINTS,
                            ["No cookies set on this response — nothing to flag."])
    total = len(set_cookie_headers)
    secure = sum(1 for c in set_cookie_headers if "secure" in c.lower())
    httponly = sum(1 for c in set_cookie_headers if "httponly" in c.lower())
    samesite = sum(1 for c in set_cookie_headers if "samesite" in c.lower())

    notes = [f"{total} cookie(s) observed."]
    ratio = (secure + httponly + samesite) / (total * 3)
    pts = int(COOKIE_MAX_POINTS * ratio)

    if secure < total:
        notes.append(f"{total - secure} cookie(s) missing the 'Secure' flag.")
    if httponly < total:
        notes.append(f"{total - httponly} cookie(s) missing the 'HttpOnly' flag.")
    if samesite < total:
        notes.append(f"{total - samesite} cookie(s) missing a 'SameSite' attribute.")
    if secure == total and httponly == total and samesite == total:
        notes = [f"{total} cookie(s) observed, all correctly flagged (Secure + HttpOnly + SameSite)."]

    return HeaderCheck("Cookie flags", True, f"{total} cookie(s)", pts, COOKIE_MAX_POINTS, notes)


def check_disclosure(headers: Dict[str, str]) -> HeaderCheck:
    leaking = [h for h in INFO_DISCLOSURE_HEADERS if headers.get(h)]
    if not leaking:
        return HeaderCheck("Information disclosure", False, None, DISCLOSURE_MAX_POINTS,
                            DISCLOSURE_MAX_POINTS, ["No common stack-fingerprinting headers observed."])
    details = [f"{h}: {headers.get(h)}" for h in leaking]
    penalty = min(len(leaking) * 2, DISCLOSURE_MAX_POINTS)
    pts = max(DISCLOSURE_MAX_POINTS - penalty, 0)
    return HeaderCheck("Information disclosure", True, ", ".join(details), pts, DISCLOSURE_MAX_POINTS,
                        [f"Leaking: {d}" for d in details])


def grade_from_score(score: int) -> str:
    if score >= 95:
        return "A+"
    if score >= 85:
        return "A"
    if score >= 70:
        return "B"
    if score >= 55:
        return "C"
    if score >= 40:
        return "D"
    return "F"



@dataclass
class ScanResult:
    url: str
    final_url: Optional[str] = None
    status_code: Optional[int] = None
    response_time_ms: Optional[float] = None
    checks: List[HeaderCheck] = field(default_factory=list)
    score: int = 0
    grade: str = "F"
    raw_headers: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None


def scan_target(
    url: str,
    timeout: int,
    headers: dict,
    cookies: dict,
    verify_ssl: bool,
    follow_redirects: bool,
) -> ScanResult:
    result = ScanResult(url=url)
    try:
        start = time.perf_counter()
        resp = requests.get(
            url, headers=headers, cookies=cookies, timeout=timeout,
            verify=verify_ssl, allow_redirects=follow_redirects,
        )
        elapsed = (time.perf_counter() - start) * 1000

        result.status_code = resp.status_code
        result.final_url = resp.url
        result.response_time_ms = round(elapsed, 1)
        result.raw_headers = dict(resp.headers)

        h = resp.headers
        checks: List[HeaderCheck] = [
            check_csp(h.get("Content-Security-Policy")),
            check_hsts(h.get("Strict-Transport-Security")),
            check_simple("X-Frame-Options", h.get("X-Frame-Options"), ["DENY", "SAMEORIGIN"]),
            check_simple("X-Content-Type-Options", h.get("X-Content-Type-Options"), ["nosniff"]),
            check_referrer_policy(h.get("Referrer-Policy")),
            check_permissions_policy(h.get("Permissions-Policy")),
            check_simple("Cross-Origin-Opener-Policy", h.get("Cross-Origin-Opener-Policy"),
                         ["same-origin", "same-origin-allow-popups"]),
            check_simple("Cross-Origin-Resource-Policy", h.get("Cross-Origin-Resource-Policy"),
                         ["same-origin", "same-site"]),
            check_simple("Cross-Origin-Embedder-Policy", h.get("Cross-Origin-Embedder-Policy"),
                         ["require-corp", "credentialless"]),
        ]

        set_cookie_headers = []
        if "Set-Cookie" in resp.raw.headers:
            set_cookie_headers = resp.raw.headers.get_all("Set-Cookie") or []
        elif h.get("Set-Cookie"):
            set_cookie_headers = [h.get("Set-Cookie")]
        checks.append(check_cookies(set_cookie_headers))
        checks.append(check_disclosure(dict(h)))

        result.checks = checks
        total_pts = sum(c.grade_points for c in checks)
        result.score = min(int(total_pts), 100)
        result.grade = grade_from_score(result.score)

    except requests.exceptions.Timeout:
        result.error = "Request timed out"
    except requests.exceptions.SSLError as e:
        result.error = f"SSL error: {e}"
    except requests.exceptions.ConnectionError:
        result.error = "Connection failed"
    except Exception as e:  # noqa
        result.error = str(e)

    return result


def print_result(result: ScanResult, verbose: bool):
    if result.error:
        print(f"{C_BAD}[{BOX['cross']} ERROR ]{RESET} {Fore.WHITE}{result.url}{RESET}")
        print(f"          {C_BAD}└─ {result.error}{RESET}")
        return

    gcolor = grade_color(result.grade)
    print(f"{gcolor}[ GRADE {result.grade:<2} ]{RESET} {Fore.WHITE}{result.url}{RESET} "
          f"{C_MUTE}(status {result.status_code}, {result.response_time_ms} ms){RESET}")
    print(f"          {grade_bar(result.score)}")

    for check in result.checks:
        icon = BOX["check"] if check.present and check.grade_points >= check.max_points else \
            (BOX["warn"] if check.present else BOX["cross"])
        ccolor = C_OK if check.present and check.grade_points >= check.max_points else \
            (C_WARN if check.present else C_BAD)
        print(f"          {ccolor}{icon} {check.name:<28}{RESET} "
              f"{C_MUTE}{check.grade_points}/{check.max_points} pts{RESET}")
        if verbose:
            for note in check.notes:
                print(f"              {C_MUTE}› {note}{RESET}")
    print()


def print_summary(results: List[ScanResult]):
    scanned = [r for r in results if not r.error]
    errored = [r for r in results if r.error]

    section_header("SCAN SUMMARY", Fore.MAGENTA, BOX["spark"])
    if scanned:
        avg = sum(r.score for r in scanned) / len(scanned)
        best = max(scanned, key=lambda r: r.score)
        worst = min(scanned, key=lambda r: r.score)
        print(f"  {BOLD}Average score:{RESET} {grade_bar(int(avg))}")
        print(f"  {C_OK}Best : {best.url} → {best.grade} ({best.score}/100){RESET}")
        print(f"  {C_BAD}Worst: {worst.url} → {worst.grade} ({worst.score}/100){RESET}")

        grade_counts = {}
        for r in scanned:
            grade_counts[r.grade] = grade_counts.get(r.grade, 0) + 1
        hr(Fore.MAGENTA)
        for g in ["A+", "A", "B", "C", "D", "F"]:
            if g in grade_counts:
                gcolor = grade_color(g)
                bar = (BOX["bullet"] * grade_counts[g]) if UNICODE_OK else ("*" * grade_counts[g])
                print(f"  {gcolor}{g:<3}{RESET} : {gcolor}{grade_counts[g]:>3}{RESET}  {gcolor}{bar}{RESET}")

    if errored:
        print(f"\n  {C_MUTE}{len(errored)} target(s) could not be reached.{RESET}")

    hr(Fore.MAGENTA)
    print(f"  {BOLD}Total targets scanned:{RESET} {len(results)}")
    print()


def save_json(results: List[ScanResult], path: str):
    data = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "author": AUTHOR,
        "organization": ORG,
        "results": [
            {
                "url": r.url,
                "final_url": r.final_url,
                "status_code": r.status_code,
                "response_time_ms": r.response_time_ms,
                "score": r.score,
                "grade": r.grade,
                "error": r.error,
                "checks": [asdict(c) for c in r.checks],
            }
            for r in results
        ],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def save_csv(results: List[ScanResult], path: str):
    fields = ["url", "final_url", "status_code", "response_time_ms", "score", "grade", "error"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "url": r.url, "final_url": r.final_url, "status_code": r.status_code,
                "response_time_ms": r.response_time_ms, "score": r.score,
                "grade": r.grade, "error": r.error,
            })


def parse_header_list(items: Optional[List[str]]) -> dict:
    headers = {}
    if not items:
        return headers
    for item in items:
        if ":" in item:
            k, v = item.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def parse_cookie_string(cookie_str: Optional[str]) -> dict:
    cookies = {}
    if not cookie_str:
        return cookies
    for part in cookie_str.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


def load_targets(args) -> List[str]:
    targets = []
    if args.url:
        targets.append(args.url)
    if args.list:
        if not os.path.isfile(args.list):
            print(C_BAD + f"[!] File not found: {args.list}" + RESET)
            sys.exit(1)
        with open(args.list, "r", encoding="utf-8") as f:
            targets.extend(line.strip() for line in f if line.strip() and not line.startswith("#"))
    return targets


def confirm_authorization(skip: bool) -> bool:
    if skip:
        return True
    info_box(
        [
            f"{BOX['warn']} HeaderX only sends a normal, passive GET request per target.",
            f"{BOX['warn']} Still — only assess targets you OWN or are AUTHORIZED to test.",
        ],
        title="AUTHORIZATION",
        color=Fore.YELLOW,
    )
    try:
        answer = input(f"{BOLD}Type 'yes' to confirm you are authorized: {RESET}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer == "yes"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="headerx",
        description=f"{TOOL_NAME} — HTTP Security Header Analyzer & Grader by {AUTHOR} ({ORG})",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  headerx.py -u https://example.com\n"
            "  headerx.py -l targets.txt --threads 10 -o report.json\n"
            "  headerx.py -u https://example.com -v --yes\n"
        ),
    )
    parser.add_argument("-u", "--url", help="Target URL to analyze")
    parser.add_argument("-l", "--list", help="File containing a list of target URLs (one per line)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--threads", type=int, default=5, help="Concurrent worker threads (default: 5)")
    parser.add_argument("-H", "--header", action="append", help="Custom header 'Key: Value' (repeatable)")
    parser.add_argument("-b", "--cookies", help="Cookie string 'a=1; b=2'")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("--no-redirects", action="store_true", help="Do not follow HTTP redirects")
    parser.add_argument("-o", "--output", help="Save results to file (.json or .csv, inferred from extension)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed notes for every header check")
    parser.add_argument("--yes", action="store_true", help="Skip the authorization confirmation prompt")
    parser.add_argument("--no-banner", action="store_true", help="Suppress the ASCII banner")
    parser.add_argument("--version", action="store_true", help="Show version information and exit")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.version:
        print(f"{TOOL_NAME} v{VERSION} — by {AUTHOR} ({ORG})")
        return

    if not args.no_banner:
        render_banner()

    targets = load_targets(args)
    if not targets:
        parser.print_help()
        print(C_BAD + "\n[!] No target provided. Use -u/--url or -l/--list.\n" + RESET)
        sys.exit(1)

    if not confirm_authorization(args.yes):
        print(C_BAD + "\n[!] Authorization not confirmed. Aborting.\n" + RESET)
        sys.exit(1)

    headers = parse_header_list(args.header)
    cookies = parse_cookie_string(args.cookies)
    headers.setdefault("User-Agent", f"Mozilla/5.0 ({TOOL_NAME}/{VERSION}; +{SITE})")

    section_header(f"ANALYZING {len(targets)} TARGET(S)", Fore.CYAN, BOX["arrow"])
    print(f"{C_MUTE}  threads={args.threads}  timeout={args.timeout}s  "
          f"redirects={'off' if args.no_redirects else 'on'}{RESET}\n")

    results: List[ScanResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {
            pool.submit(
                scan_target, url, args.timeout, headers, cookies,
                not args.no_verify_ssl, not args.no_redirects,
            ): url
            for url in targets
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
            print()
            print_result(result, args.verbose)

    print_summary(results)

    if args.output:
        ext = os.path.splitext(args.output)[1].lower()
        if ext == ".csv":
            save_csv(results, args.output)
        else:
            save_json(results, args.output)
        print(C_OK + f"{BOX['check']} Report saved to: {args.output}\n" + RESET)

    print(C_MUTE + f"{BOX['h']*62}" + RESET)
    print(C_ACC + f"  {TOOL_NAME} · Made by {AUTHOR} — Founder & CEO of {ORG}" + RESET)
    print(C_MUTE + f"  {SITE}  |  {PORTFOLIO}" + RESET)
    print(C_MUTE + f"{BOX['h']*62}\n" + RESET)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(C_WARN + "\n\n[!] Interrupted by user. Exiting.\n" + RESET)
        sys.exit(130)
