<div align="center">

```
 ██╗  ██╗███████╗ █████╗ ██████╗ ███████╗██████╗ ██╗  ██╗
 ██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗╚██╗██╔╝
███████║█████╗  ███████║██║  ██║█████╗  ██████╔╝ ╚███╔╝
██╔══██║██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗ ██╔██╗
 ██║  ██║███████╗██║  ██║██████╔╝███████╗██║  ██║██╔╝ ██╗
 ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
```

### ✦ HTTP Security Header Analyzer & Grader ✦

**One passive request. No exploitation. Posture, not proof.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Made by Mindless](https://img.shields.io/badge/Made%20by-Mindless-ff69b4.svg)](https://linxploit.com/founder)
[![Linxploit](https://img.shields.io/badge/Linxploit-linxploit.com-black.svg)](https://linxploit.com)

**Made by [Mindless](https://linxploit.com/founder) — Founder & CEO of [Linxploit](https://linxploit.com)**

</div>

---

## 🧠 What is HeaderX?

**HeaderX** sends a single, normal HTTP GET request to a target — the same request any browser makes — and grades the security posture of the response headers it gets back.

It checks for the presence *and quality* of modern browser security controls (CSP, HSTS, frame protection, cookie flags, and more), flags server-fingerprinting headers that leak stack info, and rolls everything up into a clear **0–100 score and A+ → F letter grade** per target.

Like every tool in the Linxploit X-Suite, HeaderX is upfront about its limits: a low grade means there's hardening work worth doing, not a confirmed, exploitable vulnerability.

---

## ✨ Features

- 🎨 **Ultra-clean ASCII UI** — gradient banner, boxed panels, per-check pass/warn/fail icons, and a colorized score bar, with zero heavy UI dependencies.
- 🧮 **Weighted 0–100 grading engine** across 9 security headers, cookie flags, and information-disclosure headers — not just "present / missing".
- 🧩 **Quality-aware checks**, not just presence checks:
  - **CSP** — flags `unsafe-inline`, `unsafe-eval`, wildcard sources, and missing `frame-ancestors`.
  - **HSTS** — checks `max-age` against the 180-day recommendation, `includeSubDomains`, and `preload`.
  - **Referrer-Policy** — rewards privacy-conscious values, docks points for leaky ones.
  - **X-Frame-Options / X-Content-Type-Options / COOP / CORP / COEP** — validates against recommended values.
  - **Permissions-Policy** — checks that browser feature access is explicitly scoped.
- 🍪 **Cookie flag audit** — checks every `Set-Cookie` header for `Secure`, `HttpOnly`, and `SameSite`.
- 🕵️ **Information-disclosure detection** — flags `Server`, `X-Powered-By`, `X-AspNet-Version`, and similar stack-fingerprinting headers.
- ⚡ **Concurrent multi-target scanning** — a single URL or an entire list, in parallel, with configurable thread count.
- 🔀 **Redirect handling** — follows redirects by default (toggle with `--no-redirects`) and reports the final URL analyzed.
- 🔐 **Custom headers, cookies & SSL control** — analyze authenticated pages the same way a logged-in browser would.
- 📊 **Exportable reports** — full **JSON** (every check + notes) or summary **CSV**.
- 🛡️ **Authorization gate** — confirms you're allowed to assess a target before making a request (skippable with `--yes` for your own pipelines).

---

## 📸 Preview

```
         ✦ HTTP Security Header Analyzer & Grader ✦
v2.0.0 · One passive request. No exploitation. Posture, not proof.

═══ ➤ ANALYZING 2 TARGET(S) ═════════════════════════════
  threads=5  timeout=10s  redirects=on

[ GRADE A+ ] https://secure.example.com (status 200, 84.1 ms)
          [██████████████████████████████] 100/100
          ✔ Content-Security-Policy      20/20 pts
          ✔ Strict-Transport-Security    15/15 pts
          ✔ X-Frame-Options              10/10 pts
          ✔ Cookie flags                 10/10 pts
          ✔ Information disclosure       5/5 pts

[ GRADE F  ] https://legacy.example.com (status 200, 61.7 ms)
          [░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░]   1/100
          ✘ Content-Security-Policy      0/20 pts
          ✘ Strict-Transport-Security    0/15 pts
          ⚠ Cookie flags                 0/10 pts
          ⚠ Information disclosure       1/5 pts

═══ ✦ SCAN SUMMARY ══════════════════════════════════════
  Average score: [███████████████░░░░░░░░░░░░░░░]  50/100
  Best : https://secure.example.com → A+ (100/100)
  Worst: https://legacy.example.com → F (1/100)
```

---

## 📦 Installation

```bash
git clone https://github.com/linxploit/headerx.git
cd headerx
pip install -r requirements.txt
```

Requires **Python 3.8+**.

---

## 🚀 Usage

### Analyze a single site

```bash
python3 headerx.py -u "https://example.com"
```

### Analyze a list of targets

```bash
python3 headerx.py -l examples/targets.txt --threads 10
```

### See the reasoning behind every score

```bash
python3 headerx.py -u "https://example.com" -v
```

### Analyze an authenticated page

```bash
python3 headerx.py -u "https://example.com/dashboard" \
  -H "Authorization: Bearer <token>" \
  -b "session=abc123"
```

### Save a report

```bash
python3 headerx.py -l examples/targets.txt -o report.json
python3 headerx.py -l examples/targets.txt -o report.csv
```

### Skip the authorization prompt (for your own automated pipelines)

```bash
python3 headerx.py -u "https://example.com" --yes
```

### Full option reference

```bash
python3 headerx.py --help
```

| Flag | Description |
|---|---|
| `-u`, `--url` | Single target URL |
| `-l`, `--list` | File with one target URL per line |
| `-t`, `--timeout` | Request timeout in seconds (default: `10`) |
| `--threads` | Concurrent worker threads (default: `5`) |
| `-H`, `--header` | Custom header `"Key: Value"`, repeatable |
| `-b`, `--cookies` | Cookie string `"a=1; b=2"` |
| `--no-verify-ssl` | Disable SSL certificate verification |
| `--no-redirects` | Do not follow HTTP redirects |
| `-o`, `--output` | Save report to `.json` or `.csv` |
| `-v`, `--verbose` | Show detailed notes for every header check |
| `--yes` | Skip the authorization confirmation prompt |
| `--no-banner` | Suppress the ASCII banner |
| `--version` | Print version info and exit |

---

## 🧭 Grading breakdown (100 points total)

| Check | Points | What it looks for |
|---|---|---|
| Content-Security-Policy | 20 | Presence + no `unsafe-inline`/`unsafe-eval`/wildcards + `frame-ancestors` |
| Strict-Transport-Security | 15 | Presence + `max-age` ≥ 180 days + `includeSubDomains` + `preload` |
| X-Frame-Options | 10 | Presence + value is `DENY` or `SAMEORIGIN` |
| X-Content-Type-Options | 10 | Presence + value is `nosniff` |
| Referrer-Policy | 10 | Presence + a privacy-conscious value |
| Permissions-Policy | 10 | Presence (feature access explicitly scoped) |
| Cross-Origin-Opener-Policy | 5 | Presence + recommended value |
| Cross-Origin-Resource-Policy | 5 | Presence + recommended value |
| Cross-Origin-Embedder-Policy | 5 | Presence + recommended value |
| Cookie flags | 10 | `Secure` + `HttpOnly` + `SameSite` on every `Set-Cookie` |
| Information disclosure | 5 | No `Server` / `X-Powered-By` / similar version-leaking headers |

**Grade scale:** A+ (95–100) · A (85–94) · B (70–84) · C (55–69) · D (40–54) · F (below 40)

> ⚠️ **A grade reflects header hygiene, not a full security assessment.** Missing headers are hardening opportunities to review and prioritize — always validate manually and in context before reporting findings.

---

## ⚖️ Responsible use

HeaderX performs a single, ordinary GET request per target — nothing more than a browser does when loading a page. There is no attack traffic, no fuzzing, and no state-changing request. Still:

- Only run HeaderX against targets you **own** or have **explicit permission** to assess.
- HeaderX will ask you to confirm authorization before scanning, every time, unless you pass `--yes`.
- You are solely responsible for how you use this tool and for complying with all applicable laws and the terms of any authorization you've been granted.

---

## 🛠️ Project structure

```
headerx/
├── headerx.py            # Main executable — the tool itself
├── requirements.txt        # Python dependencies
├── examples/
│   └── targets.txt          # Example target list for -l/--list
├── tests/
│   └── test_headerx.py      # Unit tests for the grading engine
├── LICENSE                 # MIT License
└── README.md                # You are here
```

---

## 🤝 Contributing

Issues and pull requests are welcome — new header checks, better default-value heuristics, and additional export formats are all great contributions. Please keep additions passive and read-only, in line with HeaderX's design.

---

## 📜 License

Released under the [MIT License](LICENSE).

---

<div align="center">

### Made by **Mindless**
**Founder & CEO of [Linxploit](https://linxploit.com)**

🌐 [linxploit.com](https://linxploit.com) &nbsp;·&nbsp; 👤 [linxploit.com/founder](https://linxploit.com/founder)

</div>
