# SERAHKAN-CLI

> **AI-powered Nuclei orchestration engine** — a lightweight, fast Go CLI wrapper for modern web vulnerability assessment. It drives [ProjectDiscovery Nuclei](https://github.com/projectdiscovery/nuclei), adds stealth/WAF-aware crawling, supports authenticated scanning, and pipes results into a local LLM (Ollama / LM Studio) for instant defensive analysis and remediation playbooks.

![License](https://img.shields.io/badge/license-MIT-green)
![Go](https://img.shields.io/badge/go-1.21%2B-00ADD8)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

```
   _____ ______ _____          _    _  _    _          _ _
  / ____|  ____|  __ \   /\   | |  | || |  / \   /\   | | |
 | (___ | |__  | |__) | /  \  | |__| || | /  /  /  \  | | |
  \___ \|  __| |  _  / / /\ \ |  __  || |/  /  / /\ \ | | |
  ____) | |____| | \ \/ ____ \| |  | || |\  \ / ____ \| | |
 |_____/|______|_|  \_\_/    \_\_|  |_||_| \_/_/    \_\_|_|
  SERAHKAN CLI [vdev]
  AI-powered web security scanner
```

---

## Demo

### Laporan AI Defensive Analysis

Analisis otomatis dengan AI yang menghasilkan laporan terstruktur berisi root cause analysis, vulnerability audit, dan remediation playbook:

![Laporan AI](aset-gambar/hasil%20laporan%20dengan%20ai.png)

### Output JSON Mentah (--skip-ai)

Ketika AI tidak aktif, serahkan CLI menampilkan findings dalam format JSON mentah yang siap di-parse atau dipipeline:

![Output JSON](aset-gambar/hasil%20laporan%20output%20json.png)

---

## Why serahkan-cli?

Nuclei is powerful but raw. `serahkan-cli` wraps it so you can:

- **Scan in one command** with opinionated, battle-tested profiles (`fast` → `brutal-aggressive`, plus `web-full`, `web-auth`, and `stealth`).
- **Stay under the radar** — the `stealth` profile uses a low rate-limit and concurrency with behavioral jitter and automatic HTML export, ideal for anti-blocking low-and-slow scans.
- **Route through a proxy** — a single `--proxy` flag forwards all traffic (Nuclei + Katana crawler) through HTTP/SOCKS5.
- **Authenticate before scanning** — submit a login form automatically and scan the authenticated surface, not just the login page.
- **Bypass / tolerate WAFs** — built-in stealth headers, randomized user agents, behavioral rate-limit jitter, and a crawler pre-check that warns instead of aborting on CDN headers.
- **Get a real remediation report** — findings are deduplicated and sent to your local LLM, which returns a structured ASCII defensive analysis (root cause + PoC + hardening playbook).
- **Re-render anytime** — the `report` command turns a saved JSON scan into a polished HTML/Markdown report; `--export sarif` feeds dashboards.
- **Stay machine-readable** — full `--output json` pipeline plus SARIF export for CI and security tooling.

---

## Table of Contents

- [Demo](#demo)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
  - [`scan`](#scan) · [`report`](#report) · [`config`](#config) · [`doctor`](#doctor) · [`version`](#version)
- [Scan Profiles](#scan-profiles)
- [Focus Presets](#focus-presets)
- [Anti-Blocking & Stealth Scanning](#anti-blocking--stealth-scanning)
- [Authenticated Scanning](#authenticated-scanning)
- [WAF & CDN Handling](#waf--cdn-handling)
- [Crawling](#crawling)
- [AI Analysis](#ai-analysis)
- [Skip AI Mode](#skip-ai-mode)
- [Reporting & Export](#reporting--export)
- [URL Sanitization](#url-sanitization)
- [Output Schemas](#output-schemas)
- [Full Flag Reference](#full-flag-reference)
- [Configuration & Precedence](#configuration--precedence)
- [Cookbook](#cookbook)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Installation

Requires **Go 1.21+** and a local **Nuclei** binary. `serahkan-cli` looks for `nuclei.exe` in the current/executable directory first, then falls back to `PATH`.

### From source (Linux / macOS)

```bash
git clone https://github.com/Zyrexnn/serahkan-cli.git
cd serahkan-cli
go build -o serahkan .
```

### Windows

Build the binary, then make sure Nuclei is available:

```powershell
go build -o serahkan.exe .
```

If you don't have Nuclei yet, use the bundled, Defender-aware installer (run **as Administrator** — it whitelists the folder so Defender doesn't quarantine Nuclei as a HackTool/PUA, then downloads the official Windows/amd64 binary):

```powershell
powershell -ExecutionPolicy Bypass -File install-nuclei.ps1
```

Prefer a manual install? Either drop `nuclei.exe` next to `serahkan.exe`, or install via Go:

```powershell
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

> **Windows Defender note:** Nuclei is frequently flagged as *HackTool/PUA* and silently removed. If `serahkan scan` reports `nuclei is not installed`, whitelist the folder:
> ```powershell
> Add-MpPreference -ExclusionPath "C:\path\to\serahkan-cli"
> ```

### Verify

```bash
serahkan doctor
```

---

## Quick Start

```bash
# 1. Point it at your local LLM once (persisted to config.json)
serahkan config set ai.endpoint http://127.0.0.1:1234/v1/chat/completions
serahkan config set ai.model qwen2.5-coder-1.5b-instruct

# 2. Anti-blocking scan with automatic HTML report — no AI needed
serahkan scan -t https://example.com --profile stealth

# 3. Authenticated app scan (AI analysis runs automatically if configured)
serahkan scan -t https://example.com/login --profile web-auth --login-data "username=admin&password=admin"

# 4. Raw findings fast, no AI
serahkan scan -t https://example.com --profile benchmark-web --skip-ai
```

---

## Commands

### `scan`

The primary command. Runs Nuclei against a target (or a file of targets), applies the selected profile, filters by severity, and optionally sends findings to a local LLM.

Without `--crawl`, the scanner performs a direct single-target scan with stealth headers. With `--crawl`, a Katana-powered discovery phase runs first and discovered paths (including `<form action>` endpoints) are fed into Nuclei.

```bash
serahkan scan -t https://example.com/login --profile web-auth
serahkan scan -T targets.txt --profile deep --output json
```

### `report`

Turns a previously saved JSON scan (`serahkan scan ... --output json`) into a static, shareable report — **without re-running the scan**.

| Flag | Default | Description |
|---|---|---|
| `--input`, `-i` | *(required)* | Path to the JSON scan report. |
| `--format`, `-f` | `html` | `html` or `markdown`. |
| `--output`, `-o` | auto | Output file path (auto-named if omitted). |

```bash
serahkan report --input report.json --format html --output report.html
serahkan report --input report.json --format markdown
```

### `config`

Persisted CLI configuration. Subcommands: `set`, `show`, `unset`.

```bash
serahkan config set ai.endpoint http://127.0.0.1:1234/v1/chat/completions
serahkan config set ai.model qwen2.5-coder-1.5b-instruct
serahkan config show
serahkan config unset ai.api_key
```

### `doctor`

Checks that `nuclei` is resolvable and the configured AI endpoint is reachable.

```bash
serahkan doctor
```

### `version`

Prints the `serahkan-cli` version, build commit, build date, Go version, OS/arch — **and resolves + displays the installed Nuclei version**.

```bash
serahkan version
```

---

## Scan Profiles

Profiles set the complete Nuclei argument set: timeouts, retries, severity filtering, concurrency, rate limits, protocols, and template inclusion. Selected via `--profile`; defaults to `balanced`.

| Profile | Severity | Timeout | Max Duration | Retries | Rate Limit | Concurrency | OOB | Headless | DAST | Forced Tags | Protocols | AI |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `fast` | high, critical | 8s | 60s | 0 | profile | profile | off | off | off | — | http | skipped |
| `balanced` | medium, high, critical | 10s | 120s | 0 | profile | profile | off | off | off | — | http | enabled |
| `deep` | medium, high, critical | 30s | 300s | 2 | profile | profile | on | off | off | — | http | enabled |
| `web-full` | info → critical | 30s | 420s | 1 | profile | profile | on | on | on | fuzz | http, headless, js | enabled |
| `web-auth` | info → critical | 30s | 420s | 2 | profile | profile | on | on | on | — | http, headless, js | enabled |
| `benchmark-web` | info → critical | 25s | 300s | 3 | profile | profile | off | off | off | — | http | skipped |
| `stealth` | medium, high, critical | 20s | 180s | 1 | 5 rps | 10 | off | off | off | — | http | enabled (auto HTML export) |
| `brutal-aggressive` | info → critical | 45s | 600s | 3 | 800 | 300 | on | on | on | cve, sqli, xss, lfi, rce, misconfig, exposure | http, headless, js, dns | skipped |

> `"info → critical"` = `info,low,medium,high,critical`. Rate-limit / concurrency shown as `profile` inherit from config or code defaults (overridable with `--rate-limit` / `--concurrency`).

### Profile notes

- **`fast`** — quick go/no-go. High/critical only, no AI, HTTP templates only.
- **`balanced`** — default daily driver. AI on, OOB off.
- **`deep`** — longer timeouts, OOB interaction, 2 retries for flaky endpoints.
- **`web-full`** — full web coverage: headless + DAST/fuzz + OOB + `fuzz` forced tag, raw HTTP capture.
- **`web-auth`** — built for **login-protected apps**. Applies `web-vulns` focus by default and is designed to be paired with `--login-data` / `--cookie` so you scan the authenticated surface. AI enabled with a generous 120s timeout.
- **`benchmark-web`** — tuned for public vuln demos (DVWA, WebGoat, testphp). Applies the `web-vulns` focus (`xss,sqli,lfi,rfi,ssrf,ssti,redirect`) and uses 3 retries for unstable hosts.
- **`stealth`** — low-and-slow anti-blocking scan: 5 requests/sec, concurrency 10, behavioral jitter, no crawling, and **automatic HTML export** of the report. Pair with `--proxy` and/or `--waf-strict` for maximum discretion.
- **`brutal-aggressive`** — max coverage: 300 concurrency / 800 rate-limit, all severities, broad forced-tag set. Pair with `--skip-ai` for speed.

---

## Focus Presets

`--focus` appends targeted tags/templates on top of the active profile (additive, never removes profile flags).

| Preset | Behavior |
|---|---|
| `exposures` | Appends `-t http/exposures`. |
| `web-vulns` | Appends `-tags xss,sqli,lfi,rfi,ssrf,ssti,redirect`. |
| `fuzz` | Enables DAST, adds `-itags fuzz`, appends `-tags fuzz`. |
| `misconfig` | Appends `-tags misconfig,exposure,config`. |
| `cves` | Appends `-t http/cves`. |

```bash
serahkan scan -t https://example.com --focus web-vulns
serahkan scan -t https://example.com --focus cves --severity high,critical
```

---

## Anti-Blocking & Stealth Scanning

Getting rate-limited or WAF-blocked? Combine these:

| Technique | How |
|---|---|
| **Slow down** | `--profile stealth` (5 rps / concurrency 10) or `--rate-limit 5 --concurrency 10`. |
| **Rotate identity** | `--proxy http://127.0.0.1:8080` + `--header "User-Agent: ..."`. |
| **Respect WAF** | `--waf-strict` aborts the crawl scan when a real block pattern is detected (avoids IP bans). |
| **Auto report** | `stealth` exports an HTML report automatically; otherwise `--export html`. |

```bash
# Single target, low-and-slow, auto HTML export
serahkan scan -t https://target.com --profile stealth

# Maximum discretion: stealth + proxy + abort on WAF block
serahkan scan -t https://target.com --profile stealth \
  --proxy http://127.0.0.1:8080 --waf-strict \
  --header "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36"
```

---

## Authenticated Scanning

Login-gated apps usually return little on an unauthenticated `/login` request. `serahkan-cli` can authenticate **before** the scan and then scan the authenticated session.

### Options

| Flag | Default | Description |
|---|---|---|
| `--login-url` | same as `--target` | Login form **action** URL. If omitted, the tool GETs the target, finds the `<form action="…">`, and submits there automatically. |
| `--login-data` | — | URL-encoded POST body, e.g. `username=admin&password=admin`. |
| `--login-data-file` | — | Reads the POST body from a file (avoids credentials in shell history). |
| `--login-threshold` | `0` (auto) | HTTP status considered "login success" (e.g. `302`). Auto mode treats `200`/`301`/`302` as success. |

On success, the session cookies are captured and passed to Nuclei via the `Cookie` header, and `auth_mode` becomes `login_form`.

```bash
# Auto-detect the form action, then login
serahkan scan -t https://app.example.com/login --profile web-auth --login-data "username=admin&password=admin"

# Credentials from a file (recommended)
serahkan scan -t https://app.example.com/login --profile web-auth --login-data-file creds.txt

# Already have a session cookie? Skip login entirely
serahkan scan -t https://app.example.com/dashboard --profile web-auth --cookie "session=abc123"
```

> If the login endpoint uses a non-POST method or a custom path, set `--login-url` explicitly to the real action URL.

---

## WAF & CDN Handling

### Pre-scan crawler check (non-blocking by default)

When `--crawl` is enabled, a lightweight pre-check hits the target to detect active WAF/interactive-challenge blocks. Historically this **aborted** the whole scan on any Cloudflare/CDN header — which broke scans against sites that merely *use* Cloudflare as a CDN. That is now fixed:

- **Default:** the pre-check only **logs a warning** and proceeds. CDN vendor headers (`cloudflare`, `incapsula`, `imperva`, `akamai`, `waf`) and bare vendor names in the body are treated as *infrastructure*, not blocks.
- A scan is still flagged as blocked only when it hits a real challenge pattern (`Error 1006`, `captcha`, `Just a moment`, `Access denied`, `Attention Required`, `403 Forbidden`, `Request blocked`, etc.).

### Flags

| Flag | Default | Description |
|---|---|---|
| `--waf-skip` | `false` | Skip the crawler pre-check entirely (never aborts on WAF/CDN signals). |
| `--waf-strict` | `false` | Restore the old hard-abort behavior — abort the crawl scan if a real block pattern is detected. |

```bash
# Crawl a Cloudflare-fronted site without the pre-check aborting
serahkan scan -t https://bhismalearning.com/login --profile benchmark-web --crawl --waf-skip
```

### Post-scan filtering

Every Nuclei finding's response body is still inspected for WAF/challenge signatures. Matches are excluded from results and counted in `waf_blocked` so security-infrastructure responses never masquerade as vulnerabilities.

---

## Crawling

`--crawl` runs a Katana-powered discovery phase before the Nuclei scan:

1. **Headless pass** (TLS-impersonating browser) for JS-heavy SPAs.
2. **Standard HTTP pass** fallback if headless fails.

Discovered links **and** `<form action="…">` endpoints are collected, de-duplicated, and written to a temp file passed to Nuclei via `-list`. If crawling yields ≤ 1 URL, an interactive prompt asks whether to force-scan the primary target.

```bash
[?] Crawler yielded no new paths. Force scan the primary target URL instead? (y/N):
```

---

## AI Analysis

Findings are deduplicated by vulnerability type and sent to your local LLM with a strict system prompt that returns a fixed ASCII report:

```
[=] TARGET PROFILE
[=] ROOT CAUSE ANALYSIS
[=] ACTIVE VULNERABILITY AUDIT & MANUAL VALIDATION
[=] REMEDIATION & HARDENING PLAYBOOK
```

The prompt is tuned to avoid common local-LLM failure modes:

- **No false positives on normal patterns** — `addEventListener` / standard JS is *not* reported as a vulnerability.
- **Informational findings stay informational** — e.g. a deprecated `XSS-Protection` header is reported as LOW RISK, not an actionable exploit.
- **No hallucinated curl** — if the input has no PoC command, the report says `N/A` rather than inventing one.
- **Valid remediation code** — code blocks are required to be syntactically complete (properly closed brackets, real values).

If the model output doesn't match the expected structure, a deterministic fallback report is generated from the parsed findings (so you always get something usable).

![Laporan AI](aset-gambar/hasil%20laporan%20dengan%20ai.png)

---

## Skip AI Mode

When AI is not available or you want raw findings only, use `--skip-ai` to bypass AI analysis entirely. Instead of the AI report, `serahkan-cli` dumps the findings directly as formatted JSON to the terminal:

```bash
serahkan scan -t https://example.com --skip-ai --profile benchmark-web
```

This is useful for:

- **CI/CD pipelines** — pipe raw JSON directly to other tools.
- **Quick triage** — see all findings without waiting for AI inference.
- **Offline environments** — no LLM configured, still get structured output.
- **Custom post-processing** — feed the JSON into your own analysis scripts.

![Output JSON](aset-gambar/hasil%20laporan%20output%20json.png)

---

## Reporting & Export

Beyond the live text/JSON output, `serahkan-cli` can produce shareable artifacts.

### Live export (`serahkan scan --export`)

| Mode | Output |
|---|---|
| `html` | Standalone HTML report. |
| `markdown` | Markdown report. |
| `sarif` | SARIF 2.1.0 file for security dashboards (severity → `error`/`warning`/`note`). |

```bash
serahkan scan -t https://example.com --export html
serahkan scan -t https://example.com --export sarif
```

### Offline re-render (`serahkan report`)

Run a scan once with `--output json`, then generate reports any time without re-scanning:

```bash
serahkan scan -t https://example.com --output json > report.json
serahkan report --input report.json --format html --output report.html
serahkan report --input report.json --format markdown
```

---

## URL Sanitization

Target URLs are pre-processed to strip tracking/challenge tokens that cause template mismatches:

- Cloudflare: `__cf_chl_f_tk`, `__cf_chl_rt`, `challenge`
- Social: `fbclid`, `gclid`, `msclkid`
- Marketing: `_hsenc`, `_hsm`, `oly_enc_id`, `ss_compile`, `vero_id`
- Generic: `trk`

```bash
serahkan scan -t "http://example.com/?__cf_chl_f_tk=abc&page=1"
# effective target -> http://example.com/?page=1
```

---

## Output Schemas

### Text mode (default)

Prints an ASCII summary (target, finding count, AI status, duration) plus the full AI defensive report. When `--skip-ai` is active, the summary is shown followed by a raw JSON dump of the findings. When no findings match, it lists diagnostic reasons (unauthenticated state, timeout caps, login-page suggestions, etc.).

### JSON mode (`--output json`)

Single JSON object:

| Field | Type | Description |
|---|---|---|
| `target` | string | Scanned target URL. |
| `severities` | string[] | Active severity filter. |
| `finding_count` | int | Findings after severity + WAF filtering. |
| `raw_findings` | int | Total parsed Nuclei lines. |
| `filtered_findings` | int | Lines dropped by severity filter. |
| `waf_blocked` | int | Findings excluded by WAF/challenge detection. |
| `skipped_reasons` | string[] | Diagnostic coverage notes. |
| `profile` | string | Active profile. |
| `focus` | string | Active focus preset. |
| `auth_mode` | string | `none`, `header`, `cookie`, `cookie_file`, `login_form`, or `mixed`. |
| `nuclei_execution` | object | Engine metadata: headless, DAST, OOB, protocols, tags, concurrency, rate-limit, totals, stderr. |
| `nuclei_command` | string[] | Full Nuclei arg array (only with `--show-nuclei-command`). |
| `ai_used` / `ai_status` / `ai_error` / `ai_analysis` | mixed | AI pipeline state and report text. |
| `findings` | array | Parsed findings (template ID, name, severity, matched-at, host, description, curl, request, response). |
| `duration_seconds` | int | Scan duration. |
| `generated_at_unix_utc` | int | Report timestamp. |

```bash
serahkan scan -t https://example.com --output json > report.json
```

---

## Full Flag Reference

### Public flags (`serahkan scan --help`)

| Flag | Default | Description |
|---|---|---|
| `--target`, `-t` | *(required)* | Target URL (`http://`/`https://`). Mutually exclusive with `--target-file`. |
| `--target-file`, `-T` | — | File of one URL per line. Mutually exclusive with `--target`. |
| `--profile` | `balanced` | `fast`, `balanced`, `deep`, `web-full`, `web-auth`, `benchmark-web`, `stealth`, `brutal-aggressive`. |
| `--focus` | — | `exposures`, `web-vulns`, `fuzz`, `misconfig`, `cves`. |
| `--severity` | `medium,high,critical` | Comma list; use `info,low,medium,high,critical` for everything. |
| `--max-duration` | `120` | Nuclei phase cap (seconds). `0` disables. |
| `--timeout` | `10` | Per-request timeout (seconds). |
| `--retries` | `0` | Connection retries. |
| `--proxy` | — | HTTP/SOCKS5 proxy for all requests (e.g. `http://127.0.0.1:8080`). |
| `--interactsh` | `false` | Enable out-of-band interaction templates. |
| `--skip-ai` | `false` | Skip AI analysis, dump raw findings JSON to terminal. |
| `--ai-endpoint` | config | Override AI endpoint. |
| `--ai-model` | config | Override AI model. |
| `--ai-api-key` | config | Override API key (cloud endpoints). |
| `--ai-timeout` | `25` | AI completion timeout (seconds). |
| `--ai-findings` | `5` | Max findings sent to AI. |
| `--output` | `text` | `text` or `json`. |
| `--export` | — | `html`, `markdown`, or `sarif` report file. |
| `--crawl` | `false` | Pre-scan Katana discovery. |
| `--show-nuclei-command` | `false` | Print Nuclei args, expose engine logs. |
| `--verbose`, `-v` | `false` | Debug logging on stderr. |

### Hidden / advanced flags

| Flag | Default | Description |
|---|---|---|
| `--login-url` | target | Login form action URL. |
| `--login-data` | — | Login POST body. |
| `--login-data-file` | — | Login POST body from file. |
| `--login-threshold` | `0` | Status code treated as login success. |
| `--waf-skip` | `false` | Skip crawler WAF pre-check. |
| `--waf-strict` | `false` | Abort crawl scan on real WAF block. |
| `--concurrency` | profile | Nuclei concurrency. |
| `--rate-limit` | profile | Nuclei requests/sec. |
| `--raw-http` | profile | Include raw HTTP (`-irr`). |
| `--enable-headless` / `--enable-dast` / `--tech-detect` | profile | Engine feature toggles. |
| `--force-tags` | — | Run normally-ignored tags (e.g. `fuzz`). |
| `--header` / `--cookie` / `--cookie-file` | — | Authenticated scanning headers. |
| `--tags` / `--exclude-tags` / `--templates` / `--workflows` / `--protocols` | — | Nuclei template selectors. |

---

## Configuration & Precedence

```
CLI Flags  >  config.json  >  Profile Defaults  >  Code Defaults
```

**`config.json` keys:** `ai.endpoint`, `ai.model`, `ai.api_key`, `ai.timeout_seconds`, `ai.retry_count`.
**`config.yaml` keys:** `rate-limit`, `concurrency`, `ai-endpoint`, `ai-model`, `timeout_seconds`.
**Env vars:** `SERAHKAN_AI_ENDPOINT`, `SERAHKAN_AI_MODEL`, `SERAHKAN_AI_API_KEY`, `SERAHKAN_CONFIG`.

---

## Cookbook

```bash
# Fast unauthenticated triage
serahkan scan -t https://example.com --profile fast

# Routine scan with AI
serahkan scan -t https://example.com

# Anti-blocking, low-and-slow, auto HTML export
serahkan scan -t https://target.com --profile stealth

# Anti-blocking + proxy rotation + abort on WAF block
serahkan scan -t https://target.com --profile stealth --proxy http://127.0.0.1:8080 --waf-strict

# Authenticated web app (auto-detect login form)
serahkan scan -t https://app.example.com/login --profile web-auth --login-data "user=admin&pass=admin"

# Cloudflare-fronted target, crawl without pre-check abort
serahkan scan -t https://bhismalearning.com/login --profile benchmark-web --crawl --waf-skip

# Deep + OOB, no AI
serahkan scan -t https://example.com --profile deep --interactsh --skip-ai

# Maximum coverage, constrained rate
serahkan scan -t https://internal.app --profile brutal-aggressive --concurrency 100 --rate-limit 200 --skip-ai

# Mass scan from file, JSON out
serahkan scan -T targets.txt --profile deep --output json > mass.json

# HTML report for a login-protected app
serahkan scan -t https://app.example.com/login --profile web-auth --login-data-file creds.txt --export html

# SARIF export for dashboards
serahkan scan -t https://example.com --export sarif

# Re-render a saved JSON scan into a shareable HTML report (no re-scan)
serahkan report --input mass.json --format html --output mass.html
```

---

## Troubleshooting

### `scan failed: nuclei is not installed or not available in PATH`

`serahkan-cli` couldn't find `nuclei.exe` locally or on `PATH`. On **Windows**, Defender may have quarantined it as a HackTool/PUA. Fix:

```powershell
# Option A — bundled installer (run as Administrator)
powershell -ExecutionPolicy Bypass -File install-nuclei.ps1

# Option B — whitelist the folder, then install manually
Add-MpPreference -ExclusionPath "C:\path\to\serahkan-cli"
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### AI analysis missing or falls back

Check `serahkan doctor` — the configured AI endpoint must be reachable. Use `--skip-ai` for raw findings only.

### Crawl finds nothing

If the target is a single page with no links, the crawler yields ≤ 1 URL and prompts to force-scan the primary target. Answer `y` to proceed.

---

## License

Released under the [MIT License](LICENSE). `serahkan-cli` is an independent wrapper and is not affiliated with ProjectDiscovery.
