# SERAHKAN-CLI

> **AI-powered Nuclei orchestration engine** — a lightweight, fast Go CLI wrapper for modern web vulnerability assessment. It drives [ProjectDiscovery Nuclei](https://github.com/projectdiscovery/nuclei), adds stealth/WAF-aware crawling, supports authenticated scanning, and pipes results into a local LLM (Ollama / LM Studio) for instant defensive analysis and remediation playbooks.

```
   _____ ______ _____          _    _  _    _          _ _
  / ____|  ____|  __ \   /\   | |  | || |  / \   /\   | | |
 | (___ | |__  | |__) | /  \  | |__| || | /  /  /  \  | | |
  \___ \|  __| |  _  / / /\ \ |  __  || |/  /  / /\ \ | | |
  ____) | |____| | \ \/ ____ \| |  | || |\  \ / ____ \| | |
 |_____/|______|_|  \_\_/    \_\_|  |_||_| \_/_/    \_\_|_|
```

---

## Why serahkan-cli?

Nuclei is powerful but raw. `serahkan-cli` wraps it so you can:

- **Scan in one command** with opinionated, battle-tested profiles (`fast` → `brutal-aggressive`, plus `web-full` and `web-auth`).
- **Authenticate before scanning** — submit a login form automatically and scan the authenticated surface, not just the login page.
- **Bypass / tolerate WAFs** — built-in stealth headers, randomized user agents, behavioral rate-limit jitter, and a crawler pre-check that warns instead of aborting on CDN headers.
- **Get a real remediation report** — findings are deduplicated and sent to your local LLM, which returns a structured ASCII defensive analysis (root cause + PoC + hardening playbook).
- **Stay machine-readable** — full `--output json` pipeline for dashboards and CI.

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
  - [`config`](#config) · [`scan`](#scan) · [`doctor`](#doctor) · [`version`](#version)
- [Scan Profiles](#scan-profiles)
- [Focus Presets](#focus-presets)
- [Authenticated Scanning](#authenticated-scanning)
- [WAF & CDN Handling](#waf--cdn-handling)
- [Crawling](#crawling)
- [AI Analysis](#ai-analysis)
- [URL Sanitization](#url-sanitization)
- [Output Schemas](#output-schemas)
- [Full Flag Reference](#full-flag-reference)
- [Configuration & Precedence](#configuration--precedence)

---

## Installation

Requires **Go 1.21+** and a local **Nuclei** binary (bundled `nuclei.exe` in the repo root takes priority; otherwise it falls back to `PATH`).

```cmd
git clone https://github.com/Zyrexnn/serahkan-cli.git
cd serahkan-cli
go build -o serahkan.exe .
```

Optional: move `serahkan.exe` into a folder on your `PATH` so you can invoke `serahkan` anywhere.

Verify the toolchain:

```cmd
serahkan doctor
```

---

## Quick Start

```cmd
:: 1. Point it at your local LLM once (persisted to config.json)
serahkan config set ai.endpoint http://127.0.0.1:1234/v1/chat/completions
serahkan config set ai.model qwen2.5-coder-1.5b-instruct

:: 2. Scan a target — AI analysis runs automatically if configured
serahkan scan -t https://example.com/login --profile web-auth --login-data "username=admin&password=admin"

:: 3. Or just get raw findings fast, no AI
serahkan scan -t https://example.com --profile benchmark-web --skip-ai
```

---

## Commands

### `config`

Persisted CLI configuration. Subcommands: `set`, `show`, `unset`.

```cmd
serahkan config set ai.endpoint http://127.0.0.1:1234/v1/chat/completions
serahkan config set ai.model qwen2.5-coder-1.5b-instruct
serahkan config show
serahkan config unset ai.api_key
```

### `scan`

The primary command. Runs Nuclei against a target (or a file of targets), applies the selected profile, filters by severity, and optionally sends findings to a local LLM.

Without `--crawl`, the scanner performs a direct single-target scan with stealth headers. With `--crawl`, a Katana-powered discovery phase runs first and discovered paths (including `<form action>` endpoints) are fed into Nuclei.

```cmd
serahkan scan -t https://example.com/login --profile web-auth
serahkan scan -T targets.txt --profile deep --output json
```

### `doctor`

Checks that `nuclei` is resolvable and the configured AI endpoint is reachable.

```cmd
serahkan doctor
```

### `version`

Prints version, build commit, build date, Go version, and OS/arch.

```cmd
serahkan version
```

---

## Scan Profiles

Profiles set the complete Nuclei argument set: timeouts, retries, severity filtering, concurrency, rate limits, protocols, and template inclusion. Selected via `--profile`; defaults to `balanced`.

| Profile | Severity | Timeout | Max Duration | Retries | OOB | Headless | DAST | Forced Tags | Protocols | AI |
|---|---|---|---|---|---|---|---|---|---|---|
| `fast` | high, critical | 8s | 60s | 0 | off | off | off | — | http | skipped |
| `balanced` | medium, high, critical | 10s | 120s | 0 | off | off | off | — | http | enabled |
| `deep` | medium, high, critical | 30s | 300s | 2 | on | off | off | — | http | enabled |
| `web-full` | info → critical | 30s | 420s | 1 | on | on | on | fuzz | http, headless, js | enabled |
| `web-auth` | info → critical | 30s | 420s | 2 | on | on | on | — | http, headless, js | enabled |
| `benchmark-web` | info → critical | 25s | 300s | 3 | off | off | off | — | http | skipped |
| `brutal-aggressive` | info → critical | 45s | 600s | 3 | on | on | on | cve, sqli, xss, lfi, rce, misconfig, exposure | http, headless, js, dns | skipped |

> `"info → critical"` = `info,low,medium,high,critical`.

### Profile notes

- **`fast`** — quick go/no-go. High/critical only, no AI, HTTP templates only.
- **`balanced`** — default daily driver. AI on, OOB off.
- **`deep`** — longer timeouts, OOB interaction, 2 retries for flaky endpoints.
- **`web-full`** — full web coverage: headless + DAST/fuzz + OOB + `fuzz` forced tag, raw HTTP capture.
- **`web-auth`** — built for **login-protected apps**. Applies `web-vulns` focus by default and is designed to be paired with `--login-data` / `--cookie` so you scan the authenticated surface. AI enabled with a generous 120s timeout.
- **`benchmark-web`** — tuned for public vuln demos (DVWA, WebGoat, testphp). Applies the `web-vulns` focus (`xss,sqli,lfi,rfi,ssrf,ssti,redirect`) and uses 3 retries for unstable hosts.
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

```cmd
serahkan scan -t https://example.com --focus web-vulns
serahkan scan -t https://example.com --focus cves --severity high,critical
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

```cmd
:: Auto-detect the form action, then login
serahkan scan -t https://app.example.com/login --profile web-auth --login-data "username=admin&password=admin"

:: Credentials from a file (recommended)
serahkan scan -t https://app.example.com/login --profile web-auth --login-data-file creds.txt

:: Already have a session cookie? Skip login entirely
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

```cmd
:: Crawl a Cloudflare-fronted site without the pre-check aborting
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

```cmd
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

---

## URL Sanitization

Target URLs are pre-processed to strip tracking/challenge tokens that cause template mismatches:

- Cloudflare: `__cf_chl_f_tk`, `__cf_chl_rt`, `challenge`
- Social: `fbclid`, `gclid`, `msclkid`
- Marketing: `_hsenc`, `_hsm`, `oly_enc_id`, `ss_compile`, `vero_id`
- Generic: `trk`

```cmd
serahkan scan -t "http://example.com/?__cf_chl_f_tk=abc&page=1"
:: effective target -> http://example.com/?page=1
```

---

## Output Schemas

### Text mode (default)

Prints an ASCII summary (target, finding count, AI status, duration) plus the full AI defensive report. When no findings match, it lists diagnostic reasons (unauthenticated state, timeout caps, login-page suggestions, etc.).

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

```cmd
serahkan scan -t https://example.com --output json > report.json
```

---

## Full Flag Reference

### Public flags (`serahkan scan --help`)

| Flag | Default | Description |
|---|---|---|
| `--target`, `-t` | *(required)* | Target URL (`http://`/`https://`). Mutually exclusive with `--target-file`. |
| `--target-file`, `-T` | — | File of one URL per line. Mutually exclusive with `--target`. |
| `--profile` | `balanced` | `fast`, `balanced`, `deep`, `web-full`, `web-auth`, `benchmark-web`, `brutal-aggressive`. |
| `--focus` | — | `exposures`, `web-vulns`, `fuzz`, `misconfig`, `cves`. |
| `--severity` | `medium,high,critical` | Comma list; use `info,low,medium,high,critical` for everything. |
| `--max-duration` | `120` | Nuclei phase cap (seconds). `0` disables. |
| `--timeout` | `10` | Per-request timeout (seconds). |
| `--retries` | `0` | Connection retries. |
| `--interactsh` | `false` | Enable out-of-band interaction templates. |
| `--skip-ai` | `false` | Skip AI analysis. |
| `--ai-endpoint` | config | Override AI endpoint. |
| `--ai-model` | config | Override AI model. |
| `--ai-api-key` | config | Override API key (cloud endpoints). |
| `--ai-timeout` | `25` | AI completion timeout (seconds). |
| `--ai-findings` | `5` | Max findings sent to AI. |
| `--output` | `text` | `text` or `json`. |
| `--export` | — | `html` or `markdown` report file. |
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

```cmd
:: Fast unauthenticated triage
serahkan scan -t https://example.com --profile fast

:: Routine scan with AI
serahkan scan -t https://example.com

:: Authenticated web app (auto-detect login form)
serahkan scan -t https://app.example.com/login --profile web-auth --login-data "user=admin&pass=admin"

:: Cloudflare-fronted target, crawl without pre-check abort
serahkan scan -t https://bhismalearning.com/login --profile benchmark-web --crawl --waf-skip

:: Deep + OOB, no AI
serahkan scan -t https://example.com --profile deep --interactsh --skip-ai

:: Maximum coverage, constrained rate
serahkan scan -t https://internal.app --profile brutal-aggressive --concurrency 100 --rate-limit 200 --skip-ai

:: Mass scan from file, JSON out
serahkan scan -T targets.txt --profile deep --output json > mass.json

:: HTML report for a login-protected app
serahkan scan -t https://app.example.com/login --profile web-auth --login-data-file creds.txt --export html
```
