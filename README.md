# serahkan-cli

A high-efficiency Go-based wrapper orchestration engine for [Nuclei](https://github.com/projectdiscovery/nuclei). serahkan-cli wraps raw Nuclei execution, applies structured argument construction through configurable profiles, parses JSONL output in real time, and routes filtered findings to a local LLM for defensive analysis — all within a single command.

## Core Capabilities

- Profile-driven scan orchestration with six tuned presets covering fast triage through maximum-coverage auditing.
- Real-time JSONL parsing with per-severity filtering, malformed-line resilience, and structured result aggregation.
- WAF interception detection that automatically identifies and excludes findings blocked by security filters (Cloudflare, rate limiting, access denial).
- URL sanitization that strips tracking and challenge tokens from target URLs before execution.
- Dynamic concurrency and rate-limit control via global CLI flags that override any profile default.
- Optional local LLM integration for automated defensive analysis of filtered findings.
- Structured JSON output with full execution metadata, auth mode detection, and Nuclei stderr capture.
- Transparent command construction via `--show-nuclei-command` with dynamic `-silent` suppression for full engine visibility.

## Requirements

- `nuclei` (or `nuclei.exe`) available in the working directory or on `PATH`.
- A local AI endpoint reachable at the configured address (default: `http://127.0.0.1:1234/v1/chat/completions`). AI can be skipped with `--skip-ai`.

## Build and Install

```powershell
go build -o serahkan.exe .
.\serahkan.exe version
```

Build with embedded metadata:

```powershell
$env:SERAHKAN_VERSION="0.2.0"
$env:SERAHKAN_COMMIT="abc1234"
.\scripts\build.ps1
.\serahkan.exe version
```

## Commands

### `scan`

The primary command. Runs a Nuclei scan against a target, applies profile-driven argument construction, filters results by severity, and optionally sends findings to a local LLM for defensive analysis.

```powershell
go run . scan --target http://example.com
go run . scan --target http://example.com --profile deep --output json
go run . scan --target http://example.com --profile brutal-aggressive --skip-ai
```

### `doctor`

Checks that `nuclei` is resolvable and that the configured AI endpoint is reachable.

```powershell
go run . doctor
```

### `config`

View, set, or unset persistent configuration values.

```powershell
go run . config view
go run . config set ai.endpoint http://127.0.0.1:1234/v1/chat/completions
go run . config set ai.model qwen2.5-coder-1.5b-instruct
go run . config unset ai.api_key
```

Supported keys: `ai.endpoint`, `ai.model`, `ai.api_key`.

### `version`

Displays application version, build commit, build date, Go version, and OS/arch.

```powershell
go run . version
```

## Scan Profiles

Profiles control the full set of Nuclei arguments: timeouts, retries, severity filtering, concurrency, rate limits, protocol types, and template inclusion strategy. The active profile is selected via `--profile` and defaults to `balanced`.

| Profile | Severity | Timeout | Scan Cap | Retries | OOB | Headless | DAST | Default Ignored Tags | Types | AI |
|---|---|---|---|---|---|---|---|---|---|---|
| `fast` | high, critical | 8s | 60s | 0 | disabled | off | off | — | http | skipped |
| `balanced` | medium, high, critical | 10s | 120s | 0 | disabled | off | off | — | http | enabled |
| `deep` | medium, high, critical | 30s | 300s | 2 | enabled | off | off | — | — | enabled |
| `web-full` | info, low, medium, high, critical | 30s | 420s | 1 | enabled | on | on | fuzz | http, headless, javascript | enabled |
| `benchmark-web` | info, low, medium, high, critical | 25s | 300s | 3 | disabled | off | off | — | http | skipped |
| `brutal-aggressive` | info, low, medium, high, critical | 45s | 600s | 3 | enabled | on | on | cve, sqli, xss, lfi, rce, misconfig, exposure | http, headless, javascript, dns | skipped |

### Profile Details

#### `fast`

High-speed baseline. Restricts to high and critical severities, skips AI analysis, and limits to HTTP-only templates. Intended for quick go/no-go assessments.

```powershell
go run . scan --target http://example.com --profile fast
```

#### `balanced`

The default. Medium-throughput configuration with AI analysis enabled and out-of-band interaction disabled. Suitable for routine daily scanning.

```powershell
go run . scan --target http://example.com
go run . scan --target http://example.com --profile balanced --ai-model llama-3.2-3b-instruct
```

#### `deep`

Extended depth analysis. Increases timeouts, enables out-of-band interaction templates, and retries unstable endpoints. AI analysis is enabled with a longer timeout.

```powershell
go run . scan --target http://example.com --profile deep
go run . scan --target http://example.com --profile deep --include-http --include-oob
```

#### `web-full`

Comprehensive web-vulnerability hunting. Enables headless browser templates, DAST/fuzz scanning, out-of-band interaction, and includes the `fuzz` default-ignored tag. Captures raw HTTP request/response data.

```powershell
go run . scan --target http://example.com --profile web-full
go run . scan --target http://example.com --profile web-full --cookie "session=abc123"
```

#### `benchmark-web`

Specialized profile optimized for public vulnerable demo environments (e.g., DVWA, WebGoat, testphp). Disables DAST isolation and the `-itags fuzz` restriction to ensure Nuclei loads the complete set of standard HTTP vulnerability templates without filtering. Uses elevated connection retries (3) to handle unstable demo endpoints gracefully. The `web-vulns` focus is applied by default, injecting `xss`, `sqli`, `lfi`, `rfi`, `ssrf`, `ssti`, and `redirect` tags.

```powershell
go run . scan --target http://testphp.vulnweb.com/ --profile benchmark-web
go run . scan --target http://testphp.vulnweb.com/ --profile benchmark-web --output json
```

#### `brutal-aggressive`

Maximum throughput coverage. Sets full severity inclusion, 600-second scan cap, elevated concurrency (300) and rate limit (800), headless and DAST enabled, out-of-band interaction active, and 3 retries. The default-ignored tag set is broadened to `cve`, `sqli`, `xss`, `lfi`, `rce`, `misconfig`, and `exposure` to maximize template loading across core web-application vulnerability classes.

```powershell
go run . scan --target http://example.com --profile brutal-aggressive --skip-ai
go run . scan --target http://example.com --profile brutal-aggressive --output json
```

## Focus Presets

The `--focus` flag applies a targeted template or tag injection on top of the active profile. Presets are additive — they append tags or template paths without removing flags set by the profile.

| Preset | Behavior |
|---|---|
| `exposures` | Appends `-t http/exposures` to run exposure-detection templates. |
| `web-vulns` | Appends `-tags xss,sqli,lfi,rfi,ssrf,ssti,redirect` for broad web-vulnerability coverage. |
| `fuzz` | Enables DAST, adds `-itags fuzz`, and appends `-tags fuzz` for parameter-fuzzing templates. |
| `misconfig` | Appends `-tags misconfig,exposure,config` for misconfiguration-focused scanning. |
| `cves` | Appends `-t http/cves` to run HTTP-layer CVE templates. |

```powershell
go run . scan --target http://example.com --focus web-vulns
go run . scan --target http://example.com --focus cves --severity high,critical
go run . scan --target http://example.com --focus misconfig --profile deep
```

## Advanced Observability Flags

### `--show-nuclei-command`

Prints the exact Nuclei argument array constructed by the wrapper. When this flag is active, the internal `-silent` flag is dynamically removed from the execution arguments, exposing Nuclei's template-loading logs, match notifications, and stderr diagnostics in real time.

```powershell
go run . scan --target http://example.com --show-nuclei-command
go run . scan --target http://example.com --profile benchmark-web --show-nuclei-command --output json
```

Use this to verify which flags the wrapper injects, diagnose template-starvation issues, or confirm that specific tags and templates are being loaded by Nuclei.

### `--parity-mode`

Strips the wrapper down to minimal argument construction: no concurrency/rate-limit overrides, no `-no-banner`, no `-omit-raw`, and no `-irr`. Designed for direct comparison between wrapper-managed execution and raw Nuclei behavior when diagnosing unexpected output.

```powershell
go run . scan --target http://example.com --parity-mode --show-nuclei-command
go run . scan --target http://example.com --parity-mode --output json
```

### `--concurrency` and `--rate-limit`

Global CLI flags that override profile-hardcoded concurrency and rate-limit values. When explicitly passed via the terminal, these values take precedence over any defaults set by the active profile (e.g., brutal-aggressive's 300/800). When not set, the profile defaults apply normally.

```powershell
go run . scan --target http://example.com --profile brutal-aggressive --concurrency 100 --rate-limit 200
go run . scan --target http://example.com --concurrency 50 --rate-limit 100
```

This allows fine-tuning throughput without modifying profiles, useful for targets with strict rate-limiting or resource-constrained environments.

## URL Sanitization

The target URL is automatically pre-processed before being passed to Nuclei. Tracking and challenge tokens commonly injected by CDNs, analytics platforms, and security challenges are stripped to prevent template mismatches and ensure clean execution strings.

Detected and removed tokens include:

- Cloudflare challenge tokens (`__cf_chl_f_tk`, `__cf_chl_rt`, `challenge`)
- Social media tracking (`fbclid`, `gclid`, `msclkid`)
- Marketing automation (`_hsenc`, `_hsm`, `oly_enc_id`, `ss_compile`, `vero_id`)
- Generic tracking parameters (`trk`)

```powershell
# Tracking tokens are stripped automatically
go run . scan --target "http://example.com/?__cf_chl_f_tk=abc123&page=1"
# Effective target: http://example.com/?page=1

# Clean URLs pass through unchanged
go run . scan --target http://example.com
```

## WAF Interception Detection

The output parser inspects the raw response body of every finding for known WAF and security-block patterns. Findings that match these patterns are excluded from the result set and counted separately, preventing false positives from security infrastructure responses.

Detected patterns include:

- `Error 1015` (Cloudflare rate limiting)
- `You are being rate limited`
- `Access denied | freemodel.dev used Cloudflare to restrict access`
- `Attention Required! | Cloudflare`
- `403 Forbidden`, `Request blocked`, `Security block`
- `Verify you are human`, `Checking your browser`

The JSON output reports WAF-blocked findings via the `waf_blocked` field and includes a diagnostic message in `skipped_reasons` when any findings are intercepted.

```powershell
go run . scan --target http://example.com --profile benchmark-web --output json
# waf_blocked will show count of intercepted findings
```

## Output Schemas

### Text Mode

Default output. Prints an ASCII summary with target, finding count, AI status, duration, and the full AI defensive analysis report. When no findings match, the output lists active diagnostic reasons (disabled OOB, severity filtering, unauthenticated state, scan timeout caps, etc.).

```powershell
go run . scan --target http://example.com --profile balanced
```

### JSON Mode

Machine-readable output. Returns a single JSON object with the following structure:

| Field | Type | Description |
|---|---|---|
| `target` | string | The scanned target URL. |
| `severities` | string[] | Active severity filter. |
| `finding_count` | int | Number of findings after severity and WAF filtering. |
| `raw_findings` | int | Total lines parsed from Nuclei stdout. |
| `filtered_findings` | int | Lines discarded by severity filter. |
| `waf_blocked` | int | Findings excluded due to WAF/security-block pattern detection. |
| `skipped_reasons` | string[] | Diagnostic messages explaining reduced coverage. |
| `profile` | string | Active scan profile name. |
| `focus` | string | Active focus preset, if any. |
| `auth_mode` | string | Detected authentication mode: `none`, `header`, `cookie`, `cookie_file`, or `mixed`. |
| `nuclei_execution` | object | Execution metadata including parity mode, automatic scan, headless, DAST, OOB, types, tags, exclude tags, templates, workflows, include-default-ignored-tags, concurrency, rate-limit, total lines, malformed lines, waf blocked, and stderr. |
| `nuclei_command` | string[] | The full Nuclei argument array (only present when `--show-nuclei-command` is active). |
| `ai_used` | bool | Whether AI analysis was invoked. |
| `ai_status` | string | AI result: `ok`, `unavailable`, `fallback`, or `not_used`. |
| `ai_error` | string | AI error message, if any. |
| `ai_analysis` | string | The AI defensive analysis report text. |
| `findings` | array | Parsed Nuclei finding objects with template ID, name, severity, matched at, host, description, curl command, request, and response fields. |
| `duration_seconds` | int | Total scan duration in seconds. |
| `generated_at_unix_utc` | int | Unix timestamp of report generation. |

```powershell
go run . scan --target http://example.com --output json
go run . scan --target http://example.com --profile benchmark-web --output json > report.json
```

## Full Reference

### Global Flags

| Flag | Default | Description |
|---|---|---|
| `--target`, `-t` | *(required)* | Target URL to scan. Must start with `http://` or `https://`. |
| `--profile` | `balanced` | Scan preset. |
| `--focus` | *(none)* | Template focus preset. |
| `--severity` | `medium,high,critical` | Comma-separated severity levels. |
| `--include-low-info` | `false` | Include info and low severities. |
| `--timeout` | `10` | Nuclei per-request timeout in seconds. |
| `--scan-timeout` | `120` | Maximum Nuclei phase duration in seconds. `0` disables the limit. |
| `--retries` | `0` | Nuclei connection retries. |
| `--concurrency` | `0` | Nuclei connection concurrency. Overrides profile defaults when explicitly set. `0` uses profile value. |
| `--rate-limit` | `0` | Nuclei requests per second rate limit. Overrides profile defaults when explicitly set. `0` uses profile value. |
| `--no-interactsh` | `true` | Disable out-of-band interaction templates. |
| `--include-oob` | `false` | Enable out-of-band templates by clearing `--no-interactsh`. |
| `--include-http` | `false` | Include raw HTTP request/response data (`-irr`). |
| `--enable-headless` | `false` | Enable headless browser templates. |
| `--enable-dast` | `false` | Enable DAST/fuzz templates. |
| `--automatic-scan` | `false` | Enable Nuclei automatic technology-based scan (`-as`). Falls back to normal scan if no tech-tagged templates match. |
| `--include-default-ignored-tags` | *(none)* | Include tags normally ignored by Nuclei, such as `fuzz`. |
| `--tags` | *(none)* | Nuclei template tags to include. |
| `--exclude-tags` | *(none)* | Nuclei template tags to exclude. |
| `--templates` | *(none)* | Specific Nuclei template files or directories. |
| `--workflows` | *(none)* | Specific Nuclei workflow files or directories. |
| `--type` | *(none)* | Nuclei protocol types: `http`, `headless`, `javascript`. |
| `--header` | *(none)* | Custom request header. Repeatable. |
| `--cookie` | *(none)* | Cookie value sent as a `Cookie` header. |
| `--cookie-file` | *(none)* | File containing headers/cookies for authenticated scans. |
| `--skip-ai` | `false` | Skip AI analysis. |
| `--ai-endpoint` | *(config)* | Override AI endpoint. |
| `--ai-model` | *(config)* | Override AI model. |
| `--ai-api-key` | *(config)* | Override AI API key. |
| `--ai-timeout` | `25` | AI completion timeout in seconds. |
| `--limit` | `5` | Maximum findings sent to AI for analysis. |
| `--output` | `text` | Output format: `text` or `json`. |
| `--show-nuclei-command` | `false` | Print the constructed Nuclei command and remove `-silent` for engine visibility. |
| `--parity-mode` | `false` | Minimal wrapper flags for raw Nuclei comparison. |
| `--legacy-compatible` | `false` | Use settings close to the original wrapper behavior. |
| `--verbose`, `-v` | `false` | Enable verbose debug logging on stderr. |

### Configuration Precedence

```text
flag > environment variable > config file > default
```

Supported environment variables: `SERAHKAN_AI_ENDPOINT`, `SERAHKAN_AI_MODEL`, `SERAHKAN_AI_API_KEY`, `SERAHKAN_CONFIG`.

### Recommended Usage

```powershell
# Quick baseline check
go run . scan --target http://example.com --profile fast

# Routine balanced scan with AI analysis
go run . scan --target http://example.com

# Deep scan with full web coverage and OOB
go run . scan --target http://example.com --profile deep --include-oob

# Web vulnerability hunting with headless and DAST
go run . scan --target http://example.com --profile web-full

# Benchmark a public vulnerable demo target
go run . scan --target http://testphp.vulnweb.com/ --profile benchmark-web

# Maximum coverage for authorized internal targets
go run . scan --target http://internal-app.local --profile brutal-aggressive --skip-ai

# Override concurrency and rate-limit for constrained targets
go run . scan --target http://example.com --profile brutal-aggressive --concurrency 100 --rate-limit 200

# Authenticated scan with session cookie
go run . scan --target http://example.com --profile web-full --cookie "session=abc123"

# Verify wrapper argument construction
go run . scan --target http://example.com --show-nuclei-command

# Raw Nuclei parity comparison
go run . scan --target http://example.com --parity-mode --show-nuclei-command --output json

# CVE-focused scan with custom severity
go run . scan --target http://example.com --focus cves --severity high,critical

# JSON report saved to file
go run . scan --target http://example.com --profile balanced --output json > scan-report.json
```
