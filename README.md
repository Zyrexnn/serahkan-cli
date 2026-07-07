# SERAHKAN-CLI

An AI-powered Nuclei orchestration engine built with Go. `serahkan-cli` is a lightweight, lightning-fast CLI wrapper designed for modern vulnerability assessment, engineered to seamlessly integrate with local LLMs (Ollama/LM Studio) for instant defensive analysis and remediation playbook generation.

## Key Features

- **Native Configuration Wizard:** Setup your local AI endpoint and model once via `serahkan config` without touching configuration files manually.
- **Smart Configuration Fallback:** Uses an elegant hierarchical priority system (`CLI Flags` > `config.yaml` > `Profile Defaults`).
- **WAF-Aware Concurrency Control:** Embedded rate-limiting and sanitization mechanisms to optimize scanning speeds against strict target firewalls.
- **Symmetric UI Terminal:** Beautiful ASCII art banner with aligned meta-summaries using rigid column layouts.
- **Pure JSON Purity:** Dedicated `--output json` pipeline that emits strictly valid indented structural data, sanitized from terminal ANSI color codes.
- **Default Stealth Engine:** Automatic programmatic browser User-Agent randomization from a pool of 14 modern browser signatures, signature stripping, and behavioral rate-limit jitter (±15% concurrency / ±10% rate-limit) to bypass modern cloud WAF solutions seamlessly.
- **Pre-flight WAF Verification:** Smart early-exit mechanism that inspects target responses against 18 industrial WAF/Cloudflare block patterns (like Error 1006 or CAPTCHA walls) before scaling workers, preventing wasted scans against protected endpoints.
- **Intelligent Interactive Crawling:** Integrated optional multi-phase pre-scan link discovery powered natively by Katana (Headless + TLS Handshake Impersonation) with an interactive shell prompt fallback when crawling yields insufficient paths.

## Installation & Setup

### 1. Clone and Build Binary

```cmd
git clone https://github.com/Zyrexnn/serahkan-cli.git
cd serahkan-cli
go build -o serahkan.exe .
```

### 2. Register Global Path (Optional)

Move `serahkan.exe` into a dedicated folder and append it to your Windows System Environment Variables so you can invoke `serahkan` anywhere.

## Usage Workflow

### 1. One-Time Setup (Configure AI Environment)

Initialize your local LLM orchestrator parameters. This generates or updates the local `config.yaml`:

```cmd
serahkan config --endpoint http://127.0.0.1:1234/v1/chat/completions --model qwen2.5-coder-1.5b-instruct
```

### 2. Execute Scanning (AI Auto-Enabled)

Run your targeted vulnerability scan. The tool automatically detects your `config.yaml` parameters and pipes results to your local AI:

```cmd
serahkan scan --target https://example.com/login --profile benchmark-web
```

### 3. Pure JSON Output (For Pipelines/Dashboards)

Generate raw structural pretty-printed JSON logs, entirely isolated from styling pipelines:

```cmd
serahkan scan --target https://example.com/login --profile benchmark-web --output json
```

### 4. Diagnostics Mode (Skip AI)

Bypass AI report generation on the fly to fetch instant target metrics:

```cmd
serahkan scan --target https://example.com/login --profile benchmark-web --skip-ai
```

## Commands

### `config`

Manage persisted CLI configuration. Use `--endpoint` and `--model` flags to write values directly to `config.yaml`.

```cmd
serahkan config --endpoint http://127.0.0.1:1234/v1/chat/completions --model qwen2.5-coder-1.5b-instruct
serahkan config view
serahkan config set ai.endpoint http://127.0.0.1:1234/v1/chat/completions
serahkan config set ai.model qwen2.5-coder-1.5b-instruct
serahkan config unset ai.api_key
```

### `scan`

The primary command. Runs a Nuclei scan against a target, applies profile-driven argument construction, filters results by severity, and optionally sends findings to a local LLM for defensive analysis.

Without `--crawl`, the scanner defaults to an ultra-fast, single-target direct scan with built-in stealth headers (randomized User-Agent, stripped browser signatures, and behavioral jitter). All scans automatically apply stealth evasions regardless of the crawl flag.

Passing `--crawl` activates the dual-phase crawler pipeline before the core Nuclei phase:
- **Phase 1:** Headless browser rendering via Katana with TLS handshake impersonation for JavaScript-heavy single-page applications.
- **Phase 2:** Standard HTTP parsing fallback if the headless phase fails, ensuring maximum coverage on both dynamic and static targets.

When the crawler discovers more than one unique URL, discovered paths are written to a temporary targets file and passed to Nuclei via `-list` for multi-page scanning. If crawling yields 0 or 1 URL, an interactive prompt asks whether to force-scan the primary target.

```cmd
serahkan scan --target http://example.com
serahkan scan --target http://example.com --profile deep --output json
serahkan scan --target http://example.com --profile brutal-aggressive --skip-ai
serahkan scan --target http://example.com --crawl
serahkan scan --target http://example.com --crawl --profile web-full
```

### `doctor`

Checks that `nuclei` is resolvable and that the configured AI endpoint is reachable.

```cmd
serahkan doctor
```

### `version`

Displays application version, build commit, build date, Go version, and OS/arch.

```cmd
serahkan version
```

## Scan Profiles

Profiles control the full set of Nuclei arguments: timeouts, retries, severity filtering, concurrency, rate limits, protocol types, and template inclusion strategy. The active profile is selected via `--profile` and defaults to `balanced`.

| Profile | Severity | Timeout | Scan Cap | Retries | OOB | Headless | DAST | Default Ignored Tags | Types | AI |
|---|---|---|---|---|---|---|---|---|---|---|
| `fast` | high, critical | 8s | 60s | 0 | disabled | off | off | -- | http | skipped |
| `balanced` | medium, high, critical | 10s | 120s | 0 | disabled | off | off | -- | http | enabled |
| `deep` | medium, high, critical | 30s | 300s | 2 | enabled | off | off | -- | -- | enabled |
| `web-full` | info, low, medium, high, critical | 30s | 420s | 1 | enabled | on | on | fuzz | http, headless, javascript | enabled |
| `benchmark-web` | info, low, medium, high, critical | 25s | 300s | 3 | disabled | off | off | -- | http | skipped |
| `brutal-aggressive` | info, low, medium, high, critical | 45s | 600s | 3 | enabled | on | on | cve, sqli, xss, lfi, rce, misconfig, exposure | http, headless, javascript, dns | skipped |

### Profile Details

#### `fast`

High-speed baseline. Restricts to high and critical severities, skips AI analysis, and limits to HTTP-only templates. Intended for quick go/no-go assessments.

```cmd
serahkan scan --target http://example.com --profile fast
```

#### `balanced`

The default. Medium-throughput configuration with AI analysis enabled and out-of-band interaction disabled. Suitable for routine daily scanning.

```cmd
serahkan scan --target http://example.com
serahkan scan --target http://example.com --profile balanced --ai-model llama-3.2-3b-instruct
```

#### `deep`

Extended depth analysis. Increases timeouts, enables out-of-band interaction templates, and retries unstable endpoints. AI analysis is enabled with a longer timeout.

```cmd
serahkan scan --target http://example.com --profile deep
serahkan scan --target http://example.com --profile deep --include-http --include-oob
```

#### `web-full`

Comprehensive web-vulnerability hunting. Enables headless browser templates, DAST/fuzz scanning, out-of-band interaction, and includes the `fuzz` default-ignored tag. Captures raw HTTP request/response data.

```cmd
serahkan scan --target http://example.com --profile web-full
serahkan scan --target http://example.com --profile web-full --cookie "session=abc123"
```

#### `benchmark-web`

Specialized profile optimized for public vulnerable demo environments (e.g., DVWA, WebGoat, testphp). Disables DAST isolation and the `-itags fuzz` restriction to ensure Nuclei loads the complete set of standard HTTP vulnerability templates without filtering. Uses elevated connection retries (3) to handle unstable demo endpoints gracefully. The `web-vulns` focus is applied by default, injecting `xss`, `sqli`, `lfi`, `rfi`, `ssrf`, `ssti`, and `redirect` tags.

```cmd
serahkan scan --target http://testphp.vulnweb.com/ --profile benchmark-web
serahkan scan --target http://testphp.vulnweb.com/ --profile benchmark-web --output json
```

#### `brutal-aggressive`

Maximum throughput coverage. Sets full severity inclusion, 600-second scan cap, elevated concurrency (300) and rate limit (800), headless and DAST enabled, out-of-band interaction active, and 3 retries. The default-ignored tag set is broadened to `cve`, `sqli`, `xss`, `lfi`, `rce`, `misconfig`, and `exposure` to maximize template loading across core web-application vulnerability classes.

```cmd
serahkan scan --target http://example.com --profile brutal-aggressive --skip-ai
serahkan scan --target http://example.com --profile brutal-aggressive --output json
```

## Focus Presets

The `--focus` flag applies a targeted template or tag injection on top of the active profile. Presets are additive -- they append tags or template paths without removing flags set by the profile.

| Preset | Behavior |
|---|---|
| `exposures` | Appends `-t http/exposures` to run exposure-detection templates. |
| `web-vulns` | Appends `-tags xss,sqli,lfi,rfi,ssrf,ssti,redirect` for broad web-vulnerability coverage. |
| `fuzz` | Enables DAST, adds `-itags fuzz`, and appends `-tags fuzz` for parameter-fuzzing templates. |
| `misconfig` | Appends `-tags misconfig,exposure,config` for misconfiguration-focused scanning. |
| `cves` | Appends `-t http/cves` to run HTTP-layer CVE templates. |

```cmd
serahkan scan --target http://example.com --focus web-vulns
serahkan scan --target http://example.com --focus cves --severity high,critical
serahkan scan --target http://example.com --focus misconfig --profile deep
```

## Advanced Observability Flags

### `--show-nuclei-command`

Prints the exact Nuclei argument array constructed by the wrapper. When this flag is active, the internal `-silent` flag is dynamically removed from the execution arguments, exposing Nuclei's template-loading logs, match notifications, and stderr diagnostics in real time.

```cmd
serahkan scan --target http://example.com --show-nuclei-command
serahkan scan --target http://example.com --profile benchmark-web --show-nuclei-command --output json
```

Use this to verify which flags the wrapper injects, diagnose template-starvation issues, or confirm that specific tags and templates are being loaded by Nuclei.

### `--parity-mode`

Strips the wrapper down to minimal argument construction: no concurrency/rate-limit overrides, no `-no-banner`, no `-omit-raw`, and no `-irr`. Designed for direct comparison between wrapper-managed execution and raw Nuclei behavior when diagnosing unexpected output.

```cmd
serahkan scan --target http://example.com --parity-mode --show-nuclei-command
serahkan scan --target http://example.com --parity-mode --output json
```

### `--concurrency` and `--rate-limit`

Global CLI flags that override profile-hardcoded concurrency and rate-limit values. When explicitly passed via the terminal, these values take precedence over any defaults set by the active profile (e.g., brutal-aggressive's 300/800). When not set, the profile defaults apply normally.

```cmd
serahkan scan --target http://example.com --profile brutal-aggressive --concurrency 100 --rate-limit 200
serahkan scan --target http://example.com --concurrency 50 --rate-limit 100
```

This allows fine-tuning throughput without modifying profiles, useful for targets with strict rate-limiting or resource-constrained environments.

## URL Sanitization

The target URL is automatically pre-processed before being passed to Nuclei. Tracking and challenge tokens commonly injected by CDNs, analytics platforms, and security challenges are stripped to prevent template mismatches and ensure clean execution strings.

Detected and removed tokens include:

- Cloudflare challenge tokens (`__cf_chl_f_tk`, `__cf_chl_rt`, `challenge`)
- Social media tracking (`fbclid`, `gclid`, `msclkid`)
- Marketing automation (`_hsenc`, `_hsm`, `oly_enc_id`, `ss_compile`, `vero_id`)
- Generic tracking parameters (`trk`)

```cmd
:: Tracking tokens are stripped automatically
serahkan scan --target "http://example.com/?__cf_chl_f_tk=abc123&page=1"
:: Effective target: http://example.com/?page=1

:: Clean URLs pass through unchanged
serahkan scan --target http://example.com
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

```cmd
serahkan scan --target http://example.com --profile benchmark-web --output json
:: waf_blocked will show count of intercepted findings
```

## Interactive Prompt Behavior

When the `--crawl` flag is active and the Katana crawler extracts 0 or 1 unique URL from the target, the scanner pauses and presents an interactive prompt to the user:

```cmd
[WARN] Crawler extracted 0 unique sub-pages (target might be protected).
[?] Crawler yielded no new paths. Force scan the primary target URL instead? (y/N):
```

Entering `y` or `yes` proceeds with a standard single-target scan against the original URL without crawling. Any other input (including pressing Enter for the default `N`) aborts the scan, returning a `scan aborted by user` message. This behavior prevents unnecessary scans against WAF-protected or single-page targets where multi-page crawling would not add value.

## Output Schemas

### Text Mode

Default output. Prints an ASCII summary with target, finding count, AI status, duration, and the full AI defensive analysis report. When no findings match, the output lists active diagnostic reasons (disabled OOB, severity filtering, unauthenticated state, scan timeout caps, etc.).

```cmd
serahkan scan --target http://example.com --profile balanced
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

```cmd
serahkan scan --target http://example.com --output json
serahkan scan --target http://example.com --profile benchmark-web --output json > report.json
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
| `--crawl` | `false` | Enable optional programmatic multi-phase web crawling via Katana before the core scan phase. |
| `--verbose`, `-v` | `false` | Enable verbose debug logging on stderr. |

### Configuration Precedence

```
CLI Flags > config.yaml > Profile Defaults > Code Defaults
```

Supported environment variables: `SERAHKAN_AI_ENDPOINT`, `SERAHKAN_AI_MODEL`, `SERAHKAN_AI_API_KEY`, `SERAHKAN_CONFIG`.

### Recommended Usage

```cmd
:: Quick baseline check
serahkan scan --target http://example.com --profile fast

:: Routine balanced scan with AI analysis
serahkan scan --target http://example.com

:: Deep scan with full web coverage and OOB
serahkan scan --target http://example.com --profile deep --include-oob

:: Web vulnerability hunting with headless and DAST
serahkan scan --target http://example.com --profile web-full

:: Benchmark a public vulnerable demo target
serahkan scan --target http://testphp.vulnweb.com/ --profile benchmark-web

:: Maximum coverage for authorized internal targets
serahkan scan --target http://internal-app.local --profile brutal-aggressive --skip-ai

:: Override concurrency and rate-limit for constrained targets
serahkan scan --target http://example.com --profile brutal-aggressive --concurrency 100 --rate-limit 200

:: Authenticated scan with session cookie
serahkan scan --target http://example.com --profile web-full --cookie "session=abc123"

:: Verify wrapper argument construction
serahkan scan --target http://example.com --show-nuclei-command

:: Raw Nuclei parity comparison
serahkan scan --target http://example.com --parity-mode --show-nuclei-command --output json

:: CVE-focused scan with custom severity
serahkan scan --target http://example.com --focus cves --severity high,critical

:: JSON report saved to file
serahkan scan --target http://example.com --profile balanced --output json > scan-report.json
```
