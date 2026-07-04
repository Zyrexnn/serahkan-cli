# serahkan-cli

`serahkan-cli` is a Go CLI for running Nuclei scans, filtering findings, and requesting defensive analysis from a local LLM.

## Features

- `scan` to run Nuclei and AI analysis
- `scan --output json` for machine-readable output
- `scan --profile fast|balanced|deep|web-full` for speed and coverage presets
- `doctor` to check local dependencies
- `config` to persist AI configuration
- `version` to show build and runtime metadata

## Requirements

- `nuclei` or `nuclei.exe` must be available in the workspace or on `PATH`
- a local AI endpoint must be running, default: `http://127.0.0.1:1234/v1/chat/completions`

## Build

Development:

```powershell
go run . version
go run . doctor
go run . scan --target http://example.com
```

Standard build:

```powershell
go build -o serahkan.exe .
.\serahkan.exe version
```

Build with metadata:

```powershell
$env:SERAHKAN_VERSION="0.1.0"
$env:SERAHKAN_COMMIT="abc1234"
.\scripts\build.ps1
.\serahkan.exe version
```

## Configuration

Configuration precedence:

```text
flag > env > config file > default
```

Supported environment variables:

- `SERAHKAN_AI_ENDPOINT`
- `SERAHKAN_AI_MODEL`
- `SERAHKAN_AI_API_KEY`
- `SERAHKAN_CONFIG` to override the config file path

Persistent config example:

```powershell
go run . config set ai.endpoint http://127.0.0.1:1234/v1/chat/completions
go run . config set ai.model qwen2.5-coder-1.5b-instruct
go run . config view
```

## Commands

### `scan`

The scanner now uses faster defaults intended for routine web target checks:

- scan profile default: `balanced`
- Nuclei request timeout default: `10s`
- Nuclei retries default: `0`
- global Nuclei scan timeout default: `120s`
- `interactsh` is disabled by default
- AI timeout default: `25s`
- AI finding limit default: `5`
- raw HTTP request/response capture is disabled by default

Profiles:

- `fast`: high/critical only, shorter timeouts, AI skipped by default
- `balanced`: faster day-to-day default with AI enabled
- `deep`: slower, broader scan with longer timeouts and AI enabled
- `web-full`: broader web bug hunting mode with low/info severity, OOB, headless, DAST, and fuzz-tag inclusion

Examples:

```powershell
go run . scan --target http://example.com
go run . scan --target http://example.com --profile fast
go run . scan --target http://example.com --profile balanced
go run . scan --target http://example.com --profile deep
go run . scan --target http://example.com --profile web-full
go run . scan --target http://example.com --severity high,critical
go run . scan --target http://example.com --skip-ai
go run . scan --target http://example.com --include-http
go run . scan --target http://example.com --scan-timeout 90
go run . scan --target http://example.com --include-low-info --include-oob
go run . scan --target http://example.com --enable-headless --enable-dast
go run . scan --target http://example.com --header "Authorization: Bearer TOKEN"
go run . scan --target http://example.com --cookie "session=abc123"
go run . scan --target http://example.com --tags xss,sqli --type http,headless
go run . scan --target http://example.com --output json
go run . scan --target http://example.com --ai-model llama-3.2-3b-instruct-uncensored
```

Main flags:

- `--target`, `-t` target URL
- `--profile` scan preset: `fast`, `balanced`, `deep`, or `web-full`
- `--severity` comma-separated severity list
- `--include-low-info` include `info` and `low` severities
- `--timeout` Nuclei request timeout
- `--scan-timeout` maximum total duration for the Nuclei phase, in seconds
- `--retries` Nuclei scan retries
- `--no-interactsh` disable OOB templates
- `--include-oob` enable OOB/interactsh templates
- `--enable-headless` enable headless browser templates
- `--enable-dast` enable DAST/fuzz templates
- `--automatic-scan` enable Nuclei technology-based automatic scan. If Nuclei cannot map detected tech to templates, the wrapper falls back to a normal template scan
- `--include-default-ignored-tags` include tags normally ignored by Nuclei, such as `fuzz`
- `--include-http` include raw request/response data from Nuclei (`-irr`)
- `--skip-ai` skip AI analysis and use deterministic fallback reporting
- `--header` custom request header, repeatable
- `--cookie` cookie value sent as a `Cookie` header
- `--cookie-file` file containing headers/cookies for authenticated scans
- `--tags`, `--exclude-tags` select or exclude Nuclei tags
- `--templates`, `--workflows` run specific Nuclei templates or workflows
- `--type` select Nuclei protocol types, such as `http`, `headless`, or `javascript`
- `--show-nuclei-command` print the final Nuclei command used by the wrapper
- `--legacy-compatible` use settings close to the original wrapper behavior
- `--ai-endpoint` override AI endpoint
- `--ai-model` override AI model
- `--ai-api-key` override AI API key
- `--ai-timeout` AI timeout
- `--limit` maximum number of findings sent for AI analysis
- `--output text|json`

`text` mode prints an ASCII report. `json` mode returns a JSON object containing the target, severity, raw finding count, filtered finding count, active scan profile, AI status, analysis, and finding list.

When no findings match the current configuration, the output explains active limitations such as disabled OOB, disabled headless/DAST, unauthenticated scan state, severity filtering, ignored Nuclei tags, and scan timeout caps.

Recommended usage:

```powershell
# Fastest routine scan
go run . scan --target http://example.com --profile fast

# Balanced scan with AI analysis
go run . scan --target http://example.com --profile balanced

# Deep scan when you want broader coverage
go run . scan --target http://example.com --profile deep

# Full web bug hunting mode
go run . scan --target http://example.com --profile web-full

# Authenticated web scan using a session cookie
go run . scan --target http://example.com --profile web-full --cookie "session=abc123"

# Fast scan but still keep AI enabled
go run . scan --target http://example.com --profile fast --skip-ai=false

# Balanced scan with custom AI model
go run . scan --target http://example.com --profile balanced --ai-model qwen2.5-coder-1.5b-instruct
```

### `doctor`

```powershell
go run . doctor
```

`doctor` checks:

- `nuclei` binary resolution
- reachability of the active AI endpoint

### `config`

```powershell
go run . config view
go run . config set ai.endpoint http://127.0.0.1:1234/v1/chat/completions
go run . config set ai.model qwen2.5-coder-1.5b-instruct
go run . config unset ai.api_key
```

Supported keys:

- `ai.endpoint`
- `ai.model`
- `ai.api_key`

### `version`

```powershell
go run . version
```

Shows:

- application version
- build commit
- build date
- Go version
- OS/arch
