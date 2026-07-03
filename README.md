# serahkan-cli

`serahkan-cli` is a Go CLI for running Nuclei scans, filtering findings, and requesting defensive analysis from a local LLM.

## Features

- `scan` to run Nuclei and AI analysis
- `scan --output json` for machine-readable output
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

Examples:

```powershell
go run . scan --target http://example.com
go run . scan --target http://example.com --severity high,critical
go run . scan --target http://example.com --output json
go run . scan --target http://example.com --ai-model llama-3.2-3b-instruct-uncensored
```

Main flags:

- `--target`, `-t` target URL
- `--severity` comma-separated severity list
- `--timeout` Nuclei request timeout
- `--retries` Nuclei scan retries
- `--no-interactsh` disable OOB templates
- `--ai-endpoint` override AI endpoint
- `--ai-model` override AI model
- `--ai-api-key` override AI API key
- `--ai-timeout` AI timeout
- `--limit` maximum number of findings sent for AI analysis
- `--output text|json`

`text` mode prints an ASCII report. `json` mode returns a JSON object containing the target, severity, finding count, AI status, analysis, and finding list.

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
