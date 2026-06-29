# serahkan-cli

`serahkan-cli` adalah CLI Go untuk menjalankan scan Nuclei, memfilter temuan, lalu meminta analisis defensif dari local LLM.

## Fitur

- `scan` untuk menjalankan Nuclei dan analisis AI
- `scan --output json` untuk output machine-readable
- `doctor` untuk cek dependency lokal
- `config` untuk menyimpan konfigurasi AI secara persisten
- `version` untuk metadata build/runtime

## Kebutuhan

- `nuclei` atau `nuclei.exe` tersedia di workspace atau `PATH`
- endpoint AI lokal aktif, default: `http://127.0.0.1:1234/v1/chat/completions`

## Build

Development:

```powershell
go run . version
go run . doctor
go run . scan --target http://example.com
```

Build biasa:

```powershell
go build -o serahkan.exe .
.\serahkan.exe version
```

Build dengan metadata:

```powershell
$env:SERAHKAN_VERSION="0.1.0"
$env:SERAHKAN_COMMIT="abc1234"
.\scripts\build.ps1
.\serahkan.exe version
```

## Konfigurasi

Precedence konfigurasi:

```text
flag > env > config file > default
```

Environment variable yang didukung:

- `SERAHKAN_AI_ENDPOINT`
- `SERAHKAN_AI_MODEL`
- `SERAHKAN_AI_API_KEY`
- `SERAHKAN_CONFIG` untuk override path config file

Contoh config persisten:

```powershell
go run . config set ai.endpoint http://127.0.0.1:1234/v1/chat/completions
go run . config set ai.model qwen2.5-coder-1.5b-instruct
go run . config view
```

## Commands

### `scan`

Contoh:

```powershell
go run . scan --target http://example.com
go run . scan --target http://example.com --severity high,critical
go run . scan --target http://example.com --output json
go run . scan --target http://example.com --ai-model llama-3.2-3b-instruct-uncensored
```

Flag utama:

- `--target`, `-t` target URL
- `--severity` daftar severity dipisah koma
- `--timeout` timeout request Nuclei
- `--retries` retry scan Nuclei
- `--no-interactsh` disable template OOB
- `--ai-endpoint` override endpoint AI
- `--ai-model` override model AI
- `--ai-api-key` override API key AI
- `--ai-timeout` timeout AI
- `--limit` batas jumlah finding yang dianalisis AI
- `--output text|json`

Mode `text` menampilkan laporan ASCII. Mode `json` mengeluarkan objek JSON dengan target, severity, jumlah temuan, status AI, analisis, dan daftar finding.

### `doctor`

```powershell
go run . doctor
```

`doctor` memeriksa:

- resolusi binary `nuclei`
- reachability endpoint AI aktif

### `config`

```powershell
go run . config view
go run . config set ai.endpoint http://127.0.0.1:1234/v1/chat/completions
go run . config set ai.model qwen2.5-coder-1.5b-instruct
go run . config unset ai.api_key
```

Key yang didukung:

- `ai.endpoint`
- `ai.model`
- `ai.api_key`

### `version`

```powershell
go run . version
```

Menampilkan:

- versi aplikasi
- commit build
- tanggal build
- versi Go
- OS/arch
