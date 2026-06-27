# serahkan-cli 🛡️🤖

[![Go Version](https://img.shields.io/github/go-mod/go-version/Zyrexnn/serahkan-cli)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**serahkan-cli** adalah sebuah AI-powered Bug Bounty & Pentesting CLI wrapper yang ditulis menggunakan bahasa Go (Golang). Alat ini dirancang untuk mengorkestrasi alat pemindaian kerentanan standar industri seperti **Nuclei**, menyaring hasilnya secara otomatis untuk menghemat memori, dan mengirimkan payload tersebut ke **Local LLM** (Ollama atau LM Studio) untuk menghasilkan analisis keamanan secara mendalam dan rekomendasi perbaikan kode secara instan.

---

## 🚀 Fitur Utama

- **Orkestrasi Otomatis:** Menjalankan pemindaian Nuclei secara terprogram dari CLI.
- **Log Filtering & Sanitization:** Secara otomatis menyaring log hasil scan Nuclei dan membuang tingkat bahaya rendah (`low` / `info`) agar tidak memenuhi konteks LLM dan menghindari masalah kehabisan memori (*Out Of Memory* / OOM).
- **Integrasi Local LLM:** Berkomunikasi secara sinkron melalui HTTP client bawaan menuju local LLM server (LM Studio / Ollama).
- **Anti-Censorship System Prompt:** Menggunakan prompt instruksi khusus yang memaksa LLM lokal memberikan analisis teknis murni tanpa penolakan (uncensored security analysis).
- **Output Laporan Terstruktur:** Menghasilkan laporan bergaya ASCII yang mencakup:
  - Profil Target & Status Risiko
  - Analisis Root Cause (Penyebab Utama)
  - Langkah Validasi Manual Proof of Concept (PoC) dengan perintah `curl` asli.
  - Playbook Remediasi & Pengerasan (*Hardening*) Kode secara nyata.

---

## 📊 Arsitektur Sistem

Aliran data pada `serahkan-cli` berjalan sebagai *single-binary conductor* yang sinkron:

```text
[Input Pengguna] ──> [Cobra CLI] ──> [Proses Sub-aplikasi Nuclei]
                                               │
                                               ▼ (Output JSONL)
[Parser & Log Filter] 🚀 ──────────────────────┘
   │ (Menghapus log severity rendah/info)
   ▼
[Hasil Tersaring (Vulnerability Name, Host, Snippet Request/Response)]
   │
   ▼
[Client AI Lokal via HTTP] ──> [LM Studio / Ollama Server]
   │
   ▼ (Stream Output Laporan Keamanan)
[Tampilan Terminal Akhir]
```

---

## 💻 Spesifikasi & Batasan Perangkat Keras

Aplikasi ini dioptimalkan khusus untuk berjalan pada mesin lokal dengan VRAM terbatas:
- **Target GPU:** NVIDIA GeForce RTX 2050 (4GB VRAM) atau setara.
- **Rekomendasi Local LLM:**
  - `qwen2.5-coder-1.5b-instruct` (Default, sangat cepat dan ringan).
  - `llama-3.2-3b-instruct-uncensored` (Alternatif yang seimbang untuk akurasi).
- **Optimalisasi Memori:** Seluruh proses parsing request-response HTTP dari scanner telah dibatasi agar hanya mengirim data esensial ke LLM demi mencegah latensi berlebih.

---

## 🛠️ Persyaratan Sistem

Sebelum menjalankan `serahkan-cli`, pastikan sistem Anda memenuhi komponen berikut:

1. **Nuclei Scanner:**
   - Aplikasi akan otomatis mencari file `nuclei` atau `nuclei.exe` di direktori kerja (workspace root).
   - Jika tidak ditemukan, ia akan menggunakan perintah `nuclei` global yang terdaftar di `PATH` sistem Anda.
2. **Local LLM Server (LM Studio / Ollama):**
   - Pastikan server LLM lokal Anda aktif dan berjalan di alamat default: `http://127.0.0.1:1234/v1/chat/completions`.
   - Konfigurasi default menggunakan model: `qwen2.5-coder-1.5b-instruct`.

---

## 📦 Instalasi

Untuk mengompilasi dan membangun aplikasi ini dari kode sumber, ikuti langkah-langkah berikut:

```bash
# 1. Clone repositori ini
git clone https://github.com/Zyrexnn/serahkan-cli.git
cd serahkan-cli

# 2. Unduh dependensi Go
go mod download

# 3. Build executable binary
go build -o serahkan
```

---

## 📖 Panduan Perintah (Command List)

Perintah utama dari `serahkan-cli` adalah perintah `scan`.

### 1. Perintah `scan`
Menjalankan pemindaian Nuclei terhadap target tertentu dan menganalisis temuannya menggunakan AI.

#### Sintaksis:
```bash
./serahkan scan --target <url_target> [flags]
```

#### Flags:
| Flag | Shortcut | Tipe Data | Deskripsi | Default |
| :--- | :--- | :--- | :--- | :--- |
| `--target` | `-t` | `string` | **(Wajib)** URL target pemindaian (contoh: `http://example.com`) | |
| `--severity` | | `string` | Filter tingkat bahaya kerentanan yang ingin dianalisis (dipisahkan koma) | `medium,high,critical` |
| `--timeout` | | `int` | Timeout dalam detik per request HTTP Nuclei | `30` |
| `--retries` | | `int` | Jumlah percobaan ulang untuk pemindaian Nuclei | `2` |
| `--verbose` | `-v` | `bool` | Tampilkan log debugging verbose di stderr | `false` |
| `--no-interactsh` | | `bool` | Nonaktifkan template OOB (out-of-band) untuk mengurangi dependensi | `false` |
| `--ai-endpoint` | | `string` | Endpoint API AI lokal (override environment variable) | `http://127.0.0.1:1234/v1/chat/completions` |
| `--ai-model` | | `string` | Nama model AI yang digunakan | `qwen2.5-coder-1.5b-instruct` |
| `--ai-api-key` | | `string` | API key untuk endpoint AI (diperlukan untuk endpoint cloud) | |
| `--ai-timeout` | | `int` | Timeout dalam detik untuk respons AI | `120` |
| `--limit` | | `int` | Jumlah maksimal temuan yang dikirim ke AI untuk analisis | `10` |

#### Environment Variables:
Anda juga dapat mengonfigurasi AI melalui environment variable:

| Variable | Deskripsi |
| :--- | :--- |
| `SERAHKAN_AI_ENDPOINT` | Endpoint API AI lokal |
| `SERAHKAN_AI_MODEL` | Nama model AI |
| `SERAHKAN_AI_API_KEY` | API key untuk AI endpoint |

#### Contoh Perintah:
```bash
# Memindai target dengan severity bawaan (medium, high, critical)
./serahkan scan -t http://testphp.vulnweb.com

# Memindai target hanya untuk kerentanan tingkat tinggi dan kritis
./serahkan scan --target http://testphp.vulnweb.com --severity high,critical

# Memindai dengan model AI berbeda
./serahkan scan -t http://example.com --ai-model llama-3.2-3b-instruct-uncensored

# Memindai dengan timeout yang lebih lama dan limit temuan lebih banyak
./serahkan scan -t http://example.com --timeout 60 --limit 20

# Mengaktifkan mode verbose untuk debugging
./serahkan scan -t http://example.com --verbose
```

---

## 📝 Contoh Output Laporan AI

Setelah pemindaian selesai dan menemukan celah keamanan yang sesuai dengan filter, `serahkan-cli` akan menampilkan output seperti ini di terminal Anda:

```text
 [SCAN] Running automated vulnerability scanning on http://testphp.vulnweb.com...
 [PARSER] Log filtering completed. Analyzing severity payload...
 [AI] Local LLM is generating defensive analysis and remediation code...

================================================================================
                       AI DEFENSIVE ANALYSIS REPORT                             
================================================================================
+-------------------------------------------------------------------------+
|                      AI DEFENSIVE ANALYSIS REPORT                       |
+-------------------------------------------------------------------------+

[=] TARGET PROFILE
    - Target Host : testphp.vulnweb.com
    - Risk Status : HIGH ALERT

[=] ROOT CAUSE ANALYSIS
    Target terdeteksi rentan terhadap Cross-Site Scripting (XSS) akibat kurangnya
    sanitasi dan encoding pada parameter input masukan pengguna sebelum dirender
    kembali ke dalam halaman HTML.

[=] ACTIVE VULNERABILITY AUDIT & MANUAL VALIDATION
===========================================================================
[!] FINDING 1: Cross-Site Scripting (Reflected)
    - Risk Level  : High
    - Technical Overview: Parameter search rentan terhadap injeksi skrip HTML/JS.
    - Manual Proof-of-Concept Validation:
      * Execute Command:
        $ curl -G "http://testphp.vulnweb.com/search.php" --data-urlencode "query=<script>alert(1)</script>"
      * Expected Response Indicator: <script>alert(1)</script> ditemukan langsung di dalam body response HTML.
---------------------------------------------------------------------------

[=] REMEDIATION & HARDENING PLAYBOOK
===========================================================================
[*] ACTION 1: Implement Output Encoding
    - Targeted Component: PHP Application (search.php)
    - Implementation Code:
      <?php
      // Gunakan htmlspecialchars untuk melakukan encoding sebelum output dirender
      $allowed_query = htmlspecialchars($_GET['query'], ENT_QUOTES, 'UTF-8');
      echo "Hasil pencarian untuk: " . $allowed_query;
      ?>
================================================================================
```

---

## 📁 Struktur Direktori Proyek

```text
serahkan-cli/
├── cmd/
│   ├── root.go         # Konfigurasi basis Cobra CLI
│   └── scan.go         # Implementasi perintah 'serahkan scan' beserta flags
├── internal/
│   ├── ai/             # Client HTTP untuk berkomunikasi dengan Local LLM
│   ├── parser/         # Parser log JSONL Nuclei & penyaringan tingkat bahaya
│   └── runner/         # Logic eksekusi subprocess nuclei / nuclei.exe
├── go.mod              # Modul definisi Go
├── go.sum              # Checksum dependensi Go
└── prd.md              # Dokumen persyaratan produk (Product Requirement Document)
```

---

## ⚖️ Penafian (Disclaimer)
Alat ini dibuat hanya untuk tujuan pendidikan dan pengujian keamanan yang sah (*authorized pentesting* / *bug bounty*). Penggunaan alat ini untuk menyerang target tanpa izin tertulis dari pemilik sistem adalah ilegal dan dapat dikenakan sanksi hukum. Pembuat tidak bertanggung jawab atas penyalahgunaan atau kerusakan yang disebabkan oleh alat ini.
