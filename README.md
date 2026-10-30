# Isolated Security Scanner Workspace

Workspace terisolasi untuk melakukan analisis keamanan statis (*Static Application Security Testing* / SAST), audit dependensi rantai pasok (*supply chain*), dan inspeksi repositori malware tanpa perlu melakukan `git clone` atau eksekusi kode berbahaya di mesin lokal.

Repositori ini memanfaatkan **Claude Code** dan **GitHub MCP Server** (*Model Context Protocol*) untuk membaca dan menganalisis kode secara remote via API resmi GitHub.

---

## 📁 Struktur Direktori

```text
scan-repo/
├── .gitignore              # Proteksi token, node_modules, dan hasil scan
├── security-scanner.md     # System instructions dan operational guardrails untuk scanner
├── README.md               # Dokumentasi setup dan panduan penggunaan
├── reports/                # Tempat menyimpan berkas laporan audit (.md / .json)
└── rules/                  # Berkas signature deteksi (Semgrep, YARA, Regex)
```

---

## 🛡️ Prinsip Keamanan & Guardrails

Dalam menjalankan inspeksi kode malware atau PoC berbahaya:
1. **No Local Execution:** Dilarang menjalankan skrip instalasi paket (`npm install`, `bun install`, `pip install`) atau menjalankan biner repositori target.
2. **API-Only Fetching:** Seluruh pembacaan pohon direktori dan berkas dilakukan secara remote menggunakan fungsi GitHub MCP (`get_file_contents`, `list_directory_contents`).
3. **Read-Only Scope:** Token GitHub yang digunakan dibatasi hanya untuk akses repositori publik (*read-only*), tanpa hak akses tulis (*write/admin*).

---

## 🚀 Konfigurasi & Persiapan

### 1. Buat Berkas `.env`
Buat berkas `.env` di root direktori (berkas ini sudah diabaikan oleh `.gitignore`):

```env
GITHUB_PERSONAL_ACCESS_TOKEN=ghp_yourPersonalAccessTokenHere
```

> **Catatan:** Buat Personal Access Token (classic) di GitHub dengan izin minimal: `public_repo`.

### 2. Konfigurasi MCP Server (`.mcp.json`)
Buat berkas `.mcp.json` di root direktori untuk mengaktifkan server GitHub MCP pada Claude Code:

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_yourPersonalAccessTokenHere"
      }
    }
  }
}
```

---

## 🔍 Cara Menjalankan Pemindaian

1. Buka terminal di direktori proyek ini:
   ```powershell
   cd scan-repo
   ```

2. Jalankan Claude Code CLI:
   ```powershell
   claude
   ```

3. Jalankan prompt pemindaian dengan mengaitkan panduan audit di `security-scanner.md`:
   ```text
   Gunakan instruksi di @security-scanner.md dan manfaatkan GitHub MCP server.
   Lakukan triage keamanan pada repository "owner/target-repo":
   1. Baca manifest package.json dan bunfig.toml secara remote.
   2. Petakan struktur direktori src/ dan scripts/.
   3. Jangan unduh biner dan jangan jalankan kode apapun.
   4. Tulis hasil temuan ke dalam reports/target-repo-analysis.md.
   ```