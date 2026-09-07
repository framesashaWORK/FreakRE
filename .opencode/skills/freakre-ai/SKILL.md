---
name: freakre-ai
description: Use when analyzing binaries with FreakRE — PE/ELF/Mach-O/DEX/WASM/COFF scanning, decompilation, xrefs, entropy, imports, YARA, shellcode, scripts (PS1/VBS/AU3/AHK/BAT), PDF, .NET, Python, firmware (UEFI/BIOS), memory dumps, or AI-driven RE via CLI JSON and HTTP API on :8080
---

# FreakRE AI Skill

FreakRE — модульный RE-фреймворк на Rust. Этот скилл делает его доступным для ИИ-агентов через CLI (JSON) и HTTP API (`http://localhost:8080`).

## Когда использовать

- `просканируй бинарник`, `анализ PE`, `проверь на малварь/бэкдор/шеллкод`
- `декомпилируй функцию`, `покажи CFG`, `найди xref`, `энтропия`, `импорты`
- `запусти freakRE`, `freakre api`, `freakre server`, `порт 8080`
- `проверь скрипт` (PowerShell/VBS/AutoIt/AHK/Batch), `проанализируй PDF`, `проверь .NET`
- `анализ прошивки` (UEFI/BIOS), `дамп памяти` (Minidump), `Python .pyc/PyInstaller`
- `ARM shellcode`, `AArch64 shellcode`, `архитектура шеллкода`

## Быстрый старт: CLI (без сервера)

Основной бинарник — `freakre-scanner` (имя crate), собирается как `freakre` / `bibleteks`:

```bash
# Сборка
cargo build --release -p freakre-scanner

# Сканирование (человеко-читаемо)
./target/release/freakre suspicious.exe
./target/release/freakre /path/to/samples/ --findings-only

# JSON для ИИ — главный способ для агентов
./target/release/freakre -f json target.exe > report.json
./target/release/freakre -f json -r rules.yar target.exe
./target/release/freakre -f json --min-severity high ./samples/

# CSV
./target/release/freakre -f csv target.exe > results.csv
```

### JSON схема `FileReport` (`scanner/src/report.rs:59`)

```json
{
  "path": "sample.exe",
  "size": 12345,
  "sha256": "...", "md5": "...",
  "file_type": "PE32 / PE32+ / ELF / Mach-O / WASM / DEX / COFF / Script/PowerShell / Script/AutoIt / Script/AutoHotkey / Script/VBScript / Script/Batch / PDF / .NET / BIOS/MBR / UEFI / Minidump / unknown",
  "suspicion_score": 0.0,
  "verdict": "Clean | Suspicious | Malicious | Error",
  "findings": [{"severity": "Critical|High|Medium|Low|Info", "module": "pe-parser", "rule_id": "PE_RWX_SECTION", "description": "...", "details": "..."}],
  "strings_found": 123,
  "sections_entropy": [{"name": ".text", "entropy": 7.2, "classification": "packed"}],
  "pe_info": {"machine": "...", "entry_point": "0x401000", "is_dotnet": false, "has_overlay": false},
  "elf_info": {...}, "macho_info": {...}, "wasm_info": {...}, "dex_info": {...},
  "script_info": {"kind": "PowerShell|AutoIt|AutoHotkey|Batch|VBScript", "obfuscation_score": 0.3},
  "pdf_info": {"has_javascript": true, "has_openaction": true, "finding_count": 3},
  "dotnet_info": {"clr_version": "v4.0.30319", "num_method_refs": 123},
  "pyc_info": {"python_version": "3.8", "is_pyinstaller": false},
  "firmware_info": {"kind": "UEFI Volume|Mbr|GPT Disk", "embedded_pe_count": 1},
  "memdump_info": {"kind": "Minidump|ELF Core|Mach-O Core", "embedded_pe_count": 0},
  "dll_info": {"dll_type": "System|COM/ActiveX|Injectable|Resource-only|WDM Driver|.NET|Native", "architecture": "x64", "export_count": 1636, "is_com": false, "is_injectable": false, "calling_conventions": ["MicrosoftX64"], "dll_name": "KERNEL32.dll"},
  "architecture_info": {"arch": "AArch64", "endian": "little", "bitness": 64, "confidence": 0.9},
  "backdoor_report": {"risk_score": 0.5, "verdict": "...", "mitre_techniques": ["T1059"]},
  "shellcode_report": {"verdict": "...", "patterns_detected": [...]},
  "xref_summary": {"total_xrefs": 10, "correlated_pairs": 1},
  "cfg_summary": {"num_blocks": 5, "num_edges": 6, "anomalies": [...]},
  "signature_summary": {"libraries_found": ["zlib"], "compiler": "MSVC"},
  "ml_classification": {"classification": "Malicious", "confidence": 0.9, "top_features": [...]},
  "scan_duration_ms": 42
}
```

**Для ИИ-агента:** всегда используй `-f json`, парси `verdict` + `suspicion_score` + `findings`. Exit codes: `0=Clean, 1=Suspicious, 2=Malicious`.

## HTTP API на :8080 (`freakre-server`)

### Запуск

```bash
# Собрать и запустить
cargo build --release -p freakre-server
./target/release/freakre-server --port 8080
# или
cargo run -p freakre-server -- --port 8080 --host 127.0.0.1

# Проверка
curl http://localhost:8080/health
curl http://localhost:8080/api/capabilities
```

### Эндпоинты

| Метод | Путь | Описание |
|-------|------|----------|
| `GET` | `/health` | `{"status":"ok","version":"0.1.0"}` |
| `GET` | `/api/capabilities` | Список возможностей и модулей |
| `POST` | `/api/scan` | Сканировать файл (JSON / multipart) |
| `POST` | `/api/scan/base64` | Сканировать base64-данные |
| `POST` | `/api/strings` | Только извлечение строк |
| `POST` | `/api/entropy` | Только энтропия секций |
| `POST` | `/api/decompile` | Декомпиляция (если собран с `decompiler`) |
| `POST` | `/api/xrefs` | Cross-references |

#### `POST /api/scan`

```bash
# Вариант 1: локальный путь (сервер имеет доступ к FS)
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"path": "C:/samples/suspicious.exe", "min_severity": "info"}'

# Вариант 2: загрузка файла (multipart)
curl -X POST http://localhost:8080/api/scan \
  -F "file=@suspicious.exe" -F "min_severity=high"

# Вариант 3: base64 (удобно для ИИ без файловой системы)
curl -X POST http://localhost:8080/api/scan/base64 \
  -H "Content-Type: application/json" \
  -d '{"filename": "sample.exe", "data_base64": "TVqQAAMAAAAEAAAA..."}'
```

Ответ — тот же `FileReport` JSON, что и в CLI. Для директорий — массив `FileReport[]` + `ScanSummary`.

#### `POST /api/strings`, `/api/entropy`, `/api/xrefs`

```bash
curl -X POST http://localhost:8080/api/strings -F "file=@sample.exe"
curl -X POST http://localhost:8080/api/entropy -F "file=@sample.exe"
curl -X POST http://localhost:8080/api/xrefs -F "file=@sample.exe"
```

#### `POST /api/decompile`

```bash
curl -X POST http://localhost:8080/api/decompile \
  -F "file=@sample.exe" -F "address=0x401000" -F "arch=x86_64"
# Ответ: {"address":"0x401000","c_pseudocode":"int main() { ... }","ir":"..."}
```

## Библиотека для агентов (Rust)

```rust
use freakre_scanner::Scanner;
use std::path::Path;

let scanner = Scanner::new(); // или .with_yara_rules(Path::new("rules.yar"))?
let report = scanner.scan_file(Path::new("sample.exe"));
println!("{}", report.verdict); // Clean/Suspicious/Malicious
```

## Модули и что спрашивать у ИИ

| Модуль | Сигналы | Вопрос для ИИ |
|--------|---------|---------------|
| `pe-parser` | RWX, TLS callbacks, overlay, .NET | "Есть ли RWX секции?" |
| `import-analyzer` | injection, persistence, anti-debug | "Какие техники MITRE?" |
| `entropy-rs` | >7.0 = packer | "Упакован ли файл?" |
| `backdoor-analyzer` | C2, beacon | "Есть бэкдор?" |
| `shellcode-analyzer` | GetPC, XOR, ARM/AArch64 | "Есть шеллкод? Какая архитектура?" |
| `cfg-builder` | аномалии CFG | "Есть обфускация?" |
| `yara-lite` | правила | "Сматчилось YARA?" |
| `ml-detection` | классификация | "ML вердикт?" |
| `decompiler` | C-псевдокод | "Что делает функция 0x401000?" |
| `script-analyzer` | PS1/VBS/AU3/AHK/BAT обфускация | "Есть вредоносный скрипт?" |
| `pdf-analyzer` | JavaScript, OpenAction, encryption | "PDF с кодом?" |
| `dotnet-analyzer` | CLR, reflection, native API | ".NET с подозрительным кодом?" |
| `pyc-parser` | Python bytecode, PyInstaller | "Python-пакет или .pyc?" |
| `firmware-analyzer` | UEFI, BIOS, GPT/MBR, embedded PE | "Прошивка с вложенным PE?" |
| `memdump-analyzer` | Minidump, in-memory PE | "Дамп памяти с кодом?" |
| `dll-analyzer` | DLL type, COM, injectable, SSP/AP | "Какой тип DLL? Есть COM/инжект?" |

## Паттерн для ИИ-агента (рекомендуемый workflow)

1. **Triage:** `POST /api/scan` (или CLI `-f json`) → проверь `verdict`/`score`
2. **Углубление:** если `Suspicious/Malicious` → смотри `findings` по `severity DESC`, `sections_entropy`, `xref_summary.correlated_pairs`
3. **Объяснение:** `pe_info` + `backdoor_report.mitre_techniques` → сформулируй отчет человеку
4. **Декомпиляция:** `POST /api/decompile` для подозрительных функций (из `cfg_summary`/`signature_summary`)
5. **Скриптинг:** используй `freakre-script` (sandboxed Lua DSL) или `scripting` (Rhai) для автоматизации

## Ошибки

- `FileReport.verdict == "Error"` → файл не читается
- HTTP `400` → неверный запрос (`path` не существует)
- HTTP `413` → файл слишком большой (лимит 100MB)
- `decompiler` не собран → `{"error":"decompiler feature not enabled"}`

## Где код

- Сканер: `scanner/src/scanner.rs:29`, `scanner/src/main.rs:19`, `scanner/src/report.rs:59`
- HTTP сервер: `freakre-server/src/main.rs`
- Этот скилл: `.opencode/skills/freakre-ai/SKILL.md`
- Документация: `README.md:46`, `RE_COMPONENTS.md:1`
