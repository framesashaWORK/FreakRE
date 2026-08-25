# 🔥 FreakRE — Полное руководство пользователя

**FreakRE** (Freak Reverse Engineering) — модульный фреймворк для реверс-инжиниринга бинарных файлов, написанный на Rust. Поддерживает PE, ELF, Mach-O, 17 архитектур, встроенный декомпилятор, систему плагинов и скриптинг.

---

## 📋 Оглавление

1. [Установка и сборка](#1-установка-и-сборка)
2. [Быстрый старт](#2-быстрый-старт)
3. [Архитектура проекта](#3-архитектура-проекта)
4. [Desktop UI](#4-desktop-ui)
5. [CLI Scanner](#5-cli-scanner)
6. [Системные плагины](#6-системные-плагины)
7. [Скриптинг (Rhai)](#7-скриптинг-rhai)
8. [Project Database](#8-project-database)
9. [Поддерживаемые архитектуры](#9-поддерживаемые-архитектуры)
10. [Binary Diffing](#10-binary-diffing)
11. [Написание собственных плагинов](#11-написание-собственных-плагинов)
12. [Конфигурация scoring](#12-конфигурация-scoring)
13. [Fuzz-тестирование](#13-fuzz-тестирование)
14. [FAQ](#14-faq)

---

## 1. Установка и сборка

### Требования
- Rust 1.75+ (nightly для fuzzing)
- CMake (для capstone-ffi)
- Git

### Сборка Desktop UI
```bash
cd bibleteks
cargo build --release -p freakre-desktop
./target/release/freakre-desktop
```

### Сборка CLI Scanner
```bash
cargo build --release -p scanner
./target/release/scanner path/to/binary.exe
```

### Сборка с декомпилятором
```bash
cargo build --release -p scanner --features decompiler
```

### Запуск тестов
```bash
cargo test --workspace
```

---

## 2. Быстрый старт

### Анализ одного файла через CLI
```bash
# Базовый анализ
./target/release/scanner malware.exe

# С YARA правилами
./target/release/scanner malware.exe --yara rules.yar

# JSON вывод для автоматизации
./target/release/scanner malware.exe --json > report.json

# Анализ директории
./target/release/scanner ./samples/
```

### Анализ через Desktop UI
1. Запустите `freakre-desktop`
2. Перетащите файл в окно или нажмите **Browse Files**
3. Просмотрите результаты во вкладках:
   - **📊 Dashboard** — обзор всех сканов
   - **📋 Report** — детальная информация о файле
   - **🔍 Findings** — список находок по серьёзности
   - **📈 Entropy** — энтропия секций
   - **🔢 Hex** — hex-дамп с поиском
   - **⚙️ Disasm** — дизассемблирование (Capstone)
   - **🕸 Graph** — визуализация CFG
   - **🧩 Plugins** — системные плагины
   - **⚙️ Advanced** — YARA, настройки

---

## 3. Архитектура проекта

```
freakre/
├── pe-parser/          # Zero-copy PE парсер (TLS, overlay, Rich header, .NET)
├── elf-parser/         # ELF парсер с security warnings
├── macho-parser/       # Mach-O + Fat binary парсер
├── entropy-rs/         # Shannon entropy + классификация
├── str-extract/        # Извлечение строк (ASCII, Unicode, wide)
├── import-analyzer/    # Анализ импортов + behavioral rules
├── yara-lite/          # Совместимый с YARA движок правил
├── backdoor-analyzer/  # MITRE ATT&CK маппинг
├── shellcode-analyzer/ # Детекция shellcode + API hash resolution
├── xrefs/              # Cross-references (string + import)
├── cfg-builder/        # Построение Control Flow Graph
├── func-sigs/          # FLIRT-like сигнатуры функций
├── freakre-ir/         # Универсальный IR (SSA, P-code-like)
│   └── arch.rs         # Реестр 17 архитектур
├── dataflow/           # Live vars, reaching defs, use-def chains
├── type-propagation/   # Type inference из memory access patterns
├── decompiler/         # IR → AST → C pseudocode
├── func-finder/        # Поиск границ функций (prologue scan + recursive descent)
├── project-db/         # Persistent storage (sled) + Undo/Redo
├── type-system/        # C-style типы, struct layout, typedefs
├── scripting/          # Rhai embedded scripting engine
├── plugins/            # Plugin API + dynamic loading
├── sys-plugins/        # 4 встроенных системных плагина
├── diffing/            # Binary diffing (BinDiff-like)
├── ml-detection/       # ML ensemble classifier (8 decision trees)
├── capstone-ffi/       # Multi-arch disassembler bindings
├── scanner/            # CLI orchestrator
├── desktop-ui/         # egui-based GUI
└── fuzz/               # 14 fuzz targets для парсеров
```

---

## 4. Desktop UI

### Вкладки

| Вкладка | Назначение | Горячая клавиша |
|---------|-----------|-----------------|
| Dashboard | Обзор сканов, drag & drop | — |
| Report | Детали файла, хеши, секции | — |
| Findings | Список находок с фильтрацией | — |
| Entropy | График энтропии секций | — |
| Hex | Hex-дамп с поиском и навигацией | — |
| Disasm | Дизассемблирование (Capstone x86/x64) | — |
| Graph | Визуализация CFG с реальными edges | — |
| Plugins | Системные плагины + output log | — |
| Advanced | YARA rules, upcoming features | — |

### Навигация в Hex View
- **Offset field** — ввод адреса (Enter для перехода)
- **Search** — поиск подстроки в байтах
- **⏪ 0x0** — начало файла
- **◀ / ▶** — навигация ±0x100 байт

### Дизассемблирование
- Переключение x86 ↔ x86_64 чекбоксом
- **Go to Entry Point** — прыжок к точке входа PE/Mach-O/ELF
- Capstone-based дизассемблер с fallback LDE

---

## 5. CLI Scanner

### Формат вывода
```
╔══════════════════════════════════════════╗
║  File: malware.exe                       ║
║  Type: PE32+  Size: 245 KB               ║
║  SHA256: a1b2c3...                       ║
║  Score: 87%  Verdict: MALICIOUS          ║
╚══════════════════════════════════════════╝

[CRITICAL] PE_NO_ASLR — PE lacks ASLR
[HIGH]     IMPORT_INJECTION — VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
[HIGH]     HIGH_ENTROPY_SECTION — .text entropy 7.82
[MEDIUM]   PE_TLS_CALLBACKS — 2 TLS callback(s) detected
...
```

### Exit codes
| Code | Значение |
|------|----------|
| 0 | Clean |
| 1 | Suspicious |
| 2 | Malicious |
| 3 | Error |

---

## 6. Системные плагины

FreakRE поставляется с 4 встроенными плагинами:

### 🔐 Crypto Constants Finder (`Ctrl+Shift+C`)
Ищет известные криптографические константы в коде функций:
- AES S-Box / Inverse S-Box
- SHA-256 Init Hash / Round Constants
- MD5 Init Vector
- CRC32 Polynomial
- DES S-Boxes
- Blowfish P-Array
- RC4 Init Permutation
- ChaCha20 / Salsa20 constants
- Camellia, Whirlpool S-Boxes

При обнаружении автоматически ставит label и comment на функцию.

### 📝 String Analyzer (`Ctrl+Shift+S`)
Классифицирует строки по категориям:
- **URLs** (http, https, ftp, ws, wss)
- **API calls** (CreateProcess, VirtualAlloc, LoadLibrary...)
- **Crypto material** (RSA keys, certificates, SSH keys)
- **Paths** (UNC paths, registry keys)
- **IP addresses**
- **Auth tokens** (OAuth, API keys, passwords)

### 🏷 Function Classifier (`Ctrl+Shift+F`)
Классифицирует функции по эвристикам:
- **thunk** — single JMP (import trampoline)
- **stub** — < 16 bytes
- **leaf** — no CALL instructions
- **recursive** — calls itself
- **complex** — > 512 bytes, > 10 calls
- **entry_point** — CRT startup pattern
- **lib_stub** — prologue + ret only
- **normal** — everything else

### 📊 Entropy Mapper (`Ctrl+Shift+E`)
Sliding-window анализ энтропии (window=256, step=128):
- 🔴 **Packed regions** (entropy ≥ 7.5) — авто-label
- ⚠️ **High entropy** (entropy ≥ 7.0)
- 📉 **Low entropy/padding** (entropy ≤ 1.0)

---

## 7. Скриптинг (Rhai)

Встроенный Rhai-движок для автоматизации анализа.

### Пример: найти все функции с crypto-константами
```rust
let funcs = list_functions();
for f in funcs {
    let bytes = get_bytes(f.address, f.size);
    if bytes.contains([0x67, 0x45, 0x23, 0x01]) {
        set_label(f.address, "md5_init_" + to_hex(f.address));
        print("Found MD5 at " + to_hex(f.address));
    }
}
```

### Доступные API
| Функция | Описание |
|---------|----------|
| `list_functions()` | Все функции в проекте |
| `get_function(addr)` | Информация о функции |
| `get_bytes(addr, len)` | Чтение байтов |
| `set_label(addr, name)` | Установить метку |
| `set_comment(addr, text)` | Установить комментарий |
| `get_xrefs_to(addr)` | Кто ссылается НА адрес |
| `get_xrefs_from(addr)` | Куда ссылается адрес |
| `decompile(addr)` | Декомпилировать в C |
| `search_strings(pattern)` | Поиск строк |

---

## 8. Project Database

FreakRE использует embedded БД (sled) для хранения состояния проекта.

### Что хранится
- **Functions** — адреса, размеры, code bytes
- **Labels** — пользовательские имена
- **Comments** — заметки по адресам
- **Bookmarks** — закладки
- **Types** — определённые пользователем структуры
- **Xrefs** — bidirectional cross-references
- **Undo/Redo** — до 1000 действий

### Undo/Redo
Все изменения (labels, comments, types, functions) записываются в undo-стек.
- `Ctrl+Z` — отменить
- `Ctrl+Y` — повторить

---

## 9. Поддерживаемые архитектуры

| # | Архитектура | Prologue Detection | IR Lifter | Endian |
|---|-------------|-------------------|-----------|--------|
| 1 | x86 (IA-32) | ✅ | ✅ | LE |
| 2 | x86-64 (AMD64) | ✅ | ✅ | LE |
| 3 | ARM32 | ✅ | ✅ | LE |
| 4 | ARM32 Thumb | ✅ | ✅ | LE |
| 5 | AArch64 | ✅ | ✅ | LE |
| 6 | AArch64 BE | ✅ | ❌ | BE |
| 7 | MIPS32 LE | ✅ | ❌ | LE |
| 8 | MIPS32 BE | ✅ | ❌ | BE |
| 9 | MIPS64 LE | ✅ | ❌ | LE |
| 10 | MIPS64 BE | ✅ | ❌ | BE |
| 11 | RISC-V 32 | ✅ | ❌ | LE |
| 12 | RISC-V 64 | ✅ | ❌ | LE |
| 13 | PowerPC 32 | ✅ | ❌ | BE |
| 14 | PowerPC 64 | ✅ | ❌ | BE |
| 15 | PowerPC 64 LE | ✅ | ❌ | LE |
| 16 | SPARC 32 | ✅ | ❌ | BE |
| 17 | SPARC 64 | ✅ | ❌ | BE |

**Prologue Detection** — поиск функций через паттерны прологов/эпилогов.
**IR Lifter** — конвертация native code → freakre-ir (SSA form).

Автодетекция архитектуры из заголовков:
- PE Machine field → `Arch::from_pe_machine()`
- ELF e_machine → `Arch::from_elf_machine()`
- Mach-O cpu_type → `Arch::from_macho_cputype()`

---

## 10. Binary Diffing

Сравнение двух бинарников (patch analysis, version comparison):

```rust
use diffing::{diff_binaries, DiffConfig};

let result = diff_binaries(&funcs_a, &funcs_b, &DiffConfig::default());
println!("Similarity: {:.1}%", result.similarity * 100.0);
println!("Matched: {}, Added: {}, Removed: {}", 
    result.matched.len(), result.added.len(), result.removed.len());
```

Алгоритмы матчинга:
1. **Name-based** — точное совпадение имён
2. **Size-based** — одинаковый размер функции
3. **Mnemonic-based** — MD-index (как в Diaphora)
4. **Levenshtein distance** — fuzzy matching инструкций

---

## 11. Написание собственных плагинов

### Минимальный плагин
```rust
use plugins::{Plugin, PluginContext, PluginMetadata, MenuItem};

pub struct MyPlugin;
impl Default for MyPlugin { fn default() -> Self { Self } }

impl Plugin for MyPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "My Plugin".into(),
            version: "1.0.0".into(),
            author: Some("Me".into()),
            description: "Does something useful".into(),
            license: Some("MIT".into()),
            homepage: None,
        }
    }

    fn menu_items(&self) -> Vec<MenuItem> {
        vec![MenuItem::new("Analyze/My Analysis", "Run My Analysis")]
    }

    fn on_menu_item(&mut self, ctx: &mut PluginContext, path: &str) {
        if path == "Analyze/My Analysis" {
            self.analyze(ctx);
        }
    }

    fn analyze(&mut self, ctx: &mut PluginContext) {
        ctx.println("[MyPlugin] Running analysis...");
        // Ваш код здесь
    }
}
```

### Загрузка как dynamic library
```rust
// В вашем crate:
plugins::export_plugin!(MyPlugin);
```

Компиляция:
```bash
cargo build --release
# Скопировать .dll/.so/.dylib в ./plugins/
```

---

## 12. Конфигурация Scoring

Все веса suspicion score настраиваются через `ScoringConfig`:

```rust
use scanner::scanner::ScoringConfig;

let mut config = ScoringConfig::default();
config.import_weight = 0.30;      // Увеличить вес импортов
config.ml_weight = 0.20;          // Увеличить вес ML
config.critical_weights = [0.0, 0.25, 0.30, 0.35]; // Агрессивнее
```

Поля конфигурации:
| Поле | Default | Описание |
|------|---------|----------|
| `import_weight` | 0.25 | Вес import analyzer score |
| `backdoor_weight` | 0.25 | Вес backdoor analyzer score |
| `shellcode_signal` | 0.25 | Бонус за shellcode detection |
| `ml_weight` | 0.15 | Вес ML classifier confidence |
| `yara_per_match` | 0.15 | Бонус за каждое YARA совпадение |
| `critical_weights` | [0, 0.20, 0.25, 0.30] | Diminishing returns для Critical |
| `high_weights` | [0, 0.10, 0.15, 0.18, 0.20, 0.22] | Diminishing returns для High |
| `compounding_3plus` | 0.05 | Бонус при 3+ активных сигналах |
| `compounding_5plus` | 0.05 | Бонус при 5+ активных сигналах |

---

## 13. Fuzz-тестирование

7 fuzz targets для парсеров (требует nightly Rust):

```bash
# Установка cargo-fuzz
cargo install cargo-fuzz

# Запуск фаззинга PE парсера
cargo +nightly fuzz run fuzz_pe_parser --jobs 8

# Запуск с таймаутом
cargo +nightly fuzz run fuzz_pe_parser -- -max_total_time=300

# Все targets:
# fuzz_pe_parser, fuzz_elf_parser, fuzz_macho_parser
# fuzz_import_analyzer, fuzz_str_extract, fuzz_entropy, fuzz_yara
```

---

## 14. FAQ

### Q: Чем FreakRE отличается от Ghidra/IDA?
**A:** FreakRE написан на Rust (memory-safe, быстрый), имеет встроенный collaborative RE (планируется), AI assistant (планируется), WASM-плагины (безопаснее нативных), и полностью open-source.

### Q: Поддерживает ли .NET анализ?
**A:** Детекция .NET CLR assemblies есть (`pe.is_dotnet()`), но полноценный IL-декомпилятор пока не реализован. Для .NET используйте ILSpy/dnSpy параллельно.

### Q: Можно ли использовать как библиотеку?
**A:** Да! Каждый crate — независимая библиотека. Добавьте в Cargo.toml:
```toml
[dependencies]
pe-parser = { path = "../bibleteks/pe-parser" }
func-finder = { path = "../bibleteks/func-finder" }
freakre-ir = { path = "../bibleteks/freakre-ir" }
```

### Q: Как добавить новую архитектуру?
**A:**
1. Добавить вариант в `freakre-ir/src/arch.rs`
2. Добавить prologue/epilogue паттерны в `func-finder/src/lib.rs`
3. Реализовать lifter в `freakre-ir/src/<arch>_lifter.rs`
4. Добавить Capstone bindings в `capstone-ffi`

### Q: Где хранятся проекты?
**A:** Project Database использует sled (embedded key-value store). Файлы БД создаются в указанной директории при открытии проекта.

---

## 📄 Лицензия

MIT License

## 🤝 Контрибуция

PR приветствуются! Приоритетные направления:
- IR lifters для новых архитектур
- Улучшение декомпилятора
- Collaborative RE
- AI-assisted analysis
- Больше function signatures

---

*FreakRE v0.1.0 — Built with 🔥 in Rust*
