# 🔧 RE Tool Components

Этот документ описывает 6 новых crates, добавленных для превращения BibleTeks из malware scanner в полноценный reverse engineering tool.

---

## 📦 Обзор компонентов

### 1. `project-db` — Persistent Storage
**Назначение:** Хранение проекта анализа (как IDA `.idb` или Ghidra `.rep`)

**Возможности:**
- ✅ Functions management (create, update, delete)
- ✅ Labels & Comments (user-defined names and annotations)
- ✅ Bookmarks (quick navigation)
- ✅ Type system (struct definitions)
- ✅ Cross-references (bidirectional xref tracking)
- ✅ Undo/Redo (full history of all modifications)

**Использование:**
```rust
use project_db::{ProjectDatabase, FunctionEntry};

let db = ProjectDatabase::create(
    "./my_project.bdb",
    PathBuf::from("binary.exe"),
    "sha256hash".to_string(),
    "x86_64".to_string(),
    "PE".to_string(),
)?;

// Add a function
let func = FunctionEntry::new(0x401000, "main".to_string(), 256);
db.add_function(func)?;

// Set label
db.set_label(0x401000, "entry_point".to_string())?;

// Undo last action
db.undo()?;
```

---

### 2. `func-finder` — Function Boundary Analysis
**Назначение:** Поиск функций в бинарном коде

**Возможности:**
- ✅ Prologue scanning (push ebp; mov ebp, esp, etc.)
- ✅ Recursive descent from entry points
- ✅ Call target resolution
- ✅ Function merging (overlapping candidates)
- ✅ Multi-architecture support (x86, x64, ARM, ARM64, MIPS)

**Использование:**
```rust
use func_finder::{FunctionFinder, Architecture};

let finder = FunctionFinder::new(Architecture::X86_64);
let functions = finder.find_all(&code, &[entry_point])?;

for func in functions {
    println!("Function at 0x{:X}, size: {} bytes", func.start, func.size);
}
```

**Поддерживаемые архитектуры:**
- x86 (32-bit)
- x86_64 (64-bit)
- ARM32
- ARM64
- MIPS32
- MIPS64

---

### 3. `type-system` — Type Inference Engine
**Назначение:** Система типов для декомпиляции

**Возможности:**
- ✅ Parse C-style type declarations
- ✅ Struct layout calculation (with alignment)
- ✅ Enum definitions
- ✅ Type inference from usage
- ✅ Type merging (for conflict resolution)
- ✅ Windows/POSIX type libraries (DWORD, HANDLE, pid_t, etc.)

**Использование:**
```rust
use type_system::TypeEngine;
use project_db::{Type, PrimitiveType};

let mut engine = TypeEngine::new();

// Parse a type
let ty = engine.parse_type("int*")?;

// Add a struct
let point = engine.add_struct("Point", vec![
    ("x".to_string(), Type::Primitive(PrimitiveType::I32)),
    ("y".to_string(), Type::Primitive(PrimitiveType::I32)),
])?;

println!("Point size: {} bytes", point.total_size);

// Generate C code
let c_code = engine.struct_to_c("Point")?;
println!("{}", c_code);
```

---

### 4. `scripting` — Embedded Scripting (Rhai)
**Назначение:** Автоматизация анализа через скрипты

**Возможности:**
- ✅ Rhai scripting language (Python-like syntax)
- ✅ Database access from scripts
- ✅ Built-in functions (list_functions, set_label, get_xrefs_to, etc.)
- ✅ Script templates (find strings, crypto constants, etc.)
- ✅ Output capture

**Использование:**
```rust
use scripting::ScriptEngine;
use std::sync::{Arc, Mutex};

let db = Arc::new(Mutex::new(ProjectDatabase::create(...)));
let mut engine = ScriptEngine::new().with_context(db);

engine.eval(r#"
    let funcs = db.list_functions();
    for func in funcs {
        if func.name.contains("main") {
            print("Found main at " + func.address.to_hex());
        }
    }
"#)?;

let output = engine.get_output();
for line in output {
    println!("{}", line);
}
```

**Встроенные функции:**
- `db.list_functions()` — список всех функций
- `db.get_function(addr)` — получить функцию по адресу
- `db.set_label(addr, name)` — установить имя
- `db.set_comment(addr, text)` — установить комментарий
- `db.get_xrefs_to(addr)` — перекрёстные ссылки
- `db.callers(addr)` — кто вызывает эту функцию
- `db.callees(addr)` — что вызывает эта функция
- `print(msg)` / `println(msg)` — вывод
- `to_hex(n)` — преобразовать в hex

**Готовые шаблоны:**
```rust
use scripting::ScriptTemplates;

let script = ScriptTemplates::find_strings();
let script = ScriptTemplates::find_crypto_constants();
let script = ScriptTemplates::rename_functions();
let script = ScriptTemplates::find_call_chains();
```

---

### 5. `plugins` — Plugin System
**Назначение:** Расширение функциональности через плагины

**Возможности:**
- ✅ Plugin trait (on_load, analyze, on_function_selected, etc.)
- ✅ Menu item registration
- ✅ Dynamic library loading (.dll/.so/.dylib)
- ✅ Plugin manager (load, unload, list)
- ✅ Event notifications

**Создание плагина:**
```rust
use plugins::{Plugin, PluginContext, PluginMetadata, MenuItem};

pub struct MyPlugin;

impl Plugin for MyPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "My Plugin".to_string(),
            version: "1.0.0".to_string(),
            author: Some("Your Name".to_string()),
            description: "Example plugin".to_string(),
            license: Some("MIT".to_string()),
            homepage: None,
        }
    }

    fn on_load(&mut self, ctx: &mut PluginContext) {
        ctx.register_menu_item(MenuItem::new("Analyze/My Analysis", "Run My Analysis"));
    }

    fn analyze(&mut self, ctx: &mut PluginContext) {
        let functions = ctx.db.list_functions().unwrap();
        ctx.println(&format!("Found {} functions", functions.len()));
    }

    fn menu_items(&self) -> Vec<MenuItem> {
        vec![MenuItem::new("Analyze/My Analysis", "Run My Analysis")]
    }
}

impl Default for MyPlugin {
    fn default() -> Self {
        Self
    }
}
```

**Загрузка плагина:**
```rust
use plugins::PluginManager;

let mut manager = PluginManager::new();
manager.load_plugin(Box::new(MyPlugin))?;

// Load from directory
manager.load_from_directory(Path::new("./plugins"))?;

// List plugins
for plugin in manager.list_plugins() {
    println!("{} v{}", plugin.name, plugin.version);
}
```

---

### 6. `diffing` — Binary Diffing
**Назначение:** Сравнение двух бинарников (как BinDiff/Diaphora)

**Возможности:**
- ✅ Name-based matching
- ✅ Size-based matching
- ✅ Mnemonic-based matching (MD-index like)
- ✅ Levenshtein distance for name similarity
- ✅ Diff statistics
- ✅ Text report generation

**Использование:**
```rust
use diffing::BinaryDiffer;

let differ = BinaryDiffer::new()
    .with_threshold(0.7)  // minimum similarity
    .disable_name_matching();  // optional

let result = differ.diff(&db_a, &db_b)?;

println!("Matched: {} functions", result.stats.matched_count);
println!("Average similarity: {:.1}%", result.stats.average_similarity * 100.0);

for m in &result.matches {
    println!("{} (0x{:X}) <-> {} (0x{:X}) [{:.1}%]",
        m.name_a, m.address_a,
        m.name_b, m.address_b,
        m.similarity * 100.0
    );
}

// Generate text report
let report = diffing::generate_report(&result);
println!("{}", report);
```

**Алгоритмы сравнения:**
1. **Name-based** — точное совпадение имен (быстро, но ограничено)
2. **Size-based** — совпадение по размеру (эвристика)
3. **Mnemonic-based** — сравнение последовательностей инструкций (как Diaphora)
4. **Combined** — комбинированная оценка (name + size + mnemonics)

---

## 🔗 Интеграция

Все компоненты работают вместе:

```rust
use project_db::ProjectDatabase;
use func_finder::{FunctionFinder, Architecture};
use type_system::TypeEngine;
use scripting::ScriptEngine;
use std::sync::{Arc, Mutex};

// 1. Create project database
let db = Arc::new(Mutex::new(ProjectDatabase::create(
    "./project.bdb",
    binary_path,
    hash,
    "x86_64".to_string(),
    "PE".to_string(),
)?));

// 2. Find functions
let finder = FunctionFinder::new(Architecture::X86_64);
let functions = finder.find_all(&code, &[entry_point])?;

// 3. Add functions to database
{
    let mut db_lock = db.lock().unwrap();
    for func in functions {
        let entry = FunctionEntry::new(func.start, format!("sub_{:X}", func.start), func.size);
        db_lock.add_function(entry)?;
    }
}

// 4. Use scripting for automation
let mut engine = ScriptEngine::new().with_context(db.clone());
engine.eval(r#"
    let funcs = db.list_functions();
    for func in funcs {
        db.set_comment(func.address, "Auto-analyzed");
    }
"#)?;

// 5. Use type system
let mut type_engine = TypeEngine::new();
type_engine.add_struct("HANDLE", vec![])?;

// 6. Compare with another binary
let differ = BinaryDiffer::new();
let diff_result = differ.diff(&db_a.lock().unwrap(), &db_b.lock().unwrap())?;
```

---

## 📊 Статистика

| Component | Lines of Code | Dependencies | Status |
|-----------|---------------|--------------|--------|
| project-db | ~800 | sled, serde, chrono, uuid | ✅ Complete |
| func-finder | ~500 | serde | ✅ Complete |
| type-system | ~400 | project-db, serde | ✅ Complete |
| scripting | ~350 | rhai, project-db | ✅ Complete |
| plugins | ~300 | project-db, libloading, dirs | ✅ Complete |
| diffing | ~450 | project-db, serde | ✅ Complete |
| **Total** | **~2800** | - | ✅ **All Complete** |

---

## 🚀 Что дальше?

### Immediate (Week 1)
- [ ] Интеграция в desktop-ui
- [ ] UI для function list
- [ ] UI для labels/comments
- [ ] Undo/Redo кнопки (Ctrl+Z, Ctrl+Y)

### Short-term (Month 1)
- [ ] Plugin manager UI
- [ ] Script editor в UI
- [ ] Binary diffing view
- [ ] Type editor UI

### Long-term (Month 2-3)
- [ ] Collaborative RE (WebSocket)
- [ ] AI assistant integration
- [ ] Symbol server (PDB loading)
- [ ] Multi-architecture lifter (ARM, MIPS)

---

## 🎯 Ключевые отличия от Ghidra/IDA

| Feature | BibleTeks | Ghidra | IDA |
|---------|-----------|--------|-----|
| **Language** | Rust (fast, safe) | Java (slow) | C++ (memory bugs) |
| **License** | MIT/Apache | Apache 2.0 | Proprietary |
| **Collaboration** | ✅ Built-in | ❌ Shared projects only | ❌ No |
| **Scripting** | Rhai (embedded) | Java/Python | IDC/Python |
| **Plugin system** | WASM-ready | Java plugins | Python plugins |
| **Binary diffing** | ✅ Built-in | ❌ Plugin | ✅ BinDiff (separate) |
| **UI framework** | egui (GPU) | Java Swing | Qt |

---

## 📝 Лицензия

Все компоненты лицензированы под MIT/Apache 2.0.

---

## 🤝 Contributing

Contributions welcome! See individual crate documentation for contribution guidelines.

---

**Made with ❤️ for the reverse engineering community**
