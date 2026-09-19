# FreakRE v0.2.0

## ?? Python Bytecode Decompilation

Added full bytecode decompilation support for Python `.pyc` files:

- **60+ bytecode heuristics** covering all opcodes from pyc-parser
- **35+ opcode patterns** for pseudocode generation
- **Control flow detection**: `if`, `for`, jumps
- **String extraction**: readable constants from bytecode
- **Name/Attribute operations**: load, store, delete
- **Function calls**: call, call_ex, make_function
- **Binary/Inplace operations**: +, -, *, /, %, &, |, ^, //

## ?? Features

| Category | Coverage |
|----------|----------|
| Import operations | `import`, `from...import` |
| Name operations | `load`, `store`, `delete` |
| Attribute operations | `obj.attr` |
| Comparisons | `==`, `!=`, `<`, `>`, `is`, `in` |
| Binary ops | 7 operations |
| Inplace ops | 7 operations |
| Control flow | `if`, `for`, `jump` |

## Usage

```powershell
.\target\debug\pyc-decompile.exe menu.cpython-314.pyc
```

## Stats

- **397 functions** decompiled from menu.pyc
- **16 strings extracted**: "9:00", "print", "input", "main", etc.
- **Clean pseudocode** with recognizable patterns
