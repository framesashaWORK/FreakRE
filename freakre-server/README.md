# freakre-server — HTTP API for AI

AI-friendly JSON API for FreakRE. Запускается на `:8080`, используется ИИ-агентами (opencode, Cursor, Claude) через HTTP или через CLI JSON.

## Запуск

```bash
cargo build --release -p freakre-server
./target/release/freakre-server --port 8080
# кастомный хост/порт + YARA
./target/release/freakre-server --host 127.0.0.1 --port 8080 --rules rules.yar

# проверка
curl http://localhost:8080/health
curl http://localhost:8080/api/capabilities
```

## Эндпоинты

| Метод | Путь | Тело | Ответ |
|-------|------|------|-------|
| GET | `/health` | - | `{"status":"ok"}` |
| GET | `/api/capabilities` | - | список модулей |
| POST | `/api/scan` | `multipart file=@bin` | `FileReport` JSON |
| POST | `/api/scan/base64` | `{"filename":"a.exe","data_base64":"TVq..."}` | `FileReport` |
| POST | `/api/scan/path` | `{"path":"C:/samples/a.exe"}` | `FileReport` |
| POST | `/api/strings` | `multipart file=@bin` | `{count, strings[]}` |
| POST | `/api/entropy` | `multipart file=@bin` | `{overall_entropy, high_entropy_windows[]}` |
| POST | `/api/xrefs` | `multipart file=@bin` | `{total_xrefs, xrefs[]}` |
| POST | `/api/decompile` | `multipart file=@bin address=0x401000` | stub (нужен feature `decompiler`) |

`FileReport` — тот же, что в `freakre-scanner -f json` (`scanner/src/report.rs:59`): `verdict`, `suspicion_score`, `findings[]`, `pe_info`, `entropy`, `backdoor_report`, `shellcode_report`, `xref_summary`, `cfg_summary`, `ml_classification`.

## Примеры для ИИ

### Python (ai agent)

```python
import base64, requests
data = open("suspicious.exe","rb").read()
b64 = base64.b64encode(data).decode()
r = requests.post("http://localhost:8080/api/scan/base64", json={"filename":"suspicious.exe","data_base64":b64})
print(r.json()["verdict"], r.json()["suspicion_score"])
for f in r.json()["findings"]:
    print(f["severity"], f["module"], f["rule_id"])
```

### curl (multipart)

```bash
curl -X POST http://localhost:8080/api/scan -F "file=@suspicious.exe" | jq .verdict
curl -X POST http://localhost:8080/api/strings -F "file=@suspicious.exe" | jq .count
curl -X POST http://localhost:8080/api/entropy -F "file=@suspicious.exe" | jq
```

### opencode / Cursor (через skill)

Скилл `.opencode/skills/freakre-ai/SKILL.md` уже описывает workflow для ИИ:
1. `curl http://localhost:8080/health` — проверить сервер
2. `POST /api/scan` — триаж
3. анализ `findings` по severity
4. `POST /api/decompile` для подозрительных функций

Или без сервера, напрямую CLI:

```bash
cargo run -p freakre-scanner -- -f json suspicious.exe | jq
```

## CLI эквивалент

```bash
./target/release/freakre -f json target.exe                # = POST /api/scan
./target/release/freakre -f json -r rules.yar target.exe   # с YARA
./target/release/freakre --findings-only -f json ./samples/
```

Exit codes: `0=Clean 1=Suspicious 2=Malicious`.
