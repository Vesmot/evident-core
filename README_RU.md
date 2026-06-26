# Evident

Криптографическая утилита для фиксации и верификации файлов.

Создаёт неизменяемое доказательство существования файла в конкретный момент времени:
Ed25519 подпись + RFC 3161 временная метка (TSA).

## Установка

### cargo install (рекомендуется)

```bash
cargo install --git https://github.com/<your-org>/evident-core --bin evident
```

### из исходников

```bash
git clone https://github.com/<your-org>/evident-core
cd evident-core
cargo build --release
# бинарник: target/release/evident
```

## Быстрый старт

```bash
# 1. Инициализация ключей (один раз)
evident key init

# 2. Фиксация файла
evident seal document.pdf

# 3. Верификация
evident verify document.pdf

# 4. Читаемый отчёт
evident seal document.pdf --report
evident verify document.pdf --report
```

## Команды

| Команда | Описание |
|---|---|
| `evident key init` | Создать зашифрованный ключевой vault |
| `evident seal <file>` | Зафиксировать файл (подпись + TSA) |
| `evident seal <file> --no-tsa` | Фиксация без TSA (офлайн) |
| `evident seal <file> --git` | Включить Git-контекст в доказательство |
| `evident seal <file> --report` | Вывести свидетельство о фиксации |
| `evident verify <file>` | Верифицировать файл |
| `evident verify <file> --report` | Вывести отчёт верификации |
| `evident audit log` | Показать журнал аудита |
| `evident audit verify` | Проверить целостность цепочки аудита |

## Флаги

| Флаг | Описание |
|---|---|
| `--no-tsa` | Пропустить TSA запрос |
| `--git` | Добавить Git commit/branch в доказательство |
| `--report` | Вывести человекочитаемый отчёт на русском |
| `--json` | Вывод в JSON (для скриптов и CI) |
| `--proof <path>` | Указать путь к `.evident` файлу явно |

## Формат доказательства

Файл `<document>.evident` — JSON с полями:

```json
{
  "version": "1",
  "file_name": "document.pdf",
  "file_hash": "<sha256-hex>",
  "sealed_at": "<ISO8601 UTC>",
  "sealed_at_unix": 1234567890,
  "signer": {
    "public_key": "<hex>",
    "signature": "<hex>"
  },
  "tsa": {
    "status": "anchored",
    "provider": "FreeTSA",
    "tsr_b64": "<base64>",
    "verified_time": "<ISO8601>"
  },
  "audit": {
    "seq": 1,
    "chain_hash": "<hex>"
  }
}
```

## Хранилище

| Путь | Описание |
|---|---|
| `~/.evident/key.enc` | Зашифрованный vault (Argon2id + AES-256-GCM) |
| `~/.evident/audit.jsonl` | Append-only журнал всех операций |
| `<file>.evident` | Доказательство рядом с исходником |

## TSA провайдеры

По умолчанию используется FreeTSA (`https://freetsa.org/tsr`).
Fallback: DigiCert.

## Криптография

- Подпись: Ed25519 (ed25519-dalek 2.1)
- Хэш: SHA-256
- KDF: Argon2id (m=65536, t=3, p=1)
- Шифрование vault: AES-256-GCM
- Временная метка: RFC 3161

## Версии

| Версия | Что добавлено |
|---|---|
| v0.1 | vault, seal, verify, audit chain |
| v0.2 | RFC3161 DER, TSA anchoring |
| v0.3 | Git attestation overlay |
| v0.4 | `--report` при seal |
| v0.5 | `--report` при verify |
| v0.6 | `--version`, документация |
