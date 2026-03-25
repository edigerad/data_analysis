# Schema Standardization and Automation Layer

**Task:** Implement ECS schema standardization and automation for network telemetry data

**Date:** February 2026

---

## English

### Overview

This document describes the implementation of a schema standardization layer that converts Zeek network logs to Elastic Common Schema (ECS) format, with robust validation, automation capabilities, and comprehensive documentation.

### Implemented Features

#### 1. Raw → Normalization → Enrichment Pipeline

The pipeline is organized into clearly separated stages:

```
data_analysis/
├── scripts/
│   ├── zeek_to_dataframe.py      # Stage 1: RAW - Parse Zeek logs
│   ├── normalize.py              # Stage 2: NORMALIZE - Unified schema
│   ├── enrich_ti.py              # Stage 3: ENRICH - Threat intelligence
│   ├── ecs_mapper.py             # Stage 4: STANDARDIZE - ECS mapping
│   └── standardize_to_ecs.py     # Pipeline orchestrator
├── outputs/
│   ├── intermediate/             # Versioned intermediate artifacts
│   ├── ecs/                      # ECS-compliant outputs
│   ├── validation/               # Validation reports
│   └── versioned/                # Timestamped pipeline runs
│       └── v{YYYYMMDD_HHMMSS}/
```

#### 2. ECS vs OCSF Documentation

Full comparison added to `REPORT.md` Appendix B, covering:

- **Elastic Common Schema (ECS)**: https://www.elastic.co/guide/en/ecs/current/
  - SIEM/log analytics focused
  - Mature ecosystem with Beats/Logstash/Kibana integration
  - Hierarchical dot-notation fields

- **Open Cybersecurity Schema Framework (OCSF)**: https://schema.ocsf.io/
  - Vendor-neutral event exchange
  - Multi-vendor consortium (AWS, Splunk, IBM)
  - Strict schema validation

Key differences documented:
- Field naming conventions
- Timestamp formats (ISO 8601 vs Unix epoch)
- Governance models
- Best use cases for each

#### 3. Data Sources

Documented in `REPORT.md` with proper citations:

| Source | Description | URL |
|--------|-------------|-----|
| CIC-IDS2017 | Network intrusion dataset | https://www.unb.ca/cic/datasets/ids-2017.html |
| Malware-Traffic-Analysis | Real malware PCAPs | https://www.malware-traffic-analysis.net/ |
| Security Onion Samples | NSM test data | https://github.com/Security-Onion-Solutions/securityonion/ |

Traffic types represented: HTTP/HTTPS, DNS, SSH, SSL/TLS, connection failures, simulated C2.

#### 4. ECS Mapping Module

**File:** `scripts/ecs_mapper.py`

Complete field mapping implemented:

| Zeek/Normalized | ECS Field | Type |
|-----------------|-----------|------|
| `id.orig_h` / `src_ip` | `source.ip` | IP address |
| `id.resp_h` / `dst_ip` | `destination.ip` | IP address |
| `id.orig_p` / `src_port` | `source.port` | Integer (0-65535) |
| `id.resp_p` / `dst_port` | `destination.port` | Integer (0-65535) |
| `proto` / `protocol` | `network.transport` | Keyword |
| `ts` / `timestamp` | `@timestamp` | ISO 8601 UTC |
| `uid` | `event.id` | Keyword |
| `service` | `network.protocol` | Keyword |
| `duration` | `event.duration` | Float |
| `log_type` | `event.dataset` | Keyword |
| `dns_query` | `dns.question.name` | Keyword |
| `ti_match` | `threat.indicator.matched` | Boolean |

Default ECS fields added:
- `event.kind` = "event"
- `event.category` = "network" (inferred from log type)
- `event.type` = "connection" or "protocol"

#### 5. Automation Implementation

**File:** `scripts/standardize_to_ecs.py`

Features implemented:

1. **Missing field handling**
   - Default values for optional fields
   - Warnings logged (not errors) for missing data
   - NA values preserved for proper null semantics

2. **Type validation**
   - IP address validation (IPv4/IPv6)
   - Port range validation (0-65535)
   - Timestamp parsing (ISO 8601, Unix epoch)
   - Keyword length limits

3. **Mapping coverage metrics**
   - Percentage of source fields mapped
   - List of unmapped fields
   - List of fields with defaults applied

4. **Validation report (JSON)**
   - Summary statistics
   - Error details with sample values
   - Timestamp range
   - Type coercion warnings

**Example validation report:**
```json
{
  "summary": {
    "total_rows": 21,
    "total_source_fields": 20,
    "mapped_fields": 20,
    "mapping_coverage_pct": 100.0
  },
  "field_analysis": {
    "unmapped_fields": [],
    "fields_with_defaults": ["event.kind", "event.category"]
  },
  "validation": {
    "error_count": 0,
    "errors": []
  }
}
```

### Usage

```bash
# Standard pipeline run
python scripts/standardize_to_ecs.py

# Custom input directory
python scripts/standardize_to_ecs.py --zeek-dir /path/to/zeek/logs

# Strict validation (fail on errors)
python scripts/standardize_to_ecs.py --strict

# Process only connection logs
python scripts/standardize_to_ecs.py --log-type conn
```

### Output Files

| File | Description |
|------|-------------|
| `outputs/ecs/ecs_events.csv` | ECS-compliant dataset |
| `outputs/ecs/ecs_events.parquet` | Binary format |
| `outputs/ecs/ecs_conn_only.csv` | Connection logs only |
| `outputs/validation/validation_report.json` | Validation results |
| `outputs/validation/mapping_coverage.json` | Field mapping stats |
| `outputs/versioned/v{timestamp}/` | Timestamped run |

### Automation Research Summary

Documented approaches for automated log parsing:

1. **Elastic Agent/Filebeat** - Native Zeek modules with automatic ECS mapping
2. **Logstash Grok** - Pattern-based parsing with error handling
3. **Elasticsearch Ingest Pipelines** - Server-side processing
4. **Security Onion** - Pre-configured Zeek+ECS integration

Best practices for imperfect logs:
- Default values for missing fields
- Type coercion with error handling
- Validation warnings (not failures)
- Coverage metrics for monitoring

---

## Русский

### Обзор

Данный документ описывает реализацию слоя стандартизации схемы, который преобразует сетевые журналы Zeek в формат Elastic Common Schema (ECS) с надёжной валидацией, возможностями автоматизации и полной документацией.

### Реализованные функции

#### 1. Конвейер Raw → Normalization → Enrichment

Конвейер организован в чётко разделённые этапы:

```
data_analysis/
├── scripts/
│   ├── zeek_to_dataframe.py      # Этап 1: RAW - Парсинг Zeek журналов
│   ├── normalize.py              # Этап 2: NORMALIZE - Унифицированная схема
│   ├── enrich_ti.py              # Этап 3: ENRICH - Обогащение TI
│   ├── ecs_mapper.py             # Этап 4: STANDARDIZE - Маппинг в ECS
│   └── standardize_to_ecs.py     # Оркестратор конвейера
├── outputs/
│   ├── intermediate/             # Версионированные промежуточные артефакты
│   ├── ecs/                      # Выходные данные в формате ECS
│   ├── validation/               # Отчёты валидации
│   └── versioned/                # Запуски конвейера с метками времени
│       └── v{ГГГГММДД_ЧЧММСС}/
```

#### 2. Документация ECS vs OCSF

Полное сравнение добавлено в `REPORT.md` Приложение B:

- **Elastic Common Schema (ECS)**: https://www.elastic.co/guide/en/ecs/current/
  - Ориентирован на SIEM/анализ логов
  - Зрелая экосистема с интеграцией Beats/Logstash/Kibana
  - Иерархические поля с точечной нотацией

- **Open Cybersecurity Schema Framework (OCSF)**: https://schema.ocsf.io/
  - Вендор-нейтральный обмен событиями
  - Консорциум производителей (AWS, Splunk, IBM)
  - Строгая валидация схемы

Документированные ключевые различия:
- Соглашения об именовании полей
- Форматы временных меток (ISO 8601 vs Unix epoch)
- Модели управления
- Лучшие варианты использования для каждой схемы

#### 3. Источники данных

Документировано в `REPORT.md` с правильными ссылками:

| Источник | Описание | URL |
|----------|----------|-----|
| CIC-IDS2017 | Набор данных сетевых вторжений | https://www.unb.ca/cic/datasets/ids-2017.html |
| Malware-Traffic-Analysis | Реальные PCAP с вредоносным ПО | https://www.malware-traffic-analysis.net/ |
| Security Onion Samples | Тестовые данные NSM | https://github.com/Security-Onion-Solutions/securityonion/ |

Представленные типы трафика: HTTP/HTTPS, DNS, SSH, SSL/TLS, сбои соединений, симулированный C2.

#### 4. Модуль маппинга ECS

**Файл:** `scripts/ecs_mapper.py`

Реализован полный маппинг полей:

| Zeek/Нормализованное | ECS Поле | Тип |
|----------------------|----------|-----|
| `id.orig_h` / `src_ip` | `source.ip` | IP адрес |
| `id.resp_h` / `dst_ip` | `destination.ip` | IP адрес |
| `id.orig_p` / `src_port` | `source.port` | Целое (0-65535) |
| `id.resp_p` / `dst_port` | `destination.port` | Целое (0-65535) |
| `proto` / `protocol` | `network.transport` | Ключевое слово |
| `ts` / `timestamp` | `@timestamp` | ISO 8601 UTC |
| `uid` | `event.id` | Ключевое слово |
| `service` | `network.protocol` | Ключевое слово |
| `duration` | `event.duration` | Дробное |
| `log_type` | `event.dataset` | Ключевое слово |
| `dns_query` | `dns.question.name` | Ключевое слово |
| `ti_match` | `threat.indicator.matched` | Логическое |

Добавляемые по умолчанию ECS поля:
- `event.kind` = "event"
- `event.category` = "network" (определяется по типу журнала)
- `event.type` = "connection" или "protocol"

#### 5. Реализация автоматизации

**Файл:** `scripts/standardize_to_ecs.py`

Реализованные функции:

1. **Обработка отсутствующих полей**
   - Значения по умолчанию для опциональных полей
   - Предупреждения в логах (не ошибки) для отсутствующих данных
   - Сохранение NA значений для правильной семантики null

2. **Валидация типов**
   - Валидация IP адресов (IPv4/IPv6)
   - Проверка диапазона портов (0-65535)
   - Парсинг временных меток (ISO 8601, Unix epoch)
   - Ограничения длины ключевых слов

3. **Метрики покрытия маппинга**
   - Процент замапленных полей источника
   - Список незамапленных полей
   - Список полей со значениями по умолчанию

4. **Отчёт валидации (JSON)**
   - Сводная статистика
   - Детали ошибок с примерами значений
   - Диапазон временных меток
   - Предупреждения о приведении типов

**Пример отчёта валидации:**
```json
{
  "summary": {
    "total_rows": 21,
    "total_source_fields": 20,
    "mapped_fields": 20,
    "mapping_coverage_pct": 100.0
  },
  "field_analysis": {
    "unmapped_fields": [],
    "fields_with_defaults": ["event.kind", "event.category"]
  },
  "validation": {
    "error_count": 0,
    "errors": []
  }
}
```

### Использование

```bash
# Стандартный запуск конвейера
python scripts/standardize_to_ecs.py

# Пользовательская директория с входными данными
python scripts/standardize_to_ecs.py --zeek-dir /путь/к/zeek/логам

# Строгая валидация (ошибка при проблемах)
python scripts/standardize_to_ecs.py --strict

# Обработка только журналов соединений
python scripts/standardize_to_ecs.py --log-type conn
```

### Выходные файлы

| Файл | Описание |
|------|----------|
| `outputs/ecs/ecs_events.csv` | Набор данных в формате ECS |
| `outputs/ecs/ecs_events.parquet` | Бинарный формат |
| `outputs/ecs/ecs_conn_only.csv` | Только журналы соединений |
| `outputs/validation/validation_report.json` | Результаты валидации |
| `outputs/validation/mapping_coverage.json` | Статистика маппинга полей |
| `outputs/versioned/v{timestamp}/` | Запуск с меткой времени |

### Обзор исследования автоматизации

Документированные подходы к автоматическому парсингу логов:

1. **Elastic Agent/Filebeat** - Нативные модули Zeek с автоматическим маппингом ECS
2. **Logstash Grok** - Парсинг на основе паттернов с обработкой ошибок
3. **Elasticsearch Ingest Pipelines** - Обработка на стороне сервера
4. **Security Onion** - Предварительно настроенная интеграция Zeek+ECS

Лучшие практики для несовершенных логов:
- Значения по умолчанию для отсутствующих полей
- Приведение типов с обработкой ошибок
- Предупреждения валидации (не сбои)
- Метрики покрытия для мониторинга

---

## Summary / Резюме

### Files Created / Созданные файлы

| File | Purpose |
|------|---------|
| `scripts/ecs_mapper.py` | ECS field mapping and validation module |
| `scripts/standardize_to_ecs.py` | Pipeline entry point |
| `REPORT_SCHEMA_STANDARDIZATION.md` | This documentation |

### Files Modified / Изменённые файлы

| File | Changes |
|------|---------|
| `REPORT.md` | Added Appendix B with ECS/OCSF comparison, data sources, automation research |
| `README.md` | Added Schema Standardization section |

### Output Structure / Структура вывода

```
outputs/
├── ecs/
│   ├── ecs_events.csv
│   ├── ecs_events.parquet
│   └── ecs_conn_only.csv
├── validation/
│   ├── validation_report.json
│   ├── mapping_coverage.json
│   └── before_after_example.md
└── versioned/
    └── v20260218_HHMMSS/
        ├── ecs_events.csv
        ├── validation_report.json
        └── manifest.json
```

### Verification / Проверка

```bash
# Run pipeline / Запуск конвейера
python scripts/standardize_to_ecs.py

# Expected output / Ожидаемый вывод:
# - Mapping coverage: 100.0%
# - Validation errors: 0
# - Output checksum: 91279f28272690f3172704e26a30578ae04d8618d838a37090962cdf359ead17
```
