# Cybersecurity Data Analysis Pipeline

Local PCAP analysis pipeline using Zeek and Python on macOS (Apple Silicon).

## Project Structure

```
data_analysis/
├── data/
│   ├── raw_pcaps/      # Original PCAP captures
│   ├── zeek_logs/      # Zeek-generated log files
│   └── processed/      # Cleaned CSVs and Parquet files
├── notebooks/          # Jupyter analysis notebooks
├── scripts/            # Processing and utility scripts
├── requirements.txt
└── README.md
```

## Workflow

### 1. Capture or Obtain PCAPs

Place `.pcap` / `.pcapng` files into `data/raw_pcaps/`.

```bash
# Example: capture 1000 packets on en0
sudo tcpdump -i en0 -c 1000 -w data/raw_pcaps/capture.pcap
```

### 2. Process PCAPs with Zeek

Run Zeek against a PCAP to generate structured logs:

```bash
cd data/zeek_logs
zeek -r ../raw_pcaps/capture.pcap
```

This produces tab-separated log files (`conn.log`, `dns.log`, `http.log`, etc.).

### 3. Parse Zeek Logs into DataFrames

Use the provided helper script to load Zeek TSV logs into pandas:

```bash
python scripts/zeek_to_dataframe.py data/zeek_logs/conn.log data/processed/conn.parquet
```

Or import the parser directly in a notebook:

```python
from scripts.zeek_to_dataframe import load_zeek_log

df = load_zeek_log("data/zeek_logs/conn.log")
```

### 4. Analyze in Notebooks

Open Jupyter and explore the processed data:

```bash
jupyter lab notebooks/
```

## Prerequisites (macOS Apple Silicon)

```bash
# Install Zeek via Homebrew
brew install zeek

# Create a Python virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Key Zeek Log Files

| Log file   | Contents                          |
|------------|-----------------------------------|
| `conn.log` | Connection summaries (IP, port, duration, bytes) |
| `dns.log`  | DNS queries and responses         |
| `http.log` | HTTP requests and responses       |
| `ssl.log`  | TLS/SSL handshake metadata        |
| `files.log`| File transfers observed on the wire |

## Schema Standardization (ECS)

This project supports conversion to Elastic Common Schema (ECS) format for SIEM integration.

### Quick Start

```bash
# Run ECS standardization pipeline
python scripts/standardize_to_ecs.py

# Output files:
# - outputs/ecs/ecs_events.csv          (ECS-compliant dataset)
# - outputs/validation/validation_report.json (Validation results)
```

### ECS Field Mapping

| Zeek Field | ECS Field |
|------------|-----------|
| `id.orig_h` | `source.ip` |
| `id.resp_h` | `destination.ip` |
| `id.orig_p` | `source.port` |
| `id.resp_p` | `destination.port` |
| `proto` | `network.transport` |
| `ts` | `@timestamp` |

See `REPORT.md` Appendix B for full ECS vs OCSF comparison.

### Pipeline Architecture

```
┌─────────┐   ┌───────────┐   ┌─────────┐   ┌─────────────┐   ┌────────┐
│   RAW   │──▶│ NORMALIZE │──▶│ ENRICH  │──▶│ STANDARDIZE │──▶│ EXPORT │
│  Zeek   │   │  Unified  │   │   TI    │   │    ECS      │   │  CSV   │
│  JSON   │   │  Schema   │   │  Match  │   │   Fields    │   │ +JSON  │
└─────────┘   └───────────┘   └─────────┘   └─────────────┘   └────────┘
```

### Data Sources

| Source | Description |
|--------|-------------|
| [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) | Network intrusion dataset |
| [Malware-Traffic-Analysis](https://www.malware-traffic-analysis.net/) | Real malware PCAPs |
| [Security Onion Samples](https://github.com/Security-Onion-Solutions/securityonion/) | NSM samples |

### References

- [ECS Specification](https://www.elastic.co/guide/en/ecs/current/)
- [OCSF Schema](https://schema.ocsf.io/)
