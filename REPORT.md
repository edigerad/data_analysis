# Network Traffic Analysis for Security Threat Detection

**Course:** Cybersecurity Data Engineering
**Date:** November 2025

---

## Abstract

This report presents a reproducible pipeline for analyzing network telemetry derived from packet captures. Raw PCAP files are processed through Zeek to generate structured logs, which are then normalized, enriched with threat intelligence, and analyzed using statistical methods. The pipeline identified two hosts exhibiting indicators of compromise, demonstrating the efficacy of layered enrichment in surfacing security-relevant events from high-volume network data.

---

## 1. Introduction

Network traffic analysis remains a cornerstone of enterprise security monitoring. However, the volume of raw packet data necessitates automated processing pipelines that can extract, normalize, and enrich telemetry for efficient analysis. This work implements such a pipeline using open-source tools suitable for deployment in resource-constrained environments.

**Objectives:**
1. Transform raw packet captures into structured, queryable datasets
2. Apply a unified schema enabling cross-source correlation
3. Enrich network events with threat intelligence indicators
4. Surface anomalous patterns using interpretable statistical methods

---

## 2. Data Source Selection

### 2.1 Primary Data: Zeek Network Logs

Zeek (formerly Bro) was selected as the network security monitor for several reasons:

| Criterion | Zeek Capability |
|-----------|-----------------|
| Protocol coverage | Parses 35+ application protocols natively |
| Output format | Structured logs (TSV or JSON) with typed fields |
| Offline analysis | Supports PCAP replay via `zeek -r` |
| Extensibility | Scriptable for custom protocol analysis |

The analysis utilized `conn.log` (connection summaries) and `dns.log` (DNS transactions), which together provide visibility into network topology and name resolution patterns.

### 2.2 Reference Data: Threat Intelligence

Local text-based blocklists were employed for threat intelligence enrichment:
- **IP blacklist:** Known command-and-control infrastructure
- **Domain blacklist:** Malicious domains including DGA patterns

This approach was chosen over API-based threat feeds to ensure reproducibility and eliminate external dependencies during analysis.

---

## 3. Processing Pipeline

The pipeline implements a five-stage architecture with clear separation between raw inputs, intermediate artifacts, and final outputs.

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│    LOAD     │───▶│  NORMALIZE  │───▶│   ENRICH    │───▶│   ANALYZE   │───▶│   EXPORT    │
│  Zeek JSON  │    │   Unified   │    │   TI Match  │    │  Statistics │    │  CSV/JSON   │
│   Parser    │    │   Schema    │    │   Flags     │    │   & Alerts  │    │  + Metadata │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

### 3.1 Stage 1: Load

Zeek JSON logs are parsed into pandas DataFrames with schema enforcement. The loader handles:
- Zeek's newline-delimited JSON format
- Timestamp conversion (epoch or ISO 8601 to `datetime64[ns, UTC]`)
- Nullable integer types to preserve missing value semantics

### 3.2 Stage 2: Normalize

Field names are mapped to a unified schema aligned with Elastic Common Schema conventions:

| Zeek Field | Unified Field | Rationale |
|------------|---------------|-----------|
| `id.orig_h` | `src_ip` | Consistent naming across log types |
| `id.resp_h` | `dst_ip` | Enables JOIN operations |
| `proto` | `protocol` | Explicit, unabbreviated |
| `ts` | `timestamp` | Standard temporal field |

A `log_type` discriminator column enables filtering after merging heterogeneous logs.

### 3.3 Stage 3: Enrich

Threat intelligence enrichment adds a boolean `ti_match` column. The matcher supports:
- Exact IP matching via set lookup (O(1) complexity)
- Domain matching with subdomain inheritance (e.g., `evil.com` matches `*.evil.com`)

### 3.4 Stage 4: Analyze

Statistical analysis employs interpretable metrics without machine learning:

| Metric | Calculation | Security Relevance |
|--------|-------------|-------------------|
| Failed connection rate | `S0 + REJ / total` | Port scanning, firewall blocks |
| NXDOMAIN rate | `NXDOMAIN / total DNS` | Domain generation algorithms |
| Bytes ratio | `sent / received` | Data exfiltration |

### 3.5 Stage 5: Export

Outputs are saved in portable formats with SHA-256 checksums for reproducibility verification.

---

## 4. Key Analytical Observations

Analysis of the sample dataset (12 connections, 9 DNS queries) yielded the following findings:

### 4.1 Protocol Distribution

| Protocol | Connections | Percentage |
|----------|-------------|------------|
| TCP | 9 | 75.0% |
| UDP | 3 | 25.0% |

TCP traffic was predominantly HTTPS (port 443) and SSH (port 22), consistent with typical enterprise egress patterns.

### 4.2 Anomaly Detection Results

| Indicator | Value | Threshold | Status |
|-----------|-------|-----------|--------|
| Failed connection rate | 33.3% | >10% | **ALERT** |
| NXDOMAIN rate | 33.3% | >30% | **ALERT** |
| TI matches | 6 | >0 | **ALERT** |

### 4.3 Hosts Requiring Investigation

| Source IP | Risk Score | Indicators |
|-----------|------------|------------|
| 192.168.1.200 | 41 | 3 TI matches, 3 NXDOMAIN, 1 failed connection |
| 192.168.1.110 | 36 | 3 TI matches, 3 failed connections (S0) |

**Host 192.168.1.200** exhibited classic DGA behavior: rapid DNS queries to random-appearing domains (`asdkjqwe.xyz`, `xvnmqpfl.xyz`) returning NXDOMAIN, suggesting malware attempting to locate active C2 infrastructure.

**Host 192.168.1.110** attempted connections to three consecutive IPs in the same /24 range, all failing at the TCP handshake (S0 state). This pattern suggests either reconnaissance or attempted communication with offline C2 servers.

---

## 5. Limitations

1. **Sample size:** The demonstration dataset contains only 21 events. Production deployments would process millions of events daily, requiring distributed processing frameworks.

2. **GeoIP enrichment disabled:** Country and ASN attribution were not performed due to database licensing constraints. This limits geopolitical analysis of traffic destinations.

3. **No temporal analysis:** Beaconing detection requires time-series analysis over extended periods. The current implementation examines only aggregate statistics.

4. **Static threat intelligence:** The blocklist approach cannot detect zero-day indicators. Integration with real-time threat feeds would improve detection coverage.

5. **Single vantage point:** Analysis assumes full network visibility. Encrypted tunnels, VPNs, and east-west traffic may evade detection.

---

## 6. Future Work

1. **Scalability:** Migrate to Apache Spark or Polars for datasets exceeding memory capacity.

2. **Temporal analysis:** Implement beaconing detection using inter-arrival time analysis and Fourier transforms to identify periodic C2 callbacks.

3. **JA3/JA3S fingerprinting:** Extract TLS client fingerprints from Zeek's `ssl.log` to identify malware families by their cryptographic handshake signatures.

4. **MITRE ATT&CK mapping:** Correlate detected behaviors to ATT&CK techniques (e.g., T1071 for application-layer C2, T1568 for DGA).

5. **Automated reporting:** Generate PDF reports with visualizations for incident response documentation.

---

## 7. Conclusion

This work demonstrates that meaningful security insights can be extracted from network telemetry using a straightforward, reproducible pipeline. The combination of protocol-aware parsing (Zeek), schema normalization, and threat intelligence enrichment transforms raw packet data into actionable intelligence. The statistical approach—while less sophisticated than machine learning alternatives—provides transparent, interpretable results suitable for analyst review and regulatory compliance.

---

## 8. Time Series Analysis: SMA-Based Anomaly Detection

### 8.1 Approach

A Simple Moving Average (SMA) baseline was applied to detect anomalous spikes in network event volume. The metric used is **connections per time bucket** — the total number of events (conn + dns) aggregated into fixed-width intervals.

**SMA formula:**
```
SMA(t) = (1/W) * Σ x(t-i),  i = 0, ..., W-1
```

**Anomaly rule:**
```
anomaly(t) = True  if  x(t) > SMA(t) * K
```

### 8.2 Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Bucket size | 1 second | Dataset spans ~11 seconds; 1-minute buckets yield only 1 point |
| Window (W) | 3 | Small window appropriate for 12 total buckets |
| Multiplier (K) | 1.5 | Sensitive enough to detect spikes in a small dataset |

For production data with longer timeframes, recommended defaults are: bucket=1min, W=10, K=2.0.

### 8.3 Results

The script produced 12 time buckets from 21 events. One anomaly was detected:

| Time | Connections | SMA | Ratio |
|------|-------------|-----|-------|
| 08:12:41 | 3 | 1.667 | 1.8x |

This bucket corresponds to DGA activity from host 192.168.1.200 (NXDOMAIN queries to `asdkjqwe.xyz` and `xvnmqpfl.xyz`), consistent with findings in Section 4.3.

### 8.4 Why SMA as Baseline

- **Transparent:** analysts can manually verify SMA calculations.
- **No distributional assumptions:** unlike z-score methods, SMA does not assume normality.
- **Adaptive:** the moving window tracks gradual changes in traffic volume.
- **Auditable:** "value exceeded SMA by factor K" satisfies compliance requirements.

### 8.5 Limitations

- **Nonstationarity:** SMA assumes locally stationary traffic within window W. Business-hours vs. nighttime patterns may cause false positives.
- **Seasonality:** daily/weekly patterns are not modeled. STL decomposition or SARIMA would address this.
- **Equal weighting:** all W observations contribute equally. Exponential Moving Average (EMA) would give more weight to recent data.
- **Univariate:** only `connections` is used for the anomaly flag. Multivariate detection combining nxdomain and failed metrics would improve accuracy.

### 8.6 Generated Outputs

| File | Description |
|------|-------------|
| `outputs/time_series_1min.csv` | Time series with SMA and anomaly flags |
| `outputs/anomaly_summary.json` | JSON summary: total_buckets, total_anomalies, parameters |
| `outputs/sma_anomalies.png` | Matplotlib chart: connections + SMA + anomaly markers |

**Run the analysis:**
```bash
python scripts/time_series_sma_anomaly.py --bucket 1s --window 3 --multiplier 1.5
```

---

## 9. Big Data Technologies and Tools for Security Analytics

### 9.1 Big Data Overview

Big Data refers to datasets whose volume, velocity, and variety exceed the capacity of traditional data processing tools. **Volume** describes the sheer size of data — enterprise networks generate terabytes of logs daily. **Velocity** captures the speed at which data arrives — network packets stream continuously at line rate. **Variety** reflects the heterogeneity of formats — PCAP, Zeek logs, firewall events, endpoint telemetry, and threat feeds all differ in structure and semantics.

Network security logs are a canonical Big Data problem. A single Zeek sensor monitoring a 10 Gbps link produces millions of `conn.log` entries per hour. Correlating these with DNS logs, threat intelligence, and endpoint data across retention windows of 30–90 days yields datasets that cannot be processed on a single machine without distributed infrastructure.

### 9.2 Core Technologies

| Technology | Role | Key Capability |
|------------|------|----------------|
| **Hadoop (HDFS)** | Distributed storage | Stores petabytes of log data across commodity nodes with replication for fault tolerance. Enables batch processing of historical network telemetry. |
| **Apache Spark** | Distributed processing | In-memory computation engine that processes large-scale log data 10–100× faster than MapReduce. Supports SQL queries, streaming, and ML pipelines over security events. |
| **Apache Kafka** | Streaming ingestion | Distributed message broker that ingests millions of events per second. Decouples log producers (sensors, agents) from consumers (analytics, SIEM) with durable, replayable streams. |

In production security operations centers, these technologies form the backbone: Kafka ingests real-time events from sensors, Spark processes and enriches them at scale, and HDFS or object storage retains historical data for retrospective hunting.

### 9.3 Analytical Tools

This project uses a lightweight analytical stack suitable for research and prototyping:

| Tool | Purpose | Usage in This Project |
|------|---------|----------------------|
| **pandas** | Tabular data manipulation | Core data structure for loading, normalizing, enriching, and analyzing Zeek logs |
| **NumPy** | Numerical computation | Underlies pandas operations; used implicitly in SMA calculations and statistical metrics |
| **Matplotlib** | Visualization | Generates time series plots with SMA overlays and anomaly markers (`outputs/sma_anomalies.png`) |
| **scikit-learn** | Machine learning | Available for classification and clustering; the current pipeline uses interpretable statistical methods as a baseline |

This lightweight stack was chosen deliberately: it requires no cluster infrastructure, runs on a single machine, and produces reproducible results suitable for academic analysis. The trade-off is scalability — pandas operates in-memory on a single core, limiting dataset size to available RAM.

### 9.4 Mapping to Cybersecurity

Big Data technologies address four critical security analytics use cases:

- **Network traffic analysis:** Spark processes billions of flow records to build baseline traffic profiles and detect deviations. Distributed JOIN operations correlate connections across multiple sensors and time windows.
- **Anomaly detection:** ML pipelines on Spark identify statistical outliers in traffic volume, connection patterns, and payload characteristics at scales where single-machine tools fail.
- **Intrusion detection:** Streaming architectures (Kafka + Spark Structured Streaming) enable real-time signature matching and behavioral analysis with sub-second detection latency.
- **Log correlation:** HDFS-backed data lakes store heterogeneous log sources under unified schemas (e.g., ECS), enabling cross-source queries that surface multi-stage attack patterns invisible in any single log type.

### 9.5 Mapping to This Project

This project implements a single-machine analytical pipeline. The following diagram illustrates the architecture and its production-scale equivalent:

**This project (research scale):**
```
Raw Traffic → Zeek → pandas → SMA → Anomaly Detection
                      │                    │
                      └── CSV/JSON ────────└── matplotlib
```

**Production deployment (enterprise scale):**
```
Raw Traffic → Zeek → Kafka → Spark → ML Models → SIEM / Data Lake
                      │         │          │
                      │         └── HDFS ──└── Kibana / Grafana
                      └── millions of events/sec
```

The core analytical logic is identical: parse network telemetry, normalize fields, compute baselines, and flag deviations. The difference is **scalability infrastructure**. This project processes 21 events in pandas on a laptop; the production equivalent processes millions of events per second across a distributed cluster.

| Dimension | This Project | Production System |
|-----------|-------------|-------------------|
| **Throughput** | ~21 events (batch) | Millions of events/sec (streaming) |
| **Storage** | Local CSV files | HDFS / S3 data lake (petabytes) |
| **Processing** | Single-core pandas | Distributed Spark cluster |
| **Detection** | SMA threshold | Ensemble ML models, deep learning |
| **Visualization** | Matplotlib static plots | Kibana / Grafana real-time dashboards |
| **Retention** | Single analysis run | 30–90 day rolling windows |

The pipeline in this repository — Zeek parsing, ECS normalization, threat intelligence enrichment, and SMA-based detection — represents the same logical stages that production systems implement at scale. Migrating from pandas to Spark requires minimal algorithmic changes; the primary effort is in configuring distributed infrastructure and streaming ingestion.

---

## References

1. Paxson, V. (1999). Bro: A System for Detecting Network Intruders in Real-Time. *Computer Networks*, 31(23-24), 2435-2463.

2. Elastic. (2023). Elastic Common Schema (ECS) Reference. https://www.elastic.co/guide/en/ecs/current/

3. MaxMind. (2023). GeoLite2 Free Geolocation Data. https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

4. MITRE. (2023). ATT&CK for Enterprise. https://attack.mitre.org/

---

## Appendix A: Reproducibility

To reproduce these results:

```bash
# Environment setup
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Execute pipeline
python scripts/pipeline.py

# Verify checksums
cat outputs/metadata/data_checksums.json
```

Expected output checksum for `enriched_network_events.csv`:
```
0443cf89da0d5c310d20ce4c36f4d82fd5697547c1cc4ecf1c90f9bbc12b5669
```

---

## Appendix B: Schema Standardization (ECS)

### B.1 Data Sources

This analysis utilizes network telemetry data that represents common enterprise traffic patterns. The data sources and references include:

| Source | Description | URL |
|--------|-------------|-----|
| CIC-IDS2017 | Realistic network intrusion dataset with labeled attacks | https://www.unb.ca/cic/datasets/ids-2017.html |
| Malware-Traffic-Analysis | Real-world malware PCAP samples | https://www.malware-traffic-analysis.net/ |
| Security Onion Test PCAPs | Network security monitoring samples | https://github.com/Security-Onion-Solutions/securityonion/tree/master/samples |
| Zeek Sample Logs | Reference Zeek log formats | https://docs.zeek.org/en/master/logs/index.html |

**Traffic Types Represented:**
- Normal web browsing (HTTP/HTTPS to public servers)
- DNS resolution traffic (queries to recursive resolvers)
- SSH administrative sessions
- SSL/TLS encrypted connections
- Connection failures and anomalies (S0 states, NXDOMAIN responses)
- Simulated command-and-control communication patterns

---

### B.2 ECS vs OCSF Schema Comparison

Two major schema standardization efforts exist in the cybersecurity ecosystem. Understanding their differences is critical for choosing the right approach.

#### Elastic Common Schema (ECS)

**Official Specification:** https://www.elastic.co/guide/en/ecs/current/

ECS is Elastic's open schema for structuring event data in Elasticsearch. Key characteristics:

| Aspect | Details |
|--------|---------|
| **Primary Use Case** | SIEM, log analytics, threat hunting in Elastic Stack |
| **Structure** | Hierarchical dot-notation (e.g., `source.ip`, `destination.port`) |
| **Governance** | Elastic-led with community RFC process |
| **Tooling** | Native support in Beats, Logstash, Elasticsearch, Kibana |
| **Field Categories** | Base, Agent, Client, Cloud, Container, Destination, DNS, Error, Event, File, Host, HTTP, Log, Network, Observer, Process, Registry, Server, Source, TLS, URL, User, User Agent |

**Typical ECS Field Examples:**
```
@timestamp           → Event timestamp (ISO 8601)
source.ip            → Originating IP address
destination.port     → Target port number
event.category       → High-level event category (network, process, file)
threat.indicator.*   → Threat intelligence matches
```

#### Open Cybersecurity Schema Framework (OCSF)

**Official Specification:** https://schema.ocsf.io/

OCSF is a vendor-neutral schema developed by AWS and the OCSF consortium. Key characteristics:

| Aspect | Details |
|--------|---------|
| **Primary Use Case** | Cross-vendor event exchange, security data lake interoperability |
| **Structure** | Hierarchical with strong typing and class-based events |
| **Governance** | Linux Foundation consortium (AWS, Splunk, IBM, etc.) |
| **Tooling** | Amazon Security Lake, native support growing |
| **Event Classes** | System Activity, Findings, IAM, Network Activity, Discovery, Application Activity |

**Typical OCSF Field Examples:**
```
time                 → Event timestamp (Unix epoch ms)
src_endpoint.ip      → Source endpoint IP
dst_endpoint.port    → Destination port
category_uid         → Numeric category identifier
observables[]        → Array of observed indicators
```

#### Key Differences

| Criterion | ECS | OCSF |
|-----------|-----|------|
| **Origin** | Single vendor (Elastic) | Multi-vendor consortium |
| **Adoption** | Mature, widely deployed | Emerging, growing adoption |
| **Flexibility** | Extensible via custom fields | Strict schema validation |
| **Timestamps** | ISO 8601 strings | Unix milliseconds |
| **ID Strategy** | String-based UIDs | Integer class/category UIDs |
| **Best For** | Elastic Stack deployments | Multi-vendor data lakes |

#### When to Use Each

**Choose ECS when:**
- Deploying Elastic SIEM or using Elastic Observability
- Leveraging existing Elastic Beats and Agent infrastructure
- Need mature, well-documented field mappings
- Require compatibility with Elastic detection rules

**Choose OCSF when:**
- Building vendor-neutral security data lakes
- Using Amazon Security Lake as primary storage
- Requiring strict schema validation for data quality
- Integrating multiple security vendors with different log formats

#### This Project's Choice: ECS

This implementation uses ECS because:
1. **Mature ecosystem** - Well-documented field mappings and detection rules
2. **Zeek integration** - Existing Elastic integrations for Zeek logs
3. **Analyst familiarity** - Widely known in SOC environments
4. **Practical deployment** - Direct path to Elasticsearch/Kibana visualization

---

### B.3 ECS Field Mapping Implementation

The following table shows the complete field mapping from Zeek/normalized fields to ECS:

| Source Field | ECS Field | Description |
|--------------|-----------|-------------|
| `id.orig_h` / `src_ip` | `source.ip` | Originating IP address |
| `id.resp_h` / `dst_ip` | `destination.ip` | Responding IP address |
| `id.orig_p` / `src_port` | `source.port` | Source port number |
| `id.resp_p` / `dst_port` | `destination.port` | Destination port number |
| `proto` / `protocol` | `network.transport` | Transport protocol (tcp, udp, icmp) |
| `ts` / `timestamp` | `@timestamp` | Event timestamp (UTC ISO 8601) |
| `uid` | `event.id` | Unique event identifier |
| `service` | `network.protocol` | Application protocol (http, dns, ssl) |
| `duration` / `duration_sec` | `event.duration` | Connection duration in seconds |
| `orig_bytes` / `bytes_sent` | `source.bytes` | Bytes sent by source |
| `resp_bytes` / `bytes_recv` | `destination.bytes` | Bytes received by source |
| `query` / `dns_query` | `dns.question.name` | DNS query domain |
| `qtype_name` / `dns_qtype` | `dns.question.type` | DNS query type (A, AAAA, MX) |
| `rcode_name` / `dns_rcode` | `dns.response_code` | DNS response code |
| `log_type` | `event.dataset` | Source log type (conn, dns, http) |
| `ti_match` | `threat.indicator.matched` | Threat intelligence match flag |

**Additional ECS Fields Added:**
- `event.kind` = "event" (always for network telemetry)
- `event.category` = "network" (inferred from log type)
- `event.type` = "connection" or "protocol" (inferred from log type)

---

### B.4 Before/After Mapping Example

**Field Name Mapping:**

| Zeek/Normalized Field | ECS Field |
|----------------------|-----------|
| `src_ip` | `source.ip` |
| `dst_ip` | `destination.ip` |
| `src_port` | `source.port` |
| `dst_port` | `destination.port` |
| `protocol` | `network.transport` |
| `timestamp` | `@timestamp` |
| `uid` | `event.id` |
| `service` | `network.protocol` |
| `duration_sec` | `event.duration` |
| `bytes_sent` | `source.bytes` |
| `bytes_recv` | `destination.bytes` |
| `log_type` | `event.dataset` |
| `dns_query` | `dns.question.name` |
| `ti_match` | `threat.indicator.matched` |

**Sample Data Transformation:**

*Before (Normalized Schema):*
```
timestamp               log_type  uid                   src_ip         src_port  dst_ip          dst_port  protocol  service
2025-11-03 08:12:34     conn      CYfOwn3KhUWXr2GnVe    192.168.1.100  52134     93.184.216.34   443       tcp       ssl
2025-11-03 08:12:34     dns       CbNCRo1MkFJPBcb3ai    192.168.1.100  52135     8.8.8.8         53        udp       <NA>
```

*After (ECS Schema):*
```
@timestamp                   event.kind  event.category  event.dataset  event.id              source.ip      source.port  destination.ip   destination.port  network.transport
2025-11-03T08:12:34.112000Z  event       network         conn           CYfOwn3KhUWXr2GnVe    192.168.1.100  52134        93.184.216.34    443               tcp
2025-11-03T08:12:34.450000Z  event       network         dns            CbNCRo1MkFJPBcb3ai    192.168.1.100  52135        8.8.8.8          53                udp
```

---

### B.5 Automation Research: Log Parsing and Mapping Approaches

Modern security operations employ several automated approaches for log parsing and schema mapping:

#### 1. Elastic Agent / Filebeat Modules

**Overview:** Elastic's data shippers include pre-built modules for common log sources.

| Feature | Details |
|---------|---------|
| **Zeek Support** | Native `zeek` module parses all standard log types |
| **Schema Mapping** | Automatic ECS field mapping built-in |
| **Deployment** | Agent-based, managed via Fleet |
| **Handling Missing Fields** | Graceful handling with null values |

**Example Configuration:**
```yaml
filebeat.modules:
- module: zeek
  conn:
    enabled: true
    var.paths: ["/opt/zeek/logs/current/conn.log"]
```

#### 2. Logstash Pipelines (Grok)

**Overview:** Pattern-based parsing using Grok expressions.

| Feature | Details |
|---------|---------|
| **Flexibility** | Custom patterns for any log format |
| **Performance** | JVM-based, moderate throughput |
| **Error Handling** | `_grokparsefailure` tag for malformed logs |
| **Missing Fields** | Conditional field addition with `if [field]` |

**Example Grok Pattern:**
```ruby
filter {
  grok {
    match => { "message" => "%{IP:source.ip}:%{INT:source.port} -> %{IP:destination.ip}:%{INT:destination.port}" }
  }
  mutate {
    rename => { "src" => "source.ip" }
  }
}
```

#### 3. Elastic Ingest Pipelines

**Overview:** Server-side processing within Elasticsearch.

| Feature | Details |
|---------|---------|
| **Location** | Runs in Elasticsearch cluster |
| **Processors** | Grok, JSON, Date, GeoIP, User Agent, etc. |
| **Performance** | Distributed, scales with cluster |
| **Error Handling** | `on_failure` handlers per processor |

**Example Pipeline:**
```json
{
  "processors": [
    {
      "rename": {
        "field": "id.orig_h",
        "target_field": "source.ip",
        "ignore_missing": true
      }
    },
    {
      "date": {
        "field": "ts",
        "target_field": "@timestamp",
        "formats": ["ISO8601", "UNIX"]
      }
    }
  ]
}
```

#### 4. Security Onion Pipelines

**Overview:** Integrated security distribution with pre-configured parsing.

| Feature | Details |
|---------|---------|
| **Stack** | Zeek + Suricata + Elasticsearch + Kibana |
| **Parsing** | Logstash pipelines included |
| **Schema** | ECS-aligned with custom extensions |
| **Updates** | Community-maintained rule updates |

#### 5. Handling Imperfect Logs and Missing Fields

Real-world log data frequently contains:
- **Missing fields** - Not all Zeek connections have `service` detected
- **Type inconsistencies** - Numeric fields as strings
- **Truncated data** - Large payloads cut off
- **Encoding issues** - Non-UTF8 characters in hostnames

**Best Practices:**
```python
# 1. Default values for missing required fields
df["source.bytes"] = df["source.bytes"].fillna(0)

# 2. Type coercion with error handling
df["source.port"] = pd.to_numeric(df["source.port"], errors="coerce").astype("Int64")

# 3. Validation warnings (not failures)
if df["source.ip"].isna().sum() > 0:
    logger.warning(f"Missing source.ip in {df['source.ip'].isna().sum()} rows")

# 4. Mapping coverage metrics
coverage = mapped_fields / total_fields * 100
logger.info(f"Mapping coverage: {coverage:.1f}%")
```

#### This Implementation's Approach

The `scripts/ecs_mapper.py` module implements:

1. **Robust field mapping** with fallback handling
2. **Type validation** for IP addresses, ports, and timestamps
3. **Default ECS fields** (`event.kind`, `event.category`) added automatically
4. **Mapping coverage reporting** (% of fields successfully mapped)
5. **Validation report** (JSON) documenting errors and warnings

**Run the standardization pipeline:**
```bash
python scripts/standardize_to_ecs.py
```

**Output files:**
- `outputs/ecs/ecs_events.csv` - ECS-compliant dataset
- `outputs/validation/validation_report.json` - Validation results
- `outputs/versioned/v{timestamp}/` - Timestamped pipeline run
