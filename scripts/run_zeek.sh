#!/usr/bin/env bash
# ============================================================================
# run_zeek.sh — Offline PCAP processing with Zeek
# ============================================================================
# Usage:
#   ./scripts/run_zeek.sh <pcap_file>
#   ./scripts/run_zeek.sh data/raw_pcaps/capture.pcap
#   ./scripts/run_zeek.sh data/raw_pcaps/capture.pcap --json
#
# Output lands in data/zeek_logs/<pcap_basename>/
# ============================================================================
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ZEEK_LOGS_DIR="${PROJECT_ROOT}/data/zeek_logs"
ZEEK_POLICY="${PROJECT_ROOT}/scripts/json_logs.zeek"

# --- Validate input --------------------------------------------------------

PCAP="${1:-}"
JSON_FLAG="${2:-}"

if [[ -z "$PCAP" ]]; then
    echo "Usage: $0 <pcap_file> [--json]"
    echo ""
    echo "Options:"
    echo "  --json    Output JSON instead of TSV (recommended for Python)"
    exit 1
fi

if [[ ! -f "$PCAP" ]]; then
    # Try relative to project root
    PCAP="${PROJECT_ROOT}/${PCAP}"
fi

if [[ ! -f "$PCAP" ]]; then
    echo "Error: PCAP file not found: $1"
    exit 1
fi

# Verify Zeek is installed
if ! command -v zeek &>/dev/null; then
    echo "Error: zeek not found. Install with: brew install zeek"
    exit 1
fi

# --- Prepare output directory -----------------------------------------------

PCAP_NAME="$(basename "${PCAP}" | sed 's/\.\(pcap\|pcapng\)$//')"
OUTPUT_DIR="${ZEEK_LOGS_DIR}/${PCAP_NAME}"
mkdir -p "${OUTPUT_DIR}"

# --- Build Zeek command -----------------------------------------------------
#
# Core command:
#   zeek -r <pcap>
#
# Flags:
#   -r <file>       Read from PCAP (offline mode, no live capture)
#   -C              Ignore invalid IP checksums (common in captures)
#   LogAscii::use_json=T   Switch output from TSV to JSON (one object per line)
#
# Zeek automatically runs its default protocol analyzers and produces:
#   conn.log    — Every connection (TCP/UDP/ICMP) seen in the PCAP
#   dns.log     — DNS queries and responses
#   http.log    — HTTP requests/responses (method, host, URI, status, etc.)
#   ssl.log     — TLS handshakes (SNI, certificate subjects, JA3 hashes)
#   files.log   — Files transferred over any protocol
#   weird.log   — Protocol violations and anomalies
#   plus others depending on traffic content
# ============================================================================

ZEEK_ARGS=(
    -r "${PCAP}"
    -C
)

if [[ "$JSON_FLAG" == "--json" ]]; then
    echo "Output format: JSON (one record per line)"
    ZEEK_ARGS+=(LogAscii::use_json=T)
else
    echo "Output format: Zeek TSV (default)"
    echo "  Tip: use --json for easier Python ingestion"
fi

echo "Processing: $(basename "${PCAP}")"
echo "Output dir: ${OUTPUT_DIR}"
echo ""

# Run Zeek from the output directory so logs land there
(cd "${OUTPUT_DIR}" && zeek "${ZEEK_ARGS[@]}")

# --- Report results ---------------------------------------------------------

echo ""
echo "--- Generated logs ---"
for log in "${OUTPUT_DIR}"/*.log; do
    [[ -f "$log" ]] || continue
    LINES=$(wc -l < "$log" | tr -d ' ')
    echo "  $(basename "$log"): ${LINES} lines"
done
echo ""
echo "Done. Logs written to: ${OUTPUT_DIR}/"
