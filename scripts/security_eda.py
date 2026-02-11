#!/usr/bin/env python3
"""Security-focused exploratory data analysis for network telemetry.

Statistics-based anomaly detection without machine learning.
Designed for interpretability and actionable output.

Usage:
    python scripts/security_eda.py

    # Or import functions directly:
    from scripts.security_eda import analyze_connections, analyze_dns, generate_report
"""

from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd


@dataclass
class SecurityFindings:
    """Container for EDA findings."""

    total_connections: int = 0
    total_dns_queries: int = 0

    # Protocol analysis
    protocol_distribution: dict = field(default_factory=dict)

    # Country analysis
    country_distribution: dict = field(default_factory=dict)

    # Anomalies
    failed_connection_rate: float = 0.0
    failed_connection_sources: list = field(default_factory=list)
    nxdomain_rate: float = 0.0
    nxdomain_sources: list = field(default_factory=list)
    ti_matches: int = 0
    ti_affected_hosts: list = field(default_factory=list)
    high_upload_connections: list = field(default_factory=list)

    # Investigation priorities
    hosts_to_investigate: list = field(default_factory=list)


def analyze_protocol_distribution(conn: pd.DataFrame) -> dict:
    """Analyze traffic distribution by protocol."""
    counts = conn["protocol"].value_counts().to_dict()
    total = len(conn)

    return {
        proto: {"count": count, "percent": round(count / total * 100, 1)}
        for proto, count in counts.items()
    }


def analyze_country_distribution(conn: pd.DataFrame, country_col: str = "dst_country") -> dict:
    """Analyze traffic by destination country."""
    if country_col not in conn.columns:
        return {}

    external = conn[conn[country_col].notna()]
    if len(external) == 0:
        return {}

    stats = external.groupby(country_col).agg(
        connections=("uid", "count"),
        unique_ips=("dst_ip", "nunique"),
        bytes_out=("bytes_sent", "sum"),
    ).to_dict("index")

    return stats


def analyze_connection_states(conn: pd.DataFrame) -> dict:
    """Analyze connection states to detect failures and scanning."""
    state_counts = conn["conn_state"].value_counts()
    total = len(conn)

    # Calculate failure rate
    failed_states = ["S0", "REJ", "RSTO", "RSTR", "S1", "S2", "S3"]
    failed_count = sum(state_counts.get(s, 0) for s in failed_states)
    failed_rate = failed_count / total * 100 if total > 0 else 0

    # Find sources with most failures
    failed_conn = conn[conn["conn_state"].isin(failed_states)]
    failed_by_src = []
    if len(failed_conn) > 0:
        grouped = failed_conn.groupby("src_ip").agg(
            count=("uid", "count"),
            unique_ports=("dst_port", "nunique"),
        ).sort_values("count", ascending=False)

        for ip, row in grouped.iterrows():
            failed_by_src.append({
                "src_ip": ip,
                "failed_count": row["count"],
                "unique_ports": row["unique_ports"],
                "likely_scanning": row["unique_ports"] > 3,
            })

    return {
        "state_distribution": state_counts.to_dict(),
        "failed_rate": round(failed_rate, 1),
        "failed_sources": failed_by_src,
    }


def analyze_dns_anomalies(dns: pd.DataFrame) -> dict:
    """Analyze DNS for NXDOMAIN spikes (DGA indicator)."""
    if len(dns) == 0:
        return {"nxdomain_rate": 0, "nxdomain_sources": []}

    rcode_counts = dns["dns_rcode"].value_counts()
    nxdomain_count = rcode_counts.get("NXDOMAIN", 0)
    nxdomain_rate = nxdomain_count / len(dns) * 100

    # Find sources generating NXDOMAIN
    nx_queries = dns[dns["dns_rcode"] == "NXDOMAIN"]
    nx_sources = []
    if len(nx_queries) > 0:
        grouped = nx_queries.groupby("src_ip").agg(
            count=("uid", "count"),
            domains=("dns_query", lambda x: list(x.unique())),
        ).sort_values("count", ascending=False)

        for ip, row in grouped.iterrows():
            nx_sources.append({
                "src_ip": ip,
                "nxdomain_count": row["count"],
                "failed_domains": row["domains"][:5],  # Top 5
            })

    return {
        "rcode_distribution": rcode_counts.to_dict(),
        "nxdomain_rate": round(nxdomain_rate, 1),
        "nxdomain_sources": nx_sources,
    }


def analyze_data_transfers(conn: pd.DataFrame) -> list:
    """Find connections with unusually high upload ratios."""
    valid = conn[
        (conn["bytes_sent"].notna()) &
        (conn["bytes_recv"].notna()) &
        (conn["bytes_recv"] > 0)
    ].copy()

    if len(valid) == 0:
        return []

    valid["ratio"] = valid["bytes_sent"] / valid["bytes_recv"]
    high_upload = valid[valid["ratio"] > 1.0]

    results = []
    for _, row in high_upload.iterrows():
        results.append({
            "src_ip": row["src_ip"],
            "dst_ip": row["dst_ip"],
            "dst_port": row["dst_port"],
            "bytes_sent": int(row["bytes_sent"]),
            "bytes_recv": int(row["bytes_recv"]),
            "ratio": round(row["ratio"], 2),
        })

    return results


def analyze_ti_matches(unified: pd.DataFrame) -> dict:
    """Summarize threat intelligence matches."""
    if "ti_match" not in unified.columns:
        return {"count": 0, "affected_hosts": []}

    matches = unified[unified["ti_match"] == True]

    affected = []
    if len(matches) > 0:
        by_host = matches.groupby("src_ip").size().sort_values(ascending=False)
        affected = [{"src_ip": ip, "match_count": count} for ip, count in by_host.items()]

    return {
        "count": len(matches),
        "affected_hosts": affected,
    }


def prioritize_investigation(
    conn: pd.DataFrame,
    dns: pd.DataFrame,
    unified: pd.DataFrame,
) -> list:
    """Rank hosts by number and severity of suspicious indicators."""
    all_hosts = set(unified["src_ip"].unique())
    host_scores = []

    for host in all_hosts:
        flags = []
        score = 0

        # TI matches (high priority)
        if "ti_match" in unified.columns:
            ti_count = unified[(unified["src_ip"] == host) & (unified["ti_match"])].shape[0]
            if ti_count > 0:
                flags.append(f"TI:{ti_count}")
                score += ti_count * 10

        # Failed connections
        host_conn = conn[conn["src_ip"] == host]
        failed = host_conn[host_conn["conn_state"].isin(["S0", "REJ"])]
        if len(failed) > 0:
            flags.append(f"FAIL:{len(failed)}")
            score += len(failed) * 2

        # NXDOMAIN
        host_dns = dns[dns["src_ip"] == host]
        nx = host_dns[host_dns["dns_rcode"] == "NXDOMAIN"]
        if len(nx) > 0:
            flags.append(f"NX:{len(nx)}")
            score += len(nx) * 3

        if flags:
            host_scores.append({
                "src_ip": host,
                "score": score,
                "flags": flags,
                "event_count": len(unified[unified["src_ip"] == host]),
            })

    # Sort by score descending
    return sorted(host_scores, key=lambda x: x["score"], reverse=True)


def generate_report(findings: SecurityFindings) -> str:
    """Generate a text report from findings."""
    lines = []
    lines.append("=" * 60)
    lines.append("SECURITY EXPLORATORY DATA ANALYSIS REPORT")
    lines.append("=" * 60)
    lines.append("")

    # Overview
    lines.append("DATASET OVERVIEW")
    lines.append("-" * 40)
    lines.append(f"Total connections:  {findings.total_connections}")
    lines.append(f"Total DNS queries:  {findings.total_dns_queries}")
    lines.append("")

    # Protocol distribution
    lines.append("PROTOCOL DISTRIBUTION")
    lines.append("-" * 40)
    for proto, stats in findings.protocol_distribution.items():
        lines.append(f"  {proto:10s} {stats['count']:6d} ({stats['percent']:5.1f}%)")
    lines.append("")

    # Country distribution
    if findings.country_distribution:
        lines.append("TOP DESTINATION COUNTRIES")
        lines.append("-" * 40)
        for country, stats in list(findings.country_distribution.items())[:5]:
            lines.append(f"  {country:5s} {stats['connections']:6d} connections")
        lines.append("")

    # Anomalies
    lines.append("ANOMALY DETECTION")
    lines.append("-" * 40)

    # Failed connections
    if findings.failed_connection_rate > 10:
        lines.append(f"⚠️  ALERT: {findings.failed_connection_rate}% failed connections")
    elif findings.failed_connection_rate > 5:
        lines.append(f"⚡ WARNING: {findings.failed_connection_rate}% failed connections")
    else:
        lines.append(f"✓ Failed connection rate: {findings.failed_connection_rate}%")

    # NXDOMAIN
    if findings.nxdomain_rate > 30:
        lines.append(f"⚠️  ALERT: {findings.nxdomain_rate}% NXDOMAIN (potential DGA)")
    elif findings.nxdomain_rate > 15:
        lines.append(f"⚡ WARNING: {findings.nxdomain_rate}% NXDOMAIN")
    else:
        lines.append(f"✓ NXDOMAIN rate: {findings.nxdomain_rate}%")

    # TI matches
    if findings.ti_matches > 0:
        lines.append(f"⚠️  ALERT: {findings.ti_matches} threat intelligence matches")
    else:
        lines.append("✓ No threat intelligence matches")

    lines.append("")

    # Investigation priorities
    if findings.hosts_to_investigate:
        lines.append("HOSTS REQUIRING INVESTIGATION")
        lines.append("-" * 40)
        for host in findings.hosts_to_investigate[:10]:
            flags_str = ", ".join(host["flags"])
            lines.append(f"  {host['src_ip']:20s} score={host['score']:3d}  [{flags_str}]")
        lines.append("")
        lines.append("Flag legend: TI=threat intel, FAIL=failed conn, NX=NXDOMAIN")

    lines.append("")
    lines.append("=" * 60)

    return "\n".join(lines)


def run_analysis(
    conn: pd.DataFrame,
    dns: pd.DataFrame,
    unified: pd.DataFrame,
) -> SecurityFindings:
    """Run complete security EDA and return findings."""
    findings = SecurityFindings()

    findings.total_connections = len(conn)
    findings.total_dns_queries = len(dns)

    # Protocol
    findings.protocol_distribution = analyze_protocol_distribution(conn)

    # Country
    findings.country_distribution = analyze_country_distribution(conn)

    # Connection states
    conn_analysis = analyze_connection_states(conn)
    findings.failed_connection_rate = conn_analysis["failed_rate"]
    findings.failed_connection_sources = conn_analysis["failed_sources"]

    # DNS
    dns_analysis = analyze_dns_anomalies(dns)
    findings.nxdomain_rate = dns_analysis["nxdomain_rate"]
    findings.nxdomain_sources = dns_analysis["nxdomain_sources"]

    # TI
    ti_analysis = analyze_ti_matches(unified)
    findings.ti_matches = ti_analysis["count"]
    findings.ti_affected_hosts = ti_analysis["affected_hosts"]

    # Data transfers
    findings.high_upload_connections = analyze_data_transfers(conn)

    # Investigation priorities
    findings.hosts_to_investigate = prioritize_investigation(conn, dns, unified)

    return findings


def main():
    """Run EDA on sample data."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from scripts.zeek_to_dataframe import load_zeek_log, CONN_SCHEMA, DNS_SCHEMA
    from scripts.normalize import normalize_conn, normalize_dns, merge_normalized
    from scripts.enrich_ti import ThreatIntel, enrich_ti

    # Load data
    zeek_dir = Path("data/zeek_logs/sample")
    conn_raw = load_zeek_log(zeek_dir / "conn.log", schema=CONN_SCHEMA)
    dns_raw = load_zeek_log(zeek_dir / "dns.log", schema=DNS_SCHEMA)

    conn = normalize_conn(conn_raw)
    dns = normalize_dns(dns_raw)

    # Load TI
    ti = ThreatIntel()
    ti.load_ip_blacklist("data/ti/sample_ips.txt")
    ti.load_domain_blacklist("data/ti/sample_domains.txt")

    conn = enrich_ti(conn, ti, ip_column="dst_ip", domain_column=None)
    dns = enrich_ti(dns, ti, ip_column="dst_ip", domain_column="dns_query")

    # Merge
    unified = merge_normalized(conn, dns)

    # Run analysis
    findings = run_analysis(conn, dns, unified)

    # Print report
    print(generate_report(findings))


if __name__ == "__main__":
    main()
