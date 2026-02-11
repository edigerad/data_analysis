#!/usr/bin/env python3
"""Basic threat intelligence enrichment using local blacklists.

Usage:
    from scripts.enrich_ti import ThreatIntel, enrich_ti

    ti = ThreatIntel()
    ti.load_ip_blacklist("data/ti/bad_ips.txt")
    ti.load_domain_blacklist("data/ti/bad_domains.txt")

    df = enrich_ti(df, ti, ip_column="dst_ip", domain_column="dns_query")

Why basic TI enrichment matters in early-stage analysis:
──────────────────────────────────────────────────────────────────────────────
1. IMMEDIATE TRIAGE
   Even a small list of known-bad indicators can surface high-priority events
   instantly. A single hit on a C2 IP in millions of connections saves hours
   of manual hunting.

2. LOW FALSE-POSITIVE BASELINE
   Curated blocklists (abuse.ch, emerging threats) have low false-positive
   rates. A match is almost always worth investigating.

3. NO API DEPENDENCIES
   Local text files work offline, have zero latency, and don't rate-limit.
   Critical during incident response when external services may be blocked
   or unavailable.

4. EASY CUSTOMIZATION
   Add your own indicators from past incidents, industry ISACs, or internal
   threat research. One line per indicator, no complex formats.

5. FOUNDATION FOR LAYERED DETECTION
   TI hits alone don't prove compromise, but combined with behavioral signals
   (unusual ports, data volumes, timing) they build high-confidence alerts.

6. AUDIT TRAIL
   Local blocklists are versioned and reproducible. You know exactly which
   indicators were checked and when—important for compliance and IR reports.
──────────────────────────────────────────────────────────────────────────────
"""

from pathlib import Path

import pandas as pd


class ThreatIntel:
    """Simple threat intelligence matcher using set lookups.

    Supports:
    - IP addresses (exact match)
    - Domains (exact match and subdomain match)

    Blacklist format: one indicator per line, # comments allowed, blank lines ignored.
    """

    def __init__(self):
        self.bad_ips: set[str] = set()
        self.bad_domains: set[str] = set()
        self._sources: list[str] = []

    def load_ip_blacklist(self, path: str | Path) -> int:
        """Load IP addresses from a text file.

        Returns the number of indicators loaded.
        """
        path = Path(path)
        count = 0
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Handle inline comments
                indicator = line.split("#")[0].strip()
                if indicator:
                    self.bad_ips.add(indicator.lower())
                    count += 1
        self._sources.append(f"ip:{path.name}")
        return count

    def load_domain_blacklist(self, path: str | Path) -> int:
        """Load domains from a text file.

        Returns the number of indicators loaded.
        """
        path = Path(path)
        count = 0
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                indicator = line.split("#")[0].strip()
                if indicator:
                    # Normalize: remove leading dots, lowercase
                    indicator = indicator.lstrip(".").lower()
                    self.bad_domains.add(indicator)
                    count += 1
        self._sources.append(f"domain:{path.name}")
        return count

    def add_ip(self, ip: str) -> None:
        """Add a single IP to the blacklist."""
        self.bad_ips.add(ip.lower())

    def add_domain(self, domain: str) -> None:
        """Add a single domain to the blacklist."""
        self.bad_domains.add(domain.lstrip(".").lower())

    def check_ip(self, ip: str) -> bool:
        """Return True if IP is in the blacklist."""
        if pd.isna(ip):
            return False
        return ip.lower() in self.bad_ips

    def check_domain(self, domain: str, match_subdomains: bool = True) -> bool:
        """Return True if domain matches the blacklist.

        If match_subdomains is True (default), also matches subdomains.
        E.g., if "evil.com" is blacklisted, "malware.evil.com" also matches.
        """
        if pd.isna(domain):
            return False

        domain = domain.lower()

        # Exact match
        if domain in self.bad_domains:
            return True

        # Subdomain match: check if domain ends with .blacklisted_domain
        if match_subdomains:
            for bad in self.bad_domains:
                if domain.endswith(f".{bad}"):
                    return True

        return False

    def check_any(
        self,
        ip: str | None = None,
        domain: str | None = None,
        match_subdomains: bool = True,
    ) -> bool:
        """Return True if either IP or domain matches."""
        if ip and self.check_ip(ip):
            return True
        if domain and self.check_domain(domain, match_subdomains):
            return True
        return False

    @property
    def stats(self) -> dict:
        """Return statistics about loaded indicators."""
        return {
            "ip_count": len(self.bad_ips),
            "domain_count": len(self.bad_domains),
            "sources": self._sources,
        }

    def __repr__(self) -> str:
        return f"ThreatIntel(ips={len(self.bad_ips)}, domains={len(self.bad_domains)})"


def enrich_ti(
    df: pd.DataFrame,
    ti: ThreatIntel,
    ip_column: str | None = "dst_ip",
    domain_column: str | None = "dns_query",
    output_column: str = "ti_match",
    match_subdomains: bool = True,
) -> pd.DataFrame:
    """Add threat intelligence match flag to a DataFrame.

    Parameters
    ----------
    df : pd.DataFrame
        Input DataFrame.
    ti : ThreatIntel
        Loaded ThreatIntel instance with blacklists.
    ip_column : str | None
        Column containing IP addresses to check. Set to None to skip IP matching.
    domain_column : str | None
        Column containing domains to check. Set to None to skip domain matching.
    output_column : str
        Name of the boolean output column.
    match_subdomains : bool
        If True, subdomains of blacklisted domains also match.

    Returns
    -------
    pd.DataFrame
        DataFrame with boolean ti_match column added.

    Example
    -------
    >>> ti = ThreatIntel()
    >>> ti.load_ip_blacklist("data/ti/bad_ips.txt")
    >>> df = enrich_ti(df, ti, ip_column="dst_ip")
    >>> df[df["ti_match"]]  # show all matches
    """
    # Resolve column existence
    check_ip = ip_column and ip_column in df.columns
    check_domain = domain_column and domain_column in df.columns

    if not check_ip and not check_domain:
        raise ValueError(
            f"Neither ip_column '{ip_column}' nor domain_column '{domain_column}' "
            "found in DataFrame"
        )

    def row_check(row):
        ip = row[ip_column] if check_ip else None
        domain = row[domain_column] if check_domain else None
        return ti.check_any(ip=ip, domain=domain, match_subdomains=match_subdomains)

    df[output_column] = df.apply(row_check, axis=1)

    return df


def enrich_ti_fast(
    df: pd.DataFrame,
    ti: ThreatIntel,
    ip_column: str | None = "dst_ip",
    domain_column: str | None = "dns_query",
    output_column: str = "ti_match",
) -> pd.DataFrame:
    """Vectorized TI enrichment (faster for large datasets, exact match only).

    Note: This version does NOT support subdomain matching for performance.
    Use enrich_ti() if you need subdomain matching.
    """
    matches = pd.Series(False, index=df.index)

    if ip_column and ip_column in df.columns:
        ip_matches = df[ip_column].str.lower().isin(ti.bad_ips)
        matches = matches | ip_matches.fillna(False)

    if domain_column and domain_column in df.columns:
        domain_matches = df[domain_column].str.lower().isin(ti.bad_domains)
        matches = matches | domain_matches.fillna(False)

    df[output_column] = matches

    return df


def load_ti_from_directory(
    ti_dir: str | Path,
    ip_pattern: str = "*_ips.txt",
    domain_pattern: str = "*_domains.txt",
) -> ThreatIntel:
    """Load all blacklists from a directory.

    Expects files named like:
    - *_ips.txt for IP blacklists
    - *_domains.txt for domain blacklists

    Example directory structure:
        data/ti/
        ├── abuse_ch_ips.txt
        ├── emerging_threats_ips.txt
        ├── phishing_domains.txt
        └── malware_domains.txt
    """
    ti_dir = Path(ti_dir)
    ti = ThreatIntel()

    for ip_file in ti_dir.glob(ip_pattern):
        ti.load_ip_blacklist(ip_file)

    for domain_file in ti_dir.glob(domain_pattern):
        ti.load_domain_blacklist(domain_file)

    return ti
