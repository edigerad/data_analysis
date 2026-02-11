#!/usr/bin/env python3
"""Enrich network events with GeoIP and ASN data using MaxMind GeoLite2.

Usage:
    from scripts.enrich_geoip import enrich_geoip, enrich_asn

    df = enrich_geoip(df, ip_column="dst_ip")  # adds dst_ip_country
    df = enrich_asn(df, ip_column="dst_ip")    # adds dst_ip_asn, dst_ip_asn_org

Requires:
    - geoip2 package: pip install geoip2
    - GeoLite2-Country.mmdb and/or GeoLite2-ASN.mmdb database files

Download the free GeoLite2 databases:
    1. Create account at https://www.maxmind.com/en/geolite2/signup
    2. Download GeoLite2-Country.mmdb and GeoLite2-ASN.mmdb
    3. Place in data/geoip/

Security value of ASN enrichment:
──────────────────────────────────────────────────────────────────────────────
ASN (Autonomous System Number) identifies the network operator responsible for
an IP range. This is critical for security analytics because:

1. HOSTING PROVIDER DETECTION
   Malware C2 and phishing infrastructure often use "bulletproof" hosting
   providers. ASN lets you flag traffic to known-bad hosting networks.

2. BUSINESS CONTEXT
   ASN org names reveal if traffic goes to cloud providers (AWS, Azure, GCP),
   CDNs (Cloudflare, Akamai), or ISPs. Unexpected enterprise data flowing to
   residential ISPs is suspicious.

3. THREAT INTELLIGENCE CORRELATION
   Many threat feeds include ASN indicators. Enriching with ASN enables
   direct matching without IP-range calculations.

4. ANOMALY DETECTION
   Baseline normal ASNs for your org's traffic. New ASNs appearing suddenly
   (especially in egress) warrant investigation.

5. INCIDENT SCOPING
   During IR, quickly identify all connections to the same ASN as a known-bad
   IP. The attacker may use multiple IPs within the same provider.
──────────────────────────────────────────────────────────────────────────────
"""

import ipaddress
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import pandas as pd

# ---------------------------------------------------------------------------
# Database paths
# ---------------------------------------------------------------------------

_GEOIP_DIR = Path(__file__).parent.parent / "data" / "geoip"
DEFAULT_COUNTRY_DB_PATH = _GEOIP_DIR / "GeoLite2-Country.mmdb"
DEFAULT_ASN_DB_PATH = _GEOIP_DIR / "GeoLite2-ASN.mmdb"

# Legacy alias for backward compatibility
DEFAULT_DB_PATH = DEFAULT_COUNTRY_DB_PATH

# ---------------------------------------------------------------------------
# Reader management (lazy-loaded, cached by path)
# ---------------------------------------------------------------------------

_readers: dict[str, object] = {}


def _get_reader(db_path: Path):
    """Get or create a MaxMind database reader for the given path."""
    path_str = str(db_path)

    if path_str in _readers:
        return _readers[path_str]

    try:
        import geoip2.database
    except ImportError:
        raise ImportError("geoip2 package required. Install with: pip install geoip2")

    if not db_path.exists():
        raise FileNotFoundError(
            f"MaxMind database not found at {db_path}. "
            "Download from https://www.maxmind.com/en/geolite2/signup"
        )

    _readers[path_str] = geoip2.database.Reader(path_str)
    return _readers[path_str]


def _is_public_ip(ip_str: str) -> bool:
    """Return True if the IP is publicly routable (eligible for GeoIP/ASN lookup)."""
    if pd.isna(ip_str):
        return False

    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    # Skip non-routable addresses
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return False
    if ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return False

    return True


# ---------------------------------------------------------------------------
# Country lookup
# ---------------------------------------------------------------------------

@lru_cache(maxsize=65536)
def lookup_country(ip_str: str, db_path: str | None = None) -> str | None:
    """Look up ISO country code for an IP address.

    Returns:
        Two-letter ISO country code (e.g., "US", "DE") or None for:
        - Private/reserved IPs (RFC1918, link-local, loopback)
        - Invalid IP strings
        - IPs not found in database

    Results are cached (LRU, 64k entries) for performance.
    """
    if not _is_public_ip(ip_str):
        return None

    try:
        path = Path(db_path) if db_path else DEFAULT_COUNTRY_DB_PATH
        reader = _get_reader(path)
        response = reader.country(ip_str)
        return response.country.iso_code
    except Exception:
        return None


# ---------------------------------------------------------------------------
# ASN lookup
# ---------------------------------------------------------------------------

@dataclass
class ASNInfo:
    """ASN lookup result."""
    asn: int | None
    org: str | None


@lru_cache(maxsize=65536)
def lookup_asn(ip_str: str, db_path: str | None = None) -> ASNInfo:
    """Look up ASN number and organization for an IP address.

    Returns:
        ASNInfo dataclass with:
        - asn: Autonomous System Number (integer) or None
        - org: Organization name (string) or None

    Results are cached (LRU, 64k entries) for performance.
    """
    if not _is_public_ip(ip_str):
        return ASNInfo(asn=None, org=None)

    try:
        path = Path(db_path) if db_path else DEFAULT_ASN_DB_PATH
        reader = _get_reader(path)
        response = reader.asn(ip_str)
        return ASNInfo(
            asn=response.autonomous_system_number,
            org=response.autonomous_system_organization,
        )
    except Exception:
        return ASNInfo(asn=None, org=None)


# ---------------------------------------------------------------------------
# DataFrame enrichment functions
# ---------------------------------------------------------------------------

def enrich_geoip(
    df: pd.DataFrame,
    ip_column: str = "dst_ip",
    output_column: str | None = None,
    db_path: str | Path | None = None,
) -> pd.DataFrame:
    """Add country code column to a DataFrame based on IP addresses.

    Parameters
    ----------
    df : pd.DataFrame
        Input DataFrame containing IP addresses.
    ip_column : str
        Name of the column containing IP addresses to look up.
    output_column : str | None
        Name of the new column for country codes.
        Defaults to "{ip_column}_country".
    db_path : str | Path | None
        Path to GeoLite2-Country.mmdb.

    Returns
    -------
    pd.DataFrame
        Input DataFrame with new country code column added.
    """
    if ip_column not in df.columns:
        raise ValueError(f"Column '{ip_column}' not found in DataFrame")

    if output_column is None:
        output_column = f"{ip_column}_country"

    resolved_path = Path(db_path) if db_path else DEFAULT_COUNTRY_DB_PATH
    if not resolved_path.exists():
        raise FileNotFoundError(
            f"GeoLite2-Country database not found at {resolved_path}. "
            "Download from https://www.maxmind.com/en/geolite2/signup"
        )

    db_str = str(resolved_path)
    df[output_column] = df[ip_column].apply(lambda ip: lookup_country(ip, db_str))
    df[output_column] = df[output_column].astype("string")

    return df


def enrich_asn(
    df: pd.DataFrame,
    ip_column: str = "dst_ip",
    asn_column: str | None = None,
    org_column: str | None = None,
    db_path: str | Path | None = None,
) -> pd.DataFrame:
    """Add ASN number and organization columns to a DataFrame.

    Parameters
    ----------
    df : pd.DataFrame
        Input DataFrame containing IP addresses.
    ip_column : str
        Name of the column containing IP addresses to look up.
    asn_column : str | None
        Name of the new column for ASN numbers.
        Defaults to "{ip_column}_asn".
    org_column : str | None
        Name of the new column for organization names.
        Defaults to "{ip_column}_asn_org".
    db_path : str | Path | None
        Path to GeoLite2-ASN.mmdb.

    Returns
    -------
    pd.DataFrame
        Input DataFrame with ASN and organization columns added.

    Example
    -------
    >>> df = enrich_asn(df, ip_column="dst_ip")
    >>> df[["dst_ip", "dst_ip_asn", "dst_ip_asn_org"]].head()
             dst_ip  dst_ip_asn      dst_ip_asn_org
    0       8.8.8.8       15169              GOOGLE
    1       1.1.1.1       13335          CLOUDFLARENET
    2   192.168.1.1        <NA>                <NA>
    """
    if ip_column not in df.columns:
        raise ValueError(f"Column '{ip_column}' not found in DataFrame")

    if asn_column is None:
        asn_column = f"{ip_column}_asn"
    if org_column is None:
        org_column = f"{ip_column}_asn_org"

    resolved_path = Path(db_path) if db_path else DEFAULT_ASN_DB_PATH
    if not resolved_path.exists():
        raise FileNotFoundError(
            f"GeoLite2-ASN database not found at {resolved_path}. "
            "Download from https://www.maxmind.com/en/geolite2/signup"
        )

    db_str = str(resolved_path)

    # Perform lookups
    asn_results = df[ip_column].apply(lambda ip: lookup_asn(ip, db_str))

    # Extract ASN and org into separate columns
    df[asn_column] = asn_results.apply(lambda r: r.asn).astype("Int64")
    df[org_column] = asn_results.apply(lambda r: r.org).astype("string")

    return df


def enrich_geoip_multi(
    df: pd.DataFrame,
    ip_columns: list[str] | None = None,
    db_path: str | Path | None = None,
) -> pd.DataFrame:
    """Enrich multiple IP columns with country codes.

    Parameters
    ----------
    df : pd.DataFrame
        Input DataFrame.
    ip_columns : list[str] | None
        IP columns to enrich. Defaults to ["src_ip", "dst_ip"].
    db_path : str | Path | None
        Path to GeoLite2-Country database.

    Returns
    -------
    pd.DataFrame
        DataFrame with {col}_country added for each IP column.
    """
    if ip_columns is None:
        ip_columns = ["src_ip", "dst_ip"]

    for col in ip_columns:
        if col in df.columns:
            df = enrich_geoip(df, ip_column=col, db_path=db_path)

    return df


def enrich_asn_multi(
    df: pd.DataFrame,
    ip_columns: list[str] | None = None,
    db_path: str | Path | None = None,
) -> pd.DataFrame:
    """Enrich multiple IP columns with ASN information.

    Parameters
    ----------
    df : pd.DataFrame
        Input DataFrame.
    ip_columns : list[str] | None
        IP columns to enrich. Defaults to ["src_ip", "dst_ip"].
    db_path : str | Path | None
        Path to GeoLite2-ASN database.

    Returns
    -------
    pd.DataFrame
        DataFrame with {col}_asn and {col}_asn_org added for each IP column.
    """
    if ip_columns is None:
        ip_columns = ["src_ip", "dst_ip"]

    for col in ip_columns:
        if col in df.columns:
            df = enrich_asn(df, ip_column=col, db_path=db_path)

    return df


def enrich_all(
    df: pd.DataFrame,
    ip_columns: list[str] | None = None,
    country_db_path: str | Path | None = None,
    asn_db_path: str | Path | None = None,
) -> pd.DataFrame:
    """Enrich IP columns with both country and ASN information.

    Parameters
    ----------
    df : pd.DataFrame
        Input DataFrame.
    ip_columns : list[str] | None
        IP columns to enrich. Defaults to ["src_ip", "dst_ip"].
    country_db_path : str | Path | None
        Path to GeoLite2-Country.mmdb.
    asn_db_path : str | Path | None
        Path to GeoLite2-ASN.mmdb.

    Returns
    -------
    pd.DataFrame
        DataFrame with country, ASN, and org columns for each IP column.
    """
    if ip_columns is None:
        ip_columns = ["src_ip", "dst_ip"]

    for col in ip_columns:
        if col not in df.columns:
            continue
        df = enrich_geoip(df, ip_column=col, db_path=country_db_path)
        df = enrich_asn(df, ip_column=col, db_path=asn_db_path)

    return df


# ---------------------------------------------------------------------------
# Cache management
# ---------------------------------------------------------------------------

def get_cache_stats() -> dict:
    """Return lookup cache statistics for debugging."""
    country_info = lookup_country.cache_info()
    asn_info = lookup_asn.cache_info()

    def hit_rate(info):
        total = info.hits + info.misses
        return info.hits / total if total > 0 else 0.0

    return {
        "country": {
            "hits": country_info.hits,
            "misses": country_info.misses,
            "size": country_info.currsize,
            "hit_rate": hit_rate(country_info),
        },
        "asn": {
            "hits": asn_info.hits,
            "misses": asn_info.misses,
            "size": asn_info.currsize,
            "hit_rate": hit_rate(asn_info),
        },
    }


def clear_cache() -> None:
    """Clear all lookup caches (useful for testing or after db update)."""
    lookup_country.cache_clear()
    lookup_asn.cache_clear()
