"""
geo_engine.py
-------------
Two responsibilities:

1. Hop-by-hop parsing of `Received:` headers, in the order the email
   actually travelled (oldest hop first — RFC 5321 mail systems PREPEND
   each new Received header, so the header block must be reversed).

2. A local GeoLite2-City-style lookup. This ships as a small deterministic
   simulation table (no MaxMind license / .mmdb file required for the
   hackathon demo) but is written so swapping in the real thing is a
   one-function change — see `_real_geoip_lookup_stub()` at the bottom.

Both steps run in well under 1ms per hop since everything is in-memory.
"""

from __future__ import annotations

import ipaddress
import re
import time
from typing import List, Optional

from models import GeoHop

# --------------------------------------------------------------------------- #
# Received: header parsing
# --------------------------------------------------------------------------- #

_RECEIVED_HEADER_RE = re.compile(
    r"^Received:\s*(.+?)(?=^\S+:|\Z)", re.MULTILINE | re.DOTALL | re.IGNORECASE
)
_IP_RE = re.compile(
    r"\[?((?:\d{1,3}\.){3}\d{1,3})\]?|\[?([0-9a-fA-F:]{6,45})\]?"
)


def extract_received_chain(raw_email: str) -> List[str]:
    """
    Return the raw text of each Received: header, oldest-first (i.e. the
    order the message actually hopped through, origin -> final MTA).
    """
    headers = raw_email.split("\n\n", 1)[0]  # header block only
    matches = _RECEIVED_HEADER_RE.findall(headers)
    # Received headers are stacked newest-first in the raw source; reverse
    # so index 0 is the originating hop closest to the sender.
    return [m.strip() for m in reversed(matches)]


def extract_ip_from_hop(hop_text: str) -> Optional[str]:
    """Pull the first plausible IPv4/IPv6 literal out of a Received: hop."""
    for match in _IP_RE.finditer(hop_text):
        candidate = match.group(1) or match.group(2)
        if not candidate:
            continue
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            continue
    return None


def extract_auth_header_field(raw_email: str, field: str) -> str:
    """
    Best-effort scrape of SPF/DKIM/DMARC results out of an
    Authentication-Results: header. Returns 'unknown' if absent.
    """
    match = re.search(
        rf"Authentication-Results:.*?{field}=(\w+)", raw_email, re.IGNORECASE | re.DOTALL
    )
    return match.group(1).lower() if match else "unknown"


# --------------------------------------------------------------------------- #
# Simulated GeoLite2 City lookup
# --------------------------------------------------------------------------- #
# Keyed by IP prefix (first two octets) -> (country, city, isp, asn, risk).
# This is a small illustrative table, NOT real MaxMind data. It exists so
# the demo has deterministic, explainable output without shipping a
# GeoLite2-City.mmdb binary (which requires a MaxMind license to redistribute).
_SIMULATED_GEO_TABLE = {
    "185.220": ("Germany", "Frankfurt", "Tor Exit Relay Network", "AS208294", "high"),
    "104.244": ("United States", "San Francisco", "Cloudflare, Inc.", "AS13335", "medium"),
    "45.155":  ("Russia", "Moscow", "Bulletproof Hosting LLC", "AS206728", "high"),
    "103.99":  ("Hong Kong", "Hong Kong", "Offshore VPS Hosting", "AS63854", "high"),
    "13.107":  ("United States", "Redmond", "Microsoft Corporation", "AS8075", "low"),
    "142.250": ("United States", "Mountain View", "Google LLC", "AS15169", "low"),
    "40.92":   ("United States", "Redmond", "Microsoft Office 365", "AS8075", "low"),
    "203.0":   ("Australia", "Sydney", "APNIC-TEST-NET", "AS64496", "medium"),
    "196.216": ("Nigeria", "Lagos", "Consumer Broadband ISP", "AS37282", "medium"),
}

_HIGH_RISK_ASN_KEYWORDS = ("tor", "bulletproof", "vps", "offshore")


def _is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def geolocate_ip(ip: Optional[str]) -> GeoHop:
    """
    Simulated local GeoLite2-City lookup. In production this function's
    body is replaced with:

        import geoip2.database
        reader = geoip2.database.Reader("/data/GeoLite2-City.mmdb")
        resp = reader.city(ip)
        # -> resp.country.name, resp.city.name, resp.traits.isp, etc.

    The public interface (returns a GeoHop) stays identical, so callers
    and the API contract never change.
    """
    start = time.perf_counter()

    if not ip:
        return GeoHop(hop_index=-1, ip_address=None, is_internal=False,
                       risk_level="unknown", lookup_time_ms=0.0)

    if _is_internal(ip):
        elapsed = (time.perf_counter() - start) * 1000
        return GeoHop(hop_index=-1, ip_address=ip, is_internal=True,
                       country="Internal/Private", risk_level="low",
                       lookup_time_ms=round(elapsed, 4))

    prefix = ".".join(ip.split(".")[:2]) if "." in ip else ip[:6]
    country, city, isp, asn, risk = _SIMULATED_GEO_TABLE.get(
        prefix, ("Unresolved", "Unresolved", "Unknown Carrier", "AS0", "medium")
    )

    if any(kw in isp.lower() for kw in _HIGH_RISK_ASN_KEYWORDS):
        risk = "high"

    elapsed = (time.perf_counter() - start) * 1000
    return GeoHop(
        hop_index=-1,  # index assigned by caller once ordering is known
        ip_address=ip,
        is_internal=False,
        country=country,
        city=city,
        isp=isp,
        asn=asn,
        risk_level=risk,
        lookup_time_ms=round(elapsed, 4),
    )


def build_geolocation_trace(raw_email: str) -> List[GeoHop]:
    """Full pipeline: parse Received: hops, geolocate each, assign order."""
    hops = extract_received_chain(raw_email)
    trace: List[GeoHop] = []
    for idx, hop_text in enumerate(hops):
        ip = extract_ip_from_hop(hop_text)
        geo = geolocate_ip(ip)
        geo.hop_index = idx
        trace.append(geo)
    return trace
