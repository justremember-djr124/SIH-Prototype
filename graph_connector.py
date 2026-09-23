"""
graph_connector.py
--------------------
Sample Neo4j AuraDB connector that maps attacker infrastructure into a
graph so campaigns (not just individual emails) become visible:

    (:Domain {name}) -[:RESOLVED_VIA]-> (:IPSubnet {cidr})
    (:IPSubnet)       -[:HOSTED]->       (:PayloadURL {url})
    (:Domain)         -[:SENT]->         (:Email {analysis_id})

This is intentionally optional and defensive: if NEO4J_URI is not
configured, or the AuraDB instance is unreachable, the rest of the
pipeline continues to work — email analysis should never fail because
the graph database is down.

Requires: pip install neo4j
"""

from __future__ import annotations

import os
import re
from typing import List, Optional
from urllib.parse import urlparse

from neo4j import AsyncGraphDatabase, AsyncDriver
from neo4j.exceptions import Neo4jError, ServiceUnavailable

_driver: Optional[AsyncDriver] = None


def _configured() -> bool:
    return bool(os.environ.get("NEO4J_URI"))


async def get_driver() -> Optional[AsyncDriver]:
    """Lazily create a singleton async driver. Returns None if unconfigured."""
    global _driver
    if not _configured():
        return None
    if _driver is None:
        uri = os.environ["NEO4J_URI"]  # e.g. neo4j+s://xxxxxxxx.databases.neo4j.io
        user = os.environ.get("NEO4J_USER", "neo4j")
        password = os.environ.get("NEO4J_PASSWORD", "")
        _driver = AsyncGraphDatabase.driver(uri, auth=(user, password))
    return _driver


async def close_driver() -> None:
    global _driver
    if _driver is not None:
        await _driver.close()
        _driver = None


def _extract_domain(sender_header: str) -> Optional[str]:
    match = re.search(r"@([\w.-]+\.\w+)", sender_header)
    return match.group(1).lower() if match else None


def _extract_urls(body_text: str) -> List[str]:
    return re.findall(r"https?://[^\s<>\"']+", body_text)


async def upsert_campaign_graph(
    analysis_id: str,
    sender_header: str,
    origin_ip: Optional[str],
    body_text: str,
) -> tuple[bool, str]:
    """
    Push this email's infrastructure into the campaign graph.
    Returns (success, detail_message) — never raises to the caller.
    """
    driver = await get_driver()
    if driver is None:
        return False, "Neo4j not configured (NEO4J_URI unset) — skipped."

    domain = _extract_domain(sender_header) or "unknown-domain"
    subnet = ".".join(origin_ip.split(".")[:3]) + ".0/24" if origin_ip else "unknown-subnet"
    urls = _extract_urls(body_text)[:10]  # cap for demo hygiene

    cypher = """
    MERGE (d:Domain {name: $domain})
    MERGE (s:IPSubnet {cidr: $subnet})
    MERGE (e:Email {analysis_id: $analysis_id})
    MERGE (d)-[:SENT]->(e)
    MERGE (d)-[:RESOLVED_VIA]->(s)
    WITH d, s, e
    UNWIND $urls AS url
      MERGE (u:PayloadURL {url: url})
      MERGE (s)-[:HOSTED]->(u)
      MERGE (e)-[:REFERENCES]->(u)
    """

    try:
        async with driver.session() as session:
            await session.run(
                cypher,
                domain=domain,
                subnet=subnet,
                analysis_id=analysis_id,
                urls=urls,
            )
        return True, f"Graph updated: {domain} -> {subnet} -> {len(urls)} URL node(s)."
    except (ServiceUnavailable, Neo4jError) as exc:
        return False, f"Neo4j write failed: {exc}"
