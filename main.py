"""
main.py
-------
SentinelMX backend — AI-Powered Email Threat Detection, GeoLocation, and
Forensic Intelligence Platform (SIH26106).

Pipeline for POST /api/v1/analyze-email:
    1. Hash the raw payload as-received (evidence_locker) — chain of custody.
    2. Redact PII from the payload (pii_redaction) — nothing sensitive
       leaves the server.
    3. Parse Received: header hops and geolocate each (geo_engine).
    4. Scrape SPF/DKIM/DMARC from Authentication-Results.
    5. Send the redacted text + forensic context to Claude (claude_analyzer).
    6. Best-effort push attacker infrastructure into Neo4j (graph_connector).
    7. Assemble and return AnalysisResponse; also append to the in-memory
       threat feed the dashboard polls.

Run with:
    uvicorn main:app --reload --port 8000
(from inside the backend/ directory — see the project README for the full
setup guide.)
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import List

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from models import (
    AnalysisResponse,
    AnalyzeEmailRequest,
    GraphIngestStatus,
    ThreatFeedItem,
)
from pii_redaction import redact_pii
from geo_engine import build_geolocation_trace, extract_ip_from_hop, extract_received_chain, extract_auth_header_field
from claude_analyzer import analyze_with_claude
from evidence_locker import generate_evidence_record
from graph_connector import upsert_campaign_graph, close_driver

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sentinelmx")

# In-memory threat feed for the demo dashboard. Swap for a real datastore
# (Postgres, etc.) before anything resembling production use.
_THREAT_FEED: List[ThreatFeedItem] = []
_MAX_FEED_ITEMS = 200


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("SentinelMX backend starting up.")
    yield
    await close_driver()
    logger.info("SentinelMX backend shut down cleanly.")


app = FastAPI(
    title="SentinelMX API",
    description="AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform",
    version="1.0.0",
    lifespan=lifespan,
)

# NOTE: allow_origins=["*"] is convenient for a hackathon demo (dashboard
# served from a plain file:// or a different local port). Lock this down
# to your actual dashboard origin before deploying anywhere real.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/v1/health")
async def health_check() -> dict:
    return {"status": "ok", "service": "SentinelMX", "version": "1.0.0"}


@app.post("/api/v1/analyze-email", response_model=AnalysisResponse)
async def analyze_email(payload: AnalyzeEmailRequest) -> AnalysisResponse:
    raw_email = payload.raw_email

    # --- 1. Evidence hash (pre-redaction, pre-transformation) ------------- #
    analysis_id, evidence = generate_evidence_record(raw_email, payload.case_reference)

    # --- 2. PII redaction --------------------------------------------------#
    redacted_email, pii_summary = redact_pii(raw_email)

    # --- 3. Header hop geolocation ---------------------------------------#
    try:
        geo_trace = build_geolocation_trace(raw_email)
    except Exception as exc:  # malformed headers shouldn't kill the request
        logger.warning("Geo trace parsing failed: %s", exc)
        geo_trace = []

    origin_ip = geo_trace[0].ip_address if geo_trace else None

    # --- 4. Authentication results -----------------------------------------#
    spf = extract_auth_header_field(raw_email, "spf")
    dkim = extract_auth_header_field(raw_email, "dkim")
    dmarc = extract_auth_header_field(raw_email, "dmarc")

    # --- 5. Claude structured analysis --------------------------------------#
    try:
        claude_result = await analyze_with_claude(redacted_email, geo_trace, spf, dkim, dmarc)
    except RuntimeError as exc:
        logger.error("Claude analysis failed: %s", exc)
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    # --- 6. Campaign graph (best-effort, never fatal) ----------------------#
    from_header_match = raw_email.split("\nFrom:", 1)
    sender_header = from_header_match[1].splitlines()[0] if len(from_header_match) > 1 else ""
    graph_success, graph_detail = await upsert_campaign_graph(
        analysis_id, sender_header, origin_ip, raw_email
    )
    graph_status = GraphIngestStatus(attempted=True, success=graph_success, detail=graph_detail)

    # --- 7. Assemble response + update in-memory threat feed --------------#
    response = AnalysisResponse(
        analysis_id=analysis_id,
        case_reference=payload.case_reference,
        claude_analysis=claude_result,
        geolocation_trace=geo_trace,
        pii_redaction_summary=pii_summary,
        evidence=evidence,
        graph_ingest=graph_status,
    )

    _THREAT_FEED.insert(
        0,
        ThreatFeedItem(
            analysis_id=analysis_id,
            generated_at_utc=response.generated_at_utc,
            verdict=claude_result.verdict,
            risk_score=claude_result.risk_score,
            sender_hint=sender_header.strip()[:120] or None,
            sha256_hash=evidence.sha256_hash,
        ),
    )
    del _THREAT_FEED[_MAX_FEED_ITEMS:]

    return response


@app.get("/api/v1/threat-feed", response_model=List[ThreatFeedItem])
async def threat_feed(limit: int = 25) -> List[ThreatFeedItem]:
    return _THREAT_FEED[: max(1, min(limit, _MAX_FEED_ITEMS))]


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
