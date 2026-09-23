"""
models.py
---------
Pydantic v2 schemas shared across the SentinelMX backend.

These define:
  - The inbound request shape for /api/v1/analyze-email
  - The structured JSON contract we force Claude to respond in
  - The final API response, which wraps Claude's verdict with our own
    forensic metadata (evidence hash, geolocation trace, PII redaction log)
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------- #
# Request
# --------------------------------------------------------------------------- #

class AnalyzeEmailRequest(BaseModel):
    raw_email: str = Field(
        ...,
        min_length=1,
        description="Full raw RFC822 email source, headers + body, exactly as received.",
    )
    case_reference: Optional[str] = Field(
        default=None,
        description="Optional analyst-supplied case/ticket ID for chain-of-custody tagging.",
    )


# --------------------------------------------------------------------------- #
# Sub-objects
# --------------------------------------------------------------------------- #

class Verdict(str, Enum):
    benign = "benign"
    suspicious = "suspicious"
    malicious = "malicious"
    inconclusive = "inconclusive"


class AuthenticationSummary(BaseModel):
    spf: str = Field(description="pass | fail | softfail | neutral | none | unknown")
    dkim: str = Field(description="pass | fail | none | unknown")
    dmarc: str = Field(description="pass | fail | none | unknown")
    notes: Optional[str] = None


class GeoHop(BaseModel):
    hop_index: int
    ip_address: Optional[str]
    is_internal: bool
    country: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    risk_level: str = Field(default="unknown", description="low | medium | high | unknown")
    lookup_time_ms: float = 0.0


class PIIRedactionSummary(BaseModel):
    ssn_redacted: int = 0
    credit_card_redacted: int = 0
    phone_number_redacted: int = 0
    bank_account_redacted: int = 0
    email_address_redacted: int = 0
    total_redactions: int = 0


class EvidenceRecord(BaseModel):
    sha256_hash: str
    payload_size_bytes: int
    captured_at_utc: str
    algorithm: str = "SHA-256"
    chain_of_custody_note: str = (
        "Hash computed client-side (server ingress) prior to any redaction or "
        "third-party transmission. Any modification to the original payload "
        "invalidates this hash."
    )


class GraphIngestStatus(BaseModel):
    attempted: bool = False
    success: bool = False
    detail: Optional[str] = None


# --------------------------------------------------------------------------- #
# The structured schema Claude is instructed to return
# --------------------------------------------------------------------------- #

class ClaudeThreatAnalysis(BaseModel):
    verdict: Verdict
    risk_score: int = Field(ge=0, le=100)
    threat_categories: List[str]
    authentication_summary: AuthenticationSummary
    forensic_indicators: List[str]
    social_engineering_cues: List[str]
    technical_summary: str
    recommended_actions: List[str]


# --------------------------------------------------------------------------- #
# Final API response
# --------------------------------------------------------------------------- #

class AnalysisResponse(BaseModel):
    analysis_id: str
    case_reference: Optional[str] = None
    generated_at_utc: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    claude_analysis: ClaudeThreatAnalysis
    geolocation_trace: List[GeoHop]
    pii_redaction_summary: PIIRedactionSummary
    evidence: EvidenceRecord
    graph_ingest: GraphIngestStatus


class ThreatFeedItem(BaseModel):
    analysis_id: str
    generated_at_utc: str
    verdict: Verdict
    risk_score: int
    sender_hint: Optional[str] = None
    sha256_hash: str
