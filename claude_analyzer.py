"""
claude_analyzer.py
-------------------
Wraps the official `anthropic` Python SDK to turn a (PII-redacted) email,
plus our own header/geo forensics, into a strictly-structured JSON verdict.

Model: claude-sonnet-4-6
    Anthropic's current general-purpose model, a strong fit for this kind
    of structured-extraction + reasoning task. If you are pinned to a
    specific dated snapshot for reproducibility in a report, check
    https://docs.claude.com/en/docs/about-claude/models/overview for the
    current list of model IDs and swap the constant below.

Only the redacted text and our own derived metadata are ever sent to the
API — the raw, un-redacted payload never leaves the server process.
"""

from __future__ import annotations

import json
import os
from typing import List

from anthropic import AsyncAnthropic, APIError, APIConnectionError

from models import ClaudeThreatAnalysis, GeoHop

MODEL_NAME = "claude-sonnet-4-6"

_SYSTEM_PROMPT = """You are SentinelMX's forensic email-threat analysis engine, used by a \
Security Operations Center. You will be given a PII-REDACTED email (headers + body) plus \
pre-computed authentication and geolocation forensics. Analyze it for phishing, malware \
delivery, business email compromise, and social engineering.

Respond with ONLY a single valid JSON object — no markdown code fences, no prose before or \
after — matching EXACTLY this schema:

{
  "verdict": "benign" | "suspicious" | "malicious" | "inconclusive",
  "risk_score": <integer 0-100>,
  "threat_categories": [<strings, e.g. "phishing", "credential_harvesting", "bec", "malware_delivery">],
  "authentication_summary": {
    "spf": "pass" | "fail" | "softfail" | "neutral" | "none" | "unknown",
    "dkim": "pass" | "fail" | "none" | "unknown",
    "dmarc": "pass" | "fail" | "none" | "unknown",
    "notes": <string or null>
  },
  "forensic_indicators": [<strings — concrete technical evidence found, e.g. header anomalies>],
  "social_engineering_cues": [<strings — persuasion/urgency/authority tactics observed, empty list if none>],
  "technical_summary": <string, 2-4 sentences, analyst-facing>,
  "recommended_actions": [<strings — concrete SOC next steps>]
}

Notes on redaction: some values in the body will appear as [REDACTED-SSN], [REDACTED-CARD], \
[REDACTED-PHONE], [REDACTED-ACCOUNT], or [REDACTED-EMAIL]. Treat the PRESENCE of these tokens \
as a strong signal (e.g. a request for a card number is itself suspicious) without trying to \
reconstruct the original value. Base authentication_summary on the auth results provided to \
you, not on speculation. If evidence is thin, prefer "inconclusive" over guessing "malicious"."""


def _format_geo_context(trace: List[GeoHop]) -> str:
    if not trace:
        return "No Received: header hops could be parsed."
    lines = []
    for hop in trace:
        if hop.is_internal:
            lines.append(f"  Hop {hop.hop_index}: {hop.ip_address} (internal/private network)")
        else:
            lines.append(
                f"  Hop {hop.hop_index}: {hop.ip_address} -> {hop.city}, {hop.country} "
                f"| ISP: {hop.isp} | ASN: {hop.asn} | risk: {hop.risk_level}"
            )
    return "\n".join(lines)


def _build_user_prompt(
    redacted_email: str,
    geo_trace: List[GeoHop],
    spf: str,
    dkim: str,
    dmarc: str,
) -> str:
    return f"""=== PRE-COMPUTED AUTHENTICATION RESULTS ===
SPF: {spf}
DKIM: {dkim}
DMARC: {dmarc}

=== HOP-BY-HOP GEOLOCATION TRACE (origin -> final MTA) ===
{_format_geo_context(geo_trace)}

=== PII-REDACTED RAW EMAIL (headers + body) ===
{redacted_email}
"""


def _strip_code_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]
    return text.strip()


async def analyze_with_claude(
    redacted_email: str,
    geo_trace: List[GeoHop],
    spf: str,
    dkim: str,
    dmarc: str,
) -> ClaudeThreatAnalysis:
    """
    Calls the Claude API and returns a validated ClaudeThreatAnalysis.
    Raises RuntimeError with an analyst-readable message on failure —
    callers should catch this and surface a 502/503 to the client rather
    than letting a raw SDK exception escape.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not set. Export it before starting the server "
            "(see the setup guide's Environment Variables step)."
        )

    client = AsyncAnthropic(api_key=api_key)
    user_prompt = _build_user_prompt(redacted_email, geo_trace, spf, dkim, dmarc)

    try:
        response = await client.messages.create(
            model=MODEL_NAME,
            max_tokens=1500,
            temperature=0,  # deterministic triage output
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
    except APIConnectionError as exc:
        raise RuntimeError(f"Could not reach the Anthropic API: {exc}") from exc
    except APIError as exc:
        raise RuntimeError(f"Anthropic API returned an error: {exc}") from exc

    # Concatenate all text blocks (there should normally be exactly one).
    raw_text = "".join(block.text for block in response.content if block.type == "text")
    cleaned = _strip_code_fences(raw_text)

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Claude did not return valid JSON. Raw output: {raw_text[:500]}"
        ) from exc

    try:
        return ClaudeThreatAnalysis.model_validate(parsed)
    except Exception as exc:  # pydantic ValidationError
        raise RuntimeError(f"Claude's JSON did not match the expected schema: {exc}") from exc
