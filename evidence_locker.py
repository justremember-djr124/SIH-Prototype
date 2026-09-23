"""
evidence_locker.py
--------------------
Generates an immutable, cryptographic fingerprint of the raw email exactly
as it was submitted — computed BEFORE redaction or any transformation —
for legal/forensic chain-of-custody purposes.

For the hackathon prototype this also appends a line to a local, append-only
JSONL ledger (`evidence_ledger.jsonl`) so a judge can see a persisted audit
trail. In a production deployment this ledger would instead be a write-once
object store (e.g. S3 Object Lock) or a permissioned blockchain ledger.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from models import EvidenceRecord

_LEDGER_PATH = os.path.join(os.path.dirname(__file__), "evidence_ledger.jsonl")


def generate_evidence_record(raw_payload: str, case_reference: Optional[str] = None) -> tuple[str, EvidenceRecord]:
    """
    Hash the raw payload and return (analysis_id, EvidenceRecord).

    The hash is computed over the UTF-8 bytes of the payload exactly as
    received — no normalization, no stripping — so it is reproducible by
    any third party holding the same original file.
    """
    payload_bytes = raw_payload.encode("utf-8")
    sha256_hash = hashlib.sha256(payload_bytes).hexdigest()
    analysis_id = str(uuid.uuid4())
    captured_at = datetime.now(timezone.utc).isoformat()

    record = EvidenceRecord(
        sha256_hash=sha256_hash,
        payload_size_bytes=len(payload_bytes),
        captured_at_utc=captured_at,
    )

    _append_to_ledger(analysis_id, case_reference, record)
    return analysis_id, record


def _append_to_ledger(analysis_id: str, case_reference: Optional[str], record: EvidenceRecord) -> None:
    """Append-only audit trail. Failures here are logged, never fatal."""
    try:
        with open(_LEDGER_PATH, "a", encoding="utf-8") as fh:
            fh.write(
                json.dumps(
                    {
                        "analysis_id": analysis_id,
                        "case_reference": case_reference,
                        **record.model_dump(),
                    }
                )
                + "\n"
            )
    except OSError as exc:  # pragma: no cover - disk issues shouldn't crash analysis
        print(f"[evidence_locker] WARNING: could not write to ledger: {exc}")
