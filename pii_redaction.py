"""
pii_redaction.py
-----------------
Regex-based PII redaction, applied BEFORE any content is sent to an
external processor (i.e. before the Claude API call). This keeps SSNs,
card numbers, phone numbers, and raw financial identifiers off the wire
to the LLM while still letting the model reason over redacted structure
(e.g. "a credit card number appeared in the body" is preserved as a signal).

This is intentionally conservative: false positives (over-redaction) are
acceptable for a threat-triage tool; false negatives are not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Tuple

from models import PIIRedactionSummary

# --------------------------------------------------------------------------- #
# Patterns
# --------------------------------------------------------------------------- #

# US SSN: 123-45-6789 (also matches space/dot separated variants)
_SSN_RE = re.compile(r"\b\d{3}[-. ]\d{2}[-. ]\d{4}\b")

# Credit card: 13-19 digits, optionally grouped by spaces/dashes in 4s.
# Loose match first, then Luhn-validated to cut down false positives.
_CC_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")

# Phone numbers: rough international/US coverage. Requires at least one
# separator (space/dash/dot/parens) between groups — this deliberately
# excludes bare, unseparated digit runs (e.g. "021000021") so those fall
# through to the bank-account pattern below instead of being mislabeled.
# An unseparated run is inherently ambiguous (could be either); either way
# it still gets redacted, just under the more likely category.
_PHONE_RE = re.compile(
    r"(?<!\d)(\+?\d{1,3}[-.\s])?\(?\d{2,4}\)?[-.\s]\d{3,4}(?:[-.\s]\d{2,4})?(?!\d)"
)

# IBAN-style / generic bank account numbers (8-34 alphanumeric, country-code
# prefixed for IBAN, or long pure-digit runs commonly used as account numbers).
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
_BANK_ACCT_RE = re.compile(r"\b\d{8,17}\b")

# Email addresses (redacted separately so we can still show "sender domain"
# structure to the model without leaking full mailbox identities of third
# parties named in the body).
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")


def _luhn_valid(digits: str) -> bool:
    """Standard Luhn checksum to reduce credit-card false positives."""
    total = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


@dataclass
class RedactionCounts:
    ssn: int = 0
    credit_card: int = 0
    phone: int = 0
    bank_account: int = 0
    email: int = 0


def redact_pii(text: str, *, redact_emails: bool = True) -> Tuple[str, PIIRedactionSummary]:
    """
    Redact sensitive information from `text`.

    Returns (redacted_text, summary). Order of operations matters: more
    specific / higher-confidence patterns (SSN, IBAN) run before the looser
    numeric patterns (generic bank account) to avoid double-tagging.
    """
    counts = RedactionCounts()
    redacted = text

    # 1. SSNs
    redacted, n = _SSN_RE.subn("[REDACTED-SSN]", redacted)
    counts.ssn += n

    # 2. IBAN-style bank identifiers
    redacted, n = _IBAN_RE.subn("[REDACTED-IBAN]", redacted)
    counts.bank_account += n

    # 3. Credit cards (Luhn-checked)
    def _cc_sub(match: re.Match) -> str:
        digits = re.sub(r"[ -]", "", match.group(0))
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            counts.credit_card += 1
            return "[REDACTED-CARD]"
        return match.group(0)

    redacted = _CC_CANDIDATE_RE.sub(_cc_sub, redacted)

    # 4. Phone numbers
    def _phone_sub(match: re.Match) -> str:
        digits_only = re.sub(r"\D", "", match.group(0))
        if 7 <= len(digits_only) <= 15:
            counts.phone += 1
            return "[REDACTED-PHONE]"
        return match.group(0)

    redacted = _PHONE_RE.sub(_phone_sub, redacted)

    # 5. Remaining long digit runs -> generic bank/financial account numbers
    redacted, n = _BANK_ACCT_RE.subn("[REDACTED-ACCOUNT]", redacted)
    counts.bank_account += n

    # 6. Email addresses (optional — keep sender/recipient headers separate
    #    from this pass; this targets addresses embedded in the *body*).
    if redact_emails:
        redacted, n = _EMAIL_RE.subn("[REDACTED-EMAIL]", redacted)
        counts.email += n

    summary = PIIRedactionSummary(
        ssn_redacted=counts.ssn,
        credit_card_redacted=counts.credit_card,
        phone_number_redacted=counts.phone,
        bank_account_redacted=counts.bank_account,
        email_address_redacted=counts.email,
        total_redactions=(
            counts.ssn + counts.credit_card + counts.phone
            + counts.bank_account + counts.email
        ),
    )
    return redacted, summary
