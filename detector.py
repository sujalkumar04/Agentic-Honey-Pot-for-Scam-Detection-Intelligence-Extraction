"""
Scam detection module using keyword and regex pattern matching.
"""

import re

SCAM_KEYWORDS = {
    "urgent", "blocked", "verify", "otp", "upi", "kyc", "payment", "link",
    "suspend", "expire", "immediately", "click", "account", "bank", "transfer",
    "prize", "winner", "lottery", "refund", "update", "confirm", "credentials"
}

SCAM_PATTERNS = [
    r"click\s+(here|this|the\s+link)",
    r"(verify|confirm)\s+(your\s+)?(account|identity|details)",
    r"(send|share)\s+(your\s+)?(otp|pin|password)",
    r"(urgent|immediate)\s+(action|attention)",
    r"account\s+(blocked|suspended|locked)",
    r"(upi|bank)\s+(id|pin|transfer)",
    r"(kyc|verification)\s+(pending|required|expired)",
    r"(won|winner|prize|lottery)",
]


def _normalize_text(text: str) -> str:
    """
    Normalize text for consistent matching.

    Args:
        text: Input text to normalize.

    Returns:
        Lowercase, stripped text.
    """
    return text.lower().strip()


def _check_keywords(text: str) -> int:
    """
    Count scam keyword occurrences in text.

    Args:
        text: Input text to analyze.

    Returns:
        Number of scam keywords found.
    """
    normalized = _normalize_text(text)
    return sum(1 for keyword in SCAM_KEYWORDS if keyword in normalized)


def _check_patterns(text: str) -> int:
    """
    Count scam pattern matches in text.

    Args:
        text: Input text to analyze.

    Returns:
        Number of scam patterns matched.
    """
    normalized = _normalize_text(text)
    return sum(1 for pattern in SCAM_PATTERNS if re.search(pattern, normalized))


def detect_scam(messages: list[dict[str, str]]) -> bool:
    """
    Detect if conversation contains scam indicators.

    Analyzes all messages in conversation for scam keywords and patterns.
    Returns True if threshold is met (>=3 keywords OR >=1 pattern match).

    Args:
        messages: List of message dicts with 'content' key.

    Returns:
        True if scam detected, False otherwise.
    """
    if not messages:
        return False

    total_keyword_hits = 0
    total_pattern_hits = 0

    for message in messages:
        content = message.get("content", "")
        total_keyword_hits += _check_keywords(content)
        total_pattern_hits += _check_patterns(content)

    return total_keyword_hits >= 3 or total_pattern_hits >= 1
