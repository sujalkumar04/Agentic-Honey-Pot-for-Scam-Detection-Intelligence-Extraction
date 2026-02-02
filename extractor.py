"""
Hybrid intelligence extraction module using Groq LLM with regex fallback.
"""

import re
from typing import Any

from groq_extractor import groq_extract

PATTERNS = {
    "bank_accounts": r"\b\d{9,18}\b",
    "upi_ids": r"\b[\w.\-]+@[\w]+\b",
    "urls": r"https?://[^\s<>\"{}|\\^`\[\]]+",
    "phone_numbers": r"\+91[\s\-]?\d{10}|\b[6-9]\d{9}\b",
}

SUSPICIOUS_KEYWORDS = {
    "otp", "pin", "cvv", "password", "transfer", "urgent", "blocked",
    "suspend", "verify", "kyc", "refund", "prize", "lottery", "winner",
    "click", "link", "account", "bank", "upi", "payment", "expired"
}

FIELD_MAPPING = {
    "bankAccounts": "bank_accounts",
    "upiIds": "upi_ids",
    "phishingLinks": "urls",
    "phoneNumbers": "phone_numbers",
    "suspiciousKeywords": "suspicious_keywords"
}


def _extract_pattern(text: str, pattern: str) -> list[str]:
    """
    Extract matches for a regex pattern from text.

    Args:
        text: Input text to search.
        pattern: Regex pattern to match.

    Returns:
        List of unique matches found.
    """
    return list(set(re.findall(pattern, text, re.IGNORECASE)))


def _extract_keywords(text: str) -> list[str]:
    """
    Extract suspicious keywords from text.

    Args:
        text: Input text to analyze.

    Returns:
        List of suspicious keywords found.
    """
    text_lower = text.lower()
    return [kw for kw in SUSPICIOUS_KEYWORDS if kw in text_lower]


def _merge_unique(existing: list[Any], new: list[Any]) -> list[Any]:
    """
    Merge two lists and remove duplicates.

    Args:
        existing: Existing list of items.
        new: New items to add.

    Returns:
        Combined list with duplicates removed.
    """
    combined = set(existing) if existing else set()
    combined.update(new)
    return list(combined)


def merge_intelligence(base: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """
    Merge two intelligence dictionaries with deduplication.

    Args:
        base: Base intelligence dictionary to merge into.
        new: New intelligence data to merge.

    Returns:
        Merged dictionary with deduplicated lists.
    """
    if base is None:
        base = {}
    if new is None:
        return base

    all_keys = set(base.keys()) | set(new.keys())

    for key in all_keys:
        base_val = base.get(key, [])
        new_val = new.get(key, [])

        if isinstance(base_val, list) and isinstance(new_val, list):
            base[key] = _merge_unique(base_val, new_val)
        elif isinstance(new_val, list):
            base[key] = list(set(new_val))
        elif isinstance(base_val, list):
            pass
        else:
            base[key] = new_val

    return base


def _regex_extract(text: str) -> dict[str, list[str]]:
    """
    Extract intelligence using regex patterns.

    Args:
        text: Input text to analyze.

    Returns:
        Dictionary with extracted bank accounts, UPI IDs, URLs, phone numbers, keywords.
    """
    result = {}
    for key, pattern in PATTERNS.items():
        matches = _extract_pattern(text, pattern)
        if matches:
            result[key] = matches

    keywords = _extract_keywords(text)
    if keywords:
        result["suspicious_keywords"] = keywords

    return result


def _has_values(data: dict) -> bool:
    """
    Check if dictionary has any non-empty values.

    Args:
        data: Dictionary to check.

    Returns:
        True if any value is truthy, False otherwise.
    """
    return any(bool(v) for v in data.values())


def _normalize_groq_result(groq_result: dict) -> dict[str, list[str]]:
    """
    Normalize Groq LLM result to match local field names.

    Args:
        groq_result: Raw result from Groq extractor.

    Returns:
        Normalized dictionary with local field names.
    """
    normalized = {}
    for groq_key, local_key in FIELD_MAPPING.items():
        values = groq_result.get(groq_key, [])
        if values:
            normalized[local_key] = values
    return normalized


def extract_intel(text: str, intelligence: dict[str, Any]) -> dict[str, Any]:
    """
    Extract intelligence from text using hybrid Groq + regex approach.

    Primary: Attempts Groq LLM extraction for intelligent parsing.
    Fallback: Uses regex patterns if Groq fails or returns empty.

    Args:
        text: Input text to extract intelligence from.
        intelligence: Existing intelligence dictionary to merge into.

    Returns:
        Updated intelligence dictionary with extracted data.
    """
    if intelligence is None:
        intelligence = {}

    groq_result = groq_extract(text)

    if _has_values(groq_result):
        normalized = _normalize_groq_result(groq_result)
        for key, values in normalized.items():
            intelligence[key] = _merge_unique(intelligence.get(key, []), values)
    else:
        regex_result = _regex_extract(text)
        for key, values in regex_result.items():
            intelligence[key] = _merge_unique(intelligence.get(key, []), values)

    return intelligence
