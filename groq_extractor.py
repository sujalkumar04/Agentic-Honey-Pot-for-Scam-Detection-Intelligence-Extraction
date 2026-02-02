"""
Groq LLM-based intelligence extraction module.
"""

import os
import json
from groq import Groq

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
MODEL = "llama3-8b-8192"
TIMEOUT = 3

SYSTEM_PROMPT = """You are an intelligence extraction assistant. Analyze the given text and extract any scam-related information.

Return ONLY a valid JSON object with this exact structure:
{
  "bankAccounts": [],
  "upiIds": [],
  "phishingLinks": [],
  "phoneNumbers": [],
  "suspiciousKeywords": []
}

Rules:
- bankAccounts: Extract any bank account numbers (9-18 digits)
- upiIds: Extract UPI IDs (format: name@bank)
- phishingLinks: Extract any URLs or links
- phoneNumbers: Extract phone numbers (Indian format preferred)
- suspiciousKeywords: Extract scam-related keywords like OTP, KYC, verify, urgent, blocked, etc.

Return ONLY the JSON object, no other text."""


def groq_extract(text: str) -> dict:
    """
    Extract scam intelligence from text using Groq LLM.

    Uses Groq's fast inference to intelligently parse text for scam indicators
    including bank accounts, UPI IDs, phishing links, phone numbers, and keywords.

    Args:
        text: Input text to analyze for scam intelligence.

    Returns:
        Dictionary with keys: bankAccounts, upiIds, phishingLinks,
        phoneNumbers, suspiciousKeywords. Returns empty dict on failure.
    """
    if not GROQ_API_KEY or not text:
        return _empty_result()

    try:
        client = Groq(api_key=GROQ_API_KEY, timeout=TIMEOUT)

        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Extract intelligence from this text:\n\n{text}"}
            ],
            temperature=0.1,
            max_tokens=500
        )

        content = response.choices[0].message.content.strip()
        return _parse_response(content)

    except Exception:
        return _empty_result()


def _parse_response(content: str) -> dict:
    """
    Parse LLM response into structured dictionary.

    Handles markdown code blocks and validates JSON structure.

    Args:
        content: Raw LLM response string.

    Returns:
        Parsed dictionary with intelligence fields.
    """
    try:
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]

        result = json.loads(content.strip())

        return {
            "bankAccounts": result.get("bankAccounts", []),
            "upiIds": result.get("upiIds", []),
            "phishingLinks": result.get("phishingLinks", []),
            "phoneNumbers": result.get("phoneNumbers", []),
            "suspiciousKeywords": result.get("suspiciousKeywords", [])
        }

    except (json.JSONDecodeError, KeyError, TypeError):
        return _empty_result()


def _empty_result() -> dict:
    """
    Return empty intelligence structure.

    Returns:
        Dictionary with all intelligence fields as empty lists.
    """
    return {
        "bankAccounts": [],
        "upiIds": [],
        "phishingLinks": [],
        "phoneNumbers": [],
        "suspiciousKeywords": []
    }
