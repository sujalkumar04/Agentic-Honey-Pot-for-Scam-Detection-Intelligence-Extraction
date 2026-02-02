"""
Hybrid scam classification module using Groq LLM with rule-based fallback.
"""

from groq_classifier import groq_classify

SCAM_RULES = [
    ({"@upi", "upi", "pay", "transfer"}, "UPI_PAYMENT_SCAM"),
    ({"http", "https", "link"}, "PHISHING_LINK"),
    ({"otp", "code"}, "OTP_FRAUD"),
    ({"kyc", "verify account", "blocked"}, "BANK_KYC_FRAUD"),
    ({"job", "salary", "hiring"}, "JOB_SCAM"),
    ({"lottery", "prize", "winner"}, "LOTTERY_SCAM"),
]


def classify_scam_rule_based(text: str) -> str:
    """
    Classify scam type using keyword-based rules.

    Checks text against predefined keyword sets to determine scam category.

    Args:
        text: Input text to classify.

    Returns:
        Scam type string: UPI_PAYMENT_SCAM, PHISHING_LINK, OTP_FRAUD,
        BANK_KYC_FRAUD, JOB_SCAM, LOTTERY_SCAM, or UNKNOWN.
    """
    if not text:
        return "UNKNOWN"

    text_lower = text.lower()

    for keywords, scam_type in SCAM_RULES:
        for keyword in keywords:
            if keyword in text_lower:
                return scam_type

    return "UNKNOWN"


def classify_scam(text: str) -> str:
    """
    Classify scam type using hybrid Groq + rule-based approach.

    Primary: Attempts Groq LLM classification for intelligent categorization.
    Fallback: Uses rule-based keyword matching if Groq fails or returns UNKNOWN.

    Args:
        text: Input text to classify.

    Returns:
        Scam type string: UPI_PAYMENT_SCAM, PHISHING_LINK, OTP_FRAUD,
        BANK_KYC_FRAUD, JOB_SCAM, LOTTERY_SCAM, or UNKNOWN.
    """
    if not text:
        return "UNKNOWN"

    groq_result = groq_classify(text)

    if groq_result != "UNKNOWN":
        return groq_result

    return classify_scam_rule_based(text)
