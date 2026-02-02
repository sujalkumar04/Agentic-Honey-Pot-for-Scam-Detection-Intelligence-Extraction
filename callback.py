"""
Callback module for reporting scam intelligence to external API.
"""

import requests
from typing import Any

CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
TIMEOUT = 5


def send_callback(session_id: str, session: dict[str, Any]) -> bool:
    """
    Send scam intelligence report to external callback API.

    Posts session data including scam detection results, extracted intelligence,
    and agent notes to the hackathon reporting endpoint.

    Args:
        session_id: Unique identifier for the conversation session.
        session: Session dictionary containing scamDetected, scamType,
                 messages, and intelligence data.

    Returns:
        True if callback succeeded (HTTP 200), False otherwise.
    """
    payload = {
        "sessionId": session_id,
        "scamDetected": session.get("scamDetected", False),
        "scamType": session.get("scamType", "UNKNOWN"),
        "totalMessagesExchanged": len(session.get("messages", [])),
        "extractedIntelligence": session.get("intelligence", {}),
        "agentNotes": _generate_notes(session),
    }

    try:
        response = requests.post(
            CALLBACK_URL,
            json=payload,
            timeout=TIMEOUT
        )
        return response.status_code == 200
    except Exception:
        return False


def _generate_notes(session: dict[str, Any]) -> str:
    """
    Generate human-readable agent notes from session data.

    Creates a summary string describing detected scam type, tactics used,
    and extracted intelligence items.

    Args:
        session: Session dictionary with scamType and intelligence.

    Returns:
        Formatted notes string for reporting.
    """
    notes = []
    
    scam_type = session.get("scamType", "UNKNOWN")
    intel = session.get("intelligence", {})
    
    if session.get("scamDetected"):
        scam_details = _get_scam_details(scam_type, intel)
        notes.append(f"{scam_type} detected. {scam_details}")
    
    if intel.get("phone_numbers"):
        notes.append(f"Phone numbers: {', '.join(intel['phone_numbers'])}")
    if intel.get("upi_ids"):
        notes.append(f"UPI IDs: {', '.join(intel['upi_ids'])}")
    if intel.get("bank_accounts"):
        notes.append(f"Bank accounts: {', '.join(intel['bank_accounts'])}")
    if intel.get("urls"):
        notes.append(f"URLs: {', '.join(intel['urls'])}")
    
    msg_count = len(session.get("messages", []))
    notes.append(f"Total messages: {msg_count}")
    
    return " | ".join(notes) if notes else "No significant activity detected."


def _get_scam_details(scam_type: str, intel: dict[str, Any]) -> str:
    """
    Generate scam-specific details based on type and intelligence.

    Args:
        scam_type: Classified scam type string.
        intel: Extracted intelligence dictionary.

    Returns:
        Descriptive string about the scam tactics used.
    """
    upi_ids = intel.get("upi_ids", [])
    urls = intel.get("urls", [])
    phone_numbers = intel.get("phone_numbers", [])
    
    if scam_type == "UPI_PAYMENT_SCAM" and upi_ids:
        return f"Scammer requested transfer to {upi_ids[0]}"
    elif scam_type == "PHISHING_LINK" and urls:
        return f"Scammer shared malicious link {urls[0]}"
    elif scam_type == "OTP_FRAUD":
        return "Scammer attempted to steal OTP/verification code"
    elif scam_type == "BANK_KYC_FRAUD":
        return "Scammer impersonated bank for KYC verification"
    elif scam_type == "JOB_SCAM":
        return "Scammer offered fake job opportunity"
    elif scam_type == "LOTTERY_SCAM":
        return "Scammer claimed victim won lottery/prize"
    else:
        return "Scammer used urgency and social engineering"
