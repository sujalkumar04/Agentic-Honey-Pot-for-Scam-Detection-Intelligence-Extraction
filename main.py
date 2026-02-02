"""
================================================================================
🍯 Agentic Honey-Pot for Scam Detection & Intelligence Extraction
================================================================================

Purpose:
    AI-powered honeypot system that detects scams, engages scammers with a
    realistic persona, extracts intelligence, and reports findings in real-time.

API Endpoint:
    POST /honeypot
    - Accepts scam messages
    - Detects and classifies scam type
    - Extracts phone numbers, UPI IDs, URLs, bank accounts
    - Returns realistic persona-based replies
    - Auto-reports intelligence via callback

Tech Stack:
    - FastAPI (Python 3.11+)
    - Groq LLM (with regex fallback)
    - Pydantic validation
    - Session-based memory
    - Render deployment ready

Author:
    GUVI Hackathon 2026

License:
    MIT License
================================================================================
"""

import os
from dotenv import load_dotenv

load_dotenv()
from fastapi import FastAPI, Header, HTTPException, Depends
from pydantic import BaseModel
from typing import Any, Optional, Union

from memory import load_session, save_session, append_message
from detector import detect_scam
from agent import generate_reply
from extractor import extract_intel
from callback import send_callback
from scam_classifier import classify_scam

app = FastAPI(title="Agentic Honeypot API", version="1.0.0")


@app.get("/")
async def root():
    """Health check endpoint."""
    return {"status": "ok", "message": "Agentic Honeypot API is running"}


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


def verify_api_key(x_api_key: str = Header(...)) -> str:
    """Verify API key from request header."""
    api_key = os.getenv("API_KEY")
    if not api_key or x_api_key != api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key


# ============================================================================
# Request/Response Models (Hackathon Spec Compliant)
# ============================================================================

class MessageBody(BaseModel):
    """Incoming message structure."""
    sender: str
    text: str
    timestamp: Optional[Union[int, str, float]] = None  # Optional, accept any format

    class Config:
        extra = "allow"


class HistoryMessage(BaseModel):
    """Conversation history message structure."""
    sender: str
    text: str
    timestamp: Optional[Union[int, str, float]] = None

    class Config:
        extra = "allow"


class Metadata(BaseModel):
    """Optional metadata about the conversation."""
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None

    class Config:
        extra = "allow"


class HoneypotRequest(BaseModel):
    """
    Honeypot API request body.
    
    Matches hackathon specification:
    - sessionId: Unique conversation identifier
    - message: Current incoming message
    - conversationHistory: Previous messages (optional)
    - metadata: Channel/language info (optional)
    """
    sessionId: str
    message: MessageBody
    conversationHistory: Optional[list[HistoryMessage]] = None
    metadata: Optional[Metadata] = None

    class Config:
        extra = "allow"


class HoneypotResponse(BaseModel):
    """
    Honeypot API response body.
    
    Format: {"status": "success", "reply": "..."}
    """
    status: str
    reply: str


# ============================================================================
# Main Endpoint
# ============================================================================

@app.post("/honeypot", response_model=HoneypotResponse)
async def honeypot(
    request: HoneypotRequest,
    api_key: str = Depends(verify_api_key)
) -> HoneypotResponse:
    """
    Process incoming scam message and generate response.
    
    Flow:
    1. Load/create session
    2. Incorporate conversation history if provided
    3. Add new message to session
    4. Extract intelligence (Groq + regex)
    5. Detect and classify scam
    6. Generate persona-based reply
    7. Trigger callback if thresholds met
    """
    session_id = request.sessionId
    user_message = request.message.text

    # Load or create session
    session = load_session(session_id)

    # Incorporate conversation history if provided (for multi-turn support)
    if request.conversationHistory:
        _sync_conversation_history(session_id, request.conversationHistory)
        session = load_session(session_id)

    # Add current message
    append_message(session_id, "user", user_message)
    session = load_session(session_id)

    # Extract intelligence from user message
    session["intelligence"] = extract_intel(user_message, session.get("intelligence", {}))

    # Detect scam
    scam_detected = detect_scam(session["messages"])
    session["scamDetected"] = scam_detected

    # Classify scam type
    conversation_text = " ".join([m.get("content", "") for m in session["messages"]])
    scam_type = classify_scam(conversation_text)
    session["scamType"] = scam_type

    # Store metadata if provided
    if request.metadata:
        session["metadata"] = {
            "channel": request.metadata.channel,
            "language": request.metadata.language,
            "locale": request.metadata.locale
        }

    # Generate reply
    reply = generate_reply(
        history=session["messages"],
        latest_message=user_message,
        scam_detected=scam_detected
    )

    # Add reply to session
    append_message(session_id, "assistant", reply)
    session = load_session(session_id)

    # Extract intel from reply (in case agent mentions extractable data)
    session["intelligence"] = extract_intel(reply, session.get("intelligence", {}))

    # Save session
    save_session(session_id, session)

    # Check if callback should be triggered
    should_callback = (
        len(session["messages"]) >= 10 or
        _has_significant_intel(session.get("intelligence", {}))
    )

    if should_callback and not session.get("callbackSent", False):
        send_callback(session_id, session)
        session["callbackSent"] = True
        save_session(session_id, session)

    return HoneypotResponse(status="success", reply=reply)


# ============================================================================
# Helper Functions
# ============================================================================

def _sync_conversation_history(session_id: str, history: list[HistoryMessage]) -> None:
    """
    Sync provided conversation history with session memory.
    
    Adds any messages from conversationHistory that aren't already in session.
    """
    session = load_session(session_id)
    existing_contents = {m.get("content", "") for m in session.get("messages", [])}

    for msg in history:
        if msg.text not in existing_contents:
            role = "user" if msg.sender in ["scammer", "user"] else "assistant"
            append_message(session_id, role, msg.text)


def _has_significant_intel(intelligence: dict[str, Any]) -> bool:
    """Check if extracted intelligence contains actionable data."""
    significant_keys = ["bank_accounts", "upi_ids", "urls", "phone_numbers"]
    return any(intelligence.get(key) for key in significant_keys)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
