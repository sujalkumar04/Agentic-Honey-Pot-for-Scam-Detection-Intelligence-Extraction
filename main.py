"""
Agentic Honey-Pot for Scam Detection & Intelligence Extraction
GUVI Hackathon 2026

POST /honeypot - Main API endpoint per Problem Statement
"""

import os
from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Any

from memory import load_session, save_session, append_message
from detector import detect_scam
from agent import generate_reply
from extractor import extract_intel
from callback import send_callback
from scam_classifier import classify_scam

app = FastAPI(title="Agentic Honeypot API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# API Key verification
def verify_api_key(x_api_key: str = Header(..., alias="x-api-key")) -> str:
    """Verify x-api-key header is present."""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="x-api-key required")
    return x_api_key


# Request Models per PS Section 6
class Message(BaseModel):
    sender: str
    text: str
    timestamp: Optional[Any] = None


class HistoryMessage(BaseModel):
    sender: str
    text: str
    timestamp: Optional[Any] = None


class Metadata(BaseModel):
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None


class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: Optional[List[HistoryMessage]] = []
    metadata: Optional[Metadata] = None


# Response Model per PS Section 8
class HoneypotResponse(BaseModel):
    status: str
    reply: str


# Main Endpoint per PS
@app.post("/honeypot", response_model=HoneypotResponse)
async def honeypot(
    request: HoneypotRequest,
    api_key: str = Depends(verify_api_key)
) -> HoneypotResponse:
    """
    Process scam message and return AI agent response.
    Per Problem Statement sections 6, 7, 8.
    """
    session_id = request.sessionId
    user_message = request.message.text

    # Load session
    session = load_session(session_id)

    # Sync conversation history if provided
    if request.conversationHistory:
        existing = {m.get("content", "") for m in session.get("messages", [])}
        for msg in request.conversationHistory:
            if msg.text not in existing:
                role = "user" if msg.sender in ["scammer", "user"] else "assistant"
                append_message(session_id, role, msg.text)
        session = load_session(session_id)

    # Add current message
    append_message(session_id, "user", user_message)
    session = load_session(session_id)

    # Extract intelligence
    session["intelligence"] = extract_intel(user_message, session.get("intelligence", {}))

    # Detect scam
    scam_detected = detect_scam(session["messages"])
    session["scamDetected"] = scam_detected

    # Classify scam type
    conversation_text = " ".join([m.get("content", "") for m in session["messages"]])
    scam_type = classify_scam(conversation_text)
    session["scamType"] = scam_type

    # Generate AI agent reply
    reply = generate_reply(
        history=session["messages"],
        latest_message=user_message,
        scam_detected=scam_detected
    )

    # Add reply to session
    append_message(session_id, "assistant", reply)
    session = load_session(session_id)

    # Save session
    save_session(session_id, session)

    # Send callback per PS section 12 when thresholds met
    should_callback = (
        len(session["messages"]) >= 10 or
        any(session.get("intelligence", {}).get(k) for k in ["bank_accounts", "upi_ids", "urls", "phone_numbers"])
    )

    if should_callback and not session.get("callbackSent", False):
        send_callback(session_id, session)
        session["callbackSent"] = True
        save_session(session_id, session)

    # Return response per PS section 8
    return HoneypotResponse(status="success", reply=reply)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
