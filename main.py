"""
Agentic Honey-Pot for Scam Detection & Intelligence Extraction
GUVI Hackathon 2026
"""

import os
import uuid
from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Header, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Any, Optional, Union, List

from memory import load_session, save_session, append_message
from detector import detect_scam
from agent import generate_reply
from extractor import extract_intel
from callback import send_callback
from scam_classifier import classify_scam

app = FastAPI(title="Agentic Honeypot API", version="1.0.0")

# CORS for hackathon tester
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)


# Health endpoints
@app.get("/")
@app.head("/")
async def root():
    return {"status": "ok", "message": "Agentic Honeypot API is running"}


# Also accept POST at root for tester compatibility
@app.post("/")
async def root_post(request: Request):
    """Redirect POST at root to honeypot logic."""
    # Check API key
    api_key = request.headers.get("x-api-key")
    if not api_key:
        return JSONResponse(status_code=401, content={"status": "error", "detail": "x-api-key required"})
    
    try:
        body = await request.json()
    except:
        return JSONResponse(status_code=400, content={"status": "error", "detail": "Invalid JSON"})
    
    # Extract session ID
    session_id = body.get("sessionId") or body.get("session_id") or str(uuid.uuid4())
    
    # Extract message text
    message = body.get("message", {})
    if isinstance(message, str):
        user_message = message
    elif isinstance(message, dict):
        user_message = message.get("text") or message.get("content") or ""
    else:
        user_message = str(message) if message else ""
    
    if not user_message:
        return JSONResponse(status_code=400, content={"status": "error", "detail": "No message text"})
    
    # Process
    session = load_session(session_id)
    append_message(session_id, "user", user_message)
    session = load_session(session_id)
    
    session["intelligence"] = extract_intel(user_message, session.get("intelligence", {}))
    scam_detected = detect_scam(session["messages"])
    session["scamDetected"] = scam_detected
    
    reply = generate_reply(
        history=session["messages"],
        latest_message=user_message,
        scam_detected=scam_detected
    )
    
    append_message(session_id, "assistant", reply)
    save_session(session_id, session)
    
    return JSONResponse(content={"status": "success", "reply": reply})


@app.get("/health")
@app.head("/health")
async def health():
    return {"status": "healthy"}


@app.head("/honeypot")
async def honeypot_head():
    return {"status": "ok"}


# API Key verification - accepts any non-empty key
def verify_api_key(x_api_key: str = Header(None, alias="x-api-key")) -> str:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="x-api-key header required")
    return x_api_key


# ============================================================================
# EXACT Request Models per Problem Statement
# ============================================================================

class Message(BaseModel):
    """Message structure per PS section 6.1"""
    sender: str = "scammer"
    text: str
    timestamp: Optional[Any] = None  # Accept any format
    
    class Config:
        extra = "allow"


class HistoryMessage(BaseModel):
    """Conversation history message per PS section 6.2"""
    sender: str = "scammer"
    text: str
    timestamp: Optional[Any] = None
    
    class Config:
        extra = "allow"


class Metadata(BaseModel):
    """Metadata per PS section 6.3"""
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None
    
    class Config:
        extra = "allow"


class HoneypotRequest(BaseModel):
    """
    Request body per PS section 6.1 and 6.2
    
    Example:
    {
        "sessionId": "wertyu-dfghj-ertyui",
        "message": {
            "sender": "scammer",
            "text": "Your bank account will be blocked today.",
            "timestamp": 1770005528731
        },
        "conversationHistory": [],
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"}
    }
    """
    sessionId: str
    message: Message
    conversationHistory: Optional[List[HistoryMessage]] = Field(default_factory=list)
    metadata: Optional[Metadata] = None
    
    class Config:
        extra = "allow"


class HoneypotResponse(BaseModel):
    """
    Response per PS section 8
    
    Example:
    {"status": "success", "reply": "Why is my account being suspended?"}
    """
    status: str
    reply: str


# ============================================================================
# Main Honeypot Endpoint
# ============================================================================

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
        for msg in request.conversationHistory:
            existing = {m.get("content", "") for m in session.get("messages", [])}
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

    # Store metadata
    if request.metadata:
        session["metadata"] = {
            "channel": request.metadata.channel,
            "language": request.metadata.language,
            "locale": request.metadata.locale
        }

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

    # Send callback per PS section 12 (when thresholds met)
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


# ============================================================================
# Fallback endpoint for any JSON format
# ============================================================================

@app.api_route("/honeypot", methods=["POST", "PUT", "PATCH"])
async def honeypot_fallback(request: Request):
    """Fallback that accepts any JSON and tries to process it."""
    
    # Check API key
    api_key = request.headers.get("x-api-key")
    if not api_key:
        return JSONResponse(status_code=401, content={"status": "error", "detail": "x-api-key required"})
    
    try:
        body = await request.json()
    except:
        return JSONResponse(status_code=400, content={"status": "error", "detail": "Invalid JSON"})
    
    # Extract session ID
    session_id = body.get("sessionId") or body.get("session_id") or str(uuid.uuid4())
    
    # Extract message text
    message = body.get("message", {})
    if isinstance(message, str):
        user_message = message
    elif isinstance(message, dict):
        user_message = message.get("text") or message.get("content") or ""
    else:
        user_message = str(message) if message else ""
    
    if not user_message:
        return JSONResponse(status_code=400, content={"status": "error", "detail": "No message text"})
    
    # Process
    session = load_session(session_id)
    append_message(session_id, "user", user_message)
    session = load_session(session_id)
    
    session["intelligence"] = extract_intel(user_message, session.get("intelligence", {}))
    scam_detected = detect_scam(session["messages"])
    session["scamDetected"] = scam_detected
    
    reply = generate_reply(
        history=session["messages"],
        latest_message=user_message,
        scam_detected=scam_detected
    )
    
    append_message(session_id, "assistant", reply)
    save_session(session_id, session)
    
    return JSONResponse(content={"status": "success", "reply": reply})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
