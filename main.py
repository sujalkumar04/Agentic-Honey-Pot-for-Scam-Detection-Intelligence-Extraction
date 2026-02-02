"""
================================================================================
🍯 Agentic Honey-Pot for Scam Detection & Intelligence Extraction
================================================================================
"""

import os
import uuid
from dotenv import load_dotenv

load_dotenv()
from fastapi import FastAPI, Header, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel
from typing import Any, Optional, Union

from memory import load_session, save_session, append_message
from detector import detect_scam
from agent import generate_reply
from extractor import extract_intel
from callback import send_callback
from scam_classifier import classify_scam

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Agentic Honeypot API", version="1.0.0")

# Add CORS middleware for hackathon tester compatibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Custom exception handler for validation errors
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"status": "error", "detail": str(exc.errors())}
    )


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
# Flexible Request Models
# ============================================================================

class MessageBody(BaseModel):
    sender: Optional[str] = "scammer"
    text: str
    timestamp: Optional[Union[int, str, float]] = None
    
    class Config:
        extra = "allow"


class HistoryMessage(BaseModel):
    sender: Optional[str] = "scammer"
    text: str
    timestamp: Optional[Union[int, str, float]] = None
    
    class Config:
        extra = "allow"


class Metadata(BaseModel):
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None
    
    class Config:
        extra = "allow"


class HoneypotRequest(BaseModel):
    sessionId: Optional[str] = None
    message: MessageBody
    conversationHistory: Optional[list[HistoryMessage]] = None
    metadata: Optional[Metadata] = None
    
    class Config:
        extra = "allow"


class HoneypotResponse(BaseModel):
    status: str
    reply: str


# ============================================================================
# Main Endpoint - Flexible Format
# ============================================================================

@app.post("/honeypot", response_model=HoneypotResponse)
async def honeypot(
    request: HoneypotRequest,
    api_key: str = Depends(verify_api_key)
) -> HoneypotResponse:
    """Process incoming scam message and generate response."""
    
    # Generate sessionId if not provided
    session_id = request.sessionId or str(uuid.uuid4())
    user_message = request.message.text

    # Load or create session
    session = load_session(session_id)

    # Sync conversation history if provided
    if request.conversationHistory:
        _sync_conversation_history(session_id, request.conversationHistory)
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

    # Generate reply
    reply = generate_reply(
        history=session["messages"],
        latest_message=user_message,
        scam_detected=scam_detected
    )

    # Add reply to session
    append_message(session_id, "assistant", reply)
    session = load_session(session_id)

    # Extract intel from reply
    session["intelligence"] = extract_intel(reply, session.get("intelligence", {}))

    # Save session
    save_session(session_id, session)

    # Trigger callback if thresholds met
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
# Alternative endpoint that accepts raw JSON for maximum flexibility
# ============================================================================

@app.post("/honeypot/raw")
async def honeypot_raw(
    request: Request,
    x_api_key: str = Header(...)
) -> dict:
    """Alternative endpoint accepting any JSON format."""
    
    # Verify API key
    api_key = os.getenv("API_KEY")
    if not api_key or x_api_key != api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    try:
        body = await request.json()
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    
    # Extract fields flexibly
    session_id = body.get("sessionId") or body.get("session_id") or str(uuid.uuid4())
    
    # Handle message in different formats
    message = body.get("message", {})
    if isinstance(message, str):
        user_message = message
    elif isinstance(message, dict):
        user_message = message.get("text") or message.get("content") or message.get("body") or ""
    else:
        user_message = str(message)
    
    if not user_message:
        raise HTTPException(status_code=400, detail="No message text found")
    
    # Process the message
    session = load_session(session_id)
    append_message(session_id, "user", user_message)
    session = load_session(session_id)
    
    session["intelligence"] = extract_intel(user_message, session.get("intelligence", {}))
    scam_detected = detect_scam(session["messages"])
    session["scamDetected"] = scam_detected
    
    conversation_text = " ".join([m.get("content", "") for m in session["messages"]])
    scam_type = classify_scam(conversation_text)
    session["scamType"] = scam_type
    
    reply = generate_reply(
        history=session["messages"],
        latest_message=user_message,
        scam_detected=scam_detected
    )
    
    append_message(session_id, "assistant", reply)
    save_session(session_id, session)
    
    return {"status": "success", "reply": reply}


# ============================================================================
# Helper Functions
# ============================================================================

def _sync_conversation_history(session_id: str, history: list[HistoryMessage]) -> None:
    """Sync conversation history with session memory."""
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
