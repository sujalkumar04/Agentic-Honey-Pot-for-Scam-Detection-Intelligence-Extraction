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
from typing import Any, Optional

from memory import load_session, save_session, append_message
from detector import detect_scam
from agent import generate_reply
from extractor import extract_intel
from callback import send_callback
from scam_classifier import classify_scam

app = FastAPI()


def verify_api_key(x_api_key: str = Header(...)) -> str:
    api_key = os.getenv("API_KEY")
    if not api_key or x_api_key != api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key


class MessageBody(BaseModel):
    sender: str
    text: str
    timestamp: str

    class Config:
        extra = "allow"


class HoneypotRequest(BaseModel):
    sessionId: str
    message: MessageBody

    class Config:
        extra = "allow"


class HoneypotResponse(BaseModel):
    status: str
    reply: str


@app.post("/honeypot", response_model=HoneypotResponse)
async def honeypot(
    request: HoneypotRequest,
    api_key: str = Depends(verify_api_key)
) -> HoneypotResponse:
    session_id = request.sessionId
    user_message = request.message.text

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
    session = load_session(session_id)

    session["intelligence"] = extract_intel(reply, session.get("intelligence", {}))

    save_session(session_id, session)

    should_callback = (
        len(session["messages"]) >= 10 or
        _has_significant_intel(session.get("intelligence", {}))
    )

    if should_callback and not session.get("callbackSent", False):
        send_callback(session_id, session)
        session["callbackSent"] = True
        save_session(session_id, session)

    return HoneypotResponse(status="success", reply=reply)


def _has_significant_intel(intelligence: dict[str, Any]) -> bool:
    significant_keys = ["bank_accounts", "upi_ids", "urls", "phone_numbers"]
    return any(intelligence.get(key) for key in significant_keys)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
