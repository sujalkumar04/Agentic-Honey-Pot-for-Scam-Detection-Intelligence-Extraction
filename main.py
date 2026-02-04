"""
Agentic Honey-Pot for Scam Detection & Intelligence Extraction
GUVI Hackathon 2026

POST /honeypot - Main API endpoint per Problem Statement
"""

import os
import uuid
from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

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


@app.post("/honeypot")
async def honeypot(request: Request):
    """
    Process scam message and return AI agent response.
    Accepts any JSON format for maximum compatibility.
    """
    # Check API key
    api_key = request.headers.get("x-api-key")
    if not api_key:
        return JSONResponse(
            status_code=401,
            content={"status": "error", "reply": "x-api-key header required"}
        )
    
    # Parse JSON body
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "reply": "Invalid JSON body"}
        )
    
    # Extract sessionId (optional)
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
        return JSONResponse(
            status_code=400,
            content={"status": "error", "reply": "No message text found"}
        )
    
    # Load session
    session = load_session(session_id)
    
    # Sync conversation history if provided
    conv_history = body.get("conversationHistory", [])
    if conv_history:
        existing = {m.get("content", "") for m in session.get("messages", [])}
        for msg in conv_history:
            text = msg.get("text", "") if isinstance(msg, dict) else str(msg)
            if text and text not in existing:
                sender = msg.get("sender", "scammer") if isinstance(msg, dict) else "scammer"
                role = "user" if sender in ["scammer", "user"] else "assistant"
                append_message(session_id, role, text)
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
    return JSONResponse(content={"status": "success", "reply": reply})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
