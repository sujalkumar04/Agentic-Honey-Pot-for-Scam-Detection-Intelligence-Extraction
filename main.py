"""
Agentic Honey-Pot for Scam Detection & Intelligence Extraction
GUVI Hackathon 2026

POST /honeypot - Main API endpoint per Problem Statement
"""

import os
import uuid
import traceback
from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Header, HTTPException, Request, BackgroundTasks
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


def process_background_tasks(session_id: str, user_message: str):
    """
    Handle heavy AI tasks in background to ensure fast API response.
    Process: Extract Intelligence -> Classify Scam -> Send Callback
    """
    try:
        session = load_session(session_id)
        
        # 1. Extract Intelligence (Groq LLM)
        session["intelligence"] = extract_intel(user_message, session.get("intelligence", {}))
        
        # 2. Classify Scam Type (Groq LLM)
        conversation_text = " ".join([m.get("content", "") for m in session["messages"]])
        session["scamType"] = classify_scam(conversation_text)
        
        # Save updates
        save_session(session_id, session)
        
        # 3. Check & Send Callback
        should_callback = (
            len(session["messages"]) >= 10 or
            any(session.get("intelligence", {}).get(k) for k in ["bank_accounts", "upi_ids", "urls", "phone_numbers"])
        )
        
        if should_callback and not session.get("callbackSent", False):
            success = send_callback(session_id, session)
            if success:
                session["callbackSent"] = True
                save_session(session_id, session)
                
    except Exception as e:
        print(f"Background task error: {e}")
        traceback.print_exc()


@app.post("/honeypot")
async def honeypot(request: Request, background_tasks: BackgroundTasks):
    """
    Process scam message and return AI agent response.
    Optimized for <3s response time by moving LLM calls to background.
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
        print(f"DEBUG: Received Headers: {request.headers}")
        print(f"DEBUG: Received Body: {body}")
    except Exception as e:
        print(f"DEBUG: JSON Parse Error: {e}")
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
    
    # Detect scam (Fast local regex)
    scam_detected = detect_scam(session["messages"])
    session["scamDetected"] = scam_detected
    
    # Generate AI agent reply (Fast template selection)
    reply = generate_reply(
        history=session["messages"],
        latest_message=user_message,
        scam_detected=scam_detected
    )
    
    # Add reply to session
    append_message(session_id, "assistant", reply)
    # Save session with messages
    save_session(session_id, session)
    
    # Add heavy tasks to background to prevent timeout
    background_tasks.add_task(process_background_tasks, session_id, user_message)
    
    # Return response immediately
    return JSONResponse(content={"status": "success", "reply": reply})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
