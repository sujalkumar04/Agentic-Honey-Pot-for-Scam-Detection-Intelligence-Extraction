# 🍯 Agentic Honey-Pot for Scam Detection & Intelligence Extraction

An AI-powered honeypot system that detects scams, engages scammers with a realistic persona, extracts intelligence, and reports findings — all in real-time.

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-green.svg)](https://fastapi.tiangolo.com)
[![Groq](https://img.shields.io/badge/Groq-LLM-purple.svg)](https://groq.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📋 Features

- **Scam Detection** — Hybrid keyword + pattern matching with Groq LLM fallback
- **Scam Classification** — Categorizes scams: UPI, Phishing, OTP, KYC, Job, Lottery
- **Intelligence Extraction** — Extracts phone numbers, UPI IDs, bank accounts, URLs
- **Realistic Persona** — "Rahul" persona engages scammers naturally
- **Session Memory** — Maintains conversation history per session
- **Auto Callback** — Reports intelligence to external API after threshold
- **API Key Auth** — Secured endpoints with header-based authentication
- **Production Ready** — Docker + Render deployment support

---

## 🌟 Project Highlights

| Capability | What Makes It Special |
|------------|----------------------|
| **🤖 Hybrid AI + Regex** | Groq LLM for intelligent extraction with automatic regex fallback — zero downtime if API unavailable |
| **🎭 Agentic Persona** | "Rahul" — a confused, non-tech-savvy character who engages scammers naturally, asking questions and stalling without raising suspicion |
| **🏷️ Multi-Class Classification** | Automatically categorizes scams into 6 types (UPI, Phishing, OTP, KYC, Job, Lottery) for actionable intelligence |
| **📡 Real-Time Reporting** | Auto-triggers callback with extracted intel (phone numbers, UPI IDs, URLs) when thresholds are met |
| **⚡ Low Latency Design** | Sub-100ms response times using Groq's fast inference + lightweight regex fallback |
| **🛡️ Production-Grade** | API key auth, session memory, error handling, Docker support, Render-ready deployment |

> **Why This Matters**: Traditional honeypots passively collect data. This system *actively engages* scammers, *extracts actionable intelligence*, and *reports in real-time* — turning defense into offense.

---

## 🏗️ Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Scammer       │────▶│   FastAPI        │────▶│   Groq LLM      │
│   (Incoming)    │     │   /honeypot      │     │   (Optional)    │
└─────────────────┘     └────────┬─────────┘     └─────────────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        ▼                        ▼                        ▼
┌───────────────┐    ┌───────────────────┐    ┌───────────────────┐
│   Detector    │    │   Extractor       │    │   Classifier      │
│   (Scam?)     │    │   (Intel)         │    │   (Type)          │
└───────────────┘    └───────────────────┘    └───────────────────┘
        │                        │                        │
        └────────────────────────┼────────────────────────┘
                                 ▼
                    ┌───────────────────────┐
                    │   Agent (Rahul)       │
                    │   Generate Reply      │
                    └───────────────────────┘
                                 │
                                 ▼
                    ┌───────────────────────┐
                    │   Callback API        │
                    │   (Report Intel)      │
                    └───────────────────────┘
```

---

## 📁 Folder Structure

```
GUVI/
├── main.py              # FastAPI server & /honeypot endpoint
├── memory.py            # Session management (in-memory)
├── detector.py          # Scam detection (keyword + regex)
├── agent.py             # Rahul persona reply generator
├── extractor.py         # Hybrid intel extraction
├── groq_extractor.py    # Groq LLM-based extraction
├── scam_classifier.py   # Hybrid scam type classifier
├── groq_classifier.py   # Groq LLM-based classifier
├── callback.py          # External API callback
├── requirements.txt     # Python dependencies
├── Dockerfile           # Docker container config
├── .env                 # Environment variables (local)
├── .gitignore           # Git ignore rules
└── README.md            # This file
```

---

## 🚀 Setup Locally

### 1. Clone Repository
```bash
git clone https://github.com/your-username/agentic-honeypot.git
cd agentic-honeypot
```

### 2. Create Virtual Environment
```bash
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Linux/Mac
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Create `.env` file:
```env
API_KEY=your-api-key-here
GROQ_API_KEY=gsk_your-groq-api-key
```

| Variable | Required | Description |
|----------|----------|-------------|
| `API_KEY` | ✅ Yes | API key for endpoint authentication |
| `GROQ_API_KEY` | ❌ Optional | Groq API key for LLM features (falls back to regex) |

### 5. Run Server
```bash
uvicorn main:app --reload
```

Server runs at: `http://127.0.0.1:8000`

---

## 📡 API Usage

### Endpoint
```
POST /honeypot
```

### Headers
```
x-api-key: your-api-key
Content-Type: application/json
```

### Request Body
```json
{
  "sessionId": "unique-session-id",
  "message": {
    "sender": "scammer",
    "text": "Send ₹5000 to rahul123@upi urgently",
    "timestamp": "2026-02-02T12:00:00"
  }
}
```

### Response
```json
{
  "status": "success",
  "reply": "Haan ji, I am here. What is the matter?"
}
```

---

## 🧪 Test Commands

### PowerShell (Windows)
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/honeypot" -Method POST -Headers @{"x-api-key"="test"; "Content-Type"="application/json"} -Body '{"sessionId":"test1","message":{"sender":"scammer","text":"Send 5000 to rahul123@upi urgently","timestamp":"2026"}}'
```

### cURL (Linux/Mac)
```bash
curl -X POST http://127.0.0.1:8000/honeypot \
  -H "x-api-key: test" \
  -H "Content-Type: application/json" \
  -d '{"sessionId":"test1","message":{"sender":"scammer","text":"Send 5000 to rahul123@upi urgently","timestamp":"2026"}}'
```

---

## 📤 Callback Payload

When conditions are met (≥10 messages or significant intel), the system sends:

```json
{
  "sessionId": "test1",
  "scamDetected": true,
  "scamType": "UPI_PAYMENT_SCAM",
  "totalMessagesExchanged": 12,
  "extractedIntelligence": {
    "upi_ids": ["rahul123@upi"],
    "phone_numbers": ["+919876543210"],
    "urls": ["http://fake-bank.com"],
    "bank_accounts": ["1234567890123456"]
  },
  "agentNotes": "UPI_PAYMENT_SCAM detected. Scammer requested transfer to rahul123@upi | UPI IDs: rahul123@upi | Total messages: 12"
}
```

---

## 🚢 Deploy on Render

### 1. Push to GitHub
```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/your-username/repo.git
git push -u origin main
```

### 2. Create Render Web Service
1. Go to [render.com](https://render.com)
2. Create **New Web Service**
3. Connect GitHub repository
4. Configure:
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn main:app --host 0.0.0.0 --port 10000`
   - **Port**: `10000`

### 3. Add Environment Variables
In Render dashboard, add:
- `API_KEY` = your-api-key
- `GROQ_API_KEY` = your-groq-key

### 4. Deploy
Click **Deploy** — your API will be live at `https://your-app.onrender.com/honeypot`

---

## 🔄 Hybrid Fallback System

The system uses a **Groq-first, Regex-fallback** architecture:

| Component | Primary | Fallback |
|-----------|---------|----------|
| **Scam Classification** | Groq LLM | Rule-based keywords |
| **Intel Extraction** | Groq LLM | Regex patterns |
| **Reply Generation** | Template-based | — |
| **Scam Detection** | Keyword matching | — |

> **Note**: If `GROQ_API_KEY` is not set, the system automatically uses regex-based extraction and rule-based classification. No functionality is lost.

---

## 🎯 Scam Types Detected

| Type | Triggers |
|------|----------|
| `UPI_PAYMENT_SCAM` | upi, pay, transfer, @upi |
| `PHISHING_LINK` | http, https, link, click |
| `OTP_FRAUD` | otp, code, verification |
| `BANK_KYC_FRAUD` | kyc, verify, blocked, suspend |
| `JOB_SCAM` | job, salary, hiring, offer |
| `LOTTERY_SCAM` | lottery, prize, winner, won |

---

## 📄 License

This project is licensed under the MIT License.

---

## 🙏 Acknowledgments

- [FastAPI](https://fastapi.tiangolo.com) — Modern Python web framework
- [Groq](https://groq.com) — Ultra-fast LLM inference
- [GUVI Hackathon](https://guvi.in) — Competition platform

---

**Built with ❤️ for GUVI Hackathon 2026**
