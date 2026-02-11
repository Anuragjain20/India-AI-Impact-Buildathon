# 🕵️ Agentic Honey-Pot — Scam Detection & Intelligence Extraction

A FastAPI-powered honeypot system that autonomously detects scam messages, engages scammers via a human-like AI agent, extracts actionable intelligence, and reports findings back to the GUVI evaluation endpoint.

---

## 📐 Architecture Overview

```
Incoming Message
       │
       ▼
┌─────────────────┐
│  POST /honeypot │  ← evaluation platform sends scammer message
└────────┬────────┘
         │
         ▼
┌─────────────────┐     NO      ┌──────────────────┐
│  Scam Detection │ ──────────► │ Neutral Reply    │
│  (Claude LLM)   │             │ (no engagement)  │
└────────┬────────┘             └──────────────────┘
         │ YES
         ▼
┌─────────────────┐
│  Agent Engages  │  ← generates a naive, cooperative reply
│  (Claude LLM)   │     to keep the scammer talking
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Intel Extract  │  ← pulls UPIs, links, accounts, keywords
│  (Claude LLM)   │     from the conversation so far
└────────┬────────┘
         │  (after ≥ 4 turns + meaningful intel found)
         ▼
┌─────────────────┐
│  GUVI Callback  │  → POST extracted intel to evaluation endpoint
└─────────────────┘
```

---

## 🗂️ File Structure

```
honeypot/
├── main.py            # Full FastAPI application (single-file)
├── requirements.txt   # Python dependencies
├── .env.example       # Environment variable template
└── README.md          # This file
```

---

## ⚙️ Setup & Run

### 1. Create Environment
```bash
python -m venv env
```

### 2. Activate Environment
```bash
Powershell - .\env\Scripts\Activate.ps1
CMD - env\Scripts\activate
Ubuntu - source env/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure environment
```bash
cp .env.example .env
# Edit .env — set ANTHROPIC_API_KEY and optionally change HONEYPOT_API_KEY
```

### 5. Start the server
```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

The API will be live at `http://localhost:8000`.

---

## 🔗 Endpoints

| Method | Path                              | Description                         |
|--------|-----------------------------------|-------------------------------------|
| POST   | `/honeypot`                       | Main honeypot endpoint              |
| GET    | `/health`                         | Health check                        |
| GET    | `/debug/session/{session_id}`     | Inspect live session state (dev)    |
| POST   | `/debug/send-callback/{session_id}` | Force GUVI callback (dev/testing) |

All endpoints except `/health` require the `x-api-key` header.

---

## 📩 Request / Response Example

### Request
```http
POST /honeypot
x-api-key: my-secret-honeypot-key
Content-Type: application/json

{
  "sessionId": "wertyu-dfghj-ertyui",
  "message": {
    "sender": "scammer",
    "text": "Your bank account will be blocked today. Verify immediately.",
    "timestamp": "2026-01-21T10:15:30Z"
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

### Response
```json
{
  "status": "success",
  "reply": "Oh no, really?! What do I need to do? I'm not very good with this stuff…"
}
```

---

## 🧠 How Each Stage Works

### 1. Scam Detection
Every incoming message is classified by Claude using a zero-shot prompt. The model returns a structured JSON with `scam_detected`, `confidence`, `scam_type`, and a `reason`. If confidence ≥ 0.5 and scam is flagged, the session is marked and the agent activates.

### 2. Agent Engagement
Claude plays a naive, slightly confused human victim. It keeps the scammer talking by being cooperative without ever hinting it knows the conversation is being monitored. It never shares real data — any "personal info" it gives is obviously fabricated (e.g. `victim123@fakebank`).

### 3. Intelligence Extraction
After each agent turn, Claude scans the full conversation and extracts:
- **Bank account numbers**
- **UPI IDs**
- **Phishing / malicious links**
- **Phone numbers**
- **Suspicious keywords / phrases**

Extracted items are merged (deduplicated) into the session state.

### 4. GUVI Callback
Once the session has ≥ 4 messages exchanged AND either meaningful intel has been found or ≥ 8 messages have passed, the system POSTs the final structured payload to `https://hackathon.guvi.in/api/updateHoneyPotFinalResult`. A `/debug/send-callback/{id}` endpoint is available to trigger this manually during testing.

---

## 🏭 Deploying to Production

For public deployment (e.g. Railway, Render, Fly.io, or a VPS):

1. Set environment variables `ANTHROPIC_API_KEY` and `HONEYPOT_API_KEY` in your platform's secrets panel.
2. The `uvicorn` start command is: `uvicorn main:app --host 0.0.0.0 --port 8000`
3. Make sure your platform exposes the port publicly.
4. The evaluation platform will hit your public URL at `/honeypot`.

> **Note:** The in-memory session store (`sessions: dict`) is fine for evaluation. For production-grade persistence, swap it for Redis or a database.
