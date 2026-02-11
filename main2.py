"""
ROBUST HONEYPOT v5.1 - Enhanced Callback Reliability
=====================================================
Added comprehensive error handling and debugging for callbacks
"""

import re
import os
import json
import logging
import asyncio
import traceback
import httpx

from typing import Optional, Dict, List, Set
from dataclasses import dataclass, field
from collections import Counter
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from langchain_groq import ChatGroq

load_dotenv()

# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING - Enhanced for debugging
# ═══════════════════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

API_KEY = os.getenv("HONEYPOT_API_KEY", "my-secret-honeypot-key")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GUVI_CALLBACK_URL = os.getenv("GUVI_CALLBACK_URL", "https://hackathon.guvi.in/api/updateHoneyPotFinalResult")
GROQ_MODEL = os.getenv("GROQ_MODEL", "meta-llama/llama-4-maverick-17b-128e-instruct")

# Limits
MAX_TURNS = 30
EARLY_EXIT_TURNS = 8
HIGH_VALUE_SCORE = 30
REPETITION_THRESHOLD = 3
CIRCULAR_THRESHOLD = 2

# Callback settings
CALLBACK_TIMEOUT = 30  # Increased timeout
CALLBACK_MAX_RETRIES = 5  # More retries
CALLBACK_RETRY_DELAY = 2  # Longer delay between retries

# ═══════════════════════════════════════════════════════════════════════════════
# DATA MODELS (same as before)
# ═══════════════════════════════════════════════════════════════════════════════

class MessagePayload(BaseModel):
    sender: str
    text: str
    timestamp: int

class MetadataPayload(BaseModel):
    channel: Optional[str] = "SMS"
    language: Optional[str] = "English"
    locale: Optional[str] = "IN"

class HoneyPotRequest(BaseModel):
    sessionId: str
    message: MessagePayload
    conversationHistory: List[MessagePayload] = Field(default_factory=list)
    metadata: Optional[MetadataPayload] = None

class HoneyPotResponse(BaseModel):
    status: str
    reply: str

@dataclass
class SessionState:
    """Session state with callback tracking"""
    session_id: str
    turn_count: int = 0
    scam_detected: bool = False
    scam_confidence: float = 0.0
    
    # Intelligence
    upi_ids: List[str] = field(default_factory=list)
    bank_accounts: List[str] = field(default_factory=list)
    phone_numbers: List[str] = field(default_factory=list)
    phishing_links: List[str] = field(default_factory=list)
    amounts: List[str] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)
    
    # Conversation
    messages: List[Dict[str, str]] = field(default_factory=list)
    asked_for: Set[str] = field(default_factory=set)
    victim_responses: List[str] = field(default_factory=list)
    scammer_responses: List[str] = field(default_factory=list)
    
    # Callback tracking
    callback_sent: bool = False
    callback_attempts: int = 0
    callback_error: Optional[str] = None
    termination_scheduled: bool = False
    
    def get_intel_score(self) -> int:
        return (
            len(self.upi_ids) * 15 +
            len(self.bank_accounts) * 15 +
            len(self.phishing_links) * 10 +
            len(self.phone_numbers) * 10 +
            len(self.amounts) * 5
        )
    
    def has_critical_intel(self) -> bool:
        return bool(self.upi_ids or self.bank_accounts or self.phishing_links or self.phone_numbers)
    
    def detect_circular_conversation(self) -> bool:
        if len(self.victim_responses) < 6:
            return False
        recent = self.victim_responses[-6:]
        normalized = [r.lower().strip() for r in recent]
        counter = Counter(normalized)
        max_repeats = max(counter.values()) if counter else 0
        return max_repeats >= CIRCULAR_THRESHOLD
    
    def track_question_asked(self, question_type: str):
        self.asked_for.add(question_type)
    
    def times_asked_for(self, question_type: str) -> int:
        count = 0
        keywords = {
            "upi": ["upi", "upi id"],
            "phone": ["number", "phone", "call"],
            "link": ["link", "url"],
            "account": ["account", "bank"],
            "otp": ["otp", "code"],
            "email": ["email", "mail"]
        }
        search_terms = keywords.get(question_type, [question_type])
        for response in self.victim_responses:
            lower = response.lower()
            if any(term in lower for term in search_terms):
                count += 1
        return count

# ═══════════════════════════════════════════════════════════════════════════════
# SESSION STORE
# ═══════════════════════════════════════════════════════════════════════════════

sessions: Dict[str, SessionState] = {}

def get_session(session_id: str) -> SessionState:
    if session_id not in sessions:
        sessions[session_id] = SessionState(session_id=session_id)
    return sessions[session_id]

# ═══════════════════════════════════════════════════════════════════════════════
# INTELLIGENCE EXTRACTION (same as before)
# ═══════════════════════════════════════════════════════════════════════════════

def extract_intelligence(text: str, session: SessionState) -> None:
    """Extract intelligence using regex patterns"""
    normalized = text
    normalized = re.sub(r"(?i)\bhxxps?\b", "http", normalized)
    normalized = re.sub(r"(?i)\s*[\[\(\{]?\s*dot\s*[\]\)\}]?\s*", ".", normalized)
    normalized = re.sub(r"(?i)\s*[\[\(\{]?\s*at\s*[\]\)\}]?\s*", "@", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    
    # UPI IDs
    upi_pattern = r"\b[a-z0-9][a-z0-9._-]{1,64}@[a-z][a-z0-9]{1,24}\b"
    for match in re.finditer(upi_pattern, normalized, re.IGNORECASE):
        candidate = match.group(0)
        handle = candidate.split("@")[1].lower()
        if handle not in ["gmail", "yahoo", "outlook", "hotmail", "icloud"]:
            if candidate not in session.upi_ids:
                session.upi_ids.append(candidate)
                logger.info(f"💰 Extracted UPI: {candidate}")
    
    # Phone numbers
    phone_pattern = r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{9}(?!\d)"
    for match in re.finditer(phone_pattern, normalized):
        digits = re.sub(r"\D", "", match.group(0))
        if digits.startswith("91") and len(digits) == 12:
            digits = digits[2:]
        if len(digits) == 10:
            phone = f"+91{digits}"
            if phone not in session.phone_numbers:
                session.phone_numbers.append(phone)
                logger.info(f"📱 Extracted Phone: {phone}")
    
    # Bank accounts
    account_pattern = r"(?<!\d)\d{9,18}(?!\d)"
    phone_set = {p[-10:] for p in session.phone_numbers}
    for match in re.finditer(account_pattern, normalized):
        account = match.group(0)
        if len(account) == 10 and account in phone_set:
            continue
        if account not in session.bank_accounts:
            session.bank_accounts.append(account)
            logger.info(f"🏦 Extracted Account: {account}")
    
    # Links
    link_pattern = r"(?i)\b(?:https?://|www\.)[^\s]+"
    for match in re.finditer(link_pattern, normalized):
        link = match.group(0).rstrip(".,;:)]}\"'")
        if link not in session.phishing_links:
            session.phishing_links.append(link)
            logger.info(f"🔗 Extracted Link: {link}")
    
    # Amounts
    amount_pattern = r"\b(?:rs\.?|inr|rupees?)?\s?\d{3,7}\b"
    for match in re.finditer(amount_pattern, normalized, re.IGNORECASE):
        amount = match.group(0)
        if amount not in session.amounts:
            session.amounts.append(amount)
    
    # Keywords
    suspicious = ["urgent", "blocked", "verify", "otp", "kyc", "winner", "prize", 
                  "refund", "suspended", "immediately", "click", "link"]
    lower = normalized.lower()
    for keyword in suspicious:
        if keyword in lower and keyword not in session.keywords:
            session.keywords.append(keyword)

# ═══════════════════════════════════════════════════════════════════════════════
# SCAM DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

def detect_scam(text: str) -> tuple[bool, float]:
    """Fast rule-based scam detection"""
    lower = text.lower()
    signals = {
        "urgency": any(w in lower for w in ["urgent", "immediately", "now", "today", "asap"]),
        "authority": any(w in lower for w in ["bank", "rbi", "government", "police", "kyc"]),
        "fear": any(w in lower for w in ["blocked", "suspend", "freeze", "arrest", "penalty"]),
        "reward": any(w in lower for w in ["winner", "prize", "won", "congratulations"]),
        "payment": any(w in lower for w in ["upi", "paytm", "phonepe", "transfer", "payment"]),
        "link": bool(re.search(r"(?i)\b(?:https?://|www\.)", text)),
        "sensitive": any(w in lower for w in ["otp", "pin", "cvv", "password"])
    }
    score = sum(signals.values()) / len(signals)
    confidence = 0.3 + (score * 0.7)
    is_scam = confidence >= 0.5
    return is_scam, confidence

# ═══════════════════════════════════════════════════════════════════════════════
# VICTIM RESPONSE GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

llm = ChatGroq(
    model_name=GROQ_MODEL,
    temperature=0.8,
    api_key=GROQ_API_KEY,
)

def generate_victim_response(session: SessionState, scammer_msg: str) -> str:
    """Generate convincing victim responses with anti-repetition"""
    recent = session.messages[-8:] if len(session.messages) > 8 else session.messages
    context = "\n".join([f"{m['role']}: {m['content']}" for m in recent])
    
    missing = []
    if not session.upi_ids and session.times_asked_for("upi") < REPETITION_THRESHOLD:
        missing.append("UPI ID")
    if not session.phone_numbers and session.times_asked_for("phone") < REPETITION_THRESHOLD:
        missing.append("phone number")
    if not session.phishing_links and session.times_asked_for("link") < REPETITION_THRESHOLD:
        missing.append("verification link")
    if not session.bank_accounts and session.times_asked_for("account") < REPETITION_THRESHOLD:
        missing.append("bank account")
    
    already_asked = list(session.asked_for)
    
    if session.turn_count <= 3:
        phase = "initial confusion"
    elif session.turn_count <= 10:
        phase = "trying to comply"
    elif session.turn_count <= 20:
        phase = "getting skeptical"
    else:
        phase = "losing patience"
    
    repetition_note = ""
    if session.victim_responses:
        last_responses = session.victim_responses[-3:]
        repetition_note = f"\nYour last 3 responses: {last_responses}\nDO NOT repeat these!"
    
    prompt = f"""You are a real person texting with a scammer. Get THEIR info without repeating yourself.

AVOID REPETITION! Already asked: {', '.join(already_asked) if already_asked else 'nothing'}

CONVERSATION:
{context}

SCAMMER: {scammer_msg}

STATUS: Turn {session.turn_count}/{MAX_TURNS} | Phase: {phase} | Need: {', '.join(missing) if missing else 'wrapping up'}
{repetition_note}

STRATEGIES (pick what fits, DON'T repeat):

Need UPI (asked {session.times_asked_for("upi")} times):
→ "ok send upi id" / "which upi?" / "ur paytm number?"

Need phone (asked {session.times_asked_for("phone")} times):
→ "whats ur number?" / "ur contact?" / "which no to call?"

Need link (asked {session.times_asked_for("link")} times):
→ "send link" / "paste url" / "where is link?"

If vague/repeating:
→ "wait what?" / "how?" / "explain again?"

If stuck (turn 25+):
→ "let me ask my son" / "busy now" / "will do later"

RULES:
- Max 60 chars
- NEVER repeat last 3 responses
- Casual: "ok", "hmm", "k"
- Lowercase
- ONE question
- If looping, EXIT

Response (SHORT, NEW):"""

    try:
        response = llm.invoke(prompt)
        reply = response.content.strip().strip('"\'').replace('"', '').replace("'", "")
        if len(reply) > 120:
            reply = reply.split('.')[0].strip()
        if not reply:
            import random
            reply = random.choice(["ok", "hmm", "wait", "one sec"])
        return reply
    except Exception as e:
        logger.error(f"LLM failed: {e}")
        import random
        if not session.upi_ids and session.times_asked_for("upi") < 2:
            return random.choice(["whats ur upi?", "send upi", "upi id?"])
        elif not session.phone_numbers and session.times_asked_for("phone") < 2:
            return random.choice(["ur number?", "phone pls", "contact?"])
        else:
            return random.choice(["ok wait", "one min", "hmm"])

# ═══════════════════════════════════════════════════════════════════════════════
# TERMINATION
# ═══════════════════════════════════════════════════════════════════════════════

def should_terminate(session: SessionState) -> tuple[bool, str]:
    """Enhanced termination logic"""
    if session.turn_count >= MAX_TURNS:
        return True, "max_turns_reached"
    if session.detect_circular_conversation():
        return True, "circular_conversation"
    if session.turn_count >= EARLY_EXIT_TURNS:
        score = session.get_intel_score()
        if score >= HIGH_VALUE_SCORE:
            return True, f"high_intel_score_{score}"
        if session.has_critical_intel() and session.turn_count >= 12:
            return True, f"sufficient_intel_{score}"
    for qt in ["upi", "phone", "link", "account"]:
        if session.times_asked_for(qt) >= REPETITION_THRESHOLD and session.turn_count >= 15:
            return True, f"stuck_asking_{qt}"
    if session.turn_count >= 20 and not session.has_critical_intel():
        return True, "no_intel_long_chat"
    return False, ""

# ═══════════════════════════════════════════════════════════════════════════════
# ENHANCED CALLBACK WITH COMPREHENSIVE ERROR HANDLING
# ═══════════════════════════════════════════════════════════════════════════════

async def send_callback(session: SessionState, max_retries: int = CALLBACK_MAX_RETRIES):
    """
    Enhanced callback with detailed error handling and multiple strategies
    """
    if session.callback_sent:
        logger.info(f"⏭️  Callback already sent for {session.session_id}")
        return True
    
    payload = {
        "sessionId": session.session_id,
        "scamDetected": session.scam_detected,
        "totalMessagesExchanged": session.turn_count,
        "extractedIntelligence": {
            "bankAccounts": session.bank_accounts,
            "upiIds": session.upi_ids,
            "phishingLinks": session.phishing_links,
            "phoneNumbers": session.phone_numbers,
            "suspiciousKeywords": session.keywords,
        },
        "agentNotes": f"Intel:{session.get_intel_score()}|Conf:{session.scam_confidence:.2f}|Turns:{session.turn_count}"
    }
    
    logger.info("=" * 70)
    logger.info(f"📤 INITIATING CALLBACK: {session.session_id}")
    logger.info(f"   URL: {GUVI_CALLBACK_URL}")
    logger.info(f"   Intel Score: {session.get_intel_score()}")
    logger.info(f"   Payload: {json.dumps(payload, indent=2)}")
    logger.info("=" * 70)
    
    # Try multiple header configurations
    header_configs = [
        {"Content-Type": "application/json"},
        {"Content-Type": "application/json", "Accept": "application/json"},
        {"Content-Type": "application/json", "User-Agent": "Honeypot/5.1"},
    ]
    
    for attempt in range(max_retries):
        session.callback_attempts += 1
        headers = header_configs[attempt % len(header_configs)]
        
        logger.info(f"\n🔄 Attempt {attempt + 1}/{max_retries}")
        logger.info(f"   Headers: {headers}")
        
        try:
            async with httpx.AsyncClient(
                timeout=CALLBACK_TIMEOUT,
                follow_redirects=True
            ) as client:
                response = await client.post(
                    GUVI_CALLBACK_URL,
                    json=payload,
                    headers=headers
                )
                
                logger.info(f"   📡 Status Code: {response.status_code}")
                logger.info(f"   📋 Response Headers: {dict(response.headers)}")
                logger.info(f"   📝 Response Body: {response.text[:500]}")
                
                if response.status_code in (200, 201, 202):
                    session.callback_sent = True
                    logger.info(f"✅ ✅ ✅ CALLBACK SUCCESS! ✅ ✅ ✅")
                    return True
                elif response.status_code == 400:
                    logger.error(f"❌ BAD REQUEST (400) - Payload issue")
                    logger.error(f"   Response: {response.text}")
                    session.callback_error = f"400: {response.text[:200]}"
                elif response.status_code == 404:
                    logger.error(f"❌ NOT FOUND (404) - URL issue")
                    session.callback_error = "404: Endpoint not found"
                elif response.status_code >= 500:
                    logger.error(f"❌ SERVER ERROR ({response.status_code})")
                    session.callback_error = f"{response.status_code}: Server error"
                else:
                    logger.warning(f"⚠️  Unexpected status: {response.status_code}")
                    session.callback_error = f"{response.status_code}: {response.text[:200]}"
                    
        except httpx.TimeoutException as e:
            logger.error(f"❌ TIMEOUT after {CALLBACK_TIMEOUT}s: {e}")
            session.callback_error = f"Timeout: {e}"
        except httpx.ConnectError as e:
            logger.error(f"❌ CONNECTION ERROR: {e}")
            session.callback_error = f"ConnectError: {e}"
        except httpx.HTTPStatusError as e:
            logger.error(f"❌ HTTP ERROR: {e}")
            session.callback_error = f"HTTPError: {e}"
        except Exception as e:
            logger.error(f"❌ UNEXPECTED ERROR: {type(e).__name__}: {e}")
            logger.error(f"   Traceback:\n{traceback.format_exc()}")
            session.callback_error = f"{type(e).__name__}: {str(e)[:200]}"
        
        if attempt < max_retries - 1:
            wait_time = CALLBACK_RETRY_DELAY * (attempt + 1)
            logger.info(f"   ⏳ Waiting {wait_time}s before retry...")
            await asyncio.sleep(wait_time)
    
    logger.error(f"💥 💥 💥 CALLBACK FAILED after {max_retries} attempts 💥 💥 💥")
    logger.error(f"   Last error: {session.callback_error}")
    return False

# ═══════════════════════════════════════════════════════════════════════════════
# FASTAPI APP
# ═══════════════════════════════════════════════════════════════════════════════

app = FastAPI(title="Robust Honeypot", version="5.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

async def verify_api_key(request: Request):
    key = request.headers.get("x-api-key")
    if key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

@app.post("/honeypot", response_model=HoneyPotResponse)
async def honeypot(request: Request, body: HoneyPotRequest):
    """Main endpoint with enhanced callback reliability"""
    await verify_api_key(request)
    
    session = get_session(body.sessionId)
    scammer_msg = body.message.text
    
    logger.info(f"\n{'='*70}")
    logger.info(f"💬 Session: {session.session_id[:12]}... | Turn {session.turn_count + 1}/{MAX_TURNS}")
    logger.info(f"📨 Scammer: {scammer_msg[:80]}")
    
    if session.termination_scheduled:
        logger.info(f"🛑 Already terminated")
        return HoneyPotResponse(status="success", reply="ok bye")
    
    if not session.scam_detected:
        is_scam, confidence = detect_scam(scammer_msg)
        session.scam_detected = is_scam
        session.scam_confidence = confidence
        logger.info(f"🔍 Scam: {is_scam} ({confidence:.2f})")
        if not is_scam:
            return HoneyPotResponse(status="success", reply="sorry wrong number")
    
    extract_intelligence(scammer_msg, session)
    session.scammer_responses.append(scammer_msg)
    session.messages.append({"role": "scammer", "content": scammer_msg})
    session.turn_count += 1
    
    terminate, reason = should_terminate(session)
    
    if terminate:
        logger.info(f"🏁 TERMINATING: {reason}")
        session.termination_scheduled = True
        
        # Send callback with await to ensure it completes
        callback_success = await send_callback(session)
        logger.info(f"   Callback sent: {callback_success}")
        
        import random
        exit_reply = random.choice([
            "ok let me check with my son",
            "busy now, later",
            "ok thanks bye",
            "have to go"
        ])
        session.messages.append({"role": "victim", "content": exit_reply})
        session.victim_responses.append(exit_reply)
        logger.info(f"👋 Exit: {exit_reply}\n{'='*70}")
        return HoneyPotResponse(status="success", reply=exit_reply)
    
    victim_reply = generate_victim_response(session, scammer_msg)
    session.messages.append({"role": "victim", "content": victim_reply})
    session.victim_responses.append(victim_reply)
    
    lower = victim_reply.lower()
    if any(w in lower for w in ["upi", "paytm"]):
        session.track_question_asked("upi")
    if any(w in lower for w in ["number", "phone", "call"]):
        session.track_question_asked("phone")
    if any(w in lower for w in ["link", "url"]):
        session.track_question_asked("link")
    if any(w in lower for w in ["account", "bank"]):
        session.track_question_asked("account")
    
    logger.info(f"✅ Victim: {victim_reply}")
    logger.info(f"📊 Score: {session.get_intel_score()} | Asked: {list(session.asked_for)}")
    logger.info(f"{'='*70}\n")
    
    return HoneyPotResponse(status="success", reply=victim_reply)

@app.get("/health")
async def health():
    return {"status": "healthy", "version": "5.1.0", "callback_url": GUVI_CALLBACK_URL}

@app.get("/debug/session/{session_id}")
async def debug(session_id: str, request: Request):
    await verify_api_key(request)
    if session_id not in sessions:
        raise HTTPException(404, "Not found")
    s = sessions[session_id]
    return {
        "sessionId": session_id,
        "turns": s.turn_count,
        "intelScore": s.get_intel_score(),
        "intelligence": {
            "upiIds": s.upi_ids,
            "phones": s.phone_numbers,
            "links": s.phishing_links,
            "banks": s.bank_accounts,
        },
        "callbackStatus": {
            "sent": s.callback_sent,
            "attempts": s.callback_attempts,
            "error": s.callback_error
        },
        "askedFor": list(s.asked_for),
        "circular": s.detect_circular_conversation(),
        "terminated": s.termination_scheduled
    }

@app.get("/")
async def root():
    return {
        "name": "Robust Honeypot",
        "version": "5.1.0",
        "features": ["Enhanced callback", "Error tracking", "Multiple retry strategies"]
    }

if __name__ == "__main__":
    import uvicorn
    logger.info("🚀 Starting Robust Honeypot v5.1")
    logger.info(f"📡 Callback URL: {GUVI_CALLBACK_URL}")
    uvicorn.run(app, host="0.0.0.0", port=8000)
