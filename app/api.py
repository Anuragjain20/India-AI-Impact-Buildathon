"""
FastAPI wiring for the multi‑agent honeypot.

This keeps the web layer thin and delegates all heavy lifting to `app.core`,
so you can reuse the orchestrator with different interfaces later (CLI,
batch jobs, other transports, etc.).
"""

from datetime import datetime

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional

from .config import API_KEY
from .core import OrchestratorAgent, get_session, send_guvi_callback, sessions


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


app = FastAPI(
    title="Advanced Multi-Agent Honeypot API",
    version="2.0.0",
    description="Sophisticated multi-agent system for scam detection and intelligence extraction",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

orchestrator = OrchestratorAgent()


async def verify_api_key(request: Request) -> None:
    key = request.headers.get("x-api-key")
    if key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing x-api-key")


@app.post("/honeypot", response_model=HoneyPotResponse)
async def honeypot_endpoint(request: Request, body: HoneyPotRequest) -> HoneyPotResponse:
    await verify_api_key(request)

    session_id = body.sessionId
    scammer_text = body.message.text

    session_state = get_session(session_id)
    session_state.messages_exchanged += 1

    agent_response = await orchestrator.process_message(
        session_state,
        scammer_text,
        body.conversationHistory,
    )

    session_state.messages_exchanged += 1

    if orchestrator.should_send_callback(session_state):
        await send_guvi_callback(session_state)

    return HoneyPotResponse(status="success", reply=agent_response)


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "agents": {
            "detection": "online",
            "strategy": "online",
            "persona": "online",
            "intelligence": "online",
            "orchestrator": "online",
        },
    }


@app.get("/debug/session/{session_id}")
async def debug_session(session_id: str, request: Request):
    await verify_api_key(request)

    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    state = sessions[session_id]

    return {
        "sessionId": session_id,
        "scamDetected": state.scam_detected,
        "scamType": state.scam_type.value,
        "confidence": state.confidence_score,
        "messagesExchanged": state.messages_exchanged,
        "engagementQuality": state.engagement_quality,
        "conversationPhase": (
            state.current_strategy.conversation_phase.value
            if state.current_strategy
            else "none"
        ),
        "currentPersona": (
            state.current_strategy.recommended_persona.value
            if state.current_strategy
            else "none"
        ),
        "extractedIntelligence": state.intelligence.to_dict(),
        "agentNotes": state.agent_notes,
        "callbackSent": state.callback_sent,
        "conversationTurns": len(state.conversation_history),
    }


@app.post("/debug/send-callback/{session_id}")
async def force_callback(session_id: str, request: Request):
    await verify_api_key(request)

    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    session_state = sessions[session_id]
    session_state.callback_sent = False
    await send_guvi_callback(session_state)

    return {"status": "callback_triggered", "sessionId": session_id}


@app.get("/")
async def root():
    return {
        "name": "Advanced Multi-Agent Honeypot System",
        "version": "2.0.0",
        "description": "Sophisticated AI-powered honeypot with 5 specialized agents",
        "endpoints": {
            "main": "POST /honeypot",
            "health": "GET /health",
            "debug_session": "GET /debug/session/{session_id}",
            "force_callback": "POST /debug/send-callback/{session_id}",
        },
    }

