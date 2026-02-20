from fastapi import FastAPI, Header, HTTPException
import time

from final.agents.team_orchestrator import (
    process_message_extraction,
    process_message_reply,
)
from final.callback_service import send_callback
from final.config import API_KEY
from final.schemas import HoneypotRequest
from final.session_context_memory import SessionContextMemory
from final.session_memory import SessionMemory

app = FastAPI()

memory = SessionMemory(max_history=20)
context_memory = SessionContextMemory()

MAX_MESSAGES_PER_SESSION = 20

session_completed = {}
session_scam_confirmed = {}
session_start_time = {}


def _sync_session_history(session_id: str, conversation_history):
    memory.clear_session(session_id)
    for item in conversation_history[-memory.max_history:]:
        memory.add_message(session_id, item.sender, item.text)


@app.post("/honeypot")
async def honeypot(payload: HoneypotRequest, x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")

    session_id = payload.sessionId
    msg = payload.message.text
    incoming_sender = payload.message.sender

    if session_completed.get(session_id, False):
        return {"status": "completed"}

    if session_id not in session_start_time:
        session_start_time[session_id] = time.time()

    if payload.conversationHistory is not None:
        _sync_session_history(session_id, payload.conversationHistory)
    memory.add_message(session_id, incoming_sender, msg)

    history = memory.get_formatted_history(session_id)
    previous_intel = context_memory.get_intel(session_id)
    message_count = len(memory.get_history(session_id))

    if incoming_sender == "scammer":
        scam, reply, session_end, persona, action = await process_message_reply(
            msg,
            history,
            session_id,
            previous_intel,
            message_count,
            scam_already_confirmed=session_scam_confirmed.get(session_id, False),
        )
    else:
        scam = session_scam_confirmed.get(session_id, False)
        reply = "Okay."
        session_end = False
        persona = None
        action = None

    memory.add_message(session_id, "user", reply)

    if scam and incoming_sender == "scammer":
        session_scam_confirmed[session_id] = True
        intel = await process_message_extraction(
            msg,
            previous_intel,
            persona,
            action,
        )
        if intel:
            context_memory.append_intel(session_id, intel)

    total_messages = len(memory.get_history(session_id))
    should_finalize = session_scam_confirmed.get(session_id, False) and (
        total_messages >= MAX_MESSAGES_PER_SESSION or session_end
    )

    if should_finalize:
        cumulative_intel = context_memory.get_intel(session_id)
        started_at = session_start_time.get(session_id, time.time())
        engagement_metrics = {
            "totalMessagesExchanged": total_messages,
            "engagementDurationSeconds": max(0, int(time.time() - started_at)),
        }
        callback_ok, callback_error = await send_callback(
            session_id=session_id,
            scam_detected=True,
            total_messages=total_messages,
            intel=cumulative_intel,
            engagement_metrics=engagement_metrics,
        )

        if not callback_ok:
            raise HTTPException(
                status_code=503,
                detail=f"Mandatory final callback failed: {callback_error}",
            )

        memory.clear_session(session_id)
        context_memory.clear_session(session_id)
        session_completed[session_id] = True
        session_scam_confirmed[session_id] = False
        session_start_time.pop(session_id, None)

    return {
        "status": "success",
        "reply": reply,
    }
