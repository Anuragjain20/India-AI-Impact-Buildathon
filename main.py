from fastapi import FastAPI, Header, HTTPException
from session_memory import SessionMemory
from session_context_memory import SessionContextMemory
from callback_service import send_callback
from agents.team_orchestrator import process_message
from config import API_KEY

app = FastAPI()

memory = SessionMemory(max_history=20)
context_memory = SessionContextMemory()


@app.post("/honeypot")
async def honeypot(payload: dict, x_api_key: str = Header(None)):

    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")

    session_id = payload["sessionId"]
    msg = payload["message"]["text"]

    # -------------------------
    # Store scammer message
    # -------------------------
    memory.add_message(session_id, "scammer", msg)

    history = memory.get_formatted_history(session_id)
    previous_intel = context_memory.get_intel(session_id)

    # -------------------------
    # Process Message
    # -------------------------
    scam, reply, intel, session_end = await process_message(
        msg,
        history,
        session_id,
        previous_intel
    )

    # -------------------------
    # Store persona reply
    # -------------------------
    memory.add_message(session_id, "user", reply)

    # -------------------------
    # Store extracted intelligence
    # -------------------------
    if intel:
        context_memory.append_intel(session_id, intel)

        print("\n[CUMULATIVE INTEL AFTER MERGE]")
        print(context_memory.get_intel(session_id))


    # -------------------------
    # Send callback if scam found
    # -------------------------
    if scam and intel:
        send_callback(session_id, len(memory.get_history(session_id)), intel)

    # -------------------------
    # Clear memory if session closed
    # -------------------------
    if session_end:
        memory.clear_session(session_id)
        context_memory.clear_session(session_id)

    return {
        "status": "success",
        "reply": reply
    }
