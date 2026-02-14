from fastapi import FastAPI, Header, HTTPException
from final.session_memory import SessionMemory
from final.session_context_memory import SessionContextMemory
from final.callback_service import send_callback
from final.agents.team_orchestrator import process_message
from final.config import API_KEY
import time

app = FastAPI()

memory = SessionMemory(max_history=20)
context_memory = SessionContextMemory()

MAX_MESSAGES_PER_SESSION = 6
callback_sent_tracker = {}


@app.post("/honeypot")
async def honeypot(payload: dict, x_api_key: str = Header(None)):

    api_start_time = time.perf_counter()
    print("\n================ API REQUEST START ================")

    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")

    session_id = payload["sessionId"]
    msg = payload["message"]["text"]

    # -------------------------
    # Store scammer message
    # -------------------------
    t0 = time.perf_counter()
    memory.add_message(session_id, "scammer", msg)
    print(f"📝 memory.add_message(scammer): {time.perf_counter() - t0:.4f}s")

    t0 = time.perf_counter()
    history = memory.get_formatted_history(session_id)
    print(f"📜 get_formatted_history: {time.perf_counter() - t0:.4f}s")

    t0 = time.perf_counter()
    previous_intel = context_memory.get_intel(session_id)
    print(f"🧠 get_previous_intel: {time.perf_counter() - t0:.4f}s")

    # -------------------------
    # Process Message
    # -------------------------
    llm_start = time.perf_counter()

    cmd_start = time.perf_counter()
    message_count = len(memory.get_history(session_id))
    print(f"📊 Message Count: {message_count}")

    scam, reply, intel, session_end = await process_message(
        msg,
        history,
        session_id,
        previous_intel,
        message_count
    )

    llm_total = time.perf_counter() - llm_start
    print(f"🤖 TOTAL process_message(): {llm_total:.3f}s")

    # -------------------------
    # Store persona reply
    # -------------------------
    t0 = time.perf_counter()
    memory.add_message(session_id, "user", reply)
    print(f"📝 memory.add_message(user): {time.perf_counter() - t0:.4f}s")

    t0 = time.perf_counter()
    total_messages = len(memory.get_history(session_id))
    print(f"📊 get_history length: {time.perf_counter() - t0:.4f}s")

    # -------------------------
    # Store extracted intelligence
    # -------------------------
    if intel:
        t0 = time.perf_counter()
        context_memory.append_intel(session_id, intel)
        print(f"🧠 append_intel: {time.perf_counter() - t0:.4f}s")

    t0 = time.perf_counter()
    cumulative_intel = context_memory.get_intel(session_id)
    print(f"🧠 get_cumulative_intel: {time.perf_counter() - t0:.4f}s")

    # -------------------------
    # CALLBACK
    # -------------------------
    MIN_MESSAGES_BEFORE_CALLBACK = 4

    if session_id not in callback_sent_tracker:
        callback_sent_tracker[session_id] = False

    if (
        not callback_sent_tracker[session_id] and
        (
            total_messages >= MAX_MESSAGES_PER_SESSION
            or (session_end and total_messages >= MIN_MESSAGES_BEFORE_CALLBACK)
        )
    ):

        print("\n🔥 TRIGGERING CALLBACK 🔥")

        callback_start = time.perf_counter()

        await send_callback(
            session_id,
            total_messages,
            cumulative_intel
        )

        print(f"📡 send_callback(): {time.perf_counter() - callback_start:.3f}s")
        callback_sent_tracker[session_id] = True

    # -------------------------
    # Clear memory
    # -------------------------
    if session_end:
        t0 = time.perf_counter()
        memory.clear_session(session_id)
        context_memory.clear_session(session_id)
        callback_sent_tracker.pop(session_id, None)
        print(f"🧹 clear_session: {time.perf_counter() - t0:.4f}s")

    print(f"🚀 TOTAL API TIME: {time.perf_counter() - api_start_time:.3f}s")
    print("================ API REQUEST END ==================\n")

    return {
        "status": "success",
        "reply": reply
    }
