import requests

def send_callback(session_id, total_messages, intel):

    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": total_messages,
        "extractedIntelligence": intel.model_dump(),
        "agentNotes": intel.agentNotes
    }

    try:
        requests.post(
            "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
            json=payload,
            timeout=5
        )
    except Exception as e:
        print("Callback error:", e)
