import asyncio

import requests

CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
CALLBACK_TIMEOUT_SECONDS = 5
MAX_RETRIES = 3
RETRY_DELAYS_SECONDS = (0.5, 1.0)


def _normalize_list(values):
    unique_values = []
    seen = set()
    for value in values or []:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        unique_values.append(text)
    return unique_values


def _build_payload(
    session_id,
    scam_detected,
    total_messages,
    intel,
    engagement_metrics=None,
):
    if hasattr(intel, "model_dump"):
        extracted_data = intel.model_dump()
    elif isinstance(intel, dict):
        extracted_data = dict(intel)
    else:
        extracted_data = {}

    payload = {
        "status": "completed",
        "sessionId": session_id,
        "scamDetected": bool(scam_detected),
        "totalMessagesExchanged": int(total_messages),
        "extractedIntelligence": {
            "bankAccounts": _normalize_list(extracted_data.get("bankAccounts", [])),
            "upiIds": _normalize_list(extracted_data.get("upiIds", [])),
            "phishingLinks": _normalize_list(extracted_data.get("phishingLinks", [])),
            "phoneNumbers": _normalize_list(extracted_data.get("phoneNumbers", [])),
            "suspiciousKeywords": _normalize_list(
                extracted_data.get("suspiciousKeywords", [])
            ),
        },
        "agentNotes": str(extracted_data.get("agentNotes", "")).strip(),
    }
    if engagement_metrics:
        payload["engagementMetrics"] = engagement_metrics
    return payload


async def send_callback(
    session_id,
    scam_detected,
    total_messages,
    intel,
    engagement_metrics=None,
):
    payload = _build_payload(
        session_id,
        scam_detected,
        total_messages,
        intel,
        engagement_metrics=engagement_metrics,
    )
    print(payload)
    last_error = "Unknown callback failure"
    for attempt in range(MAX_RETRIES):
        try:
            response = await asyncio.to_thread(
                requests.post,
                CALLBACK_URL,
                json=payload,
                timeout=CALLBACK_TIMEOUT_SECONDS,
            )
            if 200 <= response.status_code < 300:
                return True, ""
            response_text = (response.text or "").strip().replace("\n", " ")
            last_error = f"HTTP {response.status_code}: {response_text[:200]}"
        except Exception as exc:
            last_error = str(exc)

        if attempt < MAX_RETRIES - 1:
            await asyncio.sleep(RETRY_DELAYS_SECONDS[attempt])

    return False, last_error

