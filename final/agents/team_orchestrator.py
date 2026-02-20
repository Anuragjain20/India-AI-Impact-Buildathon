import json
import re

from final.agents.classifier_agent import classifier_agent
from final.agents.persona_agent import build_persona_agent
from final.agents.extraction_agent import extraction_agent

from final.schemas import IntelligenceSchema
from final.rl.persona_rl import PersonaRL
from final.rl.strategy_rl import StrategyRL

persona_rl = PersonaRL()
strategy_rl = StrategyRL()

ACTIONS = ["clarify", "confused", "delay"]
SCAM_KEYWORDS = [
    "otp",
    "verify immediately",
    "verify now",
    "account blocked",
    "account suspended",
    "urgent",
    "upi",
    "bank account",
    "share your details",
    "click here",
    "refund link",
    "kyc",
    "password",
]


def intel_score(intel):
    score = 0
    score += len(intel.upiIds) * 5
    score += len(intel.phishingLinks) * 6
    score += len(intel.phoneNumbers) * 4
    score += len(intel.bankAccounts) * 5
    score += len(intel.suspiciousKeywords) * 1
    score += intel.confidenceScore * 3

    
    return score


def _fallback_scam_detection(message: str) -> bool:
    normalized = re.sub(r"\s+", " ", message.lower()).strip()
    return any(keyword in normalized for keyword in SCAM_KEYWORDS)


def _safe_load_json(raw: str) -> dict:
    content = raw.strip()
    if content.startswith("```"):
        lines = content.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        content = "\n".join(lines).strip()
    return json.loads(content)


async def _classify_message(message: str, history: str) -> bool:
    task = f"""
Conversation History:
{history}

Latest Message:
{message}
"""
    try:
        result = await classifier_agent.run(task=task)
        raw = result.messages[-1].content
        classification = _safe_load_json(raw)
        return bool(classification.get("scamDetected", False))
    except Exception:
        return _fallback_scam_detection(message)


async def process_message_reply(
    message,
    history,
    session_id,
    previous_intel,
    message_count=1,
    scam_already_confirmed=False,
):

    is_scam = scam_already_confirmed or await _classify_message(message, history)
    if not is_scam:
        return False, "Okay.", False, None, None

    persona = persona_rl.choose_persona()
    action = strategy_rl.choose_action("generic", ACTIONS)
    persona_agent = build_persona_agent(persona)

    persona_context = f"""
Conversation History:
{history}

Previously Extracted Intelligence:
{previous_intel}

Latest Message:
{message}

Strategy Action:
{action}
"""

    result = await persona_agent.run(task=persona_context)
    reply = result.messages[-1].content

    reply_lower = reply.lower()
    session_end = any(
        k in reply_lower
        for k in [
            "thank you",
            "got it",
            "okay, noted",
            "okay noted",
            "conversation complete",
            "goodbye",
        ]
    )

    
    return is_scam, reply, session_end, persona, action


async def process_message_extraction(message, previous_intel, persona, action):
    extraction_context = f"""
Latest Scammer Message:
{message}

Cumulative Intelligence:
{previous_intel}
"""

    result = await extraction_agent.run(task=extraction_context)
    raw = result.messages[-1].content

    intel = None
    try:
        intel = IntelligenceSchema.model_validate_json(raw)
    except Exception as e:
        print("Parsing failed:", e)

    if intel:
        score = intel_score(intel)
        persona_rl.update(persona, score)
        strategy_rl.update("generic", action, score, "generic", ACTIONS)

    return intel
