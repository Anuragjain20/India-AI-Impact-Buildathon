import json
import time

from final.agents.classifier_agent import classifier_agent
from final.agents.persona_agent import build_persona_agent
from final.agents.extraction_agent import extraction_agent

from final.schemas import IntelligenceSchema
from final.rl.persona_rl import PersonaRL
from final.rl.strategy_rl import StrategyRL

persona_rl = PersonaRL()
strategy_rl = StrategyRL()

ACTIONS = ["clarify", "confused", "delay"]


def intel_score(intel):
    score = 0
    score += len(intel.upiIds) * 5
    score += len(intel.phishingLinks) * 6
    score += len(intel.phoneNumbers) * 4
    score += len(intel.bankAccounts) * 5
    score += len(intel.suspiciousKeywords) * 1
    score += intel.confidenceScore * 3

    print("\n[INTEL SCORE]")
    print("Calculated Score:", score)
    return score


async def process_message_reply(
    message, history, session_id, previous_intel, message_count=1
):

    total_start = time.perf_counter()
    print("\n========== PHASE 1: GENERATE REPLY ==========")

    if message_count <= 1:
        t0 = time.perf_counter()
        res = await classifier_agent.run(task=message)
        print(f"⏱ Classifier: {time.perf_counter() - t0:.3f}s")

        raw = res.messages[-1].content
        try:
            classification = json.loads(raw)
        except:
            classification = {"scamDetected": True}

        if not classification["scamDetected"]:
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

    t0 = time.perf_counter()
    result = await persona_agent.run(task=persona_context)
    reply = result.messages[-1].content
    print(f"⏱ Persona: {time.perf_counter() - t0:.3f}s")

    session_end = any(
        k in reply.lower() for k in ["thank you", "goodbye", "conversation complete"]
    )

    print(f"✅ Phase 1 Done in {time.perf_counter() - total_start:.3f}s")
    return True, reply, session_end, persona, action


async def process_message_extraction(message, previous_intel, persona, action):

    print("\n========== PHASE 2: EXTRACTION ==========")
    t0 = time.perf_counter()

    extraction_context = f"""
Latest Scammer Message:
{message}

Cumulative Intelligence:
{previous_intel}
"""

    result = await extraction_agent.run(task=extraction_context)
    raw = result.messages[-1].content
    print(f"⏱ Extraction: {time.perf_counter() - t0:.3f}s")

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
