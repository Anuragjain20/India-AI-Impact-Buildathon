import json
import asyncio

from final.agents.classifier_agent import classifier_agent
from final.agents.persona_agent import build_persona_agent
from final.agents.extraction_agent import extraction_agent

from final.schemas import IntelligenceSchema
from final.rl.persona_rl import PersonaRL
from final.rl.strategy_rl import StrategyRL
import time
persona_rl = PersonaRL()
strategy_rl = StrategyRL()

ACTIONS = ["clarify", "confused", "delay"]


# -------------------------
# Intelligence Scoring
# -------------------------
def intel_score(intel):

    score = 0

    score += len(intel.upiIds) * 5
    score += len(intel.phishingLinks) * 6
    score += len(intel.phoneNumbers) * 4
    score += len(intel.bankAccounts) * 5
    score += len(intel.suspiciousKeywords) * 1
    score += intel.confidenceScore * 3

    print("\n[INTEL SCORE]")
    print("UPI IDs:", intel.upiIds)
    print("Phishing Links:", intel.phishingLinks)
    print("Phone Numbers:", intel.phoneNumbers)
    print("Bank Accounts:", intel.bankAccounts)
    print("Keywords:", intel.suspiciousKeywords)
    print("Confidence:", intel.confidenceScore)
    print("Calculated Score:", score)

    return score



# -------------------------
# Main Orchestration Logic
# -------------------------
async def process_message_reply(message, history, session_id, previous_intel, message_count=1):
    """
    Phase 1: Quick Reply Generation.
    Returns: (scam_detected: bool, reply: str, session_end: bool)
    """
    total_start = time.perf_counter()
    print("\n========== PHASE 1: GENERATE REPLY ==========")

    # 1. Classifier (Only for first message)
    if message_count <= 1:
        t0 = time.perf_counter()
        res = await classifier_agent.run(task=message)
        print(f"⏱ Classifier Agent: {time.perf_counter() - t0:.3f}s")

        raw_classifier_output = res.messages[-1].content
        try:
            classification = json.loads(raw_classifier_output)
        except:
            classification = {"scamDetected": True} # Default to true if parsing fails

        if not classification["scamDetected"]:
            print("No scam detected.")
            return False, "Okay.", False, None, None
    else:
        print("⏭ Skipping Classifier (Ongoing session)")

    # 2. RL Selection
    persona = persona_rl.choose_persona()
    action = strategy_rl.choose_action("generic", ACTIONS)
    
    persona_agent = build_persona_agent(persona)

    # 3. Persona Reply Generation
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
    persona_result = await persona_agent.run(task=persona_context)
    persona_reply = persona_result.messages[-1].content
    print(f"⏱ Persona Agent: {time.perf_counter() - t0:.3f}s")

    # 4. Session End Detection
    session_end = any(
        keyword in persona_reply.lower()
        for keyword in ["thank you", "goodbye", "ok noted", "conversation complete"]
    )

    print(f"✅ Phase 1 Complete in {time.perf_counter() - total_start:.3f}s")
    return True, persona_reply, session_end, persona, action


async def process_message_extraction(message, previous_intel, persona, action):
    """
    Phase 2: Heavy Extraction & RL Updates (Background).
    """
    total_start = time.perf_counter()
    print("\n========== PHASE 2: BACKGROUND EXTRACTION ==========")

    extraction_context = f"""
Latest Scammer Message:
{message}

Cumulative Intelligence So Far:
{previous_intel}
"""
    t0 = time.perf_counter()
    extraction_result = await extraction_agent.run(task=extraction_context)
    raw_extraction_output = extraction_result.messages[-1].content
    print(f"⏱ Extraction Agent: {time.perf_counter() - t0:.3f}s")

    # Parsing
    intel = None
    try:
        intel = IntelligenceSchema.model_validate_json(raw_extraction_output)
    except Exception as e:
        print("Extraction Parsing Failed:", str(e))

    # RL Update
    if intel:
        t0 = time.perf_counter()
        score = intel_score(intel)
        persona_rl.update(persona, score)
        strategy_rl.update("generic", action, score, "generic", ACTIONS)
        print(f"⏱ RL Update: {time.perf_counter() - t0:.4f}s")

    print(f"✅ Phase 2 Complete in {time.perf_counter() - total_start:.3f}s")
    return intel

