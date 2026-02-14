import json

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
async def process_message(message, history, session_id, previous_intel, message_count=1):

    total_start = time.perf_counter()
    print("\n========== NEW MESSAGE ==========")

    # -------------------------
    # 1. Classifier (Only for first message)
    # -------------------------
    if message_count <= 1:
        t0 = time.perf_counter()
        res = await classifier_agent.run(task=message)
        print(f"⏱ Classifier Agent: {time.perf_counter() - t0:.3f}s")

        raw_classifier_output = res.messages[-1].content
        classification = json.loads(raw_classifier_output)

        if not classification["scamDetected"]:
            print("No scam detected.")
            print(f"⏱ TOTAL process_message: {time.perf_counter() - total_start:.3f}s")
            return False, "Okay.", None, False
    else:
        print("⏭ Skipping Classifier (Ongoing session)")


    # -------------------------
    # 2. RL Selection
    # -------------------------
    t0 = time.perf_counter()
    persona = persona_rl.choose_persona()
    action = strategy_rl.choose_action("generic", ACTIONS)
    print(f"⏱ RL Selection: {time.perf_counter() - t0:.4f}s")

    persona_agent = build_persona_agent(persona)

    # -------------------------
    # 3. Persona Agent
    # -------------------------
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
    print(f"⏱ Persona Agent: {time.perf_counter() - t0:.3f}s")

    persona_reply = persona_result.messages[-1].content
    print(f"📏 Persona Reply Length: {len(persona_reply)} chars")

    # -------------------------
    # 4. Extraction Agent
    # -------------------------
    extraction_context = f"""
Latest Scammer Message:
{message}

Persona Reply:
{persona_reply}

Cumulative Intelligence So Far:
{previous_intel}
"""

    t0 = time.perf_counter()
    extraction_result = await extraction_agent.run(task=extraction_context)
    print(f"⏱ Extraction Agent: {time.perf_counter() - t0:.3f}s")

    raw_extraction_output = extraction_result.messages[-1].content
    print(f"📏 Extraction Output Length: {len(raw_extraction_output)} chars")

    # -------------------------
    # Parsing
    # -------------------------
    t0 = time.perf_counter()
    intel = None
    try:
        intel = IntelligenceSchema.model_validate_json(raw_extraction_output)
    except Exception as e:
        print("Extraction Parsing Failed:", str(e))
    print(f"⏱ JSON Parsing: {time.perf_counter() - t0:.4f}s")

    # -------------------------
    # RL Update
    # -------------------------
    if intel:
        t0 = time.perf_counter()
        score = intel_score(intel)
        persona_rl.update(persona, score)
        strategy_rl.update("generic", action, score, "generic", ACTIONS)
        print(f"⏱ RL Update: {time.perf_counter() - t0:.4f}s")

    # -------------------------
    # Session End
    # -------------------------
    t0 = time.perf_counter()
    session_end = any(
        keyword in persona_reply.lower()
        for keyword in ["thank you", "goodbye", "ok noted"]
    )
    print(f"⏱ Session End Detection: {time.perf_counter() - t0:.4f}s")

    print(f"⏱ TOTAL process_message: {time.perf_counter() - total_start:.3f}s")
    print("========== FLOW COMPLETE ==========\n")

    return True, persona_reply, intel, session_end
