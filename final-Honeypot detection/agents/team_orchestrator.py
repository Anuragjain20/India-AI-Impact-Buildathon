import json

from agents.classifier_agent import classifier_agent
from agents.persona_agent import build_persona_agent
from agents.extraction_agent import extraction_agent

from schemas import IntelligenceSchema
from rl.persona_rl import PersonaRL
from rl.strategy_rl import StrategyRL

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
async def process_message(message, history, session_id, previous_intel):

    print("\n========== NEW MESSAGE ==========")
    print("Session:", session_id)
    print("Incoming Message:", message)
    print("Conversation History:", history)
    print("Previous Intelligence:", previous_intel)

    # -------------------------
    # 1. Scam Classification
    # -------------------------
    print("\n--- Running Classifier Agent ---")

    res = await classifier_agent.run(task=message)

    raw_classifier_output = res.messages[-1].content
    print("Classifier Raw Output:", raw_classifier_output)

    classification = json.loads(raw_classifier_output)
    print("Parsed Classification:", classification)

    if not classification["scamDetected"]:
        print("No scam detected. Ending flow.")
        return False, "Okay.", None, False


    # -------------------------
    # 2. RL Persona + Strategy
    # -------------------------
    print("\n--- RL Persona + Strategy Selection ---")

    persona = persona_rl.choose_persona()
    action = strategy_rl.choose_action("generic", ACTIONS)

    print("Selected Persona:", persona)
    print("Selected Strategy Action:", action)

    persona_agent = build_persona_agent(persona)


    # -------------------------
    # 3. Persona Conversation
    # -------------------------
    print("\n--- Running Persona Agent ---")

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

    print("Persona Context Sent To Agent:\n", persona_context)

    persona_result = await persona_agent.run(task=persona_context)

    persona_reply = persona_result.messages[-1].content

    print("\nPersona Reply:")
    print(persona_reply)


    # -------------------------
    # 4. Intelligence Extraction
    # -------------------------
    print("\n--- Running Extraction Agent ---")

    extraction_context = f"""
Latest Scammer Message:
{message}

Conversation History:
{history}

Persona Reply:
{persona_reply}

Cumulative Intelligence So Far:
{previous_intel}

IMPORTANT RULES:
1. Extract NEW intelligence.
2. DO NOT remove previously valid intelligence.
3. Enrich cumulative intelligence if new entities appear.
"""


    print("Extraction Context Sent To Agent:\n", extraction_context)

    extraction_result = await extraction_agent.run(task=extraction_context)

    raw_extraction_output = extraction_result.messages[-1].content
    print("\nExtraction Raw Output:")
    print(raw_extraction_output)

    intel = None

    try:
        intel = IntelligenceSchema.model_validate_json(raw_extraction_output)
        print("\nParsed Intelligence Object:")
        print(intel)

    except Exception as e:
        print("Extraction Parsing Failed:", str(e))


    # -------------------------
    # 5. RL Learning + Graph Storage
    # -------------------------
    if intel:
        print("\n--- RL Update + Graph Storage ---")

        score = intel_score(intel)

        print("Updating Persona RL...")
        persona_rl.update(persona, score)

        print("Updating Strategy RL...")
        strategy_rl.update("generic", action, score, "generic", ACTIONS)

    else:
        print("No intelligence extracted. Skipping RL ")


    # -------------------------
    # 6. Session End Detection
    # -------------------------
    print("\n--- Session End Detection ---")

    session_end = False
    closing_keywords = ["thank you", "goodbye", "ok noted"]

    if any(keyword in persona_reply.lower() for keyword in closing_keywords):
        session_end = True
        print("Session Closing Detected.")

    else:
        print("Session Continues.")

    print("\n========== FLOW COMPLETE ==========")

    return True, persona_reply, intel, session_end
