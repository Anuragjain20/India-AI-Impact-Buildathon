from autogen_agentchat.agents import AssistantAgent
from final.model_client import get_model_client
from final.schemas import IntelligenceSchema

extraction_agent = AssistantAgent(
    name="Extractor",
    model_client=get_model_client(),
    system_message=f"""
You are a scam intelligence extraction agent.

You MUST return ONLY valid JSON.

Extract intelligence from the conversation.

Follow this JSON schema EXACTLY:
{IntelligenceSchema.model_json_schema()}

Rules:
- Output ONLY JSON
- scamDetected must be true if scam indicators exist
- confidenceScore must be between 0 and 1
- If no data found → return empty lists or defaults

IMPORTANT:
Once all fields (bankAccounts, upiIds, phishingLinks, phoneNumbers, suspiciousKeywords) 
are populated OR you are confident no more information can be extracted,
the next message from PersonaAgent should be a short natural closing message like "Thank you."
"""
)
