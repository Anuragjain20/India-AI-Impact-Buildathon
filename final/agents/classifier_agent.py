from autogen_agentchat.agents import AssistantAgent
from final.model_client import get_model_client

classifier_agent = AssistantAgent(
    name="Classifier",
    model_client=get_model_client(),
    system_message="""
You are a scam-intent classifier for inbound digital messages.

Return ONLY JSON (no markdown, no extra text):
{
 "scamDetected": true/false,
 "confidenceScore": float
}

Rules:
- scamDetected=true for phishing/social-engineering patterns like urgency, account-block threats, OTP/password requests, UPI/bank detail collection, suspicious payment redirection, or malicious links.
- confidenceScore must be between 0 and 1.
"""
)
