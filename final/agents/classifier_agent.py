from autogen_agentchat.agents import AssistantAgent
from final.model_client import get_model_client

classifier_agent = AssistantAgent(
    name="Classifier",
    model_client=get_model_client(),
    system_message="""
Return JSON:
{
 "scamDetected": true/false,
 "confidenceScore": float
}
""",
)
