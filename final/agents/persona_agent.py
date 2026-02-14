from autogen_agentchat.agents import AssistantAgent
from final.model_client import get_model_client_2

def build_persona_agent(persona):
    """
    PersonaAgent that asks clarifying questions and signals completion naturally.
    """
    return AssistantAgent(
        name="PersonaAgent",
        model_client=get_model_client_2(),
        system_message=f"""
You are acting as {persona} in a conversation with a potential scammer.

Rules:
- Behave naturally and ask clarifying questions to extract intelligence.
- Do NOT share personal account information.
- Always reply in natural text.
- Once all relevant information has been clarified or the extraction agent has completed,
  respond with a short closing message like "Thank you." or "Conversation complete."
- Avoid repeating questions or unnecessary explanations.
"""
    )


