import os
from autogen_ext.models.openai import OpenAIChatCompletionClient
from autogen_core.models import (
    ModelFamily,
    UserMessage,
    SystemMessage
)
from final.config import GROQ_API_KEY

def get_model_client():

    return OpenAIChatCompletionClient(
        model="meta-llama/llama-4-maverick-17b-128e-instruct",
        base_url="https://api.groq.com/openai/v1",
        api_key=GROQ_API_KEY,
        response_format={"type": "json_object"},
        model_info={
            "vision": False,
            "function_calling": True,
            "json_output": True,
            "family": ModelFamily.UNKNOWN,
            "structured_output": True,
        },
    )

def get_model_client_2():

    return OpenAIChatCompletionClient(
        model="meta-llama/llama-4-maverick-17b-128e-instruct",
        base_url="https://api.groq.com/openai/v1",
        api_key=GROQ_API_KEY,
        model_info={
            "vision": False,
            "function_calling": True,
            "json_output": True,
            "family": ModelFamily.UNKNOWN,
            "structured_output": True,
        },
        temperature=0.7,          
        max_tokens=20,            
        top_p=0.9,
    )

