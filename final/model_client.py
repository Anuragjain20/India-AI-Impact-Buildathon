import os
from autogen_ext.models.openai import OpenAIChatCompletionClient
from autogen_core.models import (
    ModelFamily,
    UserMessage,
    SystemMessage
)
from final.config import DEEPSEEK_API_KEY

def get_model_client():

    return OpenAIChatCompletionClient(
        model="deepseek-chat",
        base_url="https://api.deepseek.com/v1",
        api_key=DEEPSEEK_API_KEY,
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
        model="deepseek-chat",
        base_url="https://api.deepseek.com/v1",
        api_key=DEEPSEEK_API_KEY,
        model_info={
            "vision": False,
            "function_calling": True,
            "json_output": True,
            "family": ModelFamily.UNKNOWN,
            "structured_output": True,
        },
        temperature=0.7,          
        max_tokens=100,            
        top_p=0.9,
    )
