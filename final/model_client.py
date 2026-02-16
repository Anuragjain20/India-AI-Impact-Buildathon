import logging
from typing import List


from autogen_ext.models.openai import OpenAIChatCompletionClient
from autogen_core.models import ModelFamily
from final.config import GROQ_API_KEY


# -----------------------------------
# 🔧 CONFIG
# -----------------------------------
MODEL_NAME = "meta-llama/llama-4-maverick-17b-128e-instruct"
BASE_URL = "https://api.groq.com/openai/v1"


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# -----------------------------------
# 🔑 Normalize API Keys
# -----------------------------------
def _get_api_keys() -> List[str]:
    if isinstance(GROQ_API_KEY, list):
        return GROQ_API_KEY
    return [GROQ_API_KEY]


GROQ_API_KEYS = _get_api_keys()


if not GROQ_API_KEYS or not GROQ_API_KEYS[0]:
    raise ValueError("❌ GROQ_API_KEY is not set properly.")


# -----------------------------------
# 🚀 Failover Model Client (AutoGen Compatible)
# -----------------------------------
class FailoverOpenAIClient:

    def __init__(
        self,
        temperature=None,
        max_tokens=None,
        top_p=None,
        response_format=None,
    ):
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.top_p = top_p
        self.response_format = response_format

        # Required by AutoGen
        self.model_info = {
            "vision": False,
            "function_calling": True,
            "json_output": True,
            "family": ModelFamily.UNKNOWN,
            "structured_output": True,
        }

    async def create(self, messages, **kwargs):  # 🔥 accept ANY extra args

        for key_index, api_key in enumerate(GROQ_API_KEYS):

            client = OpenAIChatCompletionClient(
                model=MODEL_NAME,
                base_url=BASE_URL,
                api_key=api_key,
                max_retries=0,
                response_format=self.response_format,
                model_info=self.model_info,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                top_p=self.top_p,
            )

            try:
                logger.info(f"🔑 Using GROQ key {key_index + 1}")

                # 🔥 Forward all extra kwargs (tools, tool_choice, etc.)
                response = await client.create(messages=messages, **kwargs)

                logger.info(f"✅ Success with key {key_index + 1}")
                return response

            except Exception as e:
                error_str = str(e).lower()

                if any(
                    x in error_str
                    for x in [
                        "429",
                        "too many requests",
                        "rate limit",
                        "organization_restricted",
                        "invalid_api_key",
                        "unauthorized",
                        "401",
                    ]
                ):
                    logger.warning(
                        f"Key {key_index + 1} blocked/rate-limited. Switching key."
                    )
                    continue

                if any(
                    x in error_str
                    for x in ["timeout", "connection", "503", "temporarily unavailable"]
                ):
                    logger.warning(
                        f"Temporary error on key {key_index + 1}. Trying next key."
                    )
                    continue

                raise

        raise Exception("All GROQ API keys exhausted.")

def get_model_client():
    return FailoverOpenAIClient(
        response_format={"type": "json_object"},
    )


def get_model_client_2():
    return FailoverOpenAIClient(
        temperature=0.7,
        max_tokens=60,
        top_p=0.9,
    )
