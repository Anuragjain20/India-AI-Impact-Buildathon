import os
from dotenv import load_dotenv

load_dotenv()


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


DEEPSEEK_API_KEY = _required_env("DEEPSEEK_API_KEY")
API_KEY = _required_env("HONEYPOT_API_KEY")
