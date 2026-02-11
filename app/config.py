import os

from dotenv import load_dotenv

"""
Central configuration for the honeypot service.

Environment variables are loaded from a local `.env` file (if present),
so you can configure secrets without hard‑coding them.
"""

# Load environment from .env (if available)
load_dotenv()

# Core API settings
API_KEY: str = os.getenv("HONEYPOT_API_KEY", "my-secret-honeypot-key")
GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")

# Model / provider settings
GROQ_MODEL: str = os.getenv(
    "GROQ_MODEL",
    "meta-llama/llama-4-maverick-17b-128e-instruct",
)

# Callback / evaluation endpoint
GUVI_CALLBACK_URL: str = os.getenv(
    "GUVI_CALLBACK_URL",
    "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
)

