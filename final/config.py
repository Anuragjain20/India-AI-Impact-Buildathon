import os
from dotenv import load_dotenv

load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

API_KEY = os.getenv("HONEYPOT_API_KEY", "SECRET_KEY")
