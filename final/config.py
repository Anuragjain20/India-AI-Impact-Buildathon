import os
import os
from dotenv import load_dotenv


load_dotenv()


raw_keys = os.getenv("GROQ_API_KEY", "")


if raw_keys:
    GROQ_API_KEY = [key.strip() for key in raw_keys.split(",")]
else:
    GROQ_API_KEY = []


API_KEY = os.getenv("HONEYPOT_API_KEY")
