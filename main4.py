"""
Legacy entrypoint for the advanced multi‑agent honeypot.

The real implementation now lives in the `app` package (`app.core` + `app.api`),
which is easier to extend and reason about for a large‑scale deployment or
hackathon showcase.

You can:
- Run this file directly: `python main3.py`
- Or run via uvicorn: `uvicorn app.api:app --host 0.0.0.0 --port 8000`
"""

from app.api import app  # re‑export FastAPI app for backwards compatibility


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.api:app", host="0.0.0.0", port=8000, reload=False)
