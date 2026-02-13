from pydantic import BaseModel
from typing import List

class IntelligenceSchema(BaseModel):

    scamDetected: bool
    bankAccounts: List[str] = []
    upiIds: List[str] = []
    phishingLinks: List[str] = []
    phoneNumbers: List[str] = []
    suspiciousKeywords: List[str] = []
    agentNotes: str = ""
    confidenceScore: float = 0.0
