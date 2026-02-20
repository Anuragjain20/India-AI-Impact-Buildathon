from typing import List, Literal, Optional

from pydantic import BaseModel, Field

class IntelligenceSchema(BaseModel):

    scamDetected: bool
    bankAccounts: List[str] = Field(default_factory=list)
    upiIds: List[str] = Field(default_factory=list)
    phishingLinks: List[str] = Field(default_factory=list)
    phoneNumbers: List[str] = Field(default_factory=list)
    suspiciousKeywords: List[str] = Field(default_factory=list)
    agentNotes: str = ""
    confidenceScore: float = 0.0


class MessageEvent(BaseModel):
    sender: Literal["scammer", "user"]
    text: str
    timestamp: int | str


class ConversationMetadata(BaseModel):
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None


class HoneypotRequest(BaseModel):
    sessionId: str
    message: MessageEvent
    conversationHistory: Optional[List[MessageEvent]] = None
    metadata: Optional[ConversationMetadata] = None
