"""
Advanced Multi-Agent Agentic Honey-Pot for Scam Detection & Intelligence Extraction
======================================================================================

This system implements a sophisticated multi-agent architecture with:
1. Detection Agent - Analyzes scam intent with contextual understanding
2. Strategy Agent - Plans engagement strategy and conversation flow
3. Persona Agent - Generates believable human-like responses
4. Intelligence Agent - Extracts and analyzes scam indicators
5. Orchestrator Agent - Coordinates all agents and makes decisions

Each agent has specialized capabilities and they collaborate to maximize scam intelligence extraction.
"""

import os
import json
import logging
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field, asdict

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import httpx
import re
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage

# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

API_KEY = os.getenv("HONEYPOT_API_KEY", "my-secret-honeypot-key")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
GROQ_MODEL = "meta-llama/llama-4-maverick-17b-128e-instruct"

# ═══════════════════════════════════════════════════════════════════════════════
# ENUMS & DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════════════

class ScamType(str, Enum):
    PHISHING = "phishing"
    BANK_FRAUD = "bank_fraud"
    UPI_FRAUD = "upi_fraud"
    FAKE_OFFER = "fake_offer"
    IDENTITY_THEFT = "identity_theft"
    LOTTERY_SCAM = "lottery_scam"
    TECH_SUPPORT = "tech_support"
    OTHER = "other"
    NONE = "none"

class EngagementStrategy(str, Enum):
    NAIVE_VICTIM = "naive_victim"
    INTERESTED_BUYER = "interested_buyer"
    CONFUSED_ELDER = "confused_elder"
    TECH_ILLITERATE = "tech_illiterate"
    EAGER_WINNER = "eager_winner"
    WORRIED_CUSTOMER = "worried_customer"

class ConversationPhase(str, Enum):
    INITIAL = "initial"
    BUILDING_TRUST = "building_trust"
    EXTRACTING_INTEL = "extracting_intel"
    DEEP_ENGAGEMENT = "deep_engagement"
    WINDING_DOWN = "winding_down"

@dataclass
class Intelligence:
    """Extracted intelligence from scammer"""
    bank_accounts: List[str] = field(default_factory=list)
    upi_ids: List[str] = field(default_factory=list)
    phishing_links: List[str] = field(default_factory=list)
    phone_numbers: List[str] = field(default_factory=list)
    suspicious_keywords: List[str] = field(default_factory=list)
    scammer_names: List[str] = field(default_factory=list)
    organizations_mentioned: List[str] = field(default_factory=list)
    amounts_requested: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "bankAccounts": self.bank_accounts,
            "upiIds": self.upi_ids,
            "phishingLinks": self.phishing_links,
            "phoneNumbers": self.phone_numbers,
            "suspiciousKeywords": self.suspicious_keywords,
            "scammerNames": self.scammer_names,
            "organizationsMentioned": self.organizations_mentioned,
            "amountsRequested": self.amounts_requested
        }

@dataclass
class DetectionResult:
    """Result from Detection Agent"""
    scam_detected: bool
    confidence: float
    scam_type: ScamType
    urgency_level: int  # 1-5
    manipulation_tactics: List[str]
    reason: str

@dataclass
class StrategyPlan:
    """Strategy from Strategy Agent"""
    recommended_persona: EngagementStrategy
    conversation_phase: ConversationPhase
    key_questions_to_ask: List[str]
    information_to_seek: List[str]
    response_tone: str
    estimated_turns_remaining: int

@dataclass
class SessionState:
    """Complete session state"""
    session_id: str
    scam_detected: bool = False
    messages_exchanged: int = 0
    conversation_history: List[Dict[str, str]] = field(default_factory=list)
    intelligence: Intelligence = field(default_factory=Intelligence)
    agent_notes: List[str] = field(default_factory=list)
    callback_sent: bool = False
    current_strategy: Optional[StrategyPlan] = None
    scam_type: ScamType = ScamType.NONE
    confidence_score: float = 0.0
    engagement_quality: float = 0.0  # How well we're extracting intel

# ═══════════════════════════════════════════════════════════════════════════════
# PYDANTIC MODELS FOR API
# ═══════════════════════════════════════════════════════════════════════════════

class MessagePayload(BaseModel):
    sender: str
    text: str
    timestamp: int

class MetadataPayload(BaseModel):
    channel: Optional[str] = "SMS"
    language: Optional[str] = "English"
    locale: Optional[str] = "IN"

class HoneyPotRequest(BaseModel):
    sessionId: str
    message: MessagePayload
    conversationHistory: List[MessagePayload] = Field(default_factory=list)
    metadata: Optional[MetadataPayload] = None

class HoneyPotResponse(BaseModel):
    status: str
    reply: str

# ═══════════════════════════════════════════════════════════════════════════════
# IN-MEMORY SESSION STORE
# ═══════════════════════════════════════════════════════════════════════════════

sessions: Dict[str, SessionState] = {}

def get_session(session_id: str) -> SessionState:
    """Get or create session state"""
    if session_id not in sessions:
        sessions[session_id] = SessionState(session_id=session_id)
    return sessions[session_id]

# ═══════════════════════════════════════════════════════════════════════════════
# MULTI-AGENT SYSTEM - SPECIALIZED AGENTS
# ═══════════════════════════════════════════════════════════════════════════════

class DetectionAgent:
    """
    Agent 1: Scam Detection Specialist
    Analyzes messages for scam patterns, intent, and manipulation tactics
    """
    
    SYSTEM_PROMPT = """You are an expert scam detection analyst with deep knowledge of:
- Phishing tactics and social engineering
- Bank fraud and financial scams
- UPI/payment fraud patterns
- Urgency-based manipulation
- Authority impersonation
- Emotional manipulation techniques

Analyze the conversation and latest message to determine scam probability.
Consider: urgency language, authority claims, fear tactics, requests for sensitive info,
too-good-to-be-true offers, grammatical patterns, and threat implications.

Return ONLY valid JSON:
{
  "scam_detected": true/false,
  "confidence": 0.0-1.0,
  "scam_type": "phishing|bank_fraud|upi_fraud|fake_offer|identity_theft|lottery_scam|tech_support|other|none",
  "urgency_level": 1-5,
  "manipulation_tactics": ["tactic1", "tactic2"],
  "reason": "detailed explanation of why this is/isn't a scam"
}"""

    def __init__(self):
        self.llm = ChatGroq(
            model_name=GROQ_MODEL,
            temperature=0.1,
            api_key=GROQ_API_KEY,
        )
    
    async def analyze(self, latest_message: str, history: List[Dict]) -> DetectionResult:
        """Analyze message for scam indicators"""
        history_text = "\n".join([f"[{m['sender']}]: {m['text']}" for m in history])
        
        prompt = f"""{self.SYSTEM_PROMPT}

Conversation History:
{history_text}

Latest Message:
[scammer]: {latest_message}

Analyze this message and conversation context."""

        try:
            response = await self.llm.ainvoke([HumanMessage(content=prompt)])
            raw = response.content.strip()
            raw = re.sub(r"```(?:json)?\s*", "", raw).strip().rstrip("`").strip()
            data = json.loads(raw)
            
            return DetectionResult(
                scam_detected=data.get("scam_detected", False),
                confidence=data.get("confidence", 0.0),
                scam_type=ScamType(data.get("scam_type", "none")),
                urgency_level=data.get("urgency_level", 1),
                manipulation_tactics=data.get("manipulation_tactics", []),
                reason=data.get("reason", "")
            )
        except Exception as e:
            logger.error(f"Detection Agent error: {e}")
            return DetectionResult(
                scam_detected=False,
                confidence=0.0,
                scam_type=ScamType.NONE,
                urgency_level=1,
                manipulation_tactics=[],
                reason=f"Analysis error: {str(e)}"
            )


class StrategyAgent:
    """
    Agent 2: Engagement Strategy Planner
    Determines optimal conversation strategy and persona to maximize intelligence extraction
    """
    
    SYSTEM_PROMPT = """You are a strategic conversation planner for honeypot operations.
Your goal is to maximize intelligence extraction by:
- Choosing the most effective victim persona
- Determining conversation phase
- Planning questions that elicit detailed information
- Maintaining believability while extending engagement

Available personas:
- naive_victim: Inexperienced, easily convinced
- interested_buyer: Wants the offer, asks practical questions
- confused_elder: Elderly, needs repeated explanations
- tech_illiterate: Doesn't understand technical terms
- eager_winner: Excited about prizes/offers
- worried_customer: Concerned about account issues

Conversation phases:
- initial: First interaction, establishing context
- building_trust: Gaining scammer's confidence
- extracting_intel: Actively seeking operational details
- deep_engagement: Maximum information gathering
- winding_down: Conversation naturally ending

Return ONLY valid JSON:
{
  "recommended_persona": "persona_type",
  "conversation_phase": "phase",
  "key_questions_to_ask": ["question1", "question2"],
  "information_to_seek": ["bank details", "phone number"],
  "response_tone": "worried/excited/confused/interested",
  "estimated_turns_remaining": 3-8
}"""

    def __init__(self):
        self.llm = ChatGroq(
            model_name=GROQ_MODEL,
            temperature=0.3,
            api_key=GROQ_API_KEY,
        )
    
    async def plan(
        self,
        scam_type: ScamType,
        conversation_history: List[Dict],
        current_intelligence: Intelligence,
        messages_exchanged: int
    ) -> StrategyPlan:
        """Create engagement strategy"""
        
        history_text = "\n".join([f"[{m['role']}]: {m['content']}" for m in conversation_history[-6:]])
        intel_summary = f"""
Current Intelligence:
- Bank Accounts: {len(current_intelligence.bank_accounts)}
- UPI IDs: {len(current_intelligence.upi_ids)}
- Links: {len(current_intelligence.phishing_links)}
- Phone Numbers: {len(current_intelligence.phone_numbers)}
"""
        
        prompt = f"""{self.SYSTEM_PROMPT}

Scam Type: {scam_type.value}
Messages Exchanged: {messages_exchanged}

Recent Conversation:
{history_text}

{intel_summary}

What's the best strategy to continue this engagement and extract maximum intelligence?"""

        try:
            response = await self.llm.ainvoke([HumanMessage(content=prompt)])
            raw = response.content.strip()
            raw = re.sub(r"```(?:json)?\s*", "", raw).strip().rstrip("`").strip()
            data = json.loads(raw)
            
            return StrategyPlan(
                recommended_persona=EngagementStrategy(data.get("recommended_persona", "naive_victim")),
                conversation_phase=ConversationPhase(data.get("conversation_phase", "initial")),
                key_questions_to_ask=data.get("key_questions_to_ask", []),
                information_to_seek=data.get("information_to_seek", []),
                response_tone=data.get("response_tone", "neutral"),
                estimated_turns_remaining=data.get("estimated_turns_remaining", 5)
            )
        except Exception as e:
            logger.error(f"Strategy Agent error: {e}")
            return StrategyPlan(
                recommended_persona=EngagementStrategy.NAIVE_VICTIM,
                conversation_phase=ConversationPhase.INITIAL,
                key_questions_to_ask=["Can you tell me more?"],
                information_to_seek=["basic details"],
                response_tone="neutral",
                estimated_turns_remaining=5
            )


class PersonaAgent:
    """
    Agent 3: Persona & Response Generator
    Creates believable human responses based on strategy
    """
    
    PERSONA_TEMPLATES = {
        EngagementStrategy.NAIVE_VICTIM: """You are playing a naive, trusting person who:
- Believes what people tell you
- Asks simple, innocent questions
- Shows concern when threatened
- Easily confused by technical terms
- Wants to be helpful and compliant
- Uses simple, conversational language""",
        
        EngagementStrategy.CONFUSED_ELDER: """You are playing an elderly person who:
- Needs things explained multiple times
- Confused by technology and banking
- Worried about making mistakes
- Asks for step-by-step instructions
- Mentions family members sometimes
- Types slowly, occasional typos acceptable""",
        
        EngagementStrategy.INTERESTED_BUYER: """You are playing someone interested in an offer who:
- Asks practical questions about the offer
- Wants to know details and process
- Slightly skeptical but can be convinced
- Asks about payment methods
- Wants to verify legitimacy (but accepts weak proof)
- Enthusiastic but cautious""",
        
        EngagementStrategy.TECH_ILLITERATE: """You are playing someone who doesn't understand technology:
- Confused by UPI, internet banking, apps
- Needs detailed explanations
- Asks basic questions about processes
- Nervous about doing things wrong
- Prefers traditional methods
- Asks for alternative options""",
        
        EngagementStrategy.EAGER_WINNER: """You are playing someone excited about winning something:
- Very enthusiastic and grateful
- Asks how to claim the prize
- Willing to follow instructions
- Slightly impatient to get the prize
- Asks about prize details
- Easily excited by promises""",
        
        EngagementStrategy.WORRIED_CUSTOMER: """You are playing a worried bank customer:
- Genuinely concerned about account issues
- Asks for clarification
- Wants to verify the problem
- Asks for official procedures
- Slightly panicked but cooperative
- Asks questions to understand the situation"""
    }
    
    def __init__(self):
        self.llm = ChatGroq(
            model_name=GROQ_MODEL,
            temperature=0.7,
            api_key=GROQ_API_KEY,
        )
    
    async def generate_response(
        self,
        strategy: StrategyPlan,
        conversation_history: List[Dict],
        scammer_message: str
    ) -> str:
        """Generate human-like response based on persona and strategy"""
        
        persona_instruction = self.PERSONA_TEMPLATES.get(
            strategy.recommended_persona,
            self.PERSONA_TEMPLATES[EngagementStrategy.NAIVE_VICTIM]
        )
        
        system_prompt = f"""{persona_instruction}

CRITICAL RULES:
- NEVER reveal you know this is a scam
- NEVER provide real personal information
- If forced to give details, make them obviously fake (e.g., "victim123@paytm")
- Sound natural and human-like
- Show the appropriate emotional tone: {strategy.response_tone}
- Conversation phase: {strategy.conversation_phase.value}

Try to naturally work in these topics if possible:
{chr(10).join(f'- {q}' for q in strategy.key_questions_to_ask[:2])}

Respond with ONLY your message text. No explanations."""

        # Build conversation
        messages = [SystemMessage(content=system_prompt)]
        for turn in conversation_history[-8:]:  # Last 8 turns for context
            if turn["role"] == "user":
                messages.append(HumanMessage(content=turn["content"]))
            else:
                messages.append(AIMessage(content=turn["content"]))
        
        messages.append(HumanMessage(content=scammer_message))
        
        try:
            response = await self.llm.ainvoke(messages)
            return response.content.strip()
        except Exception as e:
            logger.error(f"Persona Agent error: {e}")
            return "I'm not sure I understand. Can you explain more?"


class IntelligenceAgent:
    """
    Agent 4: Intelligence Extraction Specialist
    Extracts and analyzes scam-related information from conversations
    """
    
    SYSTEM_PROMPT = """You are an intelligence extraction specialist analyzing scammer communications.

Extract ALL scam-related indicators from the SCAMMER's messages ONLY:

1. Bank Account Numbers: Any account numbers mentioned
2. UPI IDs: Payment IDs in format xyz@bank
3. Phishing Links: Any URLs or suspicious links
4. Phone Numbers: Any phone numbers shared
5. Suspicious Keywords: Manipulation phrases (urgent, verify, blocked, winner, prize, etc.)
6. Scammer Names: Any names they use
7. Organizations: Banks, companies, or authorities they claim to represent
8. Amounts: Money amounts requested or mentioned

Also provide tactical analysis in agentNotes about:
- Scammer's primary tactics
- Pressure techniques used
- Level of sophistication
- Likely next moves

Return ONLY valid JSON:
{
  "bankAccounts": [],
  "upiIds": [],
  "phishingLinks": [],
  "phoneNumbers": [],
  "suspiciousKeywords": [],
  "scammerNames": [],
  "organizationsMentioned": [],
  "amountsRequested": [],
  "agentNotes": "tactical analysis"
}"""

    def __init__(self):
        self.llm = ChatGroq(
            model_name=GROQ_MODEL,
            temperature=0.1,
            api_key=GROQ_API_KEY,
        )
    
    async def extract(self, conversation_history: List[Dict]) -> Dict[str, Any]:
        """Extract intelligence from conversation"""
        
        # Focus on scammer messages
        scammer_messages = [
            m for m in conversation_history 
            if m.get("role") == "user"
        ]
        
        conv_text = "\n".join([
            f"[SCAMMER MESSAGE {i+1}]: {m['content']}" 
            for i, m in enumerate(scammer_messages)
        ])
        
        prompt = f"""{self.SYSTEM_PROMPT}

Scammer Messages to Analyze:
{conv_text}

Extract all intelligence from these scammer messages."""

        try:
            response = await self.llm.ainvoke([HumanMessage(content=prompt)])
            raw = response.content.strip()
            raw = re.sub(r"```(?:json)?\s*", "", raw).strip().rstrip("`").strip()
            return json.loads(raw)
        except Exception as e:
            logger.error(f"Intelligence Agent error: {e}")
            return {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "suspiciousKeywords": [],
                "scammerNames": [],
                "organizationsMentioned": [],
                "amountsRequested": [],
                "agentNotes": f"Extraction error: {str(e)}"
            }


class OrchestratorAgent:
    """
    Agent 5: Master Orchestrator
    Coordinates all agents and makes high-level decisions
    """
    
    def __init__(self):
        self.detection_agent = DetectionAgent()
        self.strategy_agent = StrategyAgent()
        self.persona_agent = PersonaAgent()
        self.intelligence_agent = IntelligenceAgent()
        logger.info("🤖 Multi-Agent System Initialized")
        logger.info("   ├─ Detection Agent: Ready")
        logger.info("   ├─ Strategy Agent: Ready")
        logger.info("   ├─ Persona Agent: Ready")
        logger.info("   ├─ Intelligence Agent: Ready")
        logger.info("   └─ Orchestrator: Online")
    
    async def process_message(
        self,
        session_state: SessionState,
        scammer_message: str,
        conversation_history: List[MessagePayload]
    ) -> str:
        """
        Orchestrate all agents to process a message and generate response
        
        Flow:
        1. Detection Agent analyzes scam probability
        2. If scam detected, Strategy Agent plans engagement
        3. Persona Agent generates appropriate response
        4. Intelligence Agent extracts new intel
        5. Update session state and return response
        """
        
        logger.info(f"\n{'='*80}")
        logger.info(f"🎯 ORCHESTRATOR: Processing message for session {session_state.session_id}")
        logger.info(f"{'='*80}")
        
        # Convert API history to internal format
        history_for_detection = [
            {"sender": m.sender, "text": m.text} 
            for m in conversation_history
        ]
        
        # STEP 1: Detection Agent
        logger.info("🔍 STEP 1: Detection Agent analyzing message...")
        detection_result = await self.detection_agent.analyze(
            scammer_message,
            history_for_detection
        )
        
        logger.info(f"   ├─ Scam Detected: {detection_result.scam_detected}")
        logger.info(f"   ├─ Confidence: {detection_result.confidence:.2f}")
        logger.info(f"   ├─ Type: {detection_result.scam_type.value}")
        logger.info(f"   ├─ Urgency: {detection_result.urgency_level}/5")
        logger.info(f"   └─ Tactics: {', '.join(detection_result.manipulation_tactics)}")
        
        # Update session state
        session_state.scam_detected = detection_result.scam_detected
        session_state.confidence_score = detection_result.confidence
        session_state.scam_type = detection_result.scam_type
        
        # If not a scam, return neutral response
        if not detection_result.scam_detected or detection_result.confidence < 0.5:
            logger.info("⚠️  Not detected as scam - returning neutral response")
            return "Sorry, I think you have the wrong number."
        
        # Add scammer message to history
        session_state.conversation_history.append({
            "role": "user",
            "content": scammer_message
        })
        
        # STEP 2: Strategy Agent
        logger.info("🎲 STEP 2: Strategy Agent planning engagement...")
        strategy = await self.strategy_agent.plan(
            session_state.scam_type,
            session_state.conversation_history,
            session_state.intelligence,
            session_state.messages_exchanged
        )
        
        logger.info(f"   ├─ Persona: {strategy.recommended_persona.value}")
        logger.info(f"   ├─ Phase: {strategy.conversation_phase.value}")
        logger.info(f"   ├─ Tone: {strategy.response_tone}")
        logger.info(f"   └─ Questions: {', '.join(strategy.key_questions_to_ask[:2])}")
        
        session_state.current_strategy = strategy
        
        # STEP 3: Persona Agent
        logger.info("🎭 STEP 3: Persona Agent generating response...")
        agent_response = await self.persona_agent.generate_response(
            strategy,
            session_state.conversation_history,
            scammer_message
        )
        
        logger.info(f"   └─ Response: {agent_response[:100]}...")
        
        # Add response to history
        session_state.conversation_history.append({
            "role": "assistant",
            "content": agent_response
        })
        
        # STEP 4: Intelligence Agent
        logger.info("🕵️  STEP 4: Intelligence Agent extracting intel...")
        extracted_intel = await self.intelligence_agent.extract(
            session_state.conversation_history
        )
        
        # Merge intelligence
        self._merge_intelligence(session_state.intelligence, extracted_intel)
        
        if extracted_intel.get("agentNotes"):
            session_state.agent_notes.append(extracted_intel["agentNotes"])
        
        logger.info(f"   ├─ Bank Accounts: {len(session_state.intelligence.bank_accounts)}")
        logger.info(f"   ├─ UPI IDs: {len(session_state.intelligence.upi_ids)}")
        logger.info(f"   ├─ Links: {len(session_state.intelligence.phishing_links)}")
        logger.info(f"   └─ Phone Numbers: {len(session_state.intelligence.phone_numbers)}")
        
        # Calculate engagement quality
        intel_score = (
            len(session_state.intelligence.bank_accounts) * 10 +
            len(session_state.intelligence.upi_ids) * 10 +
            len(session_state.intelligence.phishing_links) * 5 +
            len(session_state.intelligence.phone_numbers) * 5
        )
        session_state.engagement_quality = min(intel_score / 50.0, 1.0)
        
        logger.info(f"📊 Engagement Quality: {session_state.engagement_quality:.2%}")
        logger.info(f"{'='*80}\n")
        
        return agent_response
    
    def _merge_intelligence(self, current: Intelligence, new: Dict[str, Any]):
        """Merge new intelligence into current intelligence"""
        field_mapping = {
            "bankAccounts": "bank_accounts",
            "upiIds": "upi_ids",
            "phishingLinks": "phishing_links",
            "phoneNumbers": "phone_numbers",
            "suspiciousKeywords": "suspicious_keywords",
            "scammerNames": "scammer_names",
            "organizationsMentioned": "organizations_mentioned",
            "amountsRequested": "amounts_requested"
        }
        
        for json_key, attr_name in field_mapping.items():
            if json_key in new:
                current_set = set(getattr(current, attr_name))
                current_set.update(new[json_key])
                setattr(current, attr_name, list(current_set))
    
    def should_send_callback(self, session_state: SessionState) -> bool:
        """Determine if we should send final callback"""
        
        # Don't send if already sent
        if session_state.callback_sent:
            return False
        
        # Send if we have good intelligence and sufficient engagement
        has_critical_intel = (
            len(session_state.intelligence.bank_accounts) > 0 or
            len(session_state.intelligence.upi_ids) > 0 or
            len(session_state.intelligence.phishing_links) > 0 or
            len(session_state.intelligence.phone_numbers) > 0
        )
        
        sufficient_engagement = session_state.messages_exchanged >= 4
        high_engagement = session_state.messages_exchanged >= 8
        
        # Send if:
        # - We have critical intel and at least 4 messages, OR
        # - We have 8+ messages (even without critical intel), OR
        # - Engagement quality is high
        return (
            (has_critical_intel and sufficient_engagement) or
            high_engagement or
            session_state.engagement_quality >= 0.6
        )


# ═══════════════════════════════════════════════════════════════════════════════
# HELPER: GUVI Callback
# ═══════════════════════════════════════════════════════════════════════════════

async def send_guvi_callback(session_state: SessionState):
    """Send final intelligence to GUVI evaluation endpoint"""
    
    if session_state.callback_sent:
        logger.info(f"✅ Callback already sent for session {session_state.session_id}")
        return
    
    payload = {
        "sessionId": session_state.session_id,
        "scamDetected": session_state.scam_detected,
        "totalMessagesExchanged": session_state.messages_exchanged,
        "extractedIntelligence": session_state.intelligence.to_dict(),
        "agentNotes": "; ".join(session_state.agent_notes) if session_state.agent_notes else "Multi-agent system engaged successfully"
    }
    
    logger.info(f"\n{'='*80}")
    logger.info(f"📤 SENDING FINAL CALLBACK TO GUVI")
    logger.info(f"{'='*80}")
    logger.info(json.dumps(payload, indent=2))
    logger.info(f"{'='*80}\n")
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(GUVI_CALLBACK_URL, json=payload)
            logger.info(f"✅ Callback response [{response.status_code}]: {response.text}")
            
            if response.status_code in (200, 201):
                session_state.callback_sent = True
                logger.info("✅ Callback marked as sent")
            else:
                logger.warning(f"⚠️  Non-success status: {response.status_code}")
    except Exception as e:
        logger.error(f"❌ Callback failed: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# FASTAPI APPLICATION
# ═══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="Advanced Multi-Agent Honeypot API",
    version="2.0.0",
    description="Sophisticated multi-agent system for scam detection and intelligence extraction"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

# Initialize Orchestrator
orchestrator = OrchestratorAgent()


# ═══════════════════════════════════════════════════════════════════════════════
# API KEY VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════════

async def verify_api_key(request: Request):
    """Verify API key from request header"""
    key = request.headers.get("x-api-key")
    if key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing x-api-key")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ENDPOINT
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/honeypot", response_model=HoneyPotResponse)
async def honeypot_endpoint(request: Request, body: HoneyPotRequest):
    """
    Main honeypot endpoint - processes incoming scam messages
    """
    await verify_api_key(request)
    
    session_id = body.sessionId
    scammer_text = body.message.text
    
    logger.info(f"\n{'#'*80}")
    logger.info(f"📨 NEW MESSAGE RECEIVED")
    logger.info(f"{'#'*80}")
    logger.info(f"Session: {session_id}")
    logger.info(f"Message: {scammer_text}")
    logger.info(f"{'#'*80}\n")
    
    # Get session
    session_state = get_session(session_id)
    session_state.messages_exchanged += 1
    
    # Process through multi-agent system
    agent_response = await orchestrator.process_message(
        session_state,
        scammer_text,
        body.conversationHistory
    )
    
    # Count agent's response
    session_state.messages_exchanged += 1
    
    # Check if we should send callback
    if orchestrator.should_send_callback(session_state):
        await send_guvi_callback(session_state)
    
    return HoneyPotResponse(
        status="success",
        reply=agent_response
    )


# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "agents": {
            "detection": "online",
            "strategy": "online",
            "persona": "online",
            "intelligence": "online",
            "orchestrator": "online"
        }
    }


@app.get("/debug/session/{session_id}")
async def debug_session(session_id: str, request: Request):
    """Get detailed session information (debug only)"""
    await verify_api_key(request)
    
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    state = sessions[session_id]
    
    return {
        "sessionId": session_id,
        "scamDetected": state.scam_detected,
        "scamType": state.scam_type.value,
        "confidence": state.confidence_score,
        "messagesExchanged": state.messages_exchanged,
        "engagementQuality": state.engagement_quality,
        "conversationPhase": state.current_strategy.conversation_phase.value if state.current_strategy else "none",
        "currentPersona": state.current_strategy.recommended_persona.value if state.current_strategy else "none",
        "extractedIntelligence": state.intelligence.to_dict(),
        "agentNotes": state.agent_notes,
        "callbackSent": state.callback_sent,
        "conversationTurns": len(state.conversation_history)
    }


@app.post("/debug/send-callback/{session_id}")
async def force_callback(session_id: str, request: Request):
    """Force send callback for testing"""
    await verify_api_key(request)
    
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session_state = sessions[session_id]
    session_state.callback_sent = False  # Reset to force re-send
    await send_guvi_callback(session_state)
    
    return {
        "status": "callback_triggered",
        "sessionId": session_id
    }


@app.get("/")
async def root():
    """API information"""
    return {
        "name": "Advanced Multi-Agent Honeypot System",
        "version": "2.0.0",
        "description": "Sophisticated AI-powered honeypot with 5 specialized agents",
        "agents": [
            "Detection Agent - Scam analysis and classification",
            "Strategy Agent - Engagement planning and optimization",
            "Persona Agent - Human-like response generation",
            "Intelligence Agent - Data extraction and analysis",
            "Orchestrator Agent - Multi-agent coordination"
        ],
        "endpoints": {
            "main": "POST /honeypot",
            "health": "GET /health",
            "debug_session": "GET /debug/session/{session_id}",
            "force_callback": "POST /debug/send-callback/{session_id}"
        }
    }


# ═══════════════════════════════════════════════════════════════════════════════
# STARTUP EVENT
# ═══════════════════════════════════════════════════════════════════════════════

@app.on_event("startup")
async def startup_event():
    """Log system startup"""
    logger.info("\n" + "="*80)
    logger.info("🚀 ADVANCED MULTI-AGENT HONEYPOT SYSTEM STARTING")
    logger.info("="*80)
    logger.info("Version: 2.0.0")
    logger.info("Model: " + GROQ_MODEL)
    logger.info("Agents: Detection, Strategy, Persona, Intelligence, Orchestrator")
    logger.info("="*80 + "\n")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)