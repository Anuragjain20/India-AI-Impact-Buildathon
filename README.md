# AI-Powered Scam Detection Honeypot System

An intelligent honeypot system that uses AI agents to detect, engage, and extract intelligence from scammers in real-time conversations. Built for the India AI Impact Buildathon.

## 🎯 Overview

This system acts as an AI-powered honeypot that engages with potential scammers, extracts critical intelligence (bank accounts, UPI IDs, phishing links, phone numbers), and provides actionable insights. The system uses multiple specialized AI agents working together with reinforcement learning to optimize engagement strategies.

## ✨ Features

- **Multi-Agent Architecture**: Specialized AI agents for classification, extraction, and persona-based engagement
- **Reinforcement Learning**: Adaptive persona and strategy selection based on performance
- **Intelligence Extraction**: Automatically extracts:
  - Bank account numbers
  - UPI IDs
  - Phishing links
  - Phone numbers
  - Suspicious keywords
- **Session Management**: Maintains conversation history and context across interactions
- **Smart Engagement**: Uses different personas (elderly, student, business owner) to maximize intelligence gathering
- **Real-time Processing**: Fast API responses with async processing
- **Callback Integration**: Sends extracted intelligence to external systems

## 🏗️ Architecture

### Core Components

1. **Classifier Agent**: Initial scam detection and classification
2. **Extraction Agent**: Extracts structured intelligence from conversations
3. **Persona Agent**: Engages scammers using role-play personas
4. **Team Orchestrator**: Coordinates agent interactions and workflow
5. **Reinforcement Learning**: Optimizes persona and strategy selection

### System Flow

```
Incoming Message → Classifier Agent → Persona Agent → Extraction Agent → Intelligence Storage → Callback
```

## 🚀 Installation

### Prerequisites

- Python 3.8+
- DEEPSEEK API KEY
- Honeypot API key (for authentication)

### Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd India-AI-Impact-Buildathon
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment variables**
   
   Create a `.env` file in the root directory:
   ```env
   DEEPSEEK_API_KEY=your_deepseek_api_key_here
   HONEYPOT_API_KEY=your_honeypot_api_key_here
   ```

4. **Run the application**
   ```bash
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```

## 📡 API Usage

### Endpoint: `/honeypot`

**Method**: `POST`

**Headers**:
```
x-api-key: <your_honeypot_api_key>
Content-Type: application/json
```

**Request Body**:
```json
{
  "sessionId": "unique_session_id",
  "message": {
    "text": "Hello, I need your bank details urgently!"
  }
}
```

**Response**:
```json
{
  "status": "success",
  "reply": "I'm not sure about that. Can you tell me more?"
}
```

**Session Completion Response**:
```json
{
  "status": "completed"
}
```

### Example cURL Request

```bash
curl -X POST http://localhost:8000/honeypot \
  -H "x-api-key: your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "session_123",
    "message": {
      "text": "Your account will be blocked. Send OTP immediately."
    }
  }'
```

## 📁 Project Structure

```
India-AI-Impact-Buildathon/
├── main.py                      # FastAPI application entry point
├── requirements.txt             # Python dependencies
├── .env                        # Environment variables (create this)
├── final/
│   ├── __init__.py
│   ├── config.py               # Configuration and environment variables
│   ├── model_client.py         # Deepseek API client setup
│   ├── schemas.py              # Pydantic models for intelligence
│   ├── session_memory.py       # Conversation history management
│   ├── session_context_memory.py # Intelligence storage per session
│   ├── callback_service.py     # External API callback handler
│   ├── agents/
│   │   ├── classifier_agent.py    # Scam classification agent
│   │   ├── extraction_agent.py    # Intelligence extraction agent
│   │   ├── persona_agent.py       # Persona-based engagement agent
│   │   └── team_orchestrator.py   # Agent coordination logic
│   └── rl/
│       ├── persona_rl.py       # Persona selection RL
│       └── strategy_rl.py      # Strategy selection RL
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `DEEPSEEK_API_KEY` | Primary DEEPSEEK API KEY | Yes |
| `HONEYPOT_API_KEY` | API key for honeypot endpoint authentication | Yes |

### Session Limits

Configured in `main.py`:
- `MAX_MESSAGES_PER_SESSION`: Maximum messages per session (default: 20)
- `MIN_MESSAGES_BEFORE_CALLBACK`: Minimum messages before callback (default: 10)

## 🤖 AI Agents

### Classifier Agent
- **Purpose**: Initial scam detection
- **Model**: Deepseek-chat (via Deepseek)
- **Output**: JSON with `scamDetected` and `confidenceScore`

### Extraction Agent
- **Purpose**: Extract structured intelligence
- **Model**: Deepseek-chat (JSON mode)
- **Output**: Structured intelligence schema with bank accounts, UPI IDs, links, etc.

### Persona Agent
- **Purpose**: Natural conversation engagement
- **Model**: Deepseek-chat (conversational)
- **Personas**: Elderly, Student, Business Owner
- **Strategies**: Clarify, Confused, Delay

## 🧠 Reinforcement Learning

The system uses two RL components:

1. **Persona RL**: Learns which persona works best for different scenarios
2. **Strategy RL**: Learns optimal conversation strategies using Q-learning

RL data is persisted in `/tmp/persona_scores.json` and `/tmp/strategy_q_table.json`.

## 📊 Intelligence Schema

```python
{
  "scamDetected": bool,
  "bankAccounts": List[str],
  "upiIds": List[str],
  "phishingLinks": List[str],
  "phoneNumbers": List[str],
  "suspiciousKeywords": List[str],
  "agentNotes": str,
  "confidenceScore": float,
  "engagementMetrics": {
    "totalMessagesExchanged": int,
    "engagementDurationSeconds": int
  }
}
```

## 🔄 Callback System

When a session completes, the system sends extracted intelligence to:
```
POST https://hackathon.guvi.in/api/updateHoneyPotFinalResult
```

Payload includes:
- Session ID
- Total messages exchanged
- Extracted intelligence
- Agent notes
- Engagement metrics

## 🛠️ Technologies Used

- **FastAPI**: Web framework
- **DEEPSEEK API**: LLM inference (Deepseek-chat)
- **AutoGen**: Multi-agent framework
- **Pydantic**: Data validation
- **NumPy**: Reinforcement learning calculations
- **Python-dotenv**: Environment variable management

## 📝 Development

### Running in Development Mode

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Testing

Test the API endpoint using the provided cURL example or tools like Postman.

## 🔒 Security Considerations

- API key authentication required for all endpoints
- Session isolation prevents data leakage
- No sensitive data stored permanently (session-based memory)
- Secure callback handling with timeout protection

## 📈 Performance

- Async processing for concurrent requests
- Session memory limits prevent unbounded growth
- Efficient agent coordination minimizes API calls
- RL optimization improves over time

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

[Specify your license here]

## 🙏 Acknowledgments

Built for the India AI Impact Buildathon. Uses Deepseek API for LLM inference and AutoGen for multi-agent orchestration.

## 📞 Support

For issues or questions, please open an issue in the repository.

---

**Note**: This system is designed for research and educational purposes. Ensure compliance with local laws and regulations when deploying in production environments.
