# RAADHE AI — Phase 4 Backend Proxy

Secure server-side AI proxy for RAADHE AI running on Vivo Android 16.

## Architecture & Security Model

In accordance with Phase 4 security requirements:
- **No Client-Side Secrets**: LLM API keys (`GEMINI_API_KEY`, `GROQ_API_KEY`) are stored **strictly** in server-side environment variables and are never bundled into the Flutter application or compiled into APK assets.
- **Strict Tool Allowlisting**: Incoming requests and outgoing model responses are checked against explicit Phase 3 registered phone tools (`launch_app`, `open_setting`, `toggle_flashlight`, `adjust_volume`, `set_volume`, `set_alarm`, `set_timer`). Any hallucinated or unauthorized tool is rejected with an honest error.
- **Payload Limits**: Enforces a 64KB JSON body limit to protect against oversized or abusive payloads.
- **Prompt Injection Defense**: User instructions are passed to the model wrapped in clear structural boundaries, instructing the model to reject overrides of system constraints.

---

## Setup & Running Locally

### 1. Install Dependencies
```bash
cd backend
npm install
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Edit `.env` and add your valid API key:
```env
AI_PROVIDER=gemini
GEMINI_API_KEY=AIzaSy...
GEMINI_MODEL=gemini-1.5-flash
```

Or for Groq:
```env
AI_PROVIDER=groq
GROQ_API_KEY=gsk_...
GROQ_MODEL=llama-3.3-70b-versatile
```

### 3. Start the Server
```bash
node server.js
```
The server will start on `http://0.0.0.0:3000`.

---

## API Endpoints

### `GET /health`
Returns proxy health and configured provider status without exposing credentials.
```json
{
  "status": "healthy",
  "version": "4.0.0",
  "provider": "gemini",
  "model": "gemini-1.5-flash",
  "configured": true,
  "registeredToolsCount": 7
}
```

### `GET /api/tools`
Returns the definitions of explicitly approved phone tools.

### `POST /api/chat`
Processes conversational queries, multi-step plans, and tool calling.
- **Headers**: `Content-Type: application/json`
- **Body**:
```json
{
  "message": "Open Settings and then show me Bluetooth settings.",
  "conversationHistory": [
    {"role": "user", "text": "Hello"},
    {"role": "model", "text": "Hello Devarsh! How can I help you today?"}
  ],
  "language": "gu-IN",
  "provider": "gemini"
}
```
- **Response**:
```json
{
  "success": true,
  "intent": "multiStepPlan",
  "response": "I will open Settings and then navigate to Bluetooth settings.",
  "plan": [
    {
      "step": 1,
      "description": "Open Android Settings",
      "tool": "open_setting",
      "arguments": {"settingType": "settings"},
      "risk": "low"
    },
    {
      "step": 2,
      "description": "Open Bluetooth settings",
      "tool": "open_setting",
      "arguments": {"settingType": "bluetooth"},
      "risk": "low"
    }
  ],
  "provider": "gemini",
  "model": "gemini-1.5-flash"
}
```
