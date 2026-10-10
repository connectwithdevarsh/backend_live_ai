/**
 * RAADHE AI — Secure AI Backend Proxy & Tool Calling Gateway
 * 
 * Provides server-side LLM provider integration, credential security,
 * tool-call schema validation, and rate limiting.
 */

const express = require('express');
const cors = require('cors');
const dns = require('dns');
if (dns.setDefaultResultOrder) {
  dns.setDefaultResultOrder('ipv4first');
}
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Security Middleware
app.use(cors());
app.use(express.json({ limit: '256kb' })); // Enforce request body size limits

// Explicitly Registered Native Tools Allowlist
const REGISTERED_TOOLS = [
  {
    name: 'toggle_flashlight',
    description: 'Turn the device camera flashlight torch on or off.',
    parameters: {
      enable: { type: 'boolean', description: 'true to turn on, false to turn off' }
    },
    risk: 'moderate'
  },
  {
    name: 'launch_app',
    description: 'Launch an installed application by name or package identifier.',
    parameters: {
      app_name: { type: 'string', description: 'Friendly name of the application (e.g., YouTube, Calculator, Chrome)' },
      package_name: { type: 'string', optional: true, description: 'Optional explicit Android package name' }
    },
    risk: 'low'
  },
  {
    name: 'adjust_volume',
    description: 'Adjust the device media playback volume relative to current level.',
    parameters: {
      direction: { type: 'string', enum: ['up', 'down', 'mute'], description: 'Volume adjustment direction' }
    },
    risk: 'moderate'
  },
  {
    name: 'set_volume',
    description: 'Set media stream volume to a specific absolute percentage (0 to 100).',
    parameters: {
      percent: { type: 'integer', minimum: 0, maximum: 100, description: 'Target volume percentage' }
    },
    risk: 'moderate'
  },
  {
    name: 'set_alarm',
    description: 'Create an alarm in the Android Clock application.',
    parameters: {
      hour: { type: 'integer', minimum: 0, maximum: 23, description: 'Alarm hour (0-23 in 24-hour format)' },
      minute: { type: 'integer', minimum: 0, maximum: 59, description: 'Alarm minute (0-59)' },
      message: { type: 'string', optional: true, description: 'Label for the alarm' }
    },
    risk: 'moderate'
  },
  {
    name: 'set_timer',
    description: 'Start a countdown timer in the Android Clock application.',
    parameters: {
      seconds: { type: 'integer', minimum: 1, maximum: 86400, description: 'Timer duration in seconds' },
      message: { type: 'string', optional: true, description: 'Label for the timer' }
    },
    risk: 'moderate'
  },
  {
    name: 'open_setting',
    description: 'Open a specific Android system settings panel.',
    parameters: {
      setting_type: { 
        type: 'string', 
        enum: ['wifi', 'bluetooth', 'display', 'sound', 'battery', 'settings'], 
        description: 'Target settings page identifier' 
      }
    },
    risk: 'low'
  }
];

// Helper to construct the system prompt
function buildSystemPrompt(preferredLanguage = 'English') {
  return `You are RAADHE AI, a calm, intelligent, respectful, minimal, and futuristic personal Android AI assistant.
User's Preferred Language: ${preferredLanguage}.

You have access ONLY to the following registered native phone tools on Android 16:
${JSON.stringify(REGISTERED_TOOLS, null, 2)}

INSTRUCTIONS:
1. Distinguish between:
   - "generalQuestion": questions, explanations, summaries, calculations, or conversations.
   - "singleAction": user requests a single native phone action.
   - "multiStepTask": user requests multiple sequential actions (e.g. "open settings then bluetooth", "turn on flashlight and volume up").
   - "clarification": user command is ambiguous (e.g. "set alarm for 7" without AM/PM).
   - "unsupported": requests that cannot be handled by available native tools.
2. For "generalQuestion", provide concise, accurate, elegant responses without inventing tool calls.
3. For phone actions, select ONLY from the registered tools above. NEVER invent tool names or execute arbitrary code.
4. If an action is ambiguous or high-risk, set "requiresConfirmation": true and provide a "confirmationPrompt".
5. For multi-step tasks, supply a step-by-step "plan" and ordered "toolCalls".
6. Always reply strictly in the following JSON format without Markdown codeblocks or surrounding text:
{
  "userFacingText": "Concise natural language message to the user in their preferred language (${preferredLanguage})",
  "intent": "generalQuestion" | "singleAction" | "multiStepTask" | "clarification" | "unsupported",
  "clarifyingQuestion": null | "Question asking for missing details",
  "plan": [
    { "stepNumber": 1, "description": "Step description", "toolName": "tool_name" }
  ],
  "toolCalls": [
    { "toolName": "tool_name", "arguments": { ... } }
  ],
  "requiresConfirmation": false,
  "confirmationPrompt": null | "Confirmation question if high-risk or ambiguous"
}`;
}

// Validation function for tool calls returned by the model
function validateToolCalls(toolCalls) {
  if (!Array.isArray(toolCalls)) return [];
  const valid = [];

  for (const call of toolCalls) {
    if (!call || typeof call !== 'object' || !call.toolName) continue;
    const schema = REGISTERED_TOOLS.find(t => t.name === call.toolName);
    if (!schema) {
      console.warn(`[Security Warning] Model attempted to call unregistered tool: ${call.toolName}`);
      continue; // Strictly reject unregistered tools
    }

    const args = call.arguments || {};
    let argsValid = true;

    // Validate argument schemas
    if (call.toolName === 'toggle_flashlight') {
      if (typeof args.enable !== 'boolean') args.enable = true;
    } else if (call.toolName === 'launch_app') {
      if (!args.app_name || typeof args.app_name !== 'string') argsValid = false;
    } else if (call.toolName === 'adjust_volume') {
      if (!['up', 'down', 'mute'].includes(String(args.direction).toLowerCase())) {
        args.direction = 'up';
      }
    } else if (call.toolName === 'set_volume') {
      const p = parseInt(args.percent, 10);
      args.percent = isNaN(p) ? 50 : Math.max(0, Math.min(100, p));
    } else if (call.toolName === 'set_alarm') {
      const h = parseInt(args.hour, 10);
      const m = parseInt(args.minute, 10);
      args.hour = isNaN(h) ? 7 : Math.max(0, Math.min(23, h));
      args.minute = isNaN(m) ? 0 : Math.max(0, Math.min(59, m));
    } else if (call.toolName === 'set_timer') {
      const s = parseInt(args.seconds, 10);
      args.seconds = isNaN(s) ? 300 : Math.max(1, Math.min(86400, s));
    } else if (call.toolName === 'open_setting') {
      const validSettings = ['wifi', 'bluetooth', 'display', 'sound', 'battery', 'settings'];
      if (!validSettings.includes(String(args.setting_type).toLowerCase())) {
        args.setting_type = 'settings';
      }
    }

    if (argsValid) {
      valid.push({
        toolName: call.toolName,
        arguments: args,
        risk: schema.risk
      });
    }
  }

  return valid;
}

// Health Check Endpoint (does not expose keys)
app.get('/health', (req, res) => {
  const provider = process.env.AI_PROVIDER || 'gemini';
  const hasGeminiKey = Boolean(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY.length > 5);
  const hasGroqKey = Boolean(process.env.GROQ_API_KEY && process.env.GROQ_API_KEY.length > 5);

  res.json({
    status: 'ok',
    service: 'RAADHE AI Brain Proxy',
    version: '4.0.0',
    provider: provider,
    configured: provider === 'groq' ? hasGroqKey : hasGeminiKey,
    activeModel: provider === 'groq' 
      ? (process.env.GROQ_MODEL || 'llama-3.3-70b-versatile')
      : (process.env.GEMINI_MODEL || 'gemini-2.5-flash')
  });
});

// Tools Schema Discovery Endpoint
app.get('/api/tools', (req, res) => {
  res.json({ tools: REGISTERED_TOOLS });
});

// Primary Chat & Tool-Calling Pipeline Endpoint
app.post('/api/chat', async (req, res) => {
  try {
    const { message, conversationHistory = [], language = 'English' } = req.body;

    if (!message || typeof message !== 'string' || message.trim().length === 0) {
      return res.status(400).json({ error: 'Valid "message" string is required.' });
    }

    const provider = (process.env.AI_PROVIDER || 'gemini').toLowerCase();
    const systemPrompt = buildSystemPrompt(language);

    let rawResponseText = '';

    if (provider === 'groq') {
      rawResponseText = await callGroqApi(message, conversationHistory, systemPrompt);
    } else {
      rawResponseText = await callGeminiApi(message, conversationHistory, systemPrompt);
    }

    // Clean JSON response (strip markdown fences if present)
    let cleanedJson = rawResponseText.trim();
    if (cleanedJson.startsWith('```json')) {
      cleanedJson = cleanedJson.replace(/^```json\s*/, '').replace(/```\s*$/, '');
    } else if (cleanedJson.startsWith('```')) {
      cleanedJson = cleanedJson.replace(/^```\s*/, '').replace(/```\s*$/, '');
    }

    let parsedResult;
    try {
      parsedResult = JSON.parse(cleanedJson);
    } catch (parseError) {
      console.warn('Failed to parse model JSON directly, wrapping as general text:', rawResponseText);
      parsedResult = {
        userFacingText: rawResponseText,
        intent: 'generalQuestion',
        clarifyingQuestion: null,
        plan: [],
        toolCalls: [],
        requiresConfirmation: false,
        confirmationPrompt: null
      };
    }

    // Enforce tool call validation and security filters
    parsedResult.toolCalls = validateToolCalls(parsedResult.toolCalls);

    // Verify confirmation requirement for high-risk tools
    const hasModerateOrSensitive = parsedResult.toolCalls.some(t => t.risk === 'moderate' || t.risk === 'sensitive');
    if (parsedResult.intent === 'multiStepTask' && hasModerateOrSensitive) {
      parsedResult.requiresConfirmation = true;
      parsedResult.confirmationPrompt = parsedResult.confirmationPrompt || 
        `I have prepared a multi-step task with ${parsedResult.toolCalls.length} actions. Proceed with execution?`;
    }

    res.json({
      success: true,
      data: parsedResult
    });

  } catch (err) {
    console.error('[RAADHE AI Proxy Error]:', err.message);
    res.status(502).json({
      success: false,
      error: 'AI Provider error: ' + err.message
    });
  }
});

// Provider: Google Gemini Integration
async function callGeminiApi(userMessage, history, systemPrompt) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error('GEMINI_API_KEY is not configured in server environment variables.');
  }

  const model = process.env.GEMINI_MODEL || 'gemini-2.5-flash';
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;

  // Format contents array
  const contents = [];

  // Add recent conversation history (max 8 messages)
  const recentHistory = history.slice(-8);
  for (const item of recentHistory) {
    if (item.role && item.content) {
      contents.push({
        role: item.role === 'assistant' ? 'model' : 'user',
        parts: [{ text: item.content }]
      });
    }
  }

  // Add current user prompt
  contents.push({
    role: 'user',
    parts: [{ text: userMessage }]
  });

  const body = {
    system_instruction: {
      parts: [{ text: systemPrompt }]
    },
    contents: contents,
    generationConfig: {
      temperature: 0.2,
      responseMimeType: 'application/json'
    }
  };

  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Gemini API responded with status ${response.status}: ${errorText}`);
  }

  const json = await response.json();
  const candidate = json.candidates?.[0];
  if (!candidate || !candidate.content?.parts?.[0]?.text) {
    throw new Error('Gemini API returned empty response candidate.');
  }

  return candidate.content.parts[0].text;
}

// Provider: Groq Integration (Llama-3 / Mixtral)
async function callGroqApi(userMessage, history, systemPrompt) {
  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) {
    throw new Error('GROQ_API_KEY is not configured in server environment variables.');
  }

  const model = process.env.GROQ_MODEL || 'llama-3.3-70b-versatile';
  const url = 'https://api.groq.com/openai/v1/chat/completions';

  const messages = [
    { role: 'system', content: systemPrompt }
  ];

  const recentHistory = history.slice(-8);
  for (const item of recentHistory) {
    if (item.role && item.content) {
      messages.push({
        role: item.role === 'assistant' ? 'assistant' : 'user',
        content: item.content
      });
    }
  }

  messages.push({ role: 'user', content: userMessage });

  const body = {
    model: model,
    messages: messages,
    temperature: 0.2,
    response_format: { type: 'json_object' }
  };

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`
    },
    body: JSON.stringify(body)
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Groq API responded with status ${response.status}: ${errorText}`);
  }

  const json = await response.json();
  const choice = json.choices?.[0];
  if (!choice || !choice.message?.content) {
    throw new Error('Groq API returned empty message content.');
  }

  return choice.message.content;
}

app.listen(PORT, () => {
  console.log(`[RAADHE AI Backend] Proxy listening on port ${PORT}`);
  console.log(`[RAADHE AI Backend] Active Provider: ${process.env.AI_PROVIDER || 'gemini'}`);
});
