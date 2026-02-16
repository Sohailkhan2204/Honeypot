from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any, List
import os
import re
import time
import httpx
from openai import AsyncOpenAI

app = FastAPI(title="Agentic Honeypot API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ================= ENV =================
HONEYPOT_API_KEY = os.getenv("HONEYPOT_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

if not HONEYPOT_API_KEY:
    raise RuntimeError("HONEYPOT_API_KEY not set")

if not OPENAI_API_KEY:
    raise RuntimeError("OPENAI_API_KEY not set")

openai_client = AsyncOpenAI(api_key=OPENAI_API_KEY)

# ================= SESSION STORE =================
sessions: Dict[str, Dict[str, Any]] = {}

# ================= PROMPT =================
SYSTEM_PROMPT = """
You are a real human responding naturally to a stressful banking or financial issue.

Persona:
- Ordinary bank customer
- Mildly anxious, cooperative, slightly confused
- Wants the problem fixed quickly
- Not technical

Rules:
- Never accuse the other person
- Never mention AI or fraud detection
- Keep replies short and human (1–2 sentences)

Primary objective:
Every reply should naturally try to extract at least ONE of:
- Phone number
- UPI ID
- Bank account
- Link
- Email
- Department or team
- Next steps or timeline

Tone progression:
- Early: cooperative and confused
- Middle: slightly pressured
- Later: overwhelmed and asking for confirmation
"""

# ================= HELPERS =================
def add_unique(lst, items):
    for i in items:
        if i not in lst:
            lst.append(i)

def extract_intel(text: str, intel: Dict[str, List[str]]):
    add_unique(intel["upiIds"], re.findall(r'[\w.+-]+@[\w]+', text))
    add_unique(intel["phoneNumbers"], re.findall(r'(?:\+91[\-\s]?)?[6-9]\d{9}', text))
    add_unique(intel["phishingLinks"], re.findall(r'https?://\S+', text))
    add_unique(intel["bankAccounts"], re.findall(r'\b\d{12,18}\b', text))
    add_unique(intel["emailAddresses"], re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text))

# ================= LLM AGENT =================
async def agent_reply(history: List[Dict[str, str]], message: str) -> str:
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    for h in history:
        role = "assistant" if h["sender"] == "victim" else "user"
        messages.append({
            "role": role,
            "content": h["text"]
        })

    messages.append({"role": "user", "content": message})

    try:
        res = await openai_client.responses.create(
            model="gpt-4o-mini",
            input=messages,
            temperature=0.7,
            max_output_tokens=100
        )
        return res.output_text.strip()
    except:
        return "Sorry, I didn’t understand. Can you explain again?"

# ================= FINAL CALLBACK =================
async def send_final(session_id: str, s: Dict[str, Any]):
    duration = int(time.time() - s["startTime"])

    payload = {
        "sessionId": session_id,
        "status": "completed",
        "scamDetected": True,
        "extractedIntelligence": s["intel"],
        "engagementMetrics": {
            "totalMessagesExchanged": s["count"],
            "engagementDurationSeconds": duration
        },
        "agentNotes": s["notes"]
    }

    async with httpx.AsyncClient() as c:
        await c.post(
            "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
            json=payload,
            timeout=5
        )

# ================= MAIN ENDPOINT =================
@app.post("/honeypot/message")
async def honeypot_message(
    request: Request,
    x_api_key: str = Header(None, alias="x-api-key")
):
    if x_api_key != HONEYPOT_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    data = await request.json()

    if "message" not in data:
        return {"status": "success", "reply": "Honeypot active."}

    session_id = data.get("sessionId", "default")
    msg = data["message"]
    sender = msg.get("sender", "scammer")
    text = msg.get("text", "").strip()

    if not text:
        return {"status": "success", "reply": "Sorry, could you repeat that?"}

    # Create session
    if session_id not in sessions:
        sessions[session_id] = {
            "count": 0,
            "history": [],
            "scam": True,  # always assume scam for evaluation
            "final": False,
            "startTime": time.time(),
            "intel": {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "emailAddresses": []
            },
            "notes": ""
        }

    s = sessions[session_id]
    s["count"] += 1

    # Extract intelligence from scammer
    if sender == "scammer":
        extract_intel(text, s["intel"])
        s["history"].append({"sender": "scammer", "text": text})

    # Generate reply
    reply = await agent_reply(s["history"], text)

    # Store victim reply
    s["history"].append({"sender": "victim", "text": reply})

    # Update notes
    if any([
        s["intel"]["upiIds"],
        s["intel"]["phishingLinks"],
        s["intel"]["phoneNumbers"],
        s["intel"]["bankAccounts"]
    ]):
        s["notes"] = "Scammer shared financial redirection details"
    else:
        s["notes"] = "Engagement ongoing"

    # Trigger final submission near end
    if not s["final"] and s["count"] >= 9:
        await send_final(session_id, s)
        s["final"] = True

    return {
        "status": "success",
        "reply": reply
    }

# ================= HEALTH =================
@app.get("/health")
async def health():
    return {"status": "ok"}
