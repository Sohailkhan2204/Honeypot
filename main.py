from fastapi import FastAPI, Header, HTTPException, Request
from typing import Dict, Any, List
from datetime import datetime
import os
import re
import httpx
from openai import AsyncOpenAI

app = FastAPI(title="Agentic Honeypot API")

# ================== ENV VARS ==================
HONEYPOT_API_KEY = os.getenv("HONEYPOT_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

if not HONEYPOT_API_KEY:
    raise RuntimeError("HONEYPOT_API_KEY not set")
if not OPENAI_API_KEY:
    raise RuntimeError("OPENAI_API_KEY not set")

openai_client = AsyncOpenAI(api_key=OPENAI_API_KEY)

# ================== SESSION STORE ==================
sessions: Dict[str, Dict[str, Any]] = {}

# ================== AGENT PROMPT ==================
SYSTEM_PROMPT = """
You are an elderly, naive person.
You are talking to someone who may be a scammer.

Rules:
- Sound polite, confused, and cooperative
- Never accuse them of scamming
- Never reveal you are an AI
- Ask simple clarifying questions
- Encourage them to explain steps, links, phone numbers, or UPI IDs
- Never share real OTPs, bank details, or personal info
- Keep the conversation going

If the message is in Hindi, reply in Hindi.
If in English, reply in English.
"""

# ================== SCAM LOGIC ==================
SCAM_KEYWORDS = [
    "otp", "urgent", "verify", "blocked", "suspended",
    "upi", "bank", "account", "kyc", "immediately"
]

def detect_scam(text: str) -> bool:
    return any(word in text.lower() for word in SCAM_KEYWORDS)

def extract_intel(text: str, intel: Dict[str, List[str]]):
    intel["upiIds"] += re.findall(r'[\w.+-]+@[\w]+', text)
    intel["phoneNumbers"] += re.findall(r'(?:\+91)?[6-9]\d{9}', text)
    intel["phishingLinks"] += re.findall(r'https?://\S+', text)

# ================== AI AGENT ==================
async def agent_reply(message: str, history: List[str]) -> str:
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    for h in history:
        messages.append({"role": "user", "content": h})
    messages.append({"role": "user", "content": message})

    response = await openai_client.chat.completions.create(
        model="gpt-4o-mini",
        messages=messages,
        temperature=0.7,
        max_tokens=150
    )
    return response.choices[0].message.content.strip()

# ================== GUVI CALLBACK ==================
async def send_final_to_guvi(session_id: str, session: Dict[str, Any]):
    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": session["count"],
        "extractedIntelligence": session["intel"],
        "agentNotes": "Scammer used urgency and credential theft tactics"
    }

    async with httpx.AsyncClient() as client:
        await client.post(
            "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
            json=payload,
            timeout=5
        )

# ================== MAIN ENDPOINT ==================
@app.post("/honeypot/message")
async def honeypot_message(
    request: Request,
    x_api_key: str = Header(None, alias="x-api-key")
):
    if x_api_key != HONEYPOT_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    data = await request.json()
    session_id = data["sessionId"]
    text = data["message"]["text"]

    if session_id not in sessions:
        sessions[session_id] = {
            "history": [],
            "count": 0,
            "intel": {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "suspiciousKeywords": []
            },
            "final_sent": False,
            "start": datetime.utcnow()
        }

    session = sessions[session_id]
    session["count"] += 1
    session["history"].append(text)

    scam_detected = detect_scam(text)
    extract_intel(text, session["intel"])

    reply = await agent_reply(text, session["history"])

    # Final callback after engagement
    if scam_detected and session["count"] >= 5 and not session["final_sent"]:
        await send_final_to_guvi(session_id, session)
        session["final_sent"] = True

    return {
        "status": "success",
        "scamDetected": scam_detected,
        "agentResponse": reply,
        "engagementMetrics": {
            "engagementDurationSeconds": int(
                (datetime.utcnow() - session["start"]).total_seconds()
            ),
            "totalMessagesExchanged": session["count"]
        },
        "extractedIntelligence": session["intel"],
        "agentNotes": "Scammer engagement in progress"
    }

# ================== HEALTH ==================
@app.get("/health")
async def health():
    return {"status": "ok"}
