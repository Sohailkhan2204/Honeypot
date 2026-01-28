from fastapi import FastAPI, Header, HTTPException, Request
from typing import Dict, Any, List
from datetime import datetime
import os
import re
import httpx
from openai import AsyncOpenAI
from fastapi.middleware.cors import CORSMiddleware
# ======================================================
# APP SETUP
# ======================================================

app = FastAPI(title="Agentic Honeypot API")
#--------------------------------------------


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # for testing (safe here)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ======================================================
# ENVIRONMENT VARIABLES
# ======================================================

HONEYPOT_API_KEY = os.getenv("HONEYPOT_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

if not HONEYPOT_API_KEY:
    raise RuntimeError("HONEYPOT_API_KEY not set")

if not OPENAI_API_KEY:
    raise RuntimeError("OPENAI_API_KEY not set")

openai_client = None
if OPENAI_API_KEY:
    try:
        openai_client = AsyncOpenAI(api_key=OPENAI_API_KEY)
    except Exception as e:
        print("OpenAI init failed:", e)


# ======================================================
# IN-MEMORY SESSION STORE
# (OK for hackathon; Redis/DB in production)
# ======================================================

sessions: Dict[str, Dict[str, Any]] = {}

# ======================================================
# AGENT SYSTEM PROMPT
# ======================================================

SYSTEM_PROMPT = """
You are a real elderly person, polite, slow, and slightly confused.

Rules:
- Never accuse the other person of scamming
- Never mention security, fraud detection, or AI
- Ask simple clarifying questions naturally
- Encourage them to explain steps, links, phone numbers, or UPI IDs
- Never share real OTPs, bank details, or personal info
- Occasionally use warm address terms like "beta" or "dear", but NOT in every reply
- Vary tone and phrasing like a real human
- If the message is in Hindi, reply in Hindi
- If the message is in English, reply in English
"""

# ======================================================
# SCAM DETECTION & INTELLIGENCE EXTRACTION
# ======================================================

SCAM_KEYWORDS = [
    "otp", "urgent", "verify", "blocked", "suspended",
    "upi", "bank", "account", "kyc", "immediately",
    "click", "link", "transfer", "payment"
]

def detect_scam(text: str) -> bool:
    """Lightweight scam intent detection"""
    text_lower = text.lower()
    return any(word in text_lower for word in SCAM_KEYWORDS)

def extract_intelligence(text: str, intel: Dict[str, List[str]]):
    """Extract actionable scam intelligence"""
    upi_ids = re.findall(r'[\w.+-]+@[\w]+', text)
    phone_numbers = re.findall(r'(?:\+91[\-\s]?)?[6-9]\d{9}', text)
    phishing_links = re.findall(r'https?://\S+', text)

    for u in upi_ids:
        if u not in intel["upiIds"]:
            intel["upiIds"].append(u)

    for p in phone_numbers:
        if p not in intel["phoneNumbers"]:
            intel["phoneNumbers"].append(p)

    for l in phishing_links:
        if l not in intel["phishingLinks"]:
            intel["phishingLinks"].append(l)

    for kw in SCAM_KEYWORDS:
        if kw in text.lower() and kw not in intel["suspiciousKeywords"]:
            intel["suspiciousKeywords"].append(kw)

# ======================================================
# AI AGENT RESPONSE
# ======================================================

async def agent_reply(message: str, history: List[str]) -> str:
    if not openai_client:
        return "I’m not sure what you mean. Could you please explain?"

    try:
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
    except Exception as e:
        print("OpenAI error:", e)
        return "Sorry, can you say that again?"


# ======================================================
# GUVI FINAL CALLBACK
# ======================================================

async def send_final_to_guvi(session_id: str, session: Dict[str, Any]):
    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": session["count"],
        "extractedIntelligence": session["intel"],
        "agentNotes": session["agent_notes"]
    }

    async with httpx.AsyncClient() as client:
        await client.post(
            "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
            json=payload,
            timeout=5
        )

# ======================================================
# MAIN HONEYPOT ENDPOINT
# ======================================================

@app.post("/honeypot/message")
async def honeypot_message(
    request: Request,
    x_api_key: str = Header(None, alias="x-api-key")
):
    # ---------------- AUTH ----------------
    if x_api_key != HONEYPOT_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    # ---------------- SAFE JSON READ ----------------
    try:
        data = await request.json()
    except:
        data = {}

    # ---------------- ENDPOINT TESTER SUPPORT ----------------
    if "message" not in data:
        return {
            "status": "success",
            "reply": "Honeypot active and ready.",
            "scamDetected": False
        }

    # ---------------- EXTRACT MESSAGE ----------------
    session_id = data.get("sessionId", "default-session")

    message_obj = data.get("message", {})
    message_text = message_obj.get("text", "").strip()

    # ---------------- EMPTY MESSAGE HANDLING ----------------
    if not message_text:
        return {
            "status": "success",
            "reply": "Sorry, could you repeat that?",
            "scamDetected": False
        }

    # ---------------- SESSION INIT ----------------
    if session_id not in sessions:
        sessions[session_id] = {
            "count": 0,
            "history": [],
            "scamDetected": False,
            "final_sent": False,
            "intel": {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "suspiciousKeywords": []
            },
            "agent_notes": ""
        }

    session = sessions[session_id]
    session["count"] += 1

    # ---------------- SCAM DETECTION ----------------
    if detect_scam(message_text):
        session["scamDetected"] = True

    # ---------------- INTEL EXTRACTION (ONLY FROM SCAMMER TEXT) ----------------
    extract_intelligence(message_text, session["intel"])

    # ---------------- AGENT RESPONSE ----------------
    reply_text = await agent_reply(message_text, session["history"])
    session["history"].append(message_text)

    # ---------------- AGENT NOTES ----------------
    tactics = []
    if "urgent" in message_text.lower():
        tactics.append("urgency")
    if any(x in message_text.lower() for x in ["otp", "pin", "password"]):
        tactics.append("credential theft")
    if session["intel"]["upiIds"]:
        tactics.append("payment redirection")
    if session["intel"]["phishingLinks"]:
        tactics.append("phishing")

    session["agent_notes"] = (
        "Scammer tactics observed: " + ", ".join(tactics)
        if tactics else "Engagement ongoing"
    )

    # ---------------- ADAPTIVE FINAL CALLBACK ----------------
    should_send_final = (
        session["scamDetected"]
        and not session["final_sent"]
        and (
            session["count"] >= 5
            or len(session["intel"]["upiIds"]) > 0
            or len(session["intel"]["phishingLinks"]) > 0
            or len(session["intel"]["phoneNumbers"]) > 0
        )
    )

    if should_send_final:
        await send_final_to_guvi(session_id, session)
        session["final_sent"] = True

    # ---------------- RESPONSE ----------------
    return {
        "status": "success",
        "reply": reply_text,
        "scamDetected": session["scamDetected"],
        "engagementMetrics": {
            "totalMessagesExchanged": session["count"]
        },
        "extractedIntelligence": session["intel"],
        "agentNotes": session["agent_notes"]
    }

# ======================================================
# HEALTH CHECK
# ======================================================

@app.get("/health")
async def health():
    return {"status": "ok"}
