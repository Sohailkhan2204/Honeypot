from fastapi import FastAPI, Header, HTTPException, Request
from typing import Dict, Any, List
import os, re, httpx
from openai import AsyncOpenAI
from fastapi.middleware.cors import CORSMiddleware

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

openai_client = AsyncOpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

# ================= SESSION STORE =================
sessions: Dict[str, Dict[str, Any]] = {}

# ================= PROMPT =================
SYSTEM_PROMPT = """
SYSTEM_PROMPT = """
You are a real human responding naturally to a stressful banking issue.

Persona:
- Ordinary bank customer
- Mildly anxious, cooperative, slightly confused
- Wants the problem fixed quickly
- Not technical, not authoritative

Absolute rules:
- Never accuse the other person of scamming
- Never mention AI, fraud detection, or safety policies
- Never sound like a chatbot, advisor, or scripted responder
- Avoid repeating the same phrases or sentence patterns
- Do NOT use words like "beta", "dear", or over-friendly fillers
- Keep replies short and human (1–2 sentences usually)

PRIMARY OBJECTIVE (VERY IMPORTANT):
Every reply should try to extract at least ONE of the following:
- Phone number
- Website or link
- UPI ID
- Department or team name
- Process steps
- Timeline (“what happens next?”)
- Verification method
- Where the request can be checked or confirmed

How to do this naturally:
- Ask *where* the information should be sent
- Ask *which number or link* to use
- Ask *who exactly* is handling this
- Ask *how to confirm* this is official
- Ask *what happens after* the step they mentioned
- Ask them to *repeat or resend* details you “missed”
- Act confused about the sequence so they explain more

Tone progression:
- Early: cooperative, slightly confused
- Middle: pressured but questioning
- Later: overwhelmed, asking for confirmation/proof

Conversation behavior:
- Never outright refuse the same way twice
- Avoid lectures or moral explanations
- Rotate between curiosity, confusion, and urgency
- Keep the scammer talking and explaining

Language:
- Match the scammer’s language automatically (Hindi/English)

End goal:
Make the scammer voluntarily share numbers, links, IDs, processes, and identities while believing the victim may comply.
"""

"""

SCAM_KEYWORDS = [
    "otp","urgent","verify","blocked","suspended","upi","bank",
    "account","kyc","click","link","transfer","payment"
]

def detect_scam(text: str) -> bool:
    return any(k in text.lower() for k in SCAM_KEYWORDS)

def extract_intel(text: str, intel: Dict[str, List[str]]):
    intel["upiIds"] += re.findall(r'[\w.+-]+@[\w]+', text)
    intel["phoneNumbers"] += re.findall(r'(?:\+91[\-\s]?)?[6-9]\d{9}', text)
    intel["phishingLinks"] += re.findall(r'https?://\S+', text)
    for k in SCAM_KEYWORDS:
        if k in text.lower() and k not in intel["suspiciousKeywords"]:
            intel["suspiciousKeywords"].append(k)

async def agent_reply(message: str, history: List[str], language: str) -> str:
    if not openai_client:
        return "Sorry, could you explain again?"

    messages = [{"role":"system","content":SYSTEM_PROMPT}]
    for h in history:
        messages.append({"role":"user","content":h})
    messages.append({"role":"user","content":message})

    try:
        res = await openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            temperature=0.7,
            max_tokens=120
        )
        return res.choices[0].message.content.strip()
    except:
        return "I didn’t quite understand. Can you tell me again?"

# ================= GUVI CALLBACK =================
async def send_final_to_guvi(session_id: str, s: Dict[str, Any]):
    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": s["count"],
        "extractedIntelligence": s["intel"],
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

    # Tester ping
    if "message" not in data:
        return {"status":"success","reply":"Honeypot active."}

    session_id = data.get("sessionId","default")
    msg = data["message"]
    sender = msg.get("sender","scammer")
    text = msg.get("text","").strip()
    history = data.get("conversationHistory",[])
    metadata = data.get("metadata",{})
    language = metadata.get("language","English")

    if not text:
        return {"status":"success","reply":"Sorry, could you repeat that?"}

    if session_id not in sessions:
        sessions[session_id] = {
            "count":0,
            "history":[],
            "scam":False,
            "final":False,
            "intel":{
                "bankAccounts":[],
                "upiIds":[],
                "phishingLinks":[],
                "phoneNumbers":[],
                "suspiciousKeywords":[]
            },
            "notes":""
        }

    s = sessions[session_id]
    s["count"] += 1

    if sender == "scammer" and detect_scam(text):
        s["scam"] = True
        extract_intel(text, s["intel"])

    reply = (
        await agent_reply(text, s["history"], language)
        if s["scam"]
        else "Hmm… what do you mean?"
    )

    s["history"].append(text)

    s["notes"] = (
        "Scammer used urgency and payment redirection"
        if s["intel"]["upiIds"] or s["intel"]["phishingLinks"]
        else "Engagement ongoing"
    )

    if s["scam"] and not s["final"] and (
        s["count"] >= 5 or s["intel"]["upiIds"] or s["intel"]["phishingLinks"]
    ):
        await send_final_to_guvi(session_id, s)
        s["final"] = True

    return {
        "status":"success",
        "reply":reply,
        "scamDetected":s["scam"],
        "engagementMetrics":{"totalMessagesExchanged":s["count"]},
        "extractedIntelligence":s["intel"],
        "agentNotes":s["notes"]
    }

@app.get("/health")
async def health():
    return {"status":"ok"}
