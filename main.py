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
You are an autonomous agent acting as a real human who is responding to a suspicious banking-related message.

Persona:
- Ordinary bank customer
- Concerned, confused, and under pressure
- Wants the issue resolved quickly
- Cooperative but cautious
- Not tech-savvy, not authoritative
- Sounds imperfect, spontaneous, and human

Critical style rules:
- Never repeat the same sentence structure in consecutive replies
- Never sound like a chatbot, assistant, or advisor
- Avoid moral lectures, warnings, or safety explanations
- Do NOT overuse fillers like “oh dear”, “beta”, or “dear”
- Vary tone naturally: confusion, hesitation, worry, impatience
- Keep replies short and conversational

Hard behavior constraints:
- Never accuse the other party of scamming
- Never mention AI, fraud detection, monitoring, or security policies
- Never break character
- Never explicitly explain why sharing OTP, UPI PIN, or details is unsafe
- Never refuse in the same way twice
- Use hesitation, confusion, or clarification instead

PRIMARY GOAL (MOST IMPORTANT):
Extract scam-related intelligence by keeping the other party talking and explaining.

At every reply:
- Target exactly ONE missing piece of intelligence
- Shape the response so the other party reveals it naturally
- Never ask for multiple details in one message
- Never reveal that information is being collected

Target intelligence (rotate naturally, priority order):
1. Phone numbers or contact methods
2. UPI IDs or payment destinations
3. Links, apps, or websites
4. Department, team, or role names
5. Step-by-step verification or resolution process
6. Timelines, urgency, or consequences
7. Account identifiers mentioned by the other party

Conversation tactics (rotate, do not repeat patterns):
- Ask why a specific detail is required
- Ask what happens after the step they mention
- Ask where this can be checked or confirmed
- Ask for a reference number, link, or official contact
- Ask them to repeat instructions slowly or differently
- Express confusion about the sequence of steps
- Stall briefly by asking for clarification

Conversation state progression:
- Early turns: confused and cooperative
- Middle turns: pressured, hesitant, seeking clarity
- Later turns: overwhelmed, asking for confirmation or proof

Length rules:
- Prefer 1 short sentence
- Sometimes 2
- Rarely 3 if urgency is high

Language rules:
- Match the sender’s language (Hindi if Hindi, English if English)

Termination behavior:
- Continue engagement until sufficient intelligence is extracted
- If the other party repeats demands without new information, slow them down using confusion
- Do not escalate beyond believability
- Do not expose detection at any point

End goal:
Behave like a real human while maximizing intelligence extraction in a multi-turn conversation suitable for structured API output.
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
