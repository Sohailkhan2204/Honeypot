from fastapi import FastAPI, Header, HTTPException, Request
import os

app = FastAPI()

HONEYPOT_API_KEY = os.getenv("HONEYPOT_API_KEY")

if not HONEYPOT_API_KEY:
    raise RuntimeError("HONEYPOT_API_KEY not set")

@app.post("/honeypot/webhook")
async def honeypot_webhook(
    request: Request,
    x_api_key: str = Header(None, alias="x-api-key")
):
    if x_api_key != HONEYPOT_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    data = await request.json()

    print("Received Honeypot Data:", data)

    return {
        "status": "success",
        "message": "Honeypot data received",
        "received_sections": list(data.keys())
    }
