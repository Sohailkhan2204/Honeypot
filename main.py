from fastapi import FastAPI, Header, HTTPException, Request

app = FastAPI()

HONEYPOT_API_KEY = "hp_super_secret_key_123"

@app.post("/honeypot/webhook")
async def honeypot_webhook(
    request: Request,
    x_api_key: str = Header(None)
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
