# webhook_listener.py
from fastapi import FastAPI, Request
import uvicorn

app = FastAPI()

@app.post("/webhook")
async def paystack_webhook(request: Request):
    payload = await request.json()
    print("Webhook received:", payload)

    # You could also write this to a file or database
    return {"status": True}

