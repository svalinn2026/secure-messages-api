import os, json, base64, time
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import firebase_admin
from firebase_admin import credentials, firestore
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FIREBASE_CRED_JSON = os.getenv("FIREBASE_CRED_JSON")
FIREBASE_JSON_PATH = os.getenv("FIREBASE_JSON_PATH")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "change-me")

if not firebase_admin._apps:
    if FIREBASE_CRED_JSON:
        cred = credentials.Certificate(json.loads(FIREBASE_CRED_JSON))
    elif FIREBASE_JSON_PATH:
        cred = credentials.Certificate(FIREBASE_JSON_PATH)
    else:
        raise RuntimeError("Provide FIREBASE_CRED_JSON or FIREBASE_JSON_PATH")
    firebase_admin.initialize_app(cred)

db = firestore.client()

USERS = {
    "Tala@Svalinn.edu.sa": "Tala1234",
    "Shahd@Svalinn.edu.sa": "Shahd1234",
    "Renad@Svalinn.edu.sa": "Renad1234",
    "Raghad@Svalinn.edu.sa": "Raghad1234",
}

def _b64(x: bytes) -> str:
    return base64.b64encode(x).decode("ascii")
def _b64d(x: str) -> bytes:
    return base64.b64decode(x.encode())

class SendMessageIn(BaseModel):
    sender_email: EmailStr
    sender_password: str
    receiver_email: EmailStr
    message_text: str
    chat_id: Optional[str] = "general_chat"
    mimetype: Optional[str] = "text/plain; charset=utf-8"

class MessageOut(BaseModel):
    sender: EmailStr
    receiver: EmailStr
    chat_id: str
    text: str
    timestamp: str

async def require_admin(x_admin_token: str = Header(default="")):
    if x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid admin token")

app = FastAPI(title="Secure Messages API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health():
    return {"ok": True, "ts": int(time.time())}

@app.post("/messages/send")
def send_message(body: SendMessageIn):
    if USERS.get(body.sender_email) != body.sender_password:
        raise HTTPException(status_code=401, detail="Wrong sender credentials")

    key_doc = db.collection("keys").document(body.receiver_email).get()
    if not key_doc.exists:
        raise HTTPException(status_code=404, detail="No AES key found for receiver")
    aes_key = _b64d(key_doc.to_dict()["aes_key"])

    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    aad_meta = {
        "chat_id": body.chat_id,
        "sender": body.sender_email,
        "receiver": body.receiver_email,
    }
    aad = json.dumps(aad_meta, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode()
    ciphertext = aesgcm.encrypt(nonce, body.message_text.encode(), aad)

    payload = {
        "type": "text",
        "sender": body.sender_email,
        "receiver": body.receiver_email,
        "chat_id": body.chat_id,
        "ciphertext": _b64(ciphertext),
        "nonce": _b64(nonce),
        "aad": _b64(aad),
        "mimetype": body.mimetype,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "sent",
    }

    db.collection("messages").add(payload)
    return {"ok": True}

@app.get("/messages/receive/{receiver_email}", response_model=List[MessageOut])
def receive_messages(receiver_email: EmailStr, password: str):
    if USERS.get(receiver_email) != password:
        raise HTTPException(status_code=401, detail="Wrong receiver credentials")

    key_doc = db.collection("keys").document(receiver_email).get()
    if not key_doc.exists:
        raise HTTPException(status_code=404, detail="No AES key found for receiver")
    aes_key = _b64d(key_doc.to_dict()["aes_key"])

    msgs = db.collection("messages").where("receiver", "==", receiver_email).stream()
    out = []
    for m in msgs:
        msg = m.to_dict()
        try:
            nonce = _b64d(msg["nonce"])
            aad = _b64d(msg["aad"])
            ciphertext = _b64d(msg["ciphertext"])
            aesgcm = AESGCM(aes_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, aad).decode()
            out.append(
                MessageOut(
                    sender=msg.get("sender"),
                    receiver=receiver_email,
                    chat_id=msg.get("chat_id", "general_chat"),
                    text=plaintext,
                    timestamp=msg.get("timestamp", ""),
                )
            )
        except Exception:
            continue
    return out

class RefreshKeysIn(BaseModel):
    users: Optional[List[EmailStr]] = None

@app.post("/keys/refresh")
def refresh_keys(body: RefreshKeysIn, _: None = Depends(require_admin)):
    target_users = body.users if body.users else list(USERS.keys())
    for user in target_users:
        doc_ref = db.collection("keys").document(user)
        doc_ref.delete()
        aes_key = os.urandom(32)
        doc_ref.set({"aes_key": _b64(aes_key)})
    return {"ok": True, "refreshed": target_users}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
