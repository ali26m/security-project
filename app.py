from fastapi import FastAPI, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import io
import os

app = FastAPI()

BLOCK_SIZE = 16
key = "mysecretkey12345".encode("utf-8")  # 16-byte AES key

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Or ["http://127.0.0.1:5500"] for stricter control
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def aes_encrypt(data: bytes, mode: str) -> bytes:
    iv = os.urandom(BLOCK_SIZE) if mode != "ECB" else b""
    cipher_cls = getattr(AES, f"MODE_{mode}")
    cipher = AES.new(key, cipher_cls, iv=iv) if iv else AES.new(key, cipher_cls)
    ct = cipher.encrypt(pad(data, BLOCK_SIZE))
    return iv + ct if iv else ct

def aes_decrypt(payload: bytes, mode: str) -> bytes:
    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        return unpad(cipher.decrypt(payload), BLOCK_SIZE)
    iv, ct = payload[:BLOCK_SIZE], payload[BLOCK_SIZE:]
    cipher = AES.new(key, getattr(AES, f"MODE_{mode}"), iv=iv)
    return unpad(cipher.decrypt(ct), BLOCK_SIZE)

@app.get("/")
async def root():
    return {"message": "200 OK"}

@app.post("/encrypt/")
async def encrypt_file(mode: str = Form(...), file: UploadFile = File(...)):
    data = await file.read()
    mode = mode.upper()
    ct = aes_encrypt(data, mode)

    return StreamingResponse(
        io.BytesIO(ct),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": "attachment; filename=encrypted_image.bin"
        }
    )

@app.post("/decrypt/")
async def decrypt_file(mode: str = Form(...), file: UploadFile = File(...)):
    data = await file.read()
    mode = mode.upper()
    pt = aes_decrypt(data, mode)

    return StreamingResponse(
        io.BytesIO(pt),
        media_type="image/png",  # or image/jpeg if input was jpg
        headers={
            "Content-Disposition": "attachment; filename=decrypted_image.png"
        }
    )
