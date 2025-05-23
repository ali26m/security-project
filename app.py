from fastapi import FastAPI, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import io
import os
import base64

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

def aes_encrypt_image_with_header(data: bytes, mode: str, header_size: int = 54) -> bytes:
    header = data[:header_size]
    body = data[header_size:]
    
    iv = os.urandom(BLOCK_SIZE) if mode != "ECB" else b""
    cipher_cls = getattr(AES, f"MODE_{mode}")
    cipher = AES.new(key, cipher_cls, iv=iv) if iv else AES.new(key, cipher_cls)
    
    ct = cipher.encrypt(pad(body, BLOCK_SIZE))
    encrypted_image = header + (iv + ct if iv else ct)
    
    return encrypted_image

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

# @app.post("/encrypt/")
# async def encrypt_file(mode: str = Form(...), file: UploadFile = File(...)):
#     data = await file.read()
#     mode = mode.upper()
#     ct = aes_encrypt(data, mode)

#     return StreamingResponse(
#         io.BytesIO(ct),
#         media_type="application/octet-stream",
#         headers={
#             "Content-Disposition": "attachment; filename=encrypted_image.bin"
#         }
#     )


@app.post("/encrypt_viewable")
async def encrypt_and_return_viewable_image(
    mode: str = Form(...),
    file: UploadFile = File(...)
):
    data = await file.read()
    mode = mode.upper()

    # BMP or PPM image expected
    header_size = 54  # BMP header size
    encrypted_image = aes_encrypt_image_with_header(data, mode, header_size)

    # For display
    encoded_image = base64.b64encode(encrypted_image).decode("utf-8")

    return {
        "b64_image": encoded_image,
        "download_filename": "viewable_encrypted_image.bmp"  # or .ppm
    }


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
