# main.py
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import FileResponse
from typing import List
import os, json, io
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload
from google.oauth2 import service_account
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3050", "http://localhost"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === CONFIG ===
KEYS_FILE = 'data/keys.json'
CERTS_DIR = 'certs'
SCOPES = ['https://www.googleapis.com/auth/drive']
SERVICE_ACCOUNT_FILE = 'credentials.json'

# === UTILS ===
def load_keys():  # utility for loading the key files
    if not os.path.exists(KEYS_FILE):
        os.makedirs(os.path.dirname(KEYS_FILE), exist_ok=True)
        with open(KEYS_FILE, 'w') as f:
            json.dump({}, f)
    try:
        with open(KEYS_FILE, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}

def save_keys(keys):  # for updating the key files
    with open(KEYS_FILE, 'w') as f:
        json.dump(keys, f, indent=2)

def generate_aes_key():  # generates the AES key
    return os.urandom(32)

def encrypt_aes(data: bytes, key: bytes):  # uses AES encryption to encrypt the file
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()

def decrypt_aes(data: bytes, key: bytes):  # uses AES decryption to decrypt the file
    iv = data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data[16:]) + decryptor.finalize()

def encrypt_key_for_user(aes_key: bytes, public_key): # encrypt the AES key for the user
    return public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def get_drive_service(): # used to access the Google Drive
    creds = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE, scopes=SCOPES)
    return build('drive', 'v3', credentials=creds)

def upload_to_drive(file_bytes: bytes, filename: str, encrypted_aes_key: str): # used to upload the encrypted file to Google Drive
    service = get_drive_service()
    # Delete any existing file with same name
    results = service.files().list(q=f"name='{filename}'", fields="files(id, name)").execute()
    for file in results.get("files", []):
        service.files().delete(fileId=file["id"]).execute()

    file_metadata = {'name': filename, 'description': encrypted_aes_key}
    media = MediaIoBaseUpload(io.BytesIO(file_bytes), mimetype='application/octet-stream')
    file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
    return file.get('id')

def download_from_drive(file_id: str): # used to download a file from Google Drive
    service = get_drive_service()
    request = service.files().get_media(fileId=file_id)
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, request)
    done = False
    while not done:
        _, done = downloader.next_chunk()
    return fh.getvalue()

def get_file_id_and_aes_key_by_name(filename: str):
    service = get_drive_service()
    results = service.files().list(q=f"name='{filename}'", fields="files(id, name, description)").execute()
    files = results.get("files", [])
    if not files:
        raise HTTPException(status_code=404, detail="File not found")
    file = files[0]
    return file['id'], file.get('description', '')

def encrypt_aes_key_for_users(aes_key: bytes, public_keys: dict) -> dict:
    encrypted_keys = {}
    for username, public_key in public_keys.items():
        encrypted_keys[username] = encrypt_key_for_user(aes_key, public_key).hex()
    return encrypted_keys


# === ROUTES ===

@app.post("/register_user") # used to create a user account
def register_user(username: str = Form(...)):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    os.makedirs(CERTS_DIR, exist_ok=True)
    with open(f"{CERTS_DIR}/{username}_cert.pem", 'wb') as f:
        f.write(public_pem)

    keys = load_keys()
    aes_key = generate_aes_key()
    encrypted_key = encrypt_key_for_user(aes_key, public_key)
    keys[username] = encrypted_key.hex()
    save_keys(keys)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    return {
        "message": f"User {username} registered",
        "public_key": public_pem.decode(),
        "private_key": private_pem.decode()
    }

@app.post("/upload") # used to upload and encrypt a file
async def upload_file(file: UploadFile = File(...), username: str = Form(...), filename: str = Form(...)):
    keys = load_keys()
    if username not in keys:
        raise HTTPException(status_code=403, detail="User not authorized")

    public_keys = {}
    for user in keys:
        with open(f"{CERTS_DIR}/{user}_cert.pem", 'rb') as f:
            public_keys[user] = serialization.load_pem_public_key(f.read())

    content = await file.read()

    # Encrypt the file content using AES
    aes_key = generate_aes_key()  # Generate a new AES key for this file
    encrypted_content = encrypt_aes(content, aes_key)

    # Encrypt the AES key for all authorized users
    encrypted_aes_keys = encrypt_aes_key_for_users(aes_key, public_keys)

    # Upload the encrypted content to Google Drive
    file_id = upload_to_drive(encrypted_content, filename, json.dumps(encrypted_aes_keys))

    return {"message": "Upload successful"}


@app.post("/download") # used to download the file
async def download_file(
        username: str = Form(...),
        filename: str = Form(...),
        private_key_file: UploadFile = File(...)
):
    keys = load_keys()
    if username not in keys:
        raise HTTPException(status_code=403, detail="User not authorized")

    private_key_data = await private_key_file.read()
    private_key = serialization.load_pem_private_key(private_key_data, password=None)

    # Get the file ID and encrypted AES keys from Google Drive
    file_id, encrypted_aes_keys_json = get_file_id_and_aes_key_by_name(filename)
    encrypted_aes_keys = json.loads(encrypted_aes_keys_json)

    if username not in encrypted_aes_keys:
        raise HTTPException(status_code=403, detail="User not authorized to decrypt this file")

    encrypted_aes_key_hex = encrypted_aes_keys[username]
    encrypted_aes_key = bytes.fromhex(encrypted_aes_key_hex)

    try:
        # Decrypt the AES key
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
    except ValueError as e:
        logger.error(f"Decryption failed: {e}")
        raise HTTPException(status_code=500, detail="Decryption failed")

    # Download the file from Google Drive
    encrypted_data = download_from_drive(file_id)

    # Decrypt the file content using AES
    decrypted_data = decrypt_aes(encrypted_data, aes_key)

    temp_path = f"temp_{filename}"
    with open(temp_path, 'wb') as f:
        f.write(decrypted_data)
    return FileResponse(temp_path, filename=f"decrypted_{filename}")


@app.post("/delete_user") # revokes a user's key
def delete_user(username: str = Form(...)):
    keys = load_keys()
    if username not in keys:
        raise HTTPException(status_code=404, detail="User not found")
    cert_path = os.path.join(CERTS_DIR, f"{username}_cert.pem")
    if os.path.exists(cert_path):
        os.remove(cert_path)
    del keys[username]
    save_keys(keys)
    return {"message": f"User '{username}' deleted successfully"}

# == LAUNCH
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=7500, reload=True)
