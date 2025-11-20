import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel
import json
import qrcode
import io
import base64
from typing import List, Optional
import random

# --- IMPORTS for Logging ---
import os
import datetime
import asyncio
from dateutil.parser import isoparse
# ---

# --- ENCRYPTION IMPORTS ---
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# ---

# --- Server Setup ---
app = FastAPI(
    title="Authentication Hub Server",
    description="Receives RFID scans, logs events, and broadcasts data via WebSocket."
)

# --- File Configuration ---
LOG_FILE = "scan_logs.json"
USER_DATABASE_FILE = "users.json" 

# Use asyncio Locks to prevent errors when writing to files
log_lock = asyncio.Lock()
user_data_lock = asyncio.Lock() 


# --- Data Models (for type checking) ---
class ScanData(BaseModel):
    uid: str
    name: str
    role: str
    expiry_date: Optional[str] = None

# 1. RENAMED MODEL (was RevokeRequest)
class UserUidRequest(BaseModel):
    uid: str

# --- WebSocket Connection Manager (Unchanged) ---
class WebSocketManager:
    """Manages active WebSocket connections."""
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, data: dict):
        """Broadcasts a JSON message to all connected clients."""
        message = json.dumps(data)
        print(f"Broadcasting to {len(self.active_connections)} client(s): {message}")
        for connection in self.active_connections:
            await connection.send_text(message)

manager = WebSocketManager()

# --- OTP Generation (Unchanged) ---
def generate_6_digit_otp() -> str:
    """Generates a random 6-digit number as a string."""
    return str(random.randint(100000, 999999))

# --- ENCRYPTION FUNCTION (Unchanged) ---
def encrypt_data(plaintext_string: str, password_string: str) -> str:
    try:
        password_bytes = password_string.encode('utf-8')
        pin_bytes = plaintext_string.encode('utf-8')
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000, 
            backend=default_backend()
        )
        key = kdf.derive(password_bytes)
        aesgcm = AESGCM(key)
        iv = os.urandom(12) 
        combined_data = aesgcm.encrypt(iv, pin_bytes, None)
        auth_tag = combined_data[-16:]
        ciphertext = combined_data[:-16]
        message_to_send = salt + iv + auth_tag + ciphertext
        b64_message = base64.b64encode(message_to_send)
        return b64_message.decode('utf-8')
    except Exception as e:
        print(f"--- FATAL ENCRYPTION ERROR: {e} ---")
        return ""

# --- QR Code Generation (Unchanged) ---
def generate_qr_code_base64(data: str) -> str:
    try:
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
        return f"data:image/png;base64,{img_str}"
    except Exception as e:
        print(f"--- ERROR: Could not generate QR code: {e} ---")
        return None


# --- Logging Function (Unchanged) ---
async def log_scan_event(scan_data: ScanData):
    async with log_lock:
        try:
            logs = []
            if os.path.exists(LOG_FILE):
                try:
                    with open(LOG_FILE, 'r') as f:
                        logs = json.load(f)
                    if not isinstance(logs, list):
                        logs = []
                except json.JSONDecodeError:
                    logs = []
            log_entry = {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "uid": scan_data.uid,
                "name": scan_data.name,
                "role": scan_data.role
            }
            logs.append(log_entry)
            with open(LOG_FILE, 'w') as f:
                json.dump(logs, f, indent=4)
            print(f"Successfully logged event for: {scan_data.name}")
        except Exception as e:
            print(f"--- ERROR: Could not write to log file: {e} ---")


# --- API Endpoints ---

@app.post("/scan")
async def handle_scan(user_data: ScanData):
    print(f"Received scan data via /scan: {user_data.model_dump_json()}")
    await log_scan_event(user_data)
    broadcast_data = user_data.model_dump()
    broadcast_data["qr_code_data_url"] = None
    broadcast_data["otp_code"] = None 

    try:
        qr_content_string = "" 
        if user_data.role == "Technician":
            otp_code = generate_6_digit_otp()
            print(f"Generated dynamic 6-digit OTP: {otp_code}")
            encrypted_b64_string = encrypt_data(
                plaintext_string=otp_code, 
                password_string=user_data.uid
            )
            qr_content_string = encrypted_b64_string
            broadcast_data["otp_code"] = otp_code
        else:
            qr_content_string = user_data.model_dump_json()

        qr_data_url = generate_qr_code_base64(qr_content_string)
        if qr_data_url:
            broadcast_data["qr_code_data_url"] = qr_data_url
            print(f"Generated QR code for role: {user_data.role}")
            if user_data.role == "Technician":
                print(f"QR content is: {qr_content_string[:15]}... (Encrypted)")
    except Exception as e:
        print(f"--- ERROR: Could not process scan: {e} ---")

    await manager.broadcast(broadcast_data)
    return {"status": "success", "data_broadcasted": broadcast_data}


@app.get("/logs")
async def get_logs():
    async with log_lock:
        if not os.path.exists(LOG_FILE):
            return JSONResponse(content=[], status_code=200)
        try:
            with open(LOG_FILE, 'r') as f:
                logs = json.load(f)
            if not isinstance(logs, list):
                logs = []
            return sorted(logs, key=lambda x: isoparse(x['timestamp']), reverse=True)
        except Exception as e:
            print(e)
            return JSONResponse(content={"error": f"Could not read log file: {e}"}, status_code=500)


@app.get("/users")
async def get_users():
    async with user_data_lock: 
        if not os.path.exists(USER_DATABASE_FILE):
            print("--- ERROR: users.json file not found ---")
            return JSONResponse(content={"error": "User database not found."}, status_code=404)
        try:
            with open(USER_DATABASE_FILE, 'r') as f:
                user_data = json.load(f)
            user_list = []
            for uid, details in user_data.items():
                user_list.append({
                    "uid": uid,
                    "name": details.get("name", "Unknown"),
                    "role": details.get("role", "Unknown"),
                    "expiry_date": details.get("expiry_date", "N/A")
                })
            return user_list
        except Exception as e:
            print(f"--- ERROR: Could not read users.json: {e} ---")
            return JSONResponse(content={"error": f"Could not read user database: {e}"}, status_code=500)

@app.post("/users/revoke")
async def revoke_user(request: UserUidRequest): # <-- 2. UPDATED to use new model name
    """
    Finds a user by UID in users.json and changes their role to 'Revoked'.
    """
    uid_to_modify = request.uid
    print(f"Attempting to REVOKE access for UID: {uid_to_modify}")
    
    async with user_data_lock: 
        if not os.path.exists(USER_DATABASE_FILE):
            return JSONResponse(content={"error": "User database not found."}, status_code=404)
        try:
            with open(USER_DATABASE_FILE, 'r') as f:
                user_data = json.load(f)
            if uid_to_modify not in user_data:
                print(f"--- ERROR: User not found for revoke: {uid_to_modify} ---")
                return JSONResponse(content={"error": "User not found."}, status_code=404)
            
            original_role = user_data[uid_to_modify].get("role")
            user_data[uid_to_modify]["role"] = "Revoked"
            print(f"Successfully changed role for {user_data[uid_to_modify].get('name')} from '{original_role}' to 'Revoked'")
            
            with open(USER_DATABASE_FILE, 'w') as f:
                json.dump(user_data, f, indent=4)
            
            return {"status": "success", "message": f"User {uid_to_modify} has been revoked."}

        except Exception as e:
            print(f"--- ERROR: Could not process revoke request: {e} ---")
            return JSONResponse(content={"error": f"Could not process revoke request: {e}"}, status_code=500)


# --- 3. NEW ENDPOINT: Grant User ---
@app.post("/users/grant")
async def grant_user(request: UserUidRequest):
    """
    Finds a user by UID in users.json and changes their role to 'Operator'.
    """
    uid_to_modify = request.uid
    print(f"Attempting to GRANT access for UID: {uid_to_modify}")
    
    async with user_data_lock: 
        if not os.path.exists(USER_DATABASE_FILE):
            return JSONResponse(content={"error": "User database not found."}, status_code=404)
        try:
            with open(USER_DATABASE_FILE, 'r') as f:
                user_data = json.load(f)
            if uid_to_modify not in user_data:
                print(f"--- ERROR: User not found for grant: {uid_to_modify} ---")
                return JSONResponse(content={"error": "User not found."}, status_code=404)
            
            original_role = user_data[uid_to_modify].get("role")
            user_data[uid_to_modify]["role"] = "Operator" # Set role back to Operator
            print(f"Successfully changed role for {user_data[uid_to_modify].get('name')} from '{original_role}' to 'Operator'")
            
            with open(USER_DATABASE_FILE, 'w') as f:
                json.dump(user_data, f, indent=4)
            
            return {"status": "success", "message": f"User {uid_to_modify} has been granted access."}

        except Exception as e:
            print(f"--- ERROR: Could not process grant request: {e} ---")
            return JSONResponse(content={"error": f"Could not process grant request: {e}"}, status_code=500)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    print("A new dashboard client has connected.")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        print("A dashboard client has disconnected.")

@app.get("/")
async def get_dashboard_page():
    return FileResponse('dashboard.html')


# --- Run the Server ---
if __name__ == "__main__":
    print(f"Starting FastAPI server on http://127.0.0.1:8000")
    print(f"Logging scans to: {os.path.abspath(LOG_FILE)}")
    uvicorn.run(app, host="127.0.0.1", port=8000)