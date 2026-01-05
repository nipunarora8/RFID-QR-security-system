import uvicorn
from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel
import json
import os
import datetime
import asyncio
from dateutil.parser import isoparse
from typing import Optional, List, Dict
import base64
import time

# --- ENCRYPTION IMPORTS (Unchanged) ---
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# ---

# --- Server Setup ---
app = FastAPI(
    title="Mobile Admin Server",
    description="Handles mobile registration, verification, and serves the admin panel."
)

# --- File Configuration ---
# Admin Server is in src/servers/ -> src -> root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MOBILE_DEVICES_FILE = os.path.join(BASE_DIR, "data", "mobile_devices.json")
LOG_FILE = os.path.join(BASE_DIR, "data", "scan_logs.json")
LOGIN_FILE = os.path.join(BASE_DIR, "data", "login_credentials.json")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

# Use asyncio Locks to prevent errors when writing to files
mobile_data_lock = asyncio.Lock()
log_lock = asyncio.Lock()
login_lock = asyncio.Lock() 


# --- Data Models (Unchanged) ---
class MobileRegistrationRequest(BaseModel):
    device_token: str
    user_name: str
    role: str = "Operator" 

class MobileTokenRequest(BaseModel):
    device_token: str

class LoginRequest(BaseModel):
    username: str
    password: str
    
class UserUidRequest(BaseModel):
    uid: str

class MobileUser(BaseModel):
    device_token: str
    user_name: str
    role: str
    token_expiry: str
    status: str

# --- Login Data Handler (Unchanged) ---
async def load_login_data():
    """Reads login credentials from the JSON file."""
    async with login_lock:
        if not os.path.exists(LOGIN_FILE):
            print(f"--- SECURITY ALERT: {LOGIN_FILE} not found. ---")
            return {}
        try:
            with open(LOGIN_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"--- ERROR loading {LOGIN_FILE}: {e} ---")
            return {}


# --- Mobile Data Handlers (Unchanged) ---
async def load_mobile_data():
    """Loads the mobile device dictionary where keys are usernames."""
    async with mobile_data_lock:
        if not os.path.exists(MOBILE_DEVICES_FILE):
            return {}
        try:
            with open(MOBILE_DEVICES_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"--- ERROR loading {MOBILE_DEVICES_FILE}: {e} ---")
            return {}

async def save_mobile_data(data):
    """Saves the mobile device dictionary."""
    async with mobile_data_lock:
        try:
            with open(MOBILE_DEVICES_FILE, 'w') as f:
                json.dump(data, f, indent=4)
            return True
        except Exception as e:
            print(f"--- ERROR saving {MOBILE_DEVICES_FILE}: {e} ---")
            return False

# --- Authentication Dependency (Unchanged) ---
def authenticate_admin(request: Request):
    """Checks for a valid Authorization header (Basic token)."""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Basic "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing or invalid."
        )
    
    try:
        encoded_token = auth_header.split(" ")[1]
        decoded_bytes = base64.b64decode(encoded_token)
        username, role = decoded_bytes.decode("utf-8").split(":")
        
        if not username or not role:
             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format.")
             
        return {"username": username, "role": role}

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token."
        )

# --- API Endpoints ---

# Login Endpoint (Unchanged)
@app.post("/api/login")
async def login(request: LoginRequest):
    credentials = await load_login_data()
    username = request.username
    password = request.password
    
    if username not in credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password.")
    
    user_details = credentials[username]
    
    if user_details["password"] == password:
        role = user_details["role"] 
        token_payload = f"{username}:{role}"
        token = base64.b64encode(token_payload.encode('utf-8')).decode('utf-8')
        
        return {"status": "success", "token": token, "role": role, "username": username}
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid username or password."
    )


@app.post("/api/mobile/register")
async def register_device(request: MobileRegistrationRequest, auth: dict = Depends(authenticate_admin)):
    """Handles the initial registration of a new device/user. (Unchanged)"""
    mobile_data = await load_mobile_data()
    username = request.user_name
    
    if username in mobile_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail=f"User '{username}' is already registered to a device. One user per device enforced."
        )

    for user, info in mobile_data.items():
        if info.get("device_token") == request.device_token:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Device token already registered under a different user.")

    expiry_date = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    
    mobile_data[username] = {
        "device_token": request.device_token,
        "full_name": request.user_name,
        "role": request.role,
        "token_expiry": expiry_date.isoformat(),
        "status": "Active",
        "registered_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }
    
    await save_mobile_data(mobile_data)
    
    return {"status": "success", "message": "Device registered.", "expires_at": expiry_date.isoformat()}


@app.post("/api/mobile/verify")
async def verify_device_access(request: MobileTokenRequest):
    """Heartbeat endpoint: Checks access by searching for the device_token. (Unchanged)"""
    token = request.device_token
    mobile_data = await load_mobile_data()
    
    user_info = None
    for user_key, info in mobile_data.items():
        if info.get("device_token") == token:
            user_info = info
            break
            
    if not user_info:
        return JSONResponse(
            content={"status": "invalid", "message": "Token not found."}, 
            status_code=401
        )

    current_time = datetime.datetime.now(datetime.timezone.utc)
    token_expiry = isoparse(user_info.get("token_expiry"))
    
    if user_info.get("status") != "Active":
        return {"status": "revoked", "message": f"Access is {user_info.get('status')}"}

    if current_time > token_expiry:
        return {"status": "expired", "message": "Token has expired."}

    return {
        "status": "active", 
        "user_name": user_info.get("full_name"),
        "role": user_info.get("role"),
        "expires_at": user_info.get("token_expiry")
    }

# NEW: Admin Endpoint to get all users (Unchanged)
@app.get("/api/admin/users", response_model=List[MobileUser])
async def get_all_mobile_users(auth: dict = Depends(authenticate_admin)):
    """Returns a list of all registered mobile users (Requires Admin/Tech login)."""
    mobile_data_dict = await load_mobile_data()
    user_list = []
    
    for username, details in mobile_data_dict.items():
        user_list.append(MobileUser(
            device_token=details.get("device_token", "N/A"),
            user_name=username, # Use the key (username) here
            role=details.get("role", "N/A"),
            token_expiry=details.get("token_expiry", "N/A"),
            status=details.get("status", "N/A")
        ))
        
    return user_list

# --- Authorization Helper for Management Endpoints ---
async def check_management_permission(managing_user_role: str, target_user_role: str):
    """Checks if the managing user has permission to modify the target user."""
    # Admins can manage anyone
    if managing_user_role == "Admin":
        return True
        
    # Technicians can only manage Operators or Revoked users
    if managing_user_role == "Technician":
        if target_user_role in ["Technician", "Admin"]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Technicians cannot modify other Technicians or Admins.")
        return True
        
    # Default fail
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized role.")

# NEW: Admin Endpoint to revoke access
@app.post("/api/admin/revoke")
async def revoke_mobile_user(request: UserUidRequest, auth: dict = Depends(authenticate_admin)):
    """Revokes access for a specific user (by username)."""
    username = request.uid
    mobile_data = await load_mobile_data()
    
    if username not in mobile_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
        
    # 1. CRITICAL BACKEND CHECK
    target_role = mobile_data[username].get("role")
    await check_management_permission(auth['role'], target_role)
    
    mobile_data[username]["status"] = "Revoked"
    await save_mobile_data(mobile_data)
    
    return {"status": "success", "message": f"Access revoked for {username}."}

# NEW: Admin Endpoint to grant access
@app.post("/api/admin/grant")
async def grant_mobile_user(request: UserUidRequest, auth: dict = Depends(authenticate_admin)):
    """Grants (reactivates) access for a specific user (by username)."""
    username = request.uid
    mobile_data = await load_mobile_data()
    
    if username not in mobile_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
        
    # 2. CRITICAL BACKEND CHECK
    target_role = mobile_data[username].get("role")
    await check_management_permission(auth['role'], target_role)
        
    mobile_data[username]["status"] = "Active"
    mobile_data[username]["role"] = "Operator" # Ensure role is set back to Operator
    await save_mobile_data(mobile_data)
    
    return {"status": "success", "message": f"Access granted for {username}."}

# NEW ENDPOINT: Delete User
@app.post("/api/admin/delete")
async def delete_mobile_user(request: UserUidRequest, auth: dict = Depends(authenticate_admin)):
    """Deletes a user's mobile registration entry entirely (by username)."""
    username = request.uid
    mobile_data = await load_mobile_data()
    
    if username not in mobile_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
        
    # 3. CRITICAL BACKEND CHECK
    target_role = mobile_data[username].get("role")
    await check_management_permission(auth['role'], target_role)

    del mobile_data[username]
    await save_mobile_data(mobile_data)
    
    return {"status": "success", "message": f"User {username} deleted."}


# --- Frontend Endpoints (Unchanged) ---
@app.get("/")
async def get_login_page():
    return FileResponse(os.path.join(TEMPLATES_DIR, 'admin_login.html'))

@app.get("/register")
async def get_register_page():
    return FileResponse(os.path.join(TEMPLATES_DIR, 'mobile_register.html'))

@app.get("/dashboard")
async def get_admin_dashboard_page():
    return FileResponse(os.path.join(TEMPLATES_DIR, 'admin_dashboard.html'))


# --- Run the Server ---
if __name__ == "__main__":
    print(f"Starting Mobile Admin Server on http://127.0.0.1:8001")
    print(f"*** WARNING: Credentials stored in {LOGIN_FILE} ***")
    uvicorn.run(app, host="127.0.0.1", port=8001)