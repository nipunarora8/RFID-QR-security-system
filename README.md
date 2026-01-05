# RFID & QR Security System

<div align="center">
  <img src="static/logo.png" alt="Project Logo" width="200"/>
  <br>
  <p><b>A secure, two-factor authentication access control system using RFID cards and dynamic QR codes.</b></p>
</div>

---

## 📱 Mobile App & Demo

### 🎥 Demo Video
Watch the system in action:

https://user-images.githubusercontent.com/assets/demo_video.mp4
<!-- Check pointing to local file for now in case github hosting isn't available -->
[**⬇️ Download Demo Video**](demo_video.mp4)

### 🤖 Android App
To use the mobile scanning features, install the companion app:

[**⬇️ Download RFID-QR.apk**](RFID-QR.apk)
<video controls src="demo_video.mp4" title="Title"></video>
---

## 🚀 Features

- **Dual-Factor Authentication**: Combines physical RFID cards with mobile QR code verification.
- **Role-Based Access**: Distinguishes between 'Operators' (standard access) and 'Technicians' (requires OTP).
- **Real-Time Dashboard**: Monitor access logs and active users via a web interface.
- **Admin Panel**: Manage users, register devices, and revoke access remotely.
- **Dynamic OTP**: Technicians generate a time-sensitive One-Time Password for enhanced security.

## 🛠️ Tech Stack

- **Hardware**: Arduino (RC522 RFID Module), Serial Communication.
- **Backend**: Python (FastAPI, Uvicorn).
- **Frontend**: HTML5, CSS3, JavaScript (WebSocket for real-time updates).
- **Mobile**: Android (APK included).
- **Security**: AES-GCM Encryption, TOTP-like logic.

## 📂 Project Structure

```bash
.
├── src/                  # Source code for servers and scripts
│   ├── access_control.py # Main hardware interface script
│   └── servers/          # Backend servers (Admin & Dashboard)
├── templates/            # Web interface HTML files
├── static/               # Assets (Images, Icons)
├── data/                 # JSON databases (Users, Logs, Devices)
├── RFID-QR.apk           # Android Companion App
└── demo_video.mp4        # System Demonstration
```

## ⚙️ Installation & Setup

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/RFID-QR-security-system.git
    cd RFID-QR-security-system
    ```

2.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Hardware Setup**:
    -   Connect the Arduino with RC522 to your computer.
    -   Verify the `SERIAL_PORT` in `src/access_control.py`.

## 🖥️ Usage Guide

### 1. Start the Dashboard (Monitoring)
Runs the main visual interface for security personnel.
```bash
python src/servers/dashboard_server.py
```
📍 **URL**: `http://127.0.0.1:8000`

### 2. Start the Admin Server (Management)
Handles mobile device registration and user management.
```bash
python src/servers/admin_server.py
```
📍 **URL**: `http://127.0.0.1:8001`

### 3. Run the Access Control Host
Bridges the physical RFID reader with the backend servers.
```bash
python src/access_control.py
```

---

*Note: This project was built for a hackathon.*
