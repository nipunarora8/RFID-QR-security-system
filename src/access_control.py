import serial
import time
import json
import datetime
import requests
import os # <-- Import OS to check for file existence

# --- (1) CONFIGURE THIS ---
SERIAL_PORT = '/dev/cu.usbserial-120' # Your port
BAUD_RATE = 9600
# Define base dir as the project root (src/access_control.py -> src -> root)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USER_DATABASE_FILE = os.path.join(BASE_DIR, "data", "users.json")
DASHBOARD_SERVER_URL = "http://127.0.0.1:8000/scan" 
# ---

def load_user_data(filename):
    """
    Loads the user database from the specified JSON file.
    Returns a dictionary.
    """
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
            # This will now print on every scan, which is good for debugging
            print(f"Successfully loaded {len(data)} users from {filename}.")
            return data
    except Exception as e:
        print(f"--- ERROR loading {filename}: {e} ---")
        return {}


def get_access_lines(uid_string, database):
    """
    Checks the UID against the loaded database.
    Also checks for "Revoked" status and expiry date.
    """
    # 1. Check if UID exists in our database
    user_info = database.get(uid_string)
    
    if not user_info:
        return ("Access", "Denied", None) 

    # 2. We found the user, now get their info
    name = user_info.get("name", "Unknown")
    role = user_info.get("role", "No Role")
    expiry_str = user_info.get("expiry_date")

    # --- 3. CRITICAL CHECK for "Revoked" ---
    if role == "Revoked":
        print(f"Access DENIED for {name}. User access has been revoked.")
        return (name, "Revoked", user_info)
    # --- END OF CHECK ---

    # 4. Check if the card is expired
    try:
        today = datetime.date.today()
        expiry_date = datetime.datetime.strptime(expiry_str, "%Y-%m-%d").date()
        
        if today > expiry_date:
            print(f"Access DENIED for {name}. Card expired on {expiry_date}.")
            return (name, "Card Expired", user_info) 
            
    except (ValueError, TypeError):
        print(f"Could not check expiry for {name}. Granting access by default.")

    # 5. If we reach here, access is granted!
    print(f"Access GRANTED for {name}, Role: {role}")
    return (name, role, user_info)


# (send_to_dashboard function is unchanged)
def send_to_dashboard(uid, user_info):
    if user_info:
        data_to_send = user_info.copy()
        data_to_send["uid"] = uid 
    else:
        data_to_send = {
            "uid": uid,
            "name": "Unknown",
            "role": "Denied"
        }
    try:
        requests.post(DASHBOARD_SERVER_URL, json=data_to_send, timeout=0.5)
        print(f"Successfully sent UID {uid} to dashboard server.")
    except requests.exceptions.RequestException as e:
        print(f"--- WARNING: Could not send data to dashboard server: {e} ---")


def main():
    print("Starting Python Access Control Host...")
    print(f"Attempting to connect to {SERIAL_PORT} at {BAUD_RATE} baud.")
    
    # --- THIS IS THE KEY CHANGE ---
    # We no longer load the database here.
    # We just check if the file exists one time at the start.
    if not os.path.exists(USER_DATABASE_FILE):
        print(f"CRITICAL ERROR: {USER_DATABASE_FILE} not found. Exiting.")
        return
    # --- END OF CHANGE ---

    try:
        ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)
        print("Serial connection successful. Waiting for 'System Initialized.'...")
        
        while True:
            try:
                arduino_message = ser.readline().decode('utf-8').strip()
                if "System Initialized" in arduino_message:
                    print("Arduino is ready. Listening for card scans...")
                    break
            except UnicodeDecodeError:
                print("Received non-UTF-8 byte, ignoring.")
            time.sleep(0.1)

        # Main loop to listen for UIDs
        while True:
            incoming_data = ""
            try:
                if ser.in_waiting > 0:
                    incoming_data = ser.readline().decode('utf-8').strip()
            except UnicodeDecodeError:
                print(f"Received corrupt data, discarding.")
                continue 
            
            if incoming_data and incoming_data.startswith("UID:"):
                uid = incoming_data[4:] 
                print(f"\nReceived UID: {uid}")
                
                # --- THIS IS THE FIX ---
                # Load the MOST RECENT user data on *every scan*
                user_database = load_user_data(USER_DATABASE_FILE)
                if not user_database:
                    print("--- WARNING: Could not load user database, skipping scan. ---")
                    # Send a default "Denied" to Arduino just in case
                    ser.write(b"Access\n")
                    ser.flush()
                    time.sleep(0.05)
                    ser.write(b"Denied\n")
                    ser.flush()
                    continue # Skip this scan, wait for next
                # --- END OF FIX ---

                # Get all 3 pieces of data (now using fresh data)
                line1, line2, user_info_for_dashboard = get_access_lines(uid, user_database)
                
                print(f"  Response L1: {line1}")
                print(f"  Response L2: {line2}")
                
                # Send the responses back to the Arduino
                response_line_1 = f"{line1}\n"
                response_line_2 = f"{line2}\n"
                ser.write(response_line_1.encode('utf-8'))
                ser.flush() 
                time.sleep(0.05) 
                ser.write(response_line_2.encode('utf-8'))
                ser.flush() 
                
                # Send the full data to the dashboard server
                send_to_dashboard(uid, user_info_for_dashboard)

    except serial.SerialException as e:
        print(f"\n--- ERROR ---")
        print(f"Could not open serial port '{SERIAL_PORT}'.")
        print(f"Details: {e}")
    except KeyboardInterrupt:
        print("\nExiting program. Closing serial port.")
    finally:
        if 'ser' in locals() and ser.is_open:
            ser.close()
            print("Serial port closed.")

if __name__ == "__main__":
    main()