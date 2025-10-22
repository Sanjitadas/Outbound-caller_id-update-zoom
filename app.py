# app.py
# app.py
import os
import time
import base64
import requests
from flask import Flask, request, jsonify, render_template
from threading import Lock
from openpyxl import load_workbook
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "supersecretkey")

# ---------------- Configuration ----------------
ZOOM_BASE_URL = "https://api.zoom.us/v2"
CLIENT_ID = os.getenv("ZOOM_CLIENT_ID")
CLIENT_SECRET = os.getenv("ZOOM_CLIENT_SECRET")
ACCOUNT_ID = os.getenv("ZOOM_ACCOUNT_ID")

# ---------------- Token cache ----------------
token_cache = {"access_token": None, "expiry": 0}
token_lock = Lock()

# ---------------- Live report cache ----------------
report_cache = {"updates": []}  # stores dicts of each update: {email, success: True/False}

# ---------------- Helper Functions ----------------
def generate_access_token():
    """Step 1: Generate Zoom OAuth token using account-level credentials"""
    with token_lock:
        if token_cache["access_token"] and time.time() < token_cache["expiry"]:
            return token_cache["access_token"]

        auth_header = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
        url = f"https://zoom.us/oauth/token?grant_type=account_credentials&account_id={ACCOUNT_ID}"
        headers = {"Authorization": f"Basic {auth_header}"}
        response = requests.post(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        token_cache["access_token"] = data["access_token"]
        token_cache["expiry"] = time.time() + data["expires_in"] - 60  # refresh 1 min early
        return token_cache["access_token"]

def get_zoom_headers():
    token = generate_access_token()
    return {"Authorization": f"Bearer {token}", "Accept": "application/json"}

def zoom_get_users():
    """Step 2: Fetch Zoom Phone users"""
    headers = get_zoom_headers()
    url = f"{ZOOM_BASE_URL}/phone/users?page_size=100"
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    return resp.json().get("users", [])

def get_user_extension_id(email):
    users = zoom_get_users()
    for u in users:
        if u.get("email", "").lower() == email.lower():
            return u.get("extension_id")
    return None

def get_line_keys(extension_id):
    """Step 3: Fetch line keys"""
    headers = get_zoom_headers()
    url = f"{ZOOM_BASE_URL}/phone/extension/{extension_id}/line_keys"
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        return []
    return resp.json().get("line_keys", [])

def patch_line_key(extension_id, line_key_id, new_caller_id):
    """Step 4: Update outbound caller ID"""
    headers = get_zoom_headers()
    url = f"{ZOOM_BASE_URL}/phone/extension/{extension_id}/line_keys"
    payload = {
        "line_keys": [
            {
                "line_key_id": line_key_id,
                "index": 1,  # or pass real index if needed
                "outbound_caller_id": new_caller_id
            }
        ]
    }
    resp = requests.patch(url, headers=headers, json=payload)
    if resp.status_code in (200, 204):
        return {"success": True, "line_key_id": line_key_id}
    else:
        return {"success": False, "line_key_id": line_key_id, "error": resp.text}

def log_update(email, success):
    """Store update result for live reporting"""
    report_cache["updates"].append({"email": email, "success": success})
# ---------------- Routes ----------------
@app.route("/")
def index():
    return render_template("index.html")  # your UI template

@app.route("/single_update", methods=["POST"])
def single_update():
    """
    Form fields:
    - email
    - caller_id
    """
    email = request.form.get("email", "").strip()
    caller_id = request.form.get("caller_id", "").strip()
    if not email or not caller_id:
        return jsonify({"status": "error", "message": "Email and Caller ID required"}), 400

    ext_id = get_user_extension_id(email)
    if not ext_id:
        return jsonify({"status": "error", "message": f"No extension found for {email}"}), 404

    line_keys = get_line_keys(ext_id)
    if not line_keys:
        return jsonify({"status": "error", "message": f"No line keys found for {email}"}), 404

    results = []
    for lk in line_keys:
        success = patch_line_key(ext_id, lk.get("line_key_id"), caller_id)
        results.append({
            "line_key_id": lk.get("line_key_id"),
            "success": success
        })

    return jsonify({"status": "success", "email": email, "results": results})

@app.route("/bulk_update", methods=["POST"])
def bulk_update():
    """
    Excel file with columns: email | caller_id
    """
    file = request.files.get("excel_file")
    if not file:
        return jsonify({"status": "error", "message": "Excel file required"}), 400

    wb = load_workbook(file)
    sheet = wb.active
    results = []

    for row in sheet.iter_rows(min_row=1, values_only=True):
        if not row or len(row) < 2:
            continue
        email, caller_id = row
        if not email or not caller_id:
            continue

        ext_id = get_user_extension_id(email)
        if not ext_id:
            results.append({"email": email, "status": "error", "message": "No extension found"})
            continue

        line_keys = get_line_keys(ext_id)
        if not line_keys:
            results.append({"email": email, "status": "error", "message": "No line keys found"})
            continue

        lk_results = []
        for lk in line_keys:
            res = patch_line_key(ext_id, lk.get("line_key_id"), caller_id)
            lk_results.append(res)
        results.append({"email": email, "status": "success", "line_keys": lk_results})

    return jsonify({"status": "success", "results": results})

@app.route("/dashboard")
def dashboard():
    """Live report dashboard"""
    total = len(report_cache["updates"])
    success_count = sum(1 for u in report_cache["updates"] if u["success"])
    fail_count = total - success_count

    return render_template("dashboard.html", total=total, success=success_count, fail=fail_count)
@app.route("/refresh_users", methods=["GET"])
def refresh_users():
    try:
        users = zoom_get_users()
        return jsonify({"status": "success", "zoom_users": users})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ---------------- Run App ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)









