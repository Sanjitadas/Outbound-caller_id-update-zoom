# app.py
import os
import time
import base64
import requests
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
from threading import Lock
from openpyxl import load_workbook
from dotenv import load_dotenv
from functools import wraps
from datetime import datetime
import json
from init_db import load_users_from_db, save_user_to_db, delete_user_from_db
import sqlite3

DB_FILE = "caller_id_manager.db"
# Load .env variables
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "supersecretkey")

# ---------------- Configuration ----------------
ZOOM_BASE_URL = "https://api.zoom.us/v2"
CLIENT_ID = os.getenv("ZOOM_CLIENT_ID")
CLIENT_SECRET = os.getenv("ZOOM_CLIENT_SECRET")
ACCOUNT_ID = os.getenv("ZOOM_ACCOUNT_ID")

# ---------------- Token Cache ----------------
token_cache = {"access_token": None, "expiry": 0}
token_lock = Lock()

# ---------------- Users (Default Admins) ----------------
users = load_users_from_db()  # load existing users
# optional: insert default admins if DB empty
if not users:
    default_admins = {
        "sanjita.das@blackbox.com": {"password": "Admin@123", "role": "admin"},
        "rajeev.gupta@blackbox.com": {"password": "Admin@123", "role": "admin"}
    }
    for email, info in default_admins.items():
        save_user_to_db(email, info["password"], info["role"])
    users = load_users_from_db()

# ---------------- Live Report Cache ----------------
report_cache = {"updates": []}

# ---------------- JSON Persistence ----------------
REPORT_FILE = "update_report.json"

# Load report cache from file on server start
if os.path.exists(REPORT_FILE):
    try:
        with open(REPORT_FILE, "r") as f:
            report_cache["updates"] = json.load(f)
    except Exception as e:
        print("Error loading report cache:", e)

# Save report cache to file
def save_report():
    try:
        with open(REPORT_FILE, "w") as f:
            json.dump(report_cache["updates"], f, indent=2)
    except Exception as e:
        print("Error saving report cache:", e)

# ---------------- Helper Functions ----------------
def generate_access_token():
    """Generate Zoom access token (account_credentials grant)"""
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
    """Fetch Zoom Phone users"""
    headers = get_zoom_headers()
    url = f"{ZOOM_BASE_URL}/phone/users?page_size=100"
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    return resp.json().get("users", [])

def get_user_extension_id(email):
    """Get Zoom user extension_id by email"""
    users_list = zoom_get_users()
    for u in users_list:
        if u.get("email", "").lower() == email.lower():
            return u.get("extension_id")
    return None

def get_line_keys(extension_id):
    """Fetch line keys for a given extension"""
    headers = get_zoom_headers()
    url = f"{ZOOM_BASE_URL}/phone/extension/{extension_id}/line_keys"
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        return []
    return resp.json().get("line_keys", [])

def patch_line_key(extension_id, line_key_id, new_caller_id):
    """Update outbound caller ID for a line key"""
    headers = get_zoom_headers()
    url = f"{ZOOM_BASE_URL}/phone/extension/{extension_id}/line_keys"
    payload = {
        "line_keys": [
            {
                "line_key_id": line_key_id,
                "index": 1,
                "outbound_caller_id": new_caller_id
            }
        ]
    }
    try:
        resp = requests.patch(url, headers=headers, json=payload)
        if resp.status_code in (200, 204):
            return True, "Updated"
        else:
            return False, resp.text
    except Exception as e:
        return False, str(e)


def log_update(email, caller_id, success, reason=None, update_type="S"):
    """Store live report in memory, JSON, and SQLite"""
    entry = {
        "email": email,
        "caller_id": caller_id,
        "success": success,
        "reason": reason,
        "type": update_type,
        "time": datetime.now().strftime("%d-%b-%Y %H:%M:%S")
    }

    # Append to in-memory cache
    report_cache["updates"].append(entry)

    # Persist to JSON
    save_report()

    # Persist to DB
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''
            INSERT INTO update_logs (identifier, caller_id, success, reason, type, time)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (email, caller_id, success, reason, update_type, entry["time"]))
        conn.commit()
        conn.close()
    except Exception as e:
        print("Error saving update log to DB:", e)

def get_all_zoom_users():
    try:
        return zoom_get_users()
    except Exception:
        return []

def get_update_report():
    return report_cache.get("updates", [])

def get_email_from_extension_id(ext_id):
    """Reverse lookup email from extension_id if available."""
    try:
        user_info = get_user_by_extension(ext_id)
        return user_info.get("email") if user_info else None
    except Exception:
        return None

def save_user_data(email, extension_id, extension_number, line_key_id, line_index, caller_id, display_name):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO users
        (email, extension_id, extension_number, line_key_id, line_index, caller_id, display_name)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (email, extension_id, extension_number, line_key_id, line_index, caller_id, display_name))
    conn.commit()
    conn.close()

# ---------------- Login Required Decorator ----------------
def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if "email" not in session:
                return redirect(url_for("login"))
            if role and session.get("role") != role:
                flash("Access denied", "danger")
                return redirect(url_for("index"))
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ---------------- Routes ----------------
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").lower()
        password = request.form.get("password","")
        user = users.get(email)
        if user and user["password"] == password:
            session["email"] = email
            session["role"] = user["role"]
            flash(f"Logged in as {email}", "success")
            if user["role"]=="admin":
                return redirect(url_for("dashboard"))
            else:
                return redirect(url_for("index"))
        flash("Invalid credentials","danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
def home():
    if "email" in session:
        return redirect(url_for("dashboard") if session.get("role")=="admin" else url_for("index"))
    return redirect(url_for("login"))

@app.route("/index")
@login_required()
def index():
    updates = load_reports_from_db()  # live and persisted
    return render_template("index.html", report=updates)


@app.route("/get_report", methods=["GET"])
@login_required()
def get_report():
    """Return report to frontend"""
    return jsonify({"status": "success", "report": get_update_report()})

def load_reports_from_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT identifier, caller_id, success, reason, type, time FROM update_logs ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return [
        {
            "email": r[0],
            "caller_id": r[1],
            "success": bool(r[2]),
            "reason": r[3],
            "type": r[4],
            "time": r[5]
        }
        for r in rows
    ]

# ---------------- Dashboard ----------------
@app.route("/dashboard")
@login_required(role="admin")
def dashboard():
    updates = load_reports_from_db()
    total_admin = sum(1 for u in users.values() if u["role"]=="admin")
    total_users = sum(1 for u in users.values() if u["role"]=="user")
    total_actions = len(updates)
    successful_updates = sum(1 for u in updates if u.get("success"))

    return render_template(
        "dashboard.html",
        total_admin=total_admin,
        total_users=total_users,
        total_actions=total_actions,
        successful_updates=successful_updates,
        updates=updates
    )
@app.route("/refresh_users", methods=["GET","POST"])
@login_required(role="admin")
def refresh_users():
    try:
        users = zoom_get_users()
        return jsonify({"status": "success", "zoom_users": users})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# ---------------- Single Update ----------------
@app.route("/single_update", methods=["POST"])
@login_required()
def single_update():
    update_type = request.form.get("update_type", "email").strip()
    identifier = request.form.get("identifier", "").strip()
    caller_id = request.form.get("caller_id", "").strip()

    if not identifier or not caller_id:
        return jsonify({"status": "error", "message": "Identifier and Caller ID required"}), 400

    # Determine email and extension_id based on selection
    if update_type == "email":
        email_updated = identifier
        ext_id = get_user_extension_id(email_updated)
    else:
        ext_id = identifier
        email_updated = get_email_from_extension_id(ext_id) or f"Extension_{ext_id}"

    if not ext_id:
        log_update(identifier, caller_id, False, "No extension found", "S")
        return jsonify({"status": "error", "message": f"No extension found for {identifier}"}), 404

    line_keys = get_line_keys(ext_id)
    if not line_keys:
        log_update(identifier, caller_id, False, "No line keys found", "S")
        return jsonify({"status": "error", "message": f"No line keys found for {identifier}"}), 404

    results = []
    for lk in line_keys:
        current_id = lk.get("key_assignment", {}).get("phone_number", "")
        if current_id == caller_id:
            log_update(identifier, caller_id, False, "Caller ID already same", "S")
            results.append({
                "line_key_id": lk.get("line_key_id"),
                "success": False,
                "reason": "Caller ID already same"
            })
            continue

        success, reason = patch_line_key(ext_id, lk.get("line_key_id"), caller_id)
        log_update(identifier, caller_id, success, reason, "S")
        results.append({
            "line_key_id": lk.get("line_key_id"),
            "success": success,
            "reason": reason
        })

    return jsonify({
        "status": "success",
        "identifier": identifier,
        "updated_line_keys": results
    })

# ---------------- Bulk Update ----------------
@app.route("/bulk_update", methods=["POST"])
@login_required()
def bulk_update():
    update_type = request.form.get("update_type", "email").strip()
    file = request.files.get("excel_file")
    if not file:
        return jsonify({"status": "error", "message": "Excel file required"}), 400

    wb = load_workbook(file)
    sheet = wb.active
    results = []

    for row in sheet.iter_rows(min_row=1, values_only=True):
        if not row or len(row) < 2:
            continue

        identifier, caller_id = row
        if not identifier or not caller_id:
            continue

        identifier = str(identifier).strip()
        caller_id = str(caller_id).strip()

        # Determine based on selected type
        if update_type == "email":
            email_updated = identifier
            ext_id = get_user_extension_id(email_updated)
        else:
            ext_id = identifier
            email_updated = get_email_from_extension_id(ext_id) or f"Extension_{ext_id}"

        if not ext_id:
            log_update(identifier, caller_id, False, "No extension found", "B")
            results.append({
                "identifier": identifier,
                "status": "fail",
                "reason": "No extension found"
            })
            continue

        line_keys = get_line_keys(ext_id)
        if not line_keys:
            log_update(identifier, caller_id, False, "No line keys found", "B")
            results.append({
                "identifier": identifier,
                "status": "fail",
                "reason": "No line keys"
            })
            continue

        lk_results = []
        for lk in line_keys:
            current_id = lk.get("key_assignment", {}).get("phone_number", "")
            if current_id == caller_id:
                log_update(identifier, caller_id, False, "Caller ID already same", "B")
                lk_results.append({
                    "line_key_id": lk.get("line_key_id"),
                    "success": False,
                    "reason": "Caller ID already same"
                })
                continue

            success, reason = patch_line_key(ext_id, lk.get("line_key_id"), caller_id)
            log_update(identifier, caller_id, success, reason, "B")
            lk_results.append({
                "line_key_id": lk.get("line_key_id"),
                "success": success,
                "reason": reason
            })

        results.append({
            "identifier": identifier,
            "updated_line_keys": lk_results
        })

    return jsonify({"status": "success", "results": results})

# ---------------- Manage Users ----------------
@app.route("/manage_users", methods=["GET","POST"])
@login_required(role="admin")
def manage_users():
    if request.method == "POST":
        action = request.form.get("action")
        email = request.form.get("email","").lower()
        password = request.form.get("password","")
        role = request.form.get("role","user")

        if action == "add" and email and password:
            if email in users:
                flash(f"User {email} already exists", "warning")
            else:
                users[email] = {"password": password, "role": role}
                save_user_to_db(email, password, role)  # persist
                flash(f"Added user {email}", "success")

        elif action=="update" and email in users:
            if password:
                users[email]["password"] = password
            if role:
                users[email]["role"] = role
            save_user_to_db(email, users[email]["password"], users[email]["role"])  # persist
            flash(f"Updated user {email}", "success")

        elif action=="delete" and email in users:
            users.pop(email)
            delete_user_from_db(email)  # persist
            flash(f"Deleted user {email}", "success")

    # This runs for both GET and POST
    sorted_users = dict(sorted(users.items()))
    return render_template("manage_users.html", users=sorted_users)


@app.route("/delete_user/<email>", methods=["POST"])
@login_required(role="admin")
def delete_user(email):
    if email in users:
        users.pop(email)
        flash(f"Deleted user {email}", "success")
    return redirect(url_for("manage_users"))

@app.route('/update_user_role/<email>', methods=['POST'])
def update_user_role(email):
    role = request.form.get('role')
    if email in users:
        users[email]['role'] = role
        flash(f'Role updated for {email}', 'success')
    return redirect(url_for('manage_users'))

@app.route("/update_user_password/<email>", methods=["POST"])
@login_required()
def update_user_password(email):
    new_password = request.form.get("password")
    if email in users:
        users[email]["password"] = new_password
        save_user_to_db(email, new_password, users[email]["role"])
        flash(f"Password updated for {email}", "success")
    return redirect(url_for("manage_users"))

# ---------------- Run App ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)










