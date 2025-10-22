# test_zoom_api.py
import os
import time
import base64
import requests
from dotenv import load_dotenv

load_dotenv()

BASE_URL = "https://api.zoom.us/v2"
CLIENT_ID = os.environ.get("ZOOM_CLIENT_ID")
CLIENT_SECRET = os.environ.get("ZOOM_CLIENT_SECRET")
ACCOUNT_ID = os.environ.get("ZOOM_ACCOUNT_ID")

TEST_EMAIL = "allain.jovellano@blackbox.com"
NEW_CALLER_ID = "+12185551234"

def get_access_token():
    """Generate Zoom OAuth token"""
    url = "https://zoom.us/oauth/token?grant_type=account_credentials&account_id=" + ACCOUNT_ID
    auth = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
    headers = {"Authorization": f"Basic {auth}"}
    resp = requests.post(url, headers=headers)
    resp.raise_for_status()
    data = resp.json()
    print(f"Generated Access Token (expires in {data.get('expires_in')}s)")
    return data["access_token"]

def _headers(token):
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

def get_user_by_email(token, email):
    """Get user info directly by email"""
    url = f"{BASE_URL}/users/{email}"
    resp = requests.get(url, headers=_headers(token), timeout=15)
    resp.raise_for_status()
    user = resp.json()
    print(f"User found: {user.get('email')} -> ID: {user.get('id')}")
    return user

def get_line_keys(token, extension_id):
    url = f"{BASE_URL}/phone/extension/{extension_id}/line_keys"
    resp = requests.get(url, headers=_headers(token), timeout=15)
    if resp.status_code == 404:
        print("Line keys not found (maybe user has no phone lines)")
        return []
    resp.raise_for_status()
    keys = resp.json().get("line_keys", [])
    print(f"Fetched {len(keys)} line keys")
    return keys

def patch_line_key(token, extension_id, line_key_id, new_caller_id):
    url = f"{BASE_URL}/phone/extension/{extension_id}/line_keys/{line_key_id}"
    payload = {"outbound_caller_id": new_caller_id}
    resp = requests.patch(url, headers=_headers(token), json=payload, timeout=15)
    resp.raise_for_status()
    print(f"Updated line key {line_key_id} -> {new_caller_id}")
    return resp.json()

if __name__ == "__main__":
    try:
        token = get_access_token()
        user = get_user_by_email(token, TEST_EMAIL)
        extension_id = user.get("id")
        line_keys = get_line_keys(token, extension_id)

        if not line_keys:
            print("No line keys to update.")
        else:
            for lk in line_keys:
                patch_line_key(token, extension_id, lk["id"], NEW_CALLER_ID)
        print("Test completed successfully.")
    except requests.HTTPError as e:
        print(f"HTTPError: {e}")
    except Exception as e:
        print(f"Error: {e}")










