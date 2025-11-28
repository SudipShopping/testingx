import os
import json
import requests # Still needed for some specific non-session calls if any, but mostly replaced by fast_session
import datetime
import pytz
import uuid
import hashlib # For password hashing
import secrets # For temporary codes
import html # For escaping user names
import traceback # For detailed error logging
from urllib.parse import quote # 🆕 ADDED FOR URL ENCODING
from flask import Flask, request, jsonify, send_file
import atexit # 🆕 ADDED for scheduler cleanup
from apscheduler.schedulers.background import BackgroundScheduler # 🆕 ADDED for scheduler

# ⚡ SPEED OPTIMIZATION IMPORTS
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 🚨 REAL API DEPENDENCY: requests_oauthlib is required for posting
try:
    from requests_oauthlib import OAuth1Session
except ImportError:
    print("Warning: requests_oauthlib not found. Real API posting will fail.")
    class OAuth1Session:
        def __init__(self, *args, **kwargs): pass
        def post(self, url, data, **kwargs): # Changed json to data for v1.1 compatibility
            return type('MockResponse', (object,), {'json': lambda: {'errors': [{'message': 'OAuth library missing.', 'code': 999}]}, 'status_code': 401})()


# ==============================
# 🔒 HARDCODED SECRETS & CONFIG
# ==============================
WEBHOOK_SECRET = "c4a8b97e3c92a6ff12d7f183f5e65bc1"
MAIN_BOT_TOKEN = "8428126884:AAEjbdgawLFrNqrxTsMS95MfMH0LouDJbYw"
LINK_BOT_TOKEN = "8196170842:AAHf85B9JPC8ARw2p4Ax0mkRZ0UdU1nyb3s"
ADMIN_BOT_TOKEN = "8272656277:AAEUXGW5MMWwgWuk7W388ntIXFS0nEGniZ8" # Admin Bot Token
PUBLIC_BASE_URL = "https://tweet2telegram-nqgw.onrender.com" # ◀️ আপনার আসল URL ব্যবহার করুন
WEBSITE_URL = "https://bit.ly/flashautomation" # ◀️ ADDED

# ===========================
# 💳 PAYMENT CONFIGURATION
# ===========================
PAYMENT_AMOUNT_INR = "520"
PAYMENT_AMOUNT_USD = "6"
UPI_ID = "yourname@okaxis"  # ◀️ CHANGE THIS
CRYPTO_WALLET = "TYourTRC20WalletAddress"  # ◀️ CHANGE THIS

PAYMENT_INSTRUCTIONS = f"""
💳 <b>Payment & Verify to Access TweetAutomation Bot</b>

💰 <b>Amount:</b> ₹{PAYMENT_AMOUNT_INR} (INR) or ${PAYMENT_AMOUNT_USD} (USD)

📱 <b>Payment Methods:</b>

<b>1️⃣ UPI (India):</b>
   UPI ID: <code>{UPI_ID}</code>
   
<b>2️⃣ Crypto (Worldwide):</b>
   USDT (TRC20): <code>{CRYPTO_WALLET}</code>

<b>📸 After Payment:</b>
1. Take a screenshot of your payment
2. Send the screenshot here with Payment ID/UTR as caption
   Example: Send image with caption "UTR123456789"

⏳ Admin will verify within 1-24 hours.
"""

# Supabase Configuration (PRIMARY for ALL data)
SUPABASE_URL = "https://xebasaxioqlbnrzkmyjh.supabase.co"
SUPABASE_API_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InhlYmFzYXhpb3FsYm5yemtteWpoIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2MzEzMjk3OCwiZXhwIjoyMDc4NzA4OTc4fQ.n2tGsrKODd6Dp7OtbsE3xOQ_wPtdU4QHLaBqtT7tcRA"
SB_TABLE_ACCOUNTS = "user_x_accounts" # This was already in Supabase
SB_HEADERS = {
    "apikey": SUPABASE_API_KEY,
    "Authorization": f"Bearer {SUPABASE_API_KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=representation"
}
SB_HEADERS_UPSERT = {**SB_HEADERS, "Prefer": "return=representation,resolution=merge-duplicates"}

# Super admins (can manage keys/admins, broadcast, block/unblock)
ADMIN_IDS = [6535216093]
ADMIN_CONTACT = "@ox_anonymous"

# Bot usernames (for UX hints)
MAIN_BOT_USERNAME = "@TweetAutomation_bot"
LINK_BOT_USERNAME = "@TweetXLinks_bot"
ADMIN_BOT_USERNAME = "@TweetAdminBotplusWeb_bot"

# ❌ REMOVED: DATABASE_NAME = "automation.db"
TIMEZONE = "Asia/Kolkata" # Indian Time
kolkata_tz = pytz.timezone(TIMEZONE)

MAIN_BOT_API = f"https://api.telegram.org/bot{MAIN_BOT_TOKEN}"
LINK_BOT_API = f"https://api.telegram.org/bot{LINK_BOT_TOKEN}"
ADMIN_BOT_API = f"https://api.telegram.org/bot{ADMIN_BOT_TOKEN}"

# Configuration for new features
MAX_ACCOUNTS_PER_USER = 250  # 🔧 Maximum 250 accounts/tweets
MAX_TWEET_LINES = 25
MAX_MESSAGE_LENGTH = 4000
MAX_SCHEDULE_DAYS = 365
PASSWORD_RESET_TIMEOUT_MINUTES = 10

API_KEY_STEPS = [
    {"name": "X Username", "field": "username", "prompt": "🔑 Enter the **X Username** (e.g., myhandle)."},
    {"name": "API Key", "field": "api_key", "prompt": "🔒 Enter the **API Key (Consumer Key)**."},
    {"name": "API Secret Key", "field": "api_secret", "prompt": "🔐 Enter the **API Key Secret (Consumer Secret)**."},
    {"name": "Access Token", "field": "access_token", "prompt": "🧰 Enter the **Access Token**."},
    {"name": "Access Token Secret", "field": "access_token_secret", "prompt": "🗝️ Enter the **Access Token Secret**."},
    {"name": "Bearer Token (Optional)", "field": "bearer_token", "prompt": "🪪 (Optional) Enter the **Bearer Token** (or type 'skip')."}
]

# ⚡ SPEED OPTIMIZATION: Thread pool for concurrent posting
posting_executor = ThreadPoolExecutor(max_workers=50)

# ⚡ SPEED OPTIMIZATION: Fast HTTP session with connection pooling
def create_fast_session():
    session = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=50,
        pool_maxsize=100,
        max_retries=Retry(total=2, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
    )
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

fast_session = create_fast_session()

# ======================
# 🚀 NEW: SUPABASE HELPERS (OPTIMIZED WITH FAST SESSION)
# ======================
def sb_select(table, params, single=False, select="*"):
    """Generic Supabase SELECT"""
    try:
        url = f"{SUPABASE_URL}/rest/v1/{table}?select={select}"
        for key, value in params.items():
            if isinstance(value, str) and ("in." in value or "neq." in value or "lte." in value or "is." in value):
                url += f"&{key}={value}"
            else:
                url += f"&{key}=eq.{value}"

        if single:
            url += "&limit=1"
            
        # ⚡ USE FAST SESSION
        r = fast_session.get(url, headers=SB_HEADERS, timeout=10)
        r.raise_for_status()
        data = r.json()
        
        if single:
            return data[0] if data else None
        return data
    except Exception as e:
        print(f"Supabase SELECT error on table {table}: {e}")
        return None if single else []

def sb_insert(table, data):
    """Generic Supabase INSERT"""
    try:
        url = f"{SUPABASE_URL}/rest/v1/{table}"
        # ⚡ USE FAST SESSION
        r = fast_session.post(url, headers=SB_HEADERS, json=data, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"Supabase INSERT error on table {table}: {e}")
        return None

def sb_update(table, data, params):
    """Generic Supabase UPDATE"""
    try:
        url = f"{SUPABASE_URL}/rest/v1/{table}?"
        param_list = []
        for key, value in params.items():
            param_list.append(f"{key}=eq.{value}")
        url += "&".join(param_list) # <-- ফিক্স করা হয়েছে
            
        # ⚡ USE FAST SESSION
        r = fast_session.patch(url, headers=SB_HEADERS, json=data, timeout=10)
        r.raise_for_status()
        return True
    except Exception as e:
        print(f"Supabase UPDATE error on table {table}: {e}")
        return False

def sb_upsert(table, data_list, on_conflict=None):
    """Generic Supabase UPSERT"""
    try:
        url = f"{SUPABASE_URL}/rest/v1/{table}"
        
        headers = SB_HEADERS_UPSERT
        if on_conflict:
             headers = {**headers, "Prefer": f"return=representation,resolution=merge-duplicates,on_conflict={on_conflict}"}

        # ⚡ USE FAST SESSION
        r = fast_session.post(url, headers=headers, json=data_list, timeout=10)
        
        if r.status_code not in [200, 201]:
            print(f"Supabase UPSERT error on table {table} ({r.status_code}): {r.text}")
            r.raise_for_status()
            
        return r.json()
    except Exception as e:
        print(f"Supabase UPSERT error on table {table}: {e}")
        return None

def sb_delete(table, params):
    """Generic Supabase DELETE"""
    try:
        url = f"{SUPABASE_URL}/rest/v1/{table}?"
        query_params = []
        for key, value in params.items():
            # Support for "in" operator, e.g., {"id": "in.(1,2,3)"}
            if isinstance(value, str) and ("in." in value or "neq." in value or "lte." in value or "is." in value):
                query_params.append(f"{key}={value}")
            else:
                query_params.append(f"{key}=eq.{value}")
        
        url += "&".join(query_params)
            
        # ⚡ USE FAST SESSION
        r = fast_session.delete(url, headers=SB_HEADERS, timeout=10)
        
        if r.status_code not in [200, 204]:
            print(f"Supabase DELETE error on table {table} ({r.status_code}): {r.text}")
            r.raise_for_status()
            
        # ✅ FIX: Safe parsing of Content-Range header
        content_range = r.headers.get('Content-Range', '0-0/0')
        
        # Handle both "0-4/5" and "*/0" formats
        try:
            if '/' in content_range:
                count = int(content_range.split('/')[-1])
            else:
                count = 0
        except (ValueError, IndexError):
            count = 0
            
        return count

    except Exception as e:
        print(f"Supabase DELETE error on table {table}: {e}")
        return 0

# ===========================
# 💳 PAYMENT HELPERS
# ===========================
def save_payment_request(uid, username, payment_method, file_id, payment_id, amount):
    """Save payment request to Supabase"""
    try:
        data = {
            "tg_id": uid,
            "username": username,
            "payment_method": payment_method,
            "payment_proof": file_id,
            "payment_id": payment_id,
            "amount": amount,
            "status": "PENDING",
            "created_at": now_utc_iso()
        }
        result = sb_insert("payment_requests", data)
        return result is not None
    except Exception as e:
        print(f"Save payment request error: {e}")
        return False

def is_user_authorized(uid):
    """Check if user has approved payment OR is super admin"""
    try:
        # Super admin always authorized
        if is_super_admin(uid):
            return True
            
        # Check approved payment
        row = sb_select("payment_requests", 
                       {"tg_id": uid, "status": "APPROVED"}, 
                       single=True, select="id")
        return row is not None
    except Exception as e:
        print(f"Authorization check error: {e}")
        return False

# ============
# HELPERS (Updated to use Supabase)
# ============
def now_utc_iso():
    return datetime.datetime.now(pytz.utc).isoformat(timespec='milliseconds')

def tz_now_str():
    return datetime.datetime.now(kolkata_tz).strftime("%Y-%m-%d %I:%M:%S %p %Z")

def hash_password(password: str) -> str:
    """Hashes a password using SHA256."""
    return hashlib.sha256(password.encode()).hexdigest()

def check_password(password: str, hash: str) -> bool:
    """Checks if a given password matches the hash."""
    return hash_password(password) == hash

def send_msg(api_url, chat_id, text, reply_markup=None):
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True
    }
    if reply_markup:
        payload["reply_markup"] = json.dumps(reply_markup)
    try:
        # ⚡ USE FAST SESSION
        r = fast_session.post(f"{api_url}/sendMessage", json=payload, timeout=10)
        r.raise_for_status()
        return True, r.status_code
    except Exception as e:
        print(f"send_msg error to {chat_id}: {e}")
        return False, str(e)

def is_admin(uid: int) -> bool:
    row = sb_select("admins", {"tg_id": uid}, single=True)
    return row is not None

def is_super_admin(uid: int) -> bool:
    return uid in ADMIN_IDS

def is_blocked(uid: int) -> bool:
    row = sb_select("users", {"tg_id": uid}, single=True, select="blocked")
    return bool(row and row["blocked"])

def set_state(uid: int, scope: str, state: str, data: dict = None):
    data_to_upsert = {
        "tg_id": uid,
        "scope": scope,
        "state": state,
        "data": data if data is not None else {},
        "updated_at": now_utc_iso()
    }
    sb_upsert("user_state", [data_to_upsert], on_conflict="tg_id")

def get_state(uid: int):
    row = sb_select("user_state", {"tg_id": uid}, single=True, select="scope,state,data")
    if row:
        data = row.get("data", {})
        if not isinstance(data, dict):
            data = {}
        return (row["scope"], row["state"], data)
    return (None, None, {})

def clear_state(uid: int):
    sb_delete("user_state", {"tg_id": uid})

def record_user(user):
    uid = user["id"]
    uname = user.get("username")
    data_to_upsert = {
        "tg_id": uid,
        "username": uname,
        "joined_at": now_utc_iso()
    }
    # Only update username on conflict
    sb_upsert("users", [data_to_upsert], on_conflict="tg_id")


def set_webhook(bot_token, path):
    url = f"https://api.telegram.org/bot{bot_token}/setWebhook"
    full = f"{PUBLIC_BASE_URL}{path}"
    try:
        r = fast_session.get(url, params={"url": full}, timeout=10)
        print("setWebhook", path, r.status_code, r.text)
    except Exception as e:
        print("setWebhook error:", path, e)

def setup_webhooks():
    set_webhook(MAIN_BOT_TOKEN, "/webhook_main")
    set_webhook(LINK_BOT_TOKEN, "/webhook_link")
    set_webhook(ADMIN_BOT_TOKEN, "/webhook_admin")

def parse_indian_datetime(text: str) -> datetime.datetime or None:
    # ◀️ UPDATED: This function is now simpler, it only parses "YYYY-MM-DD HH:MM AM/PM"
    india_tz = pytz.timezone(TIMEZONE)
    now = datetime.datetime.now(india_tz).replace(microsecond=0)
    text = text.strip()
    
    dt_format = "%Y-%m-%d %I:%M %p"  
    
    try:
        dt = datetime.datetime.strptime(text, dt_format)
        dt = india_tz.localize(dt)

        max_dt = now + datetime.timedelta(days=MAX_SCHEDULE_DAYS)
        if dt > now and dt < max_dt:
            return dt.astimezone(pytz.utc).replace(microsecond=0)
            
    except Exception as e:
        print(f"Parse datetime error: {e}")
        pass
        
    return None

# --- Supabase API Functions (NOW PRIMARY) ---

# ◀️ UPDATED: Using your new debug function
def sb_upsert_account(uid: int, keys: dict) -> bool:
    username = keys.get("username", "").strip().lower()
    
    if not username:
        print("❌ Username is empty!")
        return False
    
    payload = {
        "tg_id": uid,
        "username": username,
        "api_key": keys.get("api_key", ""),
        "api_secret": keys.get("api_secret", ""),
        "access_token": keys.get("access_token", ""),
        "access_token_secret": keys.get("access_token_secret", ""),
        "bearer_token": keys.get("bearer_token")
    }
    
    print(f"\n{'='*60}")
    print(f"🔍 SUPABASE UPSERT ATTEMPT (user_x_accounts)")
    print(f"{'='*60}")
    print(f"User ID: {uid}")
    print(f"Username: {username}")
    
    try:
        # We can use upsert directly
        url = f"{SUPABASE_URL}/rest/v1/{SB_TABLE_ACCOUNTS}"
        # Upsert based on the composite primary key (tg_id, username)
        headers = {**SB_HEADERS, "Prefer": "return=representation,resolution=merge-duplicates,on_conflict=tg_id,username"}
        
        # ⚡ USE FAST SESSION
        r = fast_session.post(url, headers=headers, json=payload, timeout=10)
        
        print(f"\n📊 UPSERT Request:")
        print(f"URL: {url}")
        print(f"Status Code: {r.status_code}")
        print(f"Response Body: {r.text}")
        
        if r.status_code in (200, 201):
            print(f"\n✅ SUCCESS! Account @{username} linked for user {uid}")
            print(f"{'='*60}\n")
            return True
        else:
            print(f"\n❌ FAILED!")
            try:
                error_detail = r.json()
                print(f"Error Details: {json.dumps(error_detail, indent=2)}")
            except:
                pass
            print(f"{'='*60}\n")
            return False
            
    except requests.exceptions.Timeout:
        print(f"\n⏱️ TIMEOUT! Supabase request took too long")
        print(f"{'='*60}\n")
        return False
    except requests.exceptions.ConnectionError as e:
        print(f"\n🔌 CONNECTION ERROR! Cannot reach Supabase")
        print(f"Error: {e}")
        print(f"{'='*60}\n")
        return False
    except Exception as e:
        print(f"\n💥 EXCEPTION!")
        print(f"Error: {e}")
        traceback.print_exc()
        print(f"{'='*60}\n")
        return False

def sb_list_accounts(uid: int):
    try:
        url = f"{SUPABASE_URL}/rest/v1/{SB_TABLE_ACCOUNTS}?tg_id=eq.{uid}&select=username,api_key,api_secret,access_token,access_token_secret,bearer_token"
        # ⚡ USE FAST SESSION
        r = fast_session.get(url, headers=SB_HEADERS, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print(f"Supabase list exception: {e}")
    return [] # Return empty list on failure

def sb_delete_account(uid: int, username: str) -> bool:
    try:
        url = f"{SUPABASE_URL}/rest/v1/{SB_TABLE_ACCOUNTS}?tg_id=eq.{uid}&username=eq.{username}"
        # ⚡ USE FAST SESSION
        r = fast_session.delete(url, headers=SB_HEADERS, timeout=10)
        if r.status_code in (200, 204):
            return True
    except Exception as e:
        print(f"Supabase delete exception: {e}")
    return False

# --- Local Fallback/Primary DB Helpers (Updated) ---

def get_user_x_accounts(uid: int):
    return sb_list_accounts(uid) # Directly call the Supabase function

def delete_user_account(uid: int, username: str) -> bool:
    return sb_delete_account(uid, username) # Directly call the Supabase function

# 
# 🛠️ *** FIX 1 ***
# `get_unscheduled_tweets` ফাংশনটি প্রতিস্থাপন করা হয়েছে
# 
def get_unscheduled_tweets(uid: int):
    # ✅ FIX: সব প্রয়োজনীয় columns SELECT করুন
    params = {
        "tg_id": uid,
        "post_status": "PENDING",
        "scheduled_time": "is.null"
    }
    
    # Direct Supabase query with proper select
    try:
        url = f"{SUPABASE_URL}/rest/v1/scheduled_tweets?select=id,tweet_text,tg_id,post_status,scheduled_time"
        url += f"&tg_id=eq.{uid}"
        url += "&post_status=eq.PENDING"
        url += "&scheduled_time=is.null"
        url += "&order=id.asc"
            
        # ⚡ USE FAST SESSION
        r = fast_session.get(url, headers=SB_HEADERS, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"Supabase get_unscheduled_tweets error: {e}")
        return []

# 
# ✅ *** FINAL FIX: API v2 ***
# `post_tweet_to_x` ফাংশনটি প্রতিস্থাপন করা হয়েছে
#
def post_tweet_to_x(tweet_id, user_id, account_username, tweet_text):
    accounts = get_user_x_accounts(user_id)  
    
    keys = next((acc for acc in accounts if acc['username'] == account_username), None)
    
    if not keys or not keys['api_key'] or not keys['access_token'] or not keys['access_token_secret']:
        return None, "Account credentials missing or incomplete."

    # ✅ USE API v2 (Free tier compatible)
    url = "https://api.twitter.com/2/tweets"
    
    auth = OAuth1Session(
        keys['api_key'],
        client_secret=keys['api_secret'],
        resource_owner_key=keys['access_token'],
        resource_owner_secret=keys['access_token_secret']
    )
    
    payload = {"text": tweet_text}
    
    try:
        # ⚡ USE FAST SESSION TIMEOUT
        response = auth.post(url, json=payload, timeout=10)
        
        if response.status_code == 201:
            data = response.json()
            tweet_id_str = data.get('data', {}).get('id')
            
            if tweet_id_str:
                tweet_link = f"https://x.com/{account_username}/status/{tweet_id_str}?t=19"
                return tweet_link, None
            else:
                return None, "Tweet posted but ID not found"
        else:
            error_json = None
            error_message = f'HTTP Error {response.status_code}'
            try:
                error_json = response.json()
            except:
                pass
                
            print(f"CRITICAL API ERROR {response.status_code}: {response.text}")
            
            if error_json:
                if 'errors' in error_json and isinstance(error_json['errors'], list) and error_json['errors']:
                    error_message = error_json['errors'][0].get('message', error_message)
                elif 'detail' in error_json:
                    error_message = error_json['detail']
                elif 'title' in error_json:
                    error_message = error_json['title']
            
            if response.status_code == 429:
                error_message = "Rate limit: 17 tweets/day (Free tier). Try tomorrow."
            
            return None, error_message
            
    except Exception as e:
        return None, f"Connection/Library Error: {e}"


# ==========================
# MAIN BOT: COMMAND HANDLER 
# ==========================
def main_bot_handle(update):
    # ❌ Removed: conn = None 
    chat_id = None
    try:
        # ◀️ UPDATED: Handle callback queries for AM/PM
        if "callback_query" in update:
            cb = update["callback_query"]
            chat_id = cb["message"]["chat"]["id"]
            uid = cb["from"]["id"]
            data = cb["data"]
            
            scope, state, flow_data = get_state(uid)
            
            if state == "schedule_flow_ampm":
                # Pass the full callback update to the handler
                return main_bot_flow_continue(uid, chat_id, data, state, flow_data, is_callback=True, callback_update=update)
            else:
                # Answer callback to remove "loading"
                # ⚡ USE FAST SESSION
                fast_session.post(f"{MAIN_BOT_API}/answerCallbackQuery", json={"callback_query_id": cb["id"]})
                return jsonify({"ok": True})

        if "message" not in update:
            return jsonify({"ok": True})

        msg = update["message"]
        chat_id = msg["chat"]["id"]
        from_user = msg["from"]
        text = msg.get("text", "") or ""
        uid = from_user["id"]
        
        record_user(from_user)

        if is_blocked(uid):
            send_msg(MAIN_BOT_API, chat_id, f"🚫 You have been blocked by the administrator. Contact {ADMIN_CONTACT} for details.")
            return jsonify({"ok": True})
        
        scope, state, flow_data = get_state(uid)

        # ===== 💳 PAYMENT PHOTO HANDLER (ADD THIS) =====
        if state == "waiting_payment_proof":
            photo = msg.get("photo")
            caption = msg.get("caption", "").strip()
            
            if not photo:
                send_msg(MAIN_BOT_API, chat_id,
                        "❌ Please send a <b>screenshot</b> of your payment.\n\n"
                        "Add your Payment ID/UTR as caption.\n"
                        "Example: Send image with caption <code>UTR123456789</code>")
                return jsonify({"ok": True})
            
            if not caption or len(caption) < 4:
                send_msg(MAIN_BOT_API, chat_id,
                        "❌ Please add a <b>caption</b> with your Payment ID/UTR.\n\n"
                        "Example: Send image with caption <code>UTR123456789</code>")
                return jsonify({"ok": True})
            
            # Get largest photo
            file_id = photo[-1]["file_id"]
            
            # Extract payment ID
            payment_id = caption.split()[0]  # First word
            
            # Detect method
            payment_method = "UPI" if "utr" in caption.lower() or "upi" in caption.lower() else "CRYPTO"
            amount = f"₹{PAYMENT_AMOUNT_INR}" if payment_method == "UPI" else f"${PAYMENT_AMOUNT_USD}"
            
            username = from_user.get("username", "No Username")
            
            # Save to database
            saved = save_payment_request(uid, username, payment_method, file_id, payment_id, amount)
            
            if not saved:
                send_msg(MAIN_BOT_API, chat_id, "❌ Failed to save payment request. Please try again or contact admin.")
                return jsonify({"ok": True})
            
            clear_state(uid)
            
            # Notify user
            send_msg(MAIN_BOT_API, chat_id,
                    f"✅ <b>Payment Request Submitted!</b>\n\n"
                    f"Payment ID: <code>{payment_id}</code>\n"
                    f"Method: {payment_method}\n"
                    f"Amount: {amount}\n\n"
                    f"⏳ Admin will verify within 1-24 hours.\n"
                    f"You'll receive a notification once approved.")
            
            # Notify admin with screenshot
            admin_msg = (
                f"🔔 <b>NEW PAYMENT REQUEST</b>\n\n"
                f"User: @{username} (ID: <code>{uid}</code>)\n"
                f"Payment ID: <code>{payment_id}</code>\n"
                f"Method: {payment_method}\n"
                f"Amount: {amount}\n\n"
                f"<b>Commands:</b>\n"
                f"Reply: <code>/approve {uid}</code>\n"
                f"Or: <code>/decline {uid} reason</code>"
            )
            
            try:
                # Send screenshot to admin
                fast_session.post(f"{ADMIN_BOT_API}/sendPhoto",
                                json={"chat_id": ADMIN_IDS[0], 
                                     "photo": file_id, 
                                     "caption": admin_msg, 
                                     "parse_mode": "HTML"},
                                timeout=10)
            except Exception as e:
                print(f"Admin notification error: {e}")
                send_msg(ADMIN_BOT_API, ADMIN_IDS[0], admin_msg)
            
            return jsonify({"ok": True})
        # ===== END PAYMENT PHOTO HANDLER =====

        # 1. Handle Flow State
        if state:
            if scope == "main":
                return main_bot_flow_continue(uid, chat_id, text, state, flow_data)
            else:
                clear_state(uid)

        # Parse command
        cmd = text.split()[0].lower() if text.startswith("/") else None

        AUTH_COMMANDS = ["/add_account", "/delete_account", "/accounts", "/add_tweet", "/schedule_tweet", "/connectlinkbot", "/status", "/delete_tweet_text", "/connect_web"]
        
        if cmd == "/start":
            first_name = html.escape(from_user.get("first_name", "User"))
            start_text = (
                f"👋 Welcome, <b>{first_name}</b>! This is the <b>Tweet ➜ Telegram Automation Main Bot</b>!\n\n"
                f"🌐 <b>Website Dashboard:</b> {WEBSITE_URL}\n\n"
            )
            
            if not is_user_authorized(uid):
                start_text += (
                    f"⚠️ <b>Access Required</b>\n\n"
                    f"💳 <b>Price:</b> ₹{PAYMENT_AMOUNT_INR} or ${PAYMENT_AMOUNT_USD}\n\n"
                    f"Use <b>/connect</b> to see payment details."
                )
            else:
                start_text += "✅ <b>You are authorized!</b>\n\nUse <b>/help</b> to see all commands."
            
            send_msg(MAIN_BOT_API, chat_id, start_text)
            return jsonify({"ok": True})

        if cmd == "/help":
            base = (
                "✨ <b>User Commands</b>\n"
                "/start - Welcome message\n"
                "/connect - Make payment for access\n"
                "/cancel - ❌ Cancel any active operation\n"  # 🆕 ADD THIS
            )
            if is_user_authorized(uid):
                base += (
                    "\n🌐 <b>Authorized Commands</b>\n"
                    "/add_account - Start 6-step X API key setup\n"
                    "/add_tweet - Add a new tweet text (supports bulk add)\n"
                    "/schedule_tweet - Schedule all pending tweets for all accounts\n" # ◀️ UPDATED
                    "/delete_tweet_text - Delete a saved tweet text\n"
                    "/delete_account - Remove a linked account\n"
                    "/accounts - List your linked accounts\n"
                    "/connect_web - Generate web sign-up key for dashboard\n"
                    "/connectlinkbot - Generate Link Bot handshake key\n"
                    "/status - Link Bot connection status\n"
                    "/cancel - ❌ Cancel any active operation"  # 🆕 ADD THIS
                )
            send_msg(MAIN_BOT_API, chat_id, base)
            return jsonify({"ok": True})

        if cmd == "/connect":
            # Already authorized
            if is_user_authorized(uid):
                send_msg(MAIN_BOT_API, chat_id, 
                        "✅ You are already authorized! Use <b>/help</b> for commands.")
                return jsonify({"ok": True})
            
            # Check pending payment
            existing = sb_select("payment_requests", 
                                {"tg_id": uid, "status": "PENDING"}, 
                                single=True, select="id,payment_id,created_at")
            
            if existing:
                time_ago = existing.get('created_at', '')[:16]
                send_msg(MAIN_BOT_API, chat_id,
                        f"⏳ <b>Payment Verification Pending</b>\n\n"
                        f"Payment ID: <code>{existing.get('payment_id', 'N/A')}</code>\n"
                        f"Submitted: {time_ago}\n\n"
                        f"Admin will verify soon. Please wait.")
                return jsonify({"ok": True})
            
            # Start payment flow
            set_state(uid, "main", "waiting_payment_proof", data={})
            send_msg(MAIN_BOT_API, chat_id, PAYMENT_INSTRUCTIONS)
            return jsonify({"ok": True})
        
        # 🆕 ==================== /CANCEL COMMAND ====================
        if cmd == "/cancel":
            scope, state, _ = get_state(uid)
            
            if state:
                clear_state(uid)
                
                # Different messages for different operations
                if "add_account" in state:
                    msg = "❌ <b>Account Setup Cancelled</b>"
                elif state == "waiting_for_tweet_text":
                    msg = "❌ <b>Add Tweet Cancelled</b>"
                elif "schedule_flow" in state:
                    msg = "❌ <b>Schedule Cancelled</b>"
                elif "delete" in state:
                    msg = "❌ <b>Delete Cancelled</b>"
                elif state == "waiting_payment_proof":
                    msg = "❌ <b>Payment Process Cancelled</b>"
                else:
                    msg = "❌ <b>Operation Cancelled</b>"
                
                send_msg(MAIN_BOT_API, chat_id, msg + "\n\n💡 Use /help for commands.")
            else:
                send_msg(MAIN_BOT_API, chat_id, "⚠️ No active operation to cancel.")
            
            return jsonify({"ok": True})
        # ===========================================================
        
        # 2. Command Guard
        if cmd and not is_user_authorized(uid) and (cmd in AUTH_COMMANDS):
            send_msg(MAIN_BOT_API, chat_id, 
                    f"🚫 You are not authorized.\n\n"
                    f"💳 Use <b>/connect</b> to make payment (₹{PAYMENT_AMOUNT_INR} or ${PAYMENT_AMOUNT_USD})")
            return jsonify({"ok": True})

        # 3. Authorized Command Execution
        if is_user_authorized(uid):
            
            if cmd == "/connect_web":
                return handle_connect_web(uid, chat_id)
            
            if cmd == "/add_account":
                return handle_add_account_start(uid, chat_id)
            
            if cmd == "/add_tweet":
                return handle_add_tweet_start(uid, chat_id)
                
            if cmd == "/schedule_tweet":
                # ◀️ UPDATED: New flow starts here
                return handle_schedule_tweet_start(uid, chat_id)

            if cmd == "/delete_tweet_text":
                return handle_delete_tweet_text_start(uid, chat_id)

            if cmd == "/delete_account":
                return handle_delete_account_start(uid, chat_id)

            if cmd == "/accounts":
                return handle_list_accounts(uid, chat_id)

            if cmd == "/connectlinkbot":
                return handle_generate_link_bot_key(uid, chat_id)

            if cmd == "/status":
                return handle_link_bot_status(uid, chat_id)

        # 4. Unknown
        if cmd:
            send_msg(MAIN_BOT_API, chat_id, "❌ Unknown command. Use <b>/help</b>.")
        return jsonify({"ok": True})

    except Exception as e:
        print(f"FATAL ERROR in main webhook: {e}")
        traceback.print_exc()
        if chat_id:
            try:
                send_msg(MAIN_BOT_API, chat_id, "❌ An unexpected error occurred. Please notify the admin.")
            except:
                pass
        return jsonify({"ok": True})

# --- MAIN BOT FLOW CONTINUATION ---
# ◀️ UPDATED: Added is_callback
def main_bot_flow_continue(uid, chat_id, text, state, flow_data, is_callback=False, callback_update=None):
    
    # --- Payment Flow Handler (ADD THIS FIRST) ---
    if state == "waiting_payment_proof":
        clear_state(uid)
        return handle_payment_proof_submission(uid, chat_id, text, flow_data)
    # --- End Payment Flow ---
    
    # --- New Schedule Flow ---
    if state == "schedule_flow_date":
        return handle_schedule_flow_date(uid, chat_id, text)
        
    if state == "schedule_flow_time":
        return handle_schedule_flow_time(uid, chat_id, text, flow_data)

    if state == "schedule_flow_ampm":
        # Answer callback if it is one
        if is_callback and callback_update:
            # ⚡ USE FAST SESSION
            fast_session.post(f"{MAIN_BOT_API}/answerCallbackQuery", json={"callback_query_id": callback_update["callback_query"]["id"]})
        return handle_schedule_flow_ampm(uid, chat_id, text, flow_data)
    # --- End New Schedule Flow ---

    if state.startswith("add_account_step_"):
        return handle_add_account_flow(uid, chat_id, text, state, flow_data)
        
    if state == "waiting_for_tweet_text":
        clear_state(uid)
        return handle_add_tweet_text(uid, chat_id, text)

    # ◀️ DELETED: Old schedule flow states

    if state == "waiting_for_delete_tweet_serial":
        return handle_delete_tweet_text_final(uid, chat_id, text.strip())

    if state == "waiting_for_account_to_delete":
        clear_state(uid)
        return handle_delete_account(uid, chat_id, text.strip())

    # Fallback
    clear_state(uid)
    send_msg(MAIN_BOT_API, chat_id, "⚠️ Flow reset. Please send the command again.")
    return jsonify({"ok": True})

# --- MAIN BOT HANDLERS (Updated to Supabase) ---

# ===========================
# 💳 PAYMENT PROOF SUBMISSION
# ===========================
def handle_payment_proof_submission(uid, chat_id, text, flow_data):
    """Handle payment screenshot + ID submission"""
    # This is called from main_bot_handle when photo is sent
    # The actual logic is in main_bot_handle to access msg object
    # If this function is triggered, it means text was sent instead of photo
    send_msg(MAIN_BOT_API, chat_id, "❌ Please send a <b>photo/screenshot</b> of the payment, not text.")
    return jsonify({"ok": True})

def handle_add_account_start(uid, chat_id):
    accounts = get_user_x_accounts(uid)
    if len(accounts) >= MAX_ACCOUNTS_PER_USER:
        send_msg(MAIN_BOT_API, chat_id, f"❌ Maximum limit of {MAX_ACCOUNTS_PER_USER} accounts reached.")
        return jsonify({"ok": True})
    
    step = API_KEY_STEPS[0]
    set_state(uid, "main", f"add_account_step_0", data={"current_step": 0, "keys": {}})
    send_msg(MAIN_BOT_API, chat_id, f"📝 **Add Account**\nStep 1/{len(API_KEY_STEPS)}: {step['prompt']}")
    return jsonify({"ok": True})

def handle_add_account_flow(uid, chat_id, text, state, flow_data):
    current_step = flow_data.get("current_step", 0)
    keys = flow_data.get("keys", {})
    
    current_field = API_KEY_STEPS[current_step]["field"]
    
    if text.lower() == "/cancel":
        clear_state(uid)
        send_msg(MAIN_BOT_API, chat_id, "❌ Account setup cancelled.")
        return jsonify({"ok": True})
        
    if current_field == "bearer_token" and text.lower() == "skip":
        keys["bearer_token"] = None
    else:
        keys[current_field] = text.strip()
    
    next_step = current_step + 1

    if next_step < len(API_KEY_STEPS):
        # Continue to next step
        step = API_KEY_STEPS[next_step]
        set_state(uid, "main", f"add_account_step_{next_step}", data={"current_step": next_step, "keys": keys})
        send_msg(MAIN_BOT_API, chat_id, f"📝 **Add Account**\nStep {next_step + 1}/{len(API_KEY_STEPS)}: {step['prompt']}")
    else:
        # Finalize
        clear_state(uid)
        
        username = keys.get('username', '').strip().lstrip('@').lower()
        if not username:
            send_msg(MAIN_BOT_API, chat_id, "❌ Username is required. Account setup failed.")
            return jsonify({"ok": True})
        
        keys['username'] = username # Normalize for storage

        saved = sb_upsert_account(uid, keys)

        if saved:
            send_msg(MAIN_BOT_API, chat_id, f"✅ Account @{username} successfully linked to Supabase! Use <b>/accounts</b> to view.")
        else:
            send_msg(MAIN_BOT_API, chat_id, f"❌ Failed to link account @{username} to Supabase. Please check credentials or contact admin.")

    return jsonify({"ok": True})


def handle_add_tweet_start(uid, chat_id):
    set_state(uid, "main", "waiting_for_tweet_text", data={})
    send_msg(MAIN_BOT_API, chat_id, "✍️ Send the tweet text(s) now.\n\nTo add multiple tweets, separate them with **one blank line**.")
    return jsonify({"ok": True})
    
def handle_add_tweet_text(uid, chat_id, text):
    tweets_to_add = []
    failed_tweets = []
    
    potential_tweets = text.strip().split("\n\n")
    
    for tweet_text in potential_tweets:
        tweet_text = tweet_text.strip()
        if not tweet_text:
            continue
            
        if len(tweet_text.split('\n')) > MAX_TWEET_LINES or len(tweet_text) > 280:
            failed_tweets.append(tweet_text[:50] + "...") # Add preview of failed tweet
        else:
            tweets_to_add.append(tweet_text)

    if not tweets_to_add and not failed_tweets:
        send_msg(MAIN_BOT_API, chat_id, "❌ Tweet text cannot be empty.")
        return jsonify({"ok": True})

    try:
        tweets_to_insert = []
        for tweet_text in tweets_to_add:
            tweets_to_insert.append({
                "tg_id": uid,
                "tweet_text": tweet_text,
                "post_status": "PENDING",
                "created_at": now_utc_iso()
            })
            
        if tweets_to_insert:
            sb_insert("scheduled_tweets", tweets_to_insert)
        
        ok_count = len(tweets_to_add)
        fail_count = len(failed_tweets)
        
        msg = ""
        if ok_count > 0:
            msg += f"✅ {ok_count} tweet(s) saved successfully to Supabase.\nUse <b>/schedule_tweet</b> to set a time and account."
        
        if fail_count > 0:
            msg += f"\n❌ {fail_count} tweet(s) failed (too long: max {MAX_TWEET_LINES} lines / 280 chars)."
        
        send_msg(MAIN_BOT_API, chat_id, msg)
        
    except Exception as e:
        print(f"Add bulk tweet failed: {e}")
        send_msg(MAIN_BOT_API, chat_id, "❌ Failed to save tweet texts to Supabase due to a database error.")
        
    return jsonify({"ok": True})

# ◀️ --- START: NEW MASS SCHEDULE FLOW ---

# STEP 1: Start the flow
def handle_schedule_tweet_start(uid, chat_id):
    tweets = get_unscheduled_tweets(uid)
    accounts = get_user_x_accounts(uid)
    
    if not tweets:
        send_msg(MAIN_BOT_API, chat_id, "❌ No saved tweets. Use <b>/add_tweet</b> first.")
        return jsonify({"ok": True})
        
    if not accounts:
        send_msg(MAIN_BOT_API, chat_id, "❌ No accounts. Use <b>/add_account</b> first.")
        return jsonify({"ok": True})
    
    # 🔧 Enforce 250 limit
    total_accounts = len(accounts)
    usable_accounts = min(total_accounts, 250)
    num_to_schedule = min(usable_accounts, len(tweets))
    num_to_delete = len(tweets) - num_to_schedule

    msg = f"📊 <b>Schedule Status:</b>\n\n"
    msg += f"📱 Accounts: {total_accounts}"
    if total_accounts > 250:
        msg += f" (using first 250)\n"
    else:
        msg += "\n"
    
    msg += f"📝 Unscheduled tweets: {len(tweets)}\n\n"
    msg += f"✅ <b>Will schedule: {num_to_schedule} tweets</b>\n"
    
    if num_to_delete > 0:
        msg += f"🗑️ <b>Will delete: {num_to_delete} extra tweets</b>\n"
    
    msg += f"\n📅 Send the <b>Date</b> (e.g., <code>2025-11-20</code>):"

    set_state(uid, "main", "schedule_flow_date", data={})
    send_msg(MAIN_BOT_API, chat_id, msg)
    return jsonify({"ok": True})

# STEP 2: Get Date, Ask for Time
def handle_schedule_flow_date(uid, chat_id, text):
    try:
        # Simple validation: Check if it's a valid date format
        datetime.datetime.strptime(text.strip(), '%Y-%m-%d')
    except ValueError:
        send_msg(MAIN_BOT_API, chat_id, "❌ Invalid date format. Please send the <b>Date</b> in <code>YYYY-MM-DD</code> format:")
        return jsonify({"ok": True}) # Keep state

    set_state(uid, "main", "schedule_flow_time", data={"date": text.strip()})
    send_msg(MAIN_BOT_API, chat_id, "⏰ Send the <b>Time</b> (e.g., <code>09:30</code> or <code>14:00</code>):")
    return jsonify({"ok": True})

# STEP 3: Get Time, Ask for AM/PM
def handle_schedule_flow_time(uid, chat_id, text, flow_data):
    try:
        # Simple validation: Check if it's a valid time format
        datetime.datetime.strptime(text.strip(), '%H:%M')
    except ValueError:
        send_msg(MAIN_BOT_API, chat_id, "❌ Invalid time format. Please send the <b>Time</b> in <code>HH:MM</code> (24-hour) format:")
        return jsonify({"ok": True}) # Keep state

    # Convert HH:MM to HH:MM AM/PM
    time_obj = datetime.datetime.strptime(text.strip(), '%H:%M')
    time_12hr = time_obj.strftime('%I:%M')
    am_pm = time_obj.strftime('%p')

    flow_data["time"] = time_12hr
    flow_data["ampm"] = am_pm
    
    # We have all data, now call the final scheduling function
    clear_state(uid)
    return mass_schedule_tweets(uid, flow_data["date"], flow_data["time"], flow_data["ampm"], chat_id=chat_id)

# STEP 4: (DEPRECATED - Merged into Step 3)
# def handle_schedule_flow_ampm(uid, chat_id, text, flow_data): ...

def handle_schedule_flow_ampm(uid, chat_id, text, flow_data): return jsonify({"ok": True})

# STEP 5: Final Scheduling Logic (◀️ *** NEW LOGIC IMPLEMENTED ***)
def mass_schedule_tweets(uid, date_str, time_str, ampm_str, chat_id=None):
    full_time_str = f"{date_str} {time_str} {ampm_str}"
    parsed_dt_utc = parse_indian_datetime(full_time_str)
    
    if not parsed_dt_utc:
        if chat_id:
            send_msg(MAIN_BOT_API, chat_id, f"❌ Invalid or past schedule time (<code>{full_time_str}</code>). Flow reset.")
        return jsonify({"status": "error", "message": "Invalid or past schedule time."})

    accounts = get_user_x_accounts(uid)
    tweets = get_unscheduled_tweets(uid) # Fetches in ASC order
    
    # 🔧 Enforce 250 account limit
    if len(accounts) > 250:
        accounts = accounts[:250]

    if not accounts or not tweets:
        if chat_id:
            send_msg(MAIN_BOT_API, chat_id, "❌ No accounts or unscheduled tweets found. Flow reset.")
        return jsonify({"status": "error", "message": "No accounts or unscheduled tweets found."})

    num_to_schedule = min(len(accounts), len(tweets))
    tweets_to_schedule = tweets[:num_to_schedule]
    tweets_to_delete = tweets[num_to_schedule:]
    
    scheduled_count = 0
    deleted_count = 0
    
    try:
        # 
        # 🛠️ *** FIX 2 ***
        # `mass_schedule_tweets` এর UPDATE লজিকটি প্রতিস্থাপন করা হয়েছে
        # 
        
        # ✅ FIX: Remove timezone for Supabase storage
        scheduled_time_iso = parsed_dt_utc.strftime('%Y-%m-%dT%H:%M:%S')

        # --- Schedule Tweets ---
        for i in range(num_to_schedule):
            tweet = tweets_to_schedule[i]
            account = accounts[i]
            
            update_data = {
                "scheduled_time": scheduled_time_iso,  # ← Use cleaned format
                "account_username": account['username']
            }
            
            # ✅ FIX: শুধু id দিয়ে UPDATE করুন, বাকি conditions verify করা হয়েছে GET-এ
            try:
                url = f"{SUPABASE_URL}/rest/v1/scheduled_tweets?id=eq.{tweet['id']}"
                # ⚡ USE FAST SESSION
                r = fast_session.patch(url, headers=SB_HEADERS, json=update_data, timeout=10)
                
                if r.status_code in (200, 204):
                    scheduled_count += 1 # <-- Simplified count fix
            except Exception as e:
                print(f"Error scheduling tweet ID {tweet['id']}: {e}")

        # --- Delete Remaining Tweets ---
        if tweets_to_delete:
            ids_to_delete = [t['id'] for t in tweets_to_delete]
            # Build "in" query param: (1,2,3)
            ids_param = f"in.({','.join(map(str, ids_to_delete))})"
            
            deleted_count = sb_delete("scheduled_tweets", {"id": ids_param, "tg_id": uid, "post_status": "PENDING"})

        
        ist_time = parsed_dt_utc.astimezone(kolkata_tz).strftime('%Y-%m-%d %I:%M %p %Z')
        message = f"✅ Successfully scheduled <b>{scheduled_count}</b> tweets for <b>{ist_time}</b>."
        
        if deleted_count > 0:
            message += f"\n🗑️ <b>{deleted_count}</b> extra unscheduled tweets were deleted."
        
        if chat_id:
            send_msg(MAIN_BOT_API, chat_id, message)
        return jsonify({"status": "ok", "message": message, "scheduled_count": scheduled_count, "deleted_count": deleted_count})

    except Exception as e:
        print(f"Mass schedule failed: {e}")
        traceback.print_exc()
        message = f"❌ An internal error occurred during scheduling: {e}. Flow reset."
        if chat_id:
            send_msg(MAIN_BOT_API, chat_id, message)
        return jsonify({"status": "error", "message": "Database error during scheduling."})


# ◀️ --- END: NEW MASS SCHEDULE FLOW ---


def handle_delete_tweet_text_start(uid, chat_id):
    tweets = get_unscheduled_tweets(uid)
    
    if not tweets:
        send_msg(MAIN_BOT_API, chat_id, "❌ No unscheduled tweet text found to delete.")
        return jsonify({"ok": True})

    tweet_list = []
    for t in tweets:
        preview = t["tweet_text"].split('\n')[0][:50]
        tweet_list.append(f"ID <code>{t['id']}</code>: {preview}...")
        
    set_state(uid, "main", "waiting_for_delete_tweet_serial", data={})
    
    msg = (
        "🗑️ <b>Delete Tweet Text</b>\n"
        "<b>Available Unscheduled Tweets:</b>\n" + "\n".join(tweet_list) +
        "\n\nSend the **Tweet ID** (e.g., `123`) to permanently delete the text."
    )
    send_msg(MAIN_BOT_API, chat_id, msg)
    return jsonify({"ok": True})

def handle_delete_tweet_text_final(uid, chat_id, tweet_id_text):
    clear_state(uid)
    try:
        tweet_id = int(tweet_id_text)
    except ValueError:
        send_msg(MAIN_BOT_API, chat_id, "❌ Invalid Tweet ID format. Must be a number. Flow reset.")
        return jsonify({"ok": True})

    try:
        # We can only delete tweets that are PENDING and NOT SCHEDULED (scheduled_time is null)
        delete_params = {
            "id": tweet_id,
            "tg_id": uid,
            "post_status": "PENDING",
            "scheduled_time": "is.null"
        }
        deleted_count = sb_delete("scheduled_tweets", delete_params)
        
        if deleted_count == 0:
            # Check why it failed
            row = sb_select("scheduled_tweets", {"id": tweet_id, "tg_id": uid}, single=True, select="post_status,scheduled_time")
            if row:
                status = row['post_status']
                if status == 'POSTED':
                    send_msg(MAIN_BOT_API, chat_id, f"❌ Cannot delete Tweet ID <code>{tweet_id}</code>. It has already been posted.")
                elif row['scheduled_time']:
                    send_msg(MAIN_BOT_API, chat_id, f"❌ Cannot delete scheduled Tweet ID <code>{tweet_id}</code>. You must use the web dashboard to manage scheduled ones.")
                else:
                    send_msg(MAIN_BOT_API, chat_id, f"❌ Tweet ID <code>{tweet_id}</code> not found or already processed.")
            else:
                send_msg(MAIN_BOT_API, chat_id, f"❌ Tweet ID <code>{tweet_id}</code> not found or not owned by you.")
        else:
            send_msg(MAIN_BOT_API, chat_id, f"✅ Tweet text <code>{tweet_id}</code> successfully deleted.")
            
    except Exception as e:
        print(f"Delete tweet failed: {e}")
        send_msg(MAIN_BOT_API, chat_id, "❌ An error occurred during deletion. Flow reset.")
        
    return jsonify({"ok": True})

def handle_delete_account_start(uid, chat_id):
    accounts = get_user_x_accounts(uid)
    if not accounts:
        send_msg(MAIN_BOT_API, chat_id, "❌ No linked accounts to delete. Use <b>/add_account</b> first.")
        return jsonify({"ok": True})
        
    account_list = ", ".join([f"@{a['username']}" for a in accounts])
    
    set_state(uid, "main", "waiting_for_account_to_delete", data={})
    send_msg(MAIN_BOT_API, chat_id, f"🗑️ **Delete Account**\nYour accounts: {account_list}\n\nSend the **Username** (e.g., `myhandle`) to unlink it.")
    return jsonify({"ok": True})

def handle_delete_account(uid, chat_id, username):
    username = username.strip().lstrip('@').lower()

    if delete_user_account(uid, username):
        try:
            # Delete associated pending/scheduled tweets
            delete_params = {
                "account_username": username,
                "tg_id": uid,
                "post_status": "neq.POSTED" # Delete all except POSTED
            }
            sb_delete("scheduled_tweets", delete_params)
            
            send_msg(MAIN_BOT_API, chat_id, f"✅ Account @{username} unlinked from Supabase. Pending schedules involving this account have been removed.")
        except Exception as e:
            print(f"Delete account scheduled tweets cleanup failed: {e}")
            send_msg(MAIN_BOT_API, chat_id, f"⚠️ Account @{username} unlinked, but cleanup of old schedules failed.")
    else:
        send_msg(MAIN_BOT_API, chat_id, f"❌ Account @{username} not found in Supabase or not linked to your user ID.")

    return jsonify({"ok": True})

def handle_list_accounts(uid, chat_id):
    accounts = get_user_x_accounts(uid)
    if not accounts:
        send_msg(MAIN_BOT_API, chat_id, "❌ No linked accounts. Use <b>/add_account</b> first.")
        return jsonify({"ok": True})
    
    account_list = []
    for i, a in enumerate(accounts, 1):
        has_bearer = "✅" if a.get('bearer_token') else "❌"
        account_list.append(f"<b>{i}. @{a['username']}</b> (Bearer: {has_bearer})")
        
    msg = (
        "📚 <b>Linked Accounts (from Supabase)</b>\n" + 
        "\n".join(account_list) +
        "\n\nUse <b>/delete_account</b> to remove a linked account."
    )
    send_msg(MAIN_BOT_API, chat_id, msg)
    return jsonify({"ok": True})

def handle_connect_web(uid, chat_id):
    try:
        web_user = sb_select("web_users", {"tg_id": uid}, single=True, select="email")
        
        if web_user:
            send_msg(MAIN_BOT_API, chat_id, 
                     f"✅ You are already registered with: <code>{web_user['email']}</code>\n\n"
                     "You can log in on the website. This command is only for generating a *sign-up* key.")
            return jsonify({"ok": True})

        web_key = str(uuid.uuid4().hex[:10]).upper()
        expires_at = datetime.datetime.now(pytz.utc) + datetime.timedelta(minutes=10) # 10 minute expiry for signup
        
        # Delete old keys for this user
        sb_delete("web_keys", {"tg_id": uid})
        
        # Insert new key
        sb_insert("web_keys", {
            "key": web_key,
            "tg_id": uid,
            "created_at": now_utc_iso(),
            "expires_at": expires_at.isoformat()
        })
        
        msg = (
            "🌐 <b>Web Dashboard Sign Up Key</b>\n\n"
            "Use this key on the website sign-up page. It is valid for **10 minutes**.\n\n"
            f"Key: <code>{web_key}</code>\n"
            f"Expires: {expires_at.astimezone(kolkata_tz).strftime('%Y-%m-%d %I:%M %p %Z')}"
        )
        send_msg(MAIN_BOT_API, chat_id, msg)
        
    except Exception as e:
        print(f"Handle connect web error: {e}")
        send_msg(MAIN_BOT_API, chat_id, f"❌ Database error: {e}")
    
    return jsonify({"ok": True})

def handle_generate_link_bot_key(uid, chat_id):
    try:
        key = str(uuid.uuid4())
        exp = datetime.datetime.now(pytz.utc) + datetime.timedelta(minutes=5)
        
        # Delete old pending handshakes for this user
        sb_delete("user_link_bot_connections", {"main_bot_tg_id": uid, "link_bot_chat_id": "is.null"})
        
        # Insert new handshake key
        sb_insert("user_link_bot_connections", {
            "main_bot_tg_id": uid,
            "handshake_key": key,
            "handshake_expire": exp.isoformat(),
            "link_bot_chat_id": None
        })
        
        send_msg(MAIN_BOT_API, chat_id,
            "🔗 <b>Link Bot Handshake Key</b>\n"
            f"<code>{key}</code>\n\n"
            f"Go to {LINK_BOT_USERNAME}, send <b>/connectmainbot</b>, and then send this key when prompted.\n"
            "This key expires in <b>5 minutes</b>.")
    except Exception as e:
        print(f"Link bot key generation failed: {e}")
        # Check for unique constraint violation (less likely now but good practice)
        if "unique constraint" in str(e):
            send_msg(MAIN_BOT_API, chat_id, "⚠️ **Wait!** You already have a connection pending or active. Please try again in a minute, or run `/status`.")
        else:
            send_msg(MAIN_BOT_API, chat_id, "❌ Failed to generate Link Bot key.")
        
    return jsonify({"ok": True})

# 
# 🛠️ *** BUG FIX ***
# আপনার দেওয়া কোড দিয়ে `handle_link_bot_status` ফাংশনটি প্রতিস্থাপন করা হয়েছে
# 
def handle_link_bot_status(uid, chat_id):
    # ✅ FIX: Raw query দিয়ে properly fetch করা
    try:
        url = f"{SUPABASE_URL}/rest/v1/user_link_bot_connections?select=link_bot_chat_id&main_bot_tg_id=eq.{uid}&link_bot_chat_id=not.is.null"
        # ⚡ USE FAST SESSION
        r = fast_session.get(url, headers=SB_HEADERS, timeout=10)
        r.raise_for_status()
        rows = r.json()
    except Exception as e:
        print(f"Link bot status fetch failed: {e}")
        rows = []
    
    connected_chats = [r['link_bot_chat_id'] for r in rows if r.get('link_bot_chat_id') is not None]
    
    reply_markup = None
    
    if connected_chats:
        chat_list = "\n".join([f"- <code>{cid}</code>" for cid in connected_chats])
        status_msg = (
            f"📊 <b>Status</b>\nLink Bot: ✅ Connected to {len(connected_chats)} chat(s).\n"
            f"Connected Chats:\n{chat_list}\n\n"
            f"To disconnect any of these, use <code>/disconnect</code> in the respective Link Bot chat, or click below."
        )
        
        reply_markup = {
            'inline_keyboard': [
                [
                    {
                        'text': "🛑 Disconnect Link Bot (in Link Bot)",
                        'url': f"tg://resolve?domain={LINK_BOT_USERNAME.lstrip('@')}&text=/disconnect"
                    }
                ]
            ]
        }
    else:
        status_msg = (
            f"📊 <b>Status</b>\nLink Bot: ❌ Not connected\nUse <b>/connectlinkbot</b> to pair.\n"
            f"🕒 Local Time: {tz_now_str()}"
        )

    send_msg(MAIN_BOT_API, chat_id, status_msg, reply_markup=reply_markup)
    return jsonify({"ok": True})


# ==========================
# ADMIN BOT: COMMAND HANDLER 
# ==========================
def admin_bot_handle(update):
    chat_id = None
    try:
        if "message" not in update: return jsonify({"ok": True})
        msg = update["message"]
        chat_id = msg["chat"]["id"]
        text = msg.get("text", "") or ""
        uid = msg["from"]["id"]
        
        if not is_super_admin(uid):
            send_msg(ADMIN_BOT_API, chat_id, "🚫 You are not authorized to use the Admin Bot.")
            return jsonify({"ok": True})

        scope, state, flow_data = get_state(uid)
        if state and scope == "admin":
            return admin_bot_flow_continue(uid, chat_id, text, state, flow_data)
        
        cmd = text.split()[0].lower() if text.startswith("/") else None
        
        if cmd == "/start" or cmd == "/help":
            base = (
                "👑 <b>Admin Bot Commands</b>\n"
                "/pending - View pending payment requests\n"
                "/approve [user_id] - Approve payment\n"
                "/decline [user_id] [reason] - Decline payment\n"
                "/users - Manage user authorization and blocking\n"
                "/block_user [ID] - Block user access\n"
                "/unblock_user [ID] - Unblock user access\n"
                "/broadcast - Send a message to all active users\n"
            )
            send_msg(ADMIN_BOT_API, chat_id, base)
            return jsonify({"ok": True})

        if cmd == "/pending": return handle_pending_payments(chat_id)
        
        if cmd == "/approve":
            parts = text.split(maxsplit=1)
            if len(parts) < 2:
                send_msg(ADMIN_BOT_API, chat_id, "❌ Usage: <code>/approve [user_id]</code>")
            else:
                return handle_approve_payment(chat_id, parts[1].strip())
            return jsonify({"ok": True})

        if cmd == "/decline":
            parts = text.split(maxsplit=2)
            if len(parts) < 3:
                send_msg(ADMIN_BOT_API, chat_id, "❌ Usage: <code>/decline [user_id] [reason]</code>")
            else:
                return handle_decline_payment(chat_id, parts[1].strip(), parts[2].strip())
            return jsonify({"ok": True})

        if cmd == "/users": return handle_list_users_for_management(uid, chat_id, ADMIN_BOT_API)
        
        if cmd == "/broadcast":
            set_state(uid, "admin", "waiting_for_broadcast_message", data={})
            send_msg(ADMIN_BOT_API, chat_id, "📣 Send the message to broadcast to all active users now.")
            return jsonify({"ok": True})

        if cmd in ["/block_user", "/unblock_user"]:
            parts = text.split(maxsplit=1)
            if len(parts) < 2:
                send_msg(ADMIN_BOT_API, chat_id, f"❌ Usage: <b>{cmd} [User ID]</b>. Find User IDs using /users.")
            else:
                return handle_set_user_block_status_direct(chat_id, parts[1].strip(), cmd == "/block_user", ADMIN_BOT_API)
        
        if cmd: send_msg(ADMIN_BOT_API, chat_id, "❌ Unknown Admin command. Use <b>/help</b>.")
        return jsonify({"ok": True})

    except Exception as e:
        print(f"FATAL ERROR in admin webhook: {e}")
        return jsonify({"ok": True})

def admin_bot_flow_continue(uid, chat_id, text, state, flow_data):
    if state == "waiting_for_broadcast_message":
        clear_state(uid)
        return handle_broadcast_do(uid, chat_id, text, ADMIN_BOT_API)
    
    # Fallback
    clear_state(uid)
    send_msg(ADMIN_BOT_API, chat_id, "⚠️ Admin flow reset. Please send the command again.")
    return jsonify({"ok": True})

# ===========================
# 👑 ADMIN: PAYMENT MANAGEMENT
# ===========================
def handle_pending_payments(chat_id):
    """Show all pending payment requests"""
    try:
        url = f"{SUPABASE_URL}/rest/v1/payment_requests?select=*&status=eq.PENDING&order=created_at.desc&limit=20"
        r = fast_session.get(url, headers=SB_HEADERS, timeout=10)
        r.raise_for_status()
        requests = r.json()
        
        if not requests:
            send_msg(ADMIN_BOT_API, chat_id, "✅ No pending payment requests.")
            return jsonify({"ok": True})
        
        msg = "<b>💳 PENDING PAYMENT REQUESTS</b>\n\n"
        
        for req in requests[:10]:
            created = req['created_at'][:16].replace('T', ' ')
            msg += (
                f"👤 @{req.get('username', 'N/A')}\n"
                f"ID: <code>{req['tg_id']}</code>\n"
                f"Payment: <code>{req['payment_id']}</code>\n"
                f"{req['payment_method']} | {req['amount']}\n"
                f"Time: {created}\n"
                f"<code>/approve {req['tg_id']}</code> | <code>/decline {req['tg_id']} reason</code>\n"
                f"━━━━━━━━━━━━━━━━\n"
            )
        
        send_msg(ADMIN_BOT_API, chat_id, msg)
        
    except Exception as e:
        print(f"Pending payments error: {e}")
        traceback.print_exc()
        send_msg(ADMIN_BOT_API, chat_id, f"❌ Error: {e}")
    
    return jsonify({"ok": True})

def handle_approve_payment(chat_id, user_id_text):
    """Approve a payment request by user ID"""
    try:
        tg_id = int(user_id_text)
    except ValueError:
        send_msg(ADMIN_BOT_API, chat_id, "❌ Invalid user ID format.")
        return jsonify({"ok": True})
    
    try:
        # Get PENDING payment for this user
        req = sb_select("payment_requests", 
                       {"tg_id": tg_id, "status": "PENDING"}, 
                       single=True)
        
        if not req:
            send_msg(ADMIN_BOT_API, chat_id, f"❌ No pending payment found for user ID <code>{tg_id}</code>.")
            return jsonify({"ok": True})
        
        # Update to APPROVED
        sb_update("payment_requests", 
                 {"status": "APPROVED", "admin_response": "Approved", "updated_at": now_utc_iso()},
                 {"tg_id": tg_id, "status": "PENDING"})
        
        # Notify user
        send_msg(MAIN_BOT_API, tg_id,
                f"🎉 <b>PAYMENT APPROVED!</b>\n\n"
                f"Your payment has been verified.\n"
                f"You now have full access to TweetAutomation bot.\n\n"
                f"Use <b>/help</b> to see all commands.")
        
        # Notify admin
        send_msg(ADMIN_BOT_API, chat_id,
                f"✅ Payment APPROVED for user <code>{tg_id}</code> (@{req.get('username', 'N/A')}).\n"
                f"Payment ID: <code>{req['payment_id']}</code>")
        
    except Exception as e:
        print(f"Approve payment error: {e}")
        traceback.print_exc()
        send_msg(ADMIN_BOT_API, chat_id, f"❌ Error: {e}")
    
    return jsonify({"ok": True})

def handle_decline_payment(chat_id, user_id_text, reason):
    """Decline a payment request"""
    try:
        tg_id = int(user_id_text)
    except ValueError:
        send_msg(ADMIN_BOT_API, chat_id, "❌ Invalid user ID format.")
        return jsonify({"ok": True})
    
    try:
        # Get PENDING payment
        req = sb_select("payment_requests", 
                       {"tg_id": tg_id, "status": "PENDING"}, 
                       single=True)
        
        if not req:
            send_msg(ADMIN_BOT_API, chat_id, f"❌ No pending payment found for user ID <code>{tg_id}</code>.")
            return jsonify({"ok": True})
        
        # Update to DECLINED
        sb_update("payment_requests",
                 {"status": "DECLINED", "admin_response": reason, "updated_at": now_utc_iso()},
                 {"tg_id": tg_id, "status": "PENDING"})
        
        # Notify user
        send_msg(MAIN_BOT_API, tg_id,
                f"❌ <b>PAYMENT DECLINED</b>\n\n"
                f"Reason: {reason}\n\n"
                f"Please contact admin {ADMIN_CONTACT} or make a new payment using /connect.")
        
        # Notify admin
        send_msg(ADMIN_BOT_API, chat_id,
                f"❌ Payment DECLINED for user <code>{tg_id}</code>.\n"
                f"Reason: {reason}")
        
    except Exception as e:
        print(f"Decline payment error: {e}")
        traceback.print_exc()
        send_msg(ADMIN_BOT_API, chat_id, f"❌ Error: {e}")
    
    return jsonify({"ok": True})

# --- OTHER ADMIN HANDLERS ---
def handle_list_users_for_management(uid, chat_id, api_url):
    try:
        # RPC ফাংশন সরিয়ে সরাসরি ডেটা আনা হচ্ছে
        users_list = sb_select("users", {}, select="tg_id,username,blocked")
        if not users_list:
            send_msg(api_url, chat_id, "👥 No users found.")
            return jsonify({"ok": True})

        rows = users_list[:50] # Limit to 50

        lines = ["👥 <b>User Management List (Top 50)</b>"]
        for i, r in enumerate(rows, 1):
            blocked_status = "🔴 BLOCKED" if r["blocked"] else "🟢 Active"
            uname = r["username"] or "<i>No Username</i>"
            lines.append(f"<b>{i}.</b> [ID: <code>{r['tg_id']}</code>] {blocked_status} | @{uname}")

        lines.append("\nUse <b>/block_user [User ID]</b> or <b>/unblock_user [User ID]</b>.")
        send_msg(api_url, chat_id, "\n".join(lines))

    except Exception as e:
        print(f"List users failed: {e}")
        traceback.print_exc()
        send_msg(api_url, chat_id, f"❌ Failed to list users due to an internal error: {e}")
        
    return jsonify({"ok": True})

def handle_set_user_block_status_direct(chat_id, user_id_text, block_status: bool, api_url):
    try:
        target_uid = int(user_id_text)
    except ValueError:
        send_msg(api_url, chat_id, "❌ Invalid User ID format. Must be an integer.")
        return jsonify({"ok": True})

    if target_uid in ADMIN_IDS and block_status:
        send_msg(api_url, chat_id, "🚫 Cannot block Super Admin.")
        return jsonify({"ok": True})

    try:
        new_status = 1 if block_status else 0
        action = "BLOCKED" if block_status else "UNBLOCKED"
        
        row = sb_select("users", {"tg_id": target_uid}, single=True, select="blocked")
        
        if not row:
            # User doesn't exist, create them
            record_user({"id": target_uid, "username": f"guest_{target_uid}"})
            
        updated = sb_update("users", {"blocked": new_status}, {"tg_id": target_uid})

        if updated:
            send_msg(api_url, chat_id, f"✅ User <code>{target_uid}</code> successfully {action}.")
        else:
            send_msg(api_url, chat_id, f"⚠️ User <code>{target_uid}</code> status could not be updated or was already set.")
            
    except Exception as e:
        print(f"Block/Unblock failed: {e}")
        send_msg(api_url, chat_id, "❌ An error occurred while updating block status.")
        
    return jsonify({"ok": True})

def handle_broadcast_do(uid, chat_id, message_text, api_url):
    try:
        rows = sb_select("users", {"blocked": 0}, select="tg_id")
        
        total = len(rows)
        ok = 0
        fail = 0
        
        send_msg(api_url, chat_id, f"📣 Starting broadcast to {total} users...")
        
        for i, r in enumerate(rows):
            target_id = r["tg_id"]
            success, _ = send_msg(MAIN_BOT_API, target_id, f"📣 <b>Broadcast</b>\n\n{message_text}")
            if success:
                ok += 1
            else:
                fail += 1
                
            if (i + 1) % 50 == 0:
                send_msg(api_url, chat_id, f"✅ Broadcast progress: {ok}/{total} sent so far.")
                
        send_msg(api_url, chat_id, f"✅ Broadcast finished.\nDelivered: {ok}/{total}. Failed: {fail}.")
    except Exception as e:
        print(f"Broadcast DB error: {e}")
        send_msg(api_url, chat_id, f"❌ Broadcast failed due to DB error: {e}")
        
    return jsonify({"ok": True})

# ==========================
# LINK BOT: COMMAND HANDLER
# ==========================
def link_bot_handle(update):
    chat_id = None
    try:
        if "message" not in update: return jsonify({"ok": True})
        msg = update["message"]
        chat_id = msg["chat"]["id"]
        text = msg.get("text", "") or ""
        uid = msg["from"]["id"] 
        scope, state, flow_data = get_state(uid)
        
        if state and scope == "link":
            if state == "waiting_for_handshake_key":
                return link_bot_try_connect(uid, chat_id, text)
        
        cmd = text.split()[0].lower()
        if cmd == "/start":
            send_msg(LINK_BOT_API, chat_id, f"👋 Welcome to the <b>Tweet Link Bot</b>!\n\n1. Go to {MAIN_BOT_USERNAME} and use <b>/connectlinkbot</b>.\n2. Send <b>/connectmainbot</b> here.\n3. Enter the key.")
            return jsonify({"ok": True})

        if cmd == "/connectmainbot":
            set_state(uid, "link", "waiting_for_handshake_key", data={"chat_id": chat_id})
            send_msg(LINK_BOT_API, chat_id, "🔑 Send your <b>Handshake Key</b> now.")
            return jsonify({"ok": True})
            
        if cmd == "/status":
            clear_state(uid) 
            row = sb_select("user_link_bot_connections", {"link_bot_chat_id": chat_id}, single=True, select="main_bot_tg_id")
            if row: send_msg(LINK_BOT_API, chat_id, f"✅ <b>Connected</b> to User ID: <code>{row['main_bot_tg_id']}</code>.")
            else: send_msg(LINK_BOT_API, chat_id, "❌ <b>Not Connected</b>.")
            return jsonify({"ok": True})
                    
        if cmd == "/disconnect":
            clear_state(uid) 
            sb_delete("user_link_bot_connections", {"link_bot_chat_id": chat_id})
            send_msg(LINK_BOT_API, chat_id, "🛑 <b>Disconnected!</b>")
            return jsonify({"ok": True})

        return jsonify({"ok": True})
    except: return jsonify({"ok": True})

def link_bot_try_connect(uid, chat_id, key_or_text):
    key = key_or_text.strip()
    try:
        temp_key_row = sb_select("user_link_bot_connections", {"handshake_key": key, "link_bot_chat_id": "is.null"}, single=True, select="main_bot_tg_id,handshake_expire")
        if not temp_key_row:
            send_msg(LINK_BOT_API, chat_id, "❌ Invalid key.")
            return jsonify({"ok": True})
        
        main_bot_tg_id = temp_key_row["main_bot_tg_id"]
        sb_insert("user_link_bot_connections", { "main_bot_tg_id": main_bot_tg_id, "link_bot_chat_id": chat_id })
        sb_delete("user_link_bot_connections", {"handshake_key": key})
        clear_state(uid)
        send_msg(LINK_BOT_API, chat_id, f"✅ <b>Connection successful!</b>")
    except:
        send_msg(LINK_BOT_API, chat_id, "❌ Error connecting.")
    return jsonify({"ok": True})

# ============================
#  SCHEDULER & THREADING
# ============================
def post_single_tweet_task(tweet):
    tweet_id = tweet['id']
    tg_id = tweet['tg_id']
    tweet_text = tweet['tweet_text']
    account_username = tweet['account_username']
    
    if is_blocked(tg_id):
        return (tweet_id, False, None, "User blocked", tg_id, account_username)
    
    sb_update("scheduled_tweets", {"post_status": "PROCESSING"}, {"id": tweet_id})
    post_link, error = post_tweet_to_x(tweet_id, tg_id, account_username, tweet_text)
    
    if post_link:
        return (tweet_id, True, post_link, None, tg_id, account_username)
    else:
        return (tweet_id, False, None, error, tg_id, account_username)

def check_and_post_scheduled_tweets():
    now_utc_for_check = datetime.datetime.now(pytz.utc).replace(microsecond=0)
    now_iso = now_utc_for_check.strftime('%Y-%m-%dT%H:%M:%S')
    
    try:
        encoded_time = quote(now_iso, safe='')
        url = f"{SUPABASE_URL}/rest/v1/scheduled_tweets?select=id,tg_id,tweet_text,account_username,scheduled_time&post_status=eq.PENDING&scheduled_time=lte.{encoded_time}&order=scheduled_time.asc"
        r = fast_session.get(url, headers=SB_HEADERS, timeout=10)
        tweets_to_post = r.json()
        if not tweets_to_post: return 0
    except: return 0

    posted_count = 0
    futures = []
    for tweet in tweets_to_post:
        futures.append(posting_executor.submit(post_single_tweet_task, tweet))
    
    for future in as_completed(futures):
        try:
            tweet_id, success, post_link, error, tg_id, account_username = future.result()
            if success:
                posted_count += 1
                sb_update("scheduled_tweets", {"post_status": "POSTED", "post_link": post_link}, {"id": tweet_id})
                send_msg(MAIN_BOT_API, tg_id, f"🎉 <b>Tweet Posted!</b>\nAccount: @{account_username}\nLink: {post_link}")
                try:
                    url = f"{SUPABASE_URL}/rest/v1/user_link_bot_connections?select=link_bot_chat_id&main_bot_tg_id=eq.{tg_id}&link_bot_chat_id=not.is.null"
                    r = fast_session.get(url, headers=SB_HEADERS, timeout=5)
                    for row in r.json(): send_msg(LINK_BOT_API, row['link_bot_chat_id'], post_link)
                except: pass
            else:
                sb_update("scheduled_tweets", {"post_status": "FAILED"}, {"id": tweet_id})
                if error != "User blocked":
                    send_msg(MAIN_BOT_API, tg_id, f"❌ <b>Tweet Failed</b>\nAccount: @{account_username}\nError: {error}")
        except: pass
    return posted_count

# ============================
# FLASK APP ROUTES
# ============================
app = Flask(__name__)

def scheduled_job():
    with app.app_context():
        check_and_post_scheduled_tweets()

scheduler = BackgroundScheduler(timezone=pytz.timezone('Asia/Kolkata'))
scheduler.add_job(func=scheduled_job, trigger="interval", seconds=5, id='tweet_auto_poster')
scheduler.start()
atexit.register(lambda: scheduler.shutdown())

@app.route("/webhook_main", methods=["POST"])
def webhook_main(): return main_bot_handle(request.get_json(silent=True) or {})

@app.route("/webhook_link", methods=["POST"])
def webhook_link(): return link_bot_handle(request.get_json(silent=True) or {})

@app.route("/webhook_admin", methods=["POST"])
def webhook_admin(): return admin_bot_handle(request.get_json(silent=True) or {})

@app.route("/scraper_notify", methods=["POST"])
def scraper_notify():
    data = request.get_json(silent=True) or {}
    secret = request.headers.get("X-Webhook-Secret") or data.get("webhook_secret")
    
    if secret != WEBHOOK_SECRET:
        return jsonify({"status": "error", "message": "Invalid WEBHOOK_SECRET"}), 401

    print(f"Scraper Notify called but scraping is disabled. Data: {data}")
    return jsonify({"status": "warning", "message": "Scraping is disabled. This endpoint is inactive."}), 200

@app.route("/check_scheduler", methods=["GET"])
def scheduler_trigger():
    posted = check_and_post_scheduled_tweets()
    return jsonify({"status": "ok", "message": f"Attempted posting scheduled tweets. Posted {posted}."})

@app.route("/health")
def health(): return jsonify({"ok": True, "time": tz_now_str()})

# --- WEBSITE API ENDPOINTS ---
def validate_web_access(func):
    def wrapper(*args, **kwargs):
        access_key = request.headers.get("X-Access-Key")
        if not access_key: access_key = request.args.get("key")
        if not access_key: return jsonify({"status": "error", "message": "Authorization required"}), 401
        try:
            row = sb_select("web_keys", {"key": access_key}, single=True, select="tg_id,expires_at")
            if not row: return jsonify({"status": "error", "message": "Invalid Access Key"}), 401
            expires = datetime.datetime.fromisoformat(row["expires_at"]).replace(tzinfo=pytz.utc)
            if expires < datetime.datetime.now(pytz.utc): return jsonify({"status": "error", "message": "Access Key expired"}), 401
            tg_id = row['tg_id']
            if is_blocked(tg_id): return jsonify({"status": "error", "message": "User is blocked."}), 401
            kwargs['tg_id'] = tg_id
            return func(*args, **kwargs)
        except: return jsonify({"status": "error", "message": "Internal error"}), 500
    wrapper.__name__ = func.__name__
    return wrapper

@app.route("/api/signup", methods=["POST"])
def api_signup():
    data = request.json
    email = data.get('email', '').strip().lower()
    password = data.get('password')
    web_key = data.get('web_key')
    if not email or not password or not web_key: return jsonify({"status": "error", "message": "Missing fields"}), 400
    try:
        key_row = sb_select("web_keys", {"key": web_key}, single=True, select="tg_id,expires_at")
        if not key_row: return jsonify({"status": "error", "message": "Invalid Sign Up Key."}), 401
        expires = datetime.datetime.fromisoformat(key_row["expires_at"]).replace(tzinfo=pytz.utc)
        if expires < datetime.datetime.now(pytz.utc): return jsonify({"status": "error", "message": "Sign Up Key has expired."}), 401
        tg_id = key_row['tg_id']
        sb_delete("web_keys", {"key": web_key})
        if sb_select("web_users", {"email": email}, single=True): return jsonify({"status": "error", "message": "Email registered."}), 409
        if sb_select("web_users", {"tg_id": tg_id}, single=True): return jsonify({"status": "error", "message": "Telegram ID already linked."}), 409
        sb_insert("web_users", { "email": email, "password_hash": hash_password(password), "tg_id": tg_id, "created_at": now_utc_iso() })
        send_msg(MAIN_BOT_API, tg_id, "✅ **Web Account Linked!** You can now log in.")
        return jsonify({"status": "ok", "message": "Sign up successful."}), 201
    except Exception as e:
        print(f"API signup error: {e}")
        return jsonify({"status": "error", "message": "DB error"}), 500

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.json
    email = data.get('email', '').strip().lower()
    password = data.get('password')
    try:
        row = sb_select("web_users", {"email": email}, single=True, select="tg_id,password_hash")
        if not row or not check_password(password, row['password_hash']): return jsonify({"status": "error", "message": "Invalid credentials"}), 401
        tg_id = row['tg_id']
        if is_blocked(tg_id): return jsonify({"status": "error", "message": "Account blocked."}), 403
        web_key = str(uuid.uuid4().hex[:10]).upper()
        expires_at = datetime.datetime.now(pytz.utc) + datetime.timedelta(days=7)
        sb_upsert("web_keys", [{ "key": web_key, "tg_id": tg_id, "created_at": now_utc_iso(), "expires_at": expires_at.isoformat() }], on_conflict="key")
        return jsonify({"status": "ok", "tg_id": tg_id, "access_key": web_key}), 200
    except: return jsonify({"status": "error", "message": "Server error"}), 500

@app.route("/api/forgot_password", methods=["POST"])
def api_forgot_password():
    data = request.json
    email = data.get('email', '').strip().lower()
    try:
        row = sb_select("web_users", {"email": email}, single=True, select="tg_id")
        if not row: return jsonify({"status": "error", "message": "Email not found."}), 404
        target_tg_id = row['tg_id']
        reset_code = ''.join(secrets.choice('0123456789') for _ in range(4))
        expires_at = datetime.datetime.now(pytz.utc) + datetime.timedelta(minutes=PASSWORD_RESET_TIMEOUT_MINUTES)
        sb_upsert("forgot_password_codes", [{ "email": email, "code": reset_code, "tg_id": target_tg_id, "expires_at": expires_at.isoformat() }], on_conflict="email")
        
        send_msg(ADMIN_BOT_API, ADMIN_IDS[0], f"🔔 **PASSWORD RESET REQUEST**\nEmail: {email}\nCode: <code>{reset_code}</code>\nManually email this code to user.")
        send_msg(MAIN_BOT_API, target_tg_id, f"🔑 **Password Reset**\nRequest received for {email}. Admin will email the code shortly.")
        return jsonify({"status": "ok", "message": "Admin notified."}), 200
    except: return jsonify({"status": "error", "message": "Error"}), 500

@app.route("/api/verify_forgot_code", methods=["POST"])
def api_verify_forgot_code():
    data = request.json
    email = data.get('email', '').strip().lower()
    code = data.get('code')
    try:
        row = sb_select("forgot_password_codes", {"email": email, "code": code}, single=True, select="expires_at")
        if not row: return jsonify({"status": "error", "message": "Invalid code"}), 401
        expires = datetime.datetime.fromisoformat(row["expires_at"]).replace(tzinfo=pytz.utc)
        if expires < datetime.datetime.now(pytz.utc): return jsonify({"status": "error", "message": "Code expired"}), 401
        return jsonify({"status": "ok", "message": "Verified"}), 200
    except: return jsonify({"status": "error", "message": "Error"}), 500

@app.route("/api/reset_password", methods=["POST"])
def api_reset_password():
    data = request.json
    email = data.get('email', '').strip().lower()
    code = data.get('code')
    new_password = data.get('new_password')
    try:
        row = sb_select("forgot_password_codes", {"email": email, "code": code}, single=True, select="tg_id,expires_at")
        if not row: return jsonify({"status": "error", "message": "Invalid code"}), 401
        expires = datetime.datetime.fromisoformat(row["expires_at"]).replace(tzinfo=pytz.utc)
        if expires < datetime.datetime.now(pytz.utc): return jsonify({"status": "error", "message": "Code expired"}), 401
        sb_update("web_users", {"password_hash": hash_password(new_password)}, {"email": email})
        sb_delete("forgot_password_codes", {"email": email})
        send_msg(MAIN_BOT_API, row['tg_id'], "✅ Password updated.")
        return jsonify({"status": "ok", "message": "Password reset"}), 200
    except: return jsonify({"status": "error", "message": "Error"}), 500

@app.route("/api/verify_key", methods=["GET", "POST"])
def api_verify_key():
    key = request.headers.get("X-Access-Key") or (request.args.get("key") if request.method == "GET" else request.json.get("key"))
    if not key: return jsonify({"status": "error", "message": "Key required"}), 400
    try:
        row = sb_select("web_keys", {"key": key}, single=True, select="tg_id,expires_at")
        if row and datetime.datetime.fromisoformat(row["expires_at"]).replace(tzinfo=pytz.utc) > datetime.datetime.now(pytz.utc):
            if is_blocked(row['tg_id']): return jsonify({"status": "error", "message": "Blocked"}), 401
            return jsonify({"status": "ok", "tg_id": row["tg_id"]}), 200
    except: pass
    return jsonify({"status": "error", "message": "Invalid key"}), 401

@app.route("/api/get_accounts", methods=["GET"])
@validate_web_access
def api_get_accounts(tg_id): return jsonify(get_user_x_accounts(tg_id)), 200

@app.route("/api/get_account_details/<string:username>", methods=["GET"])
@validate_web_access
def api_get_account_details(tg_id, username):
    accounts = get_user_x_accounts(tg_id)
    account = next((acc for acc in accounts if acc['username'].lower() == username.lower()), None)
    if account: return jsonify(account), 200
    else: return jsonify({"status": "error", "message": "Not found"}), 404

@app.route("/api/update_account", methods=["POST"])
@validate_web_access
def api_update_account(tg_id):
    keys = request.json
    keys['username'] = keys.get('username', '').strip().lstrip('@').lower()
    if sb_upsert_account(tg_id, keys): return jsonify({"status": "ok", "message": "Updated"}), 200
    return jsonify({"status": "error", "message": "Failed"}), 500

@app.route("/api/get_tweets", methods=["GET"])
@validate_web_access
def api_get_tweets(tg_id):
    try:
        url = f"{SUPABASE_URL}/rest/v1/scheduled_tweets?tg_id=eq.{tg_id}&order=scheduled_time.desc,created_at.desc"
        r = fast_session.get(url, headers=SB_HEADERS, timeout=10)
        return jsonify(r.json()), 200
    except: return jsonify([]), 500

@app.route("/api/delete_tweet", methods=["POST"])
@validate_web_access
def api_delete_tweet(tg_id):
    tweet_id = request.json.get("tweet_id")
    if sb_delete("scheduled_tweets", {"id": tweet_id, "tg_id": tg_id, "post_status": "neq.POSTED"}):
        return jsonify({"status": "ok", "message": "Deleted"}), 200
    return jsonify({"status": "error", "message": "Failed"}), 404

@app.route("/api/delete_all_tweets", methods=["POST"])
@validate_web_access
def api_delete_all_tweets(tg_id):
    try:
        count = sb_delete("scheduled_tweets", {"tg_id": tg_id, "post_status": "neq.POSTED"})
        return jsonify({"status": "ok", "message": f"Deleted {count}"}), 200
    except: return jsonify({"status": "error"}), 500

@app.route("/api/post_all_tweets_now", methods=["POST"])
@validate_web_access
def api_post_all_tweets_now(tg_id):
    # Reusing instant post logic via internal function call or refactor. 
    # For now, simplistic implementation mimicking the route logic:
    # (Note: In a real refactor, logic should be in a helper function)
    tweets = get_unscheduled_tweets(tg_id)
    accounts = get_user_x_accounts(tg_id)
    if not tweets or not accounts: return jsonify({"status": "error"}), 400
    if len(accounts) > 250: accounts = accounts[:250]
    
    count_to_post = min(len(tweets), len(accounts))
    tweets_to_post = tweets[:count_to_post]
    
    posted_count = 0
    futures = []
    for i in range(count_to_post):
        payload = {"id": tweets_to_post[i]['id'], "tg_id": tg_id, "tweet_text": tweets_to_post[i]['tweet_text'], "account_username": accounts[i]['username']}
        futures.append(posting_executor.submit(post_single_tweet_task, payload))
        
    for f in as_completed(futures):
        tid, success, link, err, uid, uname = f.result()
        if success: 
            posted_count += 1
            sb_update("scheduled_tweets", {"post_status": "POSTED", "post_link": link, "account_username": uname, "scheduled_time": now_utc_iso()}, {"id": tid})
        else:
            sb_update("scheduled_tweets", {"post_status": "FAILED", "account_username": uname}, {"id": tid})
            
    # Delete extras
    if len(tweets) > count_to_post:
        extras = tweets[count_to_post:]
        ids = [t['id'] for t in extras]
        sb_delete("scheduled_tweets", {"id": f"in.({','.join(map(str, ids))})"})
        
    return jsonify({"status": "ok", "posted": posted_count}), 200

@app.route("/api/schedule_tweets", methods=["POST"])
@validate_web_access
def api_schedule_tweets(tg_id):
    data = request.json
    return mass_schedule_tweets(tg_id, data.get("date"), data.get("time"), data.get("ampm"))

@app.route("/api/add_account", methods=["POST"])
@validate_web_access
def api_add_account(tg_id):
    return api_update_account(tg_id)

@app.route("/api/delete_account", methods=["POST"])
@validate_web_access
def api_delete_account(tg_id):
    username = request.json.get("username", "").strip().lstrip('@').lower()
    if delete_user_account(tg_id, username):
        sb_delete("scheduled_tweets", {"account_username": username, "tg_id": tg_id, "post_status": "neq.POSTED"})
        return jsonify({"status": "ok", "message": "Deleted"}), 200
    return jsonify({"status": "error", "message": "Not found"}), 404

@app.route("/api/status", methods=["GET"])
@validate_web_access
def api_status(tg_id):
    accounts = get_user_x_accounts(tg_id)
    pending = sb_select("scheduled_tweets", {"tg_id": tg_id, "post_status": "PENDING", "scheduled_time": "is.null"}, select="id")
    try:
        url = f"{SUPABASE_URL}/rest/v1/user_link_bot_connections?select=link_bot_chat_id&main_bot_tg_id=eq.{tg_id}&link_bot_chat_id=not.is.null"
        r = fast_session.get(url, headers=SB_HEADERS, timeout=5)
        link_status = len(r.json()) > 0
    except: link_status = False
    return jsonify({"status": "ok", "account_count": len(accounts), "pending_tweets": len(pending), "link_bot_connected": link_status, "server_time_ist": tz_now_str()}), 200

@app.route("/test_supabase_insert", methods=["GET"])
def test_supabase_insert():
    return jsonify({"status": "ok", "message": "Test endpoint"}), 200

# Static Files
@app.route("/")
def serve_index(): return send_file("index.html")
@app.route("/manifest.json")
def serve_manifest(): return send_file("manifest.json")
@app.route("/sw.js")
def serve_sw(): return send_file("sw.js")
@app.route("/icon.svg")
def serve_icon(): return send_file("icon.svg")
@app.route("/icon-192.png")
def serve_icon_192(): return send_file("icon-192.png", mimetype="image/png")
@app.route("/icon-512.png")
def serve_icon_512(): return send_file("icon-512.png", mimetype="image/png")
@app.route("/icon-1024.png")
def serve_icon_1024(): return send_file("icon-1024.png", mimetype="image/png")
@app.route("/screen1.png")
def serve_screen1(): return send_file("screen1.png", mimetype="image/png")
@app.route("/screen2.png")
def serve_screen2(): return send_file("screen2.png", mimetype="image/png")

if __name__ == "__main__":
    setup_webhooks()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
