import os
import json
import requests
import datetime
import pytz
import uuid
import hashlib
import secrets
import html
import traceback
from urllib.parse import quote
from flask import Flask, request, jsonify, send_file
import atexit
from apscheduler.schedulers.background import BackgroundScheduler
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
        def post(self, url, data, **kwargs):
            return type('MockResponse', (object,), {'json': lambda: {'errors': [{'message': 'OAuth library missing.', 'code': 999}]}, 'status_code': 401})()


# ==============================
# 🔒 HARDCODED SECRETS & CONFIG
# ==============================
WEBHOOK_SECRET = "c4a8b97e3c92a6ff12d7f183f5e65bc2"
MAIN_BOT_TOKEN = "7929052016:AAFO2NoAIrUysVp8asmv_ahpokm6XU0m1YA"
LINK_BOT_TOKEN = "8155706951:AAHyxvsqR-7RMZMDz2H9F1NbMaljzxca4PY"
ADMIN_BOT_TOKEN = "8364186351:AAF_yh4m4B-csYVZlBvgr1ajT7s0627EgPQ"
PUBLIC_BASE_URL = "https://testingx.onrender.com"
WEBSITE_URL = "https://bit.ly/flashautomation"

# ===========================
# 💳 PAYMENT CONFIGURATION (NEW)
# ===========================
PAYMENT_AMOUNT_INR = "520"
PAYMENT_AMOUNT_USD = "6"

# 🛠️ Payment Details
UPI_ID_VAL = "yourname@okaxis" 

# Crypto Wallets for specific chains
CRYPTO_WALLETS = {
    "BSC": "0xYourBSCWalletAddressHere",  # BNB Smart Chain (BEP20)
    "SOL": "YourSolanaWalletAddressHere", # Solana
    "TRX": "TYourTRC20WalletAddress"      # Tron (TRC20)
}

# Supabase Configuration
SUPABASE_URL = "https://tongguqakjcajxqhxszh.supabase.co"
SUPABASE_API_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRvbmdndXFha2pjYWp4cWh4c3poIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2NDMyOTYxOSwiZXhwIjoyMDc5OTA1NjE5fQ.fT8lhXtwnIZFbdV-wuYp2pcXXHhteyAkVlnEpRpBMBo"
SB_TABLE_ACCOUNTS = "user_x_accounts"
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

# Bot usernames
MAIN_BOT_USERNAME = "@TweetAutomation_bot"
LINK_BOT_USERNAME = "@TweetXLinks_bot"
ADMIN_BOT_USERNAME = "@TweetAdminBotplusWeb_bot"

TIMEZONE = "Asia/Kolkata"
kolkata_tz = pytz.timezone(TIMEZONE)

MAIN_BOT_API = f"https://api.telegram.org/bot{MAIN_BOT_TOKEN}"
LINK_BOT_API = f"https://api.telegram.org/bot{LINK_BOT_TOKEN}"
ADMIN_BOT_API = f"https://api.telegram.org/bot{ADMIN_BOT_TOKEN}"

# Configuration
MAX_ACCOUNTS_PER_USER = 250
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

# ⚡ SPEED OPTIMIZATION: Fast HTTP session
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
# 🚀 SUPABASE HELPERS
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
        url += "&".join(param_list)
            
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
            if isinstance(value, str) and ("in." in value or "neq." in value or "lte." in value or "is." in value):
                query_params.append(f"{key}={value}")
            else:
                query_params.append(f"{key}=eq.{value}")
        url += "&".join(query_params)
        r = fast_session.delete(url, headers=SB_HEADERS, timeout=10)
        if r.status_code not in [200, 204]:
            print(f"Supabase DELETE error on table {table} ({r.status_code}): {r.text}")
            r.raise_for_status()
        content_range = r.headers.get('Content-Range', '0-0/0')
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
    """Checks if user is a Super Admin or has an APPROVED payment request"""
    try:
        if is_super_admin(uid):
            return True
        # Check if user has an approved payment
        row = sb_select("payment_requests", 
                        {"tg_id": uid, "status": "APPROVED"}, 
                        single=True, select="id")
        return row is not None
    except Exception as e:
        print(f"Authorization check error: {e}")
        return False

# ============
# HELPERS
# ============
def now_utc_iso():
    return datetime.datetime.now(pytz.utc).isoformat(timespec='milliseconds')

def tz_now_str():
    return datetime.datetime.now(kolkata_tz).strftime("%Y-%m-%d %I:%M:%S %p %Z")

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def check_password(password: str, hash: str) -> bool:
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

# --- Supabase API Functions ---

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
    print(f"🔍 SUPABASE UPSERT ATTEMPT: User {uid} -> @{username}")
    try:
        url = f"{SUPABASE_URL}/rest/v1/{SB_TABLE_ACCOUNTS}"
        headers = {**SB_HEADERS, "Prefer": "return=representation,resolution=merge-duplicates,on_conflict=tg_id,username"}
        r = fast_session.post(url, headers=headers, json=payload, timeout=10)
        if r.status_code in (200, 201):
            print(f"✅ SUCCESS! Account @{username} linked")
            return True
        else:
            print(f"❌ FAILED! Status: {r.status_code}, Body: {r.text}")
            return False
    except Exception as e:
        print(f"💥 EXCEPTION in upsert_account: {e}")
        return False

def sb_list_accounts(uid: int):
    try:
        url = f"{SUPABASE_URL}/rest/v1/{SB_TABLE_ACCOUNTS}?tg_id=eq.{uid}&select=username,api_key,api_secret,access_token,access_token_secret,bearer_token"
        r = fast_session.get(url, headers=SB_HEADERS, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print(f"Supabase list exception: {e}")
    return []

def sb_delete_account(uid: int, username: str) -> bool:
    try:
        url = f"{SUPABASE_URL}/rest/v1/{SB_TABLE_ACCOUNTS}?tg_id=eq.{uid}&username=eq.{username}"
        r = fast_session.delete(url, headers=SB_HEADERS, timeout=10)
        if r.status_code in (200, 204):
            return True
    except Exception as e:
        print(f"Supabase delete exception: {e}")
    return False

def get_user_x_accounts(uid: int):
    return sb_list_accounts(uid)

def delete_user_account(uid: int, username: str) -> bool:
    return sb_delete_account(uid, username)

def get_unscheduled_tweets(uid: int):
    try:
        url = f"{SUPABASE_URL}/rest/v1/scheduled_tweets?select=id,tweet_text,tg_id,post_status,scheduled_time"
        url += f"&tg_id=eq.{uid}&post_status=eq.PENDING&scheduled_time=is.null&order=id.asc"
        r = fast_session.get(url, headers=SB_HEADERS, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"Supabase get_unscheduled_tweets error: {e}")
        return []

def post_tweet_to_x(tweet_id, user_id, account_username, tweet_text):
    accounts = get_user_x_accounts(user_id)  
    keys = next((acc for acc in accounts if acc['username'] == account_username), None)
    if not keys or not keys['api_key'] or not keys['access_token']:
        return None, "Account credentials missing or incomplete."

    url = "https://api.twitter.com/2/tweets"
    auth = OAuth1Session(
        keys['api_key'],
        client_secret=keys['api_secret'],
        resource_owner_key=keys['access_token'],
        resource_owner_secret=keys['access_token_secret']
    )
    payload = {"text": tweet_text}
    
    try:
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
            error_message = f'HTTP Error {response.status_code}'
            try:
                error_json = response.json()
                if 'errors' in error_json and error_json['errors']:
                    error_message = error_json['errors'][0].get('message', error_message)
                elif 'detail' in error_json:
                    error_message = error_json['detail']
            except: pass
            
            if response.status_code == 429:
                error_message = "Rate limit exceeded (17/day Free tier)."
            return None, error_message
            
    except Exception as e:
        return None, f"Connection/Library Error: {e}"


# ==========================
# MAIN BOT: COMMAND HANDLER 
# ==========================
def main_bot_handle(update):
    chat_id = None
    try:
        # ==========================
        # 🟢 CALLBACK QUERY HANDLER
        # ==========================
        if "callback_query" in update:
            cb = update["callback_query"]
            chat_id = cb["message"]["chat"]["id"]
            uid = cb["from"]["id"]
            data = cb["data"]
            
            # --- Payment Selection Logic ---
            if data == "pay_upi":
                msg = (
                    f"💳 <b>UPI Payment (India)</b>\n\n"
                    f"💰 Amount: <b>₹{PAYMENT_AMOUNT_INR}</b>\n"
                    f"🆔 UPI ID: <code>{UPI_ID_VAL}</code>\n\n"
                    f"1. Send money to the UPI ID above.\n"
                    f"2. Take a screenshot.\n"
                    f"3. Send the screenshot here with your <b>UTR/Transaction ID</b> as caption."
                )
                set_state(uid, "main", "waiting_payment_proof", data={"method": "UPI"})
                fast_session.post(f"{MAIN_BOT_API}/answerCallbackQuery", json={"callback_query_id": cb["id"]})
                send_msg(MAIN_BOT_API, chat_id, msg)
                return jsonify({"ok": True})

            elif data == "pay_crypto":
                networks_markup = {
                    "inline_keyboard": [
                        [{"text": "🔶 BSC (BEP20)", "callback_data": "net_bsc"}],
                        [{"text": "🟣 SOLANA", "callback_data": "net_sol"}],
                        [{"text": "🔴 TRON (TRC20)", "callback_data": "net_trx"}]
                    ]
                }
                fast_session.post(f"{MAIN_BOT_API}/answerCallbackQuery", json={"callback_query_id": cb["id"]})
                send_msg(MAIN_BOT_API, chat_id, "⛓️ <b>Select Network Chain:</b>", reply_markup=networks_markup)
                return jsonify({"ok": True})

            elif data.startswith("net_"):
                chain = data.split("_")[1].upper() # BSC, SOL, or TRX
                wallet = CRYPTO_WALLETS.get(chain, "Contact Admin")
                
                msg = (
                    f"🪙 <b>CRYPTO Payment ({chain})</b>\n\n"
                    f"💰 Amount: <b>${PAYMENT_AMOUNT_USD} USDT</b>\n"
                    f"⛓️ Network: <b>{chain}</b>\n"
                    f"👛 Address:\n<code>{wallet}</code>\n\n"
                    f"1. Send exactly ${PAYMENT_AMOUNT_USD}.\n"
                    f"2. Take a screenshot.\n"
                    f"3. Send the screenshot here with your <b>Transaction Hash (TxID)</b> as caption."
                )
                
                set_state(uid, "main", "waiting_payment_proof", data={"method": "CRYPTO", "chain": chain})
                fast_session.post(f"{MAIN_BOT_API}/answerCallbackQuery", json={"callback_query_id": cb["id"]})
                send_msg(MAIN_BOT_API, chat_id, msg)
                return jsonify({"ok": True})
            
            # --- Existing Flow Logic ---
            scope, state, flow_data = get_state(uid)
            if state == "schedule_flow_ampm":
                return main_bot_flow_continue(uid, chat_id, data, state, flow_data, is_callback=True, callback_update=update)
            else:
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

        # ===== 💳 PAYMENT PHOTO HANDLER =====
        if state == "waiting_payment_proof":
            photo = msg.get("photo")
            caption = msg.get("caption", "").strip()
            
            if not photo:
                send_msg(MAIN_BOT_API, chat_id, "❌ Please send a <b>screenshot</b> of your payment, not text.")
                return jsonify({"ok": True})
            
            if not caption or len(caption) < 4:
                send_msg(MAIN_BOT_API, chat_id, "❌ Please add a <b>caption</b> with your Payment ID/UTR/TxID.\n\nType the ID in the 'Add a caption...' field when sending the image.")
                return jsonify({"ok": True})
            
            file_id = photo[-1]["file_id"]
            payment_id = caption.split()[0] # Take first word as ID
            
            method_type = flow_data.get("method", "UNKNOWN")
            chain_info = flow_data.get("chain", "")
            
            full_method_str = f"{method_type} ({chain_info})" if chain_info else method_type
            amount = f"₹{PAYMENT_AMOUNT_INR}" if method_type == "UPI" else f"${PAYMENT_AMOUNT_USD}"
            username = from_user.get("username", "No Username")
            
            saved = save_payment_request(uid, username, full_method_str, file_id, payment_id, amount)
            
            if not saved:
                send_msg(MAIN_BOT_API, chat_id, "❌ Failed to save payment request. Please try again.")
                return jsonify({"ok": True})
            
            clear_state(uid)
            send_msg(MAIN_BOT_API, chat_id, f"✅ <b>Payment Request Submitted!</b>\n\nPayment ID: <code>{payment_id}</code>\nMethod: {full_method_str}\nAmount: {amount}\n\n⏳ Admin will verify within 1-24 hours.")
            
            # Notify admin with photo
            admin_msg = f"🔔 <b>NEW PAYMENT REQUEST</b>\nUser: @{username} (ID: <code>{uid}</code>)\nPayment ID: <code>{payment_id}</code>\nMethod: {full_method_str}\nAmount: {amount}\n\n<b>Commands:</b>\nReply: <code>/approve {uid}</code>\nOr: <code>/decline {uid} reason</code>"
            try:
                fast_session.post(f"{MAIN_BOT_API}/sendPhoto", json={"chat_id": ADMIN_IDS[0], "photo": file_id, "caption": admin_msg, "parse_mode": "HTML"}, timeout=10)
            except:
                send_msg(MAIN_BOT_API, ADMIN_IDS[0], admin_msg)
            
            return jsonify({"ok": True})
        # ===== END PAYMENT PHOTO HANDLER =====

        if state:
            if scope == "main":
                return main_bot_flow_continue(uid, chat_id, text, state, flow_data)
            else:
                clear_state(uid)

        cmd = text.split()[0].lower() if text.startswith("/") else None
        AUTH_COMMANDS = ["/add_account", "/delete_account", "/accounts", "/add_tweet", "/schedule_tweet", "/connectlinkbot", "/status", "/delete_tweet_text", "/connect_web"]
        
        if cmd == "/start":
            first_name = html.escape(from_user.get("first_name", "User"))
            start_text = f"👋 Welcome, <b>{first_name}</b>! This is the <b>Tweet ➜ Telegram Automation Main Bot</b>!\n\n🌐 <b>Website Dashboard:</b> {WEBSITE_URL}\n\n"
            
            if not is_user_authorized(uid):
                start_text += f"⚠️ <b>Access Required</b>\n\n💳 <b>Price:</b> ₹{PAYMENT_AMOUNT_INR} or ${PAYMENT_AMOUNT_USD}\n\nUse <b>/connect</b> to access services."
            else:
                start_text += "✅ <b>You are authorized!</b>\n\nUse <b>/help</b> to see all commands."
            
            send_msg(MAIN_BOT_API, chat_id, start_text)
            return jsonify({"ok": True})

        if cmd == "/help":
            base = "✨ <b>User Commands</b>\n/start - Welcome message\n/connect - Make payment for access\n/cancel - ❌ Cancel operation\n"
            if is_user_authorized(uid):
                base += "\n🌐 <b>Authorized Commands</b>\n/add_account - Setup X API key\n/add_tweet - Add new tweet text\n/schedule_tweet - Schedule pending tweets\n/delete_tweet_text - Delete saved text\n/delete_account - Remove linked account\n/accounts - List accounts\n/connect_web - Generate web sign-up key\n/connectlinkbot - Link Bot handshake\n/status - Connection status"
            send_msg(MAIN_BOT_API, chat_id, base)
            return jsonify({"ok": True})

        # ===========================
        # 🟢 CONNECT COMMAND
        # ===========================
        if cmd == "/connect":
            if is_user_authorized(uid):
                send_msg(MAIN_BOT_API, chat_id, "✅ You are already authorized! Use <b>/help</b> for commands.")
                return jsonify({"ok": True})
            
            existing = sb_select("payment_requests", {"tg_id": uid, "status": "PENDING"}, single=True, select="id,payment_id,created_at")
            if existing:
                time_ago = existing.get('created_at', '')[:16].replace('T', ' ')
                send_msg(MAIN_BOT_API, chat_id, f"⏳ <b>Payment Verification Pending</b>\n\nPayment ID: <code>{existing.get('payment_id', 'N/A')}</code>\nSubmitted: {time_ago}\n\nAdmin will verify soon.")
                return jsonify({"ok": True})
            
            payment_markup = {
                "inline_keyboard": [
                    [{"text": "🇮🇳 UPI {India}", "callback_data": "pay_upi"}],
                    [{"text": "🌍 CRYPTO_USDT {Worldwide}", "callback_data": "pay_crypto"}]
                ]
            }
            msg = (
                "💳 <b>Access to Premium Services</b>\n\n"
                f"To use this bot, a one-time payment is required.\n"
                f"<b>Price:</b> ₹{PAYMENT_AMOUNT_INR} (INR) / ${PAYMENT_AMOUNT_USD} (USD)\n\n"
                "👇 <b>Select your payment method:</b>"
            )
            set_state(uid, "main", "waiting_payment_method", data={})
            send_msg(MAIN_BOT_API, chat_id, msg, reply_markup=payment_markup)
            return jsonify({"ok": True})
        
        if cmd == "/cancel":
            scope, state, _ = get_state(uid)
            if state:
                clear_state(uid)
                send_msg(MAIN_BOT_API, chat_id, "❌ <b>Operation Cancelled</b>")
            else:
                send_msg(MAIN_BOT_API, chat_id, "⚠️ No active operation to cancel.")
            return jsonify({"ok": True})
        
        if cmd and not is_user_authorized(uid) and (cmd in AUTH_COMMANDS):
            send_msg(MAIN_BOT_API, chat_id, f"🚫 You are not authorized.\n\n💳 Use <b>/connect</b> to access services.")
            return jsonify({"ok": True})

        if is_user_authorized(uid):
            if cmd == "/connect_web": return handle_connect_web(uid, chat_id)
            if cmd == "/add_account": return handle_add_account_start(uid, chat_id)
            if cmd == "/add_tweet": return handle_add_tweet_start(uid, chat_id)
            if cmd == "/schedule_tweet": return handle_schedule_tweet_start(uid, chat_id)
            if cmd == "/delete_tweet_text": return handle_delete_tweet_text_start(uid, chat_id)
            if cmd == "/delete_account": return handle_delete_account_start(uid, chat_id)
            if cmd == "/accounts": return handle_list_accounts(uid, chat_id)
            if cmd == "/connectlinkbot": return handle_generate_link_bot_key(uid, chat_id)
            if cmd == "/status": return handle_link_bot_status(uid, chat_id)

        if cmd:
            send_msg(MAIN_BOT_API, chat_id, "❌ Unknown command. Use <b>/help</b>.")
        return jsonify({"ok": True})

    except Exception as e:
        print(f"FATAL ERROR in main webhook: {e}")
        traceback.print_exc()
        return jsonify({"ok": True})

def main_bot_flow_continue(uid, chat_id, text, state, flow_data, is_callback=False, callback_update=None):
    if state == "waiting_payment_proof":
        send_msg(MAIN_BOT_API, chat_id, "❌ Please send a <b>screenshot</b> of the payment, not text.")
        return jsonify({"ok": True})
        
    if state == "schedule_flow_date":
        return handle_schedule_flow_date(uid, chat_id, text)
    if state == "schedule_flow_time":
        return handle_schedule_flow_time(uid, chat_id, text, flow_data)
    if state == "schedule_flow_ampm":
        if is_callback and callback_update:
            fast_session.post(f"{MAIN_BOT_API}/answerCallbackQuery", json={"callback_query_id": callback_update["callback_query"]["id"]})
        return handle_schedule_flow_ampm(uid, chat_id, text, flow_data)
    if state.startswith("add_account_step_"):
        return handle_add_account_flow(uid, chat_id, text, state, flow_data)
    if state == "waiting_for_tweet_text":
        clear_state(uid)
        return handle_add_tweet_text(uid, chat_id, text)
    if state == "waiting_for_delete_tweet_serial":
        return handle_delete_tweet_text_final(uid, chat_id, text.strip())
    if state == "waiting_for_account_to_delete":
        clear_state(uid)
        return handle_delete_account(uid, chat_id, text.strip())

    clear_state(uid)
    send_msg(MAIN_BOT_API, chat_id, "⚠️ Flow reset. Please send the command again.")
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
        step = API_KEY_STEPS[next_step]
        set_state(uid, "main", f"add_account_step_{next_step}", data={"current_step": next_step, "keys": keys})
        send_msg(MAIN_BOT_API, chat_id, f"📝 **Add Account**\nStep {next_step + 1}/{len(API_KEY_STEPS)}: {step['prompt']}")
    else:
        clear_state(uid)
        username = keys.get('username', '').strip().lstrip('@').lower()
        if not username:
            send_msg(MAIN_BOT_API, chat_id, "❌ Username is required. Account setup failed.")
            return jsonify({"ok": True})
        keys['username'] = username 
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
        if not tweet_text: continue
        if len(tweet_text.split('\n')) > MAX_TWEET_LINES or len(tweet_text) > 280:
            failed_tweets.append(tweet_text[:50] + "...") 
        else:
            tweets_to_add.append(tweet_text)

    if not tweets_to_add and not failed_tweets:
        send_msg(MAIN_BOT_API, chat_id, "❌ Tweet text cannot be empty.")
        return jsonify({"ok": True})

    try:
        tweets_to_insert = []
        for tweet_text in tweets_to_add:
            tweets_to_insert.append({
                "tg_id": uid, "tweet_text": tweet_text, "post_status": "PENDING", "created_at": now_utc_iso()
            })
        if tweets_to_insert:
            sb_insert("scheduled_tweets", tweets_to_insert)
        
        ok_count = len(tweets_to_add)
        fail_count = len(failed_tweets)
        msg = ""
        if ok_count > 0:
            msg += f"✅ {ok_count} tweet(s) saved successfully.\nUse <b>/schedule_tweet</b> to set a time and account."
        if fail_count > 0:
            msg += f"\n❌ {fail_count} tweet(s) failed (too long: max {MAX_TWEET_LINES} lines / 280 chars)."
        send_msg(MAIN_BOT_API, chat_id, msg)
    except Exception as e:
        print(f"Add bulk tweet failed: {e}")
        send_msg(MAIN_BOT_API, chat_id, "❌ Failed to save tweet texts to Supabase.")
    return jsonify({"ok": True})

def handle_schedule_tweet_start(uid, chat_id):
    tweets = get_unscheduled_tweets(uid)
    accounts = get_user_x_accounts(uid)
    if not tweets:
        send_msg(MAIN_BOT_API, chat_id, "❌ No saved tweets. Use <b>/add_tweet</b> first.")
        return jsonify({"ok": True})
    if not accounts:
        send_msg(MAIN_BOT_API, chat_id, "❌ No accounts. Use <b>/add_account</b> first.")
        return jsonify({"ok": True})
    
    total_accounts = len(accounts)
    usable_accounts = min(total_accounts, 250)
    num_to_schedule = min(usable_accounts, len(tweets))
    num_to_delete = len(tweets) - num_to_schedule

    msg = f"📊 <b>Schedule Status:</b>\n\n📱 Accounts: {total_accounts}"
    if total_accounts > 250: msg += f" (using first 250)\n"
    else: msg += "\n"
    msg += f"📝 Unscheduled tweets: {len(tweets)}\n\n✅ <b>Will schedule: {num_to_schedule} tweets</b>\n"
    if num_to_delete > 0: msg += f"🗑️ <b>Will delete: {num_to_delete} extra tweets</b>\n"
    msg += f"\n📅 Send the <b>Date</b> (e.g., <code>2025-11-20</code>):"

    set_state(uid, "main", "schedule_flow_date", data={})
    send_msg(MAIN_BOT_API, chat_id, msg)
    return jsonify({"ok": True})

def handle_schedule_flow_date(uid, chat_id, text):
    try:
        datetime.datetime.strptime(text.strip(), '%Y-%m-%d')
    except ValueError:
        send_msg(MAIN_BOT_API, chat_id, "❌ Invalid date format. Please send the <b>Date</b> in <code>YYYY-MM-DD</code> format:")
        return jsonify({"ok": True}) 
    set_state(uid, "main", "schedule_flow_time", data={"date": text.strip()})
    send_msg(MAIN_BOT_API, chat_id, "⏰ Send the <b>Time</b> (e.g., <code>09:30</code> or <code>14:00</code>):")
    return jsonify({"ok": True})

def handle_schedule_flow_time(uid, chat_id, text, flow_data):
    try:
        datetime.datetime.strptime(text.strip(), '%H:%M')
    except ValueError:
        send_msg(MAIN_BOT_API, chat_id, "❌ Invalid time format. Please send the <b>Time</b> in <code>HH:MM</code> (24-hour) format:")
        return jsonify({"ok": True})
    time_obj = datetime.datetime.strptime(text.strip(), '%H:%M')
    time_12hr = time_obj.strftime('%I:%M')
    am_pm = time_obj.strftime('%p')
    flow_data["time"] = time_12hr
    flow_data["ampm"] = am_pm
    clear_state(uid)
    return mass_schedule_tweets(uid, flow_data["date"], flow_data["time"], flow_data["ampm"], chat_id=chat_id)

def handle_schedule_flow_ampm(uid, chat_id, text, flow_data): return jsonify({"ok": True})

def mass_schedule_tweets(uid, date_str, time_str, ampm_str, chat_id=None):
    full_time_str = f"{date_str} {time_str} {ampm_str}"
    parsed_dt_utc = parse_indian_datetime(full_time_str)
    if not parsed_dt_utc:
        if chat_id: send_msg(MAIN_BOT_API, chat_id, f"❌ Invalid or past schedule time (<code>{full_time_str}</code>). Flow reset.")
        return jsonify({"status": "error", "message": "Invalid or past schedule time."})

    accounts = get_user_x_accounts(uid)
    tweets = get_unscheduled_tweets(uid) 
    if len(accounts) > 250: accounts = accounts[:250]

    if not accounts or not tweets:
        if chat_id: send_msg(MAIN_BOT_API, chat_id, "❌ No accounts or unscheduled tweets found. Flow reset.")
        return jsonify({"status": "error", "message": "No accounts or unscheduled tweets found."})

    num_to_schedule = min(len(accounts), len(tweets))
    tweets_to_schedule = tweets[:num_to_schedule]
    tweets_to_delete = tweets[num_to_schedule:]
    scheduled_count = 0
    deleted_count = 0
    
    try:
        scheduled_time_iso = parsed_dt_utc.strftime('%Y-%m-%dT%H:%M:%S')
        for i in range(num_to_schedule):
            tweet = tweets_to_schedule[i]
            account = accounts[i]
            update_data = { "scheduled_time": scheduled_time_iso, "account_username": account['username'] }
            try:
                url = f"{SUPABASE_URL}/rest/v1/scheduled_tweets?id=eq.{tweet['id']}"
                r = fast_session.patch(url, headers=SB_HEADERS, json=update_data, timeout=10)
                if r.status_code in (200, 204): scheduled_count += 1 
            except Exception as e: print(f"Error scheduling tweet ID {tweet['id']}: {e}")

        if tweets_to_delete:
            ids_to_delete = [t['id'] for t in tweets_to_delete]
            ids_param = f"in.({','.join(map(str, ids_to_delete))})"
            deleted_count = sb_delete("scheduled_tweets", {"id": ids_param, "tg_id": uid, "post_status": "PENDING"})

        ist_time = parsed_dt_utc.astimezone(kolkata_tz).strftime('%Y-%m-%d %I:%M %p %Z')
        message = f"✅ Successfully scheduled <b>{scheduled_count}</b> tweets for <b>{ist_time}</b>."
        if deleted_count > 0: message += f"\n🗑️ <b>{deleted_count}</b> extra unscheduled tweets were deleted."
        if chat_id: send_msg(MAIN_BOT_API, chat_id, message)
        return jsonify({"status": "ok", "message": message, "scheduled_count": scheduled_count, "deleted_count": deleted_count})

    except Exception as e:
        print(f"Mass schedule failed: {e}")
        message = f"❌ An internal error occurred during scheduling: {e}. Flow reset."
        if chat_id: send_msg(MAIN_BOT_API, chat_id, message)
        return jsonify({"status": "error", "message": "Database error during scheduling."})

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
    msg = "🗑️ <b>Delete Tweet Text</b>\n<b>Available Unscheduled Tweets:</b>\n" + "\n".join(tweet_list) + "\n\nSend the **Tweet ID** (e.g., `123`) to permanently delete the text."
    send_msg(MAIN_BOT_API, chat_id, msg)
    return jsonify({"ok": True})

def handle_delete_tweet_text_final(uid, chat_id, tweet_id_text):
    clear_state(uid)
    try:
        tweet_id = int(tweet_id_text)
    except ValueError:
        send_msg(MAIN_BOT_API, chat_id, "❌ Invalid Tweet ID format. Must be a number.")
        return jsonify({"ok": True})

    try:
        delete_params = { "id": tweet_id, "tg_id": uid, "post_status": "PENDING", "scheduled_time": "is.null" }
        deleted_count = sb_delete("scheduled_tweets", delete_params)
        if deleted_count == 0:
            send_msg(MAIN_BOT_API, chat_id, f"❌ Tweet ID <code>{tweet_id}</code> not found, already scheduled, or not owned by you.")
        else:
            send_msg(MAIN_BOT_API, chat_id, f"✅ Tweet text <code>{tweet_id}</code> successfully deleted.")
    except Exception as e:
        send_msg(MAIN_BOT_API, chat_id, "❌ An error occurred during deletion.")
    return jsonify({"ok": True})

def handle_delete_account_start(uid, chat_id):
    accounts = get_user_x_accounts(uid)
    if not accounts:
        send_msg(MAIN_BOT_API, chat_id, "❌ No linked accounts to delete.")
        return jsonify({"ok": True})
    account_list = ", ".join([f"@{a['username']}" for a in accounts])
    set_state(uid, "main", "waiting_for_account_to_delete", data={})
    send_msg(MAIN_BOT_API, chat_id, f"🗑️ **Delete Account**\nYour accounts: {account_list}\n\nSend the **Username** (e.g., `myhandle`) to unlink it.")
    return jsonify({"ok": True})

def handle_delete_account(uid, chat_id, username):
    username = username.strip().lstrip('@').lower()
    if delete_user_account(uid, username):
        try:
            delete_params = { "account_username": username, "tg_id": uid, "post_status": "neq.POSTED" }
            sb_delete("scheduled_tweets", delete_params)
            send_msg(MAIN_BOT_API, chat_id, f"✅ Account @{username} unlinked. Pending schedules removed.")
        except Exception as e:
            send_msg(MAIN_BOT_API, chat_id, f"⚠️ Account @{username} unlinked, but cleanup failed.")
    else:
        send_msg(MAIN_BOT_API, chat_id, f"❌ Account @{username} not found.")
    return jsonify({"ok": True})

def handle_list_accounts(uid, chat_id):
    accounts = get_user_x_accounts(uid)
    if not accounts:
        send_msg(MAIN_BOT_API, chat_id, "❌ No linked accounts.")
        return jsonify({"ok": True})
    account_list = []
    for i, a in enumerate(accounts, 1):
        has_bearer = "✅" if a.get('bearer_token') else "❌"
        account_list.append(f"<b>{i}. @{a['username']}</b> (Bearer: {has_bearer})")
    msg = "📚 <b>Linked Accounts</b>\n" + "\n".join(account_list)
    send_msg(MAIN_BOT_API, chat_id, msg)
    return jsonify({"ok": True})

def handle_connect_web(uid, chat_id):
    try:
        web_user = sb_select("web_users", {"tg_id": uid}, single=True, select="email")
        if web_user:
            send_msg(MAIN_BOT_API, chat_id, f"✅ You are already registered with: <code>{web_user['email']}</code>")
            return jsonify({"ok": True})

        web_key = str(uuid.uuid4().hex[:10]).upper()
        expires_at = datetime.datetime.now(pytz.utc) + datetime.timedelta(minutes=10)
        sb_delete("web_keys", {"tg_id": uid})
        sb_insert("web_keys", { "key": web_key, "tg_id": uid, "created_at": now_utc_iso(), "expires_at": expires_at.isoformat() })
        
        msg = f"🌐 <b>Web Dashboard Sign Up Key</b>\n\nKey: <code>{web_key}</code>\nExpires: {expires_at.astimezone(kolkata_tz).strftime('%Y-%m-%d %I:%M %p %Z')}"
        send_msg(MAIN_BOT_API, chat_id, msg)
    except Exception as e:
        send_msg(MAIN_BOT_API, chat_id, f"❌ Database error: {e}")
    return jsonify({"ok": True})

def handle_generate_link_bot_key(uid, chat_id):
    try:
        key = str(uuid.uuid4())
        exp = datetime.datetime.now(pytz.utc) + datetime.timedelta(minutes=5)
        sb_delete("user_link_bot_connections", {"main_bot_tg_id": uid, "link_bot_chat_id": "is.null"})
        sb_insert("user_link_bot_connections", { "main_bot_tg_id": uid, "handshake_key": key, "handshake_expire": exp.isoformat(), "link_bot_chat_id": None })
        send_msg(MAIN_BOT_API, chat_id, f"🔗 <b>Link Bot Handshake Key</b>\n<code>{key}</code>\n\nGo to {LINK_BOT_USERNAME}, send <b>/connectmainbot</b>, and enter this key.")
    except Exception as e:
        send_msg(MAIN_BOT_API, chat_id, "❌ Failed to generate key.")
    return jsonify({"ok": True})

def handle_link_bot_status(uid, chat_id):
    try:
        url = f"{SUPABASE_URL}/rest/v1/user_link_bot_connections?select=link_bot_chat_id&main_bot_tg_id=eq.{uid}&link_bot_chat_id=not.is.null"
        r = fast_session.get(url, headers=SB_HEADERS, timeout=10)
        rows = r.json()
    except: rows = []
    connected_chats = [r['link_bot_chat_id'] for r in rows if r.get('link_bot_chat_id') is not None]
    
    if connected_chats:
        chat_list = "\n".join([f"- <code>{cid}</code>" for cid in connected_chats])
        status_msg = f"📊 <b>Status</b>\nLink Bot: ✅ Connected to {len(connected_chats)} chat(s).\n{chat_list}"
    else:
        status_msg = f"📊 <b>Status</b>\nLink Bot: ❌ Not connected\nUse <b>/connectlinkbot</b> to pair."
    send_msg(MAIN_BOT_API, chat_id, status_msg)
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
            base = "👑 <b>Admin Bot Commands</b>\n/pending - View pending payment requests\n/approve [user_id] - Approve payment\n/decline [user_id] [reason] - Decline payment\n/users - Manage user authorization\n/block_user [ID] - Block user\n/unblock_user [ID] - Unblock user\n/broadcast - Send message to all users\n/add_admin [ID] - Add new admin\n/remove_admin [ID] - Remove admin"
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
            
        if cmd == "/add_admin":
            set_state(uid, "admin", "waiting_for_admin_id_to_add", data={})
            send_msg(ADMIN_BOT_API, chat_id, "👑 Send the <b>Telegram User ID</b> to add as authorized.")
            return jsonify({"ok": True})
            
        if cmd == "/remove_admin":
            set_state(uid, "admin", "waiting_for_admin_id_to_remove", data={})
            send_msg(ADMIN_BOT_API, chat_id, "👑 Send the <b>Telegram User ID</b> to remove from authorized.")
            return jsonify({"ok": True})

        if cmd in ["/block_user", "/unblock_user"]:
            parts = text.split(maxsplit=1)
            if len(parts) < 2:
                send_msg(ADMIN_BOT_API, chat_id, f"❌ Usage: <b>{cmd} [User ID]</b>.")
            else:
                return handle_set_user_block_status_direct(chat_id, parts[1].strip(), cmd == "/block_user", ADMIN_BOT_API)
        
        if cmd: send_msg(ADMIN_BOT_API, chat_id, "❌ Unknown Admin command.")
        return jsonify({"ok": True})

    except Exception as e:
        print(f"FATAL ERROR in admin webhook: {e}")
        return jsonify({"ok": True})

def admin_bot_flow_continue(uid, chat_id, text, state, flow_data):
    if state == "waiting_for_broadcast_message":
        clear_state(uid)
        return handle_broadcast_do(uid, chat_id, text, ADMIN_BOT_API)
    if state == "waiting_for_admin_id_to_add":
        clear_state(uid)
        return handle_add_admin_id(uid, chat_id, text.strip(), ADMIN_BOT_API)
    if state == "waiting_for_admin_id_to_remove":
        clear_state(uid)
        return handle_remove_admin_id(uid, chat_id, text.strip(), ADMIN_BOT_API)
        
    clear_state(uid)
    return jsonify({"ok": True})

# ===========================
# 👑 ADMIN: PAYMENT MANAGEMENT
# ===========================
def handle_pending_payments(chat_id):
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
            msg += f"👤 @{req.get('username', 'N/A')}\nID: <code>{req['tg_id']}</code>\nPayment: <code>{req['payment_id']}</code>\n{req['payment_method']} | {req['amount']}\nTime: {created}\n<code>/approve {req['tg_id']}</code> | <code>/decline {req['tg_id']} reason</code>\n━━━━━━━━━━━━━━━━\n"
        
        send_msg(ADMIN_BOT_API, chat_id, msg)
    except Exception as e:
        send_msg(ADMIN_BOT_API, chat_id, f"❌ Error: {e}")
    return jsonify({"ok": True})

def handle_approve_payment(chat_id, user_id_text):
    try:
        tg_id = int(user_id_text)
    except ValueError:
        send_msg(ADMIN_BOT_API, chat_id, "❌ Invalid user ID format.")
        return jsonify({"ok": True})
    
    try:
        req = sb_select("payment_requests", {"tg_id": tg_id, "status": "PENDING"}, single=True)
        if not req:
            send_msg(ADMIN_BOT_API, chat_id, f"❌ No pending payment found for user ID <code>{tg_id}</code>.")
            return jsonify({"ok": True})
        
        sb_update("payment_requests", {"status": "APPROVED", "admin_response": "Approved", "updated_at": now_utc_iso()}, {"tg_id": tg_id, "status": "PENDING"})
        
        send_msg(MAIN_BOT_API, tg_id, f"🎉 <b>PAYMENT APPROVED!</b>\n\nYour payment has been verified.\nYou now have full access to TweetAutomation bot.\n\nUse <b>/help</b> to see all commands.")
        send_msg(ADMIN_BOT_API, chat_id, f"✅ Payment APPROVED for user <code>{tg_id}</code> (@{req.get('username', 'N/A')}).")
    except Exception as e:
        send_msg(ADMIN_BOT_API, chat_id, f"❌ Error: {e}")
    return jsonify({"ok": True})

def handle_decline_payment(chat_id, user_id_text, reason):
    try:
        tg_id = int(user_id_text)
    except ValueError:
        send_msg(ADMIN_BOT_API, chat_id, "❌ Invalid user ID format.")
        return jsonify({"ok": True})
    
    try:
        req = sb_select("payment_requests", {"tg_id": tg_id, "status": "PENDING"}, single=True)
        if not req:
            send_msg(ADMIN_BOT_API, chat_id, f"❌ No pending payment found for user ID <code>{tg_id}</code>.")
            return jsonify({"ok": True})
        
        sb_update("payment_requests", {"status": "DECLINED", "admin_response": reason, "updated_at": now_utc_iso()}, {"tg_id": tg_id, "status": "PENDING"})
        
        send_msg(MAIN_BOT_API, tg_id, f"❌ <b>PAYMENT DECLINED</b>\n\nReason: {reason}\n\nPlease contact admin {ADMIN_CONTACT} or make a new payment using /connect.")
        send_msg(ADMIN_BOT_API, chat_id, f"❌ Payment DECLINED for user <code>{tg_id}</code>.\nReason: {reason}")
    except Exception as e:
        send_msg(ADMIN_BOT_API, chat_id, f"❌ Error: {e}")
    return jsonify({"ok": True})

# --- OTHER ADMIN HANDLERS ---
def handle_list_users_for_management(uid, chat_id, api_url):
    try:
        users_list = sb_select("users", {}, select="tg_id,username,blocked")
        if not users_list:
            send_msg(api_url, chat_id, "👥 No users found.")
            return jsonify({"ok": True})
        
        rows = users_list[:50]
        lines = ["👥 <b>User Management List (Top 50)</b>"]
        for i, r in enumerate(rows, 1):
            blocked_status = "🔴 BLOCKED" if r["blocked"] else "🟢 Active"
            uname = r["username"] or "<i>No Username</i>"
            lines.append(f"<b>{i}.</b> [ID: <code>{r['tg_id']}</code>] {blocked_status} | @{uname}")
        lines.append("\nUse <b>/block_user [User ID]</b> or <b>/unblock_user [User ID]</b>.")
        send_msg(api_url, chat_id, "\n".join(lines))
    except Exception as e:
        send_msg(api_url, chat_id, f"❌ Error: {e}")
    return jsonify({"ok": True})

def handle_set_user_block_status_direct(chat_id, user_id_text, block_status: bool, api_url):
    try:
        target_uid = int(user_id_text)
    except: return jsonify({"ok": True})
    if target_uid in ADMIN_IDS and block_status:
        send_msg(api_url, chat_id, "🚫 Cannot block Super Admin.")
        return jsonify({"ok": True})
    
    updated = sb_update("users", {"blocked": 1 if block_status else 0}, {"tg_id": target_uid})
    action = "BLOCKED" if block_status else "UNBLOCKED"
    if updated: send_msg(api_url, chat_id, f"✅ User <code>{target_uid}</code> successfully {action}.")
    else: send_msg(api_url, chat_id, f"⚠️ Failed to update user status.")
    return jsonify({"ok": True})

def handle_broadcast_do(uid, chat_id, message_text, api_url):
    try:
        rows = sb_select("users", {"blocked": 0}, select="tg_id")
        total = len(rows)
        ok = 0
        send_msg(api_url, chat_id, f"📣 Starting broadcast to {total} users...")
        for r in rows:
            success, _ = send_msg(MAIN_BOT_API, r["tg_id"], f"📣 <b>Broadcast</b>\n\n{message_text}")
            if success: ok += 1
        send_msg(api_url, chat_id, f"✅ Broadcast finished.\nDelivered: {ok}/{total}.")
    except Exception as e:
        send_msg(api_url, chat_id, f"❌ Broadcast failed: {e}")
    return jsonify({"ok": True})

def handle_add_admin_id(uid, chat_id, text, api_url):
    try:
        new_id = int(text)
        r = sb_select("users", {"tg_id": new_id}, single=True, select="username")
        uname = r["username"] if r and r["username"] else None
        if is_admin(new_id):
            send_msg(api_url, chat_id, f"⚠️ User ID <code>{new_id}</code> is already Authorized.")
        else:
            sb_insert("admins", {"tg_id": new_id, "username": uname})
            send_msg(api_url, chat_id, f"✅ User ID <code>{new_id}</code> added as <b>Authorized</b>.")
    except:
        send_msg(api_url, chat_id, "❌ Failed to add admin.")
    return jsonify({"ok": True})

def handle_remove_admin_id(uid, chat_id, text, api_url):
    try:
        rid = int(text)
        if rid == uid:
            send_msg(api_url, chat_id, "🚫 You cannot remove yourself.")
            return jsonify({"ok": True})
        deleted_count = sb_delete("admins", {"tg_id": rid})
        if deleted_count > 0:
            send_msg(api_url, chat_id, f"✅ User ID <code>{rid}</code> removed from Authorized.")
        else:
            send_msg(api_url, chat_id, f"❌ User ID <code>{rid}</code> not found.")
    except:
        send_msg(api_url, chat_id, "❌ Error removing admin.")
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
    """Single tweet posting task (runs in separate thread)"""
    tweet_id = tweet['id']
    tg_id = tweet['tg_id']
    tweet_text = tweet['tweet_text']
    account_username = tweet['account_username']
    
    print(f"📤 [Thread {threading.current_thread().name}] Processing ID:{tweet_id} → @{account_username}")
    
    if is_blocked(tg_id):
        print(f"    ⚠️ SKIPPED (user blocked)")
        return (tweet_id, False, None, "User blocked", tg_id, account_username)
    
    sb_update("scheduled_tweets", {"post_status": "PROCESSING"}, {"id": tweet_id})
    post_link, error = post_tweet_to_x(tweet_id, tg_id, account_username, tweet_text)
    
    if post_link:
        print(f"    ✅ SUCCESS: {post_link}")
        return (tweet_id, True, post_link, None, tg_id, account_username)
    else:
        print(f"    ❌ FAILED: {error}")
        return (tweet_id, False, None, error, tg_id, account_username)

def check_and_post_scheduled_tweets():
    """Posts all scheduled tweets that are due now."""
    now_utc_for_check = datetime.datetime.now(pytz.utc).replace(microsecond=0)
    now_iso = now_utc_for_check.strftime('%Y-%m-%dT%H:%M:%S')
    
    print(f"\n{'='*70}")
    print(f"🕐 SCHEDULER RUN (CONCURRENT MODE)")
    print(f"    UTC Time: {now_iso}")
    print(f"{'='*70}")
    
    try:
        encoded_time = quote(now_iso, safe='')
        url = f"{SUPABASE_URL}/rest/v1/scheduled_tweets?select=id,tg_id,tweet_text,account_username,scheduled_time&post_status=eq.PENDING&scheduled_time=lte.{encoded_time}&order=scheduled_time.asc"
        r = fast_session.get(url, headers=SB_HEADERS, timeout=10)
        tweets_to_post = r.json()
        print(f"✅ Found {len(tweets_to_post)} tweets ready to post")
        if not tweets_to_post: return 0
    except Exception as e:
        print(f"❌ Fetch failed: {e}")
        return 0

    posted_count = 0
    futures = []
    
    print(f"\n⚡ MAXIMUM SPEED MODE: Posting {len(tweets_to_post)} tweets with {min(len(tweets_to_post), 50)} parallel threads...\n")
    
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
        except Exception as e:
            print(f"❌ Error processing result: {e}")
            
    print(f"\n{'='*70}\n")
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
        except Exception as e:
            print(f"Web access validation error: {e}")
            return jsonify({"status": "error", "message": "Internal error"}), 500
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
        tg_id = key_row['tg_id']
        sb_delete("web_keys", {"key": web_key})
        if sb_select("web_users", {"email": email}, single=True): return jsonify({"status": "error", "message": "Email registered."}), 409
        sb_insert("web_users", { "email": email, "password_hash": hash_password(password), "tg_id": tg_id, "created_at": now_utc_iso() })
        send_msg(MAIN_BOT_API, tg_id, "✅ **Web Account Linked!** You can now log in.")
        return jsonify({"status": "ok", "message": "Sign up successful."}), 201
    except Exception as e:
        print(f"API signup failed: {e}")
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
    except Exception as e:
        print(f"API login failed: {e}")
        return jsonify({"status": "error", "message": "Server error"}), 500

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
    except Exception as e:
        print(f"API forgot password failed: {e}")
        return jsonify({"status": "error", "message": "Error"}), 500

@app.route("/api/verify_forgot_code", methods=["POST"])
def api_verify_forgot_code():
    data = request.json
    email = data.get('email', '').strip().lower()
    code = data.get('code')
    try:
        row = sb_select("forgot_password_codes", {"email": email, "code": code}, single=True, select="expires_at")
        if not row: return jsonify({"status": "error", "message": "Invalid code"}), 401
        expires = datetime.datetime.fromisoformat(row["expires_at"]).replace(tzinfo=pytz.utc)
        if expires < datetime.datetime.now(pytz.utc):
            sb_delete("forgot_password_codes", {"email": email})
            return jsonify({"status": "error", "message": "Code expired."}), 401
        return jsonify({"status": "ok", "message": "Verified"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": "Error"}), 500

@app.route("/api/reset_password", methods=["POST"])
def api_reset_password():
    data = request.json
    email = data.get('email', '').strip().lower()
    code = data.get('code')
    new_password = data.get('new_password')
    try:
        row = sb_select("forgot_password_codes", {"email": email, "code": code}, single=True, select="tg_id")
        if not row: return jsonify({"status": "error", "message": "Invalid code"}), 401
        sb_update("web_users", {"password_hash": hash_password(new_password)}, {"email": email})
        sb_delete("forgot_password_codes", {"email": email})
        send_msg(MAIN_BOT_API, row['tg_id'], "✅ Password updated.")
        return jsonify({"status": "ok", "message": "Password reset"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": "Error"}), 500

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

# ◀️ RESTORED: Get single account details for editing
@app.route("/api/get_account_details/<string:username>", methods=["GET"])
@validate_web_access
def api_get_account_details(tg_id, username):
    accounts = get_user_x_accounts(tg_id)
    account = next((acc for acc in accounts if acc['username'].lower() == username.lower()), None)
    if account: return jsonify(account), 200
    else: return jsonify({"status": "error", "message": "Account not found or not owned by user"}), 404

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

# ◀️ RESTORED: Delete ALL tweets
@app.route("/api/delete_all_tweets", methods=["POST"])
@validate_web_access
def api_delete_all_tweets(tg_id):
    try:
        delete_params = { "tg_id": tg_id, "post_status": "neq.POSTED" }
        deleted_count = sb_delete("scheduled_tweets", delete_params)
        return jsonify({"status": "ok", "message": f"Deleted {deleted_count} tweets."}), 200
    except Exception as e:
        print(f"API delete all tweets failed: {e}")
        return jsonify({"status": "error", "message": "Database error"}), 500

# ◀️ RESTORED: Post ALL tweets instantly
@app.route("/api/post_all_tweets_now", methods=["POST"])
@validate_web_access
def api_post_all_tweets_now(tg_id):
    tweets = get_unscheduled_tweets(tg_id)
    accounts = get_user_x_accounts(tg_id)

    if not tweets: return jsonify({"status": "error", "message": "No pending tweets found."}), 400
    if not accounts: return jsonify({"status": "error", "message": "No linked accounts found."}), 400

    if len(accounts) > 250: accounts = accounts[:250]

    count_to_post = min(len(tweets), len(accounts))
    tweets_to_post = tweets[:count_to_post]
    tweets_to_delete = tweets[count_to_post:]

    print(f"\n⚡ INSTANT POST: User {tg_id} posting {count_to_post} tweets concurrently...")

    futures = []
    for i in range(count_to_post):
        tweet_data = tweets_to_post[i]
        account_data = accounts[i]
        task_payload = {
            "id": tweet_data['id'], "tg_id": tg_id,
            "tweet_text": tweet_data['tweet_text'], "account_username": account_data['username']
        }
        futures.append(posting_executor.submit(post_single_tweet_task, task_payload))

    posted_count = 0
    failed_count = 0
    
    link_bot_chat_ids = []
    try:
        url = f"{SUPABASE_URL}/rest/v1/user_link_bot_connections?select=link_bot_chat_id&main_bot_tg_id=eq.{tg_id}&link_bot_chat_id=not.is.null"
        r = fast_session.get(url, headers=SB_HEADERS, timeout=5)
        if r.status_code == 200: link_bot_chat_ids = [row.get('link_bot_chat_id') for row in r.json() if row.get('link_bot_chat_id')]
    except: pass

    for future in as_completed(futures):
         tweet_id, success, post_link, error, uid, username = future.result()
         if success:
             posted_count += 1
             sb_update("scheduled_tweets", {"post_status": "POSTED", "post_link": post_link, "account_username": username, "scheduled_time": now_utc_iso()}, {"id": tweet_id})
             for chat_id in link_bot_chat_ids: send_msg(LINK_BOT_API, chat_id, post_link)
         else:
             failed_count += 1
             sb_update("scheduled_tweets", {"post_status": "FAILED", "account_username": username}, {"id": tweet_id})

    deleted_count = 0
    if tweets_to_delete:
        ids_to_delete = [t['id'] for t in tweets_to_delete]
        ids_param = f"in.({','.join(map(str, ids_to_delete))})"
        deleted_count = sb_delete("scheduled_tweets", {"id": ids_param, "tg_id": tg_id, "post_status": "PENDING"})

    summary_msg = f"⚡ <b>Instant Post Summary</b>\n\n✅ Posted: {posted_count}\n❌ Failed: {failed_count}\n🗑️ Deleted Extras: {deleted_count}"
    send_msg(MAIN_BOT_API, tg_id, summary_msg)

    return jsonify({ "status": "ok", "message": "Instant post complete.", "posted": posted_count, "failed": failed_count, "deleted": deleted_count })

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

if __name__ == "__main__":
    setup_webhooks()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
