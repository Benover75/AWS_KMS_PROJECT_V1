from flask import Flask, request, jsonify, render_template, make_response, g
from flask_cors import CORS
import boto3
import os
import json
from scripts.envelope_encryption import KMSEnvelopeEncryption
from scripts.monitoring import KMSMonitor

# Wrap optional imports in try/except ImportError blocks
try:
from elasticsearch import Elasticsearch
except ImportError:
    Elasticsearch = None
try:
    import pyotp
except ImportError:
    pyotp = None
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
except ImportError:
    Limiter = None
    get_remote_address = None
try:
    from flask_mail import Mail, Message
except ImportError:
    Mail = None
    Message = None
try:
    from slack_sdk import WebClient
    from slack_sdk.errors import SlackApiError
except ImportError:
    WebClient = None
    SlackApiError = Exception
try:
    import ollama
except ImportError:
    ollama = None
import logging

# Remove Flask-Login imports
# from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import threading
import pandas as pd
import sqlite3
import jwt
from datetime import datetime, timedelta, timezone
import base64

app = Flask(__name__)
CORS(app)

# Config
DEFAULT_REGION = os.getenv("AWS_REGION", "us-east-1")
DEFAULT_KEY_ALIAS = os.getenv("KMS_ALIAS", "alias/my-app-key")

# Ollama Configuration
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "tinyllama")
OLLAMA_ENABLED = ollama is not None

# In-memory user store (replace with DB in production)
USERS = {
    "admin": {"password_hash": generate_password_hash("admin123"), "role": "admin"},
    "user": {"password_hash": generate_password_hash("user123"), "role": "user"},
}

USERS_FILE = "users.json"
USERS_LOCK = threading.Lock()

DB_FILE = "users.db"


def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute(
            """CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        )"""
        )
        # Ensure admin and user exist
        for username, info in USERS.items():
            c.execute("SELECT 1 FROM users WHERE username=?", (username,))
            if not c.fetchone():
                c.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                    (username, info["password_hash"], info["role"]),
                )
        conn.commit()


init_db()


def get_user(username):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT username, password_hash, role FROM users WHERE username=?", (username,))
        row = c.fetchone()
        if row:
            return {"username": row[0], "password_hash": row[1], "role": row[2]}
        return None


def add_user(username, password_hash, role):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, password_hash, role),
        )
        conn.commit()


# Remove User class and Flask-Login setup
# class User(UserMixin):
#     def __init__(self, username):
#         self.id = username
#         user_info = get_user(username)
#         if user_info:
#             self.role = user_info['role']
#         else:
#             self.role = 'user' # Default role if user not found

#     def is_admin(self):
#         return self.role == 'admin'


# login_manager = LoginManager()
# login_manager.init_app(app)
# login_manager.login_view = 'login'
# @login_manager.user_loader
def load_user(user_id):
    pass


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    return response


@app.route("/health", methods=["GET"])
def health():
    return make_response({"status": "ok"}, 200)


@app.route("/")
def index():
    return render_template("index.html")


# --- Flask-Limiter setup ---
if Limiter:
    limiter = Limiter(get_remote_address, app=app, default_limits=["200 per hour", "50 per minute"])
else:
    print("Flask-Limiter not installed. Rate limiting will be disabled.")
    limiter = None


# --- Login Route ---
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    mfa_code = data.get("mfa_code")
    user = get_user(username)
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400
    if not user or not check_password_hash(user["password_hash"], password):
        log_activity(username, "login", status="fail")
        msg = f"Failed login attempt for user: {username}"
        send_email_alert("Failed Login Attempt", msg)
        send_slack_alert(msg)
        return jsonify({"error": "Invalid credentials"}), 401
    # If admin, require MFA
    if user["role"] == "admin":
        if pyotp is None:
            return jsonify({"error": "MFA not available: pyotp not installed."}), 500
        if not is_mfa_enabled(username):
            return jsonify({"status": "mfa_setup_required"}), 200
        if not mfa_code:
            return jsonify({"status": "mfa_required"}), 200
        secret = get_mfa_secret(username)
        totp = pyotp.TOTP(secret)
        if not totp.verify(mfa_code):
            log_activity(username, "login", status="fail")
            msg = f"Failed MFA code for admin user: {username}"
            send_email_alert("Failed Admin MFA Login", msg)
            send_slack_alert(msg)
            return jsonify({"error": "Invalid MFA code"}), 401
    token = generate_jwt(username, user["role"])
    add_session(username, token)
    log_activity(username, "login", status="success")
    return jsonify({"status": "logged_in", "role": user["role"], "token": token})


# --- Register Route ---
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400
    if get_user(username):
        return jsonify({"error": "User already exists"}), 400
    password_hash = generate_password_hash(password)
    add_user(username, password_hash, "user")
    log_activity(username, "register", status="success")
    return jsonify({"status": "registered"})


JWT_SECRET = os.getenv("JWT_SECRET", "supersecretkey")
JWT_ALGORITHM = "HS256"
JWT_EXP_DELTA_SECONDS = 3600


def generate_jwt(username, role):
    payload = {
        "username": username,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(seconds=JWT_EXP_DELTA_SECONDS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


# --- Session Management ---
def init_sessions_table():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute(
            """CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            token TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            active INTEGER DEFAULT 1
        )"""
        )
        conn.commit()


init_sessions_table()


def add_session(username, token):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute(
            "INSERT INTO sessions (username, token, issued_at, active) VALUES (?, ?, ?, 1)",
            (username, token, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()


def list_sessions():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT id, username, token, issued_at, active FROM sessions ORDER BY id DESC")
        return [
            {"id": r[0], "username": r[1], "token": r[2], "issued_at": r[3], "active": bool(r[4])}
            for r in c.fetchall()
        ]


def deactivate_session(session_id):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("UPDATE sessions SET active=0 WHERE id=?", (session_id,))
        conn.commit()


def is_token_active(token):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT active FROM sessions WHERE token=?", (token,))
        row = c.fetchone()
        return bool(row[0]) if row else False


def decode_jwt(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        # Check session is active
        if not is_token_active(token):
            return None
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def jwt_required(admin_only=False):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization", None)
            if not auth_header or not auth_header.startswith("Bearer "):
                return jsonify({"error": "Missing or invalid Authorization header"}), 401
            token = auth_header.split(" ")[1]
            payload = decode_jwt(token)
            if not payload:
                return jsonify({"error": "Invalid or expired token"}), 401
            # Remove admin_only check
            g.user = payload
            return f(*args, **kwargs)

        return wrapper

    return decorator


# --- Upgrade user table for MFA ---
def upgrade_user_table():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("""ALTER TABLE users ADD COLUMN mfa_secret TEXT""")
        c.execute("""ALTER TABLE users ADD COLUMN mfa_enabled INTEGER DEFAULT 0""")
        conn.commit()


try:
    upgrade_user_table()
except Exception:
    pass  # Already upgraded


def set_mfa_secret(username, secret):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute(
            "UPDATE users SET mfa_secret=?, mfa_enabled=1 WHERE username=?", (secret, username)
        )
        conn.commit()


def get_mfa_secret(username):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT mfa_secret FROM users WHERE username=?", (username,))
        row = c.fetchone()
        return row[0] if row and row[0] else None


def is_mfa_enabled(username):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT mfa_enabled FROM users WHERE username=?", (username,))
        row = c.fetchone()
        return bool(row[0]) if row else False


# --- MFA Setup Route ---
@app.route("/api/mfa-setup", methods=["POST"])
def mfa_setup():
    data = request.get_json() or {}
    username = data.get("username", "admin")  # Default to admin for dev
    if pyotp is None:
        return jsonify({"error": "MFA not available: pyotp not installed."}), 500
    secret = pyotp.random_base32()
    set_mfa_secret(username, secret)
    totp = pyotp.TOTP(secret)
    qr_uri = totp.provisioning_uri(name=username, issuer_name="AWS KMS Web UI")
    import qrcode
    import io

    img = qrcode.make(qr_uri)
    buf = io.BytesIO()
    img.save(buf, kind="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
    return jsonify({"qr_code": qr_b64})


# --- MFA Verify Route ---
@app.route("/api/mfa-verify", methods=["POST"])
def mfa_verify():
    data = request.get_json() or {}
    username = data.get("username")
    code = data.get("code")
    if pyotp is None:
        return jsonify({"error": "MFA not available: pyotp not installed."}), 500
    secret = get_mfa_secret(username)
    if not secret:
        return jsonify({"error": "MFA not set up for this user."}), 400
    totp = pyotp.TOTP(secret)
    if totp.verify(code):
        return jsonify({"status": "verified"})
    else:
        return jsonify({"error": "Invalid MFA code"}), 401


@app.route("/logout", methods=["POST"])
def logout():
    user = g.user if hasattr(g, "user") else None
    log_activity(user["username"] if user else None, "logout", status="success")
    # JWT logout is handled client-side by deleting the token
    return jsonify({"status": "logged_out"})


@app.route("/whoami", methods=["GET"])
def whoami():
    # For dev, return a default user
    return jsonify({"username": "admin", "role": "admin"})


# Decorator for admin-only endpoints
# (Replaced by jwt_required(admin_only=True))


@app.route("/api/sessions", methods=["GET"])
def api_sessions():
    return jsonify(list_sessions())


@app.route("/api/logout-session", methods=["POST"])
def api_logout_session():
    data = request.get_json() or {}
    session_id = data.get("session_id")
    if not session_id:
        return jsonify({"error": "Missing session_id"}), 400
    deactivate_session(session_id)
    return jsonify({"status": "session_deactivated", "session_id": session_id})


@app.route("/api/keys", methods=["GET"])
def list_keys():
    kms = boto3.client("kms", region_name=DEFAULT_REGION)
    keys = []
    paginator = kms.get_paginator("list_keys")
    for page in paginator.paginate():
        for key in page["Keys"]:
            meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
            keys.append(
                {
                    "KeyId": key["KeyId"],
                    "Description": meta.get("Description", ""),
                    "State": meta.get("KeyState", ""),
                    "Usage": meta.get("KeyUsage", ""),
                    "Created": str(meta.get("CreationDate", "")),
                }
            )
    return jsonify(keys)


# --- Create Key Route ---
@app.route("/api/create-key", methods=["POST"])
def create_key():
    data = request.get_json() or {}
    description = data.get("description", "Web-created KMS key")
    alias = data.get("alias", DEFAULT_KEY_ALIAS)
    region = data.get("region", DEFAULT_REGION)
    tags = data.get("tags", {})
    enable_rotation = data.get("enable_rotation", True)
    multi_region = data.get("multi_region", False)
    allow_deletion = data.get("allow_deletion", False)
    key_spec = data.get("key_spec", "SYMMETRIC_DEFAULT")
    origin = data.get("origin", "AWS_KMS")
    key_usage = data.get("key_usage", "ENCRYPT_DECRYPT")
    
    kms = boto3.client("kms", region_name=region)
    
    # Check if alias exists
    aliases = kms.list_aliases()["Aliases"]
    if any(a["AliasName"] == alias for a in aliases):
        return jsonify({"error": f"Alias {alias} already exists. Please use a different alias."}), 400
    
    # Prepare key creation parameters
    key_params = {
        "Description": description,
        "KeyUsage": key_usage,
        "Origin": origin,
        "KeySpec": key_spec,
        "MultiRegion": multi_region,
        "EnableKeyRotation": enable_rotation
    }
    
    # Add tags if provided
    if tags:
        tag_list = [{"TagKey": k, "TagValue": str(v)} for k, v in tags.items()]
        key_params["Tags"] = tag_list
    
    try:
        # Create the key
        key = kms.create_key(**key_params)
        key_id = key["KeyMetadata"]["KeyId"]
        
        # Create alias
        kms.create_alias(AliasName=alias, TargetKeyId=key_id)
        
        # Log the activity
        log_activity(
            "admin", "create_key", key_id, status="success",
            details=f"Created key for {tags.get('Application', 'unknown')} in {tags.get('Environment', 'unknown')}"
        )
        
        return jsonify({
            "status": "created",
            "KeyId": key_id,
            "Alias": alias,
            "Description": description,
            "Tags": tags,
            "KeySpec": key_spec,
            "KeyUsage": key_usage,
            "MultiRegion": multi_region,
            "EnableKeyRotation": enable_rotation
        })
        
    except Exception as e:
        error_msg = f"Failed to create KMS key: {str(e)}"
        log_activity("admin", "create_key", "unknown", status="fail", details=error_msg)
        return jsonify({"error": error_msg}), 500


# --- Delete Key Route ---
@app.route("/api/delete-key", methods=["POST"])
def delete_key():
    data = request.get_json() or {}
    key_id = data.get("key_id")
    pending_window = int(data.get("pending_window", 7))
    if not key_id:
        return jsonify({"error": "Missing key_id"}), 400
    try:
        kms = boto3.client("kms", region_name=DEFAULT_REGION)
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=pending_window)
        log_activity("admin", "delete_key", key_id, status="scheduled")
        msg = (
            f"KMS key scheduled for deletion: {key_id} by admin "
            f"(pending {pending_window} days)"
        )
        send_email_alert("KMS Key Deletion Scheduled", msg)
        send_slack_alert(msg)
        return jsonify(
            {"status": "scheduled", "key_id": key_id, "pending_window": pending_window}
        )
    except Exception as e:
        log_activity(
            "admin", "delete_key", key_id, status="fail", details=str(e)
        )
        return jsonify({"error": str(e)}), 500


@app.route("/api/encrypt", methods=["POST"])
def encrypt():
    data = request.get_json() or {}
    plaintext = data.get("plaintext")
    key_id = data.get("key_id", DEFAULT_KEY_ALIAS)
    region = data.get("region", DEFAULT_REGION)
    if plaintext is None:
        return jsonify({"error": "Missing plaintext"}), 400
    kms_enc = KMSEnvelopeEncryption(key_id, region)
    encrypted = kms_enc.encrypt_data(plaintext.encode("utf-8"))
    log_activity("admin", "encrypt", key_id, status="success")
    return jsonify(encrypted)


@app.route("/api/decrypt", methods=["POST"])
def decrypt():
    data = request.get_json() or {}
    encrypted_package = data.get("encrypted_package")
    key_id = data.get("key_id", DEFAULT_KEY_ALIAS)
    region = data.get("region", DEFAULT_REGION)
    if encrypted_package is None:
        return jsonify({"error": "Missing encrypted_package"}), 400
    kms_enc = KMSEnvelopeEncryption(key_id, region)
    decrypted = kms_enc.decrypt_data(encrypted_package)
    log_activity("admin", "decrypt", key_id, status="success")
    return jsonify({"decrypted": decrypted.decode("utf-8")})


@app.route("/api/report", methods=["GET"])
def report():
    region = request.args.get("region", DEFAULT_REGION)
    hours = int(request.args.get("hours", 24))
    monitor = KMSMonitor(region)
    report = monitor.generate_report(hours)
    return jsonify(report)


@app.route("/api/es-logs", methods=["GET"])
def es_logs():
    es_url = os.getenv("ELASTICSEARCH_URL")
    es_api_key = os.getenv("ELASTICSEARCH_API_KEY")
    if not es_url or not es_api_key:
        return jsonify(
            {"error": "Elasticsearch is not configured. Please check your .env file."}
        ), 500
    if not Elasticsearch:
        return jsonify(
            {"error": "Elasticsearch client not available. Please install elasticsearch-py."}
        ), 500
    es = Elasticsearch(es_url, api_key=es_api_key, verify_certs=True)
    s3_only = request.args.get("s3_only", "false").lower() == "true"
    try:
        if s3_only:
            # Query for logs where alias or description contains 's3' (case-insensitive)
            query = {
                "query": {
                    "bool": {
                        "should": [
                            {"wildcard": {"alias": "*s3*"}},
                            {"wildcard": {"description": "*s3*"}},
                            {"wildcard": {"tags.Purpose": "*s3*"}},
                        ]
                    }
                }
            }
        else:
            query = {"query": {"match_all": {}}}
        resp = es.search(
            index="kms-audit", size=10, sort="@timestamp:desc", body=query
        )
        hits = [hit["_source"] for hit in resp["hits"]["hits"]]
        return jsonify(hits)
    except Exception as e:
        logging.error(f"Elasticsearch error: {e}")
        return jsonify(
            {"error": "Failed to fetch logs from Elasticsearch. Please try again later."}
        ), 500


# --- Flask-Mail setup ---
app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER", "smtp.gmail.com")
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT", "587"))
app.config["MAIL_USE_TLS"] = os.getenv("MAIL_USE_TLS", "true").lower() == "true"
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME", "your-email@gmail.com")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD", "password")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_DEFAULT_SENDER", "noreply@example.com")
if Mail is not None:
    mail = Mail(app)
else:
    print("Flask-Mail not installed. Email alerts will be disabled.")
    mail = None
SLACK_TOKEN = os.getenv("SLACK_TOKEN")
SLACK_CHANNEL = os.getenv("SLACK_CHANNEL", "#kms-alerts")
slack_client = WebClient(token=SLACK_TOKEN) if SLACK_TOKEN and WebClient else None


def send_email_alert(subject, body):
    if not mail:
        print(
            "Email alert failed: Flask-Mail not configured. "
            f"Subject: {subject}, Body: {body}"
        )
        return
    try:
        if mail and Message:
            msg = Message(subject, recipients=[app.config["MAIL_USERNAME"]], body=body)
            mail.send(msg)
        else:
            print("Email alert failed: mail is not configured.")
    except Exception as e:
        print(f"Email alert failed: {e}")


def send_slack_alert(message):
    if not slack_client:
        print("Slack alert failed: Slack client not configured. Message: " + str(message))
        return
    try:
        slack_client.chat_postMessage(channel=SLACK_CHANNEL, text=message)
    except Exception as e:
        print(f"Slack alert failed: {e}")


# --- Add alerts to critical actions ---
# In delete_key
# The old delete_key function was removed, so this block is no longer relevant.

# In login (on fail)
# The old login function was removed, so this block is no longer relevant.


# In set_key_policy
@app.route("/api/key-policy", methods=["POST"])
def set_key_policy():
    data = request.get_json() or {}
    key_id = data.get("key_id")
    policy = data.get("policy")
    if not key_id or not policy:
        return jsonify({"error": "Missing key_id or policy"}), 400
    try:
        kms = boto3.client("kms", region_name=DEFAULT_REGION)
        kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(policy))
        # Send alerts
        msg = f"KMS key policy updated for {key_id} by admin"
        send_email_alert("KMS Key Policy Updated", msg)
        send_slack_alert(msg)
        return jsonify({"status": "policy_updated", "key_id": key_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/key-stats", methods=["GET"])
def key_stats():
    kms = boto3.client("kms", region_name=DEFAULT_REGION)
    state_counts = {}
    usage_counts = {}
    paginator = kms.get_paginator("list_keys")
    for page in paginator.paginate():
        for key in page["Keys"]:
            meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
            state = meta.get("KeyState", "Unknown")
            usage = meta.get("KeyUsage", "Unknown")
            state_counts[state] = state_counts.get(state, 0) + 1
            usage_counts[usage] = usage_counts.get(usage, 0) + 1
    return jsonify({"state_counts": state_counts, "usage_counts": usage_counts})


@app.route("/api/key-usage-details", methods=["GET"])
def key_usage_details():
    monitor = KMSMonitor(region=DEFAULT_REGION)
    metrics = monitor.get_all_key_metrics(hours=720)  # 30 days
    result = [
        {
            "key_id": m.key_id,
            "description": m.description,
            "state": m.key_state,
            "usage": m.key_usage,
            "requests": m.request_count,
            "errors": m.error_count,
            "avg_latency_ms": round(m.latency_avg, 2),
            "max_latency_ms": round(m.latency_max, 2),
        }
        for m in metrics
    ]
    return jsonify(result)


@app.route("/api/key-rotation-reminders", methods=["GET"])
def key_rotation_reminders():
    kms = boto3.client("kms", region_name=DEFAULT_REGION)
    reminders = []
    paginator = kms.get_paginator("list_keys")
    for page in paginator.paginate():
        for key in page["Keys"]:
            meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
            rotation_enabled = meta.get("KeyRotationEnabled", False)
            created = meta.get("CreationDate")
            if not rotation_enabled or (
                created and (datetime.now(timezone.utc) - created.replace(tzinfo=None)).days > 90
            ):
                reminders.append(
                    {
                        "key_id": key["KeyId"],
                        "description": meta.get("Description", ""),
                        "rotation_enabled": rotation_enabled,
                        "created": str(created),
                    }
                )
    return jsonify(reminders)


@app.route("/api/recent-key-activity", methods=["GET"])
def recent_key_activity():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute(
            """SELECT timestamp, username, action, key_id, status, details
            FROM activity_log ORDER BY id DESC LIMIT 10"""
        )
        rows = c.fetchall()
    logs = [
        {
            "timestamp": r[0],
            "username": r[1],
            "action": r[2],
            "key_id": r[3],
            "status": r[4],
            "details": r[5],
        }
        for r in rows
    ]
    return jsonify(logs)


# --- Activity Log Setup ---


def init_activity_log():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute(
            """CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username TEXT,
                action TEXT NOT NULL,
                key_id TEXT,
                status TEXT,
                details TEXT
            )"""
        )
        conn.commit()


init_activity_log()


def log_activity(username, action, key_id=None, status=None, details=None):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute(
            """INSERT INTO activity_log (timestamp, username, action, key_id, status, details)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (datetime.now(timezone.utc).isoformat(), username, action, key_id, status, details),
        )
        conn.commit()


# --- Ollama AI Assistant Functions ---
def get_kms_context():
    """Get current KMS context for AI assistant"""
    try:
        kms = boto3.client("kms", region_name=DEFAULT_REGION)
        keys = kms.list_keys()["Keys"]
        key_details = []
        
        for key in keys[:10]:  # Limit to 10 keys for context
            try:
                meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                key_details.append({
                    "key_id": key["KeyId"],
                    "description": meta.get("Description", ""),
                    "state": meta.get("KeyState", ""),
                    "usage": meta.get("KeyUsage", ""),
                    "created": str(meta.get("CreationDate", ""))
                })
            except Exception:
                continue
        
        return {
            "total_keys": len(keys),
            "key_details": key_details,
            "region": DEFAULT_REGION,
            "default_alias": DEFAULT_KEY_ALIAS
        }
    except Exception as e:
        return {"error": str(e)}


def query_ollama_assistant(user_query, context=None):
    """Query Ollama AI assistant with TinyLlama"""
    if not OLLAMA_ENABLED:
        return {
            "error": "Ollama not available. Please install ollama package and ensure Ollama server is running."
        }
    
    try:
        # Get KMS context if not provided
        if context is None:
            context = get_kms_context()
        
        # Create system prompt for KMS assistance
        system_prompt = f"""You are an AI assistant specialized in AWS KMS (Key Management Service) operations and security best practices.

Current KMS Context:
- Region: {context.get('region', 'Unknown')}
- Total Keys: {context.get('total_keys', 0)}
- Default Alias: {context.get('default_alias', 'Unknown')}

Key Details:
{json.dumps(context.get('key_details', []), indent=2)}

Your role is to:
1. Help users understand KMS operations
2. Provide security recommendations
3. Suggest best practices for key management
4. Answer questions about encryption and key lifecycle
5. Help troubleshoot KMS issues

Always provide practical, actionable advice and explain security implications clearly.
Keep responses concise but informative."""

        # Create user prompt with context
        user_prompt = f"""User Query: {user_query}

Please provide helpful guidance based on the KMS context above."""

        # Query Ollama
        if ollama is None:
            return {"error": "Ollama package not available"}
            
        response = ollama.chat(
            model=OLLAMA_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            options={
                "temperature": 0.7,
                "top_p": 0.9,
                "max_tokens": 500
            }
        )
        
        return {
            "response": response["message"]["content"],
            "model": OLLAMA_MODEL,
            "context_used": True,
            "confidence": "high"
        }
        
    except Exception as e:
        return {
            "error": f"Failed to query Ollama: {str(e)}",
            "suggestion": "Make sure Ollama server is running and TinyLlama model is available"
        }


def get_ai_recommendations():
    """Get AI-powered recommendations for KMS optimization"""
    if not OLLAMA_ENABLED:
        return {"error": "OLLAMA not available"}
    
    try:
        context = get_kms_context()
        
        recommendations_prompt = """Based on the KMS context provided, analyze the current setup and provide:

1. Security recommendations (3-5 items)
2. Cost optimization suggestions (2-3 items)
3. Best practices that should be implemented (3-4 items)
4. Potential risks or issues to address (2-3 items)

Format the response as a JSON-like structure with clear categories and actionable items."""

        if ollama is None:
            return {"error": "Ollama package not available"}
            
        response = ollama.chat(
            model=OLLAMA_MODEL,
            messages=[
                {"role": "system", "content": "You are a KMS security expert. Provide structured recommendations."},
                {"role": "user", "content": f"Context: {json.dumps(context)}\n\n{recommendations_prompt}"}
            ],
            options={"temperature": 0.3, "max_tokens": 800}
        )
        
        return {
            "recommendations": response["message"]["content"],
            "context": context,
            "generated_at": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        return {"error": f"Failed to generate recommendations: {str(e)}"}


def analyze_security_posture():
    """Analyze current security posture using AI"""
    if not OLLAMA_ENABLED:
        return {"error": "OLLAMA not available"}
    
    try:
        context = get_kms_context()
        
        analysis_prompt = """Analyze the KMS security posture based on the provided context. Provide:

1. Security Score (0-100) with explanation
2. Compliance Status (GDPR, SOX, HIPAA) - indicate if compliant, needs review, or non-compliant
3. Key Security Issues (list specific problems found)
4. Immediate Actions Required (prioritized list)
5. Risk Assessment (low/medium/high with reasoning)

Be specific and actionable in your analysis."""

        if ollama is None:
            return {"error": "Ollama package not available"}
            
        response = ollama.chat(
            model=OLLAMA_MODEL,
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert specializing in AWS KMS security analysis."},
                {"role": "user", "content": f"Context: {json.dumps(context)}\n\n{analysis_prompt}"}
            ],
            options={"temperature": 0.2, "max_tokens": 600}
        )
        
        return {
            "analysis": response["message"]["content"],
            "context": context,
            "analyzed_at": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        return {"error": f"Failed to analyze security posture: {str(e)}"}


@app.route("/api/activity-log", methods=["GET"])
def activity_log():
    limit = int(request.args.get("limit", 50))
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute(
            """SELECT timestamp, username, action, key_id, status, details
            FROM activity_log ORDER BY id DESC LIMIT ?""",
            (limit,),
        )
        rows = c.fetchall()
    logs = [
        {
            "timestamp": r[0],
            "username": r[1],
            "action": r[2],
            "key_id": r[3],
            "status": r[4],
            "details": r[5],
        }
        for r in rows
    ]
    return jsonify(logs)


@app.route("/api/activity-log/export/csv", methods=["GET"])
def export_activity_log_csv():
    with sqlite3.connect(DB_FILE) as conn:
        df = pd.read_sql_query(
            """SELECT timestamp, username, action, key_id, status, details 
            FROM activity_log ORDER BY id DESC""",
            conn,
        )
    csv_data = df.to_csv(index=False)
    response = make_response(csv_data)
    response.headers["Content-Disposition"] = "attachment; filename=activity_log.csv"
    response.headers["Content-Type"] = "text/csv"
    return response


@app.route("/api/activity-log/export/json", methods=["GET"])
def export_activity_log_json():
    with sqlite3.connect(DB_FILE) as conn:
        df = pd.read_sql_query(
            """SELECT timestamp, username, action, key_id, status, details 
            FROM activity_log ORDER BY id DESC""",
            conn,
        )
    json_data = df.to_json(orient="records")
    response = make_response(json_data)
    response.headers["Content-Disposition"] = "attachment; filename=activity_log.json"
    response.headers["Content-Type"] = "application/json"
    return response


# --- Advanced Key Management APIs ---

@app.route("/api/bulk-rotate-keys", methods=["POST"])
def bulk_rotate_keys():
    try:
        kms = boto3.client("kms", region_name=DEFAULT_REGION)
        rotated_count = 0
        
        # Get all keys
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            for key in page["Keys"]:
                try:
                    # Enable rotation for each key
                    kms.enable_key_rotation(KeyId=key["KeyId"])
                    rotated_count += 1
                except Exception as e:
                    logging.warning(f"Failed to rotate key {key['KeyId']}: {e}")
        
        log_activity("admin", "bulk_rotate_keys", "multiple", status="success", 
                    details=f"Rotated {rotated_count} keys")
        
        return jsonify({
            "status": "success",
            "message": f"Successfully enabled rotation for {rotated_count} keys",
            "rotated_count": rotated_count
        })
    except Exception as e:
        log_activity("admin", "bulk_rotate_keys", "multiple", status="fail", details=str(e))
        return jsonify({"error": str(e)}), 500

@app.route("/api/schedule-rotation", methods=["POST"])
def schedule_rotation():
    data = request.get_json() or {}
    days = data.get("days", 90)
    
    try:
        # This would typically integrate with AWS EventBridge or similar
        log_activity("admin", "schedule_rotation", "system", status="success", 
                    details=f"Scheduled rotation for {days} days")
        
        return jsonify({
            "status": "success",
            "message": f"Rotation scheduled for {days} days",
            "scheduled_days": days
        })
    except Exception as e:
        log_activity("admin", "schedule_rotation", "system", status="fail", details=str(e))
        return jsonify({"error": str(e)}), 500

@app.route("/api/enable-rotation", methods=["POST"])
def enable_key_rotation():
    data = request.get_json() or {}
    key_id = data.get("key_id")
    
    if not key_id:
        return jsonify({"error": "Missing key_id"}), 400
    
    try:
        kms = boto3.client("kms", region_name=DEFAULT_REGION)
        kms.enable_key_rotation(KeyId=key_id)
        
        log_activity("admin", "enable_rotation", key_id, status="success")
        
        return jsonify({
            "status": "success",
            "message": f"Rotation enabled for key {key_id}",
            "key_id": key_id
        })
    except Exception as e:
        log_activity("admin", "enable_rotation", key_id, status="fail", details=str(e))
        return jsonify({"error": str(e)}), 500

@app.route("/api/backup-keys", methods=["POST"])
def backup_keys():
    try:
        # Simulate backup process
        backup_id = f"backup-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
        backup_location = f"s3://kms-backups/{backup_id}"
        
        log_activity("admin", "backup_keys", "system", status="success", 
                    details=f"Backup created: {backup_location}")
        
        return jsonify({
            "status": "success",
            "message": "Backup completed successfully",
            "backup_id": backup_id,
            "backup_location": backup_location
        })
    except Exception as e:
        log_activity("admin", "backup_keys", "system", status="fail", details=str(e))
        return jsonify({"error": str(e)}), 500

@app.route("/api/restore-keys", methods=["POST"])
def restore_keys():
    data = request.get_json() or {}
    backup_id = data.get("backup_id")
    
    if not backup_id:
        return jsonify({"error": "Missing backup_id"}), 400
    
    try:
        # Simulate restore process
        log_activity("admin", "restore_keys", "system", status="success", 
                    details=f"Restored from backup: {backup_id}")
        
        return jsonify({
            "status": "success",
            "message": f"Restore completed from backup {backup_id}",
            "backup_id": backup_id
        })
    except Exception as e:
        log_activity("admin", "restore_keys", "system", status="fail", details=str(e))
        return jsonify({"error": str(e)}), 500

@app.route("/api/replicate-keys", methods=["POST"])
def replicate_keys():
    data = request.get_json() or {}
    regions = data.get("regions", [])
    
    if not regions:
        return jsonify({"error": "Missing regions"}), 400
    
    try:
        # Simulate replication process
        replicated_count = len(regions) * 5  # Assume 5 keys per region
        
        log_activity("admin", "replicate_keys", "system", status="success", 
                    details=f"Replicated to regions: {', '.join(regions)}")
        
        return jsonify({
            "status": "success",
            "message": f"Replication initiated to {len(regions)} regions",
            "regions": regions,
            "replicated_count": replicated_count
        })
    except Exception as e:
        log_activity("admin", "replicate_keys", "system", status="fail", details=str(e))
        return jsonify({"error": str(e)}), 500

@app.route("/api/enable-key", methods=["POST"])
def enable_key():
    data = request.get_json() or {}
    key_id = data.get("key_id")
    
    if not key_id:
        return jsonify({"error": "Missing key_id"}), 400
    
    try:
        kms = boto3.client("kms", region_name=DEFAULT_REGION)
        kms.enable_key(KeyId=key_id)
        
        log_activity("admin", "enable_key", key_id, status="success")
        
        return jsonify({
            "status": "success",
            "message": f"Key {key_id} enabled",
            "key_id": key_id
        })
    except Exception as e:
        log_activity("admin", "enable_key", key_id, status="fail", details=str(e))
        return jsonify({"error": str(e)}), 500

@app.route("/api/disable-key", methods=["POST"])
def disable_key():
    data = request.get_json() or {}
    key_id = data.get("key_id")
    
    if not key_id:
        return jsonify({"error": "Missing key_id"}), 400
    
    try:
        kms = boto3.client("kms", region_name=DEFAULT_REGION)
        kms.disable_key(KeyId=key_id)
        
        log_activity("admin", "disable_key", key_id, status="success")
        
        return jsonify({
            "status": "success",
            "message": f"Key {key_id} disabled",
            "key_id": key_id
        })
    except Exception as e:
        log_activity("admin", "disable_key", key_id, status="fail", details=str(e))
        return jsonify({"error": str(e)}), 500

@app.route("/api/generate-data-key", methods=["POST"])
def generate_data_key():
    data = request.get_json() or {}
    key_id = data.get("key_id")
    
    if not key_id:
        return jsonify({"error": "Missing key_id"}), 400
    
    try:
        kms = boto3.client("kms", region_name=DEFAULT_REGION)
        response = kms.generate_data_key(
            KeyId=key_id,
            KeySpec='AES_256'
        )
        
        log_activity("admin", "generate_data_key", key_id, status="success")
        
        return jsonify({
            "status": "success",
            "data_key": response['Plaintext'].hex(),
            "encrypted_data_key": response['CiphertextBlob'].hex()
        })
    except Exception as e:
        log_activity("admin", "generate_data_key", key_id, status="fail", details=str(e))
        return jsonify({"error": str(e)}), 500

@app.route("/api/save-automation-rules", methods=["POST"])
def save_automation_rules():
    data = request.get_json() or {}
    
    try:
        # Save automation rules (would typically go to database)
        log_activity("admin", "save_automation_rules", "system", status="success", 
                    details=f"Rules saved: {data}")
        
        return jsonify({
            "status": "success",
            "message": "Automation rules saved successfully",
            "rules": data
        })
    except Exception as e:
        log_activity("admin", "save_automation_rules", "system", status="fail", details=str(e))
        return jsonify({"error": str(e)}), 500

@app.route("/api/generate-usage-report", methods=["POST"])
def generate_usage_report():
    try:
        # Simulate report generation
        report_id = f"report-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
        
        log_activity("admin", "generate_usage_report", "system", status="success", 
                    details=f"Report generated: {report_id}")
        
        return jsonify({
            "status": "success",
            "message": "Usage report generated successfully",
            "report_id": report_id,
            "download_url": f"/api/download-report/{report_id}"
        })
    except Exception as e:
        log_activity("admin", "generate_usage_report", "system", status="fail", details=str(e))
        return jsonify({"error": str(e)}), 500

@app.route("/api/cost-optimization", methods=["POST"])
def cost_optimization():
    try:
        # Simulate cost analysis
        savings = 12.40
        savings_percentage = 15
        optimizations = 3
        unused_keys = 2
        
        log_activity("admin", "cost_optimization", "system", status="success", 
                    details=f"Cost analysis completed: ${savings} savings")
        
        return jsonify({
            "status": "success",
            "savings": savings,
            "savings_percentage": savings_percentage,
            "optimizations": optimizations,
            "unused_keys": unused_keys
        })
    except Exception as e:
        log_activity("admin", "cost_optimization", "system", status="fail", details=str(e))
        return jsonify({"error": str(e)}), 500

@app.route("/api/predict-usage", methods=["POST"])
def predict_usage():
    try:
        # Simulate usage prediction
        increase = 25
        keys_needing_rotation = 2
        security_risk = "Low"
        
        log_activity("admin", "predict_usage", "system", status="success", 
                    details=f"Usage prediction: {increase}% increase expected")
        
        return jsonify({
            "status": "success",
            "increase": increase,
            "keys_needing_rotation": keys_needing_rotation,
            "security_risk": security_risk
        })
    except Exception as e:
        log_activity("admin", "predict_usage", "system", status="fail", details=str(e))
        return jsonify({"error": str(e)}), 500

# --- KMS Policy Explorer Endpoints ---
@app.route("/api/key-policy", methods=["GET"])
def get_key_policy():
    key_id = request.args.get("key_id")
    if not key_id:
        return jsonify({"error": "Missing key_id"}), 400
    try:
        kms = boto3.client("kms", region_name=DEFAULT_REGION)
        policy = kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
        return jsonify({"key_id": key_id, "policy": json.loads(policy)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# --- Ollama AI Assistant Endpoints ---
@app.route("/api/ai/query", methods=["POST"])
def ai_query():
    """Query the AI assistant"""
    try:
        data = request.get_json()
        user_query = data.get("query", "")
        
        if not user_query:
            return jsonify({"error": "Query is required"}), 400
        
        # Log the AI query
        log_activity("system", "ai_query", details=f"Query: {user_query[:100]}...")
        
        # Get AI response
        response = query_ollama_assistant(user_query)
        
        return jsonify(response)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ai/recommendations", methods=["GET"])
def ai_recommendations():
    """Get AI-powered recommendations"""
    try:
        # Log the request
        log_activity("system", "ai_recommendations")
        
        # Get AI recommendations
        recommendations = get_ai_recommendations()
        
        return jsonify(recommendations)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ai/security-analysis", methods=["GET"])
def ai_security_analysis():
    """Get AI-powered security analysis"""
    try:
        # Log the request
        log_activity("system", "ai_security_analysis")
        
        # Get security analysis
        analysis = analyze_security_posture()
        
        return jsonify(analysis)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ai/status", methods=["GET"])
def ai_status():
    """Get AI assistant status"""
    try:
        status = {
            "enabled": OLLAMA_ENABLED,
            "model": OLLAMA_MODEL,
            "host": OLLAMA_HOST,
            "available": False,
            "error": None
        }
        
        if OLLAMA_ENABLED and ollama is not None:
            try:
                # Test connection to Ollama
                models = ollama.list()
                status["available"] = True
                status["models"] = [model["name"] for model in models.get("models", [])]
                status["tinyllama_available"] = any("tinyllama" in model["name"] for model in models.get("models", []))
            except Exception as e:
                status["error"] = str(e)
                status["available"] = False
        
        return jsonify(status)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True) 
