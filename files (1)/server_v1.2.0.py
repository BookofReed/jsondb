#!/usr/bin/env python3
"""
JSON Database Server v1.2.0
REST API backed by a JSON file.
Auth: username/password sessions  +  API key (both accepted simultaneously).
"""

import json
import os
import uuid
import hashlib
import secrets
import datetime
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, static_folder="ui")
CORS(app)

DB_FILE     = "data/database.json"
CONFIG_FILE = "data/config.json"

SESSION_HOURS      = 8
SESSION_DURATION   = SESSION_HOURS * 3600   # seconds
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES    = 15

# In-memory stores — intentionally reset on restart (local-use tool)
_sessions       = {}   # token -> {username, role, label, expires: datetime}
_login_attempts = {}   # username -> {count: int, locked_until: datetime|None}

# Pre-computed dummy hash for constant-time user-not-found checks
_DUMMY_HASH = generate_password_hash("__dummy_constant__")


# ─── Security headers ─────────────────────────────────────────────────────────

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]          = "SAMEORIGIN"
    response.headers["X-XSS-Protection"]         = "1; mode=block"
    response.headers["Referrer-Policy"]          = "strict-origin-when-cross-origin"
    return response


# ─── Persistence helpers ────────────────────────────────────────────────────

def load_db():
    if not os.path.exists(DB_FILE):
        return {"records": {}, "meta": {"created": _now(), "total_records": 0}}
    with open(DB_FILE, "r") as f:
        return json.load(f)

def save_db(db):
    db["meta"]["total_records"] = len(db["records"])
    db["meta"]["last_modified"]  = _now()
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2)

def load_config():
    if not os.path.exists(CONFIG_FILE):
        admin_key      = secrets.token_hex(32)
        admin_password = secrets.token_urlsafe(14)
        config = {
            "api_keys": {
                admin_key: {
                    "role": "admin",
                    "label": "Default Admin Key",
                    "created": _now()
                }
            },
            "users": {
                "admin": {
                    "password_hash": generate_password_hash(admin_password),
                    "role": "admin",
                    "created": _now()
                }
            }
        }
        save_config(config)
        print("\n" + "=" * 60)
        print("  FIRST RUN — CREDENTIALS GENERATED")
        print(f"  Username : admin")
        print(f"  Password : {admin_password}")
        print(f"  API Key  : {admin_key}")
        print("  Save these — they won't be shown again.")
        print("=" * 60 + "\n")
        return config

    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)

    # Migrate pre-v1.2.0 configs that lack a users section
    if "users" not in config:
        admin_password = secrets.token_urlsafe(14)
        config["users"] = {
            "admin": {
                "password_hash": generate_password_hash(admin_password),
                "role": "admin",
                "created": _now()
            }
        }
        save_config(config)
        print("\n" + "=" * 60)
        print("  MIGRATION — ADMIN USER ACCOUNT CREATED")
        print(f"  Username : admin")
        print(f"  Password : {admin_password}")
        print("  Save this — it won't be shown again.")
        print("=" * 60 + "\n")

    return config

def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)

def _now():
    return datetime.datetime.utcnow().isoformat() + "Z"


# ─── Session helpers ─────────────────────────────────────────────────────────

def _clean_sessions():
    """Evict expired sessions from memory."""
    now     = datetime.datetime.utcnow()
    expired = [t for t, s in _sessions.items() if now > s["expires"]]
    for t in expired:
        del _sessions[t]


# ─── Auth middleware ─────────────────────────────────────────────────────────

def require_api_key(role="reader"):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            _clean_sessions()

            # ── Session token ────────────────────────────────────────────────
            token = request.headers.get("X-Session-Token")
            if token:
                session = _sessions.get(token)
                if not session:
                    return jsonify({"error": "Session invalid or expired. Please log in again."}), 401
                role_order   = ["reader", "writer", "admin"]
                required_idx = role_order.index(role)
                actual_idx   = role_order.index(session.get("role", "reader"))
                if actual_idx < required_idx:
                    return jsonify({"error": f"Insufficient permissions. '{role}' role required."}), 403
                request.api_role  = session["role"]
                request.api_label = session["label"]
                return f(*args, **kwargs)

            # ── API key ──────────────────────────────────────────────────────
            key = request.headers.get("X-API-Key") or request.args.get("api_key")
            if not key:
                return jsonify({
                    "error": "Missing authentication",
                    "hint":  "Send X-Session-Token (login) or X-API-Key header"
                }), 401
            config   = load_config()
            key_data = config["api_keys"].get(key)
            if not key_data:
                return jsonify({"error": "Invalid API key"}), 403
            role_order   = ["reader", "writer", "admin"]
            required_idx = role_order.index(role)
            actual_idx   = role_order.index(key_data.get("role", "reader"))
            if actual_idx < required_idx:
                return jsonify({"error": f"Insufficient permissions. '{role}' role required."}), 403
            request.api_role  = key_data["role"]
            request.api_label = key_data.get("label", "unknown")
            return f(*args, **kwargs)
        return decorated
    return decorator


# ─── Auth endpoints ──────────────────────────────────────────────────────────

@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    username = str(body.get("username", "")).strip().lower()
    password = str(body.get("password", ""))

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    now = datetime.datetime.utcnow()

    # Rate limiting
    attempt     = _login_attempts.get(username, {"count": 0, "locked_until": None})
    locked_until = attempt.get("locked_until")
    if locked_until:
        if now < locked_until:
            remaining = int((locked_until - now).total_seconds())
            return jsonify({"error": f"Too many failed attempts. Try again in {remaining}s."}), 429
        else:
            # Lockout window passed — reset
            _login_attempts.pop(username, None)
            attempt = {"count": 0, "locked_until": None}

    config = load_config()
    user   = config.get("users", {}).get(username)

    # Always run a hash check regardless of whether the user exists.
    # This prevents user-enumeration via response timing.
    hash_to_check = user["password_hash"] if user else _DUMMY_HASH
    valid = check_password_hash(hash_to_check, password) and (user is not None)

    if not valid:
        attempt["count"] = attempt.get("count", 0) + 1
        if attempt["count"] >= MAX_LOGIN_ATTEMPTS:
            attempt["locked_until"] = now + datetime.timedelta(minutes=LOCKOUT_MINUTES)
            attempt["count"] = 0
            _login_attempts[username] = attempt
            return jsonify({
                "error": f"Too many failed attempts. Account locked for {LOCKOUT_MINUTES} minutes."
            }), 429
        _login_attempts[username] = attempt
        remaining_attempts = MAX_LOGIN_ATTEMPTS - attempt["count"]
        return jsonify({
            "error": "Invalid username or password",
            "attempts_remaining": remaining_attempts
        }), 401

    # Success
    _login_attempts.pop(username, None)
    token = secrets.token_hex(32)
    _sessions[token] = {
        "username": username,
        "role":     user["role"],
        "label":    f"user:{username}",
        "expires":  now + datetime.timedelta(seconds=SESSION_DURATION)
    }

    return jsonify({
        "success":    True,
        "token":      token,
        "username":   username,
        "role":       user["role"],
        "expires_in": SESSION_DURATION
    })


@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    token = request.headers.get("X-Session-Token")
    if token and token in _sessions:
        del _sessions[token]
    return jsonify({"success": True})


@app.route("/api/auth/me", methods=["GET"])
@require_api_key("reader")
def auth_me():
    return jsonify({
        "label": request.api_label,
        "role":  request.api_role
    })


# ─── Records API ─────────────────────────────────────────────────────────────

@app.route("/api/records", methods=["GET"])
@require_api_key("reader")
def list_records():
    db      = load_db()
    records = list(db["records"].values())
    filter_key = request.args.get("filter_key")
    filter_val = request.args.get("filter_val")
    if filter_key and filter_val:
        records = [r for r in records
                   if str(r.get("data", {}).get(filter_key, "")).lower() == filter_val.lower()]
    try:
        page  = int(request.args.get("page", 1))
        limit = int(request.args.get("limit", 50))
    except ValueError:
        return jsonify({"error": "page and limit must be integers"}), 400
    if page  < 1:            page  = 1
    if limit < 1 or limit > 1000: limit = 50
    total   = len(records)
    start   = (page - 1) * limit
    records = records[start:start + limit]
    return jsonify({
        "records":    records,
        "pagination": {"page": page, "limit": limit, "total": total, "pages": -(-total // limit)},
        "meta":       db["meta"]
    })

@app.route("/api/records/<record_id>", methods=["GET"])
@require_api_key("reader")
def get_record(record_id):
    db     = load_db()
    record = db["records"].get(record_id)
    if not record:
        return jsonify({"error": f"Record '{record_id}' not found"}), 404
    return jsonify(record)

@app.route("/api/records", methods=["POST"])
@require_api_key("writer")
def create_record():
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Request body must be valid JSON"}), 400
    db        = load_db()
    record_id = body.pop("id", str(uuid.uuid4()))
    if record_id in db["records"]:
        return jsonify({"error": f"Record '{record_id}' already exists. Use PUT to update."}), 409
    record = {
        "id":         record_id,
        "data":       body,
        "created_at": _now(),
        "updated_at": _now(),
        "created_by": request.api_label
    }
    db["records"][record_id] = record
    save_db(db)
    return jsonify({"success": True, "record": record}), 201

@app.route("/api/records/<record_id>", methods=["PUT"])
@require_api_key("writer")
def update_record(record_id):
    """PUT replaces the entire data object."""
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Request body must be valid JSON"}), 400
    db = load_db()
    if record_id not in db["records"]:
        return jsonify({"error": f"Record '{record_id}' not found. Use POST to create."}), 404
    existing = db["records"][record_id]
    existing["data"]       = body
    existing["updated_at"] = _now()
    existing["updated_by"] = request.api_label
    save_db(db)
    return jsonify({"success": True, "record": existing})

@app.route("/api/records/<record_id>", methods=["PATCH"])
@require_api_key("writer")
def patch_record(record_id):
    """PATCH merges specific fields only, leaving others intact."""
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Request body must be valid JSON"}), 400
    db = load_db()
    if record_id not in db["records"]:
        return jsonify({"error": f"Record '{record_id}' not found"}), 404
    db["records"][record_id]["data"].update(body)
    db["records"][record_id]["updated_at"] = _now()
    db["records"][record_id]["updated_by"] = request.api_label
    save_db(db)
    return jsonify({"success": True, "record": db["records"][record_id]})

@app.route("/api/records/<record_id>", methods=["DELETE"])
@require_api_key("writer")
def delete_record(record_id):
    db = load_db()
    if record_id not in db["records"]:
        return jsonify({"error": f"Record '{record_id}' not found"}), 404
    deleted = db["records"].pop(record_id)
    save_db(db)
    return jsonify({"success": True, "deleted": deleted})


# ─── Admin: API key management ───────────────────────────────────────────────

@app.route("/api/admin/keys", methods=["GET"])
@require_api_key("admin")
def list_keys():
    config    = load_config()
    safe_keys = []
    for k, v in config["api_keys"].items():
        safe_keys.append({
            "key_preview": k[:8] + "..." + k[-4:],
            "key_hash":    hashlib.sha256(k.encode()).hexdigest()[:12],
            **v
        })
    return jsonify({"keys": safe_keys})

@app.route("/api/admin/keys", methods=["POST"])
@require_api_key("admin")
def create_key():
    body = request.get_json(silent=True) or {}
    role = body.get("role", "reader")
    if role not in ["reader", "writer", "admin"]:
        return jsonify({"error": "role must be reader, writer, or admin"}), 400
    new_key = secrets.token_hex(32)
    config  = load_config()
    config["api_keys"][new_key] = {
        "role":    role,
        "label":   body.get("label", f"{role}-key"),
        "created": _now()
    }
    save_config(config)
    return jsonify({
        "success": True, "key": new_key, "role": role,
        "warning": "Store this key — it won't be shown again"
    }), 201

@app.route("/api/admin/keys/<key_hash>", methods=["DELETE"])
@require_api_key("admin")
def delete_key(key_hash):
    config    = load_config()
    to_delete = None
    for k in config["api_keys"]:
        if hashlib.sha256(k.encode()).hexdigest()[:12] == key_hash:
            to_delete = k
            break
    if not to_delete:
        return jsonify({"error": "Key not found"}), 404
    if config["api_keys"][to_delete]["role"] == "admin" and \
       sum(1 for v in config["api_keys"].values() if v["role"] == "admin") <= 1:
        return jsonify({"error": "Cannot delete the last admin key"}), 400
    del config["api_keys"][to_delete]
    save_config(config)
    return jsonify({"success": True})


# ─── Admin: User management ──────────────────────────────────────────────────

@app.route("/api/admin/users", methods=["GET"])
@require_api_key("admin")
def list_users():
    config = load_config()
    users  = [
        {"username": uname, "role": udata["role"], "created": udata.get("created", "")}
        for uname, udata in config.get("users", {}).items()
    ]
    return jsonify({"users": users})

@app.route("/api/admin/users", methods=["POST"])
@require_api_key("admin")
def create_user():
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    username = str(body.get("username", "")).strip().lower()
    password = str(body.get("password", ""))
    role     = body.get("role", "reader")

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400
    if len(username) < 3 or len(username) > 32:
        return jsonify({"error": "username must be 3–32 characters"}), 400
    if not all(c.isalnum() or c in "-_" for c in username):
        return jsonify({"error": "username may only contain letters, numbers, hyphens, underscores"}), 400
    if len(password) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400
    if role not in ["reader", "writer", "admin"]:
        return jsonify({"error": "role must be reader, writer, or admin"}), 400

    config = load_config()
    if username in config.get("users", {}):
        return jsonify({"error": f"User '{username}' already exists"}), 409

    config.setdefault("users", {})[username] = {
        "password_hash": generate_password_hash(password),
        "role":          role,
        "created":       _now()
    }
    save_config(config)
    return jsonify({"success": True, "username": username, "role": role}), 201

@app.route("/api/admin/users/<username>", methods=["DELETE"])
@require_api_key("admin")
def delete_user(username):
    config = load_config()
    users  = config.get("users", {})
    if username not in users:
        return jsonify({"error": f"User '{username}' not found"}), 404
    admin_count = sum(1 for u in users.values() if u["role"] == "admin")
    if users[username]["role"] == "admin" and admin_count <= 1:
        return jsonify({"error": "Cannot delete the last admin user"}), 400
    del config["users"][username]
    save_config(config)
    # Invalidate any active sessions for this user
    to_remove = [t for t, s in _sessions.items() if s.get("username") == username]
    for t in to_remove:
        del _sessions[t]
    return jsonify({"success": True})

@app.route("/api/admin/users/<username>/password", methods=["PUT"])
@require_api_key("admin")
def set_user_password(username):
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Request body must be valid JSON"}), 400
    password = str(body.get("password", ""))
    if len(password) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400
    config = load_config()
    if username not in config.get("users", {}):
        return jsonify({"error": f"User '{username}' not found"}), 404
    config["users"][username]["password_hash"] = generate_password_hash(password)
    save_config(config)
    # Force re-login after password change
    to_remove = [t for t, s in _sessions.items() if s.get("username") == username]
    for t in to_remove:
        del _sessions[t]
    return jsonify({"success": True})


# ─── Stats endpoint ───────────────────────────────────────────────────────────

@app.route("/api/stats", methods=["GET"])
@require_api_key("reader")
def stats():
    db = load_db()
    return jsonify({
        "total_records": len(db["records"]),
        "meta":          db["meta"],
        "db_size_bytes": os.path.getsize(DB_FILE) if os.path.exists(DB_FILE) else 0
    })


# ─── UI serving ───────────────────────────────────────────────────────────────

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_ui(path):
    if path and os.path.exists(os.path.join("ui", path)):
        return send_from_directory("ui", path)
    return send_from_directory("ui", "index.html")


# ─── Health check ─────────────────────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": "1.2.0"})


if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    os.makedirs("ui", exist_ok=True)
    load_config()
    db = load_db()
    if not os.path.exists(DB_FILE):
        save_db(db)
    app.run(host="0.0.0.0", port=5000, debug=False)
