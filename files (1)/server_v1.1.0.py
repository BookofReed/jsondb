#!/usr/bin/env python3
"""
JSON Database Server
A lightweight REST API backed by a JSON file with API key authentication.
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

app = Flask(__name__, static_folder="ui")
CORS(app)

DB_FILE = "data/database.json"
CONFIG_FILE = "data/config.json"


# ─── Persistence helpers ────────────────────────────────────────────────────

def load_db():
    if not os.path.exists(DB_FILE):
        return {"records": {}, "meta": {"created": _now(), "total_records": 0}}
    with open(DB_FILE, "r") as f:
        return json.load(f)

def save_db(db):
    db["meta"]["total_records"] = len(db["records"])
    db["meta"]["last_modified"] = _now()
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2)

def load_config():
    if not os.path.exists(CONFIG_FILE):
        # Bootstrap: create a default admin key on first run
        admin_key = secrets.token_hex(32)
        config = {
            "api_keys": {
                admin_key: {
                    "role": "admin",
                    "label": "Default Admin Key",
                    "created": _now()
                }
            }
        }
        save_config(config)
        print("\n" + "="*60)
        print("  FIRST RUN — ADMIN API KEY GENERATED")
        print(f"  Key: {admin_key}")
        print("  Save this! It won't be shown again.")
        print("="*60 + "\n")
        return config
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)

def _now():
    return datetime.datetime.utcnow().isoformat() + "Z"

# ─── Auth middleware ─────────────────────────────────────────────────────────

def require_api_key(role="reader"):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            key = request.headers.get("X-API-Key") or request.args.get("api_key")
            if not key:
                return jsonify({"error": "Missing API key", "hint": "Pass X-API-Key header or ?api_key= param"}), 401
            config = load_config()
            key_data = config["api_keys"].get(key)
            if not key_data:
                return jsonify({"error": "Invalid API key"}), 403
            role_order = ["reader", "writer", "admin"]
            required_idx = role_order.index(role)
            actual_idx = role_order.index(key_data.get("role", "reader"))
            if actual_idx < required_idx:
                return jsonify({"error": f"Insufficient permissions. '{role}' role required."}), 403
            request.api_role = key_data["role"]
            request.api_label = key_data.get("label", "unknown")
            return f(*args, **kwargs)
        return decorated
    return decorator

# ─── Records API ─────────────────────────────────────────────────────────────

@app.route("/api/records", methods=["GET"])
@require_api_key("reader")
def list_records():
    db = load_db()
    records = list(db["records"].values())
    # Filtering
    filter_key = request.args.get("filter_key")
    filter_val = request.args.get("filter_val")
    if filter_key and filter_val:
        records = [r for r in records if str(r.get("data", {}).get(filter_key, "")).lower() == filter_val.lower()]
    # Pagination — validate inputs to avoid 500 on bad params
    try:
        page = int(request.args.get("page", 1))
        limit = int(request.args.get("limit", 50))
    except ValueError:
        return jsonify({"error": "page and limit must be integers"}), 400
    if page < 1:
        page = 1
    if limit < 1 or limit > 1000:
        limit = 50
    total = len(records)
    start = (page - 1) * limit
    records = records[start:start + limit]
    return jsonify({
        "records": records,
        "pagination": {"page": page, "limit": limit, "total": total, "pages": -(-total // limit)},
        "meta": db["meta"]
    })

@app.route("/api/records/<record_id>", methods=["GET"])
@require_api_key("reader")
def get_record(record_id):
    db = load_db()
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
    db = load_db()
    record_id = body.pop("id", str(uuid.uuid4()))
    if record_id in db["records"]:
        return jsonify({"error": f"Record '{record_id}' already exists. Use PUT to update."}), 409
    record = {
        "id": record_id,
        "data": body,
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
    """PUT replaces the entire data object. Use PATCH for partial updates."""
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Request body must be valid JSON"}), 400
    db = load_db()
    if record_id not in db["records"]:
        return jsonify({"error": f"Record '{record_id}' not found. Use POST to create."}), 404
    existing = db["records"][record_id]
    existing["data"] = body  # Full replacement, not merge
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
    config = load_config()
    # Never return full key values — return masked versions
    safe_keys = []
    for k, v in config["api_keys"].items():
        safe_keys.append({
            "key_preview": k[:8] + "..." + k[-4:],
            "key_hash": hashlib.sha256(k.encode()).hexdigest()[:12],
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
    config = load_config()
    config["api_keys"][new_key] = {
        "role": role,
        "label": body.get("label", f"{role}-key"),
        "created": _now()
    }
    save_config(config)
    return jsonify({"success": True, "key": new_key, "role": role, "warning": "Store this key — it won't be shown again"}), 201

@app.route("/api/admin/keys/<key_hash>", methods=["DELETE"])
@require_api_key("admin")
def delete_key(key_hash):
    config = load_config()
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

# ─── Stats endpoint ───────────────────────────────────────────────────────────

@app.route("/api/stats", methods=["GET"])
@require_api_key("reader")
def stats():
    db = load_db()
    return jsonify({
        "total_records": len(db["records"]),
        "meta": db["meta"],
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
    return jsonify({"status": "ok", "version": "1.1.0"})

if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    os.makedirs("ui", exist_ok=True)
    load_config()  # triggers first-run key generation if needed
    db = load_db()
    if not os.path.exists(DB_FILE):
        save_db(db)  # persist initial DB file on first run
    app.run(host="0.0.0.0", port=5000, debug=False)
