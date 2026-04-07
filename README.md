# JSON Database Server

A lightweight, locally-running REST API database backed by a JSON file.
Includes API key authentication (reader / writer / admin roles) and a browser-based admin UI.

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the server
python server.py
```

On first run, an admin API key is printed to the terminal. **Save it immediately.**

- **API**: http://localhost:5000/api
- **Admin UI**: http://localhost:5000

---

## Authentication

All endpoints require an `X-API-Key` header (or `?api_key=` query param).

| Role    | Permissions                         |
|---------|-------------------------------------|
| reader  | GET (list, get, stats)              |
| writer  | reader + POST, PUT, PATCH, DELETE   |
| admin   | writer + key management             |

---

## API Endpoints

### Records

| Method | Path                    | Role   | Description             |
|--------|-------------------------|--------|-------------------------|
| GET    | /api/records            | reader | List (paginated, filter)|
| GET    | /api/records/:id        | reader | Get one record          |
| POST   | /api/records            | writer | Create record           |
| PUT    | /api/records/:id        | writer | Replace record data     |
| PATCH  | /api/records/:id        | writer | Partial update          |
| DELETE | /api/records/:id        | writer | Delete record           |
| GET    | /api/stats              | reader | DB statistics           |

### Keys (admin only)

| Method | Path                    | Description              |
|--------|-------------------------|--------------------------|
| GET    | /api/admin/keys         | List all keys (masked)   |
| POST   | /api/admin/keys         | Create new key           |
| DELETE | /api/admin/keys/:hash   | Revoke key by hash       |

---

## cURL Examples

```bash
export KEY="your_api_key_here"
export BASE="http://localhost:5000"

# List records
curl -H "X-API-Key: $KEY" $BASE/api/records

# Create a record
curl -X POST \
  -H "X-API-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"Alice","email":"alice@example.com","plan":"pro"}' \
  $BASE/api/records

# Update specific fields (PATCH)
curl -X PATCH \
  -H "X-API-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d '{"plan":"enterprise"}' \
  $BASE/api/records/RECORD_ID

# Delete a record
curl -X DELETE -H "X-API-Key: $KEY" $BASE/api/records/RECORD_ID

# Filter records
curl -H "X-API-Key: $KEY" \
  "$BASE/api/records?filter_key=plan&filter_val=pro"

# Create a writer key
curl -X POST \
  -H "X-API-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d '{"label":"mobile-app","role":"writer"}' \
  $BASE/api/admin/keys
```

---

## File Structure

```
jsondb/
├── server.py         # Flask API server
├── requirements.txt
├── README.md
├── data/
│   ├── database.json # Your records (auto-created)
│   └── config.json   # API keys (auto-created)
└── ui/
    └── index.html    # Admin dashboard
```

---

## Security Notes

- API keys are stored in `data/config.json` — keep this file private
- Keys are never returned in full after creation
- At least one admin key is always preserved (cannot delete the last admin)
- For production use, add HTTPS via a reverse proxy (nginx/caddy)
