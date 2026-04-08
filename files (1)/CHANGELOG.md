# Changelog

## server_v1.0.0.py
**Initial release**
- Full CRUD REST API (GET, POST, PUT, PATCH, DELETE)
- JSON file persistence with metadata tracking
- 3-tier API key auth: reader / writer / admin
- Pagination and field filtering on list endpoint
- Admin key management endpoints
- Stats endpoint
- Serves UI from /ui folder
- Auto-generates admin key on first run

---

## server_v1.1.0.py
**Bug fixes**
- Removed unused `hmac` import
- Fixed `PUT` endpoint: now fully replaces `data` object instead of merging (was identical to PATCH — semantically wrong)
- Fixed `list_records`: `page` and `limit` params now return 400 on non-integer input instead of crashing with 500; added bounds clamping
- Fixed startup: initial `database.json` is now persisted on first run so stats reflect a valid `last_modified` timestamp immediately
- Bumped `/api/health` version string to `1.1.0`

---

## index_v1.1.1.html
**v1.0.0** — Initial release
- Auth gate with API key login
- Records table with search, pagination, edit, delete
- Raw JSON textarea for add/edit

**v1.1.0** — Key-value field builder
- Replaced raw JSON textarea in Add Record view with dynamic key/value row builder
- Replaced raw JSON textarea in Edit modal with key/value row builder
- Added + Add field / × remove buttons per row
- Added column headers (Key / Value) above field rows

**v1.1.1** — Bug fix
- Fixed truncated file: toast() function was cut off mid-word
- Restored missing setTimeout() call in toast()
- Restored missing </script>, </body>, </html> closing tags
- Full audit passed: all 30 functions resolve, all 26 element IDs verified

---

## server_v1.3.0.py
**Security hardening & performance (QC audit)**
- FIX #1 — threading locks (`_db_lock`, `_config_lock`) protect all read-modify-write cycles; eliminates race conditions under concurrent requests
- FIX #2 — config cache (`_config_cache`) avoids a disk read on every authenticated request; invalidated on every `save_config()` call
- FIX #3 — background session cleanup thread (every 5 minutes) replaces the O(n) scan that ran on every single request; middleware does a cheap inline expiry check instead
- FIX #4 — CORS restricted to `localhost:5000` / `127.0.0.1:5000` only (was open wildcard `*`)
- FIX #5 — path traversal fix in UI serving: removed manual `os.path.exists` pre-check; `send_from_directory` uses `safe_join` internally; `NotFound` caught for SPA fallback
- FIX #6 — IP-based rate limiting added alongside per-username tracking; uses X-Forwarded-For (first hop); IP threshold set to `MAX_LOGIN_ATTEMPTS * 3`
- FIX #7 — `_sessions`, `_login_attempts`, `_ip_attempts` dicts are bounded (`MAX_SESSIONS = 10_000`, `MAX_TRACKED = 10_000`); `_evict_oldest()` removes oldest entries on overflow
- FIX #8 — API key hash in list/delete endpoints changed from truncated 12-char prefix to full 64-char SHA-256 hex to eliminate collision risk
- Refactored rate-limit logic into `_check_lockout()` / `_record_failure()` helpers
- Bumped `/api/health` version string to `1.3.0`

---

## server_v1.2.0.py
**Login / session security**
- Added `POST /api/auth/login` — validates username + password, issues an 8-hour session token
- Added `POST /api/auth/logout` — server-side session invalidation
- Added `GET /api/auth/me` — returns role/label of current session or API key
- `require_api_key` now accepts `X-Session-Token` (session) OR `X-API-Key` (direct, fully backward compatible)
- Brute-force protection: 5 failed login attempts triggers a 15-minute lockout per username
- Constant-time dummy hash check on unknown usernames to prevent user enumeration via timing
- Security response headers added to all responses: `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy`
- First-run now generates both an API key AND an admin user (`admin` / auto-generated password)
- Migration path: existing `config.json` files without a `users` section get an admin user created automatically on startup
- Added `POST /api/admin/users` — create user (admin only, validates username chars/length, password min 8 chars)
- Added `GET /api/admin/users` — list all users (admin only, passwords never returned)
- Added `DELETE /api/admin/users/:username` — remove user, invalidates active sessions, cannot delete last admin
- Added `PUT /api/admin/users/:username/password` — change password, force re-login for that user
- Removed unused `hmac` import (carried forward from v1.1.0 fix)
- Bumped `/api/health` version string to `1.2.0`
- Added `werkzeug` dependency for `generate_password_hash` / `check_password_hash`

---

## index_v1.5.0.html
**Security & UX fixes (QC audit)**
- FIX #10 — session persistence via `sessionStorage`: token/role/username saved on login, restored on page load (validated against `/api/auth/me`), cleared on logout or 401
- FIX #12 — API key "Authenticate" button now has `id="apikey-btn"` and is disabled/re-enabled during the request to prevent double-submission
- FIX #13 — `recordMap` cache cleared at the start of every `loadRecords()` call to prevent unbounded memory growth across paginated loads
- FIX #14 — removed dead `.session-banner` CSS block that was never rendered

---

## index_v1.4.0.html
**Login UI + session auth + Users management view**
- Login gate now has two tabs: "Username / Password" and "API Key"
- Username/password tab POSTs to `/api/auth/login`, stores session token — raw key is never kept in memory
- Displays remaining attempts warning and lockout message from server responses
- Sign-in button disabled during request to prevent double-submission
- All `apiFetch()` calls now send `X-Session-Token` (session login) or `X-API-Key` (API key login) automatically
- Auto-logout on any 401 response with toast notification (handles session expiry gracefully)
- Topbar now shows username and role badge after login (hidden when using raw API key with no username)
- Users nav item (sidebar) only visible to admin-role sessions
- New **Users** view: card grid of all user accounts with avatar initial, role badge, created date, Remove button
- Create user inline form in Users view: username, password, role fields with server-side error display
- Delete user calls `DELETE /api/admin/users/:username` with confirmation
- Logout calls `POST /api/auth/logout` to invalidate server session before clearing local state
- `new-key-display` panel hidden on logout (prevents stale key being visible after re-login)
- Enter key works on both username and password fields in login form
- cURL guide updated: new Auth tab with login/logout/API-key examples; all other examples updated to use `X-Session-Token`
- Added Users view CSS: `.user-grid`, `.user-card`, `.user-avatar`, `.user-info`, `.user-name`, `.user-meta`
- Added auth gate CSS: `.auth-tabs`, `.auth-tab`, `.auth-panel`, `.auth-error`, `.auth-attempts`

---

## index_v1.3.0.html
**Nested field support**
- Added `{}` nest-toggle button to every top-level field row
- Clicking `{}` switches the value cell from a text input to a sub-field block (indented, blue left-border)
- Sub-fields have their own Key / Value inputs and individual remove buttons
- `+ Add sub-field` button appends more sub-rows to an active nested block
- Nested fields produce JSON objects (e.g. `"phone": {"mobile": "...", "work": "..."}`)
- `populateKvList` auto-detects object values and renders them as nested entries when editing
- `kvListToObject` reads nested blocks and builds correct object structure
- Replaced old `makeKvRow` with `makeKvEntry` (wrapper div containing row + nested block) and `makeSubRow` (sub-field row)
- Updated kv-row CSS grid from 3-column to 4-column (`1fr 1fr 32px 32px`) to accommodate nest button
- Added `kv-val-cell` wrapper, `kv-val-obj` placeholder, `kv-nested`, `kv-sub-row`, `kv-sub-header`, `kv-nest-btn` CSS
- Updated cURL Write tab example to show nested field syntax

---

## index_v1.2.0.html
**Bug fixes**
- Removed Cloudflare email-decode script tag (injected when file was previously served through Cloudflare CDN)
- Restored obfuscated email in cURL example back to `jane@example.com` (Cloudflare had replaced it with an encoded `<a>` tag, breaking the copy-code button)
- Fixed `openEdit()`: now uses a `recordMap` cache keyed by ID; onclick passes only the record ID instead of inline `JSON.stringify(r)`, eliminating parse failures when record data contains quotes
- Fixed `createRecord()`: header element removal now scoped to `#new-fields-list` parent instead of `document.querySelector('.kv-header')` which could remove the wrong header if the edit modal was open
- Fixed `copyCode()`: now clones the code block and removes the button node before reading `innerText`, replacing the fragile `replace('copy\n', '')` string approach
- Fixed `escAttr()`: added `&` and `>` escaping (was only escaping `"` and `<`)
- Applied `escAttr()` to all dynamic table cell content in `renderRecords()` and `loadKeys()`
