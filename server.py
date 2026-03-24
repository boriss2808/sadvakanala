#!/usr/bin/env python3
"""
Lančana barijera - upravljački sustav
- /          korisničko sučelje (prijava + kontrola)
- /admin     admin sučelje (upravljanje korisnicima)
- /api       API endpoint
"""

import hashlib, hmac, time, json, os, sqlite3, threading, secrets, urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

PORT       = int(os.environ.get("PORT", 8765))

MANIFEST = """{
  "name": "Barijera",
  "short_name": "Barijera",
  "description": "Upravljanje lančanom barjerom",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#0d0d0d",
  "theme_color": "#0d0d0d",
  "orientation": "portrait",
  "icons": [
    {
      "src": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 192 192'><rect width='192' height='192' fill='%230d0d0d'/><text y='140' x='96' text-anchor='middle' font-size='120' font-family='sans-serif'>⛓</text></svg>",
      "sizes": "192x192",
      "type": "image/svg+xml"
    }
  ]
}"""

SW_JS = """
const CACHE = 'barijera-v1';
self.addEventListener('install', e => { self.skipWaiting(); });
self.addEventListener('activate', e => { e.waitUntil(clients.claim()); });
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;
  e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
});
"""

TUYA_BASE  = "https://openapi.tuyaeu.com"
DB_PATH    = "/tmp/barijera.db"
MOTOR_TIME = 10

# ─── Tuya podaci (iz env varijabli ili hardkodirano) ──────────────────────────
TUYA_ACCESS_ID     = os.environ.get("TUYA_ACCESS_ID", "")
TUYA_ACCESS_SECRET = os.environ.get("TUYA_ACCESS_SECRET", "")
TUYA_DEVICE_ID     = os.environ.get("TUYA_DEVICE_ID", "")
ADMIN_PASSWORD     = os.environ.get("ADMIN_PASSWORD", "admin123")
ADMIN_TOKENS       = set()  # in-memory admin sessions

# ─── Baza ─────────────────────────────────────────────────────────────────────
db_lock = threading.Lock()

def init_db():
    with sqlite3.connect(DB_PATH) as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            active   INTEGER DEFAULT 1,
            created_at REAL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token    TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at REAL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS state (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS admin_sessions (
            token TEXT PRIMARY KEY,
            created_at REAL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT NOT NULL,
            action     TEXT NOT NULL,
            created_at REAL DEFAULT 0
        );
        INSERT OR IGNORE INTO state (key, value) VALUES ('is_open', '0');
        INSERT OR IGNORE INTO state (key, value) VALUES ('is_moving', '0');
        INSERT OR IGNORE INTO state (key, value) VALUES ('move_started_at', '0');
        """)

def db_get(key):
    with db_lock:
        with sqlite3.connect(DB_PATH) as c:
            r = c.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
    return r[0] if r else None

def db_set(key, value):
    with db_lock:
        with sqlite3.connect(DB_PATH) as c:
            c.execute("INSERT OR REPLACE INTO state (key,value) VALUES (?,?)", (key, str(value)))

def get_barrier_state():
    is_open    = db_get('is_open') == '1'
    is_moving  = db_get('is_moving') == '1'
    started_at = float(db_get('move_started_at') or 0)
    if is_moving and (time.time() - started_at) >= MOTOR_TIME:
        new_open = not is_open
        db_set('is_open', '1' if new_open else '0')
        db_set('is_moving', '0')
        return {"is_open": new_open, "is_moving": False, "remaining": 0}
    remaining = max(0, MOTOR_TIME - (time.time() - started_at)) if is_moving else 0
    return {"is_open": is_open, "is_moving": is_moving, "remaining": round(remaining, 1)}

def add_log(username, action):
    with db_lock:
        with sqlite3.connect(DB_PATH) as c:
            c.execute("INSERT INTO log (username,action,created_at) VALUES (?,?,?)",
                      (username, action, time.time()))

def get_log(limit=20):
    with db_lock:
        with sqlite3.connect(DB_PATH) as c:
            rows = c.execute(
                "SELECT username, action, created_at FROM log ORDER BY created_at DESC LIMIT ?",
                (limit,)).fetchall()
    return [{"username": r[0], "action": r[1], "time": r[2]} for r in rows]

def create_user(username, password):
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    with db_lock:
        with sqlite3.connect(DB_PATH) as c:
            try:
                c.execute("INSERT INTO users (username,password,created_at) VALUES (?,?,?)",
                          (username, pw_hash, time.time()))
                return True
            except sqlite3.IntegrityError:
                return False

def delete_user(username):
    with db_lock:
        with sqlite3.connect(DB_PATH) as c:
            c.execute("DELETE FROM users WHERE username=?", (username,))
            c.execute("DELETE FROM sessions WHERE username=?", (username,))

def toggle_user(username, active):
    with db_lock:
        with sqlite3.connect(DB_PATH) as c:
            c.execute("UPDATE users SET active=? WHERE username=?", (1 if active else 0, username))

def get_users():
    with db_lock:
        with sqlite3.connect(DB_PATH) as c:
            rows = c.execute("SELECT username, active, created_at FROM users ORDER BY created_at DESC").fetchall()
    return [{"username": r[0], "active": bool(r[1]), "created_at": r[2]} for r in rows]

def verify_user(username, password):
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    with db_lock:
        with sqlite3.connect(DB_PATH) as c:
            r = c.execute("SELECT active FROM users WHERE username=? AND password=?",
                          (username, pw_hash)).fetchone()
    return r and r[0] == 1

def create_session(username):
    token = secrets.token_hex(32)
    with db_lock:
        with sqlite3.connect(DB_PATH) as c:
            c.execute("INSERT INTO sessions (token,username,created_at) VALUES (?,?,?)",
                      (token, username, time.time()))
    return token

def get_session_user(token):
    if not token: return None
    with db_lock:
        with sqlite3.connect(DB_PATH) as c:
            r = c.execute("SELECT username FROM sessions WHERE token=?", (token,)).fetchone()
    return r[0] if r else None

def delete_session(token):
    with db_lock:
        with sqlite3.connect(DB_PATH) as c:
            c.execute("DELETE FROM sessions WHERE token=?", (token,))

# ─── Tuya ─────────────────────────────────────────────────────────────────────
def sha256_hex(data):
    return hashlib.sha256(data.encode()).hexdigest()

def hmac_sha256(secret, message):
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest().upper()

def get_token():
    t = str(int(time.time() * 1000))
    path = "/v1.0/token?grant_type=1"
    sign = hmac_sha256(TUYA_ACCESS_SECRET, TUYA_ACCESS_ID + t + "\n".join(["GET", sha256_hex(""), "", path]))
    req = urllib.request.Request(TUYA_BASE + path, headers={
        "client_id": TUYA_ACCESS_ID, "sign": sign, "sign_method": "HMAC-SHA256", "t": t})
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read())
    if not data.get("success"): raise Exception(data.get("msg"))
    return data["result"]["access_token"]

def send_impulse(is_closing=True):
    # is_closing=True  → barijera se zatvara → lanac gore → switch_1
    # is_closing=False → barijera se otvara  → lanac dolje → switch_2
    channel = "switch_1" if is_closing else "switch_2"
    token = get_token()
    t = str(int(time.time() * 1000))
    # Pokusaj 1: direktni True
    body = json.dumps({"commands": [{"code": channel, "value": True}]}, separators=(',',':'))
    path = f"/v1.0/devices/{TUYA_DEVICE_ID}/commands"
    sign = hmac_sha256(TUYA_ACCESS_SECRET, TUYA_ACCESS_ID + token + t + "\n".join(["POST", sha256_hex(body), "", path]))
    headers = {"client_id": TUYA_ACCESS_ID, "access_token": token, "sign": sign,
               "sign_method": "HMAC-SHA256", "t": t, "Content-Type": "application/json"}
    req = urllib.request.Request(TUYA_BASE + path, data=body.encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        result = json.loads(resp.read())
    print(f"  Impuls na {channel} (True): {result}")
    if result.get("success"):
        return result
    # Pokusaj 2: inching format "0000000001" za 1 sekundu
    t2 = str(int(time.time() * 1000))
    # switch_inching format: "XXXXXXXXXD" gdje X=kanal(0=off,1=on), D=trajanje u 0.1s
    # Za switch_1: pozicija 0, za switch_2: pozicija 1
    inching_val = "1000000001" if is_closing else "0100000001"
    body2 = json.dumps({"commands": [{"code": "switch_inching", "value": inching_val}]}, separators=(',',':'))
    sign2 = hmac_sha256(TUYA_ACCESS_SECRET, TUYA_ACCESS_ID + token + t2 + "\n".join(["POST", sha256_hex(body2), "", path]))
    headers["sign"] = sign2
    headers["t"] = t2
    req2 = urllib.request.Request(TUYA_BASE + path, data=body2.encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req2, timeout=10) as resp2:
        result2 = json.loads(resp2.read())
    print(f"  Impuls inching {channel}: {result2}")
    return result2

# ─── HTML stranice ────────────────────────────────────────────────────────────

LOGIN_HTML = """<!DOCTYPE html>
<html lang="hr"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
<title>Barijera</title>
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#0d0d0d">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black">
<meta name="apple-mobile-web-app-title" content="Barijera">
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#0d0d0d">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black">
<meta name="apple-mobile-web-app-title" content="Barijera">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root { --bg: #0d0d0d; --surface: #161616; --border: #252525; --border2: #333; --text: #efefef; --text2: #777; --text3: #444; --green: #4ade80; --error: #f87171; --mono: 'DM Mono', monospace; --sans: 'DM Sans', sans-serif; }
body { background: var(--bg); color: var(--text); font-family: var(--sans); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px; }
body::before { content: ''; position: fixed; inset: 0; background-image: linear-gradient(var(--border) 1px, transparent 1px), linear-gradient(90deg, var(--border) 1px, transparent 1px); background-size: 48px 48px; opacity: 0.2; pointer-events: none; }
.box { position: relative; z-index: 1; background: var(--surface); border: 1px solid var(--border2); border-radius: 16px; padding: 32px 28px; width: 100%; max-width: 340px; display: flex; flex-direction: column; gap: 16px; }
.title { font-family: var(--mono); font-size: 11px; letter-spacing: 0.15em; text-transform: uppercase; color: var(--text2); text-align: center; }
.field { display: flex; flex-direction: column; gap: 5px; }
.field label { font-family: var(--mono); font-size: 10px; letter-spacing: 0.08em; text-transform: uppercase; color: var(--text3); }
.field input { background: #1e1e1e; border: 1px solid var(--border2); border-radius: 8px; color: var(--text); font-family: var(--mono); font-size: 13px; padding: 11px 14px; outline: none; width: 100%; transition: border-color 0.2s; }
.field input:focus { border-color: #555; }
.btn { background: #1a4a2e; border: 1px solid #22633e; border-radius: 8px; color: var(--green); font-family: var(--mono); font-size: 11px; letter-spacing: 0.1em; text-transform: uppercase; padding: 13px; cursor: pointer; transition: all 0.15s; }
.btn:hover { background: #1f5c38; }
.err { font-family: var(--mono); font-size: 11px; color: var(--error); text-align: center; display: none; }
.err.show { display: block; }
</style></head><body>
<div class="box">
  <div class="title">&#128274; Pristup barijeri</div>
  <div class="field"><label>Korisničko ime</label><input type="text" id="u" autocomplete="off" autocorrect="off" autocapitalize="none" placeholder="username"></div>
  <div class="field"><label>Lozinka</label><input type="password" id="p" placeholder="••••••••" onkeydown="if(event.key==='Enter')login()"></div>
  <button class="btn" onclick="login()">Prijavi se &rarr;</button>
  <div class="err" id="err">Pogrešno korisničko ime ili lozinka</div>
</div>
<script>
if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');
</script>
<script>
async function login() {
  const u = document.getElementById('u').value.trim();
  const p = document.getElementById('p').value;
  if (!u||!p) return;
  const res = await fetch('/api', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({action:'login', username:u, password:p})});
  const data = await res.json();
  if (data.success) {
    localStorage.setItem('token', data.token);
    localStorage.setItem('username', data.username);
    window.location.href = '/';
  } else {
    document.getElementById('err').classList.add('show');
  }
}
</script></body></html>"""

CONTROL_HTML = """<!DOCTYPE html>
<html lang="hr"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
<title>Barijera</title>
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#0d0d0d">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black">
<meta name="apple-mobile-web-app-title" content="Barijera">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root { --bg: #0d0d0d; --surface: #161616; --border: #252525; --border2: #333; --text: #efefef; --text2: #777; --text3: #444; --open: #4ade80; --closed: #60a5fa; --error: #f87171; --mono: 'DM Mono', monospace; --sans: 'DM Sans', sans-serif; }
body { background: var(--bg); color: var(--text); font-family: var(--sans); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px; overflow: hidden; }
body::before { content: ''; position: fixed; inset: 0; background-image: linear-gradient(var(--border) 1px, transparent 1px), linear-gradient(90deg, var(--border) 1px, transparent 1px); background-size: 48px 48px; opacity: 0.2; pointer-events: none; }
.app { position: relative; z-index: 1; width: 100%; max-width: 360px; display: flex; flex-direction: column; align-items: center; gap: 0; }
.top { font-family: var(--mono); font-size: 10px; letter-spacing: 0.15em; text-transform: uppercase; color: var(--text3); margin-bottom: 40px; display: flex; align-items: center; gap: 10px; width: 100%; justify-content: space-between; }
.top-left { display: flex; align-items: center; gap: 8px; }
.top-dot { width: 5px; height: 5px; border-radius: 50%; background: var(--open); box-shadow: 0 0 6px var(--open); transition: all 0.3s; }
.top-dot.error { background: var(--error); box-shadow: 0 0 6px var(--error); }
.top-dot.connecting { background: var(--text3); box-shadow: none; animation: blink 1s ease-in-out infinite; }
.logout { color: var(--text3); cursor: pointer; font-size: 10px; letter-spacing: 0.08em; text-decoration: none; }
.logout:hover { color: var(--text2); }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }
.main-btn { width: 220px; height: 220px; border-radius: 50%; border: 1.5px solid var(--border2); background: var(--surface); cursor: pointer; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 12px; position: relative; transition: border-color 0.3s, transform 0.1s; outline: none; -webkit-tap-highlight-color: transparent; }
.main-btn:hover { border-color: #555; }
.main-btn:active { transform: scale(0.97); }
.main-btn:disabled { opacity: 0.4; cursor: not-allowed; pointer-events: none; }
.progress-ring { position: absolute; inset: -8px; width: calc(100% + 16px); height: calc(100% + 16px); transform: rotate(-90deg); pointer-events: none; }
.ring-bg { fill: none; stroke: var(--border); stroke-width: 2; }
.ring-fg { fill: none; stroke-width: 2; stroke-linecap: round; stroke: var(--open); stroke-dasharray: 0 754; transition: stroke 0.3s; }
.ring-fg.closing { stroke: var(--closed); }
.arrow { font-size: 64px; line-height: 1; transition: color 0.3s; user-select: none; }
.arrow.open { color: var(--open); }
.arrow.closed { color: var(--closed); }
.btn-label { font-family: var(--mono); font-size: 13px; letter-spacing: 0.12em; text-transform: uppercase; color: var(--text2); transition: color 0.3s; font-weight: 500; }
.btn-label.open { color: var(--open); }
.btn-label.closed { color: var(--closed); }
@keyframes pulse-open   { 0%,100%{box-shadow:0 0 0 0 rgba(74,222,128,0)}  50%{box-shadow:0 0 0 14px rgba(74,222,128,0.07)} }
@keyframes pulse-close  { 0%,100%{box-shadow:0 0 0 0 rgba(96,165,250,0)}  50%{box-shadow:0 0 0 14px rgba(96,165,250,0.07)} }
.main-btn.moving-open  { animation: pulse-open 1s ease-in-out infinite;  border-color: var(--open); }
.main-btn.moving-close { animation: pulse-close 1s ease-in-out infinite; border-color: var(--closed); }
@keyframes bounce-up   { 0%,100%{transform:translateY(0)} 40%{transform:translateY(-8px)} }
@keyframes bounce-down { 0%,100%{transform:translateY(0)} 40%{transform:translateY(8px)} }
.arrow.bouncing-up   { animation: bounce-up 0.8s ease-in-out infinite; }
.arrow.bouncing-down { animation: bounce-down 0.8s ease-in-out infinite; }
.status-area { margin-top: 40px; height: 64px; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 6px; }
.status-text { font-size: 18px; font-weight: 500; letter-spacing: 0.08em; color: var(--text2); transition: color 0.3s; text-align: center; }
.status-text.active { color: var(--text); }
.countdown { font-family: var(--mono); font-size: 28px; font-weight: 500; letter-spacing: -0.02em; transition: color 0.3s; min-height: 36px; display: flex; align-items: center; }
.countdown.opening { color: var(--open); }
.countdown.closing { color: var(--closed); }
.countdown.idle { color: var(--text3); font-size: 12px; font-weight: 400; letter-spacing: 0.05em; }
.last-action { margin-top: 24px; font-family: var(--mono); font-size: 10px; color: var(--text3); text-align: center; letter-spacing: 0.06em; }
</style></head><body>
<div class="app">
  <div class="top">
    <div class="top-left">
      <div class="top-dot connecting" id="topDot"></div>
      <span id="topName">Barijera</span>
    </div>
    <a class="logout" onclick="logout()">odjava</a>
  </div>

  <button class="main-btn" id="mainBtn" onclick="handleClick()" disabled>
    <svg class="progress-ring" viewBox="0 0 252 252">
      <circle class="ring-bg" cx="126" cy="126" r="120"/>
      <circle class="ring-fg" id="ringFg" cx="126" cy="126" r="120"/>
    </svg>
    <span class="arrow" id="arrow">&#8593;</span>
    <span class="btn-label" id="btnLabel">ucitavam...</span>
  </button>

  <div class="status-area">
    <div class="countdown" id="countdown"></div>
    <div class="status-text" id="statusText">spajanje...</div>
  </div>

  <div class="last-action" id="lastAction"></div>
</div>
<script>
if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');
</script>
<script>
const API = window.location.origin + '/api';
const MOTOR = 10;
const CIRC  = 2 * Math.PI * 120;
let token = localStorage.getItem('token');
let username = localStorage.getItem('username') || '';
let isMoving = false, currentOpen = false, countdownInterval = null, pollInterval = null;

if (!token) { window.location.href = '/login'; }

document.getElementById('topName').textContent = username || 'Barijera';

window.addEventListener('load', () => { setRingDash(0); fetchState(); });

function logout() {
  fetch(API, {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({action:'logout', token})});
  localStorage.removeItem('token');
  localStorage.removeItem('username');
  window.location.href = '/login';
}

async function api(body) {
  const res = await fetch(API, {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({...body, token})});
  const data = await res.json();
  if (data.error === 'unauthorized') { window.location.href = '/login'; }
  return data;
}

async function fetchState() {
  setDot('connecting');
  try {
    const data = await api({action:'state'});
    if (!data.success) throw new Error(data.msg);
    applyState(data);
    document.getElementById('mainBtn').disabled = false;
    setDot('ok');
    if (data.last_action) showLastAction(data.last_action);
  } catch(e) { setDot('error'); document.getElementById('statusText').textContent = 'greska spajanja'; }
}

function applyState(data) {
  if (data.is_moving) {
    const opening = !data.is_open;
    if (!isMoving) { isMoving = true; showMoving(opening, data.remaining || 0); }
    if (!pollInterval) startPolling();
  } else {
    if (isMoving) stopMovingUI();
    currentOpen = data.is_open;
    updateIdleUI();
  }
}

async function handleClick() {
  if (isMoving) return;
  try {
    const data = await api({action:'impulse'});
    if (!data.success) throw new Error(data.msg);
    const opening = !currentOpen;
    isMoving = true;
    showMoving(opening, MOTOR);
    startPolling();
    if (data.last_action) showLastAction(data.last_action);
  } catch(e) {
    document.getElementById('statusText').textContent = 'greska: ' + e.message;
  }
}

function showMoving(opening, remaining) {
  const btn = document.getElementById('mainBtn');
  btn.classList.add(opening ? 'moving-close' : 'moving-open');
  btn.disabled = true;
  const arrow = document.getElementById('arrow');
  arrow.className = 'arrow ' + (opening ? 'closed bouncing-down' : 'open bouncing-up');
  arrow.textContent = opening ? '\u2193' : '\u2191';
  const label = document.getElementById('btnLabel');
  label.className = 'btn-label ' + (opening ? 'closed' : 'open');
  label.textContent = opening ? 'LANAC SE SPUŠTA' : 'LANAC SE PODIŽE';
  document.getElementById('ringFg').className = 'ring-fg' + (opening ? ' closing' : '');
  document.getElementById('countdown').className = 'countdown ' + (opening ? 'closing' : 'opening');
  document.getElementById('statusText').className = 'status-text active';
  document.getElementById('statusText').textContent = opening ? 'LANAC SE SPUŠTA' : 'LANAC SE PODIŽE';
  clearInterval(countdownInterval);
  let r = remaining;
  updateCountdown(r); setRingDash(r / MOTOR);
  countdownInterval = setInterval(() => {
    r -= 0.1; if (r <= 0) { clearInterval(countdownInterval); return; }
    updateCountdown(r); setRingDash(r / MOTOR);
  }, 100);
}

function stopMovingUI() {
  isMoving = false; clearInterval(countdownInterval); setRingDash(0);
  setTimeout(() => { document.getElementById('mainBtn').disabled = false; }, 300);
}

function updateIdleUI() {
  const btn = document.getElementById('mainBtn');
  btn.classList.remove('moving-open','moving-close'); btn.style.animation='';
  const arrow = document.getElementById('arrow');
  arrow.className = 'arrow ' + (currentOpen ? 'open' : 'closed');
  arrow.textContent = currentOpen ? '\u2191' : '\u2193';
  const label = document.getElementById('btnLabel');
  label.className = 'btn-label ' + (currentOpen ? 'open' : 'closed');
  label.textContent = currentOpen ? 'ZATVORI' : 'OTVORI';
  document.getElementById('countdown').className = 'countdown idle';
  document.getElementById('countdown').textContent = '';
  document.getElementById('statusText').className = 'status-text';
  document.getElementById('statusText').textContent = currentOpen ? 'BARIJERA JE OTVORENA' : 'BARIJERA JE ZATVORENA';
}

function showLastAction(la) {
  const t = new Date(la.time * 1000);
  const ts = t.toLocaleTimeString('hr-HR', {hour:'2-digit', minute:'2-digit'});
  const ds = t.toLocaleDateString('hr-HR', {day:'2-digit', month:'2-digit'});
  document.getElementById('lastAction').textContent = la.action + ' — ' + la.username + '  ' + ds + ' ' + ts;
}

function startPolling() {
  if (pollInterval) return;
  pollInterval = setInterval(async () => {
    try {
      const data = await api({action:'state'});
      if (data.success) {
        applyState(data);
        if (data.last_action) showLastAction(data.last_action);
        if (!data.is_moving) stopPolling();
      }
    } catch(e) {}
  }, 2000);
}

function stopPolling() { if (pollInterval) { clearInterval(pollInterval); pollInterval = null; } }
function setRingDash(f) { document.getElementById('ringFg').style.strokeDasharray = (f*CIRC)+' '+CIRC; }
function updateCountdown(s) { document.getElementById('countdown').textContent = Math.ceil(s)+'s'; }
function setDot(s) { document.getElementById('topDot').className = 'top-dot'+(s==='error'?' error':s==='connecting'?' connecting':''); }
</script></body></html>"""

ADMIN_HTML = """<!DOCTYPE html>
<html lang="hr"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin — Barijera</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root { --bg: #0d0d0d; --surface: #161616; --surface2: #1e1e1e; --border: #252525; --border2: #333; --text: #efefef; --text2: #777; --text3: #444; --green: #4ade80; --blue: #60a5fa; --red: #f87171; --amber: #fbbf24; --mono: 'DM Mono', monospace; --sans: 'DM Sans', sans-serif; }
body { background: var(--bg); color: var(--text); font-family: var(--sans); min-height: 100vh; padding: 32px 24px; max-width: 680px; margin: 0 auto; }
h1 { font-family: var(--mono); font-size: 12px; letter-spacing: 0.15em; text-transform: uppercase; color: var(--text2); margin-bottom: 32px; display: flex; align-items: center; justify-content: space-between; }
.logout { color: var(--text3); cursor: pointer; font-size: 10px; }
.logout:hover { color: var(--text2); }
section { margin-bottom: 32px; }
.section-title { font-family: var(--mono); font-size: 10px; letter-spacing: 0.12em; text-transform: uppercase; color: var(--text3); margin-bottom: 12px; }
.card { background: var(--surface); border: 1px solid var(--border2); border-radius: 12px; overflow: hidden; }
.add-row { display: flex; gap: 8px; padding: 14px 16px; border-bottom: 1px solid var(--border); }
.add-row input { background: var(--surface2); border: 1px solid var(--border2); border-radius: 6px; color: var(--text); font-family: var(--mono); font-size: 12px; padding: 8px 12px; outline: none; flex: 1; }
.add-row input:focus { border-color: #555; }
.add-row input::placeholder { color: var(--text3); }
.btn-add { background: #1a4a2e; border: 1px solid #22633e; border-radius: 6px; color: var(--green); font-family: var(--mono); font-size: 10px; letter-spacing: 0.08em; text-transform: uppercase; padding: 8px 14px; cursor: pointer; white-space: nowrap; }
.btn-add:hover { background: #1f5c38; }
.user-row { display: flex; align-items: center; justify-content: space-between; padding: 12px 16px; border-bottom: 1px solid var(--border); }
.user-row:last-child { border-bottom: none; }
.user-name { font-family: var(--mono); font-size: 12px; color: var(--text); }
.user-date { font-family: var(--mono); font-size: 10px; color: var(--text3); margin-top: 2px; }
.user-actions { display: flex; gap: 8px; align-items: center; }
.badge { font-family: var(--mono); font-size: 9px; letter-spacing: 0.08em; text-transform: uppercase; padding: 3px 8px; border-radius: 4px; }
.badge.active { background: #1a4a2e; color: var(--green); border: 1px solid #22633e; }
.badge.inactive { background: #2a1a1a; color: var(--red); border: 1px solid #4a2222; }
.btn-sm { font-family: var(--mono); font-size: 9px; letter-spacing: 0.08em; text-transform: uppercase; padding: 4px 10px; border-radius: 4px; cursor: pointer; border: 1px solid var(--border2); background: var(--surface2); color: var(--text2); }
.btn-sm:hover { color: var(--text); border-color: #555; }
.btn-sm.danger { color: var(--red); border-color: #4a2222; }
.btn-sm.danger:hover { background: #2a1a1a; }
.log-row { display: flex; align-items: center; justify-content: space-between; padding: 10px 16px; border-bottom: 1px solid var(--border); font-family: var(--mono); font-size: 11px; }
.log-row:last-child { border-bottom: none; }
.log-action { color: var(--text2); }
.log-action.otvorio { color: var(--green); }
.log-action.zatvorio { color: var(--blue); }
.log-user { color: var(--text3); font-size: 10px; }
.log-time { color: var(--text3); font-size: 10px; }
.empty { padding: 20px 16px; font-family: var(--mono); font-size: 11px; color: var(--text3); text-align: center; }
.state-bar { background: var(--surface); border: 1px solid var(--border2); border-radius: 12px; padding: 16px 20px; display: flex; align-items: center; justify-content: space-between; margin-bottom: 32px; }
.state-label { font-family: var(--mono); font-size: 10px; letter-spacing: 0.1em; text-transform: uppercase; color: var(--text3); }
.state-value { font-family: var(--mono); font-size: 13px; }
.state-value.open { color: var(--green); }
.state-value.closed { color: var(--blue); }
.msg { font-family: var(--mono); font-size: 11px; padding: 8px 12px; border-radius: 6px; margin-top: 8px; display: none; }
.msg.ok { background: #1a4a2e; color: var(--green); border: 1px solid #22633e; display: block; }
.msg.err { background: #2a1a1a; color: var(--red); border: 1px solid #4a2222; display: block; }
</style></head><body>
<h1>&#9881; Admin — Barijera <span class="logout" onclick="logout()">odjava</span></h1>

<div class="state-bar">
  <span class="state-label">Trenutno stanje</span>
  <span class="state-value" id="stateVal">učitavam...</span>
</div>

<section>
  <div class="section-title">Korisnici</div>
  <div class="card">
    <div class="add-row">
      <input type="text" id="newUser" placeholder="korisničko ime" autocomplete="off" autocapitalize="none" autocorrect="off">
      <input type="password" id="newPass" placeholder="lozinka">
      <button class="btn-add" onclick="addUser()">+ Dodaj</button>
    </div>
    <div id="msg" class="msg"></div>
    <div id="userList"></div>
  </div>
</section>

<section>
  <div class="section-title">Log aktivnosti</div>
  <div class="card" id="logList"></div>
</section>

<script>
const API = window.location.origin + '/api';
let adminToken = localStorage.getItem('admin_token');
if (!adminToken) { window.location.href = '/admin/login'; }


async function api(body) {
  const res = await fetch(API, {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({...body, admin_token: adminToken})});
  const data = await res.json();
  if (data.error === 'unauthorized') { window.location.href = '/admin/login'; }
  return data;
}

function logout() {
  localStorage.removeItem('admin_token');
  window.location.href = '/admin/login';
}

async function load() {
  const [users, log, state] = await Promise.all([
    api({action:'admin_users'}),
    api({action:'admin_log'}),
    api({action:'state'})
  ]);

  if (state.success) {
    const sv = document.getElementById('stateVal');
    if (state.is_moving) { sv.textContent = 'u pokretu...'; sv.className = 'state-value'; }
    else if (state.is_open) { sv.textContent = 'Otvorena'; sv.className = 'state-value open'; }
    else { sv.textContent = 'Zatvorena'; sv.className = 'state-value closed'; }
  }

  if (users.success) {
    const el = document.getElementById('userList');
    if (!users.users.length) { el.innerHTML = '<div class="empty">Nema korisnika</div>'; }
    else el.innerHTML = users.users.map(u => {
      const d = new Date(u.created_at * 1000).toLocaleDateString('hr-HR');
      const tv = u.active ? '0' : '1';
      return '<div class="user-row">' +
        '<div><div class="user-name">' + u.username + '</div><div class="user-date">dodano ' + d + '</div></div>' +
        '<div class="user-actions">' +
        '<span class="badge ' + (u.active?'active':'inactive') + '">' + (u.active?'aktivan':'blokiran') + '</span>' +
        '<button class="btn-sm btn-tog" data-u="' + u.username + '" data-a="' + tv + '">' + (u.active?'blokiraj':'aktiviraj') + '</button>' +
        '<button class="btn-sm btn-del danger" data-u="' + u.username + '">obrisi</button>' +
        '</div></div>';
    }).join('');
    document.getElementById('userList').onclick = e => {
      const t = e.target;
      if (t.classList.contains('btn-tog')) toggleUser(t.dataset.u, t.dataset.a === '1');
      if (t.classList.contains('btn-del')) deleteUser(t.dataset.u);
    };
  }

  if (log.success) {
    const el = document.getElementById('logList');
    if (!log.log.length) { el.innerHTML = '<div class="empty">Nema aktivnosti</div>'; }
    else el.innerHTML = log.log.map(l => {
      const t = new Date(l.time * 1000);
      const ts = t.toLocaleTimeString('hr-HR',{hour:'2-digit',minute:'2-digit'});
      const ds = t.toLocaleDateString('hr-HR',{day:'2-digit',month:'2-digit'});
      const cls = l.action.toLowerCase().includes('otvori') ? 'otvorio' : 'zatvorio';
      return '<div class="log-row"><span class="log-action ' + cls + '">' + l.action + '</span>' +
        '<span class="log-user">' + l.username + '</span>' +
        '<span class="log-time">' + ds + ' ' + ts + '</span></div>';
    }).join('');
  }
}

async function addUser() {
  const u = document.getElementById('newUser').value.trim();
  const p = document.getElementById('newPass').value;
  const msg = document.getElementById('msg');
  if (!u||!p) { showMsg('Unesite korisničko ime i lozinku', false); return; }
  const data = await api({action:'admin_add_user', username:u, password:p});
  if (data.success) {
    document.getElementById('newUser').value = '';
    document.getElementById('newPass').value = '';
    showMsg('Korisnik ' + u + ' dodan', true);
    load();
  } else { showMsg(data.msg || 'Greška', false); }
}

async function deleteUser(u) {
  if (!confirm('Obrisati korisnika ' + u + '?')) return;
  await api({action:'admin_delete_user', username:u});
  load();
}

async function toggleUser(u, active) {
  await api({action:'admin_toggle_user', username:u, active});
  load();
}

function showMsg(text, ok) {
  const el = document.getElementById('msg');
  el.textContent = text;
  el.className = 'msg ' + (ok?'ok':'err');
  setTimeout(() => { el.className = 'msg'; }, 3000);
}

load();
setInterval(load, 10000);
</script></body></html>"""

ADMIN_LOGIN_HTML = """<!DOCTYPE html>
<html lang="hr"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin — Prijava</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root { --bg: #0d0d0d; --surface: #161616; --border2: #333; --text: #efefef; --text2: #777; --text3: #444; --amber: #fbbf24; --error: #f87171; --mono: 'DM Mono', monospace; --sans: 'DM Sans', sans-serif; }
body { background: var(--bg); color: var(--text); font-family: var(--sans); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px; }
.box { background: var(--surface); border: 1px solid var(--border2); border-radius: 16px; padding: 32px 28px; width: 100%; max-width: 320px; display: flex; flex-direction: column; gap: 16px; }
.title { font-family: var(--mono); font-size: 11px; letter-spacing: 0.15em; text-transform: uppercase; color: var(--text2); text-align: center; }
.field { display: flex; flex-direction: column; gap: 5px; }
.field label { font-family: var(--mono); font-size: 10px; letter-spacing: 0.08em; text-transform: uppercase; color: var(--text3); }
.field input { background: #1e1e1e; border: 1px solid var(--border2); border-radius: 8px; color: var(--text); font-family: var(--mono); font-size: 13px; padding: 11px 14px; outline: none; width: 100%; }
.btn { background: #2a1f0a; border: 1px solid #5a3e0a; border-radius: 8px; color: var(--amber); font-family: var(--mono); font-size: 11px; letter-spacing: 0.1em; text-transform: uppercase; padding: 13px; cursor: pointer; }
.err { font-family: var(--mono); font-size: 11px; color: var(--error); text-align: center; display: none; }
.err.show { display: block; }
</style></head><body>
<div class="box">
  <div class="title">&#9881; Admin pristup</div>
  <div class="field"><label>Admin lozinka</label><input type="password" id="p" placeholder="••••••••" onkeydown="if(event.key==='Enter')login()"></div>
  <button class="btn" onclick="login()">Prijavi se &rarr;</button>
  <div class="err" id="err">Pogrešna lozinka</div>
</div>
<script>
if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');
</script>
<script>
async function login() {
  const p = document.getElementById('p').value;
  const res = await fetch('/api', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({action:'admin_login', password:p})});
  const data = await res.json();
  if (data.success) { localStorage.setItem('admin_token', data.token); window.location.href = '/admin'; }
  else document.getElementById('err').classList.add('show');
}
</script></body></html>"""

# ─── HTTP Handler ─────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(f"  [{args[1]}] {args[0]}")

    def cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(200); self.cors(); self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/" or path == "":
            self.html(CONTROL_HTML)
        elif path == "/login":
            self.html(LOGIN_HTML)
        elif path == "/admin":
            self.html(ADMIN_HTML)
        elif path == "/admin/login":
            self.html(ADMIN_LOGIN_HTML)
        elif path == "/manifest.json":
            self.json_file(MANIFEST)
        elif path == "/sw.js":
            body = SW_JS.encode("utf-8")
            self.send_response(200); self.cors()
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        if urlparse(self.path).path != "/api":
            self.send_response(404); self.end_headers(); return
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length))
        action = body.get("action", "")

        # ── Javne akcije ──
        if action == "login":
            u, p = body.get("username",""), body.get("password","")
            if verify_user(u, p):
                t = create_session(u)
                self.respond(200, {"success": True, "token": t, "username": u})
            else:
                self.respond(200, {"success": False, "msg": "Pogrešni podaci"})
            return

        if action == "admin_verify":
            at = body.get("admin_token","")
            self.respond(200, {"success": at == hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()})
            return

        if action == "debug_admin":
            self.respond(200, {"password_set": ADMIN_PASSWORD, "tokens_count": len(ADMIN_TOKENS)})
            return

        if action == "admin_login":
            if body.get("password","") == ADMIN_PASSWORD:
                t = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()
                self.respond(200, {"success": True, "token": t})
            else:
                self.respond(200, {"success": False})
            return

        # ── Admin akcije ──
        if action.startswith("admin_"):
            at = body.get("admin_token","")
            if at != hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest():
                self.respond(401, {"error": "unauthorized"}); return

            if action == "admin_users":
                self.respond(200, {"success": True, "users": get_users()})
            elif action == "admin_log":
                self.respond(200, {"success": True, "log": get_log(30)})
            elif action == "admin_add_user":
                u, p = body.get("username","").strip(), body.get("password","")
                if not u or not p:
                    self.respond(200, {"success": False, "msg": "Nedostaju podaci"})
                elif create_user(u, p):
                    self.respond(200, {"success": True})
                else:
                    self.respond(200, {"success": False, "msg": "Korisnik već postoji"})
            elif action == "admin_delete_user":
                delete_user(body.get("username",""))
                self.respond(200, {"success": True})
            elif action == "admin_toggle_user":
                toggle_user(body.get("username",""), body.get("active", True))
                self.respond(200, {"success": True})
            return

        # ── Zaštićene korisničke akcije ──
        # Admin može koristiti state akciju s admin_token
        at = body.get("admin_token","")
        if at and at == hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest():
            username = "admin"
        else:
            username = get_session_user(body.get("token",""))
        if not username:
            self.respond(200, {"error": "unauthorized"}); return

        if action == "logout":
            delete_session(body.get("token",""))
            self.respond(200, {"success": True})

        elif action == "state":
            s = get_barrier_state()
            logs = get_log(1)
            self.respond(200, {"success": True, **s, "last_action": logs[0] if logs else None})

        elif action == "impulse":
            s = get_barrier_state()
            if s.get("is_moving"):
                self.respond(200, {"success": False, "msg": "Barijera je u pokretu"}); return
            try:
                was_open = s.get("is_open", False)
                is_closing = was_open  # ako je otvorena → zatvaramo → switch_1
                result = send_impulse(is_closing=is_closing)
                if result.get("success"):
                    db_set("is_open", "1" if was_open else "0")
                    db_set("is_moving", "1")
                    db_set("move_started_at", str(time.time()))
                    action_text = "Zatvorio barijeru" if is_closing else "Otvorio barijeru"
                    add_log(username, action_text)
                    logs = get_log(1)
                    self.respond(200, {"success": True, "last_action": logs[0] if logs else None})
                else:
                    self.respond(200, result)
            except Exception as e:
                self.respond(500, {"success": False, "msg": str(e)})
        else:
            self.respond(400, {"success": False, "msg": "Nepoznata akcija"})

    def html(self, content):
        body = content.encode("utf-8")
        self.send_response(200); self.cors()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def json_file(self, content):
        body = content.encode("utf-8")
        self.send_response(200); self.cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def respond(self, code, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(code); self.cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    print(f"Server pokrenut na portu {PORT}")
    print(f"Admin lozinka: {ADMIN_PASSWORD}")
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    server.serve_forever()
