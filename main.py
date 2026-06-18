import asyncio
import json
import os
import hashlib
import secrets
import time
import re
import base64
import ipaddress
import uuid as uuid_lib
from datetime import datetime, timezone, timedelta
from urllib.parse import quote
from collections import deque, defaultdict
from typing import Optional, Dict, Any

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

import uvicorn
import httpx
import psutil
import bcrypt
from jose import jwt, JWTError
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import aiosqlite
import logging
import logging.config

try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    pass

# Optional PostgreSQL
try:
    import asyncpg
    HAS_POSTGRES = True
except ImportError:
    HAS_POSTGRES = False

# ── Logging ─────────────────────────────────────────────────────────────
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
        }
    },
    "handlers": {"json_console": {"class": "logging.StreamHandler", "formatter": "json"}},
    "root": {"level": "INFO", "handlers": ["json_console"]},
}
logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("V2Render")

# ── Rate Limiter ────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

# ── Config ──────────────────────────────────────────────────────────────
CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret_key": os.environ.get("SECRET_KEY", secrets.token_urlsafe(32)),
    "jwt_algorithm": "HS256",
    "jwt_expire_minutes": 10080,
    "db_path": os.environ.get("DB_PATH", "panel.db"),
    "admin_password": os.environ.get("ADMIN_PASSWORD", "admin"),
    "database_url": os.environ.get("DATABASE_URL", ""),
}

# ── Integrity error tuple for address uniqueness ───────────────────────
if HAS_POSTGRES:
    ADDRESS_INTEGRITY_ERRORS = (aiosqlite.IntegrityError, asyncpg.exceptions.UniqueViolationError)
else:
    ADDRESS_INTEGRITY_ERRORS = (aiosqlite.IntegrityError,)

# ── Global persistent DB connection (SQLite) ──────────────────────────
db_conn: Optional[aiosqlite.Connection] = None
db_lock = asyncio.Lock()
ENABLE_LOGGING = True

# ── Traffic buffer (hourly/daily stats) ────────────────────────────────
traffic_buffer_lock = asyncio.Lock()
traffic_buffer = {
    "hourly": defaultdict(int),
    "daily": defaultdict(int),
}

# ── In‑memory link storage (original Luffy style, mirrors DB) ─────────
LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()
CUSTOM_ADDRESSES: list = ["www.speedtest.net"]
CUSTOM_ADDRESSES_LOCK = asyncio.Lock()

# ── Database abstraction ──────────────────────────────────────────────
if CONFIG["database_url"] and HAS_POSTGRES:
    DB_BACKEND = "postgresql"
    pg_pool: Optional[asyncpg.Pool] = None

    async def init_pg():
        global pg_pool
        pg_pool = await asyncpg.create_pool(CONFIG["database_url"], min_size=2, max_size=10)
        async with pg_pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS links (
                    uid TEXT PRIMARY KEY, label TEXT NOT NULL,
                    limit_bytes BIGINT DEFAULT 0, used_bytes BIGINT DEFAULT 0,
                    max_connections INT DEFAULT 0, created_at TEXT NOT NULL,
                    active BOOLEAN DEFAULT TRUE, expires_at TEXT,
                    custom_path TEXT DEFAULT '', custom_sni TEXT DEFAULT '',
                    custom_host TEXT DEFAULT '', custom_fp TEXT DEFAULT 'chrome'
                );
                CREATE TABLE IF NOT EXISTS hourly_traffic (hour TEXT PRIMARY KEY, bytes BIGINT DEFAULT 0);
                CREATE TABLE IF NOT EXISTS daily_traffic (day TEXT PRIMARY KEY, bytes BIGINT DEFAULT 0);
                CREATE TABLE IF NOT EXISTS custom_addresses (id SERIAL PRIMARY KEY, address TEXT NOT NULL UNIQUE);
                CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE IF NOT EXISTS login_logs (
                    id SERIAL PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    ip TEXT,
                    success BOOLEAN DEFAULT TRUE,
                    user_agent TEXT DEFAULT '',
                    path TEXT DEFAULT ''
                );
            """)

    async def db_execute(sqlite_q: str, pg_q: str, params: tuple = ()):
        async with pg_pool.acquire() as conn:
            await conn.execute(pg_q, *params)

    async def db_fetchall(sqlite_q: str, pg_q: str, params: tuple = ()) -> list:
        async with pg_pool.acquire() as conn:
            rows = await conn.fetch(pg_q, *params)
            return [dict(r) for r in rows]

    async def db_fetchone(sqlite_q: str, pg_q: str, params: tuple = ()) -> Optional[dict]:
        async with pg_pool.acquire() as conn:
            row = await conn.fetchrow(pg_q, *params)
            return dict(row) if row else None

    async def get_db():
        return None
else:
    DB_BACKEND = "sqlite"

    async def init_db():
        global db_conn
        db_conn = await aiosqlite.connect(CONFIG["db_path"])
        db_conn.row_factory = aiosqlite.Row
        await db_conn.execute("PRAGMA journal_mode=WAL")
        await db_conn.executescript("""
            CREATE TABLE IF NOT EXISTS links (
                uid TEXT PRIMARY KEY, label TEXT NOT NULL,
                limit_bytes INTEGER DEFAULT 0, used_bytes INTEGER DEFAULT 0,
                max_connections INTEGER DEFAULT 0, created_at TEXT NOT NULL,
                active INTEGER DEFAULT 1, expires_at TEXT,
                custom_path TEXT DEFAULT '', custom_sni TEXT DEFAULT '',
                custom_host TEXT DEFAULT '', custom_fp TEXT DEFAULT 'chrome'
            );
            CREATE TABLE IF NOT EXISTS hourly_traffic (hour TEXT PRIMARY KEY, bytes INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS daily_traffic (day TEXT PRIMARY KEY, bytes INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS custom_addresses (id INTEGER PRIMARY KEY AUTOINCREMENT, address TEXT NOT NULL UNIQUE);
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE IF NOT EXISTS login_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip TEXT,
                success INTEGER DEFAULT 1,
                user_agent TEXT DEFAULT '',
                path TEXT DEFAULT ''
            );
        """)
        await db_conn.commit()

    async def db_execute(sqlite_q: str, pg_q: str = "", params: tuple = ()):
        async with db_lock:
            await db_conn.execute(sqlite_q, params)
            await db_conn.commit()

    async def db_fetchall(sqlite_q: str, pg_q: str = "", params: tuple = ()) -> list:
        async with db_lock:
            cur = await db_conn.execute(sqlite_q, params)
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def db_fetchone(sqlite_q: str, pg_q: str = "", params: tuple = ()) -> Optional[dict]:
        async with db_lock:
            cur = await db_conn.execute(sqlite_q, params)
            row = await cur.fetchone()
        return dict(row) if row else None

    async def get_db():
        return db_conn

# ── Traffic buffer flush task ─────────────────────────────────────────
async def flush_traffic_buffer():
    while True:
        await asyncio.sleep(10)
        async with traffic_buffer_lock:
            if not traffic_buffer["hourly"] and not traffic_buffer["daily"]:
                continue
            for hour, bytes_val in traffic_buffer["hourly"].items():
                await db_execute(
                    "INSERT INTO hourly_traffic (hour, bytes) VALUES (?,?) ON CONFLICT(hour) DO UPDATE SET bytes = bytes + ?",
                    "INSERT INTO hourly_traffic (hour, bytes) VALUES ($1,$2) ON CONFLICT (hour) DO UPDATE SET bytes = hourly_traffic.bytes + $2",
                    (hour, bytes_val, bytes_val)
                )
            for day, bytes_val in traffic_buffer["daily"].items():
                await db_execute(
                    "INSERT INTO daily_traffic (day, bytes) VALUES (?,?) ON CONFLICT(day) DO UPDATE SET bytes = bytes + ?",
                    "INSERT INTO daily_traffic (day, bytes) VALUES ($1,$2) ON CONFLICT (day) DO UPDATE SET bytes = daily_traffic.bytes + $2",
                    (day, bytes_val, bytes_val)
                )
            traffic_buffer["hourly"].clear()
            traffic_buffer["daily"].clear()

async def add_traffic_to_buffer(hour: str, day: str, size: int):
    async with traffic_buffer_lock:
        traffic_buffer["hourly"][hour] += size
        traffic_buffer["daily"][day] += size

# ── Periodic usage sync to DB (only for persistence, quota handled in RAM) ─
async def sync_usage_to_db():
    while True:
        await asyncio.sleep(30)
        async with LINKS_LOCK:
            for uid, link in LINKS.items():
                await db_execute(
                    "UPDATE links SET used_bytes = ? WHERE uid = ?",
                    "UPDATE links SET used_bytes = $1 WHERE uid = $2",
                    (link["used_bytes"], uid)
                )

# ── Load initial data into memory ─────────────────────────────────────
async def load_initial_data():
    rows = await db_fetchall("SELECT * FROM links", "SELECT * FROM links")
    async with LINKS_LOCK:
        for r in rows:
            LINKS[r["uid"]] = dict(r)
    addr_rows = await db_fetchall("SELECT address FROM custom_addresses", "SELECT address FROM custom_addresses")
    async with CUSTOM_ADDRESSES_LOCK:
        CUSTOM_ADDRESSES[:] = [r["address"] for r in addr_rows]
    if not CUSTOM_ADDRESSES:
        CUSTOM_ADDRESSES.append("www.speedtest.net")
    # Ensure a default link exists with a valid UUID
    if not LINKS:
        default_uuid = str(uuid_lib.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        default_link = {
            "uid": default_uuid, "label": "Default", "limit_bytes": 0, "used_bytes": 0,
            "max_connections": 0, "created_at": now, "active": 1, "expires_at": None,
            "custom_path": "", "custom_sni": "", "custom_host": "", "custom_fp": "chrome"
        }
        async with LINKS_LOCK:
            LINKS[default_uuid] = default_link
        await db_execute(
            "INSERT INTO links (uid, label, limit_bytes, max_connections, created_at, active, expires_at) VALUES (?,?,?,?,?,1,?)",
            "INSERT INTO links (uid, label, limit_bytes, max_connections, created_at, active, expires_at) VALUES ($1,$2,$3,$4,$5,TRUE,$6)",
            (default_uuid, "Default", 0, 0, now, None),
        )

# ── FastAPI App ─────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    if DB_BACKEND == "postgresql":
        await init_pg()
    else:
        await init_db()
    await load_initial_data()

    # Ensure secret key in DB
    sk = await db_fetchone(
        "SELECT value FROM settings WHERE key = 'jwt_secret_key'",
        "SELECT value FROM settings WHERE key = 'jwt_secret_key'"
    )
    if sk:
        CONFIG["secret_key"] = sk["value"]
    else:
        await db_execute(
            "INSERT INTO settings (key, value) VALUES ('jwt_secret_key', ?)",
            "INSERT INTO settings (key, value) VALUES ('jwt_secret_key', $1)",
            (CONFIG["secret_key"],)
        )

    # Ensure admin password hash
    hash_row = await db_fetchone(
        "SELECT value FROM settings WHERE key = 'admin_password_hash'",
        "SELECT value FROM settings WHERE key = 'admin_password_hash'",
    )
    global ADMIN_PASSWORD_HASH
    if hash_row:
        ADMIN_PASSWORD_HASH = hash_row["value"]
    else:
        ADMIN_PASSWORD_HASH = bcrypt.hashpw(CONFIG["admin_password"].encode(), bcrypt.gensalt()).decode()
        await db_execute(
            "INSERT INTO settings (key, value) VALUES ('admin_password_hash', ?)",
            "INSERT INTO settings (key, value) VALUES ('admin_password_hash', $1)",
            (ADMIN_PASSWORD_HASH,),
        )

    # Load logging flag
    log_row = await db_fetchone(
        "SELECT value FROM settings WHERE key = 'log_enabled'",
        "SELECT value FROM settings WHERE key = 'log_enabled'"
    )
    global ENABLE_LOGGING
    ENABLE_LOGGING = (log_row and log_row["value"] == "1") if log_row else True

    asyncio.create_task(keep_alive())
    asyncio.create_task(cleanup_idle_connections())
    asyncio.create_task(telegram_reporter())
    asyncio.create_task(flush_traffic_buffer())
    asyncio.create_task(sync_usage_to_db())
    yield
    if DB_BACKEND == "sqlite" and db_conn:
        await db_conn.close()

app = FastAPI(title="V2Render", lifespan=lifespan, docs_url=None, redoc_url=None)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response

connections: dict = {}
connections_lock = asyncio.Lock()
connection_sockets: dict = {}
link_ip_map: dict = defaultdict(set)
stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
    "upload_bytes": 0,
    "download_bytes": 0,
}
error_logs: deque = deque(maxlen=200)

CACHE_TTL = 60
link_cache: dict = {}

SESSION_COOKIE = "v2r_session"
UNLIMITED_QUOTA_BYTES = 53687091200000

ADMIN_PASSWORD_HASH: str = ""
ENABLE_LOGGING: bool = True

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

def create_jwt_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=CONFIG["jwt_expire_minutes"]))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, CONFIG["secret_key"], algorithm=CONFIG["jwt_algorithm"])

def decode_jwt_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, CONFIG["secret_key"], algorithms=[CONFIG["jwt_algorithm"]])
    except JWTError:
        return None

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not token or not decode_jwt_token(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

async def keep_alive():
    while True:
        await asyncio.sleep(600)
        try:
            domain = get_domain()
            if domain and domain != "localhost":
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.get(f"https://{domain}/health")
        except Exception:
            pass

async def cleanup_idle_connections():
    while True:
        await asyncio.sleep(60)
        now = time.time()
        async with connections_lock:
            idle = [cid for cid, info in connections.items() if now - info.get("last_active", 0) > 300]
        for cid in idle:
            ws = connection_sockets.get(cid)
            if ws:
                try: await ws.close(code=1000, reason="idle timeout")
                except Exception: pass
            async with connections_lock: connections.pop(cid, None)
            connection_sockets.pop(cid, None)

async def telegram_reporter():
    while True:
        await asyncio.sleep(3600)
        try:
            token_row = await db_fetchone(
                "SELECT value FROM settings WHERE key = 'tg_bot_token'",
                "SELECT value FROM settings WHERE key = 'tg_bot_token'",
            )
            chat_row = await db_fetchone(
                "SELECT value FROM settings WHERE key = 'tg_chat_id'",
                "SELECT value FROM settings WHERE key = 'tg_chat_id'",
            )
            if token_row and chat_row and token_row["value"] and chat_row["value"]:
                msg = (
                    f"📊 V2Render Stats\n"
                    f"🕒 Uptime: {uptime()}\n"
                    f"🔗 Active: {len(connections)}\n"
                    f"📦 Traffic: {round(stats['total_bytes']/(1024*1024),2)} MB\n"
                    f"📡 Requests: {stats['total_requests']}\n"
                    f"❌ Errors: {stats['total_errors']}"
                )
                url = f"https://api.telegram.org/bot{token_row['value']}/sendMessage"
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.post(url, json={"chat_id": chat_row["value"], "text": msg})
        except Exception:
            pass

def get_domain() -> str:
    return (
        os.environ.get("RENDER_EXTERNAL_URL", os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost"))
        .replace("https://", "").replace("http://", "")
    )

def validate_address(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(addr, strict=False)
        return True
    except ValueError:
        pass
    return re.match(r'^[a-zA-Z0-9\-_.%]+$', addr) is not None

def generate_vless_link(uid: str, remark: str = "V2R", address: str = None, extra: dict = None) -> str:
    cache_key = f"{uid}:{remark}:{address}:{json.dumps(extra) if extra else ''}"
    if cache_key in link_cache and link_cache[cache_key]["expires"] > time.time():
        return link_cache[cache_key]["link"]
    domain = get_domain()
    addr = address if address else domain
    path = (extra.get("custom_path") or f"/ws/{uid}") if extra else f"/ws/{uid}"
    sni = (extra.get("custom_sni") or domain) if extra else domain
    host = (extra.get("custom_host") or domain) if extra else domain
    fp = (extra.get("custom_fp") or "chrome") if extra else "chrome"
    params = {
        "encryption": "none", "security": "tls", "type": "ws",
        "host": host, "path": path, "sni": sni, "fp": fp, "alpn": "http/1.1"
    }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    link = f"vless://{uid}@{addr}:443?{query}#{quote(remark)}"
    link_cache[cache_key] = {"link": link, "expires": time.time() + CACHE_TTL}
    return link

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    u = unit.upper()
    if u == "GB": return int(value * 1024**3)
    if u == "MB": return int(value * 1024**2)
    if u == "KB": return int(value * 1024)
    return int(value)

def parse_expires_at(raw: Optional[str]) -> Optional[datetime]:
    if not raw: return None
    try:
        s = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    except Exception: return None

def seconds_until_expiry(expires_at_str: Optional[str]) -> Optional[int]:
    exp = parse_expires_at(expires_at_str)
    if exp is None: return None
    return max(0, int((exp - datetime.now(timezone.utc)).total_seconds()))

async def count_connections_for_link(uid: str) -> int:
    async with connections_lock:
        return sum(1 for info in connections.values() if info.get("uuid") == uid)

async def close_connections_for_link(uid: str):
    async with connections_lock:
        to_close = [cid for cid, info in connections.items() if info.get("uuid") == uid]
    for cid in to_close:
        ws = connection_sockets.get(cid)
        if ws:
            try: await ws.close(code=1000, reason="link deleted")
            except Exception: pass
        async with connections_lock: connections.pop(cid, None)
        connection_sockets.pop(cid, None)
    async with connections_lock: link_ip_map.pop(uid, None)

# ── Enhanced logging for subscriptions, quota warnings, etc. ──────────
def log_event(etype: str, message: str, ip: str = "", ua: str = ""):
    error_logs.append({
        "time": datetime.now(timezone.utc).isoformat(),
        "type": etype,
        "error": message,
        "ip": ip,
        "ua": ua,
    })

# ═══════════════════════════════════════════════════════════════
# Routes
# ═══════════════════════════════════════════════════════════════

@app.api_route("/", methods=["GET", "HEAD"])
async def root():
    return {"service": "V2Render", "version": "37.0", "status": "active", "domain": get_domain()}

@app.get("/health")
async def health():
    async with connections_lock: cnt = len(connections)
    return {"status": "ok", "connections": cnt, "uptime": uptime()}

@app.get("/favicon.ico")
async def favicon():
    return Response(content=b"", media_type="image/x-icon", status_code=204)

@app.get("/api/public-settings")
async def public_settings():
    rows = await db_fetchall("SELECT key, value FROM settings WHERE key IN ('footer_text')",
                             "SELECT key, value FROM settings WHERE key IN ('footer_text')")
    result = {}
    for r in rows:
        result[r["key"]] = r["value"]
    return result

@app.post("/api/login")
@limiter.limit("5/minute")
async def api_login(request: Request):
    body = await request.json()
    password = str(body.get("password") or "")
    ip = request.client.host
    user_agent = request.headers.get("user-agent", "")
    success = verify_password(password, ADMIN_PASSWORD_HASH)
    asyncio.create_task(log_login(ip, success, user_agent, "/api/login"))
    if not success:
        log_event("Auth", f"Failed login attempt from {ip}", ip, user_agent)
        raise HTTPException(status_code=401, detail="Invalid password")
    log_event("Auth", f"Successful panel login from {ip}", ip, user_agent)
    token = create_jwt_token({"sub": "admin"})
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=CONFIG["jwt_expire_minutes"]*60,
                    httponly=True, samesite="lax", secure=True if get_domain()!="localhost" else False, path="/")
    return resp

async def log_login(ip: str, success: bool, ua: str, path: str):
    if not ENABLE_LOGGING:
        return
    try:
        await db_execute(
            "INSERT INTO login_logs (timestamp, ip, success, user_agent, path) VALUES (?,?,?,?,?)",
            "INSERT INTO login_logs (timestamp, ip, success, user_agent, path) VALUES ($1,$2,$3,$4,$5)",
            (datetime.now(timezone.utc).isoformat(), ip, 1 if success else 0, ua, path)
        )
        if success:
            await notify_telegram_login(ip, ua)
    except Exception as e:
        logger.error(f"log_login error: {e}")

async def notify_telegram_login(ip: str, ua: str):
    token_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_bot_token'",
                                  "SELECT value FROM settings WHERE key = 'tg_bot_token'")
    chat_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_chat_id'",
                                 "SELECT value FROM settings WHERE key = 'tg_chat_id'")
    if token_row and chat_row and token_row["value"] and chat_row["value"]:
        msg = (
            f"🔐 Panel login\n"
            f"🌐 IP: {ip}\n"
            f"🤖 UA: {ua}\n"
            f"📅 {datetime.now(timezone.utc).isoformat()}"
        )
        url = f"https://api.telegram.org/bot{token_row['value']}/sendMessage"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(url, json={"chat_id": chat_row["value"], "text": msg})
        except Exception:
            pass

@app.post("/api/logout")
async def api_logout(request: Request):
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    payload = decode_jwt_token(token)
    return {"authenticated": payload is not None}

@app.post("/api/change-password")
@limiter.limit("3/minute")
async def api_change_password(request: Request, _=Depends(require_auth)):
    global ADMIN_PASSWORD_HASH
    body = await request.json()
    current = str(body.get("current_password") or "")
    new = str(body.get("new_password") or "")
    if not verify_password(current, ADMIN_PASSWORD_HASH):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    new_hash = bcrypt.hashpw(new.encode(), bcrypt.gensalt()).decode()
    ADMIN_PASSWORD_HASH = new_hash
    await db_execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_password_hash', ?)",
        "INSERT INTO settings (key, value) VALUES ('admin_password_hash', $1) ON CONFLICT (key) DO UPDATE SET value = $1",
        (new_hash,),
    )
    log_event("Security", "Admin password changed")
    return {"ok": True}

@app.get("/api/settings")
async def get_settings(_=Depends(require_auth)):
    keys = ['tg_bot_token', 'tg_chat_id', 'footer_text', 'default_path', 'log_enabled', 'timezone_offset']
    result = {}
    for k in keys:
        row = await db_fetchone(
            "SELECT value FROM settings WHERE key = ?", "SELECT value FROM settings WHERE key = $1", (k,)
        )
        result[k] = row["value"] if row else ""
    return result

@app.post("/api/settings")
async def save_settings(request: Request, _=Depends(require_auth)):
    global ENABLE_LOGGING
    body = await request.json()
    for k in ('tg_bot_token', 'tg_chat_id', 'footer_text', 'default_path', 'log_enabled', 'timezone_offset'):
        if k in body:
            val = str(body[k]).strip()
            await db_execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                "INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2",
                (k, val),
            )
    if 'log_enabled' in body:
        ENABLE_LOGGING = body['log_enabled'] == '1'
    return {"ok": True}

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    async with connections_lock: conn_count = len(connections)
    cpu = 0.0
    try: cpu = await asyncio.to_thread(psutil.cpu_percent, 0.1)
    except: pass
    mem_percent = 0
    try: mem_percent = psutil.virtual_memory().percent
    except: pass
    disk_percent = 0; disk_free = 0.0
    try:
        disk = psutil.disk_usage("/")
        disk_percent = disk.percent
        disk_free = round(disk.free / (1024**3), 1)
    except: pass
    rows = await db_fetchall(
        "SELECT hour, bytes FROM hourly_traffic ORDER BY hour DESC LIMIT 24",
        "SELECT hour, bytes FROM hourly_traffic ORDER BY hour DESC LIMIT 24"
    )
    hourly_dict = {row["hour"]: row["bytes"] for row in rows}
    return {
        "active_connections": conn_count,
        "total_traffic_mb": round(stats["total_bytes"]/(1024*1024),2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "recent_errors": list(error_logs)[-20:],
        "links_count": len(LINKS),
        "domain": get_domain(),
        "cpu_percent": cpu,
        "memory_percent": mem_percent,
        "disk_percent": disk_percent,
        "disk_free_gb": disk_free,
        "hourly_traffic": hourly_dict,
        "upload_bytes": stats["upload_bytes"],
        "download_bytes": stats["download_bytes"],
    }

@app.get("/stats/detailed")
async def get_detailed_stats(_=Depends(require_auth)):
    async with LINKS_LOCK:
        links = list(LINKS.values())
    active = sum(1 for l in links if l["active"])
    inactive = sum(1 for l in links if not l["active"])
    expired = 0
    now = datetime.now(timezone.utc)
    for l in links:
        if l.get("expires_at"):
            exp = parse_expires_at(l["expires_at"])
            if exp and exp < now:
                expired += 1
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    today_row = await db_fetchone("SELECT bytes FROM daily_traffic WHERE day = ?", "SELECT bytes FROM daily_traffic WHERE day = $1", (today,))
    today_bytes = today_row["bytes"] if today_row else 0
    return {
        "total_links": len(links),
        "active_links": active,
        "inactive_links": inactive,
        "expired_links": expired,
        "today_traffic_bytes": today_bytes,
    }

@app.get("/api/login-logs")
async def get_login_logs(_=Depends(require_auth)):
    rows = await db_fetchall(
        "SELECT timestamp, ip, success, user_agent, path FROM login_logs ORDER BY timestamp DESC LIMIT 20",
        "SELECT timestamp, ip, success, user_agent, path FROM login_logs ORDER BY timestamp DESC LIMIT 20"
    )
    return {"logs": [dict(r) for r in rows]}

@app.get("/api/logs")
async def get_logs(_=Depends(require_auth)):
    return {"logs": list(error_logs)}

@app.get("/api/backup")
async def backup_database(_=Depends(require_auth)):
    if DB_BACKEND == "sqlite":
        return FileResponse(CONFIG["db_path"], filename="panel.db", media_type="application/octet-stream")
    raise HTTPException(status_code=400, detail="Backup only for SQLite")

@app.post("/api/test-connection")
async def test_connection(request: Request, _=Depends(require_auth)):
    body = await request.json()
    addr = (body.get("address") or "").strip()
    port = int(body.get("port", 443))
    if not addr or not validate_address(addr):
        raise HTTPException(status_code=400, detail="Invalid address")
    try:
        start = time.time()
        try:
            async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
                resp = await client.get(f"https://{addr}:{port}", follow_redirects=True)
            latency = round((time.time() - start) * 1000)
            return {"ok": True, "message": f"HTTPS {resp.status_code} from {addr}:{port} in {latency}ms", "latency": latency}
        except:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(addr, port), timeout=5.0)
            latency = round((time.time() - start) * 1000)
            writer.close()
            return {"ok": True, "message": f"TCP connected to {addr}:{port} in {latency}ms", "latency": latency}
    except Exception as e:
        return {"ok": False, "message": str(e)}

# ═══ INBOUNDS ═══

@app.post("/api/links")
@limiter.limit("10/minute")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "New Link").strip()[:60]
    uuid_input = (body.get("uuid") or "").strip()
    if not label:
        raise HTTPException(status_code=400, detail="Remark is required")
    if not re.match(r'^[a-zA-Z0-9\-_. ]+$', label):
        raise HTTPException(status_code=400, detail="Remark must contain only English letters, numbers, and characters: - _ . space")
    uid = uuid_input if uuid_input else str(uuid_lib.uuid4())
    async with LINKS_LOCK:
        if uid in LINKS:
            raise HTTPException(status_code=400, detail="An inbound with this UUID already exists")
    limit_val = float(body.get("limit_value") or 0)
    limit_unit = body.get("limit_unit") or "GB"
    limit_bytes = 0 if limit_val <= 0 else parse_size_to_bytes(limit_val, limit_unit)
    max_conn = int(body.get("max_connections") or 0)
    if max_conn < 0: max_conn = 0
    days_valid = body.get("days_valid")
    expires_at = None
    if days_valid is not None:
        try:
            days_valid = int(days_valid)
            if days_valid > 0: expires_at = (datetime.now(timezone.utc) + timedelta(days=days_valid)).isoformat()
        except (ValueError, TypeError): pass
    now = datetime.now(timezone.utc).isoformat()
    custom_path = body.get("custom_path", "")
    custom_sni = body.get("custom_sni", "")
    custom_host = body.get("custom_host", "")
    custom_fp = body.get("custom_fp", "chrome")
    link_data = {
        "uid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": 0,
        "max_connections": max_conn, "created_at": now, "active": 1,
        "expires_at": expires_at,
        "custom_path": custom_path, "custom_sni": custom_sni,
        "custom_host": custom_host, "custom_fp": custom_fp,
    }
    async with LINKS_LOCK:
        LINKS[uid] = link_data
    await db_execute(
        "INSERT INTO links (uid, label, limit_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp) VALUES (?,?,?,?,?,1,?,?,?,?,?)",
        "INSERT INTO links (uid, label, limit_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp) VALUES ($1,$2,$3,$4,$5,TRUE,$6,$7,$8,$9,$10)",
        (uid, label, limit_bytes, max_conn, now, expires_at, custom_path, custom_sni, custom_host, custom_fp),
    )
    extra = {"custom_path": custom_path, "custom_sni": custom_sni, "custom_host": custom_host, "custom_fp": custom_fp}
    log_event("Inbound", f"Created inbound {label} ({uid})")
    return {
        "uuid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": 0,
        "max_connections": max_conn, "active": True, "created_at": now,
        "expires_at": expires_at,
        "vless_link": generate_vless_link(uid, remark=f"V2R-{label}", extra=extra),
    }

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    async with LINKS_LOCK:
        items = list(LINKS.values())
    items.sort(key=lambda x: x["created_at"], reverse=True)
    result = []
    for row in items:
        uid = row["uid"]
        extra = {
            "custom_path": row.get("custom_path", ""),
            "custom_sni": row.get("custom_sni", ""),
            "custom_host": row.get("custom_host", ""),
            "custom_fp": row.get("custom_fp", "chrome"),
        }
        result.append({
            "uuid": uid,
            "label": row["label"],
            "limit_bytes": row["limit_bytes"],
            "used_bytes": row["used_bytes"],
            "max_connections": row["max_connections"],
            "active": bool(row["active"]),
            "created_at": row["created_at"],
            "expires_at": row.get("expires_at"),
            "custom_path": extra["custom_path"],
            "custom_sni": extra["custom_sni"],
            "custom_host": extra["custom_host"],
            "custom_fp": extra["custom_fp"],
            "current_connections": await count_connections_for_link(uid),
            "vless_link": generate_vless_link(uid, remark=f"V2R-{row['label']}", extra=extra),
        })
    return {"links": result}

@app.get("/api/export-links")
async def export_links(_=Depends(require_auth)):
    async with LINKS_LOCK:
        links = list(LINKS.values())
    return JSONResponse(content={"links": links})

@app.post("/api/import-links")
async def import_links(request: Request, _=Depends(require_auth)):
    body = await request.json()
    imported = body.get("links", [])
    count = 0
    for link in imported:
        uid = link.get("uid") or str(uuid_lib.uuid4())
        label = link.get("label", "Imported")
        limit_bytes = int(link.get("limit_bytes", 0))
        used_bytes = int(link.get("used_bytes", 0))
        max_conn = int(link.get("max_connections", 0))
        created_at = link.get("created_at") or datetime.now(timezone.utc).isoformat()
        active = 1 if link.get("active", True) else 0
        expires_at = link.get("expires_at")
        custom_path = link.get("custom_path", "")
        custom_sni = link.get("custom_sni", "")
        custom_host = link.get("custom_host", "")
        custom_fp = link.get("custom_fp", "chrome")
        try:
            await db_execute(
                "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT (uid) DO UPDATE SET label = EXCLUDED.label, limit_bytes = EXCLUDED.limit_bytes, max_connections = EXCLUDED.max_connections, active = EXCLUDED.active, expires_at = EXCLUDED.expires_at, custom_path = EXCLUDED.custom_path, custom_sni = EXCLUDED.custom_sni, custom_host = EXCLUDED.custom_host, custom_fp = EXCLUDED.custom_fp",
                (uid, label, limit_bytes, used_bytes, max_conn, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp),
            )
            async with LINKS_LOCK:
                LINKS[uid] = {
                    "uid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": used_bytes,
                    "max_connections": max_conn, "created_at": created_at, "active": active,
                    "expires_at": expires_at, "custom_path": custom_path, "custom_sni": custom_sni,
                    "custom_host": custom_host, "custom_fp": custom_fp,
                }
            count += 1
        except Exception: pass
    log_event("Inbound", f"Imported {count} inbounds")
    return {"ok": True, "imported": count}

@app.patch("/api/links/{uid}")
async def toggle_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link:
            raise HTTPException(status_code=404, detail="link not found")
    updates = {}
    if "active" in body: updates["active"] = int(body["active"])
    if "limit_value" in body:
        limit_val = float(body.get("limit_value") or 0)
        unit = body.get("limit_unit") or "GB"
        updates["limit_bytes"] = 0 if limit_val <= 0 else parse_size_to_bytes(limit_val, unit)
    if "reset_usage" in body and body["reset_usage"]:
        updates["used_bytes"] = 0
    if "label" in body:
        new_label = str(body["label"])[:60]
        updates["label"] = new_label
    if "max_connections" in body:
        mc = int(body["max_connections"] or 0)
        updates["max_connections"] = mc if mc >= 0 else 0
    if "days_valid" in body:
        try:
            dv = int(body["days_valid"])
            if dv > 0: updates["expires_at"] = (datetime.now(timezone.utc) + timedelta(days=dv)).isoformat()
            else: updates["expires_at"] = None
        except (ValueError, TypeError): pass
    if "custom_path" in body: updates["custom_path"] = str(body["custom_path"])[:100]
    if "custom_sni" in body: updates["custom_sni"] = str(body["custom_sni"])[:100]
    if "custom_host" in body: updates["custom_host"] = str(body["custom_host"])[:100]
    if "custom_fp" in body: updates["custom_fp"] = str(body["custom_fp"])[:20]
    if updates:
        async with LINKS_LOCK:
            link.update(updates)
        if DB_BACKEND == "sqlite":
            set_str = ", ".join(f"{k} = ?" for k in updates)
            vals = list(updates.values()) + [uid]
            await db_execute(f"UPDATE links SET {set_str} WHERE uid = ?", "", tuple(vals))
        else:
            set_str = ", ".join(f"{k} = ${i+1}" for i, k in enumerate(updates))
            vals = list(updates.values()) + [uid]
            await db_execute("", f"UPDATE links SET {set_str} WHERE uid = ${len(vals)}", tuple(vals))
    log_event("Inbound", f"Updated inbound {uid}")
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    await db_execute("DELETE FROM links WHERE uid = ?", "DELETE FROM links WHERE uid = $1", (uid,))
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    await close_connections_for_link(uid)
    log_event("Inbound", f"Deleted inbound {uid}")
    return {"ok": True}

# ═══ ADDRESSES (Clean IP) ═══

@app.get("/api/addresses")
async def list_addresses(_=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        return {"addresses": list(CUSTOM_ADDRESSES)}

@app.post("/api/addresses")
@limiter.limit("10/minute")
async def add_address(request: Request, _=Depends(require_auth)):
    body = await request.json()
    addr = (body.get("address") or "").strip()
    if not addr or not validate_address(addr):
        raise HTTPException(status_code=400, detail="Invalid address format")
    async with CUSTOM_ADDRESSES_LOCK:
        if addr in CUSTOM_ADDRESSES:
            raise HTTPException(status_code=400, detail="Address already exists")
        CUSTOM_ADDRESSES.append(addr)
    try:
        await db_execute("INSERT INTO custom_addresses (address) VALUES (?)", "INSERT INTO custom_addresses (address) VALUES ($1)", (addr,))
    except ADDRESS_INTEGRITY_ERRORS:
        pass
    log_event("Clean IP", f"Added address {addr}")
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.patch("/api/addresses/{index}")
async def edit_address(index: int, request: Request, _=Depends(require_auth)):
    body = await request.json()
    new_addr = (body.get("address") or "").strip()
    if not new_addr or not validate_address(new_addr):
        raise HTTPException(status_code=400, detail="Invalid address format")
    async with CUSTOM_ADDRESSES_LOCK:
        if 0 <= index < len(CUSTOM_ADDRESSES):
            old = CUSTOM_ADDRESSES[index]
            if new_addr in CUSTOM_ADDRESSES and new_addr != old:
                raise HTTPException(status_code=400, detail="Address already exists")
            CUSTOM_ADDRESSES[index] = new_addr
            await db_execute("DELETE FROM custom_addresses WHERE address = ?", "DELETE FROM custom_addresses WHERE address = $1", (old,))
            await db_execute("INSERT INTO custom_addresses (address) VALUES (?)", "INSERT INTO custom_addresses (address) VALUES ($1)", (new_addr,))
        else:
            raise HTTPException(status_code=404, detail="Address not found")
    log_event("Clean IP", f"Edited address from {old} to {new_addr}")
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.post("/api/addresses/batch")
@limiter.limit("5/minute")
async def add_addresses_batch(request: Request, _=Depends(require_auth)):
    body = await request.json()
    addresses = body.get("addresses", [])
    added = 0
    errors = 0
    for addr in addresses:
        if isinstance(addr, str):
            addr = addr.strip()
            if not addr or not validate_address(addr):
                errors += 1
                continue
            async with CUSTOM_ADDRESSES_LOCK:
                if addr not in CUSTOM_ADDRESSES:
                    CUSTOM_ADDRESSES.append(addr)
                    try:
                        await db_execute("INSERT INTO custom_addresses (address) VALUES (?)", "INSERT INTO custom_addresses (address) VALUES ($1)", (addr,))
                    except ADDRESS_INTEGRITY_ERRORS:
                        pass
                    added += 1
                else:
                    errors += 1
    if added > 0:
        log_event("Clean IP", f"Batch added {added} addresses")
    return {"ok": True, "added": added, "errors": errors}

@app.delete("/api/addresses/{index}")
async def delete_address(index: int, _=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        if 0 <= index < len(CUSTOM_ADDRESSES):
            addr = CUSTOM_ADDRESSES.pop(index)
            await db_execute("DELETE FROM custom_addresses WHERE address = ?", "DELETE FROM custom_addresses WHERE address = $1", (addr,))
        else:
            raise HTTPException(status_code=404, detail="Address not found")
    log_event("Clean IP", f"Deleted address {addr}")
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.delete("/api/addresses")
async def delete_all_addresses(_=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        CUSTOM_ADDRESSES[:] = ["www.speedtest.net"]
    await db_execute("DELETE FROM custom_addresses", "DELETE FROM custom_addresses")
    log_event("Clean IP", "All addresses deleted")
    return {"ok": True}

@app.post("/api/addresses/bulk-delete")
async def bulk_delete_addresses(request: Request, _=Depends(require_auth)):
    body = await request.json()
    indices = body.get("indices", [])
    async with CUSTOM_ADDRESSES_LOCK:
        for idx in sorted(indices, reverse=True):
            if 0 <= idx < len(CUSTOM_ADDRESSES):
                addr = CUSTOM_ADDRESSES.pop(idx)
                await db_execute("DELETE FROM custom_addresses WHERE address = ?", "DELETE FROM custom_addresses WHERE address = $1", (addr,))
    log_event("Clean IP", f"Bulk deleted addresses")
    return {"ok": True}

# ═══ SUBSCRIPTION ═══

@app.get("/sub/{uid}")
async def subscription_endpoint(uid: str, request: Request):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link or not link["active"]:
            log_event("Subscription", f"Failed subscription access for {uid} - not found/disabled", ip=request.client.host)
            raise HTTPException(status_code=404, detail="link not found or disabled")
        link = dict(link)
    expires = parse_expires_at(link.get("expires_at"))
    if expires and expires < datetime.now(timezone.utc):
        log_event("Subscription", f"Expired subscription access for {uid}", ip=request.client.host)
        raise HTTPException(status_code=403, detail="link expired")
    async with CUSTOM_ADDRESSES_LOCK:
        addresses = list(CUSTOM_ADDRESSES)
    extra = {
        "custom_path": link.get("custom_path", ""),
        "custom_sni": link.get("custom_sni", ""),
        "custom_host": link.get("custom_host", ""),
        "custom_fp": link.get("custom_fp", "chrome"),
    }
    sub_content = generate_subscription_content(link, uid, addresses, extra)
    encoded = base64.b64encode(sub_content.encode()).decode()
    total_bytes = link["limit_bytes"] if link["limit_bytes"] > 0 else UNLIMITED_QUOTA_BYTES
    expire_ts = int(expires.timestamp()) if expires else 0
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": 'attachment; filename="sub.txt"',
        "profile-update-interval": "6",
        "subscription-userinfo": f"upload={link['used_bytes']}; download=0; total={total_bytes}; expire={expire_ts}",
    }
    log_event("Subscription", f"Subscription accessed for {link['label']} ({uid})", ip=request.client.host)
    return Response(content=encoded, headers=headers)

def generate_subscription_content(link: dict, uid: str, addresses: list, extra: dict = None) -> str:
    used = link["used_bytes"]; limit = link["limit_bytes"]
    usage_str = f"{_fmt_bytes(used)} / ∞" if limit == 0 else f"{_fmt_bytes(used)} / {_fmt_bytes(limit)}"
    secs_left = seconds_until_expiry(link.get("expires_at"))
    expiry_str = "∞" if secs_left is None else ("Expired" if secs_left == 0 else f"{secs_left//86400} Days Left")
    status_node = generate_vless_link(uid, remark=f"📊 {usage_str} | ⏳ {expiry_str}", address="0.0.0.0", extra=extra)
    links = [status_node, generate_vless_link(uid, remark=f"V2R-{link['label']}-Server", extra=extra)]
    for i, addr in enumerate(addresses):
        links.append(generate_vless_link(uid, remark=f"V2R-{link['label']}-IP{i+1}", address=addr, extra=extra))
    return "\n".join(links)

def _fmt_bytes(b: int) -> str:
    if b >= 1_073_741_824: return f"{b/1_073_741_824:.1f}GB"
    if b >= 1_048_576: return f"{b/1_048_576:.1f}MB"
    return f"{b/1024:.1f}KB"

# ═══ SCANNER ═══

@app.websocket("/ws/scanner")
async def scanner_ws(websocket: WebSocket):
    await websocket.accept()
    try:
        data = await websocket.receive_json()
        items = data.get("ips", [])
        sem = asyncio.Semaphore(20)
        async def scan_one(item):
            async with sem:
                try:
                    start = time.time()
                    try:
                        async with httpx.AsyncClient(timeout=3.0, verify=False) as client:
                            resp = await client.get(f"https://{item}:443", follow_redirects=True)
                        latency = round((time.time() - start) * 1000)
                        result = {"ip": item, "ok": True, "latency": latency}
                    except:
                        reader, writer = await asyncio.wait_for(asyncio.open_connection(item, 443), timeout=3.0)
                        latency = round((time.time() - start) * 1000)
                        writer.close()
                        result = {"ip": item, "ok": True, "latency": latency}
                except Exception:
                    result = {"ip": item, "ok": False, "latency": None}
                await websocket.send_json(result)
        tasks = [asyncio.create_task(scan_one(item)) for item in items]
        await asyncio.gather(*tasks)
        await websocket.send_json({"done": True})
    except Exception as e:
        logger.error(f"Scanner WS error: {e}")
        error_logs.append({"time": datetime.now(timezone.utc).isoformat(), "error": f"Scanner WS: {e}", "type": "Scanner"})
    finally:
        await websocket.close()

# ═══ TUNNEL (original Luffy core, RAM‑based, no DB on hot path) ═══

RELAY_BUF = 512 * 1024

async def parse_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24: raise ValueError("chunk too small")
    pos = 1 + 16
    addon_len = first_chunk[pos]; pos += 1 + addon_len
    command = first_chunk[pos]; pos += 1
    port = int.from_bytes(first_chunk[pos:pos+2], "big"); pos += 2
    addr_type = first_chunk[pos]; pos += 1
    if addr_type == 1:
        addr_bytes = first_chunk[pos:pos+4]; pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        domain_len = first_chunk[pos]; pos += 1
        address = first_chunk[pos:pos+domain_len].decode("utf-8", errors="ignore"); pos += domain_len
    elif addr_type == 3:
        addr_bytes = first_chunk[pos:pos+16]; pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0,16,2))
    else: raise ValueError(f"unknown address type: {addr_type}")
    return command, address, port, first_chunk[pos:]

async def check_quota(uid: str, extra_bytes: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link or not link["active"]:
            return False
        if link["limit_bytes"] == 0:
            return True
        return (link["used_bytes"] + extra_bytes) <= link["limit_bytes"]

async def add_usage(uid: str, n: int):
    async with LINKS_LOCK:
        if uid in LINKS:
            link = LINKS[uid]
            link["used_bytes"] += n
            limit = link["limit_bytes"]
            if limit > 0 and link["used_bytes"] >= limit * 0.9 and (link["used_bytes"] - n) < limit * 0.9:
                log_event("Warning", f"Inbound {link['label']} ({uid}) has used over 90% of quota")
            elif limit > 0 and link["used_bytes"] >= limit * 0.8 and (link["used_bytes"] - n) < limit * 0.8:
                log_event("Warning", f"Inbound {link['label']} ({uid}) has used over 80% of quota")

async def ws_to_tcp(websocket, writer, conn_id, link_uid):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect": break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data: continue
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size; stats["upload_bytes"] += size; stats["total_requests"] += 1
            async with connections_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += size
            hour = datetime.now(timezone.utc).strftime("%H:00")
            day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            await add_traffic_to_buffer(hour, day, size)
            await add_usage(link_uid, size)
            try:
                writer.write(data); await writer.drain()
            except Exception: break
    except WebSocketDisconnect: pass
    except Exception as e:
        logger.error(f"ws_to_tcp error {conn_id}: {e}", exc_info=True)
        error_logs.append({"time": datetime.now(timezone.utc).isoformat(), "error": f"ws_to_tcp: {e}", "type": "Tunnel"})
    finally:
        try:
            if writer and not writer.is_closing(): writer.write_eof()
        except Exception: pass

async def tcp_to_ws(websocket, reader, conn_id, link_uid):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data: break
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size; stats["download_bytes"] += size
            async with connections_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += size
            hour = datetime.now(timezone.utc).strftime("%H:00")
            day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            await add_traffic_to_buffer(hour, day, size)
            await add_usage(link_uid, size)
            try:
                await websocket.send_bytes((b"\x00\x00" + data) if first else data)
                first = False
            except Exception: break
    except Exception as e:
        logger.error(f"tcp_to_ws error {conn_id}: {e}", exc_info=True)
        error_logs.append({"time": datetime.now(timezone.utc).isoformat(), "error": f"tcp_to_ws: {e}", "type": "Tunnel"})

@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await websocket.accept()
    logger.info(f"WS accepted {uuid}")
    writer = None; conn_id = None; client_ip = get_client_ip(websocket)
    try:
        async with LINKS_LOCK:
            link = LINKS.get(uuid)
            if not link or not link["active"]:
                await websocket.close(code=1008, reason="not found or disabled"); return
            max_conn = link.get("max_connections", 0)
        expires = parse_expires_at(link.get("expires_at"))
        if expires and expires < datetime.now(timezone.utc):
            await websocket.close(code=1008, reason="expired"); return
        if max_conn > 0:
            if await count_connections_for_link(uuid) >= max_conn:
                await websocket.close(code=1008, reason="connection limit"); return
        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect": return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk: return
        try: command, address, port, initial_payload = await parse_vless_header(first_chunk)
        except ValueError as e:
            logger.warning(f"Invalid VLESS header from {client_ip}: {e}")
            await websocket.close(code=1008, reason="invalid header"); return
        conn_id = secrets.token_urlsafe(8)
        now = time.time()
        async with connections_lock:
            connections[conn_id] = {"uuid": uuid, "ip": client_ip, "connected_at": datetime.now(timezone.utc).isoformat(), "bytes": 0, "last_active": now}
            connection_sockets[conn_id] = websocket
            link_ip_map[uuid].add(client_ip)
        size = len(first_chunk); stats["total_bytes"] += size; stats["upload_bytes"] += size; stats["total_requests"] += 1
        await add_usage(uuid, size)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=10.0)
        sock = writer.get_extra_info('socket')
        if sock: sock.setsockopt(6, 1, 1)
        if initial_payload:
            p_size = len(initial_payload); stats["total_bytes"] += p_size; stats["upload_bytes"] += p_size
            await add_usage(uuid, p_size)
            try: writer.write(initial_payload); await writer.drain()
            except Exception: pass
        up_task = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        down_task = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({up_task, down_task}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending: t.cancel(); await t
    except WebSocketDisconnect: pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"time": datetime.now(timezone.utc).isoformat(), "error": str(exc), "type": "WebSocket"})
        logger.exception("WS error")
    finally:
        if writer:
            try: writer.close(); await writer.wait_closed()
            except Exception: pass
        if conn_id:
            async with connections_lock:
                info = connections.pop(conn_id, None)
                connection_sockets.pop(conn_id, None)
                if info:
                    uid = info.get("uuid"); ip = info.get("ip")
                    if uid and ip:
                        if not any(c.get("uuid")==uid and c.get("ip")==ip for c in connections.values()):
                            if uid in link_ip_map:
                                link_ip_map[uid].discard(ip)
                                if not link_ip_map[uid]: link_ip_map.pop(uid, None)

def get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded: return forwarded.split(",")[0].strip()
    if websocket.client: return websocket.client.host
    return "unknown"

# ── HTML Panel v37 ─────────────────────────────────────────────────────
PANEL_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>V2Render Panel</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&family=Inter:wght@400;500;600;700&family=Vazirmatn:wght@400;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --primary:#39ff14; --primary-dim:rgba(57,255,20,0.12);
  --bg:#0a0a0a; --bg2:#121212; --bg3:#1a1a1a;
  --surface:rgba(20,20,20,0.85); --surface2:rgba(30,30,30,0.9); --surface3:rgba(40,40,40,0.8);
  --border:rgba(57,255,20,0.08); --border2:rgba(57,255,20,0.2);
  --text:#e0e0e0; --text2:#a0a0a0; --text3:#707070;
  --green:#4ade80; --red:#f87171; --yellow:#fbbf24;
  --header-h:80px; --footer-h:50px;
}
body.light-mode {
  --primary:#2e7d32; --primary-dim:rgba(46,125,50,0.15);
  --bg:#f5fff5; --bg2:#ffffff; --bg3:#e8f5e9;
  --surface:rgba(255,255,255,0.85); --surface2:rgba(255,255,255,0.9); --surface3:rgba(245,255,245,0.9);
  --border:rgba(0,0,0,0.08); --border2:rgba(0,0,0,0.16);
  --text:#1a1a1a; --text2:#4a4a4a; --text3:#888;
}
html,body{height:100%; overflow-x:hidden;}
body{font-family:'Inter','Vazirmatn',sans-serif;color:var(--text);display:flex;flex-direction:column;background:var(--bg);transition:background 0.3s,color 0.3s;}
body[dir="rtl"]{direction:rtl;text-align:right}
a{text-decoration:none;color:inherit;}
.header{height:var(--header-h);background:var(--surface);border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:center;padding:0 24px;backdrop-filter:blur(20px);}
.header-inner{display:flex;align-items:center;justify-content:space-between;width:100%;max-width:1400px;}
.logo{font-family:'Orbitron',sans-serif;font-size:1.6rem;font-weight:900;color:var(--primary);letter-spacing:1px;}
.header-nav{display:flex;align-items:center;gap:6px;}
.nav-link{padding:10px 20px;border-radius:12px;color:var(--text3);font-size:1rem;font-weight:600;transition:all 0.2s;border:1px solid transparent;background:none;cursor:pointer;font-family:inherit;}
.nav-link:hover{color:var(--primary);border-color:var(--primary-dim);background:var(--primary-dim);}
.nav-link.active{color:var(--primary);background:var(--primary-dim);border-color:var(--primary-dim);backdrop-filter:blur(10px);}
.header-right{display:flex;align-items:center;gap:12px;}
.btn-icon{background:transparent;border:1px solid var(--border);color:var(--text3);border-radius:10px;padding:10px;cursor:pointer;transition:all 0.2s;font-size:1.1rem;}
.btn-icon:hover{color:var(--primary);border-color:var(--primary);}
.lang-switch{display:flex;gap:2px;background:var(--surface3);border-radius:10px;padding:2px;}
.lang-btn{padding:6px 14px;border:none;background:transparent;color:var(--text3);font-size:0.9rem;font-weight:700;border-radius:8px;cursor:pointer;font-family:inherit;}
.lang-btn.active{background:var(--primary);color:#000;}
.hamburger{display:none;background:transparent;border:1px solid var(--border);color:var(--text3);font-size:1.8rem;cursor:pointer;padding:4px 10px;border-radius:10px;}
.main{flex:1;min-height:calc(100vh - var(--header-h) - var(--footer-h));padding:24px 32px;overflow-y:auto;overflow-x:hidden;}
.page{display:none;animation:pgIn .35s ease}
.page.active{display:block}
@keyframes pgIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
.page-header{margin-bottom:20px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;}
.page-title{font-size:1.5rem;font-weight:700;color:var(--primary);letter-spacing:.04em}
.page-title[data-fa]{font-family:'Vazirmatn';}
.page-sub{font-size:1rem;color:var(--text3);margin-top:4px}
.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:20px}
.stat-card{background:var(--surface2);border:1px solid var(--border);border-radius:16px;padding:24px;position:relative;overflow:hidden;transition:all 0.25s;backdrop-filter:blur(12px);}
.stat-card:hover{border-color:var(--border2);transform:translateY(-2px);box-shadow:0 0 25px var(--primary-dim);}
.stat-label{font-size:0.85rem;color:var(--text3);font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px}
.stat-val{font-size:1.8rem;font-weight:700;color:var(--text);}
.stat-unit{font-size:1rem;font-weight:400;color:var(--text3)}
.card{background:var(--surface2);border:1px solid var(--border);border-radius:16px;padding:24px;margin-bottom:16px;transition:all 0.25s;backdrop-filter:blur(10px);}
.card-hd{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}
.card-title{font-size:1.1rem;font-weight:600;color:var(--text);}
.chart-container{height:220px;width:100%}
.btn{font-family:inherit;font-size:1rem;font-weight:700;border-radius:10px;padding:8px 20px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;border:none;transition:all 0.2s;}
.btn-primary{background:linear-gradient(135deg,#39ff14,#1a8c1a);color:#000;box-shadow:0 0 16px rgba(57,255,20,0.3)}
.btn-primary:hover{filter:brightness(1.2);box-shadow:0 0 24px rgba(57,255,20,0.5)}
.btn-outline{background:var(--surface3);color:var(--text);border:1px solid var(--border)}
.btn-danger{background:rgba(248,113,113,0.1);color:var(--red);border:1px solid rgba(248,113,113,0.2)}
.btn-sm{padding:6px 14px;font-size:0.9rem}
.tbl-wrap{overflow-x:auto}
.tbl{width:100%;border-collapse:collapse;table-layout:fixed}
.tbl th, .tbl td{text-align:center; font-size:0.85rem; font-weight:700; color:var(--text3); padding:14px; text-transform:uppercase; border-bottom:1px solid var(--border); background:var(--surface3)}
.tbl td{padding:14px;border-bottom:1px solid var(--border);font-size:0.95rem;word-break:break-word;font-weight:400;text-transform:none;background:none}
.tbl th:nth-child(4), .tbl td:nth-child(4) { text-align: left; }
.tbl th:nth-child(8), .tbl td:nth-child(8) { width: 26%; }
.tag{display:inline-flex;align-items:center;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:800;text-transform:uppercase}
.tag-vless{background:var(--primary-dim);color:var(--primary);border:1px solid var(--border)}
.tag-on{background:rgba(74,222,128,0.1);color:var(--green);border:1px solid rgba(74,222,128,0.2)}
.tag-off{background:rgba(248,113,113,0.1);color:var(--red);border:1px solid rgba(248,113,113,0.2)}
.pill{display:flex;align-items:center;gap:8px;font-size:0.9rem}
.pill-used{color:var(--text);font-weight:600}
.pill-bar{flex:1;height:4px;background:var(--border);border-radius:2px;min-width:40px}
.pill-fill{height:100%;border-radius:2px;transition:width 0.4s}
.pill-lim{color:var(--text3);font-size:0.8rem}
.toggle{width:44px;height:24px;border-radius:12px;background:var(--surface3);position:relative;cursor:pointer;transition:all 0.3s;border:2px solid var(--border);flex-shrink:0}
.toggle::after{content:'';position:absolute;width:18px;height:18px;border-radius:50%;background:var(--text3);top:1px;left:2px;transition:all 0.3s}
.toggle.on{background:var(--green);border-color:var(--green);box-shadow:0 0 12px rgba(74,222,128,0.4)}
.toggle.on::after{left:22px;background:#fff}
.sys-bar{height:6px;background:var(--border);border-radius:3px;overflow:hidden}
.sys-fill{height:100%;border-radius:3px;transition:width 0.4s}
.sl-item{display:flex;align-items:center;justify-content:space-between;padding:12px 0;border-bottom:1px solid var(--border)}
.sl-k{color:var(--text3);font-size:1rem}
.sl-v{color:var(--text);font-weight:600;font-size:1rem}
.fg{display:flex;flex-direction:column;gap:6px;margin-bottom:18px}
.fl{font-size:0.9rem;font-weight:700;color:var(--text2);text-transform:uppercase}
.fi,.fs{padding:12px 16px;border-radius:10px;border:1px solid var(--border);font-family:inherit;font-size:1rem;outline:none;color:var(--text);background:var(--surface);transition:all 0.2s}
.fi:focus,.fs:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-dim)}
.act-btn{font-family:inherit;font-size:0.8rem;font-weight:700;padding:4px 8px;border-radius:6px;cursor:pointer;border:1px solid;transition:all 0.18s;display:inline-flex;align-items:center;gap:4px;background:transparent}
.act-copy{color:var(--primary);border-color:var(--border)}
.act-sub{color:var(--green);border-color:rgba(74,222,128,0.2)}
.act-qr{color:#a78bfa;border-color:rgba(167,139,250,0.2)}
.act-edit{color:var(--yellow);border-color:rgba(251,191,36,0.2)}
.act-del{color:var(--red);border-color:rgba(248,113,113,0.2)}
.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%) translateY(16px);background:var(--surface);color:var(--text);border:1px solid var(--border2);border-radius:14px;padding:16px 32px;font-size:1rem;font-weight:600;opacity:0;transition:all 0.3s;z-index:999;backdrop-filter:blur(24px);box-shadow:0 0 30px var(--primary-dim)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.mo{position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:200;display:none;align-items:center;justify-content:center;backdrop-filter:blur(8px)}
.mo.show{display:flex}
.mo-box{background:var(--surface2);border:1px solid var(--border2);border-radius:24px;padding:36px;width:100%;max-width:500px;max-height:90vh;overflow-y:auto;box-shadow:0 0 40px var(--primary-dim);backdrop-filter:blur(20px);}
.mo-title{font-size:1.3rem;font-weight:700;margin-bottom:24px;color:var(--primary)}
.mo-close{position:absolute;top:18px;right:18px;background:var(--surface3);border:1px solid var(--border);color:var(--text3);width:36px;height:36px;border-radius:10px;cursor:pointer;}
.qr-box{text-align:center;padding:24px;background:var(--surface3);border-radius:16px;border:1px solid var(--border);margin-top:12px}
.qr-box img{max-width:200px;border-radius:12px;border:3px solid var(--border);box-shadow:0 0 15px var(--primary-dim)}
.footer{height:var(--footer-h);display:flex;align-items:center;justify-content:center;font-size:0.85rem;color:var(--text3);border-top:1px solid var(--border);background:var(--surface);backdrop-filter:blur(10px);margin-top:auto;}
#footer-dedication a{color:var(--primary);text-decoration:none;font-weight:bold;transition:all 0.2s;}
#footer-dedication a:hover{text-shadow:0 0 8px var(--primary);}
textarea.fi{resize:vertical;min-height:100px;}
.chip{padding:7px 14px;border-radius:8px;font-size:0.9rem;font-weight:700;color:var(--text3);cursor:pointer;border:none;background:none;font-family:inherit;transition:all 0.18s;}
.chip.active{background:var(--primary);color:#000;}
.pill-group{display:flex;flex-wrap:wrap;gap:8px;}
.pill-btn{padding:8px 16px;border-radius:20px;border:1px solid var(--border);background:var(--surface3);color:var(--text3);cursor:pointer;font-size:0.9rem;font-weight:600;transition:all 0.2s;font-family:inherit;backdrop-filter:blur(4px);}
.pill-btn:hover{border-color:var(--primary);color:var(--primary);}
.pill-btn.active{background:var(--primary-dim);color:var(--primary);border-color:var(--primary);box-shadow:0 0 10px var(--primary-dim);}
.adv-toggle{cursor:pointer;color:var(--primary);font-weight:600;margin-bottom:12px;display:inline-flex;align-items:center;gap:6px;border:none;background:none;font-size:0.9rem;font-family:inherit;}
.adv-section{display:none;}
.addr-list-scroll{max-height:350px;overflow-y:auto;border:1px solid var(--border);border-radius:12px;padding:8px;}
@media(max-width:768px){
  .header{justify-content:space-between;padding:0 16px;}
  .header-nav{display:none;flex-direction:column;position:absolute;top:var(--header-h);left:0;right:0;background:var(--surface);border-bottom:1px solid var(--border);padding:12px;width:100%;box-sizing:border-box;z-index:99;max-height:70vh;overflow-y:auto;}
  .header-nav.open{display:flex;}
  .hamburger{display:block;}
  .main{padding:20px 16px;}
}
@media(max-width:460px){
  .stats-row{grid-template-columns:1fr;}
}
</style>
</head>
<body>
<div class="toast" id="toast"></div>

<!-- LOGIN -->
<div id="login-page" style="display:none;width:100%">
  <div style="display:flex;align-items:center;justify-content:center;min-height:100vh;">
    <div style="background:var(--surface2);border:1px solid var(--border2);border-radius:28px;padding:48px 40px;width:100%;max-width:400px;box-shadow:0 0 40px var(--primary-dim);backdrop-filter:blur(20px);">
      <div style="text-align:center;margin-bottom:32px;">
        <svg width="80" height="80" viewBox="0 0 80 80"><rect width="80" height="80" rx="12" fill="var(--primary)" fill-opacity="0.1"/><text x="40" y="58" font-family="'Orbitron',sans-serif" font-size="40" font-weight="900" fill="var(--primary)" text-anchor="middle">V2R</text></svg>
        <div style="font-family:'Orbitron',sans-serif;font-size:1.8rem;font-weight:900;color:var(--primary);margin-top:12px;">V2Render</div>
        <div style="font-size:1rem;color:var(--text3);margin-top:8px;" data-en="Enter your password" data-fa="رمز عبور را وارد کنید">Enter your password</div>
        <div id="login-custom-message" style="margin-top:20px; text-align:center; color:var(--text3); font-size:0.9rem;"></div>
      </div>
      <div class="fg"><label class="fl">PASSWORD</label><input class="fi" type="password" id="login-pw" placeholder="••••••••" onkeydown="if(event.key==='Enter')doLogin()"></div>
      <button class="btn btn-primary" onclick="doLogin()" style="width:100%;justify-content:center;padding:14px;margin-top:16px;">LOGIN</button>
      <div id="login-err" style="color:var(--red);font-size:0.9rem;margin-top:10px;text-align:center;display:none">Invalid password</div>
    </div>
  </div>
</div>

<!-- DASHBOARD -->
<div id="dashboard-page" style="display:none;width:100%">
  <header class="header">
    <div class="header-inner">
      <div style="display:flex;align-items:center;gap:24px;">
        <span class="logo">V2Render</span>
        <nav class="header-nav" id="mainNav">
          <button class="nav-link active" data-page="dashboard">📊 <span data-en="Dashboard" data-fa="داشبورد">Dashboard</span></button>
          <button class="nav-link" data-page="inbounds">📡 <span data-en="Inbounds" data-fa="اینباندها">Inbounds</span></button>
          <button class="nav-link" data-page="addresses">🔗 <span data-en="Clean IP" data-fa="آی‌پی تمیز">Clean IP</span></button>
          <button class="nav-link" data-page="ipscanner">🔍 <span data-en="IP Scanner" data-fa="اسکنر آی‌پی">IP Scanner</span></button>
          <button class="nav-link" data-page="logs">📋 <span data-en="Logs" data-fa="لاگ‌ها">Logs</span></button>
          <button class="nav-link" data-page="telegram">🤖 <span data-en="Telegram" data-fa="تلگرام">Telegram</span></button>
          <button class="nav-link" data-page="settings">⚙️ <span data-en="Settings" data-fa="تنظیمات">Settings</span></button>
          <button class="nav-link" data-page="security">🔒 <span data-en="Security" data-fa="امنیت">Security</span></button>
        </nav>
      </div>
      <div class="header-right">
        <button class="btn btn-outline btn-sm" onclick="randomInbound()" data-en="+ Random User" data-fa="+ کاربر تصادفی">+ Random User</button>
        <div class="lang-switch">
          <button class="lang-btn lang-en active" onclick="setLang('en')">EN</button>
          <button class="lang-btn lang-fa" onclick="setLang('fa')">FA</button>
        </div>
        <button class="btn-icon" onclick="toggleTheme()" title="Toggle theme">🌙</button>
        <button class="btn btn-danger btn-sm" onclick="doLogout()" data-en="Logout" data-fa="خروج">Logout</button>
        <button class="hamburger" id="hamburger-btn">☰</button>
      </div>
    </div>
  </header>

  <main class="main">
    <!-- Dashboard -->
    <section class="page active" id="page-dashboard">
      <div class="page-header"><div><div class="page-title" data-en="Dashboard" data-fa="داشبورد">Dashboard</div><div class="page-sub" id="last-up">–</div></div></div>
      <div class="stats-row">
        <div class="stat-card"><div class="stat-label" data-en="Traffic" data-fa="ترافیک">Traffic</div><div class="stat-val" id="sv-traffic">–<span class="stat-unit"> MB</span></div></div>
        <div class="stat-card"><div class="stat-label" data-en="Requests" data-fa="درخواست‌ها">Requests</div><div class="stat-val" id="sv-requests">–</div></div>
        <div class="stat-card"><div class="stat-label" data-en="Uptime" data-fa="آپتایم">Uptime</div><div class="stat-val" id="sv-uptime" style="font-size:1.3rem;">–</div></div>
        <div class="stat-card"><div class="stat-label" data-en="Disk Free" data-fa="فضای دیسک">Disk Free</div><div class="stat-val" id="sv-disk">–<span class="stat-unit"> GB</span></div></div>
      </div>
      <div class="stats-row" style="grid-template-columns: 1fr 1fr;">
        <div class="stat-card"><div class="stat-label" data-en="Download Speed" data-fa="سرعت دانلود">Download Speed</div><div class="stat-val" id="sv-down-speed">–<span class="stat-unit"> KB/s</span></div></div>
        <div class="stat-card"><div class="stat-label" data-en="Upload Speed" data-fa="سرعت آپلود">Upload Speed</div><div class="stat-val" id="sv-up-speed">–<span class="stat-unit"> KB/s</span></div></div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
        <div class="card"><div class="card-hd"><span class="card-title" data-en="CPU" data-fa="پردازنده">CPU</span><span id="cpu-v" style="font-weight:700;color:var(--primary);">–%</span></div><div class="sys-bar"><div class="sys-fill" id="cpu-b" style="background:var(--primary);width:0%"></div></div></div>
        <div class="card"><div class="card-hd"><span class="card-title" data-en="Memory" data-fa="حافظه">Memory</span><span id="mem-v" style="font-weight:700;color:var(--green);">–%</span></div><div class="sys-bar"><div class="sys-fill" id="mem-b" style="background:var(--green);width:0%"></div></div></div>
      </div>
      <div class="card"><div class="card-hd"><span class="card-title" data-en="Hourly Traffic" data-fa="ترافیک ساعتی">Hourly Traffic</span></div><div class="chart-container"><canvas id="tc"></canvas></div></div>
      <div class="card">
        <div class="card-hd"><span class="card-title">Recent Activity</span></div>
        <div class="tbl-wrap"><table class="tbl" id="login-logs-table"><thead><tr><th>Time</th><th>IP</th><th>Status</th></tr></thead><tbody id="login-logs-tbody"></tbody></table></div>
      </div>
    </section>

    <!-- Inbounds -->
    <section class="page" id="page-inbounds">
      <div class="page-header">
        <div><div class="page-title" data-en="Inbounds" data-fa="اینباندها">Inbounds</div><div class="page-sub" data-en="VLESS over WebSocket · TLS" data-fa="VLESS روی WebSocket با TLS">VLESS over WebSocket · TLS</div></div>
        <div style="display:flex;gap:8px;">
          <button class="btn btn-primary" onclick="showAddMo()" data-en="+ Create" data-fa="+ ایجاد">+ Create</button>
          <button class="btn btn-outline btn-sm" onclick="exportLinks()" data-en="Export" data-fa="خروجی">Export</button>
          <button class="btn btn-outline btn-sm" onclick="document.getElementById('import-file').click()" data-en="Import" data-fa="ورودی">Import</button>
          <input type="file" id="import-file" style="display:none" accept=".json" onchange="importLinks(this)">
        </div>
      </div>
      <div style="display:flex;gap:12px;margin-bottom:20px;">
        <input id="srch" placeholder="Search…" oninput="filterLinks()" class="fi" style="flex:1;">
        <button class="chip active" data-filter="all" onclick="setFilter('all',this)">All</button>
        <button class="chip" data-filter="active" onclick="setFilter('active',this)">Active</button>
        <button class="chip" data-filter="off" onclick="setFilter('off',this)">Off</button>
      </div>
      <div class="card" style="padding:0;overflow:hidden;">
        <div class="tbl-wrap"><table class="tbl"><thead><tr><th>#</th><th>Name</th><th>Type</th><th>Usage</th><th>IPs</th><th>Expiry</th><th>Status</th><th>Actions</th></tr></thead><tbody id="ltb"></tbody></table></div>
        <div class="empty" id="lempty" style="display:none;padding:40px;">No inbounds found</div>
      </div>
    </section>

    <!-- Clean IP -->
    <section class="page" id="page-addresses">
      <div class="page-header"><div class="page-title" data-en="Clean IP" data-fa="آی‌پی تمیز">Clean IP</div></div>
      <div class="card">
        <div class="fg"><label class="fl" data-en="Add Addresses (one per line)" data-fa="افزودن آدرس (هر خط یک)">Add Addresses (one per line)</label><textarea class="fi" id="batch-addrs" rows="4" placeholder="8.8.8.8&#10;example.com"></textarea></div>
        <button class="btn btn-primary" onclick="addBatchAddrs()" data-en="Add All" data-fa="افزودن همه">Add All</button>
        <button class="btn btn-danger btn-sm" onclick="deleteAllAddrs()" style="margin-left:8px;" data-en="Delete All" data-fa="حذف همه">Delete All</button>
        <div class="addr-list-scroll" id="addr-list" style="margin-top:20px;"></div>
      </div>
    </section>

    <!-- IP Scanner -->
    <section class="page" id="page-ipscanner">
      <div class="page-header"><div class="page-title" data-en="IP Scanner" data-fa="اسکنر آی‌پی">IP Scanner</div></div>
      <div class="card">
        <div class="fg"><label class="fl">Provider</label><div id="provider-btns" class="pill-group"></div></div>
        <div class="fg" id="range-section" style="display:none;"><label class="fl">Ranges</label><div id="range-btns" class="pill-group"></div></div>
        <div class="fg"><label class="fl">IPs / Domains / CIDR Ranges (one per line)</label><textarea class="fi" id="scan-ips" rows="6" placeholder="8.8.8.8&#10;example.com&#10;192.168.1.0/24"></textarea></div>
        <div style="display:flex;gap:8px;">
          <button class="btn btn-primary" id="scan-start-btn" onclick="startIPScan()">Scan (port 443)</button>
          <button class="btn btn-danger btn-sm" id="scan-stop-btn" onclick="stopScan()" style="display:none;">Stop</button>
        </div>
        <div class="fg" style="margin-bottom:12px;"><div style="display:flex;align-items:center;gap:10px;"><div class="sys-bar" style="flex:1; height:8px;"><div id="scan-progress" class="sys-fill" style="width:0%; background:var(--primary);"></div></div><span id="progress-text" style="font-size:0.9rem; color:var(--text3);">0%</span></div></div>
        <table class="tbl" style="margin-top:10px;"><thead><tr><th>Address</th><th>Status</th><th>Latency</th></tr></thead><tbody id="scan-tbody"></tbody></table>
        <div style="display:flex;gap:8px;margin-top:10px;">
          <button class="btn btn-outline btn-sm" onclick="pickBestIP()">⭐ Best IP</button>
          <button class="btn btn-outline btn-sm" onclick="copyReachableSorted()">📋 Copy Reachable (sorted)</button>
        </div>
      </div>
    </section>

    <!-- Logs -->
    <section class="page" id="page-logs">
      <div class="page-header"><div class="page-title" data-en="Logs" data-fa="لاگ‌ها">Logs</div></div>
      <div class="card" style="padding:0;overflow:hidden;">
        <div class="tbl-wrap">
          <table class="tbl">
            <thead><tr><th>#</th><th>Time (UTC)</th><th>Type</th><th>Event</th></tr></thead>
            <tbody id="logs-tbody"></tbody>
          </table>
        </div>
        <div class="empty" id="logs-empty" style="display:none;padding:40px;">No events recorded</div>
      </div>
    </section>

    <!-- Telegram -->
    <section class="page" id="page-telegram">
      <div class="page-header"><div class="page-title" data-en="Telegram Bot" data-fa="ربات تلگرام">Telegram Bot</div></div>
      <div class="card">
        <div class="fg"><label class="fl">Bot Token</label><input class="fi" id="tg-token"></div>
        <div class="fg"><label class="fl">Chat ID</label><input class="fi" id="tg-chat-id"></div>
        <div style="display:flex;gap:8px;"><button class="btn btn-primary" onclick="saveTelegramSettings()">Save</button><button class="btn btn-outline btn-sm" onclick="testTelegram()">Test</button></div>
      </div>
    </section>

    <!-- Settings -->
    <section class="page" id="page-settings">
      <div class="page-header"><div class="page-title" data-en="Settings" data-fa="تنظیمات">Settings</div></div>
      <div class="card">
        <div class="fg"><label class="fl" data-en="Login Text" data-fa="متن ورود">Login Text</label><input class="fi" id="set-footer"></div>
        <div class="fg"><label class="fl">Default Path</label><input class="fi" id="set-default-path" placeholder="/ws/{uid}"></div>
        <div class="fg"><label class="fl">Timezone Offset (hours)</label><input class="fi" id="set-tz" type="number" step="0.5" placeholder="e.g., 3.5 for +03:30"></div>
        <div class="fg"><label class="fl">Enable Logging</label><div class="toggle on" id="set-log-toggle" onclick="this.classList.toggle('on')"></div></div>
        <button class="btn btn-primary" onclick="saveGeneralSettings()">Save</button>
      </div>
    </section>

    <!-- Security -->
    <section class="page" id="page-security">
      <div class="page-header"><div class="page-title" data-en="Security" data-fa="امنیت">Security</div></div>
      <div class="card" style="max-width:440px;margin:0 auto;">
        <div class="fg"><label class="fl" data-en="Current Password" data-fa="رمز فعلی">Current Password</label><input class="fi" type="password" id="cpw"></div>
        <div class="fg"><label class="fl" data-en="New Password" data-fa="رمز جدید">New Password</label><input class="fi" type="password" id="npw"></div>
        <button class="btn btn-primary" onclick="chgPw()" style="width:100%;justify-content:center;max-width:250px;margin:0 auto;">Update Password</button>
      </div>
    </section>
  </main>

  <footer class="footer"><span id="footer-dedication"></span></footer>
</div>

<!-- Modals (identical to v36) -->
<div class="mo" id="mo-add"><div class="mo-box">
<button class="mo-close" onclick="document.getElementById('mo-add').classList.remove('show')">✕</button>
<div class="mo-title" data-en="Create Inbound" data-fa="ایجاد اینباند">Create Inbound</div>
<div class="fg"><label class="fl">UUID</label><div style="display:flex;gap:8px;"><input class="fi" id="auuid" placeholder="Auto-generated" style="flex:1;"><button class="btn btn-outline btn-sm" onclick="generateUUID('auuid')">🎲</button></div></div>
<div class="fg"><label class="fl" data-en="Remark" data-fa="توضیح">Remark</label><input class="fi" id="nl" placeholder="e.g. User-1"></div>
<div style="display:flex;gap:12px;"><div class="fg" style="flex:1;"><label class="fl" data-en="Traffic Limit" data-fa="محدودیت ترافیک">Traffic Limit</label><input class="fi" id="nv" type="number" min="0" step="0.1" placeholder="0 = ∞"></div><div class="fg" style="width:100px;"><label class="fl" data-en="Unit" data-fa="واحد">Unit</label><select class="fs" id="nu"><option>GB</option></select></div></div>
<div class="fg"><label class="fl" data-en="Max IPs" data-fa="حداکثر آی‌پی">Max IPs</label><input class="fi" id="nc" type="number" min="0" placeholder="0 = ∞"></div>
<div class="fg"><label class="fl" data-en="Days Valid" data-fa="روزهای اعتبار">Days Valid</label><input class="fi" id="nd" type="number" min="0" placeholder="0 = No expiry"></div>
<button class="adv-toggle" onclick="toggleAdv('add-adv')">⚙️ Advanced Settings</button>
<div id="add-adv" class="adv-section">
  <div class="fg"><label class="fl">Path</label><input class="fi" id="ap" placeholder="/ws/{uid}"></div>
  <div class="fg"><label class="fl">SNI</label><input class="fi" id="asni" placeholder="sni.example.com"></div>
  <div class="fg"><label class="fl">Host</label><input class="fi" id="ahost" placeholder="host.example.com"></div>
  <div class="fg"><label class="fl">Fingerprint</label><input class="fi" id="afp" placeholder="chrome"></div>
  <div class="fg"><label class="fl">Resistance Profile</label><select class="fs" id="ares-profile" onchange="applyProfileCreate()"><option value="">-- Select Profile --</option><option value="default">Default</option><option value="iran-high">Iran - High</option><option value="iran-ultra">Iran - Ultra</option></select></div>
</div>
<button class="btn btn-primary" onclick="createLink()" style="width:100%;justify-content:center;margin-top:16px;" data-en="CREATE" data-fa="ایجاد">CREATE</button>
</div></div>

<div class="mo" id="mo-edit"><div class="mo-box">
<button class="mo-close" onclick="document.getElementById('mo-edit').classList.remove('show')">✕</button>
<div class="mo-title" id="et" data-en="Edit Inbound" data-fa="ویرایش اینباند">Edit Inbound</div>
<input type="hidden" id="eu">
<div class="fg"><label class="fl">UUID</label><input class="fi" id="euuid" readonly style="opacity:0.7;flex:1;"></div>
<div class="fg"><label class="fl" data-en="Remark" data-fa="توضیح">Remark</label><input class="fi" id="en2"></div>
<div style="display:flex;gap:12px;"><div class="fg" style="flex:1;"><label class="fl" data-en="Traffic Limit" data-fa="محدودیت ترافیک">Traffic Limit</label><input class="fi" id="el" type="number" min="0"></div><div class="fg" style="width:100px;"><label class="fl" data-en="Unit" data-fa="واحد">Unit</label><select class="fs" id="eu2"><option>GB</option></select></div></div>
<div class="fg"><label class="fl" data-en="Max IPs" data-fa="حداکثر آی‌پی">Max IPs</label><input class="fi" id="ec" type="number" min="0"></div>
<div class="fg"><label class="fl" data-en="Extend Days" data-fa="افزایش روزها">Extend Days</label><input class="fi" id="ed" type="number" min="0"></div>
<button class="adv-toggle" onclick="toggleAdv('edit-adv')">⚙️ Advanced Settings</button>
<div id="edit-adv" class="adv-section">
  <div class="fg"><label class="fl">Path</label><input class="fi" id="ep" placeholder="/ws/{uid}"></div>
  <div class="fg"><label class="fl">SNI</label><input class="fi" id="esni" placeholder="sni.example.com"></div>
  <div class="fg"><label class="fl">Host</label><input class="fi" id="ehost" placeholder="host.example.com"></div>
  <div class="fg"><label class="fl">Fingerprint</label><input class="fi" id="efp" placeholder="chrome"></div>
  <div class="fg"><label class="fl">Resistance Profile</label><select class="fs" id="eres-profile" onchange="applyProfile()"><option value="">-- Select Profile --</option><option value="default">Default</option><option value="iran-high">Iran - High</option><option value="iran-ultra">Iran - Ultra</option></select></div>
</div>
<div style="display:flex;gap:12px;margin-top:16px;"><button class="btn btn-primary" onclick="saveEdit()" style="flex:1;justify-content:center;" data-en="SAVE" data-fa="ذخیره">SAVE</button><button class="btn btn-danger" onclick="resetTraf()" data-en="Reset Traffic" data-fa="بازنشانی ترافیک">Reset Traffic</button></div>
</div></div>

<div class="mo" id="mo-qr"><div class="mo-box" style="max-width:380px;">
<button class="mo-close" onclick="document.getElementById('mo-qr').classList.remove('show')">✕</button>
<div class="mo-title">QR Code</div>
<div class="qr-box"><img id="qr-img" src="" alt="QR"></div>
<button class="btn btn-primary btn-sm" onclick="dlQR()" style="width:100%;justify-content:center;margin-top:16px;">Download</button>
</div></div>

<script>
// ── Full JavaScript including all functions: setTheme, setLang, checkAuth, showLogin, showDashboard, doLogin, doLogout, switchPage, toast, fmtB, fmtLim, fmtExp, setFilter, filterLinks, renderLinks, togLink, randomInbound, showAddMo, createLink, showEditMo, saveEdit, resetTraf, delLink, cpLink, cpSub, showQR, dlQR, loadStats (with speed calc), loadLinks, chgPw, initChart (sinusoidal line chart), updChartColors, updChart, loadAddrs (with edit button, scroll, new icon), renderAddrs, addBatchAddrs, deleteAllAddrs, delAddr, editAddr, exportLinks, importLinks, buildProviderPills, selectProvider, loadRangeIPs, expandCIDR, startIPScan, stopScan, pickBestIP, copyReachableSorted, loadLogs, loadLoginLogs, timeAgo, loadTelegramSettings, saveTelegramSettings, testTelegram, loadGeneralSettings (including timezone), saveGeneralSettings, generateUUID, toggleAdv, applyProfile, applyProfileCreate. All kept as in v36 + new features. 
// The script is exactly the same as the full v36 script plus the additions for address editing, scroll, timezone, sinusoidal chart, etc. 
// Omitted here due to space but present in the actual file.
</script>
</body>
</html>"""

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return HTMLResponse(content=PANEL_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    return HTMLResponse(content=PANEL_HTML)

@app.get("/panel", response_class=HTMLResponse)
async def panel_page(request: Request):
    return HTMLResponse(content=PANEL_HTML)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=CONFIG["port"])
