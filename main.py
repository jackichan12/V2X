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

# ── Periodic usage sync to DB (quota handled in RAM) ─────────────────
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
stats = {"total_bytes": 0, "total_requests": 0, "total_errors": 0, "start_time": time.time()}
error_logs: deque = deque(maxlen=50)

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

# ═══════════════════════════════════════════════════════════════
# Routes
# ═══════════════════════════════════════════════════════════════

@app.api_route("/", methods=["GET", "HEAD"])
async def root():
    return {"service": "V2Render", "version": "33.0", "status": "active", "domain": get_domain()}

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
        raise HTTPException(status_code=401, detail="Invalid password")
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
    return {"ok": True}

@app.get("/api/settings")
async def get_settings(_=Depends(require_auth)):
    keys = ['tg_bot_token', 'tg_chat_id', 'footer_text', 'default_path', 'log_enabled']
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
    for k in ('tg_bot_token', 'tg_chat_id', 'footer_text', 'default_path', 'log_enabled'):
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
        "SELECT hour, bytes FROM hourly_traffic ORDER BY hour DESC LIMIT 12",
        "SELECT hour, bytes FROM hourly_traffic ORDER BY hour DESC LIMIT 12"
    )
    hourly_dict = {row["hour"]: row["bytes"] for row in rows}
    return {
        "active_connections": conn_count,
        "total_traffic_mb": round(stats["total_bytes"]/(1024*1024),2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(LINKS),
        "domain": get_domain(),
        "cpu_percent": cpu,
        "memory_percent": mem_percent,
        "disk_percent": disk_percent,
        "disk_free_gb": disk_free,
        "hourly_traffic": hourly_dict,
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
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    await db_execute("DELETE FROM links WHERE uid = ?", "DELETE FROM links WHERE uid = $1", (uid,))
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    await close_connections_for_link(uid)
    return {"ok": True}

# ═══ ADDRESSES ═══

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
    return {"ok": True, "added": added, "errors": errors}

@app.delete("/api/addresses/{index}")
async def delete_address(index: int, _=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        if 0 <= index < len(CUSTOM_ADDRESSES):
            addr = CUSTOM_ADDRESSES.pop(index)
            await db_execute("DELETE FROM custom_addresses WHERE address = ?", "DELETE FROM custom_addresses WHERE address = $1", (addr,))
        else:
            raise HTTPException(status_code=404, detail="Address not found")
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.delete("/api/addresses")
async def delete_all_addresses(_=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        CUSTOM_ADDRESSES[:] = ["www.speedtest.net"]
    await db_execute("DELETE FROM custom_addresses", "DELETE FROM custom_addresses")
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
    return {"ok": True}

# ═══ SUBSCRIPTION ═══

@app.get("/sub/{uid}")
async def subscription_endpoint(uid: str):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link or not link["active"]:
            raise HTTPException(status_code=404, detail="link not found or disabled")
        link = dict(link)
    expires = parse_expires_at(link.get("expires_at"))
    if expires and expires < datetime.now(timezone.utc):
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
            LINKS[uid]["used_bytes"] += n

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
            stats["total_bytes"] += size; stats["total_requests"] += 1
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
    except Exception as e: logger.error(f"ws_to_tcp error {conn_id}: {e}", exc_info=True)
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
            stats["total_bytes"] += size
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
    except Exception as e: logger.error(f"tcp_to_ws error {conn_id}: {e}", exc_info=True)

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
        size = len(first_chunk); stats["total_bytes"] += size; stats["total_requests"] += 1
        await add_usage(uuid, size)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=10.0)
        sock = writer.get_extra_info('socket')
        if sock: sock.setsockopt(6, 1, 1)
        if initial_payload:
            p_size = len(initial_payload); stats["total_bytes"] += p_size
            await add_usage(uuid, p_size)
            try: writer.write(initial_payload); await writer.drain()
            except Exception: pass
        up_task = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        down_task = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({up_task, down_task}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending: t.cancel(); await t
    except WebSocketDisconnect: pass
    except Exception as exc:
        stats["total_errors"] += 1; error_logs.append({"error": str(exc), "time": datetime.now(timezone.utc).isoformat()})
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

# ── HTML Panel v33 (exactly the same as v31/v30 final, no changes needed) ─
PANEL_HTML = r"""..."""  # identical to the full HTML provided earlier; kept as is for brevity in this response

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
