import asyncio
import json
import os
import hashlib
import secrets
import time
import re
import base64
from datetime import datetime, timezone, timedelta
from urllib.parse import quote
from collections import deque, defaultdict
from typing import Optional, Dict, Any

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends, UploadFile, File
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

# Optional PostgreSQL support
try:
    import asyncpg
    HAS_POSTGRES = True
except ImportError:
    HAS_POSTGRES = False

# ── Logging Configuration ─────────────────────────────────────────────────
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
        }
    },
    "handlers": {
        "json_console": {
            "class": "logging.StreamHandler",
            "formatter": "json",
        }
    },
    "root": {"level": "INFO", "handlers": ["json_console"]},
}
logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("V2Render")

# ── Rate Limiter ──────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

# ── Config ────────────────────────────────────────────────────────────────
CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret_key": os.environ.get("SECRET_KEY", secrets.token_urlsafe(32)),
    "jwt_algorithm": "HS256",
    "jwt_expire_minutes": 10080,
    "db_path": os.environ.get("DB_PATH", "panel.db"),
    "admin_password": os.environ.get("ADMIN_PASSWORD", "admin"),
    "database_url": os.environ.get("DATABASE_URL", ""),
}

# ── Database Abstraction ──────────────────────────────────────────────────
if CONFIG["database_url"] and HAS_POSTGRES:
    DB_BACKEND = "postgresql"
    pg_pool: Optional[asyncpg.Pool] = None

    async def init_pg():
        global pg_pool
        pg_pool = await asyncpg.create_pool(CONFIG["database_url"], min_size=2, max_size=10)
        async with pg_pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS links (
                    uid TEXT PRIMARY KEY,
                    label TEXT NOT NULL,
                    limit_bytes BIGINT DEFAULT 0,
                    used_bytes BIGINT DEFAULT 0,
                    max_connections INT DEFAULT 0,
                    created_at TEXT NOT NULL,
                    active BOOLEAN DEFAULT TRUE,
                    expires_at TEXT
                );
                CREATE TABLE IF NOT EXISTS hourly_traffic (
                    hour TEXT PRIMARY KEY,
                    bytes BIGINT DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS daily_traffic (
                    day TEXT PRIMARY KEY,
                    bytes BIGINT DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS custom_addresses (
                    id SERIAL PRIMARY KEY,
                    address TEXT NOT NULL UNIQUE
                );
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );
            """)

    async def db_execute(query_sqlite: str, query_pg: str, params: tuple = ()):
        async with pg_pool.acquire() as conn:
            await conn.execute(query_pg, *params)

    async def db_fetchall(query_sqlite: str, query_pg: str, params: tuple = ()) -> list:
        async with pg_pool.acquire() as conn:
            rows = await conn.fetch(query_pg, *params)
            return [dict(row) for row in rows]

    async def db_fetchone(query_sqlite: str, query_pg: str, params: tuple = ()) -> Optional[dict]:
        async with pg_pool.acquire() as conn:
            row = await conn.fetchrow(query_pg, *params)
            return dict(row) if row else None

    async def get_db():
        return None

    async def pg_dump_tables() -> dict:
        """Export all tables as JSON."""
        async with pg_pool.acquire() as conn:
            links = [dict(row) for row in await conn.fetch("SELECT * FROM links")]
            hourly = [dict(row) for row in await conn.fetch("SELECT * FROM hourly_traffic")]
            daily = [dict(row) for row in await conn.fetch("SELECT * FROM daily_traffic")]
            addresses = [dict(row) for row in await conn.fetch("SELECT address FROM custom_addresses")]
            settings = [dict(row) for row in await conn.fetch("SELECT * FROM settings")]
        return {"links": links, "hourly_traffic": hourly, "daily_traffic": daily, "addresses": addresses, "settings": settings}

else:
    DB_BACKEND = "sqlite"

    async def get_db() -> aiosqlite.Connection:
        db = await aiosqlite.connect(CONFIG["db_path"])
        db.row_factory = aiosqlite.Row
        await db.execute("PRAGMA journal_mode=WAL")
        return db

    async def db_execute(query_sqlite: str, query_pg: str = "", params: tuple = ()):
        db = await get_db()
        try:
            await db.execute(query_sqlite, params)
            await db.commit()
        finally:
            await db.close()

    async def db_fetchall(query_sqlite: str, query_pg: str = "", params: tuple = ()) -> list:
        db = await get_db()
        try:
            cursor = await db.execute(query_sqlite, params)
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
        finally:
            await db.close()

    async def db_fetchone(query_sqlite: str, query_pg: str = "", params: tuple = ()) -> Optional[dict]:
        db = await get_db()
        try:
            cursor = await db.execute(query_sqlite, params)
            row = await cursor.fetchone()
            return dict(row) if row else None
        finally:
            await db.close()

    async def init_db():
        db = await get_db()
        try:
            await db.executescript("""
                CREATE TABLE IF NOT EXISTS links (
                    uid TEXT PRIMARY KEY,
                    label TEXT NOT NULL,
                    limit_bytes INTEGER DEFAULT 0,
                    used_bytes INTEGER DEFAULT 0,
                    max_connections INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    active INTEGER DEFAULT 1,
                    expires_at TEXT
                );
                CREATE TABLE IF NOT EXISTS hourly_traffic (
                    hour TEXT PRIMARY KEY,
                    bytes INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS daily_traffic (
                    day TEXT PRIMARY KEY,
                    bytes INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS custom_addresses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    address TEXT NOT NULL UNIQUE
                );
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );
            """)
            await db.commit()
        finally:
            await db.close()

    async def sqlite_dump_tables() -> dict:
        """Export all tables as JSON (from SQLite)."""
        links = await db_fetchall("SELECT * FROM links")
        hourly = await db_fetchall("SELECT * FROM hourly_traffic")
        daily = await db_fetchall("SELECT * FROM daily_traffic")
        addresses = await db_fetchall("SELECT address FROM custom_addresses")
        settings = await db_fetchall("SELECT * FROM settings")
        return {"links": links, "hourly_traffic": hourly, "daily_traffic": daily, "addresses": addresses, "settings": settings}

# ── FastAPI App ───────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    if DB_BACKEND == "postgresql":
        await init_pg()
    else:
        await init_db()
    # Load or create admin password hash
    existing_hash = await db_fetchone(
        "SELECT value FROM settings WHERE key = 'admin_password_hash'",
        "SELECT value FROM settings WHERE key = 'admin_password_hash'",
    )
    global ADMIN_PASSWORD_HASH
    if existing_hash:
        ADMIN_PASSWORD_HASH = existing_hash["value"]
    else:
        ADMIN_PASSWORD_HASH = bcrypt.hashpw(CONFIG["admin_password"].encode(), bcrypt.gensalt()).decode()
        await db_execute(
            "INSERT INTO settings (key, value) VALUES ('admin_password_hash', ?)",
            "INSERT INTO settings (key, value) VALUES ('admin_password_hash', $1)",
            (ADMIN_PASSWORD_HASH,),
        )
    # Default link
    existing_link = await db_fetchone(
        "SELECT uid FROM links WHERE uid = ?",
        "SELECT uid FROM links WHERE uid = $1",
        ("Default",),
    )
    if not existing_link:
        now = datetime.now(timezone.utc).isoformat()
        await db_execute(
            "INSERT INTO links (uid, label, created_at, active) VALUES (?, ?, ?, 1)",
            "INSERT INTO links (uid, label, created_at, active) VALUES ($1, $2, $3, TRUE)",
            ("Default", "Default", now),
        )
    asyncio.create_task(keep_alive())
    asyncio.create_task(cleanup_idle_connections())
    yield
    if DB_BACKEND == "postgresql" and pg_pool:
        await pg_pool.close()

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

# ── In-memory structures ──────────────────────────────────────────────────
connections: dict = {}
connections_lock = asyncio.Lock()
connection_sockets: dict = {}
link_ip_map: dict = defaultdict(set)
stats = {"total_bytes": 0, "total_requests": 0, "total_errors": 0, "start_time": time.time()}
error_logs: deque = deque(maxlen=50)
http_client: Optional[httpx.AsyncClient] = None

CACHE_TTL = 60
link_cache: dict = {}

SESSION_COOKIE = "v2r_session"
UNLIMITED_QUOTA_BYTES = 53687091200000

ADMIN_PASSWORD_HASH: str = ""

# ── Auth helpers ──────────────────────────────────────────────────────────
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

# ── Background tasks ──────────────────────────────────────────────────────
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
            idle_ids = [cid for cid, info in connections.items() if now - info.get("last_active", 0) > 300]
        for cid in idle_ids:
            ws = connection_sockets.get(cid)
            if ws:
                try:
                    await ws.close(code=1000, reason="idle timeout")
                except Exception:
                    pass
            async with connections_lock:
                connections.pop(cid, None)
            connection_sockets.pop(cid, None)

# ── Helpers ───────────────────────────────────────────────────────────────
def get_domain() -> str:
    return (
        os.environ.get("RENDER_EXTERNAL_URL", os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost"))
        .replace("https://", "").replace("http://", "")
    )

def generate_vless_link(uid: str, remark: str = "V2R", address: str = None) -> str:
    cache_key = f"{uid}:{remark}:{address}"
    cached = link_cache.get(cache_key)
    if cached and cached["expires"] > time.time():
        return cached["link"]
    domain = get_domain()
    addr = address if address else domain
    path = f"/ws/{uid}"
    params = {
        "encryption": "none", "security": "tls", "type": "ws",
        "host": domain, "path": path, "sni": domain, "fp": "chrome", "alpn": "http/1.1"
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
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 * 1024 * 1024)
    if unit == "MB": return int(value * 1024 * 1024)
    if unit == "KB": return int(value * 1024)
    return int(value)

def parse_expires_at(raw: Optional[str]) -> Optional[datetime]:
    if not raw: return None
    try:
        normalised = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalised)
        if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception: return None

def seconds_until_expiry(expires_at_str: Optional[str]) -> Optional[int]:
    exp = parse_expires_at(expires_at_str)
    if exp is None: return None
    remaining = (exp - datetime.now(timezone.utc)).total_seconds()
    return max(0, int(remaining))

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

# ── Routes ─────────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"service": "V2Render", "version": "16.0", "status": "active", "domain": get_domain()}

@app.get("/health")
async def health():
    async with connections_lock: conn_count = len(connections)
    return {"status": "ok", "connections": conn_count, "uptime": uptime()}

@app.get("/favicon.ico")
async def favicon():
    return Response(content=b"", media_type="image/x-icon", status_code=204)

@app.post("/api/login")
@limiter.limit("5/minute")
async def api_login(request: Request):
    body = await request.json()
    password = str(body.get("password") or "")
    if not verify_password(password, ADMIN_PASSWORD_HASH):
        raise HTTPException(status_code=401, detail="Invalid password")
    token = create_jwt_token({"sub": "admin"})
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=CONFIG["jwt_expire_minutes"]*60,
                    httponly=True, samesite="lax", secure=True if get_domain()!="localhost" else False, path="/")
    return resp

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

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    async with connections_lock: conn_count = len(connections)
    cpu_percent = await asyncio.to_thread(psutil.cpu_percent, 0.1)
    disk = psutil.disk_usage("/")
    return {
        "active_connections": conn_count,
        "total_traffic_mb": round(stats["total_bytes"]/(1024*1024),2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(await db_fetchall("SELECT uid FROM links WHERE active=1", "SELECT uid FROM links WHERE active = TRUE")),
        "domain": get_domain(),
        "cpu_percent": cpu_percent,
        "memory_percent": psutil.virtual_memory().percent,
        "disk_percent": disk.percent,
        "disk_free_gb": round(disk.free / (1024**3), 1),
        "hourly_traffic": dict(await db_fetchall("SELECT hour, bytes FROM hourly_traffic ORDER BY hour DESC LIMIT 12", "SELECT hour, bytes FROM hourly_traffic ORDER BY hour DESC LIMIT 12")),
    }

@app.get("/api/logs")
async def get_logs(_=Depends(require_auth)):
    return {"logs": list(error_logs)}

@app.get("/api/backup")
async def backup_database(_=Depends(require_auth)):
    if DB_BACKEND == "sqlite":
        return FileResponse(CONFIG["db_path"], filename="panel.db", media_type="application/octet-stream")
    else:
        raise HTTPException(status_code=400, detail="Backup only available for SQLite")

@app.get("/api/export")
async def export_data(_=Depends(require_auth)):
    if DB_BACKEND == "sqlite":
        data = await sqlite_dump_tables()
    else:
        data = await pg_dump_tables()
    return JSONResponse(content=data)

@app.post("/api/test-connection")
async def test_connection(request: Request, _=Depends(require_auth)):
    body = await request.json()
    address = body.get("address", "").strip()
    port = int(body.get("port", 443))
    if not address or not re.match(r'^[a-zA-Z0-9\-_.]+$', address):
        raise HTTPException(status_code=400, detail="Invalid address")
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=5.0)
        writer.close()
        return {"ok": True, "message": f"Connected to {address}:{port}"}
    except Exception as e:
        return {"ok": False, "message": str(e)}

@app.post("/api/links")
@limiter.limit("10/minute")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "New Link").strip()[:60]
    if not re.match(r'^[a-zA-Z0-9\-_. ]+$', label):
        raise HTTPException(status_code=400, detail="Inbound name must contain only English letters, numbers, and characters: - _ . space")
    if not label: raise HTTPException(status_code=400, detail="Inbound name is required")
    existing = await db_fetchone("SELECT uid FROM links WHERE label = ?", "SELECT uid FROM links WHERE label = $1", (label,))
    if existing: raise HTTPException(status_code=400, detail="An inbound with this name already exists")
    limit_value = float(body.get("limit_value") or 0)
    limit_unit = body.get("limit_unit") or "GB"
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    max_conn = int(body.get("max_connections") or 0)
    if max_conn < 0: max_conn = 0
    days_valid = body.get("days_valid")
    expires_at = None
    if days_valid is not None:
        try:
            days_valid = int(days_valid)
            if days_valid > 0: expires_at = (datetime.now(timezone.utc) + timedelta(days=days_valid)).isoformat()
        except (ValueError, TypeError): pass
    uid = label
    now = datetime.now(timezone.utc).isoformat()
    await db_execute(
        "INSERT INTO links (uid, label, limit_bytes, max_connections, created_at, active, expires_at) VALUES (?,?,?,?,?,1,?)",
        "INSERT INTO links (uid, label, limit_bytes, max_connections, created_at, active, expires_at) VALUES ($1,$2,$3,$4,$5,TRUE,$6)",
        (uid, label, limit_bytes, max_conn, now, expires_at),
    )
    return {
        "uuid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": 0,
        "max_connections": max_conn, "active": True, "created_at": now,
        "expires_at": expires_at,
        "vless_link": generate_vless_link(uid, remark=f"V2R-{label}"),
    }

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    rows = await db_fetchall("SELECT * FROM links ORDER BY created_at DESC", "SELECT * FROM links ORDER BY created_at DESC")
    result = []
    for row in rows:
        uid = row["uid"]
        result.append({
            "uuid": uid,
            "label": row["label"],
            "limit_bytes": row["limit_bytes"],
            "used_bytes": row["used_bytes"],
            "max_connections": row["max_connections"],
            "active": bool(row["active"]),
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "current_connections": await count_connections_for_link(uid),
            "vless_link": generate_vless_link(uid, remark=f"V2R-{row['label']}"),
        })
    return {"links": result}

@app.get("/api/export-links")
async def export_links(_=Depends(require_auth)):
    links = await db_fetchall("SELECT * FROM links", "SELECT * FROM links")
    return JSONResponse(content={"links": [dict(row) for row in links]})

@app.post("/api/import-links")
async def import_links(request: Request, _=Depends(require_auth)):
    body = await request.json()
    imported = body.get("links", [])
    count = 0
    for link in imported:
        uid = link.get("uid") or link.get("label") or secrets.token_hex(8)
        label = link.get("label", "Imported")
        limit_bytes = int(link.get("limit_bytes", 0))
        used_bytes = int(link.get("used_bytes", 0))
        max_conn = int(link.get("max_connections", 0))
        created_at = link.get("created_at") or datetime.now(timezone.utc).isoformat()
        active = 1 if link.get("active", True) else 0
        expires_at = link.get("expires_at")
        try:
            await db_execute(
                "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at) VALUES (?,?,?,?,?,?,?,?)",
                "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (uid) DO UPDATE SET label = EXCLUDED.label, limit_bytes = EXCLUDED.limit_bytes, max_connections = EXCLUDED.max_connections, active = EXCLUDED.active, expires_at = EXCLUDED.expires_at",
                (uid, label, limit_bytes, used_bytes, max_conn, created_at, active, expires_at),
            )
            count += 1
        except Exception:
            pass
    return {"ok": True, "imported": count}

@app.patch("/api/links/{uid}")
async def toggle_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    link = await db_fetchone("SELECT * FROM links WHERE uid = ?", "SELECT * FROM links WHERE uid = $1", (uid,))
    if not link: raise HTTPException(status_code=404, detail="link not found")
    updates = {}
    if "active" in body: updates["active"] = int(body["active"])
    if "limit_value" in body:
        limit_value = float(body.get("limit_value") or 0)
        limit_unit = body.get("limit_unit") or "GB"
        updates["limit_bytes"] = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    if "reset_usage" in body and body["reset_usage"]: updates["used_bytes"] = 0
    if "label" in body:
        new_label = str(body["label"])[:60]
        if new_label != uid:
            existing = await db_fetchone("SELECT uid FROM links WHERE label = ? AND uid != ?", "SELECT uid FROM links WHERE label = $1 AND uid != $2", (new_label, uid))
            if existing: raise HTTPException(status_code=400, detail="Label already in use")
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
    if updates:
        if DB_BACKEND == "sqlite":
            set_clause = ", ".join(f"{k} = ?" for k in updates)
            values = list(updates.values()) + [uid]
            await db_execute(f"UPDATE links SET {set_clause} WHERE uid = ?", "", tuple(values))
        else:
            set_clause = ", ".join(f"{k} = ${i+1}" for i, k in enumerate(updates))
            values = list(updates.values()) + [uid]
            await db_execute("", f"UPDATE links SET {set_clause} WHERE uid = ${len(values)}", tuple(values))
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    await db_execute("DELETE FROM links WHERE uid = ?", "DELETE FROM links WHERE uid = $1", (uid,))
    await close_connections_for_link(uid)
    return {"ok": True}

@app.get("/api/addresses")
async def list_addresses(_=Depends(require_auth)):
    rows = await db_fetchall("SELECT address FROM custom_addresses", "SELECT address FROM custom_addresses")
    return {"addresses": [row["address"] for row in rows]}

@app.post("/api/addresses")
@limiter.limit("10/minute")
async def add_address(request: Request, _=Depends(require_auth)):
    body = await request.json()
    address = (body.get("address") or "").strip()
    if not address or not re.match(r'^[a-zA-Z0-9\-_. ]+$', address):
        raise HTTPException(status_code=400, detail="Invalid address format")
    try:
        await db_execute("INSERT INTO custom_addresses (address) VALUES (?)", "INSERT INTO custom_addresses (address) VALUES ($1)", (address,))
    except (aiosqlite.IntegrityError, asyncpg.exceptions.UniqueViolationError):
        raise HTTPException(status_code=400, detail="Address already exists")
    return {"ok": True}

@app.delete("/api/addresses/{index}")
async def delete_address(index: int, _=Depends(require_auth)):
    rows = await db_fetchall("SELECT id, address FROM custom_addresses ORDER BY id", "SELECT id, address FROM custom_addresses ORDER BY id")
    if 0 <= index < len(rows):
        address_id = rows[index]["id"]
        await db_execute("DELETE FROM custom_addresses WHERE id = ?", "DELETE FROM custom_addresses WHERE id = $1", (address_id,))
    else: raise HTTPException(status_code=404, detail="Address not found")
    return {"ok": True}

@app.delete("/api/addresses")
async def delete_all_addresses(_=Depends(require_auth)):
    await db_execute("DELETE FROM custom_addresses", "DELETE FROM custom_addresses")
    return {"ok": True}

@app.post("/api/addresses/bulk-delete")
async def bulk_delete_addresses(request: Request, _=Depends(require_auth)):
    body = await request.json()
    indices = body.get("indices", [])
    rows = await db_fetchall("SELECT id FROM custom_addresses ORDER BY id", "SELECT id FROM custom_addresses ORDER BY id")
    for idx in indices:
        if 0 <= idx < len(rows):
            await db_execute("DELETE FROM custom_addresses WHERE id = ?", "DELETE FROM custom_addresses WHERE id = $1", (rows[idx]["id"],))
    return {"ok": True}

@app.get("/sub/{uid}")
async def subscription_endpoint(uid: str):
    link = await db_fetchone("SELECT * FROM links WHERE uid = ?", "SELECT * FROM links WHERE uid = $1", (uid,))
    if not link or not link["active"]: raise HTTPException(status_code=404, detail="link not found or disabled")
    expires_at = parse_expires_at(link["expires_at"])
    if expires_at and expires_at < datetime.now(timezone.utc): raise HTTPException(status_code=403, detail="link expired")
    addresses_rows = await db_fetchall("SELECT address FROM custom_addresses", "SELECT address FROM custom_addresses")
    addresses = [row["address"] for row in addresses_rows]
    sub_content = generate_subscription_content(link, uid, addresses)
    encoded = base64.b64encode(sub_content.encode()).decode()
    total_bytes = link["limit_bytes"] if link["limit_bytes"] > 0 else UNLIMITED_QUOTA_BYTES
    expire_ts = 0
    if expires_at is not None: expire_ts = int(expires_at.timestamp())
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": 'attachment; filename="sub.txt"',
        "profile-update-interval": "6",
        "subscription-userinfo": f"upload={link['used_bytes']}; download=0; total={total_bytes}; expire={expire_ts}",
    }
    return Response(content=encoded, headers=headers)

def generate_subscription_content(link: dict, uid: str, addresses: list) -> str:
    used = link["used_bytes"]; limit = link["limit_bytes"]
    usage_str = f"{_fmt_bytes(used)} / ∞" if limit == 0 else f"{_fmt_bytes(used)} / {_fmt_bytes(limit)}"
    secs_left = seconds_until_expiry(link.get("expires_at"))
    expiry_str = "∞" if secs_left is None else ("Expired" if secs_left == 0 else f"{secs_left//86400} Days Left")
    status_node = generate_vless_link(uid, remark=f"📊 {usage_str} | ⏳ {expiry_str}", address="0.0.0.0")
    links_out = [status_node, generate_vless_link(uid, remark=f"V2R-{link['label']}-Server")]
    for i, addr in enumerate(addresses):
        links_out.append(generate_vless_link(uid, remark=f"V2R-{link['label']}-IP{i+1}", address=addr))
    return "\n".join(links_out)

def _fmt_bytes(b: int) -> str:
    if b >= 1_073_741_824: return f"{b/1_073_741_824:.1f}GB"
    if b >= 1_048_576: return f"{b/1_048_576:.1f}MB"
    return f"{b/1024:.1f}KB"

# ── WebSocket tunnel ──────────────────────────────────────────────────────
RELAY_BUF = 256 * 1024

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

async def atomic_check_and_add_usage(db, uid: str, size: int) -> bool:
    if DB_BACKEND == "sqlite":
        cursor = await db.execute(
            "UPDATE links SET used_bytes = used_bytes + ? WHERE uid = ? AND (limit_bytes = 0 OR used_bytes + ? <= limit_bytes) AND active = 1",
            (size, uid, size)
        )
        await db.commit()
        return cursor.rowcount > 0
    else:
        async with pg_pool.acquire() as conn:
            result = await conn.execute(
                "UPDATE links SET used_bytes = used_bytes + $1 WHERE uid = $2 AND (limit_bytes = 0 OR used_bytes + $1 <= limit_bytes) AND active = TRUE",
                size, uid
            )
            return result == "UPDATE 1"

async def ws_to_tcp(websocket, writer, conn_id, link_uid, db):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect": break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data: continue
            size = len(data)
            if not await atomic_check_and_add_usage(db, link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size; stats["total_requests"] += 1
            async with connections_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += size
                    connections[conn_id]["last_active"] = time.time()
            hour = datetime.now(timezone.utc).strftime("%H:00")
            await db_execute(
                "INSERT INTO hourly_traffic (hour, bytes) VALUES (?,?) ON CONFLICT(hour) DO UPDATE SET bytes = bytes + ?",
                "INSERT INTO hourly_traffic (hour, bytes) VALUES ($1,$2) ON CONFLICT (hour) DO UPDATE SET bytes = hourly_traffic.bytes + $2",
                (hour, size, size)
            )
            day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            await db_execute(
                "INSERT INTO daily_traffic (day, bytes) VALUES (?,?) ON CONFLICT(day) DO UPDATE SET bytes = bytes + ?",
                "INSERT INTO daily_traffic (day, bytes) VALUES ($1,$2) ON CONFLICT (day) DO UPDATE SET bytes = daily_traffic.bytes + $2",
                (day, size, size)
            )
            try: writer.write(data); await writer.drain()
            except Exception: break
    except WebSocketDisconnect: pass
    except Exception as e: logger.error(f"ws_to_tcp error conn={conn_id}: {e}", exc_info=True)
    finally:
        try:
            if writer and not writer.is_closing(): writer.write_eof()
        except Exception: pass

async def tcp_to_ws(websocket, reader, conn_id, link_uid, db):
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data: break
            size = len(data)
            if not await atomic_check_and_add_usage(db, link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size
            async with connections_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += size
                    connections[conn_id]["last_active"] = time.time()
            hour = datetime.now(timezone.utc).strftime("%H:00")
            await db_execute(
                "INSERT INTO hourly_traffic (hour, bytes) VALUES (?,?) ON CONFLICT(hour) DO UPDATE SET bytes = bytes + ?",
                "INSERT INTO hourly_traffic (hour, bytes) VALUES ($1,$2) ON CONFLICT (hour) DO UPDATE SET bytes = hourly_traffic.bytes + $2",
                (hour, size, size)
            )
            day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            await db_execute(
                "INSERT INTO daily_traffic (day, bytes) VALUES (?,?) ON CONFLICT(day) DO UPDATE SET bytes = bytes + ?",
                "INSERT INTO daily_traffic (day, bytes) VALUES ($1,$2) ON CONFLICT (day) DO UPDATE SET bytes = daily_traffic.bytes + $2",
                (day, size, size)
            )
            try:
                await websocket.send_bytes(data)
            except Exception: break
    except Exception as e: logger.error(f"tcp_to_ws error conn={conn_id}: {e}", exc_info=True)

@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await websocket.accept()
    logger.info(f"WebSocket accepted for uuid={uuid}")
    writer = None; conn_id = None; client_ip = get_client_ip(websocket)
    db = None
    try:
        link = await db_fetchone("SELECT * FROM links WHERE uid = ?", "SELECT * FROM links WHERE uid = $1", (uuid,))
        if not link or not link["active"]:
            await websocket.close(code=1008, reason="link not found or disabled"); return
        max_conn = link["max_connections"]
        expires_at = parse_expires_at(link["expires_at"])
        if expires_at and expires_at < datetime.now(timezone.utc):
            await websocket.close(code=1008, reason="link expired"); return
        if max_conn > 0:
            current_conns = await count_connections_for_link(uuid)
            if current_conns >= max_conn:
                await websocket.close(code=1008, reason="connection limit reached"); return

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

        if DB_BACKEND == "sqlite":
            db = await get_db()
        else:
            db = None

        size = len(first_chunk); stats["total_bytes"] += size; stats["total_requests"] += 1
        await atomic_check_and_add_usage(db, uuid, size)

        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=10.0)
        sock = writer.get_extra_info('socket')
        if sock: sock.setsockopt(6, 1, 1)

        if initial_payload:
            p_size = len(initial_payload); stats["total_bytes"] += p_size
            await atomic_check_and_add_usage(db, uuid, p_size)
            try: writer.write(initial_payload); await writer.drain()
            except Exception: pass

        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid, db))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid, db))
        done, pending = await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending: t.cancel(); await t
    except WebSocketDisconnect: logger.info(f"WebSocket disconnected by client {client_ip}")
    except Exception as exc:
        stats["total_errors"] += 1; error_logs.append({"error": str(exc), "time": datetime.now(timezone.utc).isoformat()}); logger.exception("WebSocket error")
    finally:
        if writer:
            try: writer.close(); await writer.wait_closed()
            except Exception: pass
        if db and DB_BACKEND == "sqlite":
            try: await db.close()
            except Exception: pass
        if conn_id:
            async with connections_lock:
                info = connections.pop(conn_id, None); connection_sockets.pop(conn_id, None)
                if info:
                    uid = info.get("uuid"); ip = info.get("ip")
                    if uid and ip:
                        has_other = any(c.get("uuid")==uid and c.get("ip")==ip for c in connections.values())
                        if not has_other:
                            if uid in link_ip_map:
                                link_ip_map[uid].discard(ip)
                                if not link_ip_map[uid]: link_ip_map.pop(uid, None)

def get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded: return forwarded.split(",")[0].strip()
    if websocket.client: return websocket.client.host
    return "unknown"

# ── HTML Panel (V2Render v16 final with all fixes) ────────────────────────
PANEL_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>V2Render Panel</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&family=Inter:wght@400;500;600;700&family=Vazirmatn:wght@400;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
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
html{font-size:18px;}
body{font-family:'Inter','Vazirmatn',sans-serif;color:var(--text);display:flex;flex-direction:column;min-height:100vh;background:var(--bg);transition:background 0.3s,color 0.3s;}
body[dir="rtl"]{direction:rtl;text-align:right}
a{text-decoration:none;color:inherit;}

/* Header */
.header{height:var(--header-h);background:var(--surface);border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:center;padding:0 24px;z-index:100;backdrop-filter:blur(20px);}
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

/* Main */
.main{flex:1;padding:24px 32px;overflow-y:auto;display:flex;flex-direction:column;}
.page{display:none;animation:pgIn .35s ease;flex:1;}
.page.active{display:flex;flex-direction:column;}
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
.tbl{width:100%;border-collapse:collapse}
.tbl th{text-align:left;font-size:0.85rem;font-weight:700;color:var(--text3);padding:14px;text-transform:uppercase;border-bottom:1px solid var(--border);background:var(--surface3)}
.tbl td{padding:14px;border-bottom:1px solid var(--border);font-size:0.95rem}
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
.mo-box{background:var(--surface2);border:1px solid var(--border2);border-radius:24px;padding:36px;width:100%;max-width:500px;box-shadow:0 0 40px var(--primary-dim);backdrop-filter:blur(20px);}
.mo-title{font-size:1.3rem;font-weight:700;margin-bottom:24px;color:var(--primary)}
.mo-close{position:absolute;top:18px;right:18px;background:var(--surface3);border:1px solid var(--border);color:var(--text3);width:36px;height:36px;border-radius:10px;cursor:pointer;}
.qr-box{text-align:center;padding:24px;background:var(--surface3);border-radius:16px;border:1px solid var(--border);margin-top:12px}
.qr-box img{max-width:200px;border-radius:12px;border:3px solid var(--border);box-shadow:0 0 20px var(--primary-dim)}
.footer{height:var(--footer-h);display:flex;align-items:center;justify-content:center;font-size:0.85rem;color:var(--text3);border-top:1px solid var(--border);background:var(--surface);backdrop-filter:blur(10px);margin-top:auto;}
textarea.fi{resize:vertical;min-height:100px;}
.chip{padding:7px 14px;border-radius:8px;font-size:0.9rem;font-weight:700;color:var(--text3);cursor:pointer;border:none;background:none;font-family:inherit;transition:all 0.18s;}
.chip.active{background:var(--primary);color:#000;}

@media(max-width:768px){
  .header{justify-content:space-between;padding:0 16px;}
  .header-nav{display:none;flex-direction:column;position:absolute;top:var(--header-h);left:0;right:0;background:var(--surface);border-bottom:1px solid var(--border);padding:12px;}
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

<div id="login-page" style="display:none;width:100%">
  <div style="display:flex;align-items:center;justify-content:center;min-height:100vh;">
    <div style="background:var(--surface2);border:1px solid var(--border2);border-radius:28px;padding:48px 40px;width:100%;max-width:400px;box-shadow:0 0 40px var(--primary-dim);backdrop-filter:blur(20px);">
      <div style="text-align:center;margin-bottom:32px;">
        <svg width="80" height="80" viewBox="0 0 80 80"><rect width="80" height="80" rx="12" fill="var(--primary)" fill-opacity="0.1"/><text x="40" y="58" font-family="'Orbitron',sans-serif" font-size="40" font-weight="900" fill="var(--primary)" text-anchor="middle">V2R</text></svg>
        <div style="font-family:'Orbitron',sans-serif;font-size:1.8rem;font-weight:900;color:var(--primary);margin-top:12px;">V2Render</div>
        <div style="font-size:1rem;color:var(--text3);margin-top:8px;" data-en="Enter your password" data-fa="رمز عبور را وارد کنید">Enter your password</div>
      </div>
      <div class="fg">
        <label class="fl">PASSWORD</label>
        <input class="fi" type="password" id="login-pw" placeholder="••••••••" onkeydown="if(event.key==='Enter')doLogin()">
      </div>
      <button class="btn btn-primary" onclick="doLogin()" style="width:100%;justify-content:center;padding:14px;margin-top:16px;">LOGIN</button>
      <div id="login-err" style="color:var(--red);font-size:0.9rem;margin-top:10px;text-align:center;display:none">Invalid password</div>
    </div>
  </div>
</div>

<div id="dashboard-page" style="display:none;width:100%">
  <header class="header">
    <div class="header-inner">
      <div class="header-left" style="display:flex;align-items:center;gap:24px;">
        <span class="logo">V2Render</span>
        <nav class="header-nav" id="mainNav">
          <button class="nav-link active" data-page="dashboard" data-en="Dashboard" data-fa="داشبورد">Dashboard</button>
          <button class="nav-link" data-page="inbounds" data-en="Inbounds" data-fa="اینباندها">Inbounds</button>
          <button class="nav-link" data-page="traffic" data-en="Traffic" data-fa="ترافیک">Traffic</button>
          <button class="nav-link" data-page="addresses" data-en="Clean IP" data-fa="آی‌پی تمیز">Clean IP</button>
          <button class="nav-link" data-page="tools" data-en="Tools" data-fa="ابزارها">Tools</button>
          <button class="nav-link" data-page="logs" data-en="Logs" data-fa="لاگ‌ها">Logs</button>
          <button class="nav-link" data-page="security" data-en="Security" data-fa="امنیت">Security</button>
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
        <button class="hamburger" onclick="document.getElementById('mainNav').classList.toggle('open')">☰</button>
      </div>
    </div>
  </header>

  <main class="main">
    <!-- Dashboard -->
    <section class="page active" id="page-dashboard">
      <div class="page-header">
        <div>
          <div class="page-title" data-en="Dashboard" data-fa="داشبورد">Dashboard</div>
          <div class="page-sub" id="last-up">–</div>
        </div>
      </div>
      <div class="stats-row">
        <div class="stat-card"><div class="stat-label" data-en="Traffic" data-fa="ترافیک">Traffic</div><div class="stat-val" id="sv-traffic">–<span class="stat-unit"> MB</span></div></div>
        <div class="stat-card"><div class="stat-label" data-en="Inbounds" data-fa="اینباندها">Inbounds</div><div class="stat-val" id="sv-links">–</div></div>
        <div class="stat-card"><div class="stat-label" data-en="Uptime" data-fa="آپتایم">Uptime</div><div class="stat-val" id="sv-uptime" style="font-size:1.3rem;">–</div></div>
        <div class="stat-card"><div class="stat-label" data-en="Disk Free" data-fa="فضای دیسک">Disk Free</div><div class="stat-val" id="sv-disk">–<span class="stat-unit"> GB</span></div></div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
        <div class="card"><div class="card-hd"><span class="card-title" data-en="CPU" data-fa="پردازنده">CPU</span><span id="cpu-v" style="font-weight:700;color:var(--primary);">–%</span></div><div class="sys-bar"><div class="sys-fill" id="cpu-b" style="background:var(--primary);"></div></div></div>
        <div class="card"><div class="card-hd"><span class="card-title" data-en="Memory" data-fa="حافظه">Memory</span><span id="mem-v" style="font-weight:700;color:var(--green);">–%</span></div><div class="sys-bar"><div class="sys-fill" id="mem-b" style="background:var(--green);"></div></div></div>
      </div>
      <div class="card"><div class="card-hd"><span class="card-title" data-en="Hourly Traffic" data-fa="ترافیک ساعتی">Hourly Traffic</span></div><div class="chart-container"><canvas id="tc"></canvas></div></div>
    </section>

    <!-- Inbounds -->
    <section class="page" id="page-inbounds">
      <div class="page-header">
        <div>
          <div class="page-title" data-en="Inbounds" data-fa="اینباندها">Inbounds</div>
          <div class="page-sub" data-en="VLESS over WebSocket · TLS" data-fa="VLESS روی WebSocket با TLS">VLESS over WebSocket · TLS</div>
        </div>
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

    <!-- Traffic -->
    <section class="page" id="page-traffic">
      <div class="page-header"><div class="page-title" data-en="Traffic" data-fa="ترافیک">Traffic</div></div>
      <div class="card">
        <div class="sl-item"><span class="sl-k">Total Traffic</span><span id="t-tr" class="sl-v">–</span></div>
        <div class="sl-item"><span class="sl-k">Total Requests</span><span id="t-rq" class="sl-v">–</span></div>
        <div class="sl-item"><span class="sl-k">Uptime</span><span id="t-up" class="sl-v">–</span></div>
      </div>
    </section>

    <!-- Clean IP -->
    <section class="page" id="page-addresses">
      <div class="page-header">
        <div class="page-title" data-en="Clean IP" data-fa="آی‌پی تمیز">Clean IP</div>
        <select id="addr-inbound-select" class="fs" onchange="renderAddrLinks()" style="min-width:200px;"></select>
      </div>
      <div class="card">
        <div class="fg">
          <label class="fl" data-en="Add Addresses (one per line)" data-fa="افزودن آدرس (هر خط یک)">Add Addresses (one per line)</label>
          <textarea class="fi" id="batch-addrs" rows="4" placeholder="8.8.8.8&#10;example.com"></textarea>
        </div>
        <button class="btn btn-primary" onclick="addBatchAddrs()" data-en="Add All" data-fa="افزودن همه">Add All</button>
        <button class="btn btn-danger btn-sm" onclick="deleteAllAddrs()" style="margin-left:8px;" data-en="Delete All" data-fa="حذف همه">Delete All</button>
        <button class="btn btn-danger btn-sm" onclick="bulkDeleteAddrs()" style="margin-left:8px;" data-en="Delete Selected" data-fa="حذف انتخاب‌شده">Delete Selected</button>
        <div id="addr-links-table" style="margin-top:20px;"></div>
      </div>
    </section>

    <!-- Tools -->
    <section class="page" id="page-tools">
      <div class="page-header"><div class="page-title" data-en="Tools" data-fa="ابزارها">Tools</div></div>
      <div class="card">
        <div class="fg">
          <label class="fl">Test Connection</label>
          <div style="display:flex;gap:8px;">
            <input class="fi" id="test-addr" placeholder="IP or domain" style="flex:1;">
            <input class="fi" id="test-port" placeholder="Port" value="443" style="width:100px;">
            <button class="btn btn-primary" onclick="testConnection()">Test</button>
          </div>
          <div id="test-result" style="margin-top:8px;"></div>
        </div>
      </div>
      <div class="card">
        <div class="fg">
          <label class="fl">Export / Backup</label>
          <button class="btn btn-outline btn-sm" onclick="window.open('/api/export')">Export All Data (JSON)</button>
          <button class="btn btn-outline btn-sm" onclick="window.open('/api/backup')" style="margin-left:8px;">Download SQLite Backup</button>
        </div>
      </div>
    </section>

    <!-- Logs -->
    <section class="page" id="page-logs">
      <div class="page-header"><div class="page-title" data-en="Logs" data-fa="لاگ‌ها">Logs</div></div>
      <div class="card">
        <div id="logs-content"></div>
      </div>
    </section>

    <!-- Security -->
    <section class="page" id="page-security">
      <div class="page-header"><div class="page-title" data-en="Security" data-fa="امنیت">Security</div></div>
      <div style="max-width:440px;margin:0 auto;">
        <div class="card">
          <div class="fg"><label class="fl" data-en="Current Password" data-fa="رمز فعلی">Current Password</label><input class="fi" type="password" id="cpw"></div>
          <div class="fg"><label class="fl" data-en="New Password" data-fa="رمز جدید">New Password</label><input class="fi" type="password" id="npw"></div>
          <button class="btn btn-primary" onclick="chgPw()" style="width:100%;justify-content:center;" data-en="Update Password" data-fa="بروزرسانی رمز">Update Password</button>
        </div>
      </div>
    </section>
  </main>

  <footer class="footer"><span>V2Render Panel · VLESS WS Tunnel</span></footer>
</div>

<!-- Modals (with fixed translations) -->
<div class="mo" id="mo-add"><div class="mo-box">
<button class="mo-close" onclick="document.getElementById('mo-add').classList.remove('show')">✕</button>
<div class="mo-title" data-en="Create Inbound" data-fa="ایجاد اینباند">Create Inbound</div>
<div class="fg"><label class="fl" data-en="Remark" data-fa="توضیح">Remark</label><input class="fi" id="nl" placeholder="e.g. User-1"></div>
<div style="display:flex;gap:12px;">
<div class="fg" style="flex:1;"><label class="fl" data-en="Traffic Limit" data-fa="محدودیت ترافیک">Traffic Limit</label><input class="fi" id="nv" type="number" min="0" step="0.1" placeholder="0 = ∞"></div>
<div class="fg" style="width:100px;"><label class="fl" data-en="Unit" data-fa="واحد">Unit</label><select class="fs" id="nu"><option>GB</option></select></div>
</div>
<div class="fg"><label class="fl" data-en="Max IPs" data-fa="حداکثر آی‌پی">Max IPs</label><input class="fi" id="nc" type="number" min="0" placeholder="0 = ∞"></div>
<div class="fg"><label class="fl" data-en="Days Valid" data-fa="روزهای اعتبار">Days Valid</label><input class="fi" id="nd" type="number" min="0" placeholder="0 = No expiry"></div>
<button class="btn btn-primary" onclick="createLink()" style="width:100%;justify-content:center;margin-top:16px;" data-en="CREATE" data-fa="ایجاد">CREATE</button>
</div></div>

<div class="mo" id="mo-edit"><div class="mo-box">
<button class="mo-close" onclick="document.getElementById('mo-edit').classList.remove('show')">✕</button>
<div class="mo-title" id="et" data-en="Edit Inbound" data-fa="ویرایش اینباند">Edit Inbound</div>
<input type="hidden" id="eu">
<div class="fg"><label class="fl" data-en="Name" data-fa="نام">Name</label><input class="fi" id="en2" readonly style="opacity:0.5;"></div>
<div style="display:flex;gap:12px;">
<div class="fg" style="flex:1;"><label class="fl" data-en="Traffic Limit" data-fa="محدودیت ترافیک">Traffic Limit</label><input class="fi" id="el" type="number" min="0"></div>
<div class="fg" style="width:100px;"><label class="fl" data-en="Unit" data-fa="واحد">Unit</label><select class="fs" id="eu2"><option>GB</option></select></div>
</div>
<div class="fg"><label class="fl" data-en="Max IPs" data-fa="حداکثر آی‌پی">Max IPs</label><input class="fi" id="ec" type="number" min="0"></div>
<div class="fg"><label class="fl" data-en="Extend Days" data-fa="افزایش روزها">Extend Days</label><input class="fi" id="ed" type="number" min="0"></div>
<div style="display:flex;gap:12px;margin-top:16px;">
<button class="btn btn-primary" onclick="saveEdit()" style="flex:1;justify-content:center;" data-en="SAVE" data-fa="ذخیره">SAVE</button>
<button class="btn btn-danger" onclick="resetTraf()" data-en="Reset Traffic" data-fa="بازنشانی ترافیک">Reset Traffic</button>
</div>
</div></div>

<div class="mo" id="mo-qr"><div class="mo-box" style="max-width:380px;">
<button class="mo-close" onclick="document.getElementById('mo-qr').classList.remove('show')">✕</button>
<div class="mo-title">QR Code</div>
<div class="qr-box" id="qr-container"></div>
<button class="btn btn-primary btn-sm" onclick="dlQR()" style="width:100%;justify-content:center;margin-top:16px;">Download</button>
</div></div>

<script>
// ── Globals ──────────────────────────────────────────────────────────────
const $=s=>document.querySelector(s),$m=id=>document.getElementById(id);
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
const langMap={en:{edit:'Edit',copy:'Copy',sub:'Sub',qr:'QR',del:'Del'},fa:{edit:'ویرایش',copy:'کپی',sub:'اشتراک',qr:'QR',del:'حذف'}};
function tr(k){return(langMap[lang]&&langMap[lang][k])||langMap['en'][k]||k;}
let lang=localStorage.getItem('ll')||'en',theme=localStorage.getItem('theme')||'dark';
let allLinks=[],cf='all',sData={},tChart=null,allAddrs=[],isAuthenticated=false;

function setTheme(t){theme=t;document.body.classList.toggle('light-mode',t==='light');localStorage.setItem('theme',t);document.querySelector('.btn-icon').textContent=t==='light'?'☀️':'🌙';updChartColors();}
function toggleTheme(){setTheme(theme==='dark'?'light':'dark');}
function setLang(l){
  lang=l; document.querySelectorAll('.lang-en,.lang-fa').forEach(e=>e.classList.remove('active'));
  document.querySelectorAll(`.lang-${l}`).forEach(e=>e.classList.add('active'));
  document.body.dir=l==='fa'?'rtl':'ltr';
  document.querySelectorAll('[data-en]').forEach(el=>{const v=el.getAttribute('data-'+l);if(v)el.textContent=v;});
  document.querySelectorAll('[data-ph-en]').forEach(el=>{const v=el.getAttribute('data-ph-'+l);if(v)el.placeholder=v;});
  localStorage.setItem('ll',l);
  document.querySelectorAll('.mo-title[data-en]').forEach(el=>{const v=el.getAttribute('data-'+l);if(v)el.textContent=v;});
  filterLinks();
}

async function checkAuth(){try{const r=await fetch('/api/me');(await r.json()).authenticated?showDashboard():showLogin();}catch{showLogin();}}
function showLogin(){isAuthenticated=false;$m('login-page').style.display='';$m('dashboard-page').style.display='none';}
function showDashboard(){isAuthenticated=true;$m('login-page').style.display='none';$m('dashboard-page').style.display='';initChart();loadStats();loadLinks();loadAddrs();populateAddrInboundSelect();loadLogs();}

async function doLogin(){const pw=$m('login-pw').value;$m('login-err').style.display='none';try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});if(r.ok){$m('login-pw').value='';showDashboard();}else $m('login-err').style.display='block';}catch{$m('login-err').style.display='block';}}
async function doLogout(){await fetch('/api/logout',{method:'POST'});showLogin();}

document.querySelectorAll('.nav-link[data-page]').forEach(el=>el.addEventListener('click',()=>{switchPage(el.dataset.page);document.getElementById('mainNav').classList.remove('open');}));
function switchPage(id){document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));$m('page-'+id).classList.add('active');document.querySelectorAll('.nav-link').forEach(n=>n.classList.toggle('active',n.dataset.page===id));}

function toast(msg,err=false){const t=$m('toast');t.textContent=msg;t.className='toast'+(err?' err':'')+' show';clearTimeout(t._hide);t._hide=setTimeout(()=>t.classList.remove('show'),3000);}

function fmtB(b){if(!b||b===0)return'0 B';return b>=1073741824?(b/1073741824).toFixed(2)+' GB':b>=1048576?(b/1048576).toFixed(2)+' MB':(b/1024).toFixed(1)+' KB';}
function fmtLim(b){if(!b||b===0)return'∞';const g=b/1073741824;return(g%1===0?g.toFixed(0):g.toFixed(1))+' GB';}
function fmtExp(ea){if(!ea||ea===0)return'∞';const d=new Date(ea)-new Date();if(d<=0)return'Expired';const days=Math.floor(d/86400000);if(days>0)return days+'d';const hours=Math.floor(d/3600000);if(hours>0)return hours+'h';return Math.floor(d/60000)+'m';}

function setFilter(f,el){cf=f;document.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));el.classList.add('active');filterLinks();}
function filterLinks(){const q=($m('srch')?.value||'').toLowerCase();let r=allLinks;if(cf==='active')r=r.filter(l=>l.active);else if(cf==='off')r=r.filter(l=>!l.active);if(q)r=r.filter(l=>l.label.toLowerCase().includes(q)||l.uuid.toLowerCase().includes(q));renderLinks(r);}
function renderLinks(links){
  const tb=$m('ltb'),em=$m('lempty');
  if(!links||!links.length){tb.innerHTML='';em.style.display='block';return;}
  em.style.display='none';let idx=links.length;
  tb.innerHTML=links.map(l=>{const u=l.used_bytes||0,lim=l.limit_bytes||0,pct=lim>0?Math.min(100,(u/lim)*100):0,col=pct>90?'var(--red)':pct>70?'var(--yellow)':'var(--primary)',ex=fmtExp(l.expires_at),ec=ex==='Expired'?'var(--red)':ex==='∞'?'var(--text3)':'var(--text2)',i=idx--,cc=l.current_connections||0,mc2=l.max_connections||0;return`<tr><td>${i}</td><td style="font-weight:600">${esc(l.label)}</td><td><span class="tag tag-vless">VLESS</span></td><td><div class="pill"><span class="pill-used">${fmtB(u)}</span><div class="pill-bar"><div class="pill-fill" style="width:${pct}%;background:${col}"></div></div><span>${fmtLim(lim)}</span></div></td><td>${cc}/${mc2||'∞'}</td><td style="color:${ec}">${ex}</td><td><span class="tag ${l.active?'tag-on':'tag-off'}">${l.active?'On':'Off'}</span></td><td><div style="display:flex;gap:4px;"><button class="toggle ${l.active?'on':''}" data-uid="${l.uuid}" onclick="togLink(this)"></button><button class="act-btn act-edit" onclick="showEditMo('${l.uuid}')">${tr('edit')}</button><button class="act-btn act-copy" onclick="cpLink('${esc(l.vless_link)}')">${tr('copy')}</button><button class="act-btn act-sub" onclick="cpSub('${l.uuid}')">${tr('sub')}</button><button class="act-btn act-qr" onclick="showQR('${esc(l.vless_link)}')">${tr('qr')}</button><button class="act-btn act-del" onclick="delLink('${l.uuid}')">${tr('del')}</button></div></td></tr>`}).join('');
}

async function togLink(el){const uid=el.dataset.uid,l=allLinks.find(x=>x.uuid===uid);if(!l)return;const na=!l.active;try{await fetch('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({active:na})});l.active=na;filterLinks();loadStats();}catch{toast('Failed',true);}}
async function randomInbound(){const names=['User','Client','Node','Peer'];const n=names[Math.floor(Math.random()*names.length)]+'-'+Math.floor(Math.random()*1000);try{await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:n,limit_value:0})});toast(`Created ${n}`);loadLinks();loadStats();}catch{toast('Error',true);}}
function showAddMo(){$m('mo-add').classList.add('show');}
async function createLink(){const label=$m('nl').value.trim()||'New';const v=parseFloat($m('nv').value)||0,mc=parseInt($m('nc').value)||0,days=parseInt($m('nd').value)||0;try{await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label,limit_value:v,limit_unit:'GB',max_connections:mc,days_valid:days})});toast('Created');$m('mo-add').classList.remove('show');loadLinks();loadStats();}catch{toast('Error',true);}}
function showEditMo(uid){const l=allLinks.find(x=>x.uuid===uid);if(!l)return;$m('eu').value=uid;$m('en2').value=l.label;$m('el').value=l.limit_bytes>0?(l.limit_bytes/1073741824):'';$m('ec').value=l.max_connections||'';$m('ed').value='';$m('et').textContent=(lang==='fa'?'ویرایش: ':'EDIT: ')+l.label;$m('mo-edit').classList.add('show');}
async function saveEdit(){const uid=$m('eu').value,v=parseFloat($m('el').value)||0,mc=parseInt($m('ec').value)||0,days=parseInt($m('ed').value)||0;const body={limit_value:v,limit_unit:'GB',max_connections:mc};if(days)body.days_valid=days;try{await fetch('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});toast('Updated');$m('mo-edit').classList.remove('show');loadLinks();}catch{toast('Error',true);}}
async function resetTraf(){const uid=$m('eu').value;if(!confirm('Reset?'))return;try{await fetch('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({reset_usage:true})});toast('Reset');loadLinks();}catch{toast('Error',true);}}
async function delLink(uid){if(!confirm('Delete?'))return;try{await fetch('/api/links/'+uid,{method:'DELETE'});toast('Deleted');loadLinks();loadStats();}catch{toast('Error',true);}}
function cpLink(txt){navigator.clipboard.writeText(txt).then(()=>toast('Copied!')).catch(()=>toast('Failed',true));}
async function cpSub(uid){await navigator.clipboard.writeText('https://'+location.host+'/sub/'+uid);toast('Sub URL copied!');}
let qrCodeInstance=null;
function showQR(txt){
  $m('mo-qr').classList.add('show');
  const container=$m('qr-container');
  container.innerHTML='';
  if(qrCodeInstance){qrCodeInstance.clear();qrCodeInstance=null;}
  if(typeof QRCode !== 'undefined'){
    qrCodeInstance=new QRCode(container,{text:txt,width:200,height:200,colorDark:'#39ff14',colorLight:'#1e1e1e'});
  } else {
    container.innerHTML=`<img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(txt)}" alt="QR">`;
  }
}
function dlQR(){
  if(qrCodeInstance){
    const canvas=document.querySelector('#qr-container canvas');
    if(canvas){
      const a=document.createElement('a');
      a.href=canvas.toDataURL('image/png');
      a.download='qr.png';
      a.click();
      return;
    }
  }
  const img=document.querySelector('#qr-container img');
  if(img){
    const a=document.createElement('a');
    a.href=img.src;
    a.download='qr.png';
    a.click();
  }
}

async function loadStats(){
  try{const r=await fetch('/stats');if(r.status===401){showLogin();return;}sData=await r.json();
    $m('sv-traffic').innerHTML=(sData.total_traffic_mb||0)+'<span class="stat-unit"> MB</span>';
    $m('sv-links').textContent=sData.links_count;$m('sv-uptime').textContent=sData.uptime;$m('sv-domain').textContent=sData.domain;
    $m('sv-disk').innerHTML=(sData.disk_free_gb||0)+'<span class="stat-unit"> GB</span>';
    $m('last-up').textContent='Updated '+new Date().toLocaleTimeString();
    $m('t-tr').textContent=(sData.total_traffic_mb||0)+' MB';$m('t-rq').textContent=sData.total_requests;$m('t-up').textContent=sData.uptime;
    if(sData.cpu_percent!==undefined){const c=sData.cpu_percent;$m('cpu-v').textContent=c.toFixed(1)+'%';$m('cpu-b').style.width=c+'%';}
    if(sData.memory_percent!==undefined){const m=sData.memory_percent;$m('mem-v').textContent=m.toFixed(1)+'%';$m('mem-b').style.width=m+'%';}
    updChart();
  }catch{}
}
async function loadLinks(){try{const r=await fetch('/api/links');if(r.status===401){showLogin();return;}const d=await r.json();allLinks=d.links||[];filterLinks();}catch{}}
async function chgPw(){const cur=$m('cpw').value,nw=$m('npw').value;if(!cur||!nw){toast('Fill fields',true);return;}if(nw.length<4){toast('Min 4 chars',true);return;}try{const r=await fetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:cur,new_password:nw})});if(!r.ok)throw new Error((await r.json()).detail||'Error');toast('Password updated');}catch(e){toast(e.message,true);}}

function initChart(){
  const ctx = $m('tc');
  if (!ctx || tChart) return;
  tChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: [],
      datasets: [{
        label: 'MB',
        data: [],
        backgroundColor: 'rgba(57,255,20,0.55)',
        borderColor: '#39ff14'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: 'rgba(57,255,20,0.3)' } },
        y: { ticks: { color: 'rgba(57,255,20,0.3)', callback: v => v + ' MB' } }
      }
    }
  });
  updChartColors();
}
function updChartColors(){if(!tChart)return;const col=theme==='light'?'#000':'rgba(57,255,20,0.4)';tChart.options.scales.x.ticks.color=col;tChart.options.scales.y.ticks.color=col;tChart.update();}
function updChart(){if(!tChart||!sData.hourly_traffic)return;const entries=Object.entries(sData.hourly_traffic).sort((a,b)=>a[0].localeCompare(b[0])).slice(-12);tChart.data.labels=entries.map(x=>x[0]);tChart.data.datasets[0].data=entries.map(x=>Math.round(x[1]/1048576));tChart.update();}

async function loadAddrs(){try{const r=await fetch('/api/addresses');allAddrs=(await r.json()).addresses||[];renderAddrLinks();}catch{}}
function populateAddrInboundSelect(){
  const sel=$m('addr-inbound-select');
  if(!sel) return;
  sel.innerHTML = allLinks.map(l=>`<option value="${l.uuid}">${esc(l.label)}</option>`).join('');
  if(allLinks.length>0) renderAddrLinks();
}
function renderAddrLinks(){
  const uid = $m('addr-inbound-select')?.value;
  if(!uid) return;
  const link = allLinks.find(l=>l.uuid===uid);
  const domain = sData.domain || location.hostname;
  let html = `<div style="margin-bottom:12px;font-weight:600">${esc(link?.label||'')} – ${fmtB(link?.used_bytes||0)} / ${fmtLim(link?.limit_bytes||0)}</div>`;
  html += `<div style="display:flex;align-items:center;gap:8px;padding:8px 0;border-bottom:1px solid var(--border);"><input type="checkbox" id="addr-check-all" onchange="toggleAllAddrChecks(this)"> <label for="addr-check-all">Select All</label></div>`;
  html += `<div style="display:flex;justify-content:space-between;padding:8px 0;"><span>🌐 ${domain}</span><span><a class="act-btn act-copy" onclick="cpLink('${esc(generateLinkForAddr(uid,domain))}')">${tr('copy')}</a></span></div>`;
  allAddrs.forEach((addr,i)=>{
    html += `<div style="display:flex;align-items:center;gap:8px;padding:8px 0;border-top:1px solid var(--border);"><input type="checkbox" class="addr-check" data-index="${i}"><span>🌐 ${esc(addr)}</span><div><a class="act-btn act-copy" onclick="cpLink('${esc(generateLinkForAddr(uid,addr))}')">${tr('copy')}</a><a class="act-btn act-del" onclick="delAddr(${i})">${tr('del')}</a></div></div>`;
  });
  $m('addr-links-table').innerHTML = html;
}
function generateLinkForAddr(uid,addr){
  const link = allLinks.find(l=>l.uuid===uid);
  const remark = `V2R-${link?.label||uid}`;
  const domain = sData.domain || location.hostname;
  const path = `/ws/${uid}`;
  const params = `encryption=none&security=tls&type=ws&host=${domain}&path=${encodeURIComponent(path)}&sni=${domain}&fp=chrome&alpn=http/1.1`;
  return `vless://${uid}@${addr}:443?${params}#${encodeURIComponent(remark)}`;
}
function toggleAllAddrChecks(master){
  document.querySelectorAll('.addr-check').forEach(cb=>cb.checked=master.checked);
}
async function bulkDeleteAddrs(){
  const checks=document.querySelectorAll('.addr-check:checked');
  if(!checks.length) return toast('No addresses selected',true);
  const indices=Array.from(checks).map(cb=>parseInt(cb.dataset.index));
  try{
    await fetch('/api/addresses/bulk-delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({indices})});
    toast('Deleted selected');
    await loadAddrs();
  }catch{toast('Error',true);}
}
async function addBatchAddrs(){const raw=$m('batch-addrs').value;const lines=raw.split('\n').map(l=>l.trim()).filter(l=>l);let ok=0,fail=0;for(const addr of lines){if(!/^[a-zA-Z0-9\-_. ]+$/.test(addr)){fail++;continue;}try{const r=await fetch('/api/addresses',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({address:addr})});if(r.ok)ok++;else fail++;}catch{fail++;}}if(ok)toast(`Added ${ok}`);if(fail)toast(`${fail} failed`,true);$m('batch-addrs').value='';await loadAddrs();}
async function deleteAllAddrs(){if(!confirm('Delete all addresses?'))return;try{await fetch('/api/addresses',{method:'DELETE'});toast('All deleted');await loadAddrs();}catch{toast('Error',true);}}
async function delAddr(i){if(!confirm('Delete?'))return;try{await fetch('/api/addresses/'+i,{method:'DELETE'});toast('Deleted');await loadAddrs();}catch{toast('Error',true);}}

async function exportLinks(){
  try{
    const r=await fetch('/api/export-links');
    const data=await r.json();
    const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});
    const a=document.createElement('a');
    a.href=URL.createObjectURL(blob);
    a.download='v2render-links.json';
    a.click();
  }catch{toast('Export failed',true);}
}
async function importLinks(input){
  const file=input.files[0];
  if(!file) return;
  try{
    const text=await file.text();
    const data=JSON.parse(text);
    const r=await fetch('/api/import-links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
    const res=await r.json();
    toast(`Imported ${res.imported} links`);
    loadLinks();
    loadStats();
  }catch{toast('Import failed',true);}
  input.value='';
}

async function testConnection(){
  const addr=$m('test-addr').value.trim();
  const port=$m('test-port').value||443;
  if(!addr){toast('Enter address',true);return;}
  try{
    const r=await fetch('/api/test-connection',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({address:addr,port:parseInt(port)})});
    const d=await r.json();
    $m('test-result').innerHTML=d.ok?`<span style="color:var(--green)">${d.message}</span>`:`<span style="color:var(--red)">${d.message}</span>`;
  }catch(e){
    $m('test-result').innerHTML=`<span style="color:var(--red)">Error</span>`;
  }
}

async function loadLogs(){
  try{
    const r=await fetch('/api/logs');
    const data=await r.json();
    const logs=data.logs||[];
    const el=$m('logs-content');
    if(!el) return;
    if(logs.length===0) el.innerHTML='<div style="color:var(--text3)">No errors recorded</div>';
    else el.innerHTML=logs.map(l=>`<div style="padding:6px 0;border-bottom:1px solid var(--border);font-size:0.9rem;"><span style="color:var(--text3)">${l.time||''}</span> – ${esc(l.error)}</div>`).join('');
  }catch{}
}

setTheme(theme);setLang(lang);checkAuth();
setInterval(()=>{if(isAuthenticated){loadStats();loadLinks();}},12000);
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
