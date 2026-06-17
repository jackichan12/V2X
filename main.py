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

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse
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
    "jwt_expire_minutes": 10080,  # 7 days
    "db_path": os.environ.get("DB_PATH", "panel.db"),
    "admin_password": os.environ.get("ADMIN_PASSWORD", "admin"),
}

# ── Database Helpers (SQLite) ─────────────────────────────────────────────
async def get_db() -> aiosqlite.Connection:
    db = await aiosqlite.connect(CONFIG["db_path"])
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL")
    return db

async def db_execute(query: str, params: tuple = ()):
    db = await get_db()
    try:
        await db.execute(query, params)
        await db.commit()
    finally:
        await db.close()

async def db_fetchall(query: str, params: tuple = ()) -> list:
    db = await get_db()
    try:
        cursor = await db.execute(query, params)
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        await db.close()

async def db_fetchone(query: str, params: tuple = ()) -> Optional[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(query, params)
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
                protocol TEXT DEFAULT 'vless',
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
        """)
        await db.commit()
    finally:
        await db.close()

# ── FastAPI App ───────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    existing = await db_fetchone("SELECT uid FROM links WHERE uid = ?", ("Default",))
    if not existing:
        now = datetime.now(timezone.utc).isoformat()
        await db_execute(
            "INSERT INTO links (uid, label, protocol, created_at, active) VALUES (?, ?, 'vless', ?, 1)",
            ("Default", "Default", now)
        )
    asyncio.create_task(keep_alive())
    asyncio.create_task(cleanup_idle_connections())
    yield

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

ADMIN_PASSWORD_HASH = bcrypt.hashpw(CONFIG["admin_password"].encode(), bcrypt.gensalt()).decode()

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

def generate_uuid(seed: str = None) -> str:
    if seed is None:
        return (
            str(secrets.token_hex(16))[:8] + "-" + secrets.token_hex(2) + "-" +
            secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(6)
        )
    h = hashlib.sha256(f"{seed}{CONFIG['secret_key']}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def generate_link(uid: str, protocol: str = "vless", remark: str = "V2R", address: str = None) -> str:
    cache_key = f"{uid}:{protocol}:{remark}:{address}"
    cached = link_cache.get(cache_key)
    if cached and cached["expires"] > time.time():
        return cached["link"]
    domain = get_domain()
    addr = address if address else domain
    path = f"/ws/{uid}"
    if protocol == "vless":
        params = {
            "encryption": "none", "security": "tls", "type": "ws",
            "host": domain, "path": path, "sni": domain, "fp": "chrome", "alpn": "http/1.1"
        }
        query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
        link = f"vless://{uid}@{addr}:443?{query}#{quote(remark)}"
    elif protocol == "vmess":
        config = {
            "v": "2", "ps": remark, "add": addr, "port": "443", "id": uid, "aid": "0",
            "scy": "auto", "net": "ws", "type": "none", "host": domain, "path": path,
            "tls": "tls", "sni": domain, "alpn": "http/1.1", "fp": "chrome"
        }
        link = "vmess://" + base64.b64encode(json.dumps(config).encode()).decode()
    elif protocol == "trojan":
        link = f"trojan://{uid}@{addr}:443?security=tls&type=ws&host={domain}&path={quote(path)}&sni={domain}&alpn=http/1.1#{quote(remark)}"
    elif protocol == "hysteria2":
        link = f"hysteria2://{uid}@{addr}:443?insecure=0&sni={domain}&alpn=h3&obfs=none#{quote(remark)}"
    else:
        link = f"vless://{uid}@{addr}:443?#Unknown-Protocol"
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
    if not raw:
        return None
    try:
        normalised = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalised)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None

def seconds_until_expiry(expires_at_str: Optional[str]) -> Optional[int]:
    exp = parse_expires_at(expires_at_str)
    if exp is None:
        return None
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
            try:
                await ws.close(code=1000, reason="link deleted")
            except Exception:
                pass
        async with connections_lock:
            connections.pop(cid, None)
        connection_sockets.pop(cid, None)
    async with connections_lock:
        link_ip_map.pop(uid, None)

# ── Routes ─────────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"service": "V2Render", "version": "3.0", "status": "active", "domain": get_domain()}

@app.get("/health")
async def health():
    async with connections_lock:
        conn_count = len(connections)
    return {"status": "ok", "connections": conn_count, "uptime": uptime()}

@app.post("/api/login")
@limiter.limit("5/minute")
async def api_login(request: Request):
    body = await request.json()
    password = str(body.get("password") or "")
    if not verify_password(password, ADMIN_PASSWORD_HASH):
        raise HTTPException(status_code=401, detail="Invalid password")
    token = create_jwt_token({"sub": "admin"})
    resp = JSONResponse({"ok": True})
    resp.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=CONFIG["jwt_expire_minutes"] * 60,
        httponly=True,
        samesite="lax",
        secure=True if get_domain() != "localhost" else False,
        path="/"
    )
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
    ADMIN_PASSWORD_HASH = bcrypt.hashpw(new.encode(), bcrypt.gensalt()).decode()
    return {"ok": True}

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    async with connections_lock:
        conn_count = len(connections)
    return {
        "active_connections": conn_count,
        "total_traffic_mb": round(stats["total_bytes"] / (1024 * 1024), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(await db_fetchall("SELECT uid FROM links WHERE active=1")),
        "domain": get_domain(),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory_percent": psutil.virtual_memory().percent,
        "hourly_traffic": dict(await db_fetchall("SELECT hour, bytes FROM hourly_traffic ORDER BY hour DESC LIMIT 12")),
    }

@app.post("/api/links")
@limiter.limit("10/minute")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "New Link").strip()[:60]
    if not re.match(r'^[a-zA-Z0-9\-_. ]+$', label):
        raise HTTPException(status_code=400, detail="Inbound name must contain only English letters, numbers, and characters: - _ . space")
    if not label:
        raise HTTPException(status_code=400, detail="Inbound name is required")
    existing = await db_fetchone("SELECT uid FROM links WHERE label = ?", (label,))
    if existing:
        raise HTTPException(status_code=400, detail="An inbound with this name already exists")
    protocol = body.get("protocol", "vless").lower()
    if protocol not in ("vless", "vmess", "trojan", "hysteria2"):
        raise HTTPException(status_code=400, detail="Invalid protocol")
    limit_value = float(body.get("limit_value") or 0)
    limit_unit = body.get("limit_unit") or "GB"
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    max_conn = int(body.get("max_connections") or 0)
    if max_conn < 0:
        max_conn = 0
    days_valid = body.get("days_valid")
    expires_at = None
    if days_valid is not None:
        try:
            days_valid = int(days_valid)
            if days_valid > 0:
                expires_at = (datetime.now(timezone.utc) + timedelta(days=days_valid)).isoformat()
        except (ValueError, TypeError):
            pass
    uid = label
    now = datetime.now(timezone.utc).isoformat()
    await db_execute(
        "INSERT INTO links (uid, label, protocol, limit_bytes, max_connections, created_at, active, expires_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
        (uid, label, protocol, limit_bytes, max_conn, now, expires_at)
    )
    return {
        "uuid": uid, "label": label, "protocol": protocol,
        "limit_bytes": limit_bytes, "used_bytes": 0,
        "max_connections": max_conn, "active": True, "created_at": now,
        "expires_at": expires_at,
        "vless_link": generate_link(uid, protocol, remark=f"V2R-{label}"),
    }

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    rows = await db_fetchall("SELECT * FROM links ORDER BY created_at DESC")
    result = []
    for row in rows:
        uid = row["uid"]
        protocol = row.get("protocol", "vless")
        result.append({
            "uuid": uid,
            "label": row["label"],
            "protocol": protocol,
            "limit_bytes": row["limit_bytes"],
            "used_bytes": row["used_bytes"],
            "max_connections": row["max_connections"],
            "active": bool(row["active"]),
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "current_connections": await count_connections_for_link(uid),
            "vless_link": generate_link(uid, protocol, remark=f"V2R-{row['label']}"),
        })
    return {"links": result}

@app.patch("/api/links {"links": result}

@app.patch("/api/links}"),
        })
    return {"links": result}

@app.patch("/api/links/{uid}")
async def toggle {"links": result}

@app.patch("/api/links/{uid}")
async def toggle_link(uid: str, {"links": result}

@app.patch("/api/links/{uid}")
async def toggle_link(uid: str,/{uid}")
async def toggle_link(uid: str,/{uid}")
async def toggle_link(uid: str,_link(uid: str, request: Request, _=Depends(require_a request: Request, _=Depends(require_auth request: Request, _=Depends(require_auth)):
    body = await request.json()
    link request: Request, _=Depends(require_auth)):
    body = await request.json()
    link request: Request, _=Depends(require_auth)):
   uth)):
    body = await request.json()
    link =)):
    body = await request.json()
    link = await db_fetchone("SELECT * FROM links = await db_fetchone("SELECT * FROM links = await db_fetchone("SELECT * FROM links body = await request.json()
    link = await db_fetchone("SELECT * FROM links await db_fetchone("SELECT * FROM links WHERE uid = ?", (uid,))
    if not WHERE uid = ?", (uid,))
    WHERE uid = ?", (uid,))
    if not WHERE uid = ?", (uid,))
    if not link:
        raise HTTPException(status_code=404, detail WHERE uid = ?", (uid,))
    if not link:
        raise HTTPException(status_code=404, link:
        raise HTTPException(status_code=404, detail if not link:
        raise HTTPException(status_code=404, detail="link not found")
    updates = {}
    if " link:
        raise HTTPException(status_code=404, detail="link not found")
    updates = {}
    if "="link not found")
    updates = {}
    if " detail="link not found")
    updates = {}
="link not found")
    updates = {}
    if "active" in body:
        updates["active"] = intactive" in body:
        updates["active"] = intactive" in body:
        updates["active"] = intactive" in body:
        updates["active"] = int(body["active"])
    if "limit_value"    if "active" in body:
        updates["active"] = int(body["active"])
    if(body["active"])
    if "limit_value" in body(body["active"])
    if "limit_value" in body(body["active"])
    if "limit_value" in body:
        limit_value = float(body.get in body:
        limit_value = float "limit_value" in body:
        limit_value = float(body.get("limit_value") or 0)
:
        limit_value = float(body.get("limit_value") or 0)
        limit_unit = body.get:
        limit_value = float(body.get("limit_value") or 0)
        limit_unit = body.get("limit_value") or 0)
        limit_unit = body.get(body.get("limit_value") or 0)
        limit_unit = body.get("limit_unit") or "        limit_unit = body.get("limit_unit") or("limit_unit") or "GB"
        updates["limit("limit_unit") or "GB"
        updates["limit_bytes"] = 0 if limit_value <= 0 else("limit_unit") or "GB"
        updates["limit_bytes"] = 0 if limit_value <= GB"
        updates["limit_bytes"] = 0 if "GB"
        updates["limit_bytes"] = 0 if limit_value <= 0 else_bytes"] = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    parse_size_to_bytes(limit_value, limit_unit)
   0 else parse_size_to_bytes(limit_value, limit limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    if "reset_usage" parse_size_to_bytes(limit_value, limit_unit)
    if "reset_usage" in body and body["reset if "reset_usage" in body and body["reset_usage"]:
        updates["used_bytes"] = _unit)
    if "reset_usage" in body and body["reset_usage"]:
        updates["used_bytes"] =  in body and body["reset_usage"]:
        updates if "reset_usage" in body and body["reset_usage"]:
        updates["used_bytes"] = _usage"]:
        updates["used_bytes"] = 0
    if "label" in body:
        new0
    if "label" in body:
["used_bytes"] = 0
    if "label" in body:
        new_label = str(body["label0
    if "label" in body:
        new0
    if "label" in body:
        new_label = str(body["label"])[:60_label = str(body["label"])[:60]
        if new_label != uid        new_label = str(body["label"])[:60]
        if new_label != uid"])[:60]
        if new_label !=_label = str(body["label"])[:60]
        if new_label != uid]
        if new_label != uid:
            existing = await:
            existing = await db_fetchone("SELECT uid FROM links WHERE label = ? AND uid != ?",:
            existing = await db_fetchone("SELECT uid FROM links WHERE label = ? AND uid != ?", uid:
            existing = await db_fetchone("SELECT uid FROM links WHERE label = ? AND uid != ?",:
            existing = await db_fetchone("SELECT uid FROM links WHERE label = ? AND uid != ?", db_fetchone("SELECT uid FROM links WHERE label = ? AND uid != ?", (new_label, uid))
 (new_label, uid))
            if existing:
                raise (new_label, uid))
            if existing:
                raise (new_label, uid))
            if existing:
                raise (new_label, uid))
            if existing:
                raise            if existing:
                raise HTTPException(status_code=400 HTTPException(status_code=400, detail="Label already in use")
            updates["label"] = HTTPException(status_code=400, detail="Label already in use")
            updates["label HTTPException(status_code=400, detail="Label already in use")
            updates["label"] = HTTPException(status_code=400, detail="Label already in use")
            updates["label"] = new_label
   , detail="Label already in use")
            updates["label"] = new_label
    if "max_connections" new_label
    if "max_connections""] = new_label
    if "max_connections" in body:
        mc = new_label
    if "max_connections" in body:
        mc = if "max_connections" in body:
        mc = in body:
        mc = int(body["max_connections in body:
        mc = int(body["max_connections int(body["max_connections"] or 0)
        updates["max_connections"] = mc if mc >=  int(body["max_connections"] or 0)
        updates["max_connections"] = mc if mc >=  int(body["max_connections"] or 0)
        updates["max_connections"] = mc if mc >= "] or 0)
        updates["max_connections"] = mc if mc >= 0 else 0
   "] or 0)
        updates["max_connections"] = mc if mc >= 0 else 0
   0 else 0
    if "days_valid"0 else 0
    if "days_valid"0 else 0
    if "days_valid" in body:
        try:
            dv = int(body["days if "days_valid" in body:
        try:
            if "days_valid" in body:
        try:
            dv = int(body["days_valid"])
            if dv > in body:
        try:
            dv = int(body["days_valid"])
            if dv > 0:
                updates[" in body:
        try:
            dv = int(body["days_valid"])
            if dv > 0:
                updates["_valid"])
            if dv > 0:
                updates[" dv = int(body["days_valid"])
            if dv > 0:
                updates["expires_at"] = (datetime.now(timezone.utc) + timedelta(d 0:
                updates["expires_at"] = (datetime.now(timezone.utc) + timedelta(dexpires_at"] = (datetime.now(timezone.utc) + timedelta(dexpires_at"] = (datetime.now(timezone.utc) + timedelta(dexpires_at"] = (datetime.now(timezone.utc) + timedelta(days=dv)).isoformat()
            else:
                updatesays=dv)).isoformat()
            elseays=dv)).isoformat()
            else:
                updatesays=dv)).isoformat()
            else:
                updatesays=dv)).isoformat()
            else:
                updates["expires_at"] = None
        except (["expires_at"] = None
        except (:
                updates["expires_at"] = None
        except (ValueError, TypeError):
           ["expires_at"] = None
        except (ValueError, TypeError):
            pass
    if updates:
["expires_at"] = None
        except (ValueError, TypeError):
            pass
    if updates:
ValueError, TypeError):
            pass
    if updates:
        set_clause = ", ".join(f"{k}ValueError, TypeError):
            pass
    if updates:
        set_clause = ", ".join(f"{k} pass
    if updates:
        set_clause = ",        set_clause = ", ".join(f"{k}        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list = ?" for k in updates)
        values = ".join(f"{k} = ?" for k in = ?" for k in updates)
        values = list(updates.values()) + [uid]
        await = ?" for k in updates)
        values = list(updates.values()) + [uid]
       (updates.values()) + [uid]
        await db list(updates.values()) + [uid]
        await db_execute(f"UPDATE links updates)
        values = list(updates.values()) + [uid]
        await db_execute(f" db_execute(f"UPDATE links SET {set_clause} await db_execute(f"UPDATE links SET {set_clause} WHERE uid = ?", tuple_execute(f"UPDATE links SET {set_clause} WHERE uid = ?", tuple(values))
    return SET {set_clause} WHERE uid = ?", tuple(values))
    return {"ok": True}

@appUPDATE links SET {set_clause} WHERE uid = ?", tuple(values))
    return WHERE uid = ?", tuple(values))
    return {"ok": True}

@app.delete("/api/links/{(values))
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete {"ok": True}

@app.delete("/api/links/{.delete("/api/links/{uid}")
async def delete_link {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: struid}")
async def delete_link_link(uid: str, _=Dependsuid}")
async def delete_link(uid: str, _=Depends(require(uid: str, _=Depends(require_auth)):
    await db_exec, _=Depends(require_auth)):
    await db_execute("DELETE FROM links WHERE(uid: str, _=Depends(require_auth)):
    await db_execute("DELETE FROM links WHERE(require_auth)):
    await db_execute("DELETE FROM links WHERE uid = ?", (uid_auth)):
    await db_execute("DELETE FROM links WHERE uid = ?", (uid,))
    await closeute("DELETE FROM links WHERE uid = ?", (uid uid = ?", (uid,))
    await close_ uid = ?", (uid,))
    await close_,))
    await close_connections_for_link(uid)
_connections_for_link(uid)
    return {"ok": True}

@app.get("/api/,))
    await close_connections_for_link(uid)
    return {"ok": True}

@app.get("/api/connections_for_link(uid)
    return {"ok": True}

@app.get("/api/connections_for_link(uid)
    return {"ok": True}

@app.get("/api/    return {"ok": True}

@app.getaddresses")
async def list_addresses(_=Dependsaddresses")
async def list_addresses(_=Depends(require_auth)):
    rows = await db_faddresses")
async def list_addresses(_=Depends(require_auth)):
    rows = await db_faddresses")
async def list_addresses(_=Depends(require_auth)):
    rows = await db_f("/api/addresses")
async def list_addresses(_=Depends(require_auth)):
   (require_auth)):
    rows = await db_fetchall("SELECT address FROM custom_addresses")
    returnetchall("SELECT address FROM custom_addresses")
   etchall("SELECT address FROM custom_addresses")
    return rows = await db_fetchall("SELECT address FROM custom_addresses")
    return {"addresses": [rowetchall("SELECT address FROM custom_addresses")
    return {"addresses": [row["address"] for row in {"addresses": [row["address"] for row in rows]}

@app.post("/api/addresses")
@ return {"addresses": [row["address"] for row in rows]}

@app.post("/api/addresses")
@ {"addresses": [row["address"] for row in rows]}

@app.post("/api/addresses")
@["address"] for row in rows]}

@app rows]}

@app.post("/api/addresseslimiter.limit("10/minute")
async def add_addresslimiter.limit("10/minute")
limiter.limit("10/minute")
async def add_address.post("/api/addresses")
@limiter.limit("10/minute")
async def add_address(request: Request, _")
@limiter.limit("10/minute")
async def add_address(request: Request, _(request: Request, _=Depends(require_aasync def add_address(request: Request, _=Depends(require_auth)):
    body = await(request: Request, _=Depends(require_a=Depends(require_auth)):
    body=Depends(require_auth)):
    body = await request.json()
    address = (body.get("addressuth)):
    body = await request.json()
    address = (body.get("address") or "").strip()
    request.json()
    address = (body.get("address") or "").strip()
    if not address or not re.match(r'^[a-zA-Z0-uth)):
    body = await request.json()
    address = (body.get("address") or "").strip()
    if not address or not re.match(r'^[a = await request.json()
    address = (body.get("address") or "").strip()
    if not address or not re.match(r'^[a") or "").strip()
    if not address or not re if not address or not re9\-_. ]+-zA-Z0-9\-_. ]+-zA-Z0-9\-_. ]+.match(r'^[a-zA-Z0-9\-_. ]+.match(r'^[a-zA-Z0-9\-_. ]+$', address):
        raise$', address):
        raise HTTPException(status_code=400$', address):
        raise HTTPException(status_code=400$', address):
        raise HTTPException(status_code=400, detail="Invalid address format")
    try:
        await$', address):
        raise HTTPException(status_code=400, detail="Invalid address format")
    try:
        await HTTPException(status_code=400, detail="Invalid address format, detail="Invalid address format")
    try:
        await db_execute("INSERT INTO custom_addresses (address), detail="Invalid address format")
    try:
        await db_execute("INSERT INTO custom_addresses (address) db_execute("INSERT INTO custom_addresses (address) db_execute("INSERT INTO custom_addresses (address)")
    try:
        await db_execute("INSERT INTO VALUES (?)", (address VALUES (?)", (address VALUES (?)", (address,))
    except aiosqlite.IntegrityError VALUES (?)", (address,))
    except aiosqlite.IntegrityError custom_addresses (address) VALUES (?)", (address,))
    except aiosqlite.IntegrityError:
        raise HTTPException(status,))
    except aiosqlite.IntegrityError:
        raise HTTPException(status_code=400, detail=",))
    except aiosqlite.IntegrityError:
        raise HTTPException(status_code=400, detail=":
        raise HTTPException(status_code=400, detail=":
        raise HTTPException(status_code=400, detail="Address already exists")
    return {"ok": True}

@app_code=400, detail="Address already exists")
    returnAddress already exists")
    return {"ok": True}

Address already exists")
    return {"ok": True}

@appAddress already exists")
    return {"ok": True}

@app.delete("/api/addresses/{index}")
async.delete("/api/addresses/{index}")
async {"ok": True}

@app.delete("/api/addresses/{index}")
async def delete_address(index: int, _=Depends(require_auth@app.delete("/api/addresses/{index}")
async.delete("/api/addresses/{index}")
async def delete_address(index: int, _=Depends(require_auth)):
    def delete_address(index: int, _= def delete_address(index: int, _=Depends(require_auth)):
    rows)):
    rows = await db_f def delete_address(index: int, _=Depends(require_auth)):
    rows rows = await db_fDepends(require_auth)):
    rows = await db_f = await db_fetchall("SELECT id, address FROM custom_addresses ORDER BY id")
    if etchall("SELECT id, address FROM custom_addresses ORDER = await db_fetchall("SELECT id, address FROM custom_addresses ORDERetchall("SELECT id, address FROM custom_addresses ORDER BY id")
    if 0 <= index < len(etchall("SELECT id, address FROM custom_addresses ORDER BY id")
    if 0 <= index < len(0 <= index < len( BY id")
    if 0 <= index < len(rows):
        address_id = rows[index]["id"]
        BY id")
    if 0 <= index < len(rows):
        address_id = rows[index]["id"]
       rows):
        address_id = rows[index]["id"]
       rows):
        address_id = rows[index]["id"]
       rows):
        address_id = rows[index]["id"]
        await db_execute("DELETE FROM custom_addresses WHERE id await db_execute("DELETE FROM custom_addresses WHERE id await db_execute("DELETE FROM custom_addresses WHERE id = ?", (address_id,))
    else:
        await db_execute("DELETE FROM custom_addresses WHERE id = ?", (address_id,))
    else:
        await db_execute("DELETE FROM custom_addresses WHERE id = ?", (address_id,))
    else:
        = ?", (address_id,))
    else:
        = ?", (address_id,))
    else:
        raise HTTPException(status_code=404, detail="Address not found")
    return {"ok": True}

 raise HTTPException(status_code=404, detail="Address not found")
    return {"ok": True raise HTTPException(status_code=404, detail="Address not found")
    return {"ok raise HTTPException(status_code=404, detail="Address not found")
    return {"ok": True}

@app.get("/ raise HTTPException(status_code=404, detail="Address not found")
    return {"ok": True}

@app.get("/@app.get("/sub/{uid}")
async def subscription_endpoint(uid:}

@app.get("/sub/{uid}")
async def": True}

@app.get("/sub/{uid}")
async def subscription_endpoint(uid: str):
    link = awaitsub/{uid}")
async def subscription_endpoint(uid: str):
    link = await db_fetchone("SELECTsub/{uid}")
async def subscription_endpoint(uid: str):
    link = await db_fetchone("SELECT str):
    link = await db_fetchone("SELECT subscription_endpoint(uid: str):
    link = await db_fetchone("SELECT * FROM links WHERE uid = db_fetchone("SELECT * FROM links WHERE uid = * FROM links WHERE uid = ?", (uid * FROM links WHERE uid = ?", (uid * FROM links WHERE uid = ?", (uid,))
    if not link or ?", (uid,))
    if not link or ?", (uid,))
    if not link or,))
    if not link or not,))
    if not link or not link["active"]:
        raise HTTPException(status_code not link["active"]:
        raise HTTPException(status_code not link["active"]:
        raise HTTPException(status_code=404, detail="link not found or disabled not link["active"]:
        raise HTTPException(status_code=404, detail="link not found or disabled link["active"]:
        raise HTTPException(status_code=404, detail="link not found or disabled=404, detail="link not found or disabled")
    expires_at = parse_expires_at(link["=404, detail="link not found or disabled")
    expires_at = parse_expires_at(link["")
    expires_at = parse_expires_at(link["expires_at"])
    if")
    expires_at = parse_expires_at(link["expires_at"])
    if")
    expires_at = parse_expires_at(link["expires_at"])
    if expires_at and expiresexpires_at"])
    if expires_at and expiresexpires_at"])
    if expires_at and expires expires_at and expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code= expires_at and expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=403_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=403_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=403403403, detail="link expired")
    addresses_rows = await db_fetchall("SELECT address FROM custom_addresses")
   , detail="link expired")
    addresses_rows = await db_fetchall("SELECT address, detail="link expired")
    addresses_rows = await db_fetchall("SELECT address FROM custom_addresses")
   , detail="link expired")
    addresses_rows = await db_fetchall("SELECT address FROM custom_addresses")
    addresses = [row["address, detail="link expired")
    addresses_rows = await db_fetchall("SELECT address FROM custom_addresses")
    addresses = [row["address addresses = [row["address"] for row in addresses_rows FROM custom_addresses")
    addresses = [row["address"] for row in addresses_rows addresses = [row["address"] for row in addresses_rows"] for row in addresses_rows]
    protocol = link.get"] for row in addresses_rows]
    protocol = link]
    protocol = link.get("protocol", "vless]
    protocol = link.get("protocol", "vless]
    protocol = link.get("protocol", "vless")
    sub_content = generate_subscription_content(link,("protocol", "vless")
    sub_content = generate_subscription_content(link,.get("protocol", "vless")
    sub_content = generate_subscription_content(link, uid, addresses, protocol")
    sub_content = generate_subscription_content(link,")
    sub_content = generate_subscription_content(link, uid, addresses, protocol)
    encoded = base64 uid, addresses, protocol)
    encoded = base64 uid, addresses, protocol)
    encoded = base64.b64encode(sub_content.encode()).decode()
    total_bytes)
    encoded = base64.b64encode(sub_content.encode()).decode()
    total_bytes = link["limit uid, addresses, protocol)
    encoded = base64.b64encode(sub_content.encode()).decode()
    total_bytes.b64encode(sub_content.encode()).decode()
    total_bytes.b64encode(sub_content.encode()).decode()
    total_bytes = link["limit_bytes"] if link["limit = link["limit_bytes"] if link["limit_bytes"] if link["limit_bytes = link["limit_bytes"] if link["limit_bytes"] > 0 else = link["limit_bytes"] if link["limit_bytes"] > 0 else UNLIMITED__bytes"] > 0 else UNLIMITED__bytes"] > 0 else UNLIMITED_QUOTA_BYTES
    expire"] > 0 else UNLIMITED_QUOTA_BYTES
    expire_ts =  UNLIMITED_QUOTA_BYTES
    expire_ts = 0
    if expires_atQUOTA_BYTES
    expire_ts = 0
    if expires_at is not None:
_ts = 0
    if expires_at is not None:
        expire_ts = int(expQUOTA_BYTES
    expire_ts = 0
    if expires_at is not None:
        expire_ts = int(expires_at.timestamp())
   0
    if expires_at is not None:
        expire_ts = int(expires_at.timestamp())
    is not None:
        expire_ts = int(exp        expire_ts = int(expires_at.timestamp())
   ires_at.timestamp())
    headers = {
        "Content headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Dires_at.timestamp())
    headers = {
        "Content-Type": "text/plain; charset=utf-8 headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-D-Type": "text/plain; charset=utf-8",
        "Content-Disposition": 'attachment; filename headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": 'attachment; filename="sub.txtisposition": 'attachment; filename",
        "Content-Disposition": 'attachment; filename="sub.txt"',
        "profile-upisposition": 'attachment; filename="sub.txt"',
        "profile"',
        "profile-update-interval": "6",
        "subscription-user="sub.txt"',
        "profile-update-interval": "6",
        "subscription-userdate-interval": "6",
        "subscription-userinfo": f"upload="sub.txt"',
        "profile-update-interval": "6",
        "subscription-userinfo": f"upload={link['used_bytes']}; download=0; total-update-interval": "6",
        "subscription-userinfo": f"upload={link['used_bytes']}; download=0; totalinfo": f"uploadinfo": f"upload={link['used_bytes']}; download=0; total={link['used_bytes']}; download=0; total={total_bytes}; expire={expire_ts}",
={total_bytes}; expire={expire_ts}",
={link['used_bytes']}; download=0; total={total_bytes}; expire={expire_ts}",
    }
    return={total_bytes}; expire={expire_ts}",
    }
    return Response(content=encoded, headers=headers={total_bytes}; expire={expire_ts}",
    }
    return Response(content=encoded, headers=headers    }
    return Response(content=encoded, headers=headers)

def generate_subscription_content(link: dict,    }
    return Response(content=encoded, headers=headers)

def generate_subscription_content(link: dict, uid Response(content=encoded, headers=headers)

def generate_subscription_content(link: dict, uid)

def generate_subscription_content(link: dict, uid: str, addresses: list, protocol: str))

def generate_subscription_content(link: dict, uid: str, addresses: list, protocol: str) -> uid: str, addresses: list, protocol: str) ->: str, addresses: list, protocol: str) ->: str, addresses: list, protocol: str) -> -> str:
    used = link["used_bytes"]
    str:
    used = link["used_bytes"]
    str:
    used = link["used_bytes"]
    str:
    used = link["used_bytes"]
    limit = link["limit_bytes"]
    expires_at_str str:
    used = link["used_bytes"]
    limit = link["limit_bytes"]
    expires_at_str = limit = link["limit_bytes"]
    expires_at_str = link.get("expires_at")
    usage_str = f limit = link["limit_bytes"]
    expires_at_str = link.get("expires_at")
    usage_str = f limit = link["limit_bytes"]
    expires_at_str = link.get("expires_at")
    usage_str = f = link.get("expires_at")
    usage_str = f"{_fmt_bytes(used)} / ∞ link.get("expires_at")
    usage_str = f"{_fmt_bytes(used)} / ∞"{_fmt_bytes(used)} / ∞"{_fmt_bytes(used)} / ∞"{_fmt_bytes(used)} / ∞" if limit == 0" if limit == 0" if limit == 0" if limit == 0 else f"{_fmt_bytes(used)} / {_" if limit == 0 else f"{_fmt_bytes(used)} / {_ else f"{_fmt_bytes(used)} / {_ else f"{_fmt_bytes(used)} / {_ else f"{_fmt_bytes(used)} / {_fmt_bytes(limit)}"
    secs_left = secondsfmt_bytes(limit)}"
    secs_left = secondsfmt_bytes(limit)}"
    secs_left = secondsfmt_bytes(limit)}"
    secs_left = seconds_until_expiry(expires_at_str)
fmt_bytes(limit)}"
    secs_left = seconds_until_expiry(exp_until_expiry(expires_at_str)
_until_expiry(exp_until_expiry(expires_at_str)
    if secs_left is None:
        expiry_str =    if secs_left is None:
        expiry_str =ires_at_str)
    if secs_left is None:
        expiry_str = "∞"
    elif secs_left ==    if secs_left is None:
        expiry_str = "∞"
    elif secs_left == 0:
ires_at_str)
    if secs_left is None:
        expiry_str = "∞"
    elif sec "∞"
    elif secs_left == 0:
 "∞"
    elif secs_left == 0:
 0:
        expiry_str = "Expired"
    else:
               expiry_str = "Expired"
    else:
        expiry_str = f"{secs_left //s_left == 0:
        expiry_str = "Expired"
    else:
               expiry_str = "Expired"
    else:
        expiry_str = f"{secs_left // 86400        expiry_str = "Expired"
    else:
        expiry_str = f"{secs_left // 86400} Days Left"
    status_node = generate_link expiry_str = f"{secs_left // 86400} Days Left"
    status_node = generate_link(uid, protocol 86400} Days Left"
    status_node = generate_link expiry_str = f"{secs_left // 86400} Days Left"
    status_node = generate_link(uid, protocol, remark=f"📊 {usage} Days Left"
    status_node = generate_link(uid, protocol, remark=f"(uid, protocol, remark=f"📊 {usage_str} |, remark=f"📊 {usage_str} |(uid, protocol, remark=f"📊 {usage_str} | ⏳ {expiry_str} | ⏳ {expiry📊 {usage_str} | ⏳ {expiry_str}", address="0.0.0.0")
 ⏳ {expiry_str}", address="0. ⏳ {expiry_str}", address="0.0.0.0")
    links_out = [status_str}", address="0.0.0.0")
_str}", address="0.0.0.0")
    links_out = [status_node, generate_link(uid0.0.0")
    links_out = [status_node, generate_link(uid, protocol, remark=f_node, generate_link(uid, protocol, remark=f"    links_out = [status_node, generate_link(uid, protocol, remark=f"V2R-{link    links_out = [status_node, generate_link(uid, protocol, remark=f"V2R-{link, protocol, remark=f"V2R-{link['label']}-Server")]
"V2R-{link['label']}-Server")]
    for i, addr inV2R-{link['label']}-Server['label']}-Server")]
    for i, addr in['label']}-Server")]
    for i, addr in    for i, addr in enumerate(addresses):
        links enumerate(addresses):
        links_out.append(generate_link(")]
    for i, addr in enumerate(addresses):
        links_out.append(generate_link(uid, protocol, enumerate(addresses):
        links_out.append(generate_link(uid, protocol, remark=f"V2R-{ enumerate(addresses):
        links_out.append(generate_link(uid, protocol, remark=f"_out.append(generate_link(uid, protocol, remark=f"V2R-{link['label']}-IPuid, protocol, remark=f"V2R-{link['label']}-IP{i+1}", address= remark=f"V2R-{link['label']}-IPlink['label']}-IP{i+1}", address=addr))
    return "\nV2R-{link['label']}-IP{i+1}", address=addr))
    return "\n{i+1}", address=addr))
    return "\naddr))
    return "\n".join(links_out)

{i+1}", address=addr))
    return "\n".join(links_out)

def _fmt_bytes(b".join(links_out)

def _fmt_bytes(b".join(links_out)

def _fmt_bytes(b".join(links_out)

def _fmt_bytes(b: int) -> str:
    if b >= 1def _fmt_bytes(b: int) -> str:
    if b >= 1: int) -> str:
    if b >= 1_073_741_824: int) -> str:
    if b >= 1_073_741_824: return f"{b /: int) -> str:
    if b >= 1_073_741_824_073_741_824_073_741_824: return f"{b / 1_073_741: return f"{b / 1_073_741_824:.1f}GB"
    if 1_073_741_824:.1f}GB"
    if b >= 1_048: return f"{b / 1_073_741_824:.1f}GB"
    if b >=: return f"{b / 1_073_741_824:.1f}GB"
    if b >= 1_048_576: return f"{_824:.1f}GB"
    if b >= 1_048_576: return f"{b / 1_048_576:. b >= 1_048_576: return f"{b / 1_048_576:.1f}_576: return f"{b / 1_048_576:.1f}MB 1_048_576: return f"{b / 1_048_576:.1f}b / 1_048_576:.1f}1f}MB"
    return f"{b / 102MB"
    return f"{b / 102"
    return f"{b / 1024:.1f}KB"

#MB"
    return f"{b / 102MB"
    return f"{b / 1024:.1f}KB"

# ── WebSocket tunnel4:.1f}KB"

# ── WebSocket tunnel ──────────────────────────────────────────────────────
RELAY_B4:.1f}KB"

# ── WebSocket tunnel ──────────────────────────────────────────────────────
RELAY_B ── WebSocket tunnel ──────────────────────────────────────────────────────
RELAY_B4:.1f}KB"

# ── WebSocket tunnel ──────────────────────────────────────────────────────
RELAY_B ──────────────────────────────────────────────────────
RELAY_BUF = 64 * 1024

async def parseUF = 64 * 1024UF = 64 * 1024

async def parseUF = 64 * 1024

async def parse_vless_header(first_chunk: bytes):
UF = 64 * 1024

async def parse_vless_header(first_chunk: bytes):
_vless_header(first_chunk: bytes):


async def parse_vless_header(first_chunk: bytes):
    if len(first_chunk_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24:
           if len(first_chunk) < 24:
           if len(first_chunk) < 24:
           if len(first_chunk) < 24:
        raise ValueError("chunk too small")
    pos = ) < 24:
        raise ValueError("chunk too raise ValueError("chunk too small")
    pos =  raise ValueError("chunk too small")
    pos = 1 + 16
    addon_len = raise ValueError("chunk too small")
    pos = 1 + 16
    addon_len = first_ch1 + 16
    addon_len = first_chunk[pos]
    pos += 1 + addon_len small")
    pos = 1 + 16
    addon_len = first_chunk[pos]
1 + 16
    addon_len = first_chunk[pos]
    pos += 1 + addunk[pos]
    pos += 1 + add first_chunk[pos]
    pos += 1 + addon_len
    command = first_chunk[pos]

    command = first_chunk[pos]
    pos +=    pos += 1 + addon_len
    command = first_chunk[pos]
    pos +=on_len
    command = first_chunk[pos]
    pos +=on_len
    command = first_chunk[pos]
    pos += 1
    port = int.from_bytes(first_ch    pos += 1
    port = int.from_bytes(first_chunk[pos:pos + 2 1
    port = int.from_bytes(first_chunk[pos:pos + 2], " 1
    port = int.from_bytes(first_chunk[pos:pos + 2], "big")
    pos 1
    port = int.from_bytes(first_chunk[pos:pos + 2], "big")
    posunk[pos:pos + 2], "big")
    pos += 2
    addr], "big")
    pos += 2
    addrbig")
    pos += 2
    addr += 2
    addr_type = first_chunk[pos += 2
    addr_type = first_chunk[pos]
    pos += 1
    if_type = first_chunk[pos]
    pos += 1_type = first_chunk[pos]
    pos += 1
    if addr_type == 1:
        addr_bytes_type = first_chunk[pos]
    pos += 1
    if addr_type == 1:
        addr_bytes]
    pos += 1
    if addr_type == 1:
        addr_bytes = first addr_type == 1:
        addr_bytes = first_chunk[pos:
    if addr_type == 1:
        addr_bytes = first_chunk[pos:pos + 4]
        = first_chunk[pos:pos + 4]
        pos += 4
        address = ".".join(str = first_chunk[pos:pos + 4]
        pos += 4
        address = ".".join(str(b) for b in addr_bytes)
_chunk[pos:pos + 4]
        pos += 4
        address = ".".join(strpos + 4]
        pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        domain pos += 4
        address = ".".join(str(b) for b in addr_bytes)
(b) for b in addr_bytes)
    elif addr_type == 2:
        domain_len = first_ch    elif addr_type == 2:
        domain_len =(b) for b in addr_bytes)
    elif addr_type == 2:
        domain_len = first_chunk[pos_len = first_chunk[pos]
        pos += 1    elif addr_type == 2:
        domain_len = first_chunk[pos]
        pos += 1unk[pos]
        pos += 1
        address = first_ch first_chunk[pos]
        pos += 1]
        pos += 1
        address = first_ch
        address = first_chunk[pos
        address = first_chunk[pos:pos + domain_len].decode("utf-8", errors="ignoreunk[pos:pos + domain_len].decode("utf
        address = first_chunk[pos:pos + domain_len].decode("utf-8", errors="ignoreunk[pos:pos + domain_len].decode("utf-8", errors="ignore")
        pos += domain:pos + domain_len].decode("utf-8", errors="ignore")
        pos += domain")
        pos += domain_len
    elif addr_type-8", errors="ignore")
        pos += domain_len
    elif addr_type == 3:
        addr")
        pos += domain_len
    elif addr_type == 3:
        addr_bytes = first_chunk[pos_len
    elif addr_type == 3:
        addr_len
    elif addr_type == 3:
        addr_bytes = first_chunk[pos:pos + 16]
 == 3:
        addr_bytes = first_chunk[pos:pos + 16]
        pos += 16
_bytes = first_chunk[pos:pos + 16]
:pos + 16]
        pos += 16
        address = ":".join(f"{addr_bytes[i]:_bytes = first_chunk[pos:pos + 16]
        pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{        pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i        address = ":".join(f"{addr_bytes[i]:        pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes02x}{addr_bytes[i+1]:02x}" for i in range(0, 16,addr_bytes[i+1]:02x}" for i in range(+1]:02x}" for i in range(0, 16, 2))
    else:
        raise02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, [i+1]:02x}" for i in range(0 20, 16, 2))
    else:
        raise ValueError(f"unknown address type: {addr_type ValueError(f"unknown address type: {addr_type2))
    else:
        raise ValueError(f"unknown address type: {addr_type, 16, 2))
    else:
        raise ValueError(f"unknown address type: {addr_type))
    else:
        raise ValueError(f"unknown address type: {addr_type}")
    return command}")
    return command, address, port, first_chunk[pos:]

async def atomic_check_and_add}")
    return command, address, port, first_chunk[pos:]

async def atomic_check_and_add}")
    return command, address, port, first_chunk[pos:]

async def atomic_check_and_add}")
    return command, address, port, first_chunk[pos:]

async def atomic_check_and_add, address, port, first_chunk[pos:]

async def atomic_check_and_add_usage(uid: str, size: int) ->_usage(uid: str, size: int) ->_usage(uid: str, size: int)_usage(uid: str, size: int)_usage(uid: str, size: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute(
            "UPDATE links SET bool:
    db = await get_db()
    try:
        cursor = await db.execute(
            "UPDATE links SET bool:
    db = await get_db()
    try:
        cursor = await db.execute(
            "UPDATE links SET -> bool:
    db = await get_db()
    try:
        cursor = await db.execute(
            "UPDATE links SET -> bool:
    db = await get_db()
    try:
        cursor = await db.execute(
            " used_bytes = used_bytes + ? WHERE uid = ? AND (limit_bytes = 0 used_bytes = used_bytes + ? WHERE uid = ? AND (limit_bytes = 0 OR used_bytes = used_bytes + ? WHERE uid = ? AND (limit_bytes = 0 OR used used_bytes = used_bytes + ? WHERE uid = ? AND (limit_bytes = 0 OR usedUPDATE links SET used_bytes = used_bytes + ? WHERE uid = ? AND (limit_bytes = 0 OR used_bytes + ? <= limit_bytes OR used used_bytes + ? <= limit_bytes) AND active = 1_bytes + ? <= limit_bytes) AND active = 1",
            (size, uid) AND active = 1",
            (size_bytes + ? <= limit_bytes) AND active = 1",
            (size, uid_bytes + ? <= limit_bytes) AND active = 1",
            (size, uid",
            (size, uid, size)
        )
        await db.commit()
        return, size)
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await, uid, size)
        )
        await db.commit()
        return cursor.rowcount > 0, size)
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await, size)
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await cursor.rowcount > 0
    finally:
        await db.close()

async def ws_to_tcp(webs db.close()

async def ws_to_tcp(webs
    finally:
        await db.close()

async def ws db.close()

async def ws_to_tcp(webs db.close()

async def ws_to_tcp(websocket, writer, connocket, writer, connocket, writer, conn_to_tcp(websocket, writer, conn_id, link_uid):
    try:
ocket, writer, conn_id, link_uid):
    try:
        while True:
            msg = await websocket.receive_id, link_uid):
    try:
        while True:
            msg = await websocket.receive_id, link_uid):
    try:
        while True:
            msg = await websocket.receive_id, link_uid):
    try:
        while True:
            msg = await websocket.receive        while True:
            msg = await websocket.re()
            if msg["type"] == "websocket.dis()
            if msg["type"] == "websocket.dis()
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes()
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytesceive()
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.getconnect":
                break
            data = msg.get("bytes") or (msg.get("text") or "").encodeconnect":
                break
            data = msg.get("bytes") or (msg.get("text") or "").encode") or (msg.get("text") or "").encode()
            if not data:
                continue
            size =") or (msg.get("text") or "").encode()
            if not data:
                continue
            size =("bytes") or (msg.get("text") or "").encode()
            if not data:
()
            if not data:
                continue
            size =()
            if not data:
                continue
            size = len(data)
            if not await atomic_check_and len(data)
            if not await atomic_check_and len(data)
            if not await atomic_check_and_add_usage(link_                continue
            size = len(data)
            if not await atomic_check_and_add_usage(link_ len(data)
            if not await atomic_check_and_add_usage(link__add_usage(link__add_usage(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded")
                break
uid, size):
                await websocket.close(code=1008, reason="quota exceeded")
                break
uid, size):
                await websocket.close(code=1008, reason="quota exceeded")
                break
uid, size):
                await websocket.close(code=1008, reason="quota exceeded")
                break
uid, size):
                await websocket.close(code=1008, reason="quota exceeded")
                break
            stats["total_bytes"]            stats["total_bytes"] += size
            stats["total_requests"] += 1
            async with connections            stats["total_bytes"] += size
            stats["total_requests"] += 1
            async with connections            stats["total_bytes"] += size
            stats["total_requests"] += 1
            async with connections            stats["total_bytes"] += size
            stats["total_requests"] += 1
            async with connections += size
            stats["total_requests"] += 1
            async with connections_lock:
                if conn_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += size
                    connections_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += size
                   _lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += size
                   _lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += size
                    connections_id in connections:
                    connections[conn_id]["bytes"] += size
                    connections[conn_id]["last_active"] = time.time()
            hour connections[conn_id]["last_active"] = time.time()
            hour connections[conn_id]["last_active"] = time.time()
            hour = datetime.now(timezone.utc).[conn_id]["last_active"] = time.time()
            hour = datetime.now(timezone.utc). = datetime.now(timezone.utc).strftime("%H:00")
           [conn_id]["last_active"] = time.time()
            hour = datetime.now(timezone.utc).strftime("%H:00")
            await db_exec = datetime.now(timezone.utc).strftime("%H:00")
            await db_execstrftime("%H:00")
            await db_execute(
                "INSERT INTO hourly_traffic (hour await db_execute(
                "INSERT INTO hourly_traffic (hour, bytes) VALUES (?,strftime("%H:00")
            await db_execute(
                "INSERT INTO hourly_traffic (hour, bytes) VALUES (?, ?) ON CONFLICTute(
                "INSERT INTO hourly_traffic (hour, bytes) VALUES (?, ?) ON CONFLICTute(
                "INSERT INTO hourly_traffic (hour, bytes) VALUES (?,, bytes) VALUES (?, ?) ON CONFLICT(hour) DO UPDATE SET bytes = bytes + ?",
 ?) ON CONFLICT(hour) DO UPDATE SET(hour) DO UPDATE SET bytes = bytes + ?",
(hour) DO UPDATE SET bytes = bytes + ?",
 ?) ON CONFLICT(hour) DO UPDATE SET bytes = bytes + ?",
                (hour, size,                (hour, size, size)
            )
 bytes = bytes + ?",
                (hour, size, size)
            )
            day                (hour, size, size)
            )
            day = datetime.now(timezone.utc).strftime("%                (hour, size, size)
            )
            day = datetime.now(timezone.utc).strftime("% size)
            )
            day = datetime.now(timezone.utc).strftime("%Y-%m            day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            await db_execute(
 = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            await db_execute(
Y-%m-%d")
            await db_execute(
Y-%m-%d")
            await db_execute(
                "INSERT INTO daily_traffic (day,-%d")
            await db_execute(
                "INSERT INTO daily_traffic (day, bytes) VALUES (                "INSERT INTO daily_traffic (day, bytes                "INSERT INTO daily_traffic (day, bytes) VALUES (?, ?) ON CONFLICT(day                "INSERT INTO daily_traffic (day, bytes) VALUES (?, ?) ON CONFLICT(day bytes) VALUES (?, ?) ON CONFLICT(day) DO UPDATE SET bytes = bytes + ?",
                (?, ?) ON CONFLICT(day) DO UPDATE SET bytes = bytes + ?",
                (day, size, size)
) VALUES (?, ?) ON CONFLICT(day) DO UPDATE SET bytes = bytes + ?",
                () DO UPDATE SET bytes = bytes + ?",
                (day, size, size)
            )
            try:
                writer.write(data)
                await) DO UPDATE SET bytes = bytes + ?",
                (day, size, size)
            )
            try:
               day, size, size)
            )
            try:
                           )
            try:
                writer.write(dataday, size, size)
            )
            try:
                writer.write(data)
                await writer.drain()
            except Exception:
                break
    except Web writer.drain()
            except Exception:
                break
    except Web writer.write(data)
                await writer.drain()
            except Exception:
                break
    except Web writer.write(data)
                await writer.drain()
            except Exception:
                break
    except Web)
                await writer.drain()
            except Exception:
                break
    except WebSocketDisSocketDisconnect:
        pass
    except ExceptionSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"ws_to_tcp error connSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"ws_toSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"ws_to_tcp error connconnect:
        pass
    except Exception as e:
        logger.error(f"ws_to_tcp error conn={conn_id}: {e as e:
        logger.error(f"ws_to_tcp error conn={conn_id}: {e}", exc_info=True)
   ={conn_id}: {e}", exc_info=True)
_tcp error conn={conn_id}: {e}", exc_info=True)
    finally:
        try:
           ={conn_id}: {e}", exc_info=True)
    finally:
        try:
           }", exc_info=True)
    finally:
        try:
            if writer and not writer.is_closing():
                writer.write finally:
        try:
            if writer and not writer.is_closing():
                writer.write_eof()
        except Exception    finally:
        try:
            if writer and not writer.is_closing():
                writer.write if writer and not writer.is_closing():
                writer.write_eof()
        except Exception:
            pass

async def if writer and not writer.is_closing():
                writer.write_eof()
        except Exception_eof()
        except Exception:
            pass

async def tcp_to_ws(websocket, reader, conn:
            pass

async def tcp_to_ws(websocket, reader, conn_id, link_uid):
_eof()
        except Exception:
            pass

async def tcp_to_ws(websocket, reader, tcp_to_ws(websocket, reader, conn_id, link_uid):
    first = True
   :
            pass

async def tcp_to_ws(websocket, reader, conn_id, link_uid):
    first = True
    try:
        while True:
_id, link_uid):
    first = True
       first = True
    try:
        while True:
 conn_id, link_uid):
    first = True
    try:
        while True:
            data = try:
        while True:
            data = await reader.read            data = await reader.read(RELAY try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data:
                           data = await reader.read(RELAY_BUF)
            if not data:
                break
            size = len await reader.read(RELAY_BUF)
            if not data:
                break
            size = len(RELAY_BUF)
            if not data:
                break
            size = len(data)
            if not await_BUF)
            if not data:
                break
            size = len(data)
            if not await break
            size = len(data)
            if not await atomic_check_and_add_usage(link_uid(data)
            if not await atomic_check_and_add_usage(link_uid, size):
                await webs(data)
            if not await atomic_check_and_add_usage(link_uid, size):
                await webs atomic_check_and_add_usage(link_uid, size):
                await websocket.close(code=100 atomic_check_and_add_usage(link_uid, size):
                await websocket.close(code=100, size):
                await websocket.close(code=1008, reason="quota exceeded")
                break
ocket.close(code=1008, reason="quota exceeded")
                break
            stats["total_bytesocket.close(code=1008, reason="quota exceeded")
                break
            stats["total_bytes"] += size
            async with connections_lock:
                if8, reason="quota exceeded")
                break
            stats["total_bytes"] += size
            async8, reason="quota exceeded")
                break
            stats["total_bytes"] += size            stats["total_bytes"] += size
            async with connections_lock:
                if conn_id in"] += size
            async with connections_lock:
                if conn_id in connections:
                    connections[conn_id][" conn_id in connections:
                    connections[conn_id with connections_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += size
                   
            async with connections_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += size
                    connections[conn_id]["last connections:
                    connections[conn_id]["bytes"] += size
                    connections[conn_id]["last_active"] = time.timebytes"] += size
                    connections[conn_id]["last_active"] = time.time()
            hour = datetime.now]["bytes"] += size
                    connections[conn_id]["last_active"] = time.time()
            hour = datetime.now connections[conn_id]["last_active"] = time.time()
            hour = datetime.now(timezone.utc)._active"] = time.time()
            hour = datetime.now(timezone.utc).strftime("%H:()
            hour = datetime.now(timezone.utc).strftime("%H:(timezone.utc).strftime("%H:00")
            await db_execute(
                "INSERT(timezone.utc).strftime("%H:00")
            await dbstrftime("%H:00")
            await db_execute(
                "INSERT INTO hourly_t00")
            await db_execute(
                "INSERT INTO hourly_traffic (hour,00")
            await db_execute(
                "INSERT INTO hourly_traffic (hour, bytes INTO hourly_traffic (hour_execute(
                "INSERT INTO hourly_traffic (hour, bytes) VALUES (?, ?)raffic (hour, bytes) VALUES (?, ?) ON CONFLICT(hour) DO UPDATE SET bytes bytes) VALUES (?, ?) ON CONFLICT(hour) DO UPDATE SET bytes = bytes + ?",
) VALUES (?, ?) ON CONFLICT(hour) DO UPDATE SET bytes = bytes + ?",
                (, bytes) VALUES (?, ?) ON CONFLICT(hour) DO UPDATE SET bytes = bytes + ?",
                ( ON CONFLICT(hour) DO UPDATE SET bytes = bytes + ?",
                (hour, size, size = bytes + ?",
                (hour, size, size                (hour, size, size)
            )
            day = datetime.now(timezone.utc).strftime("%Yhour, size, size)
            )
            day = datetime.now(timezone.utc).strftime("%Yhour, size, size)
            )
            day = datetime.now(timezone.utc).strftime("%Y)
            )
            day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
           )
            )
            day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
           -%m-%d")
            await db_execute(
               -%m-%d")
            await db_execute(
                "INSERT INTO daily_traffic (day, bytes)-%m-%d")
            await db_execute(
                "INSERT INTO daily_traffic (day, bytes) await db_execute(
                "INSERT INTO daily_traffic (day, bytes) VALUES (?, ?) ON await db_execute(
                "INSERT INTO daily_traffic (day, bytes) VALUES (?, ?) ON "INSERT INTO daily_traffic (day, bytes) VALUES (?, ?) ON CONFLICT(day) VALUES (?, ?) ON CONFLICT(day) DO UPDATE SET bytes = bytes + ?",
                (day VALUES (?, ?) ON CONFLICT(day) DO UPDATE SET bytes = bytes + ?",
                (day, size, size)
            )
            try:
                CONFLICT(day) DO UPDATE SET bytes = bytes + ?",
                (day, size, size)
            CONFLICT(day) DO UPDATE SET bytes = bytes + ?",
                (day, size, size)
            DO UPDATE SET bytes = bytes + ?",
                (day, size, size)
            )
            try:
                await, size, size)
            )
            try:
                await websocket.send_bytes await websocket.send_bytes((b"\x00\x00" + data )
            try:
                await websocket.send_bytes((b"\x )
            try:
                await websocket.send_bytes((b"\x00\x00" + websocket.send_bytes((b"\x00\x00" + data) if first else data((b"\x00\x00" + data) if first else data)
                first = False
) if first else data)
                first = False
00\x00" + data) if first else data)
                first = False
            except Exception:
                break data) if first else data)
                first = False
            except Exception:
                break
    except Exception as e:
        logger.error(f")
                first = False
            except Exception:
                break
    except Exception as e:
        logger.error(f"tcp_to_ws error            except Exception:
                break
    except Exception as e:
        logger.error(f"tcp_to_ws error            except Exception:
                break
    except Exception as e:
        logger.error(f"
    except Exception as e:
        logger.error(f"tcp_to_ws error conn={conn_id}: {e}", exc_info=True)

@app.websocket("/wstcp_to_ws error conn={conn_id}: {e}", exc_info=True)

@app.websocket("/ws conn={conn_id}: {e}", exc_info=True)

 conn={conn_id}: {e}", exc_info=True)

tcp_to_ws error conn={conn_id}: {e}", exc_info=True)

@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await websocket@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await websocket@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: Web/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await websocket: WebSocket, uuid: str):
    await websocket.accept()
    writer =.accept()
    writer = None
    conn_id.accept()
    writer = None
    conn_idSocket, uuid: str):
    await websocket.accept()
    writer = None
    conn_id.accept()
    writer = None
    conn_id = None
    client_ip = get_client_ip(webs None
    conn_id = None
    client_ip = None
    client_ip = get_client_ip(websocket)
    try:
        link = await db_fetchone("SELECT * FROM = None
    client_ip = get_client_ip(websocket)
    try:
        link = await db_fetchone("SELECT * FROM = None
    client_ip = get_client_ip(websocket)
    try:
        link = await db_focket)
    try:
        link = await db_fetchone("SELECT * FROM links WHERE uid = ?", = get_client_ip(websocket)
    try:
        link = await db_fetchone("SELECT * FROM links WHERE uid = ?", (uuid,))
        if links WHERE uid = ?", (uuid,))
        if not link or notetchone("SELECT * FROM links WHERE uid = ?", (uuid,))
        if not link or not (uuid,))
        if not link or not link["active"]:
            await webs links WHERE uid = ?", (uuid,))
        if not link or not link["active"]:
            await webs not link or not link["active"]:
            await websocket.close(code=1008, reason link["active"]:
            await websocket.close(code=1008, reason="link not found or disabled")
            return
        link["active"]:
            await websocket.close(code=1008, reason="link not found or disabled")
            return
       ocket.close(code=1008, reason="linkocket.close(code=1008, reason="link not found or disabled")
            return
        max="link not found or disabled")
            return
        max_conn = link["max_connections"]
        expires max_conn = link["max_connections"]
        expires_at max_conn = link["max_connections"]
        expires_at = parse_expires_at(link["expires_at not found or disabled")
            return
        max_conn = link["max_connections"]
        expires_at = parse_expires_at(link["expires_at"])
_conn = link["max_connections"]
        expires_at = parse_expires_at(link["expires_at = parse_expires_at(link["expires_at"])
        if expires_at is not None and expires_at < datetime = parse_expires_at(link["expires_at"])
        if expires_at is not None and expires_at < datetime.now(timezone.utc"])
        if expires_at is not None and expires_at < datetime.now(timezone.utc        if expires_at is not None and expires_at < datetime_at"])
        if expires_at is not None and expires_at < datetime.now(timezone.utc):
            await websocket.close(code=1008, reason.now(timezone.utc):
            await websocket.close(code=1008, reason="link expired):
            await websocket.close(code=1008, reason):
            await websocket.close(code=1008, reason="link expired")
            return
        if max_conn > 0:
            current_conns = await count.now(timezone.utc):
            await websocket.close(code=1008, reason="link expired")
            return
        if max_conn > 0:
            current_conns = await count_connections_for="link expired")
            return
        if max_conn")
            return
        if max_conn > 0:
            current_conns = await count="link expired")
            return
        if max_conn > 0:
            current_conns = await count_connections_for_link(uuid)
           _link(uuid)
            if current_conns >= max_conn:
                await websocket.close(code=1008, reason > 0:
            current_conns = await count_connections_for_link(uuid)
           _connections_for_link(uuid)
            if current_conns >= max_conn:
                await websocket.close_connections_for_link(uuid)
            if current_conns >= max_conn:
                await websocket.close if current_conns >= max_conn:
                await websocket.close(code=1008, reason="connection limit reached")
               ="connection limit reached")
                return

        first_msg = await asyncio.wait_for(websocket.receive(), if current_conns >= max_conn:
                await websocket.close(code=1008, reason="connection limit reached")
               (code=1008, reason="connection limit reached")
                return

        first_msg = await asyncio.wait_for(websocket.receive(),(code=1008, reason="connection limit reached")
                return

        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
 return

        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        if first_msg["type return

        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.dis timeout=15.0)
        if first_msg["type        if first_msg["type"] == "websocket.disconnect":
            return
        timeout=15.0)
        if first_msg["type"] == "websocket.disconnect":
            return
        first_chunk = first"] == "websocket.disconnect":
            return
        first_chunk = first_msgconnect":
            return
        first_chunk = first"] == "websocket.disconnect":
            return
        first_chunk = first_msg.get("bytes") or ( first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
       _msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk:
.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk:
_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk:
first_msg.get("text") or "").encode()
        if not first_chunk:
            return

        try:
 if not first_chunk:
            return

        try:
            return

        try:
            command, address            return

        try:
            command, address            return

        try:
            command, address, port, initial_payload = await parse            command, address, port, initial_payload = await parse_vless_header(first_chunk)
        except ValueError as e:
            logger.w            command, address, port, initial_payload = await parse_vless_header(first_chunk)
, port, initial_payload = await parse_vless_header(first_chunk)
        except ValueError as e:
            logger.warning(f", port, initial_payload = await parse_vless_header(first_chunk)
        except ValueError as e:
            logger.warning(f"Invalid VLESS header from {_vless_header(first_chunk)
        except ValueError as e:
            logger.warning(f"Invalid VLESS header from {arning(f"Invalid VLESS header from {client_ip}: {e}")
        except ValueError as e:
            logger.warning(f"Invalid VLESS header from {client_ip}: {e}")
Invalid VLESS header from {client_ip}: {e}")
client_ip}: {e}")
            await websocket.closeclient_ip}: {e}")
            await websocket.close(code=1008            await websocket.close(code=1008, reason="invalid header")
            await websocket.close(code=1008, reason="invalid header")
            await websocket.close(code=1008, reason="invalid header")
(code=1008, reason="invalid header")
            return

        conn_id = secrets.token_urlsafe(8)
        now, reason="invalid header")
            return

        conn_id = secrets.token_urlsafe(8)
        now            return

        conn_id = secrets.token_urlsafe(8)
        now = time.time()
        async            return

        conn_id = secrets.token_urlsafe(8)
        now = time.time()
        async with connections_lock:
            connections[conn_id] = {
            return

        conn_id = secrets.token_urlsafe(8)
        now = time.time()
        async with connections_lock:
            connections[conn_id] = {
 = time.time()
        async with connections_lock:
            connections[conn_id] = {
                "uuid": uuid, = time.time()
        async with connections_lock:
            connections[conn_id] = {
                "uuid with connections_lock:
            connections[conn_id] = {
                "uuid": uuid,                "uuid": uuid,                "uuid": uuid, "ip": client_ip,
                "connected_at": datetime.now(timezone.utc).isoformat(),
                "": uuid, "ip": client_ip,
                "connected_at": datetime.now(timezone.utc).isoformat(),
                " "ip": client_ip,
                "connected_at": datetime.now(timezone.utc).isoformat(),
                " "ip": client_ip,
                "connected_at": datetime.now(timezone.utc).isoformat(),
                "bytes": 0, "last_active": now
            "ip": client_ip,
                "connected_at": datetime.now(timezone.utc).isoformat(),
                "bytes": 0, "bytes": 0, "last_active": now
           bytes": 0, "last_active": now
            }
            connection_socketsbytes": 0, "last_active": now
            }
            connection_sockets[conn_id] = websocket
            link_ip_map[u }
            connection_socketslast_active": now
            }
            connection_sockets[conn_id] = websocket }
            connection_sockets[conn_id] = websocket
            link_ip_map[u[conn_id] = websocket
            link_ip_map[uuid].add(client_ip)

uid].add(client_ip)

[conn_id] = websocket
            link_ip_map[uuid].add(client_ip)


            link_ip_map[uuid].add(client_ip)

        size = len(first_chunkuid].add(client_ip)

        size = len(first_chunk)
        stats["total_bytes"] += size
        stats["total_requests"] += 1
               size = len(first_chunk)
        stats["total_bytes"] += size
        stats["total_requests"] += 1
               size = len(first_chunk)
        stats["total_bytes"] += size
        stats["total_requests"] += 1
               size = len(first_chunk)
        stats["total_bytes"] += size
        stats["total_requests"] += 1
       )
        stats["total_bytes"] += size
        stats["total_requests"] += 1
        await atomic_check_and_add await atomic_check_and_add_usage(uuid, size)

        reader await atomic_check_and_add_usage(uuid, size)

        reader await atomic_check_and_add_usage(uuid, size)

        reader await atomic_check_and_add_usage(uuid, size)

        reader_usage(uuid, size)

        reader, writer = await as, writer = await asyncio.wait_for, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port), timeout=10.0
        )

, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port), timeout=10.0
        )

, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port), timeout=10.0
        )

        if initial_payloadyncio.wait_for(
            asyncio.open_connection(address, port), timeout=10.0
        )

        if initial_payload:
            p_size = len(initial_payload)
            stats["total_bytes(
            asyncio.open_connection(address, port), timeout=10.0
        )

        if initial_payload:
            p_size = len(initial_payload)
            stats["total_bytes        if initial_payload:
            p_size = len(initial_payload)
            stats["total_bytes        if initial_payload:
            p_size = len(initial_payload)
            stats["total_bytes"] += p_size
           :
            p_size = len(initial_payload)
            stats["total_bytes"] += p_size
           "] += p_size
            await atomic_check_and_add_usage(uuid, p_size)
            try:
"] += p_size
            await atomic_check_and_add_usage(uuid, p_size)
            try:
                writer.write(initial_payload)
                await writer"] += p_size
            await atomic_check_and_add_usage(uuid, p_size)
            try:
                writer.write(initial_payload)
                await writer await atomic_check_and_add_usage(uuid, p_size)
            try:
                writer.write(initial_payload)
                await writer.drain()
 await atomic_check_and_add_usage(uuid, p_size)
            try:
                writer.write(initial_payload)
                writer.write(initial_payload)
                await writer.drain()
            except Exception:
                pass

        task_up =.drain()
            except Exception:
                pass.drain()
            except Exception:
                pass

        task_up = asyncio.create_task(ws_to_tcp(webs            except Exception:
                pass

        task_up = asyncio.create_task(ws_to_tcp(webs                await writer.drain()
            except Exception:
                pass

        task_up = asyncio.create_task( asyncio.create_task(ws_to_tcp(webs

        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, connocket, writer, conn_id, uuid))
        taskocket, writer, conn_id, uuid))
        task_down = asyncio.create_task(tcp_to_wsws_to_tcp(websocket, writer, conn_id, uuid))
        task_down = asyncioocket, writer, conn_id, uuid))
        task_down = asyncio.create_task(tcp_to_ws_id, uuid))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
       _down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({task(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({task_up done, pending = await asyncio.wait({task_up_up, task_down}, return_when=asyncio.Ftask_up, task_down}, return_when=asyncio.F asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
            try:
, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
            try:
IRST_COMPLETED)
        for t in pending:
            t.cancel()
            try:
IRST_COMPLETED)
        for t in pending:
            t.cancel()
            try:
                await t
            except asyncio            try:
                await t
            except asyncio                await t
            except asyncio.CancelledError:
                pass

    except WebSocket                await t
            except asyncio.CancelledError:
                pass

    except WebSocket                await t
            except asyncio.CancelledError:
                pass

    except WebSocket.CancelledError:
                pass

    except WebSocketDisconnect:
        pass
.CancelledError:
                pass

    except WebSocketDisconnect:
        pass
Disconnect:
        pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"errorDisconnect:
        pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"errorDisconnect:
        pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "": str(exc), "time": datetime.now": str(exc), "time": datetime.now": str(exc), "time": datetime.now(timezone.utc).isoformat()})
        logger": str(exc), "time": datetime.now(timezone.utc).isoformat()})
        loggertime": datetime.now(timezone.utc).(timezone.utc).isoformat()})
        logger.exception("WebSocket error")
    finally:
        if writer:
            try:
                writer.close()
(timezone.utc).isoformat()})
        logger.exception("WebSocket error")
    finally:
        if writer:
            try:
                writer.close()
.exception("WebSocket error")
    finally:
        if writer:
            try:
                writer.close()
.exception("WebSocket error")
    finally:
        if writer:
            try:
                writer.close()
isoformat()})
        logger.exception("WebSocket error")
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
                           await writer.wait_closed()
            except Exception:
                pass
        if conn_id:
            async                await writer.wait_closed()
            except Exception:
                pass
        if conn_id:
            async                await writer.wait_closed()
            except Exception:
                pass
        if conn_id:
            async                await writer.wait_closed()
            except Exception:
                pass
        if conn_id:
            async except Exception:
                pass
        if conn_id:
            async with connections_lock:
                info with connections_lock:
                info = connections.pop(conn_id with connections_lock:
                info = connections.pop(conn_id with connections_lock:
                info = connections.pop(conn_id, None)
                connection_sockets.pop(conn_id with connections_lock:
                info = connections.pop(conn_id, None)
                connection_sockets.pop(conn_id, None)
                if info:
                    uid = connections.pop(conn_id, None)
                connection_sockets.pop(conn_id, None)
                if info, None)
                connection_sockets.pop(conn_id, None)
                if info:
                    uid = info, None)
                connection_sockets.pop(conn_id, None)
                if info:
                    uid = info.get, None)
                if info:
                    uid = = info.get("uuid")
                    ip = info.get("ip")
                    if uid and ip:
                       :
                    uid = info.get("uuid")
                    ip =.get("uuid")
                    ip = info.get("ip")
                    if uid and ip:
                        has_other = any(
("uuid")
                    ip = info.get("ip")
                    if uid and ip:
                        has_other = any(
 info.get("uuid")
                    ip = info.get("ip")
                    if uid and ip:
                        has_other = any(
                            c.get("uuid") info.get("ip")
                    if uid and ip:
                        has_other = any(
                            c.get("uuid")                            c.get("uuid") == uid and c.get("                            c.get("uuid") == uid and c.get("ip") == ip
                            for c in connections.values()
                        )
                        if not has_other:
                            has_other = any(
                            c.get("uuid") == uid and c.get("ip") == ip
                            == uid and c.get("ip") == ip
                            for c in connections.values()
                        )
                        if not has_other:
                            if uid in link_ip_map:
                                == uid and c.get("ip") == ip
                            for c in connections.values()
                        )
                        if not has_other:
                            if uid in link_ip_map:
                               ip") == ip
                            for c in connections.values()
                        )
                        if not has_other:
                            if uid in link_ip_map:
                                link_ip_map[uid]. if uid in link_ip_map:
                                link_ip_map for c in connections.values()
                        )
                        if not has_other:
                            if uid in link_ip_map:
                                link_ip_map[uid].discard(ip)
                                if not link_ip_map[uid link_ip_map[uid].discard(ip)
                                link_ip_map[uid].discard(ip)
                               discard(ip)
                                if not link_ip_map[uid].discard(ip)
                                if not link_ip_map[uid]:
                                    link_ip_map.pop(uid, None)

]:
                                    link_ip_map.pop(uid, None)

 if not link_ip_map[uid]:
                                    link_ip_map.pop(uid, None)

 if not link_ip_map[uid]:
                                    link_ip_map.pop(uid, None)

[uid]:
                                    link_ip_map.pop(uid, None)

def get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarddef get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarddef get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarddef get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarddef get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if websocket.client:
       ed-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if websocket.client:
       ed-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if websocket.client:
        return websocket.client.host
    return "unknowned-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if websocket.client:
        return websocket.client.host
    return "unknowned-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if websocket.client:
        return websocket.client.host
    return "unknown return websocket.client.host
    return "unknown"

# ── HTML Panel (fully redes return websocket.client.host
    return "unknown"

# ── HTML Panel (fully redes"

# ── HTML Panel (fully redesigned V2Render theme,"

# ── HTML Panel (fully redesigned V2Render theme,"

# ── HTML Panel (fully redesigned V2Render theme, darkigned V2Render theme, dark phosphigned V2Render theme, dark phosphor green / dark phosph dark phosph phosphor green / light softor green / light soft light soft green) ─
PANEL_HTML = r"""<!DOCTYPE html>
<htmlor green / light soft green) ─
PANEL_HTML = ror green / light soft green) ─
PANEL_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name=" green) ─
PANEL_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name=" green) ─
PANEL_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=viewport" content="width=device-width, initial-scale=viewport" content="width=device-width, initial-scale=="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>V2Render Panel</title>
1.0, maximum-scale=1.0, user-scalable=no">
<title>1.0, maximum-scale=1.0, user-scalable=no">
<title>V2Render Panel</title>
<link href="https://fonts1.0, maximum-scale=1.0, user-scalable=no">
<title>V2Render Panel</title>
<link href="https://fontsV2Render Panel</title>
<link href="https://fonts<link href="https://fonts.googleapis.com/css2?familyV2Render Panel</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght.googleapis.com/css2?family=Orbitron:wght@700;900&family=Inter:wght@300.googleapis.com/css2?family=Orbitron:wght@700;900&family=Inter:wght@300.googleapis.com/css2?family=Orbitron:wght@700;900&family=Inter=Orbitron:wght@700;900&family=Inter:wght@300;400;500;600;700&family=Vaz@700;900&family=Inter:wght@300;400;500;600;700&;400;500;600;700&family=Vazirmatn:wght@400;600;700;800&;400;500;600;700&family=Vazirmatn:wght@400;600;700;800&display:wght@300;400;500;600;700&family=Vazirmatn:wght@400;600;700;irmatn:wght@400;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdnjsfamily=Vazirmatn:wght@400;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdnjsdisplay=swap" rel="stylesheet">
<script src=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4800&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
*{.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
*{.1/chart.umd.js"></script>
<style>
*{Chart.js/4.4.1/chart.umd.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
 <style>
*{margin:0;padding:0;box-sizing:bordermargin:0;padding:0;box-sizing:border-box}
:root{
 margin:0;padding:0;box-sizing:border-box}
:root{
  --primary:#39ff14margin:0;padding:0;box-sizing:border-box}
:root{
  --primary:#39ff14; --primary-dim: --primary:#39ff14; --primary-dim:-box}
:root{
  --primary:#39ff14; --primary-dim:rgba(57 --primary:#39ff14; --primary-dim:rgba(57,255,20,0.12; --primary-dim:rgba(57rgba(57,255,20,0.rgba(57,255,20,0.12);
  --bg:#0a0a0a; --bg2:#121,255,20,0.12);
  --bg:#0a0a0a; --bg2:#);
  --bg:#0a0a0a; --bg2:#121,255,20,0.12);
  --bg:#0a0a0a; --bg2:#121212; --bg3:#12);
  --bg:#0a0a0a; --bg2:#121212; --bg3:#1a1a1a212; --bg3:#1a1a1a121212; --bg3:#1a1a1a;
  --surface:#141414; --surface2:#212; --bg3:#1a1a1a;
  --surface:#141414; --surface2:#1e1e1e; --surface3:#2621a1a1a;
  --surface:#141414; --surface2:#1e1e1e; --surface3:#262626;
  --border;
  --surface:#141414; --surface2:#1e1e1e; --surface3:#262;
  --surface:#141414; --surface2:#1e1e1e; --surface3:#262626;
  --border:rgba(57,2551e1e1e; --surface3:#262626;
  --border:rgba(57,255626;
  --border:rgba:rgba(57,255626;
  --border:rgba(57,255,20,0.08); --border2:,20,0.08); --border2:rg,20,0.08); --border2:rgba(57,255,20,0.18);
  --text:#e(57,255,20,0.08); --border2:rgba(57,255,20,0.18);
  --text:#e,20,0.08); --border2:rgba(57,255,20,0.18);
rgba(57,255,20,0.18);
  --text:#eba(57,255,20,0.18);
  --text:#e0e0e0; --text2:#a0a0a0;0e0e0; --text2:#a  --text:#e0e0e0; --text2:#a0a0a0; --text3:#707070;
  --green:#4ade80; --green-dim:rgba(740e0e0; --text2:#a0a0a0; --text3:#707070;
  --green:#4ade80; --green-dim:rgba(74,222,128,00e0e0; --text2:#a0a0a0; --text3:#707070;
  --green:#4ade80; --green --text3:#707070;
  --green:#4ade80; --green-dim:rgba(74,222,128,00a0a0; --text3:#707070;
  --green:#4ade80; --green-dim:rgba(74,222,128,0.1);
  --red,222,128,0.1);
  --red:#f87171; --.1);
  --red:#f87171; --red-dim:rgba(248,113-dim:rgba(74,222,128,0.1);
  --red.1);
  --red:#f87171; --red-dim::#f87171; --red-dim:red-dim:rgba(248,113,113,0.1);
  --yellow:#fbbf,113,0.1);
  --yellow:#fbbf24;
  --nav-w:64:#f87171; --red-dim:rgba(248,113,113,0.1);
  --yellow:#fbbf24;
  --nav-w:64px;
}
body.lrgba(248,113,113,0.1);
  --yellow:#fbbf24;
  --nav-w:64px;
}
body.lightrgba(248,113,113,0.1);
  --yellow:#fbbf24;
  --nav-w:64px;
24;
  --nav-w:64px;
}
body.light-mode {
  --primary:#2epx;
}
body.light-mode {
  --primary:#2e7d32; --primary-dim:rgba(46,125,50,0ight-mode {
  --primary:#2e7d32; --primary-dim:rgba(46,125,50,0.15);
  --bg-mode {
  --primary:#2e7d32; --primary-dim:rgba(46}
body.light-mode {
  --primary:#2e7d32; --primary-dim:rgba(46,125,50,0.15);
  --bg:#f5fff5; --bg2:#7d32; --primary-dim:rgba(46,125,50,0.15);
  --bg:#f5fff5; --bg2:#.15);
  --bg:#f5fff:#f5fff5; --bg2:#,125,50,0.15);
  --bg:#f5fff5; --bg2:#ffffff; --bg3:#e8f5e9ffffff; --bg3:#e8f5e95; --bg2:#ffffff; --bg3:#e8f5e9;
  --surface:#ffffffffffff; --bg3:#e8f5e9;
  --surface:#ffffff; --surface2ffffff; --bg3:#e8f5e9;
  --surface:#ffffff; --surface2;
  --surface:#ffffff; --surface2:#f1f8f1; --surface3:#e0f0e0;
  --border:rgba(;
  --surface:#ffffff; --surface2:#f1f8f1; --surface3:#e0f0e0;
  --border:rgba(; --surface2:#f1f8f1; --surface3:#e0f0e0;
 :#f1f8f1; --surface3:#e0f0e0;
  --border:rgba(:#f1f8f1; --surface3:#e0f0e0;
  --border:rgba(0,0,0,0,0,0,0.08); --border0,0,0,0.08); --border:rgba(0,0,0,0.08); --border2:rgba(0,0,0,0.16);
  --text:#1a0,0,0,0.08); --border2:rgba(0,0,0,0.16);
  --text:#1a0.08); --border2:rgba(0,0,0,0.16);
  --text:#1a1a1a;2:rgba(0,0,0,0.16);
  --text:#1a1a1a; --text2:#4a4a4a; --text --border2:rgba(0,0,0,0.16);
  --text:#1a1a1a; --text2:#4a4a4a; --text1a1a; --text2:#4a4a4a; --text3:#888;
}
html1a1a; --text --text2:#4a4a4a; --text3:#888;
}
html,body{height:100%;background:var(--bg);transition: background3:#888;
}
html,body{height:100%;background:var(--bg);transition: background3:#888;
}
html,body{height:100%;background:var(--bg);transition: background,body{height:100%;background:var(--bg);transition: background 0.3s,2:#4a4a4a; --text3:#888;
}
html,body{height:100%;background:var(--bg);transition: background 0. 0.3s, color 0 0.3s, color 0 0.3s, color 0.3s;}
body{font-family:'Inter','Vazirmatn',sans-serif;color:var(--text color 0.3s;}
body{font-family:'Inter','Vazirmatn',3s, color 0.3s;}
body{font-family:'Inter','Vazirmatn',sans-serif.3s;}
body{font-family:'Inter','Vazirmatn',sans-serif;.3s;}
body{font-family:'Inter','Vazirmatn',sans-serif;color:var(--text);display:flex;min-height);display:flex;min-height:100vh;}
body[dir="rtl"]{direction:rtl;sans-serif;color:var(--text);display:flex;min-height:100vh;}
body;color:var(--text);display:flex;min-height:100vh;}
body[dir="rtl"]{direction:rtl;text-align:right}
::-color:var(--text);display:flex;min-height:100vh;}
body[dir="rtl"]{direction:rtl;text-align:right}
::-:100vh;}
body[dir="rtl"]{direction:rtl;text-align:right}
text-align:right}
::-webkit-scrollbar{width:4px}::-webkit[dir="rtl"]{direction:rtl;text-align:right}
::-webkit-scrollbar{width:4px}::-webkitwebkit-scrollbar{width:4px}::-webkitwebkit-scrollbar{width:4px}::-webkit::-webkit-scrollbar{width:4px}::-webkit-scrollbar-thumb{background:var(--primary-dim-scrollbar-thumb{background:var(--primary-dim-scrollbar-thumb{background:var(--primary-dim-scrollbar-thumb{background:var(--primary-dim);border-radius:4px}
.bg-fixed{position:fixed;inset:0-scrollbar-thumb{background:var(--primary-dim);border-radius:4px}
.bg-fixed{position:fixed;inset:0);border-radius:4px}
.bg-fixed{position:fixed;inset:0;z-index:0;pointer-events:none;background:rad);border-radius:4px}
.bg-fixed{position:fixed;inset:0;z-index:0;pointer-events:none;background:rad);border-radius:4px}
.bg-fixed{position:fixed;inset:0;z-index:0;pointer-events:n;z-index:0;pointer-events:n;z-index:0;pointer-events:none;background:radial-gradient(ellipse ial-gradient(ellipse 70% 50% atial-gradient(ellipse 70% 50% at 50% -10one;background:radial-gradient(ellipse one;background:radial-gradient(ellipse 70% 50% at 50% -1070% 50% at 50% -10%,var(--primary-dim),transparent 60%) 50% -10%,var(--primary-dim),transparent 60%)}
.grid-fixed%,var(--primary-dim),transparent 60%)}
.grid-fixed{position70% 50% at 50% -10%,var(--primary-dim),transparent 60%)%,var(--primary-dim),transparent 60%)}
.grid-fixed{position:fixed;inset:}
.grid-fixed{position:fixed;inset:{position:fixed;inset:0;z-index:0;pointer-events:none;background-image:linear-gradient(rgba(128,128,128,0.03) :fixed;inset:0;z-index:0;pointer-events:none}
.grid-fixed{position:fixed;inset:0;z-index:0;pointer-events:none;background-image:linear-gradient(rgba(128,128,128,0.03) 0;z-index:0;pointer-events:none;background-image:linear-gradient(rgba(128,128,128,0.03) 1px,transparent 0;z-index:0;pointer-events:none;background-image:linear-gradient(rgba(128,128,128,0.03) 1px,transparent 1px),1px,transparent 1px),linear-gradient(90deg,rgba(128,128;background-image:linear-gradient(rgba(128,128,128,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(128,1281px,transparent 1px),linear-gradient(90deg,rgba(128,1281px),linear-gradient(90deg,rgba(128,128linear-gradient(90deg,rgba(128,128,128,0.03) 1px,trans,128,0.03) 1px,transparent 1px);background-size:56px 56,128,0.03) 1px,transparent 1px);background-size:56px 56,128,0.03) 1px,transparent 1px);background-size:56px 56,128,0.03) 1px,transparent 1px);background-size:56px 56parent 1px);background-size:56px 56px}
.sidebar{position:fixed;left:0;top:0;px}
.sidebar{position:fixed;left:0;top:0;bottom:0;px}
.sidebar{position:fixed;left:0;top:0;bottom:0;width:px}
.sidebar{position:fixed;left:0;top:0;bottom:0;width:px}
.sidebar{position:fixed;left:0;top:0;bottom:0;width:bottom:0;width:var(--nav-w);backgroundwidth:var(--nav-w);backgroundvar(--nav-w);background:var(--surface);bordervar(--nav-w);background:var(--surface);bordervar(--nav-w);background:var(--surface);border-right:1px solid var(--border);display:flex:var(--surface);border-right:1px solid var(--border);display:flex:var(--surface);border-right:1px solid var(--border);display:flex-right:1px solid var(--border);display:flex;flex-direction:column;z-index:100;transition-right:1px solid var(--border);display:flex;flex-direction:column;z-index:100;transition;flex-direction:column;z-index:100;transition:all .3s cubic-bezier(.4,0,.2,1);backdrop-filter:blur;flex-direction:column;z-index:100;transition:all .3s cubic;flex-direction:column;z-index:100;transition:all .3s cubic-bezier(.4,0,.2,1);:all .3s cubic-bezier(.4,0,.2,1);backdrop-filter:blur:all .3s cubic-bezier(.4,0,.2,1);backdrop-filter:blur(20px);}
.sidebar::after{content-bezier(.4,0,.2,1);backdrop-filter:blur(20px);}
.sbackdrop-filter:blur(20px);}
.sidebar::after{content:'';position:absolute(20px);}
.sidebar::after{content:'';position:absolute;top:0;right:0;bottom:0;width:1px;(20px);}
.sidebar::after{content:'';position:absolute;top:0;right:0;bottom:0;width:1px;:'';position:absolute;top:0;right:0;bottom:0;width:1px;idebar::after{content:'';position:absolute;top:0;right:0;bottom:0;width:1px;;top:0;right:0;bottom:0;width:1px;background:linear-gradient(180deg,transparent,var(--primary) 30%,background:linear-gradient(180deg,transparent,var(--primary) 30%,background:linear-gradient(180deg,transparent,var(--primary) 30%,var(--primary) 70%,transparent); opacitybackground:linear-gradient(180deg,transparent,var(--primary) 30%,var(--primary) 70background:linear-gradient(180deg,transparent,var(--primary) 30%,var(--primary) 70var(--primary) 70%,transparent); opacityvar(--primary) 70%,transparent); opacity:0.3;}
.light-mode:0.3;}
.light-mode%,transparent); opacity:0.3;}
.light%,transparent); opacity:0.3;}
.light:0.3;}
.light-mode .sidebar::after{display:none;}
.sb-brand{padding:16px 0;display:flex;flex-direction:column; .sidebar::after{display:none;}
.sb-brand{padding:16px 0;display:flex;flex-direction:column;align-mode .sidebar::after{display:none;}
.sb-brand{padding:-mode .sidebar::after{display:none;}
.sb-brand{padding: .sidebar::after{display:none;}
.sb-brand{padding:16px 0;display:flex;flex-direction:column;align-items:center;gap:2px;border-bottom:1px solid var(--border);flex-shrink:0-items:center;gap:2px;border-bottom:1px solid var(--border);flex-shrink:016px 0;display:flex;flex-direction:column;align-items:center;gap:2px;border-bottom:1px solid var(--border);flex-shrink:0}
.sb-logo{16px 0;display:flex;flex-direction:column;align-items:center;gap:2px;border-bottom:1px solid var(--border);flex-shrink:0}
.sb-logo{align-items:center;gap:2px;border-bottom:1px solid var(--border);flex-shrink:0}
.sb-logo{width:36px;height}
.sb-logo{width:36px;height}
.sb-logo{width:36px;height:36px;}
.sb-title{font-family:'width:36px;heightwidth:36px;height:36px;}
.sb-title{font-family:':36px;}
.sb-title{font-family:'Orbitron',sans-serif;font-size:8:36px;}
.sb-title{font-family:'Orbitron',sans-serif;font-sizeOrbitron',sans-serif;font-size:8px;letter-spacing:.:36px;}
.sb-title{font-family:'Orbitron',sans-serif;font-size:8px;letter-spacing:.18em;color:varOrbitron',sans-serif;font-size:8px;letter-spacing:.18em;color:varpx;letter-spacing:.18em;color:var(--primary);text-transform::8px;letter-spacing:.18em;color:var(--primary);text-transform:18em;color:var(--primary);text-transform:(--primary);text-transform:uppercase;white-space:nowrap;overflow:hidden(--primary);text-transform:uppercase;white-space:nowrap;overflow:hiddenuppercase;white-space:nowrap;overflow:hidden;margin-top:4px;}
.sb-nav{flexuppercase;white-space:nowrap;overflow:hidden;margin-top:4px;}
.sb-nav{flex:1;display:flexuppercase;white-space:nowrap;overflow:hidden;margin-top:4px;}
.sb-nav{flex:1;display:flex;flex-direction:column;;margin-top:4px;}
.sb-nav{flex:1;display:flex;flex-direction:column;justify-content:flex-end;padding-bottom:12;margin-top:4px;}
.sb-nav{flex:1;display:flex;flex-direction:column;justify-content:flex-end;padding-bottom::1;display:flex;flex-direction:column;justify-content:flex-end;padding-bottom:12px;gap:2px;padding-left:8;flex-direction:column;justify-content:flex-end;padding-bottom:12px;gap:2justify-content:flex-end;padding-bottom:12px;gap:2px;padding-left:8px;gap:2px;padding-left:812px;gap:2px;padding-left:8px;padding-right:8px}
.navpx;padding-right:8px}
.nav-item{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px;padding-left:8px;padding-right:8px}
.nav-item{display:flex;flex-directionpx;padding-right:8px}
.nav-item{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3pxpx;padding-right:8px}
.nav-item{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px-item{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px;padding:10px 6px;border-radius:12px;color:varpx;padding:10px 6px;border-radius:12px;color:var(--text3);:column;align-items:center;justify-content:center;gap:3px;padding:10px 6px;border-radius:12px;color:var(--text3);cursor:;padding:10px 6px;border-radius:12px;color:var(--text3);cursor:pointer;transition:all .;padding:10px 6px;border-radius:12px;color:var(--text3);cursor:pointer;transition:all .(--text3);cursor:pointer;transition:all .cursor:pointer;transition:all .2s;border:1pointer;transition:all .2s;border:12s;border:1px solid transparent;background:n2s;border:1px solid transparent;background:none;width:100%;font-family:inherit;}
.nav-item:hover{color:2s;border:1px solid transparent;background:none;width:100%;font-family:inherit;}
.nav-item:hover{color:px solid transparent;background:none;width:100%;font-family:inherit;}
.nav-item:hover{color:var(--primary);border-color:var(--px solid transparent;background:none;width:100%;font-family:inherit;}
.nav-item:hover{color:var(--primary);border-color:var(--one;width:100%;font-family:inherit;}
.nav-item:hover{color:var(--primary);border-color:var(--primary-dim);var(--primary);border-color:var(--primary-dim);}
.nav-item.active{color:var(--primary);var(--primary);border-color:var(--primary-dim);}
.nav-item.active{color:var(--primary);border-color:var(--primaryprimary-dim);}
.nav-item.active{primary-dim);}
.nav-item.active{color:var(--primary);border-color:var(--primary-dim);background:var(--primary-dim}
.nav-item.active{color:var(--primary);border-color:var(--primary-dim);background:var(--border-color:var(--primary-dim);background:var(---dim);background:var(--primary-dim);box-shadow:color:var(--primary);border-color:var(--primary-dim);background:var(--primary-dim);box-shadow:0 0 12px);box-shadow:0 0 12pxprimary-dim);box-shadow:0 0 12px var(--primary-dim);}
.nav-icon{width:primary-dim);box-shadow:0 0 12px var(--primary-dim);}
0 0 12px var(--primary-dim);}
.nav-icon{width:18px;height:18px;flex-shrink:0;transition: var(--primary-dim);}
.nav-icon{width:18px;height:18px;flex-shrink var(--primary-dim);}
.nav-icon{width:18px;height:18px;flex-shrink18px;height:18px;flex-shrink.nav-icon{width:18px;height:18px;flex-shrink:0;transition:transformtransform .2s}
.nav-item:hover .nav-icon,.nav-item.active .nav-icon:0;transition:transform .2s}
.nav-item:hover .nav-icon,.:0;transition:transform .2s}
.nav-item:hover .nav-icon,.:0;transition:transform .2s}
.nav-item:hover .nav-icon,. .2s}
.nav-item:hover .nav-icon,.nav-item.active .nav-icon{transform:scale(1.1)}
.nav-labelnav-item.active .nav-icon{transform:scale(1.1)}
.nav-label{font-size:8nav-item.active .nav-icon{transform:scale(1.1)}
.nav-label{font-size:8nav-item.active .nav-icon{transform:scale(1.1)}
.nav-label{font-size:8.5px;font-weight:600;letter-spacing:.05em;white-space{transform:scale(1.1)}
.nav-label{font-size:8.5px;font-weight:600;letter-spacing:.05em;white-space{font-size:8.5px;font-weight:600;letter-spacing:.05em;white-space.5px;font-weight:600;letter-spacing:.05em;white-space:nowrap;.5px;font-weight:600;letter-spacing:.05em;white-space:nowrap;overflow:hidden}
.nav-badge{position:absolute;top:nowrap;overflow:hidden}
.nav-badge{position:absolute;top:5px;right::nowrap;overflow:hidden}
.nav-badge{position:absolute;top:5px;right::nowrap;overflow:hidden}
.nav-badge{position:absolute;top:5px;right:5px;background:varoverflow:hidden}
.nav-badge{position:absolute;top:5px;right:5px;background:var:5px;right:5px;background:var(--primary);color:#0005px;background:var(--primary);color:#0005px;background:var(--primary);color:#000;font-size:8px;font-weight:800;min-width:14px;height:(--primary);color:#000;font-size:8px;font-weight:800;min-width:14px(--primary);color:#000;font-size:8px;font-weight:800;min-width:;font-size:8px;font-weight:800;font-size:8px;font-weight:800;min-width:14px;height:14px;border-radius:7px;display:flex;align-items14px;border-radius:7px;display:flex;align-items;height:14px;border-radius:7px;display:flex;align-items:center;justify-content14px;height:14px;border-radius:7px;display:flex;align-items:center;justify-content:center;padding:0;min-width:14px;height:14px;border-radius:7px;display:flex;align-items:center;justify-content:center;justify-content:center;justify-content:center;padding:0 3px}
.sb-bottom{padding:8px;border-top:1:center;padding:0 3px}
.sb-bottom{padding:8 3px}
.sb-bottom{padding:8:center;padding:0 3px}
.sb-bottom{padding:8px;border-top:1:center;padding:0 3px}
.sb-bottom{padding:8px;border-top:1px solid var(--border);display:flex;flex-directionpx solid var(--border);display:flex;flex-directionpx;border-top:1px solid var(--border);display:flex;flex-direction:column;gap:6px;border-top:1px solid var(--border);display:flex;flex-direction:column;gap:6px solid var(--border);display:flex;flex-direction:column;gap:6px;flex-shrink:column;gap:6px;flex-shrink:column;gap:6px;flex-shrink:0}
.lang-row{display:flex;gappx;flex-shrink:0}
.lang-row{display:flex;gap:4px}
.lang-btn{flex:1;padding:5px 2px;flex-shrink:0}
.lang-row{display:flex;gap:4px}
.lang-btn{flex:1;padding:5px 2px;:0}
.lang-row{display:flex;gap:4px}
.lang-btn{flex:1;padding:5px 2px;border:1px:0}
.lang-row{display:flex;gap:4px}
.lang-btn{flex:1;padding:5px 2px;border:1px solid var:4px}
.lang-btn{flex:1;padding:5px 2px;border:1px solidpx;border:1px solid var(--border);border-radius:7px;background:noneborder:1px solid var(--border);border-radius:7px;background:none;color:var(--text solid var(--border);border-radius:7px;background:none;color:var(--text(--border);border-radius:7px;background:none;color:var(--text3);font-size:9 var(--border);border-radius:7px;background:none;color:var(--text3);font-size:9px;font-weight:700;cursor:pointer;transition:all .2s;font-family:inherit;letter-spacing:.;color:var(--text3);font-size:9px;font-weight:700;cursor:pointer;transition:all .2s;font-family:inherit;letter3);font-size:9px;font-weight:700;cursor:pointer;transition:all .2s;font-family:inherit;letter-spacing:.05em}
3);font-size:9px;font-weight:700;cursor:pointer;transition:all .2s;font-family:inherit;letter-spacing:.px;font-weight:700;cursor:pointer;transition:all .2s;font-family:inherit;letter05em}
.lang-btn.active{background:var(--primary-dim);border-color:var(--primary);-spacing:.05em}
.lang-btn.active{background:var(--primary-dim);border-color:var(--primary);color:var(--primary)}
.lang-btn:hover:not(..lang-btn.active{background:var(--primary-dim);border-color:var(--primary);color:var(--primary)}
05em}
.lang-btn.active{background:var(--primary-dim);border-color:var(--primary);-spacing:.05em}
.lang-btn.active{background:var(--primary-dim);border-color:var(--primary);color:var(--primary)}
.lang-btn:hover:not(.color:var(--primary)}
.lang-btn:hover:not(.active){border-color:var(--primary-dim);color:.lang-btn:hover:not(.active){border-color:var(--primary-dim);color:color:var(--primary)}
.lang-btn:hover:not(.active){border-color:var(--primary-dim);color:active){border-color:var(--primary-dim);color:var(--primary)}
.logout-btn{display:flex;align-items:center;justactive){border-color:var(--primary-dim);color:var(--primary)}
.logout-btn{display:flex;align-items:center;justvar(--primary)}
.logout-btn{display:flex;align-items:center;justvar(--primary)}
.logout-btn{display:flex;align-items:center;justify-content:center;paddingvar(--primary)}
.logout-btn{display:flex;align-items:center;justify-content:center;padding:7px;border:ify-content:center;padding:7px;border:ify-content:center;padding:7px;border:1px solid rgba(248,113,113,.:7px;border:1px solid rgba(248ify-content:center;padding:7px;border:1px solid rgba(248,113,113,.1px solid rgba(248,113,113,.15);border-radius:8px;background:rg1px solid rgba(248,113,113,.15);border-radius:8px;background:rg15);border-radius:8px;background:rgba(248,113,113,.06);color:rg,113,113,.15);border-radius:8px;background:rgba(248,113,113,.06);color:rgba(248,113,15);border-radius:8px;background:rgba(248,113,113,.ba(248,113,113,.06);color:rgba(248,113,113,.06);color:rgba(248,113,113,.6);cursor:pointer;transition:all .2s;ba(248,113,113,.6);cursor:pointer;transition:all .2s113,.6);cursor:pointer;transition:all .2s;font-size:10px;gap:406);color:rgba(248,113,113,.6);cursor:pointer;transition:all .2s;font-size:10px;gap:4px;font-weight:600;font-family:ba(248,113,113,.6);cursor:pointer;transition:all .2sfont-size:10px;gap:4px;font-weight:600;font-family:inherit}
.logout-btn:hover{background;font-size:10px;gap:4px;font-weight:600;font-family:inherit}
.logout-btn:hover{backgroundpx;font-weight:600;font-family:inherit}
.logout-btn:hover{background:rgba(248,inherit}
.logout-btn:hover{background:rgba(248,;font-size:10px;gap:4px;font-weight:600;font-family:inherit}
.logout-btn:hover{background:rgba(248,:rgba(248,113,113,.12);border-color:rgba(248,113,113,.3);color:var(--red)}
.theme-toggle{background:transparent;border:1px solid var(--:rgba(248,113,113,.12);border-color:rgba(248,113,113,.3);color:var(--red)}
.theme-toggle{background:transparent;border:1px solid var(--113,113,.12);border-color:rgba(248,113,113,.3);color:var(--113,113,.12);border-color:rgba(248,113,113,.3);color:var(--113,113,.12);border-color:rgba(248,113,113,.3);color:var(--red)}
.theme-toggle{background:transparent;border:1px solid var(--border);color:var(--text3);border-radius:7px;padding:border);color:var(--text3);border-radius:7px;padding:4border);color:var(--text3);border-radius:7px;padding:4red)}
.theme-toggle{background:transparent;border:1px solid var(--border);color:var(--text3);border-radius:7px;padding:4px;cursor:pointer;displayred)}
.theme-toggle{background:transparent;border:1px solid var(--border);color:var(--text3);border-radius:7px;padding:4px;cursor:pointer;display4px;cursor:pointer;display:flex;alignpx;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all 0.2s;}
.theme-toggle:hover{backgroundpx;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all 0.2s;}
:flex;align-items:center;justify-content:center;transition:all 0.2s;}
:flex;align-items:center;justify-content:center;transition:all 0.2s;}
.theme-toggle:hover{background:var(--surface3);-items:center;justify-content:center;transition:all 0.2s;}
.theme-toggle:hover{background:var(--surface3);color:var(--primary);:var(--surface3);color:var(--primary.theme-toggle:hover{background:var(--surface3);color:var(--primary);border-color:var(--primary.theme-toggle:hover{background:var(--surface3);color:var(--primary);border-color:var(--primarycolor:var(--primary);border-color:var(--primary);}
.main{margin-left:var(--nav-w);border-color:var(--primary);}
.main{margin-left:var(--nav-w););border-color:var(--primary);}
.main{margin-left:var(--nav-w););}
.main{margin-left:var(--nav-w);flex:1;padding:24px 28px 48px;min-height:100vh;position:relative);}
.main{margin-left:var(--nav-w);flex:1;padding:24px 28px 48px;min-height:100vh;position:relativeflex:1;padding:24px 28px 48px;min-height:flex:1;padding:24px 28px 48px;min-height:100vh;position:relative;z-index:1}
.page{display:none;animation:flex:1;padding:24px 28px 48px;min-height:100vh;position:relative;z-index:1}
.page{display:none;;z-index:1}
.page{display:none;;z-index:1}
.page{display:none;100vh;position:relative;z-index:1}
.page{display:none;animation:pgIn .pgIn .35s ease}
.page.active{display:block}
@animation:pgIn .35s ease}
.page.active{display:block}
@keyframes pgIn{from{opacity:0;transform:translateYanimation:pgIn .35s ease}
.page.active{display:block}
@keyframes pgIn{fromanimation:pgIn .35s ease}
.page.active{display:block}
@keyframes pgIn{from{opacity:0;transform:translateY35s ease}
.page.active{display:block}
@keyframes pgIn{from{opacity:0;keyframes pgIn{from{opacity:0;transform:translateY(10px)}to{opacity(10px)}to{opacity{opacity:0;transform:translateY(10px)}to{opacity(10px)}to{opacity:1;transform:none}}
.page-header{margin-bottom:20px;display:flex;align-items:centertransform:translateY(10px)}to{opacity:1;transform:none}}
.page-header{margin-bottom:20px;display:flex;align-items:center:1;transform:none}}
.page-header{margin-bottom:20px;display:flex;align-items:center:1;transform:none}}
.page-header{margin-bottom:20px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px}
.page-title{font-family:':1;transform:none}}
.page-header{margin-bottom:20px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px}
.page-title{font-family:';justify-content:space-between;flex-wrap:wrap;gap:10px}
.page-title{font-family:';justify-content:space-between;flex-wrap:wrap;gap:10px}
.page-title{font-family:';justify-content:space-between;flex-wrap:wrap;gap:10px}
.page-title{font-family:'Orbitron',sans-serif;font-size:16px;font-weight:Orbitron',sans-serif;font-size:16px;font-weight:700;color:var(--Orbitron',sans-serif;font-size:16px;font-weight:700;color:var(--primary);letter-spacing:.04em}
.page-subOrbitron',sans-serif;font-size:16px;font-weight:700;color:var(--primary);letter-spacing:.Orbitron',sans-serif;font-size:16px;font-weight:700;color:var(--primary);letter-spacing:.700;color:var(--primary);letter-spacing:.primary);letter-spacing:.04em}
.page-sub{{font-size:11px;color:var(--text304em}
.page-sub{font-size:11px;04em}
.page-sub{font-size:11px;color:var(--text3);margin-top:304em}
.page-sub{font-size:11px;color:var(--text3);margin-top:3font-size:11px;color:var(--text3);margin-top:3px}
.stats-row{display:grid;grid-template-columns:repeat(4);margin-top:3px}
.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:color:var(--text3);margin-top:3px}
.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:px}
.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:px}
.stats-row{display:grid;grid-template-columns:repeat(4,1fr);,1fr);gap:10px;margin-bottom:14px}
.stat-card{10px;margin-bottom:14px}
.stat-card{10px;margin-bottom:14px}
.stat-card{background:var(--surface2);border:1px solidgap:10px;margin-bottom:14px}
.stat-card{background:var(--surface2);border:1px solid var(--border);border-radius10px;margin-bottom:14px}
.stat-card{background:var(--surface2);border:1px solid var(--border);border-radius:12px;padding:background:var(--surface2);border:1px solid var(--border);border-radius:12px;padding:16px;position:relative;overflow:hidden;transitionbackground:var(--surface2);border:1px solid var(--border);border-radius:12px;padding:16px;position:relative;overflow:hidden;transition var(--border);border-radius:12px;padding:16px;position:relative;overflow:hidden;transition:12px;padding:16px;position:relative16px;position:relative;overflow:hidden;:all .25s;animation:cIn .5:all .25s;animation:cIn .5:all .25s;animation:cIn .5s ease both}
.stat-card::before{content:'';position:absolute;top;overflow:hidden;transition:all .25s;animation:cIn .5s ease both}
.stat-card::before{content:'';position:absolute;toptransition:all .25s;animation:cIn .5s ease both}
.stat-card::before{content:'';position:absolute;tops ease both}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;heights ease both}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,:0;left:0;right:0;height:1px;background:linear-gradient(90deg,:0;left:0;right:0;height:1px;background:linear-gradient(90deg,:0;left:0;right:0;height:1px;background:linear-gradient(90deg,:1px;background:linear-gradient(90deg,transparent,var(--primary),transparent); opacity:0.3;}
.light-mode .stat-card::before{display:none;}
.stat-card:hover{border-colortransparent,var(--primary),transparent); opacity:0.3;}
.light-mode .stat-card::before{display:none;}
.stat-card:hover{border-colortransparent,var(--primary),transparent); opacity:0.3;}
.light-mode .stat-card::before{display:none;}
.stat-card:hover{border-colortransparent,var(--primary),transparent); opacity:0.3;}
.light-mode .stat-card::before{display:none;}
transparent,var(--primary),transparent); opacity:0.3;}
.light-mode .stat-card::before{display:none;}
:var(--border2);transform:translateY(-2:var(--border2);transform:translateY(-2:var(--border2);transform:translateY(-2px);box-shadow:0.stat-card:hover{border-color:var(--border2);transform:translateY(-2px);box-shadow:0 0 20px var(--primary-dim)}
@key.stat-card:hover{border-color:var(--border2);transform:translateY(-2px);box-shadow:0 0 20px var(--primary-dim)}
@keypx);box-shadow:0px);box-shadow:0 0 20px var(--primary-dim)}
@keyframes cIn{from{opacity:0;transformframes cIn{from{opacity:0;transformframes cIn{from{opacity:0;transform 0 20px var(--primary-dim)}
@keyframes cIn{from{opacity:0;transform 0 20px var(--primary-dim)}
@keyframes cIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
.stat-label{font-size::translateY(12px)}to{opacity:1;transform:none}}
.stat-label{font-size::translateY(12px)}to{opacity:1;transform:none}}
:translateY(12px)}to{opacity:1;transform:none}}
.stat-label{font-size::translateY(12px)}to{opacity:1;transform:none}}
.stat-label{font-size:9.5px;color:var(--text3);9.5px;color:var(--text3);.stat-label{font-size:9.5px;color:var(--text3);font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px9.5px;color:var(--text3);font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:9.5px;color:var(--text3);font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px}
.stat-val{font-size:20px;font}
.stat-val{font-size:20px;font-weight:700;color8px}
.stat-val{font-size:20px;fontpx}
.stat-val{font-size:20px;fontpx}
.stat-val{font-size:20px;font-weight:700;color:var(--text);letter-spacing:-.02em}
.stat-unit{font-size:-weight:700;color:var(--text);letter-sp:var(--text);letter-spacing:-.02em}
-weight:700;color:var(--text);letter-spacing:-.02em}
.stat-unit{font-size:11px;font-weight:400;color:var(---weight:700;color:var(--text);letter-spacing:-.02em}
.stat-unit{font-size:11px;font-weight:400;color:var(--11px;font-weight:400;color:var(--acing:-.02em}
.stat-unit{font-size:11px;font-weight:400;color:var(--text3)}
.card{background:var(--.stat-unit{font-size:11px;font-weight:400;color:var(--text3)}
.card{background:var(--surface2);border:1px solid vartext3)}
.card{background:var(--surface2);border:1px solid var(--border);border-radius:text3)}
.card{background:var(--surface2);border:1px solid var(--text3)}
.card{background:var(--surface2);border:1px solid var(--border);border-radius:surface2);border:1px solid var(--border);border-radius:12px;padding:16px;margin-bottom:10px;position:relative;(--border);border-radius:12px;padding:16px;margin-bottom:10px;position:relative;12px;padding:16px;margin-bottom:10px;position:relative;overflow:hidden;transition:all .25s;animation:cIn .5border);border-radius:12px;padding:16px;margin-bottom:10px;position:relative;overflow:hidden;transition:all .25s;animation:cIn .5s ease both}
.card::before{content:'';position:absolute;12px;padding:16px;margin-bottom:10px;position:relative;overflow:hidden;transition:all .25s;animation:cIn .5overflow:hidden;transition:all .25s;animation:cIn .5s ease both}
.card::before{content:'';position:absolute;top:overflow:hidden;transition:all .25s;animation:cIn .5s ease both}
.card::before{content:'';position:absolute;top:s ease both}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:lineartop:0;left:0;right:0;height:s ease both}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear0;left:0;right:0;height:0;left:0;right:0;height:-gradient(90deg,transparent,var1px;background:linear-gradient(90deg,transparent,var(--primary),transparent); opacity:0.2;}
.light-mode .card::before-gradient(90deg,transparent,var(--primary),transparent); opacity:0.2;}
.l1px;background:linear-gradient(90deg,transparent,var(--primary),transparent); opacity:0.2;}
.light-mode .1px;background:linear-gradient(90deg,transparent,var(--primary),transparent); opacity:0.2;}
.light-mode .card::before(--primary),transparent); opacity:0.2;}
.light-mode .card::before{display:none;}
.card-hd{display:flex;align-items{display:none;}
.card-hd{display:flexight-mode .card::before{display:none;}
.cardcard::before{display:none;}
.card-hd{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px{display:none;}
.card-hd{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}
.card-title{font-size:center;justify-content:space-between;margin-bottom:12px}
.card-title{font-size:12px;align-items:center;justify-content:space-between;margin-bottom:12px}
.card-title{font-size-hd{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}
.card-title{font-size:12px;font-weight}
.card-title{font-size:12px;font-weight:12px;font-weight:600;color:var(--text);display:flex;align-items:center;;font-weight:600;color:var(--text);display:flex;align-items:center;gap::12px;font-weight:600;color:var(--text);display:flex;align-items:center;:600;color:var(--text);display:flex;align-items:center;gap:6px}
.chart-container{height:600;color:var(--text);display:flex;align-items:center;gap:6px}
.chart-container{heightgap:6px}
.chart-container{height6px}
.chart-container{heightgap:6px}
.chart-container{height:170px;width:100%}
.btn{font-family:inherit;font-size:11.5px;:170px;width:100%}
.btn{font-family:inherit;font-size:11.5px;font-weight:700;border-radius:8px;padding:170px;width:100%}
.btn{font-family:inherit;font-size:11.5px;font-weight:700;border-radius:8px;padding:170px;width:100%}
.btn{font-family:inherit;font-size:11.5px;:170px;width:100%}
.btn{font-family:inherit;font-size:11.5px;font-weight:700;borderfont-weight:700;border-radius:8px;padding:7px 14px;cursor:pointer;display:7px 14px;cursor:pointer;display:inline-flex;align-items:center;gap:5:7px 14px;cursor:pointer;display:inline-flex;align-items:center;gap:5px;border:none;transition:all .font-weight:700;border-radius:8px;padding:7px 14px;cursor:pointer;display:inline-flex;align-items:center;gap:5px;border:none;transition:all .-radius:8px;padding:7px 14px;cursor:pointer;display:inline-flex;:inline-flex;align-items:center;gap:5px;border:none;transition:all .2s;letter-spacing:.03em}
.btn-gold{background:linear-gradient(135degpx;border:none;transition:all .2s;letter-spacing:.03em}
.btn-gold2s;letter-spacing:.03em}
.btn-gold{background:linear-gradient(135deg,#392s;letter-spacing:.03em}
.btn-gold{background:linear-gradient(align-items:center;gap:5px;border:none;transition:all .2s;letter-spacing:.03em}
.btn-gold{,#39ff14,#1a8c1a);color:#{background:linear-gradient(135deg,#39ff14,#1a8c1a);colorff14,#1a8c1a);color:#135deg,#39ff14,#1a8cbackground:linear-gradient(135deg,#39ff14,#1a8c1a);color:#000;box-shadow:0 0 16px rgba000;box-shadow:0 0 16px rgba(57,255,20:#000;box-shadow:0 0 16px rgba(57,255,20000;box-shadow:0 0 16px rgba(57,255,20,0.3)}
.btn-gold:hover{filter1a);color:#000;box-shadow:0 0 16px rgba(57,255,20,0.3)}
.btn-g(57,255,20,0.3)}
.btn,0.3)}
.btn-gold:hover{filter:brightness(1.2);transform:translateY,0.3)}
.btn-gold:hover{filter:brightness(1.2);transform:translateY:brightness(1.2);transform:translateYold:hover{filter:brightness(1.-gold:hover{filter:brightness(1.2);transform:translateY(-1px);box-shadow:0 0 24px rgba(57,255(-1px);box-shadow:0 0 24(-1px);box-shadow:0 0 24px rgba(57,255,20,0.5(-1px);box-shadow:0 0 24px rgba(57,255,20,0.5)}
.btn-ghost{background:var2);transform:translateY(-1px);box-shadow:0 0 24px rgba(57,255,20,0.5,20,0.5px rgba(57,255,20,0.5)}
.btn-ghost{background:var(--surface3);color:var(--text);border:)}
.btn-ghost{background:var(--surface3);color:var(--text);border:1px(--surface3);color:var(--text);border:1px solid var(--border)}
.btn-danger)}
.btn-ghost{background:var(--surface3);color:var(--text);border:1px solid var(--border)}
.btn-danger{background:var(--red)}
.btn-ghost{background:var(--surface3);color:var(--text);border:1px solid var(--border)}
.btn-danger{background:var(--1px solid var(--border)}
.btn-danger solid var(--border)}
.btn-danger{background:var(--red-dim);color:var(--red);border:1px solid rgba(248{background:var(--red-dim);color:var(--red);border:1px solid rgba(248-dim);color:var(--red);border:1px solid rgba(248,113,113red-dim);color:var(--red);border:1px solid rgba(248{background:var(--red-dim);color:var(--red);border:1px solid rgba(248,113,113,.15)}
.btn-sm{padding,113,113,.15)}
.btn-sm{padding,113,113,.15)}
.btn-sm{padding:4px 9px;font-size:10.5px}
.grid-2{display:grid;grid,.15)}
.btn-sm{padding:4px 9px,113,113,.15)}
.btn-sm{padding:4px 9px;font-size:10.5px}
.grid-2:4px 9px;font-size:10.5px}
.grid-2{display:grid;grid:4px 9px;font-size:10.5px}
.grid-2{display:grid;grid-template-columns:1fr;font-size:10.5px}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.tbl-wrap{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.tbl-wrap-template-columns:1fr 1fr;gap:10px}
.tbl-wrap-template-columns:1fr 1fr;gap:10px}
.tbl-wrap{overflow-x:auto}
 1fr;gap:10px}
.tbl-wrap{overflow-x:auto}
.tbl{width:100%;border-collapse:collapse}
.t{overflow-x:auto}
.tbl{width:100%;border-collapse:collapse}
.tbl th{text{overflow-x:auto}
.tbl{width:100%;border-collapse:collapse}
.tbl th{text.tbl{width:100%;border-collapse:collapse}
.tbl th{text-align:left;font-size{overflow-x:auto}
.tbl{width:100%;border-collapse:collapse}
.tbl th{text-align:left;font-size:9.5px;bl th{text-align:left;font-size-align:left;font-size:9.5px;-align:left;font-size:9.5px;:9.5px;font-weight:700;color:var(--text3);padding:9px 11font-weight:700;color:var(--text3);:9.5px;font-weight:700;color:var(--text3);padding:9px 11font-weight:700;color:var(--text3);padding:9px 11px;text-transform:uppercase;letter-spacing:.06em;border-bottomfont-weight:700;color:var(--text3);padding:9px 11px;text-transform:uppercase;letter-spacing:.px;text-transform:uppercase;letter-spacing:.padding:9px 11px;text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid var(--borderpx;text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid var(--border);background:var(--surface:1px solid var(--border);background:var(--surface06em;border-bottom:1px solid var(--border06em;border-bottom:1px solid var(--border);background:var(--surface3)}
.tbl td{padding:9px 11px;border);background:var(--surface3)}
.tbl td{padding:9px 11px;border-bottom:13)}
.tbl td{padding:9px 11px;border-bottom:1px solid var(--border);3)}
.tbl td{padding:9px 11px;border-bottom:1px solid var(--border););background:var(--surface3)}
.tbl td{padding:9px 11px;border-bottom:1px solid var(--border);-bottom:1px solid var(--border);font-size:12.5px;vertical-align:middlepx solid var(--border);font-size:12.5px;vertical-align:middle}
.tag{display:inlinefont-size:12.5px;vertical-align:middlefont-size:12.5px;vertical-align:middlefont-size:12.5px;vertical-align:middle}
.tag{display:inline-flex;align-items:center}
.tag{display:inline-flex;align-items:center;padding:2px 7px;border-radius:4px;font-size:9px;font-weight-flex;align-items:center;padding:2px 7px;border-radius:}
.tag{display:inline-flex;align-items:center;padding:2px 7px;border-radius:}
.tag{display:inline-flex;align-items:center;padding:2px 7px;border-radius:4px;font-size:9px;font-weight:;padding:2px 7px;border-radius:4px;font-size:9px;font-weight:800;letter-spacing:.05em;text-transform:uppercase}
.tag-vless{background:var(--primary:800;letter-spacing:.05em;text-transform:uppercase}
.tag-vless{background:var(--primary4px;font-size:9px;font-weight:800;letter-spacing:.05em;text-transform:uppercase}
.tag-vless{background:var(--primary-dim);color:var(--primary);border:4px;font-size:9px;font-weight:800;letter-spacing:.05em;text-transform:uppercase}
.tag-vless{background:var(--primary-dim);color:var(--primary);border:1px800;letter-spacing:.05em;text-transform:uppercase}
.tag-vless{background:var(--primary-dim);color:var(--primary);border:1px-dim);color:var(--primary);border:1px solid var(--border)}
.tag-on{background:var-dim);color:var(--primary);border:1px solid var(--border)}
.tag-on{background:var1px solid var(--border)}
.tag-on{background:var(--green-dim);color:var(--green solid var(--border)}
.tag-on{background:var(--green-dim);color:var(--green solid var(--border)}
.tag-on{background:var(--green-dim);color:var(--green-dim);color:var(--green);border(--green-dim);color:var(--green);border:1px solid rgba(74,222,128,.);border:1px solid rgba(74,222);border:1px solid rgba(74,222,128,.(--green);border:1px solid rgba(74:1px solid rgba(74,222,128,.2)}
.tag-off{background:var(--red-dim);,128,.2)}
.tag-off{background2)}
.tag-off{background:var(--red-dim,222,128,.2)}
.tag-off{background:var(--red-dim);color:var(--red);2)}
.tag-off{background:var(--red-dim);color:var(--red);border:1px solid rgbacolor:var(--red);border:1px solid rgba(248,113,113,.2)}
.pill{display:flex;align-items:center;:var(--red-dim);color:var(--red);border:1px solid rgba(248,113,113,.2)}
.pill{display:flex;align);color:var(--red);border:1px solid rgba(248,113,113,.2)}
.pill{display:flex;align-items:center;border:1px solid rgba(248,113,113,.2)}
.pill{display:flex;align-items:center;gap:7px;font-size:11(248,113,113,.2)}
.pill{display:flex;align-items:center;gap:7px;font-size:11px}
.pill-used{color:var(--textgap:7px;font-size:11px}
.pill-used{color:var(--text-items:center;gap:7px;font-size:11px}
.pill-used{color:var(--text);font-weight:600}
gap:7px;font-size:11px}
.pill-used{color:var(--text);font-weightpx}
.pill-used{color:var);font-weight:600}
.pill-bar{flex:1;height:4px;background:var(--border);font-weight:600}
.pill-bar{flex:1;height:4px;background:var(--border.pill-bar{flex:1;height:4px;background:var(--border);border-radius:2px:600}
.pill-bar{flex:1;height:4px;background:var(--border(--text);font-weight:600}
.pill-bar{flex:1;height:4px;background:var(--border);border-radius:2px;min-width:40px);border-radius:2px;min-width:40px);border-radius:2px;min-width:40px}
.pill-fill{height:100%;border-radius:2px;transition:width .4s}
.p;min-width:40px}
.pill-fill{height:100%;border-radius:2px;transition:width .4s}
.pill-lim{);border-radius:2px;min-width:40px}
.pill-fill{height:100%;border-radius:2px;transition:width .4s}
}
.pill-fill{height:100%;border-radius:2px;transition:width .4s}
.p}
.pill-fill{height:100%;border-radius:2px;transition:width .4s}
.pill-lim{color:var(--text3);font-size:10px}
.toggleill-lim{color:var(--text3);font-size:10px}
.toggle{width:32px;color:var(--text3);font-size:10px}
.toggle{width:32px;height:17px;border-radius:9px;background.pill-lim{color:var(--text3);font-size:10px}
.toggle{width:32ill-lim{color:var(--text3);font-size:10px}
.toggle{width:32{width:32px;height:17px;border-radius:9px;background:var(--surface3);position:relative;cursor:pointer;transition:all .height:17px;border-radius:9px;background:var(--surface3);position:relative;cursor:pointer;transition:all .28s;border:1:var(--surface3);position:relative;cursor:pointer;transition:all .28s;borderpx;height:17px;border-radius:9px;background:var(--surface3);position:relative;cursor:pointer;transition:all .28s;border:1px;height:17px;border-radius:9px;background:var(--surface3);position:relative;cursor:pointer;transition:all .28s;border:1px solid var(--border);flex-shrink:0}
.toggle::px solid var(--border);flex-shrink:0:1px solid var(--border);flex-shrink:0px solid var(--border);flex-shrink:0}
.toggle::after{content:'';position:absolute;width:1128s;border:1px solid var(--border);flex-shrink:0}
.toggle::after{after{content:'';position:absolute;width:11}
.toggle::after{content:'';position:absolute;width:11px;height}
.toggle::after{content:'';position:absolute;width:11px;height:11px;border-radius:50%;background:var(--text3);top:2px;content:'';position:absolute;width:11px;height:11px;px;height:11px;border-radius:50%;background:var(--text3);top:2px;:11px;border-radius:50%;background:var(--text3);top:2px;px;height:11px;border-radius:50%;background:var(--text3);top:2px;left:2px;transition:all .28s cubicborder-radius:50%;background:var(--text3);top:2px;left:2px;transitionleft:2px;transition:all .28s cubicleft:2px;transition:all .28s cubic-bezier(.4,left:2px;transition:all .28s cubic-bezier(.4,0,.2,1)}
.toggle.on{background:var(--green);-bezier(.4,0,.2,1)}
.toggle.on{background:var(--green);border-color:all .28s cubic-bezier(.4,0,.2,1)}
.toggle.on{background:var(--green);border-color:var(--green-bezier(.4,0,.2,1)}
.toggle.on{background:var(--green);0,.2,1)}
.toggle.on{background:var(--green);border-color:var(--green);box-shadow:0 0 10px rgba(border-color:var(--green);box-shadow:0 0 :var(--green);box-shadow:0 0 );box-shadow:0 0 10px rgba(74,222,128,.3)}
.toggle.on::border-color:var(--green);box-shadow:0 0 10px rgba(74,222,128,.3)}
.toggle.on::74,222,128,.3)}
.toggle.on::10px rgba(74,222,128,.3)}
.toggle.on::after{left:10px rgba(74,222,128,.3)}
.toggle.on::after{left:17px;background:#fff}
.sys-bar{height:6after{left:17px;background:#fff}
.safter{left:17px;background:#fff}
.sys-bar{height:6after{left:17px;background:#fff}
.s17px;background:#fff}
.sys-bar{height:6px;background:var(--border);border-radius:3px;overflow:hidden}
px;background:var(--border);border-radius:3px;overflow:hidden}
.sys-fill{heightys-bar{height:6px;background:var(--border);border-radius:3px;overflow:hidden}
.sys-fill{heightpx;background:var(--border);border-radius:3px;overflow:hidden}
.sys-fill{heightys-bar{height:6px;background:var(--border);border-radius:3px;overflow:hidden}
.sys-fill{height:100%;border-radius:3px;transition:width .4s}
.sl.sys-fill{height:100%;border-radius:3px;transition:width .4s}
.sl-item{display:flex;align-items:center:100%;border-radius:3px;transition:width .4s}
.sl-item{display:flex;align-items:center;justify-content:space-between;:100%;border-radius:3px;transition:width .4s}
.sl-item{display:flex;align-items:center;justify-content:space-between;:100%;border-radius:3px;transition:width .4s}
.sl-item{display:flex;align-items:center;justify-content:space-between;-item{display:flex;align-items:center;justify-content:space-between;padding:10px 0;justify-content:space-between;padding:10px 0padding:10px 0;border-bottom:1pxpadding:10px 0;border-bottom:1pxpadding:10px 0;border;border-bottom:1px solid var(--border)}
.sl-k{color:var(--text3);font-size:11.5px}
;border-bottom:1px solid var(--border)}
.sl-k{color:var(--text3);font-size solid var(--border)}
.sl-k{color:var(--text3);font-size:11. solid var(--border)}
.sl-k{color:var(--text3);font-size:11.5px}
.sl-v{color:-bottom:1px solid var(--border)}
.sl-k{color:var(--text3);font-size:11.5px}
.sl-v.sl-v{color:var(--text);font-weight:600;font-size:11.5px}
.f:11.5px}
5px}
.sl-v{color:var(--text);font-weight:600;font-size:var(--text);font-weight:600;font-size:11.5px}
.fg{display:flex;{color:var(--text);font-weight:600;font-size:11.5px}
.fg{display:flex;g{display:flex;flex-direction:column;gap:4px;margin-bottom:11px}
.fl.sl-v{color:var(--text);font-weight:600;font-size:11.5px}
.fg{display:flex;flex-direction:column;gap11.5px}
.fg{display:flex;flex-direction:column;gap:4px;margin-bottom:11px}
.fl{font-size:9flex-direction:column;gap:4px;margin-bottom:11px}
.fl{font-size:9flex-direction:column;gap:4px;margin-bottom:11px}
.fl{font-size:9{font-size:9.5px;font-weight:700;color:var:4px;margin-bottom:11px}
.fl{font-size:9.5px;font-weight:700;color:var.5px;font-weight:700;color:var.5px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:.08em}
.fi,.fs{p.5px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:.08em}
.fi,.(--text2);text-transform:uppercase;letter-spacing(--text2);text-transform:uppercase;letter-spacing:.08em}
.fi,.fs{padding:8px 12px;border-radius:8px;border(--text2);text-transform:uppercase;letter-spacing:.08em}
.fi,.fs{padding:8adding:8fs{padding:8px 12px;border-radius:8px;border:1px solid var(--:.08em}
.fi,.fs{padding:8px 12px;border-radius:8px;border:1px solid var(--border);font-family:inherit;font-size:12.5px;outline:n:1px solid var(--border);font-family:inherit;font-size:12.5px;outline:npx 12px;border-radius:8px;border:1px solid var(--border);font-family:inherit;font-size:12.5px;outline:npx 12px;border-radius:8px;border:1px solid var(--border);font-family:inherit;font-size:12.5px;outline:nborder);font-family:inherit;font-size:12.one;color:var(--text);background:var(--surface);transition:all .2s}
.fi:focusone;color:var(--text);background:var(--surface);transition:all .2s}
.fione;color:var(--text);background:var(--surface);transition:all .2s}
.fi:one;color:var(--text);background:var(--surface);transition:all .2s}
.fi:focus5px;outline:none;color:var(--text);background:var(--surface);transition:all .2s}
.fi:focus,.fs:focus{border-color:var(--primary);,.fs:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-dim)}
.fr{:focus,.fs:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-dim)}
.fr{focus,.fs:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-dim)}
.fr{,.fs:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-dim)}
.fr{box-shadow:0 0 0 3px var(--primary-dim)}
.fr{display:flex;gap:display:flex;gap:8px;flex-wrap:display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end}
.fr .fgdisplay:flex;gap:8px;flex-wrap:wrap;align-items:flex-end}
.fr .display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end}
.fr .fg8px;flex-wrap:wrap;align-items:flex-end}
.fr .fgwrap;align-items:flex-end}
.fr .fg{margin-bottom:0;flex:1;min-width{margin-bottom:0;flex:1;min-widthfg{margin-bottom:0;flex:1;min-width{margin-bottom:0;flex:1;min-width{margin-bottom:0;flex:1;min-width:90px}
.act-btn{font:90px}
.act-btn{font-family:inherit;font-size:90px}
.act-btn{font-family:inherit;font-size:90px}
.act-btn{font-family:inherit;font-size:90px}
.act-btn{font-family:inherit;font-size-family:inherit;font-size:9.5px;font-weight:700;border-radius:6px;padding:9.5px;font-weight:700;border:9.5px;font-weight:700;border:9.5px;font-weight:700;border-radius:6px;padding:4px 8px;cursor:pointer;display:inline-flex;align-items:9.5px;font-weight:700;border-radius:6px;padding:4px 8px;cursor:pointer;display:inline-flex;align-items:4px 8px;cursor:pointer;display:inline-flex;align-items:center;gap:3px;border:1px-radius:6px;padding:4px 8px;cursor:pointer;display:inline-flex;align-items:center;gap:3px;border:1px-radius:6px;padding:4px 8px;cursor:pointer;display:inline-flex;align-items:center;gap:3px;border:1px:center;gap:3px;border:1px:center;gap:3px;border:1px solid;transition:all .18s}
.act-c solid;transition:all .18s}
.act-c solid;transition:all .18s}
.act-copy{background:var(--primary-dim);color:var(--primary);border-color:var(--border)}
.act solid;transition:all .18s}
.act-copy{background:var(--primary-dim);color:var(--primary);border-color:var(--border)}
.act solid;transition:all .18s}
.act-copy{background:var(--primary-dim);color:var(--primary);border-color:var(--border)}
.actopy{background:var(--primary-dim);color:var(--primary);border-color:var(--border)}
.actopy{background:var(--primary-dim);color:var(--primary);border-color:var(--border)}
.act-sub{background:var(---sub{background:var(---sub{background:var(--green-dim);color:var(--green);border-color:-sub{background:var(--green-dim);color:var(--green);border-color:-sub{background:var(--green-dim);color:var(--green);border-color:green-dim);color:var(--green);border-color:rgba(74,222,128,.2)}
.act-qr{background:rgba(167,139,250,.1);color:#a78bfa;green-dim);color:var(--green);border-color:rgba(74,222,128,.2)}
.act-qr{background:rgba(167,139,250,.1);colorrgba(74,222,128,.2)}
.act-qr{background:rgba(167,139,250,.1);colorrgba(74,222,128,.2)}
.act-qr{background:rgba(167,139,250,.1);color:#argba(74,222,128,.2)}
.act-qr{background:rgba(167,139,250,.1);colorborder-color:rgba(167,139,250,.2)}
.act-edit{background:rgba(251,191,36,.08);color:var(--yellow);border-color:rgba(251,191,36,.2)}
.act-del{background:var(--red-dim);color:var(--red);border-color:rgba(248,113,113,.18)}
.toast{position::#a78bfa;border-color:rgba(167,139,250,.2)}
.act-edit{background:rgba(251,191,36,.08);color:var(--yellow);border-color:rgba(251,191,36,.2)}
.act-del{background:var(--red-dim);color:var(--red);border-color:rgba(248,113,113,.18)}
.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-:#a78bfa;border-color:rgba(167,139,250,.2)}
.act-edit{background:rgba(251,191,36,.08);color:var(--yellow);border-color:rgba(251,191,36,.2)}
.act-del{background:var(--red-dim);color:var(--red);border-color:rgba(248,113,113,.18)}
.toast{position:fixed;bottom:20px;left:50%;transform78bfa;border-color:rgba(167,139,250,.2)}
.act-edit{background:rgba(251,191,36,.08);color:var(--yellow);border-color:rgba(251,191,36,.2)}
.act-del{background:var(--red-dim);color:var(--red);border-color:rgba(248,113,113,.18)}
.toast{position:fixed;bottom:20px:#a78bfa;border-color:rgba(167,139,250,.2)}
.act-edit{background:rgba(251,191,36,.08);color:var(--yellow);border-color:rgba(251,191,36,.2)}
.act-del{background:var(--red-dim);color:var(--red);border-color:rgba(248,113,113,.18)}
.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-fixed;bottom:20px;left:50%;transform:translateX(-50%) translateY(16px);background:var(--surface);color:var(--text);border:1px solid var(--border2);border-radius:10px;padding:12px 20px;50%) translateY(16px);background:var(--surface);color:var(--text);border:1px solid var(--border2);border-radius:10px;padding:12px 20px:translateX(-50%) translateY(16px);background:var(--surface);color:var(--text);border:1px solid var(--border2);border-radius:10px;padding:;left:50%;transform:translateX(-50%) translateY(16px);background:var(--surface);color:var(--text);border:1px solid var(--border2);border-radius:10px;padding:12px 20px;font-size:13px;font-weight:600;opacity:0;transition:all .350%) translateY(16px);background:var(--surface);color:var(--text);border:1px solid var(--border2);border-radius:10px;padding:12px 20px;font-size:13px;font-weight:600;opacity:0;transition:all .3font-size:13px;font-weight:600;opacity:0;transition:all .3;font-size:13px;font-weight:600;opacity:0;transition:all .3s;z-index:999;backdrop-filter:blur(24px);box-shadow:0 0 20px var(--primary-dim)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.mo{position12px 20px;font-size:13px;font-weight:600;opacity:0;transition:all .3s;z-index:999;backdrop-filter:blur(24px);box-shadow:0 0 20px var(--primary-dim)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.mo{position:fixed;inset:s;z-index:999;backdrop-filter:blur(24px);box-shadow:0 0 20px var(--primary-dim)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.mo{position:fixed;inset:s;z-index:999;backdrop-filter:blur(24px);box-shadow:0 0 20px var(--primary-dim)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.mo{position:fixed;inset:0;background:rgbas;z-index:999;backdrop-filter:blur(24px);box-shadow:0 0 20px var(--primary-dim)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.mo{position:fixed;inset:0;background:rgba0;background:rgba(0,0,0(0,0,0,.7);z-index:200;display:none;0;background:rgba(0,0,0,.7);z-index:200;display:none;align-items:center;just:fixed;inset:0;background:rgba(0,0,0,.7);z-index:200;display:none;align-items:center;just(0,0,0,.7);z-index:200;display:none;,.7);z-index:200;display:none;align-items:center;justalign-items:center;justify-content:center;backify-content:center;backdrop-filter:blur(ify-content:center;backdrop-filter:blur(8px)}
.mo.show{displayalign-items:center;justify-content:center;backdrop-filter:blur(8px)}
.mo.showify-content:center;backdrop-filter:blur(8px)}
.mo.show{display:flex}
.mo-box{background:var(--surface2);border::flex}
.mo-box{background:var(--surface2);border:{display:flex}
.mo-box{background:var(--surface2);border:1px8px)}
.mo.show{display:flex}
.mo-box{background:var(--surface2);border:drop-filter:blur(8px)}
.mo.show{display:flex}
.mo-box{background:var(--surface2);border:1px solid var(--border2);border-radius:181px solid var(--border2);border-radius:18px;padding:24px;width:100%;max-width:460px;position:relative;box-shadow:1px solid var(--border2);border-radius:18px;padding:24px;width:100%;max-width:460px;position:relative;box solid var(--border2);border-radius:18px;padding:24px;width:100%;max-width:460px;position:relative;box-shadow:1px solid var(--border2);border-radius:18px;padding:24px;width:100%;max-width:460px;position:relative;box-shadow:px;padding:24px;width:100%;max-width:460px;position:relative;box-shadow0 0 30px var(--primary-dim);transform:scale(.92);-shadow:0 0 30px var(--primary-dim);transform:scale(.92);opacity:0;0 0 30px var(--primary-dim);transform:scale(.92);opacity:0;transition:all .38s0 0 30px var(--primary-dim);transform:scale(.92);opacity:0;:0 0 30px var(--primary-dim);transform:scale(.92);opacity:0;transition:all .38sopacity:0;transition:all .38s cubic-bezier(.34,1.56,.64,1)}
.mo.show .mo-box{transform:scale(1);opacity:1}
.mo-titletransition:all .38s cubic-bezier(.34,1.56,.64,1)}
.mo.show .mo-box{transform:scale(1);opacity:1}
.mo-title cubic-bezier(.34,1.56,.64,1)}
.mo.show .mo-box{transform:scale(1);opacity:1}
.mo-title{font-family:'Orbitron',sans-seriftransition:all .38s cubic-bezier(.34,1.56,.64,1)}
.mo.show .mo-box{transform:scale(1);opacity:1}
.mo-title cubic-bezier(.34,1.56,.64,1)}
.mo.show .mo-box{transform:scale(1);opacity:1}
.mo-title{font-family:'Orbitron',sans-serif;font-size:14px;font-weight:700;margin-bottom:16px;color:var(--primary{font-family:'Orbitron',sans-serif;font-size:14px;font-weight:700;margin-bottom:16px;color:var(--primary);letter-spacing:.06em}
.mo-close{position:absolute;top{font-family:'Orbitron',sans-serif;font-size:14px;font-weight:700;margin-bottom:16px;color:var(--primary);letter-spacing:.06em}
.mo-close{position:absolute;top;font-size:14px;font-weight:700;margin-bottom:16px;color:var(--primary);letter-spacing:.06em}
.mo-close{position:absolute;top{font-family:'Orbitron',sans-serif;font-size:14px;font-weight:700;margin-bottom:16px;color:var(--primary);letter-spacing:.06em}
.mo-close{position:absolute;top);letter-spacing:.06em}
.mo-close{position:absolute;top:14px;right:14px;background:var(--surface3);border:1px solid var(--border);color:var(--text3);width:30px;height:30px;:14px;right:14px;background:var(--surface3);border:1px solid var(--border);color:var(--text3);width:30px;height:30px;:14px;right:14px;background:var(--surface3);border:1px solid var(--border);color:var(--text3);width:30px;height:30px;:14px;right:14px;background:var(--surface3);border:1px solid var(--border);color:var(--text3);width:30px;height:30px;:14px;right:14px;background:var(--surface3);border:1px solid var(--border);color:var(--text3);width:30px;height:30px;border-radius:7px;cursor:pointer;display:flex;align-items:center;justify-content:centerborder-radius:7px;cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:14px;}
.qr-box{text-align:center;padding:20px;background:varborder-radius:7px;cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:14px;}
.qr-box{text-align:center;padding:20px;background:varborder-radius:7px;cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:14px;}
.qr-box{text-align:center;padding:20px;background:varborder-radius:7px;cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:14px;}
.qr-box{text-align:center;padding:20px;background;font-size:14px;}
.qr-box{text-align:center;padding:20px;background:var(--surface3);border-radius:12px;border:1px solid var(--border);margin-top:12px(--surface3);border-radius:12px;border:1px solid var(--border);margin-top:12px}
.qr-box img{max-width:200px;border-radius:8px;border:3px(--surface3);border-radius:12px;border:1px solid var(--border);margin-top:12px}
.qr-box img{max-width:200px;border-radius:8px;border:3px solid var(--surface3);border-radius:12px;border:1px solid var(--border);margin-top:12px}
.qr-box img{max-width:200px;border-radius:8px;border:3px:var(--surface3);border-radius:12px;border:1px solid var(--border);margin-top:12px}
.qr-box img{max-width:200px;border-radius:8}
.qr-box img{max-width:200px;border-radius:8px;border:3px solid var(--border);box-shadow:0 0 15px solid var(--border);box-shadow:0 0 15px var(--primary-dim)}
.tb{display:flex;align-items:center;gap:7px;margin-bottom:14px;flex-wrap:wrap}
.search-wrap{flex:1;min-width:160px;position:relative}
.search-wrap svg{position:absolute;(--border);box-shadow:0 0 15px var(--primary-dim)}
.tb{display:flex;align-items:center;gap:7px;margin-bottom:14px;flex-wrap:wrap}
.search-wrap{flex:1;min-width:160px;position:relative}
.search-wrap sv solid var(--border);box-shadow:0 0 15px var(--primary-dim)}
.tb{display:flex;align-items:center;gap:7px;margin-bottom:14px;flex-wrap:wrap}
.search-wrap{flex:1;min-width:160px;position:relative}
.search-wrap svpx;border:3px solid var(--border);box-shadow:0 0 15px var(--primary-dim)}
.tb{display:flex;align-items:center;gap:7px;margin-bottom:14px;flex-wrap:wrap}
.search-wrap{flex:1;min-width:160px;position:relative}
.search-wrap sv var(--primary-dim)}
.tb{display:flex;align-items:center;gap:7px;margin-bottom:14px;flex-wrap:wrap}
.search-wrap{flex:1;min-width:160px;position:relative}
.search-wrap svleft:12px;top:50%;transform:translateg{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:g{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:g{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--text3)}
.search-wrap input{width:100%;padding:9px 12px 9g{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--text3)}
.search-wrap input{width:100%;padding:9px 12px 9pxY(-50%);color:var(--text3)}
.search-wrap input{width:100%;padding:9px var(--text3)}
.search-wrap input{width:100%;padding:9px 12px 9pxvar(--text3)}
.search-wrap input{width:100%;padding:9px 12px 9px 34px;background:var(--surface2);border: 34px;background:var(--surface2);border:12px 9px 34px;background:var(--surface2);border:1px solid var(--border);border-radius:8px 34px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;color:var(--textpx 34px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;color:var(--text1px solid var(--border);border-radius:8px;color:var(--text);font-size:131px solid var(--border);border-radius:8px;color:var(--text;color:var(--text);font-size:13px;font-family:inherit;outline:none;}
.filter-chips{display:flex;gap:3px;padding:3px;background:var(--surface2););font-size:13px;font-family:inherit;outline:none;}
.filter-chips{display:flex;gap:3px;padding:3px;background);font-size:13px;font-family:inherit;outline:none;}
.filter-chips{display:flex;gap:3px;padding:3px;background:var(--surface2);px;font-family:inherit;outline:none;}
.filter-chips{display:flex;gap:3px;padding:3px;background:var(--surface2););font-size:13px;font-family:inherit;outline:none;}
.filter-chips{display:flex;gap:3px;padding:3px;background:var(--surface2);border:1px solid var(--border);border-radius:8px}
.chip{padding:7px 12px;border-radius:6:var(--surface2);border:1px solid var(--border);border-radius:8px}
.chip{padding:7px 12px;border-radius:6border:1px solid var(--border);border-radius:8px}
.chip{padding:7px 12px;border-radius:6px;fontborder:1px solid var(--border);border-radius:8px}
.chip{padding:7px 12px;border-radius:6border:1px solid var(--border);border-radius:8px}
.chip{padding:7px 12px;border-radius:6px;px;font-size:11.5px;font-weight:700;color:var(--text3);cursor:pointer;border:none;background:none;transition:all .18s;font-family:inherit}
.chpx;font-size:11.5px;font-weight:700;color:var(--text3);cursor:pointer;border:none;background:none;transition:all .18s;font-family:inherit}
.chip.active{background:var(---size:11.5px;font-weight:700;color:var(--text3);cursor:pointer;border:none;background:none;transition:all .18s;font-family:inherit}
.chippx;font-size:11.5px;font-weight:700;color:var(--text3);cursor:pointer;border:none;background:none;transition:all .18s;font-family:inherit}
.chip.active{font-size:11.5px;font-weight:700;color:var(--text3);cursor:pointer;border:none;background:none;transition:all .18s;font-family:inherit}
.chipip.active{background:var(--primary);color:#primary);color:#000}
.m-cards{display:none;flex-direction:column;gap:12px}
.active{background:var(--primary);color:#000}
.m-cards{display:none;flex-direction:column;gap:12px}
background:var(--primary);color:#000}
.m-cards{display:none;flex-direction:column.active{background:var(--primary);color:#000}
.m-cards{display:none;flex-direction:column;gap:12px}
000}
.m-cards{display:none;flex-direction:column;gap:12px}
.m-card{border:1px solid var(--border);border-radius:12px;padding:16px;background:var(--surface2)}
.m-card{border:1px solid var(--border);border-radius:12px;padding:16px;background:var(--surface2)}
.m-card-hd{display:flex;align-items:.m-card{border:1px solid var(--border);border-radius:12px;padding:16px;background:var(--surface2)}
.m-card-hd{display:flex;align-items:center;justify-content:;gap:12px}
.m-card{border:1px solid var(--border);border-radius:12px;padding:16px;background:var(--surface2)}
.m-card-hd{display:flex;align-items:.m-card{border:1px solid var(--border);border-radius:12px;padding:16px;background:var(--surface2)}
.m-card-hd{display:flex;align-items:center;justify-content:.m-card-hd{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}
.m-card-acts{display:flex;gap:6px;flex-wrap:wrap;margin-top:12px}
.empty{text-align:center;padding:36px;color:space-between;margin-bottom:12px}
.m-card-acts{display:flex;gap:6px;flex-wrap:wrap;margin-top:12px}
.empty{text-align:center;padding:36px;center;justify-content:space-between;margin-bottom:12px}
.m-card-acts{display:flex;gap:6px;flex-wrap:wrap;margin-top:12px}
.empty{space-between;margin-bottom:12px}
.m-card-acts{display:flex;gap:6px;flex-wrap:wrap;margin-top:12px}
.empty{text-align:center;padding:36px;colorcenter;justify-content:space-between;margin-bottom:12px}
.m-card-acts{display:flex;gap:6px;flex-wrap:wrap;margin-top:12px}
.empty{text-align:center;paddingvar(--text3)}
.mob-hd{display:none;position:fixed;top:0;left:0;right:0;color:var(--text3)}
.mob-hd{display:ntext-align:center;padding:36px;color:var(--text3)}
.mob-hd{display:none;position:fixed;top:0;left:0;right:0;background:var(--surface);border-bottom:1px solid var(--border);:var(--text3)}
.mob-hd{display:none;position:fixed;top:0;left:0;right:0;background:var(--surface);border-bottom:1px solid var(--border);:36px;color:var(--text3)}
.mob-hd{display:none;position:fixed;top:0;left:0;right:0;background:var(--surface);border-bottom:1px solidbackground:var(--surface);border-bottom:1px solid var(--border);z-index:90;align-items:center;justify-content:space-between;backone;position:fixed;top:0;left:0;right:0;background:var(--surface);border-bottom:1px solid var(--border);z-index:90;align-items:center;justify-content:space-between;backdrop-filter:blur(20pxz-index:90;align-items:center;justify-content:space-between;backdrop-filter:blur(20px);}
.mob-tl-group{display:flex;gap:10px;align-items:center;flex-direction:row;}
.logoutz-index:90;align-items:center;justify-content:space-between;backdrop-filter:blur(20px);}
.mob-tl-group{display:flex;gap:10px;align-items:center;flex-direction:row;}
.logout-mob{display:none var(--border);z-index:90;align-items:center;justify-content:space-between;backdrop-filter:blur(20px);}
.mob-tl-group{display:flex;gap:10px;align-items:center;flex-direction:row;}
.logoutdrop-filter:blur(20px);}
.mob-tl-group{display:flex;gap:10px;align-items:center;flex-direction:row;}
.logout-mob{display:none);}
.mob-tl-group{display:flex;gap:10px;align-items:center;flex-direction:row;}
.logout-mob{display:none;color:var(--red) !important;}
.logout-mob{display:none;color:var(--red) !important;}
.logout-mob:hover{background:;color:var(--red) !important;}
.logout-mob:hover{background:var(--red-dim) !important;border-color:rgba(248,-mob{display:none;color:var(--red) !important;}
.logout-mob:hover{background:var(--red-dim) !important;border-color:rg;color:var(--red) !important;}
.logout-mob:hover{background:var(--red-dim) !important;border-color:rgba(248-mob:hover{background:var(--red-dim) !var(--red-dim) !important;border-color:rgba(248,113,113,.3) !important;}
/* Login page */
.login-wrap{display:flex;align-items:center;just113,113,.3) !important;}
/* Login page */
.login-wrap{display:flex;align-items:center;justify-content:centerba(248,113,113,.3) !important;}
/* Login page */
.login-wrap{display:flex;align-items:center;justify-content:center;min-height:100vh;width:100%}
.login-box{background:var,113,113,.3) !important;}
/* Login page */
.login-wrap{display:flex;align-items:center;justify-content:center;min-height:100vh;width:100%}
.login-box{background:varimportant;border-color:rgba(248,113,113,.3) !important;}
/* Login page */
.login-wrap{display:flex;align-items:center;justify-content:center;min-height:100vh;width:100%}
.login-box{background:var(--surface2);border:ify-content:center;min-height:100vh;width:100%}
.login-box{background:var(--surface2);border:1px solid var(--border2);border-radius:20px;padding:36px 32px;width:100%;;min-height:100vh;width:100%}
.login-box{background:var(--surface2);border:1px solid var(--border2);border-radius:20px;padding:36px 32px;width(--surface2);border:1px solid var(--border2);border-radius:20px;padding:36px 32px;width:100%;(--surface2);border:1px solid var(--border2);border-radius:20px;padding:36px 32px;width:100%;max-width:360px;box-shadow:1px solid var(--border2);border-radius:20px;padding:36px 32px;width:100%;max-width:360px;box-shadow:max-width:360px;box-shadow:0 0 25px var(--:100%;max-width:360px;box-shadow:max-width:360px;box-shadow:0 0 25px var(--primary-dim)}
.login-logo{text-align:center;margin-bottom:28px}
.login-title{font-family:'Orbitron',sans-serif;font-size:22px;font-weight:900;color:var(--primary);letter-spacing:.1em}
.login-sub{font-size:11px;color:var(--0 0 25px var(--primary-dim)}
.login-logo{text-align:center;margin-bottom:28px}
.login-title{font-family:'Orbitron',sans-serif;font-size:22px;font-weight:900;color:var(--primary);letter-spacing:.1em}
.login-sub{font-size:11px;color:var(--0 0 25px var(--primary-dim)}
.login-logo{text-align:center;margin-bottom:28px}
.login-title{font-family:'Orbitron',sans-serif;font-size:22px;font-weight:900;color:varprimary-dim)}
.login-logo{text-align:center;margin-bottom:28px}
.login-title{font-family:'Orbitron',sans-serif;font-size:22px;font-weight:900;color:var(--primary);letter-spacing:.1em}
.login-sub{font-size:11px;color:var(--0 0 25px var(--primary-dim)}
.login-logo{text-align:center;margin-bottom:28px}
.login-title{font-family:'Orbitron',sans-serif;font-size:22px;font-weight:900;color:var(--primary);letter-spacing:.1em}
.login-sub{font-size:11text3);margin-top:6px}
@media(max-width:768px){
  .mob-hd{displaytext3);margin-top:6px}
@media(max-width:768px){
  .mob-hd{display(--primary);letter-spacing:.1em}
.login-sub{font-size:11px;color:var(--text3);margin-top:6px}
@media(max-width:768px){
  .mob-hd{display:flex;height:65text3);margin-top:6px}
@media(max-width:768px){
  .mob-hd{displaypx;color:var(--text3);margin-top:6px}
@media(max-width:768px){
  .mob-hd{display:flex;height:65:flex;height:65px;padding:0 20px;}
  .sidebar{transform:none !important;width::flex;height:65px;padding:0 20px;}
  .sidebar{transform:none !important;width:px;padding:0 20px;}
  .sidebar{transform:none !important;width::flex;height:65px;padding:0 20px;}
  .sidebar{transform:none !important;width:100% !important;height:78px;top:auto;bottom:0;border-right:none;borderpx;padding:0 20px;}
  .sidebar{transform:none !important;width:100% !important;height:78px;top:auto;bottom:0;border-right:none;border-top:1px solid var100% !important;height:78px;top:auto;bottom:0;border-right:none;border-top:1px solid var(--border);flex-direction:row;padding:0;background:var(--surface);}
  .sb100% !important;height:78px;top:auto;bottom:0;border-right:none;border-top:1px solid var(--border);flex-direction:row;padding:0;background:var(--surface);}
  .sb100% !important;height:78px;top:auto;bottom:0;border-right:none;border-top:1px solid var(--border);flex-direction:row;padding:0;background:var(--surface);}
  .sb-top:1px solid var(--border);flex-direction:row;padding:0;background:var(--surface);}
  .sb-brand,.sb-bottom{display:none !important;}
  .sb-nav{flex-direction:row;width:100%;padding:0;align(--border);flex-direction:row;padding:0;background:var(--surface);}
  .sb-brand,.sb-bottom{display:none !important;}
  .sb-nav{flex-direction:row;width:100%;padding:0;align-items:-brand,.sb-bottom{display:none !important;}
  .sb-nav{flex-direction:row;width:100%;padding:0;align-items:-brand,.sb-bottom{display:none !important;}
  .sb-nav{flex-direction:row;width:100%;padding:0;align-items:-items:center;justify-content:space-between;gap:0;}
  .nav-item{flex:1;padding:12px 0;border-radius:0;}
  .nav-icon{width:24px;height:24px;margin-bottom:5px;}
  .nav-label{font-size:10px-brand,.sb-bottom{display:none !important;}
  .sb-nav{flex-direction:row;width:100%;padding:0;align-items:center;justify-content:space-between;gap:0;}
  .nav-item{flex:1;padding:12px 0;border-radius:0;}
  .nav-icon{width:24px;height:24px;margin-bottom:5px;}
  .nav-label{font-size:10pxcenter;justify-content:space-between;gap:0;}
  .nav-item{flex:1;padding:12px 0;border-radius:0;}
  .nav-icon{width:24px;height:24px;margin-bottom:5px;}
  .nav-labelcenter;justify-content:space-between;gap:0;}
  .nav-item{flex:1;padding:12px 0;border-radius:0;}
  .nav-icon{width:24px;height:24px;margin-bottom:5px;}
  .nav-label{font-size:10pxcenter;justify-content:space-between;gap:0;}
  .nav-item{flex:1;padding:12px 0;border-radius:0;}
  .nav-icon{width:24px;height:24px;margin-bottom:5px;}
  .nav-label{font-size:10px;letter-spacing:0;}
  .logout-mob{display:flex;}
  .main{margin-left:;letter-spacing:0;}
  .logout-mob{display:flex;}
  .main{margin-left:{font-size:10px;letter-spacing:0;}
  .logout-mob{display:flex;}
 ;letter-spacing:0;}
  .logout-mob{display:flex;}
 ;letter-spacing:0;}
  .logout-mob{display:flex;}
  .main{margin-left:0;padding-top:85px;padding-left:18px;padding-right:18px;padding-bottom:100px;}
}
@media(max-width0;padding-top:85px;padding-left:18px;padding-right:18px;padding-bottom:100px;}
}
@media(max-width .main{margin-left:0;padding-top:85px;padding-left:18px;padding-right:18px;padding-bottom:100px;}
}
@media(max-width .main{margin-left:0;padding-top:85px;padding-left:18px;padding-right:18px;padding-bottom:100px;}
}
@media(max-width0;padding-top:85px;padding-left:18px;padding-right:18px;padding-bottom:100px;}
}
@media(max-width:460px){.stats-row{grid-template-columns::460px){.stats-row{grid-template-columns:1fr;gap:14:460px){.:460px){.:460px){.stats-row{grid-template-columns:1fr;gap:141fr;gap:14px;}}
</style>
</head>
<body>
<div class="bg-fixed"></div>
<div class="grid-fixed"></div>
<divpx;}}
</style>
</stats-row{grid-template-columns:1fr;gap:14px;}}
</style>
</head>
<body>
<div class="bg-fixed"></div>
<div class="grid-fixed"></div>
<div classstats-row{grid-template-columns:1fr;gap:14px;}}
</style>
</head>
<body>
<div class="bg-fixed"></div>
<div class="px;}}
</style>
</ class="toast" id="toast"></div>

<div id="login-page" style="display:nonehead>
<body>
<div class="bg-fixed"></div>
<div class="grid-fixed"></div>
<div class="toast" id="toast"></div>

<div id="login-page" style="display:none="toast" idgrid-fixed"></div>
<div class="toast" id="toast"></div>

<div id="login-page" style="display:none;width:100%">
head>
<body>
<div class="bg-fixed"></div>
<div class="grid-fixed"></div>
<div class="toast" id="toast"></div>

<div id="login-page" style="display:none;width:100%">
  <div class="login-wrap">
    <div class="login-box">
      <div class="login-logo">
        <svg width=";width:100%">
  <div class="login-wrap">
    <div class="login-box">
      <div class="login-logo">
        <svg width="="toast"></div>

<div id="login-page" style="display:none;width:100%">
  <div class="login-wrap">
    <div class="login-box">
      <div class="login-logo">
        <svg  <div class="login-wrap">
    <div class="login-box">
      <div class="login-logo">
        <svg width=";width:100%">
  <div class="login-wrap">
    <div class="login-box">
      <div class="login-logo">
        <svg width="80" height="80" viewBox="0 0 80 80" fill="none">
          <rect width="80" height="80" height="80" viewBox="0 0 80 80" fill="none">
          <rect width="80" height="80" rx width="80" height="80" viewBox="0 0 80 80" fill="none">
          <rect width="80" height="80" rx="12" fill="var(--primary)" fill-opacity="0.80" height="80" viewBox="0 0 80 80" fill="none">
          <rect width="80" height="80" rx="80" height="80" viewBox="0 0 80 80" fill="none">
          <rect width="80" height="80" rx="12" fill="var(--primary)" fill-opacity="0.1"/>
          <text x="40" y="58" font-family="'Orbitron', sans-serif" font-size="40" font="12" fill="var(--primary)" fill-opacity="0.1"/>
          <text x="40" y="58" font-family="'Orbitron', sans-serif"1"/>
          <text x="40" y="58" font-family="'Orbitron', sans-serif"12" fill="var(--primary)" fill-opacity="0.1"/>
          <text x="40" y="58" font-family="'Orbitron', sans-serif"80" rx="12" fill="var(--primary)" fill-opacity="0.1"/>
          <text x="40" y="58" font-family="'Orbitron', sans-serif" font-size="40"-weight="900" fill="var(--primary)" text-an font-size="40" font-weight="900" fill="var(--primary)" text-an font-size="40" font-weight="900" fill="var(--primary)" text-anchor="middle">V2 font-size="40" font-weight="900" fill="var(--primary)" text-anchor="middle">V2 font-weight="900" fill="var(--primary)" text-anchor="middle">V2R</text>
        </svg>
        <div class="login-title">V2Render Panel</div>
       chor="middle">V2R</text>
        </svg>
        <div class="login-title">V2Render Panel</div>
       chor="middle">V2R</text>
        </svg>
        <div class="login-title">V2Render Panel</div>
        <div class="login-subR</text>
        </svg>
        <div class="login-title">V2Render Panel</div>
       R</text>
        </svg>
        <div class="login-title">V2Render Panel</div>
        <div class="login-sub">Enter your password to continue</div>
      </div>
      <div class <div class="login-sub">Enter your password to continue</div>
      </div>
      <div class <div class="login-sub">Enter your password to continue</div>
      </div>
      <div class">Enter your password to continue</div>
      </ <div class="login-sub">Enter your password to continue</div>
      </div>
     ="fg">
        <label class="fl">PASSWORD</label>
        <input class="fi" type="password" id="login-p="fg">
        <label class="fl">PASSWORD</label>
        <input class="fi" type="password" id="login="fg">
        <label class="fl">PASSWORD</label>
        <input class="fi" type="password" id="login-pw" placeholder="••••••••" onkeydown="ifdiv>
      <div class="fg">
        <label class="fl">PASSWORD</label>
        <input class="fi" type="password" id="login-pw" placeholder="••••••••" onkeydown="if(event.key== <div class="fg">
        <label class="fl">PASSWORD</label>
        <input class="fi" type="password" id="login-pw" placeholder="••••••••" onkeyw" placeholder="••••••••" onkeydown="if(event.key==-pw" placeholder="••••••••" onkeydown="if(event.key==='Enter')doLogin()">
      </div>
      <button class="btn btn-gold" onclick="doLogin()" style="width(event.key==='Enter')doLogin()">
      </div>
      <button class="btn btn-gold" onclick='Enter')doLogin()">
      </div>
      <button class="btn btn-gold" onclick="doLogin()" style="width:100%;justify-content:center;padding:12px;margin-top:6px;">LOGIN</button>
      <div id="login-err" style="down="if(event.key==='Enter')doLogin()">
      </div>
      <button class="btn btn-gold" onclick="doLogin()" style="width='Enter')doLogin()">
      </div>
      <button class="btn btn-gold" onclick="doLogin()" style="width:100%;justify-content:center;padding:12px;margin-top:6px;">LOGIN</button>
      <div id="login-err" style=":100%;justify-content:center;padding:12px;margin-top:6px;">LOGIN</button>
      <div id="login-err" style="color:var(--red);font-size:12px;margin-top:10px;text-align:center;display:none">Invalid password="doLogin()" style="width:100%;justify-content:center;padding:12px;margin-top:6px;">LOGIN</button>
      <div id="login-err" style="color:var(--red);font-size:12px;margin-top:10px;text-align:center;display:none">Invalid passwordcolor:var(--red);font-size:12px;margin-top:10px;text-align:center;display:100%;justify-content:center;padding:12px;margin-top:6px;">LOGIN</button>
      <div id="login-err" style="color:var(--red);font-size:12px;margin-top:10px;text-align:center;display:none">Invalid password</div>
    </div>
  </div>
</div>

<div idcolor:var(--red);font-size:12px;margin-top:10px;text-align:center;display</div>
    </div>
  </div>
</div>

<div id="dashboard-page" style="display:none;width:100%</div>
    </div>
  </div>
</div>

<div id="dashboard-page" style="display:n:none">Invalid password</div>
    </div>
  </div>
</div>

<div id="dashboard-page" style="display:none;width:100%="dashboard-page" style="display:none;width:100%:none">Invalid password</div>
    </div>
  </div>
</div>

<div id="dashboard-page" style="display:none;width:100%">
  <div class="mob-hd">
    <div class="mob-tl-group">
     ">
  <div class="mob-hd">
    <div class="mob-tl-group">
one;width:100%">
  <div class="mob-hd">
    <div class="mob-tl-group">
      <button class="theme-toggle"">
  <div class="mob-hd">
    <div class="mob-tl-group">
     ">
  <div class="mob-hd">
    <div class="mob-tl-group">
      <button class="theme-toggle" onclick="toggleTheme()" id="theme-btn-mob">🌙</button>
      <div class="lang      <button class="theme-toggle" onclick="toggleTheme()" id="theme-btn-mob">🌙</button>
      <div class="lang onclick="toggleTheme()" id="theme-btn-mob">🌙</button>
      <div class="lang-row">
        <button class="lang-btn lang-en active" onclick="setLang('en')">EN</ <button class="theme-toggle" onclick="toggleTheme()" id="theme-btn-mob">🌙</button>
      <div class="lang-row">
        <button class="lang-btn lang-en active" onclick="setLang('en')">EN</ <button class="theme-toggle" onclick="toggleTheme()" id="theme-btn-mob">🌙</button>
      <div class="lang-row">
        <button class="lang-btn lang-en active" onclick="setLang('en')">EN</-row">
        <button class="lang-btn lang-en active" onclick="setLang('en')">EN</button>
        <button class="lang-btn lang-fa" onclick="setLang('fa')">FA</button-row">
        <button class="lang-btn lang-en active" onclick="setLang('en')">EN</button>
        <button class="lang-btn lang-fa" onclick="setLang('fa')">FA</buttonbutton>
        <button class="lang-btn lang-fa" onclick="setLang('fa')">FA</button>
      </div>
    </div>
    <span style="font-family:'Orbitron',sans-serif;font-size:16px;font-weight:button>
        <button class="lang-btn lang-fa" onclick="setLang('fa')">FA</button>
        <button class="lang-btn lang-fa" onclick="setLang('fa')">FA</button>
      </div>
    </div>
    <span style="font-family:'Orbitron',sans-serif;font-size:16px;font-weight:700;color:var(--primary);letter-spacing:1px;">V2Render>
      </div>
    </div>
    <span style="font-family:'Orbitron',sans-serif;font-size:16px;font-weight:700;color:var(--primary);letter-spacing:1px;">V2Render700;color:var(--primary);letter-spacing:1px;">V2Renderbutton>
      </div>
    </div>
    <span style="font-family:'Orbitron',sans-serif;font-size:16px;font-weight:700;color:var(--primary);letter-spacing:1px;">V2Render>
      </div>
    </div>
    <span style="font-family:'Orbitron',sans-serif;font-size:16px;font-weight:700;color:var(--primary);letter-spacing:1px;">V2Render</span>
  </div>

  <aside class="</span>
  </div>

  <aside class="</span>
  </div>

  <aside class="</span>
  </div>

  <aside class="sidebar" id="sb">
    <div class="sb-brand">
      <svg class="sb-logo</span>
  </div>

  <aside class="sidebar" id="sb">
    <div class="sb-brand">
      <svg class="sb-logo" viewsidebar" id="sb">
    <div class="sb-brand">
      <svg class="sb-logo" viewsidebar" id="sb">
    <div class="sb-brand">
      <svg classsidebar" id="sb">
    <div class="sb-brand">
      <svg class="sb-logo" viewBox="0 0 36 36">
        <rect width="36" height="36" rx="6Box="0 0 36 36">
        <rect width="36" height="36" rx="6Box="0 0 36 36">
        <rect width="36" height="36" rx="6="sb-logo" viewBox="0 0 36 36">
        <rect width="36" height="36" rx="6" fill="var(--primary)" fill-opacity="0.15"/>
        <text" viewBox="0 0 36 36">
        <rect width="36" height="36" rx="6" fill="var(--primary)" fill-opacity="0.15"/>
        <text" fill="var(--primary)" fill" fill="var(--primary)" fill" fill="var(--primary)" fill x="18" y="26" font-family="'Orbitron', sans-serif" font-size="18" font-weight="900" fill="var x="18" y="26" font-family="'Orbitron', sans-serif" font-size="18" font-weight="900" fill="var-opacity="0.15"/>
        <text x="18" y="26" font-family="'Orbitron', sans-serif" font-size="18" font-weight="900" fill="var-opacity="0.15"/>
        <text x="18" y="26" font-family="'Orbitron', sans-serif" font-size="18" font-weight="900" fill="var(---opacity="0.15"/>
        <text x="18" y="26" font-family="'Orbitron', sans-serif" font-size="18" font-weight="900" fill="var(--(--primary)" text-anchor="middle">V2R</text>
      </svg>
      <div class="sb-title">V2Render</div>
(--primary)" text-anchor="middle">V2R</text>
      </svg>
      <div class="sb-title">(--primary)" text-anchor="middle">V2R</text>
      </svg>
      <div class="sb-title">V2Render</div>
    </div>
   primary)" text-anchor="middle">V2R</text>
      </svg>
      <div class="sb-title">V2Render</div>
    </div>
   primary)" text-anchor="middle">V2R</text>
      </svg>
      <div class="sb-title">V2Render</div>
    </div>
       </div>
    <nav class="sb-nav">
      <button class="nav-item active" data-page="dashboard">
        <svg classV2Render</div>
    </div>
    <nav class="sb-nav">
      <button class="nav-item active" data-page="dashboard">
        <svg class="nav-icon" viewBox <nav class="sb-nav">
      <button class="nav-item active" data-page="dashboard">
        <svg class="nav-icon" viewBox <nav class="sb-nav">
      <button class="nav-item active" data-page="dashboard">
        <svg class="nav-icon" viewBox <nav class="sb-nav">
      <button class="nav-item active" data-page="dashboard">
        <svg class="nav-icon" viewBox="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width=" x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7"1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7"14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7"7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
        <span class="nav-label" data-en="Dashboard" data-fa="داشبورد">Dashboard</span7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
        <span class="nav-label" data-en="Dashboard" data-fa="داشبورد">Dashboard</span height="7" rx="1"/></svg>
        <span class="nav-label" data-en="Dashboard" data-fa="داشبورد">Dashboard</span>
      </button>
      <button class="nav-item" data-page="inbounds">
        <svg class height="7" rx="1"/></svg>
        <span class="nav-label" data-en="Dashboard" data-fa="داشبورد">Dashboard</span>
      </button>
      <button class="nav-item" data-page="inbounds">
        <svg height="7" rx="1"/></svg>
        <span class="nav-label" data-en="Dashboard" data-fa="داشبورد">Dashboard</span>
      </button>
      <button class="nav-item" data-page="inbounds">
        <svg class>
      </button>
      <button class="nav-item" data-page="inbounds">
        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7"="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx=">
      </button>
      <button class="nav-item" data-page="inbounds">
        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7"="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx=" r="4"/><line x1="23" r="4"/><line x1="23" y1="11" x2="17" y2="11"/><line x1="20" y9" cy="7" r="4"/><line x1="23" y1="11" x2="17" y2="11"/><line x1 r="4"/><line x1="23" y1="11" x2="17" y2="11"/><line x1="20" y1="9" cy="7" r="4"/><line x1="23" y1="11" x2="17" y2="11"/><line x y1="11" x2="17" y2="11"/><line x1="20" y1="1="8" x2="20" y2="14"/></svg>
        <span class="nav-label" data-en="Inbounds" data-fa="اینباندها">Inbounds="20" y1="8" x2="20" y2="14"/></svg>
        <span class="nav-label" data-en="Inbounds" data-fa="اینباندها">Inbounds8" x2="20" y2="14"/></svg>
        <span class="nav-label" data-en="Inbounds" data-fa="اینباندها">Inbounds1="20" y1="8" x2="20" y2="14"/></svg>
        <span class="nav-label" data-en="Inbounds" data-fa="اینباندها">Inbounds8" x2="20" y2="14"/></svg>
        <span class="nav-label" data-en="Inbounds" data-fa="اینباندها">Inbounds</span>
        <span class="nav-badge" id="nb">0</</span>
        <span class="nav-badge" id="nb">0</</span>
        <span class="nav-badge" id="nb">0</</span>
        <span class="nav-badge" id="nb">0</</span>
        <span class="nav-badge" id="nb">0</span>
      </button>
      <button class="nav-item" data-page="traffic">
        <svg class="nav-icon" viewBox="0 0 24span>
      </button>
      <button class="nav-item" data-page="traffic">
        <svg class="nav-icon" viewBox="0 0 24span>
      </button>
      <button class="nav-item" data-page="traffic">
        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
        <span class="nav-label" data-en="Traffic" data-fa="ترافیک">Trafficspan>
      </button>
      <button class="nav-item" data-page="traffic">
        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
        <span class="nav-label" data-en="Traffic" data-fa="ترافیک">Trafficspan>
      </button>
      <button class="nav-item" data-page="traffic">
        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
        <span class="nav-label" data-en="Traffic" data-fa="ترافیک">Traffic 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
        <span class="nav-label" data-en="Traffic" data-fa="ترافیک">Traffic 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
        <span class="nav-label" data-en="Traffic" data-fa="ترافیک">Traffic</span>
      </button>
      <button class="</span>
      </button>
      <button class="nav-item" data-page="addresses">
        <svg</span>
      </button>
      <button class="nav-item" data-page="addresses">
        <svg</span>
      </button>
      <button class="nav-item" data-page="addresses">
        <svg</span>
      </button>
      <button class="nav-item" data-page="addresses">
        <svgnav-item" data-page="addresses">
        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10 class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10 class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/ class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/ class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/"/><line x1="2" y1="12" x2="22" y2="12"/"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 ><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10za15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.34 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>
        <span class="nav-label" data-en="Clean IP" data-fa="آی‌پی تمیز">Clean IP</span>
      </button>
      <button class="nav-item" data-page="security">
        <svg class="nav-icon" viewBox="0 0 24 24" fill 0 014-10z"/></svg>
        <span class="nav-label" data-en="Clean IP" data-fa="آی‌پی تمیز">Clean IP</span>
      </button>
      <button class="nav-item" data-page="security">
        <svg class="nav-icon" viewBox="0 0014-10z"/></svg>
        <span class="nav-label" data-en="Clean IP" data-fa="آی‌پی تمیز">Clean IP</span>
      </button>
      <button class="nav-item" data-page="security">
        <svg class="nav-icon" viewBox="0 0 24 24" fill"/></svg>
        <span class="nav-label" data-en="Clean IP" data-fa="آی‌پی تمیز">Clean IP</span>
      </button>
      <button class="nav-item" data-page="security">
        <svg class="nav-icon" viewBox="0 0 0 014-10z"/></svg>
        <span class="nav-label" data-en="Clean IP" data-fa="آی‌پی تمیز">Clean IP</span>
      </button>
      <button class="nav-item" data-page="security">
        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="current 24 24" fill="none" stroke="current="none" stroke="currentColor" stroke-width="2="none" stroke="currentColor" stroke-width="2 24 24" fill="none" stroke="currentColor" stroke-width="2Color" stroke-width="2Color" stroke-width="2"><rect x="3" y="11" width="18""><rect x="3" y="11" width="18" height"><rect x="3" y="11" width="18" height="11" rx="2"/><path"><rect x="3" y="11" width="18" height="11" rx="2"/><path"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
        <span class="nav-label" data-en height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
        <span class="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
        <span class d="M7 11V7a5 5 0 0110 0v4"/></ d="M7 11V7a5 5 0 0110 0v4"/></svg>
        <span class="nav-label" data-en="Security" data-fa="امنیت">Security</span>
     ="Security" data-fa="امنیت">Security</span>
      </button>
      <button class="nav-item logout-mob" onclick="doLogout()">
        <svg class="nav-icon" viewBox="0 0="nav-label" data-en="Security" data-fa="امنیت">Security</span>
      </button>
      <button class="nav-item logout-mob" onclick="doLogout()">
        <svg class="nav-icon" viewBox="="nav-label" data-en="Security" data-fa="امنیت">Security</span>
      </button>
      <button class="nav-item logout-mob" onclick="doLogout()">
        <svg class="nav-icon" viewBox="svg>
        <span class="nav-label" data-en="Security" data-fa="امنیت">Security</span>
      </button>
      <button class="nav-item logout-mob" onclick="doLogout()">
        <svg class="nav-icon" viewBox="0 0 </button>
      <button class="nav-item logout-mob" onclick="doLogout()">
        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="210 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/ 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y><line x1="21" y1="12" x2="9" y2="12"/></svg>
        <span class="nav-label" data-en><line x1="21" y1="12" x2="9" y2="12"/></svg>
        <span class="nav-label" data-en" y1="12" x2="9" y2="12"/></svg>
        <span class="nav-label" data-en="Logout" data-f" y1="12" x2="9" y2="12"/></svg>
        <span class="nav-label" data-en2="12"/></svg>
        <span class="nav-label" data-en="Logout" data-f="Logout" data-fa="خروج">Logout</span>
      </button>
    </nav>
    <div class="sb-bottom">
      <button class="Logout" data-fa="خروج">Logout</span>
      </button>
    </nav>
    <div class="sb-bottom">
      <button classa="خروج">Logout</span>
      </button>
    </nav>
    <div class="sb-bottom">
      <button class="theme-toggle" onclick="toggleTheme()" id="theme-btn-desk" style="margin-bottom:4px;font-size:12px">🌙 Theme="Logout" data-fa="خروج">Logout</span>
      </button>
    </nav>
    <div class="sb-bottom">
      <button class="theme-toggle" onclick="toggleTheme()" id="theme-btn-desk" style="margin-bottom:4px;font-size:12a="خروج">Logout</span>
      </button>
    </nav>
    <div class="sb-bottom">
      <button class="theme-toggle" onclick="toggleTheme()" id="theme-btn-desk" style="margin-bottom:4px;font-size:12px">🌙 Theme="theme-toggle" onclick="toggleTheme()" id="theme-btn-desk" style="margin-bottom:4px;font-size:12="theme-toggle" onclick="toggleTheme()" id="theme-btn-desk" style="margin-bottom:4px;font-size:12</button>
      <div class="lang-row">
        <button class="lang-btn lang-en active" onclick="setLang('en')">px">🌙 Theme</button>
      <div class="lang-row">
        <button class="lang-btn lang-en active" onclick="setLang('en')"></button>
      <div class="lang-row">
        <button class="lang-btn lang-en active" onclick="px">🌙 Theme</button>
      <div class="lang-row">
        <button class="lang-btn lang-en active" onclick="setLang('en')">px">🌙 Theme</button>
      <div class="lang-row">
        <button class="lang-btn lang-en active" onclick="setLang('en')">EN</button>
        <button class="lang-btn lang-fa" onclick="setLang('fa')">FA</button>
      </div>
      <button class="logout-btn" onclick="doLogout()" style="margin-top:2px">
        <svg width="12" height="12" viewBox="0 0 EN</button>
        <button class="lang-btn lang-fa" onclick="setLang('fa')">FA</button>
      </div>
      <button class="logout-btn" onclick="doLogout()" style="margin-top:2px">
        <svg width="12" height="12" viewBox="0 0 EN</button>
        <button class="lang-btn lang-fa" onclick="setLang('fa')">FA</button>
      </div>
      <button class="logout-btn" onclick="doLogout()" style="margin-top:2px">
        <svg width="12" height="12" viewsetLang('en')">EN</button>
        <button class="lang-btn lang-fa" onclick="setLang('fa')">FA</button>
      </div>
      <button class="logout-btn" onclick="doLogout()" style="margin-top:2px">
        <svg width="12" height="12" viewBox="0 0 EN</button>
        <button class="lang-btn lang-fa" onclick="setLang('fa')">FA</button>
      </div>
      <button class="logout-btn" onclick="doLogout()" style="margin-top:2px">
        <svg width="12" height="12" view24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="MBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M9 21H5a2 2 0 Box="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2M9 21H5a2 2 0 9 21H5a2 2 0 01-2-2V5a5"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="1201-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" yh4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="1201-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
        <span data-en="Logout" data2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
        <span data-en="Logout" data" x2="9" y2="12"/></svg>
        <span data-en="Logout" data-fa="خروج">Logout</span>
      </button>
    </div>
  </aside>

  <main class1="12" x2="9" y2="12"/></svg>
        <span data-en="Logout" data-fa="خروج">Logout</span>
      </button>
    </div>
  </aside>

  <main class="main">
    <section class" x2="9" y2="12"/></svg>
        <span data-en="Logout" data-fa="خروج">Logout</span>
      </button>
    </div>
  </aside>

  <main class-fa="خروج">Logout</span>
      </button>
    </div>
  </aside>

  <main class="main">
    <section class="page active" id="page-dashboard">
      <div class="page-header">
        <div>
          <div class="page-title" data-en="Dashboard" data-fa="داشبورد">Dashboard</div>
          <div class="page-sub" id="last-up">–</div>
        </div>
       -fa="خروج">Logout</span>
      </button>
    </div>
  </aside>

  <main class="main">
    <section class="page active" id="page-dashboard">
      <div class="page-header">
        <div>
          <div class="page-title" data-en="Dashboard" data-fa="داشبورد">Dashboard</div>
          <div class="page-sub" id="last-up">–</div>
        </div>
        <div style="main">
    <section class="page active" id="page-dashboard">
      <div class="page-header">
        <div>
          <div class="page-title" data-en="Dashboard" data-fa="داشبورد">Dashboard</div>
          <div class="page-sub" id="last-up">–</div>
        </div>
        <div style="page active" id="page-dashboard">
      <div class="page-header">
        <div>
          <div class="page-title" data-en="Dashboard" data-fa="داشبورد">Dashboard</div>
          <div class="page-sub" id="last-up">–</div>
        </div>
        <div style="main">
    <section class="page active" id="page-dashboard">
      <div class="page-header">
        <div>
          <div class="page-title" data-en="Dashboard" data-fa="داشبورد">Dashboard</div>
          <div class="page-sub" id="last-up">–</div>
        </div>
        <div style <div style="display:flex;gap:6px">
          <button class="btn btn-ghost btn="display:flex;gap:6px">
          <button class="btn btn-ghost btn-sm"="display:flex;gap:6px">
          <button class="btn btn-ghost="display:flex;gap:6px">
          <button class="btn btn-ghost btn-sm" onclick="qCreate(.5,'GB')" data-en="+ 0.5 GB" data-fa="+ ۰="display:flex;gap:6px">
          <button class="btn btn-ghost btn-sm" onclick="qCreate(.5,'GB')" data-en="+ 0.5 GB" data-sm" onclick="qCreate(.5,'GB')" data-en="+ 0.5 GB" data-fa="+ ۰. onclick="qCreate(.5,'GB')" data-en="+ 0.5 GB" data btn-sm" onclick="qCreate(.5,'GB')" data-en="+ 0.5 GB" data-fa="+ ۰.۵ گیگ">+ 0.5 GB</button>
          <button.۵ گیگ">+ 0.5 GB</button>
          <button class="btn btn-gold btn-sm" onclick="qCreate(1,'GB')-fa="+ ۰.۵ گیگ">+ 0.5 GB</button>
          <button class="btn btn-gold btn-sm" onclick="qCreate(1,'GB')" data-en="+ 1 GB" data-fa="+ ۱ گیگ">+ 1 GB</۵ گیگ">+ 0.5 GB</button>
          <button class="btn btn-gold btn-sm" onclick="qCreate(1,'GB')" data-en="+ 1 GB" data-fa="+ ۱ گیگ">+ 1 GB</-fa="+ ۰.۵ گیگ">+ 0.5 GB</button>
          <button class="btn btn-gold btn-sm" onclick="qCreate(1,'GB')" data-en="+ 1 GB" data-fa="+ ۱ گیگ">+ 1 GB</ class="btn btn-gold btn-sm" onclick="qCreate(1,'GB')" data-en="+ 1 GB" data-fa="+ ۱ گیگ">+ 1 GB</" data-en="+ 1 GB" data-fa="+ ۱ گیگ">+ 1 GB</button>
        </div>
      </div>
      <div class="stats-row">
        <div class="stat-card" style="animation-delay:.08button>
        </div>
      </div>
      <div class="stats-row">
        <div class="stat-card" style="animation-delay:.08s"><div class="stat-label" data-en="Traffic" data-fa="ترافیک">Traffic</div><div class="stat-val" id="sv-traffic">–<span class="stat-unit"> MB</span></div></div>
        <div class="stat-card" style="animation-delay:.16s"><div class="stat-label" data-en="button>
        </div>
      </div>
      <div class="stats-row">
        <div class="stat-card" style="animation-delay:.08s"><div class="stat-label" data-en="Traffic" data-fa="ترافیک">Traffic</div><div class="stat-val" id="sv-traffic">–<span class="stat-unit"> MB</span></div></div>
        <div class="stat-card" style="animation-delay:.16s"><div class="stat-label" data-en="button>
        </div>
      </div>
      <div class="stats-row">
        <div class="stat-card" style="animation-delay:.08s"><div class="stat-label" data-en="Traffic" data-fa="ترافیک">Traffic</div><div class="stat-val" id="sv-traffic">–<span class="stat-unit"> MB</span></div></div>
        <div class="stat-card" style="animation-delay:.16s"><div class="button>
        </div>
      </div>
      <div class="stats-row">
        <div class="stat-card" style="animation-delay:.08s"><div class="stat-label" data-en="Traffic" data-fa="ترافیک">Traffic</div><div class="stat-val" id="sv-traffic">–<span class="stat-unit"> MB</span></div></div>
        <div class="stat-card" style="animation-delay:.16s"><div class="stat-label" data-en="s"><div class="stat-label" data-en="Traffic" data-fa="ترافیک">Traffic</divInbounds" data-fa="اینباندInbounds" data-fa="اینباندstat-label" data-en="Inbounds" data-fa="اینباندها">Inbounds</div><div class="stat-val" id="sv-links">–</div></div>
        <div classInbounds" data-fa="اینباندها">Inbounds</div><div class="stat-val" id="sv-links">–</div></div>
        <div class="stat-card" style><div class="stat-val" id="sv-traffic">–<span class="stat-unit"> MB</span></div></div>
        <div class="stat-card" style="animation-delay:.16s"><div class="stat-label" data-en="Inbounds" data-fa="اینباندها">Inbounds</div><div class="stat-val" id="sv-links">–</div></div>
        <div class="stat-card" style="animationها">Inbounds</div><div class="stat-val" id="sv-links">–</div></div>
        <div class="ها">Inbounds</div><div class="stat-val" id="sv-links">–</div></div>
        <div class="stat-card" style="animation-delay:.24s"><div class="stat-label" data-en="Uptime" data-fa="آپتایم">U="stat-card" style="animation-delay:.24s"><div class="stat-label" data-en="Uptime" data-fa="آپتایم">Uptime</div><div="animation-delay:.24s"><div class="stat-label" data-en="Uptime" data-fa="آپتایم">Uptime</div><div class="stat-val" id="sv-uptime" style="font-size:15px">–</div></-delay:.24s"><div class="stat-label" data-en="Uptime" data-fa="آپتایم">Uptime</div><div class="stat-val" id="sv-uptime" style="font-size:15px">–</div></div>
        <div classstat-card" style="animation-delay:.24s"><div class="stat-label" data-en="Uptime" data-fa="آپتایم">Uptime</div><div class="stat-val" id="sv-uptime" style="font-size:15px">–</div></ptime</div><div class="stat-val" id="sv-uptime" style="font-size:15px">–</div></ class="stat-val" id="sv-uptime" style="font-size:15px">–</div></div>
        <div class="stat-card" style="animation-delay:.32s"><div class="stat-label" data-en="Domain"div>
        <div class="stat-card" style="animation-delay:.32s"><div class="stat-label" data-en="Domain" data-fa="دامنه">Domain</div><div class="stat-val" id="sv-domain" style="font-size:10px;word-break:break-all="stat-card" style="animation-delay:.32s"><div class="stat-label" data-en="Domain" data-fa="دامنه">Domain</div><div class="stat-val" id="sv-domain" style="font-size:10px;word-break:break-all;font-weight:500">–</div></div>
      </div>
      <div class="grid-2">
        <div class="card">
          <div class="card-hd"><divdiv>
        <div class="stat-card" style="animation-delay:.32s"><div class="stat-label" data-en="Domain" data-fa="دامنه">Domain</div><div class="stat-val" id="sv-domain" style="font-size:10px;word-break:break-all;font-weight:500">–</div></div>
      </div>
      <div class="grid-2">
        <div class="card">
          <div class="card-hd"><div class="card-title" datadiv>
        <div class="stat-card" style="animation-delay:.32s"><div class="stat-label" data-en="Domain" data-fa="دامنه">Domain</div><div class="stat-val" id="sv-domain" style="font-size:10px;word-break:break-all;font-weight:500">–</div></div>
      </div>
      <div class="grid-2">
        <div class="card">
          <div class="card-hd"><div class="card-title" data data-fa="دامنه">Domain</div><div class="stat-val" id="sv-domain" style="font-size:10px;word-break:break-all;font-weight:500">–</div></div>
      </div>
      <div class="grid-2">
        <div class="card">
          <div class="card-hd"><div class="card-title" data;font-weight:500">–</div></div>
      </div>
      <div class="grid-2">
        <div class="card">
          <div class="card-hd"><div class="card-title" data-en="CPU" data-fa="پردازنده">CPU</div><span class="card-title" data-en="CPU" data-fa="پردازنده">CPU</div-en="CPU" data-fa="پردازنده">CPU</div><span id="cpu-v-en="CPU" data-fa="پردازنده">CPU</div><span id="cpu-v-en="CPU" data-fa="پردازنده">CPU</div><span id="cpu-v" style="font-size:17px;font-weight:700;color:var(--primary)">–%</span></div>
 id="cpu-v" style="font-size:17px;font-weight:700;color:var(--primary)">–%</span></div>
><span id="cpu-v" style="font-size:17px;font-weight:700;color:var(--" style="font-size:17px;font-weight:700;color:var(--primary)">–%</span></div>
" style="font-size:17px;font-weight:700;color:var(--primary)">–%</span></div>
          <div class="sys-bar"><div class="sys-fill" id="cpu-b" style="background:var(--primary)"></div></div>
        </div          <div class="sys-bar"><div class="sys-fill" id="cpu-b" style="background:var(--primary)"></div          <div class="sys-bar"><div class="sys-fill" id="cpu-b" style="background:var(--primary)"></div></div>
       primary)">–%</span></div>
          <div class="sys-bar"><div class="sys-fill" id="cpu-b" style="background:var(--primary)"></div></div>
        </div>
        <div class="card">
          <div class="card-hd"><div class="card-title" data          <div class="sys-bar"><div class="sys-fill" id="cpu-b" style="background:var(--primary)"></div></div>
        </div>
        <div class="card">
          <div class="card-hd"><div class="card-title" data>
        <div class="card">
          <div class="card-hd"><div class="card-title" data></div>
        </div>
        <div class="card">
          <div class="card-hd"><div class="card-title" data-en="Memory" data-f </div>
        <div class="card">
          <div class="card-hd"><div-en="Memory" data-fa="حافظه">Memory</div><span id="mem-v" style="font-size:17px;font-weight:700;color:var(--green)">–%</span></div>
          <div class="sys-bar"><div class="sys-fill" id="mem-b" style="background:var(--green)"></div></div>
        </div>
      </div>
      <div class="-en="Memory" data-fa="حافظه">Memory</div><span id="mem-v" style="font-size:17px;font-weight:700;color:var(--green)">–%</span></div>
          <div class="sys-bar"><div class="sys-fill" id="mem-b" style="background:var(--green)"></div></div>
        </div>
      </div>
      <div-en="Memory" data-fa="حافظه">Memory</div><span id="mem-v" style="font-size:17px;font-weight:700;color:var(--green)">–%</span></div>
          <div class="sys-bar"><div class="sys-fill" id="mem-b" style="background:var(--green)"></div></div>
        </div>
      </div>
a="حافظه">Memory</div><span id="mem-v" style="font-size:17px;font-weight:700;color:var(--green)">–%</span></div>
          <div class="sys-bar"><div class="sys-fill" id="mem-b" style="background:var(--green)"></div></div>
        </div>
      </div>
      <div class=" class="card-title" data-en="Memory" data-fa="حافظه">Memory</div><span id="mem-v" style="font-size:17px;font-weight:700;color:var(--green)">–%</span></div>
          <div class="sys-bar"><div class="sys-fill" id="mem-b" style="background:var(--green)"></div></div>
        </card">
        <div class="card-hd"><div class class="card">
        <div class="card-hd"><div class      <div class="card">
        <div class="card-hd"><div class="card-title" data-en="Hourly Traffic" data-fa="ترافیک ساعتی">Hourly Traffic</div></divcard">
        <div class="card-hd"><div class="card-title" data-en="Hourly Traffic" data-fa="ترافیک ساعتی">Hourly Traffic</div></div>
        <div class="div>
      </div>
      <div class="card">
        <div class="card-hd"><div class="card-title" data-en="Hourly Traffic" data-fa="ترافیک ساعتی">Hourly Traffic</div></div>
        <div="card-title" data-en="Hourly Traffic" data-fa="ترافیک ساعتی">Hourly Traffic</div></div>
        <div="card-title" data-en="Hourly Traffic" data-fa="ترافیک ساعتی">Hourly Traffic</div></div>
        <div class="chart-container"><canvas id="tc"></canvas></div>
      </div>
    </section>

    <section class="page" id="page-inbounds">
     >
        <div class="chart-container"><canvas id="tc"></canvas></div>
      </div>
    </section>

    <section class="page" id="pagechart-container"><canvas id="tc"></canvas></div>
      </div>
    </section>

    <section class="page" id="page-inbounds">
      class="chart-container"><canvas id="tc"></canvas></div>
      </div>
    </section>

    <section class="page" id="page-inbounds">
      <div class="page-header">
        <div>
          <div class="page-title" data-en="Inbounds" data-fa="این class="chart-container"><canvas id="tc"></canvas></div>
      </div>
    </section>

    <section class="page" id="page-inbounds">
      <div class="page-header">
        <div>
          <div class="page-title" data-en="Inbounds" data-fa="این <div class="page-header">
        <div>
          <div class="page-title" data-en="Inbounds" data-fa="این-inbounds">
      <div class="page-header">
        <div>
          <div class="page-title" data-en="Inbounds" data-fa="این <div class="page-header">
        <div>
          <div class="page-title" data-en="Inbounds" data-fa="اینباندها">Inbounds</div>
          <div class="page-sub" data-en="Multi-protocol · VLESS/VMess/Trojan/Hysteria2" data-fa="چند پروتکل · VLESS/VMess/Trojan/Hysteria2">Multi-protocol · VLESS/VMess/Trojan/Hysteria2</div>
        </div>
        <button class="btn btnباندها">Inbounds</div>
          <div class="page-sub" data-en="Multi-protocol · VLESS/VMess/Trojan/Hysteria2" data-fa="چند پروتکل · VLESS/VMess/Trojan/Hysteria2">Multi-protocol · VLESS/VMess/Trojan/Hysteria2</div>
        </div>
       باندها">Inbounds</div>
          <div class="page-sub" data-en="Multi-protocol · VLESS/VMess/Trojan/Hysteria2" data-fa="چند پروتکل · VLESS/VMess/Trojan/Hysteria2">Multi-protocol · VLESS/VMess/Trojan/Hysteria2</div>
باندها">Inbounds</div>
          <div class="page-sub" data-en="Multi-protocol · VLESS/VMess/Trojan/Hysteria2" data-fa="چند پروتکل · VLESS/VMess/Trojan/Hysteria2">Multi-protocol · VLESS/VMess/Trojan/Hysteria2</div>
        </div>
        <button class="باندها">Inbounds</div>
          <div class="page-sub" data-en="Multi-protocol · VLESS/VMess/Trojan/Hysteria2" data-fa="چند پروتکل · VLESS/VMess/Trojan/Hysteria2">Multi-protocol · VLESS/VMess/Trojan/Hysteria2</div>
        </div>
        <button class="btn btn-g-gold" onclick="showAddMo()" data-en=" <button class="btn btn-gold" onclick="showAddMo()" data-en="+ Add" data-fa        </div>
        <button class="btn btn-gold" onclick="showAddMo()" data-en="+ Add" data-fa="+ افزودن">+ Add</button>
      </div>
      <div class="tb">
       btn btn-gold" onclick="showAddMo()" data-en="+ Add" data-fa="+ افزودن">+ Add</button>
      </div>
      <div class="tb">
       old" onclick="showAddMo()" data-en="+ Add" data-fa="+ افزودن">+ Add</button>
      </div>
      <div class="tb">
        <div class="search+ Add" data-fa="+ افزودن">+ Add</button>
      </div>
      <div class="tb">
        <div class="="+ افزودن">+ Add</button>
      </div>
      <div class="tb">
        <div class="search-wrap">
          <svg width="15" height="15" viewBox="0 0 24 24" fill=" <div class="search-wrap">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1 <div class="search-wrap">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1-wrap">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1search-wrap">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line xnone" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          <input id="srch" data-ph-en="Search name…" data-ph-fa="جستجوی نام…" placeholder="Search name…" oninput="filterLinks()">
        </div>
        <div class="filter-chips">
          <button class="chip active" data-filter="all"="21" x2="16.65" y2="16.65"/></svg>
          <input id="srch" data-ph-en="Search name…" data-ph-fa="جستجوی نام…" placeholder="Search name…" oninput="filterLinks()">
        </div>
        <div class="filter-chips">
          <button class="chip active" data-filter="all"="21" x2="16.65" y2="16.65"/></svg>
          <input id="srch" data-ph-en="Search name…" data-ph-fa="جستجوی نام…" placeholder="Search name…" oninput="filterLinks()">
        </div>
        <div class="filter-chips">
          <button class="chip active" data-filter="all"1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          <input id="srch" data-ph-en="Search name…" data-ph-fa="جستجوی نام…" placeholder="Search name…" oninput="filterLinks()">
        </div>
        <div class="filter-chips">
          <button class="chip active" data-filter="all" onclick="setFilter('all="21" x2="16.65" y2="16.65"/></svg>
          <input id="srch" data-ph-en="Search name…" data-ph-fa="جستجوی نام…" placeholder="Search name…" oninput="filterLinks()">
        </div>
        <div class="filter-chips">
          <button class="chip active" data-filter="all" onclick="setFilter('all',this)" data-en="All" data-fa="همه">All onclick="setFilter('all',this)" data-en="All" data-fa="همه">All onclick="setFilter('all',this)" data-en="All" data-fa="همه">All</',this)" data-en="All" data-fa="همه">All</button>
          <button class="chip" data-filter="active" onclick="setFilter('active',this)" data onclick="setFilter('all',this)" data-en="All" data-fa="همه">All</button>
          <button class="chip" data-filter="active" onclick="setFilter('active',this)" data-en="Active" data-fa="ف</button>
          <button class="chip" data-filter="active" onclick="setFilter('active',this)" data</button>
          <button class="chip" data-filter="active" onclick="setFilter('active',this)" data-en="Active" data-fa="فbutton>
          <button class="chip" data-filter="active" onclick="setFilter('active',this)"-en="Active" data-fa="فعال">Active</button>
          <button class="chip" data-filter="off" onclick="setFilter('off',this)" data-en="Off" dataعال">Active</button>
          <button class="chip" data-filter="off" onclick="setFilter('off',this)" data-en="Off" data-en="Active" data-fa="فعال">Active</button>
          <button class="chip" data-filter="off" onclick="setFilter('off',this)" data-en="Off" dataعال">Active</button>
          <button class="chip" data-filter="off" onclick="setFilter('off',this)" data-en="Off" data-fa="غیرفعال">Off</button>
        </div>
      </div>
      <div class="card" style="padding data-en="Active" data-fa="فعال">Active</button>
          <button class="chip" data-filter="off" onclick="setFilter('off',this)" data-en="Off" data-fa="غیرفعال">Off</button>
        </div>
      </div>
      <div class="card" style="padding:0;overflow:hidden-fa="غیرفعال">Off</button>
        </div>
      </div>
      <div class="card" style="padding:0;overflow:hidden-fa="غیرفعال">Off</button>
        </div>
      </div>
      <div class="card" style="padding:0;overflow:hidden-fa="غیرفعال">Off</button>
        </div>
      </div>
      <div class="card" style="padding:0;overflow:hidden:0;overflow:hidden">
        <div class="tbl-wrap">
          <table class="tbl">
            <thead><tr>
              <th data-en="#" data-fa="#">#</th>
              <th data-en="Name" data-fa="نام">Name</th>
              <th data-en="Type" data-fa="نوع">Type</th>
              <th data">
        <div class="tbl-wrap">
          <table class="tbl">
            <thead><tr>
              <th data-en="#" data-fa="#">#</th>
              <th data-en="Name" data-fa="نام">Name</th>
              <th data-en="Type" data-fa="نوع">Type</th>
">
        <div class="tbl-wrap">
          <table class="tbl">
            <thead><tr>
              <th data-en="#" data-fa="#">#</th>
              <th data-en="Name" data-fa="نام">Name</th>
              <th data-en="Type" data-fa="نوع">Type</">
        <div class="tbl-wrap">
          <table class="tbl">
            <thead><tr>
              <th data-en="#" data-fa="#">#</th>
              <th data-en="Name" data-fa="نام">Name</th>
              <th data-en="Type" data-fa="نوع">Type</th>
">
        <div class="tbl-wrap">
          <table class="tbl">
            <thead><tr>
              <th data-en="#" data-fa="#">#</th>
              <th data-en="Name" data-fa="نام">Name</th>
              <th data-en="Type" data-fa="نوع">Type</-en="Usage" data-fa="              <th data-en="Usage" data-fa="مصرف">Usage</th>
              <th data-en="Usage" data-fa="مصرف">Usage</              <th data-en="Usage" data-fa="مصرف">Usage</th>
              <th data-en="IPs" data-fa="آی‌پی">IPs</th>
              <th data-en="Usage" data-fa="مصرف">Usage</th>
              <th data-en="IPs" data-fa="آی‌پی">IPs</مصرف">Usage</th>
              <th data-en="IPs" data-fa="آیth>
              <th data-en="IPs" data-fa="آی‌پی">IPs</th>
              <th data-en="IPs" data-fa="آی‌پی">IPs</th>
              <th data-en="Expiry" data-fa="انقضا">Expiry</th>
              <th data-en="Status" data-fa="وضعیت">Status</th>
              <th data-en="Expiry" data-fa="انقضا">Expiry</th>
              <th data-en="Status" data-fa="th>
              <th data-en="Expiry" data-fa="انقضا">Expiry</th>
              <th data-en="Status" data-fa="وضعیت">Status</‌پی">IPs</th>
              <th data-en="Expiry" data-fa="انقضا">Expiry</th>
              <th data-en="Status" data-fa="وضعیت">Status</th>
              <th data-en="Actions" data-fa="عملیات">Actions</th>
            </tr></thead>
           th>
              <th data-en="Expiry" data-fa="انقضا">Expiry</th>
              <th data-en="Status" data-fa="وضعیت">Status</th>
              <th data-en="Actions" data-fa="عملیات">Actions</th>
            </tr></thead>
th>
              <th data-en="Actions" data-fa="عملیات">Actions</th>
            </tr></thead>
            <tbody id="ltb"></وضعیت">Status</th>
              <th data-en="Actions" data-fa="عملیات">Actions</th>
            </tr></thead>
           th>
              <th data-en="Actions" data-fa="عملیات">Actions</th>
            </tr></thead>
            <tbody id="ltb <tbody id="ltb"></tbody>
          </table>
        </div>
        <div class="m-cards" id="mcards"></div>
        <div class="empty" id="lempty" style="display:none" data-en="No inbounds found" data-fa="هیچ اینباندی یافت نشد">No inbounds found</div>
            <tbody id="ltb"></tbody>
          </table>
        </div>
        <div class="m-cards" id="mcards"></div>
        <div class="empty" id="lempty" style="display:none" data-en="No inbounds found" data-fa="هیچ اینباندی یافت نشد">No inbounds found</div>
     tbody>
          </table>
        </div>
        <div class="m-cards" id="mcards"></div>
        <div class="empty" id="lempty" style="display:none" data-en="No inbounds found" data-fa="هیچ اینباندی یافت نشد">No inbounds found <tbody id="ltb"></tbody>
          </table>
        </div>
        <div class="m-cards" id="mcards"></div>
        <div class="empty" id="lempty" style="display:none" data-en="No inbounds found" data-fa="هیچ اینباندی یافت نشد">No"></tbody>
          </table>
        </div>
        <div class="m-cards" id="mcards"></div>
        <div class="empty" id="lempty" style="display:none" data-en="No inbounds found" data-fa="هیچ اینباندی یافت نشد">No inbounds found</div>
      </div>
    </section>

    <section class="page" id="page-traffic">
      <div class="page-header"><div </div>
    </section>

    <section class="page" id="page-traffic">
      <div class="page-header"><div</div>
      </div>
    </section>

    <section class="page" id="page-traffic">
      <div class="page-header"><div inbounds found</div>
      </div>
    </section>

    <section class="page" id="page-traffic">
      <div class="page-header"><div      </div>
    </section>

    <section class="page" id="page-traffic">
      <div class="page-header"><div><div class="page-title" data-en="Traffic" data-fa="ترافیک">Traffic</div><div class="page-sub" data-en="Statistics><div class="page-title" data-en="Traffic" data-fa="ترافیک">Traffic</div><div class="page-sub" data-en="Statistics><div class="page-title" data-en="Traffic" data-fa="ترافیک">Traffic</div><div class="page-sub" data-en="Statistics" data-fa="><div class="page-title" data-en="Traffic" data-fa="ترافیک">Traffic</div><div class="page-sub" data-en="Statistics><div class="page-title" data-en="Traffic" data-fa="ترافیک">Traffic</div><div class="page-sub" data-en="Statistics" data-fa="آمار">Statistics</div></div></div>
      <div class="card">
        <div class="sl-item" data-fa="آمار">Statistics</div></div></div>
      <div class="card">
        <div class="sl-item"><" data-fa="آمار">Statistics</div></div></div>
      <div class="card">
        <div class="sl-item"><span class="sl-kآمار">Statistics</div></div></div>
      <div class="card">
        <div class="sl-item"><span class="sl-k" data-en="Total Traffic" data-fa="کل ترافیک">Total Traffic</span><span class="sl-v" id="t" data-fa="آمار">Statistics</div></div></div>
      <div class="card">
        <div class="sl-item"><span class="sl-k" data-en="Total Traffic" data-fa="کل ترافیک">Total Traffic</span><span class="sl-v" id="t"><span class="sl-k" data-en="Total Traffic" data-fa="کل ترافیک">Total Traffic</span><span class="sl-v" id="tspan class="sl-k" data-en="Total Traffic" data-fa="کل ترافیک">Total Traffic</span><span class="sl-v" id="t" data-en="Total Traffic" data-fa="کل ترافیک">Total Traffic</span><span class="sl-v" id="t-tr">–</span></div>
        <div class="sl-item"><span class="sl-k" data-en="Total Requests" data-fa="کل درخواست‌ها">Total Requests</span><span class="sl-v" id="t-rq">–</span></div>
        <div class="sl-item"><span class="sl-k" data-en="Uptime" data-f-tr">–</span></div>
        <div class="sl-item"><span class="sl-k" data-en="Total Requests" data-fa="کل درخواست‌ها">Total Requests</span><span class="sl-v" id="t-rq">–</span></div>
        <div class="sl-item"><span class="sl-k" data-en="Uptime" data-f-tr">–</span></div>
        <div class="sl-item"><span class="sl-k" data-en="Total Requests" data-fa="کل درخواست‌ها">Total Requests</span><span class="sl-v" id="t-rq">–</span></div>
        <div class="sl-item"><span class="sl-k" data-en="-tr">–</span></div>
        <div class="sl-item"><span class="sl-k" data-en="Total Requests" data-fa="کل درخواست‌ها">Total Requests</span><span class="sl-v" id="t-rq">–</span></div>
        <div class="sl-item"><span class="sl-k" data-en="Uptime" data-f-tr">–</span></div>
        <div class="sl-item"><span class="sl-k" data-en="Total Requests" data-fa="کل درخواست‌ها">Total Requests</span><span class="sl-v" id="t-rq">–</span></div>
        <div class="sl-item"><span class="sl-k" data-en="Uptime" data-fa="آپتایم">Uptime</span><span class="sl-v" id="ta="آپتایم">Uptime</span><span class="sl-v" id="tUptime" data-fa="آپتایم">Uptime</span><span class="sl-v" id="t-up">–</span></div>
      </div>
    </section>

    <section class="page" ida="آپتایم">Uptime</span><span class="sl-v" id="t-up">–</span></div>
      </div>
    </section>

    <section class="page" id="page-addresses">
      <div class="a="آپتایم">Uptime</span><span class="sl-v" id="t-up">–</span></div>
      </div>
    </section>

    <section class="page" id="page-addresses-up">–</span></div>
      </div>
    </section>

    <section class="page" id="page-addresses">
      <div class="-up">–</span></div>
      </div>
    </section>

    <section class="page" id="page-addresses">
="page-addresses">
      <div class="page-header">
        <div><div class="page-title" data-en="Clean IP" data-fa="آی‌پی تمیز">Clean IP</page-header">
        <div><div class="page-title" data-en="Clean IP" data-fa="آی‌پی">
      <div class="page-header">
        <div><div class="page-title" data-en="Clean IP" data-fa="آی‌پی تمیز">Clean IP</page-header">
        <div><div class="page-title" data-en="Clean IP" data-fa="آی‌پی تمیز">Clean IP</div><div class="page-sub" data-en="Subscription alternative addresses" data-fa="آدرس‌های جایگزین اشتراک">Subscription alternative addresses</div></      <div class="page-header">
        <div><div class="page-title" data-en="Clean IP" data-fa="آی‌پی تمیز">Clean IP</div><div class="page-sub" data-en="Subscription alternative addresses" data-fa="آدرس‌های جایگزین اشتراک">Subscription alternative addressesdiv><div class="page-sub" data-en="Subscription alternative addresses" data-fa="آدرس‌های جایگزین اشتراک">Subscription alternative addresses</div></div>
        <button class="btn btn-gold" onclick="showAddAddrMo()" data-en="+ Add" data-fa="+ افزودن">+ Add</button>
      </div>
      <div class="card">
        <div style="font-size:12px;color:var(--text3);margin-bottom: تمیز">Clean IP</div><div class="page-sub" data-en="Subscription alternative addresses" data-fa="آدرس‌های جایگزین اشتراک">Subscription alternative addresses</div></div>
        <button class="btn btn-gold" onclick="showAddAddrMo()" data-en="+ Add" data-fa="+ افزودن">+ Add</button>
      </div>
      <div class="card">
        <div style="font-size:12px;color:var(--text3);margin-bottom:div><div class="page-sub" data-en="Subscription alternative addresses" data-fa="آدرس‌های جایگزین اشتراک">Subscription alternative addresses</div></div>
        <button class="btn btn-gold" onclick="showAddAddrMo()" data-en="+ Add" data-fa="+ افزودن">+ Add</button>
      </div>
      <div class="card">
        <div style="font-size:12px;color:var(--text3);margin-bottom:div>
        <button class="btn btn-gold" onclick="showAddAddrMo()" data-en="+ Add" data-fa="+ افزودن">+ Add</button>
      </div>
      <div class="card">
        <div style="font-size:12px;color:var(--text3);margin-bottom:12px" data-en="Default: www.speedtest.net" data-fa="</div></div>
        <button class="btn btn-gold" onclick="showAddAddrMo()" data-en="+ Add" data-fa="+ افزودن">+ Add</button>
      </div>
      <div class="card">
        <div style="font-size:12px;color:var(--text3);margin-bottom:12px" data-en="Default: www.speedtest.net" data-fa="پیش‌فرض: www.speedtest.net">Default: www.speed12px" data-en="Default: www.speedtest.net" data-fa="پیش‌فرض: www.speedtest.net">Default: www.speed12px" data-en="Default: www.speedtest.net" data-fa="پیش‌فرض: www.speedtest.net">Default: www.speedپیش‌فرض: www.speedtest.net">Default: www.speedtest.net</div>
        <div id="addr-list"></div>
      </div>
    </section>

    <section class="page12px" data-en="Default: www.speedtest.net" data-fa="پیش‌فرض: www.speedtest.net">Default: www.speedtest.net</div>
        <div id="addr-list"></div>
      </div>
    </section>

    <section class="pagetest.net</div>
        <div id="addr-list"></div>
      </divtest.net</div>
        <div id="addr-list"></div>
      </div>
    </section>

    <section class="pagetest.net</div>
        <div id="addr-list"></div>
      </div>
    </section>

    <section class="page" id="page-security">
      <div class="page-header"><div><div class="page-title" data-en" id="page-security">
      <div class="page-header"><div><div class="page-title" data-en="Security" data-fa="امنیت">Security</div><div class="page-sub" data-en="Change panel password" data-fa="تغییر رمز پ" id="page-security">
      <div class="page-header"><div><div class="page-title" data-en="Security" data-fa="امنیت">Security</div><div class="page-sub" data-en="Change panel password" data-fa="تغییر رمز پ>
    </section>

    <section class="page" id="page-security">
      <div class="page-header"><div><div class="page-title" data-en="Security" data-fa="امنیت">Security</div><div class="page-sub" data-en="Change panel password" data-fa="تغییر رمز پنل">Change panel password</div" id="page-security">
      <div class="page-header"><div><div class="page-title" data-en="Security" data-fa="امنیت">Security</div><div class="page-sub" data-en="Change panel password" data-fa="تغییر رمز پ="Security" data-fa="امنیت">Security</div><div class="page-sub" data-en="Change panel password" data-fa="تغییر رمز پنل">Change panel password</div></div></div>
      <div class="card" style="max-width:380px">
        <div class="fg"><label class="fl" data-en="Current Password" data-fa="رمز فعلی">Current Password</label><input class="fi" type="password" id="cpw" data-ph-en="Current password" data-ph-fa="رمز فعلی" placeholder="نل">Change panel password</div></div></div>
      <div class="card" style="max-width:380px">
        <div class="fg"><label class="fl" data-en="Current Password" data-fa="رمز فعلی">Current Password</label><input class="fi" type="password" id="cpw" data-ph-en="Current password" data-ph-fa="رمز فعلی" placeholder="نل">Change panel password</div></div></div>
      <div class="card" style="max-width:380px">
        <div class="fg"><label class="fl" data-en="Current Password" data-fa="رمز فعلی">Current Password</label><input class="fi" type="password" id="cpw" data-ph-en="Current password" data-ph-fa="رمز فعلی" placeholder="Current password"></div>
></div></div>
      <div class="card" style="max-width:380px">
        <div class="fg"><label class="fl" dataنل">Change panel password</div></div></div>
      <div class="card" style="max-width:380px">
        <div class="fg"><label class="fl" data-en="Current Password" data-fa="رمز فعلی">Current Password</label><input class="fi" type="password" id="cpw" data-ph-en="Current password" data-ph-fa="رمز فعلی" placeholder="Current password"></div>
        <div class="fg"><label class="fl" dataCurrent password"></div>
        <div class="fg"><label class="fl" data        <div class="fg"><label class="fl" data-en="New Password" data-fa="رمز جدید">New Password</label><input class="fi" type="password" id="npw-en="Current Password" data-fa="رمز فعلی">Current Password</label><input class="fi" type="password" id="cpw" data-ph-en="Current password" data-ph-fa="رمز فعلی" placeholder="Current password"></div>
        <div class="fg"><label class="fl" data-en="New Password" data-fa="رمز جدید">New Password</label><input class="fi" type="password" id="npwCurrent password"></div>
        <div class="fg"><label class="fl" data-en="New Password" data-fa="رمز جدید">New Password</label><input class="fi" type="password" id="npw-en="New Password" data-fa="رمز جدید">New Password</label><input class="fi" type="password" id="npw-en="New Password" data-fa="رمز جدید">New Password</label><input class="fi" type="password" id="npw" data-ph-en="Min 4 chars" data-ph-fa="حداقل ۴ کاراکتر" placeholder="Min 4 chars"></div>
        <button class="btn btn-gold" onclick="chgPw" data-ph-en="Min 4 chars" data-ph-fa="حداقل ۴ کاراکتر" placeholder="Min 4 chars"></div>
        <button class="btn btn-gold" onclick="chgPw()" style="margin-top:10px;width:100%;justify-content:center;" data-en="" data-ph-en="Min 4 chars" data-ph-fa="حداقل ۴ کاراکتر" placeholder="Min 4 chars"></div>
        <button class="btn btn-gold" onclick="chgPw()" style="margin-top:10px;width:100%;justify-content:center;" data-en" data-ph-en="Min 4 chars" data-ph-fa="حداقل ۴ کاراکتر" placeholder="Min 4 chars"></div>
        <button class="btn btn-gold" onclick="chgPw()" style="margin-top:10px;width:100%;justify-content:center;" data-en="Update Password" data-fa="بروزرس" data-ph-en="Min 4 chars" data-ph-fa="حداقل ۴ کاراکتر" placeholder="Min 4 chars"></div>
        <button class="btn btn-gold" onclick="chgPw()" style="margin-top:10px;width:100%;justify-content:center;" data-en="Update Password" data-fa="بروزرس()" style="margin-top:10px;width:100%;justify-content:center;" data-en="Update Password" data-fa="بروزرسانی رمز">Update Password</button>
      </div>
    </section>
  </main>
</div>

<!-- Modals -->
<div class="mo" id="mo-add" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-add').classList.remove('Update Password" data-fa="بروزرسانی رمز">Update Password</button>
      </div>
    </section>
  </main>
</div>

<!-- Modals -->
<div class="mo" id="="Update Password" data-fa="بروزرسانی رمز">Update Password</button>
      </div>
    </section>
  </main>
</div>

<!-- Modals -->
<div class="mo" id="mo-add" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-add').classList.remove('انی رمز">Update Password</button>
      </div>
    </section>
  </main>
</div>

<!-- Modals -->
<div class="mo" id="mo-add" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-add').classList.remove('show')">✕</انی رمز">Update Password</button>
      </div>
    </section>
  </main>
</div>

<!-- Modals -->
<div class="mo" id="mo-add" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-add').classList.remove('show')">✕</show')">✕</button>
    <div class="mo-title" data-en="ADD INBOUNDmo-add" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-add').classList.remove('show')">✕</button>
    <div class="mo-title" data-en="ADD INBOUNDshow')">✕</button>
    <div class="mo-title" data-en="ADD INBOUNDbutton>
    <div class="mo-title" data-en="ADD INBOUND" data-fa="افbutton>
    <div class="mo-title" data-en="ADD INBOUND" data-fa="اف" data-fa="افزودن اینباند">ADD INBOUND</div>
    <div class="fg"><label class" data-fa="افزودن اینباند">ADD INBOUND" data-fa="افزودن اینباند">ADD INBOUNDزودن اینباند">ADD INBOUND</div>
    <divزودن اینباند">ADD INBOUND</div>
    <div class="fg"><label class="fl" data-en="Remark" data-fa="توضیح">Remark</label><input class="fi" id="nl="fl" data-en="Remark" data-fa="توضیح">Remark</label><input class="fi</div>
    <div class="fg"><label class="fl" data-en="Remark" data-fa="توضیح">Remark</label><input class="fi</div>
    <div class="fg"><label class="fl" data-en="Remark" data-fa="توضیح">Remark</label><input class="fi" id="nl" data-ph-en="e.g. User 1" class="fg"><label class="fl" data-en="Remark" data-fa="توضیح">Remark</label><input class="fi" id="nl" data-ph-en="e.g. User 1"" data-ph-en="e.g. User 1" data-ph-fa="مثلاً کاربر ۱" placeholder="e.g. User 1"></div>
    <div class="fg"><label class="fl" data-en="Protocol" data-fa="پروتکل" id="nl" data-ph-en="e.g. User 1" data-ph-fa="مثلاً کاربر ۱" placeholder="e.g. User 1"></div>
    <div class="fg"><label class="fl" data-en="Protocol" data-fa="پروتکل" id="nl" data-ph-en="e.g. User 1" data-ph-fa="مثلاً کاربر ۱" placeholder="e.g. User 1"></div>
    <div class="fg"><label class="fl" data-en="Protocol" data-fa="پروتکل data-ph-fa="مثلاً کاربر ۱" placeholder="e.g. User 1"></div>
    <div class="fg"><label class="fl" data-en="Protocol" data-fa="پروتکل data-ph-fa="مثلاً کاربر ۱" placeholder="e.g. User 1"></div>
    <div class="fg"><label class="fl" data-en="Protocol" data-fa="پرو">Protocol</label>
      <select class="fs" id="npro">
        <option value="vless">VLESS</option>
        <option value="vmess">VMess</option>
        <option value="trojan">Trojan</option>
        <option value="hysteria2">Hysteria2</option>
      </select>
    </div>
    <div class="fr">
     ">Protocol</label>
      <select class="fs" id="npro">
        <option value="vless">VLESS</option>
        <option value="vmess">VMess</option>
        <option value="trojan">Trojan</option>
        <option value="hysteria2">Hysteria2</option>
      </select>
    </div>
    <div class="fr">
     ">Protocol</label>
      <select class="fs" id="npro">
        <option value="vless">VLESS</option>
        <option value="vmess">VMess</option>
        <option value="trojan">Trojan</option>
        <option value="hysteria2">Hysteria2</option>
      </select>
    </div>
    <div class="fr">
      <div class="fg"><label">Protocol</label>
      <select class="fs" id="npro">
        <option value="vless">VLESS</option>
        <option value="vmess">VMess</option>
        <option value="trojan">Trojan</option>
        <option value="hysteria2">Hysteria2</option>
      </select>
    </div>
    <div class="fr">
     تکل">Protocol</label>
      <select class="fs" id="npro">
        <option value="vless">VLESS</option>
        <option value="vmess">VMess</option>
        <option value="trojan">Trojan</option>
        <option value="hysteria2">Hysteria2</option>
      </select>
    </div>
    <div class="fr">
      <div class="fg"><label class="fl" data-en="Traffic Limit" data-fa="م <div class="fg"><label class="fl" data-en="Traffic Limit" data-fa="محد class="fl" data-en="Traffic Limit" data-fa="محدودیت ترافیک">Traffic Limit</label><input class="fi" id="nv" type="number" min="0" step <div class="fg"><label class="fl" data-en="Traffic Limit" data-fa="محدودیت ترافیک">Traffic Limit</label><input class="fi" id="nv" type="number" min="0" step <div class="fg"><label class="fl" data-en="Traffic Limit" data-fa="محدودیت ترافیک">Traffic Limit</label><input class="fi" id="nv" type="number" min="0" stepحدودیت ترافیک">Traffic Limit</label><input class="fi" id="nv" type="number" min="0" stepودیت ترافیک">Traffic Limit</label><input class="fi" id="nv" type="number" min="0" step=".1" data-ph-en="0 = ∞" data-ph-fa="۰ = نامحدود" placeholder="0 = ∞"></div>
      <div class="fg" style="=".1" data-ph-en="0 = ∞" data-ph-fa="۰ = نامحدود" placeholder="0 = ∞"></div>
      <div class="fg" style="max-width=".1" data-ph-en="0 = ∞" data-ph-fa="۰ = نامحدود" placeholder="0 = ∞"></div>
      <div class="fg" style="max=".1" data-ph-en="0 = ∞" data-ph-fa="۰ = نامحدود" placeholder="0 = ∞"></div>
      <div class="fg" style="max-width:100px"><label class="fl" data-en="Unit" data-fa="واحد">Unit</label><select class="fs" id="nu=".1" data-ph-en="0 = ∞" data-ph-fa="۰ = نامحدود" placeholder="0 = ∞"></div>
      <div class="fg" style="max-width:100px"><label class="fl" data-en="Unit" data-fa="واحد">Unit</label><select classmax-width:100px"><label class="fl" data-en="Unit" data-fa="واحد">Unit</label><select:100px"><label class="fl" data-en="Unit" data-fa="واحد">Unit</label><select class-width:100px"><label class="fl" data-en="Unit" data-fa="واحد">Unit</label><select class"><option>GB</option></select></div>
    </div>
    <div class="fg"><label class="fl" data-en="Max IPs" data-fa="حداکثر آی‌پی">Max IPs</label><input class="fi" id="nc" type="number" min="0" data-ph-en="0 = ∞" data-ph-fa="۰ = نامحدود" placeholder="0 = ∞"></div>
   ="fs" id="nu"><option>GB</option></select></div>
    </div>
    <div class="fg"><label class="fl" data-en="Max IPs" data-fa="حداکثر آی‌پی">Max IPs</label><input class="fi" id="nc" type="number" min="0" data-ph-en="0 = ∞" data-ph-fa="۰ = نامحدود" placeholder="0 = ∞"></div>
    class="fs" id="nu"><option>GB</option></select></div>
    </div>
    <div class="fg"><label class="fl" data-en="Max IPs" data-fa="حداکثر آی‌پی">Max IPs</label><input class="fi" id="nc" type="number" min="0" data-ph-en="0 = ∞" data-ph-fa="۰ = نامحدود" placeholder="0="fs" id="nu"><option>GB</option></select></div>
    </div>
    <div class="fg"><label class="fl" data-en="Max IPs" data-fa="حداکثر آی‌پی">Max IPs</label><input class="fi" id="nc" type="number" min="0" data-ph-en="0 = ∞" data-ph-fa="۰ = نامحدود" placeholder="0 = ∞"></div>
   ="fs" id="nu"><option>GB</option></select></div>
    </div>
    <div class="fg"><label class="fl" data-en="Max IPs" data-fa="حداکثر آی‌پی">Max IPs</label><input class="fi" id="nc" type="number" min="0" data-ph-en="0 = ∞" data-ph-fa="۰ = نامحدود" placeholder="0 <div class="fg"><label class="fl" data-en="Days Valid" data <div class="fg"><label class="fl" data-en="Days Valid" data = ∞"></div>
    <div class="fg"><label class="fl" data-en="Days Valid" data-fa="روزهای <div class="fg"><label class="fl" data-en="Days Valid" data-fa="روزهای = ∞"></div>
    <div class="fg"><label class="fl" data-en="Days Valid" data-fa="روزهای اعتبار">Days Valid</label><input class="fi" id="nd" type="number" min="0-fa="روزهای اعتبار">Days Valid</label><input class="fi" id="nd" type="number" min="0-fa="روزهای اعتبار">Days Valid</label><input class="fi" id="nd" type="number" min="0 اعتبار">Days Valid</label><input class="fi" id="nd" type="number" min=" اعتبار">Days Valid</label><input class="fi" id="nd" type="number" min="0" data-ph-en="0 = No expiry" data-ph-fa="۰ = بدون انقضا" placeholder="0 = No expiry"></div" data-ph-en="0 = No expiry" data-ph-fa="۰ = بدون انقضا" placeholder="0 = No expiry"></div>
    <button class="btn btn-gold" onclick="createLink()" style="width:100%;just" data-ph-en="0 = No expiry" data-ph-fa="۰ = بدون انقضا" placeholder="0 = No expiry"></div>
    <button class="btn btn-gold" onclick="createLink()" style="width:100%;just" data-ph-en="0 = No expiry" data-ph-fa="۰ = بدون انقضا" placeholder="0 = No expiry"></div>
    <button class="btn btn-gold" onclick="createLink()" style="width:100%;just0" data-ph-en="0 = No expiry" data-ph-fa="۰ = بدون انقضا" placeholder="0 = No expiry"></div>
    <button class="btn btn-gold" onclick="createLink()" style="width:100%;justify-content:center;margin-top:12px>
    <button class="btn btn-gold" onclick="createLink()" style="width:100%;justify-content:center;margin-top:12px;paddingify-content:center;margin-top:12px;padding:12px;" data-en="CREATE" data-fa="ایجاد">CREATE</button>
  </div>
</div>

<div class="mo" id="mo-edit" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-edit').classList.remove('show')">✕</button>
    <div classify-content:center;margin-top:12px;padding:12px;" data-en="CREATE" data-fa="ایجاد">CREATE</button>
  </div>
</div>

<div class="mo" id="mo-edit" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-edit').classList.remove('show')">✕</ify-content:center;margin-top:12px;padding:12px;" data-en="CREATE" data-fa="ایجاد">CREATE</button>
  </div>
</div>

<div class="mo" id="mo-edit" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-edit').classList.remove('show')">✕</button>
    <;padding:12px;" data-en="CREATE" data-fa="ایجاد">CREATE</button>
  </div>
</div>

<div class="mo" id="mo-edit" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-edit').classList.remove('show')">✕</:12px;" data-en="CREATE" data-fa="ایجاد">CREATE</button>
  </div>
</div>

<div class="mo" id="mo-edit" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-edit').classList.remove('show')">✕</button>
    <div class="mo-title" id="et">EDIT INBOUND</div>
    <input type="hidden"button>
    <div class="mo-title" id="et">EDIT INBOUND</div>
   div class="mo-title" id="et">EDIT INBOUND</div>
   button>
    <div class="mo-title" id="et">EDIT INBOUND</div="mo-title" id="et">EDIT INBOUND</div>
    <input type="hidden" id="eu">
    <div class="fg"><label class="fl" data-en id="eu">
    <div class="fg"><label class="fl" data-en <input type="hidden" id="eu">
    <div class="fg"><label class="fl" data-en="Name" data <input type="hidden" id="eu">
    <div class="fg"><label class="fl" data-en="Name" data>
    <input type="hidden" id="eu">
    <div class="fg"><label class="fl" data-en="Name" data="Name" data-fa="نام">Name</label><input class="fi" id="en2" readonly style="="Name" data-fa="نام">Name</label><input class="fi" id="en2" readonly style="-fa="نام">Name</label><input class="fi" id="en2" readonly style="opacity:.5;cursor:not-allowed"></div>
    <div class="fr">
      <div class="fg"><label class="fl" data-en="Tra-fa="نام">Name</label><input class="fi" id="en2" readonly style="opacity:.5;cursor:not-allowed"></div>
    <div class="fr">
      <div class="fg"><label class="fl" data-en="Tra-fa="نام">Name</label><input class="fi" id="en2" readonly style="opacity:.5;cursor:not-allowed"></div>
    <div class="fr">
      <div class="fg"><label class="opacity:.5;cursor:not-allowed"></div>
    <div class="fr">
      <div class="fg"><label class="fl" data-en="Traffic Limitopacity:.5;cursor:not-allowed"></div>
    <div class="fr">
      <div class="fg"><label class="fl" data-en="Traffic Limit" data-fa="محدودیت ترافیک">Traffic Limit</label><input class="fi" id="el" type="number" min="0" step=".1" data-ph-en="0 = ∞" data-ph-fa="۰ = نامحدود" placeholder="0 = ∞"></div>
      <div class="fg" style="max-width:100px"><label class="fl" data-en="Unit" data-fa="واحد">Unit</ffic Limit" data-fa="محدودیت ترافیک">Traffic Limit</label><input class="fi" id="el" type="number" min="0" step=".1" data-ph-en="0 = ∞" data-ph-fa="۰ = نامحدود" placeholder="0 = ∞"></div>
      <div class="fg" style="max-width:100px"><label class="fl" data-en="Unit" data-fa="واحد">Unit</label><select class="fs" id="eu2fl" data-en="Traffic Limit" data-fa="محدودیت ترافیک">Traffic Limit</label><input class="fi" id="el" type="number" min="0" step=".1" data-ph-en="0 = ∞" data-ph-fa="۰ = نامحدود" placeholder="0 = ∞"></div>
      <div class="fg" style="max-width:100px"><label class="fl" data-en="Unit" data-fa="واحد">Unit</label><select class="fs" id="eu2" data-fa="محدودیت ترافیک">Traffic Limit</label><input class="fi" id="el" type="number" min="0" step=".1" data-ph-en="0 = ∞" data-ph-fa="۰ = نامحدود" placeholder="0 = ∞"></div>
      <div class="fg" style="max-width:100px"><label class="fl" data-en="Unit" data-fa="واحد">Unit</label><select class="fs" id="eu2ffic Limit" data-fa="محدودیت ترافیک">Traffic Limit</label><input class="fi" id="el" type="number" min="0" step=".1" data-ph-en="0 = ∞" data-ph-fa="۰ = نامحدود" placeholder="0 = ∞"></div>
      <div class="fg" style="max-width:100px"><label class="fl" data-en="Unit" data-fa="واحد">Unit</label><select class="fs" id="eu2label><select class="fs" id="eu2"><option>GB</option></select></div>
   "><option>GB</option></select></div>
   "><option>GB</option></select></div>
   "><option>GB</option></select></div>
    </div>
    <div class="fg"><label class="fl" data-en="Max IPs" data-fa="حداکثر آی‌پی">Max IP"><option>GB</option></select></div>
    </div>
    <div class="fg"><label class="fl" data-en="Max IPs" data-fa="حداکثر آی </div>
    <div class="fg"><label class="fl" data-en="Max IPs" data-fa="حداکثر آی‌پی">Max IP </div>
    <div class="fg"><label class="fl" data-en="Max IPs" data-fa="حداکثر آی‌پی">Max IP </div>
    <div class="fg"><label class="fl" data-en="Max IPs" data-fa="حداکثر آی‌پی">Max IPs</label><input class="fi" id="ec" type="number" min="0" data-ph-en="0 = ∞s</label><input class="fi" id="ec" type="number" min="0" data-ph-en="0 = ∞‌پی">Max IPs</label><input class="fi" id="ec" type="number" min="0" data-ph-ens</label><input class="fi" id="ec" type="number" min="0" data-ph-en="0 = ∞" data-ph-fa="۰ = نامحدود" placeholder="0 = ∞"></div>
   s</label><input class="fi" id="ec" type="number" min="0" data-ph-en="0 = ∞" data-ph-fa="۰ = نامحدود" placeholder="0 = ∞"></div>
   " data-ph-fa="۰ = نامحدود" placeholder="0 = ∞"></div>
   " data-ph-fa="۰ = نامحدود" placeholder="0 = ∞"></div>
   ="0 = ∞" data-ph-fa="۰ = نامحدود" placeholder="0 <div class="fg"><label class="fl" data-en="Extend Days" data-fa="افزایش روزها">Extend Days</label><input class="fi" id="ed" type="number" min="0" data-ph-en="0 = no change" data-ph-fa="۰ = بدون تغییر" placeholder="0 = no change"></div>
    <div style="display:flex;gap:10px;margin-top: <div class="fg"><label class="fl" data-en="Extend Days" data-fa="افزایش روزها">Extend Days</label><input class="fi" id="ed" type="number" min="0" data-ph-en="0 = no change" data-ph-fa="۰ = بدون تغییر" placeholder="0 = no change"></div>
    <div style="display:flex;gap:10px;margin-top: <div class="fg"><label class="fl" data-en="Extend Days" data-fa="افزایش روزها">Extend Days</label><input class="fi" id="ed" type="number" min="0" data-ph-en="0 = no change" data-ph-fa="۰ = بدون تغییر" placeholder="0 = no change"></div>
    <div style="display:flex;gap:10px;margin-top: <div class="fg"><label class="fl" data-en="Extend Days" data-fa="افزایش روزها">Extend Days</label><input class="fi" id="ed" type="number" min="0" data-ph-en="0 = no change" data-ph-fa="۰ = بدون تغییر" placeholder="0 = no change"></div>
    <div style="display:flex;gap:10px;margin-top: = ∞"></div>
    <div class="fg"><label class="fl" data-en="Extend Days" data-fa="افزایش روزها">Extend Days</label><input class="fi" id="ed" type="number" min="0" data-ph-en="0 = no change" data-ph-fa="۰ = بدون تغییر" placeholder="0 = no change"></div>
    <div style="display:flex;gap:10px;margin-top:16px">
      <button class="btn btn-gold" onclick="saveEdit()" style="flex:1;just16px">
      <button class="btn btn-gold" onclick="saveEdit()" style="flex:16px">
      <button class="btn btn-gold" onclick="saveEdit()" style="flex:1;just16px">
      <button class="btn btn-gold" onclick="saveEdit()" style="flex:1;justify16px">
      <button class="btn btn-gold" onclick="saveEdit()" style="flex:1;justify-content:center;padding:ify-content:center;padding:12px;" data-en="SAVE" data-fa="ذخیره">SAVE</button>
      <button class="btn btn-danger1;justify-content:center;padding:12px;" data-en="SAVE" data-fa="ذخیره">SAVE</button>
     ify-content:center;padding:12px;" data-en="SAVE" data-fa="ذخیره">SAVE</button>
      <button class="btn btn-danger-content:center;padding:12px;" data-en="SAVE" data-fa="ذخیره">SAVE</button>
      <button class="btn btn-danger12px;" data-en="SAVE" data-fa="ذخیره">SAVE</button>
      <button class="btn btn-danger" onclick="resetTraf()" style="padding:12px;" data-en="Reset Traffic" data-fa="بازنشانی" onclick="resetTraf()" style="padding:12px;" data-en="Reset Traffic" data-fa="بازنشانی ترافیک <button class="btn btn-danger" onclick="resetTraf()" style="padding:12px;" data-en="Reset Traffic" data-fa="باز" onclick="resetTraf()" style="padding:12px;" data-en="Reset Traffic" data-fa="بازنشانی ترافیک">Reset Traffic</button>
    </div>
  </div>
</div>

<div class="mo" id="mo-qr" onclick="if(event.target" onclick="resetTraf()" style="padding:12px;" data-en="Reset Traffic" data-fa="بازنشانی ترافیک ترافیک">Reset Traffic</button>
    </div>
  </div>
</div>

<div class="mo" id="mo-qr" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="mo-box" style="max-width:340px">
    <button class="mo-close" onclick="document.getElementById('mo-qr').classList.remove('show')">✕</button>
    <div class="mo-title" data-en="QR CODE" data-fa="کد QR">QR CODE</div>
    <div class="qr-box"><img">Reset Traffic</button>
    </div>
  </div>
</div>

<div class="mo" id="mo-qr" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="mo-box" styleنشانی ترافیک">Reset Traffic</button>
    </div>
  </div>
</div>

<div class="mo" id="mo-qr" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="mo-box" style="max-width:340px">
    <button class="mo-close" onclick="document.getElementById('mo-qr').classList.remove('show')">✕</button>
    <div class="mo-title" data-en="QR CODE" data-fa="کد QR">QR CODE</div>
   ===this)this.classList.remove('show')">
  <div class="mo-box" style="max-width:340px">
    <button class="mo-close" onclick="document.getElementById('mo-qr').classList.remove('show')">✕</button>
    <div class="mo-title" data-en="QR CODE" data-fa="کد QR">QR CODE</div>
    <div class="qr-box">Reset Traffic</button>
    </div>
  </div>
</div>

<div class="mo" id="mo-qr" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="mo id="qr-img" src="" alt="QR"></="max-width:340px">
    <button class="mo-close" onclick="document.getElementById('mo-qr').classList.remove('show')">✕</button>
    <div class="mo-title" data-en="QR CODE" data-fa="کد QR">QR CODE</div>
    <div class="qr-box"><img id="qr-img" src="" alt="QR"></ <div class="qr-box"><img id="qr-img" src="" alt="QR"></div>
    <div style"><img id="qr-img" src="" alt="QR"></div>
    <div style="display:flex;gap-box" style="max-width:340px">
    <button class="mo-close" onclick="document.getElementById('mo-qr').classList.remove('show')">✕</button>
    <div class="mo-title" data-en="QR CODE" data-fa="کد QR">QR CODE</div>
    <div class="qr-box"><img id="qr-img" src="" alt="QR"></div>
    <div style="display:flex;gapdiv>
    <div style="display:flex;gap:10px;margin-top:16px;justify-content:center">
      <button class="btn btn-gold btn-sm" onclick="dlQR()" style="div>
    <div style="display:flex;gap:10px;margin-top:16px;justify-content:center">
      <button class="btn btn-gold btn-sm" onclick="="display:flex;gap:10px;margin-top:16px;justify-content:center">
      <button class="btn btn-gold btn-sm" onclick="dlQR()" style=":10px;margin-top:16px;justify-content:center">
      <button class="btn btn-gold btn-sm" onclick=":10px;margin-top:16px;justify-content:center">
      <button class="btn btn-gold btn-sm" onclick="dlQR()" style="padding:10px 16px;" data-en="Download" data-fa="دانلود">Download</button>
padding:10px 16px;" data-en="Download" data-fa="دانلود">Download</button>
      <button class="btn btn-ghost btn-sm" onclick="document.getElementById('mo-qr').classList.remove('show')" style="padding:10px 16px;" data-en="Close" data-fa="بستنdlQR()" style="padding:10px 16px;" data-en="Download" data-fa="دانلود">Download</button>
      <button class="btn btn-ghost btn-sm" onclick="document.getElementById('mo-qr').classList.remove('show')" style="padding:10px 16px;" data-en="Close" data-fa="padding:10px 16px;" data-en="Download" data-fa="دانلود">Download</button>
      <button class="btn btn-ghost btn-sm" onclick="document.getElementById('mo-qr').classList.remove('show')" style="padding:10px 16px;" data-en="Close" data-fa="بستن">dlQR()" style="padding:10px 16px;" data-en="Download" data-fa="دانلود">Download</button>
      <button class="btn btn-ghost btn-sm" onclick="document.getElementById('mo-qr').classList.remove('show')" style="padding:10px 16px;" data-en="Close" data-fa="      <button class="btn btn-ghost btn-sm" onclick="document.getElementById('mo-qr').classList.remove('show')" style="padding:10px 16px;" data-en="Close" data-fa="بستن">Close</button>
    </div>
  </div>
</div>

<div class="mo" id="mo-addr" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-addr').classList.remove('show')">✕</button>
    <div class="mo-title" data-en="ADD CLEAN IP" data-fa="افزودن آی‌پی تمیز">ADD">Close</button>
    </div>
  </div>
</div>

<div class="mo" id="mo-addr" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-addr').classList.remove('show')">✕</button>
    <div class="mo-title" data-en="ADD CLEAN IP" data-fa="افزودن آی‌پی تمیز">ADDبستن">Close</button>
    </div>
  </div>
</div>

<div class="mo" id="mo-addr" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-addr').classList.remove('show')">✕</button>
    <div class="mo-title" data-en="ADD CLEAN IP" data-fa="افزودن آی‌Close</button>
    </div>
  </div>
</div>

<div class="mo" id="mo-addr" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-addr').classList.remove('show')">✕</button>
    <div class="mo-title" data-en="ADD CLEAN IP" data-fa="افزودن آی‌پی تمیز">ADDبستن">Close</button>
    </div>
  </div>
</div>

<div class="mo" id="mo-addr" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-addr').classList.remove('show')">✕</button>
    <div class="mo-title" data-en="ADD CLEAN IP" data-fa="افزودن آی‌ CLEAN IP</div>
    <div class="fg"><label class="fl" CLEAN IP</div>
    <div class="fg"><label class="fl"پی تمیز">ADD CLEAN IP</div>
    <div class="fg"><label class="fl" CLEAN IP</div>
    <div class="fg"><label class="fl" data-en="IPs / Domains (one per line)" data-fa="آی‌پی‌ها / دامنه‌ها (پی تمیز">ADD CLEAN IP</div>
    <div class="fg"><label class="fl" data-en="IPs / Domains (one per line)" data-fa="آی‌پی‌ها / دامنه‌ها (هر خط data-en="IPs / Domains (one per line)" data-fa="آی‌پی‌ها / دامنه‌ها (هر خط data-en="IPs / Domains (one per line)" data-fa="آی‌پی‌ها / دامنه‌ها (هر خط یک)">IPs / Domains (one per line)</label><textarea class="fi" id="na" rows="5" data-ph-en="8.8.8 data-en="IPs / Domains (one per line)" data-fa="آی‌پی‌ها / دامنه‌ها (هر خط یک)">IPs / Domains (one per line)</label><textarea class="fi" id="na" rows="5" data-ph-en="8.8.8هر خط یک)">IPs / Domains (one per line)</label><textarea class="fi" id="na" rows="5" data-ph-en="8.8.8 یک)">IPs / Domains (one per line)</label><textarea class="fi" id="na" rows="5" data-ph-en="8.8.8 یک)">IPs / Domains (one per line)</label><textarea class="fi" id="na" rows="5" data-ph-en="8.8.8.8&#10;example.com" data-ph-fa="۸.۸.۸.۸&#10;example.com" placeholder="8.8.8.8&#10;example.com" style="resize:vertical;font-family:monospace"></textarea></div>
    <button class="btn btn-gold" onclick="addAddrs()" style="width:100%;justify-content:center;margin-top:12px;padding:12px;" data-en="ADD ALL" data-fa="افزودن همه.8&#10;example.com" data-ph-fa="۸.۸.۸.۸&#10;example.com" placeholder="8.8.8.8&#10;example.com" style="resize:vertical;font-family:monospace"></textarea></div>
    <button class="btn btn-gold" onclick="addAddrs()" style="width:100%;justify-content:center;margin-top:12px;padding:12px;" data-en=".8&#10;example.com" data-ph-fa="۸.۸.۸.۸&#10;example.com" placeholder="8.8.8.8&#10;example.com" style="resize:vertical;font-family:monospace"></textarea></div>
    <button class="btn btn-gold" onclick="addAddrs()" style="width:100%;justify-content:center;margin-top:12px;padding:12px;" data-en="ADD ALL" data.8&#10;example.com" data-ph-fa="۸.۸.۸.۸&#10;example.com" placeholder="8.8.8.8&#10;example.com" style="resize:vertical;font-family:monospace"></textarea></div>
    <button class="btn btn-gold" onclick="addAddrs()" style="width:100%;justify-content:center;margin-top:12px;padding:12px;" data-en="ADD ALL" data-fa="افزودن همه.8&#10;example.com" data-ph-fa="۸.۸.۸.۸&#10;example.com" placeholder="8.8.8.8&#10;example.com" style="resize:vertical;font-family:monospace"></textarea></div>
    <button class="btn btn-gold" onclick="addAddrs()" style="width:100%;justify-content:center;margin-top:12px;padding:12px;" data-en="ADD ALL" data-fa">ADD ALL</button>
  </div>
</div>

<script>
function $(s){return document.querySelector(s);}
function $m(id){return document.getElementById(id);}
function esc(s){return String(sADD ALL" data-fa="افزودن همه">ADD ALL</button>
  </div>
</div>

<script>
function $(s){return document.querySelector(s);}
function $m(id){return document.getElementById(id-fa="افزودن همه">ADD ALL</button>
  </div>
</div>

<script>
function $(s){return document.querySelector(s);}
function $m(id){return document.getElementById(id">ADD ALL</button>
  </div>
</div>

<script>
function $(s){return document.querySelector(s);}
function $m(id){return document.getElementById(id="افزودن همه">ADD ALL</button>
  </div>
</div>

<script>
function $(s){return document.querySelector(s);}
function $m(id){return document.getElementById(id);}
function esc(s).replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

const langMap={
  en:{edit:'Edit',copy:'Copy',sub:'Sub',qr:'QR',del);}
function esc(s){return String(s).replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

const langMap={
  en:{edit:'Edit',copy);}
function esc(s){return String(s).replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

const langMap={
  en:{edit:'Edit',copy);}
function esc(s){return String(s).replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

const langMap={
  en:{edit:'Edit',copy){return String(s).replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

const langMap={
  en:{edit:'Edit',copy:'Copy',sub:'Sub:'Del'},
  fa:{edit:'ویرایش',copy:'کپی',sub:'اشتراک',qr:'QR',del:'حذف'}
};
function tr(key){return(langMap[lang]&&langMap[lang][key])||langMap['en'][key]||key:'Copy',sub:'Sub',qr:'QR',del:'Del'},
  fa:{edit:'ویرایش',copy:'کپی',sub:'اشتراک',qr:'QR',del:'حذف:'Copy',sub:'Sub',qr:'QR',del:'Del'},
  fa:{edit:'ویرایش',copy:'کپی',sub:'اشتراک',qr:'QR',del:'حذف'}
};
function tr(key){return(langMap[lang]&&langMap[lang][key])||langMap['en'][key]||key:'Copy',sub:'Sub',qr:'QR',del:'Del'},
  fa:{edit:'ویرایش',copy:'کپی',sub:'اشتراک',qr:'QR',del:'حذف'}
};
function tr(key){return(langMap[lang]&&langMap[lang][key])||langMap['en'][key]||key;}

let lang=localStorage.getItem('ll',qr:'QR',del:'Del'},
  fa:{edit:'ویرایش',copy:'کپی',sub:'اشتراک',qr:'QR',del:'حذف'}
};
function tr(key){return(langMap[lang]&&langMap[lang][key])||langMap['en'][key]||key;}

let lang=localStorage.getItem('ll')||'en';
let theme=local'}
};
function tr(key){return(langMap[lang]&&langMap[lang][key])||langMap['en'][key]||key;}

let lang=localStorage.getItem('ll')||'en';
let theme=local;}

let lang=localStorage.getItem('ll')||'en';
let theme=localStorage.getItem('theme')||'dark';
let allLinks=[];
let cf='all')||'en';
let theme=localStorage.getItem('theme')||'dark';
let allLinks=[];
let cf='all';
let;}

let lang=localStorage.getItem('ll')||'en';
let theme=localStorage.getItem('theme')||'dark';
let allLinks=[];
let cf='all';
letStorage.getItem('theme')||'dark';
let allLinks=[];
let cf='allStorage.getItem('theme')||'dark';
let allLinks=[];
let cf='all';
let sData={};
let tChart=null;
let allAddrs=[];
let isAuthenticated=false;

function setTheme(t){
  theme=t;
  if(t==='light')document.body.classList.add('light-mode');
  else document.body.classList';
let sData={};
let tChart=null;
let allAddrs=[];
let isAuthenticated=false;

function setTheme(t){
  theme=t;
  if(t==='light')document.body.classList.add('light-mode sData={};
let tChart=null;
let allAddrs=[];
let isAuthenticated=false;

function setTheme(t){
  theme=t;
  if(t==='light')document.body.classList.add('light-mode');
  else document.body.classList sData={};
let tChart=null;
let allAddrs=[];
let isAuthenticated=false;

function setTheme(t){
  theme=t;
  if(t==='light')document.body.classList.add('light-mode');
  else document.body.classList.remove('light-mode');
  localStorage.setItem('theme',t);
  const icon=t==='light'?'☀️':'🌙';
  const mb=$m('theme-btn-mob');
  const db=$m('theme-btn-desk');
  if(mb)mb.innerHTML=icon;
  if(db)db.innerHTML=icon+' Theme';
  updChartColors();
}
function toggleTheme(){setTheme(theme==='dark'?'light':'dark');}

function setLang(l){
  lang';
let sData={};
let tChart=null;
let allAddrs=[];
let isAuthenticated=false;

function setTheme(t){
  theme=t;
  if(t==='light')document.body.classList.add('light-mode');
  else document.body.classList.remove('light-mode');
  localStorage.setItem('theme',t);
  const icon=t==='light'?'☀️':'🌙';
  const mb=$m('theme-btn-mob');
  const db=$m('theme-btn-desk');
  if(mb)mb.innerHTML=icon;
  if(db)db.innerHTML=icon+' Theme';
  updChartColors();
}
function toggleTheme(){setTheme(theme==='dark'?'light':'dark');}

function setLang(l){
  lang.remove('light-mode');
  localStorage.setItem('theme',t);
  const icon=t==='light'?'☀️':'🌙';
  const mb=$m('theme-btn-mob');
  const db=$m('theme-btn-desk');
  if(mb)mb.innerHTML=icon;
  if(db)db.innerHTML=icon+' Theme';
  updChartColors();
}
function toggleTheme(){setTheme(theme==='dark'?'light':'dark');}

function setLang(l){
  lang');
  else document.body.classList.remove('light-mode');
  localStorage.setItem('theme',t);
  const icon=t==='light'?'☀️':'🌙';
  const mb=$m('theme-btn-mob');
  const db=$m('theme-btn-desk');
  if(mb)mb.innerHTML=icon;
  if(db)db.innerHTML=icon+' Theme';
  updChartColors();
}
function toggleTheme(){setTheme(theme==='dark'?'light':'dark');}

function.remove('light-mode');
  localStorage.setItem('theme',t);
  const icon=t==='light'?'☀️':'🌙';
  const mb=$m('theme-btn-mob');
  const db=$m('theme-btn-desk');
  if(mb)mb.innerHTML=icon;
  if(db)db.innerHTML=icon+' Theme';
  updChartColors();
}
function toggleTheme(){setTheme(theme==='dark'?'light':'dark');}

function setLang(l){
  lang=l;
  document.querySelectorAll('.lang-en').forEach(e=>e.classList.toggle('active',l==='en'));
  document.querySelectorAll('.lang-fa').forEach(e=>e.classList.toggle('=l;
  document.querySelectorAll('.lang-en').forEach(e=>e.classList.toggle('active',l==='en'));
  document.querySelectorAll('.lang-fa').forEach(e=>e.classList.toggle('active',l==='fa=l;
  document.querySelectorAll('.lang-en').forEach(e=>e.classList.toggle('active',l==='en'));
  document.querySelectorAll('.lang-fa').forEach(e=>e.classList.toggle('active',l==='fa setLang(l){
  lang=l;
  document.querySelectorAll('.lang-en').forEach(e=>e.classList.toggle('active',l==='en'));
  document.querySelectorAll('.lang-fa').forEach(e=>e.classList.toggle('active',l==='=l;
  document.querySelectorAll('.lang-en').forEach(e=>e.classList.toggle('active',l==='en'));
  document.querySelectorAll('.lang-fa').forEach(e=>e.classList.toggle('active',l==='faactive',l==='fa'));
  document.body.dir=l==='fa'?'rtl':'ltr';
  document.querySelectorAll('[data-en]').forEach(el=>{
    const v=el.getAttribute('data-'+l'));
  document.body.dir=l==='fa'?'rtl':'ltr';
  document.querySelectorAll('[data-en]').forEach(el=>{
    const v=el.getAttribute('data-'+l'));
  document.body.dir=l==='fa'?'rtl':'ltr';
  document.querySelectorAll('[data-en]').forEach(el=>{
    const v=el.getAttribute('data-'+lfa'));
  document.body.dir=l==='fa'?'rtl':'ltr';
  document.querySelectorAll('[data-en]').forEach(el=>{
    const v=el.getAttribute('data-'+l);
    if(v)el'));
  document.body.dir=l==='fa'?'rtl':'ltr';
  document.querySelectorAll('[data-en]').forEach(el=>{
    const v=el.getAttribute('data-'+l);
    if(v)el.textContent=v;
  });
  document.querySelectorAll('[data-ph-en]').forEach(el=>{
    const v=el.getAttribute('data-ph-'+l);
    if(v)el.placeholder=v);
    if(v)el.textContent=v;
  });
  document.querySelectorAll('[data-ph-en]').forEach(el=>{
    const v=el.getAttribute('data-ph-'+l);
    if(v)el.placeholder=v;
  });
  localStorage.setItem('ll',l);
  filterLinks();
}

async function checkAuth(){
  try{
    const r=await fetch('/api/me');
    const d=await r.json();
    if(d.authenticated){
      showDashboard();
    } else {
      showLogin();
    }
  } catch(e){);
    if(v)el.textContent=v;
  });
  document.querySelectorAll('[data-ph-en]').forEach(el=>{
    const v=el.getAttribute('data-ph-'+l);
    if(v)el.placeholder=v);
    if(v)el.textContent=v;
  });
  document.querySelectorAll('[data-ph-en]').forEach(el=>{
    const v=el.getAttribute('data-ph-'+l);
    if(v)el.placeholder=v;
  });
  localStorage.setItem('ll',l);
  filterLinks();
}

async function checkAuth(){
  try{
    const r=await fetch('/api/me');
    const d=await r.json();
    if(d.authenticated){
      showDashboard();
    } else {
      showLogin();
    }
  } catch(e){showLogin();}
}

function.textContent=v;
  });
  document.querySelectorAll('[data-ph-en]').forEach(el=>{
    const v=el.getAttribute('data-ph-'+l);
    if(v)el.placeholder=v;
  });
  localStorage.setItem('ll',l);
  filterLinks();
}

async function checkAuth(){
  try{
    const r=await fetch('/api/me');
    const d=await r.json();
    if(d.authenticated){
      showDashboard();
    } else {
      showLogin();
    }
  } catch(e){showLogin();}
}

function;
  });
  localStorage.setItem('ll',l);
  filterLinks();
}

async function checkAuth(){
  try{
    const r=await fetch('/api/me');
    const d=await r.json();
    if(d.authenticated){
      showDashboard();
    } else {
      showLogin();
    }
  } catch(e){showLogin();}
}

function showLogin(){
  isAuthenticated=false;
  $m('login-page').style.display='showLogin();}
}

function showLogin(){
  isAuthenticated=false;
  $m('login-page').style.display='';
  $m('dashboard-page').style.display='none';
}

function showDashboard(){
  isAuthenticated=true;
  $m(';
  });
  localStorage.setItem('ll',l);
  filterLinks();
}

async function checkAuth(){
  try{
    const r=await fetch('/api/me');
    const d=await r.json();
    if(d.authenticated){
      showDashboard();
    } else {
      showLogin();
    }
  } catch(e){showLogin();}
}

function showLogin(){
  isAuthenticated=false;
  $m('login-page').style.display='';
  $m('dashboard-page').style.display='none';
}

function showDashboard(){
  isAuthenticated=true;
  $m('login-page').style.display='none';
  $ showLogin(){
  isAuthenticated=false;
  $m('login-page').style.display='';
  $m('dashboard-page').style.display='none';
}

function showDashboard(){
  isAuthenticated=true;
  $ showLogin(){
  isAuthenticated=false;
  $m('login-page').style.display='';
  $m('dashboard-page').style.display='none';
}

function showDashboard(){
  isAuthenticated=true;
  $';
  $m('dashboard-page').style.display='none';
}

function showDashboard(){
  isAuthenticated=true;
  $m('login-page').style.display='none';
  $m('dashboard-page').style.display='';
  initChart();
  loadStats();
  loadLinks();
  loadAddrs();
}

async function doLogin(){
  const pw=$m('login-pw').value;
  $login-page').style.display='none';
  $m('dashboard-page').style.display='';
  initChart();
  loadStats();
  loadLinks();
  loadAddrs();
}

async function doLogin(){
  const pw=$m('login-pw').valuem('dashboard-page').style.display='';
  initChart();
  loadStats();
  loadLinks();
  loadAddrs();
}

async function doLogin(){
  const pw=$m('login-pw').value;
  $m('login-page').style.display='none';
  $m('dashboard-page').style.display='';
  initChart();
  loadStats();
  loadLinks();
  loadAddrs();
}

async function doLogin(){
  const pw=$m('login-pw').value;
  $m('login-err').style.display='none';
  try{
    const r=await fetch('/api/login',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({password:pw})
    });
    if(r.ok){
      $m('login-pw').value='';
      showDashboard();
    } else {
      $m('login-err').style.display='block';
    }
  } catch(e){$m('login-err').style.display='block';}
}

async functionm('login-page').style.display='none';
  $m('dashboard-page').style.display='';
  initChart();
  loadStats();
  loadLinks();
  loadAddrs();
}

async function doLogin(){
  const pw=$m('login-pw').value;
  $m('login-err').style.display='none';
  try{
    const r=await fetch('/api/login',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
     m('login-err').style.display='none';
  try{
    const r=await fetch('/api/login',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
     ;
  $m('login-err').style.display='none';
  try{
    const r=await fetch('/api/login',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({password:pw})
    });
    if(r.ok){
      $m('login-pw').value='';
      showDashboard();
    } else {
      $m('login-err').style.display='block';
    }
  } catch(e){$m('login-err').style.display='block';}
}

async function doLogout(){
  await fetch('/api/logout',m('login-err').style.display='none';
  try{
    const r=await fetch('/api/login',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({password:pw})
    });
    if(r.ok){
      $m('login-pw').value='';
      showDashboard();
    } else {
      $m('login-err').style.display='block';
    }
  } catch(e){$m('login-err').style.display='block';}
}

async function doLogout(){
  await fetch('/api/logout', doLogout(){
  await fetch('/api/logout',{method:'POST'});
  showLogin();
}

document.querySelectorAll('.nav-item[data-page]').forEach(el=>{
  el.addEventListener('click',()=>switchPage(el.dataset.page body:JSON.stringify({password:pw})
    });
    if(r.ok){
      $m('login-pw').value='';
      showDashboard();
    } else {
      $m('login-err').style.display='block';
    }
  } catch(e){$m('login-err').style.display='block';}
}

async function doLogout(){
  await fetch('/api/logout',{method:'POST'});
  showLogin();
}

document.querySelectorAll('.nav-item[data-page]').forEach(el=>{
  el.addEventListener('click',()=>switchPage(el.dataset.page body:JSON.stringify({password:pw})
    });
    if(r.ok){
      $m('login-pw').value='';
      showDashboard();
    } else {
      $m('login-err').style.display='block';
    }
  } catch(e){$m('login-err').style.display='block';}
}

async function doLogout(){
  await fetch('/api/logout',{method:'POST'});
  showLogin();
}

document.querySelectorAll('.nav-item[data-page]').forEach(el=>{
  el.addEventListener('click',()=>switchPage(el.dataset.page));
});

function switchPage(id{method:'POST'});
  showLogin();
}

document.querySelectorAll('.nav-item[data-page]').forEach(el=>{
  el.addEventListener('click',()=>switchPage(el.dataset.page));
});

function switchPage(id{method:'POST'});
  showLogin();
}

document.querySelectorAll('.nav-item[data-page]').forEach(el=>{
  el.addEventListener('click',()=>switchPage));
});

function switchPage(id){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  const target=$m('page-'+id);
  if(target)target.classList.add('active');
  document.querySelectorAll('.nav-item').forEach(n=>n));
});

function switchPage(id){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  const target=$m('page-'+id);
  if(target)target.classList.add('active');
  document.querySelectorAll('.nav-item').forEach(n){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  const target=$m('page-'+id);
  if(target)target.classList.add('active');
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.toggle('active',n.dataset.page===id));
}

function toast(msg,err=false){
  const t=$m('toast');
  t.textContent=msg;
  t.className='toast'+(err?' err':'')+' show';
  clearTimeout(t._hide);
  t._hide=setTimeout(()=>t.classList.remove('show'),3000);
}

function fmtB(b){
  if(!b||b===0)return'0 B';
  return b>=107374182){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  const target=$m('page-'+id);
  if(target)target.classList.add('active');
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.toggle('active',n.dataset.page===id));
}

function toast(msg,err=false){
  const t=$m('toast');
  t.textContent=msg;
  t.className='toast'+(err?' err':'')+' show';
  clearTimeout(t._hide);
  t._hide=setTimeout(()=>t.classList.remove('show'),3000);
}

function fmtB(b){
  if(!b||b===0)return'0 B';
  return b>=107374182(el.dataset.page));
});

function switchPage(id){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  const target=$m('page-'+id);
  if(target)target.classList.add('active');
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.toggle('active',n.dataset.page===id));
}

function toast(msg,err=false){
  const t=$m('toast');
  t.textContent=msg;
  t.className='toast'+(err?' err':'')+' show';
  clearTimeout(t._hide);
  t._hide=setTimeout(()=>t.classList.remove('show'),3000);
}

function fmtB(b){
  if(!b||b===0)return'0 B';
  return b>=107374182.classList.toggle('active',n.dataset.page===id));
}

function toast(msg,err=false){
  const t=$m('toast');
  t.textContent=msg;
  t.className='toast'+(err?' err':'')+' show';
  clearTimeout(t._hide);
  t._hide=setTimeout(()=>t.classList.remove('show'),3000);
}

function fmtB(b){
  if(!b||b===0)return'0 B';
  return b>=1073741824?(b/1073741824).toFixed(2)+' GB':
         b>=1048576?(b/104=>n.classList.toggle('active',n.dataset.page===id));
}

function toast(msg,err=false){
  const t=$m('toast');
  t.textContent=msg;
  t.className='toast'+(err?' err':'')+' show';
  clearTimeout(t._hide);
  t._hide=setTimeout(()=>t.classList.remove('show'),3000);
}

function fmtB(b){
  if(!b||b===0)return'0 B';
  return b>=1073741824?(b/1073741824).toFixed(2)+' GB':
         b>=1048576?(b/1044?(b/1073741824).toFixed(2)+' GB':
         b>=1048576?(b/1044?(b/1073741824).toFixed(2)+' GB':
         b>=1048576?(b/1048576).toFixed(8576).toFixed(2)+' MB':
        4?(b/1073741824).toFixed(2)+' GB':
         b>=1048576?(b/1048576).toFixed(2)+' MB':
         (b/1024).toFixed(1)+' KB';
}
function fmtLim(b){
  if(!b||b===0)return8576).toFixed(2)+' MB':
         (b/1024).toFixed(1)+' KB';
}
function fmtLim(b){
  if(!b||b===0)return8576).toFixed(2)+' MB':
         (b/1024).toFixed(1)+' KB';
}
function fmtLim(b){
  if(!b||b===0)return2)+' MB':
         (b/1024).toFixed(1)+' KB';
}
function fmtLim(b){
  if(!b||b===0)return (b/1024).toFixed(1)+' KB';
}
function fmtLim(b){
  if(!b||b===0)return'∞';
  const g=b/1073741824;
  return(g%1===0?g'∞';
  const g=b/1073741824;
  return(g%1===0?g.toFixed(0):g.toFixed(1))+''∞';
  const g=b/1073741824;
  return(g%1===0?g.toFixed(0):g.toFixed(1))+' GB';
}
function fmtExp(ea){
  if(!ea||ea===0)return'∞';
  const d=new Date(ea)-new Date();
  if(d<=0)return'Expired';
  const days=Math.floor(d/86400000);
  if(days>0)return days+'d';
  const hours=Math.floor(d/3600000);
  if'∞';
  const g=b/1073741824;
  return(g%1===0?g.toFixed(0):g.toFixed(1))+' GB';
}
function fmtExp(ea){
  if(!ea||ea===0)return'∞';
  const d=new Date(ea)-new Date();
  if(d'∞';
  const g=b/1073741824;
  return(g%1===0?g.toFixed(0):g.toFixed(1))+' GB';
}
function fmtExp(ea){
  if(!ea||ea===0)return'∞';
  const d=new Date(ea)-new Date();
  if(d<=0)return'Expired';
  const days=Math.floor(d/86400000);
  if(days>0)return days+'d';
  const hours=Math.floor(d/3600000);
  if.toFixed(0):g.toFixed(1))+' GB';
}
function fmtExp(ea){
  if(!ea||ea===0)return'∞';
  const d=new Date(ea)-new Date();
  if(d<=0)return'Expired';
  const days=Math.floor(d/86400000);
  if(days>0)return days+'d';
  const hours=Math.floor(d/3600000);
  if(hours>0)return GB';
}
function fmtExp(ea){
  if(!ea||ea===0)return'∞';
  const d=new Date(ea)-new Date();
  if(d<=0)return'Expired';
  const days=Math.floor(d/86400000);
  if(days>0)return days+'d';
  const hours=Math.floor(d/3600000);
  if(hours>0)return hours+'h';
  return Math.floor(d/60000)+'m<=0)return'Expired';
  const days=Math.floor(d/86400000);
  if(days>0)return days+'d';
  const hours=Math.floor(d/3600000);
  if(hours>0)return hours+'h';
  return Math.floor(d/60000)+'m';
}

function setFilter(filter(hours>0)return hours+'h';
  return Math.floor(d/60000)+'m';
}

function setFilter(filter hours+'h';
  return Math.floor(d/60000)+'m';
}

function setFilter(filter(hours>0)return hours+'h';
  return Math.floor(d/60000)+'m';
}

function setFilter(filter,el){
  cf=filter;
  document.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));
  if(el)el';
}

function setFilter(filter,el){
  cf=filter;
  document.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));
  if(el)el,el){
  cf=filter;
  document.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));
  if(el)el,el){
  cf=filter;
  document.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));
  if(el)el,el){
  cf=filter;
  document.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));
  if(el)el.classList.add('active');
  filterLinks();
}

function filterLinks(){
  const q=($m('srch')?.value||'').toLowerCase();
  let r=allLinks;
  if(cf==='active').classList.add('active');
  filterLinks();
}

function filterLinks(){
  const q=($m('srch')?.value||'').toLowerCase();
  let r=allLinks;
  if(cf==='active').classList.add('active');
  filterLinks();
}

function filterLinks(){
  const q=($m('srch')?.value||'').toLowerCase();
  let r=allLinks;
  if(cf==='active').classList.add('active');
  filterLinks();
}

function filterLinks(){
  const q=($m('srch')?.value||'').toLowerCase();
  let r=allLinks;
  if(cf==='active').classList.add('active');
  filterLinks();
}

function filterLinks(){
  const q=($m('srch')?.value||'').toLowerCase();
  let r=allLinks;
  ifr=r.filter(l=>l.active);
  else if(cf==='off')r=r.filter(l=>!l.active);
  if(q)r=r.filter(l=>r=r.filter(l=>l.active);
  else if(cf==='off')r=r.filter(l=>!l.active);
  if(q)r=r.filter(l=>l.active);
  else if(cf==='off')r=r.filter(l=>!l.active);
  if(q)r=r.filter(l=>lr=r.filter(l=>l.active);
  else if(cf==='off')r=r.filter(l=>!l.active);
  if(q)r=r.filter(l=>(cf==='active')r=r.filter(l=>l.active);
  else if(cf==='off')r=r.filter(l=>!l.active);
  if(q)r=r.filter(l=>ll.label.toLowerCase().includes(q)||l.uuid.toLowerCase().includes(q));
  renderLinks(r);
}

function renderLinks(links){
  const tb=$m('ltb');
  const em=$m('lempty');
  const mc=$m('mcards');
  if(!links||r=r.filter(l=>l.label.toLowerCase().includes(q)||l.uuid.toLowerCase().includes(q));
  renderLinks(r);
}

function renderLinks(links){
  const tb=$m('ltb');
  const em=$m('lempty');
  const mc=$m('mcards');
  if(!links||!links.length){
    tb.label.toLowerCase().includes(q)||l.uuid.toLowerCase().includes(q));
  renderLinks(r);
}

function renderLinks(links){
  const tb=$m('ltb');
  const em=$m('lempty');
  const mc=$m('mcards');
  if(!links||l.label.toLowerCase().includes(q)||l.uuid.toLowerCase().includes(q));
  renderLinks(r);
}

function renderLinks(links){
  const tb=$m('ltb');
  const em=$m('lempty');
  const mc=$m('mcards');
  if(!links||.label.toLowerCase().includes(q)||l.uuid.toLowerCase().includes(q));
  renderLinks(r);
}

function renderLinks(links){
  const tb=$m('ltb');
  const em=$m('lempty');
  const mc=$m('mcards');
  if(!links||!links.length){
    tb.innerHTML='';
    mc.innerHTML='';
    em.style.display='block';
.innerHTML='';
    mc.innerHTML='';
    em.style!links.length){
    tb.innerHTML='';
    mc.innerHTML='';
    em.style.display='block';
    const!links.length){
    tb.innerHTML='';
    mc.innerHTML='';
    em.style.display='block';
    const!links.length){
    tb.innerHTML='';
    mc.innerHTML='';
    em.style.display='block';
    const emptyText=em.getAttribute('data-'+    const emptyText=em.get.display='block';
    const emptyText=em emptyText=em.getAttribute('data-'+ emptyText=em.getAttribute('data-'+lang)||em.getAttribute('data-en')||'No inbounds found';
    em.textContent=emptyText;
    return;
  }
lang)||em.getAttribute('data-en')||'No inbounds found';
    em.textContent=emptyText;
    return;
  }
Attribute('data-'+lang)||em.getAttribute('data-en')||'No inbounds found';
    em.textContent=emptyText;
    return;
  }
.getAttribute('data-'+lang)||em.getAttribute('data-en')||'No inbounds found';
    em.textContent=emptyText;
    return;
  }
lang)||em.getAttribute('data-en')||'No inbounds found';
    em.textContent=emptyText;
    return;
  }
  em.style.display='none';
  let idx=links.length;
  const rows=links.map(l=>{
    const u=l.used_bytes||0;
    const lim=l.limit_bytes  em.style.display='none';
  let idx=links.length;
  const rows=links.map(l=>{
    const u=l.used_bytes||0;
    const lim=l.limit_bytes||0;
    const pct=lim>  em.style.display='none';
  let idx=links.length;
  const rows=links.map(l=>{
    const u=l.used_bytes||0;
    const lim=l.limit_bytes||0;
    const p  em.style.display='none';
  let idx=links.length;
  const rows=links.map(l=>{
    const u=l.used_bytes||0;
    const lim=l.limit_bytes||0;
    const p  em.style.display='none';
  let idx=links.length;
  const rows=links.map(l=>{
    const u=l.used_bytes||0;
    const lim=l.limit_bytes||0;
    const p||0;
    const pct=lim>0?Math.min(100,(u/lim)*100):00?Math.min(100,(u/lim)*100):0ct=lim>0?Math.min(100,(u/lim)*100):0;
    const col=pct>90?'var(--red)':pct>70?'var(--yellow)':'var(--primary)';
    const ex=fmtExp(l.expires_at);
    const ec=ex==='Expired'?'var(--red)':ex==='∞'?'var(--text3)':'var(--text2)';
    const i=idx--;
    const cc=l.current_connections||0ct=lim>0?Math.min(100,(u/lim)*100):0;
    const col=pct>90?'var(--red)':pct>70?'var(--yellow)':'var(--primary)';
    const ex=fmtExp(l.expires_at);
    const ec=ex==='Expired'?'var(--red)':ex==='∞'?'var(--text3)':'var(--text2)';
    const i=idx--;
    const cc=l.current_connections||0ct=lim>0?Math.min(100,(u/lim)*100):0;
    const col=pct>90?'var(--red)':pct>70?'var(--yellow)':'var(--primary)';
    const ex=fmtExp(l.expires_at);
    const ec=ex==='Expired'?'var(--red)':ex==='∞'?'var(--text3)':'var(--text2)';
    const i=idx--;
    const cc=l.current_connections||0;
    const col=pct>90?'var(--red)':pct>70?'var(--yellow)':'var(--primary)';
    const ex=fmtExp(l.expires_at);
    const ec=ex==='Expired'?'var(--red)':ex==='∞'?'var(--text3)':'var(--text2)';
    const i=idx--;
    const cc=l;
    const col=pct>90?'var(--red)':pct>70?'var(--yellow)':'var(--primary)';
    const ex=fmtExp(l.expires_at);
    const ec=ex==='Expired'?'var(--red)':ex==='∞'?'var(--text3)':'var(--text2)';
    const i=idx--;
    const cc=l.current_connections||0;
    const mc2=l.max_connections||0;
    return{l,p;
    const mc2=l.max_connections||0;
    return{l,pct,col,ex;
    const mc2=l.max_connections||0;
    return{l,pct,col,ex;
    const mc2=l.max_connections||0;
    return{l,pct,col,ex.current_connections||0;
    const mc2=l.max_connections||0;
    return{l,pct,col,ex,ec,i,cc,mc2,u,lim};
  });

  const editText=tr('edit');
  const copyText=tr('copy');
ct,col,ex,ec,i,cc,mc2,u,lim};
  });

  const editText=tr('edit');
  const copyText=tr('copy');
  const subText=tr('sub');
 ,ec,i,cc,mc2,u,lim};
  });

  const editText=tr('edit');
  const copyText=tr('copy');
,ec,i,cc,mc2,u,lim};
  });

  const editText=tr('edit');
  const copyText=tr('copy');
  const subText=tr('sub');
  const qrText=tr('qr');
  const delText=tr('del');

  tb.innerHTML=rows.map(r=>`<tr>
    <td style="color:var(--text,ec,i,cc,mc2,u,lim};
  });

  const editText=tr('edit');
  const copyText=tr('copy');
  const subText=tr('sub');
  const qrText=tr('qr');
  const delText=tr('del');

  tb.innerHTML=rows.map(r=>`<tr>
    <td style="color  const subText=tr('sub');
  const qrText=tr('qr');
  const delText=tr('del');

  tb.innerHTML=rows.map(r=>`<tr>
    <td style="color:var(--text3);font-size:10.5px">${r.i}</td>
    <td style="font-weight:600">${esc(r.l.label)}</td>
    <td><span class="tag tag-vless">${r.l.protocol.toUpperCase()}</span></td>
    <td><div class="pill"><span class="pill-used">${fmtB(r.u)}</span><div class="pill-bar"><div class="pill-fill" style="width:${r.p const qrText=tr('qr');
  const delText=tr('del');

  tb.innerHTML=rows.map(r=>`<tr>
    <td style="color:var(--text3);font-size:10.5px">${r.i}</td>
    <td style="font-weight:600">${esc(r.l.label)}</td>
    <td><span class="tag tag-vless">${r.l.protocol.toUpperCase()}</span></td>
    <td><div class="pill"><span class="pill-used">${fmtB(r.u)}</span><div class="pill-bar"><div class="pill-fill" style="width:${r.p  const subText=tr('sub');
  const qrText=tr('qr');
  const delText=tr('del');

  tb.innerHTML=rows.map(r=>`<tr>
    <td style="color:var(--text3);font-size:10.5px">${r.i}</td>
    <td style="font-weight:600">${esc(r.l.label)}</td>
    <td><span class="tag tag-vless">${r.l.protocol.toUpperCase()}</span></td>
    <td><div class="pill"><span class="pill-used">${fmtB(r.u)}</span><div class="pill-bar"><div class="pill-fill" style="width:${r.pct}%;background:${3);font-size:10.5px">${r.i}</td>
    <td style="font-weight:600">${esc(r.l.label)}</td>
    <td><span class="tag tag-vless">${r.l.protocol.toUpperCase()}</span></td>
    <td><div class="pill"><span class="pill-used">${fmtB(r.u)}</span><div class="pill-bar"><div class="pill-fill" style="width:${r.p:var(--text3);font-size:10.5px">${r.i}</td>
    <td style="font-weight:600">${esc(r.l.label)}</td>
    <td><span class="tag tag-vless">${r.l.protocol.toUpperCase()}</span></td>
    <td><div class="pill"><span class="pill-used">${fmtB(r.u)}</span><div class="pill-bar"><div class="pill-fill" style="width:${r.pct}%;background:${r.col}"></div></div><span class="pill-lim">${fmtLim(r.lim)}</span></ct}%;background:${r.col}"></div></div><span class="pill-lim">${fmtLim(r.lim)}</span></r.col}"></div></div><span class="pill-lim">${fmtLim(r.lim)}</span></ct}%;background:${r.col}"></div></div><span class="pill-lim">${fmtLim(r.lim)}</span></div></tdct}%;background:${r.col}"></div></div><span class="pill-lim">${fmtLim(r.lim)}</span></div></td>
    <td style="font-size:11px;font-weight:600;color:${r.mc2>0&&r.cc>=r.mcdiv></td>
    <td style="font-size:11px;font-weight:600;color:${r.mc2>0&&r.cc>=r.mcdiv></td>
    <td style="font-size:11px;font-weight:600;color:${r.mc2>0&&r.cc>=r.mc2?'var(--red)div></td>
    <td style="font-size:11px;font-weight:600;color:${r.mc2>0&&r.cc>=r.mc>
    <td style="font-size:11px;font-weight:600;color:${r.mc2>0&&r.cc>=r.mc2?'var(--red)':'var(--text2)'}">${r.cc}/${r.mc2||'∞'}</td>
    <td style="font-size:10.5px;font-weight:7002?'var(--red)':'var(--text2)'}">${r.cc}/${r.mc2||'∞'}</td>
    <td style="font-size:10.5px;font-weight:700;color2?'var(--red)':'var(--text2)'}">${r.cc}/${r.mc2||'∞'}</td>
    <td style="font-size:10.5px;font-weight:700;color':'var(--text2)'}">${r.cc}/${r.mc2||'∞'}</td>
    <td style="font-size:10.5px;font-weight:700;color:${r.ec}">${r.ex}</td>
    <td><span class="tag ${r.l.active?'tag-on':'tag-off'}">${r.l.active?'On':'Off'}</span></td>
    <td><div style="display:flex;gap:3px;align-items:center;flex-wrap:wrap">
      <button class="toggle ${r.l.active?'on':''}" data-uid="${r.l.uuid}" onclick="t2?'var(--red)':'var(--text2)'}">${r.cc}/${r.mc2||'∞'}</td>
    <td style="font-size:10.5px;font-weight:700;color:${r.ec}">${r.ex}</td>
    <td><span class="tag ${r.l.active?'tag-on':'tag-off'}">${r.l.active?'On':'Off'}</span></td>
    <td><div style="display:flex;gap:3px;align-items:center;flex-wrap:wrap">
      <button class="toggle ${r.l.active?'on':''}" data-uid="${r.l.uuid}" onclick="t;color:${r.ec}">${r.ex}</td>
    <td><span class="tag ${r.l.active?'tag-on':'tag-off'}">${r.l.active?'On':'Off'}</span></td>
    <td><div style="display:flex;gap:3px;align-items:center;flex-wrap:wrap">
      <button class="toggle ${r.l.active?'on':''}" data-uid="${r.l.uuid}" onclick="t:${r.ec}">${r.ex}</td>
    <td><span class="tag ${r.l.active?'tag-on':'tag-off'}">${r.l.active?'On':'Off'}</span></td>
    <td><div style="display:flex;gap:3px;align-items:center;flex-wrap:wrap">
      <button class="toggle ${r.l.active?'on':''}" data-uid="${r.l.uuid}" onclick="t:${r.ec}">${r.ex}</td>
    <td><span class="tag ${r.l.active?'tag-on':'tag-off'}">${r.l.active?'On':'Off'}</span></td>
    <td><div style="display:flex;gap:3px;align-items:center;flex-wrap:wrap">
      <button class="toggle ${r.l.active?'on':''}" data-uid="${r.l.uogLink(this)"></button>
      <button class="act-btn act-edit" onclick="ogLink(this)"></button>
      <button class="act-btn act-edit" onclick="showEditogLink(this)"></button>
      <button class="act-btn act-edit" onclick="showEditogLink(this)"></button>
      <button class="act-btn act-edit" onclick="showEdituid}" onclick="togLink(this)"></button>
      <button class="act-btn act-edit" onclick="showEditMo('${r.l.uuid}')">${editText}</button>
      <button class="act-btn act-copy" onclick="cpLink('${esc(r.lshowEditMo('${r.l.uuid}')">${editText}</button>
      <button class="act-btn act-copy" onclick="cpMo('${r.l.uuid}')">${editText}</button>
      <button class="act-btn act-copy" onclick="cpLink('${esc(r.lMo('${r.l.uuid}')">${editText}</button>
      <button class="act-btn act-copy" onclick="cpLink('${esc(r.lMo('${r.l.uuid}')">${editText}</button>
      <button class="act-btn act-copy" onclick="cpLink('${esc(r.l.vless_link||'')}')">${copyText}</button>
      <button class="act-btn act-sub" onclick="cpSub('${r.l.uuid}')">${subText}</button>
      <button class="act-btn act-qr" onclick="show.vless_link||'')}')">${copyText}</button>
      <button class="act-btn act-sub" onclick="cpSub('${r.l.uuid}')">${subText}</button>
      <button class="act-btn act-qr" onclick="showLink('${esc(r.l.vless_link||'')}')">${copyText}</button>
      <button class="act-btn act-sub" onclick="cpSub('${r.l.uuid}')">${subText}</button>
      <button class="act-btn act-qr" onclick="show.vless_link||'')}')">${copyText}</button>
      <button class="act-btn act-sub" onclick="cpSub('${r.l.uuid}')">${subText}</button>
      <button class="act-btn act-qr" onclick="showQR('${esc(r.l.vless_link||'')}')">${qrText}</button>
      <button class="act-btn act-del" onclick="delLink('${r.l.uuid}')">${delText}</button>
    </div></td>
  </tr>`).join('');

  mc.innerHTML=rows.map(r=>`<div class="m-card">
    <div class="m-card-hd">
      <div style="display.vless_link||'')}')">${copyText}</button>
      <button class="act-btn act-sub" onclick="cpSub('${r.l.uuid}')">${subText}</button>
      <button class="act-btn act-qr" onclick="showQR('${esc(r.l.vless_link||'')}')">${qrText}</button>
      <button class="act-btn act-del" onclick="delLink('${r.l.uuid}')">${delText}</button>
    </div></td>
  </tr>`).join('');

  mc.innerHTML=rows.map(r=>`<div class="m-card">
    <div class="m-card-hd">
      <div style="display:flex;align-itemsQR('${esc(r.l.vless_link||'')}')">${qrText}</button>
      <button class="act-btn act-del" onclick="delLink('${r.l.uuid}')">${delText}</button>
    </div></td>
  </tr>`).join('');

  mc.innerHTML=rows.map(r=>`<div class="m-card">
    <div class="m-card-hd">
      <div style="display:flex;align-items:QR('${esc(r.l.vless_link||'')}')">${qrText}</button>
      <button class="act-btn act-del" onclick="delLink('${r.l.uuid}')">${delText}</button>
    </div></td>
  </tr>`).join('');

  mc.innerHTML=rows.map(r=>`<div class="m-card">
    <div class="m-card-hd">
      <div style="display:flex;align-items:center;gap:7pxQR('${esc(r.l.vless_link||'')}')">${qrText}</button>
      <button class="act-btn act-del" onclick="delLink('${r.l.uuid}')">${delText}</button>
    </div></td>
  </tr>`).join('');

  mc.innerHTML=rows.map(r=>`<div class="m-card">
    <div class="m-card-hd">
      <div style="display:flex;:flex;align-items:center;gap:7px">
        <span style="font-size:11px;color:var(--text3)">#${r.i}</span>
       :center;gap:7px">
        <span style="font-size:11px;color:var(--text3)">#${rcenter;gap:7px">
        <span style="font-size:11px;color:var(--text3)">#${r.i}</span>
       ">
        <span style="font-size:11px;color:var(--text3)">#${r.i}</span>
        <span style="font-weight:600;font-size:14px">${esc(r.l.label)}</span>
        <span class="tag tag-vless">${r.l.protocol.toUpperCase()}</span>
      </div>
      <button class="togglealign-items:center;gap:7px">
        <span style="font-size:11px;color:var(--text3)">#${r.i}</span>
        <span style="font-weight:600;font-size:14px">${esc(r.l.label)}</span>
        <span class="tag tag-vless">${r.l.protocol.toUpperCase()}</span>
      </div>
      <button class="toggle <span style="font-weight:600;font-size:14px">${esc(r.l.label)}</span>
        <span class="tag tag-vless">${r.l.protocol.toUpperCase()}</span>
      </div>
      <button class="toggle.i}</span>
        <span style="font-weight:600;font-size:14px">${esc(r.l.label)}</span>
        <span class="tag tag-vless">${r.l.protocol.toUpperCase()}</span>
      </div>
      <button class="toggle ${r.l.active <span style="font-weight:600;font-size:14px">${esc(r.l.label)}</span>
        <span class="tag tag-vless">${r.l.protocol.toUpperCase()}</span>
      </div>
      <button class="toggle ${r.l.active ${r.l.active?'on':''}" data-uid="${r.l.uuid}" onclick="togLink(this)"></button>
    </div>
    <div class="pill"><span class="pill-used">${fmtB(r.u)}</span><div class="pill-bar"><div class="pill-fill" style="width:${r.pct}%;background:${r.col}"></div></div><span class ${r.l.active?'on':''}" data-uid="${r.l.uuid}" onclick="togLink(this)"></button>
    </div>
    <div class="pill"><span class="pill-used">${fmtB(r.u)}</span><div class="pill-bar"><div class="pill-fill" style="width:${r.pct}%;background:${r.col}"></div></div><span class="pill-lim">${fmtLim(r.lim)}</span></div>
    ${r.l.active?'on':''}" data-uid="${r.l.uuid}" onclick="togLink(this)"></button>
    </div>
    <div class="pill"><span class="pill-used">${fmtB(r.u)}</span><div class="pill-bar"><div class="pill-fill" style="width:${r.pct}%;background:${r.col}"></div></div><span class?'on':''}" data-uid="${r.l.uuid}" onclick="togLink(this)"></button>
    </div>
    <div class="pill"><span class="pill-used">${fmtB(r.u)}</span><div class="pill-bar"><div class="pill-fill" style="width:${r.pct}%;background:${r.col}"></div></div><span class="pill-lim">${fmtLim(r.lim)}</span></div>
    <div style="font-size:11.5px;color?'on':''}" data-uid="${r.l.uuid}" onclick="togLink(this)"></button>
    </div>
    <div class="pill"><span class="pill-used">${fmtB(r.u)}</span><div class="pill-bar"><div class="pill-fill" style="width:${r.pct}%;background:${r.col}"></div></div><span class="pill-lim">${fmtLim(r.lim)}</span></div>
    <div style="font-size:11.5px;color="pill-lim">${fmtLim(r.lim)}</span></div>
    <div style="font-size:11.5px;color:${r.ec <div style="font-size:11.5px;color:${r.ec="pill-lim">${fmtLim(r.lim)}</span></div>
    <div style="font-size:11.5px;color:${r.ec};margin-top:6px:${r.ec};margin-top:6px;font-weight:600">⏳ ${r.ex:${r.ec};margin-top:6px;font-weight:600">⏳ ${r.ex};margin-top:6px;font-weight:600">⏳ ${r.ex};margin-top:6px;font-weight:600">⏳ ${r.ex;font-weight:600">⏳ ${r.ex} · ${r.cc}/${r.mc2} · ${r.cc}/${r.mc2||'∞'} IPs</} · ${r.cc}/${r.mc2||'∞'} IPs</div>
    <div} · ${r.cc}/${r.mc2||'∞'} IPs</div>
    <div class="} · ${r.cc}/${r.mc2||'∞'} IPs</div>
    <div class="||'∞'} IPs</div>
    <div class="m-card-acts">
     div>
    <div class="m-card-acts">
      <button class="act-btn class="m-card-acts">
      <button class="act-btnm-card-acts">
      <button class="act-btn act-edit" onclick="showEditMo('${r.l.uuid}')">${editm-card-acts">
      <button class="act-btn act-edit" onclick="showEditMo('${r.l.uuid}')">${editText}</button>
      <button class="act-btn act-edit" onclick="showEditMo('${r.l.uuid}')">${edit act-edit" onclick="showEditMo('${r.l.uuid}')">${editText}</button>
      <button class="act-btn act act-edit" onclick="showEditMo('${r.l.uuid}')">${editText}</button>
      <button class="act-btn actText}</button>
      <button class="act-btn act-copy" onclick="cpLink('${esc(r.l.vless_link||'')}')">${copyText <button class="act-btn act-copy" onclick="cpLink('${esc(r.l.vless_link||'')}')">${copyText}</button>
      <button class="act-btn act-sub" onclick="cpSub('${r.l.uuid}')">${subText}</button>
      <button class="act-btn act-qr" onclick="showQR('${esc(r.l.vless_link||'')}')">${qrText}</button>
      <button class="act-btn act-delText}</button>
      <button class="act-btn act-copy" onclick="cpLink('${esc(r.l.vless_link||'')}')">${copyText-copy" onclick="cpLink('${esc(r.l.vless_link||'')}')">${copyText}</button>
      <button class="act-btn act-sub" onclick="cpSub('${r.l.uuid}')">${subText}</button>
      <button class="act-btn act-qr" onclick="showQR('${esc(r.l.vless_link||'')}')">${qrText}</button>
      <button class="act-btn act-del-copy" onclick="cpLink('${esc(r.l.vless_link||'')}')">${copyText}</button>
      <button class="act-btn act-sub" onclick="cpSub('${r.l.uuid}')">${subText}</button>
      <button class="act-btn act-qr" onclick="showQR('${esc(r.l.vless_link||'')}')">${qrText}</button>
      <button class="act-btn act-del}</button>
      <button class="act-btn act-sub" onclick="cpSub('${r.l.uuid}')">${subText}</button>
      <button class="act-btn act-qr" onclick="showQR('${esc(r.l.vless_link||'')}')">${qrText}</button>
      <button class="act-btn act-del" onclick="delLink('${r.l.uuid" onclick="delLink('${r.l.uuid}')">${delText}</button>
    </div}</button>
      <button class="act-btn act-sub" onclick="cpSub('${r.l.uuid}')">${subText}</button>
      <button class="act-btn act-qr" onclick="showQR('${esc(r.l.vless_link||'')}')">${qrText}</button>
      <button class="act-btn act-del" onclick="delLink('${r.l.uuid}')">${delText}</button" onclick="delLink('${r.l.uuid}')">${delText}</button>
   " onclick="delLink('${r.l.uuid}')">${delText}</button>
    </div}')">${delText}</button>
    </div>
  </div>`).join('');
}

async function tog>
  </div>`).join('');
}

async>
    </div>
  </div>`).join('');
}

async function togLink(el){
  const uid=el.dataset.uid;
  const l=allLinks.find(x=>x.uuid===uid);
  </div>
  </div>`).join('');
}

async function togLink(el){
  const uid=el.dataset.uid;
  const l=allLinks.find(x=>x.uuid===uid);
  if(!l)return;
>
  </div>`).join('');
}

async function togLink(el){
  const uid=el.dataset.uid;
  const l=allLinks.find(x=>x.uuid===uid);
  if(!l)return;
Link(el){
  const uid=el.dataset.uid;
  const l=allLinks.find(x=>x.uuid===uid);
  if(!l)return function togLink(el){
  const uid=el.dataset.uid;
  const l=allLinks.find(x=>x.uuid===uid);
  if(!l)return;
  const na=!l.active;
  try{
    const r=await fetch('/api/links/'+uid,{
      method:'PATCH',
      headers:{'Content-Type':'application/json if(!l)return;
  const na=!l.active;
  try{
    const r=await fetch('/api/links/'+uid,{
      method:'PATCH',
      headers:{'Content-Type':'application/json  const na=!l.active;
  try{
    const r=await fetch('/api/links/'+uid,{
      method:'PATCH',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({active:na})
    });
    if(!r.ok)throw new Error();
    l.active=na;
    filterLinks();
    loadStats();
  }catch(e){toast('Failed to toggle',true);}
}

async function qCreate(v,u){
  const ns=['Ali','Sara','Reza','Nima','Mina','Arash'];
  const n=ns[Math.floor  const na=!l.active;
  try{
    const r=await fetch('/api/links/'+uid,{
      method:'PATCH',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({active:na})
    });
    if(!r.ok)throw new Error();
    l.active=na;
    filterLinks();
    loadStats();
  }catch(e){toast('Failed to toggle',true);}
}

async function qCreate(v,u){
  const ns=['Ali','Sara','Reza','Nima','Mina','Arash'];
  const n=ns[Math.floor(Math.random()*ns;
  const na=!l.active;
  try{
    const r=await fetch('/api/links/'+uid,{
      method:'PATCH',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({active:na})
    });
    if(!r.ok)throw new Error();
    l.active=na;
    filterLinks();
    loadStats();
  }catch(e){toast('Failed to toggle',true);}
}

async function qCreate(v,u){
  const ns=['Ali','Sara','Reza','Nima','Mina','Arash'];
  const n=ns[Math.floor(Math.random()*'},
      body:JSON.stringify({active:na})
    });
    if(!r.ok)throw new Error();
    l.active=na;
    filterLinks();
    loadStats();
  }catch(e){toast('Failed to toggle',true);}
}

async function qCreate(v,u){
  const ns=['Ali','Sara','Reza','Nima','Mina','Arash'];
  const n=ns[Math.floor'},
      body:JSON.stringify({active:na})
    });
    if(!r.ok)throw new Error();
    l.active=na;
    filterLinks();
    loadStats();
  }catch(e){toast('Failed to toggle',true);}
}

async function qCreate(v,u){
  const ns=['Ali','Sara','Reza','Nima','Mina','Arash'];
  const n=ns[Math.floor(Math.random()*ns.length)]+'-'+Math.floor(Math.random()*ns.length)]+'-'+Math.floor(Math.random()*100);
  try{
.length)]+'-'+Math.floorns.length)]+'-'+Math.floor(Math.random()*100);
  try{
    const(Math.random()*ns.length)]+'-'+Math.floor(Math.random()*100);
  try{
    const r=await fetch('/api/links',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(Math.random()*100);
  try{
    const r=await fetch('/api/links',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({label:n,limit    const r=await fetch('/api/links',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({label:n,limit(Math.random()*100);
  try{
    const r=await fetch('/api/links',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({label:n,limit r=await fetch('/api/links',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({label:n,limit_value:v,limit_unit:u,protocol:'vless'})
    });
    if(!r.ok)throw new Error();
    toast('Created: '+n);
    await loadLinks();
    await loadStats({label:n,limit_value:v,limit_unit:u,protocol:'vless'})
    });
    if(!r.ok)throw new Error();
    toast('Created: '+n);
_value:v,limit_unit:u,protocol:'vless'})
    });
    if(!r.ok)throw new Error();
    toast('Created: '+n);
    await loadLinks();
   _value:v,limit_unit:u,protocol:'vless'})
    });
    if(!r.ok)throw new Error();
    toast('Created: '+n);
    await loadLinks();
    await loadStats();
  }catch(e){toast('Error creating link',true);}
}

function showAddMo(){$m('mo-add').classList.add('show');}

async function createLink(){
  const label=$m('nl').value.trim()||'New Link';
  if(!/^[a-zA-Z0-9\-_. ]+$/.test(label)){toast('Only English letters allowed',true);_value:v,limit_unit:u,protocol:'vless'})
    });
    if(!r.ok)throw new Error();
    toast('Created: '+n);
    await loadLinks();
    await loadStats();
  }catch(e){toast('Error creating link',true);}
}

function showAddMo(){$m('mo-add').classList.add('show');}

async function createLink(){
  const label=$m('nl').value.trim()||'New Link';
  if(!/^[a-zA-Z0-9\-_. ]+$/.test(label)){toast('Only English letters allowed',true);();
  }catch(e){toast('Error creating link',true);}
}

function showAddMo(){$m('mo-add').classList.add('show');}

async function createLink(){
  const label=$m('nl').value.trim()||'New Link';
  if(!/^[a-zA-Z0-9\-_. ]+$/.test(label)){toast('Only    await loadLinks();
    await loadStats();
  }catch(e){toast('Error creating link',true);}
}

function showAddMo(){$m('mo-add').classList.add('show');}

async function createLink(){
  const label=$m('nl').value.trim()||'New Link';
  if(!/^[a-zA-Z0-9\-_. ]+$/.test(label)){toast('Only English letters allowed',true); await loadStats();
  }catch(e){toast('Error creating link',true);}
}

function showAddMo(){$m('mo-add').classList.add('show');}

async function createLink(){
  const label=$m('nl').value.trim()||'New Link';
  if(!/^[a-zA-Z0-9\-_. ]+$/.test(label)){toast('Onlyreturn;}
  const protocol=$m('npro').value;
  const v=parseFloat($m('nv').return;}
  const protocol=$m('npro').value;
  const v=parseFloat($m('nv'). English letters allowed',true);return;}
  const protocol=$m('npro').value;
  const v=parsereturn;}
  const protocol=$m('npro').value;
  const v=parseFloat($m('nv').value)||0;
  const mc=parseInt($m('nc').value)||0;
  const days=parseInt($m('nd').value)||0 English letters allowed',true);return;}
  const protocol=$m('npro').value;
  const v=parseFloat($m('nv').value)||0;
  const mc=parseInt($m('nc').value)||0;
  const days=parseInt($m('nd').value)||0value)||0;
  const mc=parseInt($m('nc').value)||0;
  const days=parseInt($m('nd').value)||0value)||0;
  const mc=parseInt($m('nc').value)||0;
  const days=parseInt($m('nd').value)||0Float($m('nv').value)||0;
  const mc=parseInt($m('nc').value)||0;
  const days=parseInt($m(';
  try{
    const r=await fetch('/api;
  try{
    const r=await fetch('/api/links',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({label,protocol,;
  try{
    const r=await fetch('/api/links',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({label,protocol,limit_value:v,limit_unit;
  try{
    const r=await fetch('/api/links',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({label,protocol,limit_value:v,limit_unitnd').value)||0;
  try{
    const r=await fetch('/api/links',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({label,protocol,limit_value:v,limit_unit/links',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({label,protocol,limit_value:v,limit_unit:'GB',max_connections:mc,days_valid:days})
    });
    if(!r.ok)throw new Error();
    toast('Created');
    $m('nl').value='';$m('nv').value='';$m('nc').value='';$m('nd').value='';
    $m('mo-add').classList.remove('show');
    await loadLinks();
    await loadStats();
  }catch(e){toast('Error creating link',true);}
}

function showEditMo(uid){
  const l=allLinks.find(xlimit_value:v,limit_unit:'GB',max_connections:mc,days_valid:days})
    });
    if(!r.ok)throw new Error();
    toast('Created');
    $m('nl').value='';$m('nv').value='';$m('nc').value='';$m('nd').value='';
    $m('mo-add').classList.remove('show');
    await loadLinks();
    await loadStats();
  }catch(e){toast('Error creating link',true);}
}

function showEditMo(uid){
  const l=allLinks.find(x=>:'GB',max_connections:mc,days_valid:days})
    });
    if(!r.ok)throw new Error();
    toast('Created');
    $m('nl').value='';$m('nv').value='';$m('nc').value='';$m('nd').value='';
    $m('mo-add').classList.remove('show');
    await loadLinks();
    await loadStats();
  }catch(e){toast('Error creating link',true);}
}

function showEditMo(uid){
  const l:'GB',max_connections:mc,days_valid:days})
    });
    if(!r.ok)throw new Error();
    toast('Created');
    $m('nl').value='';$m('nv').value='';$m('nc').value='';$m('nd').value='';
    $m('mo-add').classList.remove('show');
    await loadLinks();
    await loadStats();
  }catch(e){toast('Error creating link',true);}
}

function showEditMo(uid){
  const l:'GB',max_connections:mc,days_valid:days})
    });
    if(!r.ok)throw new Error();
    toast('Created');
    $m('nl').value='';$m('nv').value='';$m('nc').value='';$m('nd').value='';
    $m('mo-add').classList.remove('show');
    await loadLinks();
    await loadStats();
  }catch(e){toast('Error creating link',true);}
}

function showEditMo(uid){
  const l==>x.uuid===uid);
  if(!l)return;
  $m('eu').value=uid;
 x.uuid===uid);
  if(!l)return;
  $m('eu').value=uid;
 =allLinks.find(x=>x.uuid===uid);
  if(!l)return;
  $m('eu').value=uid;
  $m('en2').=allLinks.find(x=>x.uuid===uid);
  if(!l)return;
  $m('eu').value=uid;
  $m('en2allLinks.find(x=>x.uuid===uid);
  if(!l)return;
  $m('eu').value=uid;
  $m('en2'). $m('en2').value=l.label;
  $ $m('en2').value=l.label;
  $m('el').value=l.limit_bytes>0?(l.limit_bytes/1073741824):'';
  $m('ec').value=l.label;
  $m('el').value=l.limit_bytes>0?(l.limit_bytes/1073741824):'';
  $m('ec').value=l.max_connections>0?l.max').value=l.label;
  $m('el').value=l.limit_bytes>0?(l.limit_bytes/1073741824):'';
  $m('ec').value=l.label;
  $m('el').value=l.limit_bytes>0?(l.limit_bytes/1073741824):'';
  $m('ec').value=l.max_connections>0?l.max_m('el').value=l.limit_bytes>0?(l.limit_bytes/1073741824):'';
  $m('ec').value=l.max_connections>0?l.max_connections:'';
  $m('ed').value='';
  $m('et').textContent=(lang==='fa'?'ویرایش: ':'EDIT: 'value=l.max_connections>0?l.max_connections:'';
  $m('ed').value='';
  $m('et').textContent=(lang==='fa'?'ویرایش: ':'EDIT: '_connections:'';
  $m('ed').value='';
  $m('et').textContent=(lang==='fa'?'ویرایش: ':'EDIT: 'value=l.max_connections>0?l.max_connections:'';
  $m('ed').value='';
  $m('et').textContent=(lang==='fa'?'ویرایش: ':'EDIT: 'connections:'';
  $m('ed').value='';
  $m('et').textContent=(lang==='fa'?'ویرایش: ':'EDIT: ')+l.label;
  $m('mo-edit').classList.add('show');
}

async function saveEdit(){
  const uid=$m('eu').value;
  const v=parseFloat($m('el').value)||0;
  const mc=parseInt($m('ec').value)||0;
  const days=parseInt($m('ed').value)||0;
  const body={limit_value:v,limit_unit:'GB',max_connections)+l.label;
  $m('mo-edit').classList.add('show');
}

async function saveEdit(){
  const uid=$m('eu').value;
  const v=parseFloat($m('el').value)||0;
  const mc=parseInt($m('ec').value)||0;
  const days=parseInt($m('ed').value)||0;
  const body={limit_value:v,limit_unit:'GB',max_connections)+l.label;
  $m('mo-edit').classList.add('show');
}

async function saveEdit(){
  const uid=$m('eu').value;
  const v=parseFloat($m('el').value)||0;
  const mc=parseInt($m('ec').value)||0;
  const days=parseInt($m('ed').value)||0;
  const body={limit_value:v,limit_unit:'GB',max_connections)+l.label;
  $m('mo-edit').classList.add('show');
}

async function saveEdit(){
  const uid=$m('eu').value;
  const v=parseFloat($m('el').value)||0;
  const mc=parseInt($m('ec').value)||0;
  const days=parseInt($m('ed').value)||0;
  const body={limit_value:v,limit_unit:'GB',max_connections)+l.label;
  $m('mo-edit').classList.add('show');
}

async function saveEdit(){
  const uid=$m('eu').value;
  const v=parseFloat($m('el').value)||0;
  const mc=parseInt($m('ec').value)||0;
  const days=parseInt($m('ed').value)||0;
  const body={limit_value:v,limit_unit:'GB',max_connections:mc};
  if(days>0)body.d:mc};
  if(days>0)body.days_valid=days;
  try{
    const r:mc};
  if(days>0)body.days_valid=days;
 :mc};
  if(days>0)body.days_valid=days;
  try{
    const r=:mc};
  if(days>0)body.days_valid=days;
  try{
    const r=ays_valid=days;
  try{
    const r=await fetch('/api/links/'+uid,{
      method:'PATCH',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(body)
    });
    if(!r.ok)=await fetch('/api/links/'+uid,{
      method:'PATCH',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(body)
    });
    if(!r.ok) try{
    const r=await fetch('/api/links/'+uid,{
      method:'PATCH',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(body)
    });
    if(!r.ok)await fetch('/api/links/'+uid,{
      method:'PATCH',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(body)
    });
    if(!r.ok)await fetch('/api/links/'+uid,{
      method:'PATCH',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(body)
    });
    if(!r.ok)throw new Error();
    toast('Updated');
    $m('mo-edit').classList.remove('show');
    await loadLinks();
  }catch(e){toast('Error updating',true);}
}

async function resetTrafthrow new Error();
    toast('Updated');
    $m('mo-edit').classList.remove('show');
    await loadLinks();
  }catch(e){toast('Error updating',true);}
}

async function resetTrafthrow new Error();
    toast('Updated');
    $m('mo-edit').classList.remove('show');
    await loadLinks();
  }catch(e){toast('Error updating',true);}
}

async function resetTrafthrow new Error();
    toast('Updated');
    $m('mo-edit').classList.remove('show');
    await loadLinks();
  }catch(e){toast('Error updating',true);}
}

async function resetTrafthrow new Error();
    toast('Updated');
    $m('mo-edit').classList.remove('show');
    await loadLinks();
  }catch(e){toast('Error updating',true);}
}

async function resetTraf(){
  const uid=$m('eu').value;
  if(!confirm('Reset traffic for this inbound?'))return;
  try{
    const r=await fetch('/api/links/'(){
  const uid=$m('eu').value;
  if(!confirm('Reset traffic for this inbound?'))return;
  try{
    const r=await fetch('/api/links/'(){
  const uid=$m('eu').value;
  if(!confirm('Reset traffic for this inbound?'))return;
  try{
    const r=await fetch('/api/links/'(){
  const uid=$m('eu').value;
  if(!confirm('Reset traffic for this inbound?'))return;
  try{
    const r=await fetch('/api/links/'(){
  const uid=$m('eu').value;
  if(!confirm('Reset traffic for this inbound?'))return;
  try{
    const r=await fetch('/api/links/'+uid,{
      method:'PATCH',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({reset_usage:true})
    });
    if(!r.ok)throw new Error();
    toast('Tra+uid,{
      method:'PATCH',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({reset_usage:true})
    });
    if(!r.ok)throw new Error();
    toast('+uid,{
      method:'PATCH',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({reset_usage:true})
    });
    if(!r.ok)throw new Error();
    toast+uid,{
      method:'PATCH',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({reset_usage:true})
    });
    if(!r.ok)throw new Error();
    toast('Tra+uid,{
      method:'PATCH',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({reset_usage:true})
    });
    if(!r.ok)throw new Error();
    toast('Traffic reset');
    await loadLinks();
  }catch(e){toast('Error resetting',true);}
}

async function delLink(uid){
  if(!confirm('Delete this inbound?'))return;
  try{
    const r=await fetch('/api/links/'+uid,{method:'DELETE'});
    if(!r.ok)throw new Error();
    toast('Deleted');
    await loadLinks();
    await loadStats();
  }catch(e){toast('Error deleting',true);}
}

function cpLink(txt){
  if(!txt){toast('No link to copy',true);return;}
  navigator.clipboard.writeText(txt).then(()=>toast('Copied!')).catch(()=>toast('Failed to copy',true));
}

async function cpSub(uid){
  try{
    await navigator.clipboard.writeText('https://'+location.host+'/sub/'+uid);
    toast('Sub URL copied!');
  }catch(e){toast('Failed to copy',true);}
}

function showQR(txt){
  if(!txt){toast('No QR data',true);return;}
  $m('qr-img').src='https://api.qrserver.com/v1/create-qr-code/?size=280x280&data='+encodeURIComponent(txt);
  $m('mo-qr').classList.add('show');
}

function dlQR(){
  const a=document.createElement('a');
  a.href=$m('qr-img').src;
  a.download='v2render-qr.png';
  a.click();
}

async function loadStats(){
  try{
    const r=await fetch('/stats');
    if(r.status===401){showLogin();return;}
    if(!r.ok)throw new Error();
    sData=await r.json();
    $m('sv-traffic').innerHTML=(sData.total_traffic_mb||0)+'<span class="stat-unit"> MB</spanTraffic reset');
    await loadLinks();
  }catch(e){toast('Error resetting',true);}
}

async function delLink(uid){
  if(!confirm('Delete this inbound?'))return;
  try{
    const r=await fetch('/api/links/'+uid,{method:'DELETE'});
    if(!r.ok)throw new Error();
    toast('Deleted');
    await loadLinks();
    await loadStats();
  }catch(e){toast('Error deleting',true);}
}

function cpLink(txt){
  if(!txt){toast('No link to copy',true);return;}
  navigator.clipboard.writeText(txt).then(()=>toast('Copied!')).catch(()=>toast('Failed to copy',true));
}

async function cpSub(uid){
  try{
    await navigator.clipboard.writeText('https://'+location.host+'/sub/'+uid);
    toast('Sub URL copied!');
  }catch(e){toast('Failed to copy',true);}
}

function showQR(txt){
  if(!txt){toast('No QR data',true);return;}
  $m('qr-img').src='https://api.qrserver.com/v1/create-qr-code/?size=280x280&data='+encodeURIComponent(txt);
  $m('mo-qr').classList.add('show');
}

function dlQR(){
  const a=document.createElement('a');
  a.href=$m('qr-img').src;
  a.download='v2render-qr.png';
  a.click();
}

async function loadStats(){
  try{
    const r=await fetch('/stats');
    if(r.status===401){showLogin();return;}
    if(!r.ok)throw new Error();
    sData=await r.json();
    $m('sv-traffic').innerHTML=(sData.total_traffic_mb||0)+'<span class="stat-unit"> MB</span('Traffic reset');
    await loadLinks();
  }catch(e){toast('Error resetting',true);}
}

async function delLink(uid){
  if(!confirm('Delete this inbound?'))return;
  try{
    const r=await fetch('/api/links/'+uid,{method:'DELETE'});
    if(!r.ok)throw new Error();
    toast('Deleted');
    await loadLinks();
    await loadStats();
  }catch(e){toast('Error deleting',true);}
}

function cpLink(txt){
  if(!txt){toast('No link to copy',true);return;}
  navigator.clipboard.writeText(txt).then(()=>toast('Copied!')).catch(()=>toast('Failed to copy',true));
}

async function cpSub(uid){
  try{
    await navigator.clipboard.writeText('https://'+location.host+'/sub/'+uid);
    toast('Sub URL copied!');
  }catch(e){toast('Failed to copy',true);}
}

function showQR(txt){
  if(!txt){toast('No QR data',true);return;}
  $m('qr-img').src='https://api.qrserver.com/v1/create-qr-code/?size=280x280&data='+encodeURIComponent(txt);
  $m('mo-qr').classList.add('show');
}

function dlQR(){
  const a=document.createElement('a');
  a.href=$m('qr-img').src;
  a.download='v2render-qr.png';
  a.click();
}

async function loadStats(){
  try{
    const r=await fetch('/stats');
    if(r.status===401){showLogin();return;}
    if(!r.ok)throw new Error();
    sData=await r.json();
    $m('sv-traffic').innerHTML=(sData.total_traffic_mb||0)+'<span class="stat-unit"> MB</spanffic reset');
    await loadLinks();
  }catch(e){toast('Error resetting',true);}
}

async function delLink(uid){
  if(!confirm('Delete this inbound?'))return;
  try{
    const r=await fetch('/api/links/'+uid,{method:'DELETE'});
    if(!r.ok)throw new Error();
    toast('Deleted');
    await loadLinks();
    await loadStats();
  }catch(e){toast('Error deleting',true);}
}

function cpLink(txt){
  if(!txt){toast('No link to copy',true);return;}
  navigator.clipboard.writeText(txt).then(()=>toast('Copied!')).catch(()=>toast('Failed to copy',true));
}

async function cpSub(uid){
  try{
    await navigator.clipboard.writeText('https://'+location.host+'/sub/'+uid);
    toast('Sub URL copied!');
  }catch(e){toast('Failed to copy',true);}
}

function showQR(txt){
  if(!txt){toast('No QR data',true);return;}
  $m('qr-img').src='https://api.qrserver.com/v1/create-qr-code/?size=280x280&data='+encodeURIComponent(txt);
  $m('mo-qr').classList.add('show');
}

function dlQR(){
  const a=document.createElement('a');
  a.href=$m('qr-img').src;
  a.download='v2render-qr.png';
  a.click();
}

async function loadStats(){
  try{
    const r=await fetch('/stats');
    if(r.status===401){showLogin();return;}
    if(!r.ok)throw new Error();
    sData=await r.json();
    $m('sv-traffic').innerHTML=(sData.total_traffic_mb||0)+'<span class="stat-unit"> MB</spanffic reset');
    await loadLinks();
  }catch(e){toast('Error resetting',true);}
}

async function delLink(uid){
  if(!confirm('Delete this inbound?'))return;
  try{
    const r=await fetch('/api/links/'+uid,{method:'DELETE'});
    if(!r.ok)throw new Error();
    toast('Deleted');
    await loadLinks();
    await loadStats();
  }catch(e){toast('Error deleting',true);}
}

function cpLink(txt){
  if(!txt){toast('No link to copy',true);return;}
  navigator.clipboard.writeText(txt).then(()=>toast('Copied!')).catch(()=>toast('Failed to copy',true));
}

async function cpSub(uid){
  try{
    await navigator.clipboard.writeText('https://'+location.host+'/sub/'+uid);
    toast('Sub URL copied!');
  }catch(e){toast('Failed to copy',true);}
}

function showQR(txt){
  if(!txt){toast('No QR data',true);return;}
  $m('qr-img').src='https://api.qrserver.com/v1/create-qr-code/?size=280x280&data='+encodeURIComponent(txt);
  $m('mo-qr').classList.add('show');
}

function dlQR(){
  const a=document.createElement('a');
  a.href=$m('qr-img').src;
  a.download='v2render-qr.png';
  a.click();
}

async function loadStats(){
  try{
    const r=await fetch('/stats');
    if(r.status===401){showLogin();return;}
    if(!r.ok)throw new Error();
    sData=await r.json();
    $m('sv-traffic').innerHTML=(sData.total_traffic_mb||0)+'<span class=">';
    $m('sv-links').textContent=sData.links_count||0;
    $m('sv-uptime').textContent=sData.uptime||'–';
    $m('sv-domain').textContent=sData.domain||'–';
    $m>';
    $m('sv-links').textContent=sData.links_count||0;
    $m('sv-uptime').textContent=sData.uptime||'–';
    $m('sv-domain').textContent=sData.domain||'–';
    $m('nb').textContent=sData.l>';
    $m('sv-links').textContent=sData.links_count||0;
    $m('sv-uptime').textContent=sData.uptime||'–';
    $m('sv-domain').textContent=sData.domain||'–';
    $m('nb').textContent=sData.l>';
    $m('sv-links').textContent=sData.links_count||0;
    $m('sv-uptime').textContent=sData.uptime||'–';
    $m('sv-domain').textContent=sData.domain||'–';
    $m('nb').textContent=sData.lstat-unit"> MB</span>';
    $m('sv-links').textContent=sData.links_count||0;
    $m('sv-uptime').textContent=sData.uptime||'–';
    $m('sv-domain').textContent=sData.domain||'–';
    $m('nb').textContent=sData.links_count||0;
    $m('last-up').('nb').textContent=sData.links_count||0;
   inks_count||0;
    $m('last-up').inks_count||0;
    $m('last-up').inks_count||0;
    $m('last-up').textContent='Updated '+new Date().toLocaleTimeString();
    if($m('t-tr'))$m('t-tr').textContent=(sData.total $m('last-up').textContent='Updated '+new Date().toLocaleTimeString();
    if($m('t-tr'))$m('t-tr').textContent=(sData.totaltextContent='Updated '+new Date().toLocaleTimeString();
    if($m('t-tr'))$m('t-tr').textContent=(sData.totaltextContent='Updated '+new Date().toLocaleTimeString();
    if($m('t-tr'))$m('t-tr').textContent=(sData.totaltextContent='Updated '+new Date().toLocaleTimeString();
    if($m('t-tr'))$m('t-tr').textContent=(sData.total_traffic_mb||_traffic_mb||0)+' MB';
    if($m('t-rq'))$m('t-rq').textContent=(sData.total_requests||0).toLocaleString();
    if($m('t_traffic_mb||0)+' MB';
    if($m('t-rq'))$m('t-rq').textContent=(sData.total_requests||0).toLocaleString();
    if($m('t_traffic_mb||0)+' MB';
    if($m('t-rq'))$m('t-rq').textContent=(sData.total_requests||0).toLocaleString();
    if($m('t-up'))$m('t_traffic_mb||0)+' MB';
    if($m('t-rq'))$m('t-rq').textContent=(sData.total_requests||0).toLocaleString();
    if($m('t0)+' MB';
    if($m('t-rq'))$m('t-rq').textContent=(sData.total_requests||0).toLocaleString();
    if($m('t-up'))$m('t-up'))$m('t-up').textContent=sData.uptime||'–';
    if(sData.cpu_percent!==undefined){
      const c=sData.cpu_percent;
      const cc=c>80?'var(--red)':c>50?'var-up'))$m('t-up').textContent=sData.uptime||'–';
    if(sData.cpu_percent!==undefined){
      const c=sData.cpu_percent;
      const cc=c>80?'var(--red)':c>50?'var(--yellow)':'-up').textContent=sData.uptime||'–';
    if(sData.cpu_percent!==undefined){
      const c=sData.cpu_percent;
      const cc=c>80?'var(--red)':c>50?'var-up'))$m('t-up').textContent=sData.uptime||'–';
    if(sData.cpu_percent!==undefined){
      const c=sData.cpu_percent;
      const cc=c>80?'var(--red)':c>50?'var(--yellow)':'-up').textContent=sData.uptime||'–';
    if(sData.cpu_percent!==undefined){
      const c=sData.cpu_percent;
      const cc=c>80?'var(--red)':c>50?'var(--yellow)':'var(--primary)';
      $m('cpu-v').textContent=c.toFixed(1)+'%';
      $m('cpu-v').style.color=cc;
      $var(--primary)';
      $m('cpu-v').textContent=c.toFixed(1)+'%';
      $m('cpu-v').style.color=cc;
      $m('cpu-b').style(--yellow)':'var(--primary)';
      $m('cpu-v').textContent=c.toFixed(1)+'%';
      $m('cpu-v').style.color=cc;
      $m('cpu-b').stylevar(--primary)';
      $m('cpu-v').textContent=c.toFixed(1)+'%';
      $m('cpu-v').style.color=cc;
      $m('cpu-b').style.width=c+'%';
      $m('cpu-b').style.background=cc;
    }
    if(sData.memory_percent!==undefined){
      const m=sData.memory_percent;
      const mc=m(--yellow)':'var(--primary)';
      $m('cpu-v').textContent=c.toFixed(1)+'%';
      $m('cpu-v').style.color=cc;
      $m('cpu-b').style.width=c+'%';
      $m('cpu-b').style.background=cc;
    }
    if(sData.memory_percent!==undefined){
      const m=sData.memory_percent;
      const mc=m>80m('cpu-b').style.width=c+'%';
      $m('cpu-b').style.background=cc;
    }
    if(sData.memory_percent!==undefined){
      const m=sData.memory_percent;
.width=c+'%';
      $m('cpu-b').style.background=cc;
    }
    if(sData.memory_percent!==undefined){
      const m=sData.memory_percent;
      const mc=m>80?'var(--red)':m>50?'var(--yellow)':'var(--green)';
      $m('mem-v').textContent=m.toFixed(1)+'%';
      $m('mem-v').style.color=mc;
      $m('mem-b').style.width=m+'%';
      $m('mem-b').style.background=mc;
    }
    updChart();
  }catch(e){}
}

async function loadLinks(){
  try{
    const r=await fetch('/api/links');
.width=c+'%';
      $m('cpu-b').style.background=cc;
    }
    if(sData.memory_percent!==undefined){
      const m=sData.memory_percent;
      const mc=m>80?'var(--red)':m>50?'var(--yellow)':'var(--green)';
      $m('mem-v').textContent=m.toFixed(1)+'%';
      $m('mem-v').style.color=mc;
      $m('mem-b').style.width=m+'%';
      $m('mem-b').style.background=mc;
    }
    updChart();
  }catch(e){}
}

async function loadLinks(){
  try{
    const r=await fetch('/api/links');
>80?'var(--red)':m>50?'var(--yellow)':'var(--green)';
      $m('mem-v').textContent=m.toFixed(1)+'%';
      $m('mem-v').style.color=mc;
      $m('mem-b').style.width=m+'%';
      $m('mem-b').style.background=mc;
    }
    updChart();
  }catch(e){}
}

async function loadLinks(){
  try{
    const r=await fetch('/api/?'var(--red)':m>50?'var(--yellow)':'var(--green)';
      $m('mem-v').textContent=m.toFixed(1)+'%';
      $m('mem-v').style.color=mc;
      $m('mem-b').style.width=m+'%';
      $m('mem-b').style.background=mc;
    }
    updChart();
  }catch(e){}
}

async function loadLinks(){
  try{
    const r=await fetch('/api/links');
      const mc=m>80?'var(--red)':m>50?'var(--yellow)':'var(--green)';
      $m('mem-v').textContent=m.toFixed(1)+'%';
      $m('mem-v').style.color=mc;
      $m('mem-b').style.width=m+'%';
      $m('mem-b').style.background=mc;
    }
    updChart();
  }catch(e){}
}

async function loadLinks(){
  try{
    const r=await fetch('/api/links');
    if    if(r.status===401){showLogin();return;}
    if(!r.ok)throw new Error    if(r.status===401){showLogin();return;}
    if(!r.ok)throw new Errorlinks');
    if(r.status===401){showLogin();return;}
    if(!    if(r.status===401){showLogin();return;}
    if(!r.ok)throw new Error();
    const d=await(r.status===401){showLogin();return;}
    if(!r.ok)throw new Error();
    const d=await r.json();
    allLinks=d.links||[];
    filterLinks();
  }catch(e){}
}

async function chgPw(){
  const cur=$m();
    const d=await r.json();
    allLinks=d.links||[];
    filterLinks();
  }catch(e){}
}

async function chgPw(){
  const cur();
    const d=await r.json();
    allLinks=d.links||[];
    filterLinks();
  }catch(e){}
}

async function chgPw(){
  const curr.ok)throw new Error();
    const d=await r.json();
    allLinks=d.links||[];
    filterLinks();
  }catch(e){}
}

async function chgPw(){
  const cur r.json();
    allLinks=d.links||[];
    filterLinks();
  }catch(e){}
}

async function chgPw(){
  const cur=$m('cpw').value;
  const nw=$m('npw').value;
  if(!cur||!nw){toast('Fill all fields',true);('cpw').value;
  const nw=$m('npw').value;
  if(!cur||!nw){toast('Fill all fields',true);return;}
  if(nw=$m('cpw').value;
  const nw=$m('npw').value;
  if(!cur||!nw){toast('Fill all fields',true);=$m('cpw').value;
  const nw=$m('npw').value;
  if(!cur||!nw){toast('Fill all fields',true);return;}
  if(nw.length<4){toast('Password must be at least 4 characters',true);return;}
  try{
    const r=await fetch('/api/change-password',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({current_password:cur,new_password:nw})
    });
    if(!r.ok){
      const d=await r.json().catch(()=>({}));
      throw new Error(d.detail||'Error=$m('cpw').value;
  const nw=$m('npw').value;
  if(!cur||!nw){toast('Fill all fields',true);return;}
  if(nw.length<4){toast('Password must be at least 4 characters',true);return;}
  try{
    const r=await fetch('/api/change-password',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({current_password:cur,new_password:nw})
    });
    if(!r.ok){
      const d=await r.json().catch(()=>({}));
      throw new Error(d.detail||'Errorreturn;}
  if(nw.length<4){toast('Password must be at least 4 characters',true);return;}
  try{
    const r=await fetch('/api/change-password',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({current_password:cur,new_password:nw})
    });
    if(!r.ok){
      const d=await r.json().catch(()=>({}));
      throw new Error(d.detail||'Error changing password');
    }
   .length<4){toast('Password must be at least 4 characters',true);return;}
  try{
    const r=await fetch('/api/change-password',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({current_password:cur,new_password:nw})
    });
    if(!r.ok){
      const d=await r.json().catch(()=>({}));
      throw new Error(d.detail||'Error changing password');
    }
   return;}
  if(nw.length<4){toast('Password must be at least 4 characters',true);return;}
  try{
    const r=await fetch('/api/change-password',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({current_password:cur,new_password:nw})
    });
    if(!r.ok){
      const d=await r.json().catch(()=>({}));
      throw new Error(d.detail||'Error changing password');
    }
    toast('Password updated successfully');
    $m('cpw').value='';$m('npw').value='';
  changing password');
    }
    toast('Password updated successfully');
    $m('cpw').value='';$m('np toast('Password updated successfully');
    $m('cpw').value=' toast('Password updated successfully');
    $m('cpw').value='';$m('npw').value='';
  }catch(e){toast(e.message,true);}
}

function initChart(){
  const ctx=$m('tc');
  if(!ctx||tChart)return changing password');
    }
    toast('Password updated successfully');
    $m('cpw').value='';$m('npw').value='';
  }catch(e){toast(e.message,true);}
}

function initChart(){
  const ctx=$m('tc');
  if(!ctx||tChart)return;
  tChart=new Chart }catch(e){toast(e.message,true);}
}

function initChart(){
  const ctx=$m('tc');
  if(!ctx||tChart)return;
  tChart=new Chartw').value='';
  }catch(e){toast(e.message,true);}
}

function initChart(){
  const ctx=$m('tc');
  if(!ctx||tChart)return;
  tChart=new Chart(ctx,{
    type:'bar',
    data:{
      labels:[],
      datasets:[{label:'MB',data:[],backgroundColor:'rgba(';$m('npw').value='';
  }catch(e){toast(e.message,true);}
}

function initChart(){
  const ctx=$m('tc');
  if(!ctx||tChart)return;
  tChart=new Chart(ctx,{
    type:'bar',
    data:{
      labels:[],
      datasets:[{label:'MB',data:[],backgroundColor:'rgba(;
  tChart=new Chart(ctx,{
    type:'bar',
    data:{
      labels:[],
      datasets:[{label:'MB',data:[],backgroundColor:'rgba(57,255,20,0.55)',borderColor:'#39ff14',borderWidth:1,borderRadius:4}]
    },
    options:{
      responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{
        x:{grid:{display:false},ticks:{color:'rgba(57,255,20,0.3)',font:{size:10}}},
        y:{grid:{color:'rgba(255,255,255,0.04)'},ticks:{color:'rgba((ctx,{
    type:'bar',
    data:{
      labels:[],
      datasets:[{label:'MB',data:[],backgroundColor:'rgba(57,255,20,0.55)',borderColor:'#39ff14',borderWidth:1,borderRadius:4}]
    },
    options:{
      responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false}},
(ctx,{
    type:'bar',
    data:{
      labels:[],
      datasets:[{label:'MB',data:[],backgroundColor:'rgba(57,255,20,0.55)',borderColor:'#39ff14',borderWidth:1,borderRadius:4}]
    },
    options:{
      responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false}},
57,255,20,0.55)',borderColor:'#39ff14',borderWidth:1,borderRadius:4}]
    },
    options:{
      responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false}},
57,255,20,0.55)',borderColor:'#39ff14',borderWidth:1,borderRadius:4}]
    },
    options:{
      responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false}},
57,255,20,0.3)',font:{size:10},callback:v=>v+'      scales:{
        x:{grid:{display:false},ticks:{color:'rgba(57,255,20,0.3)',font:{size:10}}},
        y:{grid:{color:'rgba(255,255,255,0.04)'},ticks:{color:'rgba(57,255,20,0.3)',font:{size:10},callback:v      scales:{
        x:{grid:{display:false},ticks:{color:'rgba(57,255,20,0.3)',font:{size:10}}},
        y:{grid:{color:'rgba(255,255,255,0.04)'},ticks:{color:'rgba(57,255,20,0.3)',font:{size:10},callback:v=>v+' MB'},beginAt      scales:{
        x:{grid:{display:false},ticks:{color:'rgba(57,255,20,0.3)',font:{size:10}}},
        y:{grid:{color:'rgba(255,255,255,0.04)'},ticks:{color:'rgba(57,255,20,0.3)',font:{size:10},callback:v=>v+' MB'},beginAtZero      scales:{
        x:{grid:{display:false},ticks:{color:'rgba(57,255,20,0.3)',font:{size:10}}},
        y:{grid:{color:'rgba(255,255,255,0.04)'},ticks:{color:'rgba(57,255,20,0.3)',font:{size:10},callback:v=>v+' MB'},beginAtZero MB'},beginAtZero=>v+' MB'},beginAtZero:true}
      }
    }
  });
  updChartZero:true}
      }
    }
  });
  updChart:true}
      }
    }
  });
  updChart:true}
      }
    }
  });
  updChartColors();
}

function updChartColors(){
  if(!tChart)return;
  const col=theme==='light'?'rgba(0,0,0,0.5)':'rgba:true}
      }
    }
  });
  updChartColors();
}

function updChartColors(){
  if(!tChart)return;
  const col=theme==='light'?'rgba(0,0,0,0.5)':'rgba(57,255,Colors();
}

function updChartColors(){
  if(!tChart)return;
  const col=theme==='light'?'rgba(0,0,0,0.5)':'rgba(57,255,20Colors();
}

function updChartColors(){
  if(!tChart)return;
  const col=theme==='light'?'rgba(0,0,0,0.5)':'rgba(57,255,Colors();
}

function updChartColors(){
  if(!tChart)return;
  const col=theme==='light'?'rgba(0,0,0,0.5)':'rgba(57,255,20,0.4)';
  const gridCol=theme==='light'?'rgba(0,0,0,0.08)':'rgba(255,255,255,0.06)';
  tChart.options.scales.x.ticks.color=col;
  tChart.options.scales.y.ticks.color=col;
  tChart.options.scales.y.grid.color=gridCol;
  tChart.update();
}

function updChart(){
  if(!tChart||!sData.hourly_traffic)(57,255,20,0.4)';
  const gridCol=theme==='light'?'rgba(0,0,0,0.08)':'rgba(255,255,255,0.06)';
  tChart.options.scales.x.ticks.color=col;
  tChart.options.scales.y.ticks.color=col;
  tChart.options.scales.y.grid.color=gridCol;
  tChart.update();
}

function updChart(){
  if(!tChart||!sData.hourly_traffic)20,0.4)';
  const gridCol=theme==='light'?'rgba(0,0,0,0.08)':'rgba(255,255,255,0.06)';
  tChart.options.scales.x.ticks.color=col;
  tChart.options.scales.y.ticks.color=col;
  tChart.options.scales.y.grid.color=gridCol;
  tChart.update();
}

function updChart(){
  if(!tChart||!sData.hourly_traffic)return;
  const entries=,0.4)';
  const gridCol=theme==='light'?'rgba(0,0,0,0.08)':'rgba(255,255,255,0.06)';
  tChart.options.scales.x.ticks.color=col;
  tChart.options.scales.y.ticks.color=col;
  tChart.options.scales.y.grid.color=gridCol;
  tChart.update();
}

function updChart(){
  if(!tChart||!sData.hourly_traffic)return;
  const entries=20,0.4)';
  const gridCol=theme==='light'?'rgba(0,0,0,0.08)':'rgba(255,255,255,0.06)';
  tChart.options.scales.x.ticks.color=col;
  tChart.options.scales.y.ticks.color=col;
  tChart.options.scales.y.grid.color=gridCol;
  tChart.update();
}

function updChart(){
  if(!tChart||!sData.hourly_traffic)return;
  const entries=return;
  const entries=Object.entries(sData.hreturn;
  const entries=Object.entries(sData.hourly_traffic)
    .sort((a,b)=>a[0].Object.entries(sData.hourly_traffic)
    .sort((a,b)=>a[0].Object.entries(sData.hourly_traffic)
    .sort((a,b)=>a[0].Object.entries(sData.hourly_traffic)
    .sort((a,b)=>a[0].localeCompare(b[0])).slice(-12);
  tChart.data.labels=entries.map(x=>x[0]);
  tChart.data.datasets[0].data=entries.map(x=>Math.round(x[1]/1048576));
  tChart.update();
}

async functionourly_traffic)
    .sort((a,b)=>a[0].localeCompare(b[0])).slice(-12);
  tChart.data.labels=entries.map(x=>x[0]);
  tChart.data.datasets[0].data=entries.map(x=>Math.round(x[1]/1048576));
 localeCompare(b[0])).slice(-12);
  tChart.data.labels=entries.map(x=>x[0]);
  tChart.data.datasets[0].data=entries.map(x=>Math.round(x[1]/1048576));
  tChart.update();
}

localeCompare(b[0])).slice(-12);
  tChart.data.labels=entries.map(x=>x[0]);
  tChart.data.datasets[0].data=entries.map(x=>Math.round(x[1]/1048576));
  tChart.update();
}

async functionlocaleCompare(b[0])).slice(-12);
  tChart.data.labels=entries.map(x=>x[0]);
  tChart.data.datasets[0].data=entries.map(x=>Math.round(x[1]/1048576));
  tChart.update();
}

async function loadAddrs(){
  try{
    const r=await fetch('/api/addresses');
    if(!r.ok)throw new Error();
    const d=await r.json();
    allAddrs=d.addresses||[];
    renderAddrs();
  }catch(e){}
}

function renderAddrs(){
  const el=$m('addr-list');
  if(!el)return;
  if(!allAddrs||!allAddrs.length){
    el.innerHTML='<div style="color:var(--text3);font-size:12px">No addresses added loadAddrs(){
  try{
    const r=await fetch('/api/addresses');
    if(!r.ok)throw new Error();
    const d=await r.json();
    allAddrs=d.addresses||[];
    renderAddrs();
  }catch(e){}
}

function renderAddrs(){
  const el=$m('addr-list');
  if(!el)return;
  if(!allAddrs||!allAddrs.length){
    el.innerHTML='<div style="color:var(--text3);font-size:12px">No addresses added</div>';
 tChart.update();
}

async function loadAddrs(){
  try{
    const r=await fetch('/api/addresses');
    if(!r.ok)throw new Error();
    const d=await r.json();
    allAddrs=d.addresses||[];
    renderAddrs();
  }catch(e){}
}

function renderAddrs(){
  const el=$m('addr-list');
  if(!el)return;
  if(!allAddrs||!allAddrs.length){
    el.innerHTML='<div style="color:var(--text3);font-size:12px">No addresses addedasync function loadAddrs(){
  try{
    const r=await fetch('/api/addresses');
    if(!r.ok)throw new Error();
    const d=await r.json();
    allAddrs=d.addresses||[];
    renderAddrs();
  }catch(e){}
}

function renderAddrs(){
  const el=$m('addr-list');
  if(!el)return;
  if(!allAddrs||!allAddrs.length){
    el.innerHTML='<div style="color:var(--text3);font-size:12px">No addresses added loadAddrs(){
  try{
    const r=await fetch('/api/addresses');
    if(!r.ok)throw new Error();
    const d=await r.json();
    allAddrs=d.addresses||[];
    renderAddrs();
  }catch(e){}
}

function renderAddrs(){
  const el=$m('addr-list');
  if(!el)return;
  if(!allAddrs||!allAddrs.length){
    el.innerHTML='<div style="color:var(--text3);font-size:12px">No addresses added</div>';
   </div>';
    return;
  }
  el.innerHTML=allAddrs.map((a,i)=>`<div style="display:flex;align-items:center;justify-content:space-between;padding    return;
  }
  el.innerHTML=allAddrs.map((a,i)=>`<div style="display:flex;align-items:center;justify-content:space-between;padding</div>';
    return;
  }
  el.innerHTML=allAddrs.map((a,i)=>`<div style="display:flex;align-items:center;justify-content:space-between;padding</div>';
    return;
  }
  el.innerHTML=allAddrs.map((a,i)=>`<div style="display:flex;align-items:center;justify-content:space-between;padding return;
  }
  el.innerHTML=allAddrs.map((a,i)=>`<div style="display:flex;align-items:center;justify-content:space-between;padding:12px 14px;background:var(--surface3);border:1px solid var(--border);border-radius:10px;margin-bottom:8px">
    <div style="display:flex;align-items::12px 14px;background:var(--surface3);border:1px solid var(--border);border-radius:10px;margin-bottom:8px">
    <div style="display:flex;align-items::12px 14px;background:var(--surface3);border:1px solid var(--border);border-radius:10px;margin-bottom:8px">
    <div style="display:flex;align-items::12px 14px;background:var(--surface3);border:1px solid var(--border);border-radius:10px;margin-bottom:8px">
    <div style="display:12px 14px;background:var(--surface3);border:1px solid var(--border);border-radius:10px;margin-bottom:8px">
    <div style="display:flex;aligncenter;gap:10px">
      <span style="color:var(--primary);font-size:16px">🌐</span>
      <div><div style="font-size:14px;font-weight:600">${esc(a)}</div><div style="font-size:11px;color:var(--text3);margin-top:2px;">Address #${i+1}</div></div>
    </div>
    <button class="act-btn act-del" onclick="delAddr(${i})">${tr('del')}</button>
  </div>`).join('');
}

function showAddcenter;gap:10px">
      <span style="color:var(--primary);font-size:16px">🌐</span>
      <div><div style="font-size:14px;font-weight:600">${esc(a)}</div><div style="font-size:11px;color:var(--text3);margin-top:2px;">Address #${i+1}</div></div>
    </div>
    <button class="act-btn act-del" onclick="delAddr(${i})">${tr('del')}</button>
  </div>`).join('');
}

function showAddcenter;gap:10px">
      <span style="color:var(--primary);font-size:16px">🌐</span>
      <div><div style="font-size:14px;font-weight:600">${esc(a)}</div><div style="font-size:11px;color:var(--text3);margin-top:2px;">Address #${i+1}</div></div>
    </div>
    <button class="act-btn act-del" onclick="delAddr(${i})">${tr('del')}</button>
  </div>`).join('');
}

function showAdd:flex;align-items:center;gap:10px">
      <span style="color:var(--primary);font-size:16px">🌐</span>
      <div><div style="font-size:14px;font-weight:600">${esc(a)}</div><div style="font-size:11px;color:var(--text3);margin-top:2px;">Address #${i+1}</div></div>
    </div>
    <button class="act-btn act-del" onclick="delAddr(${i})">${tr('del')}</button>
  </div>`).join('');
}

function showAdd-items:center;gap:10px">
      <span style="color:var(--primary);font-size:16px">🌐</span>
      <div><div style="font-size:14px;font-weight:600">${esc(a)}</div><div style="font-size:11px;color:var(--text3);margin-top:2px;">Address #${i+1}</div></div>
    </div>
    <button class="act-btn act-del" onclick="delAddr(${i})">${tr('del')}</button>
  </div>`).join('');
}

function showAddAddrMo(){$m('na').value='';AddrMo(){$m('na').value='';AddrMo(){$m('na').value='';AddrMo(){$m('na').value='';$m('mo-addr').classList.add('showAddrMo(){$m('na').value='';$m('mo-addr').classList.add('show$m('mo-addr').classList.add('show$m('mo-addr').classList.add('show$m('mo-addr').classList.add('show');}

async function addAddrs(){
  const lines');}

async function addAddrs(){
  const lines=($m('na').value||'').trim().split('\n').map(l=>l.trim()).filter(l=>l);
  let');}

async function addAddrs(){
  const lines=($m('na').value||'').trim().split('\n').map(l=>l.trim()).filter(l=>l);
  let');}

async function addAddrs(){
  const lines=($m('na').value||'').trim().split('\n').map(l=>l.trim()).filter(l=>l);
  let');}

async function addAddrs(){
  const lines=($m('na').value||'').trim().split('\n').map(l=>l.trim()).filter(l=>l);
  let=($m('na').value||'').trim().split('\n').map(l=>l.trim()).filter(l=>l);
  let ok=0,fail=0;
  for(const a of lines){
    if(!/^[a-zA-Z0-9\-_. ]+$/.test(a)){ ok=0,fail=0;
  for(const a of lines){
    if(!/^[a-zA-Z0-9\-_. ]+$/.test(a)){fail++;continue ok=0,fail=0;
  for(const a of lines){
    if(!/^[a-zA-Z0-9\-_. ]+$/.test(a)){fail++;continue ok=0,fail=0;
  for(const a of lines){
    if(!/^[a-zA-Z0-9\-_. ]+$/.test(a)){fail++;continue ok=0,fail=0;
  for(const a of lines){
    if(!/^[a-zA-Z0-9\-_. ]+$/.test(a)){fail++;continuefail++;continue;}
    try{
      const r=await fetch('/api/addresses',{
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({address:a})
      });
      if(r.ok)ok++;else fail++;
    };}
    try{
      const r=await fetch('/api/addresses',{
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({address:a})
      });
      if(r.ok)ok++;else fail++;
    };}
    try{
      const r=await fetch('/api/addresses',{
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({address:a})
      });
      if(r.ok)ok++;else fail++;
;}
    try{
      const r=await fetch('/api/addresses',{
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({address:a})
      });
      if(r.ok)ok++;else fail++;
    };}
    try{
      const r=await fetch('/api/addresses',{
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({address:a})
      });
      if(r.ok)ok++;else fail++;
    }catch(e){fail++;}
  }
  if(ok)toast('Added '+ok);
  if(fail)toast(fail+' failed',true);
  if(ok){$m('mo-addr').classList.remove('show');await loadAddrs();}
}

async function delAddrcatch(e){fail++;}
  }
  if(ok)toast('Added '+ok);
  if(fail)toast(fail+' failed',true);
  if(ok){$m('mo-addr').classList.remove('show');await loadAddrs();}
}

async function delAddr(i){
  if(!confirm    }catch(e){fail++;}
  }
  if(ok)toast('Added '+ok);
  if(fail)toast(fail+' failed',true);
  if(ok){$m('mo-addr').classList.remove('show');await loadAddrs();}
}

async function delAddr(i){
  ifcatch(e){fail++;}
  }
  if(ok)toast('Added '+ok);
  if(fail)toast(fail+' failed',true);
  if(ok){$m('mo-addr').classList.remove('show');await loadAddrs();}
}

async function delAddrcatch(e){fail++;}
  }
  if(ok)toast('Added '+ok);
  if(fail)toast(fail+' failed',true);
  if(ok){$m('mo-addr').classList.remove('show');await loadAddrs();}
}

async function delAddr(i){
  if(!confirm('Delete this address?'))return;
  try{
    const r=await fetch('/api/addresses/'+i,{method:'DELETE'});
    if(!r.ok)throw new Error();
    toast('Deleted');
    await(i){
  if(!confirm('Delete this address?'))return;
  try{
    const r=await fetch('/api/addresses/'+i,{method:'DELETE'});
    if(!r.ok)throw new Error();
    toast('Deleted');
    await loadAddrs();
  }catch(e){toast('Error deleting',true);}
}

setTheme(theme);
setLang(lang);
checkAuth();
let('Delete this address?'))return;
  try{
    const r=await fetch('/api/addresses/'+i,{method:'DELETE'});
    if(!r.ok)throw new Error();
    toast('Deleted');
    await loadAddrs();
  }catch(e){toast('Error deleting',true);}
}

setTheme(theme);
setLang(lang);
checkAuth();
let statsInterval=null;
function startPolling(){
  if(statsInterval)clearInterval(statsInterval);
  statsInterval=setInterval(function(){
    if(isAuthenticated){loadStats();loadLinks();}
  },12000);
}
startPolling();
</script>
</body(!confirm('Delete this address?'))return;
  try{
    const r=await fetch('/api/addresses/'+i,{method:'DELETE'});
    if(!r.ok)throw new Error();
    toast('Deleted');
    await loadAddrs();
  }catch(e){toast('Error deleting',true);}
}

setTheme(theme);
setLang(lang);
checkAuth();
let statsInterval=null;
function startPolling(){
  if(statsInterval)clearInterval(statsInterval);
  statsInterval=setInterval(function(){
    if(isAuthenticated){loadStats();loadLinks();}
  },12000);
}
startPolling();
</script>
</body(i){
  if(!confirm('Delete this address?'))return;
  try{
    const r=await fetch('/api/addresses/'+i,{method:'DELETE'});
    if(!r.ok)throw new Error();
    toast('Deleted');
    await loadAddrs();
  }catch(e){toast('Error deleting',true);}
}

setTheme(theme);
setLang(lang);
checkAuth();
let loadAddrs();
  }catch(e){toast('Error deleting',true);}
}

setTheme(theme);
setLang(lang);
checkAuth();
let statsInterval=null;
function startPolling(){
  if(statsInterval)clearInterval(statsInterval);
  statsInterval=setInterval(function(){
    if(isAuthenticated){loadStats();loadLinks();}
  },12000);
}
startPolling();
</script>
</body>
</html>"""

@app.get("/login", response_class=HTMLResponse statsInterval=null;
function startPolling(){
  if(statsInterval)clearInterval(statsInterval);
  statsInterval=setInterval(function(){
    if(isAuthenticated){loadStats();loadLinks();}
  },12000);
}
startPolling();
</script>
</body>
</html>"""

@app.get("/login", response_class=HTMLResponse>
</html>"""

@app.get("/login", response_class=HTMLResponse>
</html>"""

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    statsInterval=null;
function startPolling(){
  if(statsInterval)clearInterval(statsInterval);
  statsInterval=setInterval(function(){
    if(isAuthenticated){loadStats();loadLinks();}
  },12000);
}
startPolling();
</script>
</body>
</html>"""

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return HTMLResponse(content=P)
async def login_page(request: Request):
    return HTMLResponse(content=PANEL_HTML)
async def login_page(request: Request):
    return HTMLResponse(content=PANEL_HTML)
async def login_page(request: Request):
    return HTMLResponse(content=PANEL_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    return HTMLResponse(content=PANEL_HTML)

@app.get("/panel", response_class=HTMLResponse)
async def panel_page(request: Request):
 return HTMLResponse(content=PANEL_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    return HTMLResponse(content=PANEL_HTML)

@app.get("/panel", response_classANEL_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    return HTMLResponse(content=PANEL_HTML)

@app.get("/panel", response_class=HTMLResponse)
async def panel_page(request: Request):
    return HTMLResponse(content=PANEL_HTML)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=CONFIG["port"])
```)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    return HTMLResponse(content=PANEL_HTML)

@app.get("/panel", response_class=HTMLResponse)
async def panel_page(request: Request):
    return HTMLResponse(content=PANEL_HTML)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=CONFIG["port"])
```)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    return HTMLResponse(content=PANEL_HTML)

@app.get("/panel", response_class=HTMLResponse)
async def panel_page(request: Request):
    return HTMLResponse(content=PANEL_HTML)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=CONFIG["port"])
```    return HTMLResponse(content=PANEL_HTML)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=CONFIG["port"])
```=HTMLResponse)
async def panel_page(request: Request):
    return HTMLResponse(content=PANEL_HTML)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=CONFIG["port"])
