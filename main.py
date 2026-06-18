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
            "INSERT INTO links (uid, label, created_at, active) VALUES (?, ?, ?, 1)",
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

def generate_vless_link(uid: str, remark: str = "V2R", address: str = None) -> str:
    cache_key = f"{uid}:{remark}:{address}"
    cached = link_cache.get(cache_key)
    if cached and cached["expires"] > time.time():
        return cached["link"]
    domain = get_domain()
    addr = address if address else domain
    path = f"/ws/{uid}"
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "host": domain,
        "path": path,
        "sni": domain,
        "fp": "chrome",
        "alpn": "http/1.1"
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
    return {"service": "V2Render", "version": "7.0", "status": "active", "domain": get_domain()}

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
        "INSERT INTO links (uid, label, limit_bytes, max_connections, created_at, active, expires_at) VALUES (?, ?, ?, ?, ?, 1, ?)",
        (uid, label, limit_bytes, max_conn, now, expires_at)
    )
    return {
        "uuid": uid, "label": label,
        "limit_bytes": limit_bytes, "used_bytes": 0,
        "max_connections": max_conn, "active": True, "created_at": now,
        "expires_at": expires_at,
        "vless_link": generate_vless_link(uid, remark=f"V2R-{label}"),
    }

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    rows = await db_fetchall("SELECT * FROM links ORDER BY created_at DESC")
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

@app.patch("/api/links/{uid}")
async def toggle_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    link = await db_fetchone("SELECT * FROM links WHERE uid = ?", (uid,))
    if not link:
        raise HTTPException(status_code=404, detail="link not found")
    updates = {}
    if "active" in body:
        updates["active"] = int(body["active"])
    if "limit_value" in body:
        limit_value = float(body.get("limit_value") or 0)
        limit_unit = body.get("limit_unit") or "GB"
        updates["limit_bytes"] = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    if "reset_usage" in body and body["reset_usage"]:
        updates["used_bytes"] = 0
    if "label" in body:
        new_label = str(body["label"])[:60]
        if new_label != uid:
            existing = await db_fetchone("SELECT uid FROM links WHERE label = ? AND uid != ?", (new_label, uid))
            if existing:
                raise HTTPException(status_code=400, detail="Label already in use")
            updates["label"] = new_label
    if "max_connections" in body:
        mc = int(body["max_connections"] or 0)
        updates["max_connections"] = mc if mc >= 0 else 0
    if "days_valid" in body:
        try:
            dv = int(body["days_valid"])
            if dv > 0:
                updates["expires_at"] = (datetime.now(timezone.utc) + timedelta(days=dv)).isoformat()
            else:
                updates["expires_at"] = None
        except (ValueError, TypeError):
            pass
    if updates:
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [uid]
        await db_execute(f"UPDATE links SET {set_clause} WHERE uid = ?", tuple(values))
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    await db_execute("DELETE FROM links WHERE uid = ?", (uid,))
    await close_connections_for_link(uid)
    return {"ok": True}

@app.get("/api/addresses")
async def list_addresses(_=Depends(require_auth)):
    rows = await db_fetchall("SELECT address FROM custom_addresses")
    return {"addresses": [row["address"] for row in rows]}

@app.post("/api/addresses")
@limiter.limit("10/minute")
async def add_address(request: Request, _=Depends(require_auth)):
    body = await request.json()
    address = (body.get("address") or "").strip()
    if not address or not re.match(r'^[a-zA-Z0-9\-_. ]+$', address):
        raise HTTPException(status_code=400, detail="Invalid address format")
    try:
        await db_execute("INSERT INTO custom_addresses (address) VALUES (?)", (address,))
    except aiosqlite.IntegrityError:
        raise HTTPException(status_code=400, detail="Address already exists")
    return {"ok": True}

@app.delete("/api/addresses/{index}")
async def delete_address(index: int, _=Depends(require_auth)):
    rows = await db_fetchall("SELECT id, address FROM custom_addresses ORDER BY id")
    if 0 <= index < len(rows):
        address_id = rows[index]["id"]
        await db_execute("DELETE FROM custom_addresses WHERE id = ?", (address_id,))
    else:
        raise HTTPException(status_code=404, detail="Address not found")
    return {"ok": True}

@app.get("/sub/{uid}")
async def subscription_endpoint(uid: str):
    link = await db_fetchone("SELECT * FROM links WHERE uid = ?", (uid,))
    if not link or not link["active"]:
        raise HTTPException(status_code=404, detail="link not found or disabled")
    expires_at = parse_expires_at(link["expires_at"])
    if expires_at and expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="link expired")
    addresses_rows = await db_fetchall("SELECT address FROM custom_addresses")
    addresses = [row["address"] for row in addresses_rows]
    sub_content = generate_subscription_content(link, uid, addresses)
    encoded = base64.b64encode(sub_content.encode()).decode()
    total_bytes = link["limit_bytes"] if link["limit_bytes"] > 0 else UNLIMITED_QUOTA_BYTES
    expire_ts = 0
    if expires_at is not None:
        expire_ts = int(expires_at.timestamp())
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": 'attachment; filename="sub.txt"',
        "profile-update-interval": "6",
        "subscription-userinfo": f"upload={link['used_bytes']}; download=0; total={total_bytes}; expire={expire_ts}",
    }
    return Response(content=encoded, headers=headers)

def generate_subscription_content(link: dict, uid: str, addresses: list) -> str:
    used = link["used_bytes"]
    limit = link["limit_bytes"]
    expires_at_str = link.get("expires_at")
    usage_str = f"{_fmt_bytes(used)} / ∞" if limit == 0 else f"{_fmt_bytes(used)} / {_fmt_bytes(limit)}"
    secs_left = seconds_until_expiry(expires_at_str)
    if secs_left is None:
        expiry_str = "∞"
    elif secs_left == 0:
        expiry_str = "Expired"
    else:
        expiry_str = f"{secs_left // 86400} Days Left"
    status_node = generate_vless_link(uid, remark=f"📊 {usage_str} | ⏳ {expiry_str}", address="0.0.0.0")
    links_out = [status_node, generate_vless_link(uid, remark=f"V2R-{link['label']}-Server")]
    for i, addr in enumerate(addresses):
        links_out.append(generate_vless_link(uid, remark=f"V2R-{link['label']}-IP{i+1}", address=addr))
    return "\n".join(links_out)

def _fmt_bytes(b: int) -> str:
    if b >= 1_073_741_824: return f"{b / 1_073_741_824:.1f}GB"
    if b >= 1_048_576: return f"{b / 1_048_576:.1f}MB"
    return f"{b / 1024:.1f}KB"

# ── WebSocket tunnel ──────────────────────────────────────────────────────
RELAY_BUF = 64 * 1024

async def parse_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24:
        raise ValueError("chunk too small")
    pos = 1 + 16
    addon_len = first_chunk[pos]
    pos += 1 + addon_len
    command = first_chunk[pos]
    pos += 1
    port = int.from_bytes(first_chunk[pos:pos + 2], "big")
    pos += 2
    addr_type = first_chunk[pos]
    pos += 1
    if addr_type == 1:
        addr_bytes = first_chunk[pos:pos + 4]
        pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        domain_len = first_chunk[pos]
        pos += 1
        address = first_chunk[pos:pos + domain_len].decode("utf-8", errors="ignore")
        pos += domain_len
    elif addr_type == 3:
        addr_bytes = first_chunk[pos:pos + 16]
        pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown address type: {addr_type}")
    return command, address, port, first_chunk[pos:]

async def atomic_check_and_add_usage(uid: str, size: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute(
            "UPDATE links SET used_bytes = used_bytes + ? WHERE uid = ? AND (limit_bytes = 0 OR used_bytes + ? <= limit_bytes) AND active = 1",
            (size, uid, size)
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()

async def ws_to_tcp(websocket, writer, conn_id, link_uid):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data:
                continue
            size = len(data)
            if not await atomic_check_and_add_usage(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded")
                break
            stats["total_bytes"] += size
            stats["total_requests"] += 1
            async with connections_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += size
                    connections[conn_id]["last_active"] = time.time()
            hour = datetime.now(timezone.utc).strftime("%H:00")
            await db_execute(
                "INSERT INTO hourly_traffic (hour, bytes) VALUES (?, ?) ON CONFLICT(hour) DO UPDATE SET bytes = bytes + ?",
                (hour, size, size)
            )
            day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            await db_execute(
                "INSERT INTO daily_traffic (day, bytes) VALUES (?, ?) ON CONFLICT(day) DO UPDATE SET bytes = bytes + ?",
                (day, size, size)
            )
            try:
                writer.write(data)
                await writer.drain()
            except Exception:
                break
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"ws_to_tcp error conn={conn_id}: {e}", exc_info=True)
    finally:
        try:
            if writer and not writer.is_closing():
                writer.write_eof()
        except Exception:
            pass

async def tcp_to_ws(websocket, reader, conn_id, link_uid):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data:
                break
            size = len(data)
            if not await atomic_check_and_add_usage(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded")
                break
            stats["total_bytes"] += size
            async with connections_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += size
                    connections[conn_id]["last_active"] = time.time()
            hour = datetime.now(timezone.utc).strftime("%H:00")
            await db_execute(
                "INSERT INTO hourly_traffic (hour, bytes) VALUES (?, ?) ON CONFLICT(hour) DO UPDATE SET bytes = bytes + ?",
                (hour, size, size)
            )
            day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            await db_execute(
                "INSERT INTO daily_traffic (day, bytes) VALUES (?, ?) ON CONFLICT(day) DO UPDATE SET bytes = bytes + ?",
                (day, size, size)
            )
            try:
                await websocket.send_bytes((b"\x00\x00" + data) if first else data)
                first = False
            except Exception:
                break
    except Exception as e:
        logger.error(f"tcp_to_ws error conn={conn_id}: {e}", exc_info=True)

@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await websocket.accept()
    logger.info(f"WebSocket accepted for uuid={uuid}")
    writer = None
    conn_id = None
    client_ip = get_client_ip(websocket)
    try:
        link = await db_fetchone("SELECT * FROM links WHERE uid = ?", (uuid,))
        if not link or not link["active"]:
            logger.warning(f"Link {uuid} not found or disabled")
            await websocket.close(code=1008, reason="link not found or disabled")
            return
        max_conn = link["max_connections"]
        expires_at = parse_expires_at(link["expires_at"])
        if expires_at is not None and expires_at < datetime.now(timezone.utc):
            logger.warning(f"Link {uuid} expired")
            await websocket.close(code=1008, reason="link expired")
            return
        if max_conn > 0:
            current_conns = await count_connections_for_link(uuid)
            if current_conns >= max_conn:
                logger.warning(f"Link {uuid} connection limit reached")
                await websocket.close(code=1008, reason="connection limit reached")
                return

        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect":
            return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk:
            return

        try:
            command, address, port, initial_payload = await parse_vless_header(first_chunk)
            logger.info(f"VLESS header parsed: addr={address}:{port}, payload={len(initial_payload)} bytes")
        except ValueError as e:
            logger.warning(f"Invalid VLESS header from {client_ip}: {e}")
            await websocket.close(code=1008, reason="invalid header")
            return

        conn_id = secrets.token_urlsafe(8)
        now = time.time()
        async with connections_lock:
            connections[conn_id] = {
                "uuid": uuid, "ip": client_ip,
                "connected_at": datetime.now(timezone.utc).isoformat(),
                "bytes": 0, "last_active": now
            }
            connection_sockets[conn_id] = websocket
            link_ip_map[uuid].add(client_ip)

        size = len(first_chunk)
        stats["total_bytes"] += size
        stats["total_requests"] += 1
        await atomic_check_and_add_usage(uuid, size)

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port), timeout=10.0
        )

        if initial_payload:
            p_size = len(initial_payload)
            stats["total_bytes"] += p_size
            await atomic_check_and_add_usage(uuid, p_size)
            try:
                writer.write(initial_payload)
                await writer.drain()
            except Exception:
                pass

        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass

    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected by client {client_ip}")
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now(timezone.utc).isoformat()})
        logger.exception("WebSocket error")
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        if conn_id:
            async with connections_lock:
                info = connections.pop(conn_id, None)
                connection_sockets.pop(conn_id, None)
                if info:
                    uid = info.get("uuid")
                    ip = info.get("ip")
                    if uid and ip:
                        has_other = any(
                            c.get("uuid") == uid and c.get("ip") == ip
                            for c in connections.values()
                        )
                        if not has_other:
                            if uid in link_ip_map:
                                link_ip_map[uid].discard(ip)
                                if not link_ip_map[uid]:
                                    link_ip_map.pop(uid, None)

def get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if websocket.client:
        return websocket.client.host
    return "unknown"

# ── HTML Panel (V2Render v7 - refined for desktop, larger fonts, batch Clean IP, consistent layout) ─────
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
  --surface:#141414; --surface2:#1e1e1e; --surface3:#262626;
  --border:rgba(57,255,20,0.08); --border2:rgba(57,255,20,0.18);
  --text:#e0e0e0; --text2:#a0a0a0; --text3:#707070;
  --green:#4ade80; --green-dim:rgba(74,222,128,0.1);
  --red:#f87171; --red-dim:rgba(248,113,113,0.1);
  --yellow:#fbbf24;
  --nav-w:72px;
  --base-font:16px;
}
body.light-mode {
  --primary:#2e7d32; --primary-dim:rgba(46,125,50,0.15);
  --bg:#f5fff5; --bg2:#ffffff; --bg3:#e8f5e9;
  --surface:#ffffff; --surface2:#f1f8f1; --surface3:#e0f0e0;
  --border:rgba(0,0,0,0.08); --border2:rgba(0,0,0,0.16);
  --text:#1a1a1a; --text2:#4a4a4a; --text3:#888;
}
html{font-size:var(--base-font);}
body{font-family:'Inter','Vazirmatn',sans-serif;color:var(--text);display:flex;min-height:100vh;background:var(--bg);transition:background 0.3s,color 0.3s;}
body[dir="rtl"]{direction:rtl;text-align:right}
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-thumb{background:var(--primary-dim);border-radius:4px}
.bg-fixed{position:fixed;inset:0;z-index:0;pointer-events:none;background:radial-gradient(ellipse 70% 50% at 50% -10%,var(--primary-dim),transparent 60%)}
.grid-fixed{position:fixed;inset:0;z-index:0;pointer-events:none;background-image:linear-gradient(rgba(128,128,128,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(128,128,128,0.03) 1px,transparent 1px);background-size:56px 56px}
.sidebar{position:fixed;left:0;top:0;bottom:0;width:var(--nav-w);background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:100;transition:all .3s;backdrop-filter:blur(20px);}
.sidebar::after{content:'';position:absolute;top:0;right:0;bottom:0;width:1px;background:linear-gradient(180deg,transparent,var(--primary) 30%,var(--primary) 70%,transparent);opacity:0.3;}
.light-mode .sidebar::after{display:none;}
.sb-brand{padding:16px 0;display:flex;flex-direction:column;align-items:center;gap:4px;border-bottom:1px solid var(--border);flex-shrink:0}
.sb-logo{width:36px;height:36px;}
.sb-title{font-family:'Orbitron',sans-serif;font-size:0.7rem;letter-spacing:.15em;color:var(--primary);text-transform:uppercase;white-space:nowrap;overflow:hidden;margin-top:4px;}
.sb-nav{flex:1;display:flex;flex-direction:column;justify-content:flex-end;padding-bottom:12px;gap:4px;padding-left:8px;padding-right:8px}
.nav-item{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px;padding:10px 6px;border-radius:12px;color:var(--text3);cursor:pointer;transition:all .2s;border:1px solid transparent;background:none;width:100%;font-family:inherit;}
.nav-item:hover{color:var(--primary);border-color:var(--primary-dim);}
.nav-item.active{color:var(--primary);border-color:var(--primary-dim);background:var(--primary-dim);box-shadow:0 0 12px var(--primary-dim);}
.nav-icon{width:20px;height:20px;flex-shrink:0;transition:transform .2s}
.nav-item:hover .nav-icon,.nav-item.active .nav-icon{transform:scale(1.1)}
.nav-label{font-size:0.7rem;font-weight:600;letter-spacing:.05em;white-space:nowrap;overflow:hidden}
.nav-badge{position:absolute;top:4px;right:4px;background:var(--primary);color:#000;font-size:0.65rem;font-weight:800;min-width:16px;height:16px;border-radius:8px;display:flex;align-items:center;justify-content:center;padding:0 3px}
.sb-bottom{padding:8px;border-top:1px solid var(--border);display:flex;flex-direction:column;gap:6px;flex-shrink:0}
.lang-row{display:flex;gap:4px}
.lang-btn{flex:1;padding:5px 2px;border:1px solid var(--border);border-radius:7px;background:none;color:var(--text3);font-size:0.75rem;font-weight:700;cursor:pointer;transition:all .2s;font-family:inherit;letter-spacing:.05em}
.lang-btn.active{background:var(--primary-dim);border-color:var(--primary);color:var(--primary)}
.lang-btn:hover:not(.active){border-color:var(--primary-dim);color:var(--primary)}
.logout-btn{display:flex;align-items:center;justify-content:center;padding:7px;border:1px solid rgba(248,113,113,.15);border-radius:8px;background:rgba(248,113,113,.06);color:rgba(248,113,113,.6);cursor:pointer;transition:all .2s;font-size:0.8rem;gap:4px;font-weight:600;font-family:inherit}
.logout-btn:hover{background:rgba(248,113,113,.12);border-color:rgba(248,113,113,.3);color:var(--red)}
.theme-toggle{background:transparent;border:1px solid var(--border);color:var(--text3);border-radius:7px;padding:4px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all 0.2s;}
.theme-toggle:hover{background:var(--surface3);color:var(--primary);border-color:var(--primary);}
.main{margin-left:var(--nav-w);flex:1;padding:24px 28px 48px;min-height:100vh;position:relative;z-index:1}
.page{display:none;animation:pgIn .35s ease}
.page.active{display:block}
@keyframes pgIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
.page-header{margin-bottom:20px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px}
.page-title{font-size:1.3rem;font-weight:700;color:var(--primary);letter-spacing:.04em}
.page-title[data-fa]{font-family:'Vazirmatn';}
.page-sub{font-size:0.9rem;color:var(--text3);margin-top:3px}
.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px}
.stat-card{background:var(--surface2);border:1px solid var(--border);border-radius:12px;padding:18px;position:relative;overflow:hidden;transition:all .25s;animation:cIn .5s ease both}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--primary),transparent);opacity:0.3;}
.light-mode .stat-card::before{display:none;}
.stat-card:hover{border-color:var(--border2);transform:translateY(-2px);box-shadow:0 0 20px var(--primary-dim)}
@keyframes cIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
.stat-label{font-size:0.75rem;color:var(--text3);font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px}
.stat-val{font-size:1.5rem;font-weight:700;color:var(--text);letter-spacing:-.02em}
.stat-unit{font-size:0.8rem;font-weight:400;color:var(--text3)}
.card{background:var(--surface2);border:1px solid var(--border);border-radius:12px;padding:18px;margin-bottom:12px;position:relative;overflow:hidden;transition:all .25s;animation:cIn .5s ease both}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--primary),transparent);opacity:0.2;}
.light-mode .card::before{display:none;}
.card-hd{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}
.card-title{font-size:0.95rem;font-weight:600;color:var(--text);display:flex;align-items:center;gap:6px}
.chart-container{height:180px;width:100%}
.btn{font-family:inherit;font-size:0.9rem;font-weight:700;border-radius:8px;padding:8px 16px;cursor:pointer;display:inline-flex;align-items:center;gap:5px;border:none;transition:all .2s;letter-spacing:.03em}
.btn-gold{background:linear-gradient(135deg,#39ff14,#1a8c1a);color:#000;box-shadow:0 0 16px rgba(57,255,20,0.3)}
.btn-gold:hover{filter:brightness(1.2);transform:translateY(-1px);box-shadow:0 0 24px rgba(57,255,20,0.5)}
.btn-ghost{background:var(--surface3);color:var(--text);border:1px solid var(--border)}
.btn-danger{background:var(--red-dim);color:var(--red);border:1px solid rgba(248,113,113,.15)}
.btn-sm{padding:4px 10px;font-size:0.8rem}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.tbl-wrap{overflow-x:auto}
.tbl{width:100%;border-collapse:collapse}
.tbl th{text-align:left;font-size:0.75rem;font-weight:700;color:var(--text3);padding:10px 12px;text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid var(--border);background:var(--surface3)}
.tbl td{padding:10px 12px;border-bottom:1px solid var(--border);font-size:0.9rem;vertical-align:middle}
.tag{display:inline-flex;align-items:center;padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:800;letter-spacing:.05em;text-transform:uppercase}
.tag-vless{background:var(--primary-dim);color:var(--primary);border:1px solid var(--border)}
.tag-on{background:var(--green-dim);color:var(--green);border:1px solid rgba(74,222,128,.2)}
.tag-off{background:var(--red-dim);color:var(--red);border:1px solid rgba(248,113,113,.2)}
.pill{display:flex;align-items:center;gap:8px;font-size:0.85rem}
.pill-used{color:var(--text);font-weight:600}
.pill-bar{flex:1;height:4px;background:var(--border);border-radius:2px;min-width:40px}
.pill-fill{height:100%;border-radius:2px;transition:width .4s}
.pill-lim{color:var(--text3);font-size:0.75rem}
.toggle{width:34px;height:18px;border-radius:9px;background:var(--surface3);position:relative;cursor:pointer;transition:all .28s;border:1px solid var(--border);flex-shrink:0}
.toggle::after{content:'';position:absolute;width:12px;height:12px;border-radius:50%;background:var(--text3);top:2px;left:2px;transition:all .28s cubic-bezier(.4,0,.2,1)}
.toggle.on{background:var(--green);border-color:var(--green);box-shadow:0 0 10px rgba(74,222,128,.3)}
.toggle.on::after{left:18px;background:#fff}
.sys-bar{height:6px;background:var(--border);border-radius:3px;overflow:hidden}
.sys-fill{height:100%;border-radius:3px;transition:width .4s}
.sl-item{display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border)}
.sl-k{color:var(--text3);font-size:0.9rem}
.sl-v{color:var(--text);font-weight:600;font-size:0.9rem}
.fg{display:flex;flex-direction:column;gap:4px;margin-bottom:12px}
.fl{font-size:0.8rem;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:.08em}
.fi,.fs{padding:10px 12px;border-radius:8px;border:1px solid var(--border);font-family:inherit;font-size:0.9rem;outline:none;color:var(--text);background:var(--surface);transition:all .2s}
.fi:focus,.fs:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-dim)}
.fr{display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end}
.fr .fg{margin-bottom:0;flex:1;min-width:90px}
.act-btn{font-family:inherit;font-size:0.75rem;font-weight:700;border-radius:6px;padding:4px 8px;cursor:pointer;display:inline-flex;align-items:center;gap:3px;border:1px solid;transition:all .18s}
.act-copy{background:var(--primary-dim);color:var(--primary);border-color:var(--border)}
.act-sub{background:var(--green-dim);color:var(--green);border-color:rgba(74,222,128,.2)}
.act-qr{background:rgba(167,139,250,.1);color:#a78bfa;border-color:rgba(167,139,250,.2)}
.act-edit{background:rgba(251,191,36,.08);color:var(--yellow);border-color:rgba(251,191,36,.2)}
.act-del{background:var(--red-dim);color:var(--red);border-color:rgba(248,113,113,.18)}
.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%) translateY(16px);background:var(--surface);color:var(--text);border:1px solid var(--border2);border-radius:10px;padding:12px 24px;font-size:0.95rem;font-weight:600;opacity:0;transition:all .3s;z-index:999;backdrop-filter:blur(24px);box-shadow:0 0 20px var(--primary-dim)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.mo{position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:200;display:none;align-items:center;justify-content:center;backdrop-filter:blur(8px)}
.mo.show{display:flex}
.mo-box{background:var(--surface2);border:1px solid var(--border2);border-radius:18px;padding:28px;width:100%;max-width:480px;position:relative;box-shadow:0 0 30px var(--primary-dim);transform:scale(.92);opacity:0;transition:all .38s cubic-bezier(.34,1.56,.64,1)}
.mo.show .mo-box{transform:scale(1);opacity:1}
.mo-title{font-size:1.1rem;font-weight:700;margin-bottom:16px;color:var(--primary);letter-spacing:.06em}
.mo-title[data-fa]{font-family:'Vazirmatn';}
.mo-close{position:absolute;top:14px;right:14px;background:var(--surface3);border:1px solid var(--border);color:var(--text3);width:32px;height:32px;border-radius:8px;cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:16px;}
.qr-box{text-align:center;padding:20px;background:var(--surface3);border-radius:12px;border:1px solid var(--border);margin-top:12px}
.qr-box img{max-width:200px;border-radius:8px;border:3px solid var(--border);box-shadow:0 0 15px var(--primary-dim)}
.tb{display:flex;align-items:center;gap:8px;margin-bottom:16px;flex-wrap:wrap}
.search-wrap{flex:1;min-width:180px;position:relative}
.search-wrap svg{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--text3)}
.search-wrap input{width:100%;padding:10px 12px 10px 36px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:0.9rem;font-family:inherit;outline:none;}
.filter-chips{display:flex;gap:3px;padding:3px;background:var(--surface2);border:1px solid var(--border);border-radius:8px}
.chip{padding:7px 14px;border-radius:6px;font-size:0.85rem;font-weight:700;color:var(--text3);cursor:pointer;border:none;background:none;transition:all .18s;font-family:inherit}
.chip.active{background:var(--primary);color:#000}
.m-cards{display:none;flex-direction:column;gap:12px}
.m-card{border:1px solid var(--border);border-radius:12px;padding:18px;background:var(--surface2)}
.m-card-hd{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}
.m-card-acts{display:flex;gap:6px;flex-wrap:wrap;margin-top:12px}
.empty{text-align:center;padding:40px;color:var(--text3)}
.mob-hd{display:none;position:fixed;top:0;left:0;right:0;background:var(--surface);border-bottom:1px solid var(--border);z-index:90;align-items:center;justify-content:space-between;backdrop-filter:blur(20px);}
.mob-tl-group{display:flex;gap:10px;align-items:center;flex-direction:row;}
.logout-mob{display:none;color:var(--red) !important;}
.logout-mob:hover{background:var(--red-dim) !important;border-color:rgba(248,113,113,.3) !important;}
/* Login page */
.login-wrap{display:flex;align-items:center;justify-content:center;min-height:100vh;width:100%}
.login-box{background:var(--surface2);border:1px solid var(--border2);border-radius:20px;padding:36px 32px;width:100%;max-width:380px;box-shadow:0 0 25px var(--primary-dim)}
.login-logo{text-align:center;margin-bottom:28px}
.login-title{font-family:'Orbitron',sans-serif;font-size:1.5rem;font-weight:900;color:var(--primary);letter-spacing:.1em}
.login-sub{font-size:0.9rem;color:var(--text3);margin-top:6px}
/* Clean IP textarea */
textarea.fi{resize:vertical;min-height:80px;}

@media(max-width:768px){
  .mob-hd{display:flex;height:65px;padding:0 20px;}
  .sidebar{transform:none !important;width:100% !important;height:78px;top:auto;bottom:0;border-right:none;border-top:1px solid var(--border);flex-direction:row;padding:0;background:var(--surface);}
  .sb-brand,.sb-bottom{display:none !important;}
  .sb-nav{flex-direction:row;width:100%;padding:0;align-items:center;justify-content:space-between;gap:0;}
  .nav-item{flex:1;padding:12px 0;border-radius:0;}
  .nav-icon{width:24px;height:24px;margin-bottom:5px;}
  .nav-label{font-size:0.7rem;}
  .logout-mob{display:flex;}
  .main{margin-left:0;padding-top:85px;padding-left:18px;padding-right:18px;padding-bottom:100px;}
}
@media(max-width:460px){
  .stats-row{grid-template-columns:1fr;gap:14px;}
}
</style>
</head>
<body>
<div class="bg-fixed"></div>
<div class="grid-fixed"></div>
<div class="toast" id="toast"></div>

<div id="login-page" style="display:none;width:100%">
  <div class="login-wrap">
    <div class="login-box">
      <div class="login-logo">
        <svg width="80" height="80" viewBox="0 0 80 80" fill="none">
          <rect width="80" height="80" rx="12" fill="var(--primary)" fill-opacity="0.1"/>
          <text x="40" y="58" font-family="'Orbitron', sans-serif" font-size="40" font-weight="900" fill="var(--primary)" text-anchor="middle">V2R</text>
        </svg>
        <div class="login-title">V2Render Panel</div>
        <div class="login-sub">Enter your password to continue</div>
      </div>
      <div class="fg">
        <label class="fl">PASSWORD</label>
        <input class="fi" type="password" id="login-pw" placeholder="••••••••" onkeydown="if(event.key==='Enter')doLogin()">
      </div>
      <button class="btn btn-gold" onclick="doLogin()" style="width:100%;justify-content:center;padding:12px;margin-top:6px;">LOGIN</button>
      <div id="login-err" style="color:var(--red);font-size:0.9rem;margin-top:10px;text-align:center;display:none">Invalid password</div>
    </div>
  </div>
</div>

<div id="dashboard-page" style="display:none;width:100%">
  <div class="mob-hd">
    <div class="mob-tl-group">
      <button class="theme-toggle" onclick="toggleTheme()" id="theme-btn-mob">🌙</button>
      <div class="lang-row">
        <button class="lang-btn lang-en active" onclick="setLang('en')">EN</button>
        <button class="lang-btn lang-fa" onclick="setLang('fa')">FA</button>
      </div>
    </div>
    <span style="font-family:'Orbitron',sans-serif;font-size:1.2rem;font-weight:700;color:var(--primary);letter-spacing:1px;">V2Render</span>
  </div>

  <aside class="sidebar" id="sb">
    <div class="sb-brand">
      <svg class="sb-logo" viewBox="0 0 36 36">
        <rect width="36" height="36" rx="6" fill="var(--primary)" fill-opacity="0.15"/>
        <text x="18" y="26" font-family="'Orbitron', sans-serif" font-size="18" font-weight="900" fill="var(--primary)" text-anchor="middle">V2R</text>
      </svg>
      <div class="sb-title">V2Render</div>
    </div>
    <nav class="sb-nav">
      <button class="nav-item active" data-page="dashboard">
        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
        <span class="nav-label" data-en="Dashboard" data-fa="داشبورد">Dashboard</span>
      </button>
      <button class="nav-item" data-page="inbounds">
        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="23" y1="11" x2="17" y2="11"/><line x1="20" y1="8" x2="20" y2="14"/></svg>
        <span class="nav-label" data-en="Inbounds" data-fa="اینباندها">Inbounds</span>
        <span class="nav-badge" id="nb">0</span>
      </button>
      <button class="nav-item" data-page="traffic">
        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
        <span class="nav-label" data-en="Traffic" data-fa="ترافیک">Traffic</span>
      </button>
      <button class="nav-item" data-page="addresses">
        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>
        <span class="nav-label" data-en="Clean IP" data-fa="آی‌پی تمیز">Clean IP</span>
      </button>
      <button class="nav-item" data-page="security">
        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
        <span class="nav-label" data-en="Security" data-fa="امنیت">Security</span>
      </button>
      <button class="nav-item logout-mob" onclick="doLogout()">
        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
        <span class="nav-label" data-en="Logout" data-fa="خروج">Logout</span>
      </button>
    </nav>
    <div class="sb-bottom">
      <button class="theme-toggle" onclick="toggleTheme()" id="theme-btn-desk" style="margin-bottom:4px;font-size:12px">🌙 Theme</button>
      <div class="lang-row">
        <button class="lang-btn lang-en active" onclick="setLang('en')">EN</button>
        <button class="lang-btn lang-fa" onclick="setLang('fa')">FA</button>
      </div>
      <button class="logout-btn" onclick="doLogout()" style="margin-top:2px">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
        <span data-en="Logout" data-fa="خروج">Logout</span>
      </button>
    </div>
  </aside>

  <main class="main">
    <!-- Dashboard -->
    <section class="page active" id="page-dashboard">
      <div class="page-header">
        <div>
          <div class="page-title" data-en="Dashboard" data-fa="داشبورد">Dashboard</div>
          <div class="page-sub" id="last-up">–</div>
        </div>
        <div style="display:flex;gap:6px">
          <button class="btn btn-ghost btn-sm" onclick="qCreate(.5,'GB')" data-en="+ 0.5 GB" data-fa="+ ۰.۵ گیگ">+ 0.5 GB</button>
          <button class="btn btn-gold btn-sm" onclick="qCreate(1,'GB')" data-en="+ 1 GB" data-fa="+ ۱ گیگ">+ 1 GB</button>
        </div>
      </div>
      <div class="stats-row">
        <div class="stat-card"><div class="stat-label" data-en="Traffic" data-fa="ترافیک">Traffic</div><div class="stat-val" id="sv-traffic">–<span class="stat-unit"> MB</span></div></div>
        <div class="stat-card"><div class="stat-label" data-en="Inbounds" data-fa="اینباندها">Inbounds</div><div class="stat-val" id="sv-links">–</div></div>
        <div class="stat-card"><div class="stat-label" data-en="Uptime" data-fa="آپتایم">Uptime</div><div class="stat-val" id="sv-uptime" style="font-size:1.2rem">–</div></div>
        <div class="stat-card"><div class="stat-label" data-en="Domain" data-fa="دامنه">Domain</div><div class="stat-val" id="sv-domain" style="font-size:0.9rem;word-break:break-all;font-weight:500">–</div></div>
      </div>
      <div class="grid-2">
        <div class="card">
          <div class="card-hd"><div class="card-title" data-en="CPU" data-fa="پردازنده">CPU</div><span id="cpu-v" style="font-size:1.1rem;font-weight:700;color:var(--primary)">–%</span></div>
          <div class="sys-bar"><div class="sys-fill" id="cpu-b" style="background:var(--primary)"></div></div>
        </div>
        <div class="card">
          <div class="card-hd"><div class="card-title" data-en="Memory" data-fa="حافظه">Memory</div><span id="mem-v" style="font-size:1.1rem;font-weight:700;color:var(--green)">–%</span></div>
          <div class="sys-bar"><div class="sys-fill" id="mem-b" style="background:var(--green)"></div></div>
        </div>
      </div>
      <div class="card">
        <div class="card-hd"><div class="card-title" data-en="Hourly Traffic" data-fa="ترافیک ساعتی">Hourly Traffic</div></div>
        <div class="chart-container"><canvas id="tc"></canvas></div>
      </div>
    </section>

    <!-- Inbounds -->
    <section class="page" id="page-inbounds">
      <div class="page-header">
        <div>
          <div class="page-title" data-en="Inbounds" data-fa="اینباندها">Inbounds</div>
          <div class="page-sub" data-en="VLESS over WebSocket · TLS" data-fa="VLESS روی WebSocket با TLS">VLESS over WebSocket · TLS</div>
        </div>
        <button class="btn btn-gold" onclick="showAddMo()" data-en="+ Add" data-fa="+ افزودن">+ Add</button>
      </div>
      <div class="tb">
        <div class="search-wrap">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          <input id="srch" data-ph-en="Search name…" data-ph-fa="جستجوی نام…" placeholder="Search name…" oninput="filterLinks()">
        </div>
        <div class="filter-chips">
          <button class="chip active" data-filter="all" onclick="setFilter('all',this)" data-en="All" data-fa="همه">All</button>
          <button class="chip" data-filter="active" onclick="setFilter('active',this)" data-en="Active" data-fa="فعال">Active</button>
          <button class="chip" data-filter="off" onclick="setFilter('off',this)" data-en="Off" data-fa="غیرفعال">Off</button>
        </div>
      </div>
      <div class="card" style="padding:0;overflow:hidden">
        <div class="tbl-wrap">
          <table class="tbl">
            <thead><tr>
              <th data-en="#" data-fa="#">#</th>
              <th data-en="Name" data-fa="نام">Name</th>
              <th data-en="Type" data-fa="نوع">Type</th>
              <th data-en="Usage" data-fa="مصرف">Usage</th>
              <th data-en="IPs" data-fa="آی‌پی">IPs</th>
              <th data-en="Expiry" data-fa="انقضا">Expiry</th>
              <th data-en="Status" data-fa="وضعیت">Status</th>
              <th data-en="Actions" data-fa="عملیات">Actions</th>
            </tr></thead>
            <tbody id="ltb"></tbody>
          </table>
        </div>
        <div class="m-cards" id="mcards"></div>
        <div class="empty" id="lempty" style="display:none" data-en="No inbounds found" data-fa="هیچ اینباندی یافت نشد">No inbounds found</div>
      </div>
    </section>

    <!-- Traffic -->
    <section class="page" id="page-traffic">
      <div class="page-header"><div><div class="page-title" data-en="Traffic" data-fa="ترافیک">Traffic</div><div class="page-sub" data-en="Statistics" data-fa="آمار">Statistics</div></div></div>
      <div class="card">
        <div class="sl-item"><span class="sl-k" data-en="Total Traffic" data-fa="کل ترافیک">Total Traffic</span><span class="sl-v" id="t-tr">–</span></div>
        <div class="sl-item"><span class="sl-k" data-en="Total Requests" data-fa="کل درخواست‌ها">Total Requests</span><span class="sl-v" id="t-rq">–</span></div>
        <div class="sl-item"><span class="sl-k" data-en="Uptime" data-fa="آپتایم">Uptime</span><span class="sl-v" id="t-up">–</span></div>
      </div>
    </section>

    <!-- Clean IP -->
    <section class="page" id="page-addresses">
      <div class="page-header">
        <div><div class="page-title" data-en="Clean IP" data-fa="آی‌پی تمیز">Clean IP</div><div class="page-sub" data-en="Subscription alternative addresses" data-fa="آدرس‌های جایگزین اشتراک">Subscription alternative addresses</div></div>
      </div>
      <div class="card">
        <div class="fg">
          <label class="fl" data-en="Add Addresses (one per line)" data-fa="افزودن آدرس (هر خط یک)">Add Addresses (one per line)</label>
          <textarea class="fi" id="batch-addrs" rows="4" placeholder="8.8.8.8&#10;example.com&#10;1.1.1.1" style="resize:vertical;"></textarea>
        </div>
        <button class="btn btn-gold btn-sm" onclick="addBatchAddrs()" data-en="Add All" data-fa="افزودن همه">Add All</button>
        <div id="addr-list" style="margin-top:16px;"></div>
      </div>
    </section>

    <!-- Security -->
    <section class="page" id="page-security">
      <div class="page-header"><div><div class="page-title" data-en="Security" data-fa="امنیت">Security</div><div class="page-sub" data-en="Change panel password" data-fa="تغییر رمز پنل">Change panel password</div></div></div>
      <div class="card" style="max-width:420px">
        <div class="fg"><label class="fl" data-en="Current Password" data-fa="رمز فعلی">Current Password</label><input class="fi" type="password" id="cpw" data-ph-en="Current password" data-ph-fa="رمز فعلی" placeholder="Current password"></div>
        <div class="fg"><label class="fl" data-en="New Password" data-fa="رمز جدید">New Password</label><input class="fi" type="password" id="npw" data-ph-en="Min 4 chars" data-ph-fa="حداقل ۴ کاراکتر" placeholder="Min 4 chars"></div>
        <button class="btn btn-gold" onclick="chgPw()" style="margin-top:10px;width:100%;justify-content:center;" data-en="Update Password" data-fa="بروزرسانی رمز">Update Password</button>
      </div>
    </section>
  </main>
</div>

<!-- Modals -->
<div class="mo" id="mo-add" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-add').classList.remove('show')">✕</button>
    <div class="mo-title" data-en="ADD INBOUND" data-fa="افزودن اینباند">ADD INBOUND</div>
    <div class="fg"><label class="fl" data-en="Remark" data-fa="توضیح">Remark</label><input class="fi" id="nl" data-ph-en="e.g. User 1" data-ph-fa="مثلاً کاربر ۱" placeholder="e.g. User 1"></div>
    <div class="fr">
      <div class="fg"><label class="fl" data-en="Traffic Limit" data-fa="محدودیت ترافیک">Traffic Limit</label><input class="fi" id="nv" type="number" min="0" step=".1" data-ph-en="0 = ∞" data-ph-fa="۰ = نامحدود" placeholder="0 = ∞"></div>
      <div class="fg" style="max-width:100px"><label class="fl" data-en="Unit" data-fa="واحد">Unit</label><select class="fs" id="nu"><option>GB</option></select></div>
    </div>
    <div class="fg"><label class="fl" data-en="Max IPs" data-fa="حداکثر آی‌پی">Max IPs</label><input class="fi" id="nc" type="number" min="0" data-ph-en="0 = ∞" data-ph-fa="۰ = نامحدود" placeholder="0 = ∞"></div>
    <div class="fg"><label class="fl" data-en="Days Valid" data-fa="روزهای اعتبار">Days Valid</label><input class="fi" id="nd" type="number" min="0" data-ph-en="0 = No expiry" data-ph-fa="۰ = بدون انقضا" placeholder="0 = No expiry"></div>
    <button class="btn btn-gold" onclick="createLink()" style="width:100%;justify-content:center;margin-top:12px;padding:12px;" data-en="CREATE" data-fa="ایجاد">CREATE</button>
  </div>
</div>

<div class="mo" id="mo-edit" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-edit').classList.remove('show')">✕</button>
    <div class="mo-title" id="et">EDIT INBOUND</div>
    <input type="hidden" id="eu">
    <div class="fg"><label class="fl" data-en="Name" data-fa="نام">Name</label><input class="fi" id="en2" readonly style="opacity:.5;cursor:not-allowed"></div>
    <div class="fr">
      <div class="fg"><label class="fl" data-en="Traffic Limit" data-fa="محدودیت ترافیک">Traffic Limit</label><input class="fi" id="el" type="number" min="0" step=".1" data-ph-en="0 = ∞" data-ph-fa="۰ = نامحدود" placeholder="0 = ∞"></div>
      <div class="fg" style="max-width:100px"><label class="fl" data-en="Unit" data-fa="واحد">Unit</label><select class="fs" id="eu2"><option>GB</option></select></div>
    </div>
    <div class="fg"><label class="fl" data-en="Max IPs" data-fa="حداکثر آی‌پی">Max IPs</label><input class="fi" id="ec" type="number" min="0" data-ph-en="0 = ∞" data-ph-fa="۰ = نامحدود" placeholder="0 = ∞"></div>
    <div class="fg"><label class="fl" data-en="Extend Days" data-fa="افزایش روزها">Extend Days</label><input class="fi" id="ed" type="number" min="0" data-ph-en="0 = no change" data-ph-fa="۰ = بدون تغییر" placeholder="0 = no change"></div>
    <div style="display:flex;gap:10px;margin-top:16px">
      <button class="btn btn-gold" onclick="saveEdit()" style="flex:1;justify-content:center;padding:12px;" data-en="SAVE" data-fa="ذخیره">SAVE</button>
      <button class="btn btn-danger" onclick="resetTraf()" style="padding:12px;" data-en="Reset Traffic" data-fa="بازنشانی ترافیک">Reset Traffic</button>
    </div>
  </div>
</div>

<div class="mo" id="mo-qr" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="mo-box" style="max-width:340px">
    <button class="mo-close" onclick="document.getElementById('mo-qr').classList.remove('show')">✕</button>
    <div class="mo-title" data-en="QR CODE" data-fa="کد QR">QR CODE</div>
    <div class="qr-box"><img id="qr-img" src="" alt="QR"></div>
    <div style="display:flex;gap:10px;margin-top:16px;justify-content:center">
      <button class="btn btn-gold btn-sm" onclick="dlQR()" style="padding:10px 16px;" data-en="Download" data-fa="دانلود">Download</button>
      <button class="btn btn-ghost btn-sm" onclick="document.getElementById('mo-qr').classList.remove('show')" style="padding:10px 16px;" data-en="Close" data-fa="بستن">Close</button>
    </div>
  </div>
</div>

<script>
// ── Globals ──────────────────────────────────────────────────────────────
function $(s){return document.querySelector(s);}
function $m(id){return document.getElementById(id);}
function esc(s){return String(s).replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
const langMap={en:{edit:'Edit',copy:'Copy',sub:'Sub',qr:'QR',del:'Del'},fa:{edit:'ویرایش',copy:'کپی',sub:'اشتراک',qr:'QR',del:'حذف'}};
function tr(key){return(langMap[lang]&&langMap[lang][key])||langMap['en'][key]||key;}
let lang=localStorage.getItem('ll')||'en';
let theme=localStorage.getItem('theme')||'dark';
let allLinks=[],cf='all',sData={},tChart=null,allAddrs=[],isAuthenticated=false;

function setTheme(t){
  theme=t; document.body.classList.toggle('light-mode', t==='light');
  localStorage.setItem('theme',t);
  $m('theme-btn-mob').innerHTML=t==='light'?'☀️':'🌙';
  $m('theme-btn-desk').innerHTML=(t==='light'?'☀️':'🌙')+' Theme';
  updChartColors();
}
function toggleTheme(){setTheme(theme==='dark'?'light':'dark');}

function setLang(l){
  lang=l; document.querySelectorAll('.lang-en,.lang-fa').forEach(e=>e.classList.remove('active'));
  document.querySelectorAll(`.lang-${l}`).forEach(e=>e.classList.add('active'));
  document.body.dir=l==='fa'?'rtl':'ltr';
  document.querySelectorAll('[data-en]').forEach(el=>{const v=el.getAttribute('data-'+l);if(v)el.textContent=v;});
  document.querySelectorAll('[data-ph-en]').forEach(el=>{const v=el.getAttribute('data-ph-'+l);if(v)el.placeholder=v;});
  localStorage.setItem('ll',l); filterLinks();
}

async function checkAuth(){
  try{const r=await fetch('/api/me');const d=await r.json();d.authenticated?showDashboard():showLogin();}
  catch(e){showLogin();}
}
function showLogin(){isAuthenticated=false;$m('login-page').style.display='';$m('dashboard-page').style.display='none';}
function showDashboard(){isAuthenticated=true;$m('login-page').style.display='none';$m('dashboard-page').style.display='';initChart();loadStats();loadLinks();loadAddrs();}

async function doLogin(){
  const pw=$m('login-pw').value;$m('login-err').style.display='none';
  try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});if(r.ok){$m('login-pw').value='';showDashboard();}else{$m('login-err').style.display='block';}}catch(e){$m('login-err').style.display='block';}
}
async function doLogout(){await fetch('/api/logout',{method:'POST'});showLogin();}

document.querySelectorAll('.nav-item[data-page]').forEach(el=>el.addEventListener('click',()=>switchPage(el.dataset.page)));
function switchPage(id){document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));const t=$m('page-'+id);if(t)t.classList.add('active');document.querySelectorAll('.nav-item').forEach(n=>n.classList.toggle('active',n.dataset.page===id));}

function toast(msg,err=false){const t=$m('toast');t.textContent=msg;t.className='toast'+(err?' err':'')+' show';clearTimeout(t._hide);t._hide=setTimeout(()=>t.classList.remove('show'),3000);}

function fmtB(b){if(!b||b===0)return'0 B';return b>=1073741824?(b/1073741824).toFixed(2)+' GB':b>=1048576?(b/1048576).toFixed(2)+' MB':(b/1024).toFixed(1)+' KB';}
function fmtLim(b){if(!b||b===0)return'∞';const g=b/1073741824;return(g%1===0?g.toFixed(0):g.toFixed(1))+' GB';}
function fmtExp(ea){if(!ea||ea===0)return'∞';const d=new Date(ea)-new Date();if(d<=0)return'Expired';const days=Math.floor(d/86400000);if(days>0)return days+'d';const hours=Math.floor(d/3600000);if(hours>0)return hours+'h';return Math.floor(d/60000)+'m';}

function setFilter(filter,el){cf=filter;document.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));if(el)el.classList.add('active');filterLinks();}
function filterLinks(){const q=($m('srch')?.value||'').toLowerCase();let r=allLinks;if(cf==='active')r=r.filter(l=>l.active);else if(cf==='off')r=r.filter(l=>!l.active);if(q)r=r.filter(l=>l.label.toLowerCase().includes(q)||l.uuid.toLowerCase().includes(q));renderLinks(r);}
function renderLinks(links){
  const tb=$m('ltb'),em=$m('lempty'),mc=$m('mcards');
  if(!links||!links.length){tb.innerHTML='';mc.innerHTML='';em.style.display='block';return;}
  em.style.display='none';let idx=links.length;
  const rows=links.map(l=>{const u=l.used_bytes||0,lim=l.limit_bytes||0,pct=lim>0?Math.min(100,(u/lim)*100):0,col=pct>90?'var(--red)':pct>70?'var(--yellow)':'var(--primary)',ex=fmtExp(l.expires_at),ec=ex==='Expired'?'var(--red)':ex==='∞'?'var(--text3)':'var(--text2)',i=idx--,cc=l.current_connections||0,mc2=l.max_connections||0;return{l,pct,col,ex,ec,i,cc,mc2,u,lim};});
  const editText=tr('edit'),copyText=tr('copy'),subText=tr('sub'),qrText=tr('qr'),delText=tr('del');
  tb.innerHTML=rows.map(r=>`<tr><td>${r.i}</td><td style="font-weight:600">${esc(r.l.label)}</td><td><span class="tag tag-vless">VLESS</span></td><td><div class="pill"><span class="pill-used">${fmtB(r.u)}</span><div class="pill-bar"><div class="pill-fill" style="width:${r.pct}%;background:${r.col}"></div></div><span class="pill-lim">${fmtLim(r.lim)}</span></div></td><td>${r.cc}/${r.mc2||'∞'}</td><td style="color:${r.ec}">${r.ex}</td><td><span class="tag ${r.l.active?'tag-on':'tag-off'}">${r.l.active?'On':'Off'}</span></td><td><div style="display:flex;gap:3px;align-items:center;flex-wrap:wrap"><button class="toggle ${r.l.active?'on':''}" data-uid="${r.l.uuid}" onclick="togLink(this)"></button><button class="act-btn act-edit" onclick="showEditMo('${r.l.uuid}')">${editText}</button><button class="act-btn act-copy" onclick="cpLink('${esc(r.l.vless_link||'')}')">${copyText}</button><button class="act-btn act-sub" onclick="cpSub('${r.l.uuid}')">${subText}</button><button class="act-btn act-qr" onclick="showQR('${esc(r.l.vless_link||'')}')">${qrText}</button><button class="act-btn act-del" onclick="delLink('${r.l.uuid}')">${delText}</button></div></td></tr>`).join('');
  mc.innerHTML=rows.map(r=>`<div class="m-card"><div class="m-card-hd"><div style="display:flex;align-items:center;gap:7px"><span style="font-size:0.8rem;color:var(--text3)">#${r.i}</span><span style="font-weight:600;font-size:1rem">${esc(r.l.label)}</span><span class="tag tag-vless">VLESS</span></div><button class="toggle ${r.l.active?'on':''}" data-uid="${r.l.uuid}" onclick="togLink(this)"></button></div><div class="pill"><span class="pill-used">${fmtB(r.u)}</span><div class="pill-bar"><div class="pill-fill" style="width:${r.pct}%;background:${r.col}"></div></div><span class="pill-lim">${fmtLim(r.lim)}</span></div><div style="font-size:0.8rem;color:${r.ec};margin-top:6px">⏳ ${r.ex} · ${r.cc}/${r.mc2||'∞'} IPs</div><div class="m-card-acts"><button class="act-btn act-edit" onclick="showEditMo('${r.l.uuid}')">${editText}</button><button class="act-btn act-copy" onclick="cpLink('${esc(r.l.vless_link||'')}')">${copyText}</button><button class="act-btn act-sub" onclick="cpSub('${r.l.uuid}')">${subText}</button><button class="act-btn act-qr" onclick="showQR('${esc(r.l.vless_link||'')}')">${qrText}</button><button class="act-btn act-del" onclick="delLink('${r.l.uuid}')">${delText}</button></div></div>`).join('');
}

async function togLink(el){const uid=el.dataset.uid,l=allLinks.find(x=>x.uuid===uid);if(!l)return;const na=!l.active;try{await fetch('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({active:na})});l.active=na;filterLinks();loadStats();}catch(e){toast('Failed to toggle',true);}}

async function qCreate(v,u){const ns=['Ali','Sara','Reza','Nima','Mina','Arash'];const n=ns[Math.floor(Math.random()*ns.length)]+'-'+Math.floor(Math.random()*100);try{await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:n,limit_value:v,limit_unit:u})});toast('Created: '+n);await loadLinks();await loadStats();}catch(e){toast('Error creating link',true);}}
function showAddMo(){$m('mo-add').classList.add('show');}
async function createLink(){const label=$m('nl').value.trim()||'New Link';if(!/^[a-zA-Z0-9\-_. ]+$/.test(label)){toast('Only English letters allowed',true);return;}const v=parseFloat($m('nv').value)||0,mc=parseInt($m('nc').value)||0,days=parseInt($m('nd').value)||0;try{await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label,limit_value:v,limit_unit:'GB',max_connections:mc,days_valid:days})});toast('Created');$m('nl').value=$m('nv').value=$m('nc').value=$m('nd').value='';$m('mo-add').classList.remove('show');await loadLinks();await loadStats();}catch(e){toast('Error creating link',true);}}
function showEditMo(uid){const l=allLinks.find(x=>x.uuid===uid);if(!l)return;$m('eu').value=uid;$m('en2').value=l.label;$m('el').value=l.limit_bytes>0?(l.limit_bytes/1073741824):'';$m('ec').value=l.max_connections>0?l.max_connections:'';$m('ed').value='';$m('et').textContent=(lang==='fa'?'ویرایش: ':'EDIT: ')+l.label;$m('mo-edit').classList.add('show');}
async function saveEdit(){const uid=$m('eu').value,v=parseFloat($m('el').value)||0,mc=parseInt($m('ec').value)||0,days=parseInt($m('ed').value)||0;const body={limit_value:v,limit_unit:'GB',max_connections:mc};if(days>0)body.days_valid=days;try{await fetch('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});toast('Updated');$m('mo-edit').classList.remove('show');await loadLinks();}catch(e){toast('Error updating',true);}}
async function resetTraf(){const uid=$m('eu').value;if(!confirm('Reset traffic?'))return;try{await fetch('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({reset_usage:true})});toast('Traffic reset');await loadLinks();}catch(e){toast('Error resetting',true);}}
async function delLink(uid){if(!confirm('Delete?'))return;try{await fetch('/api/links/'+uid,{method:'DELETE'});toast('Deleted');await loadLinks();await loadStats();}catch(e){toast('Error deleting',true);}}
function cpLink(txt){if(!txt)return;navigator.clipboard.writeText(txt).then(()=>toast('Copied!')).catch(()=>toast('Failed to copy',true));}
async function cpSub(uid){try{await navigator.clipboard.writeText('https://'+location.host+'/sub/'+uid);toast('Sub URL copied!');}catch(e){toast('Failed to copy',true);}}
function showQR(txt){if(!txt)return;$m('qr-img').src='https://api.qrserver.com/v1/create-qr-code/?size=280x280&data='+encodeURIComponent(txt);$m('mo-qr').classList.add('show');}
function dlQR(){const a=document.createElement('a');a.href=$m('qr-img').src;a.download='v2render-qr.png';a.click();}

async function loadStats(){
  try{const r=await fetch('/stats');if(r.status===401){showLogin();return;}sData=await r.json();
    $m('sv-traffic').innerHTML=(sData.total_traffic_mb||0)+'<span class="stat-unit"> MB</span>';
    $m('sv-links').textContent=sData.links_count||0;
    $m('sv-uptime').textContent=sData.uptime||'–';
    $m('sv-domain').textContent=sData.domain||'–';
    $m('nb').textContent=sData.links_count||0;
    $m('last-up').textContent='Updated '+new Date().toLocaleTimeString();
    if($m('t-tr'))$m('t-tr').textContent=(sData.total_traffic_mb||0)+' MB';
    if($m('t-rq'))$m('t-rq').textContent=(sData.total_requests||0).toLocaleString();
    if($m('t-up'))$m('t-up').textContent=sData.uptime||'–';
    if(sData.cpu_percent!==undefined){const c=sData.cpu_percent,cc=c>80?'var(--red)':c>50?'var(--yellow)':'var(--primary)';$m('cpu-v').textContent=c.toFixed(1)+'%';$m('cpu-v').style.color=cc;$m('cpu-b').style.width=c+'%';$m('cpu-b').style.background=cc;}
    if(sData.memory_percent!==undefined){const m=sData.memory_percent,mc=m>80?'var(--red)':m>50?'var(--yellow)':'var(--green)';$m('mem-v').textContent=m.toFixed(1)+'%';$m('mem-v').style.color=mc;$m('mem-b').style.width=m+'%';$m('mem-b').style.background=mc;}
    updChart();
  }catch(e){}
}
async function loadLinks(){try{const r=await fetch('/api/links');if(r.status===401){showLogin();return;}const d=await r.json();allLinks=d.links||[];filterLinks();}catch(e){}}
async function chgPw(){const cur=$m('cpw').value,nw=$m('npw').value;if(!cur||!nw){toast('Fill all fields',true);return;}if(nw.length<4){toast('Min 4 chars',true);return;}try{const r=await fetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:cur,new_password:nw})});if(!r.ok)throw new Error((await r.json()).detail||'Error');toast('Password updated');$m('cpw').value=$m('npw').value='';}catch(e){toast(e.message,true);}}

function initChart(){const ctx=$m('tc');if(!ctx||tChart)return;tChart=new Chart(ctx,{type:'bar',data:{labels:[],datasets:[{label:'MB',data:[],backgroundColor:'rgba(57,255,20,0.55)',borderColor:'#39ff14',borderWidth:1,borderRadius:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{display:false},ticks:{color:'rgba(57,255,20,0.3)',font:{size:10}}},y:{grid:{color:'rgba(255,255,255,0.04)'},ticks:{color:'rgba(57,255,20,0.3)',font:{size:10},callback:v=>v+' MB'},beginAtZero:true}}}});updChartColors();}
function updChartColors(){if(!tChart)return;const col=theme==='light'?'rgba(0,0,0,0.5)':'rgba(57,255,20,0.4)',gridCol=theme==='light'?'rgba(0,0,0,0.08)':'rgba(255,255,255,0.06)';tChart.options.scales.x.ticks.color=col;tChart.options.scales.y.ticks.color=col;tChart.options.scales.y.grid.color=gridCol;tChart.update();}
function updChart(){if(!tChart||!sData.hourly_traffic)return;const entries=Object.entries(sData.hourly_traffic).sort((a,b)=>a[0].localeCompare(b[0])).slice(-12);tChart.data.labels=entries.map(x=>x[0]);tChart.data.datasets[0].data=entries.map(x=>Math.round(x[1]/1048576));tChart.update();}

async function loadAddrs(){try{const r=await fetch('/api/addresses');if(!r.ok)throw new Error();const d=await r.json();allAddrs=d.addresses||[];renderAddrs();}catch(e){}}
function renderAddrs(){const el=$m('addr-list');if(!el)return;if(!allAddrs.length){el.innerHTML='<div style="color:var(--text3);font-size:0.9rem">No addresses added</div>';return;}el.innerHTML=allAddrs.map((a,i)=>`<div style="display:flex;align-items:center;justify-content:space-between;padding:10px 14px;background:var(--surface3);border:1px solid var(--border);border-radius:10px;margin-bottom:8px"><div style="display:flex;align-items:center;gap:10px"><span style="color:var(--primary);font-size:1.2rem">🌐</span><div><div style="font-size:0.95rem;font-weight:600">${esc(a)}</div><div style="font-size:0.75rem;color:var(--text3)">Address #${i+1}</div></div></div><button class="act-btn act-del" onclick="delAddr(${i})">${tr('del')}</button></div>`).join('');}
async function addBatchAddrs(){const raw=$m('batch-addrs').value;const lines=raw.split('\n').map(l=>l.trim()).filter(l=>l);let ok=0,fail=0;for(const addr of lines){if(!/^[a-zA-Z0-9\-_. ]+$/.test(addr)){fail++;continue;}try{const r=await fetch('/api/addresses',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({address:addr})});if(r.ok)ok++;else fail++;}catch(e){fail++;}}if(ok)toast(`Added ${ok}`);if(fail)toast(`${fail} failed`,true);$m('batch-addrs').value='';await loadAddrs();}
async function delAddr(i){if(!confirm('Delete?'))return;try{await fetch('/api/addresses/'+i,{method:'DELETE'});toast('Deleted');await loadAddrs();}catch(e){toast('Error deleting',true);}}

setTheme(theme);setLang(lang);checkAuth();
let statsInterval=null;
function startPolling(){if(statsInterval)clearInterval(statsInterval);statsInterval=setInterval(()=>{if(isAuthenticated){loadStats();loadLinks();}},12000);}
startPolling();
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
