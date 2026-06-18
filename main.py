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
    "jwt_expire_minutes": 10080,
    "db_path": os.environ.get("DB_PATH", "panel.db"),
    "admin_password": os.environ.get("ADMIN_PASSWORD", "admin"),
}

# ── Database Helpers ─────────────────────────────────────────────────────
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
    return {"service": "V2Render", "version": "8.0", "status": "active", "domain": get_domain()}

@app.get("/health")
async def health():
    async with connections_lock: conn_count = len(connections)
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
    ADMIN_PASSWORD_HASH = bcrypt.hashpw(new.encode(), bcrypt.gensalt()).decode()
    return {"ok": True}

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    async with connections_lock: conn_count = len(connections)
    return {
        "active_connections": conn_count,
        "total_traffic_mb": round(stats["total_bytes"]/(1024*1024),2),
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
    if not label: raise HTTPException(status_code=400, detail="Inbound name is required")
    existing = await db_fetchone("SELECT uid FROM links WHERE label = ?", (label,))
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
        (uid, label, limit_bytes, max_conn, now, expires_at)
    )
    return {
        "uuid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": 0,
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
            existing = await db_fetchone("SELECT uid FROM links WHERE label = ? AND uid != ?", (new_label, uid))
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
    else: raise HTTPException(status_code=404, detail="Address not found")
    return {"ok": True}

@app.delete("/api/addresses")
async def delete_all_addresses(_=Depends(require_auth)):
    await db_execute("DELETE FROM custom_addresses")
    return {"ok": True}

@app.get("/sub/{uid}")
async def subscription_endpoint(uid: str):
    link = await db_fetchone("SELECT * FROM links WHERE uid = ?", (uid,))
    if not link or not link["active"]: raise HTTPException(status_code=404, detail="link not found or disabled")
    expires_at = parse_expires_at(link["expires_at"])
    if expires_at and expires_at < datetime.now(timezone.utc): raise HTTPException(status_code=403, detail="link expired")
    addresses_rows = await db_fetchall("SELECT address FROM custom_addresses")
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
RELAY_BUF = 64 * 1024

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

async def atomic_check_and_add_usage(uid: str, size: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute(
            "UPDATE links SET used_bytes = used_bytes + ? WHERE uid = ? AND (limit_bytes = 0 OR used_bytes + ? <= limit_bytes) AND active = 1",
            (size, uid, size)
        )
        await db.commit()
        return cursor.rowcount > 0
    finally: await db.close()

async def ws_to_tcp(websocket, writer, conn_id, link_uid):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect": break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data: continue
            size = len(data)
            if not await atomic_check_and_add_usage(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size; stats["total_requests"] += 1
            async with connections_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += size
                    connections[conn_id]["last_active"] = time.time()
            hour = datetime.now(timezone.utc).strftime("%H:00")
            await db_execute("INSERT INTO hourly_traffic (hour, bytes) VALUES (?,?) ON CONFLICT(hour) DO UPDATE SET bytes = bytes + ?", (hour, size, size))
            day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            await db_execute("INSERT INTO daily_traffic (day, bytes) VALUES (?,?) ON CONFLICT(day) DO UPDATE SET bytes = bytes + ?", (day, size, size))
            try: writer.write(data); await writer.drain()
            except Exception: break
    except WebSocketDisconnect: pass
    except Exception as e: logger.error(f"ws_to_tcp error conn={conn_id}: {e}", exc_info=True)
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
            if not await atomic_check_and_add_usage(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size
            async with connections_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += size
                    connections[conn_id]["last_active"] = time.time()
            hour = datetime.now(timezone.utc).strftime("%H:00")
            await db_execute("INSERT INTO hourly_traffic (hour, bytes) VALUES (?,?) ON CONFLICT(hour) DO UPDATE SET bytes = bytes + ?", (hour, size, size))
            day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            await db_execute("INSERT INTO daily_traffic (day, bytes) VALUES (?,?) ON CONFLICT(day) DO UPDATE SET bytes = bytes + ?", (day, size, size))
            try:
                await websocket.send_bytes((b"\x00\x00" + data) if first else data)
                first = False
            except Exception: break
    except Exception as e: logger.error(f"tcp_to_ws error conn={conn_id}: {e}", exc_info=True)

@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await websocket.accept()
    logger.info(f"WebSocket accepted for uuid={uuid}")
    writer = None; conn_id = None; client_ip = get_client_ip(websocket)
    try:
        link = await db_fetchone("SELECT * FROM links WHERE uid = ?", (uuid,))
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

        size = len(first_chunk); stats["total_bytes"] += size; stats["total_requests"] += 1
        await atomic_check_and_add_usage(uuid, size)

        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=10.0)

        if initial_payload:
            p_size = len(initial_payload); stats["total_bytes"] += p_size
            await atomic_check_and_add_usage(uuid, p_size)
            try: writer.write(initial_payload); await writer.drain()
            except Exception: pass

        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending: t.cancel(); await t
    except WebSocketDisconnect: logger.info(f"WebSocket disconnected by client {client_ip}")
    except Exception as exc:
        stats["total_errors"] += 1; error_logs.append({"error": str(exc), "time": datetime.now(timezone.utc).isoformat()}); logger.exception("WebSocket error")
    finally:
        if writer:
            try: writer.close(); await writer.wait_closed()
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

# ── HTML Panel (V2Render v8) ─────────────────────────────────────────────
PANEL_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
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
  --green:#4ade80; --red:#f87171; --yellow:#fbbf24;
  --header-h:60px;
}
body.light-mode {
  --primary:#2e7d32; --primary-dim:rgba(46,125,50,0.15);
  --bg:#f5fff5; --bg2:#ffffff; --bg3:#e8f5e9;
  --surface:#ffffff; --surface2:#f1f8f1; --surface3:#e0f0e0;
  --border:rgba(0,0,0,0.08); --border2:rgba(0,0,0,0.16);
  --text:#1a1a1a; --text2:#4a4a4a; --text3:#888;
}
html{font-size:16px;}
body{font-family:'Inter','Vazirmatn',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;transition:background 0.3s,color 0.3s;}
body[dir="rtl"]{direction:rtl;text-align:right}
a{text-decoration:none;color:inherit;}
/* Header */
.header{position:fixed;top:0;left:0;right:0;height:var(--header-h);background:var(--surface);border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;padding:0 24px;z-index:100;backdrop-filter:blur(20px);}
.header-left{display:flex;align-items:center;gap:24px;}
.logo{font-family:'Orbitron',sans-serif;font-size:1.4rem;font-weight:900;color:var(--primary);letter-spacing:1px;}
.header-nav{display:flex;align-items:center;gap:4px;}
.nav-link{padding:8px 16px;border-radius:8px;color:var(--text3);font-size:0.9rem;font-weight:600;transition:all 0.2s;border:1px solid transparent;background:none;cursor:pointer;font-family:inherit;}
.nav-link:hover{color:var(--primary);border-color:var(--primary-dim);}
.nav-link.active{color:var(--primary);background:var(--primary-dim);border-color:var(--primary-dim);}
.header-right{display:flex;align-items:center;gap:12px;}
.btn-icon{background:transparent;border:1px solid var(--border);color:var(--text3);border-radius:8px;padding:8px;cursor:pointer;transition:all 0.2s;font-size:1rem;}
.btn-icon:hover{color:var(--primary);border-color:var(--primary);}
.lang-switch{display:flex;gap:2px;background:var(--surface3);border-radius:8px;padding:2px;}
.lang-btn{padding:6px 12px;border:none;background:transparent;color:var(--text3);font-size:0.85rem;font-weight:700;border-radius:6px;cursor:pointer;font-family:inherit;}
.lang-btn.active{background:var(--primary);color:#000;}
/* Main */
.main{margin-top:var(--header-h);padding:32px 24px 48px;min-height:calc(100vh - var(--header-h) - 50px);}
.page{display:none;animation:pgIn .35s ease}
.page.active{display:block}
@keyframes pgIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
.page-header{margin-bottom:24px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;}
.page-title{font-size:1.4rem;font-weight:700;color:var(--primary);}
.page-title[data-fa]{font-family:'Vazirmatn';}
.page-sub{font-size:0.95rem;color:var(--text3);margin-top:4px;}
.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:20px;}
.stat-card{background:var(--surface2);border:1px solid var(--border);border-radius:12px;padding:20px;position:relative;overflow:hidden;transition:all 0.25s;}
.stat-card:hover{border-color:var(--border2);transform:translateY(-2px);box-shadow:0 0 20px var(--primary-dim);}
.stat-label{font-size:0.8rem;color:var(--text3);font-weight:700;text-transform:uppercase;margin-bottom:8px;}
.stat-val{font-size:1.6rem;font-weight:700;color:var(--text);}
.stat-unit{font-size:0.9rem;font-weight:400;color:var(--text3);}
.card{background:var(--surface2);border:1px solid var(--border);border-radius:12px;padding:20px;margin-bottom:16px;transition:all 0.25s;}
.card-hd{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;}
.card-title{font-size:1rem;font-weight:600;color:var(--text);}
.chart-container{height:200px;width:100%;}
.btn{font-family:inherit;font-size:0.9rem;font-weight:700;border-radius:8px;padding:8px 18px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;border:none;transition:all 0.2s;}
.btn-primary{background:linear-gradient(135deg,#39ff14,#1a8c1a);color:#000;box-shadow:0 0 16px rgba(57,255,20,0.3);}
.btn-primary:hover{filter:brightness(1.2);box-shadow:0 0 24px rgba(57,255,20,0.5);}
.btn-outline{background:var(--surface3);color:var(--text);border:1px solid var(--border);}
.btn-danger{background:rgba(248,113,113,0.1);color:#f87171;border:1px solid rgba(248,113,113,0.2);}
.btn-sm{padding:4px 12px;font-size:0.85rem;}
.tbl-wrap{overflow-x:auto;}
.tbl{width:100%;border-collapse:collapse;}
.tbl th{text-align:left;font-size:0.8rem;font-weight:700;color:var(--text3);padding:12px;text-transform:uppercase;border-bottom:1px solid var(--border);background:var(--surface3);}
.tbl td{padding:12px;border-bottom:1px solid var(--border);font-size:0.95rem;}
.tag{display:inline-flex;align-items:center;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:800;text-transform:uppercase;}
.tag-vless{background:var(--primary-dim);color:var(--primary);border:1px solid var(--border);}
.tag-on{background:rgba(74,222,128,0.1);color:var(--green);border:1px solid rgba(74,222,128,0.2);}
.tag-off{background:rgba(248,113,113,0.1);color:var(--red);border:1px solid rgba(248,113,113,0.2);}
.pill{display:flex;align-items:center;gap:8px;font-size:0.85rem;}
.pill-used{color:var(--text);font-weight:600;}
.pill-bar{flex:1;height:4px;background:var(--border);border-radius:2px;}
.pill-fill{height:100%;border-radius:2px;transition:width 0.4s;}
.toggle{width:34px;height:18px;border-radius:9px;background:var(--surface3);position:relative;cursor:pointer;transition:all 0.28s;border:1px solid var(--border);}
.toggle::after{content:'';position:absolute;width:12px;height:12px;border-radius:50%;background:var(--text3);top:2px;left:2px;transition:all 0.28s;}
.toggle.on{background:var(--green);border-color:var(--green);}
.toggle.on::after{left:18px;background:#fff;}
.sys-bar{height:6px;background:var(--border);border-radius:3px;overflow:hidden;}
.sys-fill{height:100%;border-radius:3px;transition:width 0.4s;}
.fg{display:flex;flex-direction:column;gap:6px;margin-bottom:16px;}
.fl{font-size:0.85rem;font-weight:700;color:var(--text2);text-transform:uppercase;}
.fi,.fs{padding:10px 14px;border-radius:8px;border:1px solid var(--border);font-family:inherit;font-size:0.95rem;outline:none;color:var(--text);background:var(--surface);transition:all 0.2s;}
.fi:focus,.fs:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-dim);}
.act-btn{font-family:inherit;font-size:0.8rem;font-weight:700;padding:4px 8px;border-radius:6px;cursor:pointer;border:1px solid;transition:all 0.18s;display:inline-flex;align-items:center;gap:4px;background:transparent;}
.act-copy{color:var(--primary);border-color:var(--border);}
.act-sub{color:var(--green);border-color:rgba(74,222,128,0.2);}
.act-qr{color:#a78bfa;border-color:rgba(167,139,250,0.2);}
.act-edit{color:var(--yellow);border-color:rgba(251,191,36,0.2);}
.act-del{color:var(--red);border-color:rgba(248,113,113,0.2);}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(16px);background:var(--surface);color:var(--text);border:1px solid var(--border2);border-radius:12px;padding:14px 28px;font-size:1rem;font-weight:600;opacity:0;transition:all 0.3s;z-index:999;backdrop-filter:blur(24px);box-shadow:0 0 20px var(--primary-dim);}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0);}
.mo{position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:200;display:none;align-items:center;justify-content:center;backdrop-filter:blur(8px);}
.mo.show{display:flex;}
.mo-box{background:var(--surface2);border:1px solid var(--border2);border-radius:20px;padding:32px;width:100%;max-width:480px;box-shadow:0 0 30px var(--primary-dim);}
.mo-title{font-size:1.2rem;font-weight:700;margin-bottom:20px;color:var(--primary);}
.mo-close{position:absolute;top:16px;right:16px;background:var(--surface3);border:1px solid var(--border);color:var(--text3);width:32px;height:32px;border-radius:8px;cursor:pointer;}
/* Footer */
.footer{height:50px;display:flex;align-items:center;justify-content:center;font-size:0.8rem;color:var(--text3);border-top:1px solid var(--border);}
@media(max-width:768px){
  .header{padding:0 16px;}
  .header-nav{display:none;}
  .main{padding:24px 16px 48px;}
}
</style>
</head>
<body>
<div class="toast" id="toast"></div>

<!-- Login -->
<div id="login-page" style="display:none;width:100%">
  <div style="display:flex;align-items:center;justify-content:center;min-height:100vh;">
    <div style="background:var(--surface2);border:1px solid var(--border2);border-radius:20px;padding:40px 32px;width:100%;max-width:380px;box-shadow:0 0 25px var(--primary-dim);">
      <div style="text-align:center;margin-bottom:28px;">
        <svg width="80" height="80" viewBox="0 0 80 80"><rect width="80" height="80" rx="12" fill="var(--primary)" fill-opacity="0.1"/><text x="40" y="58" font-family="'Orbitron',sans-serif" font-size="40" font-weight="900" fill="var(--primary)" text-anchor="middle">V2R</text></svg>
        <div style="font-family:'Orbitron',sans-serif;font-size:1.5rem;font-weight:900;color:var(--primary);margin-top:10px;">V2Render</div>
        <div style="font-size:0.95rem;color:var(--text3);margin-top:6px;" data-en="Enter your password" data-fa="رمز عبور را وارد کنید">Enter your password</div>
      </div>
      <div class="fg">
        <label class="fl">PASSWORD</label>
        <input class="fi" type="password" id="login-pw" placeholder="••••••••" onkeydown="if(event.key==='Enter')doLogin()">
      </div>
      <button class="btn btn-primary" onclick="doLogin()" style="width:100%;justify-content:center;padding:14px;margin-top:12px;">LOGIN</button>
      <div id="login-err" style="color:var(--red);font-size:0.9rem;margin-top:10px;text-align:center;display:none">Invalid password</div>
    </div>
  </div>
</div>

<!-- Dashboard -->
<div id="dashboard-page" style="display:none;width:100%">
  <!-- Header -->
  <header class="header">
    <div class="header-left">
      <span class="logo">V2Render</span>
      <nav class="header-nav">
        <button class="nav-link active" data-page="dashboard" data-en="Dashboard" data-fa="داشبورد">Dashboard</button>
        <button class="nav-link" data-page="inbounds" data-en="Inbounds" data-fa="اینباندها">Inbounds</button>
        <button class="nav-link" data-page="traffic" data-en="Traffic" data-fa="ترافیک">Traffic</button>
        <button class="nav-link" data-page="addresses" data-en="Clean IP" data-fa="آی‌پی تمیز">Clean IP</button>
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
    </div>
  </header>

  <main class="main">
    <!-- Dashboard Page -->
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
        <div class="stat-card"><div class="stat-label" data-en="Uptime" data-fa="آپتایم">Uptime</div><div class="stat-val" id="sv-uptime" style="font-size:1.2rem;">–</div></div>
        <div class="stat-card"><div class="stat-label" data-en="Domain" data-fa="دامنه">Domain</div><div class="stat-val" id="sv-domain" style="font-size:0.95rem;word-break:break-all;">–</div></div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
        <div class="card">
          <div class="card-hd"><span class="card-title" data-en="CPU" data-fa="پردازنده">CPU</span><span id="cpu-v" style="font-weight:700;color:var(--primary);">–%</span></div>
          <div class="sys-bar"><div class="sys-fill" id="cpu-b" style="background:var(--primary);"></div></div>
        </div>
        <div class="card">
          <div class="card-hd"><span class="card-title" data-en="Memory" data-fa="حافظه">Memory</span><span id="mem-v" style="font-weight:700;color:var(--green);">–%</span></div>
          <div class="sys-bar"><div class="sys-fill" id="mem-b" style="background:var(--green);"></div></div>
        </div>
      </div>
      <div class="card">
        <div class="card-hd"><span class="card-title" data-en="Hourly Traffic" data-fa="ترافیک ساعتی">Hourly Traffic</span></div>
        <div class="chart-container"><canvas id="tc"></canvas></div>
      </div>
    </section>

    <!-- Inbounds Page -->
    <section class="page" id="page-inbounds">
      <div class="page-header">
        <div>
          <div class="page-title" data-en="Inbounds" data-fa="اینباندها">Inbounds</div>
          <div class="page-sub" data-en="VLESS over WebSocket · TLS" data-fa="VLESS روی WebSocket با TLS">VLESS over WebSocket · TLS</div>
        </div>
        <button class="btn btn-primary" onclick="showAddMo()" data-en="+ Create" data-fa="+ ایجاد">+ Create</button>
      </div>
      <div style="display:flex;gap:12px;margin-bottom:20px;">
        <input id="srch" placeholder="Search…" oninput="filterLinks()" class="fi" style="flex:1;">
        <button class="chip active" data-filter="all" onclick="setFilter('all',this)">All</button>
        <button class="chip" data-filter="active" onclick="setFilter('active',this)">Active</button>
        <button class="chip" data-filter="off" onclick="setFilter('off',this)">Off</button>
      </div>
      <div class="card" style="padding:0;overflow:hidden;">
        <div class="tbl-wrap">
          <table class="tbl" id="links-table">
            <thead><tr><th>#</th><th>Name</th><th>Type</th><th>Usage</th><th>IPs</th><th>Expiry</th><th>Status</th><th>Actions</th></tr></thead>
            <tbody id="ltb"></tbody>
          </table>
        </div>
        <div class="empty" id="lempty" style="display:none;padding:40px;">No inbounds found</div>
      </div>
    </section>

    <!-- Traffic Page -->
    <section class="page" id="page-traffic">
      <div class="page-header"><div class="page-title" data-en="Traffic" data-fa="ترافیک">Traffic</div></div>
      <div class="card">
        <div style="display:flex;justify-content:space-between;padding:12px 0;border-bottom:1px solid var(--border);"><span class="sl-k">Total Traffic</span><span id="t-tr" class="sl-v">–</span></div>
        <div style="display:flex;justify-content:space-between;padding:12px 0;border-bottom:1px solid var(--border);"><span class="sl-k">Total Requests</span><span id="t-rq" class="sl-v">–</span></div>
        <div style="display:flex;justify-content:space-between;padding:12px 0;"><span class="sl-k">Uptime</span><span id="t-up" class="sl-v">–</span></div>
      </div>
    </section>

    <!-- Clean IP Page -->
    <section class="page" id="page-addresses">
      <div class="page-header"><div class="page-title" data-en="Clean IP" data-fa="آی‌پی تمیز">Clean IP</div></div>
      <div class="card">
        <div class="fg">
          <label class="fl" data-en="Add Addresses (one per line)" data-fa="افزودن آدرس (هر خط یک)">Add Addresses (one per line)</label>
          <textarea class="fi" id="batch-addrs" rows="4" placeholder="8.8.8.8&#10;example.com"></textarea>
        </div>
        <button class="btn btn-primary" onclick="addBatchAddrs()" data-en="Add All" data-fa="افزودن همه">Add All</button>
        <button class="btn btn-danger btn-sm" onclick="deleteAllAddrs()" style="margin-left:8px;" data-en="Delete All" data-fa="حذف همه">Delete All</button>
        <div id="addr-list" style="margin-top:20px;"></div>
      </div>
    </section>

    <!-- Security Page -->
    <section class="page" id="page-security">
      <div class="page-header"><div class="page-title" data-en="Security" data-fa="امنیت">Security</div></div>
      <div style="max-width:400px;margin:0 auto;">
        <div class="card">
          <div class="fg"><label class="fl" data-en="Current Password" data-fa="رمز فعلی">Current Password</label><input class="fi" type="password" id="cpw"></div>
          <div class="fg"><label class="fl" data-en="New Password" data-fa="رمز جدید">New Password</label><input class="fi" type="password" id="npw"></div>
          <button class="btn btn-primary" onclick="chgPw()" style="width:100%;justify-content:center;">Update Password</button>
        </div>
      </div>
    </section>
  </main>

  <!-- Footer -->
  <footer class="footer">
    <span>V2Render Panel · VLESS WS Tunnel</span>
  </footer>
</div>

<!-- Modals -->
<div class="mo" id="mo-add">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-add').classList.remove('show')">✕</button>
    <div class="mo-title" data-en="Create Inbound" data-fa="ایجاد اینباند">Create Inbound</div>
    <div class="fg"><label class="fl">Remark</label><input class="fi" id="nl" placeholder="e.g. User-1"></div>
    <div style="display:flex;gap:12px;">
      <div class="fg" style="flex:1;"><label class="fl">Traffic Limit</label><input class="fi" id="nv" type="number" min="0" step="0.1" placeholder="0 = ∞"></div>
      <div class="fg" style="width:100px;"><label class="fl">Unit</label><select class="fs" id="nu"><option>GB</option></select></div>
    </div>
    <div class="fg"><label class="fl">Max IPs</label><input class="fi" id="nc" type="number" min="0" placeholder="0 = ∞"></div>
    <div class="fg"><label class="fl">Days Valid</label><input class="fi" id="nd" type="number" min="0" placeholder="0 = No expiry"></div>
    <button class="btn btn-primary" onclick="createLink()" style="width:100%;justify-content:center;margin-top:16px;">CREATE</button>
  </div>
</div>

<div class="mo" id="mo-edit">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-edit').classList.remove('show')">✕</button>
    <div class="mo-title" id="et">Edit Inbound</div>
    <input type="hidden" id="eu">
    <div class="fg"><label class="fl">Name</label><input class="fi" id="en2" readonly style="opacity:0.5;"></div>
    <div style="display:flex;gap:12px;">
      <div class="fg" style="flex:1;"><label class="fl">Traffic Limit</label><input class="fi" id="el" type="number" min="0"></div>
      <div class="fg" style="width:100px;"><label class="fl">Unit</label><select class="fs" id="eu2"><option>GB</option></select></div>
    </div>
    <div class="fg"><label class="fl">Max IPs</label><input class="fi" id="ec" type="number" min="0"></div>
    <div class="fg"><label class="fl">Extend Days</label><input class="fi" id="ed" type="number" min="0"></div>
    <div style="display:flex;gap:12px;margin-top:16px;">
      <button class="btn btn-primary" onclick="saveEdit()" style="flex:1;justify-content:center;">SAVE</button>
      <button class="btn btn-danger" onclick="resetTraf()">Reset Traffic</button>
    </div>
  </div>
</div>

<div class="mo" id="mo-qr">
  <div class="mo-box" style="max-width:360px;">
    <button class="mo-close" onclick="document.getElementById('mo-qr').classList.remove('show')">✕</button>
    <div class="mo-title">QR Code</div>
    <div style="text-align:center;padding:20px;background:var(--surface3);border-radius:12px;"><img id="qr-img" src="" alt="QR"></div>
    <button class="btn btn-primary btn-sm" onclick="dlQR()" style="width:100%;justify-content:center;margin-top:16px;">Download</button>
  </div>
</div>

<script>
// ── Globals ──────────────────────────────────────────────────────────────
const $=s=>document.querySelector(s),$m=id=>document.getElementById(id),esc=s=>String(s).replace(/</g,'&lt;').replace(/>/g,'&gt;');
const langMap={en:{edit:'Edit',copy:'Copy',sub:'Sub',qr:'QR',del:'Del'},fa:{edit:'ویرایش',copy:'کپی',sub:'اشتراک',qr:'QR',del:'حذف'}};
function tr(k){return(langMap[lang]&&langMap[lang][k])||langMap['en'][k]||k;}
let lang=localStorage.getItem('ll')||'en',theme=localStorage.getItem('theme')||'dark';
let allLinks=[],cf='all',sData={},tChart=null,allAddrs=[],isAuthenticated=false;

function setTheme(t){theme=t;document.body.classList.toggle('light-mode',t==='light');localStorage.setItem('theme',t);document.querySelector('.btn-icon').textContent=t==='light'?'☀️':'🌙';updChartColors();}
function toggleTheme(){setTheme(theme==='dark'?'light':'dark');}
function setLang(l){lang=l;document.querySelectorAll('.lang-en,.lang-fa').forEach(e=>e.classList.remove('active'));document.querySelectorAll(`.lang-${l}`).forEach(e=>e.classList.add('active'));document.body.dir=l==='fa'?'rtl':'ltr';document.querySelectorAll('[data-en]').forEach(el=>{const v=el.getAttribute('data-'+l);if(v)el.textContent=v;});localStorage.setItem('ll',l);filterLinks();}

async function checkAuth(){try{const r=await fetch('/api/me');(await r.json()).authenticated?showDashboard():showLogin();}catch{showLogin();}}
function showLogin(){$m('login-page').style.display='';$m('dashboard-page').style.display='none';}
function showDashboard(){$m('login-page').style.display='none';$m('dashboard-page').style.display='';initChart();loadStats();loadLinks();loadAddrs();}

async function doLogin(){const pw=$m('login-pw').value;$m('login-err').style.display='none';try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});if(r.ok){$m('login-pw').value='';showDashboard();}else $m('login-err').style.display='block';}catch{$m('login-err').style.display='block';}}
async function doLogout(){await fetch('/api/logout',{method:'POST'});showLogin();}

document.querySelectorAll('.nav-link[data-page]').forEach(el=>el.addEventListener('click',()=>switchPage(el.dataset.page)));
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
function showEditMo(uid){const l=allLinks.find(x=>x.uuid===uid);if(!l)return;$m('eu').value=uid;$m('en2').value=l.label;$m('el').value=l.limit_bytes>0?(l.limit_bytes/1073741824):'';$m('ec').value=l.max_connections||'';$m('ed').value='';$m('et').textContent='Edit: '+l.label;$m('mo-edit').classList.add('show');}
async function saveEdit(){const uid=$m('eu').value,v=parseFloat($m('el').value)||0,mc=parseInt($m('ec').value)||0,days=parseInt($m('ed').value)||0;const body={limit_value:v,limit_unit:'GB',max_connections:mc};if(days)body.days_valid=days;try{await fetch('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});toast('Updated');$m('mo-edit').classList.remove('show');loadLinks();}catch{toast('Error',true);}}
async function resetTraf(){const uid=$m('eu').value;if(!confirm('Reset?'))return;try{await fetch('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({reset_usage:true})});toast('Reset');loadLinks();}catch{toast('Error',true);}}
async function delLink(uid){if(!confirm('Delete?'))return;try{await fetch('/api/links/'+uid,{method:'DELETE'});toast('Deleted');loadLinks();loadStats();}catch{toast('Error',true);}}
function cpLink(txt){navigator.clipboard.writeText(txt).then(()=>toast('Copied!')).catch(()=>toast('Failed',true));}
async function cpSub(uid){await navigator.clipboard.writeText('https://'+location.host+'/sub/'+uid);toast('Sub URL copied!');}
function showQR(txt){$m('qr-img').src='https://api.qrserver.com/v1/create-qr-code/?size=280x280&data='+encodeURIComponent(txt);$m('mo-qr').classList.add('show');}
function dlQR(){const a=document.createElement('a');a.href=$m('qr-img').src;a.download='qr.png';a.click();}

async function loadStats(){
  try{const r=await fetch('/stats');if(r.status===401){showLogin();return;}sData=await r.json();
    $m('sv-traffic').innerHTML=(sData.total_traffic_mb||0)+'<span class="stat-unit"> MB</span>';
    $m('sv-links').textContent=sData.links_count;$m('sv-uptime').textContent=sData.uptime;$m('sv-domain').textContent=sData.domain;
    $m('last-up').textContent='Updated '+new Date().toLocaleTimeString();
    $m('t-tr').textContent=(sData.total_traffic_mb||0)+' MB';$m('t-rq').textContent=sData.total_requests;$m('t-up').textContent=sData.uptime;
    if(sData.cpu_percent!==undefined){const c=sData.cpu_percent;$m('cpu-v').textContent=c.toFixed(1)+'%';$m('cpu-b').style.width=c+'%';}
    if(sData.memory_percent!==undefined){const m=sData.memory_percent;$m('mem-v').textContent=m.toFixed(1)+'%';$m('mem-b').style.width=m+'%';}
    updChart();
  }catch{}
}
async function loadLinks(){try{const r=await fetch('/api/links');if(r.status===401){showLogin();return;}const d=await r.json();allLinks=d.links||[];filterLinks();}catch{}}
async function chgPw(){const cur=$m('cpw').value,nw=$m('npw').value;if(!cur||!nw){toast('Fill fields',true);return;}if(nw.length<4){toast('Min 4 chars',true);return;}try{const r=await fetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:cur,new_password:nw})});if(!r.ok)throw new Error((await r.json()).detail||'Error');toast('Password updated');}catch(e){toast(e.message,true);}}

function initChart(){const ctx=$m('tc');if(!ctx||tChart)return;tChart=new Chart(ctx,{type:'bar',data:{labels:[],datasets:[{label:'MB',data:[],backgroundColor:'rgba(57,255,20,0.55)',borderColor:'#39ff14'}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{ticks:{color:'rgba(57,255,20,0.3)'}},y:{ticks:{color:'rgba(57,255,20,0.3)',callback:v=>v+' MB'}}}}}});updChartColors();}
function updChartColors(){if(!tChart)return;const col=theme==='light'?'#000':'rgba(57,255,20,0.4)';tChart.options.scales.x.ticks.color=col;tChart.options.scales.y.ticks.color=col;tChart.update();}
function updChart(){if(!tChart||!sData.hourly_traffic)return;const entries=Object.entries(sData.hourly_traffic).sort((a,b)=>a[0].localeCompare(b[0])).slice(-12);tChart.data.labels=entries.map(x=>x[0]);tChart.data.datasets[0].data=entries.map(x=>Math.round(x[1]/1048576));tChart.update();}

async function loadAddrs(){try{const r=await fetch('/api/addresses');allAddrs=(await r.json()).addresses||[];renderAddrs();}catch{}}
function renderAddrs(){const el=$m('addr-list');if(!allAddrs.length){el.innerHTML='<div style="color:var(--text3)">No addresses</div>';return;}el.innerHTML=allAddrs.map((a,i)=>`<div style="display:flex;justify-content:space-between;padding:8px 12px;background:var(--surface3);border:1px solid var(--border);border-radius:8px;margin-bottom:6px;"><span>${esc(a)}</span><button class="act-btn act-del" onclick="delAddr(${i})">${tr('del')}</button></div>`).join('');}
async function addBatchAddrs(){const raw=$m('batch-addrs').value;const lines=raw.split('\n').map(l=>l.trim()).filter(l=>l);let ok=0,fail=0;for(const addr of lines){if(!/^[a-zA-Z0-9\-_. ]+$/.test(addr)){fail++;continue;}try{const r=await fetch('/api/addresses',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({address:addr})});if(r.ok)ok++;else fail++;}catch{fail++;}}if(ok)toast(`Added ${ok}`);if(fail)toast(`${fail} failed`,true);$m('batch-addrs').value='';await loadAddrs();}
async function deleteAllAddrs(){if(!confirm('Delete all addresses?'))return;try{await fetch('/api/addresses',{method:'DELETE'});toast('All deleted');await loadAddrs();}catch{toast('Error',true);}}
async function delAddr(i){if(!confirm('Delete?'))return;try{await fetch('/api/addresses/'+i,{method:'DELETE'});toast('Deleted');await loadAddrs();}catch{toast('Error',true);}}

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
    uvicorn.run(app, host="0.0.0.0", port=CONFIG["port"])import asyncio
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
    "jwt_expire_minutes": 10080,
    "db_path": os.environ.get("DB_PATH", "panel.db"),
    "admin_password": os.environ.get("ADMIN_PASSWORD", "admin"),
}

# ── Database Helpers ─────────────────────────────────────────────────────
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

# ── Routes (exactly as before, no changes) ───────────────────────────────
@app.get("/")
async def root():
    return {"service": "V2Render", "version": "8.0", "status": "active", "domain": get_domain()}

@app.get("/health")
async def health():
    async with connections_lock: conn_count = len(connections)
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
    ADMIN_PASSWORD_HASH = bcrypt.hashpw(new.encode(), bcrypt.gensalt()).decode()
    return {"ok": True}

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    async with connections_lock: conn_count = len(connections)
    return {
        "active_connections": conn_count,
        "total_traffic_mb": round(stats["total_bytes"]/(1024*1024),2),
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
    if not label: raise HTTPException(status_code=400, detail="Inbound name is required")
    existing = await db_fetchone("SELECT uid FROM links WHERE label = ?", (label,))
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
        (uid, label, limit_bytes, max_conn, now, expires_at)
    )
    return {
        "uuid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": 0,
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
            existing = await db_fetchone("SELECT uid FROM links WHERE label = ? AND uid != ?", (new_label, uid))
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
    else: raise HTTPException(status_code=404, detail="Address not found")
    return {"ok": True}

@app.delete("/api/addresses")
async def delete_all_addresses(_=Depends(require_auth)):
    await db_execute("DELETE FROM custom_addresses")
    return {"ok": True}

@app.get("/sub/{uid}")
async def subscription_endpoint(uid: str):
    link = await db_fetchone("SELECT * FROM links WHERE uid = ?", (uid,))
    if not link or not link["active"]: raise HTTPException(status_code=404, detail="link not found or disabled")
    expires_at = parse_expires_at(link["expires_at"])
    if expires_at and expires_at < datetime.now(timezone.utc): raise HTTPException(status_code=403, detail="link expired")
    addresses_rows = await db_fetchall("SELECT address FROM custom_addresses")
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
RELAY_BUF = 64 * 1024

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

async def atomic_check_and_add_usage(uid: str, size: int) -> bool:
    db = await get_db()
    try:
        cursor = await db.execute(
            "UPDATE links SET used_bytes = used_bytes + ? WHERE uid = ? AND (limit_bytes = 0 OR used_bytes + ? <= limit_bytes) AND active = 1",
            (size, uid, size)
        )
        await db.commit()
        return cursor.rowcount > 0
    finally: await db.close()

async def ws_to_tcp(websocket, writer, conn_id, link_uid):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect": break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data: continue
            size = len(data)
            if not await atomic_check_and_add_usage(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size; stats["total_requests"] += 1
            async with connections_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += size
                    connections[conn_id]["last_active"] = time.time()
            hour = datetime.now(timezone.utc).strftime("%H:00")
            await db_execute("INSERT INTO hourly_traffic (hour, bytes) VALUES (?,?) ON CONFLICT(hour) DO UPDATE SET bytes = bytes + ?", (hour, size, size))
            day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            await db_execute("INSERT INTO daily_traffic (day, bytes) VALUES (?,?) ON CONFLICT(day) DO UPDATE SET bytes = bytes + ?", (day, size, size))
            try: writer.write(data); await writer.drain()
            except Exception: break
    except WebSocketDisconnect: pass
    except Exception as e: logger.error(f"ws_to_tcp error conn={conn_id}: {e}", exc_info=True)
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
            if not await atomic_check_and_add_usage(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size
            async with connections_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += size
                    connections[conn_id]["last_active"] = time.time()
            hour = datetime.now(timezone.utc).strftime("%H:00")
            await db_execute("INSERT INTO hourly_traffic (hour, bytes) VALUES (?,?) ON CONFLICT(hour) DO UPDATE SET bytes = bytes + ?", (hour, size, size))
            day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            await db_execute("INSERT INTO daily_traffic (day, bytes) VALUES (?,?) ON CONFLICT(day) DO UPDATE SET bytes = bytes + ?", (day, size, size))
            try:
                await websocket.send_bytes((b"\x00\x00" + data) if first else data)
                first = False
            except Exception: break
    except Exception as e: logger.error(f"tcp_to_ws error conn={conn_id}: {e}", exc_info=True)

@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await websocket.accept()
    logger.info(f"WebSocket accepted for uuid={uuid}")
    writer = None; conn_id = None; client_ip = get_client_ip(websocket)
    try:
        link = await db_fetchone("SELECT * FROM links WHERE uid = ?", (uuid,))
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

        size = len(first_chunk); stats["total_bytes"] += size; stats["total_requests"] += 1
        await atomic_check_and_add_usage(uuid, size)

        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=10.0)

        if initial_payload:
            p_size = len(initial_payload); stats["total_bytes"] += p_size
            await atomic_check_and_add_usage(uuid, p_size)
            try: writer.write(initial_payload); await writer.drain()
            except Exception: pass

        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending: t.cancel(); await t
    except WebSocketDisconnect: logger.info(f"WebSocket disconnected by client {client_ip}")
    except Exception as exc:
        stats["total_errors"] += 1; error_logs.append({"error": str(exc), "time": datetime.now(timezone.utc).isoformat()}); logger.exception("WebSocket error")
    finally:
        if writer:
            try: writer.close(); await writer.wait_closed()
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

# ── HTML Panel (V2Render v8 - complete redesign) ─────────────────────────
PANEL_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
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
  --green:#4ade80; --red:#f87171; --yellow:#fbbf24;
  --header-h:60px;
}
body.light-mode {
  --primary:#2e7d32; --primary-dim:rgba(46,125,50,0.15);
  --bg:#f5fff5; --bg2:#ffffff; --bg3:#e8f5e9;
  --surface:#ffffff; --surface2:#f1f8f1; --surface3:#e0f0e0;
  --border:rgba(0,0,0,0.08); --border2:rgba(0,0,0,0.16);
  --text:#1a1a1a; --text2:#4a4a4a; --text3:#888;
}
html{font-size:16px;}
body{font-family:'Inter','Vazirmatn',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;transition:background 0.3s,color 0.3s;}
body[dir="rtl"]{direction:rtl;text-align:right}
a{text-decoration:none;color:inherit;}
/* Header */
.header{position:fixed;top:0;left:0;right:0;height:var(--header-h);background:var(--surface);border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;padding:0 24px;z-index:100;backdrop-filter:blur(20px);}
.header-left{display:flex;align-items:center;gap:24px;}
.logo{font-family:'Orbitron',sans-serif;font-size:1.4rem;font-weight:900;color:var(--primary);letter-spacing:1px;}
.header-nav{display:flex;align-items:center;gap:4px;}
.nav-link{padding:8px 16px;border-radius:8px;color:var(--text3);font-size:0.9rem;font-weight:600;transition:all 0.2s;border:1px solid transparent;background:none;cursor:pointer;font-family:inherit;}
.nav-link:hover{color:var(--primary);border-color:var(--primary-dim);}
.nav-link.active{color:var(--primary);background:var(--primary-dim);border-color:var(--primary-dim);}
.header-right{display:flex;align-items:center;gap:12px;}
.btn-icon{background:transparent;border:1px solid var(--border);color:var(--text3);border-radius:8px;padding:8px;cursor:pointer;transition:all 0.2s;font-size:1rem;}
.btn-icon:hover{color:var(--primary);border-color:var(--primary);}
.lang-switch{display:flex;gap:2px;background:var(--surface3);border-radius:8px;padding:2px;}
.lang-btn{padding:6px 12px;border:none;background:transparent;color:var(--text3);font-size:0.85rem;font-weight:700;border-radius:6px;cursor:pointer;font-family:inherit;}
.lang-btn.active{background:var(--primary);color:#000;}
/* Main */
.main{margin-top:var(--header-h);padding:32px 24px 48px;min-height:calc(100vh - var(--header-h) - 50px);}
.page{display:none;animation:pgIn .35s ease}
.page.active{display:block}
@keyframes pgIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
.page-header{margin-bottom:24px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;}
.page-title{font-size:1.4rem;font-weight:700;color:var(--primary);}
.page-title[data-fa]{font-family:'Vazirmatn';}
.page-sub{font-size:0.95rem;color:var(--text3);margin-top:4px;}
.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:20px;}
.stat-card{background:var(--surface2);border:1px solid var(--border);border-radius:12px;padding:20px;position:relative;overflow:hidden;transition:all 0.25s;}
.stat-card:hover{border-color:var(--border2);transform:translateY(-2px);box-shadow:0 0 20px var(--primary-dim);}
.stat-label{font-size:0.8rem;color:var(--text3);font-weight:700;text-transform:uppercase;margin-bottom:8px;}
.stat-val{font-size:1.6rem;font-weight:700;color:var(--text);}
.stat-unit{font-size:0.9rem;font-weight:400;color:var(--text3);}
.card{background:var(--surface2);border:1px solid var(--border);border-radius:12px;padding:20px;margin-bottom:16px;transition:all 0.25s;}
.card-hd{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;}
.card-title{font-size:1rem;font-weight:600;color:var(--text);}
.chart-container{height:200px;width:100%;}
.btn{font-family:inherit;font-size:0.9rem;font-weight:700;border-radius:8px;padding:8px 18px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;border:none;transition:all 0.2s;}
.btn-primary{background:linear-gradient(135deg,#39ff14,#1a8c1a);color:#000;box-shadow:0 0 16px rgba(57,255,20,0.3);}
.btn-primary:hover{filter:brightness(1.2);box-shadow:0 0 24px rgba(57,255,20,0.5);}
.btn-outline{background:var(--surface3);color:var(--text);border:1px solid var(--border);}
.btn-danger{background:rgba(248,113,113,0.1);color:#f87171;border:1px solid rgba(248,113,113,0.2);}
.btn-sm{padding:4px 12px;font-size:0.85rem;}
.tbl-wrap{overflow-x:auto;}
.tbl{width:100%;border-collapse:collapse;}
.tbl th{text-align:left;font-size:0.8rem;font-weight:700;color:var(--text3);padding:12px;text-transform:uppercase;border-bottom:1px solid var(--border);background:var(--surface3);}
.tbl td{padding:12px;border-bottom:1px solid var(--border);font-size:0.95rem;}
.tag{display:inline-flex;align-items:center;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:800;text-transform:uppercase;}
.tag-vless{background:var(--primary-dim);color:var(--primary);border:1px solid var(--border);}
.tag-on{background:rgba(74,222,128,0.1);color:var(--green);border:1px solid rgba(74,222,128,0.2);}
.tag-off{background:rgba(248,113,113,0.1);color:var(--red);border:1px solid rgba(248,113,113,0.2);}
.pill{display:flex;align-items:center;gap:8px;font-size:0.85rem;}
.pill-used{color:var(--text);font-weight:600;}
.pill-bar{flex:1;height:4px;background:var(--border);border-radius:2px;}
.pill-fill{height:100%;border-radius:2px;transition:width 0.4s;}
.toggle{width:34px;height:18px;border-radius:9px;background:var(--surface3);position:relative;cursor:pointer;transition:all 0.28s;border:1px solid var(--border);}
.toggle::after{content:'';position::'';position:absolute;width:12absolute;width:12px;height:px;height:12px;border12px;border-radius:50%;background:-radius:50%;background:var(--text3);top:2px;left:2px;var(--text3);top:2px;left:2px;transition:all transition:all 0.28s;}
0.28s;}
.toggle.on{background:.toggle.on{background:var(--green);border-color:var(--greenvar(--green);border-color:var(--green);}
.toggle.on::after{left:18px;background);}
.toggle.on::after{left:18px;background:#fff;}
.sys-bar:#fff;}
.sys-bar{height:{height:6px;background:var(--6px;background:var(--border);border);border-radius:3px;border-radius:3px;overflow:hidden;}
.soverflow:hidden;}
.sys-fill{height:100ys-fill{height:100%;border-radius:3px;transition:width 0%;border-radius:3px;transition:width 0.4s;}
.f.4s;}
.fg{g{display:display:flex;flex-directionflex;flex-direction:column;gap:6:column;gap:6px;margin-bottom:16px;}
.fl{px;margin-bottom:16px;}
.fl{font-size:0.85font-size:0.85rem;font-weight:rem;font-weight:700;color:var(--text2);text-transform:uppercase;}
.fi700;color:var(--text2);text,.fs{padding:10px -transform:uppercase;}
.fi,.fs{padding:10px 14px;border-radius:14px;border-radius:8px;border:18px;border:1px solidpx solid var(--border);font-family:inherit;font-size:0.95rem var(--border);font-family:inherit;font-size:0.95rem;outline:none;outline:none;color:var;color:var(--text);background(--text);background:var(--surface);transition:all 0.2s:var(--surface);transition:all 0.2s;}
.fi:focus,.;}
.fi:focus,.fs:focusfs:focus{b{border-colororder-color:var(--primary);box-shadow:0 0 0 3px var(--primary-dim);:var(--primary);box-shadow:0 0 0 3px var(--primary-dim);}
.}
.act-btn{font-family:act-btn{font-family:inherit;font-size:0.8reminherit;font-size:0.8rem;font-weight:700;padding;font-weight:700;padding:4px 8px;border:4px 8px;border-radius:6px;cursor-radius:6px;cursor:pointer;border:pointer;border:1:1px solid;transition:allpx solid;transition:all  0.18s;display:inline-flex;align-items0.18s;display:inline-flex;align:center;gap:4px;-items:center;gap:4px;background:transparent;}
.background:transparent;}
.act-copy{coloract-copy{color:var(--primary:var(--primary);border);border-color:var(--border);}
.act-sub{color:var(--green-color:var(--border);}
.act-sub{color:var(--green);border-color:rgba);border-color:rgba(74,222(74,222,128,0,128,0.2);.2);}
.act-qr}
.act-qr{color:#a78bfa;border-color:rgba(167,139,{color:#a78bfa;border-color:rg250,0.2);}
ba(167,139,250,0.2);}
.act-edit{.act-edit{color:var(--yellow);color:var(--yellow);border-color:rgborder-color:rgba(251,191,36,0.2);}
.ba(251,191,36,0.2);}
.act-del{color:act-del{color:var(--red);border-color:var(--red);border-color:rgba(248,113rgba(248,113,113,0.2);}
.toast{position:fixed;bottom:24,113,0.2);}
.toast{positionpx;left:50%;transform:translate:fixed;bottom:24px;leftX(-50%) translateY(16:50%;transform:translateX(-50%) translateY(16px);background:px);background:var(--surface);color:var(--var(--surface);color:var(--text);border:1px solid vartext);border:1px solid var(--border2);(--border2);border-radius:12px;padding:14px 28px;font-size:1border-radius:12px;padding:14px 28px;font-size:1rem;font-weightrem;font-weight:600;opacity:0;transition:all 0.:600;opacity:0;transition:all 0.3s;z-index:999;backdrop-filter3s;z-index:999;backdrop-filter::blur(24px);box-shadow:0 0 20px var(--primaryblur(24px);box-shadow:-dim);}
.toast.show{opacity:1;0 0 20px var(--primarytransform-dim);}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0);}
.mo{position::translateX(-50%) translateY(0);}
.mo{position:fixed;inset:0;background:rgbafixed;inset:0;background:rg(0,0,0,0.7);z-index:200;display:noneba(0,0,0,0.7);z-index:200;display:none;align-items:center;justify-content:center;align-items:center;justify;backdrop-filter:blur-content:center;backdrop-filter:blur(8px);}
.mo.show{display:flex(8px);}
.mo.show{display:;}
.mo-box{background:varflex;}
.mo-box{background:(--surface2);border:1px solid var(--border2);border-radius:20px;var(--surface2);border:1px solid varpadding:32px;width:100%;(--border2);border-radius:20px;padding:32px;width:100%;max-widthmax-width:480px;box-shadow:0 :480px;box-shadow:0 0 30px var(--primary-dim);}
0 30px var(--primary-dim);}
.mo-title.mo-title{font-size:1.2rem;font-weight:700;margin-bottom{font-size:1.2rem;:20px;color:var(--primary);}
font-weight:700;margin-bottom:20px.mo-close{position:absolute;;color:var(--primary);}
.mo-close{position:absolute;top:top:16px;right:16px16px;right:16px;background:var(--surface3);border:1px;background:var(--surface3);border:1px solid var(--border);color: solid var(--border);color:varvar(--text3);width:32px;(--text3);width:32px;height:32px;border-radius:8px;height:32px;border-radius:8px;cursor:pointer;}
/* Footercursor:pointer;}
/* Footer */
.footer{height:50 */
.footer{height:50px;displaypx;display:flex;align-items:center;justify-content::flex;align-items:center;justify-content:center;font-size:0.8center;font-size:0rem;color:var(--.8rem;colortext3);border-top::var(--text3);border-top:1px solid var(--border);}
1px solid var(--border);}
@media@media(max-width:768px){
  .header{p(max-width:768px){
  .header{padding:0 16pxadding:0 16px;}
  .header;}
  .header-nav{display:n-nav{display:none;}
  .main{pone;}
  .main{padding:24px adding:2416px 48px;}
}
</style>
</head>
<body>
<div class="topx 16px 48px;}
}
</style>
</head>
ast" id="toast"></div<body>
<div class="toast" id="toast>

<!-- Login -->
<div id="login-page"></div>

<!-- Login -->
<div" style="display:none; id="login-page" style="display:none;width:width:100%">
  <div style="display:flex;align-items100%">
  <div style="display::center;justify-content:centerflex;align-items:center;justify-content;min-height:100vh;">
    <div style:center;min-height:100vh;">
    <div style="background:var(--="background:var(--surface2);border:1px solid var(--border2);surface2);border:1pxborder-radius:20px;padding: solid var(--border2);border-radius:20px;40px 32px;widthpadding:40px 32px;width:100%;max-width::100%;max-width:380px;box-shadow:0 0 25px380px;box-shadow:0 0 25 var(--primary-dim);">
      <px var(--primary-dim);">
div style="text-align:center;margin      <div style="text-align:-bottom:28px;">
        <svg widthcenter;margin-bottom:28px;">
        <svg width="80" height="="80" height="80" viewBox="0 0 8080" viewBox="0  80"><rect width0 80 80"><rect width="80" height="80" rx="12="80" height="80" fill="var(--primary)" fill" rx="12" fill="var(--primary)" fill-opacity="0.1"/><text x="40" y="58" font-family-opacity="0.1"/><text x="40" y="58="'Orbitron',sans-serif" font-size" font-family="'Orbitron',s="40" font-weight="900" fill="varans-serif" font-size="40" font-weight="900" fill="var(--primary(--primary)" text-anchor="middle">V2R</text></svg>
        <div style="font)" text-anchor="middle">V2R</text></svg>
        <div style="-family:'Orbitron',sans-seriffont-family:'Orbitron',sans-serif;font-size:1.5rem;font-weight;font-size:1.5rem;font:900;color:var(---weight:900;color:var(--primary);margin-top:10px;">V2primary);margin-top:10px;">V2Render</div>
        <divRender</div>
        <div style="font-size:0.95rem;color style="font-size:0.95rem;color:var(--text3);margin-top:6px;" data-en:var(--text3);margin-top:6px;" data-en="Enter your password" data-fa="Enter your password" data-fa="رمز عبور را وارد کنید">="رمز عبور را وارد کنید">Enter your password</div>
Enter your password</div>
      </      </div>
      <div class="fg">
div>
      <div class="fg">
        <label class="fl">PASSWORD</label>
        <label class="fl">PASSWORD</label>
        <input class="fi"        <input class="fi" type="password" id="login-pw" placeholder=" type="password" id="login-pw" placeholder="••••••••" onkeydown="••••••••" onkeydown="if(event.key==='Enter')doLoginif(event.key==='Enter')doLogin()">
      </div>
      <button class="()">
      </div>
      <button class="btnbtn btn-primary" onclick btn-primary" onclick="doLogin="doLogin()" style="width:100%;just()" style="width:100%;justify-content:center;padding:14px;margin-top:12px;">LOGINify-content:center;padding:14px;margin-top:12px;">LOGIN</</button>
      <div id="login-err"button>
      <div id="login-err" style="color:var(--red);font-size:0 style="color:var(--red);font-size:.9rem;margin-top:10px0.9rem;margin-top:;text-align:center;display:n10px;text-align:center;display:none">Invalid password</divone">Invalid password</div>
    </div>
  </div>
</div>
    </div>
  </div>

<!-- Dashboard -->
<div id="dashboard-page" style="display:none;width:100%>
</div>

<!-- Dashboard -->
<div id="dashboard-page" style="display:none;width:100">
  <!-- Header%">
  <!-- -->
  <header class="header">
    Header -->
  <header class="header">
    <div class="header-left">
      <span <div class="header-left">
      <span class="logo"> class="logo">V2Render</span>
      <nav class="headerV2Render</span>
      <nav class="-nav">
        <button class="nav-link activeheader-nav">
        <button class="nav-link active" data-page="dashboard" data" data-page="dashboard" data-en="Dashboard" data-fa="داش-en="Dashboard" data-fa="بورد">Dashboard</button>
        <button class="داشبورد">Dashboard</button>
        <button class="nav-link" data-pagenav-link" data-page="inbounds="inbounds" data-en="Inbounds" data-en="Inbounds" data-fa="اینباندها">Inbounds</button>
       " data-fa="اینباندها">Inbounds</button>
        <button class=" <button class="nav-link" data-pagenav-link" data-page="traffic="traffic" data-en="Traffic" data-fa="تر" data-en="Traffic" data-fa="ترافیک">Traffic</button>
        <button class="nav-link" data-page="addressافیک">Traffic</button>
        <button class="nav-link" data-pagees" data-en="Clean IP="addresses" data-en="Clean IP" data-fa="آی‌پی تمیز" data-fa="آی‌پی تمیز">Clean IP</button">Clean IP</button>
        <button class="nav>
        <button class="nav-link" data-page="security" data-en="Security-link" data-page="security" data-en="Security" data-fa="امنیت" data-fa="امنیت">Security</button>
      </nav>
   ">Security</button>
      </nav>
    </div>
    <div class="header-right">
 </div>
    <div class="header-right">
      <button class="btn btn      <button class="btn btn-out-outline btn-sm" onclick="randomline btn-sm" onclick="randomInbound()" data-en="+Inbound()" data-en="+ Random User" data-fa Random User" data-fa="="+ کاربر تصادفی">++ کاربر تصادفی">+ Random User</button>
 Random User</button>
      <div class="lang-switch">
        <button class="lang-btn lang      <div class="lang-switch">
        <button class="lang-btn lang-en active" onclick="setLang('en')">-en active" onclick="setLang('EN</button>
        <button classen')">EN</button>
        <button="lang-btn lang-fa" onclick="setLang('fa')">FA</ class="lang-btn lang-fa" onclick="setLang('fa')">FA</button>
      </div>
      <button class="btnbutton>
      </div>
      <button class="btn-icon" onclick="toggleTheme()" title="Toggle theme">🌙</button-icon" onclick="toggleTheme()" title="Toggle theme">🌙</>
      <button class="btn btnbutton>
      <button class="btn btn-danger btn-sm" onclick="doLogout()"-danger btn-sm" onclick="doLogout()" data-en="Logout" data-fa="خروج data-en="Logout" data-fa="">Logout</button>
خروج">Logout</button>
    </div>
  </header>

  <main    </div>
  </header>

  <main class="main">
    <!-- Dashboard Page class="main">
    <!-- Dashboard -->
    <section class=" Page -->
    <section class="page active" id="page-dashboard">
      <div class="page-header">
       page active" id="page-dashboard">
      <div class="page-header">
        <div>
          <div class="page-title" data <div>
          <div class="page-title" data-en="Dashboard" data-fa="د-en="Dashboard" data-fa="اشبورد">Dashboard</داشبورد">Dashboard</div>
          <div class="page-sub" id="last-up">–</div>
          <div class="page-sub" id="last-up">–</div>
        </div>
      </div>
     div>
        </div>
      </div>
      <div class="stats-row">
        <div class="stat-card"><div class=" <div class="stats-row">
        <div class="stat-card"><div class="stat-label" data-en="Traffic" data-fa="ترstat-label" data-en="Traffic" data-fa="ترافیک">Traffic</div><div class="stat-val" id="sv-traffic">–افیک">Traffic</div><div class="stat-val" id="sv-traffic">–<span<span class="stat-unit"> MB</span></div></div>
        <div class="stat-unit"> MB</span></div></div>
        <div class=" class="stat-card"><div class="statstat-card"><div class="stat-label" data-label" data-en="Inbounds" data-fa="اینباندها">In-en="Inbounds" data-fa="اینباندها">Inbounds</bounds</div><div classdiv><div class="stat="stat-val" id="sv-links">–-val" id="sv-links">–</div></</div></div>
        <div class="stat-card"><div class="stat-label" data-endiv>
        <div class="stat-card"><div class="stat-label" data-en="Uptime" data-fa="آپتایم">Uptime="Uptime" data-fa="آپتایم">Uptime</div</div><div class="stat-val" id="sv><div class="stat-val" id="sv-uptime" style="font-size:-uptime" style="font-size:11.2rem;">.2rem;">–</div></div>
        <div class="stat–</div></div>
        <div class="stat-card"><div class="stat-label-card"><div class="stat-label" data-en="" data-en="Domain" data-fa="دامDomain" data-fa="دامنه">Domain</div><div class="stat-val" id="sv-domain" styleنه">Domain</div><div class="stat-val" id="sv-domain" style="font-size="font-size:0.95rem;word:0.95rem;word-break-break:break-all;">–</:break-all;">–</div></div>
      </div>
      <div stylediv></div>
      </div>
      <div style="display:grid;grid-template-column="display:grid;grid-template-columns:1frs:1fr 1fr;gap:16px;">
        <div 1fr;gap:16px;">
        <div class="card">
 class="card">
          <div class="card-hd          <div class="card-hd"><span"><span class="card-title" data class="card-title" data-en="CPU" data-f-en="CPU" data-fa="پردازنده">CPU</spana="پردازنده">CPU</span><span id="cpu-v><span id="cpu-v" style="" style="font-weight:700;color:font-weight:700;color:var(--primary);">–%</span></div>
         var(--primary);">–%</span></div>
          <div class="sys-bar <div class="sys-bar"><div class=""><div class="sys-fill" idsys-fill" id="cpu-b="cpu-b" style="background:var" style="background:var(--primary);"></div></div>
        </div>
       (--primary);"></div></div>
        </div <div class="card">
          <div class="card-hd"><span class="card-title">
        <div class="card">
          <div class="card-hd"><span class data-en="Memory" data-fa="card-title" data-en="Memory" data-fa="حافظه">Memory="حافظه">Memory</span><span id="</span><span id="mem-v" style="fontmem-v" style="font-weight:700-weight:700;color:var(--green);;color:var(--green);">–%</span></div>
          <div class">–%</span></div>
="sys-bar"><div class="sys          <div class="sys-bar"><div class="sys-fill" id="mem-b" style="background:-fill" id="mem-b" style="background:var(--green);"></divvar(--green);"></div></div>
        </div>
      </div>
     ></div>
        </div>
      </div>
 <div class="card">
        <div class="      <div class="card">
card-hd"><span class="card-title        <div class="card-hd"><span class="card-title" data-en="Hourly Traffic"" data-en="Hourly Traffic" data-fa="ترافیک ساعتی"> data-fa="ترافیکHourly Traffic</span></div>
 ساعتی">Hourly Traffic</span></div>
        <div class="chart-container"><canvas        <div class="chart-container"><canvas id="tc"></canvas></div>
      </div>
 id="tc"></canvas></div>
      </div>
    </section>

    <!-- Inbounds Page    </section>

    <!-- Inbounds Page -->
 -->
    <section class="page"    <section class="page" id="page-in id="page-inbounds">
      <div class="bounds">
page-header">
        <div>
          <div class="page-title" data-en="      <div class="page-header">
        <div>
          <div class="page-title" data-en="Inbounds" data-fa="اینInbounds" data-fa="اینباندها">Inbounds</div>
باندها">Inbounds</div>
          <div          <div class="page-sub" data class="page-sub" data-en="VLESS over WebSocket · TLS" data-en="VLESS over WebSocket · TLS" data-fa="VLESS روی WebSocket با-fa="VLESS روی WebSocket با TLS">VLESS over WebSocket · TLS</div>
        </div>
        TLS">VLESS over WebSocket · TLS</div>
        </div>
        <button class="btn btn-primary" onclick=" <button class="btn btn-primaryshowAddMo()" data-en="+" onclick="showAddMo()" data-en="+ Create" data-fa Create" data-fa="+ ایجاد">+="+ ایجاد">+ Create</button>
      </div>
      <div style Create</button>
      </div>
      <div style="display:flex;gap="display:flex;gap:12px;margin-bottom:20:12px;margin-bottom:20px;">
        <input id="srchpx;">
        <input id="" placeholder="Searchsrch" placeholder="Search…" oninput="filterLinks…" oninput="filterLinks()" class()" class="="fi" style="flex:1;">
        <buttonfi" style="flex:1;">
        <button class="chip active" data class="chip active" data-filter="all" onclick="setFilter('all-filter="all" onclick="setFilter('all',this)">All',this)">All</button>
</button>
        <button class="chip        <button class="chip" data-filter="active" onclick="setFilter('active" data-filter="active" onclick="setFilter('active',this)">Active</button>
        <button class',this)">Active</button>
        <button class="chip" data-filter="="chip" data-filter="off" onclick="setFilteroff" onclick="setFilter('off',this('off',this)">Off</button>
      </div>
      <div class)">Off</button>
      </div>
      <div class="card" style="padding="card" style="padding:0;overflow:hidden;">
        <div class=":0;overflow:hidden;">
        <div class="tbl-wrap">
tbl-wrap">
          <table class="tbl" id="links          <table class="tbl" id="links-table">
-table">
            <thead            <thead><tr><th>#</><tr><th>#</th><thth><th>Name</th><th>Name</th><th>Type</>Type</th><th>Usage</th><th>Usage</th><th>IPs</th><th>Expiry</th><th>IPs</th><th>Expth><th>Status</th><th>iry</th><th>Status</th><th>Actions</th></tr></Actions</th></tr></thead>
            <tbody idthead>
            <tbody id="ltb"></tbody="ltb"></tbody>
>
          </table>
        </          </table>
        </div>
        <div class="empty" id="lemptydiv>
        <div class="empty" id="lem" style="display:none;paddingpty" style="display:none;padding:40px;">No inbounds found</div>
:40px;">No in      </div>
    </sectionbounds found</div>
      </div>
    </section>

    <!-- Traffic Page -->
>

    <!-- Traffic Page -->
    <section class    <section class="page" id="page-traffic="page" id="page-traffic">
      <div class="">
      <div class="page-header">
        <div classpage-header">
        <div class="page-title" data-en="Traffic" data-fa="ترافیک">="page-title" data-en="Traffic" data-fa="ترافیک">Traffic</div>
      </div>
      <divTraffic</div>
      </div>
      <div class="card">
        class="card">
        <div style <div style="display:flex;justify-content:space-between;padding:12px 0;border="display:flex;justify-content:space-bottom:1px solid var(--border-between;padding:12px 0;border-bottom:);"><span class="sl-k1px solid var(--border);">Total Traffic</span><"><span class="sl-k">Total Traffic</span><spanspan id="t-tr" id="t-tr" class="sl-v">– class="sl-v">–</span></div>
        <div style="</span></div>
        <div style="display:flex;justify-content:spacedisplay:flex;justify-content:space-between;padding:12px 0;-between;padding:12px 0;border-bottom:1px solid var(--border);"><spanborder-bottom:1px solid var(--border);"><span class="sl-k">Total Requests</ class="sl-k">Total Requests</span><span><span id="t-rq" classspan id="t-rq" class="sl-v">–</span></div>
       ="sl-v">–</span></div>
        <div style="display:flex;justify <div style="display:flex;justify-content:space-between;padding:12px-content:space-between;padding:12px 0;"><span class="sl-k">Uptime 0;"><span class="sl-k">Uptime</span><span id="t-up" class="sl-v">–</span></</span><span id="t-up" class="sl-v">–</span></div>
      </div>
    </section>

    <!--div>
      </div>
    </section>

    <!-- Clean IP Page -->
    Clean IP Page -->
    <section class="page" id="page-addresses">
 <section class="page" id="page-addresses">
      <div class="page-header">
        <      <div class="page-header">
        <div classdiv class="page-title" data-en="Clean IP" data-fa="آی="page-title" data-en="Clean IP" data-fa="آی‌پی تمیز">Clean‌پی تمیز">Clean IP</ IP</div>
      </div>
      <div classdiv>
      </div>
      <div class="card">
        <div class="fg">
="card">
        <div class="fg">
          <label class="fl          <label class="fl" data-en="Add Addresses (one per" data-en="Add Addresses (one per line)" data-fa="افزودن line)" data-fa="افزودن آدرس (هر خط یک آدرس (هر خط یک)">Add Addresses (one per line)</)">Add Addresses (one per line)</label>
          <textarea class="fi" id="batch-addrs" rows="4label>
          <textarea class="fi" id="batch-addrs" rows="4" placeholder="8.8.8." placeholder="8.8.8.8&#10;example.com"></8&#10;example.com"></textarea>
        </div>
        <button class="btn btn-primary"textarea>
        </div>
        <button class="btn btn-primary" onclick="add onclick="addBatchAddrs()" data-en="AddBatchAddrs()" data-en="Add All" data-fa="افزودن همه">Add All</button All" data-fa="افزودن همه">Add All</button>
        <>
        <button class="btn btn-danger btn-sm" onclick="deletebutton class="btn btn-danger btn-sm" onclick="deleteAllAddAllAddrs()" style="marginrs()" style="margin-left:8px;" data-en="Delete-left:8px;" data-en="Delete All" data-fa=" All" data-fa="ححذف همه">Delete All</button>
ذف همه">Delete All</button>
        <div id="addr-list" style="margin        <div id="addr-list" style="margin-top:20px;"></div>
      </-top:20px;"></div>
      </div>
    </section>

    <!-- Security Page -->
div>
    </section>

    <!-- Security Page -->
    <section class="page" id    <section class="page" id="page-security">
      <div class="page="page-security">
      <div class="page-header"><div class="page-title" data-en="-header"><div class="page-title"Security" data-fa="ام data-en="Security" data-fa="امنیت">Security</div></div>
      <div style="max-widthنیت">Security</div></div>
      <div style="max:400px;margin:0 auto;">
       -width:400px;margin:0 auto;">
        <div class="card">
          <div class="fg"><label class="fl" <div class="card">
          <div class="fg"><label class=" data-en="Current Password"fl" data-en="Current Password" data-fa="رمز فعلی">Current Password</label data-fa="رمز فعلی">Current Password</label><input><input class="fi" type="password class="fi" type="password" id="cpw"></div>
          <div" id="cpw"></div>
          <div class="fg"><label class class="fg"><label class="fl" data-en="New Password" data-fa="fl" data-en="New Password" data-f="رمز جدید">New Password</label><input class="a="رمز جدید">New Password</label><input class="fi" type="password"fi" type="password" id="npw id="npw"></div>
          <button class="btn btn-primary" onclick=""></div>
          <button class="chgPw()" style="width:100btn btn-primary" onclick="chgPw()"%;justify-content: style="width:100%;justify-content:center;">Update Passwordcenter;">Update Password</button>
        </</button>
        </divdiv>
     >
      </div>
    </section </div>
    </section>
  </main>

  <!-- Footer -->
  <footer class="footer">
    <span>V2>
  </main>

  <!-- Footer -->
  <footer class="footer">
    <span>V2Render PanelRender Panel · · VL VLESS WSESS WS Tunnel</ Tunnel</span>
  </span>
  </footer>
</footer>
</div>

<!-- Modalsdiv>

<!-- Modals -->
<div class="mo -->
<div class="mo" id="mo-add">
  <div class="mo" id="mo-add">
  <div class-box">
    <button class="mo-close"="mo-box">
    <button class="mo onclick="document.getElementById('mo-add').class-close" onclick="documentList.remove('show')">.getElementById('mo-add').classList.remove('show')">✕</button>
    <✕</button>
    <div class="mo-titlediv class="mo-title" data-en" data-en="Create Inbound" data="Create Inbound" data-fa-fa="ایجاد اینباند">Create Inbound</div>
    <div="ایجاد اینباند">Create Inbound</div class="fg"><label class="fl">>
    <div class="fg"><label classRemark</label><input class="fi="fl">Remark</label><input class="fi" id="nl" placeholder="e.g. User" id="nl" placeholder="e.g. User-1"></div>
   -1"></div>
    < <div style="display:flexdiv style="display:flex;gap:12px;">
      <;gap:12divpx;">
      <div class="fg" class="fg" style="flex:1 style="flex:1;"><label class="fl">Traffic Limit</label;"><label class="fl">Traffic Limit</label><input class="fi"><input class="fi" id id="nv" type="number" min="0="nv" type="number" min="0"" step="0.1" step="0.1" placeholder="0 = placeholder="0 = ∞"></div>
      ∞"></div>
      <div <div class="fg" style="width:100 class="fg" style="widthpx;"><label class="fl">Unit</:100px;"><label class="label><select class="fsfl">Unit</label><select class="fs" id="nu" id="nu"><option>GB</"><option>GB</option></selectoption></select></div>
    </></div>
    </div>
    <divdiv>
    <div class="fg"><label class class="fg"><label class="fl">Max IPs="fl">Max IPs</label><input class="fi" id="nc" type="</label><input class="fi"number" min="0" placeholder="0 id="nc" type="number" min="0" placeholder="0 = ∞"></div>
    <div class="fg"><label = ∞"></div>
    <div class="fg class="fl">Days Valid</label><input class"><label class="fl">Days Valid</="fi" id="nd" type="number"label><input class="fi" id="nd min="0" placeholder="0" type="number" min="0" placeholder="0 = No = No expiry"></div>
    expiry"></div>
    <button class="btn btn-primary <button class="btn btn-primary" onclick="" onclick="createLink()" style="createLink()" style="width:100%;justify-content:center;margin-top:16width:100%;justify-content:px;">CREATE</button>
  </div>
center;margin-top:16px;">CREATE</button>
</div>

<div class="mo"  </div>
</div>

<div id="mo-edit">
  <div class="mo class="mo" id="mo-edit">
  <div class="mo-box">
    <button-box">
    <button class="mo- class="mo-close" onclickclose" onclick="document.getElementById('mo-="document.getElementById('mo-edit').classList.remove('edit').classList.remove('show')">✕</button>
    <div class="mo-titleshow')">✕</button>
    <div" id="et">Edit Inbound</ class="mo-title" id="div>
    <input type="hidden" id="euet">Edit Inbound</div>
    <input type">
    <div class="fg"><label="hidden" id="eu">
    <div class="fg"><label class class="fl">Name</label="fl">Name</label><input class="fi"><input class="fi" id="en2" readonly id="en2" readonly style="opacity style="opacity:0.5:0.5;"></;"></div>
    <div style="display:flex;gapdiv>
    <div style="display:flex;gap:12px;">
      <div class="fg" style:12px;">
      <div class="="flex:1;"><label class="fl">Trafficfg" style="flex:1;"><label Limit</label><input class="fi" id=" class="fl">Traffic Limit</label><input classel" type="number" min="fi" id="el" type="number" min="0"></="0"></div>
      <div class="fg"div>
      <div class="fg" style="width:100px;"><label class="fl">Unit</label style="width:100px;"><label class="fl">Unit</label><select class="fs" id="eu2><select class="fs" id="eu2"><option>GB</option"><option>GB</option></select></div>
    </div>
    <div></select></div>
    </div>
    <div class="fg"><label class="fl class="fg"><label class="fl">Max IPs">Max IPs</label><input class="</label><input class="fi" id="ec" type="number" min="fi" id="ec" type="number" min="0"></div>
    <div class="fg"><label class="fl">Extend0"></div>
    <div class="fg"><label class="fl">Extend Days</ Days</label><input class="fi" id="edlabel><input class="fi" id="ed" type="number" min="0"></div>
    <div style="" type="number" min="0"></div>
    <div styledisplay:flex;gap:12px;margin-top="display:flex;gap:12px;margin-top:16px;">
      <button:16px;">
      <button class="btn btn-primary" onclick="saveEdit() class="btn btn-primary" onclick="saveEdit()" style="flex:1;" style="flex:1;justify-content:center;">SAVEjustify-content:center;">SAVE</button>
      <button class="btn btn</button>
      <button class="btn btn-danger" onclick="resetTraf()">Reset Traffic-danger" onclick="resetTraf()</button>
    </div">Reset Traffic</button>
    </div>
  </div>
</div>

<div class="mo>
  </div>
</div>

<div class="mo" id="mo-qr">
" id="mo-qr">
  <div class="mo-box" style="max-width  <div class="mo-box" style="max:360px;">
    <button class="mo-close" onclick="document.getElementById('-width:360px;">
    <button class="mo-close" onclick="mo-qr').classList.remove('showdocument.getElementById('mo-qr').classList.remove('')">✕</button>
    <div classshow')">✕</button>
    <div class="mo-title">QR Code="mo-title">QR Code</div>
   </div>
    <div style="text-align: <div style="text-align:center;padding:20center;padding:20px;background:var(--surface3);border-radius:12px;background:var(--surface3);border-radius:12pxpx;"><img id="qr-img" src;"><img id="qr-img" src="" alt="QR"></div>
    <button class="" alt="QR"></div>
    <button class="btn btn="btn btn-primary btn-primary btn-sm"-sm" onclick="dlQR()" style="width:100%;just onclick="dlQR()" style="width:100%;justify-content:center;marginify-content:center;margin-top:16-top:16px;">Download</button>
px;">Download</button>
  </div>
</div>

<script>
// ── Globals ─────────────────  </div>
</div>

<script>
// ── Globals ──────────────────────────────────────────────────────────────
const $=s─────────────────────────────────────────────
const=>document.querySelector(s),$m= $=sid=>document.getElementById(id),esc=>document.querySelector(s),$m=id=>document.getElementById(id),esc=s=s=>String(s).replace(/</g,'&lt;').replace(/>/g,'&gt=>String(s).replace(/</g,'&lt;').replace(/>/g,'&gt;');
const langMap={en:{edit:'Edit',;');
const langMap={en:{edit:'Edit',copy:'Copy',sub:'Sub',qr:'QRcopy:'Copy',sub:'Sub',qr:'QR',del:'Del'},fa:{edit:'ویرایش',copy:'ک',del:'Del'},fa:{edit:'ویرایش',copy:'کپی',sub:'اشتراکپی',sub:'اشتراک',',qr:'QR',del:'حذف'}};
function tr(kqr:'QR',del:'حذف'}};
function tr(k){return(langMap[){return(langMaplang]&&langMap[lang][k[lang]&&langMap[lang][k])||langMap['en'][])||langMap['en'][k]||k;}
let lang=localStorage.getItem('k]||k;}
let lang=localStorage.getItem('ll')||'en',theme=localStoragell')||'en',theme=localStorage.getItem('theme')||'dark';
let allLinks=[],cf.getItem('theme')||'dark';
let allLinks=[],cf='all',sData={},tChart=null,='all',sData={},tChart=nullallAddrs=[],is,allAddrs=[],isAuthenticated=false;

function setTheme(t){themeAuthenticated=false;

function setTheme(t){theme=t;document.body.classList.t=t;document.body.classList.toggle('light-mode',t==='light');localoggle('light-mode',t==='light');localStorage.setItem('theme',t);document.querySelector('.Storage.setItem('theme',t);btn-icon').textContent=t==='document.querySelector('.btn-icon').textContent=t==='light'?'☀️':'🌙';light'?'☀️':'🌙';updChartColors();}
function toggleTheme(){setTheme(theme==='dark'?'light':'updChartColors();}
function toggleTheme(){setTheme(theme==='dark'dark');}
function setLang(l){?'light':'dark');}
function setLang(l){lang=l;document.querySelectorAll('.lang-en,.lang=l;document.querySelectorAll('.lang-en,.lang-falang-fa').forEach(e=>e.classList.remove('active'));document').forEach(e=>e.classList.remove('active'));document.querySelectorAll(`.lang-${l}`).forEach(e=>e.classList.add('.querySelectorAll(`.lang-${l}`).forEach(e=>e.classList.add('active'));document.body.dir=l==='faactive'));document.body.dir=l==='fa'?'rtl':'ltr'?'rtl':'ltr';document.querySelectorAll('[data-en]').forEach(el';document.querySelectorAll('[data-en]').forEach(el=>{const v=el.getAttribute('data=>{const v=el.getAttribute('data-'+l);if(v-'+l);if(v)el.textContent=v;});localStorage.setItem('ll',l);)el.textContent=v;});localStorage.setItem('ll',l);filterLinks();}

async function checkAuth(){filterLinks();}

async function checkAuth(){try{const r=await fetch('/api/try{const r=await fetchme');(('/api/me');(await r.json()).authenticated?showDashboard():await r.json()).authenticated?showshowLogin();}catch{showLogin();Dashboard():showLogin();}catch{showLogin();}}
function showLogin()}}
function showLogin(){$m('login-page').style.display{$m('='';$m('dashboard-page').stylelogin-page').style.display='';$m('dashboard.display='none';}
function showDashboard()-page').style.display='none';}
function show{$m('login-page').style.display='noneDashboard(){$m('login-page';$m('dashboard-page').style.display='none';$m('dashboard-page').style.display='';initChart();load').style.display='';initChart();loadStats();loadStats();loadLinks();loadAddLinks();loadAddrs();}

async function doLogin(){const pwrs();}

async function doLogin(){const pw=$m('login-pw').value;$m('login=$m('login-pw').value;$m('login-err').style.display='-err').style.display='nonenone';try{const r=await fetch';try{const r=await fetch('/api/login('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});JSON.stringify({password:pw})});if(r.ok){$m('if(r.ok){$m('login-pw').login-pw').value='';showDashboard();}else $m('login-err').style.display='value='';showDashboard();}else $m('login-err').style.display='block';}catch{$m('login-block';}catch{$m('login-err').style.display='block';}}
async function doLogout(){await fetch('/apierr').style.display='block';}}
async function doLogout(){await fetch('/api/logout',/logout',{method:'POST'});showLogin();{method:'POST'});showLogin();}

document.querySelectorAll('.nav-link[data-page]').forEach(el}

document.querySelectorAll('.nav-link[data-page]').forEach(el=>el=>el.addEventListener('click',()=>switchPage(el.addEventListener('click',()=>switchPage(el.dat.dataset.page)));
function switchPage(idaset.page)));
function switchPage(id){document.querySelectorAll('.page){document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));').forEach(p=>p.classList.remove('active'));$$m('page-'+id).m('page-'+id).classclassList.add('active');document.querySelectorAllList.add('active');document.querySelectorAll('.nav-link').forEach(n=>n.classList.t('.nav-link').forEach(n=>n.classList.toggle('active',n.dataset.page===oggle('active',n.datasetid));}

.page===id));}

function toast(msg,err=false){const t=$m('function toast(msg,err=false){const t=$m('toast');toast');t.textContent=msg;t.className='toast'+(err?' errt.textContent=msg;t.className='toast'+(err?' err':'')+' show';clearTimeout(t._hide);t._hide=set':'')+' show';clearTimeout(t._hide);t._hide=setTimeout(()=>t.classList.remove('showTimeout(()=>t.classList.remove('show'),3000);}

function fmtB(b){if(!b||b===0)return''),3000);}

function fmtB(b){if(!b||b===0)return'0 B';return b>=0 B';return b>=1073741824?(b/1073741824).1073741824?(b/1073741824).toFixed(2)+' GB':b>=toFixed(2)+' GB':b>=1048576?(b/1041048576?(b/1048576).toFixed(2)+' MB':(b/1028576).toFixed(2)+' MB':(b4).toFixed(1)+' KB';}
function fmtLim(b){if(!b||b/1024).toFixed(1)+' KB';}
function fmtLim(b){if(!b||b===0)return'∞';const g=b/===0)return'∞';const g=b/1073741824;return(g%1===01073741824;return(g%1===0?g.toFixed(0):g.toFixed(1))+' GB';}
function?g.toFixed(0):g.toFixed(1))+' GB';}
function fmtExp(ea){if fmtExp(ea){if(!ea||ea===0)return'(!ea||ea===0)return'∞';const d=new Date(ea)-new Date∞';const d=new Date(ea)-new Date();if(d<=0)return'();if(d<=0)return'Expired';const days=Math.floor(d/864Expired';const days=Math.floor(d/86400000);if(days>0)return00000);if(days>0)return days+'d';const hours=Math days+'d';const hours=Math.floor(d/3600000);if.floor(d/3600000);if(hours>0)return hours+'h';(hours>0)return hours+'h';return Math.floor(d/60000return Math.floor(d/60000)+'m)+'m';}

function setFilter(f,el){cf=f;document.querySelectorAll('.chip').forEach(c=>c.classList';}

function setFilter(f,el){cf=f;document.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'.remove('active'));el.classList.add('active');));el.classList.add('active');filterLinks();}
function filterLinks(){const qfilterLinks();}
function filterLinks(){const q=($m('srch=($m('srch')?.value||'').to')?.value||'').toLowerCase();let r=allLinks;if(cf==='active')r=r.filter(l=>LowerCase();let r=allLinks;if(cf==='active')r=r.filter(l=>l.active);else if(cl.active);else if(cf==='off')r=r.filter(l=>!l.activef==='off')r=r.filter(l);if(q)r=r=>!l.active);if(q)r=r.filter(l=>l.label.toLowerCase().includes(q)||.filter(l=>l.label.toLowerCasel.uuid.toLowerCase().includes(q));renderLinks(r);}
function renderLinks(links().includes(q)||l.uuid.toLowerCase().includes(q));renderLinks(r);}
function renderLinks){
  const tb=$m('ltb'),em=$(links){
  const tb=$mm('lempty');
 ('ltb'),em=$m('lempty');
 if(!links||!links.length){tb.innerHTML='  if(!links||!links.length){tb.innerHTML='';em.style.display='block';em.style.display='block';return;}
  em.style.display='none';let idx';return;}
  em.style.display='none';let idx=links.length;
  tb=links.length;
  tb.innerHTML=links.map(l=>{const u=l.used_bytes||0.innerHTML=links.map(l=>{const u=l.used_bytes||0,lim=l.limit_bytes||0,pct=lim,lim=l.limit_bytes||0,pct=lim>0?>0?Math.min(100,(u/lim)*100):0,colMath.min(100,(u/lim)*100):0,col=pct>90=pct>90?'var(--red)':?'var(--red)':pct>70?'var(--yellow)':'var(--primary)',ex=fmtExp(l.expires_at),pct>70?'var(--yellow)':'var(--primary)',ex=fmtExp(l.expires_at),ec=ex==='Expired'?'varec=ex==='Expired(--red)':ex==='∞'?'var(--'?'var(--red)':ex==='∞'?'var(--text3)':'var(--text3)':'var(--text2)',i=idx--,text2)',i=idx--,cc=l.current_connections||0,mc2=l.max_connections||0;returncc=l.current_connections||0,mc2=l.max_connections||0;return`<tr><td>${i`<tr><td>${i}</td><td style}</td><td style="font="font-weight:600">${esc(l.label)}</td><td><span class-weight:600">${esc(l.label)}</td><td><span class="tag tag-vless">VLESS</span="tag tag-vless">VLESS</span></td><td><div class="pill"><span class="pill-used">${fmt></td><td><div class="pill"><span class="pill-used">${fmtB(u)}B(u)}</span><div class="</span><div class="pill-bar"><div class="pill-fillpill-bar"><div class="pill-fill" style="" style="width:${pct}%;background:${col}"></div></div><spanwidth:${pct}%;background:${col>${fmtLim(lim)}</span></}"></div></div><span>${fmtLimdiv></td><td>${cc}/${mc(lim)}</span></div></td><2||'∞'}</tdtd>${cc}/${mc2||'∞'}</td><td style="color:><td style="color:${ec}">${ex}</td><td><span${ec}">${ex}</td class="tag ${l.active?'tag-on':'tag-off><td><span class="tag ${l.active'}">${l.active?'On':'?'tag-on':'tag-off'}">${l.active?'Off'}</span></td><td><divOn':'Off'}</span></td>< style="display:flex;gap:4pxtd><div style="display:flex;;"><button class="toggle ${gap:4px;"><button class="toggle ${l.active?'on':l.active?'on':''}" data-''}" data-uid="${l.uuid}"uid="${l.uuid}" onclick="togLink(this)"></button><button onclick="togLink(this)"></ class="act-btn act-edit" onclick="button><button class="act-btn act-edit" onclick="showshowEditMoEditMo('${l.u('${l.uuid}')">${tr('edituid}')">${tr('edit')}</button><button class="act-btn act-copy" onclick="cpLink')}</button><button class="act-btn act-c('${esc(l.vless_link)}opy" onclick="cpLink('${esc(l.vless_link)}')">${tr('copy')}</')">${tr('copy')}</button><button class="act-btn act-sub"button><button class="act-btn act-sub" onclick="cpSub('${l.uuid}')"> onclick="cpSub('${l.uuid}${tr('sub')}</button><button class="act-btn act-qr" onclick')">${tr('sub')}</button><button class="act-btn act-qr" onclick="showQR('${esc(l.vless_link)}')="showQR('${esc">${tr('qr')(l.vless_link)}')">${tr('}</button><button class="act-btn act-del" onclickqr')}</button><button class="act-btn act-del"="delLink('${l.uuid onclick="delLink('${l}')">${tr('del')}</button></div></td></tr>`})..uuid}')">${tr('del')}</button></div></td></tr>`join('');
}

}).join('');
}

async function togLink(el){const uid=elasync function togLink(el){const uid=.dataset.uid,l=allLinksel.dataset.uid,l=.find(x=>x.uuid===uidallLinks.find(x=>x.uuid===uid);if(!l)return;const na=!l.active;try{await fetch);if(!l)return;const na=!l.active;try{await('/api/links/'+uid,{method:'PATCH',headers fetch('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON:{'Content-Type':'application/json'},body:JSON.stringify({active:na})});l.active=.stringify({active:na})});l.active=na;na;filterLinks();loadStats();filterLinks();loadStats();}catch}catch{toast('Failed',true);}}
async function randomInbound{toast('Failed',true);}}
async function randomInbound(){const names=['(){const names=['UserUser','','Client','NodeClient','Node','Peer'];const','Peer'];const n=names[Math n=names[Math.floor(Math.random()*names.floor(Math.random()*names.length)]+'-.length)]+'-'+Math.floor(Math.random()'+Math.floor(Math.random()*1000*1000);try{await);try{await fetch('/api/links fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},',{method:'POST',headers:{body:JSON.stringify({label'Content-Type':'application/json'},body:JSON.stringify({label:n,limit:n,limit_value:0})_value:0})});toast(`Created ${n}`);loadLinks();loadStats();}catch{toast});toast(`Created ${n}`);loadLinks();loadStats();}catch{toast('Error',true);}}
function showAdd('ErrorMo(){$m('mo-add',true);}}
function showAddMo(){$m('mo-add').classList.add('show').classList.add('show');}
');}
async function createLink(){const labelasync function createLink(){const label=$m('nl').value=$m('nl').value.trim()||'New.trim()||'New';';const v=parseFloat($m('nv').value)||const v=parseFloat($m('nv').value)||0,mc=parseInt($m('nc').value0,mc=parseInt($m('nc').value)||0,days=)||0,days=parseInt($m('nd').value)||0;parseInt($m('nd').value)||0;try{await fetch('/apitry{await fetch('/api/links',{method/links',{method:'POST',headers:{:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label'Content-Type':'application/json'},body:JSON.stringify({label,limit_value:v,limit_value:v,limit_unit:'GB',max_connections:mc,days_valid:,limit_unit:'GB',max_connections:mc,days_valid:days})});toast('Created');$m('modays})});toast('Created');$m('mo-add').classList.remove('show-add').classList.remove('show');loadLinks();loadStats();}catch{');loadLinks();loadStats();}catch{toast('Error',true);}}
function showEditMo(uid){toast('Error',const l=allLinks.find(x=>xtrue);}}
function showEditMo(uid){const l.uuid===uid);if(!l)return;$=allLinks.find(x=>x.uuid===uid);if(!l)return;$m('eu').value=uid;$m('eu').value=uid;$m('en2m('en2').value=l.label;$').value=l.label;$m('m('el').value=l.limit_bytes>0?(l.limit_bytes/107el').value=l.limit_bytes>0?(3741824):'';$m('ec').value=ll.limit_bytes/1073741824):.max_connections||'';$m'';$m('ec').value=l('ed').value='';$.max_connections||'';$m('ed').value='';$m('et').textContent='Edit:m('et').textContent='Edit: '+l.label;$ '+l.label;$m('mo-edit').classList.add('m('mo-edit').classList.add('show');show}
async');}
async function saveEdit(){const uid=$m('eu').value function saveEdit(){const uid=$m('eu').value,v=parseFloat,v=parseFloat($m('el').value)||0,mc=parseInt($($m('el').value)||0,mc=parseInt($m('ecm('ec').value)||0,days=parseInt($m('ed').value)||0;const body={limit_value:v,limit_unit:'GB',max_').value)||0,days=parseInt($m('ed').value)||0connections:mc};if(days);const body={limit_value:v,limit_unit:'GB',max_connections:mc};if(days)body.days_valid=days;body.days_valid=days;try{await fetch('/api/try{await fetch('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'applicationlinks/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json/json'},body:JSON.stringify(body)});toast('Updated');$m('mo-edit'},body:JSON.stringify(body)});toast('Updated');$m('mo-edit').classList.remove('show');load').classList.remove('show');loadLinks();}catch{toast('Error',Links();}catch{toast('Error',true);}}
async function resetTtrue);}}
async function resetTraf(){const uid=$m('eu').value;raf(){const uid=$m('eu').value;if(!confirm('Reset?'))return;try{await fetch('/api/links/'+uid,{method:'PATCH',headers:{'if(!confirm('Reset?'))return;try{await fetch('/api/links/'Content-Type':'application/json'},+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({reset_usage:true})});toast('Reset');loadLinks();}body:JSON.stringify({reset_usage:true})});toast('Reset');loadLinkscatch{toast('Error',true);}}
async function delLink(uid){if();}catch{toast('Error',true);}}
async function delLink(uid(!confirm('Delete?'))return){if(!confirm('Delete?'));try{await fetch('/api/links/'+uid,{method:'DELETE'});toastreturn;try{await fetch('/api/links/'+uid,{method:'DELETE'});('Deleted');loadLinks();loadtoast('Deleted');loadLinks();loadStats();}catch{toast('Error',true);Stats();}catch{toast('Error',true);}}
function cpLink(txt){navigator.clipboard.write}}
function cpLink(txt){nText(txt).then(()=>toast('Copiedavigator.clipboard.writeText(txt).then(()=>toast('Cop!')).catch(()=>toastied!')).catch(()=>to('Failed',true));}
asyncast('Failed',true));}
 function cpSub(uid){await navigator.clipboardasync function cpSub(uid){await navigator.clipboard.writeText('https://'+.writeText('https://'+location.host+'/sub/'+uid);tolocation.host+'/sub/'+ast('Sub URL copied!');}
function showQR(txt){$uid);toast('Sub URL copied!');}
function showQR(txt){m('qr-img').src='https://api.qrserver.com/v1$m('qr-img').src='https://api.qrserver.com/v1/create-qr-code/?size=280x280&/create-qr-code/?size=data='+encodeURIComponent(txt);280x280&data='+encodeURIComponent(t$m('mo-qr').classList.addxt);$m('mo-qr').classList.add('show');}
function dl('show');}
function dlQR(){const a=document.createElement('a');a.hQR(){const a=document.createElement('aref=$m('qr-img').src;a.d');a.href=$m('ownload='qr.png';a.click();qr-img').src;a.download='qr.png';a.click();}

async function}

async function loadStats(){
  try loadStats(){
  try{const r=await{const r=await fetch('/stats');if(r.status===401){showLogin(); fetch('/stats');if(r.status===return;}sData=await r.json401){showLogin();return;}sData=await r.json();
    $m();
    $m('sv-traffic').innerHTML=(('sv-traffic').innerHTML=(sData.total_traffic_msData.total_traffic_mb||b||0)+'<span class="stat-unit"> MB</span>';
    $0)+'<span class="stat-unit"> MB</span>';
    $m('sv-links').textContent=sData.linksm('sv-links').textContent=sData_count;$m('sv-uptime').textContent=s.links_count;$m('sv-uptime').textContent=sData.uptime;$mData.uptime;$m('sv-domain').textContent=sData.domain;
('sv-domain').textContent=sData.domain;
    $m('last-up').textContent='Updated '+new Date().toLocale    $m('last-up').textContent='Updated '+new Date().toLocaleTimeString();
    $m('t-tr').textTimeString();
    $m('t-tr').textContent=(sDataContent=(sData.total_traffic_mb||0)+'.total_traffic_mb||0)+' MB';$m('t-rq').textContent=sData.total_requests;$m(' MB';$m('t-rq').textContent=sData.total_requests;$t-up').textContent=sData.uptimem('t-up').textContent=sData.uptime;
    if(sData.cpu_percent!==;
    if(sData.cundefined){const c=sDatapu_percent!==undefined){const c=sData.cpu_percent;$m('.cpu_percent;$m('cpu-v').textContent=c.toFixed(1)+'%cpu-v').textContent=c.toFixed(';$m('cpu-b').style1)+'%';$m('cpu-b')..width=c+'%';}
    if(sstyle.width=c+'%';}
    if(sData.memory_percent!Data.memory_percent!==undefined){const m=sData.memory_percent;$m('mem-v').textContent=m.toFixed==undefined){const m=sData.memory_percent;$m('mem-v').text(1)+'%';$mContent=m.toFixed(1)+'%';$('mem-b').style.width=m+'%';}
m('mem-b').style.width    updChart();
  }catch{}
}
async function loadLinks(){try{const r==m+'%';}
    updChart();
  }catch{}
}
async function loadLinks(){tryawait fetch('/api/links');if(r.status{const r=await fetch('/api/links===401){showLogin');if(r.status===401){showLogin();return;}const d=await r.json();all();return;}const d=Links=d.links||[];filterLinksawait r.json();allLinks=d.links||[];filterLinks();}catch{}}
();}catch{}}
async function chgPw(){const cur=$masync function chgP('cpw').value,nw=$m('npw(){const cur=$m('cpw').value,nw=$m('npw').value;if(!cur||!nw){toast('Fill fieldsw').value;if(!cur||!nw){toast('Fill fields',true);return',true);return;}if;}if(nw.length<4(nw.length<4){toast('Min ){toast('Min 4 chars',true);return;}try{const r=await fetch('/api/4 chars',true);return;}try{const r=change-password',{method:'POST',headers:{'Content-Type':'application/json'await fetch('/api/change-password',{method:'POST',headers:{'},body:JSON.stringify({current_passwordContent-Type':'application/json'},body:JSON.stringify({current_password:cur,new:cur,new_password:nw})});if(!r.ok)throw new_password:nw})});if(!r.ok)throw new Error((await r.json()).detail||'Error Error((await r.json()).detail||'');toast('Password updated');}Error');toast('Password updated');}catch(e){toastcatch(e){toast(e.message,true);}}

(e.message,true);}}

function initChart(){const ctx=$m('tc');if(!ctxfunction initChart(){const ctx=$m('tc');if(!ctx||tChart)return;tChart=new Chart(ctx,||tChart)return;tChart=new Chart(ctx,{type:'bar',data:{labels:[],datasets:[{label{type:'bar',data:{labels:[],datasets:[{label:'MB',data:[:'MB',data:[],backgroundColor:'],backgroundColor:'rgba(57,255,20,0.55)',borderColor:'rgba(57,255,20,#39ff14'}]},options:{responsive:true0.55)',borderColor:'#39ff14'}]},options:{responsive:true,maintainAspectRatio:false,maintainAspectRatio:,plugins:{legend:{display:false}},scales:{x:{ticks:{color:'false,plugins:{legend:{display:false}},scales:{x:{ticks:{color:'rgba(57,255,rgba(57,255,20,0.3)'}},y:{ticks:{color:'rgba(57,25520,0.3)'}},y:{ticks:{color:'rgba(57,255,20,0.3)',callback:v=>v+' MB'}}}}}});upd,20,0.3)',callback:v=>v+' MB'}}}}}});updChartColors();}
function updChartColors();}
function updChartColors(){if(!tChart)return;constChartColors(){if(!tChart)return;const col=theme==='light'?'#000':'rg col=theme==='light'?'#000':'rgba(57,255,20,0.4)ba(57,255,20,0.4)';tChart.options.scales.x.tic';tChart.options.scales.xks.color=col;tChart.options.scales.y.ticks.color=col;tChart.ticks.color=col;tChart.options.scales.y.ticks.color=col.update();}
function updChart(){;tChart.update();}
function updChart(){if(!tChart||!sData.hourif(!tChart||!ly_traffic)return;const entries=Object.entries(sData.hourly_trasData.hourly_traffic)return;const entries=Object.entries(sData.hffic).sort((a,b)=>ourly_traffic).sort((a,ba[0].localeCompare(b[0])).slice(-12);tChart.data.labels)=>a[0].localeCompare(b[0])).slice(-12);t=entries.map(x=>x[0Chart.data.labels=entries.map(x=>x[0]);tChart.data.datasets[0]);tChart.data.datasets[0].data=entries.map(x=>Math.round].data=entries.map(x[1]/1048576));tChart.update();}

async function loadAddrs(){try{const r=(x=>Math.round(x[1]/1048576));tChart.update();}

async function loadAddrs(){try{const r=await fetch('/api/addressesawait fetch('/api/addresses');allAddrs=(await r.json()).');allAddrs=(await r.json()).addresses||[];renderAddrs();}addresses||[];renderAddrs();}catchcatch{}}
function renderAddrs(){{}}
function renderAddrs(){const el=$m('addr-list');if(!const el=$m('addr-list');if(!allAddrs.length){el.innerHTMLallAddrs.length){el.innerHTML='<div style="color:var(--text3)">No addresses</='<div style="color:var(--text3)">No addresses</div>';return;}el.innerHTML=allAddrs.map((a,idiv>';return;}el.innerHTML=allAddrs.map((a)=>`<div style="display:flex,i)=>`<div style="display:flex;justify-content:space-between;padding:;justify-content:space-between;padding:8px 12px;background:8px 12px;background:var(--surface3);border:1px solid var(--border);border-radius:8var(--surface3);border:1px solid var(--border);border-radius:8px;margin-bottom:6px;"><span>${escpx;margin-bottom:6px;"><span>${esc(a)}</span><button(a)}</span><button class="act-btn act-del" onclick="delAddr class="act-btn act-del" onclick="delAddr(${i})">${tr('del')}</button></div>`(${i})">${tr('del')}</button></div>`).join('');}
async function addBatch).join('');}
async function addBatchAddAddrs(){const raw=$m('batch-addrsrs(){const raw=$m('batch-addrs').value;const lines=raw.split('\n').value;const lines=raw.split('\n').').map(l=>l.trim()).filtermap(l=>l.trim()).filter(l(l=>l);let ok=0,fail=0;for(const addr of lines=>l);let ok=0,fail=0;for(const addr of lines){if(!/^){if(!/^[a-zA-Z0-[a-zA-Z0-9\-_.9\-_. ]+$/. ]+$/.test(addr)){fail++;continuetest(addr)){fail++;continue;}try{const r=await fetch('/api/addresses',{method:';}try{const r=await fetch('/api/addresses',{method:'POSTPOST',headers:{'Content-Type':'application/json'},body:JSON.stringify({address',headers:{'Content-Type':'application/json'},body:JSON.stringify({address:addr})});:addr})});if(r.ok)ok++;else fail++;}catch{fail++;}}if(r.ok)ok++;else fail++;}catch{fail++;}}if(if(ok)toast(`Added ${ok}`);if(fail)toastok)toast(`Added ${ok}`(`${fail} failed`,true);if(fail)toast(`${fail} failed`,true);$m('batch);$m('batch-addrs').value='';await loadAddrs();}
-addrs').value='';awaitasync function deleteAllAddrs(){ loadAddrs();}
async function deleteAllAddrs(){if(!confirmif(!confirm('Delete all addresses?'))return('Delete all addresses?'))return;;try{await fetch('/api/addresses',{method:'DELETE'});toasttry{await fetch('/api/addresses',{method:'DELETE'});toast('All('All deleted');await deleted');await loadAdd loadAddrs();}catch{toast('Error',true);}}
async functionrs();}catch{toast delAddr(i){if(!confirm('('Error',true);}}
async function delAddr(i){if(!confirm('Delete?'Delete?'))return;try{await))return;try{await fetch('/api fetch('/api/addresses/'+i,{method:'DELETE'});toast('Deleted');await loadAddrs();}catch{to/addresses/'+i,{method:'DELETE'});toast('Deleted');await loadAddrs();}catch{toast('ast('Error',true);}}

setThemeError',true);}}

setTheme(theme);setLang(lang);checkAuth();
setInterval(theme);setLang(lang);(()=>{if(isAuthentcheckAuth();
setInterval(()=>{if(isAuthenticated){loadStats();loadicated){loadStats();loadLinks();}},12000);
</script>
</body>
</html>Links();}},12000);
</script>
</body>
</html>"""

@app.get("/login"""

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
", response_class=HTMLResponse)
async def login    return HTMLResponse(content_page(request: Request):
    return HTML=PANEL_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_pageResponse(content=PANEL_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async(request: Request):
    return HTMLResponse(content def dashboard_page(request: Request):
   =PANEL_HTML)

@app.get("/panel", response return HTMLResponse(content=PANEL_HTML)

@app.get("/panel", response_class=HTMLResponse)
_class=HTMLResponse)
async def panel_page(request: Request):
    return HTMLResponse(contentasync def panel_page(request: Request=PANEL_HTML)

if __name__):
    return HTMLResponse(content=PANEL_HTML)

if __name__ == "__main == "__main__":
    uvicorn.run(app, host="0__":
    uvicorn.run(app, host="0.0.0.0", port=CON.0.0.0", port=CONFIG["port"])
```FIG["port"])
