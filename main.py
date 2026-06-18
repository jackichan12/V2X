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
    return {"service": "V2Render", "version": "9.0", "status": "active", "domain": get_domain()}

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

# ── HTML Panel (V2Render v9) ─────────────────────────────────────────────
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
<div id="login-page" style="display:none;width:100%">
<div style="display:flex;align-items:center;justify-content:center;min-height:100vh;">
<div style="background:var(--surface2);border:1px solid var(--border2);border-radius:20px;padding:40px 32px;width:100%;max-width:380px;box-shadow:0 0 25px var(--primary-dim);">
<div style="text-align:center;margin-bottom:28px;">
<svg width="80" height="80" viewBox="0 0 80 80"><rect width="80" height="80" rx="12" fill="var(--primary)" fill-opacity="0.1"/><text x="40" y="58" font-family="'Orbitron',sans-serif" font-size="40" font-weight="900" fill="var(--primary)" text-anchor="middle">V2R</text></svg>
<div style="font-family:'Orbitron',sans-serif;font-size:1.5rem;font-weight:900;color:var(--primary);margin-top:10px;">V2Render</div>
<div style="font-size:0.95rem;color:var(--text3);margin-top:6px;" data-en="Enter your password" data-fa="رمز عبور را وارد کنید">Enter your password</div>
</div>
<div class="fg"><label class="fl">PASSWORD</label><input class="fi" type="password" id="login-pw" placeholder="••••••••" onkeydown="if(event.key==='Enter')doLogin()"></div>
<button class="btn btn-primary" onclick="doLogin()" style="width:100%;justify-content:center;padding:14px;margin-top:12px;">LOGIN</button>
<div id="login-err" style="color:var(--red);font-size:0.9rem;margin-top:10px;text-align:center;display:none">Invalid password</div>
</div></div></div>

<div id="dashboard-page" style="display:none;width:100%">
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
<section class="page active" id="page-dashboard">
<div class="page-header">
<div><div class="page-title" data-en="Dashboard" data-fa="داشبورد">Dashboard</div><div class="page-sub" id="last-up">–</div></div>
</div>
<div class="stats-row">
<div class="stat-card"><div class="stat-label" data-en="Traffic" data-fa="ترافیک">Traffic</div><div class="stat-val" id="sv-traffic">–<span class="stat-unit"> MB</span></div></div>
<div class="stat-card"><div class="stat-label" data-en="Inbounds" data-fa="اینباندها">Inbounds</div><div class="stat-val" id="sv-links">–</div></div>
<div class="stat-card"><div class="stat-label" data-en="Uptime" data-fa="آپتایم">Uptime</div><div class="stat-val" id="sv-uptime" style="font-size:1.2rem;">–</div></div>
<div class="stat-card"><div class="stat-label" data-en="Domain" data-fa="دامنه">Domain</div><div class="stat-val" id="sv-domain" style="font-size:0.95rem;word-break:break-all;">–</div></div>
</div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
<div class="card"><div class="card-hd"><span class="card-title" data-en="CPU" data-fa="پردازنده">CPU</span><span id="cpu-v" style="font-weight:700;color:var(--primary);">–%</span></div><div class="sys-bar"><div class="sys-fill" id="cpu-b" style="background:var(--primary);"></div></div></div>
<div class="card"><div class="card-hd"><span class="card-title" data-en="Memory" data-fa="حافظه">Memory</span><span id="mem-v" style="font-weight:700;color:var(--green);">–%</span></div><div class="sys-bar"><div class="sys-fill" id="mem-b" style="background:var(--green);"></div></div></div>
</div>
<div class="card"><div class="card-hd"><span class="card-title" data-en="Hourly Traffic" data-fa="ترافیک ساعتی">Hourly Traffic</span></div><div class="chart-container"><canvas id="tc"></canvas></div></div>
</section>

<section class="page" id="page-inbounds">
<div class="page-header">
<div><div class="page-title" data-en="Inbounds" data-fa="اینباندها">Inbounds</div><div class="page-sub" data-en="VLESS over WebSocket · TLS" data-fa="VLESS روی WebSocket با TLS">VLESS over WebSocket · TLS</div></div>
<button class="btn btn-primary" onclick="showAddMo()" data-en="+ Create" data-fa="+ ایجاد">+ Create</button>
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

<section class="page" id="page-traffic">
<div class="page-header"><div class="page-title" data-en="Traffic" data-fa="ترافیک">Traffic</div></div>
<div class="card">
<div style="display:flex;justify-content:space-between;padding:12px 0;border-bottom:1px solid var(--border);"><span class="sl-k">Total Traffic</span><span id="t-tr" class="sl-v">–</span></div>
<div style="display:flex;justify-content:space-between;padding:12px 0;border-bottom:1px solid var(--border);"><span class="sl-k">Total Requests</span><span id="t-rq" class="sl-v">–</span></div>
<div style="display:flex;justify-content:space-between;padding:12px 0;"><span class="sl-k">Uptime</span><span id="t-up" class="sl-v">–</span></div>
</div>
</section>

<section class="page" id="page-addresses">
<div class="page-header"><div class="page-title" data-en="Clean IP" data-fa="آی‌پی تمیز">Clean IP</div></div>
<div class="card">
<div class="fg"><label class="fl" data-en="Add Addresses (one per line)" data-fa="افزودن آدرس (هر خط یک)">Add Addresses (one per line)</label><textarea class="fi" id="batch-addrs" rows="4" placeholder="8.8.8.8&#10;example.com"></textarea></div>
<button class="btn btn-primary" onclick="addBatchAddrs()" data-en="Add All" data-fa="افزودن همه">Add All</button>
<button class="btn btn-danger btn-sm" onclick="deleteAllAddrs()" style="margin-left:8px;" data-en="Delete All" data-fa="حذف همه">Delete All</button>
<div id="addr-list" style="margin-top:20px;"></div>
</div>
</section>

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
<footer class="footer"><span>V2Render Panel · VLESS WS Tunnel</span></footer>
</div>

<div class="mo" id="mo-add"><div class="mo-box">
<button class="mo-close" onclick="document.getElementById('mo-add').classList.remove('show')">✕</button>
<div class="mo-title" data-en="Create Inbound" data-fa="ایجاد اینباند">Create Inbound</div>
<div class="fg"><label class="fl">Remark</label><input class="fi" id="nl" placeholder="e.g. User-1"></div>
<div style="display:flex;gap:12px;"><div class="fg" style="flex:1;"><label class="fl">Traffic Limit</label><input class="fi" id="nv" type="number" min="0" step="0.1" placeholder="0 = ∞"></div><div class="fg" style="width:100px;"><label class="fl">Unit</label><select class="fs" id="nu"><option>GB</option></select></div></div>
<div class="fg"><label class="fl">Max IPs</label><input class="fi" id="nc" type="number" min="0" placeholder="0 = ∞"></div>
<div class="fg"><label class="fl">Days Valid</label><input class="fi" id="nd" type="number" min="0" placeholder="0 = No expiry"></div>
<button class="btn btn-primary" onclick="createLink()" style="width:100%;justify-content:center;margin-top:16px;">CREATE</button>
</div></div>

<div class="mo" id="mo-edit"><div class="mo-box">
<button class="mo-close" onclick="document.getElementById('mo-edit').classList.remove('show')">✕</button>
<div class="mo-title" id="et">Edit Inbound</div>
<input type="hidden" id="eu">
<div class="fg"><label class="fl">Name</label><input class="fi" id="en2" readonly style="opacity:0.5;"></div>
<div style="display:flex;gap:12px;"><div class="fg" style="flex:1;"><label class="fl">Traffic Limit</label><input class="fi" id="el" type="number" min="0"></div><div class="fg" style="width:100px;"><label class="fl">Unit</label><select class="fs" id="eu2"><option>GB</option></select></div></div>
<div class="fg"><label class="fl">Max IPs</label><input class="fi" id="ec" type="number" min="0"></div>
<div class="fg"><label class="fl">Extend Days</label><input class="fi" id="ed" type="number" min="0"></div>
<div style="display:flex;gap:12px;margin-top:16px;"><button class="btn btn-primary" onclick="saveEdit()" style="flex:1;justify-content:center;">SAVE</button><button class="btn btn-danger" onclick="resetTraf()">Reset Traffic</button></div>
</div></div>

<div class="mo" id="mo-qr"><div class="mo-box" style="max-width:360px;">
<button class="mo-close" onclick="document.getElementById('mo-qr').classList.remove('show')">✕</button>
<div class="mo-title">QR Code</div>
<div style="text-align:center;padding:20px;background:var(--surface3);border-radius:12px;"><img id="qr-img" src="" alt="QR"></div>
<button class="btn btn-primary btn-sm" onclick="dlQR()" style="width:100%;justify-content:center;margin-top:16px;">Download</button>
</div></div>

<script>
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
    uvicorn.run(app, host="0.0.0.0", port=CONFIG["port"])
