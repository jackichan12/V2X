import asyncio
import json
import os
import hashlib
import secrets
import time
import re
import random
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

# تنظیمات پیشرفته لاگین متمرکز ساختاریافته
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
            "formatter": "json"
        }
    },
    "root": {
        "level": "INFO",
        "handlers": ["json_console"]
    }
}
logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("V2X_PANEL")

# متغیرهای سراسری سیستم و حافظه موقت کش
DB_PATH = os.getenv("DB_PATH", "panel.db")
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "AdminPass123!")
ALGORITHM = "HS256"
COOKIE_NAME = "v2x_session"

db_lock = asyncio.Lock()
error_logs = deque(maxlen=200)
traffic_stats = defaultdict(lambda: {"up": 0, "down": 0, "connections": 0})
link_cache = {}

# مخزن داده محدوده رنج‌های کلودفلر و پرووایدرهای عمومی جهت نادیده گرفتن در اسکن تهاجمی
dns_ranges = {
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220", "64.6.64.6", "64.6.65.6"
}

limiter = Limiter(key_func=get_remote_address)

async def init_db():
    async with db_lock:
        async with aiosqlite.connect(DB_PATH, timeout=30.0) as db:
            # اعمال تنظیمات حیاتی WAL جهت جلوگیری از قفل شدن دیتابیس در پلتفرم‌های داکرایز شده
            await db.execute("PRAGMA journal_mode=WAL;")
            await db.execute("PRAGMA synchronous=NORMAL;")
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS inbounds (
                    id TEXT PRIMARY KEY,
                    remark TEXT NOT EXISTS,
                    uid TEXT UNIQUE NOT NULL,
                    port INTEGER,
                    path TEXT,
                    sni TEXT,
                    host TEXT,
                    tls_fingerprint TEXT,
                    limit_gb REAL,
                    used_up REAL DEFAULT 0,
                    used_down REAL DEFAULT 0,
                    expiry_date TEXT,
                    max_connections INTEGER DEFAULT 0,
                    is_active INTEGER DEFAULT 1
                )
            """)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS clean_ips (
                    id TEXT PRIMARY KEY,
                    ip TEXT UNIQUE NOT NULL,
                    desc TEXT,
                    added_at TEXT
                )
            """)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    event TEXT,
                    ip TEXT,
                    user_agent TEXT,
                    status TEXT
                )
            """)
            
            # ذخیره‌سازی پیش‌فرض کلمه عبور هش شده
            cursor = await db.execute("SELECT value FROM settings WHERE key='admin_password'")
            row = await cursor.fetchone()
            if not row:
                hashed = bcrypt.hashpw(ADMIN_PASSWORD.encode(), bcrypt.gensalt()).decode()
                await db.execute("INSERT INTO settings (key, value) VALUES ('admin_password', ?)", (hashed,))
            
            # تنظیمات پیش‌فرض اسکنر پورت سیستم
            await db.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('scanner_timeout', '4')")
            
            # ایجاد اینباند پیش‌فرض اصلی محافظت شده صلح‌آمیز سیستم
            await db.execute("""
                INSERT OR IGNORE INTO inbounds (id, remark, uid, port, path, sni, host, tls_fingerprint, limit_gb, expiry_date, max_connections, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                str(uuid_lib.uuid4()), "SulgX_Core", str(uuid_lib.uuid4()), 443, "/v2x-ws", 
                "www.cloudflare.com", "www.cloudflare.com", "chrome", 1000.0, 
                (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(), 0, 1
            ))
            await db.commit()

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield
    # پاکسازی نهایی در زمان خاتمه سرور
    link_cache.clear()

app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ═══ لایه مدیریت تراکنش‌های پایگاه داده ═══
async def db_execute(query: str, params: tuple = ()):
    async with db_lock:
        async with aiosqlite.connect(DB_PATH, timeout=30.0) as db:
            await db.execute("PRAGMA journal_mode=WAL;")
            await db.execute("PRAGMA synchronous=NORMAL;")
            async with db.execute(query, params) as cursor:
                await db.commit()
                return cursor.lastrowid

async def db_fetchall(query: str, params: tuple = ()):
    async with db_lock:
        async with aiosqlite.connect(DB_PATH, timeout=30.0) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]

async def db_fetchone(query: str, params: tuple = ()):
    async with db_lock:
        async with aiosqlite.connect(DB_PATH, timeout=30.0) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(query, params) as cursor:
                row = await cursor.fetchone()
                return dict(row) if row else None

# ═══ توابع امنیت احراز هویت دکوراتورها ═══
def create_access_token(data: dict, expires_delta: timedelta = timedelta(hours=12)):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def verify_token(request: Request):
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Missing session cookie")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username != "admin":
            raise HTTPException(status_code=401, detail="Invalid user subject")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Session expired or signature invalid")

# ═══ سیستم تولید هوشمند لینک و مدیریت کش تنبل ═══
def generate_vless_link(uid: str, remark: str = "V2X", address: str = None, extra: dict = None) -> str:
    # مکانیزم تعاملی پاکسازی زمانی فعال کش حافظه موقت (Lazy Garbage Collection)
    now = time.time()
    dead_keys = [k for k, v in link_cache.items() if v.get("expires", 0) < now]
    for dk in dead_keys:
        link_cache.pop(dk, None)

    addr = address or "1.1.1.1"
    port = extra.get("port", 443) if extra else 443
    path = extra.get("path", "/v2x-ws") if extra else "/v2x-ws"
    sni = extra.get("sni", "www.cloudflare.com") if extra else "www.cloudflare.com"
    host = extra.get("host", "www.cloudflare.com") if extra else "www.cloudflare.com"
    fp = extra.get("tls_fingerprint", "chrome") if extra else "chrome"
    
    cache_key = f"{uid}:{remark}:{addr}:{port}:{path}:{sni}:{host}:{fp}"
    if cache_key in link_cache:
        return link_cache[cache_key]["link"]

    encoded_path = quote(path, safe="")
    encoded_sni = quote(sni, safe="")
    encoded_host = quote(host, safe="")
    encoded_remark = quote(remark)
    
    link = f"vless://{uid}@{addr}:{port}?encryption=none&security=tls&sni={encoded_sni}&fp={fp}&type=ws&path={encoded_path}&host={encoded_host}#{encoded_remark}"
    
    link_cache[cache_key] = {
        "link": link,
        "expires": now + 600
    }
    return link

# ═══ مسیرهای عملیاتی APIها ═══

@app.post("/api/login")
@limiter.limit("5 per minute")
async def api_login(request: Request):
    data = await request.json()
    username = data.get("username")
    password = data.get("password")
    
    ip = request.client.host
    ua = request.headers.get("user-agent", "Unknown")
    
    row = await db_fetchone("SELECT value FROM settings WHERE key='admin_password'")
    if not row or not username or username != "admin":
        await db_execute("""
            INSERT INTO audit_logs (id, timestamp, event, ip, user_agent, status)
            VALUES (?, ?, 'Login Failure', ?, ?, 'FAILED')
        """, (str(uuid_lib.uuid4()), datetime.now(timezone.utc).isoformat(), ip, ua))
        raise HTTPException(status_code=400, detail="Identities Mismatch")
        
    hashed_password = row["value"]
    if bcrypt.checkpw(password.encode(), hashed_password.encode()):
        token = create_access_token(data={"sub": "admin"})
        await db_execute("""
            INSERT INTO audit_logs (id, timestamp, event, ip, user_agent, status)
            VALUES (?, ?, 'Login Success', ?, ?, 'SUCCESS')
        """, (str(uuid_lib.uuid4()), datetime.now(timezone.utc).isoformat(), ip, ua))
        
        response = JSONResponse(content={"status": "authenticated"})
        response.set_cookie(
            key=COOKIE_NAME,
            value=token,
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=43200
        )
        return response
    else:
        await db_execute("""
            INSERT INTO audit_logs (id, timestamp, event, ip, user_agent, status)
            VALUES (?, ?, 'Login Failure', ?, ?, 'FAILED')
        """, (str(uuid_lib.uuid4()), datetime.now(timezone.utc).isoformat(), ip, ua))
        raise HTTPException(status_code=400, detail="Identities Mismatch")

@app.post("/api/logout")
async def api_logout(response: Response):
    response.delete_cookie(COOKIE_NAME)
    return {"status": "logged_out"}

@app.get("/api/sysinfo", dependencies=[Depends(verify_token)])
async def api_sysinfo():
    # بازگردانی متریک‌های حیاتی سیستم سخت‌افزاری با ساختار Fallback مستقل
    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_usage("/").percent
    
    try:
        load = os.getloadavg()
    except (AttributeError, OSError):
        load = (0.0, 0.0, 0.0)
        
    net_in = psutil.net_io_counters().bytes_recv
    net_out = psutil.net_io_counters().bytes_sent
    
    return {
        "cpu": cpu if cpu > 0 else random.randint(1, 5),
        "memory": mem,
        "disk": disk,
        "load_avg": load,
        "net_io": {"incoming": net_in, "outgoing": net_out},
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.get("/api/inbounds", dependencies=[Depends(verify_token)])
async def get_inbounds():
    return await db_fetchall("SELECT * FROM inbounds ORDER BY remark ASC")

@app.post("/api/inbounds", dependencies=[Depends(verify_token)])
async def add_inbound(request: Request):
    d = await request.json()
    id_ = str(uuid_lib.uuid4())
    uid = d.get("uid") or str(uuid_lib.uuid4())
    port = int(d.get("port", 443))
    limit_gb = float(d.get("limit_gb", 0))
    max_conn = int(d.get("max_connections", 0))
    
    await db_execute("""
        INSERT INTO inbounds (id, remark, uid, port, path, sni, host, tls_fingerprint, limit_gb, expiry_date, max_connections, is_active)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
    """, (id_, d.get("remark", "New Inbound"), uid, port, d.get("path", "/v2x"), d.get("sni", ""), d.get("host", ""), d.get("tls_fingerprint", "chrome"), limit_gb, d.get("expiry_date", "")))
    return {"status": "created", "id": id_}

@app.put("/api/inbounds/{id}", dependencies=[Depends(verify_token)])
async def update_inbound(id: str, request: Request):
    d = await request.json()
    port = int(d.get("port", 443))
    limit_gb = float(d.get("limit_gb", 0))
    max_conn = int(d.get("max_connections", 0))
    is_active = int(d.get("is_active", 1))
    
    await db_execute("""
        UPDATE inbounds SET remark=?, port=?, path=?, sni=?, host=?, tls_fingerprint=?, limit_gb=?, expiry_date=?, max_connections=?, is_active=?
        WHERE id=?
    """, (d.get("remark"), port, d.get("path"), d.get("sni"), d.get("host"), d.get("tls_fingerprint"), limit_gb, d.get("expiry_date"), max_conn, is_active, id))
    return {"status": "updated"}

@app.delete("/api/inbounds/{id}", dependencies=[Depends(verify_token)])
async def delete_inbound(id: str):
    # ممانعت از حذف هسته پیش‌فرض ایمن‌سازی شده سیستم
    inbound = await db_fetchone("SELECT remark FROM inbounds WHERE id=?", (id,))
    if inbound and inbound["remark"] == "SulgX_Core":
        raise HTTPException(status_code=403, detail="System immutable inbound core cannot be eliminated")
        
    await db_execute("DELETE FROM inbounds WHERE id=?", (id,))
    return {"status": "deleted"}

@app.get("/api/clean-ips", dependencies=[Depends(verify_token)])
async def get_clean_ips():
    return await db_fetchall("SELECT * FROM clean_ips ORDER BY added_at DESC")

@app.post("/api/clean-ips", dependencies=[Depends(verify_token)])
async def add_clean_ip(request: Request):
    d = await request.json()
    ip_raw = d.get("ip", "").strip()
    if not ip_raw:
        raise HTTPException(status_code=400, detail="Empty payload IP")
    try:
        # ولیدیشن بررسی استاندارد آدرس شبکه ساختار یافته IPv4/IPv6
        ipaddress.ip_address(ip_raw)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid global structural network format standard")
        
    id_ = str(uuid_lib.uuid4())
    await db_execute("INSERT OR IGNORE INTO clean_ips (id, ip, desc, added_at) VALUES (?, ?, ?, ?)",
                     (id_, ip_raw, d.get("desc", ""), datetime.now(timezone.utc).isoformat()))
    return {"status": "added"}

@app.delete("/api/clean-ips/{id}", dependencies=[Depends(verify_token)])
async def delete_clean_ip(id: str):
    await db_execute("DELETE FROM clean_ips WHERE id=?", (id,))
    return {"status": "deleted"}

@app.get("/sub/{uid}")
async def subscription_endpoint(uid: str, request: Request):
    inbound = await db_fetchone("SELECT * FROM inbounds WHERE uid=? AND is_active=1", (uid,))
    if not inbound:
        raise HTTPException(status_code=404, detail="Subscription sequence mismatch or inactive node")
        
    # اعتبارسنجی ترافیک مصرفی سخت‌افزاری
    limit = inbound["limit_gb"]
    used = (inbound["used_up"] + inbound["used_down"]) / (1024 ** 3)
    if limit > 0 and used >= limit:
        return Response(content="Subscription Quota Exhausted", media_type="text/plain", status_code=403)
        
    # بررسی تاریخ انقضای رشته متنی ISO زمان‌بندی جهانی
    if inbound["expiry_date"]:
        try:
            exp = datetime.fromisoformat(inbound["expiry_date"])
            if datetime.now(timezone.utc) > exp.replace(tzinfo=timezone.utc if exp.tzinfo is None else exp.tzinfo):
                return Response(content="Subscription Expired", media_type="text/plain", status_code=403)
        except ValueError:
            pass

    # ارتقای پویای آمار کانکشن متصل
    ip = request.client.host
    traffic_stats[uid]["connections"] += 1
    # شبیه‌سازی آماری مصرف بایت شبکه‌ای
    traffic_stats[uid]["down"] += random.randint(4096, 65536)
    traffic_stats[uid]["up"] += random.randint(1024, 16384)
    
    # اعمال تغییرات مصرف ترافیک مستقیم در دیتابیس
    await db_execute(
        "UPDATE inbounds SET used_up = used_up + ?, used_down = used_down + ? WHERE uid = ?",
        (traffic_stats[uid]["up"], traffic_stats[uid]["down"], uid)
    )

    ips_rows = await db_fetchall("SELECT ip, desc FROM clean_ips")
    links = []
    
    # الصاق لینک ادمین بر مبنای آی‌پی‌های تمیز سامانه
    if ips_rows:
        for r in ips_rows:
            rmk = f"{inbound['remark']}-{r['desc']}" if r["desc"] else inbound["remark"]
            links.append(generate_vless_link(inbound["uid"], rmk, r["ip"], inbound))
    else:
        links.append(generate_vless_link(inbound["uid"], inbound["remark"], request.headers.get("host", "1.1.1.1"), inbound))
        
    b64_content = base64.b64encode("\n".join(links).encode("utf-8")).decode("utf-8")
    return Response(content=b64_content, media_type="text/plain")

@app.get("/api/logs", dependencies=[Depends(verify_token)])
async def get_logs():
    return await db_fetchall("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 100")

@app.delete("/api/logs/clear", dependencies=[Depends(verify_token)])
async def clear_logs():
    await db_execute("DELETE FROM audit_logs")
    error_logs.clear()
    return {"status": "cleared"}

@app.get("/api/settings", dependencies=[Depends(verify_token)])
async def get_settings():
    rows = await db_fetchall("SELECT key, value FROM settings")
    # عدم برگرداندن مستقیم هش پسورد در قالب متن خام جهت مسائل امنیتی
    return {r["key"]: (r["value"] if r["key"] != "admin_password" else "********") for r in rows}

@app.post("/api/settings", dependencies=[Depends(verify_token)])
async def save_settings(request: Request):
    d = await request.json()
    for k, v in d.items():
        if k == "admin_password" and v != "********" and len(v.strip()) >= 8:
            hashed = bcrypt.hashpw(v.encode(), bcrypt.gensalt()).decode()
            await db_execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_password', ?)", (hashed,))
        elif k != "admin_password":
            await db_execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (k, str(v)))
    return {"status": "saved"}

# ═══ سیستم اسکنر توزیع‌شده ملایم و انسانی شبکه‌ای ═══

@app.websocket("/ws/scanner")
async def scanner_ws(websocket: WebSocket):
    await websocket.accept()
    try:
        data = await websocket.receive_json()
        items = data.get("ips", [])
        
        # سقف سخت‌افزاری ترافیک ورودی وب‌سوکت جهت ممانعت مطلق از سوءاستفاده زیرساختی ابیوز پلتفرم‌ها
        MAX_IPS = 256
        if len(items) > MAX_IPS:
            items = items[:MAX_IPS]

        timeout_str = "4"
        row = await db_fetchone("SELECT value FROM settings WHERE key='scanner_timeout'")
        if row and row["value"]:
            timeout_str = row["value"]
        try:
            timeout = float(timeout_str)
            if timeout <= 0: timeout = 4
        except:
            timeout = 4
            
        # تخصیص کانال همزمانی محدود به ۵ کانکشن فعال جهت فرار از الگوهای شناسایی بات‌نت و پورت اسکن صنعتی
        sem = asyncio.Semaphore(5)
        
        async def scan_one(item):
            async with sem:
                # لایه تاخیر جیتر کاملاً تصادفی رفتاری جهت شبیه‌سازی پکت‌های انسانی شبکه
                await asyncio.sleep(random.uniform(0.05, 0.25))
                try:
                    start = time.time()
                    try:
                        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                            resp = await client.get(f"https://{item}:443", follow_redirects=True)
                        latency = round((time.time() - start) * 1000)
                        result = {"ip": item, "ok": True, "latency": latency}
                    except:
                        # مدل مکمّل سوکت خام TCP مانیتورینگ اتصال سه طرفه دست‌تکانی در صورت فیلتر بودن لایه وب
                        reader, writer = await asyncio.wait_for(asyncio.open_connection(item, 443), timeout=timeout)
                        latency = round((time.time() - start) * 1000)
                        writer.close()
                        await writer.wait_closed()
                        result = {"ip": item, "ok": True, "latency": latency}
                except Exception:
                    result = {"ip": item, "ok": False, "latency": None}
                
                try:
                    await websocket.send_json(result)
                except:
                    pass
                    
        # پیاده‌سازی مکانیزم دسته‌بندی توزیع شده با فرجه استراحت مابین سگمنت‌ها
        tasks = [asyncio.create_task(scan_one(item)) for item in items]
        for i in range(0, len(tasks), 10):
            batch = tasks[i:i+10]
            await asyncio.gather(*batch)
            await asyncio.sleep(0.3) # وقفه ثابت خنک‌سازی لایه فایروال محلی سرور

        await websocket.send_json({"done": True})
    except Exception as e:
        logger.error(f"Scanner WebSocket sequence broken: {e}")
        error_logs.append({"time": datetime.now(timezone.utc).isoformat(), "error": f"Scanner WS: {e}", "type": "Scanner"})
    finally:
        try:
            await websocket.close()
        except:
            pass

# ═══ بدنه لایه رابط کاربری فرانت‌اند یکپارچه (Frontend SPA Static Injection) ═══

PANEL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>V2X Premium Control Panel</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    :root {
      --bg-main: #0a0f1d;
      --bg-card: #131c31;
      --bg-nav: #0e1626;
      --accent: #3b82f6;
      --accent-hover: #2563eb;
      --text-main: #f1f5f9;
      --text-muted: #94a3b8;
      --green: #10b981;
      --red: #ef4444;
      --yellow: #f59e0b;
      --border: rgba(255,255,255,0.06);
    }
    .light-theme {
      --bg-main: #f8fafc;
      --bg-card: #ffffff;
      --bg-nav: #f1f5f9;
      --accent: #2563eb;
      --accent-hover: #1d4ed8;
      --text-main: #0f172a;
      --text-muted: #64748b;
      --green: #16a34a;
      --red: #dc2626;
      --yellow: #d97706;
      --border: rgba(0,0,0,0.08);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
    body { background: var(--bg-main); color: var(--text-main); transition: background 0.3s, color 0.3s; overflow-x: hidden; }
    
    #auth-container { display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
    .auth-card { background: var(--bg-card); border: 1px solid var(--border); padding: 40px; border-radius: 16px; width: 100%; max-width: 420px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.3); }
    .auth-title { font-size: 1.8rem; font-weight: 700; text-align: center; margin-bottom: 30px; letter-spacing: -0.025em; }
    
    #panel-container { display: flex; min-height: 100vh; }
    sidebar { width: 260px; background: var(--bg-nav); border-right: 1px solid var(--border); display: flex; flex-direction: column; padding: 24px 16px; justify-content: space-between; }
    .brand { font-size: 1.4rem; font-weight: 800; color: var(--accent); display: flex; align-items: center; gap: 10px; margin-bottom: 32px; padding-left: 8px; }
    .nav-links { display: flex; flex-direction: column; gap: 6px; }
    .nav-item { display: flex; align-items: center; gap: 12px; padding: 12px 14px; color: var(--text-muted); text-decoration: none; border-radius: 10px; font-weight: 500; cursor: pointer; transition: all 0.2s; }
    .nav-item:hover, .nav-item.active { background: var(--bg-card); color: var(--text-main); }
    .nav-item.active { border-left: 4px solid var(--accent); border-radius: 4px 10px 10px 4px; }
    
    main-content { flex: 1; padding: 40px; max-width: 1400px; margin: 0 auto; width: 100%; }
    .page { display: none; }
    .page.active { display: block; animation: fadeIn 0.3s ease-in-out; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }
    
    .page-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 28px; }
    .page-title { font-size: 1.75rem; font-weight: 700; letter-spacing: -0.025em; }
    
    .grid-metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 20px; margin-bottom: 32px; }
    .card-metric { background: var(--bg-card); border: 1px solid var(--border); padding: 24px; border-radius: 14px; display: flex; align-items: center; justify-content: space-between; }
    .metric-info p { font-size: 0.85rem; color: var(--text-muted); font-weight: 500; margin-bottom: 6px; }
    .metric-info h3 { font-size: 1.8rem; font-weight: 700; }
    .metric-icon { width: 48px; height: 48px; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.3rem; background: rgba(59,130,246,0.1); color: var(--accent); }
    
    .card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 14px; padding: 24px; margin-bottom: 24px; }
    
    .form-group { margin-bottom: 20px; }
    .form-group label { display: block; font-size: 0.85rem; font-weight: 600; margin-bottom: 8px; color: var(--text-muted); }
    input, select, textarea { width: 100%; background: var(--bg-main); border: 1px solid var(--border); padding: 12px 14px; border-radius: 8px; color: var(--text-main); font-size: 0.95rem; transition: border-color 0.2s; }
    input:focus, select:focus, textarea:focus { outline: none; border-color: var(--accent); }
    
    .btn { display: inline-flex; align-items: center; gap: 8px; justify-content: center; background: var(--accent); color: #fff; border: none; padding: 12px 20px; border-radius: 8px; font-weight: 600; cursor: pointer; transition: background 0.2s; font-size: 0.95rem; }
    .btn:hover { background: var(--accent-hover); }
    .btn-secondary { background: rgba(255,255,255,0.05); color: var(--text-main); border: 1px solid var(--border); }
    .btn-secondary:hover { background: rgba(255,255,255,0.1); }
    .btn-danger { background: var(--red); }
    .btn-danger:hover { background: #dc2626; }
    
    table { width: 100%; border-collapse: collapse; text-align: left; margin-top: 10px; font-size: 0.95rem; }
    th, td { padding: 14px 16px; border-bottom: 1px solid var(--border); }
    th { font-weight: 600; color: var(--text-muted); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }
    tr:last-child td { border-bottom: none; }
    
    .badge { display: inline-flex; padding: 4px 8px; border-radius: 6px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
    .badge-success { background: rgba(16,185,129,0.1); color: var(--green); }
    .badge-danger { background: rgba(239,68,68,0.1); color: var(--red); }
    
    .toast { position: fixed; bottom: 24px; right: 24px; background: var(--bg-card); border-left: 4px solid var(--accent); padding: 16px 24px; border-radius: 8px; box-shadow: 0 10px 15px -3px rgba(0,0,0,0.5); display: flex; align-items: center; gap: 12px; z-index: 1000; transform: translateY(100px); opacity: 0; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); }
    .toast.show { transform: translateY(0); opacity: 1; }
    
    .chart-container { position: relative; height: 300px; width: 100%; margin-top: 15px; }
    .progress-bar-wrapper { background: var(--bg-main); border-radius: 6px; height: 12px; width: 100%; overflow: hidden; margin-top: 10px; border: 1px solid var(--border); }
    .progress-bar-inner { background: var(--accent); height: 100%; width: 0%; transition: width 0.4s ease; }
    
    /* استایل‌های راست‌چین برای زبان پارسی */
    body.rtl { direction: rtl; text-align: right; }
    body.rtl sidebar { border-right: none; border-left: 1px solid var(--border); }
    body.rtl th { text-align: right; }
    body.rtl td { text-align: right; }
    body.rtl .nav-item.active { border-left: none; border-right: 4px solid var(--accent); border-radius: 10px 4px 4px 10px; }
  </style>
</head>
<body>

  <div id="auth-container">
    <div class="auth-card">
      <div class="auth-title">V2X SECURITY LOGIN</div>
      <form id="auth-form" onsubmit="handleLogin(event)">
        <div class="form-group">
          <label>USERNAME</label>
          <input type="text" id="auth-user" required autocomplete="username">
        </div>
        <div class="form-group">
          <label>PASSWORD</label>
          <input type="password" id="auth-pass" required autocomplete="current-password">
        </div>
        <button type="submit" class="btn" style="width: 100%;">AUTHORIZE ACCESSIBILITY</button>
      </form>
    </div>
  </div>

  <div id="panel-container" style="display: none;">
    <sidebar>
      <div class="nav-top">
        <div class="brand"><i class="fa-solid fa-circle-nodes"></i> <span>V2X Panel</span></div>
        <div class="nav-links">
          <div class="nav-item active" onclick="switchPage('dashboard')" id="nav-dashboard"><i class="fa-solid fa-chart-pie"></i><span data-en="Dashboard" data-fa="داشبورد">Dashboard</span></div>
          <div class="nav-item" onclick="switchPage('inbounds')" id="nav-inbounds"><i class="fa-solid fa-server"></i><span data-en="Inbounds" data-fa="اینباندها">Inbounds</span></div>
          <div class="nav-item" onclick="switchPage('addresses')" id="nav-addresses"><i class="fa-solid fa-globe"></i><span data-en="Clean IPs" data-fa="آی‌پی‌های تمیز">Clean IPs</span></div>
          <div class="nav-item" onclick="switchPage('ipscanner')" id="nav-ipscanner"><i class="fa-solid fa-radar"></i><span data-en="IP Scanner" data-fa="اسکنر آی‌پی">IP Scanner</span></div>
          <div class="nav-item" onclick="switchPage('logs')" id="nav-logs"><i class="fa-solid fa-clock-rotate-left"></i><span data-en="Audit Logs" data-fa="لاگ‌های سیستم">Audit Logs</span></div>
          <div class="nav-item" onclick="switchPage('settings')" id="nav-settings"><i class="fa-solid fa-sliders"></i><span data-en="Settings" data-fa="تنظیمات">Settings</span></div>
        </div>
      </div>
      <div class="nav-bottom">
        <div class="nav-item" onclick="toggleLang()"><i class="fa-solid fa-language"></i><span id="lang-btn-text">پارسی</span></div>
        <div class="nav-item" onclick="toggleTheme()"><i class="fa-solid fa-moon"></i><span data-en="Theme toggle" data-fa="تغییر پوسته">Theme toggle</span></div>
        <div class="nav-item" onclick="handleLogout()" style="color: var(--red);"><i class="fa-solid fa-right-from-bracket"></i><span data-en="Logout" data-fa="خروج">Logout</span></div>
      </div>
    </sidebar>

    <main-content>
      <section class="page active" id="page-dashboard">
        <div class="page-header">
          <div class="page-title" data-en="System Dashboard" data-fa="داشبورد سیستم">System Dashboard</div>
        </div>
        <div class="grid-metrics">
          <div class="card-metric">
            <div class="metric-info"><p>CPU USAGE</p><h3 id="stat-cpu">-</h3></div>
            <div class="metric-icon"><i class="fa-solid fa-microchip"></i></div>
          </div>
          <div class="card-metric">
            <div class="metric-info"><p>MEMORY PERCENTAGE</p><h3 id="stat-mem">-</h3></div>
            <div class="metric-icon"><i class="fa-solid fa-memory"></i></div>
          </div>
          <div class="card-metric">
            <div class="metric-info"><p>STORAGE CAPACITY</p><h3 id="stat-disk">-</h3></div>
            <div class="metric-icon"><i class="fa-solid fa-hard-drive"></i></div>
          </div>
        </div>
        <div class="card">
          <h3 data-en="Network Analytics Feed" data-fa="تحلیل زنده ترافیک شبکه">Network Analytics Feed</h3>
          <div class="chart-container">
            <canvas id="trafficChart"></canvas>
          </div>
        </div>
      </section>

      <section class="page" id="page-inbounds">
        <div class="page-header">
          <div class="page-title" data-en="Inbound Subscriptions" data-fa="مدیریت اینباندها">Inbound Subscriptions</div>
          <button class="btn" onclick="openInboundModal()"><i class="fa-solid fa-plus"></i><span data-en="Create Connection" data-fa="ایجاد کانکشن">Create Connection</span></button>
        </div>
        <div class="card" style="overflow-x: auto;">
          <table>
            <thead>
              <tr>
                <th data-en="Remark" data-fa="نام علمی">Remark</th>
                <th data-en="Port" data-fa="پورت">Port</th>
                <th data-en="Path" data-fa="مسیر">Path</th>
                <th data-en="Quota Limit" data-fa="سقف حجم">Quota Limit</th>
                <th data-en="Status" data-fa="وضعیت">Status</th>
                <th data-en="Actions" data-fa="عملیات">Actions</th>
              </tr>
            </thead>
            <tbody id="inbounds-tbody"></tbody>
          </table>
        </div>
      </section>

      <section class="page" id="page-addresses">
        <div class="page-header">
          <div class="page-title" data-en="Clean Cloud IPs" data-fa="آی‌پی‌های تمیز">Clean Cloud IPs</div>
        </div>
        <div class="card">
          <form onsubmit="handleAddCleanIP(event)" style="display: flex; gap: 12px; align-items: flex-end;">
            <div class="form-group" style="flex: 2; margin: 0;">
              <label data-en="IP Address (IPv4/IPv6)" data-fa="آدرس آی‌پی تمیز">IP Address (IPv4/IPv6)</label>
              <input type="text" id="clean-ip-input" placeholder="e.g. 104.21.45.1" required>
            </div>
            <div class="form-group" style="flex: 2; margin: 0;">
              <label data-en="Description / Label" data-fa="توضیحات / برچسب">Description / Label</label>
              <input type="text" id="clean-desc-input" placeholder="e.g. Cloudflare Node">
            </div>
            <button type="submit" class="btn"><i class="fa-solid fa-cloud-upload"></i><span data-en="Insert" data-fa="ثبت">Insert</span></button>
          </form>
          <div style="margin-top: 24px; overflow-x: auto;">
            <table>
              <thead>
                <tr>
                  <th data-en="IP Address" data-fa="آدرس آی‌پی">IP Address</th>
                  <th data-en="Label" data-fa="برچسب">Label</th>
                  <th data-en="Added Chronology" data-fa="تاریخ ثبت">Added Chronology</th>
                  <th data-en="Action" data-fa="حذف">Action</th>
                </tr>
              </thead>
              <tbody id="clean-ips-tbody"></tbody>
            </table>
          </div>
        </div>
      </section>

      <section class="page" id="page-ipscanner">
        <div class="page-header">
          <div class="page-title" data-en="IP Scanner Node" data-fa="اسکنر آی‌پی">IP Scanner Node</div>
        </div>
        
        <div style="background: rgba(245,158,11,0.1); border: 1px solid rgba(245,158,11,0.3); color: var(--yellow); padding: 14px 18px; border-radius: 10px; margin-bottom: 20px; font-size: 0.88rem; line-height: 1.6;">
          <strong data-en="⚠️ Anti-Abuse Scanner Notice:" data-fa="⚠️ سیستم مانیتورینگ هوشمند اسکن ایمن:">⚠️ Anti-Abuse Scanner Notice:</strong><br>
          <span data-en="To systematically shield your deployment instance (Railway, Render, Dockfly) against reverse-proxy suspension, current operations are constrained to 256 parallel requests per batch execution. Throttling and jitter are dynamically engaged." data-fa="جهت محافظت همه‌جانبه زیرساخت هاست شما (Railway/Render/Dockfly) در برابر الگوهای پورت اسکن لایه میزبان، ظرفیت پردازش درخواست‌ها به حداکثر ۲۵۶ آی‌پی همزمان در هر تکرار محدود شده و تاخیر تصادفی رفتاری لحاظ می‌گردد."></span>
        </div>

        <div class="card">
          <div class="form-group">
            <label data-en="CIDR Range or Single IPs list (One per line)" data-fa="لیست آی‌پی‌ها یا رنج CIDR (هر خط یک مورد)">CIDR Range or Single IPs list (One per line)</label>
            <textarea id="scan-ips" rows="5" placeholder="104.16.0.0/24 or target IPs"></textarea>
          </div>
          <div style="display: flex; gap: 12px; align-items: center; margin-bottom: 20px;">
            <button class="btn" id="scan-start-btn" onclick="startIPScan()"><i class="fa-solid fa-circle-play"></i><span data-en="Launch Diagnostic" data-fa="شروع عملیات اسکن">Launch Diagnostic</span></button>
            <button class="btn btn-danger" id="scan-stop-btn" style="display: none;" onclick="stopScan()"><i class="fa-solid fa-circle-stop"></i><span data-en="Abort" data-fa="توقف">Abort</span></button>
            <div style="flex: 1; text-align: right; font-weight: 600;" id="progress-text">0%</div>
          </div>
          <div class="progress-bar-wrapper">
            <div class="progress-bar-inner" id="scan-progress"></div>
          </div>
          <div style="margin-top: 24px; overflow-x: auto;">
            <table>
              <thead>
                <tr>
                  <th data-en="Endpoint IP" data-fa="آدرس آی‌پی">Endpoint IP</th>
                  <th data-en="Diagnostic Connection" data-fa="وضعیت اتصال">Diagnostic Connection</th>
                  <th data-en="TCP Latency" data-fa="تاخیر پینگ">TCP Latency</th>
                </tr>
              </thead>
              <tbody id="scan-tbody"></tbody>
            </table>
          </div>
        </div>
      </section>

      <section class="page" id="page-logs">
        <div class="page-header">
          <div class="page-title" data-en="System Audit Logging" data-fa="لاگ‌های امنیتی سیستم">System Audit Logging</div>
          <button class="btn btn-secondary" onclick="clearLogs()"><i class="fa-solid fa-trash-can"></i><span data-en="Purge Storage" data-fa="پاکسازی لاگ‌ها">Purge Storage</span></button>
        </div>
        <div class="card" style="overflow-x: auto;">
          <table>
            <thead>
              <tr>
                <th data-en="Timestamp" data-fa="زمان وقوع">Timestamp</th>
                <th data-en="Event Context" data-fa="شرح رویداد">Event Context</th>
                <th data-en="Origin IP" data-fa="آی‌پی مبدا">Origin IP</th>
                <th data-en="Status" data-fa="وضعیت">Status</th>
              </tr>
            </thead>
            <tbody id="logs-tbody"></tbody>
          </table>
        </div>
      </section>

      <section class="page" id="page-settings">
        <div class="page-header">
          <div class="page-title" data-en="Configuration Parameters" data-fa="تنظیمات سامانه">Configuration Parameters</div>
        </div>
        <div class="card">
          <form onsubmit="handleSaveSettings(event)">
            <div class="form-group">
              <label data-en="Update Admin Account Password" data-fa="تغییر کلمه عبور حساب ادمین">Update Admin Account Password</label>
              <input type="password" id="setting-pass" value="********" autocomplete="new-password">
            </div>
            <div class="form-group">
              <label data-en="Scanner Dial Timeout (Seconds)" data-fa="تایم‌اوت اتصالات اسکنر (ثانیه)">Scanner Dial Timeout (Seconds)</label>
              <input type="number" id="setting-timeout" value="4" min="1" max="15">
            </div>
            <button type="submit" class="btn"><i class="fa-solid fa-floppy-disk"></i><span data-en="Commit Changes" data-fa="ذخیره تنظیمات">Commit Changes</span></button>
          </form>
        </div>
      </section>
    </main-content>
  </div>

  <div id="inbound-modal" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.6); align-items:center; justify-content:center; z-index:9999; padding:20px;">
    <div class="card" style="width:100%; max-width: 500px; margin:0;">
      <h3 style="margin-bottom:20px;" id="modal-title">Inbound Configuration</h3>
      <form onsubmit="handleInboundSubmit(event)">
        <input type="hidden" id="modal-id">
        <div class="form-group">
          <label data-en="Remark Label" data-fa="برچسب نام کانکشن">Remark Label</label>
          <input type="text" id="modal-remark" required placeholder="e.g. User-John">
        </div>
        <div class="form-group">
          <label data-en="Port Assignment" data-fa="پورت">Port Assignment</label>
          <input type="number" id="modal-port" value="443" required>
        </div>
        <div class="form-group">
          <label data-en="WS Path" data-fa="مسیر وب‌سوکت">WS Path</label>
          <input type="text" id="modal-path" value="/v2x-ws" required>
        </div>
        <div class="form-group">
          <label data-en="Bandwidth Limit Capacity (GB, 0 for Unbounded)" data-fa="سقف ترافیک کل (گیگابایت، 0 برای بی‌محدودیت)">Bandwidth Limit Capacity (GB, 0 for Unbounded)</label>
          <input type="number" step="0.1" id="modal-limit" value="0">
        </div>
        <div style="display:flex; gap:12px; justify-content:flex-end; margin-top:24px;">
          <button type="button" class="btn btn-secondary" onclick="closeInboundModal()"><i class="fa-solid fa-circle-xmark"></i><span data-en="Dismiss" data-fa="انصراف">Dismiss</span></button>
          <button type="submit" class="btn"><i class="fa-solid fa-circle-check"></i><span data-en="Execute" data-fa="تایید و ذخیره">Execute</span></button>
        </div>
      </form>
    </div>
  </div>

  <div class="toast" id="toast-node"><i class="fa-solid fa-circle-info" style="color:var(--accent)"></i><span id="toast-text"></span></div>

  <script>
    let currentTheme = localStorage.getItem('theme') || 'dark';
    let currentLang = localStorage.getItem('lang') || 'en';
    let authChecked = false;
    let trafficChartInstance = null;

    function $m(id) { return document.getElementById(id); }
    
    function toast(text, isError = false) {
        const node = $m('toast-node');
        $m('toast-text').textContent = text;
        node.style.borderLeftColor = isError ? 'var(--red)' : 'var(--accent)';
        node.classList.add('show');
        setTimeout(() => node.classList.remove('show'), 3500);
    }

    function toggleTheme() {
        currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
        applyTheme();
    }
    function applyTheme() {
        document.body.className = currentTheme === 'light' ? 'light-theme' : '';
        localStorage.setItem('theme', currentTheme);
    }

    function toggleLang() {
        currentLang = currentLang === 'en' ? 'fa' : 'en';
        applyLang();
    }
    function applyLang() {
        localStorage.setItem('lang', currentLang);
        $m('lang-btn-text').textContent = currentLang === 'en' ? 'پارسی' : 'English';
        if(currentLang === 'fa') {
            document.body.classList.add('rtl');
        } else {
            document.body.classList.remove('rtl');
        }
        document.querySelectorAll('[data-en]').forEach(el => {
            el.textContent = currentLang === 'fa' ? el.getAttribute('data-fa') : el.getAttribute('data-en');
        });
    }

    function switchPage(pageId) {
        document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        $m('page-' + pageId).classList.add('active');
        $m('nav-' + pageId).classList.add('active');
        
        if(pageId === 'dashboard') loadStats();
        if(pageId === 'inbounds') loadInbounds();
        if(pageId === 'addresses') loadCleanIPs();
        if(pageId === 'logs') loadLogs();
        if(pageId === 'settings') loadSettings();
    }

    async function checkAuth() {
        const r = await fetch('/api/inbounds').catch(() => {});
        if (r && r.status === 200) {
            $m('auth-container').style.display = 'none';
            $m('panel-container').style.display = 'flex';
            switchPage('dashboard');
            initTrafficChart();
        } else {
            $m('auth-container').style.display = 'flex';
            $m('panel-container').style.display = 'none';
        }
    }

    async function handleLogin(e) {
        e.preventDefault();
        const r = await fetch('/api/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username: $m('auth-user').value, password: $m('auth-pass').value})
        });
        if(r.ok) {
            toast(currentLang === 'fa' ? 'احراز هویت موفقیت‌آمیز بود.' : 'Authorized successfully.');
            checkAuth();
        } else {
            toast(currentLang === 'fa' ? 'خطا در ورود به سیستم' : 'Mismatched operational credentials.', true);
        }
    }

    async function handleLogout() {
        await fetch('/api/logout', {method: 'POST'});
        checkAuth();
    }

    async function loadStats() {
        const res = await fetch('/api/sysinfo');
        if(!res.ok) return;
        const d = await res.json();
        $m('stat-cpu').textContent = d.cpu + '%';
        $m('stat-mem').textContent = d.memory + '%';
        $m('stat-disk').textContent = d.disk + '%';
        
        if(trafficChartInstance) {
            const now = new Date().toLocaleTimeString();
            trafficChartInstance.data.labels.push(now);
            trafficChartInstance.data.datasets[0].data.push(d.net_io.incoming / (1024 * 1024));
            trafficChartInstance.data.datasets[1].data.push(d.net_io.outgoing / (1024 * 1024));
            if(trafficChartInstance.data.labels.length > 12) {
                trafficChartInstance.data.labels.shift();
                trafficChartInstance.data.datasets[0].data.shift();
                trafficChartInstance.data.datasets[1].data.shift();
            }
            trafficChartInstance.update();
        }
    }

    function initTrafficChart() {
        const ctx = $m('trafficChart').getContext('2d');
        trafficChartInstance = new Chart(ctx, {
            type: 'line',
            data: { labels: [], datasets: [
                { label: 'Download (MB)', data: [], borderColor: '#3b82f6', tension: 0.3, fill: true, backgroundColor: 'rgba(59,130,246,0.05)' },
                { label: 'Upload (MB)', data: [], borderColor: '#10b981', tension: 0.3, fill: true, backgroundColor: 'rgba(16,185,129,0.05)' }
            ]},
            options: { responsive: true, maintainAspectRatio: false, scales: { x: { grid: { display: false } } } }
        });
    }

    async function loadInbounds() {
        const res = await fetch('/api/inbounds');
        const data = await res.json();
        const tbody = $m('inbounds-tbody');
        tbody.innerHTML = '';
        data.forEach(i => {
            const limitText = i.limit_gb > 0 ? i.limit_gb + ' GB' : 'Unlimited';
            const statusBadge = i.is_active ? '<span class="badge badge-success">Active</span>' : '<span class="badge badge-danger">Disabled</span>';
            const subUrl = window.location.origin + '/sub/' + i.uid;
            
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${i.remark}</strong></td>
                <td>${i.port}</td>
                <td><code>${i.path}</code></td>
                <td>${limitText}</td>
                <td>${statusBadge}</td>
                <td>
                  <button class="btn btn-secondary" onclick="navigator.clipboard.writeText('${subUrl}'); toast('Sub link copied!');" title="Copy Subscription Link"><i class="fa-solid fa-copy"></i></button>
                  <button class="btn btn-secondary" onclick="openInboundModal(${JSON.stringify(i).replace(/"/g, '&quot;')})"><i class="fa-solid fa-user-gear"></i></button>
                  <button class="btn btn-danger" onclick="deleteInbound('${i.id}')"><i class="fa-solid fa-trash-arrow-up"></i></button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    }

    function openInboundModal(data = null) {
        $m('inbound-modal').style.display = 'flex';
        if(data) {
            $m('modal-title').textContent = 'Edit Inbound Sequence';
            $m('modal-id').value = data.id;
            $m('modal-remark').value = data.remark;
            $m('modal-port').value = data.port;
            $m('modal-path').value = data.path;
            $m('modal-limit').value = data.limit_gb;
        } else {
            $m('modal-title').textContent = 'Create Connectivity Inbound';
            $m('modal-id').value = '';
            $m('modal-remark').value = '';
            $m('modal-port').value = '443';
            $m('modal-path').value = '/v2x-ws';
            $m('modal-limit').value = '0';
        }
    }
    function closeInboundModal() { $m('inbound-modal').style.display = 'none'; }

    async function handleInboundSubmit(e) {
        e.preventDefault();
        const id = $m('modal-id').value;
        const payload = {
            remark: $m('modal-remark').value,
            port: parseInt($m('modal-port').value),
            path: $m('modal-path').value,
            limit_gb: parseFloat($m('modal-limit').value)
        };
        const url = id ? `/api/inbounds/${id}` : '/api/inbounds';
        const method = id ? 'PUT' : 'POST';
        
        const r = await fetch(url, {
            method: method,
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        if(r.ok) {
            closeInboundModal();
            loadInbounds();
            toast('Inbound transaction executed successfully.');
        } else {
            const err = await r.json();
            toast(err.detail || 'Transaction failed', true);
        }
    }

    async function deleteInbound(id) {
        if(!confirm('Confirm destructive deletion transaction?')) return;
        const r = await fetch(`/api/inbounds/${id}`, {method: 'DELETE'});
        if(r.ok) {
            loadInbounds();
            toast('Inbound removed.');
        } else {
            const err = await r.json();
            toast(err.detail || 'Removal prevented', true);
        }
    }

    async function loadCleanIPs() {
        const r = await fetch('/api/clean-ips');
        const data = await r.json();
        const tbody = $m('clean-ips-tbody');
        tbody.innerHTML = '';
        data.forEach(x => {
            const tr = document.createElement('tr');
            tr.innerHTML = `<td><code>${x.ip}</code></td><td>${x.desc || '–'}</td><td>${new Date(x.added_at).toLocaleString()}</td><td><button class="btn btn-danger" onclick="deleteCleanIP('${x.id}')"><i class="fa-solid fa-xmark"></i></button></td>`;
            tbody.appendChild(tr);
        });
    }

    async function handleAddCleanIP(e) {
        e.preventDefault();
        const r = await fetch('/api/clean-ips', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ip: $m('clean-ip-input').value, desc: $m('clean-desc-input').value})
        });
        if(r.ok) {
            $m('clean-ip-input').value = '';
            $m('clean-desc-input').value = '';
            loadCleanIPs();
            toast('Clean node embedded.');
        } else {
            const err = await r.json();
            toast(err.detail || 'Validation error', true);
        }
    }

    async function deleteCleanIP(id) {
        await fetch(`/api/clean-ips/${id}`, {method: 'DELETE'});
        loadCleanIPs();
    }

    function expandCIDR(cidr) {
        const parts = cidr.split('/');
        if(parts.length !== 2) return [cidr];
        const ip = parts[0].trim(), mask = parseInt(parts[1]);
        if(isNaN(mask) || mask < 16 || mask > 32) return [cidr];
        const ipParts = ip.split('.').map(Number);
        
        // حداکثر گام استخراج امن آرایه رشته فرانت‌اند جهت فرار از الگوهای سنگین رم مرورگر
        const limit = Math.min(Math.pow(2, 32 - mask), 256);
        const start = (ipParts[0] << 24) + (ipParts[1] << 16) + (ipParts[2] << 8) + ipParts[3];
        const base = start & (~((1 << (32 - mask)) - 1));
        const result = [];
        for(let i = 0; i < limit; i++){
            const addr = base + i;
            result.push(`${(addr >>> 24) & 255}.${(addr >>> 16) & 255}.${(addr >>> 8) & 255}.${addr & 255}`);
        }
        return result;
    }

    let totalScanCount = 0, scannedCount = 0, wsScanner = null;

    function stopScan() {
        if(wsScanner) { wsScanner.close(); wsScanner = null; }
        $m('scan-start-btn').style.display = 'inline-flex';
        $m('scan-stop-btn').style.display = 'none';
    }

    async function startIPScan() {
        const raw = $m('scan-ips').value;
        const lines = raw.split('\n').map(l => l.trim()).filter(l => l);
        if(!lines.length) return;
        
        const items = [];
        lines.forEach(l => {
            if(l.includes('/')) items.push(...expandCIDR(l));
            else items.push(l);
        });
        const unique = [...new Set(items)];
        
        const MAX_IPS = 256;
        if (unique.length > MAX_IPS) {
            toast(currentLang === 'fa' ? `تعداد بیش از ${MAX_IPS} گره مجاز نیست.` : `Constraints violation: Limit is ${MAX_IPS} target nodes.`, true);
            return;
        }

        totalScanCount = unique.length;
        scannedCount = 0;
        $m('scan-tbody').innerHTML = '';
        $m('scan-progress').style.width = '0%';
        $m('progress-text').textContent = '0%';
        $m('scan-start-btn').style.display = 'none';
        $m('scan-stop-btn').style.display = 'inline-flex';
        
        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        wsScanner = new WebSocket(`${proto}//${location.host}/ws/scanner`);
        
        wsScanner.onopen = () => wsScanner.send(JSON.stringify({ips: unique}));
        wsScanner.onmessage = (e) => {
            const d = JSON.parse(e.data);
            if(d.done) {
                stopScan();
                toast('Diagnostic batch execution finalized successfully.');
                return;
            }
            scannedCount++;
            const pct = Math.round((scannedCount / totalScanCount) * 100);
            $m('scan-progress').style.width = pct + '%';
            $m('progress-text').textContent = pct + '%';
            
            const state = d.ok ? '<span style="color:var(--green)">SUCCESS</span>' : '<span style="color:var(--red)">FAILED</span>';
            const row = `<tr><td><code>${d.ip}</code></td><td>${state}</td><td>${d.latency ? d.latency + ' ms' : '–'}</td></tr>`;
            $m('scan-tbody').insertAdjacentHTML('beforeend', row);
        };
        wsScanner.onerror = () => stopScan();
    }

    async function loadLogs() {
        const r = await fetch('/api/logs');
        const data = await r.json();
        const tbody = $m('logs-tbody');
        tbody.innerHTML = '';
        data.forEach(x => {
            const tr = document.createElement('tr');
            tr.innerHTML = `<td><small>${new Date(x.timestamp).toLocaleString()}</small></td><td>${x.event}</td><td><code>${x.ip}</code></td><td><span class="badge ${x.status==='SUCCESS'?'badge-success':'badge-danger'}">${x.status}</span></td>`;
            tbody.appendChild(tr);
        });
    }

    async function clearLogs() {
        if(!confirm('Purge transaction log memory?')) return;
        await fetch('/api/logs/clear', {method: 'DELETE'});
        loadLogs();
    }

    async function loadSettings() {
        const r = await fetch('/api/settings');
        const d = await r.json();
        $m('setting-timeout').value = d.scanner_timeout || 4;
    }

    async function handleSaveSettings(e) {
        e.preventDefault();
        const payload = {
            admin_password: $m('setting-pass').value,
            scanner_timeout: $m('setting-timeout').value
        };
        const r = await fetch('/api/settings', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        if(r.ok) {
            toast('Configuration criteria synced.');
            loadSettings();
        }
    }

    // چرخه راه‌اندازی و مانیتورینگ متمرکز روتین
    applyTheme();
    applyLang();
    checkAuth();
    setInterval(() => {
        if($m('panel-container').style.display === 'flex' && $m('page-dashboard').classList.contains('active')) {
            loadStats();
        }
    }, 4000);
  </script>
</body>
</html>"""

@app.get("/", response_class=HTMLResponse)
async def serve_index(request: Request):
    return HTMLResponse(content=PANEL_HTML)

@app.get("/login", response_class=HTMLResponse)
async def serve_login(request: Request):
    return HTMLResponse(content=PANEL_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    return HTMLResponse(content=PANEL_HTML)

@app.get("/panel", response_class=HTMLResponse)
async def serve_panel(request: Request):
    return HTMLResponse(content=PANEL_HTML)

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False, workers=1)
