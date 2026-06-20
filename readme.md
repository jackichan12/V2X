<div align="center">

# 🚀 V2X Panel (V1.0)

[![Status](https://img.shields.io/badge/Status-Stable_v1.0.0-success?style=for-the-badge)](#)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python)](#)
[![License](https://img.shields.io/badge/License-Non--Commercial-red?style=for-the-badge)](#)
[![Platform](https://img.shields.io/badge/Platform-Render_%7C_Railway_%7C_Dockfly-lightgrey?style=for-the-badge)](#)

![.]([https://via.placeholder.com/1000x450/0a0a0a/39ff14?text=V2X+Panel+Screenshot+-+Replace+With+Your+Image](https://raw.githubusercontent.com/SulgX/V2X/refs/heads/main/img/V2X.png?token=GHSAT0AAAAAAD2YZ7BHQ7I6GDQHXPFOXPTO2RXCXUQ))
![V2X Panel Screenshot]([https://via.placeholder.com/1000x450/0a0a0a/39ff14?text=V2X+Panel+Screenshot+-+Replace+With+Your+Image](https://raw.githubusercontent.com/SulgX/V2X/refs/heads/main/img/V2X.png?token=GHSAT0AAAAAAD2YZ7BHQ7I6GDQHXPFOXPTO2RXCXUQ))

> **A lightweight, self-hosted VLESS over WebSocket + TLS subscription management panel.** > Built entirely in a single Python file, powered by FastAPI and SQLite.

</div>

---

## 📖 Table of Contents
- [✨ Key Features](#-key-features)
- [📁 Repository Architecture](#-repository-architecture)
- [☁️ Deployment Platforms](#-deployment-platforms)
- [🚀 Quick Start & Deployment](#-quick-start--deployment)
- [💸 Bandwidth & Pricing Guide](#-bandwidth--pricing-guide)
- [⚖️ Strict Disclaimer](#-strict-disclaimer)
- [🙏 Acknowledgements](#-acknowledgements)

---

## ✨ Key Features

### 🔐 Security & Access
- **Robust Authentication:** JWT-based sessions with HTTP-only, secure cookies.
- **Anti-Brute Force:** Rate limiting applied to logins and API interactions.
- **Strict Passwords:** Enforced policy (min 8 chars, uppercase, lowercase, numbers).
- **Audit Logging:** Logs all login attempts (Success/Fail, IP, User-Agent).

### 📡 Inbound Management
- **Full Lifecycle:** Create, edit, toggle, and safely delete VLESS configs.
- **Granular Control:** Per-user traffic limits (GB), expiration days, and max concurrent connections.
- **Advanced Routing:** Custom Path, SNI, Host, and TLS Fingerprints per inbound.
- **Bulk Operations:** Batch activate, deactivate, reset, or delete configs.
- **Immutable Core:** The default `SulgX` inbound is systematically protected against accidental deletion.

### 📊 Real-Time Analytics
- **Live Speed Engine:** Highly accurate Download/Upload charts with adaptive spike-filtering.
- **Dynamic Metrics:** 24-hour real-time traffic bars (timezone-aware) and distribution doughnuts.
- **System Health:** Live CPU, Memory, and Disk monitoring with `loadavg` fallbacks.

### 🗺️ Clean IP & Safe Scanner
- **IP Management:** Add, edit, and bulk-import IPv4/IPv6 addresses dynamically attached to subscriptions.
- **Safe Scanner:** Scan port 443 across 24 predefined cloud providers (Cloudflare, AWS, Azure, etc.).
- **Anti-Crash:** Safely handles massive CIDR ranges (e.g., `/14`) by capping at 4,096 IPs to prevent browser freezing. Automatically excludes public DNS (8.8.8.8).

### 🤖 Smart Telegram Bot
- **Bilingual (EN/FA):** Fully translatable templates.
- **Event Alerts:** Panel Logins, Expired Users, Errors, and 90% Quota warnings.
- **Live Preview:** Real-time JSON template rendering in the dashboard.

---

## 📁 Repository Architecture

The repository is kept intentionally minimal. Everything required for production is included:

| File | Type | Purpose |
| :--- | :---: | :--- |
| `main.py` | **Core** | The beating heart of V2X. Contains FastAPI backend, WebSocket tunnels, and embedded HTML/JS frontend. |
| `requirements.txt` | **Config** | Strictly pinned Python dependencies ensuring build stability. |
| `Procfile` | **Deploy** | Standardized startup instructions for Heroku, Railway, and Render. |
| `render.yaml` | **Deploy** | Infrastructure-as-Code blueprint for instant 1-click deployments on Render. |
| `v2x-config.toml` | **Docs** | Reference guide containing the required Environment Variables for manual setups. |
| `.gitignore` | **Git** | Keeps the repository clean by excluding logs, caches, and local `.db` files. |

---

## ☁️ Deployment Platforms

V2X is built to run flawlessly across cloud PaaS providers. No Dockerfile or complex setup required.

### 🏆 Top Recommended Providers

| Platform | Free Tier Limit | Websocket | Sleep Mode | Credit Card Req? | Deployment Method |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **Render** | 750 hours / month | ✅ | Yes (Delay) | No | Auto via `render.yaml` |
| **Railway** | $5 Initial Credit | ✅ | No | No | Auto via `Procfile` |
| **Dockfly** | 1 Project (256MB) | ✅ | No | No | Manual Start Command |

<details>
<summary><b>🌍 Click to view other compatible platforms</b></summary>

| Platform | Free Tier | Websocket | Sleep Mode | Card Req? |
| :--- | :--- | :---: | :---: | :---: |
| **Koyeb** | 1 Eco Service | ✅ | No | No |
| **Fly.io** | Up to 3 Small VMs | ✅ | No | Yes (Verification) |
| **Heroku** | Eco ($5/mo) | ✅ | Yes | Yes |
| **DigitalOcean** | $5/mo Base | ✅ | No | Yes |
| **Oracle Cloud** | Always Free ARM | ✅ | No | Yes (Verification) |

</details>

---

## 🚀 Quick Start & Deployment

> [!NOTE]
> V2X will run on *any* platform that supports ASGI Python applications (Uvicorn/Gunicorn) and standard WebSocket connections.

### 1. Configure Environment Variables
You must set the following Environment Variables in your provider's dashboard:

| Variable | Example Value | Description |
| :--- | :--- | :--- |
| `ADMIN_PASSWORD` | `StrongPass!123` | Required for panel access. (Min 8 chars, mixed case, numbers). |
| `SECRET_KEY` | `random_long_string` | Used for securing JWT login cookies. |
| `DOMAIN` | `v2x.up.railway.app` | Your public domain. *Highly recommended for accurate link generation.* |
| `DB_PATH` | `/tmp/panel.db` | Where the SQLite DB is stored. Use `/data/panel.db` if using persistent volumes. |

### 2. Start Command
Use this exact command on all platforms (if required manually):
```bash
gunicorn -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:$PORT

```

---

## 💸 Bandwidth & Pricing Guide

> [!IMPORTANT]
> **V2X Panel is 100% Free.** However, your cloud provider will charge you for the bandwidth your users consume.

| Hosting Platform | Included Free Bandwidth | Cost Per Extra GB (Approx.) |
| --- | --- | --- |
| **Render** | 100 GB / month | `$0.10 / GB` |
| **Railway** | Pay as you go | `$0.10 / GB` |
| **Koyeb** | 5 GB / month | `$0.04` to `$0.10 / GB` |
| **Fly.io** | Varies by region | `$0.02 / GB` |
| **Oracle Cloud** | 10 TB / month | Standard Cloud Rates |

*Monitor your cloud provider's billing dashboard to avoid unexpected charges. Use the Panel's monthly limits to control usage.*

---

## ⚖️ Strict Disclaimer

> [!WARNING]
> **READ CAREFULLY BEFORE DEPLOYING**

* **Free & Non-Commercial:** This software is provided 100% free of charge. **It is NOT for sale.**
* **No Commercial VPNs:** Do NOT use this panel to sell VPN subscriptions. It is designed strictly for personal, educational, and experimental purposes.
* **No Platform Abuse:** Do not abuse the free tiers of cloud providers by creating multiple accounts with temporary emails.
* **Reporting:** If you see someone selling access to this specific panel or abusing infrastructure, please report it to the respective hosting provider.
* **Zero Liability:** The developer assumes absolutely **zero liability** for any damages, billing overages, or Terms of Service violations incurred. You are solely responsible for your traffic.

---

## 🙏 Acknowledgements

A massive thank you to the platforms and communities that make free internet tools possible:

* **Render**, **Railway**, and **Dockfly** for their incredible developer-friendly infrastructure.
* The open-source Python and JS communities (`FastAPI`, `Chart.js`, `aiosqlite`).
* The **V2Fly** project.
