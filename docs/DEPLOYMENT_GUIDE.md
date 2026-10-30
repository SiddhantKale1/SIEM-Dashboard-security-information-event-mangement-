# 🚀 Sentinel SIEM: Production Cloud Deployment Guide

This guide walks you through deploying the high-performance **Sentinel SIEM Platform** (Golang Backend + React SOC Frontend) to production so it is accessible from anywhere on the internet.

---

## 🏗️ Deployment Architecture Options

| Method | Frontend Host | Backend Host | Database | Setup Time | Best For |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Option A (Cloud Free Tier)** | **Vercel** | **Render** / **Railway** | Embedded / Atlas | ~5 mins | Quick public access & portfolio demo |
| **Option B (All-in-One VPS)** | **Docker (Nginx)** | **Docker (Go)** | Local Volume | ~2 mins | Self-hosted production (AWS/DigitalOcean) |
| **Option C (Bare Metal/VM)** | Static Server | Native Systemd Binary | Fast NVMe / SSD | ~3 mins | High-throughput enterprise deployments |

---

## ☁️ Option A: Free Cloud Deployment (Vercel + Render)

### Step 1: Deploy Go Backend to Render

1. Log in to your [Render Dashboard](https://dashboard.render.com).
2. Click **New +** → **Web Service** and connect your GitHub repository:
   `https://github.com/SiddhantKale1/SIEM-Dashboard-security-information-event-mangement-`
3. Configure service settings:
   - **Name:** `sentinel-siem-backend`
   - **Root Directory:** `backend`
   - **Runtime:** `Go` (or choose `Docker` — Render automatically detects `backend/Dockerfile`!)
   - **Build Command:** `go build -o siem-server ./cmd/server`
   - **Start Command:** `./siem-server`
4. Under **Environment Variables**, add:
   | Key | Value | Notes |
   | :--- | :--- | :--- |
   | `PORT` | `8000` | Port for the HTTP server |
   | `DATABASE_DIR` | `siem_data` | Directory for state store |
   | `JWT_SECRET` | *(Click 'Generate')* | 32+ char token encryption key |
5. Click **Deploy Web Service**.
6. Once deployed, Render gives you a public URL (e.g. `https://sentinel-siem-backend.onrender.com`).
   - Test it by visiting `https://sentinel-siem-backend.onrender.com/health` in your browser. It will return:
     ```json
     {"engine":"golang-enterprise-siem","runtime":"go","status":"ok"}
     ```

---

### Step 2: Deploy Frontend Dashboard to Vercel

1. Log in to [Vercel](https://vercel.com).
2. Click **Add New...** → **Project** and import your repository:
   `SIEM-Dashboard-security-information-event-mangement-`
3. Configure the Project:
   - **Framework Preset:** `Vite`
   - **Root Directory:** Click **Edit** and choose `frontend`
4. Expand **Environment Variables** and add:
   | Key | Value |
   | :--- | :--- |
   | `VITE_API_URL` | `https://sentinel-siem-backend.onrender.com/api/v1` *(your Render URL)* |
5. Click **Deploy**.
6. Vercel automatically builds and provides a global SSL domain (e.g. `https://sentinel-siem.vercel.app`).

> [!NOTE]
> Client-side SPA routing (`/threats`, `/devices`, `/logs`, `/network`) is pre-configured via [`frontend/vercel.json`](file:///home/sidd/SIEM-Dashboard-security-information-event-mangement-/frontend/vercel.json), ensuring seamless page reloads without 404 errors.

---

## 🐳 Option B: 1-Click Docker Compose (VPS / AWS EC2 / DigitalOcean)

If you have a Linux server or cloud virtual machine with Docker installed:

1. SSH into your server and clone the repository:
   ```bash
   git clone https://github.com/SiddhantKale1/SIEM-Dashboard-security-information-event-mangement-.git
   cd SIEM-Dashboard-security-information-event-mangement-
   ```
2. Start both services in detached mode:
   ```bash
   docker compose up -d --build
   ```
3. Access your SIEM:
   - **Web UI:** `http://<YOUR_SERVER_IP>` (Port 80)
   - **API & Telemetry Stream:** `http://<YOUR_SERVER_IP>:8000` (Port 8000)

---

## 🔐 Default Access & Remote Agent Enrollment

1. Open your deployed frontend URL (`https://sentinel-siem.vercel.app` or `http://<YOUR_SERVER_IP>`).
2. Log in with your configured administrator credentials (username `admin` and the password set in your `ADMIN_PASSWORD` environment variable), or register an operator account from the login screen.
3. Navigate to **Fleet Management / Devices** (`/devices`) and click **1-Click Installers**.
4. Run the one-line installer command on any machine you wish to monitor:
   - **Linux:**
     ```bash
     curl -sSL "https://YOUR_BACKEND_URL/api/v1/enrollment/install.sh" | sudo bash -s -- --server "https://YOUR_BACKEND_URL" --token "ENROLL-XXXX"
     ```
   - **Windows (PowerShell Admin):**
     ```powershell
     powershell -ExecutionPolicy Bypass -Command "irm 'https://YOUR_BACKEND_URL/api/v1/enrollment/install.ps1?token=ENROLL-XXXX&server=https://YOUR_BACKEND_URL' | iex"
     ```
5. The endpoint agent installs natively, connects over TLS, and begins streaming live event logs, processes, and metrics to your cloud SOC console in real time!
