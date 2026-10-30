# 🚀 Complete Cloud Deployment Guide: SIEM Dashboard

This guide walks you through deploying the complete **SIEM Dashboard & Threat Detection System** to the cloud so it is accessible from anywhere on the internet.

---

## 🏗️ Architecture Overview

| Component | Cloud Host | Cost | Role |
| :--- | :--- | :--- | :--- |
| **Frontend** | **Vercel** / **Netlify** | Free | React + Vite UI Dashboard |
| **Backend** | **Render** / **Railway** | Free / Low-cost | FastAPI REST API, Threat Engine & WebSockets |
| **Database** | **MongoDB Atlas** | Free (M0 Cluster) | Managed cloud MongoDB database |
| **Agents** | Any PC (Linux / Windows) | - | Autonomous telemetry streaming |

---

## Step 1: Create Free Cloud Database (MongoDB Atlas)

1. Go to [mongodb.com/cloud/atlas](https://www.mongodb.com/cloud/atlas) and sign up / log in.
2. Click **Create a Deployment** and choose the **M0 Free** cluster.
3. Choose a provider and region (e.g., AWS / us-east-1 or ap-south-1).
4. **Security & Credentials**:
   - Create a database user (e.g., `siem_admin` and set a strong password).
   - Under **Network Access**, click **Add IP Address** and select **Allow Access from Anywhere (`0.0.0.0/0`)** so your Render backend can connect.
5. Click **Connect** → **Drivers** (Python).
6. Copy your connection string. It will look like:
   ```text
   mongodb+srv://siem_admin:<password>@cluster0.abcde.mongodb.net/?retryWrites=true&w=majority
   ```
   *(Replace `<password>` with your actual password)*.

---

## Step 2: Deploy Backend to Render

1. Push your latest code to GitHub:
   ```bash
   git add .
   git commit -m "feat: add cloud deployment configurations"
   git push origin main
   ```
2. Log in to [render.com](https://render.com).
3. Click **New +** → **Web Service** and connect your GitHub repository (`SIEM-Dashboard-security-information-event-mangement-`).
4. Configure the Web Service:
   - **Name:** `siem-backend`
   - **Root Directory:** `backend`
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
5. Under **Environment Variables**, add:
   | Key | Value | Notes |
   | :--- | :--- | :--- |
   | `MONGODB_URI` | `mongodb+srv://siem_admin:<password>@cluster0.abcde.mongodb.net/?retryWrites=true&w=majority` | Your Atlas connection string |
   | `DATABASE_NAME` | `siem_mvp` | Database name |
   | `USE_MOCK_DB` | `false` | Enables real MongoDB Atlas |
   | `CORS_ORIGIN_REGEX` | `^https?://.*$` | Allows Vercel / Netlify frontend |
6. Click **Deploy Web Service**.
7. Once deployment finishes, Render gives you a public URL (e.g. `https://siem-backend.onrender.com`).
   - Visit `https://siem-backend.onrender.com/health` in your browser to verify it returns `{"status":"ok"}`.

---

## Step 3: Deploy Frontend to Vercel

1. Log in to [vercel.com](https://vercel.com).
2. Click **Add New...** → **Project** and import your GitHub repository.
3. Configure the Project:
   - **Framework Preset:** `Vite`
   - **Root Directory:** Click Edit and select `frontend`
4. Expand **Environment Variables** and add:
   | Key | Value |
   | :--- | :--- |
   | `VITE_API_URL` | `https://siem-backend.onrender.com/api/v1` *(replace with your Render backend URL)* |
5. Click **Deploy**.
6. Vercel will build and launch your dashboard at a URL like `https://siem-dashboard.vercel.app`!

> [!NOTE]
> Client-side SPA routing (`/threats`, `/endpoints`, `/login`) is handled automatically via `frontend/vercel.json` so page refreshes never return 404.

---

## Step 4: Login & Enroll Remote Endpoints

1. Open your Vercel URL: `https://siem-dashboard.vercel.app`.
2. Log in with the default credentials:
   - **Username:** `admin`
   - **Password:** `admin`
   *(The backend automatically creates this admin user in MongoDB Atlas upon your first login)*.
3. Navigate to **Fleet Management / Endpoints** and click **1-Click Installers**.
4. The dashboard displays one-line commands for both Linux and Windows.
5. Run the command on any target PC (at home, in a college lab, or on a remote VPS):
   - **Linux:**
     ```bash
     curl -sSL "https://siem-backend.onrender.com/api/v1/enrollment/install.sh" | sudo bash -s -- --server "https://siem-backend.onrender.com" --token "ENROLL-XXXX-XXXX"
     ```
   - **Windows (PowerShell as Admin):**
     ```powershell
     powershell -ExecutionPolicy Bypass -Command "irm 'https://siem-backend.onrender.com/api/v1/enrollment/install.ps1?token=ENROLL-XXXX-XXXX&server=https://siem-backend.onrender.com' | iex"
     ```
6. The agent installs as a persistent system background service (`systemd` on Linux / Scheduled Task on Windows) and starts streaming live telemetry, logs, and processes directly to your cloud dashboard!

---

## Alternative: All-in-One Docker Compose (VPS / Server)

If you have a Linux VPS (DigitalOcean, AWS EC2, Linode, or Hetzner):
1. Clone the repository on the VPS:
   ```bash
   git clone git@github.com:SiddhantKale1/SIEM-Dashboard-security-information-event-mangement-.git
   cd SIEM-Dashboard-security-information-event-mangement-
   ```
2. Start the full stack with one command:
   ```bash
   docker compose up -d --build
   ```
3. Access:
   - **Frontend UI:** `http://<your-vps-ip>` (Port 80)
   - **Backend API:** `http://<your-vps-ip>:8000`
