# SIEM Management Platform - Feature Overview

This document outlines the core architecture and feature set I have developed for the Security Information and Event Management (SIEM) MVP. My goal was to build a robust, production-ready security platform from the ground up, focusing on a premium user experience and strong backend reliability.

## 🏗️ Architecture & Tech Stack

I built this platform using a modern, decoupled architecture:
*   **Frontend:** React, TypeScript, and Vite. I designed a custom "Stripe-inspired" dark mode interface using `lucide-react` for iconography and `recharts` for data visualization.
*   **Backend:** Python and FastAPI. I implemented a highly concurrent, async API architecture.
*   **Database:** Mongita (a lightweight, file-backed MongoDB alternative) to ensure persistent data storage without requiring a heavy, external database server.
*   **Agents:** Custom Python agents deployed on endpoints that report telemetry and logs back to the server securely.

---

## 🚀 Core Features I Developed

### 1. Identity & Security (Auth)
*   **JWT Authentication:** Implemented secure login with JSON Web Tokens, protecting all API routes and frontend pages.
*   **Forced Password Policies:** I engineered a security workflow that detects default credentials (like the initial admin account). If a default password is used, I force a full-screen, un-bypassable modal requiring the user to set a strong password before accessing the dashboard.
*   **Session Management:** Built an `api.ts` interceptor that catches expired sessions and securely redirects the user to the login page without data leakage.

### 2. Live Dashboard & Analytics
*   **Real-Time Log Visualization:** I built the dashboard to fetch real data dynamically. It aggregates thousands of syslogs into hourly buckets to render an interactive area chart.
*   **Active Threat Monitoring:** The dashboard calculates and surfaces critical alerts, showing exactly how many 'Error' or 'Warning' logs occurred today in a dedicated alerts strip.
*   **Device Health Overview:** Live counters show exactly how many agents are Online, Offline, or Isolated at a glance.

### 3. Endpoint & Device Management
*   **Secure Device Enrollment:** Instead of open agent registration, I implemented a secure token system. Admins generate single-use or time-bound enrollment tokens from the UI.
*   **Token Revocation:** I built a dedicated panel in the UI to list active tokens, allowing me to instantly revoke them if compromised.
*   **Agent Telemetry:** Agents send heartbeats every few seconds. I built the backend to process these heartbeats and the frontend to display live CPU, Memory, and Network usage in real-time on the Device Details page.
*   **Network Discovery:** Added a "Detect" feature that triggers a manual network sweep to identify unmanaged devices on the local subnet.

### 4. Incident Response (Isolation Workflow)
*   **One-Click Isolation:** If a device is compromised, I built a feature allowing the admin to click "Isolate." This flips the device state, instructing the agent to sever external communications while maintaining a heartbeat to the SIEM server.
*   **Safe Restoration:** Once a threat is neutralized, I implemented a "Restore" workflow that safely brings the device back online.
*   **Audit Timelines:** I created a vertical audit timeline on the Device Details page. It tracks exactly when a device was enrolled, isolated, or restored, complete with timestamps and visual indicators.

### 5. Centralized Log Management
*   **Server-Side Search Engine:** Rather than downloading all logs to the browser, I engineered the backend to handle search filtering. The frontend passes query strings, and the backend searches across device hostnames, event IDs, and message bodies.
*   **Pagination & Filtering:** I implemented paginated API endpoints and severity filters (Error, Warning, Info) to ensure the UI remains fast even when querying thousands of logs.

---

## 🎯 Summary
I engineered this entire platform to prove that a security tool can be both incredibly powerful under the hood and beautiful on the surface. By handling everything from the database schemas and REST API to the React context providers and CSS animations, I ensured the platform is cohesive, fast, and ready for real-world deployment.
