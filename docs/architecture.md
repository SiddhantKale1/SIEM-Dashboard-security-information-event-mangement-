# SIEM MVP Architecture Document

## Overview
This document outlines the architecture for the SIEM Phase 1 - Centralized Device & Log Management MVP. The system is designed to discover and manage authorized devices, collect system telemetry and logs, normalize data into a common schema, and provide a web dashboard for monitoring and network management.

## Components

### 1. Backend (FastAPI)
The backend acts as the central API and collector. It is responsible for:
- **Authentication**: JWT-based authentication for administrators and analysts.
- **Device Enrollment**: Securely enrolling devices using single-use tokens and issuing persistent device credentials.
- **Data Ingestion**: Receiving logs, metrics, and processes from enrolled agents over HTTPS.
- **Data Normalization**: Transforming raw logs into a common schema before storing them.
- **Dashboard API**: Serving data to the React frontend.
- **Network Control Integration**: Abstracting network isolation commands to an interface (`NetworkController`), with a `MockNetworkController` implemented for the MVP.

### 2. Database (MongoDB)
MongoDB is used as the central datastore for its flexible schema support, which is useful for varied log formats.
Collections:
- `users`: Administrator and analyst accounts.
- `devices`: Enrolled and discovered devices.
- `logs`: Normalized logs from all agents.
- `metrics`: Telemetry data (CPU, RAM, Disk, Network).
- `device_events`: Audit log for device management (enrollment, removal, isolation).
- `network_actions`: Audit log for network control commands.
- `enrollment_tokens`: Short-lived tokens used to bootstrap agent enrollment.

### 3. Frontend (React Dashboard)
A React-based web dashboard (Vite + TypeScript + Tailwind CSS) providing:
- High-level overview of network and device status.
- Device management (enrollment, details, isolation, removal).
- Log explorer with search and filter capabilities.
- Real-time or near real-time metric visualization (using Recharts).
- Network status overview.

### 4. Agents
- **Windows Agent (Python)**: Uses native Windows Event Log APIs to collect security, system, and application events. Also collects host telemetry.
- **Linux Agent (Python)**: Uses standard Linux interfaces to collect journald/syslog events and host telemetry.

Agents are designed with a local queue/buffer. If the backend is unavailable, they will buffer events and retry with exponential backoff to ensure reliability without infinite disk growth.

## Architecture Diagram

```text
Windows/Linux Device
        |
        | Agent (with local buffer & retry)
        |
        | HTTPS
        v
Central API / Collector
        |
        +--> Authentication (Device credential)
        |
        +--> Validation & Parsing
        |
        +--> Normalization (Common Log Schema)
        |
        v
     MongoDB (Logs, Metrics, Devices, Audit)
        |
        v
React Dashboard (React, Tailwind, Recharts)
        |
        +--> Devices Overview & Management
        +--> Log Explorer
        +--> Metric Charts
        +--> Authorized Network Isolation UI
```

## Security & Access
- All agent-to-backend communication occurs over HTTPS.
- Agents authenticate via device credentials issued during the token-based enrollment process.
- No offensive/unauthorized actions (e.g., ARP spoofing) are permitted. Network isolation strictly relies on the configured `NetworkController`.
- Passwords and sensitive tokens are hashed using bcrypt/Argon2.

## Extensibility
The pipeline (Collection -> Normalization -> Storage) is designed such that future components like Machine Learning models, Threat Intelligence, and Alerting can process normalized data from MongoDB or via a message queue without re-architecting the ingestion or normalization layers.
