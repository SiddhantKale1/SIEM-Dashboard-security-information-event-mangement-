# Implementation Milestones

## Milestone 1 — Backend foundation
- Setup FastAPI structure and routing.
- Integrate MongoDB (PyMongo/Motor).
- Implement User Authentication (login, JWT generation, validation).
- Define base models (Pydantic).
- Implement basic Device model.

## Milestone 2 — Device enrollment
- Implement token generation for enrollment (`/enrollment/token`).
- Implement device registration endpoint (`/enrollment/register`).
- Issue and validate device credentials.
- Implement agent heartbeat endpoint and logic to update device status.

## Milestone 3 — Windows agent
- Scaffold Python agent for Windows.
- Implement Windows Event Logs collection (Security, System, Application).
- Implement telemetry collection (CPU, RAM, Disk, Network).
- Implement process listing.
- Authenticate and transmit data to the central server.

## Milestone 4 — Linux agent
- Scaffold Python agent for Linux.
- Implement Linux log collection (syslog/journald).
- Implement telemetry collection.
- Implement process listing.
- Authenticate and transmit data to the central server.

## Milestone 5 — Normalization
- Design and implement the common log schema.
- Implement parsing and normalization logic on the backend for incoming Windows and Linux logs.
- Save normalized logs to MongoDB.

## Milestone 6 — Dashboard
- Scaffold React frontend with Vite, TypeScript, and Tailwind CSS.
- Implement Authentication UI (login page).
- Implement Dashboard Overview (charts and high-level stats).
- Implement Devices list and Device details pages.
- Implement Log Explorer.
- Implement Metrics visualization (Recharts).

## Milestone 7 — Network discovery
- Implement safe network discovery (e.g., scanning local ARP tables).
- Expose discovered devices via the API (`/network/devices`).
- Distinguish discovered, managed, offline, and isolated devices on the dashboard.

## Milestone 8 — Network controller
- Define the `NetworkController` abstract class.
- Implement `MockNetworkController` for simulated isolation/restoration.
- Implement Network isolation/restoration API endpoints.
- Add Network Control UI and audit logs to the dashboard.

## Milestone 9 — Reliability
- Implement a local queue/buffer in the Python agents.
- Implement exponential backoff for agent retries.
- Ensure backend safely handles duplicate events (idempotency via unique event identifiers).

## Milestone 10 — Testing and documentation
- Write end-to-end and unit tests for backend API.
- Test agents with mocks/real systems.
- Test frontend components.
- Finalize documentation (`README.md`, `setup instructions`, etc.).
- End-to-end manual validation against the acceptance criteria.
