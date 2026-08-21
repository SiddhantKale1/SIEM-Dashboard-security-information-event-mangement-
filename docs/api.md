# API Specification

Base Path: `/api/v1`

## Authentication

### Login
`POST /auth/login`
- **Body**: Form data (username, password)
- **Response**: JWT access token.

### Get Current User
`GET /auth/me`
- **Headers**: Authorization Bearer {token}
- **Response**: User object.

## Devices

### List Devices
`GET /devices`
- **Headers**: Authorization Bearer {token}
- **Response**: List of device objects.

### Get Device
`GET /devices/{device_id}`
- **Headers**: Authorization Bearer {token}
- **Response**: Detailed device object.

### Delete Device
`DELETE /devices/{device_id}`
- **Headers**: Authorization Bearer {token}
- **Response**: Success status.

### Get Device Logs
`GET /devices/{device_id}/logs`
- **Headers**: Authorization Bearer {token}
- **Response**: List of log objects.

### Get Device Metrics
`GET /devices/{device_id}/metrics`
- **Headers**: Authorization Bearer {token}
- **Response**: Time-series metrics data.

### Get Device Processes
`GET /devices/{device_id}/processes`
- **Headers**: Authorization Bearer {token}
- **Response**: List of processes running on the device.

## Enrollment

### Generate Token
`POST /enrollment/token`
- **Headers**: Authorization Bearer {token}
- **Response**: Enrollment token (e.g., `ENROLL-8F3K-29AD`).

### Register Device
`POST /enrollment/register`
- **Body**: `{ "token": "string", "hostname": "string", "os": "string", "mac_address": "string", "ip_address": "string" }`
- **Response**: `{ "device_id": "string", "device_credential": "string" }`

## Agent (Ingestion)

*These endpoints require device authentication via API keys/credentials.*

### Heartbeat
`POST /agent/heartbeat`
- **Body**: `{ "device_id": "string", "timestamp": "datetime", "status": "online" }`
- **Response**: `{ "status": "ok" }`

### Submit Logs
`POST /agent/logs`
- **Body**: `{ "device_id": "string", "logs": [...] }`
- **Response**: `{ "status": "ok", "processed": int }`

### Submit Metrics
`POST /agent/metrics`
- **Body**: `{ "device_id": "string", "metrics": [...] }`
- **Response**: `{ "status": "ok" }`

### Submit Processes
`POST /agent/processes`
- **Body**: `{ "device_id": "string", "processes": [...] }`
- **Response**: `{ "status": "ok" }`

## Logs

### Query Logs
`GET /logs`
- **Headers**: Authorization Bearer {token}
- **Query Params**: `device_id`, `hostname`, `source_type`, `event_type`, `start_time`, `end_time`, `username`, `source_ip`
- **Response**: List of normalized log objects.

### Get Log Details
`GET /logs/{log_id}`
- **Headers**: Authorization Bearer {token}
- **Response**: Full log object including `raw_log`.

## Network

### List Discovered Devices
`GET /network/devices`
- **Headers**: Authorization Bearer {token}
- **Response**: List of discovered and managed devices on the network.

### Isolate Device
`POST /network/devices/{device_id}/isolate`
- **Headers**: Authorization Bearer {token}
- **Body**: `{ "reason": "string" }`
- **Response**: Isolation status and audit record.

### Restore Device
`POST /network/devices/{device_id}/restore`
- **Headers**: Authorization Bearer {token}
- **Body**: `{ "reason": "string" }`
- **Response**: Restoration status and audit record.

### Get Network Actions
`GET /network/actions`
- **Headers**: Authorization Bearer {token}
- **Response**: List of network audit actions.
