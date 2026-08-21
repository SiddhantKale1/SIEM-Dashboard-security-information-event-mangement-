# Database Schema (MongoDB)

## Collections

### 1. `users`
Administrators and analysts who access the dashboard.
```json
{
  "_id": "ObjectId",
  "username": "string",
  "password_hash": "string",
  "role": "string (admin|analyst)",
  "created_at": "datetime",
  "last_login": "datetime"
}
```

### 2. `devices`
Managed and discovered devices on the network.
```json
{
  "_id": "ObjectId",
  "device_id": "string",
  "hostname": "string",
  "ip_address": "string",
  "mac_address": "string",
  "os": "string (windows|linux|unknown)",
  "os_version": "string",
  "agent_version": "string",
  "status": "string (online|offline|isolated|unknown)",
  "last_seen": "datetime",
  "enrolled_at": "datetime",
  "created_at": "datetime"
}
```

### 3. `logs`
Normalized logs collected from agents.
```json
{
  "_id": "ObjectId",
  "timestamp": "datetime",
  "device_id": "string",
  "hostname": "string",
  "os": "string",
  "source_type": "string (windows_event|syslog|journald)",
  "source": "string",
  "event_id": "integer|string",
  "event_type": "string",
  "severity": "string",
  "username": "string",
  "source_ip": "string",
  "message": "string",
  "raw_log": "object|string",
  "ingested_at": "datetime"
}
```
**Indexes**: `timestamp`, `device_id`, `event_type`, `source_type`, `source_ip`

### 4. `metrics`
System telemetry data collected periodically.
```json
{
  "_id": "ObjectId",
  "timestamp": "datetime",
  "device_id": "string",
  "cpu_percent": "float",
  "memory_percent": "float",
  "memory_used_mb": "integer",
  "memory_total_mb": "integer",
  "disk_percent": "float",
  "network_rx_bytes": "integer",
  "network_tx_bytes": "integer"
}
```
**Indexes**: `timestamp`, `device_id`

### 5. `device_events`
Audit trail of device lifecycle and management events.
```json
{
  "_id": "ObjectId",
  "device_id": "string",
  "event": "string (enrolled|removed|isolated|restored|disconnected|reconnected)",
  "timestamp": "datetime",
  "details": "string"
}
```

### 6. `network_actions`
Audit log of authorized network-control actions (e.g., isolation).
```json
{
  "_id": "ObjectId",
  "action_id": "string",
  "device_id": "string",
  "action": "string (isolate|restore)",
  "requested_by": "string",
  "timestamp": "datetime",
  "status": "string (success|failed)",
  "provider": "string (mock|real)",
  "reason": "string"
}
```

### 7. `enrollment_tokens`
Tokens for bootstrapping device enrollment.
```json
{
  "_id": "ObjectId",
  "token_hash": "string",
  "created_by": "string",
  "created_at": "datetime",
  "expires_at": "datetime",
  "used": "boolean",
  "device_id": "string (optional, populated upon use)"
}
```
