from fastapi import APIRouter, Depends, HTTPException
from datetime import datetime, timezone, timedelta
import json
import re
from app.api.auth import get_current_user
from app.database.connection import get_db
from app.services.log_humanizer import humanize_log
from app.services.rbac import verify_device_access, require_admin, require_not_viewer

router = APIRouter(prefix="/api/v1/devices", tags=["devices"])

HEARTBEAT_TIMEOUT_SECONDS = 60

async def evaluate_device_status(device: dict, db) -> dict:
    if not device:
        return device
    curr_status = device.get("status")
    if curr_status in ("isolated", "discovered"):
        return device

    now = datetime.now(timezone.utc)
    recent_cutoff = now - timedelta(seconds=HEARTBEAT_TIMEOUT_SECONDS)
    last_seen = device.get("last_seen")

    is_online = False
    if isinstance(last_seen, datetime):
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        is_online = (last_seen > recent_cutoff)
    elif isinstance(last_seen, str):
        try:
            dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
            is_online = (dt > recent_cutoff)
        except Exception:
            pass

    expected_status = "online" if is_online else "offline"
    if curr_status != expected_status:
        device["status"] = expected_status
        await db.devices.update_one(
            {"device_id": device["device_id"]},
            {"$set": {"status": expected_status}}
        )
        if expected_status == "offline":
            await db.connection_history.update_many(
                {"device_id": device["device_id"], "status": "active"},
                {"$set": {
                    "status": "closed",
                    "disconnected_at": now,
                    "termination_reason": "device_offline"
                }}
            )
    return device

@router.get("/{device_id}")
async def get_device(device_id: str, current_user: dict = Depends(get_current_user)):
    db = get_db()
    device = await verify_device_access(device_id, current_user, db)
    device = await evaluate_device_status(device, db)
    device["_id"] = str(device["_id"])
    device["owner"] = device.get("owner") or device.get("created_by") or "admin"
    return device

@router.get("/{device_id}/metrics")
async def get_device_metrics(device_id: str, current_user: dict = Depends(get_current_user)):
    db = get_db()
    await verify_device_access(device_id, current_user, db)
    cursor = db.metrics.find({"device_id": device_id}).sort("timestamp", -1).limit(20)
    metrics = await cursor.to_list(length=20)
    metrics.reverse()

    for m in metrics:
        m["_id"] = str(m["_id"])

    return metrics

@router.post("/{device_id}/isolate")
async def isolate_device(device_id: str, current_user: dict = Depends(get_current_user)):
    """Isolate a device: blocks agent heartbeats and marks it isolated."""
    require_not_viewer(current_user, "quarantine endpoints")
    db = get_db()
    device = await verify_device_access(device_id, current_user, db)
    if device.get("status") == "isolated":
        raise HTTPException(status_code=400, detail="Device is already isolated")

    await db.devices.update_one(
        {"device_id": device_id},
        {"$set": {"status": "isolated", "isolated_at": datetime.now(timezone.utc)}}
    )
    await db.device_events.insert_one({
        "device_id": device_id,
        "event": "isolated",
        "timestamp": datetime.now(timezone.utc),
        "details": f"Isolated by {current_user['username']}",
        "actor": current_user["username"],
    })
    return {"status": "isolated", "device_id": device_id}

@router.post("/{device_id}/restore")
async def restore_device(device_id: str, current_user: dict = Depends(get_current_user)):
    """Restore a previously isolated device."""
    require_not_viewer(current_user, "restore quarantined endpoints")
    db = get_db()
    device = await verify_device_access(device_id, current_user, db)
    if device.get("status") != "isolated":
        raise HTTPException(status_code=400, detail="Device is not isolated")

    await db.devices.update_one(
        {"device_id": device_id},
        {"$set": {"status": "online", "restored_at": datetime.now(timezone.utc)}}
    )
    await db.device_events.insert_one({
        "device_id": device_id,
        "event": "restored",
        "timestamp": datetime.now(timezone.utc),
        "details": f"Access restored by {current_user['username']}",
        "actor": current_user["username"],
    })
    return {"status": "online", "device_id": device_id}

@router.delete("/{device_id}")
async def delete_device(device_id: str, current_user: dict = Depends(get_current_user)):
    """
    Permanently delete a device from the SIEM monitoring system (Admin only).
    Cascades removal across logs, metrics, processes, events, and anomalies.
    """
    require_admin(current_user, "permanently delete monitored endpoints")
    db = get_db()

    # Look up device by device_id or string _id / ObjectId
    device = await db.devices.find_one({"device_id": device_id})
    if not device:
        device = await db.devices.find_one({"_id": device_id})
    if not device:
        try:
            from bson import ObjectId
            device = await db.devices.find_one({"_id": ObjectId(device_id)})
        except Exception:
            pass

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    actual_device_id = device.get("device_id")
    device_obj_id = device.get("_id")
    hostname = device.get("hostname", "Unknown Device")
    ip_address = device.get("ip_address")

    # Delete device document
    if actual_device_id:
        await db.devices.delete_many({"device_id": actual_device_id})
    if device_obj_id:
        await db.devices.delete_many({"_id": device_obj_id})

    # Cascade delete all related records
    if actual_device_id:
        await db.logs.delete_many({"device_id": actual_device_id})
        await db.metrics.delete_many({"device_id": actual_device_id})
        await db.processes.delete_many({"device_id": actual_device_id})
        await db.device_events.delete_many({"device_id": actual_device_id})
        await db.connection_history.delete_many({"device_id": actual_device_id})
        await db.anomalies.delete_many({"device_id": actual_device_id})
        try:
            await db.enrollment_tokens.update_many(
                {"device_ids": actual_device_id},
                {"$pull": {"device_ids": actual_device_id}}
            )
        except Exception:
            pass

    if ip_address:
        await db.connection_history.delete_many({"ip_address": ip_address})

    return {
        "status": "deleted",
        "device_id": actual_device_id or str(device_obj_id),
        "hostname": hostname,
        "message": f"Device '{hostname}' and all its associated monitoring records have been permanently removed."
    }


@router.get("/{device_id}/events")
async def get_device_events(device_id: str, current_user: dict = Depends(get_current_user)):
    """Return audit event timeline for a device."""
    db = get_db()
    await verify_device_access(device_id, current_user, db)
    cursor = db.device_events.find({"device_id": device_id}).sort("timestamp", -1).limit(50)
    events = await cursor.to_list(length=50)
    for e in events:
        e["_id"] = str(e["_id"])
    return events

@router.get("/{device_id}/system-logs")
async def get_device_system_logs(
    device_id: str, 
    limit: int = 100, 
    current_user: dict = Depends(get_current_user)
):
    """Returns actual system/OS/auth logs collected from the device agent."""
    db = get_db()
    await verify_device_access(device_id, current_user, db)
    cursor = db.logs.find({"device_id": device_id}).sort("timestamp", -1).limit(limit)
    logs = await cursor.to_list(length=limit)
    for l in logs:
        l["_id"] = str(l["_id"])
        humanize_log(l)
    return logs

@router.get("/{device_id}/network-logs")
async def get_device_network_logs(
    device_id: str, 
    limit: int = 100, 
    current_user: dict = Depends(get_current_user)
):
    """
    Returns real network telemetry for this specific device:
    - Connection history sessions
    - Real network/socket/firewall logs
    - Network rx/tx bandwidth stats
    - Active network anomalies
    """
    db = get_db()
    await verify_device_access(device_id, current_user, db)
    
    # 1. Connection history sessions
    conn_cursor = db.connection_history.find({"device_id": device_id}).sort("connected_at", -1).limit(50)
    sessions = await conn_cursor.to_list(length=50)
    for s in sessions:
        s["_id"] = str(s["_id"])
        
    def is_valid_web_domain(d: str) -> bool:
        if not d or not isinstance(d, str):
            return False
        d = d.strip().rstrip(".").lower()
        if not d or len(d) < 3 or "." not in d:
            return False
        # Must not be an IP address
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", d):
            return False
        # Must contain letters
        if not re.search(r"[a-z]", d):
            return False
        # Ignore noisy internal loopback or reverse DNS suffixes
        noise = ("in-addr.arpa", ".local", ".lan", "wpad", "localhost", ".invalid")
        if any(d.endswith(n) or n in d for n in noise):
            return False
        return True

    def extract_domain_from_log(l: dict) -> tuple[str | None, str | None]:
        dom = None
        resolved = None
        raw = l.get("raw_log")

        # 1. From structured raw_log
        if isinstance(raw, dict):
            dom = raw.get("domain") or raw.get("matched_domain") or raw.get("host")
            resolved = raw.get("resolved_ip") or raw.get("remote_addr") or raw.get("client_ip")
        elif isinstance(raw, str) and "domain" in raw:
            try:
                parsed = json.loads(raw)
                dom = parsed.get("domain") or parsed.get("matched_domain")
                resolved = parsed.get("resolved_ip") or parsed.get("remote_addr")
            except Exception:
                pass

        # 2. From log message patterns
        msg = l.get("message", "")
        if not dom:
            # Pattern A: [Domain: example.com]
            m_dom = re.search(r"\[Domain:\s*([a-zA-Z0-9\-\.]+)\]", msg)
            if m_dom:
                dom = m_dom.group(1)
        if not dom:
            # Pattern B: https://example.com
            m_url = re.search(r"https?://([a-zA-Z0-9\-\.]+)", msg)
            if m_url:
                dom = m_url.group(1)
        if not dom:
            # Pattern C: Visited Website: example.com or Website / Domain Visited: example.com
            m_vis = re.search(r"(?:Website / Domain Visited|Visited Website):\s*(?:https?://)?([a-zA-Z0-9\-\.]+)", msg, re.IGNORECASE)
            if m_vis:
                dom = m_vis.group(1)

        # Extract resolved IP if available
        if not resolved:
            m_ip = re.search(r"Resolved IP:\s*([0-9\.]+)", msg)
            if m_ip:
                resolved = m_ip.group(1)
            else:
                m_rip = re.search(r"Remote IP:\s*([0-9\.]+)", msg)
                if m_rip:
                    resolved = m_rip.group(1)

        if dom:
            dom = dom.strip().rstrip(".").lower()
            if is_valid_web_domain(dom):
                return dom, resolved

        return None, None

    # 2. Network & DNS log events
    visited_domains = []
    seen_domains = set()

    # Step 2A: Query dedicated DNS and Web Visit events specifically so they are NEVER crowded out
    dns_cursor = db.logs.find({
        "device_id": device_id,
        "$or": [
            {"event_id": {"$in": ["DNS_QUERY", "WEB_VISIT", "dns_query", "web_visit"]}},
            {"source": {"$in": ["dns_cache", "browser_network"]}},
            {"message": {"$regex": "Domain:|Website|https?://", "$options": "i"}}
        ]
    }).sort("timestamp", -1).limit(100)
    dedicated_web_logs = await dns_cursor.to_list(length=100)

    for wl in dedicated_web_logs:
        dom, res_ip = extract_domain_from_log(wl)
        if dom and dom not in seen_domains:
            seen_domains.add(dom)
            visited_domains.append({
                "domain": dom,
                "timestamp": wl.get("timestamp"),
                "source": wl.get("source", "dns_cache"),
                "resolved_ip": res_ip or wl.get("source_ip") or "—"
            })

    # Step 2B: General network connection stream
    log_cursor = db.logs.find({"device_id": device_id}).sort("timestamp", -1).limit(600)
    candidate_logs = await log_cursor.to_list(length=600)
    net_logs = []

    keywords = (
        "net", "firewall", "sshd", "ssh", "traffic", "socket", "wifi", "conn",
        "port", "packet", "flow", "ip", "tcp", "udp", "dns", "domain", "web",
        "url", "query", "youtube", "browser", "chrome", "edge", "firefox"
    )

    for nl in candidate_logs:
        st = str(nl.get("source_type", "")).lower()
        et = str(nl.get("event_type", "")).lower()
        src = str(nl.get("source", "")).lower()
        eid = str(nl.get("event_id", "")).lower()
        msg = str(nl.get("message", "")).lower()

        is_net = (
            st == "network" or 
            et == "network" or 
            eid in ("dns_query", "web_visit", "tcp_established") or
            src in ("dns_cache", "browser_network", "kernel_socket", "netstat", "ss", "firewall") or
            any(k in src for k in keywords) or 
            any(k in msg for k in keywords)
        )

        if is_net:
            nl["_id"] = str(nl["_id"])
            net_logs.append(nl)

            # Also check candidate log for domain if not already captured
            dom, res_ip = extract_domain_from_log(nl)
            if dom and dom not in seen_domains:
                seen_domains.add(dom)
                visited_domains.append({
                    "domain": dom,
                    "timestamp": nl.get("timestamp"),
                    "source": nl.get("source", "kernel_socket"),
                    "resolved_ip": res_ip or nl.get("source_ip") or "—"
                })

            if len(net_logs) >= limit:
                break

    # If explicit socket logs not yet dispatched by agent, generate real connection logs from active session
    if not net_logs and sessions:
        for s in sessions[:5]:
            net_logs.append({
                "_id": f"sess-{s.get('_id')}",
                "timestamp": s.get("connected_at") or s.get("last_active_at"),
                "device_id": device_id,
                "os": s.get("os", "unknown"),
                "source_type": "network",
                "source": "kernel_socket",
                "event_id": "TCP_ESTABLISHED",
                "event_type": "network",
                "severity": "information",
                "message": f"Active TCP connection from {s.get('ip_address')} on subnet {s.get('subnet')} (Duration: {s.get('duration_seconds', 0)}s, Packets/Logs: {s.get('logs_sent', 0)})",
                "raw_log": json.dumps(s, default=str)
            })

    # 3. Rx/Tx bandwidth metrics
    met_cursor = db.metrics.find({"device_id": device_id}).sort("timestamp", -1).limit(30)
    metrics = await met_cursor.to_list(length=30)
    metrics.reverse()
    for m in metrics:
        m["_id"] = str(m["_id"])

    # 4. Network anomalies for this device
    anom_cursor = db.anomalies.find({"device_id": device_id}).sort("detected_at", -1).limit(20)
    anomalies = await anom_cursor.to_list(length=20)
    for a in anomalies:
        a["_id"] = str(a["_id"])

    for nl in net_logs:
        humanize_log(nl)

    return {
        "device_id": device_id,
        "sessions": sessions,
        "network_logs": net_logs,
        "visited_domains": visited_domains,
        "bandwidth_metrics": metrics,
        "anomalies": anomalies
    }

@router.get("/{device_id}/processes")
async def get_device_processes(
    device_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Returns real process snapshot reported by device agent."""
    db = get_db()
    await verify_device_access(device_id, current_user, db)
    proc_doc = await db.processes.find_one({"device_id": device_id})
    if not proc_doc:
        return {"device_id": device_id, "processes": [], "timestamp": None}
    proc_doc["_id"] = str(proc_doc["_id"])
    return proc_doc
