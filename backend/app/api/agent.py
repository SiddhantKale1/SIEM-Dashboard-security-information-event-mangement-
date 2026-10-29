from fastapi import APIRouter, Depends, HTTPException, status
from datetime import datetime, timezone
import logging
import re
import json

from app.database.connection import get_db
from app.api.auth import get_current_device
from app.schemas.enrollment import HeartbeatRequest
from app.schemas.agent import LogsRequest, MetricsRequest, ProcessesRequest
from app.services.ai_engine import AIEngine
from app.services.network_service import NetworkManager
from app.services.log_humanizer import humanize_log

router = APIRouter(prefix="/api/v1/agent", tags=["agent"])
logger = logging.getLogger(__name__)
_last_inbound_flows: dict = {}

@router.post("/heartbeat")
async def agent_heartbeat(
    request: HeartbeatRequest,
    current_device: dict = Depends(get_current_device)
):
    if request.device_id != current_device["device_id"]:
        logger.warning(f"Device ID mismatch in heartbeat. Expected {current_device['device_id']}, got {request.device_id}")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Device ID mismatch")
        
    db = get_db()
    now = datetime.now(timezone.utc)
    
    # Handle explicit offline shutdown notification
    if request.status == "offline":
        await db.devices.update_one(
            {"device_id": current_device["device_id"]},
            {"$set": {
                "status": "offline",
                "last_seen": now
            }}
        )
        await db.connection_history.update_many(
            {"device_id": current_device["device_id"], "status": "active"},
            {"$set": {
                "status": "closed",
                "disconnected_at": now,
                "termination_reason": "device_shutdown"
            }}
        )
        logger.info(f"Device {current_device.get('hostname')} ({current_device['device_id']}) shut down / went offline.")
        return {"status": "offline", "server_time": now.isoformat()}

    # Normal online heartbeat
    await db.devices.update_one(
        {"device_id": current_device["device_id"]},
        {"$set": {
            "status": "online",
            "last_seen": now
        }}
    )

    # Record or update active connection history session
    await NetworkManager.record_connection_event(
        db=db,
        device_id=current_device["device_id"],
        hostname=current_device.get("hostname", "unknown"),
        ip=current_device.get("ip_address", "127.0.0.1"),
        mac=current_device.get("mac_address", "00:00:00:00:00:00"),
        os_name=current_device.get("os", "unknown"),
        event_type="connected"
    )

    return {
        "status": "ok",
        "server_time": now.isoformat(),
        "policies": {
            "blocked_domains": []
        }
    }

@router.post("/logs")
async def receive_logs(
    request: LogsRequest,
    current_device: dict = Depends(get_current_device)
):
    if request.device_id != current_device["device_id"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Device ID mismatch")
        
    db = get_db()
    logs_to_insert = []
    hostname = current_device.get("hostname", "unknown")
    device_id = current_device["device_id"]
    
    for log in request.logs:
        log_dict = log.dict()
        log_dict["ingested_at"] = datetime.now(timezone.utc)
        log_dict["hostname"] = hostname

        # Parse Windows event text if raw_log has real details or message is Event[0]
        if log_dict.get("os") == "windows" and (log_dict.get("message", "").startswith("Event[") or log_dict.get("event_id") == "SystemEvent"):
            raw = str(log_dict.get("raw_log", ""))
            eid_match = re.search(r"Event ID:\s*(\d+)", raw)
            src_match = re.search(r"Source:\s*([^\n\r]+)", raw)
            desc_match = re.search(r"Description:\s*\r?\n?([^\r\n]+)", raw)
            if eid_match:
                log_dict["event_id"] = eid_match.group(1)
            if src_match:
                log_dict["source"] = src_match.group(1).strip()
            if desc_match and desc_match.group(1).strip() not in ("N/A", ""):
                log_dict["message"] = desc_match.group(1).strip()[:300]
            else:
                log_dict["message"] = f"Windows System Event ({log_dict.get('source', 'System')}, Event ID: {log_dict.get('event_id', '1')})"

        # Humanize log into plain-English college lab understandable format
        humanize_log(log_dict)
        if log_dict.get("is_policy_violation"):
            log_dict["severity"] = "warning"
            log_dict["event_type"] = "policy_violation"

        logs_to_insert.append(log_dict)

    # Record active inbound network TCP socket connection periodically (at most once every 5 min)
    # or whenever the agent does not report its own network sockets
    now = datetime.now(timezone.utc)
    has_agent_network_logs = any(l.get("source_type") == "network" for l in logs_to_insert)
    last_flow = _last_inbound_flows.get(device_id)
    ip_address = current_device.get("ip_address", "127.0.0.1")
    os_name = current_device.get("os", "unknown")
    
    if not has_agent_network_logs and (not last_flow or (now - last_flow).total_seconds() > 300):
        _last_inbound_flows[device_id] = now
        net_flow_log = {
            "timestamp": now,
            "ingested_at": now,
            "device_id": device_id,
            "hostname": hostname,
            "os": os_name,
            "source_type": "network",
            "source": "kernel_socket",
            "event_id": "TCP_ESTABLISHED",
            "event_type": "network",
            "severity": "information",
            "message": f"Active TCP connection from {ip_address} to SIEM port 8000 (telemetry session active)",
            "raw_log": json.dumps({
                "client_ip": ip_address,
                "server_port": 8000,
                "protocol": "TCP",
                "state": "ESTABLISHED",
                "mac": current_device.get("mac_address"),
                "subnet": current_device.get("subnet")
            })
        }
        logs_to_insert.append(net_flow_log)

    # 1. Live Threat Detection: AI inspects ALL live events in real-time
    if logs_to_insert:
        try:
            await AIEngine.analyze_logs(
                db=db,
                device_id=device_id,
                hostname=hostname,
                logs=logs_to_insert,
                ip_address=ip_address,
                os_name=os_name
            )
        except Exception as e:
            logger.error(f"Error executing AI log anomaly engine: {e}")

    # 2. Smart Persistence Filter: Only store relevant logs in DB
    # Keeps warnings, errors, network/DNS/website visits, and security/auth events.
    # Drops routine, repetitive background informational chatter so the database doesn't fill up.
    def is_log_worth_storing(l: dict) -> bool:
        sev = str(l.get("severity", "")).lower()
        if sev in ("warning", "error", "critical", "alert", "emergency"):
            return True

        st = str(l.get("source_type", "")).lower()
        src = str(l.get("source", "")).lower()
        eid = str(l.get("event_id", "")).lower()
        msg = str(l.get("message", "")).lower()

        # Network traffic, DNS queries, visited websites
        if st == "network" or eid in ("dns_query", "tcp_established") or src in ("dns_cache", "kernel_socket", "netstat", "ss", "firewall"):
            return True
        if "dns" in src or "domain" in msg or "website" in msg or "http" in msg:
            return True

        # Security, Authentication, and Privilege changes
        security_keywords = (
            "auth", "login", "logon", "failed", "failure", "passwd", "sudo", 
            "su:", "sshd", "privilege", "shadow", "useradd", "userdel", "groupadd",
            "isolate", "quarantine", "threat", "firewall", "blocked", "malware",
            "attack", "brute", "tamper", "defender", "audit"
        )
        if any(k in src for k in security_keywords) or any(k in msg for k in security_keywords):
            return True

        # Windows security event IDs
        if eid in ("4624", "4625", "4672", "4720", "4726", "4738", "1102", "7045", "4697", "4698", "4702"):
            return True

        return False

    logs_to_persist = [l for l in logs_to_insert if is_log_worth_storing(l)]

    if logs_to_persist:
        await db.logs.insert_many(logs_to_persist)

        # Database Log Cap & Auto-Prune: Keep DB healthy and capped at 5000 logs
        try:
            total_logs = await db.logs.count_documents({})
            if total_logs > 5000:
                excess = total_logs - 5000
                old_logs = await db.logs.find({}).sort("timestamp", 1).limit(excess).to_list(excess)
                for ol in old_logs:
                    await db.logs.delete_one({"_id": ol["_id"]})
        except Exception:
            pass

    # Update logs count in active connection session
    try:
        await db.connection_history.update_one(
            {"device_id": device_id, "status": "active"},
            {"$inc": {"logs_sent": len(logs_to_insert)}, "$set": {"last_active_at": datetime.now(timezone.utc)}}
        )
    except Exception:
        pass
        
    return {"status": "ok", "processed": len(logs_to_insert), "persisted": len(logs_to_persist)}

@router.post("/metrics")
async def receive_metrics(
    request: MetricsRequest,
    current_device: dict = Depends(get_current_device)
):
    if request.device_id != current_device["device_id"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Device ID mismatch")
        
    db = get_db()
    hostname = current_device.get("hostname", "unknown")
    device_id = current_device["device_id"]
    ip_address = current_device.get("ip_address", "127.0.0.1")
    os_name = current_device.get("os", "unknown")
    metrics_to_insert = [m.dict() for m in request.metrics]
        
    if metrics_to_insert:
        await db.metrics.insert_many(metrics_to_insert)

        # Real-time AI Metric Anomaly Detection Hook
        try:
            await AIEngine.analyze_metrics(
                db=db, 
                device_id=device_id, 
                hostname=hostname, 
                metrics=metrics_to_insert,
                ip_address=ip_address,
                os_name=os_name
            )
        except Exception as e:
            logger.error(f"Error executing AI metric anomaly engine: {e}")

        # Update metrics count in connection session
        try:
            await db.connection_history.update_one(
                {"device_id": device_id, "status": "active"},
                {"$inc": {"metrics_sent": len(metrics_to_insert)}, "$set": {"last_active_at": datetime.now(timezone.utc)}}
            )
        except Exception:
            pass
        
    return {"status": "ok"}

@router.post("/processes")
async def receive_processes(
    request: ProcessesRequest,
    current_device: dict = Depends(get_current_device)
):
    if request.device_id != current_device["device_id"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Device ID mismatch")
        
    db = get_db()
    hostname = current_device.get("hostname", "unknown")
    device_id = request.device_id
    ip_address = current_device.get("ip_address", "127.0.0.1")
    os_name = current_device.get("os", "unknown")
    procs = [p.dict() for p in request.processes]
    
    await db.processes.update_one(
        {"device_id": device_id},
        {"$set": {
            "timestamp": datetime.now(timezone.utc),
            "processes": procs
        }},
        upsert=True
    )

    # Real-time AI Process Anomaly Detection Hook
    try:
        await AIEngine.analyze_processes(
            db=db, 
            device_id=device_id, 
            hostname=hostname, 
            processes=procs,
            ip_address=ip_address,
            os_name=os_name
        )
    except Exception as e:
        logger.error(f"Error executing AI process anomaly engine: {e}")
        
    return {"status": "ok"}
