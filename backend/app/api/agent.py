from fastapi import APIRouter, Depends, HTTPException, status
from datetime import datetime, timezone
import logging

from app.database.connection import get_db
from app.api.auth import get_current_device
from app.schemas.enrollment import HeartbeatRequest
from app.schemas.agent import LogsRequest, MetricsRequest, ProcessesRequest

router = APIRouter(prefix="/api/v1/agent", tags=["agent"])
logger = logging.getLogger(__name__)

@router.post("/heartbeat")
async def agent_heartbeat(
    request: HeartbeatRequest,
    current_device: dict = Depends(get_current_device)
):
    if request.device_id != current_device["device_id"]:
        logger.warning(f"Device ID mismatch in heartbeat. Expected {current_device['device_id']}, got {request.device_id}")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Device ID mismatch")
        
    db = get_db()
    
    # Update device status and last_seen
    await db.devices.update_one(
        {"device_id": current_device["device_id"]},
        {"$set": {
            "status": request.status,
            "last_seen": datetime.now(timezone.utc)
        }}
    )
    
    return {"status": "ok"}

@router.post("/logs")
async def receive_logs(
    request: LogsRequest,
    current_device: dict = Depends(get_current_device)
):
    if request.device_id != current_device["device_id"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Device ID mismatch")
        
    db = get_db()
    logs_to_insert = []
    
    for log in request.logs:
        log_dict = log.dict()
        log_dict["ingested_at"] = datetime.now(timezone.utc)
        log_dict["hostname"] = current_device.get("hostname", "unknown")
        logs_to_insert.append(log_dict)
        
    if logs_to_insert:
        await db.logs.insert_many(logs_to_insert)
        
    return {"status": "ok", "processed": len(logs_to_insert)}

@router.post("/metrics")
async def receive_metrics(
    request: MetricsRequest,
    current_device: dict = Depends(get_current_device)
):
    if request.device_id != current_device["device_id"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Device ID mismatch")
        
    db = get_db()
    metrics_to_insert = [m.dict() for m in request.metrics]
        
    if metrics_to_insert:
        await db.metrics.insert_many(metrics_to_insert)
        
    return {"status": "ok"}

@router.post("/processes")
async def receive_processes(
    request: ProcessesRequest,
    current_device: dict = Depends(get_current_device)
):
    if request.device_id != current_device["device_id"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Device ID mismatch")
        
    db = get_db()
    
    # Store processes as a snapshot (for MVP, maybe just keep latest per device)
    # E.g. in a `processes` collection or just replace existing snapshot for the device.
    # To keep it simple, let's store it in a `processes` collection and just upsert the whole list.
    await db.processes.update_one(
        {"device_id": request.device_id},
        {"$set": {
            "timestamp": datetime.now(timezone.utc),
            "processes": [p.dict() for p in request.processes]
        }},
        upsert=True
    )
        
    return {"status": "ok"}
