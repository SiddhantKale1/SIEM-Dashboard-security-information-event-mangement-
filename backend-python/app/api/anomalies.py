from fastapi import APIRouter, Depends, HTTPException, Query, status
from datetime import datetime, timezone, timedelta
from typing import Optional, List
import uuid

from app.api.auth import get_current_user
from app.database.connection import get_db
from app.services.ai_engine import AIEngine
from app.services.rbac import get_user_device_ids, require_not_viewer

router = APIRouter(prefix="/api/v1/anomalies", tags=["anomalies"])

@router.get("/stats")
async def get_anomaly_stats(current_user: dict = Depends(get_current_user)):
    """
    Returns AI security posture metrics scoped by operator permissions.
    """
    db = get_db()
    is_admin = current_user.get("role") == "admin"
    base_filter: dict = {}
    if not is_admin:
        user_device_ids = await get_user_device_ids(current_user, db)
        base_filter = {"device_id": {"$in": user_device_ids}}

    total = await db.anomalies.count_documents(base_filter)
    active = await db.anomalies.count_documents({**base_filter, "status": "active"})
    critical = await db.anomalies.count_documents({**base_filter, "severity": "critical", "status": "active"})
    high = await db.anomalies.count_documents({**base_filter, "severity": "high", "status": "active"})
    medium = await db.anomalies.count_documents({**base_filter, "severity": "medium", "status": "active"})
    resolved = await db.anomalies.count_documents({**base_filter, "status": "resolved"})

    # Dynamic AI Risk Score Calculation
    calculated_risk = min(100, (critical * 35) + (high * 15) + (medium * 5))
    if active == 0:
        posture = "SECURE"
    elif calculated_risk > 70:
        posture = "CRITICAL"
    elif calculated_risk > 35:
        posture = "ELEVATED"
    else:
        posture = "MONITORED"

    # Fetch recent active anomalies for MITRE breakdown
    cursor = db.anomalies.find({**base_filter, "status": "active"}).limit(100)
    active_items = await cursor.to_list(length=100)
    
    tactic_counts: dict[str, int] = {}
    for item in active_items:
        tactic = item.get("mitre_tactic", "General")
        tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

    return {
        "risk_score": calculated_risk,
        "posture": posture,
        "total_anomalies": total,
        "active_threats": active,
        "critical_threats": critical,
        "high_threats": high,
        "medium_threats": medium,
        "resolved_threats": resolved,
        "mitre_distribution": [{"tactic": k, "count": v} for k, v in tactic_counts.items()]
    }

@router.get("")
async def list_anomalies(
    current_user: dict = Depends(get_current_user),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    device_id: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100)
):
    """
    List detected anomalies with pagination and filtering, scoped to user devices.
    """
    db = get_db()
    is_admin = current_user.get("role") == "admin"
    query: dict = {}

    if not is_admin:
        user_device_ids = await get_user_device_ids(current_user, db)
        if device_id:
            if device_id not in user_device_ids:
                raise HTTPException(status_code=403, detail="Access denied: You do not have permission to view anomalies for this device")
            query["device_id"] = device_id
        else:
            query["device_id"] = {"$in": user_device_ids}
    elif device_id:
        query["device_id"] = device_id

    if status and status != "all":
        query["status"] = status
    if severity and severity != "all":
        query["severity"] = severity

    total = await db.anomalies.count_documents(query)
    cursor = db.anomalies.find(query).sort("detected_at", -1)
    
    all_items = await cursor.to_list(length=2000)
    start = (page - 1) * limit
    paginated = all_items[start:start + limit]

    dev_map = {}
    for item in paginated:
        item["_id"] = str(item["_id"])
        did = item.get("device_id")
        if did:
            if did not in dev_map:
                d_doc = await db.devices.find_one({"device_id": did})
                dev_map[did] = d_doc or {}
            d_info = dev_map[did]
            if not item.get("ip_address") or item.get("ip_address") in ("127.0.0.1", "None", None):
                item["ip_address"] = d_info.get("ip_address", "192.168.29.178")
            if not item.get("os") or item.get("os") == "unknown":
                item["os"] = d_info.get("os", "windows" if "win" in str(d_info.get("hostname", "")).lower() else "linux")
            if not item.get("hostname") or item.get("hostname") == "unknown":
                item["hostname"] = d_info.get("hostname", "Endpoint")

        if isinstance(item.get("detected_at"), datetime):
            item["detected_at"] = item["detected_at"].isoformat()
        if isinstance(item.get("updated_at"), datetime):
            item["updated_at"] = item["updated_at"].isoformat()
        if isinstance(item.get("resolved_at"), datetime):
            item["resolved_at"] = item["resolved_at"].isoformat()

    return {
        "anomalies": paginated,
        "total": total,
        "page": page,
        "limit": limit,
        "pages": max(1, -(-total // limit))
    }

@router.get("/{anomaly_id}")
async def get_anomaly(anomaly_id: str, current_user: dict = Depends(get_current_user)):
    """
    Retrieve full AI investigation report for a specific anomaly.
    """
    db = get_db()
    all_cursor = db.anomalies.find({})
    all_items = await all_cursor.to_list(length=2000)
    target = next((item for item in all_items if str(item.get("_id")) == anomaly_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="Anomaly not found")

    is_admin = current_user.get("role") == "admin"
    did = target.get("device_id")
    if not is_admin and did:
        user_device_ids = await get_user_device_ids(current_user, db)
        if did not in user_device_ids:
            raise HTTPException(status_code=403, detail="Access denied: You do not have permission to view this incident")

    target["_id"] = str(target["_id"])
    if did:
        d_doc = await db.devices.find_one({"device_id": did})
        if d_doc:
            if not target.get("ip_address") or target.get("ip_address") in ("127.0.0.1", "None", None):
                target["ip_address"] = d_doc.get("ip_address", "192.168.29.178")
            if not target.get("os") or target.get("os") == "unknown":
                target["os"] = d_doc.get("os", "windows" if "win" in str(d_doc.get("hostname", "")).lower() else "linux")
            if not target.get("hostname") or target.get("hostname") == "unknown":
                target["hostname"] = d_doc.get("hostname", "Endpoint")

    if isinstance(target.get("detected_at"), datetime):
        target["detected_at"] = target["detected_at"].isoformat()
    if isinstance(target.get("updated_at"), datetime):
        target["updated_at"] = target["updated_at"].isoformat()
    if isinstance(target.get("resolved_at"), datetime):
        target["resolved_at"] = target["resolved_at"].isoformat()

    return target

@router.post("/{anomaly_id}/resolve")
async def resolve_anomaly(anomaly_id: str, current_user: dict = Depends(get_current_user)):
    """
    Mark an active anomaly as resolved.
    """
    require_not_viewer(current_user, "resolve anomalies")
    db = get_db()
    all_cursor = db.anomalies.find({})
    items = await all_cursor.to_list(length=2000)
    target = next((item for item in items if str(item["_id"]) == anomaly_id), None)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Anomaly not found")

    is_admin = current_user.get("role") == "admin"
    did = target.get("device_id")
    if not is_admin and did:
        user_device_ids = await get_user_device_ids(current_user, db)
        if did not in user_device_ids:
            raise HTTPException(status_code=403, detail="Access denied: You do not have permission to resolve incidents for this device")

    now = datetime.now(timezone.utc)
    await db.anomalies.update_one(
        {"_id": target["_id"]},
        {"$set": {
            "status": "resolved",
            "resolved_at": now,
            "resolved_by": current_user.get("username", "admin"),
            "updated_at": now
        }}
    )
    return {"status": "ok", "message": "Incident marked as resolved"}
