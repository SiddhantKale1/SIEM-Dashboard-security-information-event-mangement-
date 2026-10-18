from fastapi import APIRouter, Depends, Query
from datetime import datetime, timezone, timedelta
from typing import Optional
from app.api.auth import get_current_user
from app.database.connection import get_db

router = APIRouter(prefix="/api/v1/logs", tags=["logs"])

@router.get("/stats")
async def get_log_stats(current_user: dict = Depends(get_current_user)):
    """Returns real log counts using efficient count_documents() — no full table scan."""
    db = get_db()
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    today_str = today_start.isoformat()

    total      = await db.logs.count_documents({})
    logs_today = await db.logs.count_documents({"timestamp": {"$gte": today_str}})
    errors     = await db.logs.count_documents({"severity": "error"})
    warnings   = await db.logs.count_documents({"severity": "warning"})

    return {
        "logs_today": logs_today,
        "logs_total": total,
        "errors":     errors,
        "warnings":   warnings,
    }

@router.get("/hourly")
async def get_log_hourly(current_user: dict = Depends(get_current_user)):
    """Returns per-hour log counts for the last 24 hours for the dashboard chart."""
    db = get_db()
    now = datetime.now(timezone.utc)

    # Fetch the last 24h of logs once, then bucket in Python (efficient for MVP scale)
    since = now - timedelta(hours=24)
    since_str = since.isoformat()
    cursor = db.logs.find({"timestamp": {"$gte": since_str}})
    logs = await cursor.to_list(length=50000)

    # Build 24 hourly buckets
    buckets: dict[int, int] = {h: 0 for h in range(24)}
    for log in logs:
        ts = log.get("timestamp")
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception:
                continue
        if ts and hasattr(ts, "hour"):
            buckets[ts.hour] = buckets.get(ts.hour, 0) + 1

    # Return ordered from oldest hour to now
    result = []
    for offset in range(23, -1, -1):
        hour_dt = now - timedelta(hours=offset)
        result.append({
            "time": hour_dt.strftime("%H:00"),
            "count": buckets.get(hour_dt.hour, 0),
        })

    return result

@router.get("")
async def get_logs(
    current_user: dict = Depends(get_current_user),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    device_id: Optional[str] = Query(None),
):
    db = get_db()
    filter_: dict = {}
    if severity and severity != "all":
        filter_["severity"] = severity
    if device_id:
        filter_["device_id"] = device_id

    # Server-side search: fetch all severity-matched logs, filter in Python, then paginate
    if search and search.strip():
        q = search.strip().lower()
        cursor = db.logs.find(filter_).sort("timestamp", -1)
        all_logs = await cursor.to_list(length=50000)
        matched = [
            l for l in all_logs
            if q in str(l.get("hostname", "")).lower()
            or q in str(l.get("message", "")).lower()
            or q in str(l.get("source", "")).lower()
            or q in str(l.get("event_id", "")).lower()
        ]
        total_filtered = len(matched)
        start = (page - 1) * limit
        logs = matched[start: start + limit]
    else:
        total_filtered = await db.logs.count_documents(filter_)
        cursor = db.logs.find(filter_).sort("timestamp", -1).limit(limit)
        logs = await cursor.to_list(length=limit)

    for log in logs:
        log["_id"] = str(log["_id"])

    return {
        "logs": logs,
        "page": page,
        "limit": limit,
        "total": total_filtered,
        "pages": max(1, -(-total_filtered // limit)),
    }
