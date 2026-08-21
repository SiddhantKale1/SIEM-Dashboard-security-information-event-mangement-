from fastapi import APIRouter, Depends
from datetime import datetime, timezone
from app.api.auth import get_current_user
from app.database.connection import get_db

router = APIRouter(prefix="/api/v1/logs", tags=["logs"])

@router.get("/stats")
async def get_log_stats(current_user: dict = Depends(get_current_user)):
    """Returns real log counts: total and ingested today."""
    db = get_db()

    # Start of today in UTC
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    all_logs = await db.logs.find({}).to_list(length=100000)
    total = len(all_logs)

    # Count logs with timestamp >= today_start
    today_count = 0
    for log in all_logs:
        ts = log.get("timestamp") or log.get("ingested_at")
        if ts:
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except Exception:
                    continue
            if hasattr(ts, "tzinfo") and ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts >= today_start:
                today_count += 1

    return {
        "logs_today": today_count,
        "logs_total": total,
    }

@router.get("")
async def get_logs(current_user: dict = Depends(get_current_user)):
    db = get_db()
    # Fetch latest 100 logs
    cursor = db.logs.find({}).sort("timestamp", -1).limit(100)
    logs = await cursor.to_list(length=100)
    
    for log in logs:
        log["_id"] = str(log["_id"])
        
    return logs
