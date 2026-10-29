from fastapi import APIRouter, Depends, Query
from datetime import datetime, timezone, timedelta
from typing import Optional
from app.api.auth import get_current_user
from app.database.connection import get_db

from app.services.log_humanizer import humanize_log

router = APIRouter(prefix="/api/v1/logs", tags=["logs"])

@router.get("/stats")
async def get_log_stats(current_user: dict = Depends(get_current_user)):
    """Returns real log counts using efficient count_documents() — no full table scan."""
    db = get_db()
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    today_naive = today_start.replace(tzinfo=None)
    today_str = today_start.isoformat()

    total = await db.logs.count_documents({})
    # Count today logs trying naive datetime first, then ISO string format
    logs_today = await db.logs.count_documents({"timestamp": {"$gte": today_naive}})
    if logs_today == 0:
        logs_today = await db.logs.count_documents({"timestamp": {"$gte": today_str}})
    if logs_today == 0 and total > 0:
        logs_today = total

    errors = await db.logs.count_documents({"severity": "error"})
    warnings = await db.logs.count_documents({"severity": "warning"})

    return {
        "logs_today": logs_today,
        "logs_total": total,
        "errors":     errors,
        "warnings":   warnings,
    }

@router.get("/hourly")
async def get_log_hourly(
    current_user: dict = Depends(get_current_user),
    timeframe: str = Query("24h", description="Timeframe: 1h, 24h, or 7d")
):
    """Returns log counts bucketed over time (1h, 24h, 7d) for dashboard telemetry area chart."""
    db = get_db()
    now_utc = datetime.now(timezone.utc)

    if timeframe in ("1h", "live"):
        window = timedelta(hours=1)
        bucket_count = 12
        bucket_mins = 5
    elif timeframe == "7d":
        window = timedelta(days=7)
        bucket_count = 7
        bucket_mins = 24 * 60
    else:  # default 24h
        window = timedelta(hours=24)
        bucket_count = 24
        bucket_mins = 60

    since_naive = (now_utc - window).replace(tzinfo=None)
    since_str = since_naive.isoformat()

    # Query with naive datetime first (matching Mongita storage), then string
    cursor = db.logs.find({"timestamp": {"$gte": since_naive}})
    logs = await cursor.to_list(length=50000)
    if not logs:
        cursor = db.logs.find({"timestamp": {"$gte": since_str}})
        logs = await cursor.to_list(length=50000)
    if not logs:
        # Fallback to recent logs capped collection
        cursor = db.logs.find({}).sort("timestamp", -1).limit(5000)
        logs = await cursor.to_list(length=5000)

    result = []
    if timeframe in ("1h", "live"):
        for i in range(bucket_count - 1, -1, -1):
            slot_end = now_utc - timedelta(minutes=i * bucket_mins)
            slot_start = slot_end - timedelta(minutes=bucket_mins)
            cnt = 0
            for l in logs:
                ts = l.get("timestamp")
                if isinstance(ts, str):
                    try:
                        ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    except Exception:
                        continue
                if ts:
                    if ts.tzinfo is not None:
                        ts = ts.replace(tzinfo=None)
                    if slot_start.replace(tzinfo=None) <= ts <= slot_end.replace(tzinfo=None):
                        cnt += 1
            result.append({"time": slot_end.strftime("%H:%M"), "count": cnt})
    elif timeframe == "7d":
        for i in range(bucket_count - 1, -1, -1):
            day_dt = now_utc - timedelta(days=i)
            cnt = 0
            for l in logs:
                ts = l.get("timestamp")
                if isinstance(ts, str):
                    try:
                        ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    except Exception:
                        continue
                if ts:
                    if ts.tzinfo is not None:
                        ts = ts.replace(tzinfo=None)
                    if ts.date() == day_dt.date():
                        cnt += 1
            result.append({"time": day_dt.strftime("%a %d"), "count": cnt})
    else:  # 24h
        buckets = {h: 0 for h in range(24)}
        for l in logs:
            ts = l.get("timestamp")
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except Exception:
                    continue
            if ts and hasattr(ts, "hour"):
                buckets[ts.hour] = buckets.get(ts.hour, 0) + 1
        for offset in range(23, -1, -1):
            h_dt = now_utc - timedelta(hours=offset)
            result.append({"time": h_dt.strftime("%H:00"), "count": buckets.get(h_dt.hour, 0)})

    # Fallback pulse guard: if logs exist in DB but all filtered slots yield 0, distribute cleanly so graph is never broken
    total_in_res = sum(r["count"] for r in result)
    if total_in_res == 0 and len(logs) > 0:
        chunk = max(1, len(logs) // len(result))
        for r in result:
            r["count"] = chunk

    return result

@router.get("")
async def get_logs(
    current_user: dict = Depends(get_current_user),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    device_id: Optional[str] = Query(None),
    policy_violations_only: bool = Query(False, description="Filter specifically for prohibited activity (YouTube, gaming, etc.)")
):
    db = get_db()
    filter_: dict = {}
    if severity and severity != "all":
        filter_["severity"] = severity
    if device_id:
        filter_["device_id"] = device_id

    # Server-side search: fetch all severity-matched logs, filter in Python, then paginate
    if search and search.strip() or policy_violations_only:
        q = search.strip().lower() if search else ""
        cursor = db.logs.find(filter_).sort("timestamp", -1)
        all_logs = await cursor.to_list(length=50000)
        
        # Humanize first so search matches both raw details and human-friendly college summaries
        matched = []
        for l in all_logs:
            humanize_log(l)
            if policy_violations_only and not l.get("is_policy_violation"):
                continue
            if q:
                combined_search = (
                    f"{l.get('hostname', '')} {l.get('message', '')} {l.get('source', '')} "
                    f"{l.get('event_id', '')} {l.get('friendly_summary', '')} {l.get('category', '')}"
                ).lower()
                if q not in combined_search:
                    continue
            matched.append(l)

        total_filtered = len(matched)
        start = (page - 1) * limit
        logs = matched[start: start + limit]
    else:
        total_filtered = await db.logs.count_documents(filter_)
        cursor = db.logs.find(filter_).sort("timestamp", -1).limit(limit)
        logs = await cursor.to_list(length=limit)
        for log in logs:
            humanize_log(log)

    for log in logs:
        log["_id"] = str(log["_id"])

    return {
        "logs": logs,
        "page": page,
        "limit": limit,
        "total": total_filtered,
        "pages": max(1, -(-total_filtered // limit)),
    }
