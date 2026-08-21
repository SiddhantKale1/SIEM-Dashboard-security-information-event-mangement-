from fastapi import APIRouter, Depends, HTTPException
from app.api.auth import get_current_user
from app.database.connection import get_db

router = APIRouter(prefix="/api/v1/devices", tags=["devices"])

@router.get("/{device_id}")
async def get_device(device_id: str, current_user: dict = Depends(get_current_user)):
    db = get_db()
    device = await db.devices.find_one({"device_id": device_id})
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
        
    device["_id"] = str(device["_id"])
    return device

@router.get("/{device_id}/metrics")
async def get_device_metrics(device_id: str, current_user: dict = Depends(get_current_user)):
    db = get_db()
    # Fetch latest 20 metrics sorted by timestamp descending
    cursor = db.metrics.find({"device_id": device_id}).sort("timestamp", -1).limit(20)
    metrics = await cursor.to_list(length=20)
    
    # Reverse to return them in chronological order for the chart
    metrics.reverse()
    
    for m in metrics:
        m["_id"] = str(m["_id"])
        
    return metrics
