from fastapi import APIRouter, Depends
from app.api.auth import get_current_user
from app.database.connection import get_db

router = APIRouter(prefix="/api/v1/logs", tags=["logs"])

@router.get("")
async def get_logs(current_user: dict = Depends(get_current_user)):
    db = get_db()
    # Fetch latest 100 logs
    cursor = db.logs.find({}).sort("timestamp", -1).limit(100)
    logs = await cursor.to_list(length=100)
    
    for log in logs:
        log["_id"] = str(log["_id"])
        
    return logs
