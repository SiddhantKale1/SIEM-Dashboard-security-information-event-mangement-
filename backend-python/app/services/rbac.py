from typing import Optional, List
from fastapi import HTTPException, status

async def get_user_device_ids(current_user: dict, db) -> Optional[List[str]]:
    """
    Returns None if the user is an admin (meaning all devices are accessible).
    Otherwise returns a list of device_id strings that belong to the user.
    """
    if current_user.get("role") == "admin":
        return None

    username = current_user.get("username")
    cursor = db.devices.find({})
    all_devices = await cursor.to_list(length=2000)
    device_ids = [
        d.get("device_id") for d in all_devices
        if d.get("device_id") and (d.get("owner") == username or d.get("created_by") == username)
    ]
    return device_ids

async def verify_device_access(device_id: str, current_user: dict, db) -> dict:
    """
    Verifies that the device exists and that the current user has permission to access it.
    Admins can access any device. Other users can only access devices they own.
    """
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
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    if current_user.get("role") == "admin":
        return device

    owner = device.get("owner") or device.get("created_by") or "admin"
    if owner != current_user.get("username"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You do not have permission to view or manage this endpoint"
        )
    return device

def require_not_viewer(current_user: dict, action_name: str = "perform this action"):
    """Blocks viewer/auditor accounts from executing mutations."""
    if current_user.get("role") == "viewer":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied: Auditor accounts cannot {action_name} (read-only)"
        )

def require_admin(current_user: dict, action_name: str = "perform this action"):
    """Blocks non-admin accounts from executing admin-only operations."""
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied: Only SOC Administrators can {action_name}"
        )
