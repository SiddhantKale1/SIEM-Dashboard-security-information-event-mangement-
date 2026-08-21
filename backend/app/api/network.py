from fastapi import APIRouter, Depends
from app.api.auth import get_current_user
from app.services.network_service import NetworkDiscovery
from app.database.connection import get_db

router = APIRouter(prefix="/api/v1/network", tags=["network"])

@router.get("/devices")
async def get_network_devices(scan: bool = False, current_user: dict = Depends(get_current_user)):
    db = get_db()
    
    # Get discovered devices from ARP table
    discovered = NetworkDiscovery.get_arp_table(active_scan=scan)
    
    # Update or insert discovered devices into the DB as unmanaged
    from datetime import datetime, timezone
    
    for d in discovered:
        mac = d.get("mac_address")
        if not mac:
            continue
            
        # Check if device already exists (managed or unmanaged)
        existing = await db.devices.find_one({"mac_address": mac})
        
        if existing:
            # If it exists, just update last_seen if it's unmanaged (managed agents update their own last_seen)
            if existing.get("status") in ["discovered", "unmanaged"]:
                await db.devices.update_one(
                    {"_id": existing["_id"]},
                    {"$set": {"last_seen": datetime.now(timezone.utc), "ip_address": d.get("ip_address")}}
                )
        else:
            # Insert as a new unmanaged device
            new_device = {
                "device_id": None, # Unmanaged devices don't have a secure agent ID
                "mac_address": mac,
                "ip_address": d.get("ip_address"),
                "hostname": d.get("hostname", "Unknown"),
                "os": "unknown",
                "status": "discovered",
                "last_seen": datetime.now(timezone.utc),
                "created_at": datetime.now(timezone.utc)
            }
            await db.devices.insert_one(new_device)
            
    # Now fetch ALL devices from the DB (both managed and discovered)
    cursor = db.devices.find({}).sort("last_seen", -1)
    all_devices = await cursor.to_list(length=2000)
    
    result = []
    for device in all_devices:
        device["_id"] = str(device["_id"])
        result.append(device)
        
    return result
