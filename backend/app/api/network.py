from fastapi import APIRouter, Depends, Query, HTTPException, status
from datetime import datetime, timezone, timedelta
from typing import Optional, List
import logging

from app.api.auth import get_current_user
from app.services.network_service import NetworkManager
from app.database.connection import get_db

router = APIRouter(prefix="/api/v1/network", tags=["network"])
logger = logging.getLogger(__name__)

@router.get("/traffic")
async def get_network_traffic(current_user: dict = Depends(get_current_user)):
    """
    Returns real-time network traffic telemetry:
    - Active Subnet & Gateway
    - Active Connected Nodes count
    - Aggregate RX/TX throughput rate
    - Historical connection session count
    """
    db = get_db()
    net_info = NetworkManager.get_local_network_info()
    current_subnet = net_info["subnet"]
    now = datetime.now(timezone.utc)
    recent_cutoff = now - timedelta(seconds=90)

    # Find devices whose last_seen is within 90s AND whose IP is on the current subnet
    all_devices_cursor = db.devices.find({})
    all_devices = await all_devices_cursor.to_list(length=2000)

    active_count = 0
    total_tx = 0
    total_rx = 0

    for d in all_devices:
        last_seen = d.get("last_seen")
        ip = d.get("ip_address", "")
        is_recent = False
        if isinstance(last_seen, datetime):
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)
            is_recent = (last_seen > recent_cutoff)
        elif isinstance(last_seen, str):
            try:
                dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
                is_recent = (dt > recent_cutoff)
            except Exception:
                pass

        if is_recent and NetworkManager.is_ip_in_subnet(ip, current_subnet) and d.get("status") != "isolated":
            active_count += 1

    # Get latest metrics sum for throughput estimate
    recent_metrics_cursor = db.metrics.find({}).sort("timestamp", -1).limit(50)
    recent_metrics = await recent_metrics_cursor.to_list(length=50)
    for m in recent_metrics:
        total_tx += m.get("network_tx_bytes", 0)
        total_rx += m.get("network_rx_bytes", 0)

    # Total connection history sessions
    history_count = await db.connection_history.count_documents({})

    return {
        "network": net_info,
        "active_devices_count": active_count,
        "total_managed_devices": len(all_devices),
        "history_sessions_count": history_count,
        "aggregate_tx_bytes": total_tx,
        "aggregate_rx_bytes": total_rx,
        "status": "HEALTHY"
    }

@router.get("/active")
async def get_active_network_devices(
    scan: bool = Query(False, description="Trigger active ARP scan"),
    current_user: dict = Depends(get_current_user)
):
    """
    Returns only the systems currently active on the CURRENT network.
    Automatically filters out devices from previous or disconnected networks.
    """
    db = get_db()
    net_info = NetworkManager.get_local_network_info()
    current_subnet = net_info["subnet"]
    now = datetime.now(timezone.utc)
    recent_cutoff = now - timedelta(seconds=90)

    # Optional ARP scan to discover unmanaged devices on current subnet
    if scan:
        arp_nodes = NetworkManager.get_arp_devices(active_scan=True)
        for node in arp_nodes:
            mac = node["mac_address"]
            existing = await db.devices.find_one({"mac_address": mac})
            if not existing:
                await db.devices.insert_one({
                    "device_id": None,
                    "mac_address": mac,
                    "ip_address": node["ip_address"],
                    "hostname": node["hostname"],
                    "os": "unknown",
                    "status": "discovered",
                    "subnet": current_subnet,
                    "last_seen": now,
                    "created_at": now
                })

    # Fetch devices and filter strictly for the current network
    cursor = db.devices.find({})
    devices = await cursor.to_list(length=2000)

    active_list = []
    for d in devices:
        ip = d.get("ip_address", "")
        last_seen = d.get("last_seen")
        is_online = False

        if isinstance(last_seen, datetime):
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)
            is_online = (last_seen > recent_cutoff)
        elif isinstance(last_seen, str):
            try:
                dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
                is_online = (dt > recent_cutoff)
            except Exception:
                pass

        # Only present if in current subnet AND either recent or explicitly online/isolated
        in_subnet = NetworkManager.is_ip_in_subnet(ip, current_subnet)

        if in_subnet:
            d["_id"] = str(d["_id"])
            if isinstance(d.get("last_seen"), datetime):
                d["last_seen"] = d["last_seen"].isoformat()
            if isinstance(d.get("created_at"), datetime):
                d["created_at"] = d["created_at"].isoformat()
            if isinstance(d.get("enrolled_at"), datetime):
                d["enrolled_at"] = d["enrolled_at"].isoformat()

            # Dynamic current state
            if d.get("status") == "isolated":
                d["current_network_state"] = "isolated"
            elif is_online:
                d["current_network_state"] = "online"
            else:
                d["current_network_state"] = "idle"

            d["subnet"] = current_subnet
            active_list.append(d)

    return {
        "network": net_info,
        "count": len(active_list),
        "devices": active_list
    }

@router.get("/history")
async def get_connection_history(
    device_id: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    current_user: dict = Depends(get_current_user)
):
    """
    Dedicated Connection History tab:
    Chronological audit of all past and current endpoint connections,
    network switches, disconnect timestamps, and transmitted volume.
    """
    db = get_db()
    query: dict = {}
    if device_id:
        query["device_id"] = device_id

    cursor = db.connection_history.find(query).sort("connected_at", -1).limit(limit)
    records = await cursor.to_list(length=limit)

    for r in records:
        r["_id"] = str(r["_id"])
        if isinstance(r.get("connected_at"), datetime):
            r["connected_at"] = r["connected_at"].isoformat()
        if isinstance(r.get("last_active_at"), datetime):
            r["last_active_at"] = r["last_active_at"].isoformat()
        if isinstance(r.get("disconnected_at"), datetime):
            r["disconnected_at"] = r["disconnected_at"].isoformat()

    return {
        "total": len(records),
        "history": records
    }

@router.get("/devices")
async def get_legacy_network_devices(scan: bool = False, current_user: dict = Depends(get_current_user)):
    """Legacy compatibility endpoint pointing to active devices."""
    res = await get_active_network_devices(scan=scan, current_user=current_user)
    return res["devices"]
