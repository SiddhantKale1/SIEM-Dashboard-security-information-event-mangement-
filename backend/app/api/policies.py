from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
from datetime import datetime, timezone
import logging

from app.database.connection import get_db
from app.api.auth import get_current_user

router = APIRouter(prefix="/api/v1/policies", tags=["policies"])
logger = logging.getLogger(__name__)

# Standard Category Presets for Educational Institutions / Labs
CATEGORY_PRESETS: Dict[str, Dict[str, Any]] = {
    "youtube": {
        "title": "YouTube & Streaming",
        "description": "Restricts YouTube, Netflix, Twitch and related streaming CDNs",
        "icon": "Video",
        "domains": [
            "youtube.com",
            "www.youtube.com",
            "m.youtube.com",
            "youtu.be",
            "googlevideo.com",
            "ytimg.com",
            "youtubei.googleapis.com",
            "yt3.ggpht.com",
            "netflix.com",
            "www.netflix.com",
            "twitch.tv",
            "www.twitch.tv"
        ]
    },
    "social_media": {
        "title": "Social Media",
        "description": "Restricts Instagram, Facebook, TikTok, Reddit, and Twitter/X",
        "icon": "MessageCircle",
        "domains": [
            "instagram.com",
            "www.instagram.com",
            "facebook.com",
            "www.facebook.com",
            "fbcdn.net",
            "tiktok.com",
            "www.tiktok.com",
            "reddit.com",
            "www.reddit.com",
            "twitter.com",
            "x.com",
            "snapchat.com",
            "www.snapchat.com"
        ]
    },
    "gaming": {
        "title": "Online Gaming",
        "description": "Restricts Steam, Roblox, Epic Games, and Discord gaming platforms",
        "icon": "Gamepad2",
        "domains": [
            "steamcommunity.com",
            "steampowered.com",
            "roblox.com",
            "www.roblox.com",
            "epicgames.com",
            "discord.com",
            "discordapp.com"
        ]
    },
    "torrent": {
        "title": "Torrent & P2P",
        "description": "Restricts unauthorized BitTorrent trackers and file sharing",
        "icon": "DownloadCloud",
        "domains": [
            "thepiratebay.org",
            "1337x.to",
            "rarbg.to",
            "yts.mx",
            "torrentz2.eu",
            "limetorrents.pro"
        ]
    }
}

class PolicyUpdateRequest(BaseModel):
    categories: Dict[str, bool] = {}
    custom_domains: List[str] = []

class CustomDomainRequest(BaseModel):
    domain: str

def compute_all_blocked_domains(categories: Dict[str, bool], custom_domains: List[str]) -> List[str]:
    domains = set()
    for cat_name, is_enabled in categories.items():
        if is_enabled and cat_name in CATEGORY_PRESETS:
            for d in CATEGORY_PRESETS[cat_name]["domains"]:
                domains.add(d.strip().lower())
                
    for d in custom_domains:
        clean = d.strip().lower()
        clean = clean.replace("https://", "").replace("http://", "").split("/")[0]
        if clean:
            domains.add(clean)
            if not clean.startswith("www.") and "." in clean:
                domains.add(f"www.{clean}")
                
    return sorted(list(domains))

@router.get("")
async def get_global_policy(current_user: dict = Depends(get_current_user)):
    """Fetch global lab content blocking policies."""
    db = get_db()
    policy = await db.policies.find_one({"policy_id": "global"})
    if not policy:
        policy = {
            "policy_id": "global",
            "categories": {k: False for k in CATEGORY_PRESETS.keys()},
            "custom_domains": [],
            "blocked_domains": [],
            "updated_at": datetime.now(timezone.utc).isoformat()
        }

    return {
        "categories": policy.get("categories", {k: False for k in CATEGORY_PRESETS.keys()}),
        "custom_domains": policy.get("custom_domains", []),
        "blocked_domains": policy.get("blocked_domains", []),
        "presets": CATEGORY_PRESETS,
        "updated_at": policy.get("updated_at")
    }

@router.post("")
async def update_global_policy(
    request: PolicyUpdateRequest,
    current_user: dict = Depends(get_current_user)
):
    """Update global policies and recompute full blocked domain list."""
    db = get_db()
    now = datetime.now(timezone.utc)
    blocked_list = compute_all_blocked_domains(request.categories, request.custom_domains)

    await db.policies.update_one(
        {"policy_id": "global"},
        {"$set": {
            "policy_id": "global",
            "categories": request.categories,
            "custom_domains": request.custom_domains,
            "blocked_domains": blocked_list,
            "updated_at": now.isoformat(),
            "updated_by": current_user.get("username", "admin")
        }},
        upsert=True
    )

    logger.info(f"Admin {current_user.get('username')} updated global policies: {len(blocked_list)} domains blocked.")
    return {
        "status": "success",
        "message": f"Global policies updated ({len(blocked_list)} domains blocked)",
        "blocked_domains": blocked_list,
        "categories": request.categories,
        "custom_domains": request.custom_domains,
        "updated_at": now.isoformat()
    }

@router.post("/toggle/{category_key}")
async def toggle_category(
    category_key: str,
    current_user: dict = Depends(get_current_user)
):
    """1-Click toggle for preset category (e.g. youtube, gaming, social_media)."""
    if category_key not in CATEGORY_PRESETS:
        raise HTTPException(status_code=400, detail=f"Invalid category '{category_key}'")

    db = get_db()
    policy = await db.policies.find_one({"policy_id": "global"}) or {}
    categories = policy.get("categories", {})
    custom_domains = policy.get("custom_domains", [])

    # Toggle state
    current_state = categories.get(category_key, False)
    categories[category_key] = not current_state

    blocked_list = compute_all_blocked_domains(categories, custom_domains)
    now = datetime.now(timezone.utc)

    await db.policies.update_one(
        {"policy_id": "global"},
        {"$set": {
            "policy_id": "global",
            "categories": categories,
            "custom_domains": custom_domains,
            "blocked_domains": blocked_list,
            "updated_at": now.isoformat(),
            "updated_by": current_user.get("username", "admin")
        }},
        upsert=True
    )

    action = "enabled" if categories[category_key] else "disabled"
    logger.info(f"Admin {current_user.get('username')} {action} category {category_key}.")
    return {
        "status": "success",
        "category": category_key,
        "is_enabled": categories[category_key],
        "blocked_domains_count": len(blocked_list),
        "blocked_domains": blocked_list
    }

@router.post("/domains")
async def add_custom_domain(
    request: CustomDomainRequest,
    current_user: dict = Depends(get_current_user)
):
    """Add a custom domain to the global blocklist."""
    clean = request.domain.strip().lower()
    clean = clean.replace("https://", "").replace("http://", "").split("/")[0]
    if not clean or "." not in clean:
        raise HTTPException(status_code=400, detail="Invalid domain format")

    db = get_db()
    policy = await db.policies.find_one({"policy_id": "global"}) or {}
    categories = policy.get("categories", {})
    custom_domains = list(policy.get("custom_domains", []))

    if clean not in custom_domains:
        custom_domains.append(clean)

    blocked_list = compute_all_blocked_domains(categories, custom_domains)
    now = datetime.now(timezone.utc)

    await db.policies.update_one(
        {"policy_id": "global"},
        {"$set": {
            "policy_id": "global",
            "custom_domains": custom_domains,
            "blocked_domains": blocked_list,
            "updated_at": now.isoformat()
        }},
        upsert=True
    )

    return {
        "status": "success",
        "message": f"Added '{clean}' to blocked domains",
        "custom_domains": custom_domains,
        "blocked_domains": blocked_list
    }

@router.delete("/domains/{domain}")
async def remove_custom_domain(
    domain: str,
    current_user: dict = Depends(get_current_user)
):
    """Remove a custom domain from the global blocklist."""
    clean = domain.strip().lower()
    db = get_db()
    policy = await db.policies.find_one({"policy_id": "global"}) or {}
    categories = policy.get("categories", {})
    custom_domains = list(policy.get("custom_domains", []))

    if clean in custom_domains:
        custom_domains.remove(clean)

    blocked_list = compute_all_blocked_domains(categories, custom_domains)
    now = datetime.now(timezone.utc)

    await db.policies.update_one(
        {"policy_id": "global"},
        {"$set": {
            "policy_id": "global",
            "custom_domains": custom_domains,
            "blocked_domains": blocked_list,
            "updated_at": now.isoformat()
        }},
        upsert=True
    )

    return {
        "status": "success",
        "message": f"Removed '{clean}' from blocked domains",
        "custom_domains": custom_domains,
        "blocked_domains": blocked_list
    }

@router.get("/device/{device_id}")
async def get_device_policy(
    device_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get active policies resolved specifically for an endpoint."""
    db = get_db()
    global_policy = await db.policies.find_one({"policy_id": "global"}) or {}
    dev_policy = await db.policies.find_one({"policy_id": f"device:{device_id}"}) or {}

    global_blocked = set(global_policy.get("blocked_domains", []))
    dev_blocked = set(dev_policy.get("blocked_domains", []))
    all_blocked = sorted(list(global_blocked | dev_blocked))

    return {
        "device_id": device_id,
        "global_blocked_count": len(global_blocked),
        "device_specific_domains": list(dev_blocked),
        "total_active_blocked_domains": all_blocked
    }
