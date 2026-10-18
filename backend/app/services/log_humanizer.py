import re
from typing import Dict, Any, Tuple

# Restricted domains commonly monitored in educational institutions / college labs
PROHIBITED_MEDIA_DOMAINS = {
    "youtube": ("YouTube", "Video Streaming / Entertainment"),
    "googlevideo": ("YouTube", "Video Streaming (CDN)"),
    "youtu.be": ("YouTube", "Video Shortlink"),
    "ytimg": ("YouTube", "Video Thumbnail/Asset"),
    "netflix": ("Netflix", "Movie / TV Streaming"),
    "twitch": ("Twitch", "Live Gaming Stream"),
    "tiktok": ("TikTok", "Social Short Video"),
    "instagram": ("Instagram", "Social Media"),
    "facebook": ("Facebook", "Social Media"),
    "reddit": ("Reddit", "Social Forum"),
    "discord": ("Discord", "Chat / Gaming Community"),
    "steamcommunity": ("Steam", "Gaming Platform"),
    "steampowered": ("Steam", "Gaming Platform"),
    "roblox": ("Roblox", "Online Gaming"),
    "epicgames": ("Epic Games", "Gaming Platform"),
    "spotify": ("Spotify", "Music Streaming"),
    "torrent": ("BitTorrent", "P2P File Sharing"),
    "piratebay": ("The Pirate Bay", "P2P Torrent Site")
}

def detect_prohibited_content(text: str) -> Tuple[bool, str, str]:
    """
    Checks if log text or metadata indicates prohibited website access (e.g. YouTube).
    Returns: (is_prohibited, service_name, category_description)
    """
    text_lower = text.lower()
    for pattern, (name, desc) in PROHIBITED_MEDIA_DOMAINS.items():
        if pattern in text_lower:
            return True, name, desc
    return False, "", ""

def humanize_log(log: Dict[str, Any]) -> Dict[str, Any]:
    """
    Translates raw/technical security logs into plain English summaries
    that non-technical staff (e.g. college lab proctors or administrators)
    can immediately understand at a glance.
    """
    msg = str(log.get("message", "")).strip()
    raw = str(log.get("raw_log", ""))
    source = str(log.get("source", "")).lower()
    event_id = str(log.get("event_id", ""))
    hostname = log.get("hostname", "Workstation")
    combined = f"{msg} {raw} {source} {event_id}".lower()

    # Default values
    summary = msg if msg else "System background activity recorded."
    category = "⚙️ System Health"
    is_policy_violation = False
    policy_detail = None

    # 1. Prohibited Web Activity (e.g. YouTube, Gaming, Social Media)
    is_prohibited, service_name, service_desc = detect_prohibited_content(combined)
    if is_prohibited:
        is_policy_violation = True
        policy_detail = f"{service_name} ({service_desc})"
        if service_name == "YouTube":
            category = "🚫 Prohibited: YouTube"
            summary = f"Student workstation opened YouTube video streaming ({service_desc}). Prohibited in lab environment."
        else:
            category = f"⚠️ Policy: {service_name}"
            summary = f"Student workstation visited prohibited service: {service_name} ({service_desc})."

    # 2. General Website Visits (Non-prohibited)
    elif "domain:" in combined or "website / domain visited" in combined or "dns_query" in combined or "web_visit" in combined:
        domain_match = re.search(r"(?:domain:|https?://|visited website:\s*https?://)([a-zA-Z0-9\-\.]+)", msg, re.IGNORECASE)
        domain = domain_match.group(1).rstrip(".") if domain_match else "external website"
        category = "🌐 Web Activity"
        summary = f"Workstation connected to website: {domain}"

    # 3. Authentication & Logins
    elif any(k in combined for k in ("failed password", "authentication failure", "failed logon", "invalid user")) or event_id == "4625":
        user_match = re.search(r"(?:for user|for invalid user|user=)([a-zA-Z0-9_\-]+)", combined)
        target_user = user_match.group(1) if user_match else log.get("username", "account")
        category = "⚠️ Failed Login"
        summary = f"Failed login attempt: Incorrect password entered for account '{target_user}'."

    elif any(k in combined for k in ("accepted password", "successful logon", "session opened")) or event_id == "4624":
        user_match = re.search(r"(?:for user|for |user=)([a-zA-Z0-9_\-]+)", combined)
        target_user = user_match.group(1) if user_match else log.get("username", "student")
        category = "🔑 Login Success"
        summary = f"User '{target_user}' successfully logged in."

    # 4. Privilege Escalation & Admin Commands
    elif "chmod 777" in combined or "/etc/shadow" in combined or "/etc/sudoers" in combined or "sudo" in combined:
        category = "🚨 Admin Privilege"
        summary = "User requested or executed administrative (root/sudo) commands on workstation."

    # 5. Network Sockets & Port Activity
    elif source in ("kernel_socket", "netstat", "browser_network") or "conn_" in event_id.lower() or "tcp" in combined:
        category = "🌐 Network Traffic"
        proc_match = re.search(r"\(([a-zA-Z0-9_\-]+)\s+pid:", msg, re.IGNORECASE)
        proc_name = proc_match.group(1) if proc_match else "system process"
        summary = f"Active network communication stream handled by {proc_name}."

    # 6. Windows System Events
    elif log.get("os") == "windows" and "system" in source:
        category = "🖥️ Windows OS"
        summary = f"Windows system notification ({source})."

    # Enrich log dictionary
    log["friendly_summary"] = summary
    log["category"] = category
    log["is_policy_violation"] = is_policy_violation
    if policy_detail:
        log["policy_detail"] = policy_detail

    return log
