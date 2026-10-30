import re
from typing import Dict, Any

def humanize_log(log: Dict[str, Any]) -> Dict[str, Any]:
    """
    Translates raw/technical security logs into clear, actionable summaries
    for security analysts to quickly assess endpoint events.
    """
    msg = str(log.get("message", "")).strip()
    raw = str(log.get("raw_log", ""))
    source = str(log.get("source", "")).lower()
    event_id = str(log.get("event_id", ""))
    combined = f"{msg} {raw} {source} {event_id}".lower()

    # Default values
    summary = msg if msg else "System background activity recorded."
    category = "System Health"

    # 1. Authentication & Logins
    if any(k in combined for k in ("failed password", "authentication failure", "failed logon", "invalid user")) or event_id == "4625":
        user_match = re.search(r"(?:for user|for invalid user|user=)([a-zA-Z0-9_\-]+)", combined)
        target_user = user_match.group(1) if user_match else log.get("username", "account")
        category = "Failed Login"
        summary = f"Failed authentication: Incorrect credentials supplied for account '{target_user}'."

    elif any(k in combined for k in ("accepted password", "successful logon", "session opened")) or event_id == "4624":
        user_match = re.search(r"(?:for user|for |user=)([a-zA-Z0-9_\-]+)", combined)
        target_user = user_match.group(1) if user_match else log.get("username", "user")
        category = "Login Success"
        summary = f"Session initiated: User '{target_user}' logged in."

    # 2. Privilege Escalation & Admin Commands
    elif "chmod 777" in combined or "/etc/shadow" in combined or "/etc/sudoers" in combined or "sudo" in combined:
        category = "Admin Privilege"
        summary = "Administrative privilege invocation (root/sudo) detected on endpoint."

    # 3. Network Sockets & Port Activity
    elif source in ("kernel_socket", "netstat", "browser_network") or "conn_" in event_id.lower() or "tcp" in combined:
        category = "Network Traffic"
        proc_match = re.search(r"\(([a-zA-Z0-9_\-]+)\s+pid:", msg, re.IGNORECASE)
        proc_name = proc_match.group(1) if proc_match else "process"
        summary = f"Active network communication socket maintained by {proc_name}."

    # 4. Windows System Events
    elif log.get("os") == "windows" and "system" in source:
        category = "Windows OS"
        summary = f"Windows system event logged ({source})."

    # Enrich log dictionary
    log["friendly_summary"] = summary
    log["category"] = category
    log["is_policy_violation"] = False

    return log
