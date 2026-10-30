package scripts

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func GenerateLinuxInstaller(serverURL, token string) string {
	return fmt.Sprintf(`#!/usr/bin/env bash
set -e

# ====================================================================
# Sentinel SIEM Native Go Endpoint Agent — Boot-Persistent Installer (Linux)
# ====================================================================

echo "[*] Initializing Sentinel Native Go Agent Installation..."

SERVER_URL="%s"
ENROLLMENT_TOKEN="%s"

# Check arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --server) SERVER_URL="$2"; shift ;;
        --token) ENROLLMENT_TOKEN="$2"; shift ;;
    esac
    shift
done

if [ -z "$ENROLLMENT_TOKEN" ]; then
    echo "[-] Error: ENROLLMENT_TOKEN is required. Pass --token <TOKEN>"
    exit 1
fi

echo "[*] Target SIEM Server: $SERVER_URL"

# Prepare directories
AGENT_DIR="/opt/sentinel-agent"
CONFIG_DIR="/etc/sentinel-agent"
mkdir -p "$AGENT_DIR" "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

# Download the standalone Go binary agent (Zero runtime dependencies)
echo "[*] Downloading Sentinel Native Go Binary Agent..."
if ! curl -sSLf "$SERVER_URL/api/v1/enrollment/agent.bin" -o "$AGENT_DIR/sentinel-agent"; then
    echo "[!] ERROR: Failed to download Sentinel Go agent binary from $SERVER_URL" >&2
    exit 1
fi
chmod 755 "$AGENT_DIR/sentinel-agent"

# Write initial bootstrapping config
cat <<EOF > "$CONFIG_DIR/agent_config.json"
{
    "server_url": "$SERVER_URL",
    "enrollment_token": "$ENROLLMENT_TOKEN"
}
EOF
chmod 600 "$CONFIG_DIR/agent_config.json"

# Create boot-persistent systemd unit
echo "[*] Registering systemd background service (sentinel-agent.service)..."
cat <<EOF > /etc/systemd/system/sentinel-agent.service
[Unit]
Description=Sentinel SIEM Native Go Real-Time Security Agent
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$AGENT_DIR/sentinel-agent -server "$SERVER_URL" -token "$ENROLLMENT_TOKEN" -config "$CONFIG_DIR/agent_config.json"
Restart=always
RestartSec=5
WorkingDirectory=$AGENT_DIR

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sentinel-agent.service
systemctl restart sentinel-agent.service

echo "[+] SUCCESS: Sentinel Native Go Agent is permanently installed and active!"
echo "[+] Service will automatically start on every system boot."
echo "[+] Verify status with: systemctl status sentinel-agent"
`, serverURL, token)
}

func GenerateWindowsInstaller(serverURL, token string) string {
	raw := fmt.Sprintf(`# ====================================================================
# Sentinel SIEM Native Go Endpoint Agent — Boot-Persistent Installer (Windows)
# ====================================================================

$ServerUrl = "%s"
$Token = "%s"

# Ensure Administrator privileges so scheduled task and firewall can be managed
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[*] Requesting Administrator elevation for Sentinel Go Agent setup..." -ForegroundColor Yellow
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -Command §"irm '$ServerUrl/api/v1/enrollment/install.ps1?token=$Token&server=$ServerUrl' | iex§""
    exit 0
}

Write-Host "[*] Initializing Sentinel Native Go Agent Installer..." -ForegroundColor Cyan

$InstallDir = "$env:ProgramData\SentinelAgent"
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}

# Stop any older or running instances
Stop-Process -Name "sentinel-agent" -Force -ErrorAction SilentlyContinue

# Download native Go binary (Zero Python requirement)
Write-Host "[*] Downloading native Go agent binary from $ServerUrl..." -ForegroundColor Cyan
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
    Invoke-WebRequest -Uri "$ServerUrl/api/v1/enrollment/agent.exe" -OutFile "$InstallDir\sentinel-agent.exe" -UseBasicParsing -ErrorAction Stop
} catch {
    Write-Host "[!] ERROR: Failed to download Sentinel Go agent: $_" -ForegroundColor Red
    exit 1
}

# Write initial config
$Config = @{
    server_url = $ServerUrl
    enrollment_token = $Token
} | ConvertTo-Json
$Config | Set-Content -Path "$InstallDir\agent_config.json"

# Register persistent Windows Scheduled Task running as SYSTEM at startup
Write-Host "[*] Registering persistent Windows Boot Task 'Sentinel-Agent'..." -ForegroundColor Cyan
try {
    $Action = New-ScheduledTaskAction -Execute "$InstallDir\sentinel-agent.exe" -Argument "-server §"$ServerUrl§" -token §"$Token§" -config §"$InstallDir\agent_config.json§""
    $Trigger = New-ScheduledTaskTrigger -AtStartup
    $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

    Unregister-ScheduledTask -TaskName "Sentinel-Agent" -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName "SIEM-Agent-Persistent" -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName "Sentinel-Agent" -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -ErrorAction Stop | Out-Null
    Start-ScheduledTask -TaskName "Sentinel-Agent"
    Write-Host "[+] SUCCESS: Scheduled Task 'Sentinel-Agent' registered and running!" -ForegroundColor Green
} catch {
    Write-Host "[*] Spawning background agent process directly..." -ForegroundColor Cyan
    Start-Process -FilePath "$InstallDir\sentinel-agent.exe" -ArgumentList "-server §"$ServerUrl§" -token §"$Token§" -config §"$InstallDir\agent_config.json§"" -WindowStyle Hidden
}

Write-Host "[+] SUCCESS: Sentinel Native Go Agent is permanently installed and active!" -ForegroundColor Green
Write-Host "[+] Running headless with zero runtime dependencies (no Python required)." -ForegroundColor Green
Write-Host "[+] You may safely close this PowerShell window." -ForegroundColor Green
`, serverURL, token)

	return strings.ReplaceAll(raw, "§", "`")
}

func ReadUniversalAgentSource() (string, error) {
	candidates := []string{
		"agents/universal/siem_agent.py",
		"../agents/universal/siem_agent.py",
		"../../agents/universal/siem_agent.py",
		"/home/sidd/SIEM-Dashboard-security-information-event-mangement-/agents/universal/siem_agent.py",
	}

	for _, path := range candidates {
		if abs, err := filepath.Abs(path); err == nil {
			if data, err := os.ReadFile(abs); err == nil {
				return string(data), nil
			}
		}
	}
	return "", fmt.Errorf("siem_agent.py not found")
}
