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
# SIEM Real-Time Endpoint Agent — Boot-Persistent Installer (Linux)
# ====================================================================

echo "[*] Initializing SIEM Agent Installation..."

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

# Install dependencies if missing
if ! command -v python3 &> /dev/null; then
    echo "[*] Installing Python 3..."
    if command -v apt-get &> /dev/null; then
        apt-get update -qq && apt-get install -y -qq python3 python3-pip python3-psutil
    elif command -v dnf &> /dev/null; then
        dnf install -y -q python3 python3-pip python3-psutil
    fi
fi

# Ensure psutil is installed (fallback to native if pip fails)
python3 -c "import psutil" 2>/dev/null || pip3 install psutil 2>/dev/null || true

# Prepare directories
AGENT_DIR="/opt/siem-agent"
CONFIG_DIR="/etc/siem-agent"
mkdir -p "$AGENT_DIR" "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

# Download the universal agent code
echo "[*] Downloading SIEM Universal Agent..."
if ! curl -sSLf "$SERVER_URL/api/v1/enrollment/agent.py" -o "$AGENT_DIR/siem_agent.py"; then
    echo "[!] ERROR: Failed to download SIEM Universal Agent from $SERVER_URL" >&2
    exit 1
fi
chmod 755 "$AGENT_DIR/siem_agent.py"

# Write initial bootstrapping config
cat <<EOF > "$CONFIG_DIR/agent_config.json"
{
    "server_url": "$SERVER_URL",
    "enrollment_token": "$ENROLLMENT_TOKEN"
}
EOF
chmod 600 "$CONFIG_DIR/agent_config.json"

# Create boot-persistent systemd unit
echo "[*] Registering systemd background service (siem-agent.service)..."
cat <<EOF > /etc/systemd/system/siem-agent.service
[Unit]
Description=SIEM AI-Driven Real-Time Security Monitoring Agent
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $AGENT_DIR/siem_agent.py
Restart=always
RestartSec=10
WorkingDirectory=$AGENT_DIR
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable siem-agent.service
systemctl restart siem-agent.service

echo "[+] SUCCESS: SIEM Agent is permanently installed and active!"
echo "[+] Service will automatically start on every system boot."
echo "[+] Verify status with: systemctl status siem-agent"
`, serverURL, token)
}

func GenerateWindowsInstaller(serverURL, token string) string {
	raw := fmt.Sprintf(`# ====================================================================
# SIEM Real-Time Endpoint Agent — Boot-Persistent Installer (Windows)
# ====================================================================

$ServerUrl = "%s"
$Token = "%s"

# Ensure Administrator privileges so hosts file and scheduled task can be written
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[*] Requesting Administrator elevation to configure system hosts file & security task..." -ForegroundColor Yellow
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -Command §"irm '$ServerUrl/api/v1/enrollment/install.ps1?token=$Token&server=$ServerUrl' | iex§""
    exit 0
}

Write-Host "[*] Initializing SIEM Windows Permanent Agent Installer..." -ForegroundColor Cyan

# Test python availability
$PythonCmd = (Get-Command python, py, python3 -ErrorAction SilentlyContinue | Select-Object -First 1).Source
if (-not $PythonCmd) {
    Write-Host "[!] Warning: Python executable not found in PATH. Please ensure Python 3 is installed." -ForegroundColor Yellow
    $PythonCmd = "python"
} else {
    Write-Host "[*] Found Python: $PythonCmd" -ForegroundColor Green
    & $PythonCmd -m pip install psutil -q 2>$null
}

$InstallDir = "$env:ProgramData\SIEMAgent"
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}

# Write initial config
$Config = @{
    server_url = $ServerUrl
    enrollment_token = $Token
} | ConvertTo-Json
$Config | Set-Content -Path "$InstallDir\agent_config.json"

# Download universal agent
Write-Host "[*] Fetching SIEM Agent code from $ServerUrl..." -ForegroundColor Cyan
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
    Invoke-WebRequest -Uri "$ServerUrl/api/v1/enrollment/agent.py" -OutFile "$InstallDir\siem_agent.py" -UseBasicParsing -ErrorAction Stop
} catch {
    Write-Host "[!] ERROR: Failed to download SIEM Agent from $ServerUrl" -ForegroundColor Red
    Write-Host "[!] Details: $_" -ForegroundColor Red
    exit 1
}

$agentHeader = Get-Content -Path "$InstallDir\siem_agent.py" -TotalCount 5 -ErrorAction SilentlyContinue | Out-String
if ($agentHeader -match '"detail":' -or (Get-Item "$InstallDir\siem_agent.py").Length -lt 200) {
    Write-Host "[!] ERROR: Downloaded agent file is invalid or returned an API error:" -ForegroundColor Red
    Write-Host $agentHeader -ForegroundColor Yellow
    exit 1
}

# Create launcher vbs script for silent headless execution (no window popups)
$VbsLauncher = @"
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run """$PythonCmd"" ""$InstallDir\siem_agent.py""", 0, False
"@
$VbsLauncher | Set-Content -Path "$InstallDir\run_hidden.vbs"

# Install Windows Task Scheduler job running AtStartup with Highest Privileges
Write-Host "[*] Registering persistent Windows Boot Task 'SIEM-Agent-Persistent'..." -ForegroundColor Cyan
try {
    $Action = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "§"$InstallDir\run_hidden.vbs§""
    $Trigger = New-ScheduledTaskTrigger -AtStartup
    $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

    Unregister-ScheduledTask -TaskName "SIEM-Agent-Persistent" -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName "SIEM-Agent-Persistent" -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -ErrorAction Stop | Out-Null
    Start-ScheduledTask -TaskName "SIEM-Agent-Persistent"
    Write-Host "[+] SUCCESS: Scheduled Task 'SIEM-Agent-Persistent' created and started!" -ForegroundColor Green
} catch {
    Write-Host "[*] Running as background process directly..." -ForegroundColor Cyan
    Start-Process wscript.exe -ArgumentList "§"$InstallDir\run_hidden.vbs§""
}

Write-Host "[+] SUCCESS: SIEM Windows Agent is permanently installed!" -ForegroundColor Green
Write-Host "[+] It is running headless in the background and will start on every system boot." -ForegroundColor Green
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
