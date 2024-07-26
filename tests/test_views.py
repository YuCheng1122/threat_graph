import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.utils.auth import AuthManager, UserInDB
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os

load_dotenv()

client = TestClient(app)

# Helper function to create access token
def create_test_access_token(username: str):
    access_token_expires = timedelta(minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30)))
    return AuthManager.create_access_token(
        data={"sub": username}, expires_delta=access_token_expires
    )

def test_get_hourly_graphs(monkeypatch):
    def mock_get_nodes_by_time_range(start_time, end_time):
        return [
            {
                "id": "1",
                "timestamp": datetime.now(),
                "ip": "192.168.123.89",
                "node_type": "Internal",
                "risk_score": 71,
                "cti_intelligence": '{"threat": "DDoS"}',
                "host_event_log": '{"event": "connection"}',
                "host_info": '{"os": "macOS"}'
            }
        ]

    def mock_get_edges_by_time_range(start_time, end_time):
        return [
            {
                "id": "1",
                "timestamp": datetime.now(),
                "src_node_id": "1",
                "dest_node_id": "2",
                "src_node_ip": "192.168.123.89",
                "dest_node_ip": "192.168.123.90",
                "src_node_port": 3389,
                "dest_node_port": 443,
                "alert_timestamp": datetime.now(),
                "protocols": "SSH",
                "alert_type": "DNS Exfiltration",
                "alert_severity": 4,
                "alert_signature": "Data Exfiltration",
                "total_bytes": 2887,
                "duration": 16,
                "total_alerts": 9
            }
        ]

    monkeypatch.setattr("app.models.Node.get_nodes_by_time_range", mock_get_nodes_by_time_range)
    monkeypatch.setattr("app.models.Edge.get_edges_by_time_range", mock_get_edges_by_time_range)

    access_token = create_test_access_token(os.getenv("USER_EMAIL"))

    start_time = (datetime.now() - timedelta(hours=1)).isoformat()
    end_time = datetime.now().isoformat()

    response = client.get(
        f"/api/get_hourly_graphs?start_time={start_time}&end_time={end_time}",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200
    assert "nodes" in response.json()
    assert "edges" in response.json()

def test_create_node(monkeypatch):
    def mock_save(node_data):
        return True

    monkeypatch.setattr("app.models.Node.save", mock_save)

    node_data = {
        "timestamp": datetime.now().isoformat(),
        "ip": "192.168.123.89",
        "node_type": "Internal",
        "risk_score": 71,
        "cti_intelligence": '{"threat": "DDoS"}',
        "host_event_log": '{"event": "connection"}',
        "host_info": '{"os": "macOS"}'
    }

    access_token = create_test_access_token(os.getenv("USER_EMAIL"))

    response = client.post("/api/node/", json=node_data, headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 200
    assert response.json() == {"status": "node created"}

def test_create_edge(monkeypatch):
    def mock_save(edge_data):
        return True

    monkeypatch.setattr("app.models.Edge.save", mock_save)

    edge_data = {
        "timestamp": datetime.now().isoformat(),
        "src_node_id": "1",
        "dest_node_id": "2",
        "src_node_ip": "192.168.123.89",
        "dest_node_ip": "192.168.123.90",
        "src_node_port": 3389,
        "dest_node_port": 443,
        "alert_timestamp": datetime.now().isoformat(),
        "protocols": "SSH",
        "alert_type": "DNS Exfiltration",
        "alert_severity": 4,
        "alert_signature": "Data Exfiltration",
        "total_bytes": 2887,
        "duration": 16,
        "total_alerts": 9
    }

    access_token = create_test_access_token(os.getenv("USER_EMAIL"))

    response = client.post("/api/edge/", json=edge_data, headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 200
    assert response.json() == {"status": "edge created"}

def test_get_all_nodes(monkeypatch):
    def mock_get_all_nodes():
        return [
            {
                "id": "1",
                "timestamp": datetime.now(),
                "ip": "192.168.123.89",
                "node_type": "Internal",
                "risk_score": 71,
                "cti_intelligence": '{"threat": "DDoS"}',
                "host_event_log": '{"event": "connection"}',
                "host_info": '{"os": "macOS"}'
            }
        ]

    monkeypatch.setattr("app.models.Node.get_all_nodes", mock_get_all_nodes)

    access_token = create_test_access_token(os.getenv("USER_EMAIL"))

    response = client.get("/api/nodes", headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 200
    assert isinstance(response.json(), list)
    assert len(response.json()) > 0

def test_get_all_edges(monkeypatch):
    def mock_get_all_edges():
        return [
            {
                "id": "1",
                "timestamp": datetime.now(),
                "src_node_id": "1",
                "dest_node_id": "2",
                "src_node_ip": "192.168.123.89",
                "dest_node_ip": "192.168.123.90",
                "src_node_port": 3389,
                "dest_node_port": 443,
                "alert_timestamp": datetime.now(),
                "protocols": "SSH",
                "alert_type": "DNS Exfiltration",
                "alert_severity": 4,
                "alert_signature": "Data Exfiltration",
                "total_bytes": 2887,
                "duration": 16,
                "total_alerts": 9
            }
        ]

    monkeypatch.setattr("app.models.Edge.get_all_edges", mock_get_all_edges)

    access_token = create_test_access_token(os.getenv("USER_EMAIL"))

    response = client.get("/api/edges", headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 200
    assert isinstance(response.json(), list)
    assert len(response.json()) > 0
