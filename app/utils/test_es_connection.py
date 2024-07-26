import requests
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)

# Define the base URL of your FastAPI application
BASE_URL = "http://localhost:8000"

# Sample node data
node_data = {
    "id": "142.251.42.246",
    "attributes": {
        "abnormal_score": None,
        "symbol": None,
        "ip_type": "external",
        "os": "No info",
        "abnormal_count": "No info",
        "id_node": "54adef7f2d5c",
        "timestamp": "2024-07-22T06:04:53.613000"
    }
}

# Sample edge data
edge_data = {
    "source": "192.168.65.137",
    "target": "192.168.65.2",
    "attributes": {
        "timestamp": "2024-07-22T06:12:23.478000",
        "source_ip": "192.168.65.137",
        "dest_ip": "192.168.65.2",
        "source_port": 56973.0,
        "dest_port": 53.0,
        "count": 316,
        "flow.bytes_toclient": 116,
        "flow.bytes_toserver": 88
    }
}

# Send POST request to create a node
logging.info("Creating a node")
node_response = requests.post(f"{BASE_URL}/node/", json=node_data)
logging.info(f"Node Response: {node_response.json()}")

# Send POST request to create an edge
logging.info("Creating an edge")
edge_response = requests.post(f"{BASE_URL}/edge/", json=edge_data)
logging.info(f"Edge Response: {edge_response.json()}")

# Send GET request to retrieve hourly graphs
start_time = datetime(2024, 7, 22, 6, 0).isoformat()
end_time = datetime(2024, 7, 22, 7, 0).isoformat()
logging.info(f"Fetching hourly graphs between {start_time} and {end_time}")
graphs_response = requests.get(f"{BASE_URL}/get_hourly_graphs", params={"start_time": start_time, "end_time": end_time})
logging.info(f"Graphs Response: {graphs_response.json()}")
