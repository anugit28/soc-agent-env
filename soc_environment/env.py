# soc_environment/env.py
import json
import os
from .models import SystemState, BlockIP, UnblockIP, KillProcess, IsolateHost

MOCK_DATA_DIR = "soc_environment/mock_data"
FIREWALL_FILE = os.path.join(MOCK_DATA_DIR, "firewall.json")
PROCESS_FILE = os.path.join(MOCK_DATA_DIR, "processes.json")

def generate_fresh_logs():
    """Generates the isolated environment state from scratch."""
    os.makedirs(MOCK_DATA_DIR, exist_ok=True)
    
    # Easy Task Data: Brute force from 192.168.1.99
    with open(os.path.join(MOCK_DATA_DIR, "auth.log"), "w") as f:
        f.write("00:01 - Accepted publickey for admin from 10.0.0.2\n"
                "00:05 - Failed password for root from 192.168.1.99\n"
                "00:06 - Failed password for root from 192.168.1.99\n"
                "00:07 - Failed password for root from 192.168.1.99\n")

    # Medium Task Data: SQL Injection from 203.0.113.42
    with open(os.path.join(MOCK_DATA_DIR, "web.log"), "w") as f:
        f.write("GET /index.html 200 OK - IP: 10.0.0.5\n"
                "POST /login.php 500 ERROR - Payload: ' OR 1=1; -- IP: 203.0.113.42\n"
                "GET /about.html 200 OK - IP: 10.0.0.8\n")
                
    # Hard Task Data: Ransomware process running
    with open(os.path.join(MOCK_DATA_DIR, "syslog"), "w") as f:
        f.write("CRITICAL: High disk I/O detected. Multiple files encrypted.\n"
                "WARNING: Suspicious binary 'crypto_locker.bin' spawned with PID 666.\n"
                "[INFO] Authorized internal vulnerability scanner active from IP 10.0.0.50. DO NOT BLOCK.\n")

    # Reset System State Files
    with open(FIREWALL_FILE, "w") as f:
        json.dump({"blocked_ips": []}, f)
    with open(PROCESS_FILE, "w") as f:
        json.dump({"active_pids": [101, 102, 666]}, f) # 666 is the malicious process


class SOCEnvironment:
    def __init__(self):
        self.reset()

    def reset(self):
        generate_fresh_logs()
        self.step_count = 0
        return self.state()

    def state(self) -> SystemState:
        with open(f"{MOCK_DATA_DIR}/auth.log", "r") as f: auth_logs = f.read()
        with open(f"{MOCK_DATA_DIR}/web.log", "r") as f: web_logs = f.read()
        with open(f"{MOCK_DATA_DIR}/syslog", "r") as f: sys_logs = f.read()
            
        with open(FIREWALL_FILE, "r") as f: fw_data = json.load(f)
        with open(PROCESS_FILE, "r") as f: proc_data = json.load(f)

        return SystemState(
            auth_logs=auth_logs,
            web_logs=web_logs,
            sys_logs=sys_logs,
            active_firewall_rules=fw_data["blocked_ips"],
            active_pids=proc_data["active_pids"]
        )

    def step(self, action: BlockIP | UnblockIP | KillProcess | IsolateHost):
        self.step_count += 1
        
        # Handle Networking Actions
        if isinstance(action, (BlockIP, UnblockIP)):
            with open(FIREWALL_FILE, "r") as f: fw_data = json.load(f)
            
            if isinstance(action, BlockIP) and action.ip_address not in fw_data["blocked_ips"]:
                fw_data["blocked_ips"].append(action.ip_address)
            elif isinstance(action, UnblockIP) and action.ip_address in fw_data["blocked_ips"]:
                fw_data["blocked_ips"].remove(action.ip_address)
                
            with open(FIREWALL_FILE, "w") as f: json.dump(fw_data, f)

        # Handle System Actions
        elif isinstance(action, KillProcess):
            with open(PROCESS_FILE, "r") as f: proc_data = json.load(f)
            
            if action.pid in proc_data["active_pids"]:
                proc_data["active_pids"].remove(action.pid)
                
            with open(PROCESS_FILE, "w") as f: json.dump(proc_data, f)
        
        elif isinstance(action, IsolateHost):
            print(f"Executing Network Isolation on Host: {action.hostname}")
            with open(os.path.join(MOCK_DATA_DIR, "quarantine.json"), "w") as f:
                json.dump({"quarantined_hosts": [action.hostname]}, f)

        return self.state()