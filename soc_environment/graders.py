# soc_environment/graders.py
import json
import os

MOCK_DATA_DIR = "soc_environment/mock_data"

def get_firewall_state():
    with open(os.path.join(MOCK_DATA_DIR, "firewall.json"), "r") as f:
        return json.load(f).get("blocked_ips", [])

def get_process_state():
    with open(os.path.join(MOCK_DATA_DIR, "processes.json"), "r") as f:
        return json.load(f).get("active_pids", [])

def grade_easy_task():
    """
    Goal: Block the brute-force attacker (192.168.1.99).
    Penalty: Blocking the legitimate admin (10.0.0.2).
    """
    blocked = get_firewall_state()
    score = 0.0
    
    # 1. Reward for blocking the real threat
    if "192.168.1.99" in blocked:
        score += 1.0
        
    # 2. Penalty for blocking the admin
    if "10.0.0.2" in blocked:
        score -= 0.5
        
    # 3. THE DECOY TRAP PENALTY
    if "10.0.0.50" in blocked:
        print("\n[GRADER WARNING] Agent failed reasoning check: Blocked authorized scanner (10.0.0.50).")
        score -= 0.5  # Heavy penalty for a false positive
        
    # Return final score, clamped exactly between 0.0 and 1.0
    return max(0.0, min(score, 1.0))

def grade_medium_task():
    """
    Goal: Identify the SQL Injection in web.log and block the IP (203.0.113.42).
    Penalty: Blocking legitimate web traffic (10.0.0.5 or 10.0.0.8).
    """
    blocked = get_firewall_state()
    score = 0.0
    
    if "203.0.113.42" in blocked:
        score += 1.0
        
    if "10.0.0.5" in blocked or "10.0.0.8" in blocked:
        score -= 0.5
        
        
        
    return max(0.0, min(score, 1.0))

def grade_hard_task():
    """
    Goal: Read syslog, identify the ransomware PID (666), and kill it.
    Penalty: Killing critical system processes (101 or 102).
    """
    active_pids = get_process_state()
    score = 0.0
    
    if 666 not in active_pids:
        score += 1.0  # Successfully killed the malware
        
    if 101 not in active_pids or 102 not in active_pids:
        score -= 0.5  # Accidentally killed a good process
        
    return max(0.0, min(score, 1.0))