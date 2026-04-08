from pydantic import BaseModel
from typing import List

# --- OBSERVATIONS (What the agent sees) ---
class SystemState(BaseModel):
    auth_logs: str
    web_logs: str
    sys_logs: str
    active_firewall_rules: List[str]
    active_pids: List[int]

# --- ACTIONS (What the agent can do) ---
class BlockIP(BaseModel):
    ip_address: str
    reason: str

class UnblockIP(BaseModel):
    ip_address: str
    reason: str

class KillProcess(BaseModel):
    pid: int
    reason: str
    
class IsolateHost(BaseModel):
    hostname: str
    reason: str