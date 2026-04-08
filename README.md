---
title: Soc Agent Env
emoji: 🛡️
colorFrom: blue
colorTo: green
sdk: docker
pinned: false
tags:
  - openenv
---

# Cybersecurity SOC Environment (OpenEnv)

## Description
This is a simulated Security Operations Center (SOC) environment designed to test autonomous AI agents. The environment simulates a live server experiencing multiple vectors of cyber attacks, including SSH brute forcing, SQL injection, and active ransomware processes. The agent must parse logs, identify threats, and take remediation actions without disrupting legitimate network traffic or critical system processes.

## Observation Space
The agent receives a unified `SystemState` observation, containing:
* `auth_logs`: Text string of SSH authentication attempts.
* `web_logs`: Text string of HTTP requests and statuses.
* `sys_logs`: Text string of critical system events and warnings.
* `active_firewall_rules`: List of IP addresses currently blocked.
* `active_pids`: List of currently running process IDs.

## Action Space
The agent can execute the following strongly-typed actions:
* `BlockIP(ip_address, reason)`: Appends an IP to the firewall blocklist.
* `UnblockIP(ip_address, reason)`: Removes an IP from the firewall blocklist.
* `KillProcess(pid, reason)`: Terminates a running process by its integer ID.

## Setup Instructions
1. Clone this repository.
2. Install dependencies: `pip install -r requirements.txt`
3. Ensure you have your LLM API keys exported:
   ```bash
   export API_BASE_URL="[https://api.openai.com/v1](https://api.openai.com/v1)"
   export MODEL_NAME="your-model-name"
   export HF_TOKEN="your-api-key"