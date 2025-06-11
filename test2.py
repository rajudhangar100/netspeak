import requests
import json
import re
import os
from typing import Optional
import socket

APP_DOMAIN_MAP = {
    "zoom": "zoom.us",
    "youtube": "youtube.com",
    "whatsapp": "whatsapp.com",
    "netflix": "netflix.com",
    "instagram": "instagram.com",
    "facebook": "facebook.com",
    "skype": "skype.com",
    "teams": "teams.microsoft.com",
    "slack": "slack.com",
    "googlemeet": "meet.google.com",
    "meet": "meet.google.com",
}

def resolve_ip_and_interface(user_input: str, interface: Optional[str] = None) -> tuple[str, Optional[str]]:
    if interface:
        return interface, None

    for app, domain in APP_DOMAIN_MAP.items():
        if re.search(rf"\b{app}\b", user_input.lower()):
            try:
                ip = socket.gethostbyname(domain)
                print(f"[INFO] Resolved {app} ({domain}) to {ip}")
                return "eth0", ip
            except Exception as e:
                print(f"[WARN] Could not resolve {domain}: {e}")
                return "eth0", None

    print("[WARN] No app matched. Defaulting to eth0.")
    return "eth0", None

# --- GROQ API Configuration ---
GROQ_API_KEY = "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"
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

def extract_json_from_response(text: str) -> str:
    match = re.search(r"(?:json)?\s*(\{.*?\})\s*", text, re.DOTALL)
    if match:
        return match.group(1)
    match = re.search(r"(\{.*?\})", text, re.DOTALL)
    if match:
        return match.group(1)
    raise ValueError("No valid JSON object found in the model response.")

def get_vyos_config(policy_file: str, interface: str, use_dpi: bool, include_base_config: bool, global_limit_duration: Optional[str], resolved_ip: Optional[str]) -> list[str]:
    cli_commands = []

    if not os.path.exists(policy_file):
        print(f"Error: Policy file '{policy_file}' not found.")
        return []

    try:
        with open(policy_file, 'r') as f:
            policy_data = json.load(f)
    except Exception as e:
        print(f"Error reading policy file: {e}")
        return []

    APPLICATION_MAPPING = {
        "http": {"port": "80", "protocol": "tcp"},
        "https": {"port": "443", "protocol": "tcp"},
        "ftp": {"port": "21", "protocol": "tcp"},
        "ssh": {"port": "22", "protocol": "tcp"},
        "dns": {"port": "53", "protocol": "udp"},
        "smtp": {"port": "25", "protocol": "tcp"},
        "pop3": {"port": "110", "protocol": "tcp"},
        "imap": {"port": "143", "protocol": "tcp"},
        "rdp": {"port": "3389", "protocol": "tcp"},
        "zoom": {"port": "8801", "protocol": "tcp"},
        "netflix": {"port": "443", "protocol": "tcp"},
        "all": {"port": "any", "protocol": "all"}
    }

    DSCP_MAPPING = {
        "prioritise": "ef",
        "limit": "af41",
        "block": "cs0",
        "http": "af21",
        "https": "af21",
        "zoom": "ef",
        "netflix": "af41",
        "ftp": "cs1",
        "ssh": "cs2"
    }

    cli_commands.append("configure")

    qos_class_counter = 10
    policy_items = policy_data if isinstance(policy_data, list) else [policy_data]

    for item in policy_items:
        application = item.get("application", "").lower()
        action = item.get("action", "").lower()
        duration = item.get("duration")
        dscp = DSCP_MAPPING.get(application, DSCP_MAPPING.get(action, "cs0"))
        match_name = f"{application.upper()}_{action.upper()}_MATCH"

        if action in ["prioritise", "limit"]:
            bandwidth = "90%" if action == "prioritise" else (global_limit_duration or duration or "5mbit")
            burst = "10k" if action == "prioritise" else "5k"

            cli_commands += [
                f"set qos policy shaper APP_QOS_POLICY class {qos_class_counter} bandwidth '{bandwidth}'",
                f"set qos policy shaper APP_QOS_POLICY class {qos_class_counter} burst '{burst}'",
                f"set qos policy shaper APP_QOS_POLICY class {qos_class_counter} queue-type fair-queue",
                f"set qos policy shaper APP_QOS_POLICY class {qos_class_counter} set-dscp '{dscp}'",
                f"set qos policy shaper APP_QOS_POLICY class {qos_class_counter} match {match_name} ip protocol {APPLICATION_MAPPING[application]['protocol']}",
                f"set qos policy shaper APP_QOS_POLICY class {qos_class_counter} match {match_name} destination port {APPLICATION_MAPPING[application]['port']}"
            ]
            if resolved_ip:
                cli_commands.append(f"set qos policy shaper APP_QOS_POLICY class {qos_class_counter} match {match_name} source address {resolved_ip}")

            qos_class_counter += 10

    cli_commands += [
        f"set interfaces ethernet {interface} traffic-policy out APP_QOS_POLICY",
        "commit",
        "save"
    ]

    return cli_commands

def get_qos_policy(user_input: str, interface: str, use_dpi: bool, include_base_config: bool, global_limit_duration: Optional[str], resolved_ip: Optional[str]) -> Optional[dict]:
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": "llama3-70b-8192",
        "messages": [
            {"role": "system", "content": "You are a network assistant that extracts traffic control rules from user complaints. Return only a JSON object with 'application', 'action', and 'duration'. The 'action' must be either 'prioritise', 'limit', or 'block'. If duration is not relevant for the action, set it to 'N/A'."},
            {"role": "user", "content": user_input}
        ],
        "temperature": 0.2
    }

    try:
        response = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        raw_result = response.json()["choices"][0]["message"]["content"]
        cleaned_json = extract_json_from_response(raw_result)
        policy_data = json.loads(cleaned_json)
    except Exception as e:
        print(f"Failed to fetch or parse policy: {e}")
        return None

    with open("policy.json", "w") as f:
        json.dump(policy_data, f, indent=4)

    commands = get_vyos_config("policy.json", interface, use_dpi, include_base_config, global_limit_duration, resolved_ip)

    with open("vyos_cli_output.txt", "w") as f:
        f.write("\n".join(commands))

    return policy_data


if __name__ == "__main__":
    print("--- VyOS QoS Policy Generator ---")
    user_complaint = input("Enter the issue: ")

    use_dpi = False
    include_base_config = True
    global_limit = None

    resolved_interface, resolved_ip = resolve_ip_and_interface(user_complaint)

    policy = get_qos_policy(
        user_input=user_complaint,
        interface=resolved_interface,
        use_dpi=use_dpi,
        include_base_config=include_base_config,
        global_limit_duration=global_limit,
        resolved_ip=resolved_ip
    )

    if policy:
        print("\nParsed Policy:")
        print(json.dumps(policy, indent=4))
    else:
        print("Failed to generate policy.")
