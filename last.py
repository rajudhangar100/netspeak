import requests
import json
import re
import os
import socket
from typing import Optional




GROQ_API_KEY = "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"
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
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

ZONE_INTERFACE_MAP = {
    "zone1": "GigabitEthernet0/1",
    "zone2": "GigabitEthernet0/2",
    "internet": "GigabitEthernet0/3",
}


def resolve_ip_if_needed(application: str) -> list:
    domain = APP_DOMAIN_MAP.get(application)
    if domain:
        try:
            return list(set([res[4][0] for res in socket.getaddrinfo(domain, None)]))
        except Exception as e:
            print(f"[WARN] Could not resolve {domain}: {e}")
    return []


def get_cisco_config(policy_file: str = "policy.json") -> list[str]:
    cli_commands = []
    qos_policy_name = "APP_QOS_POLICY"
    class_map_counter = 10
    acl_counter = 101

    if not os.path.exists(policy_file):
        print(f"Error: Policy file '{policy_file}' not found.")
        return []

    with open(policy_file, 'r') as f:
        policy_data = json.load(f)

    class_maps = []
    policy_map = [f"policy-map {qos_policy_name}"]
    access_lists = []
    interface_commands = []

    for item in policy_data:
        application = item.get("application", "").lower()
        action = item.get("action", "").lower()
        duration = item.get("duration", "N/A")
        zone = item.get("zone", "").lower()

        class_map_name = f"{application}CLASS{class_map_counter}"
        acl_name = f"{acl_counter}"
        resolved_ips = resolve_ip_if_needed(application)
        if not resolved_ips:
            continue

        # Build Access List
        for ip in resolved_ips:
            access_lists.append(f"ip access-list extended {acl_name}")
            access_lists.append(f" permit ip host {ip} any")

        if action == "prioritise":
            class_maps.append(f"class-map match-any {class_map_name}")
            class_maps.append(f" match access-group {acl_name}")

            policy_map.append(f" class {class_map_name}")
            policy_map.append(f"  priority percent 90")
            policy_map.append(f"  set dscp ef")

        elif action == "limit":
            class_maps.append(f"class-map match-any {class_map_name}")
            class_maps.append(f" match access-group {acl_name}")

            policy_map.append(f" class {class_map_name}")
            policy_map.append(f"  bandwidth {duration}")
            policy_map.append(f"  set dscp af41")

        elif action == "block":
            for ip in resolved_ips:
                access_lists.append(f"ip access-list extended BLOCK_APP")
                access_lists.append(f" deny ip host {ip} any")
            access_lists.append(f"ip access-list extended BLOCK_APP")
            access_lists.append(f" permit ip any any")

        if zone and zone in ZONE_INTERFACE_MAP:
            interface_commands.append(f"interface {ZONE_INTERFACE_MAP[zone]}")
            if action == "block":
                interface_commands.append(f" ip access-group BLOCK_APP in")
            else:
                interface_commands.append(f" service-policy output {qos_policy_name}")

        class_map_counter += 10
        acl_counter += 1

    cli_commands += access_lists
    cli_commands += class_maps
    cli_commands += policy_map
    cli_commands += interface_commands

    return cli_commands


# The rest of your code (API call, user input, file saving) stays the same
# Just change the config generator function name when calling it

def get_qos_policy(user_input):
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": "llama3-70b-8192",
        "messages": [
            {"role": "system", "content": "You are a network assistant that extracts traffic control rules from user complaints. Return only a JSON object with 'application', 'action', 'duration', and 'zone'. The 'action' must be either 'prioritise', 'limit', or 'block'. If duration is not relevant, set it to 'N/A'. If the policy applies to a specific zone, provide the zone name, else leave zone as empty string."},
            {"role": "user", "content": user_input}
        ],
        "temperature": 0.2
    }

    print("Sending request to Groq API...")
    try:
        response = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        raw_result = response.json()["choices"][0]["message"]["content"]
        print("Raw model output:\n", raw_result)

        cleaned_json = extract_json_from_response(raw_result)
        policy_data = json.loads(cleaned_json)
    except Exception as e:
        print(f"Failed to fetch or parse policy: {e}")
        return None

    if not isinstance(policy_data, list):
        policy_data = [policy_data]

    for item in policy_data:
        if 'zone' not in item:
            item['zone'] = ""

    try:
        with open("policy.json", "w") as f:
            json.dump(policy_data, f, indent=4)
        print("Policy saved to policy.json")
    except Exception as e:
        print(f"Error writing policy.json: {e}")
        return None

    commands = get_cisco_config("policy.json")

    if commands:
        print("\n" + "=" * 40)
        print("    Generated Cisco CLI Commands")
        print("=" * 40 + "\n")
        for cmd in commands:
            print(cmd)
        print("\n" + "=" * 40)
    else:
        print("No CLI commands generated.")

    return policy_data


if __name__ == "__main__":
    print("--- Cisco QoS Policy Generator ---")

    user_complaint = input("Enter the issue: ")

    policy = get_qos_policy(user_complaint)

    if policy:
        print("\nParsed Policy:")
        print(json.dumps(policy, indent=4))
    else:
        print("Failed to generate policy.")