from flask import Flask, request, jsonify
import requests
import json
import re
import os
import socket
from flask_cors import CORS


from typing import List

app = Flask(__name__)
CORS(app)

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
    "zone1": "eth0",
    "zone2": "eth1",
    "internet": "eth2",
}

GROQ_API_KEY = "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"
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

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


def resolve_ip_if_needed(application: str) -> list:
    domain = APP_DOMAIN_MAP.get(application)
    if domain:
        try:
            return list(set([res[4][0] for res in socket.getaddrinfo(domain, None)]))
        except Exception as e:
            print(f"[WARN] Could not resolve {domain}: {e}")
    return []


def extract_json_from_response(text):
    match = re.search(r"(?:json)?\s*(\{.?\})\s", text, re.DOTALL)
    if match:
        return match.group(1)
    match = re.search(r"(\{.*?\})", text, re.DOTALL)
    if match:
        return match.group(1)
    raise ValueError("No valid JSON object found in the model response.")


def get_vyos_config(policy_data: list) -> List[str]:
    cli_commands = []
    qos_policy_name = "APP_QOS_POLICY"
    firewall_name = "APP_BLOCK_FW"

    cli_commands += ["configure"]

    cli_commands += [
        f"delete qos policy shaper {qos_policy_name}",
        f"delete firewall name {firewall_name}"
    ]

    cli_commands += [
        f"set qos policy shaper {qos_policy_name} description 'QoS Policy for Application Traffic'",
        f"set qos policy shaper {qos_policy_name} default bandwidth '100mbit'",
        f"set qos policy shaper {qos_policy_name} default burst '15k'",
        f"set qos policy shaper {qos_policy_name} default queue-type fair-queue",
        f"set firewall name {firewall_name} default-action accept",
        f"set firewall name {firewall_name} description 'Firewall to Block Specific Applications'"
    ]

    qos_class_counter = 10
    firewall_rule_counter = 10

    for item in policy_data:
        application = item.get("application", "").lower()
        action = item.get("action", "").lower()
        duration = item.get("duration", "N/A")
        zone = item.get("zone", "").lower()

        dscp = DSCP_MAPPING.get(application, DSCP_MAPPING.get(action, "cs0"))
        match_name = f"{application.upper()}_{action.upper()}_MATCH"

        if zone and zone in ZONE_INTERFACE_MAP:
            interface = ZONE_INTERFACE_MAP[zone]
            cli_commands.append(f"set interfaces ethernet {interface} traffic-policy out {qos_policy_name}")
            resolved_ips = []
        else:
            resolved_ips = resolve_ip_if_needed(application)
            if not resolved_ips:
                continue

        if action == "prioritise":
            cli_commands += [
                f"set qos policy shaper {qos_policy_name} class {qos_class_counter} bandwidth '30%'",
                f"set qos policy shaper {qos_policy_name} class {qos_class_counter} burst '10k'",
                f"set qos policy shaper {qos_policy_name} class {qos_class_counter} queue-type fair-queue",
                f"set qos policy shaper {qos_policy_name} class {qos_class_counter} set-dscp '{dscp}'"
            ]
            if resolved_ips:
                for ip in resolved_ips:
                    cli_commands.append(
                        f"set qos policy shaper {qos_policy_name} class {qos_class_counter} match {match_name}{ip.replace('.', '')} ip source address {ip}")
            else:
                cli_commands.append(
                    f"set qos policy shaper {qos_policy_name} class {qos_class_counter} match {match_name} ip protocol all")

        elif action == "limit":
            cli_commands += [
                f"set qos policy shaper {qos_policy_name} class {qos_class_counter} bandwidth '{duration}'",
                f"set qos policy shaper {qos_policy_name} class {qos_class_counter} burst '5k'",
                f"set qos policy shaper {qos_policy_name} class {qos_class_counter} queue-type fair-queue",
                f"set qos policy shaper {qos_policy_name} class {qos_class_counter} set-dscp '{dscp}'"
            ]
            if resolved_ips:
                for ip in resolved_ips:
                    cli_commands.append(
                        f"set qos policy shaper {qos_policy_name} class {qos_class_counter} match {match_name}{ip.replace('.', '')} ip source address {ip}")
            else:
                cli_commands.append(
                    f"set qos policy shaper {qos_policy_name} class {qos_class_counter} match {match_name} ip protocol all")

        elif action == "block":
            cli_commands += [
                f"set firewall name {firewall_name} rule {firewall_rule_counter} description 'Block {application}'",
                f"set firewall name {firewall_name} rule {firewall_rule_counter} action drop"
            ]
            if resolved_ips:
                for ip in resolved_ips:
                    cli_commands.append(
                        f"set firewall name {firewall_name} rule {firewall_rule_counter} source address {ip}")
            else:
                cli_commands.append(
                    f"set firewall name {firewall_name} rule {firewall_rule_counter} ip protocol all")

        qos_class_counter += 10
        firewall_rule_counter += 10

    cli_commands += ["commit", "save"]
    return cli_commands


@app.route("/generate", methods=["POST"])
def generate_policy():
    data = request.get_json()
    user_input = data.get("complaint", "")

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": "llama3-70b-8192",
        "messages": [
            {
                "role": "system",
                "content": "You are a network assistant that extracts traffic control rules from user complaints. Return only a JSON object with 'application', 'action', 'duration', and 'zone'. The 'action' must be either 'prioritise', 'limit', or 'block'. If duration is not relevant, set it to 'N/A'. If the policy applies to a specific zone, provide the zone name, else leave zone as empty string."
            },
            {"role": "user", "content": user_input}
        ],
        "temperature": 0.2
    }

    try:
        response = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        raw_result = response.json()["choices"][0]["message"]["content"]
        print("Raw model output:\n", raw_result)

        cleaned_json = extract_json_from_response(raw_result)
        policy_data = json.loads(cleaned_json)

        if not isinstance(policy_data, list):
            policy_data = [policy_data]

        for item in policy_data:
            if 'zone' not in item:
                item['zone'] = ""

        cli_commands = get_vyos_config(policy_data)

        return jsonify({
            "policy": policy_data,
            "cli_commands": cli_commands
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)
