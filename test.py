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



def resolve_ip_if_needed(interface: str, user_input: str) -> str:
    import socket

    if interface:
        return interface  # Use directly if provided

    # Try to detect known application names
    for app, domain in APP_DOMAIN_MAP.items():
        if re.search(rf"\b{app}\b", user_input.lower()):
            try:
                ip = socket.gethostbyname(domain)
                print(f"[INFO] Resolved {app} ({domain}) to {ip}")
                return ip
            except Exception as e:
                print(f"[WARN] Could not resolve {domain}: {e}")
                return "eth0"  # Fallback

    print("[WARN] No app matched. Defaulting to eth0.")
    return "eth0"


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

def get_vyos_config(
    policy_file: str = "policy.json",
    interface: str = "eth0",
    use_dpi: bool = False,
    include_base_config: bool = True,
    global_limit_duration: Optional[str] = None
) -> list[str]:
    cli_commands = []

    if not os.path.exists(policy_file):
        print(f"Error: Policy file '{policy_file}' not found.")
        return []

    try:
        with open(policy_file, 'r') as f:
            policy_data = json.load(f)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in '{policy_file}'.")
        return []
    except Exception as e:
        print(f"An error occurred while reading '{policy_file}': {e}")
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

    FWMARK_MAPPING = {
        "netflix": 100,
        "zoom": 101,
        "ftp": 102,
        "ssh": 103,
        "http": 104,
        "https": 105,
    }

    NPROBE_NFQUEUE_NUM = 25
    qos_policy_name = "APP_QOS_POLICY"
    firewall_name = "APP_BLOCK_FW"
    firewall_dpi_redirect = "DPI_REDIRECT_FW"

    cli_commands.append("configure")

    if include_base_config:
        cli_commands += [
            f"delete qos policy shaper {qos_policy_name}",
            f"delete firewall name {firewall_name}",
            f"delete firewall name {firewall_dpi_redirect}"
        ]

        if use_dpi:
            cli_commands += [
                "set container name nprobe",
                "set container name nprobe image 'ntop/nprobe:latest'",
                "set container name nprobe cap-add 'net-admin'",
                "set container name nprobe cap-add 'sys-admin'",
                f"set container name nprobe arguments '-i nf:{NPROBE_NFQUEUE_NUM} --ips-mode /data/nprobe/ips-config/ips-rules.conf -n none -b 1'",
                "set container name nprobe volume NPROBE_CONF source '/config/containers/nprobe_conf'",
                "set container name nprobe volume NPROBE_CONF destination '/data/nprobe'",
                f"set firewall name {firewall_dpi_redirect} default-action accept",
                f"set firewall name {firewall_dpi_redirect} rule 10 description 'Redirect traffic to nprobe for DPI'",
                f"set firewall name {firewall_dpi_redirect} rule 10 action queue",
                f"set firewall name {firewall_dpi_redirect} rule 10 queue {NPROBE_NFQUEUE_NUM}",
                f"set firewall name {firewall_dpi_redirect} rule 10 queue-options 'bypass'"
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
    policy_items = policy_data if isinstance(policy_data, list) else [policy_data]

    for item in policy_items:
        application = item.get("application", "").lower()
        action = item.get("action", "").lower()
        duration = item.get("duration")
        dscp = DSCP_MAPPING.get(application, DSCP_MAPPING.get(action, "cs0"))
        fwmark = FWMARK_MAPPING.get(application)

        print(f"[DEBUG] use_dpi={use_dpi}, fwmark={fwmark}, application={application}")

        if not use_dpi and not APPLICATION_MAPPING.get(application):
            continue
        if use_dpi and not fwmark:
            continue

        match_name = f"{application.upper()}_{action.upper()}_MATCH"

        if action == "prioritise":
            cli_commands += [
                f"set qos policy shaper {qos_policy_name} class {qos_class_counter} bandwidth '90%'",
                f"set qos policy shaper {qos_policy_name} class {qos_class_counter} burst '10k'",
                f"set qos policy shaper {qos_policy_name} class {qos_class_counter} queue-type fair-queue",
                f"set qos policy shaper {qos_policy_name} class {qos_class_counter} set-dscp '{dscp}'"
            ]
        elif action == "limit":
            effective_duration = global_limit_duration or duration or "5mbit"
            cli_commands += [
                f"set qos policy shaper {qos_policy_name} class {qos_class_counter} bandwidth '{effective_duration}'",
                f"set qos policy shaper {qos_policy_name} class {qos_class_counter} burst '5k'",
                f"set qos policy shaper {qos_policy_name} class {qos_class_counter} queue-type fair-queue",
                f"set qos policy shaper {qos_policy_name} class {qos_class_counter} set-dscp '{dscp}'"
            ]
        elif action == "block":
            cli_commands += [
                f"set firewall name {firewall_name} rule {firewall_rule_counter} description 'Block {application}'",
                f"set firewall name {firewall_name} rule {firewall_rule_counter} action drop"
            ]

        if action in ["prioritise", "limit"]:
            if use_dpi:
                cli_commands.append(
                    f"set qos policy shaper {qos_policy_name} class {qos_class_counter} match {match_name} mark {fwmark}"
                )
            else:
                app = APPLICATION_MAPPING.get(application)
                if app:
                    cli_commands.append(
                        f"set qos policy shaper {qos_policy_name} class {qos_class_counter} match {match_name} ip protocol {app['protocol']}")
                    if app["port"] != "any":
                        cli_commands.append(
                            f"set qos policy shaper {qos_policy_name} class {qos_class_counter} match {match_name} destination port {app['port']}")
            qos_class_counter += 10
        elif action == "block":
            if use_dpi:
                cli_commands.append(f"set firewall name {firewall_name} rule {firewall_rule_counter} mark {fwmark}")
            else:
                app = APPLICATION_MAPPING.get(application)
                if app:
                    cli_commands.append(f"set firewall name {firewall_name} rule {firewall_rule_counter} protocol {app['protocol']}")
                    if app["port"] != "any":
                        cli_commands.append(f"set firewall name {firewall_name} rule {firewall_rule_counter} destination port {app['port']}")
            firewall_rule_counter += 10

    if include_base_config:
        cli_commands.append(f"set interfaces ethernet {interface} traffic-policy out {qos_policy_name}")
        cli_commands.append(f"set interfaces ethernet {interface} firewall in name {firewall_name}")
        if use_dpi:
            cli_commands.append(f"set interfaces ethernet {interface} firewall in name {firewall_dpi_redirect}")

    cli_commands += ["commit", "save"]
    return cli_commands

def get_qos_policy(
    user_input: str,
    interface: str = "eth0",
    use_dpi: bool = False,
    include_base_config: bool = True,
    global_limit_duration: Optional[str] = None
) -> Optional[dict]:
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

    try:
        with open("policy.json", "w") as f:
            json.dump(policy_data, f, indent=4)
        print("Policy saved to policy.json")
    except Exception as e:
        print(f"Error writing policy.json: {e}")
        return None

    commands = get_vyos_config(
        policy_file="policy.json",
        interface=interface,
        use_dpi=use_dpi,
        include_base_config=include_base_config,
        global_limit_duration=global_limit_duration
    )

    if commands:
        output_file = "vyos_cli_output.txt"
        with open(output_file, "w") as f:
            f.write("=" * 40 + "\n")
            f.write("    Generated VyOS CLI Commands\n")
            f.write("=" * 40 + "\n")
            for cmd in commands:
                f.write(cmd + "\n")
            f.write("=" * 40 + "\n")

        print(f"\nCLI commands saved to: {output_file}")
    else:
        print("No CLI commands generated.")


# --- Script Entry Point ---
if __name__ == "__main__":
    print("--- VyOS QoS Policy Generator ---")

    # Hardcoded complaint
    user_complaint = input("Enter the issue: ")

    # Hardcoded config flags
    use_dpi = False
    include_base_config = True
    global_limit = None

    print(f"[DEBUG] use_dpi={use_dpi}, include_base_config={include_base_config}")

    # Infer application from complaint text using regex (basic fallback)
    resolved_interface = resolve_ip_if_needed("", user_complaint)

    policy = get_qos_policy(
        user_input=user_complaint,
        interface=resolved_interface,
        use_dpi=use_dpi,
        include_base_config=include_base_config,
        global_limit_duration=global_limit
    )



    # policy = get_qos_policy(
    #     user_input=user_complaint,
    #     interface="eth0",
    #     use_dpi=use_dpi,
    #     include_base_config=include_base_config,
    #     global_limit_duration=global_limit
    # )
    print(policy)
    if policy:
        print("\nParsed Policy:")
        print(json.dumps(policy, indent=4))
    else:
        print("Failed to generate policy.")