# This code was documented by the BeeHive Team, to help those seeking to learn.
# This documentation does not impact the function of the code.
# Please do not remove it, so that users who reuse or find this can learn.

# Importing required libraries
import json
import requests
import time
import os
import yaml
import sys

# Define function to load configuration
def load_config(path):
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.load(f, Loader=yaml.FullLoader)

# Load configuration from file or environment variables
def load_credentials():
    if os.path.exists('config.yml'):
        config = load_config('config.yml')
        return {
            'CLOUDFLARE_ZONE_ID': config['CLOUDFLARE_ZONE_ID'],
            'CLOUDFLARE_EMAIL': config['CLOUDFLARE_EMAIL'],
            'CLOUDFLARE_API_KEY': config['CLOUDFLARE_API_KEY'],
            'ABUSEIPDB_API_KEY': config['ABUSEIPDB_API_KEY']
        }
    else:
        return {
            'CLOUDFLARE_ZONE_ID': os.environ["CLOUDFLARE_ZONE_ID"],
            'CLOUDFLARE_EMAIL': os.environ["CLOUDFLARE_EMAIL"],
            'CLOUDFLARE_API_KEY': os.environ["CLOUDFLARE_API_KEY"],
            'ABUSEIPDB_API_KEY': os.environ["ABUSEIPDB_API_KEY"]
        }

credentials = load_credentials()

range_from = time.localtime(time.time() - 60 * 60 * 2.5)
range_until = time.localtime(time.time())

# Set payload for Cloudflare API requests
payload = {
    "query": """query ListFirewallEvents($zoneTag: string, $filter: FirewallEventsAdaptiveFilter_InputObject) {
        viewer {
            zones(filter: { zoneTag: $zoneTag }) {
                firewallEventsAdaptive(
                    filter: $filter
                    limit: 2500
                    orderBy: [datetime_DESC]
                ) {
                    action
                    clientASNDescription
                    clientAsn
                    clientCountryName
                    clientIP
                    clientRequestHTTPHost
                    clientRequestHTTPMethodName
                    clientRequestHTTPProtocol
                    clientRequestPath
                    clientRequestQuery
                    datetime
                    rayName
                    ruleId
                    source
                    userAgent
                }
            }
        }
    }""",
    "variables": {
        "zoneTag": credentials['CLOUDFLARE_ZONE_ID'],
        "filter": {
            "datetime_geq": time.strftime("%Y-%m-%dT%H:%M:%SZ", range_from),
            "datetime_leq": time.strftime("%Y-%m-%dT%H:%M:%SZ", range_until),
            "AND": [
                {"action_neq": "allow"},
                {"action_neq": "skip"},
                {"action_neq": "challenge_solved"},
                {"action_neq": "challenge_failed"},
                {"action_neq": "challenge_bypassed"},
                {"action_neq": "jschallenge_solved"},
                {"action_neq": "jschallenge_failed"},
                {"action_neq": "jschallenge_bypassed"},
                {"action_neq": "managed_challenge_skipped"},
                {"action_neq": "managed_challenge_non_interactive_solved"},
                {"action_neq": "managed_challenge_interactive_solved"},
                {"action_neq": "managed_challenge_bypassed"},
            ]
        }
    }
}

# Convert payload dictionary to a JSON string
payload = json.dumps(payload)

# Define headers for the API request
headers = {
    "Content-Type": "application/json",
    "X-Auth-Key": credentials['CLOUDFLARE_API_KEY'],
    "X-Auth-Email": credentials['CLOUDFLARE_EMAIL']
}

# Set the initial time to live value to 60
ttl = 60

# Define a function to get a list of blocked IP Addresses
def get_blocked_ip():
    global ttl
    ttl -= 1
    print("ttl:", ttl)
    if ttl <= 0:
        return []
    try:
        response = requests.post("https://api.cloudflare.com/client/v4/graphql/", headers=headers, data=payload)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return get_blocked_ip()

# Define a function to generate a comment for the Bad IP Address report intended for AbuseIPDB
def get_comment(event):
    return (f"Threat Blocked by BeeHive from (ASN:{event['clientAsn']}) "
            f"(Network:{event['clientASNDescription']}) "
            f"(Host:{event['clientRequestHTTPHost']}) "
            f"(Method:{event['clientRequestHTTPMethodName']}) "
            f"(Protocol:{event['clientRequestHTTPProtocol']}) "
            f"(Timestamp:{event['datetime']})")

# Define a function to report a bad IP address to AbuseIPDB
def report_bad_ip(event):
    try:
        url = 'https://api.abuseipdb.com/api/v2/report'
        params = {
            'ip': event['clientIP'],
            'categories': '9,13,14,15,16,19,20,21',
            'comment': get_comment(event),
            'timestamp': event['datetime']
        }
        headers = {
            'Accept': 'application/json',
            'Key': credentials['ABUSEIPDB_API_KEY']
        }
        response = requests.post(url=url, headers=headers, params=params)
        response.raise_for_status()
        print("reported:", event['clientIP'])
    except requests.RequestException as e:
        print(f"Error reporting IP: {e}")
        if response is not None:
            print(json.dumps(response.json(), sort_keys=True, indent=4))

# Define a list of excluded Cloudflare WAF Rule IDs
excepted_rule_ids = ["fa01280809254f82978e827892db4e46"]

# Print start time and end time within output
print("==================== Start ====================")
print("Events from:  " + time.strftime("%Y-%m-%d %H:%M:%S", range_from))
print("Events until: " + time.strftime("%Y-%m-%d %H:%M:%S", range_until))

blocked_ips = get_blocked_ip()
print(str(type(blocked_ips)))

if isinstance(blocked_ips, dict) and 'data' in blocked_ips:
    ip_bad_list = blocked_ips["data"]["viewer"]["zones"][0]["firewallEventsAdaptive"]
    print(len(ip_bad_list))

    reported_ip_list = []
    for event in ip_bad_list:
        if event['ruleId'] not in excepted_rule_ids and event['clientIP'] not in reported_ip_list:
            report_bad_ip(event)
            reported_ip_list.append(event['clientIP'])

    print(len(reported_ip_list))

print("==================== End ====================")
