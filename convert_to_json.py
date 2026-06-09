import os
import json
import base64
import ipaddress
import re
import urllib.request
import random
import copy

# Configuration URLs
CLEAN_IPS_URL = "https://raw.githubusercontent.com/gransa/Moein/refs/heads/main/Cloudflare-IPs.txt"
DNS_TOP_URL = "https://raw.githubusercontent.com/gransa/Moein/refs/heads/main/DNS-TOP.txt"
DNS_MAIN_URL = "https://raw.githubusercontent.com/gransa/Moein/refs/heads/main/DNS.txt"

def fetch_list(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            return [line.strip() for line in response.read().decode('utf-8').splitlines() if line.strip() and not line.startswith(("#", "//"))]
    except:
        return []

def is_raw_ip(address_str):
    clean = address_str.strip().replace("[", "").replace("]", "").split(":")[0]
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        return False

def parse_dns_source(pool):
    paired = []
    for item in pool:
        # Heuristic to separate Server from IP
        paired.append({"server": item, "ip": item.split("//")[-1].split(":")[0].strip("[]")})
    return paired

def build_v2rayng_template(remarks, outbound_nodes, pool_top, pool_main):
    pairs_top = parse_dns_source(pool_top)
    pairs_main = parse_dns_source(pool_main)

    # 1. Slot Filter Logic
    doh_top = [p for p in pairs_top if p["server"].startswith("https://")]
    doh_main = [p for p in pairs_main if p["server"].startswith("https://")]
    non_raw_pool = [p for p in (pairs_top + pairs_main) if not is_raw_ip(p["server"])]

    # 2. Select Servers
    chosen = [
        doh_top[0] if doh_top else {"server": "https://8.8.8.8/dns-query", "ip": "8.8.8.8"},
        doh_main[0] if doh_main else {"server": "https://1.1.1.1/dns-query", "ip": "1.1.1.1"},
        non_raw_pool[0] if non_raw_pool else {"server": "udp:8.8.8.8", "ip": "8.8.8.8"},
        non_raw_pool[1] if len(non_raw_pool) > 1 else {"server": "udp:1.1.1.1", "ip": "1.1.1.1"},
        non_raw_pool[2] if len(non_raw_pool) > 2 else {"server": "tcp:9.9.9.9", "ip": "9.9.9.9"}
    ]

    dns_servers = []
    tags = []
    for i, p in enumerate(chosen, 1):
        tag = f"remote-dns-{i}"
        tags.append(tag)
        # Force non-raw IPs into protocol format
        srv = p["server"]
        if is_raw_ip(srv) and "://" not in srv: srv = f"udp:{srv}"
        
        dns_servers.append({"address": srv, "tag": tag})
        dns_servers.append({"address": p["ip"], "domains": ["geosite:category-ir"], "expectIPs": ["geoip:ir"]})

    return {
        "remarks": remarks,
        "dns": {"servers": dns_servers, "queryStrategy": "UseIP", "tag": "dns"},
        "inbounds": [{"port": 10808, "protocol": "socks", "tag": "socks-in"}],
        "outbounds": outbound_nodes + [{"protocol": "freedom", "tag": "direct"}],
        "routing": {"rules": [{"inboundTag": tags, "balancerTag": "all", "type": "field"}], "balancers": [{"tag": "all", "selector": ["prox-1"]}]}
    }

def main():
    if not os.path.exists("Configs.txt"):
        print("Configs.txt missing!")
        return

    # Data Gathering
    top_dns = fetch_list(DNS_TOP_URL)
    main_dns = fetch_list(DNS_MAIN_URL)
    
    # Simple parse simulation (Replace with your actual node parsing)
    with open("Configs.txt", "r") as f:
        nodes = [{"protocol": "vless", "settings": {"vnext": [{"address": "example.com", "port": 443}]}, "tag": "prox-1"}]

    # Build Template
    output = [build_v2rayng_template("Generated Config", nodes, top_dns, main_dns)]

    # Write Output
    with open("NG-JSON-Configs.txt", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    
    print("Generation complete.")

if __name__ == "__main__":
    main()
