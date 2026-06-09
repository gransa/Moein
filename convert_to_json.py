import os
import json
import base64
import ipaddress
import re
import urllib.request
import random
import copy
from urllib.parse import urlparse, parse_qs

# Configuration URLs
CLEAN_IPS_URL = "https://raw.githubusercontent.com/gransa/Moein/refs/heads/main/Cloudflare-IPs.txt"
DNS_TOP_URL = "https://raw.githubusercontent.com/gransa/Moein/refs/heads/main/DNS-TOP.txt"
DNS_MAIN_URL = "https://raw.githubusercontent.com/gransa/Moein/refs/heads/main/DNS.txt"

# Port Definitions
TLS_PORTS = [443, 2053, 2083, 2087, 2096, 8443]
NON_TLS_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095]

def is_raw_ip(address_str):
    """Checks if a string is a raw IPv4 or bracketed/raw IPv6 address."""
    clean = address_str.strip().replace("[", "").replace("]", "").split(":")[0]
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        return False

def fetch_content(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.read().decode('utf-8').splitlines()
    except:
        return []

def get_identity_key(srv):
    """Normalizes server strings for uniqueness."""
    for prefix in ["tcp:", "udp:", "quic:", "https:"]:
        if srv.startswith(prefix):
            srv = srv.replace(prefix, "").replace("//", "").strip()
    return srv.split(':')[0].split('/')[0]

def parse_dns_source(pool_dns_servers):
    """Groups servers with their associated IPs."""
    paired = []
    for i in range(len(pool_dns_servers)):
        item = pool_dns_servers[i].strip()
        if not item or item.startswith(("#", "//")): continue
        
        # Simple heuristic to identify server entries
        if "://" in item or "." in item or "[" in item:
            paired.append({"server": item, "ip": item.split("//")[-1].split(":")[0].strip("[]")})
    return paired

def build_v2rayng_template(remarks, outbound_nodes, pool_top_dns, pool_main_dns):
    base_outbounds = list(outbound_nodes)
    base_outbounds.extend([
        {"protocol": "dns", "tag": "dns-out"},
        {"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}, "tag": "direct"},
        {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}
    ])

    pairs_top = parse_dns_source(pool_top_dns)
    pairs_main = parse_dns_source(pool_main_dns)

    # Filtering Logic
    doh_top = [p for p in pairs_top if p["server"].startswith("https://")]
    doh_main = [p for p in pairs_main if p["server"].startswith("https://")]
    non_raw_pool = [p for p in (pairs_top + pairs_main) if not is_raw_ip(p["server"])]

    chosen = [None] * 5
    # Slot 1: DoH from Top
    chosen[0] = doh_top[0] if doh_top else {"server": "https://8.8.8.8/dns-query", "ip": "8.8.8.8"}
    # Slot 2: DoH from Main
    chosen[1] = doh_main[0] if doh_main else {"server": "https://1.1.1.1/dns-query", "ip": "1.1.1.1"}
    # Slots 3-5: Non-raw protocols
    for i in range(2, 5):
        chosen[i] = non_raw_pool[i % len(non_raw_pool)] if non_raw_pool else {"server": "udp:8.8.8.8", "ip": "8.8.8.8"}

    dns_servers_config = []
    inbound_tags = []
    
    for i, p in enumerate(chosen, 1):
        tag = f"remote-dns-{i}"
        inbound_tags.append(tag)
        # Apply strict formatting to remove raw IPs
        srv = p["server"]
        if is_raw_ip(srv) and "://" not in srv:
            srv = f"udp:{srv}"
            
        dns_servers_config.append({"address": srv, "tag": tag})
        
        # Add matching routing rule
        dns_servers_config.append({
            "address": p["ip"],
            "domains": ["geosite:category-ir"],
            "expectIPs": ["geoip:ir"]
        })

    return {
        "remarks": remarks,
        "dns": {"servers": dns_servers_config, "queryStrategy": "UseIP", "tag": "dns"},
        "inbounds": [{"port": 10808, "protocol": "socks", "tag": "socks-in"}],
        "outbounds": base_outbounds,
        "routing": {
            "rules": [{"inboundTag": inbound_tags, "balancerTag": "all", "type": "field"}],
            "balancers": [{"tag": "all", "selector": ["prox-1"], "strategy": {"type": "leastPing"}}]
        }
    }

def main():
    # Load data
    clean_ips = fetch_content(CLEAN_IPS_URL)
    top_dns = fetch_content(DNS_TOP_URL)
    main_dns = fetch_content(DNS_MAIN_URL)
    
    # Placeholder for logic: In a real run, parse 'Configs.txt' into outbound_nodes
    # and generate output using build_v2rayng_template
    print("Code structure initialized with strict DNS filtering.")

if __name__ == "__main__":
    main()
