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

TLS_PORTS = [443, 2053, 2083, 2087, 2096, 8443]
NON_TLS_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095]

def fetch_clean_addresses(url):
    try:
        print(f"📡 Fetching clean endpoints from: {url}")
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8')
        addresses = [line.split("#")[0].split("//")[0].strip() for line in content.splitlines() 
                    if line.strip() and not line.strip().startswith(("#", "//"))]
        print(f"✅ Successfully loaded {len(addresses)} clean endpoints.")
        return addresses
    except Exception as e:
        print(f"⚠️ Warning: Could not fetch clean endpoints ({e}).")
        return []

def fetch_remote_dns(url):
    try:
        print(f"📡 Fetching remote DNS from: {url}")
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8')
        dns_list = [line.strip() for line in content.splitlines() if line.strip() and not line.strip().startswith(("#", "//"))]
        print(f"✅ Successfully loaded {len(dns_list)} DNS lines.")
        return dns_list
    except Exception as e:
        print(f"⚠️ Warning: Could not fetch DNS from {url} ({e}).")
        return []

def extract_explicit_port(url_str):
    match = re.search(r':([0-9]{2,5})(?:\?|#|$)', url_str)
    return int(match.group(1)) if match else None

def parse_vmess(url_str, tls_counter=[0], non_tls_counter=[0]):
    try:
        b64_data = url_str.replace("vmess://", "").strip()
        b64_data += "=" * ((4 - len(b64_data) % 4) % 4)
        config = json.loads(base64.b64decode(b64_data).decode('utf-8'))
       
        is_tls = str(config.get("tls", "")).lower() in ["tls", "1", "true"]
        net_type = config.get("net", "tcp")
        fp_val = config.get("fp", "chrome")
       
        final_port = int(config.get("port")) if str(config.get("port", "")).isdigit() else \
                     (TLS_PORTS[tls_counter[0] % len(TLS_PORTS)] if is_tls else NON_TLS_PORTS[non_tls_counter[0] % len(NON_TLS_PORTS)])
        if is_tls:
            tls_counter[0] += 1
        else:
            non_tls_counter[0] += 1
       
        outbound = {
            "protocol": "vmess",
            "settings": {"vnext": [{"address": config.get("add"), "port": final_port, "users": [{"id": config.get("id"), "alterId": int(config.get("aid", 0)), "security": "auto", "level": 8}]}]},
            "streamSettings": {"network": net_type, "security": "tls" if is_tls else "none"}
        }
        if net_type == "ws":
            outbound["streamSettings"]["wsSettings"] = {"host": config.get("host", ""), "path": config.get("path", "")}
        if is_tls:
            outbound["streamSettings"]["tlsSettings"] = {
                "allowInsecure": False, "fingerprint": fp_val, "serverName": config.get("host", config.get("add")), "show": False
            }
        return outbound, is_tls
    except Exception as e:
        print(f"Error parsing VMESS: {e}")
        return None, False

def parse_standard_uri(url_str, protocol, tls_counter=[0], non_tls_counter=[0], clean_addresses=[], ip_counter=[0]):
    try:
        parsed = urlparse(url_str)
        userinfo = parsed.username or parsed.netloc.split('@')[0]
        host_port = parsed.netloc.split('@')[-1]
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
       
        security = params.get("security", "").lower()
        explicit_port = extract_explicit_port(url_str)
        final_port = explicit_port if explicit_port else (TLS_PORTS[tls_counter[0] % len(TLS_PORTS)] if security in ["tls", "reality", "xtls"] else NON_TLS_PORTS[non_tls_counter[0] % len(NON_TLS_PORTS)])
       
        if security in ["tls", "reality", "xtls"] or protocol == "trojan":
            tls_counter[0] += 1
        else:
            non_tls_counter[0] += 1
       
        target_address = clean_addresses[ip_counter[0] % len(clean_addresses)] if clean_addresses else host_port.split(':')[0]
        ip_counter[0] += 1
       
        outbound = {"protocol": protocol, "settings": {}, "streamSettings": {"network": params.get("type", "tcp"), "security": "tls" if security in ["tls", "reality", "xtls"] else "none"}}
       
        if protocol == "vless":
            outbound["settings"] = {"vnext": [{"address": target_address, "port": final_port, "users": [{"id": userinfo, "encryption": params.get("encryption", "none"), "level": 8}]}]}
        elif protocol == "trojan":
            outbound["settings"] = {"servers": [{"address": target_address, "port": final_port, "password": userinfo, "level": 8}]}
       
        if "ws" in params.get("type", ""):
            outbound["streamSettings"]["wsSettings"] = {"host": params.get("host", ""), "path": params.get("path", "")}
       
        return outbound, security in ["tls", "reality", "xtls"]
    except Exception as e:
        print(f"Error parsing {protocol}: {e}")
        return None, False

def clean_dns_address(srv_str, prefix):
    clean = srv_str.replace(prefix, "").replace("//", "").strip()
    return clean.split(":")[0] if not (clean.startswith("[") and "]" in clean) else clean.split("]")[0] + "]"

def get_identity_key(srv):
    for prefix in ["tcp:", "udp:", "quic:", "https:"]:
        if srv.startswith(prefix):
            srv = srv.replace(prefix, "").replace("//", "").strip()
    domain = srv.replace("[", "").replace("]", "").split(':')[0].split('/')[0]
    try:
        ipaddress.ip_address(domain)
        return domain
    except ValueError:
        parts = domain.split('.')
        return ".".join(parts[-2:]) if len(parts) >= 2 else domain

def parse_dns_source(pool):
    paired = []
    i = 0
    while i < len(pool):
        item = pool[i].strip()
        if not item:
            i += 1
            continue
        if item.startswith(("https://", "tcp:", "quic:", "udp:")) or re.match(r'^\d', item) or item.startswith("["):
            server_url = item
            ip_address = None
            if i + 1 < len(pool) and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', pool[i+1].strip()):
                ip_address = pool[i+1].strip()
                i += 1
            paired.append({"server": server_url, "ip": ip_address or server_url})
        i += 1
    return paired

def build_bpb_fragment_template(base_node, clean_addresses):
    vnext = base_node["settings"]["vnext"][0]
    stream = base_node["streamSettings"]
    addr = random.choice(clean_addresses) if clean_addresses else vnext["address"]
    return {
        "remarks": "🌵 8 VLESS - Fragment 🔥",
        "dns": {"hosts": {"domain:googleapis.cn": "googleapis.com"}, "servers": ["8.8.8.8"]},
        "inbounds": [
            {"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "userLevel": 8}, "tag": "socks"},
            {"listen": "127.0.0.1", "port": 10809, "protocol": "http", "settings": {"userLevel": 8}, "tag": "http"}
        ],
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {"fragment": {"interval": "1-3", "length": "5-10", "packets": "tlshello"}, "vnext": [{"address": addr, "port": vnext["port"], "users": [{"id": vnext["users"][0]["id"], "encryption": "none", "level": 8}]}]},
                "streamSettings": {
                    "network": stream.get("network", "ws"),
                    "security": "tls",
                    "tlsSettings": {"fingerprint": "chrome", "serverName": stream.get("tlsSettings", {}).get("serverName", "")},
                    "wsSettings": {"path": "/?ed=2560"},
                    "sockopt": {"dialerProxy": "fragment"}
                },
                "tag": "proxy"
            },
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"}
        ]
    }

def build_dedicated_tls_ai_template(vless_tls_nodes, clean_addresses):
    outbounds = []
    shuffled = copy.deepcopy(vless_tls_nodes)
    random.shuffle(shuffled)
    for idx, node in enumerate(shuffled):
        vnext = node["settings"]["vnext"][0]
        addr = random.choice(clean_addresses) if clean_addresses else vnext["address"]
        outbounds.append({
            "protocol": "vless",
            "settings": {"vnext": [{"address": addr, "port": vnext["port"], "users": [{"id": vnext["users"][0]["id"], "level": 8}]}]},
            "streamSettings": node["streamSettings"],
            "tag": f"prox-{idx + 1}"
        })
    outbounds.extend([{"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "block"}])
    return {"remarks": "🌴 2 VLESS - TLS AI 🤖", "outbounds": outbounds, "dns": {"servers": ["8.8.8.8"]}, "inbounds": [{"port": 10808, "protocol": "socks", "tag": "socks"}]}

def build_dedicated_n_tls_ai_template(vless_ntls_nodes, clean_addresses):
    outbounds = []
    shuffled = copy.deepcopy(vless_ntls_nodes)
    random.shuffle(shuffled)
    for idx, node in enumerate(shuffled):
        vnext = node["settings"]["vnext"][0]
        addr = random.choice(clean_addresses) if clean_addresses else vnext["address"]
        outbounds.append({
            "protocol": "vless",
            "settings": {"vnext": [{"address": addr, "port": vnext["port"], "users": [{"id": vnext["users"][0]["id"], "level": 8}]}]},
            "streamSettings": node["streamSettings"],
            "tag": f"prox-{idx + 1}"
        })
    outbounds.extend([{"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "block"}])
    return {"remarks": "☘️ 4 VLESS - Non-TLS AI 🤖", "outbounds": outbounds, "dns": {"servers": ["8.8.8.8"]}, "inbounds": [{"port": 10808, "protocol": "socks", "tag": "socks"}]}

def build_v2rayng_template(remarks, outbound_nodes, pool_top_dns, pool_main_dns, clean_addresses=None, is_cloudflare=True):
    modified = copy.deepcopy(outbound_nodes)
    if clean_addresses and is_cloudflare:
        for node in modified:
            if "vnext" in node.get("settings", {}):
                node["settings"]["vnext"][0]["address"] = random.choice(clean_addresses)
            elif "servers" in node.get("settings", {}):
                node["settings"]["servers"][0]["address"] = random.choice(clean_addresses)

    for node in modified:
        node.pop("_original_address", None)

    base_outbounds = modified + [
        {"protocol": "dns", "tag": "dns-out"},
        {"protocol": "freedom", "tag": "direct"},
        {"protocol": "blackhole", "tag": "block"}
    ]

    pairs_top = parse_dns_source(pool_top_dns)
    pairs_main = parse_dns_source(pool_main_dns)

    doh_top = [p for p in pairs_top if p["server"].startswith("https://")]
    doh_main = [p for p in pairs_main if p["server"].startswith("https://")]

    chosen_providers = [None] * 5
    seen = set()

    # remote-dns-1: Only DoH from DNS-TOP.txt
    random.shuffle(doh_top)
    for p in doh_top:
        key = get_identity_key(p["server"])
        if key not in seen:
            seen.add(key)
            chosen_providers[0] = p
            break

    # remote-dns-2: Only DoH from DNS.txt
    random.shuffle(doh_main)
    for p in doh_main:
        key = get_identity_key(p["server"])
        if key not in seen:
            seen.add(key)
            chosen_providers[1] = p
            break

    # remote-dns-3,4,5: Any non-raw-IP from both lists
    non_ip = [p for p in pairs_top + pairs_main if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', p["server"].strip()) and not p["server"].strip().startswith("[")]
    random.shuffle(non_ip)
    slots = [2, 3, 4]
    for p in non_ip:
        if not slots:
            break
        key = get_identity_key(p["server"])
        if key not in seen:
            seen.add(key)
            chosen_providers[slots.pop(0)] = p

    # Fallback
    fallback = [{"server": "https://dns.google/dns-query", "ip": "8.8.8.8"}]
    for i in range(5):
        if chosen_providers[i] is None:
            chosen_providers[i] = fallback[0]

    dns_config = []
    tags = []
    for i, p in enumerate(chosen_providers, 1):
        tag = f"remote-dns-{i}"
        tags.append(tag)
        srv = p["server"]
        if srv.startswith("https://"):
            dns_config.append({"address": srv, "tag": tag})
        elif srv.startswith("tcp:"):
            dns_config.append({"address": f"tcp:{clean_dns_address(srv, 'tcp:')}", "port": 853, "tag": tag})
        else:
            dns_config.append({"address": srv, "tag": tag})

    return {
        "remarks": remarks,
        "log": {"loglevel": "warning"},
        "dns": {"servers": dns_config, "tag": "dns"},
        "inbounds": [
            {"port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True}, "tag": "socks-in"}
        ],
        "outbounds": base_outbounds,
        "routing": {
            "rules": [
                {"inboundTag": tags, "balancerTag": "all", "type": "field"},
                {"domain": ["geosite:category-ir"], "outboundTag": "direct"},
                {"ip": ["geoip:ir"], "outboundTag": "direct"}
            ],
            "balancers": [{"tag": "all", "selector": ["prox"], "strategy": {"type": "leastPing"}}]
        }
    }

def main():
    input_file = "Configs.txt"
    output_file = "NG-JSON-Configs.txt"

    if not os.path.exists(input_file):
        print(f"❌ {input_file} not found.")
        return

    clean_addresses = fetch_clean_addresses(CLEAN_IPS_URL)
    pool_top = fetch_remote_dns(DNS_TOP_URL)
    pool_main = fetch_remote_dns(DNS_MAIN_URL)

    tls_c = [0]
    ntls_c = [0]
    ip_c = [0]

    groups = {"vless_tls": [], "vless_n_tls": [], "trojan_tls": [], "trojan_n_tls": [], "vmess_tls": [], "vmess_n_tls": [], "other_protocols": []}

    with open(input_file, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    random.shuffle(lines)

    for line in lines:
        node = None
        is_tls = False
        if line.startswith("vmess://"):
            node, is_tls = parse_vmess(line, tls_c, ntls_c)
            key = "vmess_tls" if is_tls else "vmess_n_tls"
        elif line.startswith("vless://"):
            node, is_tls = parse_standard_uri(line, "vless", tls_c, ntls_c, clean_addresses, ip_c)
            key = "vless_tls" if is_tls else "vless_n_tls"
        elif line.startswith("trojan://"):
            node, is_tls = parse_standard_uri(line, "trojan", tls_c, ntls_c, clean_addresses, ip_c)
            key = "trojan_tls" if is_tls else "trojan_n_tls"
        elif "://" in line:
            proto = line.split("://")[0].lower()
            node, is_tls = parse_standard_uri(line, proto, tls_c, ntls_c, clean_addresses, ip_c)
            key = "other_protocols"
        if node:
            groups[key].append(node)

    final_output = []

    if groups["vless_tls"]:
        for i, n in enumerate(groups["vless_tls"]):
            n["tag"] = f"prox-{i+1}"
        final_output.append(build_v2rayng_template("🌴 1 VLESS - TLS LB 🔥", groups["vless_tls"], pool_top, pool_main, clean_addresses))
        final_output.append(build_dedicated_tls_ai_template(groups["vless_tls"], clean_addresses))

    if groups["vless_n_tls"]:
        for i, n in enumerate(groups["vless_n_tls"]):
            n["tag"] = f"prox-{i+1}"
        final_output.append(build_v2rayng_template("☘️ 3 VLESS - Non-TLS LB 🔥", groups["vless_n_tls"], pool_top, pool_main, clean_addresses))
        final_output.append(build_dedicated_n_tls_ai_template(groups["vless_n_tls"], clean_addresses))

    # Add other groups as before...
    if groups["trojan_tls"]:
        for i, n in enumerate(groups["trojan_tls"]):
            n["tag"] = f"prox-{i+1}"
        final_output.append(build_v2rayng_template("🌳 5 TROJAN - TLS LB 🔥", groups["trojan_tls"], pool_top, pool_main, clean_addresses))

    if groups["trojan_n_tls"]:
        for i, n in enumerate(groups["trojan_n_tls"]):
            n["tag"] = f"prox-{i+1}"
        final_output.append(build_v2rayng_template("🌳 6 TROJAN - Non-TLS LB 🔥", groups["trojan_n_tls"], pool_top, pool_main, clean_addresses))

    if groups["vmess_tls"]:
        for i, n in enumerate(groups["vmess_tls"]):
            n["tag"] = f"prox-{i+1}"
        final_output.append(build_v2rayng_template("🍀 7 VMESS - TLS LB 🔥", groups["vmess_tls"], pool_top, pool_main, clean_addresses, is_cloudflare=False))

    if groups["vless_tls"]:
        final_output.append(build_bpb_fragment_template(random.choice(groups["vless_tls"]), clean_addresses))

    if groups["other_protocols"]:
        for i, n in enumerate(groups["other_protocols"]):
            n["tag"] = f"prox-{i+1}"
        final_output.append(build_v2rayng_template("🌳 OTHER PROTOCOLS LB 🔥", groups["other_protocols"], pool_top, pool_main, clean_addresses, is_cloudflare=False))

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(final_output, f, indent=2, ensure_ascii=False)

    print(f"🎉 Successfully generated {output_file} with {len(final_output)} configs.")

if __name__ == "__main__":
    main()
