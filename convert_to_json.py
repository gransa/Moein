import os
import json
import base64
import ipaddress
import re
import urllib.request
from urllib.parse import urlparse, unquote, parse_qs

# Cloudflare clear distinct port definitions
TLS_PORTS = [443, 2053, 2083, 2087, 2096, 8443]
NON_TLS_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095]

# URL for your clean Cloudflare IPs/Domains
CLEAN_IPS_URL = "https://raw.githubusercontent.com/gransa/Moein/refs/heads/main/Cloudflare-IPs.txt"

def fetch_clean_addresses(url):
    """
    Fetches clean IPs/Domains from the remote repository.
    Falls back to an empty list if the request fails.
    """
    try:
        print(f"📡 Fetching clean endpoints from: {url}")
        req = urllib.request.Request(
            url, 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8')
            
        addresses = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            clean_addr = line.split("#")[0].split("//")[0].strip()
            if clean_addr:
                addresses.append(clean_addr)
                
        print(f"✅ Successfully loaded {len(addresses)} clean endpoints.")
        return addresses
    except Exception as e:
        print(f"⚠️ Warning: Could not fetch remote clean endpoints ({e}). Using link defaults.")
        return []

def extract_explicit_port(url_str):
    match = re.search(r':([0-9]{2,5})(?:\?|#|$)', url_str)
    if match:
        return int(match.group(1))
    return None

def parse_vmess(url_str, tls_counter=[0], non_tls_counter=[0]):
    try:
        b64_data = url_str.replace("vmess://", "").strip()
        b64_data += "=" * ((4 - len(b64_data) % 4) % 4)
        decoded = base64.b64decode(b64_data).decode('utf-8')
        config = json.loads(decoded)
        
        is_tls = str(config.get("tls", "")).lower() in ["tls", "1", "true"]
        net_type = config.get("net", "tcp")
        fp_val = config.get("fp", "chrome")
        
        explicit_port = config.get("port")
        
        if explicit_port and str(explicit_port).isdigit():
            final_port = int(explicit_port)
        else:
            if is_tls:
                final_port = TLS_PORTS[tls_counter[0] % len(TLS_PORTS)]
                tls_counter[0] += 1
            else:
                final_port = NON_TLS_PORTS[non_tls_counter[0] % len(NON_TLS_PORTS)]
                non_tls_counter[0] += 1
            
        target_address = config.get("add")
            
        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [
                    {
                        "address": target_address,
                        "port": final_port,
                        "users": [
                            {
                                "id": config.get("id"),
                                "alterId": int(config.get("aid", 0)),
                                "security": "auto",
                                "level": 8
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "network": net_type,
                "security": "tls" if is_tls else "none"
            }
        }
        
        if net_type == "ws":
            outbound["streamSettings"]["wsSettings"] = {
                "host": config.get("host", ""),
                "path": config.get("path", "")
            }
        elif net_type == "kcp":
            outbound["streamSettings"]["kcpSettings"] = {"header": {"type": config.get("type", "none")}}
            
        if is_tls:
            # Look up the original fingerprint keys natively. If missing, default strictly to ""
            pcs_value = config.get("pcs", config.get("pinnedPeerCertSha256", ""))
            
            outbound["streamSettings"]["tlsSettings"] = {
                "allowInsecure": False,
                "fingerprint": fp_val,
                "pinnedPeerCertSha256": str(pcs_value).strip() if pcs_value else "",
                "serverName": config.get("host", config.get("add")),
                "show": False
            }
            
        return outbound, is_tls
    except Exception as e:
        print(f"Error filtering VMESS format schema: {e}")
        return None, False

def parse_standard_uri(url_str, protocol, tls_counter=[0], non_tls_counter=[0], clean_addresses=[], ip_counter=[0]):
    try:
        parsed_url = urlparse(url_str)
        userinfo = parsed_url.username or parsed_url.netloc.split('@')[0]
        host_port = parsed_url.netloc.split('@')[-1]
        
        query = parse_qs(parsed_url.query)
        params = {k: v[0] for k, v in query.items()}
        
        security = params.get("security", "").lower()
        explicit_port = extract_explicit_port(url_str)
        
        if explicit_port is not None:
            final_port = explicit_port
            original_address = host_port.split(':')[0] if ':' in host_port else host_port
        else:
            original_address = host_port
            final_port = None

        if protocol == "trojan":
            if security == "none" or (final_port in NON_TLS_PORTS):
                is_tls = False
            else:
                is_tls = True
        else:
            is_tls = security in ["tls", "reality", "xtls"]

        if final_port is None:
            if is_tls:
                final_port = TLS_PORTS[tls_counter[0] % len(TLS_PORTS)]
                tls_counter[0] += 1
            else:
                final_port = NON_TLS_PORTS[non_tls_counter[0] % len(NON_TLS_PORTS)]
                non_tls_counter[0] += 1
        
        if clean_addresses:
            target_address = clean_addresses[ip_counter[0] % len(clean_addresses)]
            ip_counter[0] += 1
        else:
            target_address = original_address
            
        net_type = params.get("type", "tcp")
        fp_val = params.get("fp", "chrome")
        cert_hash = params.get("pcs", params.get("pinnedPeerCertSha256", params.get("certfp", params.get("sha256", ""))))
        
        outbound = {
            "protocol": protocol,
            "settings": {}
        }
        
        if protocol == "vless":
            outbound["settings"] = {
                "vnext": [{
                    "address": target_address,
                    "port": final_port,
                    "users": [{
                        "id": userinfo,
                        "encryption": params.get("encryption", "none"),
                        "level": 8
                    }]
                }]
            }
        elif protocol == "trojan":
            outbound["settings"] = {
                "servers": [{
                    "address": target_address,
                    "port": final_port,
                    "password": userinfo,
                    "level": 8
                }]
            }
        else:
            outbound["settings"] = {"servers": [{"address": target_address, "port": final_port}]}
            
        outbound["streamSettings"] = {
            "network": net_type,
            "security": "tls" if is_tls else "none",
            "sockopt": {
                "domainStrategy": "UseIPv4v6"
            }
        }
        
        if net_type == "ws":
            outbound["streamSettings"]["wsSettings"] = {
                "host": params.get("host", ""),
                "path": params.get("path", "")
            }
            
        if is_tls:
            tls_type = "realitySettings" if security == "reality" else "tlsSettings"
            outbound["streamSettings"][tls_type] = {
                "allowInsecure": False,
                "fingerprint": fp_val,
                "pinnedPeerCertSha256": cert_hash if cert_hash else "",
                "serverName": params.get("sni", original_address),
                "show": False
            }
            if protocol == "trojan" and "alpn" in params:
                outbound["streamSettings"][tls_type]["alpn"] = [params["alpn"]]
                
        return outbound, is_tls
    except Exception as e:
        print(f"Error filtering structural schema configurations for {protocol}: {e}")
        return None, False

def build_v2rayng_template(remarks, outbound_nodes):
    base_outbounds = list(outbound_nodes)
    base_outbounds.extend([
        {"protocol": "dns", "tag": "dns-out"},
        {"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}, "tag": "direct"},
        {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}
    ])
    
    extracted_domains = []
    for node in outbound_nodes:
        addr = None
        settings = node.get("settings", {})
        
        if "vnext" in settings and settings["vnext"]:
            addr = settings["vnext"][0].get("address")
        elif "servers" in settings and settings["servers"]:
            addr = settings["servers"][0].get("address")
            
        if addr:
            try:
                ipaddress.ip_address(addr)
            except ValueError:
                domain_entry = f"full:{addr}"
                if domain_entry not in extracted_domains:
                    extracted_domains.append(domain_entry)
                    
    return {
        "remarks": remarks,
        "log": {"loglevel": "warning"},
        "dns": {
            "servers": [
                {"address": "https://8.8.8.8/dns-query", "tag": "remote-dns"},
                {"address": "8.8.8.8", "domains": ["geosite:category-ir"], "expectIPs": ["geoip:ir"], "skipFallback": True},
                {"address": "8.8.8.8", "domains": extracted_domains, "skipFallback": True}
            ],
            "queryStrategy": "UseIP",
            "tag": "dns"
        },
        "inbounds": [
            {"port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "userLevel": 8}, "sniffing": {"destOverride": ["http", "tls"], "enabled": False, "routeOnly": False}, "tag": "socks-in"},
            {"port": 10853, "protocol": "dokodemo-door", "settings": {"address": "1.1.1.1", "network": "tcp,udp", "port": 53}, "tag": "dns-in"}
        ],
        "outbounds": base_outbounds,
        "policy": {
            "levels": {"8": {"connIdle": 300, "downlinkOnly": 1, "handshake": 4, "uplinkOnly": 1}},
            "system": {"statsOutboundUplink": True, "statsOutboundDownlink": True}
        },
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"inboundTag": ["dns-in"], "outboundTag": "dns-out", "type": "field"},
                {"inboundTag": ["socks-in"], "port": 53, "outboundTag": "dns-out", "type": "field"},
                {"inboundTag": ["remote-dns"], "balancerTag": "all", "type": "field"},
                {"inboundTag": ["dns"], "outboundTag": "direct", "type": "field"},
                {"domain": ["geosite:category-ir"], "outboundTag": "direct", "type": "field"},
                {"ip": ["geoip:ir"], "outboundTag": "direct", "type": "field"},
                {"network": "udp", "outboundTag": "block", "type": "field"},
                {"network": "tcp", "balancerTag": "all", "type": "field"}
            ],
            "balancers": [
                {
                    "tag": "all",
                    "selector": ["prox"],
                    "strategy": {"type": "leastPing"},
                    "fallbackTag": "prox-1" if len(outbound_nodes) > 0 else "direct"
                }
            ]
        },
        "stats": {},
        "observatory": {
            "subjectSelector": ["prox"],
            "probeUrl": "https://www.gstatic.com/generate_204",
            "probeInterval": "30s",
            "enableConcurrency": True
        }
    }

def main():
    input_file = "Configs.txt"
    output_file = "NG-JSON-Configs.txt"
    
    if not os.path.exists(input_file):
        print(f"Source file {input_file} not found.")
        return

    clean_addresses = fetch_clean_addresses(CLEAN_IPS_URL)

    tls_counter = [0]
    non_tls_counter = [0]
    ip_counter = [0]

    groups = {
        "vless_tls": [], "vless_n_tls": [],
        "trojan_tls": [], "trojan_n_tls": [],
        "vmess_tls": [], "vmess_n_tls": [],
        "other_protocols": []
    }
    
    with open(input_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
        
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        node_data = None
        is_tls = False
        proto_key = None
        
        if line.startswith("vmess://"):
            node_data, is_tls = parse_vmess(line, tls_counter, non_tls_counter)
            proto_key = "vmess_tls" if is_tls else "vmess_n_tls"
        elif line.startswith("vless://"):
            node_data, is_tls = parse_standard_uri(line, "vless", tls_counter, non_tls_counter, clean_addresses, ip_counter)
            proto_key = "vless_tls" if is_tls else "vless_n_tls"
        elif line.startswith("trojan://"):
            node_data, is_tls = parse_standard_uri(line, "trojan", tls_counter, non_tls_counter, clean_addresses, ip_counter)
            proto_key = "trojan_tls" if is_tls else "trojan_n_tls"
        elif "://" in line:
            p_name = line.split("://")[0].lower()
            node_data, is_tls = parse_standard_uri(line, p_name, tls_counter, non_tls_counter, clean_addresses, ip_counter)
            proto_key = "other_protocols"
            
        if node_data and proto_key:
            node_data["tag"] = f"prox-{len(groups[proto_key]) + 1}"
            groups[proto_key].append(node_data)
                
    final_output = []
    
    mapping = [
        ("🌳 VLESS - TLS LB 🔥", "vless_tls"),
        ("🌳 TROJAN - TLS LB 🔥", "trojan_tls"),
        ("🌳 VMESS - TLS LB 🔥", "vmess_tls"),
        ("🌳 VLESS - Non-TLS LB 🔥", "vless_n_tls"),
        ("🌳 TROJAN - Non-TLS LB 🔥", "trojan_n_tls"),
        ("🌳 VMESS - Non-TLS LB 🔥", "vmess_n_tls"),
        ("🌳 OTHER PROTOCOLS LB 🔥", "other_protocols")
    ]
    
    for remark, key in mapping:
        if groups[key]:
            final_output.append(build_v2rayng_template(remark, groups[key]))
            
    with open(output_file, "w", encoding="utf-8") as out:
        json.dump(final_output, out, indent=2, ensure_ascii=False)
        
    print(f"🎉 Compiled cleanly into single layout destination: '{output_file}'")

if __name__ == "__main__":
    main()
