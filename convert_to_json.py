import os
import json
import base64
import ipaddress
import re
import urllib.request
import random
import copy
from urllib.parse import urlparse, unquote, parse_qs

# Configuration URLs
CLEAN_IPS_URL = "https://raw.githubusercontent.com/gransa/Moein/refs/heads/main/Cloudflare-IPs.txt"
DNS_TOP_URL = "https://raw.githubusercontent.com/gransa/Moein/refs/heads/main/DNS-TOP.txt"
DNS_MAIN_URL = "https://raw.githubusercontent.com/gransa/Moein/refs/heads/main/DNS.txt"

# Cloudflare clear distinct port definitions
TLS_PORTS = [443, 2053, 2083, 2087, 2096, 8443]
NON_TLS_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095]

def fetch_clean_addresses(url):
    """Fetches clean IPs/Domains from the remote repository."""
    try:
        print(f"📡 Fetching clean endpoints from: {url}")
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8')
        addresses = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "//")):
                continue
            clean_addr = line.split("#")[0].split("//")[0].strip()
            if clean_addr:
                addresses.append(clean_addr)
        print(f"✅ Successfully loaded {len(addresses)} clean endpoints.")
        return addresses
    except Exception as e:
        print(f"⚠️ Warning: Could not fetch remote clean endpoints ({e}). Using link defaults.")
        return []

def fetch_remote_dns(url):
    """Fetches list of DoH / DoT / DoQ / UDP entries from remote repository."""
    try:
        print(f"📡 Fetching remote DNS from: {url}")
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8')
        dns_list = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "//")):
                continue
            dns_list.append(line)
        print(f"✅ Successfully loaded {len(dns_list)} DNS lines.")
        return dns_list
    except Exception as e:
        print(f"⚠️ Warning: Could not fetch remote DNS from {url} ({e}).")
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
                "vnext": [{
                    "address": target_address,
                    "port": final_port,
                    "users": [{
                        "id": config.get("id"),
                        "alterId": int(config.get("aid", 0)),
                        "security": "auto",
                        "level": 8
                    }]
                }]
            },
            "streamSettings": {"network": net_type, "security": "tls" if is_tls else "none"}
        }
        
        if net_type == "ws":
            outbound["streamSettings"]["wsSettings"] = {"host": config.get("host", ""), "path": config.get("path", "")}
        elif net_type == "kcp":
            outbound["streamSettings"]["kcpSettings"] = {"header": {"type": config.get("type", "none")}}
            
        if is_tls:
            pcs_value = config.get("pcs", config.get("pinnedPeerCertSha256", ""))
            if str(pcs_value).strip().upper() == "EDB3FE2BF8BCE4A7CE51CC7D619BA261B5AB600832748B9AF68738AE6D52AB5D":
                pcs_value = ""
            
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
            is_tls = not (security == "none" or (final_port in NON_TLS_PORTS))
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
        
        outbound = {"protocol": protocol, "settings": {}}
        if protocol == "vless":
            outbound["settings"] = {
                "vnext": [{
                    "address": target_address,
                    "port": final_port,
                    "users": [{"id": userinfo, "encryption": params.get("encryption", "none"), "level": 8}]
                }]
            }
        elif protocol == "trojan":
            outbound["settings"] = {
                "servers": [{"address": target_address, "port": final_port, "password": userinfo, "level": 8}]
            }
        else:
            outbound["settings"] = {"servers": [{"address": target_address, "port": final_port}]}
            
        outbound["streamSettings"] = {
            "network": net_type, "security": "tls" if is_tls else "none",
            "sockopt": {"domainStrategy": "UseIPv4v6"}
        }
        
        outbound["_original_address"] = original_address
        
        if net_type == "ws":
            outbound["streamSettings"]["wsSettings"] = {"host": params.get("host", ""), "path": params.get("path", "")}
            
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

def clean_dns_address(srv_str, prefix):
    """Strips prefixes, leading slashes, and trailing ports perfectly."""
    clean = srv_str.replace(prefix, "").replace("//", "").strip()
    if clean.startswith("[") and "]" in clean:
        parts = clean.split("]")
        return parts[0] + "]"
    return clean.split(":")[0]

def get_identity_key(srv):
    """Extracts base registration domain string for unique identifier matching."""
    try:
        if srv.startswith("https://"):
            domain = urlparse(srv).netloc
        elif srv.startswith("tcp:"):
            domain = clean_dns_address(srv, "tcp:")
        elif srv.startswith("quic:"):
            domain = clean_dns_address(srv, "quic:")
        elif srv.startswith("udp:"):
            domain = clean_dns_address(srv, "udp:")
        else:
            domain = srv
        domain_parts = domain.replace("[", "").replace("]", "").split('.')
        return ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain
    except Exception:
        return srv

def parse_dns_source(pool_dns_servers):
    """Converts text lines into paired dictionary groupings, providing safe dummy routing IPs for standalone links."""
    paired = []
    i = 0
    while i < len(pool_dns_servers):
        item = pool_dns_servers[i].strip()
        if not item:
            i += 1
            continue

        if item.startswith("https://") or item.startswith("tcp:") or item.startswith("quic:") or item.startswith("udp:"):
            server_url = item
            ip_address = None
            
            if i + 1 < len(pool_dns_servers):
                next_item = pool_dns_servers[i + 1].strip()
                if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', next_item):
                    ip_address = next_item
                    i += 1
            
            if not ip_address:
                if "quad9" in server_url:
                    ip_address = "9.9.9.9"
                elif "adguard" in server_url:
                    ip_address = "94.140.14.14"
                elif "opendns" in server_url:
                    ip_address = "208.67.222.222"
                else:
                    ip_address = "9.9.9.9"
                    
            paired.append({"server": server_url, "ip": ip_address})
        i += 1
    return paired

def build_bpb_fragment_template(base_vless_tls_node, clean_addresses):
    """Constructs the standalone template (☘️ 4 - BPB - Fragment 🔥)."""
    vnext_info = base_vless_tls_node["settings"]["vnext"][0]
    stream_info = base_vless_tls_node["streamSettings"]
    
    node_address = random.choice(clean_addresses) if clean_addresses else vnext_info["address"]
    node_port = vnext_info["port"]
    user_id = vnext_info["users"][0]["id"]
    
    network_type = stream_info.get("network", "ws")
    security_type = stream_info.get("security", "tls")
    
    tls_settings = stream_info.get("tlsSettings", {})
    ws_settings = stream_info.get("wsSettings", {})
    
    fingerprint_val = tls_settings.get("fingerprint", "chrome")
    sni_server_name = tls_settings.get("serverName", "")
    cert_fingerprint = tls_settings.get("pinnedPeerCertSha256", "")
    
    ws_host = ws_settings.get("host", sni_server_name)
    ws_path = ws_settings.get("path", "/?ed=2560")

    return {
        "remarks": "☘️ 4 - BPB - Fragment 🔥",
        "dns": {
            "hosts": {"domain:googleapis.cn": "googleapis.com"},
            "servers": ["8.8.8.8"]
        },
        "inbounds": [
            {"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "userLevel": 8}, "sniffing": {"destOverride": [], "enabled": False}, "tag": "socks"},
            {"listen": "127.0.0.1", "port": 10809, "protocol": "http", "settings": {"userLevel": 8}, "tag": "http"}
        ],
        "log": {"access": "none", "loglevel": "warning"},
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {
                    "fragment": {"interval": "1-3", "length": "5-10", "packets": "tlshello", "status": "ON for TLS"},
                    "vnext": [{"address": node_address, "port": node_port, "users": [{"encryption": "none", "flow": "", "id": user_id, "level": 8, "security": "auto"}]}]
                },
                "streamSettings": {
                    "network": network_type, "security": security_type,
                    "tlsSettings": {"allowInsecure": False, "echConfigList": "", "echForceQuery": "", "echServerKeys": "", "fingerprint": fingerprint_val, "pinnedPeerCertSha256": cert_fingerprint, "publicKey": "", "serverName": sni_server_name, "shortId": "", "show": False, "spiderX": ""},
                    "wsSettings": {"headers": {"Host": ws_host}, "path": ws_path},
                    "sockopt": {"dialerProxy": "fragment", "tcpKeepAliveIdle": 100, "mark": 255}
                },
                "tag": "proxy"
            },
            {"protocol": "freedom", "settings": {}, "tag": "direct"},
            {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"},
            {"tag": "fragment", "protocol": "freedom", "settings": {"fragment": {"packets": "tlshello", "length": "5-10", "interval": "1-3"}}, "streamSettings": {"sockopt": {"TcpNoDelay": True, "tcpKeepAliveIdle": 100, "mark": 255}}}
        ],
        "policy": {
            "levels": {"8": {"connIdle": 300, "downlinkOnly": 1, "handshake": 4, "uplinkOnly": 1}},
            "system": {"statsOutboundUplink": True, "statsOutboundDownlink": True}
        },
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"ip": ["8.8.8.8"], "outboundTag": "proxy", "port": "53", "type": "field"},
                {"domain": ["domain:ir", "geosite:category-ir", "geosite:private"], "outboundTag": "direct", "type": "field"},
                {"ip": ["geoip:ir", "geoip:private"], "outboundTag": "direct", "type": "field"}
            ]
        },
        "stats": {}
    }

def build_dedicated_tls_ai_template(vless_tls_nodes, clean_addresses):
    """Generates a structural configuration completely filled with randomized VLESS TLS configs labeled sequentially from prox-1 to prox-N with explicit fingerprint pinning tracking."""
    outbounds = []
    
    shuffled_nodes = copy.deepcopy(vless_tls_nodes)
    random.shuffle(shuffled_nodes)
    
    for idx, node in enumerate(shuffled_nodes):
        vnext = node["settings"]["vnext"][0]
        stream = node["streamSettings"]
        tls_settings = stream.get("tlsSettings", {})
        ws_settings = stream.get("wsSettings", {})
        
        addr = random.choice(clean_addresses) if clean_addresses else vnext["address"]
        
        outbounds.append({
            "mux": {"concurrency": -1, "enabled": False},
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": addr,
                    "port": vnext["port"],
                    "users": [{"encryption": "none", "id": vnext["users"][0]["id"], "level": 8}]
                }]
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "fingerprint": tls_settings.get("fingerprint", "chrome"),
                    "pinnedPeerCertSha256": tls_settings.get("pinnedPeerCertSha256", ""), # FIX: Directly map cert fingerprint (pcs)
                    "serverName": tls_settings.get("serverName", ""),
                    "show": False
                },
                "wsSettings": {
                    "headers": {"Host": ws_settings.get("headers", {}).get("Host", tls_settings.get("serverName", ""))},
                    "path": ws_settings.get("path", "/?ed=2560")
                }
            },
            "tag": f"prox-{idx + 1}"
        })
        
    outbounds.extend([
        {"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}, "tag": "direct"},
        {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}
    ])

    return {
        "remarks": "🌴VLESS - TLS AI 🤖",
        "dns": {
            "hosts": {
                "domain:googleapis.cn": "googleapis.com",
                "tcp://8.8.8.8": ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
                "udp://1.1.1.1": ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
                "https://8.8.8.8/dns-query": ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
                "https://1.1.1.1/dns-query": ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001", "104.16.132.229", "104.16.133.229", "2606:4700::6810:84e5", "2606:4700::6810:85e5"],
                "https://9.9.9.9/dns-query": ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"]
            },
            "servers": [
                "https://8.8.8.8/dns-query",
                {"address": "78.157.42.100", "domains": ["geosite:openai", "geosite:microsoft", "geosite:oracle", "geosite:docker", "geosite:adobe", "geosite:epicgames", "geosite:intel", "geosite:amd", "geosite:nvidia", "geosite:asus", "geosite:hp", "geosite:lenovo"], "skipFallback": True},
                {"address": "78.157.42.101", "domains": ["geosite:openai", "geosite:microsoft", "geosite:oracle", "geosite:docker", "geosite:adobe", "geosite:epicgames", "geosite:intel", "geosite:amd", "geosite:nvidia", "geosite:asus", "geosite:hp", "geosite:lenovo"], "skipFallback": True}
            ],
            "tag": "dns-module"
        },
        "inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "userLevel": 8}, "sniffing": {"destOverride": ["fakedns"], "enabled": True, "routeOnly": False}, "tag": "socks"}],
        "log": {"loglevel": "warning"},
        "outbounds": outbounds,
        "policy": {
            "levels": {"8": {"connIdle": 300, "downlinkOnly": 1, "handshake": 4, "uplinkOnly": 1}},
            "system": {"statsOutboundUplink": True, "statsOutboundDownlink": True}
        },
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"inboundTag": ["domestic-dns"], "outboundTag": "direct", "type": "field"},
                {"inboundTag": ["dns-module"], "balancerTag": "all", "type": "field"},
                {"type": "field", "domain": ["geosite:openai", "geosite:microsoft", "geosite:oracle", "geosite:docker", "geosite:adobe", "geosite:epicgames", "geosite:intel", "geosite:amd", "geosite:nvidia", "geosite:asus", "geosite:hp", "geosite:lenovo"], "outboundTag": "direct"}
            ],
            "balancers": [{"tag": "all", "selector": ["prox"], "strategy": {"type": "leastPing"}, "fallbackTag": "prox-1"}]
        },
        "stats": {},
        "observatory": {"subjectSelector": ["prox"], "probeUrl": "https://www.gstatic.com/generate_204", "probeInterval": "30s", "enableConcurrency": True}
    }

def build_dedicated_n_tls_ai_template(vless_ntls_nodes, clean_addresses):
    """Generates a structural configuration completely filled with randomized VLESS Non-TLS configs labeled sequentially from prox-1 to prox-N."""
    outbounds = []
    
    shuffled_nodes = copy.deepcopy(vless_ntls_nodes)
    random.shuffle(shuffled_nodes)
    
    for idx, node in enumerate(shuffled_nodes):
        vnext = node["settings"]["vnext"][0]
        ws_settings = node["streamSettings"].get("wsSettings", {})
        
        addr = random.choice(clean_addresses) if clean_addresses else vnext["address"]
        
        extracted_host = ws_settings.get("host", "").strip()
        if not extracted_host:
            extracted_host = node.get("_original_address", "")
        
        outbounds.append({
            "mux": {"concurrency": -1, "enabled": False},
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": addr,
                    "port": vnext["port"],
                    "users": [{"encryption": "none", "flow": "", "id": vnext["users"][0]["id"], "level": 8}]
                }]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "headers": {"Host": extracted_host},
                    "path": ws_settings.get("path", "/?ed=2560")
                }
            },
            "tag": f"prox-{idx + 1}"
        })
        
    outbounds.extend([
        {"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}, "tag": "direct"},
        {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}
    ])

    return {
        "remarks": "🌴 VLESS - Non-TLS AI 🤖",
        "dns": {
            "hosts": {
                "domain:googleapis.cn": "googleapis.com",
                "tcp://8.8.8.8": ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
                "udp://1.1.1.1": ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
                "https://8.8.8.8/dns-query": ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
                "https://1.1.1.1/dns-query": ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001", "104.16.132.229", "104.16.133.229", "2606:4700::6810:84e5", "2606:4700::6810:85e5"],
                "https://9.9.9.9/dns-query": ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"]
            },
            "servers": [
                "https://8.8.8.8/dns-query",
                {"address": "78.157.42.100", "domains": ["geosite:openai", "geosite:microsoft", "geosite:oracle", "geosite:docker", "geosite:adobe", "geosite:epicgames", "geosite:intel", "geosite:amd", "geosite:nvidia", "geosite:asus", "geosite:hp", "geosite:lenovo"], "skipFallback": True},
                {"address": "78.157.42.101", "domains": ["geosite:openai", "geosite:microsoft", "geosite:oracle", "geosite:docker", "geosite:adobe", "geosite:epicgames", "geosite:intel", "geosite:amd", "geosite:nvidia", "geosite:asus", "geosite:hp", "geosite:lenovo"], "skipFallback": True}
            ],
            "tag": "dns-module"
        },
        "inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "userLevel": 8}, "sniffing": {"destOverride": ["fakedns"], "enabled": True, "routeOnly": False}, "tag": "socks"}],
        "log": {"loglevel": "warning"},
        "outbounds": outbounds,
        "policy": {
            "levels": {"8": {"connIdle": 300, "downlinkOnly": 1, "handshake": 4, "uplinkOnly": 1}},
            "system": {"statsOutboundUplink": True, "statsOutboundDownlink": True}
        },
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"inboundTag": ["domestic-dns"], "outboundTag": "direct", "type": "field"},
                {"inboundTag": ["dns-module"], "balancerTag": "all", "type": "field"},
                {"type": "field", "domain": ["geosite:openai", "geosite:microsoft", "geosite:oracle", "geosite:docker", "geosite:adobe", "geosite:epicgames", "geosite:intel", "geosite:amd", "geosite:nvidia", "geosite:asus", "geosite:hp", "geosite:lenovo"], "outboundTag": "direct"}
            ],
            "balancers": [{"tag": "all", "selector": ["prox"], "strategy": {"type": "leastPing"}, "fallbackTag": "prox-1"}]
        },
        "stats": {},
        "observatory": {"subjectSelector": ["prox"], "probeUrl": "https://www.gstatic.com/generate_204", "probeInterval": "30s", "enableConcurrency": True}
    }

def build_v2rayng_template(remarks, outbound_nodes, pool_top_dns, pool_main_dns):
    base_outbounds = list(outbound_nodes)
    base_outbounds.extend([
        {"protocol": "dns", "tag": "dns-out"},
        {"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}, "tag": "direct"},
        {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}
    ])
    
    fallback_providers = [
        {"server": "https://dns.quad9.net/dns-query", "ip": "9.9.9.9"},
        {"server": "https://dns.adguard-dns.com/dns-query", "ip": "94.140.14.14"},
        {"server": "https://doh.opendns.com/dns-query", "ip": "208.67.222.222"},
        {"server": "https://doh.cleanbrowsing.org/doh/security-filter", "ip": "185.228.168.9"}
    ]
    random.shuffle(fallback_providers)

    pairs_top = parse_dns_source(pool_top_dns)
    pairs_main = parse_dns_source(pool_main_dns)

    doh_top = [p for p in pairs_top if p["server"].startswith("https://")]
    doh_main = [p for p in pairs_main if p["server"].startswith("https://")]

    random.shuffle(doh_top)
    random.shuffle(doh_main)

    chosen_providers = []
    seen_identifiers = set()

    for provider in doh_top:
        ident = get_identity_key(provider["server"])
        seen_identifiers.add(ident)
        chosen_providers.append(provider)
        break

    if not chosen_providers:
        for fb in fallback_providers:
            if fb["server"].startswith("https://"):
                seen_identifiers.add(get_identity_key(fb["server"]))
                chosen_providers.append(fb)
                break

    for provider in doh_main:
        ident = get_identity_key(provider["server"])
        if ident not in seen_identifiers:
            seen_identifiers.add(ident)
            chosen_providers.append(provider)
            break

    if len(chosen_providers) < 2 and len(chosen_providers) == 1:
        for fb in fallback_providers:
            ident = get_identity_key(fb["server"])
            if fb["server"].startswith("https://") and ident not in seen_identifiers:
                seen_identifiers.add(ident)
                chosen_providers.append(fb)
                break

    remaining_top = [p for p in pairs_top if get_identity_key(p["server"]) not in seen_identifiers]
    remaining_main = [p for p in pairs_main if get_identity_key(p["server"]) not in seen_identifiers]
    
    combined_remaining = remaining_top + remaining_main
    random.shuffle(combined_remaining)

    for provider in combined_remaining:
        if len(chosen_providers) == 5:
            break
        ident = get_identity_key(provider["server"])
        if ident not in seen_identifiers:
            seen_identifiers.add(ident)
            chosen_providers.append(provider)

    if len(chosen_providers) < 5:
        for fb in fallback_providers:
            if len(chosen_providers) == 5:
                break
            ident = get_identity_key(fb["server"])
            if ident not in seen_identifiers:
                seen_identifiers.add(ident)
                chosen_providers.append(fb)

    dns_servers_config = []
    inbound_tags = []
    
    for i, provider in enumerate(chosen_providers, 1):
        tag_name = f"remote-dns-{i}"
        inbound_tags.append(tag_name)
        srv_address = provider["server"]
        
        if srv_address.startswith("tcp:"):
            clean_host = clean_dns_address(srv_address, "tcp:")
            dns_servers_config.append({"address": f"tcp:{clean_host}", "port": 853, "tag": tag_name})
        elif srv_address.startswith("quic:"):
            clean_host = clean_dns_address(srv_address, "quic:")
            dns_servers_config.append({"address": f"quic:{clean_host}", "port": 784, "tag": tag_name})
        elif srv_address.startswith("udp:"):
            clean_host = clean_dns_address(srv_address, "udp:")
            dns_servers_config.append({"address": clean_host, "port": 53, "tag": tag_name})
        else:
            dns_servers_config.append({"address": srv_address, "tag": tag_name})
        
    for provider in chosen_providers:
        dns_servers_config.append({
            "address": provider["ip"],
            "domains": ["geosite:category-ir"],
            "expectIPs": ["geoip:ir"],
            "skipFallback": False
        })
        
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
                    
    first_provider_ip = chosen_providers[0]["ip"] if chosen_providers else "9.9.9.9"
    for domain in extracted_domains:
        dns_servers_config.append({
            "address": first_provider_ip,
            "domains": [domain],
            "skipFallback": True
        })
                    
    return {
        "remarks": remarks,
        "log": {"loglevel": "warning"},
        "dns": {
            "servers": dns_servers_config,
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
                {"inboundTag": inbound_tags, "balancerTag": "all", "type": "field"},
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
    pool_top_dns = fetch_remote_dns(DNS_TOP_URL)
    pool_main_dns = fetch_remote_dns(DNS_MAIN_URL)

    tls_counter = [0]
    non_tls_counter = [0]
    ip_counter = [0]

    groups = {
        "vless_tls": [], "vless_n_tls": [], "trojan_tls": [], "trojan_n_tls": [],
        "vmess_tls": [], "vmess_n_tls": [], "other_protocols": []
    }
    
    with open(input_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
        
    random.shuffle(lines)
    print("🎲 Raw input lines have been successfully randomized.")

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
            groups[proto_key].append(node_data)
                
    final_output = []
    
    # Process original load balancers
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
            for idx, item in enumerate(groups[key]):
                item["tag"] = f"prox-{idx + 1}"
            final_output.append(build_v2rayng_template(remark, groups[key], pool_top_dns, pool_main_dns))
            
    # Dedicated Profile 1: Full VLESS TLS Collection
    if groups["vless_tls"]:
        final_output.append(build_dedicated_tls_ai_template(groups["vless_tls"], clean_addresses))
        print("✅ Embedded dedicated full collection profile: '🌴VLESS - TLS AI 🤖'")
        
    # Dedicated Profile 2: Full VLESS Non-TLS Collection
    if groups["vless_n_tls"]:
        final_output.append(build_dedicated_n_tls_ai_template(groups["vless_n_tls"], clean_addresses))
        print("✅ Embedded dedicated full collection profile: '🌴 VLESS - Non-TLS AI 🤖'")
            
    # Standalone Profile: BPB Fragment (☘️ 4 - BPB - Fragment 🔥)
    if groups["vless_tls"]:
        random_fragment_node = random.choice(groups["vless_tls"])
        final_output.append(build_bpb_fragment_template(random_fragment_node, clean_addresses))
        print("🎲 Randomly mixed dynamic Cloudflare IP into Fragment structure.")
            
    random.shuffle(final_output)
    print("🔀 Completely randomized config structural ordering inside final file.")

    with open(output_file, "w", encoding="utf-8") as out:
        json.dump(final_output, out, indent=2, ensure_ascii=False)
        
    print(f"🎉 Compiled cleanly into single layout destination: '{output_file}'")

if __name__ == "__main__":
    main()
