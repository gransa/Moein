import os
import json
import base64
import ipaddress
import re
import urllib.request
import random
import copy
import socket
from urllib.parse import urlparse, unquote, parse_qs

# Configuration URLs
CLEAN_IPS_URL = "https://raw.githubusercontent.com/gransa/Moein/refs/heads/main/Cloudflare-IPs.txt"
DNS_TOP_URL = "https://raw.githubusercontent.com/gransa/Moein/refs/heads/main/DNS-TOP.txt"
DNS_MAIN_URL = "https://raw.githubusercontent.com/gransa/Moein/refs/heads/main/DNS.txt"

# Cloudflare official IP range lists
CF_IPV4_RANGES_URL = "https://www.cloudflare.com/ips-v4"
CF_IPV6_RANGES_URL = "https://www.cloudflare.com/ips-v6"

TLS_PORTS = [443, 2053, 2083, 2087, 2096, 8443]
NON_TLS_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095]

CLOUDFLARE_NETWORKS = []

def fetch_cloudflare_ranges():
    global CLOUDFLARE_NETWORKS
    networks = []
    headers = {'User-Agent': 'Mozilla/5.0'}
    
    for url in [CF_IPV4_RANGES_URL, CF_IPV6_RANGES_URL]:
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as response:
                content = response.read().decode('utf-8')
                for line in content.splitlines():
                    line = line.strip()
                    if line:
                        networks.append(ipaddress.ip_network(line))
        except Exception as e:
            print(f"⚠️ Could not pull live CF subnets from {url} ({e})")
            
    if not networks:
        fallback_cidrs = ["103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", 
                          "172.64.0.0/13", "173.245.48.0/20", "190.93.240.0/20", "197.234.240.0/22", 
                          "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", 
                          "172.68.0.0/16", "131.0.72.0/22", "2400:cb00::/32", "2606:4700::/32"]
        networks = [ipaddress.ip_network(cidr) for cidr in fallback_cidrs]
        
    CLOUDFLARE_NETWORKS = networks

def is_cloudflare_node(outbound):
    if not isinstance(outbound, dict):
        return False
        
    orig_addr = outbound.get("_original_address", "")
    if not orig_addr:
        settings = outbound.get("settings", {})
        if "vnext" in settings and settings["vnext"]:
            orig_addr = settings["vnext"][0].get("address", "")
        elif "servers" in settings and settings["servers"]:
            orig_addr = settings["servers"][0].get("address", "")

    if not orig_addr:
        return False

    ws_settings = outbound.get("streamSettings", {}).get("wsSettings", {})
    if isinstance(ws_settings, dict):
        ws_host = ws_settings.get("headers", {}).get("Host", ws_settings.get("host", "")).lower()
        if "workers.dev" in ws_host or "cloudflare" in ws_host:
            return True

    resolved_ips = []
    try:
        ip_clean = orig_addr.replace("[", "").replace("]", "")
        ipaddress.ip_address(ip_clean)
        resolved_ips.append(ip_clean)
    except ValueError:
        resolved_ips = resolve_domain_to_ips(orig_addr)

    for ip_str in resolved_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for network in CLOUDFLARE_NETWORKS:
                if ip_obj in network:
                    return True
        except ValueError:
            continue
    return False

def resolve_domain_to_ips(domain_str):
    resolved_ips = []
    try:
        results = socket.getaddrinfo(domain_str, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in results:
            ip = sockaddr[0]
            if "%" in ip:
                ip = ip.split("%")[0]
            if ip not in resolved_ips:
                resolved_ips.append(ip)
    except socket.gaierror:
        pass
    return resolved_ips

def fetch_clean_addresses(url):
    try:
        print(f"📡 Fetching clean endpoints from: {url}")
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8')
        
        raw_entries = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "//")):
                continue
            clean_addr = line.split("#")[0].split("//")[0].strip()
            if clean_addr:
                raw_entries.append(clean_addr)
                
        final_ips = []
        for entry in raw_entries:
            try:
                ipaddress.ip_address(entry.replace("[", "").replace("]", ""))
                final_ips.append(entry)
            except ValueError:
                ips_from_dns = resolve_domain_to_ips(entry)
                if ips_from_dns:
                    final_ips.extend(ips_from_dns)
                else:
                    final_ips.append(entry)
                    
        return list(dict.fromkeys(final_ips))
    except Exception as e:
        print(f"⚠️ Warning: Could not fetch remote clean endpoints ({e}).")
        return []

def select_smart_ip(index, total_count, ips_v4, ips_v6, all_ips):
    """Returns an IP selecting the forced version rules cleanly."""
    v6_count = max(1, int(total_count * 0.20))
    v6_start_index = total_count - v6_count

    if index == 0 and ips_v4:
        selected_ip = random.choice(ips_v4)
    elif index >= v6_start_index and ips_v6:
        selected_ip = random.choice(ips_v6)
    else:
        selected_ip = random.choice(all_ips) if all_ips else "1.1.1.1"

    if ":" in selected_ip and not selected_ip.startswith("["):
        selected_ip = f"[{selected_ip}]"
    return selected_ip

def fetch_remote_dns(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8')
        return [line.strip() for line in content.splitlines() if line.strip() and not line.strip().startswith(("#", "//"))]
    except Exception:
        return []

def extract_explicit_port(url_str):
    match = re.search(r':([0-9]{2,5})(?:\?|#|$)', url_str)
    return int(match.group(1)) if match else None

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
                    "users": [{"id": config.get("id"), "alterId": int(config.get("aid", 0)), "security": "auto", "level": 8}]
                }]
            },
            "streamSettings": {"network": net_type, "security": "tls" if is_tls else "none"}
        }
        
        if net_type == "ws":
            outbound["streamSettings"]["wsSettings"] = {"host": config.get("host", ""), "path": config.get("path", "")}
        elif net_type == "kcp":
            outbound["streamSettings"]["kcpSettings"] = {"header": {"type": "none"}}
            
        if is_tls:
            pcs_value = config.get("pcs", config.get("pinnedPeerCertSha256", ""))
            if str(pcs_value).strip().upper() == "EDB3FE2BF8BCE4A7CE51CC7D619BA261B5AB600832748B9AF68738AE6D52AB5D":
                pcs_value = ""
            
            outbound["streamSettings"]["tlsSettings"] = {
                "allowInsecure": False, "fingerprint": fp_val,
                "pinnedPeerCertSha256": str(pcs_value).strip() if pcs_value else "",
                "serverName": config.get("host", config.get("add")), "show": False
            }
        
        outbound["_original_address"] = target_address
        return outbound, is_tls
    except Exception:
        return None, False

def parse_standard_uri(url_str, protocol, tls_counter=[0], non_tls_counter=[0]):
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
                "allowInsecure": False, "fingerprint": fp_val,
                "pinnedPeerCertSha256": cert_hash if cert_hash else "",
                "serverName": params.get("sni", original_address), "show": False
            }
            if protocol == "trojan" and "alpn" in params:
                outbound["streamSettings"][tls_type]["alpn"] = [params["alpn"]]
                
        return outbound, is_tls
    except Exception:
        return None, False

def clean_dns_address(srv_str, prefix):
    clean = srv_str.replace(prefix, "").replace("//", "").strip()
    if clean.startswith("[") and "]" in clean:
        return clean.split("]")[0] + "]"
    return clean.split(":")[0]

def get_identity_key(srv):
    try:
        for prefix in ["tcp:", "udp:", "quic:", "https:"]:
            if srv.startswith(prefix):
                srv = srv.replace(prefix, "").replace("//", "").strip()
        domain = srv.replace("[", "").replace("]", "").split(':')[0].split('/')[0]
        try:
            ipaddress.ip_address(domain)
            return domain
        except ValueError:
            pass
        domain_parts = domain.split('.')
        return ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain
    except Exception:
        return srv

def parse_dns_source(pool_dns_servers):
    paired = []
    i = 0
    while i < len(pool_dns_servers):
        item = pool_dns_servers[i].strip()
        if not item:
            i += 1
            continue

        if (item.startswith("https://") or item.startswith("tcp:") or item.startswith("quic:") or 
            item.startswith("udp:") or item.startswith("[") or re.match(r'^\d{1,3}(\.\d{1,3}){3}$', item)):
            
            server_url = item
            ip_address = None
            
            if i + 1 < len(pool_dns_servers):
                next_item = pool_dns_servers[i + 1].strip()
                if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', next_item) or (next_item.startswith("[") and next_item.endswith("]")):
                    ip_address = next_item
                    i += 1
            
            if not ip_address:
                lower_url = server_url.lower()
                if "quad9" in lower_url or "9.9.9.9" in lower_url:
                    ip_address = "9.9.9.9"
                elif "adguard" in lower_url or "94.140.14.14" in lower_url or "94.140.15.15" in lower_url:
                    ip_address = "94.140.14.14"
                elif "google" in lower_url or "8.8.8.8" in lower_url:
                    ip_address = "8.8.8.8"
                elif "cloudflare" in lower_url or "1.1.1.1" in lower_url:
                    ip_address = "1.1.1.1"
                else:
                    clean_ip = server_url
                    for prefix in ["tcp:", "udp:", "quic:", "https:"]:
                        clean_ip = clean_ip.replace(prefix, "").replace("//", "")
                    clean_ip = clean_ip.split(":")[0].split("/")[0]
                    try:
                        ipaddress.ip_address(clean_ip.replace("[", "").replace("]", ""))
                        ip_address = clean_ip
                    except ValueError:
                        ip_address = "9.9.9.9"
                    
            paired.append({"server": server_url, "ip": ip_address})
        i += 1
    return paired

def build_bpb_fragment_template(base_vless_tls_node, all_ips):
    vnext_info = base_vless_tls_node["settings"]["vnext"][0]
    stream_info = base_vless_tls_node["streamSettings"]
    
    node_address = vnext_info["address"]
    if is_cloudflare_node(base_vless_tls_node) and all_ips:
        node_address = random.choice(all_ips)

    if ":" in node_address and not node_address.startswith("["):
        node_address = f"[{node_address}]"
        
    return {
        "remarks": "🌵 8 VLESS - Fragment 🔥",
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
                    "vnext": [{"address": node_address, "port": vnext_info["port"], "users": [{"encryption": "none", "flow": "", "id": vnext_info["users"][0]["id"], "level": 8, "security": "auto"}]}]
                },
                "streamSettings": {
                    "network": stream_info.get("network", "ws"), "security": stream_info.get("security", "tls"),
                    "tlsSettings": {"allowInsecure": False, "fingerprint": stream_info.get("tlsSettings", {}).get("fingerprint", "chrome"), "pinnedPeerCertSha256": stream_info.get("tlsSettings", {}).get("pinnedPeerCertSha256", ""), "serverName": stream_info.get("tlsSettings", {}).get("serverName", ""), "show": False},
                    "wsSettings": {"headers": {"Host": stream_info.get("wsSettings", {}).get("headers", {}).get("Host", "")}, "path": stream_info.get("wsSettings", {}).get("path", "/?ed=2560")},
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

def build_dedicated_tls_ai_template(vless_tls_nodes, ips_v4, ips_v6, all_ips):
    outbounds = []
    shuffled_nodes = copy.deepcopy(vless_tls_nodes)
    random.shuffle(shuffled_nodes)
    total_count = len(shuffled_nodes)
    
    for idx, node in enumerate(shuffled_nodes):
        vnext = node["settings"]["vnext"][0]
        stream = node["streamSettings"]
        
        if is_cloudflare_node(node) and all_ips:
            addr = select_smart_ip(idx, total_count, ips_v4, ips_v6, all_ips)
        else:
            addr = vnext["address"]
        
        outbounds.append({
            "mux": {"concurrency": -1, "enabled": False},
            "protocol": "vless",
            "settings": {"vnext": [{"address": addr, "port": vnext["port"], "users": [{"encryption": "none", "id": vnext["users"][0]["id"], "level": 8}]}]},
            "streamSettings": {
                "network": "ws", "security": "tls",
                "tlsSettings": {"fingerprint": stream.get("tlsSettings", {}).get("fingerprint", "chrome"), "pinnedPeerCertSha256": stream.get("tlsSettings", {}).get("pinnedPeerCertSha256", ""), "serverName": stream.get("tlsSettings", {}).get("serverName", ""), "show": False},
                "wsSettings": {"headers": {"Host": stream.get("wsSettings", {}).get("headers", {}).get("Host", "")}, "path": stream.get("wsSettings", {}).get("path", "/?ed=2560")}
            },
            "tag": f"prox-{idx + 1}"
        })
        
    outbounds.extend([
        {"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}, "tag": "direct"},
        {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}
    ])

    return {
        "remarks": "🌴 2 VLESS - TLS AI 🤖",
        "dns": {
            "hosts": {
                "domain:googleapis.cn": "googleapis.com",
                "tcp://8.8.8.8": ["8.8.8.8", "8.8.4.4"], "udp://1.1.1.1": ["1.1.1.1", "1.0.0.1"]
            },
            "servers": [
                "https://8.8.8.8/dns-query",
                {"address": "78.157.42.100", "domains": ["geosite:openai", "geosite:microsoft", "geosite:docker"], "skipFallback": True}
            ],
            "tag": "dns-module"
        },
        "inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "userLevel": 8}, "sniffing": {"destOverride": ["fakedns"], "enabled": True, "routeOnly": False}, "tag": "socks"}],
        "log": {"loglevel": "warning"},
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"inboundTag": ["dns-module"], "balancerTag": "all", "type": "field"},
                {"type": "field", "domain": ["geosite:openai", "geosite:microsoft"], "outboundTag": "direct"}
            ],
            "balancers": [{"tag": "all", "selector": ["prox"], "strategy": {"type": "leastPing"}, "fallbackTag": "prox-1"}]
        }
    }

def build_dedicated_n_tls_ai_template(vless_ntls_nodes, ips_v4, ips_v6, all_ips):
    outbounds = []
    shuffled_nodes = copy.deepcopy(vless_ntls_nodes)
    random.shuffle(shuffled_nodes)
    total_count = len(shuffled_nodes)
    
    for idx, node in enumerate(shuffled_nodes):
        vnext = node["settings"]["vnext"][0]
        
        if is_cloudflare_node(node) and all_ips:
            addr = select_smart_ip(idx, total_count, ips_v4, ips_v6, all_ips)
        else:
            addr = vnext["address"]
        
        outbounds.append({
            "mux": {"concurrency": -1, "enabled": False},
            "protocol": "vless",
            "settings": {"vnext": [{"address": addr, "port": vnext["port"], "users": [{"encryption": "none", "flow": "", "id": vnext["users"][0]["id"], "level": 8}]}]},
            "streamSettings": {"network": "ws", "wsSettings": {"headers": {"Host": node["streamSettings"].get("wsSettings", {}).get("headers", {}).get("Host", "")}, "path": node["streamSettings"].get("wsSettings", {}).get("path", "/?ed=2560")}},
            "tag": f"prox-{idx + 1}"
        })
        
    outbounds.extend([
        {"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}, "tag": "direct"},
        {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}
    ])

    return {
        "remarks": "☘️ 4 VLESS - Non-TLS AI 🤖",
        "dns": {
            "hosts": {"domain:googleapis.cn": "googleapis.com"},
            "servers": ["https://8.8.8.8/dns-query"], "tag": "dns-module"
        },
        "inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "userLevel": 8}, "sniffing": {"destOverride": ["fakedns"], "enabled": True, "routeOnly": False}, "tag": "socks"}],
        "log": {"loglevel": "warning"},
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"inboundTag": ["dns-module"], "balancerTag": "all", "type": "field"},
                {"type": "field", "domain": ["geosite:openai"], "outboundTag": "direct"}
            ],
            "balancers": [{"tag": "all", "selector": ["prox"], "strategy": {"type": "leastPing"}, "fallbackTag": "prox-1"}]
        }
    }

def build_v2rayng_template(remarks, outbound_nodes, pool_top_dns, pool_main_dns, ips_v4, ips_v6, all_ips):
    # Apply structural IP versioning parameters cleanly inside compilation layout
    processed_outbounds = []
    total_count = len(outbound_nodes)
    
    for idx, raw_node in enumerate(outbound_nodes):
        node = copy.deepcopy(raw_node)
        node["tag"] = f"prox-{idx + 1}"
        
        if is_cloudflare_node(node) and all_ips:
            addr = select_smart_ip(idx, total_count, ips_v4, ips_v6, all_ips)
            settings = node.get("settings", {})
            if "vnext" in settings and settings["vnext"]:
                settings["vnext"][0]["address"] = addr
            elif "servers" in settings and settings["servers"]:
                settings["servers"][0]["address"] = addr
                
        processed_outbounds.append(node)

    base_outbounds = list(processed_outbounds)
    base_outbounds.extend([
        {"protocol": "dns", "tag": "dns-out"},
        {"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}, "tag": "direct"},
        {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}
    ])
    
    fallback_providers = [
        {"server": "https://dns.google/dns-query", "ip": "8.8.8.8"},
        {"server": "https://dns.quad9.net/dns-query", "ip": "9.9.9.9"},
        {"server": "https://dns.adguard-dns.com/dns-query", "ip": "94.140.14.14"}
    ]
    random.shuffle(fallback_providers)

    pairs_top = parse_dns_source(pool_top_dns)
    pairs_main = parse_dns_source(pool_main_dns)
    doh_only_main = [p for p in pairs_main if p["server"].startswith("https://")]

    chosen_providers = [None, None, None, None, None]
    seen_identifiers = set()

    slot2_assigned = False
    if doh_only_main:
        random.shuffle(doh_only_main)
        for provider in doh_only_main:
            ident = get_identity_key(provider["server"])
            seen_identifiers.add(ident)
            chosen_providers[1] = provider
            slot2_assigned = True
            break

    if not slot2_assigned:
        for fb in fallback_providers:
            if fb["server"].startswith("https://"):
                ident = get_identity_key(fb["server"])
                seen_identifiers.add(ident)
                chosen_providers[1] = fb
                slot2_assigned = True
                break

    shuffled_top = list(pairs_top)
    random.shuffle(shuffled_top)
    slot1_assigned = False
    for provider in shuffled_top:
        ident = get_identity_key(provider["server"])
        if ident not in seen_identifiers:
            seen_identifiers.add(ident)
            chosen_providers[0] = provider
            slot1_assigned = True
            break

    if not slot1_assigned:
        for fb in fallback_providers:
            ident = get_identity_key(fb["server"])
            if ident not in seen_identifiers:
                seen_identifiers.add(ident)
                chosen_providers[0] = fb
                break

    remaining_slots = [2, 3, 4]
    combined_remaining = [p for p in pairs_top + pairs_main if get_identity_key(p["server"]) not in seen_identifiers]
    random.shuffle(combined_remaining)

    for provider in combined_remaining:
        if not remaining_slots:
            break
        ident = get_identity_key(provider["server"])
        if ident not in seen_identifiers:
            seen_identifiers.add(ident)
            target_slot = remaining_slots.pop(0)
            chosen_providers[target_slot] = provider

    for slot_idx in range(5):
        if chosen_providers[slot_idx] is None:
            for fb in fallback_providers:
                ident = get_identity_key(fb["server"])
                if ident not in seen_identifiers:
                    seen_identifiers.add(ident)
                    chosen_providers[slot_idx] = fb
                    break

    dns_servers_config = []
    inbound_tags = []
    
    for i, provider in enumerate(chosen_providers, 1):
        tag_name = f"remote-dns-{i}"
        inbound_tags.append(tag_name)
        srv_address = provider["server"]
        
        if srv_address.startswith("tcp:"):
            clean_host = clean_dns_address(srv_address, "tcp:")
            dns_servers_config.append({"address": clean_host, "port": 853, "tag": tag_name})
        elif srv_address.startswith("udp:"):
            clean_host = clean_dns_address(srv_address, "udp:")
            dns_servers_config.append({"address": clean_host, "port": 53, "tag": tag_name})
        elif srv_address.startswith("https://"):
            dns_servers_config.append({"address": srv_address, "tag": tag_name})
        else:
            dns_servers_config.append({"address": srv_address, "port": 53, "tag": tag_name})
        
    def clean_to_pure_ip(raw_string):
        if not raw_string:
            return "9.9.9.9"
        s = re.sub(r'^[a-zA-Z0-9+.-]+://', '', raw_string)
        s = s.split('/')[0].split('?')[0]
        if ']' in s:
            s = s.split(']')[0].replace('[', '').replace(']', '')
        else:
            s = s.split(':')[0]
        try:
            ipaddress.ip_address(s)
            return s
        except ValueError:
            return "9.9.9.9"

    for provider in chosen_providers:
        pure_domestic_ip = clean_to_pure_ip(provider["ip"])
        dns_servers_config.append({
            "address": pure_domestic_ip,
            "domains": ["geosite:category-ir"],
            "expectIPs": ["geoip:ir"],
            "skipFallback": False
        })
                    
    return {
        "remarks": remarks,
        "log": {"loglevel": "warning"},
        "dns": {"servers": dns_servers_config, "queryStrategy": "UseIP", "tag": "dns"},
        "inbounds": [
            {"port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "userLevel": 8}, "sniffing": {"destOverride": ["http", "tls"], "enabled": False}, "tag": "socks-in"},
            {"port": 10853, "protocol": "dokodemo-door", "settings": {"address": "1.1.1.1", "network": "tcp,udp", "port": 53}, "tag": "dns-in"}
        ],
        "outbounds": base_outbounds,
        "policy": {"levels": {"8": {"connIdle": 300}}, "system": {"statsOutboundUplink": True, "statsOutboundDownlink": True}},
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"inboundTag": ["dns-in"], "outboundTag": "dns-out", "type": "field"},
                {"inboundTag": ["socks-in"], "port": 53, "outboundTag": "dns-out", "type": "field"},
                {"inboundTag": inbound_tags, "balancerTag": "all", "type": "field"},
                {"domain": ["geosite:category-ir"], "outboundTag": "direct", "type": "field"},
                {"ip": ["geoip:ir"], "outboundTag": "direct", "type": "field"},
                {"network": "udp", "outboundTag": "block", "type": "field"}
            ],
            "balancers": [{"tag": "all", "selector": ["prox"], "strategy": {"type": "leastPing"}}]
        }
    }

def main():
    input_file = "Configs.txt"
    output_file = "NG-JSON-Configs.txt"
    
    if not os.path.exists(input_file):
        print(f"Source configuration file {input_file} missing.")
        return

    fetch_cloudflare_ranges()
    all_ips = fetch_clean_addresses(CLEAN_IPS_URL)
    
    ips_v4 = []
    ips_v6 = []
    for ip in all_ips:
        try:
            ip_obj = ipaddress.ip_address(ip.replace("[", "").replace("]", ""))
            if ip_obj.version == 4:
                ips_v4.append(ip)
            elif ip_obj.version == 6:
                ips_v6.append(ip)
        except ValueError:
            ips_v4.append(ip)

    pool_top_dns = fetch_remote_dns(DNS_TOP_URL)
    pool_main_dns = fetch_remote_dns(DNS_MAIN_URL)

    tls_counter, non_tls_counter = [0], [0]
    groups = {"vless_tls": [], "vless_n_tls": [], "trojan_tls": [], "trojan_n_tls": [], "vmess_tls": [], "vmess_n_tls": [], "other_protocols": []}
    
    with open(input_file, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
        
    random.shuffle(lines)

    for line in lines:
        node_data, is_tls, proto_key = None, False, None
        if line.startswith("vmess://"):
            node_data, is_tls = parse_vmess(line, tls_counter, non_tls_counter)
            proto_key = "vmess_tls" if is_tls else "vmess_n_tls"
        elif line.startswith("vless://"):
            node_data, is_tls = parse_standard_uri(line, "vless", tls_counter, non_tls_counter)
            proto_key = "vless_tls" if is_tls else "vless_n_tls"
        elif line.startswith("trojan://"):
            node_data, is_tls = parse_standard_uri(line, "trojan", tls_counter, non_tls_counter)
            proto_key = "trojan_tls" if is_tls else "trojan_n_tls"
            
        if node_data and proto_key:
            groups[proto_key].append(node_data)
                
    final_output = []
    
    # 1. VLESS TLS LB
    if groups["vless_tls"]:
        final_output.append(build_v2rayng_template("🌴 1 VLESS - TLS LB 🔥", groups["vless_tls"], pool_top_dns, pool_main_dns, ips_v4, ips_v6, all_ips))
            
    # 2. VLESS TLS AI
    if groups["vless_tls"]:
        final_output.append(build_dedicated_tls_ai_template(groups["vless_tls"], ips_v4, ips_v6, all_ips))
        
    # 3. VLESS Non-TLS LB
    if groups["vless_n_tls"]:
        final_output.append(build_v2rayng_template("☘️ 3 VLESS - Non-TLS LB 🔥", groups["vless_n_tls"], pool_top_dns, pool_main_dns, ips_v4, ips_v6, all_ips))

    # 4. VLESS Non-TLS AI
    if groups["vless_n_tls"]:
        final_output.append(build_dedicated_n_tls_ai_template(groups["vless_n_tls"], ips_v4, ips_v6, all_ips))
            
    # 5. TROJAN TLS LB
    if groups["trojan_tls"]:
        final_output.append(build_v2rayng_template("🌳 5 TROJAN - TLS LB 🔥", groups["trojan_tls"], pool_top_dns, pool_main_dns, ips_v4, ips_v6, all_ips))

    # 6. TROJAN Non-TLS LB
    if groups["trojan_n_tls"]:
        final_output.append(build_v2rayng_template("🌳 6 TROJAN - Non-TLS LB 🔥", groups["trojan_n_tls"], pool_top_dns, pool_main_dns, ips_v4, ips_v6, all_ips))

    # 7. VMESS TLS LB
    if groups["vmess_tls"]:
        final_output.append(build_v2rayng_template("🍀 7 VMESS - TLS LB 🔥", groups["vmess_tls"], pool_top_dns, pool_main_dns, ips_v4, ips_v6, all_ips))

    # 8. VLESS Fragment
    if groups["vless_tls"]:
        final_output.append(build_bpb_fragment_template(random.choice(groups["vless_tls"]), all_ips))

    with open(output_file, "w", encoding="utf-8") as out:
        json.dump(final_output, out, indent=2, ensure_ascii=False)
        
    print(f"🎉 Successfully created clean configs in destination file: '{output_file}'")

if __name__ == "__main__":
    main()
