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
            if not line:
                continue
            # Do not skip lines starting with # or // here, let parse_dns_source handle them
            # because the IP might be on the next line or after a comment symbol
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
            outbound["streamSettings"]["kcpSettings"] = {"header": {"type": "none"}}
            
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
    """Extracts base registration domain string or raw host string for uniqueness tracking."""
    try:
        proto = ""
        s = srv.strip()
        for prefix in ["tcp://", "tcp:", "udp://", "udp:", "quic://", "quic:", "https://", "tls://", "tls:"]:
            if s.startswith(prefix):
                proto = prefix.replace("://", "").replace(":", "")
                s = s.replace(prefix, "", 1).replace("//", "").strip()
                break
                
        domain = s.replace("[", "").replace("]", "").split(':')[0].split('/')[0]
        
        try:
            ipaddress.ip_address(domain)
            return f"{proto}://{domain}"
        except ValueError:
            pass
            
        domain_parts = domain.split('.')
        return ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain
    except Exception:
        return srv

def parse_dns_source(pool_dns_servers):
    """Converts text lines into paired dictionary groupings with smart local resolution fallback matching."""
    paired = []
    i = 0
    while i < len(pool_dns_servers):
        item = pool_dns_servers[i].strip()
        if not item:
            i += 1
            continue

        # Remove comment markers to help extract IPs that might be commented out on the same line
        # Example: "https://dns.google/dns-query # 8.8.8.8" -> "https://dns.google/dns-query 8.8.8.8"
        clean_item = item.replace("#", " ").replace("//", " ")
        parts = clean_item.split()
        
        server_url = None
        inline_ips = []
        
        for part in parts:
            if part.startswith(("https://", "tcp:", "quic:", "udp:", "tls:")):
                if server_url is None:
                    server_url = part
            elif re.match(r'^\d{1,3}(\.\d{1,3}){3}$', part) or (part.startswith("[") and part.endswith("]")):
                if server_url is None:
                    server_url = part # The IP itself is the server URL
                else:
                    inline_ips.append(part)
                    
        if not server_url:
            i += 1
            continue

        ip_address = None
        
        # Check inline IPs first
        for test_ip in inline_ips:
            clean_test = test_ip.replace("[", "").replace("]", "").split(':')[0]
            if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', clean_test):
                ip_address = clean_test
                break
            elif test_ip.startswith("[") and test_ip.endswith("]"):
                try:
                    ipaddress.ip_address(test_ip[1:-1])
                    ip_address = test_ip
                    break
                except ValueError:
                    pass

        # Check next line if no inline IP found
        if not ip_address and i + 1 < len(pool_dns_servers):
            next_item = pool_dns_servers[i + 1].strip().replace("#", " ").replace("//", " ").split()
            next_ip_candidate = next_item[0] if next_item else ""
            if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', next_ip_candidate):
                ip_address = next_ip_candidate
                i += 1
            elif next_ip_candidate.startswith("[") and next_ip_candidate.endswith("]"):
                try:
                    ipaddress.ip_address(next_ip_candidate[1:-1])
                    ip_address = next_ip_candidate
                    i += 1
                except ValueError:
                    pass
            
        if not ip_address:
            lower_url = server_url.lower()
            if "quad9" in lower_url or "9.9.9.9" in lower_url:
                ip_address = "9.9.9.9"
            elif "adguard" in lower_url or "94.140.14.14" in lower_url or "94.140.15.15" in lower_url:
                ip_address = "94.140.15.15" if "94.140.15.15" in lower_url else "94.140.14.14"
            elif "google" in lower_url or "8.8.8.8" in lower_url or "8.8.4.4" in lower_url:
                ip_address = "8.8.4.4" if "8.8.4.4" in lower_url else "8.8.8.8"
            elif "cloudflare" in lower_url or "1.1.1.1" in lower_url or "1.1.1.2" in lower_url or "1.0.0.1" in lower_url:
                ip_address = "1.1.1.2" if "1.1.1.2" in lower_url else "1.1.1.1"
            elif "yandex" in lower_url or "77.88.8.1" in lower_url:
                ip_address = "77.88.8.1"
            elif "opendns" in lower_url:
                ip_address = "208.67.222.222"
            else:
                clean_ip = server_url
                for prefix in ["tcp:", "udp:", "quic:", "https:", "tls:"]:
                    clean_ip = clean_ip.replace(prefix, "").replace("//", "")
                clean_ip = clean_ip.split(":")[0].split("/")[0]
                
                try:
                    ip_to_test = clean_ip.replace("[", "").replace("]", "")
                    ipaddress.ip_address(ip_to_test)
                    ip_address = clean_ip
                except ValueError:
                    parsed_doh = urlparse(server_url if "://" in server_url else f"https://{server_url}")
                    doh_host = parsed_doh.netloc.split(':')[0]
                    try:
                        ipaddress.ip_address(doh_host.replace("[", "").replace("]", ""))
                        ip_address = doh_host
                    except ValueError:
                        ip_address = server_url
                    
        paired.append({"server": server_url, "ip": ip_address})
        i += 1
    return paired

def build_bpb_fragment_template(base_vless_tls_node, clean_addresses):
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
    
    ws_host = ws_settings.get("headers", {}).get("Host", sni_server_name) if isinstance(ws_settings.get("headers"), dict) else ws_settings.get("host", sni_server_name)
    ws_path = ws_settings.get("path", "/?ed=2560")

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
                    "pinnedPeerCertSha256": tls_settings.get("pinnedPeerCertSha256", ""),
                    "serverName": tls_settings.get("serverName", ""),
                    "show": False
                },
                "wsSettings": {
                    "headers": {"Host": ws_settings.get("headers", {}).get("Host", tls_settings.get("serverName", "")) if isinstance(ws_settings.get("headers"), dict) else tls_settings.get("serverName", "")},
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
        "remarks": "🌴 2 VLESS - TLS AI 🤖",
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
                {"address": "78.157.42.100", "domains": ["geosite:openai", "geosite:microsoft", "geosite:oracle", "geosite:docker", "geosite:adobe", "geosite:epicgames", "geosite:intel", "geosite:amd", "geosite:nvidia", "geosite:asus", "hp", "geosite:lenovo"], "skipFallback": True},
                {"address": "78.157.42.101", "domains": ["geosite:openai", "geosite:microsoft", "geosite:oracle", "geosite:docker", "geosite:adobe", "geosite:epicgames", "geosite:intel", "geosite:amd", "geosite:nvidia", "geosite:asus", "hp", "geosite:lenovo"], "skipFallback": True}
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
                {"type": "field", "domain": ["geosite:openai", "geosite:microsoft", "geosite:oracle", "geosite:docker", "geosite:adobe", "geosite:epicgames", "geosite:intel", "geosite:amd", "geosite:nvidia", "geosite:asus", "hp", "geosite:lenovo"], "outboundTag": "direct"}
            ],
            "balancers": [{"tag": "all", "selector": ["prox"], "strategy": {"type": "leastPing"}, "fallbackTag": "prox-1"}]
        },
        "stats": {},
        "observatory": {"subjectSelector": ["prox"], "probeUrl": "https://www.gstatic.com/generate_204", "probeInterval": "30s", "enableConcurrency": True}
    }

def build_dedicated_n_tls_ai_template(vless_ntls_nodes, clean_addresses):
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
        "remarks": "☘️ 4 VLESS - Non-TLS AI 🤖",
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
                {"address": "78.157.42.100", "domains": ["geosite:openai", "geosite:microsoft", "geosite:oracle", "geosite:docker", "geosite:adobe", "geosite:epicgames", "geosite:intel", "geosite:amd", "geosite:nvidia", "geosite:asus", "hp", "geosite:lenovo"], "skipFallback": True},
                {"address": "78.157.42.101", "domains": ["geosite:openai", "geosite:microsoft", "geosite:oracle", "geosite:docker", "geosite:adobe", "geosite:epicgames", "geosite:intel", "geosite:amd", "geosite:nvidia", "geosite:asus", "hp", "geosite:lenovo"], "skipFallback": True}
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
                {"type": "field", "domain": ["geosite:openai", "geosite:microsoft", "geosite:oracle", "geosite:docker", "geosite:adobe", "geosite:epicgames", "geosite:intel", "geosite:amd", "geosite:nvidia", "geosite:asus", "hp", "geosite:lenovo"], "outboundTag": "direct"}
            ],
            "balancers": [{"tag": "all", "selector": ["prox"], "strategy": {"type": "leastPing"}, "fallbackTag": "prox-1"}]
        },
        "stats": {},
        "observatory": {"subjectSelector": ["prox"], "probeUrl": "https://www.gstatic.com/generate_204", "probeInterval": "30s", "enableConcurrency": True}
    }

def build_v2rayng_template(remarks, outbound_nodes, pool_top_dns, pool_main_dns, clean_addresses=None, is_cloudflare=True):
    modified_outbounds = copy.deepcopy(list(outbound_nodes))
    
    if clean_addresses and is_cloudflare:
        for node in modified_outbounds:
            settings = node.get("settings", {})
            if "vnext" in settings and settings["vnext"]:
                settings["vnext"][0]["address"] = random.choice(clean_addresses)
            elif "servers" in settings and settings["servers"]:
                settings["servers"][0]["address"] = random.choice(clean_addresses)

    for node in modified_outbounds:
        if "_original_address" in node:
            del node["_original_address"]

    base_outbounds = modified_outbounds
    base_outbounds.extend([
        {"protocol": "dns", "tag": "dns-out"},
        {"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}, "tag": "direct"},
        {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}
    ])
    
    fallback_providers = [
        {"server": "https://dns.google/dns-query", "ip": "8.8.8.8"},
        {"server": "https://dns.quad9.net/dns-query", "ip": "9.9.9.9"},
        {"server": "tcp://dns.google:853", "ip": "8.8.8.8"},
        {"server": "tcp://dns.quad9.net:853", "ip": "9.9.9.9"},
        {"server": "tls://dns.google:853", "ip": "8.8.8.8"},
        {"server": "tls://dns.quad9.net:853", "ip": "9.9.9.9"},
        {"server": "quic://dns.adguard-dns.com", "ip": "94.140.14.14"},
        {"server": "quic://dns.nextdns.io", "ip": "45.90.30.0"},
        {"server": "udp://dns.google:53", "ip": "8.8.8.8"},
        {"server": "udp://dns.quad9.net:53", "ip": "9.9.9.9"},
        {"server": "1.1.1.1", "ip": "1.1.1.1"},
        {"server": "1.0.0.1", "ip": "1.0.0.1"},
        {"server": "1.1.1.2", "ip": "1.1.1.2"}
    ]
    random.shuffle(fallback_providers)

    pairs_top = parse_dns_source(pool_top_dns)
    pairs_main = parse_dns_source(pool_main_dns)

    doh_only_top = [p for p in pairs_top if p["server"].startswith("https://")]
    doh_only_main = [p for p in pairs_main if p["server"].startswith("https://")]

    def is_raw_ip(server_str):
        s = server_str.strip()
        if re.match(r'^(https?|tcp|udp|tls|quic)://', s, re.IGNORECASE):
            return False
        if s.startswith(("tcp:", "udp:", "quic:", "tls:")):
            return False
        if s.startswith("[") and s.endswith("]"):
            try:
                ipaddress.ip_address(s[1:-1])
                return True
            except ValueError:
                pass
        parts = s.split(":")
        if len(parts) <= 2:
            try:
                ipaddress.ip_address(parts[0])
                return True
            except ValueError:
                pass
        return False

    def get_dns_type(server_str):
        s = server_str.strip().lower()
        if s.startswith("https://"): return "doh"
        if s.startswith("tcp://") or s.startswith("tcp:"): return "tcp"
        if s.startswith("tls://") or s.startswith("tls:"): return "tls"
        if s.startswith("quic://") or s.startswith("quic:"): return "quic"
        if s.startswith("udp://") or s.startswith("udp:"): return "udp"
        return "other"

    chosen_providers = [None, None, None, None, None]
    seen_identifiers = set()

    slot1_assigned = False
    if doh_only_top:
        random.shuffle(doh_only_top)
        for provider in doh_only_top:
            ident = get_identity_key(provider["server"])
            seen_identifiers.add(ident)
            chosen_providers[0] = provider
            slot1_assigned = True
            break

    if not slot1_assigned:
        for fb in fallback_providers:
            if fb["server"].startswith("https://"):
                ident = get_identity_key(fb["server"])
                if ident not in seen_identifiers:
                    seen_identifiers.add(ident)
                    chosen_providers[0] = fb
                    break

    slot2_assigned = False
    if doh_only_main:
        random.shuffle(doh_only_main)
        for provider in doh_only_main:
            ident = get_identity_key(provider["server"])
            if ident not in seen_identifiers:
                seen_identifiers.add(ident)
                chosen_providers[1] = provider
                slot2_assigned = True
                break

    if not slot2_assigned:
        for fb in fallback_providers:
            if fb["server"].startswith("https://"):
                ident = get_identity_key(fb["server"])
                if ident not in seen_identifiers:
                    seen_identifiers.add(ident)
                    chosen_providers[1] = fb
                    slot2_assigned = True
                    break

    combined_remaining = [p for p in pairs_top + pairs_main if not is_raw_ip(p["server"])]
    combined_remaining = [p for p in combined_remaining if get_identity_key(p["server"]) not in seen_identifiers]
    
    type_groups = {"doh": [], "tcp": [], "tls": [], "quic": [], "udp": [], "other": []}
    for p in combined_remaining:
        t = get_dns_type(p["server"])
        type_groups[t].append(p)
        
    for t in type_groups:
        random.shuffle(type_groups[t])
        
    slot_345_providers = []
    used_types = set()

    available_types = [t for t in ["tcp", "udp", "tls", "quic", "doh", "other"] if type_groups[t]]
    random.shuffle(available_types)
    
    for t in available_types:
        if len(slot_345_providers) >= 3:
            break
        chosen_p = type_groups[t].pop(0)
        slot_345_providers.append(chosen_p)
        seen_identifiers.add(get_identity_key(chosen_p["server"]))
        used_types.add(t)
        
    if len(slot_345_providers) < 3:
        non_ip_fallbacks = [fb for fb in fallback_providers if not is_raw_ip(fb["server"])]
        random.shuffle(non_ip_fallbacks)
        
        for fb in non_ip_fallbacks:
            if len(slot_345_providers) >= 3:
                break
            ident = get_identity_key(fb["server"])
            t = get_dns_type(fb["server"])
            
            if ident not in seen_identifiers and t not in used_types:
                seen_identifiers.add(ident)
                used_types.add(t)
                slot_345_providers.append(fb)
                
    if len(slot_345_providers) < 3:
        leftovers = []
        for p_list in type_groups.values():
            leftovers.extend(p_list)
        for fb in non_ip_fallbacks:
            leftovers.append(fb)
        random.shuffle(leftovers)
        
        for p in leftovers:
            if len(slot_345_providers) >= 3:
                break
            ident = get_identity_key(p["server"])
            if ident not in seen_identifiers:
                seen_identifiers.add(ident)
                slot_345_providers.append(p)

    for i, p in enumerate(slot_345_providers):
        chosen_providers[2 + i] = p

    for slot_idx in [0, 1]:
        if chosen_providers[slot_idx] is None:
            for fb in fallback_providers:
                if fb["server"].startswith("https://"):
                    ident = get_identity_key(fb["server"])
                    if ident not in seen_identifiers:
                        seen_identifiers.add(ident)
                        chosen_providers[slot_idx] = fb
                        break

    for slot_idx in [2, 3, 4]:
        if chosen_providers[slot_idx] is None:
            for fb in fallback_providers:
                if not is_raw_ip(fb["server"]):
                    ident = get_identity_key(fb["server"])
                    if ident not in seen_identifiers:
                        seen_identifiers.add(ident)
                        chosen_providers[slot_idx] = fb
                        break

    valid_fallback = chosen_providers[0] or chosen_providers[1] or {"server": "https://dns.google/dns-query", "ip": "8.8.8.8"}
    for slot_idx in range(5):
        if chosen_providers[slot_idx] is None:
            chosen_providers[slot_idx] = valid_fallback

    dns_servers_config = []
    inbound_tags = []
    
    for i, provider in enumerate(chosen_providers, 1):
        tag_name = f"remote-dns-{i}"
        inbound_tags.append(tag_name)
        srv_address = provider["server"]
        
        if srv_address.startswith("tcp://") or srv_address.startswith("tcp:"):
            addr = srv_address.replace("tcp://", "tcp://").replace("tcp:", "tcp://", 1) if not srv_address.startswith("tcp://") else srv_address
            if ":" not in addr[6:]: 
                addr += ":853"
            dns_servers_config.append({"address": addr, "tag": tag_name})
            
        elif srv_address.startswith("tls://") or srv_address.startswith("tls:"):
            addr = srv_address.replace("tls://", "tls://").replace("tls:", "tls://", 1) if not srv_address.startswith("tls://") else srv_address
            if ":" not in addr[6:]:
                addr += ":853"
            dns_servers_config.append({"address": addr, "tag": tag_name})
            
        elif srv_address.startswith("quic://") or srv_address.startswith("quic:"):
            addr = srv_address.replace("quic://", "quic://").replace("quic:", "quic://", 1) if not srv_address.startswith("quic://") else srv_address
            dns_servers_config.append({"address": addr, "tag": tag_name})
            
        elif srv_address.startswith("https://"):
            dns_servers_config.append({"address": srv_address, "tag": tag_name})
            
        elif srv_address.startswith("udp://") or srv_address.startswith("udp:"):
            addr = srv_address.replace("udp://", "udp://").replace("udp:", "udp://", 1) if not srv_address.startswith("udp://") else srv_address
            if ":" not in addr[6:]:
                addr += ":53"
            dns_servers_config.append({"address": addr, "tag": tag_name})
            
        else:
            if srv_address.startswith("[") and srv_address.endswith("]"):
                dns_servers_config.append({"address": srv_address, "port": 53, "tag": tag_name})
            else:
                try:
                    ipaddress.ip_address(srv_address)
                    dns_servers_config.append({"address": srv_address, "port": 53, "tag": tag_name})
                except ValueError:
                    dns_servers_config.append({"address": srv_address, "tag": tag_name})
        
    for provider in chosen_providers:
        target_ip = provider["ip"]
        is_v4 = False
        
        try:
            if isinstance(ipaddress.ip_address(target_ip), ipaddress.IPv4Address):
                is_v4 = True
        except ValueError:
            pass
            
        if not is_v4:
            extracted = ""
            s = provider["server"]
            if "://" in s:
                try: extracted = urlparse(s).hostname or ""
                except: pass
            elif s.startswith(("tcp:", "udp:", "quic:", "tls:")):
                extracted = s.split(':', 1)[1].replace("//", "").split(':')[0]
            else:
                extracted = s.split(':')[0]
                
            try:
                if isinstance(ipaddress.ip_address(extracted), ipaddress.IPv4Address):
                    target_ip = extracted
                    is_v4 = True
            except ValueError:
                pass
                
        if not is_v4:
            target_ip = "8.8.8.8"
            
        dns_servers_config.append({
            "address": target_ip,
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
                ipaddress.ip_address(addr.replace("[", "").replace("]", ""))
            except ValueError:
                domain_entry = f"full:{addr}"
                if domain_entry not in extracted_domains:
                    extracted_domains.append(domain_entry)
                    
    primary_dns_ip = chosen_providers[0]["ip"] if chosen_providers else "9.9.9.9"
    for domain in extracted_domains:
        dns_servers_config.append({
            "address": primary_dns_ip,
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
    
    if groups["vless_tls"]:
        for idx, item in enumerate(groups["vless_tls"]):
            item["tag"] = f"prox-{idx + 1}"
        final_output.append(build_v2rayng_template("🌴 1 VLESS - TLS LB 🔥", groups["vless_tls"], pool_top_dns, pool_main_dns, clean_addresses, is_cloudflare=True))
            
    if groups["vless_tls"]:
        final_output.append(build_dedicated_tls_ai_template(groups["vless_tls"], clean_addresses))
        
    if groups["vless_n_tls"]:
        for idx, item in enumerate(groups["vless_n_tls"]):
            item["tag"] = f"prox-{idx + 1}"
        final_output.append(build_v2rayng_template("☘️ 3 VLESS - Non-TLS LB 🔥", groups["vless_n_tls"], pool_top_dns, pool_main_dns, clean_addresses, is_cloudflare=True))

    if groups["vless_n_tls"]:
        final_output.append(build_dedicated_n_tls_ai_template(groups["vless_n_tls"], clean_addresses))
            
    if groups["trojan_tls"]:
        for idx, item in enumerate(groups["trojan_tls"]):
            item["tag"] = f"prox-{idx + 1}"
        final_output.append(build_v2rayng_template("🌳 5 TROJAN - TLS LB 🔥", groups["trojan_tls"], pool_top_dns, pool_main_dns, clean_addresses, is_cloudflare=True))

    if groups["trojan_n_tls"]:
        for idx, item in enumerate(groups["trojan_n_tls"]):
            item["tag"] = f"prox-{idx + 1}"
        final_output.append(build_v2rayng_template("🌳 6 TROJAN - Non-TLS LB 🔥", groups["trojan_n_tls"], pool_top_dns, pool_main_dns, clean_addresses, is_cloudflare=True))

    if groups["vmess_tls"]:
        for idx, item in enumerate(groups["vmess_tls"]):
            item["tag"] = f"prox-{idx + 1}"
        final_output.append(build_v2rayng_template("🍀 7 VMESS - TLS LB 🔥", groups["vmess_tls"], pool_top_dns, pool_main_dns, clean_addresses, is_cloudflare=False))

    if groups["vless_tls"]:
        random_fragment_node = random.choice(groups["vless_tls"])
        final_output.append(build_bpb_fragment_template(random_fragment_node, clean_addresses))
            
    if groups["other_protocols"]:
        for idx, item in enumerate(groups["other_protocols"]):
            item["tag"] = f"prox-{idx + 1}"
        final_output.append(build_v2rayng_template("🌳 OTHER PROTOCOLS LB 🔥", groups["other_protocols"], pool_top_dns, pool_main_dns, clean_addresses, is_cloudflare=False))

    for template in final_output:
        if "outbounds" in template:
            for outbound in template["outbounds"]:
                if "_original_address" in outbound:
                    del outbound["_original_address"]

    with open(output_file, "w", encoding="utf-8") as out:
        json.dump(final_output, out, indent=2, ensure_ascii=False)
        
    print(f"🎉 Compiled cleanly with strict sequence order in destination: '{output_file}'")

if __name__ == "__main__":
    main()
