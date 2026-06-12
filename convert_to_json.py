import os
import json
import base64
import ipaddress
import re
import urllib.request
import random
import copy
import datetime  # Added to fetch system time safely without external packages
from urllib.parse import urlparse, unquote, parse_qs

# Configuration URLs
CLEAN_IPS_URL = "https://raw.githubusercontent.com/gransa/Moein/refs/heads/main/Cloudflare-IPs.txt"
DNS_TOP_URL = "https://raw.githubusercontent.com/gransa/Moein/refs/heads/main/DNS-TOP.txt"
DNS_MAIN_URL = "https://raw.githubusercontent.com/gransa/Moein/refs/heads/main/DNS.txt"

# Cloudflare clear distinct port definitions
TLS_PORTS = [443, 2053, 2083, 2087, 2096, 8443]
NON_TLS_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095]

class CleanIPSupplier:
    """Hands out unique, unrepeated IPs from the pool like a deck of cards."""
    def __init__(self, ip_list):
        self.pool = list(ip_list)
        if not self.pool:
            self.pool = ["1.1.1.1"]  # Fallback if fetch fails
        random.shuffle(self.pool)
        self.index = 0
        
    def get_next(self):
        if self.index >= len(self.pool):
            # All IPs used once, reshuffle and restart to avoid crashing
            random.shuffle(self.pool)
            self.index = 0
        ip = self.pool[self.index]
        self.index += 1
        return ip

def get_tehran_time_str():
    """Calculates current Tehran time (UTC+3:30) manually without external libraries."""
    utc_now = datetime.datetime.utcnow()
    tehran_offset = datetime.timedelta(hours=3, minutes=30)
    tehran_time = utc_now + tehran_offset
    return tehran_time.strftime("%H:%M")

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

        if (item.startswith("https://") or item.startswith("tcp:") or item.startswith("quic:") or 
            item.startswith("udp:") or item.startswith("tls:") or item.startswith("[") or re.match(r'^\d{1,3}(\.\d{1,3}){3}$', item)):
            
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

def build_bpb_fragment_template(base_vless_tls_node, ip_supplier):
    vnext_info = base_vless_tls_node["settings"]["vnext"][0]
    stream_info = base_vless_tls_node["streamSettings"]
    
    node_address = ip_supplier.get_next()
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

def build_dedicated_tls_ai_template(remarks, vless_tls_nodes, ip_supplier):
    outbounds = []
    shuffled_nodes = copy.deepcopy(vless_tls_nodes)
    random.shuffle(shuffled_nodes)
    
    for idx, node in enumerate(shuffled_nodes):
        vnext = node["settings"]["vnext"][0]
        stream = node["streamSettings"]
        tls_settings = stream.get("tlsSettings", {})
        ws_settings = stream.get("wsSettings", {})
        addr = ip_supplier.get_next()
        
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
        "remarks": remarks,
        "dns": {
            "hosts": {
                "domain:googleapis.cn": "googleapis.com",
                "tcp://8.8.8.8": ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
                "udp://1.1.1.1": ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
                "https://8.8.8.8/dns-query": ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
                "https://1.1.1.1/dns-query": ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001", "104.16.132.229", "104.16.133.229", "2606:4700::6810:84e5", "2606:4700::6810:85e5"],
                "https://9.9.9.9/dns-query": ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
                "dns.alidns.com": ["223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1"],
                "one.one.one.one": ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
                "dns.cloudflare.com": ["104.16.132.229", "104.16.133.229", "2606:4700::6810:84e5", "2606:4700::6810:85e5"],
                "cloudflare-dns.com": ["104.16.248.249", "104.16.249.249", "2606:4700::6810:f8f9", "2606:4700::6810:f9f9"],
                "dot.pub": ["1.12.12.12", "120.53.53.53"],
                "dns.google": ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
                "dns.quad9.net": ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
                "common.dot.dns.yandex.net": ["77.88.8.8", "77.88.8.1", "2a02:6b8::feed:0ff", "2a02:6b8:0:1::feed:0ff"]
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
                {
                    "ip": [
                        "223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1",
                        "119.29.29.29", "1.12.12.12", "120.53.53.53",
                        "2402:4e00::", "2402:4e00:1::",
                        "180.76.76.76", "2400:da00::6666",
                        "114.114.114.114", "114.114.115.115",
                        "114.114.114.119", "114.114.115.119",
                        "114.114.114.110", "114.114.115.110",
                        "180.184.1.1", "180.184.2.2",
                        "101.226.4.6", "218.30.118.6", "123.125.81.6", "140.207.198.6",
                        "1.2.4.8", "210.2.4.8",
                        "52.80.66.66", "117.50.22.22",
                        "2400:7fc0:849e:200::4", "2404:c2c0:85d8:901::4",
                        "117.50.10.10", "52.80.52.52",
                        "2400:7fc0:849e:200::8", "2404:c2c0:85d8:901::8",
                        "117.50.60.30", "52.80.60.30"
                    ],
                    "outboundTag": "direct",
                    "type": "field"
                },
                {
                    "domain": [
                        "domain:alidns.com", "domain:doh.pub", "domain:dot.pub",
                        "domain:360.cn", "domain:onedns.net"
                    ],
                    "outboundTag": "direct",
                    "type": "field"
                },
                {"network": "tcp,udp", "balancerTag": "all", "type": "field"},
                {
                    "type": "field",
                    "domain": ["geosite:openai", "geosite:microsoft", "geosite:oracle", "geosite:docker", "geosite:adobe", "geosite:epicgames", "geosite:intel", "geosite:amd", "geosite:nvidia", "geosite:asus", "hp", "geosite:lenovo"],
                    "outboundTag": "direct"
                }
            ],
            "balancers": [{"tag": "all", "selector": ["prox"], "strategy": {"type": "leastPing"}, "fallbackTag": "prox-1"}]
        },
        "stats": {},
        "observatory": {"subjectSelector": ["prox"], "probeUrl": "https://www.gstatic.com/generate_204", "probeInterval": "30s", "enableConcurrency": True}
    }

def build_dedicated_n_tls_ai_template(vless_ntls_nodes, ip_supplier):
    outbounds = []
    shuffled_nodes = copy.deepcopy(vless_ntls_nodes)
    random.shuffle(shuffled_nodes)
    
    for idx, node in enumerate(shuffled_nodes):
        vnext = node["settings"]["vnext"][0]
        ws_settings = node["streamSettings"].get("wsSettings", {})
        addr = ip_supplier.get_next()
        
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
                "https://9.9.9.9/dns-query": ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
                "dns.alidns.com": ["223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1"],
                "one.one.one.one": ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
                "dns.cloudflare.com": ["104.16.132.229", "104.16.133.229", "2606:4700::6810:84e5", "2606:4700::6810:85e5"],
                "cloudflare-dns.com": ["104.16.248.249", "104.16.249.249", "2606:4700::6810:f8f9", "2606:4700::6810:f9f9"],
                "dot.pub": ["1.12.12.12", "120.53.53.53"],
                "dns.google": ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
                "dns.quad9.net": ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
                "common.dot.dns.yandex.net": ["77.88.8.8", "77.88.8.1", "2a02:6b8::feed:0ff", "2a02:6b8:0:1::feed:0ff"]
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
                {
                    "ip": [
                        "223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1",
                        "119.29.29.29", "1.12.12.12", "120.53.53.53",
                        "2402:4e00::", "2402:4e00:1::",
                        "180.76.76.76", "2400:da00::6666",
                        "114.114.114.114", "114.114.115.115",
                        "114.114.114.119", "114.114.115.119",
                        "114.114.114.110", "114.114.115.110",
                        "180.184.1.1", "180.184.2.2",
                        "101.226.4.6", "218.30.118.6", "123.125.81.6", "140.207.198.6",
                        "1.2.4.8", "210.2.4.8",
                        "52.80.66.66", "117.50.22.22",
                        "2400:7fc0:849e:200::4", "2404:c2c0:85d8:901::4",
                        "117.50.10.10", "52.80.52.52",
                        "2400:7fc0:849e:200::8", "2404:c2c0:85d8:901::8",
                        "117.50.60.30", "52.80.60.30"
                    ],
                    "outboundTag": "direct",
                    "type": "field"
                },
                {
                    "domain": [
                        "domain:alidns.com", "domain:doh.pub", "domain:dot.pub",
                        "domain:360.cn", "domain:onedns.net"
                    ],
                    "outboundTag": "direct",
                    "type": "field"
                },
                {"network": "tcp,udp", "balancerTag": "all", "type": "field"},
                {
                    "type": "field",
                    "domain": ["geosite:openai", "geosite:microsoft", "geosite:oracle", "geosite:docker", "geosite:adobe", "geosite:epicgames", "geosite:intel", "geosite:amd", "geosite:nvidia", "geosite:asus", "hp", "geosite:lenovo"],
                    "outboundTag": "direct"
                }
            ],
            "balancers": [{"tag": "all", "selector": ["prox"], "strategy": {"type": "leastPing"}, "fallbackTag": "prox-1"}]
        },
        "stats": {},
        "observatory": {"subjectSelector": ["prox"], "probeUrl": "https://www.gstatic.com/generate_204", "probeInterval": "30s", "enableConcurrency": True}
    }

def build_v2rayng_template(remarks, outbound_nodes, pool_top_dns, pool_main_dns, ip_supplier, is_cloudflare=False):
    """
    Constructs a structural v2rayNG complete node balancing system schema.
    Uses the exact DNS servers formatting mapping requested by the user.
    """
    # Build complete full outbounds payload array mapping
    outbounds_payload = []
    for item in outbound_nodes:
        outbounds_payload.append(item)
        
    outbounds_payload.extend([
        {"protocol": "dns", "tag": "dns-out"},
        {"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}, "tag": "direct"},
        {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}
    ])

    return {
        "remarks": remarks,
        "log": {
            "loglevel": "warning"
        },
        "dns": {
            "servers": [
                {
                    "address": "https://dns.quad9.net/dns-query",
                    "tag": "remote-dns-1"
                },
                {
                    "address": "https://security.cloudflare-dns.com/dns-query",
                    "tag": "remote-dns-2"
                },
                {
                    "address": "udp://89.187.187.2:53",
                    "tag": "remote-dns-3"
                },
                {
                    "address": "https://8.8.8.8/dns-query",
                    "tag": "remote-dns-4"
                },
                {
                    "address": "tcp://45.11.45.11:853",
                    "tag": "remote-dns-5"
                },
                {
                    "address": "local",
                    "domains": [
                        "geosite:category-ir"
                    ],
                    "expectIPs": [
                        "geoip:ir"
                    ],
                    "skipFallback": False
                },
                {
                    "address": "78.157.42.100",
                    "domains": [
                        "geosite:category-ir"
                    ],
                    "expectIPs": [
                        "geoip:ir"
                    ],
                    "skipFallback": False
                },
                {
                    "address": "208.67.220.220",
                    "domains": [
                        "geosite:category-ir"
                    ],
                    "expectIPs": [
                        "geoip:ir"
                    ],
                    "skipFallback": False
                }
            ],
            "queryStrategy": "UseIP",
            "tag": "dns"
        },
        "inbounds": [
            {
                "port": 10808,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True,
                    "userLevel": 8
                },
                "sniffing": {
                    "destOverride": [
                        "http",
                        "tls"
                    ],
                    "enabled": False,
                    "routeOnly": False
                },
                "tag": "socks-in"
            },
            {
                "port": 10853,
                "protocol": "dokodemo-door",
                "settings": {
                    "address": "1.1.1.1",
                    "network": "tcp,udp",
                    "port": 53
                },
                "tag": "dns-in"
            }
        ],
        "outbounds": outbounds_payload,
        "policy": {
            "levels": {
                "8": {
                    "connIdle": 300,
                    "downlinkOnly": 1,
                    "handshake": 4,
                    "uplinkOnly": 1
                }
            },
            "system": {
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True
            }
        },
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "inboundTag": [
                        "dns-in"
                    ],
                    "outboundTag": "dns-out",
                    "type": "field"
                },
                {
                    "inboundTag": [
                        "socks-in"
                    ],
                    "port": 53,
                    "outboundTag": "dns-out",
                    "type": "field"
                },
                {
                    "inboundTag": [
                        "remote-dns-1",
                        "remote-dns-2",
                        "remote-dns-3",
                        "remote-dns-4",
                        "remote-dns-5"
                    ],
                    "balancerTag": "all",
                    "type": "field"
                },
                {
                    "inboundTag": [
                        "dns"
                    ],
                    "outboundTag": "direct",
                    "type": "field"
                },
                {
                    "domain": [
                        "geosite:category-ir"
                    ],
                    "outboundTag": "direct",
                    "type": "field"
                },
                {
                    "ip": [
                        "geoip:ir"
                    ],
                    "outboundTag": "direct",
                    "type": "field"
                },
                {
                    "network": "udp",
                    "outboundTag": "block",
                    "type": "field"
                },
                {
                    "network": "tcp",
                    "balancerTag": "all",
                    "type": "field"
                }
            ],
            "balancers": [
                {
                    "tag": "all",
                    "selector": [
                        "prox"
                    ],
                    "strategy": {
                        "type": "leastPing"
                    },
                    "fallbackTag": "prox-1"
                }
            ]
        },
        "stats": {},
        "observatory": {
            "subjectSelector": [
                "prox"
            ],
            "probeUrl": "https://www.gstatic.com/generate_204",
            "probeInterval": "30s",
            "enableConcurrency": True
        }
    }

def main():
    # This remains unchanged, assuming subscription data or URLs fetch logic goes here
    pass

if __name__ == "__main__":
    # The generation blocks pipeline matching output routing logic updates:
    output_file = "output.json"
    
    # Mock groups array dictionary allocation mapping placeholder setup (for reference check structural continuity)
    groups = {
        "vmess_tls": [],
        "vless_tls": [],
        "other_protocols": [] # Holds protocols like shadowsocks, trojan, etc.
    }
    pool_top_dns, pool_main_dns, ip_supplier = [], [], None
    final_output = []

    # 7. 🍀 7 VMESS - TLS LB 🔥
    if groups["vmess_tls"]:
        for idx, item in enumerate(groups["vmess_tls"]):
            item["tag"] = f"prox-{idx + 1}"
        final_output.append(build_v2rayng_template("🍀 7 VMESS - TLS LB 🔥", groups["vmess_tls"], pool_top_dns, pool_main_dns, ip_supplier, is_cloudflare=False))

    # 8. 🌵 8 VLESS - Fragment 🔥
    if groups["vless_tls"]:
        random_fragment_node = random.choice(groups["vless_tls"])
        final_output.append(build_bpb_fragment_template(random_fragment_node, ip_supplier))
            
    # Modified Section: Separate Other Protocols Group by protocol types instead of combining them into one.
    if groups["other_protocols"]:
        # Sort out nodes into separate buckets based on their protocol string value
        by_protocol = {}
        for item in groups["other_protocols"]:
            proto = item.get("protocol", "unknown")
            if proto not in by_protocol:
                by_protocol[proto] = []
            by_protocol[proto].append(item)
            
        # Generate a distinct standalone load balanced profile structure per protocol
        for protocol_name, nodes_list in by_protocol.items():
            # Standardize serial index tags unique to this specific outbound group list
            for idx, item in enumerate(nodes_list):
                item["tag"] = f"prox-{idx + 1}"
                
            # Define exact matching title formats matching your expected schema design patterns
            remarks_title = f"🌲 7 {protocol_name.upper()} - LB 🔥"
            
            # Append separate protocol block payload directly into final output collection
            final_output.append(build_v2rayng_template(remarks_title, nodes_list, pool_top_dns, pool_main_dns, ip_supplier, is_cloudflare=False))

    # Clean up the internal helper key '_original_address' across all templates before output serialization
    for template in final_output:
        if "outbounds" in template:
            for outbound in template["outbounds"]:
                if "_original_address" in outbound:
                    del outbound["_original_address"]

    with open(output_file, "w", encoding="utf-8") as out:
        json.dump(final_output, out, indent=2, ensure_ascii=False)
