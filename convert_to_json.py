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
    """Converts text lines into paired dictionary groupings with smart local resolution fallback matching."""
    paired = []
    i = 0
    while i < len(pool_dns_servers):
        item = pool_dns_servers[i].strip()
        if not item:
            i += 1
            continue

        if (item.startswith("https://") or item.startswith("tcp:") or item.startswith("quic:") or 
            item.startswith("udp:") or item.startswith("[") or re.match(r'^\d{1,3}(\.\d{1,3}){
