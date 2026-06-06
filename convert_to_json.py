import os
import json
import base64
import ipaddress
from urllib.parse import urlparse, unquote, parse_qs

def parse_vmess(url_str):
    try:
        b64_data = url_str.replace("vmess://", "").strip()
        b64_data += "=" * ((4 - len(b64_data) % 4) % 4)
        decoded = base64.b64decode(b64_data).decode('utf-8')
        config = json.loads(decoded)
        
        is_tls = str(config.get("tls", "")).lower() in ["tls", "1", "true"]
        net_type = config.get("net", "tcp")
        fp_val = config.get("fp", "chrome")
        
        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [
                    {
                        "address": config.get("add"),
                        "port": int(config.get("port", 443 if is_tls else 80)),
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
            outbound["streamSettings"]["tlsSettings"] = {
                "allowInsecure": False,
                "fingerprint": fp_val,
                "pinnedPeerCertSha256": config.get("pinnedPeerCertSha256", ""),
                "serverName": config.get("host", config.get("add")),
                "show": False
            }
            
        return outbound, is_tls
    except Exception as e:
        print(f"Error filtering VMESS format schema: {e}")
        return None, False

def parse_standard_uri(url_str, protocol):
    try:
        parsed_url = urlparse(url_str)
        userinfo = parsed_url.username or parsed_url.netloc.split('@')[0]
        host_port = parsed_url.netloc.split('@')[-1]
        
        if ':' in host_port:
            address, port = host_port.split(':')
        else:
            address, port = host_port, (443 if protocol in ["vless", "trojan"] else 80)
            
        query = parse_qs(parsed_url.query)
        params = {k: v[0] for k, v in query.items()}
        
        security = params.get("security", "").lower()
        is_tls = security in ["tls", "reality", "xtls"] or protocol == "trojan"
        net_type = params.get("type", "tcp")
        fp_val = params.get("fp", "chrome")
        cert_hash = params.get("pinnedPeerCertSha256", params.get("certfp", params.get("sha256", "")))
        
        outbound = {
            "protocol": protocol,
            "settings": {}
        }
        
        if protocol == "vless":
            outbound["settings"] = {
                "vnext": [{
                    "address": address,
                    "port": int(port),
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
                    "address": address,
                    "port": int(port),
                    "password": userinfo,
                    "level": 8
                }]
            }
        else:
            outbound["settings"] = {"servers": [{"address": address, "port": int(port)}]}
            
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
                "pinnedPeerCertSha256": cert_hash,
                "serverName": params.get("sni", address),
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
    
    # Dynamically extract and store clean domains
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
                # If it successfully parses as an IP address, safely ignore it
                ipaddress.ip_address(addr)
            except ValueError:
                # It's a clean domain name string! Prefix with 'full:'
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
                # Cleared default websites: Now exclusively matches your configuration node domains
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
            node_data, is_tls = parse_vmess(line)
            proto_key = "vmess_tls" if is_tls else "vmess_n_tls"
        elif line.startswith("vless://"):
            node_data, is_tls = parse_standard_uri(line, "vless")
            proto_key = "vless_tls" if is_tls else "vless_n_tls"
        elif line.startswith("trojan://"):
            node_data, is_tls = parse_standard_uri(line, "trojan")
            proto_key = "trojan_tls" if is_tls else "trojan_n_tls"
        elif "://" in line:
            p_name = line.split("://")[0].lower()
            node_data, is_tls = parse_standard_uri(line, p_name)
            proto_key = "other_protocols"
            
        if node_data and proto_key:
            node_data["tag"] = f"prox-{len(groups[proto_key]) + 1}"
            groups[proto_key].append(node_data)
                
    final_output = []
    
    mapping = [
        ("🌳 VLESS - TLS LB 🔥", "vless_tls"),
        ("🌳 VLESS - Non-TLS LB 🔥", "vless_n_tls"),
        ("🌳 TROJAN - TLS LB 🔥", "trojan_tls"),
        ("🌳 TROJAN - Non-TLS LB 🔥", "trojan_n_tls"),
        ("🌳 VMESS - TLS LB 🔥", "vmess_tls"),
        ("🌳 VMESS - Non-TLS LB 🔥", "vmess_n_tls"),
        ("🌳 OTHER PROTOCOLS LB 🔥", "other_protocols")
    ]
    
    for remark, key in mapping:
        if groups[key]:
            final_output.append(build_v2rayng_template(remark, groups[key]))
            
    with open(output_file, "w", encoding="utf-8") as out:
        json.dump(final_output, out, indent=2, ensure_ascii=False)
        
    print(f"🎉 Array generation complete! Domains mapped dynamically into '{output_file}'")

if __name__ == "__main__":
    main()
