import os
import json
import base64
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
            "certificate fingerprint": fp_val,  # <-- Added exact custom key here
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
                "fingerprint": fp_val,
                "serverName": config.get("host", config.get("add"))
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
        
        outbound = {
            "protocol": protocol,
            "certificate fingerprint": fp_val,  # <-- Added exact custom key here
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
                "fingerprint": fp_val,
                "serverName": params.get("sni", address)
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
    
    return {
        "remarks": remarks,
        "log": {"loglevel": "warning"},
        "dns": {
            "servers": [
                {"address": "https://8.8.8.8/dns-query", "tag": "remote-dns"},
                {"address": "8.8.8.8", "domains": ["geosite:category-ir"], "expectIPs": ["geoip:ir"], "skipFallback": True},
                {"address": "8.8.8.8", "domains": ["full:digitalocean.com", "full:www.visaeurope.ch", "full:check-host.net", "full:adf.ly", "full:feedly.com", "full:www.speedtest.net"], "skipFallback": True}
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

    tls_nodes = []
    n_tls_nodes = []
    
    with open(input_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
        
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        node_data = None
        is_tls = False
        
        if line.startswith("vmess://"):
            node_data, is_tls = parse_vmess(line)
        elif line.startswith("vless://"):
            node_data, is_tls = parse_standard_uri(line, "vless")
        elif line.startswith("trojan://"):
            node_data, is_tls = parse_standard_uri(line, "trojan")
            
        if node_data:
            if is_tls:
                node_data["tag"] = f"prox-{len(tls_nodes) + 1}"
                tls_nodes.append(node_data)
            else:
                node_data["tag"] = f"prox-{len(n_tls_nodes) + 1}"
                n_tls_nodes.append(node_data)
                
    final_output = [
        build_v2rayng_template("🌳 1 - TLS LB - CF CDN 🔥", tls_nodes),
        build_v2rayng_template("🌳 2 - n-TLS LB - CF CDN 🔥", n_tls_nodes)
    ]
    
    with open(output_file, "w", encoding="utf-8") as out:
        json.dump(final_output, out, indent=2, ensure_ascii=False)
        
    print(f"🎉 Array generation complete! File updated: '{output_file}'")

if __name__ == "__main__":
    main()
