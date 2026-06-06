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
        
        # Check if TLS is enabled in VMESS configuration fields
        is_tls = str(config.get("tls", "")).lower() in ["tls", "1", "true"]
        
        return {
            "protocol": "vmess",
            "remarks": config.get("ps", "VMESS_Node"),
            "address": config.get("add"),
            "port": int(config.get("port", 0)),
            "id": config.get("id"),
            "aid": int(config.get("aid", 0)),
            "net": config.get("net", "tcp"),
            "type": config.get("type", "none"),
            "host": config.get("host", ""),
            "path": config.get("path", ""),
            "tls": "tls" if is_tls else ""
        }, is_tls
    except Exception as e:
        print(f"Error parsing VMESS block: {e}")
        return None, False

def parse_standard_uri(url_str, protocol):
    try:
        parsed_url = urlparse(url_str)
        userinfo = parsed_url.username or parsed_url.netloc.split('@')[0]
        host_port = parsed_url.netloc.split('@')[-1]
        
        if ':' in host_port:
            address, port = host_port.split(':')
        else:
            address, port = host_port, 443
            
        query = parse_qs(parsed_url.query)
        remarks = unquote(parsed_url.fragment) if parsed_url.fragment else f"{protocol.upper()}_Node"
        params = {k: v[0] for k, v in query.items()}
        
        # Determine TLS status for VLESS/Trojan based on security or security-like parameters
        security = params.get("security", "").lower()
        is_tls = security in ["tls", "reality", "xtls"] or protocol == "trojan"
        
        return {
            "protocol": protocol,
            "remarks": remarks,
            "address": address,
            "port": int(port),
            "id": userinfo,
            "sni": params.get("sni", ""),
            "type": params.get("type", "tcp"),
            "path": params.get("path", ""),
            "security": security if security else ("tls" if is_tls else "none"),
            "fp": params.get("fp", "")
        }, is_tls
    except Exception as e:
        print(f"Error parsing {protocol.upper()} block: {e}")
        return None, False

def main():
    input_file = "Configs.txt"
    output_file = "NG-JSON-Configs.txt"
    
    if not os.path.exists(input_file):
        print(f"Source file {input_file} not found.")
        return

    # Master structure containing separate configuration arrays
    output_data = {
        "tls_configs": [],
        "non_tls_configs": []
    }
    
    with open(input_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
        
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        parsed = None
        is_tls = False
        
        if line.startswith("vmess://"):
            parsed, is_tls = parse_vmess(line)
        elif line.startswith("vless://"):
            parsed, is_tls = parse_standard_uri(line, "vless")
        elif line.startswith("trojan://"):
            parsed, is_tls = parse_standard_uri(line, "trojan")
        else:
            prefix = line.split("://")[0] if "://" in line else "unknown"
            if "://" in line:
                parsed, is_tls = parse_standard_uri(line, prefix)
                
        if parsed:
            if is_tls:
                output_data["tls_configs"].append(parsed)
            else:
                output_data["non_tls_configs"].append(parsed)
            
    with open(output_file, "w", encoding="utf-8") as out:
        json.dump(output_data, out, indent=2, ensure_ascii=False)
        
    total_parsed = len(output_data["tls_configs"]) + len(output_data["non_tls_configs"])
    print(f"🎉 Structured {total_parsed} entries into '{output_file}'!")
    print(f"   🔒 TLS Nodes: {len(output_data['tls_configs'])} | 🔓 Non-TLS Nodes: {len(output_data['non_tls_configs'])}")

if __name__ == "__main__":
    main()
