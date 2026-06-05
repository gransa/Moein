import os
import re
import ssl
import socket
import json
import base64
import hashlib
import requests
from urllib.parse import urlparse, parse_qs, urlencode

def get_tls_fingerprint(host, port, sni=None):
    """
    Connects to the server over TLS and returns the SHA-256 fingerprint
    of its active certificate (hex format, uppercase).
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    server_hostname = sni if sni else host
    
    try:
        with socket.create_connection((host, int(port)), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                if cert_der:
                    return hashlib.sha256(cert_der).hexdigest().upper()
    except Exception as e:
        print(f"⚠️  Failed to connect to {host}:{port} -> {e}")
    return None

def process_vmess_line(line):
    """
    Decodes a VMess configuration payload string, extracts connection fields,
    fetches the TLS fingerprint if applicable, and updates the inner parameters.
    """
    try:
        # Strip the protocol header prefix
        b64_data = line[8:].strip()
        
        # Correct padding if the Base64 block lacks trailing '=' symbols
        missing_padding = len(b64_data) % 4
        if missing_padding:
            b64_data += '=' * (4 - missing_padding)
            
        decoded_bytes = base64.b64decode(b64_data)
        config_json = json.loads(decoded_bytes.decode('utf-8'))
        
        # Check if TLS/security flag is configured
        tls_status = str(config_json.get("tls", "")).lower()
        if tls_status not in ["tls", "xtls", "1"]:
            return line  # Return as-is if TLS isn't leveraged

        host = config_json.get("add")
        port = config_json.get("port")
        sni = config_json.get("sni", host)
        
        if not host or not port:
            return line

        new_fp = get_tls_fingerprint(host, port, sni)
        if new_fp:
            # Update the fingerprint property in VMess configuration structure
            config_json["fp"] = new_fp
            print(f"✅ Fingerprint updated for {host}:{port} (VMESS) -> {new_fp[:32]}...")
            
            # Re-encode back to safe JSON structure and wrap inside base64 string format
            updated_json_bytes = json.dumps(config_json, ensure_ascii=False).encode('utf-8')
            encoded_str = base64.b64encode(updated_json_bytes).decode('utf-8')
            return f"vmess://{encoded_str}"
            
    except Exception as e:
        print(f"❌ Error parsing VMESS configuration structure: {e}")
        
    return line

def update_standard_line(line):
    """
    Parses standard URI configurations (VLESS/Trojan), fetches live fingerprints,
    and returns updated connection configuration lines.
    """
    try:
        fragment = ""
        if "#" in line:
            line, fragment = line.split("#", 1)
            
        parsed = urlparse(line)
        protocol = parsed.scheme
        
        netloc = parsed.netloc
        if "@" in netloc:
            auth, netloc = netloc.split("@", 1)
        else:
            auth = None
            
        if ":" in netloc:
            host, port = netloc.split(":", 1)
        else:
            host, port = netloc, "443"

        query_params = parse_qs(parsed.query)
        params = {k: v[0] for k, v in query_params.items()}
        
        security = params.get("security", "").lower()
        if security not in ["tls", "xtls", "reality"]:
            return line
            
        sni = params.get("sni", host)
        new_fp = get_tls_fingerprint(host, port, sni)
        
        if new_fp:
            params["fp"] = new_fp
            print(f"✅ Fingerprint updated for {host}:{port} ({protocol.upper()}) -> {new_fp[:32]}...")
            
            new_query = urlencode(params)
            netloc_rebuilt = f"{auth}@{host}:{port}" if auth else f"{host}:{port}"
            
            rebuilt_url = f"{protocol}://{netloc_rebuilt}{parsed.path}?{new_query}"
            if fragment:
                rebuilt_url += f"#{fragment}"
            return rebuilt_url
            
    except Exception as e:
        print(f"❌ Error processing line parsing: {e}")
        
    return line

def main():
    print("🚀 Starting Multi-Protocol Fingerprint Updater...")
    
    sub_urls_env = os.getenv("EXTERNAL_SUB_URL", "")
    if not sub_urls_env:
        print("❌ Error: No subscription URLs found in environment variable 'EXTERNAL_SUB_URL'")
        return
        
    urls = [u.strip() for u in re.split(r'[\n,]+', sub_urls_env) if u.strip()]
    print(f"ℹ️ Detected {len(urls)} subscription link(s) inside configuration variable.")
    
    all_raw_configs = []
    
    for url in urls:
        print(f"📥 Fetching subscription link: {url}")
        try:
            res = requests.get(url, timeout=10)
            if res.status_code == 200:
                lines = res.text.splitlines()
                all_raw_configs.extend([l.strip() for l in lines if l.strip()])
                print("📄 Parsed subscription payload format.")
            else:
                print(f"⚠️ Failed to fetch {url} - Status Code: {res.status_code}")
        except Exception as e:
            print(f"⚠️ Request connection failed for {url}: {e}")

    print(f"📊 Total raw configurations loaded: {len(all_raw_configs)}")
    
    updated_configs = []
    
    for config in all_raw_configs:
        if config.startswith("vmess://"):
            updated_line = process_vmess_line(config)
            updated_configs.append(updated_line)
        elif config.startswith("vless://") or config.startswith("trojan://"):
            updated_line = update_standard_line(config)
            updated_configs.append(updated_line)
        else:
            # Pass through any other content (comments, ss://, shadowsocks configurations, etc.)
            updated_configs.append(config)

    # Save exactly back to output file
    output_file = "Configs.txt"
    with open(output_file, "w", encoding="utf-8") as f:
        for cfg in updated_configs:
            f.write(cfg + "\n")
            
    print(f"🎉 Process completed successfully! Verified updates written to {output_file}.")

if __name__ == "__main__":
    main()
