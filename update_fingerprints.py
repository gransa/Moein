import os
import re
import ssl
import socket
import json
import base64
import hashlib
import requests

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
        with socket.create_connection((host, int(port)), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                if cert_der:
                    return hashlib.sha256(cert_der).hexdigest().upper()
    except Exception:
        pass
    return None

def process_vmess_line(line):
    """
    Decodes VMess payload, checks for TLS, and sets the certificate hash field
    under 'cert-sha256' or 'certSha256' while leaving original parameters intact.
    """
    try:
        b64_data = line[8:].strip()
        missing_padding = len(b64_data) % 4
        if missing_padding:
            b64_data += '=' * (4 - missing_padding)
            
        decoded_bytes = base64.b64decode(b64_data)
        config_json = json.loads(decoded_bytes.decode('utf-8'))
        
        tls_status = str(config_json.get("tls", "")).lower()
        if tls_status not in ["tls", "xtls", "1"]:
            return line

        host = config_json.get("add")
        port = config_json.get("port")
        sni = config_json.get("sni", host)
        
        if not host or not port:
            return line

        new_cert_hash = get_tls_fingerprint(host, port, sni)
        
        if new_cert_hash:
            # Set the actual certificate fingerprint without erasing client profile signatures
            config_json["cert-sha256"] = [new_cert_hash]
            print(f"✅ Cert Fingerprint pinned for {host}:{port} (VMESS) -> {new_cert_hash[:32]}...")
            
            updated_json_bytes = json.dumps(config_json, ensure_ascii=False).encode('utf-8')
            encoded_str = base64.b64encode(updated_json_bytes).decode('utf-8')
            return f"vmess://{encoded_str}"
            
    except Exception as e:
        print(f"❌ Error processing VMESS certificate logic: {e}")
    return line

def update_standard_line(line):
    """
    Parses VLESS/Trojan nodes. Keeps 'fp=chrome' intact and explicitly injects
    the live certificate fingerprint into the 'cert-sha256' query string parameter.
    """
    try:
        fragment = ""
        if "#" in line:
            line, fragment = line.split("#", 1)

        match = re.match(r'^([^:]+://)([^@]+@)?([^/?]+)([^?]*)\?(.*)$', line)
        if not match:
            return line + (f"#{fragment}" if fragment else "")

        scheme, auth, netloc, path_part, query_string = match.groups()
        auth = auth if auth else ""
        
        if ":" in netloc:
            host, port = netloc.split(":", 1)
        else:
            host, port = netloc, "443"

        # Map current query keys safely
        params = {}
        pairs = query_string.split('&')
        for pair in pairs:
            if '=' in pair:
                k, v = pair.split('=', 1)
                params[k] = v
            else:
                params[pair] = ""

        # Skip non-encrypted profiles
        security = params.get("security", "").lower()
        if security not in ["tls", "xtls", "reality"]:
            return line + (f"#{fragment}" if fragment else "")

        sni = params.get("sni", host)
        new_cert_hash = get_tls_fingerprint(host, port, sni)
        
        if new_cert_hash:
            # Inject the dedicated parameter for certificate fingerprinting 
            params["cert-sha256"] = new_cert_hash
            print(f"✅ Cert Fingerprint pinned for {host}:{port} ({scheme[:-3].upper()}) -> {new_cert_hash[:32]}...")
            
            rebuilt_query = "&".join([f"{k}={v}" if v else k for k, v in params.items()])
            rebuilt_url = f"{scheme}{auth}{netloc}{path_part}?{rebuilt_query}"
            if fragment:
                rebuilt_url += f"#{fragment}"
            return rebuilt_url

    except Exception as e:
        print(f"❌ Error appending certificate fingerprint to line: {e}")
        
    return line + (f"#{fragment}" if 'fragment' in locals() and fragment else "")

def main():
    print("🚀 Starting Dedicated Certificate Fingerprint Injector...")
    
    sub_urls_env = os.getenv("EXTERNAL_SUB_URL", "")
    if not sub_urls_env:
        print("❌ Error: Missing configuration variable 'EXTERNAL_SUB_URL'")
        return
        
    urls = [u.strip() for u in re.split(r'[\n,]+', sub_urls_env) if u.strip()]
    all_raw_configs = []
    
    for url in urls:
        try:
            res = requests.get(url, timeout=10)
            if res.status_code == 200:
                lines = res.text.splitlines()
                all_raw_configs.extend([l.strip() for l in lines if l.strip()])
        except Exception as e:
            print(f"⚠️ Connection drop fetching target subscription: {e}")

    updated_configs = []
    for config in all_raw_configs:
        if config.startswith("vmess://"):
            updated_line = process_vmess_line(config)
            updated_configs.append(updated_line)
        elif config.startswith("vless://") or config.startswith("trojan://"):
            updated_line = update_standard_line(config)
            updated_configs.append(updated_line)
        else:
            updated_configs.append(config)

    output_file = "Configs.txt"
    with open(output_file, "w", encoding="utf-8") as f:
        for cfg in updated_configs:
            f.write(cfg + "\n")
            
    print(f"🎉 Process completed successfully! Output pushed to {output_file}.")

if __name__ == "__main__":
    main()
