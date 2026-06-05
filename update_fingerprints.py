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
    Decodes a VMess configuration payload string, extracts connection fields,
    fetches the TLS fingerprint, and preserves existing values if a timeout occurs.
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

        new_fp = get_tls_fingerprint(host, port, sni)
        
        if new_fp:
            config_json["fp"] = new_fp
            print(f"✅ Fingerprint updated for {host}:{port} (VMESS) -> {new_fp[:32]}...")
        else:
            if "fp" in config_json and config_json["fp"]:
                print(f"ℹ️  Keeping existing fingerprint for offline host {host}:{port}")
            else:
                print(f"⚠️  No fingerprint found or retrieved for offline host {host}:{port}")

        updated_json_bytes = json.dumps(config_json, ensure_ascii=False).encode('utf-8')
        encoded_str = base64.b64encode(updated_json_bytes).decode('utf-8')
        return f"vmess://{encoded_str}"
            
    except Exception as e:
        print(f"❌ Error parsing VMESS configuration structure: {e}")
    return line

def update_standard_line(line):
    """
    Parses VLESS/Trojan nodes using regular expressions rather than urllib.parse
    to avoid breaking mixed characters and raw strings like path=/?ed=2560.
    """
    try:
        # Step 1: Isolate user comment fragment if present
        fragment = ""
        if "#" in line:
            line, fragment = line.split("#", 1)

        # Step 2: Separate core schema and main string components
        match = re.match(r'^([^:]+://)([^@]+@)?([^/?]+)([^?]*)\?(.*)$', line)
        if not match:
            # If there's no query parameter configuration string block at all
            return line + (f"#{fragment}" if fragment else "")

        scheme, auth, netloc, path_part, query_string = match.groups()
        auth = auth if auth else ""
        
        # Parse Host and Port precisely
        if ":" in netloc:
            host, port = netloc.split(":", 1)
        else:
            host, port = netloc, "443"

        # Step 3: Turn string params cleanly into a mutable dictionary block
        params = {}
        # Splitting using native '&' boundaries cleanly
        pairs = query_string.split('&')
        for pair in pairs:
            if '=' in pair:
                k, v = pair.split('=', 1)
                params[k] = v
            else:
                params[pair] = ""

        # Step 4: Validate TLS status before reaching out
        security = params.get("security", "").lower()
        if security not in ["tls", "xtls", "reality"]:
            # Reconstruct completely untouched to prevent path modifications
            rebuilt_url = f"{scheme}{auth}{netloc}{path_part}?{query_string}"
            if fragment:
                rebuilt_url += f"#{fragment}"
            return rebuilt_url

        sni = params.get("sni", host)
        new_fp = get_tls_fingerprint(host, port, sni)
        
        if new_fp:
            params["fp"] = new_fp
            print(f"✅ Fingerprint updated for {host}:{port} ({scheme[:-3].upper()}) -> {new_fp[:32]}...")
        else:
            if "fp" in params:
                print(f"ℹ️  Keeping existing fingerprint for offline host {host}:{port}")
            else:
                print(f"⚠️  No fingerprint found or retrieved for offline host {host}:{port}")

        # Step 5: Assemble parameters strictly keeping original string structures intact
        rebuilt_query = "&".join([f"{k}={v}" if v else k for k, v in params.items()])
        rebuilt_url = f"{scheme}{auth}{netloc}{path_part}?{rebuilt_query}"
        if fragment:
            rebuilt_url += f"#{fragment}"
        return rebuilt_url

    except Exception as e:
        print(f"❌ Error processing standard line parsing: {e}")
        
    return line + (f"#{fragment}" if 'fragment' in locals() and fragment else "")

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
            updated_configs.append(config)

    output_file = "Configs.txt"
    with open(output_file, "w", encoding="utf-8") as f:
        for cfg in updated_configs:
            f.write(cfg + "\n")
            
    print(f"🎉 Process completed successfully! Verified updates written to {output_file}.")

if __name__ == "__main__":
    main()
