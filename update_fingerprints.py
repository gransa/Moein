import os
import re
import ssl
import socket
import hashlib
import requests
from urllib.parse import urlparse, parse_qs, urlencode, quote

def get_tls_fingerprint(host, port, sni=None):
    """
    Connects to the server over TLS and returns the SHA-256 fingerprint
    of its active certificate (hex format, uppercase).
    """
    context = ssl.create_default_context()
    # Bypass verification locally to pull the certificate regardless of validation state
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

def update_config_line(line):
    """
    Parses a single protocol configuration line, pulls its fresh TLS fingerprint,
    and updates/injects the fingerprint into the configuration parameters.
    """
    # Filter protocols
    if not (line.startswith("vless://") or line.startswith("trojan://")):
        return None

    try:
        # Split hash fragment (the config name alias) if it exists
        fragment = ""
        if "#" in line:
            line, fragment = line.split("#", 1)
            
        parsed = urlparse(line)
        protocol = parsed.scheme
        
        # Extract host and port handling authentication data seamlessly
        # (e.g., uuid@host:port or password@host:port)
        netloc = parsed.netloc
        if "@" in netloc:
            auth, netloc = netloc.split("@", 1)
        else:
            auth = None
            
        if ":" in netloc:
            host, port = netloc.split(":", 1)
        else:
            host, port = netloc, "443"

        # Parse query string arguments
        query_params = parse_qs(parsed.query)
        
        # Flatten query parameters from lists
        params = {k: v[0] for k, v in query_params.items()}
        
        # Only process if security explicitly demands TLS/XTLS/Reality
        security = params.get("security", "").lower()
        if security not in ["tls", "xtls", "reality"]:
            return None
            
        sni = params.get("sni", host)
        
        # Fetch fresh fingerprint
        new_fp = get_tls_fingerprint(host, port, sni)
        
        if new_fp:
            # Update configuration with the new fingerprint value
            params["fp"] = new_fp
            print(f"✅ Fingerprint updated for {host}:{port} ({protocol.upper()}) -> {new_fp[:32]}...")
            
            # Reconstruct the configuration URL
            new_query = urlencode(params)
            netloc_rebuilt = f"{auth}@{host}:{port}" if auth else f"{host}:{port}"
            
            rebuilt_url = f"{protocol}://{netloc_rebuilt}{parsed.path}?{new_query}"
            if fragment:
                rebuilt_url += f"#{fragment}"
            return rebuilt_url
            
    except Exception as e:
        print(f"❌ Error processing line parsing: {e}")
        
    return None

def main():
    print("🚀 Starting Multi-Protocol Fingerprint Updater...")
    
    # Safely pull subscription links from the Environment Variables configured in your Action
    sub_urls_env = os.getenv("EXTERNAL_SUB_URL", "")
    if not sub_urls_env:
        print("❌ Error: No subscription URLs found in environment variable 'EXTERNAL_SUB_URL'")
        return
        
    # Split by newline or comma to capture multiple URLs safely
    urls = [u.strip() for u in re.split(r'[\n,]+', sub_urls_env) if u.strip()]
    print(f"ℹ️ Detected {len(urls)} subscription link(s) inside configuration variable.")
    
    all_raw_configs = []
    
    for url in urls:
        print(f"📥 Fetching subscription link: {url}")
        try:
            res = requests.get(url, timeout=10)
            if res.status_code == 200:
                # Decodes plain text directly or splits multi-line string configs
                lines = res.text.splitlines()
                all_raw_configs.extend([l.strip() for l in lines if l.strip()])
                print("📄 Parsed subscription payload format.")
            else:
                print(f"⚠️ Failed to fetch {url} - Status Code: {res.status_code}")
        except Exception as e:
            print(f"⚠️ Request connection failed for {url}: {e}")

    print(f"📊 Total raw configurations loaded: {len(all_raw_configs)}")
    
    updated_configs = []
    count = 0
    
    for config in all_raw_configs:
        updated = update_config_line(config)
        if updated:
            updated_configs.append(updated)
            count += 1
        else:
            # Keep configuration as-is if it's non-TLS or failed to retrieve cert live
            if config.startswith("vless://") or config.startswith("trojan://"):
                updated_configs.append(config)

    # Output to target file
    output_file = "Configs.txt"
    with open(output_file, "w", encoding="utf-8") as f:
        for cfg in updated_configs:
            f.write(cfg + "\n")
            
    print(f"🎉 Process completed. Refreshed {count} configurations directly into {output_file}!")

if __name__ == "__main__":
    main()
