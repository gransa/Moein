import hashlib
import os
import socket
import ssl
from urllib.parse import urlparse, parse_qs, urlencode

def get_cert_fingerprint(host, port=443, sni=None):
    if sni is None:
        sni = host
        
    # We create a relaxed SSL context that skips strict hostname verification 
    # to ensure we grab the raw peer certificate from the target IP address.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=sni) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                fp = hashlib.sha256(cert).hexdigest().upper()
                print(f"✅ Fingerprint for {sni} via {host}:{port} -> {fp[:16]}...")
                return fp
    except Exception as e:
        print(f"❌ Failed to get fingerprint for {sni} via {host}:{port}: {e}")
        return None

def update_vless_config(line):
    try:
        if not line.startswith('vless://'):
            return line

        if '#' in line:
            config_part, remark = line.split('#', 1)
        else:
            config_part, remark = line, ""

        parsed = urlparse(config_part)
        query = parse_qs(parsed.query)

        # Check security; if plaintext/empty, it doesn't use TLS fingerprints
        security = query.get('security', [''])[0]
        if security.lower() not in ['tls', 'xtls']:
            # Return line unchanged or skip entirely since it has no cert
            return line

        host = parsed.hostname
        port = parsed.port or 443
        sni = query.get('sni', [None])[0] or query.get('host', [None])[0] or host

        fp = get_cert_fingerprint(host, port, sni)
        if not fp:
            return line

        # Re-build query parameters, replacing or adding 'pcs'
        new_query = {k: v for k, v in query.items() if k.lower() != 'pcs'}
        new_query['pcs'] = [fp]

        new_query_str = urlencode(new_query, doseq=True)
        new_url = f"vless://{parsed.netloc}{parsed.path}?{new_query_str}"
        if remark:
            new_url += f"#{remark}"
        return new_url
    except Exception:
        return line

def main():
    print("🚀 Starting Local Fingerprint Updater...")

    raw_lines = []
    # 1. Read directly from your local config source files
    input_files = ["Conf-01.txt", "Conf-02.txt"]
    
    for filename in input_files:
        if os.path.exists(filename):
            print(f"📥 Reading {filename}...")
            with open(filename, "r", encoding="utf-8") as f:
                for line in f:
                    cleaned = line.strip()
                    if cleaned:
                        raw_lines.append(cleaned)
        else:
            print(f"⚠️ Warning: {filename} not found.")

    print(f"📊 Total raw configurations loaded: {len(raw_lines)}")

    updated_configs = []
    for line in raw_lines:
        if line.startswith('vless://'):
            # Only process TLS items, keep non-tls as-is without pcs
            updated_configs.append(update_vless_config(line))
        else:
            updated_configs.append(line)

    # 2. Write all combined, updated configs into your final output file
    final_content = '\n'.join(updated_configs)
    with open("Configs.txt", "w", encoding="utf-8") as f:
        f.write(final_content)

    print(f"🎉 Process completed. Results successfully dumped to Configs.txt!")

if __name__ == "__main__":
    main()
