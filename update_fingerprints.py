import base64
import hashlib
import socket
import ssl
import os
import datetime
import requests
from urllib.parse import urlparse, parse_qs, urlencode

def get_cert_fingerprint(host, port=443, sni=None):
    """
    Connects to the host via SSL/TLS and extracts the SHA-256 certificate fingerprint.
    """
    if sni is None:
        sni = host
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=sni) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                fp = hashlib.sha256(cert).hexdigest().upper()
                print(f"✅ Fingerprint for {host}:{port} -> {fp[:32]}...")
                return fp
    except Exception as e:
        print(f"❌ Failed to get fingerprint for {host}:{port} -> {e}")
        return None

def update_vless_config(line):
    """
    Parses a VLESS link, checks if it uses TLS, grabs the remote fingerprint,
    and appends/updates it inside the 'pcs' query parameter.
    """
    try:
        if not line.startswith('vless://'):
            return line

        if '#' in line:
            config_part, remark = line.split('#', 1)
        else:
            config_part, remark = line, ""

        parsed = urlparse(config_part)
        query = parse_qs(parsed.query)

        security = query.get('security', [''])[0].lower()
        if security != 'tls':
            return line

        host = parsed.hostname
        port = parsed.port or 443
        sni = query.get('sni', [None])[0] or query.get('host', [None])[0] or host

        fp = get_cert_fingerprint(host, port, sni)
        if not fp:
            return line

        new_query = {k: v for k, v in query.items() if k.lower() != 'pcs'}
        new_query['pcs'] = [fp]

        new_query_str = urlencode(new_query, doseq=True)
        new_url = f"vless://{parsed.netloc}{parsed.path}?{new_query_str}"
        if remark:
            new_url += f"#{remark}"
        return new_url
    except Exception:
        return line

def load_remote_url(url):
    """
    Downloads a subscription link and extracts its lines.
    Supports both raw standard text configs and standard Base64 subscription blocks.
    """
    try:
        print(f"📥 Fetching subscription link: {url}")
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        content = resp.text.strip()
        
        try:
            decoded = base64.b64decode(content + '===').decode('utf-8')
            print("🔓 Decoded subscription payload from Base64 configuration.")
            return [line.strip() for line in decoded.splitlines() if line.strip()]
        except Exception:
            print("📄 Parsed subscription payload as plain text format.")
            return [line.strip() for line in content.splitlines() if line.strip()]
    except Exception as e:
        print(f"❌ Failed to download subscription lines: {e}")
        return []

def main():
    print("🚀 Starting Multi-Protocol Fingerprint Updater...")
    lines = []
    
    raw_env_items = os.environ.get("EXTERNAL_SUB_URL", "").strip()
    if raw_env_items:
        external_urls = [url.strip() for url in raw_env_items.split(",") if url.strip()]
        print(f"ℹ️ Detected {len(external_urls)} subscription link(s) inside configuration variable.")
        
        for url in external_urls:
            remote_lines = load_remote_url(url)
            lines.extend(remote_lines)
    else:
        print("⚠️ Variable empty or missing. No subscription links processed.")

    print(f"📊 Total raw configurations loaded: {len(lines)}")

    updated = []
    vless_count = 0
    for line in lines:
        if line.startswith('vless://'):
            vless_count += 1
            updated.append(update_vless_config(line))
        else:
            updated.append(line)

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    updated.append(f"\n# Last updated: {timestamp}")

    final_content = '\n'.join(updated)

    with open("Configs.txt", "w", encoding="utf-8") as f:
        f.write(final_content)

    print(f"🎉 Process completed. Updated {vless_count} VLESS configs to Configs.txt!")

if __name__ == "__main__":
    main()
