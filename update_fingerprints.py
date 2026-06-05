import requests
import base64
import hashlib
import socket
import ssl
from urllib.parse import urlparse, parse_qs, urlencode

def get_cert_fingerprint(host, port=443, sni=None):
    if sni is None:
        sni = host
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=15) as sock:
            with context.wrap_socket(sock, server_hostname=sni) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                fp = hashlib.sha256(cert).hexdigest().upper()
                print(f"✅ Fingerprint for {host}: {fp[:32]}...")
                return fp
    except Exception as e:
        print(f"❌ Failed to get fingerprint: {e}")
        return None

def update_vless_config(line):
    try:
        if not line or not line.startswith('vless://'):
            return line

        if '#' in line:
            config_part, remark = line.split('#', 1)
        else:
            config_part, remark = line, ""

        parsed = urlparse(config_part)
        query = parse_qs(parsed.query)

        host = parsed.hostname
        port = parsed.port or 443
        sni = query.get('sni', [None])[0] or query.get('host', [None])[0] or host

        fp = get_cert_fingerprint(host, port, sni)
        if not fp:
            return line

        # Update pcs parameter
        new_query = {k: v for k, v in query.items() if k.lower() != 'pcs'}
        new_query['pcs'] = [fp]

        new_query_str = urlencode(new_query, doseq=True)
        new_url = f"vless://{parsed.netloc}{parsed.path}?{new_query_str}"
        if remark:
            new_url += f"#{remark}"

        return new_url
    except Exception as e:
        print(f"⚠️ Error processing config: {e}")
        return line

def main():
    print("🚀 Starting Fingerprint Updater...")

    url = "https://raw.githubusercontent.com/gransa/Moein/main/Configs.txt"
    print(f"📥 Downloading: {url}")

    resp = requests.get(url, timeout=20)
    resp.raise_for_status()
    content = resp.text.strip()

    # Decode if it's base64
    try:
        decoded = base64.b64decode(content + '===').decode('utf-8')
        lines = [line.strip() for line in decoded.splitlines() if line.strip()]
        print("🔓 Decoded base64 subscription")
    except:
        lines = [line.strip() for line in content.splitlines() if line.strip()]

    print(f"✅ Loaded {len(lines)} lines")

    # Update configs
    updated = []
    for line in lines:
        if line.startswith('vless://'):
            updated.append(update_vless_config(line))
        else:
            updated.append(line)

    final_content = '\n'.join(updated)

    # Save as base64 (same format as before)
    final_base64 = base64.b64encode(final_content.encode('utf-8')).decode('utf-8')

    with open("Configs.txt", "w", encoding="utf-8") as f:
        f.write(final_base64)

    print(f"🎉 Successfully updated {len(updated)} configs!")
    print("✅ Configs.txt updated successfully.")

if __name__ == "__main__":
    main()
