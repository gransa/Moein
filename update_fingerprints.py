import requests
import base64
import hashlib
import socket
import ssl
from urllib.parse import urlparse, parse_qs, urlencode
import sys

def get_cert_fingerprint(host, port=443, sni=None):
    if sni is None:
        sni = host
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=sni) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                fp = hashlib.sha256(cert).hexdigest().upper()
                print(f"✅ Fingerprint for {host}: {fp[:32]}...")
                return fp
    except Exception as e:
        print(f"❌ Failed to get fingerprint for {host}: {e}")
        return None

def main():
    print("🚀 Starting Fingerprint Updater...")

    input_urls = [
        "https://github.com/gransa/Moein/raw/main/Configs.txt",
    ]

    all_configs = []

    for url in input_urls:
        try:
            print(f"📥 Downloading: {url}")
            r = requests.get(url, timeout=25)
            r.raise_for_status()
            content = r.text.strip()

            # Decode base64 if necessary
            if not content.startswith('vless://'):
                try:
                    content = base64.b64decode(content + '==').decode('utf-8')
                except:
                    pass

            lines = [line.strip() for line in content.splitlines() if line.strip() and line.startswith('vless://')]
            all_configs.extend(lines)
            print(f"✅ Loaded {len(lines)} VLESS configs from {url}")
        except Exception as e:
            print(f"❌ Error downloading {url}: {e}")

    print(f"Total VLESS configs found: {len(all_configs)}")

    updated_configs = []
    for line in all_configs:
        try:
            if '#' in line:
                url_part, remark = line.split('#', 1)
            else:
                url_part, remark = line, ""

            parsed = urlparse(url_part)
            query = parse_qs(parsed.query)

            host = parsed.hostname
            port = int(parsed.port) if parsed.port else 443
            sni = query.get('sni', [None])[0] or query.get('host', [None])[0] or host

            fp = get_cert_fingerprint(host, port, sni)

            if fp:
                new_query = {k: v for k, v in query.items() if k != 'pcs'}
                new_query['pcs'] = [fp]

                new_url = f"vless://{parsed.netloc}{parsed.path}?{urlencode(new_query, doseq=True)}"
                if remark:
                    new_url += f"#{remark.strip()}"
                updated_configs.append(new_url)
            else:
                updated_configs.append(line)
        except Exception as e:
            print(f"⚠️ Skipped one config: {e}")
            updated_configs.append(line)

    final_text = "\n".join(updated_configs)
    final_base64 = base64.b64encode(final_text.encode('utf-8')).decode('utf-8')

    with open("Configs.txt", "w", encoding="utf-8") as f:
        f.write(final_base64)

    print(f"🎉 Successfully updated {len(updated_configs)} configs!")
    print("✅ Configs.txt has been updated.")

if __name__ == "__main__":
    main()
