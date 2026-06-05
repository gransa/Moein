import requests
import base64
import hashlib
import socket
import ssl
from urllib.parse import urlparse, parse_qs, urlencode
from datetime import datetime

def get_cert_fingerprint(host, port=443, sni=None):
    """Get SHA-256 certificate fingerprint"""
    if sni is None:
        sni = host
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=15) as sock:
            with context.wrap_socket(sock, server_hostname=sni) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                fp = hashlib.sha256(cert).hexdigest().upper()
                print(f"✅ Fingerprint updated for {host} → {fp[:32]}...")
                return fp
    except Exception as e:
        print(f"❌ Failed to get fingerprint for {host}: {e}")
        return None


def update_configs():
    """Update fingerprints for all VLESS configs"""
    # Add your subscription links here
    input_urls = [
        "https://github.com/gransa/Moein/raw/main/Configs.txt",
        # Add more subscription links if needed
    ]
    
    all_configs = []
    
    for url in input_urls:
        try:
            print(f"Fetching subscription: {url}")
            r = requests.get(url, timeout=20)
            r.raise_for_status()
            content = r.text.strip()
            
            # Decode if it's base64
            if not any(content.startswith(x) for x in ['vless://', 'vmess://', 'trojan://']):
                try:
                    content = base64.b64decode(content + '==').decode('utf-8')
                except:
                    pass
            
            lines = [line.strip() for line in content.splitlines() if line.strip()]
            all_configs.extend([line for line in lines if line.startswith('vless://')])
            
        except Exception as e:
            print(f"Error fetching {url}: {e}")
    
    print(f"Found {len(all_configs)} VLESS configs")
    
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
                # Remove old pcs and add new one
                new_query = {k: v for k, v in query.items() if k != 'pcs'}
                new_query['pcs'] = [fp]
                
                new_url = f"vless://{parsed.netloc}{parsed.path}?{urlencode(new_query, doseq=True)}"
                if remark:
                    new_url += f"#{remark.strip()}"
                updated_configs.append(new_url)
            else:
                updated_configs.append(line)
        except:
            updated_configs.append(line)
    
    final_text = "\n".join(updated_configs)
    final_base64 = base64.b64encode(final_text.encode('utf-8')).decode('utf-8')
    
    with open("Configs.txt", "w", encoding="utf-8") as f:
        f.write(final_base64)
    
    print(f"\n🎉 Successfully updated {len(updated_configs)} configs!")
    return final_base64


if __name__ == "__main__":
    update_configs()
