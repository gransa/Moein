import hashlib
import os
import socket
import ssl
import json
import base64
from urllib.parse import urlparse, parse_qs, urlencode

def get_cert_fingerprint(host, port=443, sni=None):
    if not sni:
        sni = host
        
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

def process_standard_url(line, scheme):
    """Processes protocols that use standard URL formats like vless:// and trojan://"""
    try:
        if '#' in line:
            config_part, remark = line.split('#', 1)
        else:
            config_part, remark = line, ""

        parsed = urlparse(config_part)
        query = parse_qs(parsed.query)

        # Check if security uses TLS
        security = query.get('security', [''])[0]
        if security.lower() not in ['tls', 'xtls']:
            return line

        host = parsed.hostname
        port = parsed.port or 443
        sni = query.get('sni', [None])[0] or query.get('host', [None])[0] or host

        fp = get_cert_fingerprint(host, port, sni)
        if not fp:
            return line

        # Rebuild query parameter with updated pcs value
        new_query = {k: v for k, v in query.items() if k.lower() != 'pcs'}
        new_query['pcs'] = [fp]

        new_query_str = urlencode(new_query, doseq=True)
        new_url = f"{scheme}://{parsed.netloc}{parsed.path}?{new_query_str}"
        if remark:
            new_url += f"#{remark}"
        return new_url
    except Exception:
        return line

def process_vmess(line):
    """Processes vmess:// configurations which are Base64 encoded JSON blobs"""
    try:
        raw_b64 = line[8:].strip()
        # Fix missing padding if any
        padded_b64 = raw_b64 + '=' * (-len(raw_b64) % 4)
        decoded_bytes = base64.b64decode(padded_b64)
        config_data = json.loads(decoded_bytes.decode('utf-8'))

        # Check if TLS security is enabled in VMess structure
        tls_status = config_data.get('tls', '')
        # Some configs use 'tls', others use 'security': 'tls'
        if str(tls_status).lower() != 'tls' and str(config_data.get('security', '')).lower() != 'tls':
            return line

        host = config_data.get('add')
        try:
            port = int(config_data.get('port', 443))
        except ValueError:
            port = 443
            
        sni = config_data.get('sni') or config_data.get('host') or host

        fp = get_cert_fingerprint(host, port, sni)
        if not fp:
            return line

        # Set or update fingerprint field
        config_data['pcs'] = fp

        # Re-encode back to string format vmess://
        json_str = json.dumps(config_data, ensure_ascii=False)
        new_b64 = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
        return f"vmess://{new_b64}"
    except Exception:
        return line

def main():
    print("🚀 Starting Multi-Protocol Fingerprint Updater...")

    raw_lines = []
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
            updated_configs.append(process_standard_url(line, 'vless'))
        elif line.startswith('trojan://'):
            updated_configs.append(process_standard_url(line, 'trojan'))
        elif line.startswith('vmess://'):
            updated_configs.append(process_vmess(line))
        else:
            # Pass through unrecognized protocols (shadowsocks, hysteria2, etc.) or blank lines
            updated_configs.append(line)

    # Write all processed configs to your production output destination
    final_content = '\n'.join(updated_configs)
    with open("Configs.txt", "w", encoding="utf-8") as f:
        f.write(final_content)

    print(f"🎉 Process completed. Results successfully dumped to Configs.txt!")

if __name__ == "__main__":
    main()
