import os
import sys
import json
import base64
import re
from urllib.parse import urlparse, urlencode
import urllib.request

def resolve_dns(domain, record_type):
    types = {'A': 1, 'AAAA': 28}
    dns_type = types.get(record_type)
    if not dns_type:
        raise ValueError('Invalid record type')

    params = urlencode({'name': domain, 'type': dns_type})
    url = f"https://1.1.1.1/dns-query?{params}"
    
    req = urllib.request.Request(url, headers={'Accept': 'application/dns-json'})
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            if 'Answer' in data:
                return [ans['data'] for ans in data['Answer'] if ans['type'] == dns_type]
            return []
    except Exception as e:
        raise RuntimeError(f"DNS resolution failed: {e}")

def is_ipv4(ip):
    return bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip))

def is_ipv6(ip):
    return ':' in ip and bool(re.match(r'^[0-9a-fA-F:]+$', ip))

def format_server_address(server):
    if is_ipv4(server): return server
    if is_ipv6(server): return f"[{server}]"
    return server

def parse_ssconf_uri(ssconf):
    if not ssconf.startswith('ssconf://'):
        raise ValueError('Invalid ssconf URI: must start with ssconf://')
    
    url_str = ssconf.replace('ssconf://', 'https://')
    parsed = urlparse(url_str)
    
    fetch_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    if parsed.query:
        fetch_url += f"?{parsed.query}"
    return fetch_url

def main():
    default_uri = 'ssconf://s3.amazonaws.com/beedynconprd/zf38bv6oxi1nv3wfkpmxyfl8yj5fargza3foantoalu16vznl0ckxx7bgf1ufx51.json#BeePass'
    ssconf_input = os.environ.get('SSCONF_URI', default_uri)

    try:
        print(f"Processing URI: {ssconf_input}")
        fetch_url = parse_ssconf_uri(ssconf_input)

        req = urllib.request.urlopen(fetch_url)
        config = json.loads(req.read().decode())

        original_server = config['server']
        port = config['server_port']
        password = config['password']
        method = config['method']

        auth_bytes = f"{method}:{password}".encode('utf-8')
        auth = base64.b64encode(auth_bytes).decode('utf-8')

        servers = [original_server]
        if not is_ipv4(original_server) and not is_ipv6(original_server):
            print(f"Resolving DNS for host: {original_server}")
            ipv4s = resolve_dns(original_server, 'A')
            ipv6s = resolve_dns(original_server, 'AAAA')
            servers = ipv4s + ipv6s

        uris = []
        for ip in servers:
            formatted_ip = format_server_address(ip)
            custom_name = f"@{ip}-BeePass"
            uris.append(f"ss://{auth}@{formatted_ip}:{port}#{custom_name}")

        if not uris:
            raise RuntimeError('No valid server addresses found')

        sub_content = '\n'.join(uris)
        
        with open('BeePass.txt', 'w', encoding='utf-8') as f:
            f.write(sub_content)
        print("Successfully updated BeePass.txt with latest configs!")

    except Exception as e:
        print(f"Error running generator: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
