import urllib.request
import socket
import re
import concurrent.futures

# URL containing the IPs and domains
URL = "https://raw.githubusercontent.com/gransa/Moein/refs/heads/main/CF-For-Convert.txt"
OUTPUT_FILE = "Cloudflare-IPs.txt"

# Simple regex patterns to identify IPv4 and basic domain validation
IPV4_REGEX = re.compile(r'^([0-9]{1,3}\.){3}[0-9]{1,3}$')
DOMAIN_REGEX = re.compile(r'^([a-zA-Z0-9:-]+\.)+[a-zA-Z]{2,63}$')

def fetch_list(url):
    """Fetches the list from the remote URL and cleans it up."""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read().decode('utf-8')
        
        lines = [line.strip() for line in content.splitlines()]
        cleaned = [line for line in lines if line and not line.startswith('#')]
        return cleaned
    except Exception as e:
        print(f"Error fetching URL: {e}")
        return []

def resolve_domain(item):
    """
    Checks if item is an IP or domain. 
    If domain, resolves it to all available IPv4 addresses.
    Returns a set of plain IPv4 addresses.
    """
    item = item.lower()
    
    if IPV4_REGEX.match(item):
        return {item}
    
    if DOMAIN_REGEX.match(item):
        try:
            results = socket.getaddrinfo(item, None, socket.AF_INET, socket.SOCK_STREAM)
            ips = set([res[4][0] for res in results])
            return ips
        except socket.gaierror:
            return set()
            
    return set()

def main():
    print(f"Fetching source list from {URL}...")
    items = fetch_list(URL)
    if not items:
        print("No items found to convert.")
        return

    print(f"Found {len(items)} entries. Starting DNS resolution...")
    
    all_ips = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(resolve_domain, items)
        for res in results:
            if res:
                all_ips.update(res)

    print(f"Writing {len(all_ips)} unique IPs to {OUTPUT_FILE}...")
    
    def ip_key(ip):
        return [int(part) for part in ip.split('.')]

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for ip in sorted(list(all_ips), key=ip_key):
            f.write(f"{ip}\n")

    print("Done!")

if __name__ == "__main__":
    main()
