import urllib.request
import socket
import re
import concurrent.futures

# URL containing the IPs and domains
URL = "https://raw.githubusercontent.com/gransa/Moein/refs/heads/main/CF-For-Convert.txt"
OUTPUT_FILE = "a_records.txt"

# Simple regex patterns to identify IPv4 and basic domain validation
IPV4_REGEX = re.compile(r'^([0-9]{1,3}\.){3}[0-9]{1,3}$')
DOMAIN_REGEX = re.compile(r'^([a-zA-Z0-9:-]+\.)+[a-zA-Z]{2,63}$')

def fetch_list(url):
    """Fetches the list from the remote URL and cleans it up."""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read().decode('utf-8')
        
        # Clean lines: strip whitespace, filter out empty lines or comments
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
    Returns a list of tuples: (domain/host, ip)
    """
    item = item.lower()
    
    # If it's already an IPv4 address
    if IPV4_REGEX.match(item):
        return [(item, item)]
    
    # If it's a domain name, resolve it
    if DOMAIN_REGEX.match(item):
        try:
            # getaddrinfo filters out IPv6 if we specify AF_INET
            results = socket.getaddrinfo(item, None, socket.AF_INET, socket.SOCK_STREAM)
            ips = list(set([res[4][0] for res in results])) # Deduplicate IPs for this host
            return [(item, ip) for ip in ips]
        except socket.gaierror:
            # DNS resolution failed for this host
            return []
            
    return []

def main():
    print(f"Fetching source list from {URL}...")
    items = fetch_list(URL)
    if not items:
        print("No items found to convert.")
        return

    print(f"Found {len(items)} entries. Starting DNS resolution...")
    
    records = []
    # Use ThreadPoolExecutor for faster concurrent DNS requests
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(resolve_domain, items)
        for res in results:
            if res:
                records.extend(res)

    print(f"Writing {len(records)} A-records to {OUTPUT_FILE}...")
    
    # Write in classic DNS zone file A-record format: domain.com.  IN  A  1.2.3.4
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for domain, ip in sorted(records):
            # Ensure the domain ends with a dot for strict standard formatting, or leave as is if it's a raw IP
            record_name = domain if IPV4_REGEX.match(domain) else f"{domain}."
            f.write(f"{record_name:<30} IN  A  {ip}\n")

    print("Done!")

if __name__ == "__main__":
    main()
