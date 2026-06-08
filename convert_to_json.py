def build_v2rayng_template(remarks, outbound_nodes, pool_top_dns, pool_main_dns):
    base_outbounds = list(outbound_nodes)
    base_outbounds.extend([
        {"protocol": "dns", "tag": "dns-out"},
        {"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}, "tag": "direct"},
        {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}
    ])
    
    fallback_providers = [
        {"server": "https://dns.quad9.net/dns-query", "ip": "9.9.9.9"},
        {"server": "https://dns.adguard-dns.com/dns-query", "ip": "94.140.14.14"},
        {"server": "https://doh.opendns.com/dns-query", "ip": "208.67.222.222"},
        {"server": "https://doh.cleanbrowsing.org/doh/security-filter", "ip": "185.228.168.9"}
    ]
    random.shuffle(fallback_providers)

    pairs_top = parse_dns_source(pool_top_dns)
    pairs_main = parse_dns_source(pool_main_dns)

    doh_top = [p for p in pairs_top if p["server"].startswith("https://")]
    doh_main = [p for p in pairs_main if p["server"].startswith("https://")]

    random.shuffle(doh_top)
    random.shuffle(doh_main)

    chosen_providers = []
    seen_identifiers = set()

    for provider in doh_top:
        ident = get_identity_key(provider["server"])
        seen_identifiers.add(ident)
        chosen_providers.append(provider)
        break

    if not chosen_providers:
        for fb in fallback_providers:
            if fb["server"].startswith("https://"):
                seen_identifiers.add(get_identity_key(fb["server"]))
                chosen_providers.append(fb)
                break

    for provider in doh_main:
        ident = get_identity_key(provider["server"])
        if ident not in seen_identifiers:
            seen_identifiers.add(ident)
            chosen_providers.append(provider)
            break

    if len(chosen_providers) < 2 and len(chosen_providers) == 1:
        for fb in fallback_providers:
            ident = get_identity_key(fb["server"])
            if fb["server"].startswith("https://") and ident not in seen_identifiers:
                seen_identifiers.add(ident)
                chosen_providers.append(fb)
                break

    remaining_top = [p for p in pairs_top if get_identity_key(p["server"]) not in seen_identifiers]
    remaining_main = [p for p in pairs_main if get_identity_key(p["server"]) not in seen_identifiers]
    
    combined_remaining = remaining_top + remaining_main
    random.shuffle(combined_remaining)

    for provider in combined_remaining:
        if len(chosen_providers) == 5:
            break
        ident = get_identity_key(provider["server"])
        if ident not in seen_identifiers:
            seen_identifiers.add(ident)
            chosen_providers.append(provider)

    if len(chosen_providers) < 5:
        for fb in fallback_providers:
            if len(chosen_providers) == 5:
                break
            ident = get_identity_key(fb["server"])
            if ident not in seen_identifiers:
                seen_identifiers.add(ident)
                chosen_providers.append(fb)

    dns_servers_config = []
    inbound_tags = []
    
    # 1. Map Selected DNS Servers with Tags
    for i, provider in enumerate(chosen_providers, 1):
        tag_name = f"remote-dns-{i}"
        inbound_tags.append(tag_name)
        srv_address = provider["server"]
        
        if srv_address.startswith("tcp:"):
            clean_host = clean_dns_address(srv_address, "tcp:")
            dns_servers_config.append({"address": f"tcp:{clean_host}", "port": 853, "tag": tag_name})
        elif srv_address.startswith("quic:"):
            clean_host = clean_dns_address(srv_address, "quic:")
            dns_servers_config.append({"address": f"quic:{clean_host}", "port": 784, "tag": tag_name})
        elif srv_address.startswith("udp:"):
            clean_host = clean_dns_address(srv_address, "udp:")
            dns_servers_config.append({"address": clean_host, "port": 53, "tag": tag_name})
        else:
            dns_servers_config.append({"address": srv_address, "tag": tag_name})
        
    # FIX: Clean 1-to-1 dynamic mapping instead of duplicates
    for provider in chosen_providers:
        dns_servers_config.append({
            "address": provider["ip"],
            "domains": ["geosite:category-ir"],
            "expectIPs": ["geoip:ir"],
            "skipFallback": False
        })
        
    extracted_domains = []
    for node in outbound_nodes:
        addr = None
        settings = node.get("settings", {})
        if "vnext" in settings and settings["vnext"]:
            addr = settings["vnext"][0].get("address")
        elif "servers" in settings and settings["servers"]:
            addr = settings["servers"][0].get("address")
            
        if addr:
            try:
                ipaddress.ip_address(addr)
            except ValueError:
                domain_entry = f"full:{addr}"
                if domain_entry not in extracted_domains:
                    extracted_domains.append(domain_entry)
                    
    # FIX: Dynamically targets primary provider IPv4 instead of staying hardcoded
    primary_dns_ip = chosen_providers[0]["ip"] if chosen_providers else "9.9.9.9"
    for domain in extracted_domains:
        dns_servers_config.append({
            "address": primary_dns_ip,
            "domains": [domain],
            "skipFallback": True
        })
                    
    return {
        "remarks": remarks,
        "log": {"loglevel": "warning"},
        "dns": {
            "servers": dns_servers_config,
            "queryStrategy": "UseIP",
            "tag": "dns"
        },
        "inbounds": [
            {"port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "userLevel": 8}, "sniffing": {"destOverride": ["http", "tls"], "enabled": False, "routeOnly": False}, "tag": "socks-in"},
            {"port": 10853, "protocol": "dokodemo-door", "settings": {"address": "1.1.1.1", "network": "tcp,udp", "port": 53}, "tag": "dns-in"}
        ],
        "outbounds": base_outbounds,
        "policy": {
            "levels": {"8": {"connIdle": 300, "downlinkOnly": 1, "handshake": 4, "uplinkOnly": 1}},
            "system": {"statsOutboundUplink": True, "statsOutboundDownlink": True}
        },
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"inboundTag": ["dns-in"], "outboundTag": "dns-out", "type": "field"},
                {"inboundTag": ["socks-in"], "port": 53, "outboundTag": "dns-out", "type": "field"},
                {"inboundTag": inbound_tags, "balancerTag": "all", "type": "field"},
                {"inboundTag": ["dns"], "outboundTag": "direct", "type": "field"},
                {"domain": ["geosite:category-ir"], "outboundTag": "direct", "type": "field"},
                {"ip": ["geoip:ir"], "outboundTag": "direct", "type": "field"},
                {"network": "udp", "outboundTag": "block", "type": "field"},
                {"network": "tcp", "balancerTag": "all", "type": "field"}
            ],
            "balancers": [
                {
                    "tag": "all",
                    "selector": ["prox"],
                    "strategy": {"type": "leastPing"},
                    "fallbackTag": "prox-1" if len(outbound_nodes) > 0 else "direct"
                }
            ]
        },
        "stats": {},
        "observatory": {
            "subjectSelector": ["prox"],
            "probeUrl": "https://www.gstatic.com/generate_204",
            "probeInterval": "30s",
            "enableConcurrency": True
        }
    }
