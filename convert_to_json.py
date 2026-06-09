    "dns": {
      "servers": [
        {
          "address": "https://freedns.controld.com/dns-query",
          "tag": "remote-dns-1"
        },
        {
          "address": "https://doh.libredns.gr/noads",
          "tag": "remote-dns-2"
        },
        {
          "address": "udp://45.11.45.11:53",
          "tag": "remote-dns-3"
        },
        {
          "address": "https://dns.adguard.com/dns-query",
          "tag": "remote-dns-4"
        },
        {
          "address": "tcp://223.6.6.6:853",
          "tag": "remote-dns-5"
        },
        {
          "address": "https://freedns.controld.com/dns-query",
          "domains": [
            "geosite:category-ir"
          ],
          "expectIPs": [
            "geoip:ir"
          ],
          "skipFallback": false
        },
        {
          "address": "https://doh.libredns.gr/noads",
          "domains": [
            "geosite:category-ir"
          ],
          "expectIPs": [
            "geoip:ir"
          ],
          "skipFallback": false
        },
        {
          "address": "45.11.45.11",
          "domains": [
            "geosite:category-ir"
          ],
          "expectIPs": [
            "geoip:ir"
          ],
          "skipFallback": false
        },
        {
          "address": "94.140.14.14",
          "domains": [
            "geosite:category-ir"
          ],
          "expectIPs": [
            "geoip:ir"
          ],
          "skipFallback": false
        },
        {
          "address": "223.6.6.6",
          "domains": [
            "geosite:category-ir"
          ],
          "expectIPs": [
            "geoip:ir"
          ],
          "skipFallback": false
        }
      ],
      "queryStrategy": "UseIP",
      "tag": "dns"
    }
