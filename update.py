import json
import ipaddress
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

RIPE_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{}"
MAX_WORKERS = 10
TIMEOUT = 20
RETRY_COUNT = 3

FILTER_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("100.64.0.0/10"),
]

MIN_PREFIX_LENGTH = 8
MAX_PREFIX_LENGTH = 32

def is_bad_prefix(prefix):
    try:
        net = ipaddress.ip_network(prefix, strict=False)
        
        if net.prefixlen < MIN_PREFIX_LENGTH:
            return True
        if net.prefixlen > MAX_PREFIX_LENGTH:
            return True
            
        for bad_net in FILTER_NETWORKS:
            if net.subnet_of(bad_net) or net.supernet_of(bad_net):
                return True
            if net.overlaps(bad_net):
                return True
                
        if net.prefixlen == 31 and net.num_addresses == 2:
            return True
            
        return False
        
    except Exception:
        return True

prefixes = set()
lock = Lock()

def fetch_prefixes(asn):
    for attempt in range(RETRY_COUNT):
        try:
            r = requests.get(RIPE_URL.format(asn), timeout=TIMEOUT)
            r.raise_for_status()
            data = r.json()
            
            if "data" not in data or "prefixes" not in data["data"]:
                return []
            
            result = []
            for item in data["data"]["prefixes"]:
                prefix = item["prefix"]
                
                if ":" in prefix:
                    continue
                    
                try:
                    ipaddress.ip_network(prefix, strict=False)
                    
                    if is_bad_prefix(prefix):
                        continue
                        
                    result.append(prefix)
                    
                except Exception:
                    pass
                    
            return result
            
        except Exception as e:
            print(f"AS{asn}: {e} (attempt {attempt+1}/{RETRY_COUNT})")
    
    return []

def main():
    with open("asn.json", "r", encoding="utf-8") as f:
        ASNS = json.load(f)["asns"]
    
    print(f"Starting scan for {len(ASNS)} ASNs...")
    print(f"Filtering out bad ranges (reserved, private, multicast, etc.)")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_asn = {executor.submit(fetch_prefixes, asn): asn for asn in ASNS}
        
        for future in as_completed(future_to_asn):
            asn = future_to_asn[future]
            try:
                result = future.result()
                with lock:
                    for prefix in result:
                        prefixes.add(prefix)
                print(f"AS{asn}: {len(result)} valid prefixes added")
            except Exception as e:
                print(f"AS{asn} failed: {e}")
    
    if not prefixes:
        print("No valid prefixes found!")
        return
    
    prefixes_sorted = sorted(
        prefixes,
        key=lambda x: (
            int(ipaddress.ip_network(x, strict=False).network_address),
            ipaddress.ip_network(x, strict=False).prefixlen
        )
    )
    
    with open("ipv4-aggregated.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(prefixes_sorted))
    
    print(f"Done! {len(prefixes_sorted)} unique valid IPv4 prefixes saved.")
    print(f"Filtered out {len(prefixes) - len(prefixes_sorted)} invalid prefixes.")

if __name__ == "__main__":
    main()
