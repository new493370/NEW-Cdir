import json
import ipaddress
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

RIPE_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{}"
MAX_WORKERS = 10
TIMEOUT = 20
RETRY_COUNT = 3

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
                    net = ipaddress.ip_network(prefix, strict=False)
                    
                    if net.version != 4:
                        continue
                    
                    if (net.is_private or net.is_loopback or net.is_multicast or 
                        net.is_link_local or net.is_reserved or net.is_unspecified):
                        continue
                    
                    if net.prefixlen < 12 or net.prefixlen > 30:
                        continue
                    
                    first_octet = int(str(net.network_address).split('.')[0])
                    if first_octet in [0, 127, 169, 224, 239, 240, 255]:
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
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_asn = {executor.submit(fetch_prefixes, asn): asn for asn in ASNS}
        
        for future in as_completed(future_to_asn):
            asn = future_to_asn[future]
            try:
                result = future.result()
                with lock:
                    for prefix in result:
                        prefixes.add(prefix)
                print(f"AS{asn}: {len(result)} prefixes added")
            except Exception as e:
                print(f"AS{asn} failed: {e}")
    
    if not prefixes:
        print("No prefixes found!")
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
    
    print(f"Done! {len(prefixes_sorted)} unique IPv4 prefixes saved.")

if __name__ == "__main__":
    main()
