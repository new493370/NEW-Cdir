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
                    if first_octet in [0, 1, 2, 7, 9, 10, 11, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255]:
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
