import socket
import dpkt
from typing import Optional

def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

class Question:
    def __init__(self, hosts: list[str] = [], ips: list[str] = []) -> None:
        self.hosts = hosts
        self.ips = ips

    def __str__(self) -> str:
        return f"Hosts: {self.hosts}\nIPs: {self.ips}\n\n"

relation_list: list[Question] = []
def hostInIndex(list: list[Question], host: str) -> Optional[int]:
    for index, item in enumerate(list):
        if host in item.hosts: return index
    return None

with open("01.pcap", "rb") as file:
    pcap = dpkt.pcap.Reader(file)
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)

        if not isinstance(eth.data, dpkt.ip.IP): continue
        ip = eth.data

        if not isinstance(ip.data, dpkt.udp.UDP): continue
        udp = ip.data

        if udp.sport != 53: continue

        try:
            dns = dpkt.dns.DNS(udp.data)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            continue

        # an = answers, ar = aditional records, rr = resource record
        for rr in dns.an:
            if (index := hostInIndex(relation_list, rr.name)) == None: 
                    relation_list.append(Question(hosts=[rr.name]))
                    index = -1
            
            if rr.type == dpkt.dns.DNS_A:
                if inet_to_str(rr.ip) not in relation_list[index].ips: relation_list[index].ips.append(inet_to_str(rr.ip))

            elif rr.type == dpkt.dns.DNS_AAAA:
                if inet_to_str(rr.ip6) not in relation_list[index].ips: relation_list[index].ips.append(inet_to_str(rr.ip6))

            elif rr.type == dpkt.dns.DNS_CNAME:
                if rr.cname not in relation_list[index].hosts:  relation_list[index].hosts.append(rr.cname)

with open("flagged_domains.txt", 'r') as file:
    flagged_domains = [line.strip() for line in file]

flagged_ips: list[str] = []
for item in relation_list:
    for string in item.hosts:
        if string in flagged_domains:
            flagged_ips.extend(item.ips)
            break

del flagged_domains
del relation_list

total_ad_usage = 0
total_usage = 0

with open("01.pcap", "rb") as file:
    pcap = dpkt.pcap.Reader(file)
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)

        if not isinstance(eth.data, dpkt.ip.IP): continue
        ip = eth.data

        total_usage += ip.len # Bytes
        if inet_to_str(ip.src) in flagged_ips: total_ad_usage += ip.len

print("Total usage: ", total_usage)
print("Ad related usage: ", total_ad_usage)
print("Percentage: ", total_ad_usage/total_usage)

# Results with old_flagged_domains and 01 (May  6, 2023 09:29:18 - May  6, 2023 09:30:44):
# Total usage:  775424566
# Ad related usage:  302164954
# Percentage:  0.38967678772250813

# Results with flagged_domains and 01:
# Total usage:  775424566
# Ad related usage:  302164954
# Percentage:  0.38967678772250813

# Results with old_flagged_domains and 02 (May  6, 2023 09:23:21 - May  6, 2023 09:24:47):
# Total usage:  784767482
# Ad related usage:  312319435
# Percentage:  0.39797703417074054

# Results with old_flagged_domains and 03 (May  6, 2023 09:20:29 - May  6, 2023 09:21:19):
# Total usage:  82253908
# Ad related usage:  12337943
# Percentage:  0.14999825904928432

# Ad Lists:
# Most recent Ad server list from: https://github.com/StevenBlack/hosts