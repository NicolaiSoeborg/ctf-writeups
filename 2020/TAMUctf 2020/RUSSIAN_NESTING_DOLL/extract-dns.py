from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
from base64 import b64decode

pkts = rdpcap('./netlogs.pcap')
pkts = [p for p in pkts if p.haslayer(DNS)]

b64 = ""
for i, p in enumerate(pkts):
    if p.qdcount == 1:
        # LS0tLS1CRUdJTiBQR1AgTUVTU0FHRS0tLS0tClZlcnNpb246IEdudVBHI-tamu.1e100.net.
        dns_req = p.qd.qname.decode().replace("-tamu.1e100.net.", "")
        if b64.endswith(dns_req):
            print(f"Skipping {i}")
            continue
        b64 += dns_req

out = b64decode(b64)
print(out.decode())
