#!/usr/bin/env python3
import codecs
from scapy.all import *

packets = rdpcap('breach_nem.pcap')

for packet in packets:
    if hasattr(packet, 'load') and packet.load != b'\x00'*18:
        print(packet.load)

print('https://ghostbin.com/paste/jnmo7kys  +  guldjul  =  AP3{avffre_cå_yvawra__iv_fre_serz_gvy_jevgrhcf}')

flag = 'AP3{avffre_cå_yvawra__iv_fre_serz_gvy_jevgrhcf}'
print(codecs.encode(flag, 'rot_13'))
