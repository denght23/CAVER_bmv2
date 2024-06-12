#!/usr/bin/env python3

import socket
import sys
from time import sleep
import os
from scapy.all import IP, UDP, Ether, get_if_hwaddr, get_if_list, sendp, Packet, ShortField, ByteField, BitField, sniff
import random

class MyCustomPacket(Packet):
    name = "MyCustomPacket"
    fields_desc = [
        ShortField("srcPort", 0),    # 16-bit source port
        ShortField("dstPort", 0),    # 16-bit destination port
        ShortField("length", 0),     # 16-bit length
        ShortField("checksum", 0),   # 16-bit checksum
        ByteField("seq", 0)          # 8-bit sequence number
    ]

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def handle_pkt(pkt, iface):
    if UDP in pkt and pkt[UDP].dport == 1234:
        print("got a packet")
        pkt.show2()
    #    hexdump(pkt)
        sys.stdout.flush()
        rec_pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(dst=pkt[IP].src, proto = 0x43)/ MyCustomPacket(srcPort=pkt[UDP].dport, dstPort=pkt[UDP].sport, length=100, checksum=0, seq=1)
        try:
            sendp(rec_pkt, iface=iface)
        except KeyboardInterrupt:
            raise
        
def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x, iface))
    
if __name__ == '__main__':
    main()
