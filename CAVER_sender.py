#!/usr/bin/env python3

import socket
import sys
from time import sleep

from scapy.all import IP, UDP, Ether, get_if_hwaddr, get_if_list, sendp
import random
import json

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

def main():
    # with open('host_id_2_ip.json', 'r') as f:
    #     host_id_2_ip = json.load(f)
    #     print(sys.argv[1])
    # dst_ip = host_id_2_ip[sys.argv[1]]
    # 例：h8: 10.8.0.1
    sport = random.randint(49152,65535)
    dport = 1234
    addr = socket.gethostbyname(sys.argv[1])
    print(addr)
    iface = get_if()
    packet_data = f"This is CAVER data packet of flow{sys.argv[2]}."
    for i in range(120):
        pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(dst=addr, proto = 0x11) / UDP(dport=dport, sport=sport) / packet_data
        pkt.show2()
        try:
            sendp(pkt, iface=iface)
            sleep(0.1)
        except KeyboardInterrupt:
            raise
if __name__ == '__main__':
    main()
