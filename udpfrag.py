#!/usr/bin/python3
#
# Craft fragments UDP packets which may or may not be out of order
#

import argparse
from scapy.all import *
import time

# Scapy's default UDP source port is 53, which is an unideal default
SRC_PORT = 2342

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="udpfrag",
        description="Carft fragmented UDP packets in and out of order"
    )
    parser.add_argument('dst', help="Destination IP address to set packets to")
    parser.add_argument('--in-order', '-o', action="store_true", help="Send packets in order (default: out-of-order)")
    parser.add_argument('--num-pkts', '-n', default=3, type=int, choices=range(2, 10), help="Number of packets to send (default: 3)")
    parser.add_argument('--port', '-p', default=2342, type=int, help="The UDP destination port (default: 2342)")
    parser.add_argument('--interval', '-i', default=0, type=int, help="The interval in ms between packets (default: 0)")

    return parser.parse_args()

def fragment_packet(pkt, num_fragments: int):
    """Fragment a big IP datagram"""
    payload = raw(pkt[IP].payload)

    fragsize = int(len(payload) / num_fragments)
    fragments = []

    for i in range(num_fragments):
        new_pkt = pkt.copy()
        del(new_pkt[IP].payload)
        del(new_pkt[IP].chksum)
        del(new_pkt[IP].len)

        if i != num_fragments - 1:
            new_pkt[IP].flags |= 1

        new_pkt[IP].frag += i

        r = conf.raw_layer(load=payload[i * fragsize:(i + 1) * fragsize])
        r.overload_fields = pkt[IP].payload.overload_fields.copy()
        new_pkt.add_payload(r)

        fragments.append(new_pkt)

    return fragments

def craft_packets(dst: str, dst_port: int, num_fragments: int):
    payload = ""
    
    for n in range(1, num_fragments):
        payload += f"HERO" + f"{n}" * 4
    
    packet = IP(
        dst=dst,
        id=4711,
    )/UDP(
        sport=2342,
        dport=dst_port,
    )/payload

    return fragment_packet(packet, num_fragments)


if __name__ == "__main__":
    args = parse_args()

    pkts = craft_packets(args.dst, args.port, args.num_pkts)
 
    if not args.in_order:
        pkts[0], pkts[1] = pkts[1], pkts[0]

    for i in range(0, len(pkts)):
        send(pkts[i])

        if args.interval:
            time.sleep(args.interval/1000)
