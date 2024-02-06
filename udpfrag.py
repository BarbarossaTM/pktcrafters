#!/usr/bin/python3
#
# Craft fragments UDP packets which may or may not be out of order
#

import argparse
import ipaddress
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
    parser.add_argument('--num-pkts', '-n', default=3, type=int, choices=range(2, 9), help="Number of packets to send (default: 3)")
    parser.add_argument('--port', '-p', default=2342, type=int, help="The UDP destination port (default: 2342)")
    parser.add_argument('--interval', '-i', default=0, type=int, help="The interval in ms between packets (default: 0)")

    return parser.parse_args()

def generate_payload(num_fragments: int) -> str:
    """Generate a payload of format HERO[HERO...]nnnn which can be nicely fragments to [num_fragments] in both AFs."""
    payload = ""

    for n in range(1, num_fragments + 1):
        payload += "HERO" * 13 + f"{n}" * 4

    return payload[8:]

def craft_packets(dst: str, dst_port: int, num_fragments: int):
    # Craft IP header depending on AF
    af = ipaddress.ip_address(dst).version
    if af == 4:
        ip = IP(
            dst=dst,
            id=4711,
        )
    else:
        ip = IPv6(
            dst=dst
        )

    udp = UDP(
        sport=2342,
        dport=dst_port,
    )

    payload = generate_payload(num_fragments)
    packet = ip/udp/payload

    # Fragment packet
    fragsize = int(len(payload) / num_fragments)

    if af == 6:
        return fragment6(packet, fragsize + 40 + 16)

    return fragment(packet, fragsize + 10)


if __name__ == "__main__":
    args = parse_args()

    pkts = craft_packets(args.dst, args.port, args.num_pkts)

    if not args.in_order:
        pkts[0], pkts[1] = pkts[1], pkts[0]

    for i in range(0, len(pkts)):
        send(pkts[i])

        if args.interval:
            time.sleep(args.interval/1000)
