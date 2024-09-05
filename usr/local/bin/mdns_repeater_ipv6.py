#!/usr/local/bin/python3

import socket
import struct
import threading
import argparse
import time
from collections import deque

MDNS_MULTICAST_IPV6 = "ff02::fb"
MDNS_MULTICAST_IPV4 = "224.0.0.251"
MDNS_PORT = 5353
BUFFER_SIZE = 1024
LOOP_PREVENTION_CACHE_SIZE = 100  # Keep track of 100 recently forwarded packets
LOOP_PREVENTION_TTL = 5  # Time-to-live for cache entries in seconds

# Cache to store recently forwarded packets to prevent loops
loop_prevention_cache = deque(maxlen=LOOP_PREVENTION_CACHE_SIZE)

def create_socket(interface: str, is_ipv6=True):
    # Create either IPv6 or IPv4 UDP socket
    family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    # Allow multiple sockets to bind to this port
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    # Bind to the mDNS port and all addresses on the specified interface
    if is_ipv6:
        sock.bind(('::', MDNS_PORT))
        # Join the IPv6 multicast group for mDNS
        group = socket.inet_pton(socket.AF_INET6, MDNS_MULTICAST_IPV6) + struct.pack('@I', socket.if_nametoindex(interface))
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, group)
    else:
        sock.bind(('', MDNS_PORT))
        # Join the IPv4 multicast group for mDNS
        group = struct.pack('4s4s', socket.inet_aton(MDNS_MULTICAST_IPV4), socket.inet_aton('0.0.0.0'))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, group)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton('0.0.0.0'))

    return sock

def add_to_cache(addr, data):
    """Add packet to cache to prevent forwarding it again."""
    packet_signature = (addr[0], data[:20])  # Use source IP and the first 20 bytes of the packet data as a signature
    loop_prevention_cache.append((packet_signature, time.time()))

def is_in_cache(addr, data):
    """Check if a packet is already in the cache."""
    packet_signature = (addr[0], data[:20])
    now = time.time()

    # Clear expired cache entries
    while loop_prevention_cache and now - loop_prevention_cache[0][1] > LOOP_PREVENTION_TTL:
        loop_prevention_cache.popleft()

    # Check if the packet signature exists in the cache
    return any(entry[0] == packet_signature for entry in loop_prevention_cache)

def forward_mdns(data, addr, forward_interface, original_interface, is_ipv6=True, verbose=False):
    if is_in_cache(addr, data):
        if verbose:
            print(f"Loop prevention: Skipping packet from {addr} on {original_interface}")
        return

    # Create a new socket to forward the data on the other interface
    family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    forward_sock = socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    # Get the interface index for multicast traffic
    forward_if_index = socket.if_nametoindex(forward_interface)

    # Set the outgoing interface for multicast packets
    if is_ipv6:
        forward_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, struct.pack('@I', forward_if_index))
        forward_sock.sendto(data, (MDNS_MULTICAST_IPV6, MDNS_PORT))
    else:
        forward_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton('0.0.0.0'))
        forward_sock.sendto(data, (MDNS_MULTICAST_IPV4, MDNS_PORT))

    forward_sock.close()

    # Add the packet to the cache after forwarding
    add_to_cache(addr, data)

    if verbose:
        print(f"Forwarded packet from {original_interface} to {forward_interface}")

def listen_and_forward(listen_interface, forward_interface, is_ipv6=True, verbose=False):
    listen_sock = create_socket(listen_interface, is_ipv6=is_ipv6)
    
    if verbose:
        print(f"Listening on interface {listen_interface} (IPv6: {is_ipv6})")

    while True:
        data, addr = listen_sock.recvfrom(BUFFER_SIZE)
        
        if verbose:
            print(f"Received data from {addr[0]}:{addr[1]} on {listen_interface}")

        # Avoid rebroadcasting multicast packets back to the same network
        if (is_ipv6 and addr[0].startswith("ff02::")) or (not is_ipv6 and addr[0].startswith("224.")):
            if verbose:
                print("Skipping multicast packet to avoid rebroadcasting")
            continue

        if verbose:
            print(f"Forwarding packet from {addr} on {listen_interface}")

        # Forward the mDNS query/response to the other interface, avoid looping
        forward_mdns(data, addr, forward_interface, listen_interface, is_ipv6=is_ipv6, verbose=verbose)

def relay_mdns_responses(listen_interface, forward_interface, is_ipv6=True, verbose=False):
    forward_sock = create_socket(forward_interface, is_ipv6=is_ipv6)

    if verbose:
        print(f"Relaying responses on interface {forward_interface} (IPv6: {is_ipv6})")

    while True:
        data, addr = forward_sock.recvfrom(BUFFER_SIZE)

        if verbose:
            print(f"Received data from {addr[0]}:{addr[1]} on {forward_interface}")

        # Avoid rebroadcasting multicast packets back to the same network
        if (is_ipv6 and addr[0].startswith("ff02::")) or (not is_ipv6 and addr[0].startswith("224.")):
            if verbose:
                print("Skipping multicast packet to avoid rebroadcasting")
            continue

        if verbose:
            print(f"Relaying packet from {addr} on {forward_interface}")

        # Relay the mDNS response back to the original listening interface, avoid looping
        forward_mdns(data, addr, listen_interface, forward_interface, is_ipv6=is_ipv6, verbose=verbose)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='mDNS Query and Response Forwarder')
    parser.add_argument('-l', '--listen-interface', required=True, help='Interface to listen for mDNS queries')
    parser.add_argument('-f', '--forward-interface', required=True, help='Interface to forward mDNS queries and responses')
    parser.add_argument('--ipv4', action='store_true', help='Enable IPv4 multicast support')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')

    args = parser.parse_args()

    is_ipv6 = not args.ipv4

    # Create threads to listen on both interfaces and forward queries/responses
    listener_thread = threading.Thread(target=listen_and_forward, args=(args.listen_interface, args.forward_interface, is_ipv6, args.verbose))
    responder_thread = threading.Thread(target=relay_mdns_responses, args=(args.listen_interface, args.forward_interface, is_ipv6, args.verbose))

    listener_thread.start()
    responder_thread.start()

    listener_thread.join()
    responder_thread.join()
