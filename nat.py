#! /usr/bin/env python3

from socket import socket, AF_INET, SOCK_DGRAM
from selectors import DefaultSelector, EVENT_READ
from threading import Event, Thread
from queue import Queue

from parse_args import parse_args, Config
from packet import IPPacket
from nat_table import Address
import nat_table

SocketAddress = tuple[str, int]

IP_HEADER_LEN = IPPacket.HEADER_LEN
UDP_HEADER_LEN = 8
MAX_UDP_PAYLOAD = 996
MAX_PACKET_LEN = IP_HEADER_LEN + UDP_HEADER_LEN + MAX_UDP_PAYLOAD

outgoing: Queue[bytes] = Queue()
incoming: Queue[bytes] = Queue()
received_real_client_addr = Event()

def main():
    start_nat(parse_args())

def start_nat(config: Config):
    global REAL_CLIENT_ADDR, REAL_NEXT_HOP_ADDR
    REAL_CLIENT_ADDR = None
    REAL_NEXT_HOP_ADDR = ('localhost', config.real_next_hop_port)

    internal = socket(AF_INET, SOCK_DGRAM)
    internal.bind(('localhost', config.real_internal_port))
    external = socket(AF_INET, SOCK_DGRAM)
    # Port of 0 asks the OS to allocate an ephemeral UPD port
    external.bind(('localhost', 0))

    nat_table.init(config)
    sel = DefaultSelector()

    def get_real_client_addr(internal: socket):
        handle_internal(internal)
        sel.modify(internal, EVENT_READ, data=handle_internal)
        received_real_client_addr.set()

    sel.register(internal, EVENT_READ, data=get_real_client_addr)
    sel.register(external, EVENT_READ, data=handle_external)

    Thread(target=forward_outgoing, args=(external, internal.getsockname()), daemon=True).start()
    Thread(target=forward_incoming, args=(internal, external.getsockname()), daemon=True).start()

    while True:
        for key, _ in sel.select():
            handler, sock = key.data, key.fileobj
            handler(sock)

def parse_packet(data: bytes, sock_addr: SocketAddress):
    try:
        packet = IPPacket(data)
    except ValueError as e:
        print(f'Dropping packet due to error: {e}')
        return None
    except NotImplementedError:
        return None

    print(f'Socket {sock_addr} received packet of {len(packet)} bytes')
    return packet

def handle_internal(internal: socket):
    global REAL_CLIENT_ADDR
    data, REAL_CLIENT_ADDR = internal.recvfrom(MAX_PACKET_LEN)
    outgoing.put(data)

def handle_external(external: socket):
    data, _ = external.recvfrom(MAX_PACKET_LEN)
    incoming.put(data)

def forward_outgoing(external: socket, internal_addr: SocketAddress):
    while True:
        packet_data = outgoing.get()
        if (packet := parse_packet(packet_data, internal_addr)) is None:
            continue

        print('\n============================================================================\n')
        print(f'Original outgoing packet:\n{packet}\n')

        old_src = packet.src_addr()
        new_src = nat_table.to_external(old_src)
        translated = packet.update_src(new_src)

        print(f'Translated outgoing packet:\n{translated}\n')
        external.sendto(bytes(translated), REAL_NEXT_HOP_ADDR)

def forward_incoming(internal: socket, external_addr: SocketAddress):
    while not REAL_CLIENT_ADDR:
        received_real_client_addr.wait()
    while True:
        packet_data = incoming.get()
        if (packet := parse_packet(packet_data, external_addr)) is None:
            continue

        print('\n============================================================================\n')
        print(f'Original incoming packet:\n{packet}\n')

        old_dest = packet.dest_addr()
        if (new_dest := nat_table.to_internal(old_dest)) is None:
            print(f'No mapping found for {old_dest}, dropping packet')
            continue
        translated = packet.update_dest(new_dest)

        print(f'Translated incoming packet:\n{translated}\n')
        internal.sendto(bytes(translated), REAL_CLIENT_ADDR)

if __name__ == '__main__':
    main()
