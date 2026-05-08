from threading import Thread, Lock, Condition
from time import time
from secrets import randbelow
from itertools import chain
from collections import OrderedDict
from queue import Queue, Full
from typing import NamedTuple
from socket import inet_ntoa

from parse_args import Config

class Address(NamedTuple):
    ip_addr: bytes
    port_num: int

    def __repr__(self):
        return f'({inet_ntoa(self.ip_addr)}, {self.port_num})'

class Mapping(NamedTuple):
    internal: Address
    external: Address

    def __repr__(self):
        return f'{self.internal} -> {self.external}'

class NATTable(NamedTuple):
    outgoing: dict[Address, Address]
    incoming: dict[Address, Address]

def main():
    external_ip: bytes
    num_external_ports: int
    timeout: int

    table_lock = Lock()
    timeout_lock = Condition(Lock())
    timeouts: OrderedDict[Mapping, float] = OrderedDict()

    # Singleton-like
    def init_table():
        table: NATTable | None = None

        def init(config: Config):
            nonlocal table; nonlocal timeouts
            if table is not None:
                return
            table = NATTable({}, {})

            nonlocal external_ip; nonlocal num_external_ports; nonlocal timeout
            external_ip = config.external_ip
            num_external_ports = config.num_external_ports
            timeout = config.timeout

        def outgoing():
            if table is None:
                raise RuntimeError
            return table.outgoing

        def incoming():
            if table is None:
                raise RuntimeError
            return table.incoming

        def add(mapping: Mapping):
            assert mapping.internal not in outgoing()
            assert mapping.external not in incoming()
            outgoing()[mapping.internal] = mapping.external
            incoming()[mapping.external] = mapping.internal
            print(f'Added mapping: {mapping}\n')

        def remove(mapping: Mapping):
            assert mapping.internal in outgoing()
            assert mapping.external in incoming()
            outgoing().pop(mapping.internal)
            incoming().pop(mapping.external)
            print(f'Removed mapping: {mapping}')

        return init, lambda x: outgoing().get(x), lambda x: incoming().get(x), add, remove
    init1, get_external, get_internal, add, remove = init_table()

    # Also singleton-like
    def init_ports():
        available_ports: Queue[int] | None = None

        def init(num_external_ports: int):
            nonlocal available_ports
            if available_ports is not None:
                return

            initial = randbelow(num_external_ports) + 1
            wraparound_range = chain(
                range(initial, num_external_ports + 1),
                range(1, initial)
            )
            available_ports = Queue(num_external_ports)
            for i in wraparound_range:
                available_ports.put(i)

        def available():
            if available_ports is None:
                raise RuntimeError
            return available_ports

        def ports_iterator():
            while True:
                # Blocks until a port is freed
                new_port = available().get()
                print(f'Allocated port {new_port}, {available().qsize()} remaining\n')
                yield new_port

        def free_port(port: int):
            assert (1 <= port <= num_external_ports)
            assert port not in set(available().queue)
            try:
                available().put_nowait(port)
            except Full as e:
                raise RuntimeError from e
            print(f'Freed port {port}, {available().qsize()} remaining')

        return init, ports_iterator().__next__, free_port
    init2, allocate_port, free_port = init_ports()

    # Runs in seperate thread, blocks until a timeout is started
    def manage_timeouts():
        # Get the first item without popping
        get_next = lambda: next(iter(timeouts.items()), None)

        with timeout_lock:
            while True:
                while (next_timeout := get_next()) is None:
                    print('No active timeouts, sleeping...')
                    timeout_lock.wait()
                _, expiry_time = next_timeout

                while (diff := expiry_time - time()) > 0:
                    timeout_lock.wait(diff)

                with table_lock:
                    if (next_timeout := get_next()) is None:
                        continue
                    mapping, expiry_time = next_timeout
                    if time() > expiry_time:
                        remove(mapping)
                        free_port(mapping.external.port_num)
                        print(f'Timed out mapping: {timeouts.popitem(False)[0]}\n')

    def set_timeout(internal: Address | None, external: Address):
        if internal:
            with timeout_lock:
                mapping = Mapping(internal, external)
                if mapping in timeouts:
                    # Dict keeps track of timeout order
                    timeouts.move_to_end(mapping)
                timeouts[mapping] = time() + timeout
                timeout_lock.notify()
                print(f'Removing {mapping} in {timeout} seconds\n')

    def to_external(internal: Address):
        port_num = allocate_port()
        with table_lock:
            if (external := get_external(internal)) is None:
                external = Address(external_ip, port_num)
                add(Mapping(internal, external))
            else:
                free_port(port_num)
            set_timeout(internal, external)
        return external

    def to_internal(external: Address):
        with table_lock:
            internal = get_internal(external)
            set_timeout(internal, external)
        return internal

    def init(config: Config):
        init1(config)
        init2(config.num_external_ports)
        Thread(target=manage_timeouts, daemon=True).start()
    return init, to_external, to_internal
init, to_external, to_internal = main()
