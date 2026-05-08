from argparse import ArgumentParser, ArgumentTypeError
from socket import inet_aton
from dataclasses import dataclass

def ip_addr(value: str):
    try:
        return inet_aton(value)
    except OSError as e:
        raise ArgumentTypeError('must be a valid IP address') from e

def to_int(value: str):
    try:
        return int(value)
    except ValueError as e:
        raise ArgumentTypeError('must be an integer') from e

def range_int(start: int, end: int):
    def func(value: str):
        num = to_int(value)
        if not (start <= num <= end):
            raise ArgumentTypeError(f'must be in range {start}-{end}')
        return num
    return func

def port_number(value: str):
    if (port_num := to_int(value)) < 0:
        raise ArgumentTypeError('cannot be negative')
    try:
        return range_int(49152, 65535)(value)
    except ArgumentTypeError:
        print('Recommended range for ports: 49152-65535')
        return port_num

def positive_int(value: str):
    num = to_int(value)
    if num <= 0:
        raise ArgumentTypeError('must be strictly positive')
    return num

ARG_TYPES = {
    'external_ip':          ip_addr,
    'num_external_ports':   range_int(1, 65535),
    'timeout':              positive_int,
    'mtu':                  range_int(64, 1024),
    'real_internal_port':   port_number,
    'real_next_hop_port':   port_number,
}

@dataclass(frozen=True)
class Config():
    external_ip: bytes = inet_aton('1.1.1.1')
    num_external_ports: int = 10
    timeout: int = 10
    mtu: int = 1024
    real_internal_port: int = 60000
    real_next_hop_port: int = 60001

def parse_args():
    '''Parse argument values and convert them to appropriate types'''

    parser = ArgumentParser(description='Start running NAT on a local server')
    parser.add_argument('--default', '-d', action='store_true', help='Run with default arguments')
    args, _ = parser.parse_known_args()
    if args.default:
        return Config()

    for name, arg_type in ARG_TYPES.items():
        parser.add_argument(name, type=arg_type)
    return Config(**vars(parser.parse_args()))
