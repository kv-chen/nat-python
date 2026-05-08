from __future__ import annotations
from typing import overload, Generic, TypeVar, Iterable, Protocol, Self
from collections.abc import Mapping
from abc import ABC, abstractmethod
from functools import reduce

from nat_table import Address

BYTE_SIZE = 8

def byte_length(num_bits: int):
    assert num_bits >= 0
    return (num_bits + 7) // 8

class Bits():
    _bits: int
    _size: int

    @overload
    def __init__(self): ...

    @overload
    def __init__(self, value: bytes = b''): ...

    @overload
    def __init__(self, value: bytes, length: int): ...

    @overload
    def __init__(self, value: int, length: int): ...

    def __init__(self, value: bytes | int = b'', length: int | None = None):
        '''Create a bit sequence from `value` padded to `length`'''
        if isinstance(value, bytes):
            if length is None:
                length = BYTE_SIZE * len(value)
            elif BYTE_SIZE * len(value) > length:
                raise OverflowError(f'bytes too big to store in {length} bits')
            bits = int.from_bytes(value, 'big')
        elif isinstance(value, int):
            assert length is not None and length >= 0 and value >= 0
            if value.bit_length() > length:
                raise OverflowError(f'int too big to store in {length} bits')
            bits = value
        else:
            raise TypeError

        self._bits = bits & ((1 << length) - 1)
        self._size = length

    def _extract(self, start: int, end: int):
        return (self._bits >> start) & ((1 << (end - start)) - 1)

    @overload
    def __getitem__(self, key: slice) -> Bits: ...

    @overload
    def __getitem__(self, key: int) -> bool: ...

    def __getitem__(self, key: slice | int):
        '''Extract a bit or range of bits indicated by `key`'''
        if isinstance(key, int):
            if key < 0:
                key += len(self)
            if not (0 <= key < len(self)):
                raise IndexError
            bit = self._extract(key, key + 1)
            assert bit in (0, 1)
            return bool(bit)

        # Negative indexing
        start, stop, step = key.indices(len(self))
        if step == -1:
            start, stop = stop, start
        assert step == 1

        return Bits(self._extract(start, stop), stop - start)

    def __len__(self):
        return self._size

    def __int__(self):
        return self._bits

    def byte_length(self):
        return byte_length(len(self))

    def __bytes__(self):
        return int(self).to_bytes(self.byte_length(), 'big')

    def __or__(self, other: Bits):
        return Bits(self._bits | other._bits, max(len(self), len(other)))

    def __lshift__(self, n: int):
        return Bits(self._bits << n, len(self) + n)

    def __add__(self, other: object) -> Bits:
        assert isinstance(other, Bits)
        return (self << len(other)) | other

    def __eq__(self, other: object):
        return (isinstance(other, Bits)
            and self._bits == other._bits
            and len(self) == len(other))

    def __format__(self, format_spec: str):
        return format(int(self), format_spec)

    def __repr__(self):
        return f'{self:0{(len(self) + 3) // 4}X} ({int(self)})'

    def __str__(self):
        return format(self, f'0{len(self)}b')

C = TypeVar('C', bound='Concatable')
class Concatable(Protocol):
    def __add__(self: C, other: C) -> C: ...

def concat(iterable: Iterable[C]):
    return reduce(lambda x, y: x + y, iterable)

class Header(Mapping[str, Bits]):
    _fields: dict[str, Bits]

    def __init__(self, fields: dict[str, Bits]):
        self._fields = fields

    def __getitem__(self, key: str):
        return self._fields[key]

    def __iter__(self):
        return iter(self._fields)

    def __len__(self):
        return len(self._fields)

    def __bytes__(self):
        return bytes(concat(self._fields.values()))

    def __or__(self, value: Self):
        return Header(self._fields | value._fields)

    def __repr__(self):
        return repr(self.as_dict())

    def as_dict(self):
        return self._fields.copy()

    def updated(self, key: str, value: Bits):
        new = self.as_dict()
        new[key] = value
        return Header(new)

Payload = TypeVar('Payload', 'UDPPacket', bytes)

class Packet(ABC, Generic[Payload]):
    _FIELD_OFFSETS: dict[str, tuple[int, tuple[int, int]]]
    HEADER_LEN: int
    CHECKSUM_LEN: int
    _header: Header
    _payload: Payload

    @overload
    def __init__(self, data: bytes): ...

    @overload
    def __init__(self, data: Header, payload: Payload): ...

    def __init__(self, data: bytes | Header, payload: Payload | None = None):
        if payload is None:
            assert isinstance(data, bytes)
            self._header = self._parse_header(data)
            self._payload = self._parse_payload(data)
        else:
            assert isinstance(data, Header)
            self._header = data
            self._payload = payload

        # self._test_valid_parse()

    @classmethod
    def _extract_field(cls, data: bytes, name: str):
        offset = cls._FIELD_OFFSETS[name]
        start_byte, (start_bit, stop_bit) = offset
        stop_byte = start_byte + byte_length(stop_bit)
        field = Bits()
        for i, byte in enumerate(data[start_byte:stop_byte]):
            # Iterate over every byte in range, extract bits in reverse
            # E.g. version is first 4 bits, but stored at most significant bits (4-8)
            a = 8 - min(stop_bit - 8 * i, 8)
            b = 8 - max(start_bit - 8 * i, 0)
            field += Bits(byte, BYTE_SIZE)[a:b]
        return field

    @classmethod
    def _parse_header(cls, data: bytes):
        if len(data) < cls.HEADER_LEN:
            raise ValueError(f'Expected header of {cls.HEADER_LEN} bytes, received {len(data)} bytes')
        return Header({name: cls._extract_field(data, name) for name in cls._FIELD_OFFSETS})

    @abstractmethod
    def _parse_payload(self, data: bytes) -> Payload: ...

    @staticmethod
    def _calc_checksum(data: bytes):
        if len(data) % 2 == 1:
            data += b'\x00'

        checksum = 0
        for i in range(0, len(data), 2):
            word = data[i:i+2]
            temp = checksum + int.from_bytes(word, 'big')
            checksum = (temp & 0xFFFF) + (temp >> 16)
        return (~checksum) & 0xFFFF

    @overload
    def _recalc_checksum(self, header: Header) -> Bits: ...

    @overload
    def _recalc_checksum(self, header: Header, payload: bytes) -> Bits: ...

    def _recalc_checksum(self, header: Header, payload: bytes | None = None):
        '''Return the recalculated checksum'''
        header = header.updated('checksum', Bits(0, 16))
        data = bytes(header)
        if payload is not None:
            data += payload
        checksum = Bits(type(self)._calc_checksum(data), 16)
        return checksum

    @classmethod
    def verify_checksum(cls, data: bytes):
        checksum = cls._calc_checksum(data)
        if checksum != 0x0000:
            raise ValueError(f'Calculated checksum of {format(checksum, '04x')}:\n{repr(cls._parse_header(data))}')

    def _test_valid_parse(self):
        fields = self._header.values()
        data = bytes(self)

        assert len(concat(fields)) == BYTE_SIZE * self.HEADER_LEN
        assert bytes(concat(fields)) == bytes(self._header)
        assert concat(fields) + Bits(bytes(self._payload)) == Bits(data)
        assert bytes(concat(fields)) + bytes(self._payload) == data
        assert bytes(int(byte) for byte in bytes(self)) == bytes(self)

    @abstractmethod
    def _update_field(self, header: Header, name: str, value: bytes) -> Header: ...

    def __bytes__(self):
        return bytes(self._header) + bytes(self._payload)

    def __len__(self):
        return len(bytes(self))

    def __eq__(self, other: object):
        return isinstance(other, type(self)) and bytes(self) == bytes(other)

    @abstractmethod
    def __repr__(self) -> str: ...

class IPPacket(Packet['UDPPacket']):
    _FIELD_OFFSETS = {
        'version':     (0,  (0, 4)),
        'ihl':         (0,  (4, 8)),
        'dscp':        (1,  (0, 6)),
        'ecn':         (1,  (6, 8)),
        'total_len':   (2,  (0, 16)),
        'identifier':  (4,  (0, 16)),
        'flags':       (6,  (0, 3)),
        'frag_offset': (6,  (3, 16)),
        'ttl':         (8,  (0, 8)),
        'protocol':    (9,  (0, 8)),
        'checksum':    (10, (0, 16)),
        'src_addr':    (12, (0, 32)),
        'dest_addr':   (16, (0, 32)),
    }
    HEADER_LEN = 20
    CHECKSUM_LEN = 20
    UDP = 17
    ICMP = 1

    @overload
    def __init__(self, data: bytes): ...

    @overload
    def __init__(self, data: Header, payload: UDPPacket): ...

    def __init__(self, data: bytes | Header, payload: UDPPacket | None = None):
        if payload is None:
            assert isinstance(data, bytes)
            super().__init__(data)
            header = data[:self.CHECKSUM_LEN]
        else:
            assert isinstance(data, Header)
            super().__init__(data, payload)
            header = bytes(data)

        self.verify_checksum(header)
        pseudo_header = self._pseudo_header(self._header, self._payload)
        self.verify_checksum(bytes(pseudo_header) + self._payload._payload)

        ttl = int(self._header['ttl']) - 1
        if ttl <= 0:
            raise ValueError('TTL has expired')
        ttl = ttl.to_bytes(1, 'big')
        self._header = self._update_field(self._header, 'ttl', ttl)

    def _parse_payload(self, data: bytes):
        match int(self._header['protocol']):
            case self.UDP:
                return UDPPacket(data[self.HEADER_LEN:])
            case self.ICMP:
                # ;(
                raise NotImplementedError
            case _:
                raise ValueError('Unknown protocol number')

    @staticmethod
    def _pseudo_header(header: Header, udp_packet: UDPPacket):
        return Header({
            'pseudo_src_addr':      header['src_addr'],
            'pseudo_dest_addr':     header['dest_addr'],
            'pseudo_zero_byte':     Bits(0, 8),
            'pseudo_protocol':      Bits(17, 8),
            'psuedo_udp_length':    Bits(len(udp_packet), 16)
        }) | udp_packet._header

    def _update_field(self, header: Header, name: str, value: bytes):
        '''Return header with field and checksum updated'''
        updated = header.updated(name, Bits(value))
        checksum = self._recalc_checksum(updated)
        return updated.updated('checksum', checksum)

    def _update_addr(self, new_addr: Address, addr_name: str, port_name: str):
        '''Return packet with IP and UDP address fields updated'''
        ip_addr, port_num = new_addr
        port_num = port_num.to_bytes(2, 'big')
        ip_header = self._update_field(self._header, addr_name, ip_addr)

        udp_packet = self._payload
        pseudo_header = self._pseudo_header(ip_header, udp_packet)
        udp_header = udp_packet._update_field(pseudo_header, port_name, port_num)
        return IPPacket(ip_header, UDPPacket(udp_header, udp_packet._payload))

    def update_src(self, new_addr: Address):
        return self._update_addr(new_addr, 'src_addr', 'src_port')

    def update_dest(self, new_addr: Address):
        return self._update_addr(new_addr, 'dest_addr', 'dest_port')

    def _address(self, addr_name: str, port_name: str):
        ip_addr = bytes(self._header[addr_name])
        port_num = int.from_bytes(self._payload._header[port_name], 'big')
        return Address(ip_addr, port_num)

    def src_addr(self):
        return self._address('src_addr', 'src_port')

    def dest_addr(self):
        return self._address('dest_addr', 'dest_port')

    def __repr__(self):
        return '\n'.join((
            'IP Header:',
            repr(self._header),
            repr(self._payload)
        ))

class UDPPacket(Packet[bytes]):
    _FIELD_OFFSETS = {
        'src_port':    (0,  (0, 16)),
        'dest_port':   (2,  (0, 16)),
        'length':      (4,  (0, 16)),
        'checksum':    (6,  (0, 16)),
    }
    PSEUDO_HEADER_LEN = 12
    HEADER_LEN = 8
    CHECKSUM_LEN: int

    @overload
    def __init__(self, data: bytes): ...

    @overload
    def __init__(self, data: Header, payload: bytes): ...

    def __init__(self, data: bytes | Header, payload: bytes | None = None):
        if payload is None:
            assert isinstance(data, bytes)
            super().__init__(data)
        else:
            assert isinstance(data, Header)
            super().__init__(data, payload)
        self.CHECKSUM_LEN = len(self) + self.PSEUDO_HEADER_LEN

    def _parse_payload(self, data: bytes):
        return data[self.HEADER_LEN:]

    def _update_field(self, header: Header, name: str, value: bytes):
        '''Return header with field and checksum updated'''
        pseudo_header = header.updated(name, Bits(value))
        checksum = self._recalc_checksum(pseudo_header, self._payload)
        if int(checksum) == 0x0000:
            checksum = Bits(0xFFFF, 16)
        updated = self._header.updated(name, Bits(value))
        return updated.updated('checksum', checksum)

    def __repr__(self):
        return '\n'.join((
            'UDP Header:',
            repr(self._header),
            f'Followed by {len(self._payload)} bytes of data'
        ))

# def str_binary(data: bytes):
#     def format_byte(byte: int):
#         return format(byte, '08b')
    
#     return '\n'.join(
#         ' '.join(
#             f'{i + j:2}: {format_byte(data[i + j])}'
#             for j in range(min(4, len(data) - i))
#         ) for i in range(0, len(data), 4)
#     )
