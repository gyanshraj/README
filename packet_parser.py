"""IPv4 packet decoding helpers for the network packet sniffer."""

from __future__ import annotations

import socket
import struct
from dataclasses import asdict, dataclass
from typing import Any


ETHERNET_HEADER_LENGTH = 14
ETHERNET_IPV4 = 0x0800
IP_HEADER_MIN_LENGTH = 20


@dataclass(frozen=True)
class Packet:
    timestamp: float
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: int | None = None
    destination_port: int | None = None
    length: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _parse_ipv4(data: bytes, timestamp: float) -> Packet:
    if len(data) < IP_HEADER_MIN_LENGTH:
        raise ValueError("IPv4 packet is shorter than its minimum header")

    version_and_ihl, _, total_length, _, _, _, protocol, _, source, destination = (
        struct.unpack("!BBHHHBBH4s4s", data[:20])
    )
    version = version_and_ihl >> 4
    header_length = (version_and_ihl & 0x0F) * 4
    if version != 4:
        raise ValueError("packet is not IPv4")
    if header_length < IP_HEADER_MIN_LENGTH or len(data) < header_length:
        raise ValueError("IPv4 header has an invalid length")

    protocol_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(
        protocol, f"OTHER({protocol})"
    )
    source_port = destination_port = None
    transport_data = data[header_length:]
    if protocol in (6, 17) and len(transport_data) >= 4:
        source_port, destination_port = struct.unpack("!HH", transport_data[:4])

    return Packet(
        timestamp=timestamp,
        source_ip=socket.inet_ntoa(source),
        destination_ip=socket.inet_ntoa(destination),
        protocol=protocol_name,
        source_port=source_port,
        destination_port=destination_port,
        length=total_length,
    )


def decode_ethernet_frame(frame: bytes, timestamp: float) -> Packet:
    """Decode an Ethernet frame containing an IPv4 packet."""
    if len(frame) < ETHERNET_HEADER_LENGTH:
        raise ValueError("Ethernet frame is shorter than its header")
    ethertype = struct.unpack("!H", frame[12:14])[0]
    if ethertype != ETHERNET_IPV4:
        raise ValueError(f"unsupported Ethernet type: 0x{ethertype:04x}")
    return _parse_ipv4(frame[ETHERNET_HEADER_LENGTH:], timestamp)

