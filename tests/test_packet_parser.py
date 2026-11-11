import struct
import unittest

from packet_parser import decode_ethernet_frame


class PacketParserTests(unittest.TestCase):
    def test_decodes_tcp_ipv4_frame(self) -> None:
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            40,
            0,
            0,
            64,
            6,
            0,
            b"\xc0\xa8\x01\x02",
            b"\x08\x08\x08\x08",
        )
        tcp_header = struct.pack("!HH", 12345, 443) + b"\x00" * 16
        frame = b"\x00" * 12 + struct.pack("!H", 0x0800) + ip_header + tcp_header

        packet = decode_ethernet_frame(frame, 1.0)

        self.assertEqual(packet.source_ip, "192.168.1.2")
        self.assertEqual(packet.destination_ip, "8.8.8.8")
        self.assertEqual(packet.protocol, "TCP")
        self.assertEqual(packet.destination_port, 443)

    def test_rejects_non_ipv4_frame(self) -> None:
        with self.assertRaises(ValueError):
            decode_ethernet_frame(b"\x00" * 12 + b"\x08\x06" + b"\x00" * 20, 1.0)

