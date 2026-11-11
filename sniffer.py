"""Command-line network packet sniffer and web-log analyser."""

from __future__ import annotations

import argparse
import csv
import json
import socket
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Iterable

from log_analyzer import find_authentication_alerts, read_log
from packet_parser import Packet, decode_ethernet_frame


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture IPv4 packets and analyse web server authentication logs."
    )
    parser.add_argument("--interface", help="Linux interface to capture on")
    parser.add_argument("--count", type=int, default=50, help="number of packets to capture")
    parser.add_argument("--protocol", choices=("tcp", "udp", "icmp"), help="protocol filter")
    parser.add_argument("--port", type=int, help="source or destination port filter")
    parser.add_argument("--source-ip", help="source IPv4 address filter")
    parser.add_argument("--destination-ip", help="destination IPv4 address filter")
    parser.add_argument("--analyze-log", type=Path, help="Apache/Nginx access log to analyse")
    parser.add_argument("--threshold", type=int, default=10, help="authentication alert threshold")
    parser.add_argument("--output-json", type=Path, help="write packet results or alerts to JSON")
    parser.add_argument("--output-csv", type=Path, help="write packet results to CSV")
    return parser


def packet_matches(packet: Packet, args: argparse.Namespace) -> bool:
    return (
        (args.protocol is None or packet.protocol.lower() == args.protocol)
        and (
            args.port is None
            or packet.source_port == args.port
            or packet.destination_port == args.port
        )
        and (args.source_ip is None or packet.source_ip == args.source_ip)
        and (
            args.destination_ip is None
            or packet.destination_ip == args.destination_ip
        )
    )


def capture_packets(args: argparse.Namespace) -> list[Packet]:
    if args.count < 1:
        raise ValueError("--count must be at least 1")
    if args.port is not None and not 1 <= args.port <= 65535:
        raise ValueError("--port must be between 1 and 65535")
    interface = args.interface or "eth0"
    captured: list[Packet] = []
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) as raw_socket:
        raw_socket.bind((interface, 0))
        while len(captured) < args.count:
            frame, _ = raw_socket.recvfrom(65535)
            try:
                packet = decode_ethernet_frame(frame, time.time())
            except ValueError:
                continue
            if packet_matches(packet, args):
                captured.append(packet)
                print(format_packet(packet))
    return captured


def format_packet(packet: Packet) -> str:
    ports = ""
    if packet.source_port is not None and packet.destination_port is not None:
        ports = f":{packet.source_port} -> :{packet.destination_port}"
    return (
        f"{packet.source_ip}{ports} -> {packet.destination_ip} "
        f"{packet.protocol} ({packet.length} bytes)"
    )


def write_json(path: Path, values: Iterable[dict[str, object]]) -> None:
    path.write_text(json.dumps(list(values), indent=2) + "\n", encoding="utf-8")


def write_csv(path: Path, packets: Iterable[Packet]) -> None:
    rows = [packet.to_dict() for packet in packets]
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=Packet.__dataclass_fields__.keys())
        writer.writeheader()
        writer.writerows(rows)


def run(args: argparse.Namespace) -> int:
    if args.analyze_log:
        alerts = find_authentication_alerts(read_log(args.analyze_log), args.threshold)
        for alert in alerts:
            print(
                f"ALERT {alert['ip']}: "
                f"{alert['authentication_requests']} authentication requests"
            )
        if args.output_json:
            write_json(args.output_json, alerts)
        return 0

    packets = capture_packets(args)
    if args.output_json:
        write_json(args.output_json, (packet.to_dict() for packet in packets))
    if args.output_csv:
        write_csv(args.output_csv, packets)
    return 0


def main() -> int:
    try:
        return run(build_parser().parse_args())
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
