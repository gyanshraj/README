import unittest

from log_analyzer import find_authentication_alerts, parse_log_line


class LogAnalyzerTests(unittest.TestCase):
    def test_parses_common_log_format(self) -> None:
        entry = parse_log_line(
            '203.0.113.4 - - [11/Nov/2026:12:00:00 +0000] '
            '"POST /login HTTP/1.1" 401 128'
        )
        self.assertIsNotNone(entry)
        self.assertEqual(entry.status, 401)
        self.assertEqual(entry.size, 128)

    def test_detects_authentication_surge(self) -> None:
        lines = [
            f'203.0.113.4 - - [date] "POST /login HTTP/1.1" 401 10'
            for _ in range(3)
        ]
        entries = [parse_log_line(line) for line in lines]
        alerts = find_authentication_alerts(
            (entry for entry in entries if entry is not None), threshold=3
        )
        self.assertEqual(alerts[0]["ip"], "203.0.113.4")

