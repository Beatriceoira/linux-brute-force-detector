import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from brute_force_detector_linux import (
    BruteForceDetector,
    BruteForceAlert,
    LogonFailureEvent,
    parse_file,
    parse_line,
    write_report,
)


class TestLogParser(unittest.TestCase):

    def test_parse_failed_password(self):
        line = (
            "Sep 29 18:30:01 testhost sshd[1001]: "
            "Failed password for admin from 192.168.1.50 port 50001 ssh2"
        )

        event = parse_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event.ip_address, "192.168.1.50")
        self.assertEqual(event.target_user, "admin")
        self.assertEqual(event.reason, "failed_password")

    def test_parse_invalid_user(self):
        line = (
            "Sep 29 19:00:01 testhost sshd[3001]: "
            "Failed password for invalid user guest from "
            "172.16.0.25 port 52001 ssh2"
        )

        event = parse_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event.ip_address, "172.16.0.25")
        self.assertEqual(event.target_user, "guest")
        self.assertEqual(event.reason, "failed_password")

    def test_parse_iso_timestamp(self):
        line = (
            "2026-09-29T18:35:22.622505+08:00 desktop "
            "sshd-session[124609]: "
            "Failed password for testuser from 127.0.0.1 port 39376 ssh2"
        )

        event = parse_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event.ip_address, "127.0.0.1")
        self.assertEqual(event.target_user, "testuser")
        self.assertEqual(event.reason, "failed_password")

    def test_ignore_non_ssh_log(self):
        line = (
            "Sep 29 18:30:01 testhost sudo: "
            "beatriceoira : TTY=/dev/pts/0 ; USER=root"
        )

        event = parse_line(line)

        self.assertIsNone(event)

    def test_ignore_successful_login(self):
        line = (
            "Sep 29 19:30:01 testhost sshd[4001]: "
            "Accepted password for testuser from "
            "192.168.1.100 port 53001 ssh2"
        )

        event = parse_line(line)

        self.assertIsNone(event)


class TestFileParsing(unittest.TestCase):

    def test_parse_sample_log(self):
        log_file = Path(__file__).parent / "sample_auth.log"

        events = parse_file(str(log_file))

        self.assertEqual(len(events), 13)

        ips = {event.ip_address for event in events}

        self.assertIn("192.168.1.50", ips)
        self.assertIn("10.0.0.50", ips)
        self.assertIn("172.16.0.25", ips)

    def test_parse_sample_event_data(self):
        log_file = Path(__file__).parent / "sample_auth.log"

        events = parse_file(str(log_file))

        first_event = events[0]

        self.assertEqual(first_event.ip_address, "192.168.1.50")
        self.assertEqual(first_event.target_user, "admin")
        self.assertEqual(first_event.reason, "failed_password")


class TestBruteForceDetector(unittest.TestCase):

    def create_event(self, second, ip, username):
        return LogonFailureEvent(
            time=datetime(2026, 9, 29, 18, 30, second),
            ip_address=ip,
            target_user=username,
            reason="failed_password",
        )

    def test_brute_force_detection(self):
        events = [
            self.create_event(
                second,
                "192.168.1.50",
                "admin",
            )
            for second in [1, 10, 20, 30, 40]
        ]

        detector = BruteForceDetector(
            threshold=5,
            window_seconds=300,
            spray_distinct_accounts=5,
        )

        alerts = detector.analyze(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].source_ip, "192.168.1.50")
        self.assertEqual(alerts[0].alert_type, "brute_force")
        self.assertEqual(alerts[0].attempt_count, 5)
        self.assertEqual(alerts[0].targeted_accounts, [
            "admin",
            "admin",
            "admin",
            "admin",
            "admin",
        ])

    def test_password_spray_detection(self):
        usernames = [
            "alice",
            "bob",
            "charlie",
            "david",
            "admin",
        ]

        events = [
            self.create_event(
                second,
                "10.0.0.50",
                username,
            )
            for second, username in zip(
                [1, 10, 20, 30, 40],
                usernames,
            )
        ]

        detector = BruteForceDetector(
            threshold=5,
            window_seconds=300,
            spray_distinct_accounts=5,
        )

        alerts = detector.analyze(events)

        alert_types = {alert.alert_type for alert in alerts}

        self.assertIn("brute_force", alert_types)
        self.assertIn("password_spray", alert_types)

    def test_below_threshold_is_not_detected(self):
        events = [
            self.create_event(
                second,
                "172.16.0.25",
                "guest",
            )
            for second in [1, 15, 30]
        ]

        detector = BruteForceDetector(
            threshold=5,
            window_seconds=300,
            spray_distinct_accounts=5,
        )

        alerts = detector.analyze(events)

        self.assertEqual(len(alerts), 0)

    def test_events_outside_window_are_not_grouped(self):
        events = [
            LogonFailureEvent(
                time=datetime(2026, 9, 29, 18, 30, 0),
                ip_address="192.168.1.50",
                target_user="admin",
                reason="failed_password",
            ),
            LogonFailureEvent(
                time=datetime(2026, 9, 29, 18, 36, 0),
                ip_address="192.168.1.50",
                target_user="admin",
                reason="failed_password",
            ),
        ]

        detector = BruteForceDetector(
            threshold=2,
            window_seconds=300,
            spray_distinct_accounts=5,
        )

        alerts = detector.analyze(events)

        self.assertEqual(len(alerts), 0)


class TestBruteForceAlert(unittest.TestCase):

    def test_to_dict(self):
        alert = BruteForceAlert(
            source_ip="192.168.1.50",
            alert_type="brute_force",
            first_seen=datetime(2026, 9, 29, 18, 30, 1),
            last_seen=datetime(2026, 9, 29, 18, 30, 40),
            attempt_count=5,
            targeted_accounts=[
                "admin",
                "admin",
                "admin",
                "admin",
                "admin",
            ],
        )

        result = alert.to_dict()

        self.assertEqual(result["source_ip"], "192.168.1.50")
        self.assertEqual(result["alert_type"], "brute_force")
        self.assertEqual(result["attempt_count"], 5)
        self.assertEqual(result["distinct_account_count"], 1)
        self.assertEqual(result["targeted_accounts"], ["admin"])


class TestReport(unittest.TestCase):

    def test_write_report(self):
        alert = BruteForceAlert(
            source_ip="192.168.1.50",
            alert_type="brute_force",
            first_seen=datetime(2026, 9, 29, 18, 30, 1),
            last_seen=datetime(2026, 9, 29, 18, 30, 40),
            attempt_count=5,
            targeted_accounts=["admin"] * 5,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "test_report.json"

            write_report([alert], str(report_path))

            self.assertTrue(report_path.exists())

            with open(report_path, "r", encoding="utf-8") as file:
                report = json.load(file)

            self.assertEqual(len(report), 1)
            self.assertEqual(
                report[0]["source_ip"],
                "192.168.1.50",
            )
            self.assertEqual(
                report[0]["alert_type"],
                "brute_force",
            )
            self.assertEqual(
                report[0]["attempt_count"],
                5,
            )


if __name__ == "__main__":
    unittest.main()