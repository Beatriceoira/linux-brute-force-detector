#!/usr/bin/env python3
"""
Brute Force Detector — Ubuntu / Linux (SSH auth.log)
=======================================================

The Linux counterpart to Windows Event ID 4625. On Ubuntu (and most Debian-
based systems), failed SSH logon attempts are recorded by sshd in:

    /var/log/auth.log            (current)
    /var/log/auth.log.1          (rotated, plain text)
    /var/log/auth.log.2.gz       (rotated, gzipped)

This script parses those lines, extracts failed-authentication events
(the rough equivalent of a 4625), and runs the same sliding-window
brute-force / password-spray detection as the Windows version.

Lines it recognizes:
    "Failed password for USER from IP port PORT ssh2"
    "Failed password for invalid user USER from IP port PORT ssh2"
    "Invalid user USER from IP port PORT"
    "authentication failure; ... rhost=IP  user=USER"
    "Connection closed by authenticating user USER IP port PORT [preauth]"

Three input modes:
  1. live  — read directly from journald (systemd) or /var/log/auth.log
  2. file  — parse a specific log file (plain text or .gz), e.g. a rotated
             or rsync'd auth.log from another host
  3. journal — pull sshd entries from `journalctl` explicitly

Usage:
    sudo python3 brute_force_detector_linux.py --mode live --threshold 5 --window 300
    python3 brute_force_detector_linux.py --mode file --file /var/log/auth.log
    python3 brute_force_detector_linux.py --mode file --file /var/log/auth.log.2.gz
    python3 brute_force_detector_linux.py --mode journal --hours-back 24

Output:
    Prints alerts to stdout and writes a JSON report (default:
    brute_force_report.json).
"""

import argparse
import gzip
import json
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Dict, Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class LogonFailureEvent:
    time: datetime
    ip_address: str
    target_user: str
    reason: str = ""

    def __repr__(self):
        return (f"<sshd-fail {self.time.isoformat()} ip={self.ip_address} "
                f"user={self.target_user}>")


@dataclass
class BruteForceAlert:
    source_ip: str
    alert_type: str            # "brute_force" or "password_spray"
    first_seen: datetime
    last_seen: datetime
    attempt_count: int
    targeted_accounts: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "source_ip": self.source_ip,
            "alert_type": self.alert_type,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "duration_seconds": (self.last_seen - self.first_seen).total_seconds(),
            "attempt_count": self.attempt_count,
            "targeted_accounts": sorted(set(self.targeted_accounts)),
            "distinct_account_count": len(set(self.targeted_accounts)),
        }


# ---------------------------------------------------------------------------
# Log line parsing
# ---------------------------------------------------------------------------

# Standard auth.log syslog prefix, e.g.:
#   "Sep 29 14:32:01 myhost sshd[12345]: Failed password for root from 1.2.3.4 port 51514 ssh2"
SYSLOG_PREFIX_RE = re.compile(
    r"^(?:(?P<iso_ts>\d{4}-\d{2}-\d{2}T\S+)|"
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}))\s+"
    r"(?P<host>\S+)\s+(?P<proc>\S+?):\s*(?P<msg>.*)$"
)

FAILED_PW_RE = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port \d+"
)
INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"
)
AUTH_FAILURE_RE = re.compile(
    r"authentication failure;.*?rhost=(?P<ip>[\d.:a-fA-F]+)(\s+user=(?P<user>\S+))?"
)
PREAUTH_CLOSED_RE = re.compile(
    r"Connection closed by (invalid user )?(authenticating user )?(?P<user>\S+)?\s*"
    r"(?P<ip>[\d.:a-fA-F]+) port \d+ \[preauth\]"
)


def _syslog_time_to_datetime(month: str, day: str, time_str: str,
                              assumed_year: Optional[int] = None) -> datetime:
    year = assumed_year or datetime.now().year
    dt = datetime.strptime(f"{year} {month} {day} {time_str}", "%Y %b %d %H:%M:%S")
    # Handle log lines from December parsed near a new year, if ever needed.
    if dt > datetime.now() + timedelta(days=1):
        dt = dt.replace(year=year - 1)
    return dt


def parse_line(line: str) -> Optional[LogonFailureEvent]:
    m = SYSLOG_PREFIX_RE.match(line)
    if not m:
        return None
    if "sshd" not in m.group("proc"):
        return None

    msg = m.group("msg")
    if m.group("iso_ts"):
        try:
            t = datetime.fromisoformat(m.group("iso_ts")).replace(tzinfo=None)
        except ValueError:
            return None
    else:
        t = _syslog_time_to_datetime(
            m.group("month"),
            m.group("day"),
            m.group("time")
        )

    fm = FAILED_PW_RE.search(msg)
    if fm:
        return LogonFailureEvent(time=t, ip_address=fm.group("ip"),
                                  target_user=fm.group("user"), reason="failed_password")

    im = INVALID_USER_RE.search(msg)
    if im:
        return LogonFailureEvent(time=t, ip_address=im.group("ip"),
                                  target_user=im.group("user"), reason="invalid_user")

    am = AUTH_FAILURE_RE.search(msg)
    if am:
        return LogonFailureEvent(time=t, ip_address=am.group("ip"),
                                  target_user=am.group("user") or "unknown",
                                  reason="auth_failure")

    pm = PREAUTH_CLOSED_RE.search(msg)
    if pm:
        return LogonFailureEvent(time=t, ip_address=pm.group("ip"),
                                  target_user=pm.group("user") or "unknown",
                                  reason="preauth_closed")

    return None


def parse_lines(lines) -> List[LogonFailureEvent]:
    events = []
    for line in lines:
        ev = parse_line(line.rstrip("\n"))
        if ev:
            events.append(ev)
    return events


# ---------------------------------------------------------------------------
# Input sources
# ---------------------------------------------------------------------------

def read_file_lines(path: str):
    if path.endswith(".gz"):
        with gzip.open(path, "rt", errors="replace") as f:
            yield from f
    else:
        with open(path, "r", errors="replace") as f:
            yield from f


def parse_file(path: str) -> List[LogonFailureEvent]:
    return parse_lines(read_file_lines(path))


def parse_live_syslog(paths=None) -> List[LogonFailureEvent]:
    """
    Reads /var/log/auth.log (and .1 rotation) directly. Requires read
    access — typically run with sudo, since auth.log is root/adm only.
    """
    paths = paths or ["/var/log/auth.log", "/var/log/auth.log.1"]
    events = []
    for p in paths:
        try:
            events.extend(parse_file(p))
        except FileNotFoundError:
            continue
        except PermissionError:
            print(f"[!] Permission denied reading {p} — try running with sudo.",
                  file=sys.stderr)
    return events


def parse_journal(hours_back: int = 24) -> List[LogonFailureEvent]:
    """
    Pulls sshd log lines from journald via `journalctl`, formatted to look
    like classic syslog lines so the same regexes apply. Works even on
    systems where /var/log/auth.log doesn't exist (journald-only setups).
    """
    since = (datetime.now() - timedelta(hours=hours_back)).strftime("%Y-%m-%d %H:%M:%S")
    cmd = [
        "journalctl", "-u", "ssh", "-u", "sshd",
        "--since", since,
        "--no-pager", "-o", "short-iso",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except FileNotFoundError:
        print("[!] journalctl not found on this system.", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"[!] journalctl failed: {e.stderr}", file=sys.stderr)
        sys.exit(1)

    events = []
    # short-iso format: "2026-09-29T14:32:01+0000 host sshd[123]: message"
    iso_re = re.compile(
        r"^(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<proc>\S+?):\s*(?P<msg>.*)$"
    )
    for line in result.stdout.splitlines():
        m = iso_re.match(line)
        if not m or "sshd" not in m.group("proc"):
            continue
        try:
            t = datetime.fromisoformat(m.group("ts"))
        except ValueError:
            continue
        msg = m.group("msg")

        fm = FAILED_PW_RE.search(msg)
        if fm:
            events.append(LogonFailureEvent(time=t.replace(tzinfo=None),
                                              ip_address=fm.group("ip"),
                                              target_user=fm.group("user"),
                                              reason="failed_password"))
            continue
        im = INVALID_USER_RE.search(msg)
        if im:
            events.append(LogonFailureEvent(time=t.replace(tzinfo=None),
                                              ip_address=im.group("ip"),
                                              target_user=im.group("user"),
                                              reason="invalid_user"))
            continue
        am = AUTH_FAILURE_RE.search(msg)
        if am:
            events.append(LogonFailureEvent(time=t.replace(tzinfo=None),
                                              ip_address=am.group("ip"),
                                              target_user=am.group("user") or "unknown",
                                              reason="auth_failure"))
    return events


# ---------------------------------------------------------------------------
# Detection engine (identical logic to the Windows version)
# ---------------------------------------------------------------------------

class BruteForceDetector:
    def __init__(self, threshold: int = 5, window_seconds: int = 300,
                 spray_distinct_accounts: int = 5):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.spray_distinct_accounts = spray_distinct_accounts

    def analyze(self, events: List[LogonFailureEvent]) -> List[BruteForceAlert]:
        events_by_ip: Dict[str, List[LogonFailureEvent]] = defaultdict(list)
        for e in events:
            events_by_ip[e.ip_address].append(e)

        alerts = []
        for ip, evs in events_by_ip.items():
            if not ip or ip == "unknown":
                continue
            evs.sort(key=lambda e: e.time)
            alerts.extend(self._sliding_window_check(ip, evs))
        return alerts

    def _sliding_window_check(self, ip: str,
                               evs: List[LogonFailureEvent]) -> List[BruteForceAlert]:
        alerts = []
        n = len(evs)
        left = 0
        flagged_brute = False
        flagged_spray = False

        for right in range(n):
            while evs[right].time - evs[left].time > self.window:
                left += 1

            window_events = evs[left:right + 1]
            count = len(window_events)
            distinct_accounts = {e.target_user for e in window_events if e.target_user}

            if count >= self.threshold and not flagged_brute:
                alerts.append(BruteForceAlert(
                    source_ip=ip, alert_type="brute_force",
                    first_seen=window_events[0].time, last_seen=window_events[-1].time,
                    attempt_count=count,
                    targeted_accounts=[e.target_user for e in window_events],
                ))
                flagged_brute = True

            if len(distinct_accounts) >= self.spray_distinct_accounts and not flagged_spray:
                alerts.append(BruteForceAlert(
                    source_ip=ip, alert_type="password_spray",
                    first_seen=window_events[0].time, last_seen=window_events[-1].time,
                    attempt_count=count,
                    targeted_accounts=[e.target_user for e in window_events],
                ))
                flagged_spray = True

            if flagged_brute and flagged_spray:
                break

        return alerts


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_alerts(alerts: List[BruteForceAlert]):
    if not alerts:
        print("[+] No brute-force or password-spray activity detected.")
        return

    print(f"[!] {len(alerts)} alert(s) detected:\n")
    for a in alerts:
        distinct = sorted(set(a.targeted_accounts))
        print(f"  Source IP:        {a.source_ip}")
        print(f"  Type:             {a.alert_type}")
        print(f"  First seen:       {a.first_seen}")
        print(f"  Last seen:        {a.last_seen}")
        print(f"  Attempt count:    {a.attempt_count}")
        print(f"  Distinct accounts:{len(distinct)} "
              f"({', '.join(distinct[:10])}{'...' if len(distinct) > 10 else ''})")
        print("-" * 60)


def write_report(alerts: List[BruteForceAlert], path: str):
    with open(path, "w") as f:
        json.dump([a.to_dict() for a in alerts], f, indent=2)
    print(f"\n[+] Report written to {path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Detect SSH brute-force / password-spray attacks on Ubuntu/Linux "
                    "from auth.log or journald — the Linux equivalent of Windows 4625.")
    parser.add_argument("--mode", choices=["live", "file", "journal"], required=True,
                        help="Input source: live auth.log, a specific file, or journald")
    parser.add_argument("--file", help="Path to a log file (plain or .gz) — required for --mode file")
    parser.add_argument("--hours-back", type=int, default=24,
                        help="For journal mode: how far back to read (default: 24)")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Failed attempts from one IP to trigger a brute-force alert (default: 5)")
    parser.add_argument("--window", type=int, default=300,
                        help="Rolling time window in seconds (default: 300 = 5 min)")
    parser.add_argument("--spray-accounts", type=int, default=5,
                        help="Distinct usernames from one IP to trigger a spray alert (default: 5)")
    parser.add_argument("--output", default="brute_force_report.json",
                        help="Path to write JSON report (default: brute_force_report.json)")
    args = parser.parse_args()

    if args.mode == "file" and not args.file:
        parser.error("--file is required for --mode file")

    print(f"[*] Loading events (mode={args.mode})...")
    if args.mode == "live":
        events = parse_live_syslog()
    elif args.mode == "file":
        events = parse_file(args.file)
    else:
        events = parse_journal(hours_back=args.hours_back)

    print(f"[*] Loaded {len(events)} failed SSH authentication events.")

    detector = BruteForceDetector(
        threshold=args.threshold,
        window_seconds=args.window,
        spray_distinct_accounts=args.spray_accounts,
    )
    alerts = detector.analyze(events)

    print_alerts(alerts)
    write_report(alerts, args.output)


if __name__ == "__main__":
    main()
