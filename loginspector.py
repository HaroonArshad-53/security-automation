#!/usr/bin/env python3
"""
loginspector.py — spot brute-force and password-spray patterns in auth logs.

Reads syslog-style authentication logs (or stdin) and reports:
  * brute force: many failed logins for one account from one IP
  * password spray: one IP trying many different accounts

Usage:
    python3 loginspector.py /var/log/auth.log
    zcat /var/log/auth.log.*.gz | python3 loginspector.py
    python3 loginspector.py --threshold 5 --window 600 auth.log
"""

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

# Matches common "failed login" lines. Extend as needed for your log format.
PATTERNS = [
    # OpenSSH: "Failed password for invalid user admin from 1.2.3.4 port 22"
    re.compile(
        r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
    ),
    # Generic: "authentication failure ... user=bob ... rhost=1.2.3.4"
    re.compile(r"authentication failure.*user=(\S+).*rhost=(\d+\.\d+\.\d+\.\d+)"),
]

TIME_FMT = "%b %d %H:%M:%S"  # syslog, e.g. "Oct 12 09:15:32"


def parse_time(line):
    try:
        ts = datetime.strptime(" ".join(line.split()[:3]), TIME_FMT)
        return ts.replace(year=datetime.now().year)
    except (ValueError, IndexError):
        return None


def main():
    ap = argparse.ArgumentParser(description="Detect brute-force / spray patterns in auth logs.")
    ap.add_argument("logfile", nargs="?", help="log file (default: stdin)")
    ap.add_argument("--threshold", type=int, default=5, help="failures to trigger an alert (default: 5)")
    ap.add_argument("--window", type=int, default=600, help="sliding window in seconds (default: 600)")
    args = ap.parse_args()

    src = open(args.logfile, errors="replace") if args.logfile else sys.stdin
    events = []  # (timestamp, user, ip)

    for line in src:
        ts = parse_time(line)
        if not ts:
            continue
        for pat in PATTERNS:
            m = pat.search(line)
            if m:
                events.append((ts, m.group(1), m.group(2)))
                break

    if not events:
        print("No failed-login events found. Check that the log format matches PATTERNS.")
        return

    window = timedelta(seconds=args.window)
    brute, spray = defaultdict(list), defaultdict(set)

    for ts, user, ip in events:
        brute[(ip, user)].append(ts)
        spray[ip].add(user)

    print(f"Scanned {len(events)} failed logins.\n")

    print("== Possible brute force (one IP hammering one account) ==")
    found = False
    for (ip, user), times in sorted(brute.items()):
        times.sort()
        start = 0
        for end in range(len(times)):
            while times[end] - times[start] > window:
                start += 1
            if end - start + 1 >= args.threshold:
                print(f"  {ip} -> {user}: {end - start + 1} failures within {args.window}s")
                found = True
                break
    if not found:
        print("  none")

    print("\n== Possible password spray (one IP trying many accounts) ==")
    found = False
    for ip, users in sorted(spray.items()):
        if len(users) >= args.threshold:
            sample = ", ".join(sorted(users)[:5])
            extra = f" (+{len(users) - 5} more)" if len(users) > 5 else ""
            print(f"  {ip}: {len(users)} distinct accounts ({sample}{extra})")
            found = True
    if not found:
        print("  none")


if __name__ == "__main__":
    main()
