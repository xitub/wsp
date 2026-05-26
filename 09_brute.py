import re
from collections import defaultdict
from datetime import datetime


DETECTION_THRESHOLD = 5
TIME_WINDOW = 300   # 5 minutes in seconds


def parse_log_line(line):

    pattern = re.compile(
        r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*'
        r'Login failed for user.*from IP '
        r'(?P<ip>\d+\.\d+\.\d+\.\d+)'
    )

    match = pattern.match(line)

    return (
        (match.group('timestamp'), match.group('ip'))
        if match else
        (None, None)
    )


def convert_to_timestamp(timestamp_str):

    return datetime.strptime(
        timestamp_str,
        "%Y-%m-%d %H:%M:%S"
    ).timestamp()


def detect_brute_force(log_lines):

    failed_attempts = defaultdict(list)

    for line in log_lines:

        timestamp_str, ip = parse_log_line(line)

        if ip:

            timestamp = convert_to_timestamp(timestamp_str)

            failed_attempts[ip].append(timestamp)

            window_start = timestamp - TIME_WINDOW

            recent_attempts = [
                ts for ts in failed_attempts[ip]
                if ts >= window_start
            ]

            if len(recent_attempts) >= DETECTION_THRESHOLD:

                print(
                    f"Brute force detected from "
                    f"IP {ip} at {timestamp_str}"
                )


# Example log lines (replace with actual log lines)
log_lines = [

    "2024-06-02 12:00:00 Login failed for user admin "
    "from IP 192.168.1.1",

    "2024-06-02 12:00:30 Login failed for user admin "
    "from IP 192.168.1.1",

    "2024-06-02 12:01:00 Login failed for user admin "
    "from IP 192.168.1.1",

    "2024-06-02 12:01:30 Login failed for user admin "
    "from IP 192.168.1.1",

    "2024-06-02 12:02:00 Login failed for user admin "
    "from IP 192.168.1.1",
]


# Detect brute force attempts
detect_brute_force(log_lines)