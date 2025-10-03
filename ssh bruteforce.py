#!/usr/bin/env python3
"""ssh_bruteforce_detector.py
Safe, defensive script: monitors /var/log/auth.log for repeated SSH failures
and prints alerts. Optionally can call a local blocking command (commented).
Requires Python 3. Tested on typical Debian/Ubuntu-based VMs.
"""

import time
import re
from collections import defaultdict
from pathlib import Path
import subprocess

LOG_FILE = "/var/log/auth.log"   # change if your distro uses a different file
WINDOW_SECONDS = 300             # window in seconds to count failures (e.g., 5 minutes)
THRESHOLD = 5                    # how many failures in WINDOW trigger alert
SLEEP = 1                        # how many seconds between checks

# Optional: command template to block IP (uncomment to enable)
# Example using ufw (Uncomplicated Firewall). Ensure ufw is installed and configured.
# BLOCK_CMD = "sudo ufw deny from {ip} to any"
BLOCK_CMD = None

# Regex to match common OpenSSH "Failed password" log lines.
failure_re = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")


def tail_f(path: Path):
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, 2)  # go to end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line


def now_ts():
    return int(time.time())


def run_block_command(ip: str):
    if not BLOCK_CMD:
        return False, "No BLOCK_CMD configured."
    cmd = BLOCK_CMD.format(ip=ip)
    try:
        subprocess.run(cmd, shell=True, check=True)
        return True, f"Blocked {ip} with command: {cmd}"
    except subprocess.CalledProcessError as e:
        return False, f"Failed to run block command: {e}"


def main():
    log_path = Path(LOG_FILE)
    if not log_path.exists():
        print(f"[!] Log file {LOG_FILE} not found. Check path and permissions.")
        return

    print("[*] Starting SSH brute-force detector (defensive). Press Ctrl+C to stop.")
    tail = tail_f(log_path)
    failures = defaultdict(list)

    try:
        while True:
            line = next(tail)
            m = failure_re.search(line)
            if m:
                user = m.group('user')
                ip = m.group('ip')
                ts = now_ts()
                failures[ip].append(ts)
                # remove old timestamps outside window
                failures[ip] = [t for t in failures[ip] if t >= ts - WINDOW_SECONDS]
                count = len(failures[ip])
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Failed login for user '{user}' from {ip} (count={count})")
                if count >= THRESHOLD:
                    print(f"[ALERT] {ip} has {count} failures in last {WINDOW_SECONDS} seconds.")
                    # If you want to block the IP, configure BLOCK_CMD above and uncomment usage.
                    success, msg = run_block_command(ip)
                    if success:
                        print(f"[ACTION] {msg}")
                    else:
                        if BLOCK_CMD:
                            print(f"[ERROR] {msg}")
                        else:
                            print("[INFO] Blocking is disabled. To enable, set BLOCK_CMD in the script.")
                    # Reset the counter for that IP after alerting (optional)
                    failures[ip] = []
            time.sleep(SLEEP)
    except KeyboardInterrupt:
        print("\n[*] Exiting.")


if __name__ == "__main__":
    main()
