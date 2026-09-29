# Linux Brute Force Detector

A Python-based cybersecurity tool that analyzes Linux SSH authentication logs to detect **brute-force attacks** and **password-spraying activity**.

The detector parses failed SSH authentication events from `/var/log/auth.log` or `journalctl`, groups events by source IP address, and applies a sliding time-window analysis to identify suspicious authentication patterns.

## Features

* Detects SSH authentication failures
* Detects brute-force login attempts
* Detects password-spraying activity
* Groups authentication failures by source IP
* Uses configurable sliding time windows
* Supports Ubuntu/Debian-style `/var/log/auth.log`
* Supports rotated `.log` files
* Supports compressed `.gz` authentication logs
* Supports `journalctl`/systemd-based systems
* Generates a JSON security report
* Requires only the Python standard library

## Detection Logic

### Brute Force

A source IP is flagged as a brute-force source when it produces a configurable number of failed authentication attempts within a specified time window.

Default:

```text
5 failed attempts
within 5 minutes
```

Example:

```text
192.168.1.50
 ├── admin
 ├── admin
 ├── admin
 ├── admin
 └── admin
```

### Password Spray

A source IP is flagged for password spraying when it attempts authentication against a configurable number of distinct accounts within the same time window.

Default:

```text
5 distinct accounts
within 5 minutes
```

Example:

```text
192.168.1.50
 ├── alice
 ├── bob
 ├── charlie
 ├── david
 └── admin
```

## Supported Log Events

The parser recognizes common SSH authentication messages including:

```text
Failed password for USER from IP port PORT ssh2
```

```text
Failed password for invalid user USER from IP port PORT ssh2
```

```text
Invalid user USER from IP port PORT
```

```text
authentication failure; ... rhost=IP user=USER
```

and pre-authentication connection failures.

## Requirements

* Linux system
* Python 3
* OpenSSH server for generating/testing SSH authentication events
* `journalctl` for journal mode

No third-party Python packages are required.

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/brute-force-detector.git
cd brute-force-detector
```

Make the script executable:

```bash
chmod +x brute_force_detector_linux.py
```

Check Python:

```bash
python3 --version
```

## Usage

### 1. Analyze `/var/log/auth.log`

```bash
sudo python3 brute_force_detector_linux.py \
    --mode file \
    --file /var/log/auth.log
```

### 2. Analyze a rotated log

```bash
sudo python3 brute_force_detector_linux.py \
    --mode file \
    --file /var/log/auth.log.1
```

### 3. Analyze a compressed rotated log

```bash
sudo python3 brute_force_detector_linux.py \
    --mode file \
    --file /var/log/auth.log.2.gz
```

### 4. Analyze recent journal entries

Analyze the last 24 hours:

```bash
sudo python3 brute_force_detector_linux.py \
    --mode journal \
    --hours-back 24
```

Analyze the last hour:

```bash
sudo python3 brute_force_detector_linux.py \
    --mode journal \
    --hours-back 1
```

### 5. Live/auth.log mode

```bash
sudo python3 brute_force_detector_linux.py \
    --mode live
```

The live mode reads the available authentication log files, including the current and rotated logs.

## Custom Detection Thresholds

### Change the brute-force threshold

For example, detect five failed attempts:

```bash
sudo python3 brute_force_detector_linux.py \
    --mode file \
    --file /var/log/auth.log \
    --threshold 5
```

### Change the time window

Use a 10-minute window:

```bash
sudo python3 brute_force_detector_linux.py \
    --mode file \
    --file /var/log/auth.log \
    --threshold 5 \
    --window 600
```

`--window` is specified in seconds.

Common values:

| Seconds | Window     |
| ------: | ---------- |
|      60 | 1 minute   |
|     300 | 5 minutes  |
|     600 | 10 minutes |
|    1800 | 30 minutes |
|    3600 | 1 hour     |

### Change password-spray threshold

For example, detect attempts against 3 distinct accounts:

```bash
sudo python3 brute_force_detector_linux.py \
    --mode file \
    --file /var/log/auth.log \
    --spray-accounts 3
```

## Testing

The repository includes a synthetic authentication log under:

```text
tests/sample_auth.log
```

This allows the detector to be tested without relying on the machine's real authentication logs.

Run:

```bash
python3 brute_force_detector_linux.py \
    --mode file \
    --file tests/sample_auth.log \
    --threshold 5 \
    --window 300
```

Using a synthetic log is recommended for demonstrations and automated testing because real authentication logs may contain sensitive operational information.

## Generating Test SSH Events

For a local test environment, SSH authentication failures can be generated against the same machine.

Check whether SSH is running:

```bash
sudo systemctl status ssh
```

Create a dedicated test account if necessary:

```bash
sudo adduser testuser
```

Then attempt a local SSH login:

```bash
ssh testuser@localhost
```

Enter an incorrect password several times.

Check the resulting authentication events:

```bash
sudo grep "Failed password" /var/log/auth.log | tail -20
```

Then run the detector:

```bash
sudo python3 brute_force_detector_linux.py \
    --mode file \
    --file /var/log/auth.log \
    --threshold 3 \
    --window 300
```

Using a lower threshold such as `3` makes it easier to demonstrate detection with a small number of controlled test events.

## Output

The detector prints alerts to the terminal.

Example:

```text
[!] 1 alert(s) detected:

  Source IP:        127.0.0.1
  Type:             brute_force
  First seen:       2026-09-29 18:35:22
  Last seen:        2026-09-29 18:35:35
  Attempt count:    3
  Distinct accounts:1 (testuser)
------------------------------------------------------------
```

It also generates:

```text
brute_force_report.json
```

Example:

```json
[
  {
    "source_ip": "127.0.0.1",
    "alert_type": "brute_force",
    "first_seen": "2026-09-29T18:35:22",
    "last_seen": "2026-09-29T18:35:35",
    "duration_seconds": 13.0,
    "attempt_count": 3,
    "targeted_accounts": [
      "testuser"
    ],
    "distinct_account_count": 1
  }
]
```

## Command-Line Options

```text
--mode
```

Input source:

```text
live
file
journal
```

```text
--file
```

Path to a specific authentication log.

```text
--hours-back
```

Number of hours to retrieve when using journal mode.

Default:

```text
24
```

```text
--threshold
```

Number of failed attempts from one IP required for a brute-force alert.

Default:

```text
5
```

```text
--window
```

Sliding detection window in seconds.

Default:

```text
300
```

```text
--spray-accounts
```

Number of distinct accounts required for a password-spray alert.

Default:

```text
5
```

```text
--output
```

Path of the generated JSON report.

Default:

```text
brute_force_report.json
```

## Project Structure

```text
brute-force-detector/
│
├── brute_force_detector_linux.py
│
├── tests/
│   └── sample_auth.log
│
├── README.md
│
└── .gitignore
```

## Security Considerations

This tool is intended for:

* Security monitoring
* Defensive security research
* Linux/SSH log analysis
* Cybersecurity education
* Incident-response demonstrations
* Detection-engineering practice

Only analyze systems and authentication logs that you are authorized to monitor.

Avoid committing real authentication logs to source control because they may contain usernames, IP addresses, host information, and other operational data.

## Limitations

This tool is a **log-analysis detector**. It does not automatically block or ban source IP addresses.

It does not replace dedicated security monitoring or intrusion-prevention systems such as SIEM, IDS/IPS, or automated SSH protection mechanisms.

Detection accuracy also depends on the SSH log format available on the target Linux distribution.

## License

This project is intended for educational and defensive cybersecurity use.
