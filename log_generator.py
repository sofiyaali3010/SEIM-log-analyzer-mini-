"""
log_generator.py
Generates realistic Apache, SSH, and Windows-style logs including
injected attack patterns for SIEM demo purposes.
"""

import random
import os
from datetime import datetime, timedelta

# --- Sample data pools ---
LEGIT_IPS = [f"192.168.1.{i}" for i in range(10, 50)] + \
            [f"10.0.0.{i}" for i in range(5, 30)]
ATTACK_IPS = ["45.33.32.156", "185.220.101.47", "103.21.244.0",
              "198.51.100.22", "203.0.113.99"]
USERS      = ["alice", "bob", "carol", "dave", "admin", "root", "www-data"]
BAD_USERS  = ["root", "admin", "administrator", "test", "guest"]
PAGES      = ["/index.html", "/about", "/dashboard", "/api/data",
              "/login", "/static/app.js", "/favicon.ico"]
SQL_PAYLOADS = [
    "/search?q=' OR 1=1--",
    "/login?user=admin'--&pass=x",
    "/api/user?id=1 UNION SELECT * FROM users",
]
XSS_PAYLOADS = [
    "/search?q=<script>alert(1)</script>",
    "/comment?text=<img src=x onerror=alert(1)>",
]
METHODS    = ["GET", "POST", "PUT", "DELETE"]
HTTP_CODES = [200, 200, 200, 200, 301, 304, 403, 404, 500]

def apache_line(ts: datetime, ip: str, method: str,
                path: str, code: int) -> str:
    size = random.randint(500, 15000)
    return (f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
            f'"{method} {path} HTTP/1.1" {code} {size}')

def ssh_line(ts: datetime, ip: str, user: str, success: bool) -> str:
    ts_str = ts.strftime("%b %d %H:%M:%S")
    host   = "webserver01"
    if success:
        return f"{ts_str} {host} sshd[{random.randint(1000,9999)}]: Accepted password for {user} from {ip} port {random.randint(1024,65535)} ssh2"
    else:
        return f"{ts_str} {host} sshd[{random.randint(1000,9999)}]: Failed password for {user} from {ip} port {random.randint(1024,65535)} ssh2"

def generate_logs(path: str, days: int = 1) -> None:
    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
    now   = datetime.utcnow()
    start = now - timedelta(days=days)
    lines = []

    # --- Normal traffic ---
    ts = start
    while ts < now:
        ip     = random.choice(LEGIT_IPS)
        method = random.choice(METHODS[:2])
        page   = random.choice(PAGES)
        code   = random.choice(HTTP_CODES)
        lines.append(("apache", ts, apache_line(ts, ip, method, page, code)))
        ts += timedelta(seconds=random.randint(5, 120))

    # --- Normal SSH logins ---
    for _ in range(60):
        ts   = start + timedelta(seconds=random.randint(0, days * 86400))
        ip   = random.choice(LEGIT_IPS)
        user = random.choice(USERS[:5])
        lines.append(("ssh", ts, ssh_line(ts, ip, user, True)))

    # ---- INJECTED ATTACKS ----

    # 1. SSH Brute Force burst
    brute_ip  = random.choice(ATTACK_IPS)
    brute_start = start + timedelta(hours=random.randint(2, 20))
    for i in range(80):
        ts   = brute_start + timedelta(seconds=i * 2)
        user = random.choice(BAD_USERS)
        lines.append(("ssh", ts, ssh_line(ts, brute_ip, user, False)))
    # one success at the end
    lines.append(("ssh", ts + timedelta(seconds=5),
                  ssh_line(ts + timedelta(seconds=5), brute_ip, "root", True)))

    # 2. SQL Injection attempts
    sqli_ip = random.choice(ATTACK_IPS)
    sqli_start = start + timedelta(hours=random.randint(1, 18))
    for j in range(15):
        ts = sqli_start + timedelta(seconds=j * 10)
        payload = random.choice(SQL_PAYLOADS)
        lines.append(("apache", ts,
                      apache_line(ts, sqli_ip, "GET", payload, 403)))

    # 3. XSS attempts
    xss_ip = random.choice(ATTACK_IPS)
    xss_start = start + timedelta(hours=random.randint(1, 22))
    for k in range(10):
        ts = xss_start + timedelta(seconds=k * 15)
        payload = random.choice(XSS_PAYLOADS)
        lines.append(("apache", ts,
                      apache_line(ts, xss_ip, "GET", payload, 403)))

    # 4. Port scan simulation (many 404s from one IP)
    scan_ip = random.choice(ATTACK_IPS)
    scan_start = start + timedelta(hours=random.randint(3, 21))
    for m in range(40):
        ts = scan_start + timedelta(seconds=m * 1)
        lines.append(("apache", ts,
                      apache_line(ts, scan_ip, "GET",
                                  f"/probe/{random.randint(1000,9999)}", 404)))

    # Sort by timestamp and write
    lines.sort(key=lambda x: x[1])
    with open(path, "w") as f:
        for _, _, line in lines:
            f.write(line + "\n")

    print(f"[+] Generated {len(lines)} log lines → {path}")

if __name__ == "__main__":
    generate_logs("logs/sample.log", days=1)
