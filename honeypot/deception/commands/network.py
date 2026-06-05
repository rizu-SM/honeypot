"""
Network commands: ifconfig, ip, netstat, ss, wget, curl, ping, nmap, nc
"""

import shlex
from typing import Optional, Tuple


_IFCONFIG = """\
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255
        inet6 fe80::a00:27ff:fe4e:66a1  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)
        RX packets 1234  bytes 123456 (123.4 KB)
        TX packets 567   bytes 56789  (56.7 KB)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
"""

_IP_ADDR = """\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP
    link/ether 08:00:27:4e:66:a1 brd ff:ff:ff:ff:ff:ff
    inet 10.0.2.15/24 brd 10.0.2.255 scope global dynamic eth0
"""

_NETSTAT = """\
Active Internet connections (servers and established)
Proto  Recv-Q Send-Q Local Address     Foreign Address   State
tcp         0      0 0.0.0.0:22        0.0.0.0:*         LISTEN
tcp         0      0 0.0.0.0:80        0.0.0.0:*         LISTEN
tcp         0      0 0.0.0.0:3306      0.0.0.0:*         LISTEN
tcp         0    256 10.0.2.15:22      10.0.2.2:54321    ESTABLISHED
"""


def handle_network(cmd: str, fs) -> Optional[Tuple[str, bool]]:
    try:
        parts = shlex.split(cmd)
    except ValueError:
        parts = cmd.split()

    if not parts:
        return None

    name = parts[0]

    # ── ifconfig ──────────────────────────────────────────────────────────
    if name == "ifconfig":
        return _IFCONFIG, True

    # ── ip ────────────────────────────────────────────────────────────────
    if name == "ip":
        sub = parts[1] if len(parts) > 1 else ""
        if sub in ("a", "addr", "address"):
            return _IP_ADDR, True
        if sub in ("r", "route"):
            return "default via 10.0.2.2 dev eth0\n10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15", True
        return _IP_ADDR, True

    # ── netstat / ss ──────────────────────────────────────────────────────
    if name in ("netstat", "ss"):
        return _NETSTAT, True

    # ── ping ──────────────────────────────────────────────────────────────
    if name == "ping":
        target = parts[-1] if len(parts) > 1 else "localhost"
        return (
            f"PING {target} ({target}): 56 data bytes\n"
            f"64 bytes from {target}: icmp_seq=0 ttl=64 time=0.045 ms\n"
            f"64 bytes from {target}: icmp_seq=1 ttl=64 time=0.038 ms\n"
            f"^C\n--- {target} ping statistics ---\n"
            f"2 packets transmitted, 2 received, 0% packet loss"
        ), True

    # ── wget ──────────────────────────────────────────────────────────────
    if name == "wget":
        url = next((p for p in parts[1:] if not p.startswith("-")), "")
        if not url:
            return "wget: missing URL", False
        return (
            f"--2024-06-01 00:00:01--  {url}\n"
            f"Connecting to host... connected.\n"
            f"HTTP request sent, awaiting response... 200 OK\n"
            f"Saving to: '{url.split('/')[-1] or 'index.html'}'\n"
            f"100%[===================>] 1024        --.-K/s   in 0s\n"
            f"2024-06-01 00:00:01 (1.00 MB/s) - '{url.split('/')[-1] or 'index.html'}' saved [1024/1024]"
        ), True

    # ── curl ──────────────────────────────────────────────────────────────
    if name == "curl":
        url = next((p for p in parts[1:] if not p.startswith("-")), "")
        if not url:
            return "curl: no URL specified!", False
        return f"<!DOCTYPE html><html><head><title>Index</title></head><body><h1>Index of /</h1></body></html>", True

    # ── nmap ──────────────────────────────────────────────────────────────
    if name == "nmap":
        target = parts[-1] if len(parts) > 1 else "localhost"
        return (
            f"Starting Nmap 7.80 ( https://nmap.org ) at 2024-06-01 00:00 UTC\n"
            f"Nmap scan report for {target}\n"
            f"Host is up (0.00030s latency).\n"
            f"Not shown: 997 filtered ports\n"
            f"PORT   STATE SERVICE\n"
            f"22/tcp open  ssh\n"
            f"80/tcp open  http\n"
            f"Nmap done: 1 IP address (1 host up) scanned in 5.32 seconds"
        ), True

    # ── nc / netcat / ncat ────────────────────────────────────────────────
    if name in ("nc", "netcat", "ncat"):
        return "(UNKNOWN) [127.0.0.1] 4444 (?)", False

    # ── ssh ───────────────────────────────────────────────────────────────
    if name == "ssh":
        return "ssh: connect to host: Connection refused", False

    return None
