"""
SMB Sentinel - Core Scanning Engine
MR CYBER

Passive, read-only checks only:
- TCP port 445/139 reachability
- SMBv1 dialect negotiation probe (detects if legacy SMBv1 is enabled)
- SMB2 negotiation probe (detects version + signing configuration)

No exploitation, no authentication bypass, no credential brute-forcing.
This module only sends standard protocol negotiation packets that any
SMB client sends as the first step of a normal connection.
"""

import socket
import struct
import ipaddress
import threading
import queue
import ifaddr  # lightweight, pure-python, cross-platform interface lister


# ---------------------------------------------------------------------------
# Network discovery
# ---------------------------------------------------------------------------

def get_local_networks():
    """Return a list of local IPv4 networks (as strings, CIDR) this machine is on."""
    nets = []
    try:
        for adapter in ifaddr.get_adapters():
            for ip in adapter.ips:
                if ip.is_IPv4 and ip.ip != "127.0.0.1":
                    prefix = ip.network_prefix or 24
                    try:
                        net = ipaddress.ip_network(f"{ip.ip}/{prefix}", strict=False)
                        nets.append(str(net))
                    except ValueError:
                        continue
    except Exception:
        pass
    # de-dupe, keep order
    seen = set()
    out = []
    for n in nets:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


# ---------------------------------------------------------------------------
# Low level SMB probes
# ---------------------------------------------------------------------------

def _nbss_wrap(payload: bytes) -> bytes:
    """Wrap an SMB payload in a NetBIOS Session Service header."""
    length = len(payload)
    return struct.pack(">BBH", 0x00, 0x00, length) + payload if length < 0x10000 \
        else struct.pack(">I", length)[0:1] + struct.pack(">BH", 0, length) + payload


def _build_smb1_negotiate() -> bytes:
    """Build a classic SMB1 (CIFS) Negotiate Protocol Request offering
    only legacy dialects. If a server replies with a valid SMB1 header
    and selects one of these, SMBv1 is enabled on that host."""
    dialects = [
        "PC NETWORK PROGRAM 1.0",
        "LANMAN1.0",
        "Windows for Workgroups 3.1a",
        "LM1.2X002",
        "LANMAN2.1",
        "NT LM 0.12",
    ]
    header = b"\xffSMB" + bytes([0x72]) + b"\x00" * 4 + bytes([0x18]) + b"\x00\x00" \
        + b"\x00" * 2 + b"\x00" * 8 + b"\x00" * 2 + b"\x00" * 2 \
        + b"\x34\x12" + b"\x00" * 2 + b"\x00" * 2

    body = b""
    for d in dialects:
        body += b"\x02" + d.encode("ascii") + b"\x00"

    params = struct.pack("<B", 0) + struct.pack("<H", len(body)) + body
    smb = header + params
    return _nbss_wrap(smb)


def _build_smb2_negotiate() -> bytes:
    """Build a modern SMB2/3 Negotiate Request offering dialects
    2.0.2 through 3.1.1, used to detect version + signing posture."""
    header = (
        b"\xfeSMB" +           # ProtocolId
        struct.pack("<H", 64) +  # StructureSize
        b"\x00\x00" +          # CreditCharge
        b"\x00\x00\x00\x00" +  # Status
        struct.pack("<H", 0) + # Command = Negotiate
        struct.pack("<H", 1) + # CreditRequest
        b"\x00\x00\x00\x00" +  # Flags
        b"\x00\x00\x00\x00" +  # NextCommand
        b"\x00" * 8 +          # MessageId
        b"\x00" * 4 +          # Reserved
        b"\x00" * 4 +          # TreeId
        b"\x00" * 8 +          # SessionId
        b"\x00" * 16           # Signature
    )
    dialects = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]
    body = struct.pack("<H", 36)          # StructureSize
    body += struct.pack("<H", len(dialects))  # DialectCount
    body += struct.pack("<H", 1)          # SecurityMode = SIGNING_ENABLED
    body += struct.pack("<H", 0)          # Reserved
    body += struct.pack("<I", 0)          # Capabilities
    body += b"\x00" * 16                  # ClientGuid
    body += struct.pack("<Q", 0)          # NegotiateContextOffset/Reserved2
    for d in dialects:
        body += struct.pack("<H", d)

    smb = header + body
    return _nbss_wrap(smb)


def _recv_all(sock, timeout=2.5):
    sock.settimeout(timeout)
    try:
        head = sock.recv(4)
        if len(head) < 4:
            return b""
        length = struct.unpack(">I", b"\x00" + head[1:4])[0]
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        return data
    except (socket.timeout, ConnectionResetError, OSError):
        return b""


def probe_smb(ip: str, port: int = 445, timeout: float = 2.0) -> dict:
    """Connect to a host and run SMB1 + SMB2 negotiate probes.
    Returns a dict describing what was observed. Read-only, no auth."""
    result = {
        "port_open": False,
        "smb1_enabled": False,
        "smb2_supported": False,
        "smb2_dialect": None,
        "signing_enabled": None,
        "signing_required": None,
        "error": None,
    }

    # 1. Port reachability
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        result["port_open"] = True
        s.close()
    except Exception as e:
        result["error"] = "unreachable"
        return result

    # 2. SMB1 probe
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.sendall(_build_smb1_negotiate())
        resp = _recv_all(s, timeout)
        s.close()
        if resp[:4] == b"\xffSMB" and resp[4] == 0x72:
            # word count field tells us if a dialect index was selected validly
            wc_offset = 4 + 1 + 4 + 1 + 2 + 2 + 8 + 2 + 2 + 2 + 2 + 2
            if len(resp) > wc_offset:
                word_count = resp[wc_offset]
                if word_count != 0:
                    result["smb1_enabled"] = True
    except Exception:
        pass

    # 3. SMB2 probe
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.sendall(_build_smb2_negotiate())
        resp = _recv_all(s, timeout)
        s.close()
        if resp[:4] == b"\xfeSMB":
            result["smb2_supported"] = True
            # SMB2 header is 64 bytes, body starts after
            body = resp[64:]
            if len(body) >= 4:
                security_mode = struct.unpack("<H", body[2:4])[0]
                result["signing_enabled"] = bool(security_mode & 0x01)
                result["signing_required"] = bool(security_mode & 0x02)
            if len(body) >= 6:
                dialect = struct.unpack("<H", body[4:6])[0]
                dialect_map = {
                    0x0202: "SMB 2.0.2", 0x0210: "SMB 2.1",
                    0x0300: "SMB 3.0", 0x0302: "SMB 3.0.2", 0x0311: "SMB 3.1.1",
                }
                result["smb2_dialect"] = dialect_map.get(dialect, hex(dialect))
    except Exception:
        pass

    return result


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

def assess_risk(probe: dict) -> dict:
    """Turn a raw probe result into human-readable findings + risk level."""
    findings = []
    level = "safe"

    if probe.get("error") == "unreachable":
        return {"risk_level": "unknown", "findings": ["Host did not respond on SMB port."]}

    if not probe.get("port_open"):
        return {"risk_level": "unknown", "findings": ["SMB port closed or filtered."]}

    if probe.get("smb1_enabled"):
        findings.append("SMBv1 is enabled (legacy, outdated protocol).")
        level = "high"

    if probe.get("signing_required") is False and probe.get("signing_enabled") is False:
        findings.append("SMB signing is not enabled (relay/spoofing risk).")
        if level != "high":
            level = "medium"
    elif probe.get("signing_enabled") and not probe.get("signing_required"):
        findings.append("SMB signing is enabled but not required.")
        if level == "safe":
            level = "low"

    if not findings:
        findings.append("No obvious misconfigurations found in this basic check.")
        level = "safe"

    return {"risk_level": level, "findings": findings}


# ---------------------------------------------------------------------------
# Ranged scan (threaded)
# ---------------------------------------------------------------------------

def scan_range(ip_list, progress_callback=None, max_threads=30):
    """Scan a list of IPs concurrently. progress_callback(done, total, current_ip)."""
    results = {}
    q = queue.Queue()
    for ip in ip_list:
        q.put(ip)

    total = len(ip_list)
    done_counter = {"n": 0}
    lock = threading.Lock()

    def worker():
        while True:
            try:
                ip = q.get_nowait()
            except queue.Empty:
                return
            probe = probe_smb(ip)
            risk = assess_risk(probe)
            with lock:
                results[ip] = {**probe, **risk}
                done_counter["n"] += 1
                if progress_callback:
                    progress_callback(done_counter["n"], total, ip)
            q.task_done()

    threads = []
    for _ in range(min(max_threads, max(1, total))):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    return results


def ips_in_cidr(cidr: str, limit: int = None):
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = list(net.hosts())
    if limit:
        hosts = hosts[:limit]
    return [str(h) for h in hosts]
