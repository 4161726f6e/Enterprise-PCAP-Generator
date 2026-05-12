#!/usr/bin/env python3
"""
Enterprise Multi-PCAP Simulator (Clean, Single-file)

Generates one PCAP per subnet/interface plus an edge (outside) capture:
  output_dir/
    pcaps/dmz.pcap
    pcaps/servers.pcap
    pcaps/workstations.pcap
    pcaps/vpn.pcap
    pcaps/iot_byod.pcap
    pcaps/edge.pcap
    metadata/topology.json
    (optional) config.json + config.summary.txt

Traffic characteristics (minimal but non-empty):
- Internal routed traffic (gateway/SVI view):
    - workstations -> servers SMB-like
    - vpn -> dmz admin-like
- Internet TLS-like traffic:
    - inside: private IP -> internet (pre-NAT attribution by default)
    - edge: public IP -> internet (post-NAT)
    - edge inbound replies + inside de-NAT delivery
- IoT UDP DNS-like outbound traffic (inside view)

Dependencies:
  pip install scapy
"""

import argparse
import json
import os
import random
import struct
import time
from dataclasses import dataclass, asdict
from ipaddress import ip_network
from typing import Dict, List, Optional

from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap


# ============================================================
# Presets + CIDR planning (auto config)
# ============================================================

PRESETS = {
    "small": {
        "counts": {"dmz": 6, "servers": 25, "workstations": 80, "vpn": 10, "iot_byod": 30},
        "duration": 1800,
    },
    "medium": {
        "counts": {"dmz": 10, "servers": 60, "workstations": 250, "vpn": 25, "iot_byod": 120},
        "duration": 3600,
    },
    "enterprise": {
        "counts": {"dmz": 20, "servers": 150, "workstations": 1200, "vpn": 120, "iot_byod": 500},
        "duration": 7200,
    },
}

TIER_RANGES = {
    "dmz": "10.10.0.0/16",
    "servers": "10.20.0.0/16",
    "workstations": "10.30.0.0/16",
    "vpn": "10.40.0.0/16",
    "iot_byod": "10.50.0.0/16",
    "edge": "203.0.113.0/24",  # TEST-NET-3
}


def safe_mkdir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def rand_mac(rng: random.Random) -> str:
    # locally administered unicast MAC
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(rng.randint(0, 255) for _ in range(5))


def first_usable_ip(cidr: str) -> str:
    return str(next(ip_network(cidr).hosts()))


def prefix_for_hosts(host_count: int) -> int:
    """
    Choose smallest prefix that can support host_count plus:
      - network + broadcast (implicit)
      - 1 gateway reservation
    """
    needed = host_count + 3
    for p in range(32, 7, -1):
        if (2 ** (32 - p)) >= needed:
            return p
    raise ValueError(f"Too many hosts requested: {host_count}")


def allocate_subnet(parent: str, prefix: int, used: List) -> str:
    parent_net = ip_network(parent)
    for sub in parent_net.subnets(new_prefix=prefix):
        if all(not sub.overlaps(u) for u in used):
            used.append(sub)
            return str(sub)
    raise ValueError(f"No space left in {parent} for /{prefix}")


def build_auto_config(args) -> Dict:
    preset = PRESETS[args.preset]
    rng = random.Random(args.seed)

    counts = dict(preset["counts"])
    for tier in ("dmz", "servers", "workstations", "vpn", "iot_byod"):
        v = getattr(args, tier, None)
        if v is not None:
            counts[tier] = v

    used: List = []
    subnets: Dict = {}
    gateways: Dict = {}

    for tier in ("dmz", "servers", "workstations", "vpn", "iot_byod"):
        pref = prefix_for_hosts(counts[tier])
        cidr = allocate_subnet(TIER_RANGES[tier], pref, used)
        subnets[tier] = {"cidr": cidr, "name": tier}
        gateways[tier] = {"name": f"gw-{tier}", "ip": first_usable_ip(cidr), "mac": rand_mac(rng)}

    # edge fixed
    subnets["edge"] = {"cidr": TIER_RANGES["edge"], "name": "edge"}
    gateways["edge"] = {"name": "gw-edge", "ip": first_usable_ip(TIER_RANGES["edge"]), "mac": rand_mac(rng)}

    cfg = {
        "seed": args.seed,
        "topology": {
            "subnets": subnets,
            "gateways": gateways,
            "hosts": {"counts": {**counts, "edge": 0}},
        },
        "routing": {
            "nat": {
                "enabled": True,
                "internet_egress_nat": True,
                "egress_public_ip": gateways["edge"]["ip"],
                "internet_egress_nat_visibility": "pre",  # keep inside attribution by default
                "vpn_pool_nat": True,
            }
        },
        "behavior": {
            "rates": {
                "workstations_sessions_per_hour": 18,
                "servers_sessions_per_hour": 10,
                "vpn_sessions_per_hour": 6,
                "iot_sessions_per_hour": 20,
                "dmz_inbound_sessions_per_hour": 30,
            }
        },
        "time": {
            "duration_seconds": args.duration if args.duration is not None else preset["duration"],
            "base_epoch": int(time.time()),
            "seed": args.seed,
        },
        "traffic": {
            "internet": {
                "ip_pool": ["13.107.42.12", "52.96.120.34", "151.101.1.69"],
                "domain_pool": ["www.microsoft.com", "www.google.com", "cdn.office.net"],
                "cdn_pool": ["azureedge.net", "cdn.netflix.com", "video-edge.amazon.com"],
            }
        },
        "output": {
            "directory": args.output_dir,
            "pcaps": {k: {"filename": f"pcaps/{k}.pcap"} for k in subnets},
        },
    }
    return cfg


def write_config_summary(cfg: Dict, path: str) -> None:
    topo = cfg["topology"]
    lines = ["=== CONFIG SUMMARY ===", ""]
    for name, s in topo["subnets"].items():
        net = ip_network(s["cidr"])
        usable_minus_gw = max(0, (net.num_addresses - 2) - 1)
        hosts = topo["hosts"]["counts"].get(name, 0)
        util = (hosts / usable_minus_gw * 100.0) if usable_minus_gw else 0.0
        gw = topo["gateways"][name]["ip"]
        lines.append(f"{name:12s} {s['cidr']:18s} capacity={usable_minus_gw:6d} hosts={hosts:6d} util={util:6.2f}% gw={gw}")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


# ============================================================
# Model objects
# ============================================================

@dataclass
class Host:
    host_id: str
    subnet: str
    ip: str
    mac: str


@dataclass
class Gateway:
    name: str
    ip: str
    mac: str


@dataclass
class SubnetState:
    name: str
    cidr: str
    gateway: Gateway
    hosts: List[Host]
    packets: List


INTERNET_MAC = "aa:bb:cc:dd:ee:ff"


def nat_settings(cfg: Dict) -> Dict:
    return cfg.get("routing", {}).get("nat", {})


def edge_enabled(cfg: Dict, topo: Dict[str, SubnetState]) -> bool:
    return "edge" in topo and "pcaps" in cfg.get("output", {}) and "edge" in cfg["output"]["pcaps"]


def edge_public_ip(cfg: Dict, topo: Dict[str, SubnetState]) -> str:
    nat = nat_settings(cfg)
    if nat.get("egress_public_ip"):
        return nat["egress_public_ip"]
    return topo["edge"].gateway.ip


# ============================================================
# Topology builder (deterministic, safe)
# ============================================================

def build_topology(cfg: Dict, rng: random.Random) -> Dict[str, SubnetState]:
    subnets_cfg = cfg["topology"]["subnets"]
    gws_cfg = cfg["topology"]["gateways"]
    counts = cfg["topology"]["hosts"]["counts"]

    topo: Dict[str, SubnetState] = {}
    for sname, sdef in subnets_cfg.items():
        gw = gws_cfg[sname]
        topo[sname] = SubnetState(
            name=sname,
            cidr=sdef["cidr"],
            gateway=Gateway(name=gw["name"], ip=gw["ip"], mac=gw["mac"]),
            hosts=[],
            packets=[],
        )

    for sname, n in counts.items():
        if sname not in topo or n <= 0:
            continue

        net = ip_network(topo[sname].cidr)
        gw_ip = topo[sname].gateway.ip
        it = net.hosts()

        reserved = {gw_ip}
        i = 0
        while i < n:
            ip = str(next(it))
            if ip in reserved:
                continue
            topo[sname].hosts.append(
                Host(host_id=f"{sname}-{i+1:04d}", subnet=sname, ip=ip, mac=rand_mac(rng))
            )
            i += 1

    return topo


# ============================================================
# Packet emission: internal routed + internet + edge return
# ============================================================

def emit_routed(topo: Dict[str, SubnetState], src: Host, dst: Host, l4, ts: float, ttl: int = 64) -> None:
    """Gateway/SVI view: emit into BOTH source and destination subnet PCAPs."""
    src_sub = topo[src.subnet]
    dst_sub = topo[dst.subnet]

    p_src = Ether(src=src.mac, dst=src_sub.gateway.mac) / IP(src=src.ip, dst=dst.ip, ttl=ttl) / l4
    p_src.time = ts
    src_sub.packets.append(p_src)

    p_dst = Ether(src=dst_sub.gateway.mac, dst=dst.mac) / IP(src=src.ip, dst=dst.ip, ttl=ttl - 1) / l4.copy()
    p_dst.time = ts + 0.0005
    dst_sub.packets.append(p_dst)


def emit_inside_outbound_to_internet(cfg: Dict, topo: Dict[str, SubnetState], src: Host, dst_ip: str, l4, ts: float, ttl: int = 64) -> None:
    """Inside view: host->gateway. Pre-NAT attribution by default."""
    nat = nat_settings(cfg)
    src_sub = topo[src.subnet]
    src_ip = src.ip
    if nat.get("enabled") and nat.get("internet_egress_nat") and nat.get("internet_egress_nat_visibility") == "post":
        src_ip = nat.get("egress_public_ip", src.ip)

    p = Ether(src=src.mac, dst=src_sub.gateway.mac) / IP(src=src_ip, dst=dst_ip, ttl=ttl) / l4
    p.time = ts
    src_sub.packets.append(p)


def emit_edge_outbound(cfg: Dict, topo: Dict[str, SubnetState], public_ip: str, dst_ip: str, l4, ts: float, ttl: int = 64) -> None:
    if not edge_enabled(cfg, topo):
        return
    edge = topo["edge"]
    p = Ether(src=edge.gateway.mac, dst=INTERNET_MAC) / IP(src=public_ip, dst=dst_ip, ttl=ttl) / l4.copy()
    p.time = ts + 0.0002
    edge.packets.append(p)


def emit_edge_inbound(cfg: Dict, topo: Dict[str, SubnetState], public_ip: str, src_ip: str, l4, ts: float, ttl: int = 52) -> None:
    if not edge_enabled(cfg, topo):
        return
    edge = topo["edge"]
    p = Ether(src=INTERNET_MAC, dst=edge.gateway.mac) / IP(src=src_ip, dst=public_ip, ttl=ttl) / l4.copy()
    p.time = ts + 0.0003
    edge.packets.append(p)


def emit_inside_inbound_from_internet(topo: Dict[str, SubnetState], dst_host: Host, src_ip: str, l4, ts: float, ttl: int = 63) -> None:
    """De-NAT delivery: gateway->host on inside subnet."""
    sub = topo[dst_host.subnet]
    p = Ether(src=sub.gateway.mac, dst=dst_host.mac) / IP(src=src_ip, dst=dst_host.ip, ttl=ttl) / l4.copy()
    p.time = ts + 0.0006
    sub.packets.append(p)


# ============================================================
# TLS-like payload generation (no Scapy TLS dependency)
# ============================================================

def _u16(x: int) -> bytes:
    return struct.pack("!H", x)

def _u24(x: int) -> bytes:
    return x.to_bytes(3, "big")

def tls_record(content_type: int, version_bytes: bytes, payload: bytes) -> bytes:
    return bytes([content_type]) + version_bytes + _u16(len(payload)) + payload

def build_tls_client_hello_with_sni(sni: str, rng: random.Random) -> bytes:
    host = sni.encode("utf-8")
    legacy_version = b"\x03\x03"  # TLS 1.2
    random_bytes = bytes(rng.getrandbits(8) for _ in range(32))

    session_id = bytes(rng.getrandbits(8) for _ in range(rng.randint(8, 24)))
    session_id_len = bytes([len(session_id)])

    cipher_suites = b"\x13\x01\x13\x02\xc0\x2f"
    cipher_suites_len = _u16(len(cipher_suites))
    compression = b"\x01\x00"

    # SNI extension
    server_name_list = _u16(1 + 2 + len(host)) + b"\x00" + _u16(len(host)) + host
    sni_ext = _u16(0x0000) + _u16(len(server_name_list)) + server_name_list

    # padding extension
    pad_len = rng.randint(12, 64)
    padding_ext = _u16(0x0015) + _u16(pad_len) + (b"\x00" * pad_len)

    extensions = sni_ext + padding_ext
    extensions_len = _u16(len(extensions))

    ch_body = (
        legacy_version +
        random_bytes +
        session_id_len + session_id +
        cipher_suites_len + cipher_suites +
        compression +
        extensions_len + extensions
    )

    handshake = b"\x01" + _u24(len(ch_body)) + ch_body
    return tls_record(0x16, b"\x03\x01", handshake)

def build_tls_appdata(rng: random.Random, size: int) -> bytes:
    payload = bytes(rng.getrandbits(8) for _ in range(size))
    return tls_record(0x17, b"\x03\x03", payload)


# ============================================================
# Internet session modeling (PAT + edge inbound return + inside de-NAT)
# ============================================================

class PatAllocator:
    def __init__(self):
        self.used = set()

    def alloc(self, rng: random.Random, preferred: Optional[int] = None) -> int:
        if preferred and preferred not in self.used and 1024 <= preferred <= 65535:
            self.used.add(preferred)
            return preferred
        for _ in range(2000):
            p = rng.randint(30000, 60000)
            if p not in self.used:
                self.used.add(p)
                return p
        p = rng.randint(1024, 65535)
        self.used.add(p)
        return p


@dataclass
class InternetSession:
    client: Host
    dst_ip: str
    sni: str
    inside_port: int
    public_ip: str
    public_port: int
    c_seq: int
    s_seq: int


def open_tls_session(cfg: Dict, topo: Dict[str, SubnetState], rng: random.Random, pat: PatAllocator,
                     client: Host, dst_ip: str, sni: str, ts: float) -> InternetSession:
    public_ip = edge_public_ip(cfg, topo)
    inside_port = rng.randint(1024, 65535)
    public_port = pat.alloc(rng, preferred=inside_port)

    c_isn = rng.randint(1_000_000, 3_000_000_000)
    s_isn = rng.randint(1_000_000, 3_000_000_000)

    # SYN outbound (inside + edge post-NAT)
    emit_inside_outbound_to_internet(cfg, topo, client, dst_ip, TCP(sport=inside_port, dport=443, flags="S", seq=c_isn, ack=0), ts)
    emit_edge_outbound(cfg, topo, public_ip, dst_ip, TCP(sport=public_port, dport=443, flags="S", seq=c_isn, ack=0), ts)

    # SYN/ACK inbound (edge + inside de-NAT delivery)
    emit_edge_inbound(cfg, topo, public_ip, dst_ip, TCP(sport=443, dport=public_port, flags="SA", seq=s_isn, ack=c_isn + 1), ts + 0.04)
    emit_inside_inbound_from_internet(topo, client, dst_ip, TCP(sport=443, dport=inside_port, flags="SA", seq=s_isn, ack=c_isn + 1), ts + 0.04)

    # ACK outbound (inside + edge)
    emit_inside_outbound_to_internet(cfg, topo, client, dst_ip, TCP(sport=inside_port, dport=443, flags="A", seq=c_isn + 1, ack=s_isn + 1), ts + 0.08)
    emit_edge_outbound(cfg, topo, public_ip, dst_ip, TCP(sport=public_port, dport=443, flags="A", seq=c_isn + 1, ack=s_isn + 1), ts + 0.08)

    # ClientHello (inside + edge)
    ch = build_tls_client_hello_with_sni(sni, rng)
    emit_inside_outbound_to_internet(cfg, topo, client, dst_ip, TCP(sport=inside_port, dport=443, flags="PA", seq=c_isn + 1, ack=s_isn + 1)/Raw(load=ch), ts + 0.12)
    emit_edge_outbound(cfg, topo, public_ip, dst_ip, TCP(sport=public_port, dport=443, flags="PA", seq=c_isn + 1, ack=s_isn + 1)/Raw(load=ch), ts + 0.12)

    return InternetSession(
        client=client,
        dst_ip=dst_ip,
        sni=sni,
        inside_port=inside_port,
        public_ip=public_ip,
        public_port=public_port,
        c_seq=c_isn + 1 + len(ch),
        s_seq=s_isn + 1
    )


def tls_client_send(cfg: Dict, topo: Dict[str, SubnetState], rng: random.Random, sess: InternetSession, ts: float, size: int) -> None:
    ad = build_tls_appdata(rng, size)

    # outbound (inside + edge)
    emit_inside_outbound_to_internet(cfg, topo, sess.client, sess.dst_ip,
                                    TCP(sport=sess.inside_port, dport=443, flags="PA", seq=sess.c_seq, ack=sess.s_seq)/Raw(load=ad),
                                    ts)
    emit_edge_outbound(cfg, topo, sess.public_ip, sess.dst_ip,
                       TCP(sport=sess.public_port, dport=443, flags="PA", seq=sess.c_seq, ack=sess.s_seq)/Raw(load=ad),
                       ts)

    sess.c_seq += len(ad)

    # server ACK return (edge + inside)
    emit_edge_inbound(cfg, topo, sess.public_ip, sess.dst_ip,
                      TCP(sport=443, dport=sess.public_port, flags="A", seq=sess.s_seq, ack=sess.c_seq),
                      ts + 0.03)
    emit_inside_inbound_from_internet(topo, sess.client, sess.dst_ip,
                      TCP(sport=443, dport=sess.inside_port, flags="A", seq=sess.s_seq, ack=sess.c_seq),
                      ts + 0.03)


def tls_server_send(cfg: Dict, topo: Dict[str, SubnetState], rng: random.Random, sess: InternetSession, ts: float, size: int) -> None:
    ad = build_tls_appdata(rng, size)

    # inbound appdata (edge + inside)
    emit_edge_inbound(cfg, topo, sess.public_ip, sess.dst_ip,
                      TCP(sport=443, dport=sess.public_port, flags="PA", seq=sess.s_seq, ack=sess.c_seq)/Raw(load=ad),
                      ts)
    emit_inside_inbound_from_internet(topo, sess.client, sess.dst_ip,
                      TCP(sport=443, dport=sess.inside_port, flags="PA", seq=sess.s_seq, ack=sess.c_seq)/Raw(load=ad),
                      ts)

    sess.s_seq += len(ad)

    # client ACK outbound (inside + edge)
    emit_inside_outbound_to_internet(cfg, topo, sess.client, sess.dst_ip,
                                    TCP(sport=sess.inside_port, dport=443, flags="A", seq=sess.c_seq, ack=sess.s_seq),
                                    ts + 0.02)
    emit_edge_outbound(cfg, topo, sess.public_ip, sess.dst_ip,
                       TCP(sport=sess.public_port, dport=443, flags="A", seq=sess.c_seq, ack=sess.s_seq),
                       ts + 0.02)


# ============================================================
# Packet generation (non-empty)
# ============================================================

def generate_packets(cfg: Dict, topo: Dict[str, SubnetState], rng: random.Random, base_ts: float) -> None:
    duration = int(cfg["time"]["duration_seconds"])
    end_ts = base_ts + duration

    internet = cfg.get("traffic", {}).get("internet", {})
    ip_pool = internet.get("ip_pool", ["13.107.42.12"])
    domain_pool = internet.get("domain_pool", ["www.microsoft.com"])

    ws = topo["workstations"].hosts if "workstations" in topo else []
    srv = topo["servers"].hosts if "servers" in topo else []
    vpn = topo["vpn"].hosts if "vpn" in topo else []
    dmz = topo["dmz"].hosts if "dmz" in topo else []
    iot = topo["iot_byod"].hosts if "iot_byod" in topo else []

    # 1) Internal routed SMB-like exchange
    if ws and srv:
        c = rng.choice(ws)
        s = rng.choice(srv)
        t0 = base_ts + 2.0
        emit_routed(topo, c, s, TCP(sport=12345, dport=445, flags="S", seq=1000, ack=0), t0)
        emit_routed(topo, s, c, TCP(sport=445, dport=12345, flags="SA", seq=2000, ack=1001), t0 + 0.02)
        emit_routed(topo, c, s, TCP(sport=12345, dport=445, flags="A", seq=1001, ack=2001), t0 + 0.04)
        emit_routed(topo, c, s, TCP(sport=12345, dport=445, flags="PA", seq=1001, ack=2001)/Raw(load=b"\xfeSMB" + b"\x00"*60), t0 + 0.08)

    # 2) VPN -> DMZ admin-like flow
    if vpn and dmz:
        c = rng.choice(vpn)
        s = rng.choice(dmz)
        t0 = base_ts + 10.0
        emit_routed(topo, c, s, TCP(sport=23456, dport=3389, flags="S", seq=3000, ack=0), t0)
        emit_routed(topo, s, c, TCP(sport=3389, dport=23456, flags="SA", seq=4000, ack=3001), t0 + 0.03)
        emit_routed(topo, c, s, TCP(sport=23456, dport=3389, flags="A", seq=3001, ack=4001), t0 + 0.05)
        emit_routed(topo, c, s, TCP(sport=23456, dport=3389, flags="PA", seq=3001, ack=4001)/Raw(load=b"RDP-LIKE" + bytes(rng.getrandbits(8) for _ in range(120))), t0 + 0.12)

    # 3) Internet TLS-like sessions with edge return modeling
    pat = PatAllocator()

    t = base_ts
    while t < end_ts:
        # A few workstation internet sessions each minute (kept modest)
        if ws:
            for _ in range(rng.randint(0, 3)):
                client = rng.choice(ws)
                dst_ip = rng.choice(ip_pool)
                sni = rng.choice(domain_pool)
                ts = t + rng.uniform(0, 55)

                sess = open_tls_session(cfg, topo, rng, pat, client, dst_ip, sni, ts)
                tls_client_send(cfg, topo, rng, sess, ts + 0.30, size=rng.randint(300, 1500))
                if rng.random() < 0.5:
                    tls_server_send(cfg, topo, rng, sess, ts + 0.60, size=rng.randint(400, 2200))
                tls_client_send(cfg, topo, rng, sess, ts + 1.10, size=rng.randint(300, 1500))

        # IoT DNS-like UDP
        if iot:
            for _ in range(rng.randint(0, 3)):
                dev = rng.choice(iot)
                ts = t + rng.uniform(0, 55)
                payload = bytes(rng.getrandbits(8) for _ in range(rng.randint(30, 90)))
                emit_inside_outbound_to_internet(cfg, topo, dev, "8.8.8.8", UDP(sport=rng.randint(49152, 65535), dport=53)/Raw(load=payload), ts)

        t += 60.0


# ============================================================
# Output writers
# ============================================================

def write_pcaps(cfg: Dict, topo: Dict[str, SubnetState], out_dir: str) -> None:
    pcaps_dir = os.path.join(out_dir, "pcaps")
    safe_mkdir(pcaps_dir)

    for sname, subnet in topo.items():
        rel = cfg["output"]["pcaps"].get(sname, {}).get("filename", f"pcaps/{sname}.pcap")
        out_path = os.path.join(out_dir, rel)
        safe_mkdir(os.path.dirname(out_path))

        pkts = sorted(subnet.packets, key=lambda p: float(getattr(p, "time", 0.0)))
        wrpcap(out_path, pkts)
        print(f"[+] wrote {out_path}  packets={len(pkts)}")


def write_metadata(cfg: Dict, topo: Dict[str, SubnetState], out_dir: str) -> None:
    meta_dir = os.path.join(out_dir, "metadata")
    safe_mkdir(meta_dir)

    data = {
        "seed": cfg.get("seed"),
        "time": cfg.get("time", {}),
        "routing": cfg.get("routing", {}),
        "subnets": {k: v.cidr for k, v in topo.items()},
        "gateways": {k: asdict(v.gateway) for k, v in topo.items()},
        "host_counts": {k: len(v.hosts) for k, v in topo.items()},
    }
    with open(os.path.join(meta_dir, "topology.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# ============================================================
# Main
# ============================================================

def main() -> None:
    ap = argparse.ArgumentParser(description="Enterprise Multi-PCAP Simulator (clean)")

    ap.add_argument("--config", required=False, help="Use an existing config.json")
    ap.add_argument("--preset", choices=["small", "medium", "enterprise"], default="medium",
                    help="Auto-generate config from preset (default: medium)")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--duration", type=int, default=None)
    ap.add_argument("--output-dir", dest="output_dir", default="output")
    ap.add_argument("--export-config", action="store_true")

    # optional host overrides when using preset
    ap.add_argument("--dmz", type=int, default=None)
    ap.add_argument("--servers", type=int, default=None)
    ap.add_argument("--workstations", type=int, default=None)
    ap.add_argument("--vpn", type=int, default=None)
    ap.add_argument("--iot_byod", type=int, default=None)

    args = ap.parse_args()

    if args.config:
        with open(args.config, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        cfg.setdefault("output", {}).setdefault("directory", args.output_dir)
        cfg.setdefault("output", {}).setdefault("pcaps", {})
    else:
        print("[AUTO] generating config from preset")
        cfg = build_auto_config(args)

    rng = random.Random(cfg.get("seed", args.seed))
    base_ts = float(cfg.get("time", {}).get("base_epoch", time.time()))

    topo = build_topology(cfg, rng)
    generate_packets(cfg, topo, rng, base_ts)

    safe_mkdir(args.output_dir)
    write_pcaps(cfg, topo, args.output_dir)
    write_metadata(cfg, topo, args.output_dir)

    if args.export_config:
        config_path = os.path.join(args.output_dir, "config.json")
        summary_path = os.path.join(args.output_dir, "config.summary.txt")
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        write_config_summary(cfg, summary_path)
        print(f"[+] wrote {config_path}")
        print(f"[+] wrote {summary_path}")

    print("✅ Done")


if __name__ == "__main__":
    main()