# 📦 Enterprise PCAP Lab Generator
## Overview
The Enterprise PCAP Lab Generator is a single-command tool that generates realistic multi-subnet network traffic datasets for:

* SOC analyst training
* Detection engineering
* Threat hunting exercises
* PCAP-based investigations

It automatically builds:

* A segmented enterprise network topology
* Synthetic traffic across multiple tiers
* Multi-perspective PCAPs (inside + edge/NAT views)


# 🚀 Key Features
## ✅ One-Command Lab Generation
Generate a full enterprise environment with:

```
python pcap_gen.py --preset enterpriseShow more lines
```

No config required.

## ✅ Multi-PCAP Output (Realistic Visibility)
Each subnet gets its own PCAP:
```
.
├── output/
    └── pcaps/
        ├── dmz.pcap
        ├── servers.pcap
        ├── workstations.pcap
        ├── vpn.pcap
        ├── iot_byod.pcap
        └── edge.pcap
```

## Netork Visibility Model





















ViewDescriptionInside SubnetsPre-NAT traffic (attribution preserved)Edge PCAPPost-NAT external trafficReturn TrafficSimulated inbound responses

✅ Automatic Network Design
The tool automatically:

Allocates CIDRs per tier
Prevents subnet overlap
Sizes subnets based on host counts
Assigns gateway IPs correctly


✅ NAT + Edge Modeling
Simulates:

Internet egress NAT
Public IP translation
Return traffic from internet
De-NAT delivery to internal hosts


✅ Deterministic Output
All runs are reproducible:
Shellpython pcap_gen.py --seed 42Show more lines
Same inputs → same outputs

✅ Config Export (Optional)
Shellpython pcap_gen.py --preset enterprise --export-configShow more lines
Outputs:
config.json
config.summary.txt


🧠 Architecture
Network Segmentation








































TierCIDR RangePurposeDMZ10.10.0.0/16Internet-facing servicesServers10.20.0.0/16Backend systemsWorkstations10.30.0.0/16User endpointsVPN10.40.0.0/16Remote usersIoT / BYOD10.50.0.0/16Noisy devicesEdge203.0.113.0/24NAT boundary

Traffic Types Generated
Internal Traffic

Workstations → Servers (SMB-like)
VPN → DMZ (admin / RDP-like)

Internet Traffic

TLS-like sessions with:

ClientHello (SNI included)
Application data
Bidirectional communication



IoT Traffic

DNS-like UDP bursts


📁 Output Artifacts
PCAP Files
Each PCAP represents traffic from a specific network perspective.

config.json (optional)
Machine-readable configuration:

Subnets
Gateways
NAT settings
Host counts


config.summary.txt (optional)
Human-readable summary:
workstations 10.30.0.0/22 capacity=1021 hosts=800 util=78.3% gw=10.30.0.1
servers      10.20.0.0/25 capacity=125 hosts=118 util=94.4% gw=10.20.0.1

Useful for:

Lab validation
Documentation
Debugging


⚙️ Usage
Default (medium preset)
Shellpython pcap_gen.pyShow more lines

Enterprise-scale lab
Shellpython pcap_gen.py --preset enterpriseShow more lines

Custom output directory
Shellpython pcap_gen.py --output-dir lab1Show more lines

Export config + summary
Shellpython pcap_gen.py --preset enterprise --export-configShow more lines

Override host counts
Shellpython pcap_gen.py \  --preset enterprise \  --workstations 2000 \  --servers 300Show more lines

Use existing config
Shellpython pcap_gen.py --config config.jsonShow more lines

🔍 Example Analysis (Wireshark)
Find internet traffic (edge view)
ip.addr == 203.0.113.1 && tcp.port == 443


Find TLS handshakes (inside)
tcp.port == 443


Identify internal lateral movement
tcp.port == 445


🧪 Validation Checklist
After running:
✅ PCAP files are non-empty
✅ Edge PCAP contains external IPs
✅ Workstation PCAP contains TLS traffic
✅ Summary file reflects realistic utilization

🏗 Design Principles
Automatic First

No required inputs
Sensible defaults


Realistic by Design

Multi-tier segmentation
NAT + edge modeling
Bidirectional flows


Reproducible

Seed-based deterministic output


Analyst-Centric

Multiple visibility perspectives
Real-world traffic patterns


🔮 Roadmap
Planned enhancements:

Scenario injection (--scenario ransomware)
Difficulty tuning (--difficulty easy|hard)
Ground truth export (attacker IPs, compromised hosts)
Multi-site topology generation
Zeek log + endpoint log correlation


📦 Requirements

Python 3.9+
Scapy

Install:
Shellpip install scapyShow more lines

✅ Summary
This tool provides:
✅ Automated enterprise network simulation
✅ Multi-layer PCAP visibility
✅ Realistic traffic generation
✅ Reproducible lab environments
✅ Zero manual configuration required
