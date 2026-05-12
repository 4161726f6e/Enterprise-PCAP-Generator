# Enterprise PCAP Lab Generator
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

## Requirements

* Python 3.9+
* Scapy

# Key Features
## One-Command Lab Generation
Generate a full enterprise environment with:

```
python pcap_gen.py --preset enterprise
```

No config required.

## Multi-PCAP Output (Realistic Visibility)
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

## Network Visibility Model
| View | Description |
| -------------- | -------------- |
| Inside Subnets | Pre-NAT traffic |
| Edge PCAP | Post-NAT external traffic |
| Return Traffic | Simulated inbound responses |


## Automatic Network Design
The tool automatically:

* Allocates CIDRs per tier
* Prevents subnet overlap
* Sizes subnets based on host counts
* Assigns gateway IPs correctly


## NAT + Edge Modeling
Simulates:

Internet egress NAT
* Public IP translation
* Return traffic from internet
* De-NAT delivery to internal hosts


## Deterministic Output
All runs are reproducible:
```
python pcap_gen.py --seed 42
```
Same inputs → same outputs

## Config Export (Optional)
```
Shellpython pcap_gen.py --preset enterprise --export-configShow more lines
```
Outputs:
* config.json
* config.summary.txt


## Architecture
### Network Segmentation

| View | Description |
| -------------- | -------------- | -------------- |
| Tier | CIDR Range | Purpose |
| DMZ | 10.10.0.0/16 | Internet-facing systems |
| Servers | 10.20.0.0/16 | Backend systems |
| Workstations | 10.30.0.0/16 | User endpoints |
| VPN | 10.40.0.0/16 | Remote users |
| IoT / BYOD | 10.50.0.0/16 | Noisy devices |
| Edge | 203.0.113.0/24 | NAT boundary |

### Traffic Types Generated
Internal Traffic
* Workstations → Servers (SMB-like)
* VPN → DMZ (admin / RDP-like)

### Internet Traffic
TLS-like sessions
* ClientHello (SNI included)
* Application data
* Bidirectional communication

### IoT Traffic
* DNS-like UDP bursts


## Output Artifacts
### PCAP Files
Each PCAP represents traffic from a specific network perspective.

### config.json (optional)
Machine-readable configuration including:
* Subnets
* Gateways
* NAT settings
* Host counts

### config.summary.txt (optional)
Human-readable summary:
```
workstations 10.30.0.0/22 capacity=1021 hosts=800 util=78.3% gw=10.30.0.1
servers      10.20.0.0/25 capacity=125 hosts=118 util=94.4% gw=10.20.0.1
```

Useful for validation and debugging.


## Usage
### Default (medium preset)
```
python pcap_gen.py
```

### Enterprise-scale lab
```
python pcap_gen.py --preset enterprise
```

### Custom output directory
```
python pcap_gen.py --output-dir folder
```

### Export config + summary
```
python pcap_gen.py --preset enterprise --export-config
```

333 Override host counts
```
python pcap_gen.py \
   --preset enterprise \
   --workstations 2000 \
   --servers 300
```

### Use existing config
```
python pcap_gen.py --config config.json
```

## Example Analysis (Wireshark)
### Find internet traffic (edge view)
```
ip.addr == 203.0.113.1 && tcp.port == 443
```

### Find TLS handshakes (inside)
```
tcp.port == 443
```


✅ Summary
This tool provides:
✅ Automated enterprise network simulation
✅ Multi-layer PCAP visibility
✅ Realistic traffic generation
✅ Reproducible lab environments
✅ Zero manual configuration required
