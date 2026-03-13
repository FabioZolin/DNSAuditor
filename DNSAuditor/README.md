# DNS Tunneling & Exfiltration Auditor (v2.0)

A lightweight PCAP analyzing tool designed to audit DNS traffic in .pcap capture files and find potential data exfiltration or C2 packets, identifying potentially compromised hosts.

This script performs packet inspection on both outbound queries (`DNSQR`) and inbound C2 responses (`DNSRR`), identifying malicious behaviour.

## Features

DNSAuditor can:
- **Analyze PCAP files offline** without exhausting system RAM even with sizable PCAP files, thanks to sequential packet processing.
- **Calculate Shannon Entropy** to automatically detect encrypted or encoded data hidden in subdomains, the entropy is automatically adjusted based on the detected alphabet (Hex, Base32, Base64/ Regular Text) .
- **Detect Domain Anomalies** such as excessively long query lengths or abnormal subdomain counts indicating possible data exfiltration.
- **Track Specific Record Types** actively used for C2 and exfiltration (TXT, NULL, CNAME).
- **Rank Suspicious Hosts** by automatically generating a "Top Offenders" list, correlating alerts to internal IP addresses that might show indicators of compromise.
- **Filter Noise** via tiered verbosity levels (`-v` for critical alerts, `-vv` for all warnings).
- **C2 Payload Extraction:** Intercepts and decodes TXT and NULL record responses, highlighting the inbound binary/text payloads sent by the attacker.

## Setup & Requirements

Since this tool is part of the **NetAuditor Suite**, it relies on the global requirements of the project.

**1. Ensure you have installed the global requirements from the root directory:**
> pip install -r ../requirements.txt

**2. Navigate to this tool's folder and run it:**
> cd DNSAuditor
> python DNSAuditor.py -f capture.pcap

## Usage

Use the `-h` flag to display all available options and thresholds.

### Arguments List
Use the `-h` flag to display all available options and thresholds in terminal.
| Flag | Name | Description | Default |
| :--- | :--- | :--- | :--- |
| `-f` | `--file` | **(Required)** Path to the `.pcap` file | - |
| `-dl` | `--domain_length` | Max allowed domain length before flagging | `30` |
| `-et` | `--entropy_threshold` | Minimum Shannon entropy score before flagging | `4.0` |
| `-sn` | `--subdomain_number`| Max number of subdomains before flagging | `5` |
| `-v` | `--verbose` | Shows standard warnings and suspicious records | `False` |
| `-vv`| `--very_verbose` | Shows everything (including presumed legit TXT) | `False` |
| `-t` | `--txt` | Displays all TXT DNS requests | `False` |
| `-n` | `--null` | Displays all NULL DNS requests (Highly suspicious) | `False` |
| `-c` | `--cname` | Displays all CNAME DNS requests | `False` |

### Usage Examples
Run the script providing a `.pcap` or `.pcapng` file. 

#### Basic Analysis (Fast Triage)
Generates a statistical report and prints only High Entropy / NULL record alerts.
```bash 
python dns_auditor.py -f suspicious_traffic.pcap
```

#### Deep Dive (Verbose Mode)
Prints all warnings (long domains, many subdomains, CNAME/TXT requests) and suspicious inbound C2 TXT formats.
```bash
python dns_auditor.py -f suspicious_traffic.pcap -v
```

#### Custom Thresholds
If you are analyzing an environment with specific noise patterns, you can tweak the detection engine:
```bash
`python dns_auditor.py -f suspicious_traffic.pcap -dl 40 -et 4.5 -sn 6
```


## Built With
* Python 3
* [Scapy](https://scapy.net/) - Packet manipulation program & library
* [Colorama](https://pypi.org/project/colorama/) - Cross-platform colored terminal text
