# DNSAuditor

DNSAuditor is a Python tool designed for Blue Teams and SOC Analysts to aid in detecting DNS tunneling, Command & Control (C2) polling, and data exfiltration within PCAP files.


# Features

DNSAuditor can:
- **Analyze PCAP files offline** without exhausting system RAM even with sizable PCAP files, thanks to sequential packet processing.
- **Calculate Shannon Entropy** to automatically detect encrypted or encoded data hidden in subdomains.
- **Detect Domain Anomalies** such as excessively long query lengths or abnormal subdomain counts indicating possible data exfiltration.
- **Track Specific Record Types** actively used for C2 and exfiltration (TXT, NULL, CNAME).
- **Rank Suspicious Hosts** by automatically generating a "Top Offenders" list, correlating alerts to internal IP addresses that might show compromission behaviour.
- **Filter Noise** via tiered verbosity levels (`-v` for critical alerts, `-vv` for all warnings).

# Usage

Use the `-h` flag to display all available options and thresholds.

```
Usage: dns_auditor.py -f <file.pcap> [options]

Required arguments:
  -f, --file            Path to the .pcap file to analyze

Optional Thresholds:
  -dl, --domain_length int
    Specifies the max domain length before flagging (default: 30)
  -et, --entropy_threshold float
    Specifies the minimum entropy score before flagging (default: 3.2)
  -sn, --subdomain_number
    Specifies the max number of subdomains before flagging (default: 4)

Output Control Flags:
  -t, --txt             
    Display all TXT DNS requests in the output
  -n, --null            
    Display all NULL DNS requests in the output (Highly suspicious or indicating wrong DNS configurations)
  -c, --cname           
    Display all CNAME DNS requests in the output
  -v, --verbose         
    Enable verbose mode (displays Critical and Alert individual records)
  -vv, --very_verbose   
    Enable very verbose mode (displays all warnings and suspicious records)
```
