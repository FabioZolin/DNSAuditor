import argparse
import sys
import os
import math
from collections import Counter
from scapy.all import PcapReader, DNS, DNSQR, UDP, IP

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    GREEN = Fore.GREEN
    RED = Fore.RED
    YELLOW = Fore.YELLOW
    RESET = Style.RESET_ALL
except ImportError:
    GREEN = RED = YELLOW = RESET = ""

def print_banner():
    """Prints the ASCII art banner and tool name."""
    banner = f"""{GREEN}
 _____  _   _  _____                     __   _             
 |  __ \\| \\ | |/ ____|     /\\            | (_) |            
 | |  | |  \\| | (___      /  \\  _   _  __| |_| |_ ___  _ __ 
 | |  | | . ` |\\___ \\    / /\\ \\| | | |/ _` | | __/ _ \\| '__|
 | |__| | |\\  |____) |  / ____ \\ |_| | (_| | | || (_) | |   
 |_____/|_| \\_|_____/  /_/    \\_\\__,_|\\__,_|_|\\__\\___/|_|   
                                                        
        -- DNS Tunneling & Exfiltration Detector --
    {RESET}"""
    print(banner)

def is_length_suspicious(domain, threshold):
    """
    Checks if the domain length exceeds the specified threshold.
    
    Args:
        domain (str): The DNS query name.
        threshold (int): Maximum allowed length before flagging.
        
    Returns:
        bool: True if length exceeds the threshold, False otherwise.
    """
    return len(domain) > threshold

def extract_subdomains_payload(domain):
    """
    Separates subdomains from the root domain for precise entropy calculation.
    Example: 'a1b2c3d4.hacker.com' -> 'a1b2c3d4'
    
    Args:
        domain (str): The full DNS query name.
        
    Returns:
        str: Concatenated subdomains without dots, or the original domain (without dots) if no subdomains are present.
    """
    parts = domain.split('.')
    if len(parts) > 2:
        subdomains = parts[:-2] 
        payload = "".join(subdomains)
        return payload
    else:
        return "".join(parts)

def calculate_DNS_domain_entropy(looked_up_domain):
    """
    Calculates the Shannon entropy of the subdomain payload to detect encrypted or encoded data.
    
    Args:
        looked_up_domain (str): The full DNS query name.
        
    Returns:
        float: The calculated Shannon entropy score.
    """
    if not looked_up_domain:
        return 0

    clean_domain = extract_subdomains_payload(looked_up_domain)
    entropy = 0
    char_counts = Counter(clean_domain)
    total_chars = len(clean_domain)
    
    for count in char_counts.values():
        probability = count / total_chars
        entropy -= probability * math.log2(probability)
        
    return entropy

def is_entropy_suspicious(entropy, threshold):
    """Checks if the calculated entropy exceeds the specified threshold."""
    return entropy > threshold

def is_TXT_request(packet):
    """Checks if the DNS query is requesting a TXT record (Type 16)."""
    return packet[DNSQR].qtype == 16

def is_NULL_request(packet):
    """Checks if the DNS query is requesting a NULL record (Type 10)."""
    return packet[DNSQR].qtype == 10

def is_CNAME_request(packet):
    """Checks if the DNS query is requesting a CNAME record (Type 5)."""
    return packet[DNSQR].qtype == 5

def is_subdomain_number_suspicious(looked_up_domain, threshold):
    """Checks if the count of subdomains (dots) exceeds the given threshold."""
    return looked_up_domain.count(".") >= threshold

def analyze_pcap(pcap_file, domain_length_threshold, entropy_threshold, subdomain_threshold, show_txt, show_null, show_cname, verbose, very_verbose):
    """
    Main analysis engine. Parses the PCAP file, inspects DNS queries against thresholds,
    updates statistics, and prints alerts based on user-defined flags.
    
    Args:
        pcap_file (str): Path to the PCAP file.
        domain_length_threshold (int): Alert threshold for domain length.
        entropy_threshold (float): Alert threshold for Shannon entropy.
        subdomain_threshold (int): Alert threshold for number of subdomains.
        show_txt (bool): If True, print all TXT queries.
        show_null (bool): If True, print all NULL queries.
        show_cname (bool): If True, print all CNAME queries.
        verbose (bool): If True, prints additional warnings (length and subdomains).
    """
    if not os.path.isfile(pcap_file):
        print(f"[{RED}ERROR{RESET}] The file '{pcap_file}' doesn't exist or the specified path is wrong.")
        sys.exit(1)

    if very_verbose:
        verbose=True
        
    print(f"[{GREEN}INFO{RESET}] Starting file analysis: {pcap_file}...")
    

    print(f"[{YELLOW}WAIT{RESET}] Building parsing module and analyzing packets...")
    
    total_dns_queries = 0
    long_queries = 0
    high_entropy_queries = 0
    high_subdomain_queries = 0
    txt_queries = 0
    null_queries = 0
    cname_queries = 0
    txt_polling_ips = Counter()
    exfiltrating_ips = Counter()
    
    with PcapReader(pcap_file) as packets:
        for packet in packets:
            # Check if the packet has a DNS Question Record
            if packet.haslayer(DNSQR) and packet.haslayer(IP): 
                try:
                    is_exfil = False
                    is_c2 = False
                    # Extraction and cleaning of the queried domain
                    looked_up_domain = packet[DNSQR].qname.decode('utf8').rstrip('.')
                    src_ip = packet[IP].src

                    #dst ip will be implemented later
                    #dst_ip = packet[IP].dst
                    total_dns_queries += 1

                    # Check 1: Length
                    if is_length_suspicious(looked_up_domain, domain_length_threshold):
                        long_queries += 1
                        if very_verbose:
                            print(f"[{YELLOW}WARNING{RESET}] Long Query: {looked_up_domain} ({len(looked_up_domain)} chars)")

                    # Check 2: Entropy
                    entropy_score = calculate_DNS_domain_entropy(looked_up_domain)
                    if is_entropy_suspicious(entropy_score, entropy_threshold):
                        high_entropy_queries += 1
                        if not is_exfil:
                            exfiltrating_ips[src_ip] += 1
                            is_exfil=True
                        if verbose:
                            print(f"[{RED}ALERT{RESET}] High Entropy ({entropy_score:.2f}): {looked_up_domain}")

                    # Check 3: Subdomain Number
                    if is_subdomain_number_suspicious(looked_up_domain, subdomain_threshold):
                        high_subdomain_queries += 1
                        if very_verbose:
                            print(f"[{YELLOW}WARNING{RESET}] Many Subdomains in Query: {looked_up_domain} ({len(looked_up_domain)} chars)")

                    # Check 4: Specific Exfiltration Records
                    if is_TXT_request(packet):
                        txt_queries += 1
                        if not is_c2:
                            txt_polling_ips[src_ip]+=1
                            is_c2 = True
                        if show_txt or very_verbose:
                            print(f"[{YELLOW}WARNING{RESET}] TXT Request: {looked_up_domain}")

                    elif is_NULL_request(packet):
                        null_queries += 1
                        if not is_exfil:
                            exfiltrating_ips[src_ip] += 1
                            is_exfil=True
                        if show_null or verbose:
                            print(f"[{RED}CRITICAL{RESET}] NULL Request: {looked_up_domain} srcIP :{packet[IP].src}")


                    elif is_CNAME_request(packet):
                        cname_queries += 1
                        if show_cname or very_verbose:
                            print(f"[{YELLOW}WARNING{RESET}] CNAME Request: {looked_up_domain}")

                except Exception:
                    # Ignore malformed packets silently
                    pass
    
    # ------------------------------------------------------------------------- Output ------------------------------------------------------------------------- #
    print(f"\n[{GREEN}INFO{RESET}] Analysis Complete.")
    print(f"Total DNS Queries Analyzed: {total_dns_queries}")
    
    if total_dns_queries > 0:
        long_pct = (long_queries / total_dns_queries) * 100
        entropy_pct = (high_entropy_queries / total_dns_queries) * 100
        high_subdomain_pct = (high_subdomain_queries / total_dns_queries) * 100
        txt_pct = (txt_queries / total_dns_queries) * 100
        null_pct = (null_queries / total_dns_queries) * 100
        cname_pct = (cname_queries / total_dns_queries) * 100
        
        print(f"\n--- General Anomalies ---")
        print(f" - Long Queries:      {long_queries} ({long_pct:.2f}%)")
        print(f" - High Entropy:      {high_entropy_queries} ({entropy_pct:.2f}%)")
        print(f" - Many Subdomains:   {high_subdomain_queries} ({high_subdomain_pct:.2f}%)")
        
        print(f"\n--- Specific Record Types ---")
        print(f" - TXT Queries:       {txt_queries} ({txt_pct:.2f}%)")
        print(f" - NULL Queries:      {null_queries} ({null_pct:.2f}%)")
        print(f" - CNAME Queries:     {cname_queries} ({cname_pct:.2f}%)")

        if txt_polling_ips or exfiltrating_ips:
            print(f"\n--- Suspicious Hosts (Top Offenders) ---")
            # Classifica C2 / Polling (Giallo/Warning)
            if txt_polling_ips:
                print(f" [{YELLOW}C2 POLLING{RESET}] Top IPs requesting TXT records:")
                for ip, count in txt_polling_ips.most_common(5):
                    print(f"   -> {ip}: {count} requests")
            
            # Classifica Esfiltrazione Dati (Rosso/Critical)
            if exfiltrating_ips:
                print(f" [{RED}DATA EXFILTRATION{RESET}] Top IPs triggering High Entropy or NULL records:")
                for ip, count in exfiltrating_ips.most_common(5):
                    print(f"   -> {ip}: {count} alerts")

def main():
    print_banner()
    
    # Default Thresholds
    domain_length_threshold = 30
    entropy_threshold = 3.2
    subdomain_threshold = 4
    
    # Setup argparse to handle terminal input
    parser = argparse.ArgumentParser(description="PCAP analyzer to detect DNS tunneling and data exfiltration.")
    
    # Required arguments
    parser.add_argument("-f", "--file", help="Path to the .pcap file to analyze", required=True)

    # Optional Thresholds
    parser.add_argument("-dl", "--domain_length", help="Specifies the max domain length before flagging (default: 30)")
    parser.add_argument("-et", "--entropy_threshold", help="Specifies the minimum entropy score before flagging (default: 3.2)")
    parser.add_argument("-sn", "--subdomain_number", help="Specifies the max number of subdomains before flagging (default: 4)")

    # Output Control Flags
    parser.add_argument("-t", "--txt", help="Display all TXT DNS requests in the output", action="store_true")
    parser.add_argument("-n", "--null", help="Display all NULL DNS requests in the output (Highly suspicious)", action="store_true")
    parser.add_argument("-c", "--cname", help="Display all CNAME DNS requests in the output", action="store_true")
    parser.add_argument("-v", "--verbose", help="Enable verbose mode (displays Critical and Alert individual records)", action="store_true")
    parser.add_argument("-vv", "--very_verbose", help="Enable very verbose mode (displays all warnings and suspicious records)", action="store_true")
    # Parse arguments
    args = parser.parse_args()
    
    # Override defaults if provided
    if args.domain_length:
        domain_length_threshold = int(args.domain_length)
        if domain_length_threshold < 20:
            print(f"[{YELLOW}WARNING{RESET}] The max domain length threshold is low; expect a high number of false positives.")

    if args.entropy_threshold:
        entropy_threshold = float(args.entropy_threshold)
        
    if args.subdomain_number:
        subdomain_threshold = int(args.subdomain_number)

    # Start the analysis
    analyze_pcap(args.file, domain_length_threshold, entropy_threshold, subdomain_threshold, args.txt, args.null, args.cname, args.verbose, args.very_verbose)

if __name__ == "__main__":
    main()