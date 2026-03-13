import argparse
import sys
import os
import math
from collections import Counter
from scapy.all import PcapReader, DNS, DNSQR, DNSRR, UDP, IP

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
  _____  _   _  _____                     _ _ _             
 |  __ \\| \\ | |/ ____|     /\\            | (_) |            
 | |  | |  \\| | (___      /  \\  _   _  __| |_| |_ ___  _ __ 
 | |  | | . ` |\\___ \\    / /\\ \\| | | |/ _` | | __/ _ \\| '__|
 | |__| | |\\  |____) |  / ____ \\ |_| | (_| | | || (_) | |   
 |_____/|_| \\_|_____/  /_/    \\_\\__,_|\\__,_|_|\\__\\___/|_|   
                                                                  
            -- DNS Tunneling & Exfiltration Auditor --
                   -- V 2.0 by Fabio Zolin --                   
    {RESET}"""
    print(banner)

# Simple utility functions to keep the core logic clean and modular.

def extract_subdomains_payload(domain):
    """Separates subdomains from the root domain for precise entropy calculation."""
    parts = domain.split('.')
    if len(parts) > 2:
        subdomains = parts[:-2] 
        payload = "".join(subdomains)
        return payload
    else:
        return "".join(parts)
    
def analyze_entropy_smart(text, base_threshold):
    """
    Entropy calculation based on Shannon's formula and weighted on different thresholds depending on character sets.
    Returns a tuple: (is_suspicious [bool], entropy_score [float])
    """
    if not text:
        return False, 0.0
        
    # 1. Entropy Calculation (Shannon's Entropy)
    entropy = 0
    char_counts = Counter(text)
    total_chars = len(text)
    for count in char_counts.values():
        probability = count / total_chars
        entropy -= probability * math.log2(probability)
        
    # 2. Alphabet detection
    chars_in_text = set(text)
    hex_chars = set("0123456789abcdefABCDEF")
    # Base32 standard e caratteri validi per i sottodomini DNS
    base32_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz234567=-_")
    
    # 3. Dynamic thresholds logic
    if chars_in_text.issubset(hex_chars):
        # Purely Hex (theoric Max = 4.0). 
        dynamic_threshold = min(base_threshold, 3.6)
        
    elif chars_in_text.issubset(base32_chars):
        # Base 32 or regular DNS (theoric Max ~5.0).
        dynamic_threshold = min(base_threshold, 4.4)
        
    else:
        # It's free text, Base64, or contains punctuation (theoric Max > 6.0).
        # Raise the threshold to avoid false positives on normal sentences or DKIM records.
        dynamic_threshold = max(base_threshold, 4.8)
        
    # Returns whether the entropy is suspicious and the calculated score
    return (entropy > dynamic_threshold), entropy



# --- CORE ARCHITECTURE ---

class DNSQStats:
    """Class to keep track of all counters and metrics for queries."""
    def __init__(self):
        self.total_queries = 0
        self.long_queries = 0
        self.high_entropy = 0
        self.many_subdomains = 0
        self.txt = 0
        self.null = 0
        self.cname = 0
        self.c2_ips = Counter()
        self.exfil_ips = Counter()

class DNSRStats:
    """Class to keep track of all counters and metrics related to DNS responses."""
    def __init__(self):
        self.total_responses = 0
        self.null_responses = 0
        self.txt_responses = 0

def print_analysis_report(query_stats, response_stats):
    """Handles exclusively the formatting and printing of the final report to the console."""
    print(f"\n[{GREEN}INFO{RESET}] Analysis Complete.")
    print(f"Total DNS Queries Analyzed: {query_stats.total_queries}")
    print(f"Total DNS Responses Analyzed: {response_stats.total_responses}")
    
    # --- Queries stats ---
    if query_stats.total_queries > 0:
        long_pct = (query_stats.long_queries / query_stats.total_queries) * 100
        entropy_pct = (query_stats.high_entropy / query_stats.total_queries) * 100
        subdomain_pct = (query_stats.many_subdomains / query_stats.total_queries) * 100
        txt_pct = (query_stats.txt / query_stats.total_queries) * 100
        null_pct = (query_stats.null / query_stats.total_queries) * 100
        cname_pct = (query_stats.cname / query_stats.total_queries) * 100
        
        print(f"\n--- General Anomalies ---")
        print(f" - Long Queries:      {query_stats.long_queries} ({long_pct:.2f}%)")
        print(f" - High Entropy:      {query_stats.high_entropy} ({entropy_pct:.2f}%)")
        print(f" - Many Subdomains:   {query_stats.many_subdomains} ({subdomain_pct:.2f}%)")
        
        print(f"\n--- Query Record Types (Outbound) ---")
        print(f" - TXT Queries:       {query_stats.txt} ({txt_pct:.2f}%)")
        print(f" - NULL Queries:      {query_stats.null} ({null_pct:.2f}%)")
        print(f" - CNAME Queries:     {query_stats.cname} ({cname_pct:.2f}%)")

    # --- Responses stats ---
    if response_stats.total_responses > 0:
        txt_r_pct = (response_stats.txt_responses / response_stats.total_responses) * 100
        null_r_pct = (response_stats.null_responses / response_stats.total_responses) * 100
        
        print(f"\n--- Response Record Types (Inbound / C2) ---")
        print(f" - TXT Responses:  {response_stats.txt_responses} ({txt_r_pct:.2f}%)")
        print(f" - NULL Responses: {response_stats.null_responses} ({null_r_pct:.2f}%)")

    # --- Top offenders ---
    if query_stats.c2_ips or query_stats.exfil_ips:
        print(f"\n--- Suspicious Hosts (Top Offenders) ---")
        
        if query_stats.c2_ips:
            print(f" [{YELLOW}C2 POLLING{RESET}] Top IPs requesting TXT records:")
            for ip, count in query_stats.c2_ips.most_common(5):
                print(f"   -> {ip}: {count} requests")
        
        if query_stats.exfil_ips:
            print(f" [{RED}DATA EXFILTRATION{RESET}] Top IPs triggering High Entropy or NULL records:")
            for ip, count in query_stats.exfil_ips.most_common(5):
                print(f"   -> {ip}: {count} alerts")

def process_dns_queries(packet, query_stats, config):
    """Core engine: evaluates a single packet query and updates the DNSQStats object."""
    if not (packet.haslayer(DNSQR) and packet.haslayer(IP)):
        return

    try:
        is_exfil = False
        is_c2 = False
        
        looked_up_domain = packet[DNSQR].qname.decode('utf8').rstrip('.')
        src_ip = packet[IP].src
        query_stats.total_queries += 1

        # Check 1: Length
        if len(looked_up_domain) > config['domain_length']:
            query_stats.long_queries += 1
            if config['very_verbose']:
                print(f"[{YELLOW}WARNING{RESET}] Long Query from {src_ip}: {looked_up_domain} ({len(looked_up_domain)} chars)")

        # Check 2: Smart Entropy (Outbound)
        clean_domain = extract_subdomains_payload(looked_up_domain)
        is_suspicious_entropy, entropy_score = analyze_entropy_smart(clean_domain, config['entropy'])
        
        if is_suspicious_entropy:
            query_stats.high_entropy += 1
            if not is_exfil:
                query_stats.exfil_ips[src_ip] += 1
                is_exfil = True
            if config['verbose']:
                print(f"[{RED}ALERT{RESET}] High Entropy ({entropy_score:.2f}) from {src_ip}: {looked_up_domain}")

        # Check 3: Subdomain Number
        if looked_up_domain.count(".") >= config['subdomain_number']:
            query_stats.many_subdomains += 1
            if config['very_verbose']:
                print(f"[{YELLOW}WARNING{RESET}] Many Subdomains from {src_ip}: {looked_up_domain} ({len(looked_up_domain)} chars)")

        # Check 4: Specific Record Types (Direct QType Comparison)
        qtype = packet[DNSQR].qtype

        if qtype == 16: # TXT
            query_stats.txt += 1
            if not is_c2:
                query_stats.c2_ips[src_ip] += 1
                is_c2 = True
            if config['show_txt'] or config['very_verbose']:
                print(f"[{YELLOW}WARNING{RESET}] TXT Request from {src_ip}: {looked_up_domain}")

        elif qtype == 10: # NULL
            query_stats.null += 1
            if not is_exfil:
                query_stats.exfil_ips[src_ip] += 1
                is_exfil = True
            if config['show_null'] or config['verbose']:
                print(f"[{RED}CRITICAL{RESET}] NULL Request from {src_ip}: {looked_up_domain}")

        elif qtype == 5: # CNAME
            query_stats.cname += 1
            if not is_exfil:
                query_stats.exfil_ips[src_ip] += 1
                is_exfil = True
            if config['show_cname'] or config['very_verbose']:
                print(f"[{YELLOW}WARNING{RESET}] CNAME Request from {src_ip}: {looked_up_domain}")

    except Exception:
        pass


def process_dns_responses(packet, response_stats, config):
    """Analizza le risposte DNS (DNSRR) per intercettare i payload del Command & Control."""
    if not (packet.haslayer(DNSRR) and packet.haslayer(IP)):
        return
        
    try:
        dst_ip = packet[IP].dst 
        response_stats.total_responses += 1
        
        for i in range(packet[DNS].ancount):
            answer = packet[DNS].an[i]
            record_type = answer.type   
            
            try:
                domain = answer.rrname.decode('utf8', errors='ignore').rstrip('.')
            except:
                domain = str(answer.rrname)
                
            payload = answer.rdata
                
            # --- TXT Records (Type 16) ---
            if record_type == 16:
                response_stats.txt_responses += 1
                
                if isinstance(payload, list):
                    payload_text = "".join([b.decode('utf-8', errors='ignore') for b in payload])
                elif isinstance(payload, bytes):
                    payload_text = payload.decode('utf-8', errors='ignore')
                else:
                    payload_text = str(payload)
                
                # 3. Check entropy of TXT content
                is_suspicious_entropy, txt_entropy = analyze_entropy_smart(payload_text, config['entropy'])
                if is_suspicious_entropy:
                    if config['verbose'] or config['show_txt']:
                        print(f"[{RED}CRITICAL C2 PAYLOAD{RESET}] High Entropy TXT Response({txt_entropy:.2f}) to {dst_ip}: {payload_text}")

            # --- NULL Records (Type 10) ---
            elif record_type == 10:
                response_stats.null_responses += 1
                
                payload_length = len(payload) if payload else 0
                
                if config['verbose'] or config['show_null']:
                    print(f"[{RED}CRITICAL C2{RESET}] NULL Response to {dst_ip}! Inbound binary payload: {payload_length} bytes")

    except Exception:
        pass


def analyze_pcap(pcap_file, config):
    """Orchestrator: validates the file and iterates over the packets."""
    if not os.path.isfile(pcap_file):
        print(f"[{RED}ERROR{RESET}] The file '{pcap_file}' doesn't exist or the specified path is wrong.")
        sys.exit(1)

    print(f"[{GREEN}INFO{RESET}] Starting file analysis: {pcap_file}...")
    print(f"[{YELLOW}WAIT{RESET}] Building parsing module and analyzing packets (this may take a while)...")
    
    query_stats = DNSQStats()
    response_stats = DNSRStats()
    
    with PcapReader(pcap_file) as packets:
        for packet in packets:
            process_dns_queries(packet, query_stats, config)
            process_dns_responses(packet, response_stats, config)
            
    print_analysis_report(query_stats, response_stats)


def main():
    print_banner()
    # Setting up the arguments.
    parser = argparse.ArgumentParser(description="PCAP analyzer to detect DNS tunneling and data exfiltration.")
    parser.add_argument("-f", "--file", help="Path to the .pcap file to analyze", required=True)
    parser.add_argument("-dl", "--domain_length", help="Specifies the max domain length before flagging (default: 30)")
    parser.add_argument("-et", "--entropy_threshold", help="Specifies the minimum entropy score before flagging (default: 4)")
    parser.add_argument("-sn", "--subdomain_number", help="Specifies the max number of subdomains before flagging (default: 5)")

    parser.add_argument("-t", "--txt", help="Display all TXT DNS requests in the output", action="store_true")
    parser.add_argument("-n", "--null", help="Display all NULL DNS requests in the output (Highly suspicious)", action="store_true")
    parser.add_argument("-c", "--cname", help="Display all CNAME DNS requests in the output", action="store_true")
    parser.add_argument("-v", "--verbose", help="Enable verbose mode (displays Critical and Alert individual records)", action="store_true")
    parser.add_argument("-vv", "--very_verbose", help="Enable very verbose mode (displays all warnings and suspicious records)", action="store_true")
    
    args = parser.parse_args()
    #All the arguments in one single variable
    config = {
        'domain_length': int(args.domain_length) if args.domain_length else 30,
        'entropy': float(args.entropy_threshold) if args.entropy_threshold else 4,
        'subdomain_number': int(args.subdomain_number) if args.subdomain_number else 5,
        'show_txt': args.txt,
        'show_null': args.null,
        'show_cname': args.cname,
        'verbose': True if args.very_verbose else args.verbose,
        'very_verbose': args.very_verbose
    }

    if config['domain_length'] < 20:
        print(f"[{YELLOW}WARNING{RESET}] The max domain length threshold is low; expect a high number of false positives.")

    if config['entropy'] < 3:
        print(f"[{YELLOW}WARNING{RESET}] The max entropy setting is low, expect a high number of false positives.")

    analyze_pcap(args.file, config)

if __name__ == "__main__":
    main()
