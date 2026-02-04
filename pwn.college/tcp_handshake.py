from scapy.all import *
import  sys

DST_IP = "10.0.0.2"
DST_PORT = 31337
SEQ = 31337
SRC_IP = "10.0.0.1"
SRC_PORT = 31337
SA_FILTER = f"host {DST_IP} and port 31337"

def is_synack_send():
    return False

def send_tcp_handshake():
    packet_ = IP(src=SRC_IP, dst=DST_IP)
    syn_datagram = packet_ / TCP(sport=SRC_PORT, dport=DST_PORT, seq=SEQ, flags="S")
    syn_datagram.show()
    send(syn_datagram)
    
    print("[+] Sniffing response...")
    packets_ = sniff(count=1, prn=lambda x: x.show())
    
    sa_data = None
    for datagram in packets_:
        if datagram.haslayer(TCP):
            sa_data = datagram.getlayer(TCP)

    if not sa_data or sa_data.flags != "SA":
        print("[!!] Invalid response")
        sys.exit(1)
    
    print("[+] Sending response...")
    ack_datagram = packet_ / TCP(sport=SRC_PORT, dport=DST_PORT, seq=SEQ+1, ack=sa_data.seq+1, flags="A")
    ack_datagram.show()
    send(ack_datagram)

def main():
    send_tcp_handshake()
    return (0)

if __name__ == "__main__":
    main()