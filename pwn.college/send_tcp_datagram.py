from scapy.all import *

ACK = 31337
DST_PORT = 31337
FLAGS = "APRSF"
SEQ = 31337
SRC_IP = "10.0.0.1"
SRC_PORT = 31337
TARGET_IP = "10.0.0.2"

def send_packet(src, dst):
    packet_ = IP(src=src, dst=dst)
    datagram_ = packet_/TCP(sport=SRC_PORT, dport=DST_PORT, seq=SEQ, ack=ACK, flags=FLAGS)
    datagram_.show()
    send(datagram_)

def main():
    send_packet(SRC_IP, TARGET_IP)
    return (0)

if __name__ == "__main__":
    main()