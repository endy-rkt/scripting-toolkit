from scapy.all import *

IP_PROTO = 0xFF
SRC_IP = "10.0.0.1"
TARGET_IP = "10.0.0.2"

def send_packet(src, dst):
    packet_ = IP(src=src, dst=dst, proto=IP_PROTO)
    packet_.show()
    send(packet_)

def main():
    send_packet(SRC_IP, TARGET_IP)
    return (0)

if __name__ == "__main__":
    main()