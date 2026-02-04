from scapy.all import *

DST_IP = "10.0.0.2"
DST_PORT = 31337
MSG = "Hello, World!\n"
SRC_IP = "10.0.0.1"
SRC_PORT = 31338

def packet_callback(packet):
    packet.show()
    try:
        flag = packet[Raw].load.decode("utf-8")
        print(flag)
        if "pwn" in flag:
            sys.exit(0)
    except Exception as e:
        print('None')
        pass

def monitor():
    sniff(prn=packet_callback, count=-1)

def send_udp_hello():
    packet_ = IP(dst=DST_IP, src=SRC_IP)
    datagram_ = packet_/UDP(sport=SRC_PORT, dport=DST_PORT)
    data = datagram_/MSG
    data.show()
    # send(data)
    sendp(Ether()/data, iface="eth0") #best one
    monitor()

def main():
    send_udp_hello()
    return (0)

if __name__ == "__main__":
    main()