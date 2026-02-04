from scapy.all import *
import sys

# SRC_IP = "10.0.0.1"
IFACE = "eth0"
TARGET_IP = "10.0.0.2"
FRAME_TYPE = 0xFFFF

def send_ethernet_frame(src, dst):
    frame = Ether(dst=dst, src=src, type=FRAME_TYPE)
    frame.show()
    sendp(frame, iface=IFACE)

def main():
    # SRC_MAC = Ether().src
    # SRC_MAC = "92:8c:1a:49:f9:cf"
    #default iface
    SRC_MAC = get_if_hwaddr(conf.iface)
    TARGET_MAC = getmacbyip(TARGET_IP)
    
    if not (SRC_MAC and TARGET_MAC):
        print(f"[!!] Error: src or dst mac not found.")
        sys.exit(1)
    
    send_ethernet_frame(SRC_MAC, TARGET_MAC)
    return (0)

if __name__ == "__main__":
    main()