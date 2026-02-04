from scapy.all import *
import sys

FLAG = ""

def monitor3():
    sniff(filter="port 31337 and host 10.0.0.3", prn=lambda x: x.show(), count=-1)

def packet_callback2(packet):
    global FLAG
    try:
        char = packet[Raw].load.decode("utf-8")
        print(char)
        if char == "{" or FLAG != "":
            START_FLAG = True
            FLAG += char
        if char == "}" and FLAG != "":
            FLAG = "pwn.college" + FLAG
            print(FLAG)
            if "pwn" in flag:
                sys.exit(0)
    except Exception as e:
        pass

def monitor2():
    sniff(filter="port 31337 and dst 10.0.0.2", prn=packet_callback2, count=-1)

def packet_callback1(packet):
    try:
        flag = packet[Raw].load.decode("utf-8")
        print(flag)
        sys.exit(0)
    except Exception as e:
        print('None')
        pass

def monitor1():
    sniff(filter="port 31337 and dst 10.0.0.2", prn=packet_callback1, count=-1)

if __name__ == "__main__":
    monitor1()