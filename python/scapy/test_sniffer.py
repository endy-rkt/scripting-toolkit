from scapy.all import sniff, TCP

INTERFACES = "lo"

#test with mail or irc protocol
BFP_MAIL= "tcp port 110 or tcp port 25 port or tcp port 143"

BFP_IRC = "tcp port 6667 or tcp port 6697"

def packet_callback(packet):
	# print(packet.show())
	print(packet[TCP])
	return
	if packet[TCP].payload:
		my_packet = str(packet[TCP].payload)
		if "user" in my_packet.lower() or "pass" in my_packet.lower():
			print(f"[*] Destination: {packet[TCP].dst}")
			print(f"[*] str({packet[TCP].payload})")

def main():
	sniff(filter=BFP_IRC, iface=INTERFACES, prn=packet_callback, store=0)

if __name__ == "__main__":
	main()