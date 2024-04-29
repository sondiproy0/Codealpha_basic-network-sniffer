import scapy.all as scapy
import time

def sniffing(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    print(packet)
    time.sleep(0.5)

sniffing('Ethernet')
