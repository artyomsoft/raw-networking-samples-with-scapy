from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP, ICMP, TCP
from scapy.layers.l2 import Ether, ARP

from utils import mac_to_bytes



def create_arp_request(ip):
    return Ether()/ARP(pdst=ip)


def create_dhcp_discover(mac):
    return (Ether(src=mac, dst='ff:ff:ff:ff:ff:ff')
            / IP(src='0.0.0.0', dst='255.255.255.255')
            / UDP(dport=67, sport=68)
            / BOOTP(op=1, chaddr=mac_to_bytes(mac))
            / DHCP(options=[('message-type', 'discover'), 'end']))


def create_dhcp_request(mac, ip):
    return (Ether(src=mac, dst='ff:ff:ff:ff:ff:ff')
            / IP(src='0.0.0.0', dst='255.255.255.255')
            / UDP(dport=67, sport=68)
            / BOOTP(op=1, chaddr=mac_to_bytes(mac), ciaddr=ip)
            / DHCP(options=[('message-type', 'request'), 'end']))


def create_dns_request(dns_server, host_name):
    return IP(dst=dns_server)/UDP()/DNS(rd=1, qd=DNSQR(qname=host_name))


def create_ping_request(ip):
    return IP(dst=ip)/ICMP()


def create_tcp_syn(src, sport, dst, dport, seq):
    return IP(src=src, dst=dst)/TCP(seq=seq,sport=sport, dport=dport, flags="S")


def create_tcp_ack(src, sport, dst, dport, ack, seq):
    return IP(src=src, dst=dst)/TCP(ack=ack, seq=seq, sport=sport, dport=dport, flags="A")


def create_tcp_fin_ack(src, sport, dst, dport, ack, seq):
    return IP(src=src, dst=dst)/TCP(ack=ack, seq=seq, sport=sport, dport=dport, flags="FA")
