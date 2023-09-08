import socket

import scapy
from scapy.layers.dhcp import BOOTP
from scapy.layers.inet import TCP

import packets
from packets import create_dhcp_discover, create_dhcp_request, create_ping_request, create_arp_request, \
    create_dns_request
from utils import send_receive_l2, send_receive_l3, get_default_interface_mac, mac_to_bytes, send_l3, \
    get_default_interface_ip


# DHCP
def obtain_ip_configuration():
    scapy.config.Conf.checkIPaddr = False
    mac = get_default_interface_mac()
    request = create_dhcp_discover(mac)
    response = send_receive_l2(request)
    request = create_dhcp_request(mac=mac, ip=response[BOOTP].yiaddr)
    result = send_receive_l2(request)
    scapy.config.Conf.checkIPaddr = False
    return result


# ICMP
def send_ping(host_name):
    ip = socket.gethostbyname(host_name)
    request = create_ping_request(ip)
    return send_receive_l3(request)


# ARR
def obtain_mac_addr(ip):
    request = create_arp_request(ip)
    return send_receive_l2(request)


# DNS
def obtain_ip_address_by_host_name(dns_server, host_name):
    request = create_dns_request(dns_server=dns_server, host_name=host_name)
    return send_receive_l3(request)


def create_and_close_tcp_connection(host, dport):
    dst = socket.gethostbyname(host)
    src = get_default_interface_ip()
    sport = 12360
    seq = 1000
    syn = packets.create_tcp_syn(src=src, sport=sport, dst=dst, dport=dport, seq=seq)
    response = send_receive_l3(syn)
    ack = packets.create_tcp_ack(src=src, sport=sport, dst=dst, dport=dport, seq=response[TCP].ack, ack=response[TCP].seq+1)
    send_l3(ack)

    fin_ack = packets.create_tcp_fin_ack(src=src, sport=sport, dst=dst, dport=dport, seq=response[TCP].ack, ack=response[TCP].seq+1)
    response = send_receive_l3(fin_ack)
    ack = packets.create_tcp_ack(src=src, sport=sport, dst=dst, dport=dport, seq=response[TCP].ack, ack=response[TCP].seq+1)
    send_l3(ack)

