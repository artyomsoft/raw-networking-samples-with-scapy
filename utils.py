import netifaces
import scapy.sendrecv
from scapy.sendrecv import srp1, sr1


def get_default_gateway_ip():
    return netifaces.gateways()['default'][netifaces.AF_INET][0]


def get_default_interface_mac():
    interface_name = netifaces.gateways()['default'][netifaces.AF_INET][1]
    return netifaces.ifaddresses(interface_name)[netifaces.AF_LINK][0]['addr']


def get_default_interface_ip():
    interface_name = netifaces.gateways()['default'][netifaces.AF_INET][1]
    return netifaces.ifaddresses(interface_name)[netifaces.AF_INET][0]['addr']


def mac_to_bytes(mac_addr: str) -> bytes:
    return int(mac_addr.replace(":", ""), 16).to_bytes(6, "big")


def send_receive_l2(packet):
    print('L2 REQUEST')
    print('==========')
    packet.show2()
    response = srp1(packet, verbose=0, timeout=5)
    print('L2 RESPONSE')
    print('===========')
    if response:
        response.show2()
    else:
        print(response)
    return response


def send_receive_l3(packet):
    print('L3 REQUEST')
    print('==========')
    packet.show2()
    response = sr1(packet, verbose=0, timeout=5)
    print('L3 RESPONSE')
    print('===========')
    if response:
        response.show2()
    else:
        print(response)
    return response


def send_l3(packet):
    print('L3 PACKET')
    print('==========')
    packet.show2()
    scapy.sendrecv.send(packet, verbose=0)

