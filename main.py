import scapy

from samples import obtain_mac_addr, send_ping, obtain_ip_configuration, obtain_ip_address_by_host_name, \
    create_and_close_tcp_connection
from utils import get_default_gateway_ip


obtain_mac_addr(get_default_gateway_ip())

send_ping("google.com")

obtain_ip_configuration()

obtain_ip_address_by_host_name("1.1.1.1", "google.com")

create_and_close_tcp_connection("google.com", 80)

