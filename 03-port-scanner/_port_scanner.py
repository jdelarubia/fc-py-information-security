"""
import socket
socket.gethostbyaddr("8.8.8.8")
>>> ('google-public-dns-a.google.com', [], ['8.8.8.8'])

In [2]: socket.gethostbyname('www.google.com')
Out[2]: '216.58.196.4'
"""
import socket
import re
from common_ports import ports_and_services

# types aliases
IPV4 = socket.AF_INET  # socket family IP4
STREAM = socket.SOCK_STREAM  # socket type (connection based protocol: tcp/udp)
TIMEOUT = 1  # max timeout in seconds


def is_port_open(s, host_ip: str, port_num: int) -> bool:
    """Checks whether port_num is open on host_ip. strage
    FIXME: doesn't seem to work fine

    Args:
        s ([type]): [description]
        host_ip (str): [description]
        port_num (int): [description]

    Returns:
        bool: [description]
    """

    address = (host_ip, port_num)  # refactor
    # connection_result = s.connect_ex(address) == 0  # refactor
    # print(f"  checking {host_ip}:{port_num} -> {connection_result}")  # debug

    return True if s.connect_ex(address) == 0 else False


def is_valid_ip_address(target: str) -> bool:
    """REDUNDANT. is_valid_hostname checks for valid hosts and IPs!!!
    Given a string representing an IP address, return True if it's an IP address."""
    # Regex from https://riptutorial.com/regex/example/14146/match-an-ip-address
    ip_regex = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"

    pattern = re.compile(ip_regex, re.I)

    if pattern.search(target):
        return True
    return False


def is_valid_hostname(target: str) -> bool:
    """Given a name of a host, returns True if target it's a true domain name."""
    # Regex from https://www.regextester.com/99895
    # host_regex = r"^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?|^((http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
    host_regex = r"^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?|^((http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.)$"

    pattern = re.compile(host_regex, re.I)

    if pattern.search(target):
        return True
    return False


def verbose_response(url: str, ip_address: str, open_ports: list):
    message = f"Open ports for {url} ({ip_address})\n"
    message += f"PORT     SERVICE\n"

    for port in open_ports:
        message += f"{port:<9}{ports_and_services.get(port)}\n"
    return f"{message}\n"


def get_url_and_ip_address(target: str) -> tuple:
    ip_address, url = "x.x.x.x", "localhost"
    target = target.strip()

    if is_valid_ip_address(target):
        ip_address = target
        try:
            url, _, _ = socket.gethostbyaddr(target)
        except socket.herror:
            pass
    else:
        if is_valid_hostname(target):
            url = target
            try:
                ip_address = socket.gethostbyname(target)
            except socket.gaierror:
                pass
    return url, ip_address


def scan_port_range(ip_address: str, port_range: list) -> list:
    open_ports = []

    begin, end = port_range
    for port in range(begin, end):
        s = socket.socket(family=IPV4, type=STREAM)
        s.settimeout(TIMEOUT)
        # print(f"checking {port}")  # debug
        if is_port_open(s, ip_address, port):
            open_ports.append(port)
        s.close()
    return open_ports


def get_open_ports(target: str, port_range: list, verbose: bool = False):
    open_ports = []
    print("-----------------------")
    print(f"testing: {target}")
    # get host, get ip_address

    if not is_valid_hostname(target):
        return "Error: Invalid hostname"
    elif not is_valid_ip_address(target):
        return "Error: Invalid IP address"
    url, ip_address = get_url_and_ip_address(target)
    open_ports = scan_port_range(target, port_range)
    # valid_ip = is_valid_ip_address(target)
    # valid_host = is_valid_hostname(target)
    # if valid_host or valid_ip:
    #     url, ip_address = get_url_and_ip_address(target)
    #     open_ports = scan_port_range(target, port_range)
    # else:
    #     if not valid_host:
    #         return "Error: Invalid hostname"
    #     else:
    #         return "Error: Invalid IP address"

    if verbose:
        return verbose_response(url, ip_address, open_ports)
    return open_ports
