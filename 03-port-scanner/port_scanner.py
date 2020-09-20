"""port_scanner.py
"""

import socket
from common_ports import ports_and_services

# config
TIMEOUT = 0.5  # max timeout in seconds


def verbose_summary(url: str, ip_address: str, open_ports: list) -> str:
    """Return a verbose output.

    Args:
        url (str): host or ip_address
        ip_address (str):
        open_ports (list): list of open ports

    Returns:
        str: Ex.
        Open ports for hackthissite.org (137.74.187.104)\nPORT     SERVICE\n443      https
    """

    url_str = f"{ip_address}" if url == ip_address else f"{url} ({ip_address})"
    open_ports_str = "".join(
        f"\n{port:<8} {ports_and_services.get(port)}" for port in open_ports
    )

    template = f"Open ports for {url_str}\nPORT     SERVICE{open_ports_str}"

    return template


def scan_port_range(ip_address: str, family: str, port_range: list) -> list:
    """Scan a range of ports.

    Args:
        ip_address (str): ip address
        family (str): protocol family (AF_INET...)
        port_range (list): [start port, end port]

    Returns:
        list: ports open
    """
    open_ports = []
    start, end = port_range[0], port_range[-1]
    for port in range(start, end + 1):
        s = socket.socket(family=family, type=socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        if s.connect_ex((ip_address, port)) == 0:
            open_ports.append(port)
        s.close()
    return open_ports


def get_hostname(ip_address: str) -> str:
    """Given a IP address, returns the name of the host if it can be found.
    Otherwise, fails silently and echoes the ip address."""
    try:
        host, _, _ = socket.gethostbyaddr(ip_address)
    except Exception:
        return ip_address
    return host


def get_open_ports(url: str, port_range: list, verbose: bool = False) -> list:
    open_ports = []
    # print(f"\n  *** testing {url} ***")  # debug
    try:
        info = socket.getaddrinfo(
            host=url,
            port=80,
            family=0,
            type=0,
            proto=socket.IPPROTO_TCP,
            flags=socket.AI_CANONNAME,
        )
    except Exception:
        if url.split(".")[0].isnumeric():
            return "Error: Invalid IP address"
        else:
            return "Error: Invalid hostname"

    family, _, _, canonname, sockaddr = info[0]
    ip_address, _ = sockaddr  # tuple (ip_address, port)

    open_ports = scan_port_range(ip_address, family, port_range)

    if verbose:
        host = get_hostname(ip_address)
        return verbose_summary(host, ip_address, open_ports)

    return open_ports
