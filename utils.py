# utils.py
import socket

def ip_to_domain(ip):
    try:
        domain = socket.gethostbyaddr(ip)[0]
        return domain
    except socket.herror:
        return ''

def parse_address(address):
    try:
        ip, port = address.split(':')
        return ip, port
    except ValueError:
        return address, ''
