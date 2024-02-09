import argparse
import ipaddress
import json
import logging
from ipaddress import IPv4Address, IPv4Network
from typing import List, Generator, Any


logger = logging.getLogger('abuseipdb2iptables')
logger.setLevel(logging.INFO)


def filter_ipv4_ips(ips: List[str]) -> List[IPv4Address]:
    ipv4_list = []
    for ip in ips:
        try:
            ipv4_list.append(IPv4Address(ip))
        except ipaddress.AddressValueError:
            logger.warning("Invalid IPv4 address: %s", ip)
    logger.info('found %s IPv4 addresses', len(ipv4_list))
    return ipv4_list


def networks_to_iptables_rules(nets: Generator[IPv4Network, None, None]) -> Generator[str, Any, None]:
    return (f'-A INPUT -s {net} -j DROP' for net in nets)


def ips_to_networks(ips: List[IPv4Address]) -> Generator[IPv4Network, None, None]:
    return ipaddress.collapse_addresses(ips)


def read_ips_from_file(filename: str) -> List[str]:
    with open(filename, 'r') as file:
        abuseipdb_json = json.load(file)
        return [record['ipAddress'] for record in abuseipdb_json['data']]


def main(args) -> Generator[str, Any, None]:
    return networks_to_iptables_rules(
                ips_to_networks(
                    filter_ipv4_ips(
                        read_ips_from_file(args.filename)
                    )
                ))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='abuseipdb2iptables',
        description='Converts abuseipDB json file into iptables format')
    parser.add_argument('filename')
    for rule in main(parser.parse_args()):
        print(rule)