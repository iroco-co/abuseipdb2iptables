from ipaddress import IPv4Address, IPv4Network
from unittest import TestCase

from abuseipdb2iptables import read_ips_from_file, filter_ipv4_ips, ips_to_networks, networks_to_iptables_rules


class TestAbuseIpDb2IpTables(TestCase):
    def test_main(self):
        self.assertEqual(['192.168.1.2', '10.0.0.1'], read_ips_from_file('fixtures/different.json'))

    def test_filter_ipv4(self):
        self.assertEqual([IPv4Address('192.168.1.2')], filter_ipv4_ips(['192.168.1.2', '2001:470:1:c84::21']))

    def test_ip_db_to_networks(self):
        self.assertEqual([IPv4Network('10.0.0.1/32'), IPv4Network('192.168.1.2/31')], list(ips_to_networks(
            [IPv4Address('192.168.1.2'),
             IPv4Address('10.0.0.1'),
             IPv4Address('192.168.1.3')])))

    def test_networks_to_iptable_rules(self):
        self.assertEqual(['-A INPUT -s 192.168.1.2/31 -j DROP'],
                         list(networks_to_iptables_rules((ip for ip in [IPv4Network('192.168.1.2/31')]))))