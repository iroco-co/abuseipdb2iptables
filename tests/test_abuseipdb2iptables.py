import os
from ipaddress import IPv4Address, IPv4Network
from unittest import TestCase

import pytest

from abuseipdb2iptables.cli import read_ips_from_file, filter_ipv4_ips, ips_to_networks
script_dir = os.path.dirname(__file__)


class TestAbuseIpDb2IpTables(TestCase):
    def test_main(self):
        self.assertEqual(['192.168.1.2', '10.0.0.1'], read_ips_from_file(os.path.join(script_dir, 'fixtures/abuseipdb.json')))

    def test_filter_ipv4(self):
        self.assertEqual([IPv4Address('192.168.1.2')], filter_ipv4_ips(['192.168.1.2', '2001:470:1:c84::21']))

    def test_ip_db_to_networks(self):
        self.assertEqual([IPv4Network('10.0.0.1/32'), IPv4Network('192.168.1.2/31')], list(ips_to_networks(
            [IPv4Address('192.168.1.2'),
             IPv4Address('10.0.0.1'),
             IPv4Address('192.168.1.3')])))

    def test_error_abuse_ip_db(self):
        with pytest.raises(SystemExit):
            read_ips_from_file(os.path.join(script_dir, 'fixtures/error.json'))