#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import ipaddress
import pathlib
import sys
import unittest
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).parents[1] / "tools" / "yume_packet_quick.py"
SPEC = importlib.util.spec_from_file_location("yume_packet_quick", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
packet_quick = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = packet_quick
SPEC.loader.exec_module(packet_quick)


class PacketQuickTest(unittest.TestCase):
    def test_parses_scoped_ipv4_inputs(self) -> None:
        address, port = packet_quick.parse_listen("192.168.1.10:8443")
        self.assertEqual(address, ipaddress.IPv4Address("192.168.1.10"))
        self.assertEqual(port, 8443)
        self.assertEqual(
            packet_quick.parse_packet_cidr("10.89.0.0/24"),
            ipaddress.IPv4Network("10.89.0.0/24"),
        )

    def test_rejects_non_numeric_listen_address(self) -> None:
        # The parsed address is rendered into nftables and UFW rules, so a
        # name that could resolve anywhere -- or to nothing -- is refused
        # rather than looked up.
        for value in ("build-host.example:8443", "localhost:8443", "8443", ""):
            with self.assertRaises(packet_quick.SetupError):
                packet_quick.parse_listen(value)

    def test_rejects_unsafe_interface_and_packet_pool(self) -> None:
        with self.assertRaises(packet_quick.SetupError):
            packet_quick.validate_interface("eth0;reboot", "--wan")
        with self.assertRaises(packet_quick.SetupError):
            packet_quick.parse_packet_cidr("10.89.0.1/24")
        with self.assertRaises(packet_quick.SetupError):
            packet_quick.parse_packet_cidr("10.89.0.0/16")

    def test_plan_is_scoped_and_reversible_by_named_resources(self) -> None:
        config = packet_quick.SetupConfig(
            tun="yume-pkt0",
            packet_cidr=ipaddress.IPv4Network("10.89.0.0/24"),
            gateway=ipaddress.IPv4Address("10.89.0.1"),
            mtu=1420,
            owner="yume",
            wan="wlan0",
            listen_address=ipaddress.IPv4Address("192.168.1.10"),
            listen_port=8443,
            allow_from=ipaddress.IPv4Network("192.168.1.0/24"),
            firewall="ufw",
            nft_table="yume_yume_pkt0",
        )
        with mock.patch.object(packet_quick, "find_command", side_effect=lambda name: name):
            commands = packet_quick.planned_commands(config)
        rendered = [packet_quick.command_text(command) for command in commands]
        self.assertTrue(any("ip saddr 10.89.0.0/24" in line for line in rendered))
        self.assertTrue(any("from 192.168.1.0/24" in line and "port 8443" in line for line in rendered))
        self.assertTrue(any("route allow in on yume-pkt0 out on wlan0" in line for line in rendered))
        self.assertFalse(any("flush" in line or "policy drop" in line for line in rendered))


if __name__ == "__main__":
    unittest.main()
