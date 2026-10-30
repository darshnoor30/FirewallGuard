import json
import unittest

from audit_engine.parser import FirewallConfigParser, InvalidFirewallConfigError


def rule(**overrides):
    value = {
        "rule_id": "R-1",
        "name": "HTTPS",
        "action": "allow",
        "protocol": "tcp",
        "source": "10.0.0.7",
        "destination": "192.168.1.10",
        "port": "443",
        "enabled": True,
    }
    value.update(overrides)
    return value


class JsonParserTests(unittest.TestCase):
    def setUp(self):
        self.parser = FirewallConfigParser()

    def parse(self, raw_rule):
        return self.parser.parse_text(json.dumps({"rules": [raw_rule]}), "json")

    def test_valid_rule_is_normalized(self):
        parsed = self.parse(rule(action="ACCEPT", source="10.0.0.7/24"))
        self.assertEqual(parsed.source_format, "json")
        self.assertEqual(parsed.rules[0].action, "allow")
        self.assertEqual(parsed.rules[0].source, "10.0.0.0/24")

    def test_public_ipv4_alias_is_any(self):
        self.assertEqual(self.parse(rule(source="0.0.0.0/0")).rules[0].source, "any")

    def test_public_ipv6_alias_is_any(self):
        self.assertEqual(self.parse(rule(source="::/0")).rules[0].source, "any")

    def test_port_list_and_range_are_supported(self):
        parsed = self.parse(rule(port="80,443,8000:8010"))
        self.assertEqual(parsed.rules[0].port, "80,443,8000-8010")

    def test_reject_is_normalized_to_deny(self):
        self.assertEqual(self.parse(rule(action="reject")).rules[0].action, "deny")

    def test_invalid_action_is_rejected(self):
        with self.assertRaisesRegex(InvalidFirewallConfigError, "unsupported action"):
            self.parse(rule(action="permit-ish"))

    def test_invalid_address_is_rejected(self):
        with self.assertRaisesRegex(InvalidFirewallConfigError, "must be an IP"):
            self.parse(rule(source="the-internet"))

    def test_invalid_port_is_rejected(self):
        with self.assertRaisesRegex(InvalidFirewallConfigError, "outside valid range"):
            self.parse(rule(port="70000"))

    def test_enabled_must_be_boolean(self):
        with self.assertRaisesRegex(InvalidFirewallConfigError, "must be boolean"):
            self.parse(rule(enabled="false"))

    def test_duplicate_ids_are_rejected(self):
        data = {"rules": [rule(), rule(name="Duplicate")]}
        with self.assertRaisesRegex(InvalidFirewallConfigError, "Duplicate rule_id"):
            self.parser.parse_text(json.dumps(data), "json")

    def test_empty_rule_list_is_rejected(self):
        with self.assertRaisesRegex(InvalidFirewallConfigError, "at least one rule"):
            self.parser.parse_text('{"rules": []}', "json")


class IptablesParserTests(unittest.TestCase):
    def setUp(self):
        self.parser = FirewallConfigParser()

    def test_parses_iptables_save_policy_and_rule(self):
        text = "*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp -s 10.0.0.0/24 --dport 22 -j ACCEPT\nCOMMIT"
        parsed = self.parser.parse_text(text)
        self.assertEqual(parsed.source_format, "iptables-save")
        self.assertEqual(len(parsed.rules), 2)
        self.assertEqual(parsed.rules[0].kind, "policy")
        self.assertEqual(parsed.rules[1].port, "22")

    def test_parses_command_style_policy(self):
        parsed = self.parser.parse_text("-P INPUT DROP\n-A INPUT -p tcp --dport 443 -j ACCEPT")
        self.assertEqual(parsed.rules[0].action, "deny")

    def test_parses_state_and_interface(self):
        parsed = self.parser.parse_text(
            "-A INPUT -i lo -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        )
        parsed_rule = parsed.rules[0]
        self.assertEqual(parsed_rule.in_interface, "lo")
        self.assertEqual(parsed_rule.connection_states, ("ESTABLISHED", "RELATED"))

    def test_negated_matches_fail_closed(self):
        with self.assertRaisesRegex(InvalidFirewallConfigError, "Negated"):
            self.parser.parse_text("-A INPUT ! -s 10.0.0.0/8 -j ACCEPT")

    def test_unsupported_protocol_is_not_broadened_to_any(self):
        for protocol in ("gre", "esp", "47", "typo"):
            with self.subTest(protocol=protocol):
                with self.assertRaisesRegex(InvalidFirewallConfigError, "Unsupported iptables protocol"):
                    self.parser.parse_text(f"-A INPUT -p {protocol} -j ACCEPT")

    def test_auto_detection_rejects_unrecognized_text(self):
        with self.assertRaisesRegex(InvalidFirewallConfigError, "No supported"):
            self.parser.parse_text("this is not a firewall configuration")


if __name__ == "__main__":
    unittest.main()
