"""Validated parsers for FirewallGuard JSON and ``iptables-save`` inputs."""

from __future__ import annotations

import ipaddress
import json
import re
import shlex
from pathlib import Path

from audit_engine.models import FirewallRule, ParsedConfiguration


class InvalidFirewallConfigError(ValueError):
    """Raised when a firewall configuration is malformed or unsupported."""


_ACTION_ALIASES = {
    "accept": "allow",
    "allow": "allow",
    "drop": "deny",
    "reject": "deny",
    "deny": "deny",
}
_PROTOCOLS = {"any", "tcp", "udp", "icmp", "icmpv6", "all"}
_ANY_ADDRESSES = {"*", "all", "any", "0.0.0.0/0", "::/0"}
_PORT_PART = re.compile(r"^(\d{1,5})(?:[:-](\d{1,5}))?$")


def normalize_address(value: object, field_name: str) -> str:
    text = str(value).strip().lower()
    if text in _ANY_ADDRESSES:
        return "any"
    try:
        if "/" in text:
            return str(ipaddress.ip_network(text, strict=False))
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise InvalidFirewallConfigError(
            f"{field_name} must be an IP address, CIDR, or 'any': {value!r}"
        ) from exc


def normalize_ports(value: object, protocol: str) -> str:
    if protocol in {"icmp", "icmpv6"}:
        return "any"
    text = str(value).strip().lower().replace(" ", "")
    if text in {"*", "all", "any"}:
        return "any"
    normalized: list[str] = []
    for part in text.split(","):
        match = _PORT_PART.fullmatch(part)
        if not match:
            raise InvalidFirewallConfigError(
                f"Invalid port expression {value!r}; use 1-65535, a range, a list, or 'any'."
            )
        start = int(match.group(1))
        end = int(match.group(2) or start)
        if not (1 <= start <= end <= 65535):
            raise InvalidFirewallConfigError(f"Port outside valid range: {part!r}")
        normalized.append(str(start) if start == end else f"{start}-{end}")
    return ",".join(normalized)


class FirewallConfigParser:
    """Parse and normalize supported firewall configuration formats."""

    REQUIRED_FIELDS = {
        "rule_id",
        "name",
        "action",
        "protocol",
        "source",
        "destination",
        "port",
        "enabled",
    }

    def parse_file(
        self, filepath: str | Path, input_format: str = "auto"
    ) -> ParsedConfiguration:
        path = Path(filepath)
        if not path.is_file():
            raise InvalidFirewallConfigError(f"Configuration file not found: {path}")
        try:
            text = path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError as exc:
            raise InvalidFirewallConfigError("Configuration must be UTF-8 text.") from exc
        return self.parse_text(text, input_format=input_format)

    def parse_text(self, text: str, input_format: str = "auto") -> ParsedConfiguration:
        if not isinstance(text, str) or not text.strip():
            raise InvalidFirewallConfigError("Configuration is empty.")
        selected = input_format.lower()
        if selected == "auto":
            stripped = text.lstrip()
            selected = "json" if stripped.startswith(("{", "[")) else "iptables"
        if selected == "json":
            return self._parse_json_text(text)
        if selected in {"iptables", "iptables-save"}:
            return self._parse_iptables(text)
        raise InvalidFirewallConfigError(
            f"Unsupported input format {input_format!r}; choose auto, json, or iptables."
        )

    def parse_data(self, data: object) -> list[FirewallRule]:
        """Backward-compatible JSON object parser used by integrations."""
        return list(self._parse_json_data(data).rules)

    def _parse_json_text(self, text: str) -> ParsedConfiguration:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise InvalidFirewallConfigError(
                f"Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
            ) from exc
        return self._parse_json_data(data)

    def _parse_json_data(self, data: object) -> ParsedConfiguration:
        if not isinstance(data, dict):
            raise InvalidFirewallConfigError("JSON configuration must be an object.")
        raw_rules = data.get("rules")
        if not isinstance(raw_rules, list):
            raise InvalidFirewallConfigError("JSON field 'rules' must be a list.")
        if not raw_rules:
            raise InvalidFirewallConfigError("Configuration must contain at least one rule.")

        rules: list[FirewallRule] = []
        seen_ids: set[str] = set()
        for index, raw_rule in enumerate(raw_rules, start=1):
            rule = self._parse_json_rule(raw_rule, index)
            if rule.rule_id in seen_ids:
                raise InvalidFirewallConfigError(f"Duplicate rule_id: {rule.rule_id}")
            seen_ids.add(rule.rule_id)
            rules.append(rule)
        return ParsedConfiguration(tuple(rules), "json")

    def _parse_json_rule(self, raw_rule: object, index: int) -> FirewallRule:
        if not isinstance(raw_rule, dict):
            raise InvalidFirewallConfigError(f"Rule {index} must be an object.")
        missing = sorted(self.REQUIRED_FIELDS - raw_rule.keys())
        if missing:
            raise InvalidFirewallConfigError(
                f"Rule {index} is missing required fields: {', '.join(missing)}"
            )
        if type(raw_rule["enabled"]) is not bool:
            raise InvalidFirewallConfigError(f"Rule {index} field 'enabled' must be boolean.")

        rule_id = str(raw_rule["rule_id"]).strip()
        name = str(raw_rule["name"]).strip()
        if not rule_id or not name:
            raise InvalidFirewallConfigError(f"Rule {index} requires non-empty rule_id and name.")

        raw_action = str(raw_rule["action"]).strip().lower()
        if raw_action not in _ACTION_ALIASES:
            raise InvalidFirewallConfigError(
                f"Rule {rule_id} has unsupported action {raw_action!r}."
            )
        protocol = str(raw_rule["protocol"]).strip().lower()
        if protocol not in _PROTOCOLS:
            raise InvalidFirewallConfigError(
                f"Rule {rule_id} has unsupported protocol {protocol!r}."
            )
        protocol = "any" if protocol == "all" else protocol

        chain = str(raw_rule.get("chain", "UNSPECIFIED")).strip().upper()
        direction = str(raw_rule.get("direction", self._direction_for_chain(chain))).lower()
        return FirewallRule(
            rule_id=rule_id,
            name=name,
            action=_ACTION_ALIASES[raw_action],
            protocol=protocol,
            source=normalize_address(raw_rule["source"], f"Rule {rule_id} source"),
            destination=normalize_address(
                raw_rule["destination"], f"Rule {rule_id} destination"
            ),
            port=normalize_ports(raw_rule["port"], protocol),
            enabled=raw_rule["enabled"],
            description=str(raw_rule.get("description", "")).strip(),
            chain=chain,
            direction=direction,
            in_interface=str(raw_rule.get("in_interface", "any")).strip(),
            out_interface=str(raw_rule.get("out_interface", "any")).strip(),
            connection_states=tuple(
                state.strip().upper()
                for state in str(raw_rule.get("connection_states", "")).split(",")
                if state.strip()
            ),
            raw=json.dumps(raw_rule, sort_keys=True),
            line_number=index,
        )

    def _parse_iptables(self, text: str) -> ParsedConfiguration:
        rules: list[FirewallRule] = []
        warnings: list[str] = []
        table = "filter"
        for line_number, raw_line in enumerate(text.splitlines(), start=1):
            line = raw_line.strip()
            if not line or line.startswith("#") or line == "COMMIT":
                continue
            if line.startswith("*"):
                table = line[1:].strip().lower()
                continue
            if line.startswith(":"):
                policy_tokens = line.split()
                if len(policy_tokens) >= 2:
                    chain = policy_tokens[0][1:].upper()
                    target = policy_tokens[1].upper()
                    rules.append(self._policy_rule(chain, target, raw_line, line_number, table))
                    continue
            try:
                tokens = shlex.split(line)
            except ValueError as exc:
                raise InvalidFirewallConfigError(
                    f"Invalid iptables syntax on line {line_number}: {exc}"
                ) from exc
            if len(tokens) >= 3 and tokens[0] == "-P":
                chain, target = tokens[1].upper(), tokens[2].upper()
                rules.append(self._policy_rule(chain, target, raw_line, line_number, table))
                continue
            if len(tokens) >= 3 and tokens[0] == "-A":
                rules.append(self._parse_iptables_rule(tokens, raw_line, line_number, table))
                continue
            if line.startswith("-N "):
                continue
            warnings.append(f"Line {line_number} was not analyzed: {line[:80]}")

        if not rules:
            raise InvalidFirewallConfigError(
                "No supported iptables rules found. Provide iptables-save output containing -P or -A lines."
            )
        return ParsedConfiguration(tuple(rules), "iptables-save", tuple(warnings))

    def _parse_iptables_rule(
        self, tokens: list[str], raw_line: str, line_number: int, table: str
    ) -> FirewallRule:
        chain = tokens[1].upper()
        protocol = self._option(tokens, ("-p", "--protocol"), "any").lower()
        protocol = "any" if protocol == "all" else protocol
        if protocol not in _PROTOCOLS:
            protocol = "any"
        source = normalize_address(self._option(tokens, ("-s", "--source"), "any"), "source")
        destination = normalize_address(
            self._option(tokens, ("-d", "--destination"), "any"), "destination"
        )
        port_value = self._option(
            tokens,
            ("--dport", "--destination-port", "--dports"),
            "any",
        )
        target = self._option(tokens, ("-j", "--jump"), "UNSPECIFIED").upper()
        action = _ACTION_ALIASES.get(target.lower(), "jump")
        comment = self._option(tokens, ("--comment",), "")
        in_interface = self._option(tokens, ("-i", "--in-interface"), "any")
        out_interface = self._option(tokens, ("-o", "--out-interface"), "any")
        states = self._option(tokens, ("--ctstate", "--state"), "")
        if "!" in tokens:
            raise InvalidFirewallConfigError(
                f"Negated iptables matches are not yet supported (line {line_number})."
            )
        return FirewallRule(
            rule_id=f"IPT-{line_number:04d}",
            name=comment or f"{target} {protocol.upper()} in {chain}",
            action=action,
            protocol=protocol,
            source=source,
            destination=destination,
            port=normalize_ports(port_value, protocol),
            enabled=True,
            description=comment,
            chain=chain,
            direction=self._direction_for_chain(chain),
            table=table,
            in_interface=in_interface,
            out_interface=out_interface,
            connection_states=tuple(
                state.strip().upper() for state in states.split(",") if state.strip()
            ),
            raw=raw_line,
            line_number=line_number,
        )

    @staticmethod
    def _policy_rule(
        chain: str, target: str, raw_line: str, line_number: int, table: str
    ) -> FirewallRule:
        return FirewallRule(
            rule_id=f"IPT-{line_number:04d}",
            name=f"Default {chain} policy",
            action=_ACTION_ALIASES.get(target.lower(), "jump"),
            protocol="any",
            source="any",
            destination="any",
            port="any",
            enabled=True,
            description=f"Default chain policy is {target}.",
            chain=chain,
            direction=FirewallConfigParser._direction_for_chain(chain),
            kind="policy",
            table=table,
            raw=raw_line,
            line_number=line_number,
        )

    @staticmethod
    def _option(tokens: list[str], names: tuple[str, ...], default: str) -> str:
        for name in names:
            if name in tokens:
                index = tokens.index(name)
                if index + 1 >= len(tokens):
                    raise InvalidFirewallConfigError(f"Missing value after {name}.")
                return tokens[index + 1]
        return default

    @staticmethod
    def _direction_for_chain(chain: str) -> str:
        return {"INPUT": "inbound", "OUTPUT": "outbound", "FORWARD": "forward"}.get(
            chain.upper(), "unknown"
        )
