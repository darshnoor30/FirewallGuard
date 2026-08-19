# Security policy

## Supported version

Security fixes are maintained for the current `2.x` release line.

## Reporting a vulnerability

Please use GitHub's **Report a vulnerability** private security-advisory flow. Do not disclose a
suspected vulnerability in a public issue until a fix or coordinated disclosure plan is available.

Include the affected version, reproducible steps, impact, and a minimal sanitized input. Never attach
production firewall rules, credentials, private keys, tokens, internal hostnames, or customer data.

## Safe deployment

- Run the container as the included non-root user.
- Place authentication and TLS in front of any internet-accessible deployment.
- Keep the 2 MiB dashboard upload limit or reduce it for the environment.
- Do not log raw uploaded configurations.
- Retain in-memory report generation; do not switch to a shared static report path.
- Apply network egress restrictions and dependency updates through normal change control.

FirewallGuard is a defensive configuration-analysis tool. Use it only with authorization.
