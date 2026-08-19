# Selected standards alignment

FirewallGuard does **not** calculate organization-wide compliance. It tests a small, explicit set of
technical configuration patterns and reports `GAP` or `NO_GAP_DETECTED` for those patterns only.

| Framework | Selected outcome/safeguard | Implemented evidence |
|---|---|---|
| NIST CSF 2.0 | `PR.IR-01` - networks and environments protected from unauthorized logical access and usage | Unrestricted allows; public administrative, database, or SMB services; cleartext services; all-port rules |
| NIST CSF 2.0 | `PR.PS-01` - configuration management practices established and applied | Duplicate, shadowed, and disabled-rule lifecycle indicators |
| CIS Controls v8.1 | `4.4` - implement and manage a firewall on servers | Exposure, cleartext, all-port, and unrestricted allow checks |
| CIS Controls v8.1 | `12.2` - establish and maintain a secure network architecture | Unrestricted and all-port access scope |
| CIS Controls v8.1 | `12.3` - securely manage network infrastructure | Management/database/SMB exposure, cleartext services, duplication, shadowing, and disabled-rule hygiene |

## Outcome meaning

- `GAP`: at least one finding is mapped to the implemented technical check.
- `NO_GAP_DETECTED`: no mapped finding was produced by that check.
- `ACTION_REQUIRED`: at least one selected check for the framework is flagged.
- `NO_GAPS_DETECTED`: all selected checks passed.

None of these outcomes assess governance, people, process, physical safeguards, asset inventory,
monitoring effectiveness, incident response, legal obligations, or the complete framework.

## Authoritative references

- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [CIS Control 4: Secure Configuration of Enterprise Assets and Software](https://www.cisecurity.org/controls/secure-configuration-of-enterprise-assets-and-software)
- [CIS Control 12: Network Infrastructure Management](https://www.cisecurity.org/controls/network-infrastructure-management)
- [MITRE ATT&CK Remote Services](https://attack.mitre.org/techniques/T1021/)

ATT&CK references in findings are possible defensive relationships. A static firewall rule does not
prove technique execution, intent, valid-account use, exploitation, or compromise.
