# Changelog

## 2.0.0 - 2026-08-19

- Added validated JSON and real `iptables-save` parsing.
- Added IPv4/IPv6 normalization, port lists/ranges, chain policy, interface, and state awareness.
- Corrected disabled-rule, deny-rule, loopback, and established/related false positives.
- Added public administration/database/SMB, cleartext, broad-port, duplicate, and shadowed-rule checks.
- Replaced hard-coded CVSS values with a documented project-specific posture model.
- Replaced misleading compliance percentages with scoped NIST CSF 2.0/CIS Controls v8.1 checks.
- Corrected MITRE ATT&CK sub-techniques and labelled them as contextual relationships.
- Added a package-installable CLI, severity gates, guided Streamlit dashboard, and in-memory exports.
- Added professional PDF/JSON/CSV evidence, input fingerprinting, and explicit limitations.
- Added 44 automated tests, 91% measured core/report line coverage, CI, Docker, and complete docs.
