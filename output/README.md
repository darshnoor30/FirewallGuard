# Generated evidence

The included `firewall_audit_report.json` and `pdf/firewall_audit_report.pdf` were generated from
`sample_configs/vulnerable_firewall.json`. They demonstrate the report format against intentionally
vulnerable lab data; they are not results from a production environment.

Regenerate both files with:

```bash
python main.py sample_configs/vulnerable_firewall.json \
  --json-output output/firewall_audit_report.json \
  --pdf output/pdf/firewall_audit_report.pdf
```
