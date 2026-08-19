# Contributing

1. Create a focused branch and describe the security behavior being changed.
2. Add regression tests for both positive detection and false-positive resistance.
3. Run `python -m unittest discover -s tests -v`.
4. Run the vulnerable and hardened CLI samples.
5. Update the detector catalog, standards mapping, and limitations when behavior changes.

New detectors must provide evidence, remediation, a documented risk weight, and at least one negative
test. New standards references must identify the exact version and source, and must not claim full
compliance from a partial technical check.
