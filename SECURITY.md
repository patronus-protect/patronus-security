# Security Policy

## Scope and threat model

Patronus Security is a probabilistic risk **classifier**, not a guarantee. Before relying on
it, read the [Threat model](https://github.com/patronus-protect/patronus-security/blob/main/docs/concepts/threat-model.md), which states the trust boundaries
it sits on, the assumptions it makes, and — importantly — what it does **not** defend against.
This policy covers vulnerabilities in the library itself (the Rust core, the Python bindings,
and asset handling).

## Supported Versions

This project is pre-1.0. Security fixes are expected to target the latest released version.

## Reporting a Vulnerability

Do not disclose suspected vulnerabilities publicly before maintainers have had a chance to investigate.

Report vulnerabilities privately to team@patronus.studio.

After publishing on GitHub, maintainers should also enable GitHub Security Advisories for coordinated disclosure.

Please include:

- affected version or commit;
- minimal reproduction steps;
- expected and observed behavior;
- impact assessment;
- whether model assets or downloaded files are involved.
