# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems in this toolkit. Use GitHub's
"Report a vulnerability" (private security advisory) feature on the repository, or contact the maintainer through
the details on the profile page. Include the affected version, reproduction steps and impact.

Expect an acknowledgement within a few days; this is a volunteer project and no SLA is offered.

## Scope

In scope: path traversal / unsafe file writes, command or rule injection, unsafe parsing of untrusted evidence,
secret leakage in reports, manifest verification bypasses, and workflow/supply-chain weaknesses in this repository.

Out of scope: limitations that are documented in `docs/security-and-limitations.md` (for example, live collection
is not forensic imaging, and a manifest stored beside evidence is not tamper-proof).

## Safe use

Collected evidence can contain personal and organisational data. Use the toolkit only on systems you are authorised
to investigate, store evidence with restrictive permissions, and never commit real evidence to version control.
