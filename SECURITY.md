# Security policy

Mayi is an experimental development preview. There are no published releases or production-supported versions. Review [SUPPORT.md](SUPPORT.md) and [the current implementation status](docs/p2-core-authorization.md) before evaluating it. Security reports are welcome during development; accepting reports does not establish production readiness.

## Report a vulnerability privately

Use [GitHub's private vulnerability reporting form](https://github.com/startificial/mayi/security/advisories/new), also available under **Security → Advisories → Report a vulnerability**. A GitHub account is required. The report is handled privately through GitHub's advisory workflow; keep follow-up details in that conversation.

Do not put suspected vulnerability details, exploit code, credentials or customer data in a public issue, pull request or discussion. If the private form is unavailable, open an issue containing only a request for a private security contact, with no technical details, and wait for maintainers to establish a private channel. No separate security email address is currently published; do not send reports to commit-author or GitHub noreply addresses.

Include the information you can safely provide:

- Affected commit SHA or release, Go version, operating system and relevant configuration with secrets removed.
- The affected operation and security boundary, expected behavior and observed behavior.
- A minimal reproduction on a local or otherwise authorized test deployment, using synthetic identities and objects.
- Impact and preconditions: for example, foreign-tenant access, grant expansion, replay, credential disclosure or denial of service.
- Sanitized timestamps/request IDs and a suggested mitigation, if known. Share only the minimum necessary evidence; do not upload raw tokens, cookies, signing material, personal data or database dumps.

Reports against older commits are welcome, especially when they may affect current code. Do not delay a report because you cannot reproduce it on `main`.

## Response and coordinated disclosure

Repository maintainers with security-advisory access triage reports. Our targets are an acknowledgment within **7 calendar days**, an initial assessment within **14 calendar days**, and a progress update at least every **14 calendar days** while a confirmed report remains open. These are best-effort community targets, not a staffed incident-response SLA or a guaranteed fix date. If acknowledgment is overdue, follow up in the same private report.

Maintainers confirm affected versions and severity, reproduce the issue, coordinate a fix and regression tests privately where practical, and agree on disclosure timing with the reporter. We aim to publish an advisory and remediation guidance when a fix or useful mitigation is available, ordinarily within 90 calendar days of the initial report. Discuss timeline changes explicitly; no indefinite confidentiality commitment is requested. Reports that are not vulnerabilities receive an explanation rather than a silent closure. Reporter credit is offered with their consent; a CVE may be requested when appropriate.

Fixes currently target `main`. There is no promise of backports, long-term support or remediation for every historical commit. If a report affects upstream components, coordinate with the upstream project and retain only the necessary participants and evidence. Do not publish an upstream zero-day merely to open a public Mayi issue.

## Scope and responsible testing

Relevant areas include protocol parsing and authentication, tenant isolation, grants and typed object/action ceilings, credentials/replay/revocation, signing trust, browser sessions/embedding, constrained egress, persistence transactions, audit integrity and repository-selected dependency/build controls. A planned feature or incomplete requirement is documented as such; an exploitable boundary failure in the preview is still worth reporting.

Test only systems you own or have explicit permission to test. Use local synthetic data, stop if real user data or credentials become accessible, and report the minimum evidence privately. Repository publication does not authorize testing someone else's deployment. No paid bug-bounty program or reward is currently offered.

## Maintainer procedure

1. Check private-report notifications regularly and acknowledge the report with a next-update date. Keep sensitive details out of public CI logs and issues.
2. Record affected commits/versions, impact, reproduction and mitigation in the private advisory. Invite only the collaborators required to resolve it.
3. Add regression evidence for the actual failure, including foreign-tenant, call-order, replay/concurrency or recovery cases as applicable. Follow [AGENTS.md](AGENTS.md); do not bypass architecture or dependency admission to rush a fix.
4. Coordinate fix publication, release/commit guidance, advisory details and reporter credit. Explain whether operators must rotate credentials, revoke grants or perform other containment; do not imply a source update alone repairs compromised state.
5. Verify the private-report setting and this policy before each preview/release. Update the supported-version information and known limitations at the same time. Publishing a policy alone does not verify notification delivery or response performance.
