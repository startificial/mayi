# Third-party software notices and source access

Mayi's current Go module uses the standard library only. No MPL-covered component is linked into Mayi yet. The protocol candidates are being evaluated in P0. This notice does not assign a license to Mayi's first-party source.

The complete Mozilla Public License 2.0 text is retained at [tools/license-evidence/MPL-2.0.txt](tools/license-evidence/MPL-2.0.txt). For every admitted MPL component, the table below must identify the exact unmodified version and an accessible source archive. That source remains available under MPL 2.0, including its notices and recipients' rights. Modifications to covered files must also be made available under MPL 2.0; an unmodified upstream link is insufficient for modified files.

| Admitted MPL component and version | Source code under MPL 2.0 |
| --- | --- |
| None yet | No MPL dependency has been admitted. |

Distributions must include this notice, the license texts and copyright/NOTICE material for every distributed dependency, and working access to the corresponding MPL source. Copying this document into the repository does not prove that a binary/container distribution includes those materials. Add and test release packaging before distributing binaries. Preserve source availability; use a maintained source mirror if an upstream URL becomes unavailable.

The compiler and reviewed GitHub Actions are recorded in [tools/dependencies.json](tools/dependencies.json). Complete action-bundle license and notice evidence is retained under [tools/license-evidence](tools/license-evidence). Exact module approvals, license evidence hashes and source-access fields are checked by CI. Generated source, forks and copied third-party files require their own review.

See the [dependency policy](docs/dependency-policy.md), [MPL license](https://www.mozilla.org/MPL/2.0/), and [Mozilla's distribution FAQ](https://www.mozilla.org/MPL/2.0/FAQ/#q8-i-want-to-distribute-outside-my-organization-executable-programs-or-libraries-that-i-have-compiled-from-someone-elses-unchanged-mpl-licensed-source-code-either-standalone-or-part-of-a-larger-work-what-do-i-have-to-do).
