# Security Policy

If you find a vulnerability in hugmesh-tube-bff-api, or in any other HugMesh
repository, report it privately. Do not open a public issue.

Use GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
on this repository (Security tab, then "Report a vulnerability"), or open a
draft security advisory. We will acknowledge your report as quickly as we can
and agree a fix and disclosure timeline with you.

Keep exploit details out of public issues, pull requests and discussions until
a fix has shipped.

## Supported versions

Only the current `main` branch and the newest released image are supported.
Fixes are not back-ported to older versions.

## Scope

In scope: this service's code, its configuration defaults, its container image
(`Dockerfile`) and the download worker under `downloader/`. How the service is
authenticated and authorised is described in `README.md`.

The test-only keys in `src/main/resources/application-test.yml` are placeholder
values for the test profile and are not secrets. A report that only points at
them is not a vulnerability.
