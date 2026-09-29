# Security Policy

## Supported Version

Only the current `main` branch is supported with security fixes.

## Reporting a Vulnerability

Do not include live credentials, personal data, or destructive reproduction steps in a public issue. Prefer GitHub's private vulnerability-reporting or Security Advisory flow when it is enabled for this repository. Otherwise, contact the repository owner privately and provide the smallest safe reproduction.

## Secrets

- Never commit `.env`, the Sentinel agent configuration, OpenAI keys, App Attest private material, dashboard passwords, or ingestion secrets.
- Store Render secrets as secret environment variables.
- Keep the macOS agent configuration root-owned with mode `600`.
- Rotate a credential immediately if it appears in a commit, log, screenshot, support message, or shell history.

## Defensive Scope

Security testing must remain within systems the tester owns or is explicitly authorized to assess. Use bounded, non-destructive validation and avoid publishing details that would enable abuse before remediation is available.
