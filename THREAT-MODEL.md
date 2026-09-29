# Daybreak Sentinel Threat Model

## Protected Assets

- Render ingestion and dashboard credentials
- Integrity of Mac posture reports
- Availability and cost controls of the existing StudyBuddy API
- Student learning profiles and App Attest state
- Privacy of the Mac owner

## Trust Boundaries

1. The Mac agent reads a root-only local configuration.
2. The agent sends a small allowlisted JSON document to Render over HTTPS and polls outward for allowlisted control requests.
3. The Sentinel API authenticates the exact request body with HMAC-SHA-256, a five-minute timestamp window, and a one-time nonce.
4. The dashboard uses separate credentials and signed anti-CSRF tokens for acknowledgements, on-demand AI review, and `scan_now` requests.
5. Sentinel data is stored in its own directory under the Render persistent disk.

## Main Threats and Mitigations

| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Forged reports | 32+ character HMAC secret and constant-time signature comparison | A stolen ingestion secret can submit false reports until rotated |
| Replayed reports | Signed timestamp plus bounded nonce cache | A restart can clear the short replay cache if storage recovery fails |
| Dashboard guessing | Separate 12+ character password, HTTPS, constant-time comparison | Basic authentication does not provide MFA or account lockout |
| Cross-site dashboard actions | Short-lived signed anti-CSRF token, no security-route CORS, and same-origin forms | A compromised authenticated browser remains in scope |
| Telemetry leakage | Fixed check allowlist, bounded detail strings, no host identifiers by default | The chosen pseudonymous agent ID and posture still constitute security data |
| Dashboard injection | Strict schema, constrained values, HTML escaping, CSP, no scripts | Browser and dependency vulnerabilities remain external risks |
| Remote-control abuse | Outbound polling and a strict `scan_now` allowlist; no command text, arguments, shell, or device mutation | A stolen agent secret can request or submit data until rotated |
| Model misuse or leakage | AI is user-triggered, receives no device ID or raw telemetry, cannot call tools, and output is escaped advisory text | Sanitized posture data leaves Render for the configured model when requested |
| Storage exhaustion | 64 KiB request cap and bounded event retention | Valid signed senders can still consume request capacity |
| Cross-feature access | Separate authentication and storage from StudyBuddy App Attest routes | Both features still share one Node process and Render service |

## Non-Goals

Daybreak Sentinel does not guarantee prevention of compromise, replace backups or endpoint protection, inspect traffic during true system sleep, or establish that an `unknown` check is malicious.
