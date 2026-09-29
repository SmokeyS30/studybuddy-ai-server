# Daybreak Sentinel

Daybreak Sentinel is a defensive security layer hosted by the existing StudyBuddy Render service. It gives the owner a mobile control center without opening an inbound port or remote shell on the Mac.

## Components

- **Sentinel Agent:** runs read-only macOS posture checks, integrates with the local Privacy Shield, and sends an allowlisted report.
- **Sentinel API:** verifies an HMAC signature, timestamp, and one-time nonce before accepting a report.
- **Sentinel Dashboard:** displays devices, findings, history, AI-assisted reviews, and allowlisted scan requests at `/security` behind HTTPS and HTTP Basic authentication.

The control plane can request only `scan_now`. The Mac polls outward over HTTPS, performs the same read-only checks, and reports back. There is no server-initiated connection, arbitrary command execution, or remote shell. Sentinel does not upload IP addresses, usernames, process names, executable paths, filenames, browser data, or file contents.

## Checks

The macOS agent currently reports:

- Application Firewall
- Firewall stealth mode
- FileVault
- Gatekeeper
- System Integrity Protection
- Automatic update checking
- Time Machine backup availability
- Remote Login status
- Mullvad connection state
- Privacy Shield freshness and state
- Count-only listener-baseline changes

`unknown` means the check could not be verified. It is not treated as proof of compromise.

## Configure Render

The root `render.yaml` declares the required variables. Add secret values in the Render dashboard before using Sentinel:

1. Generate an ingestion secret locally:

   ```bash
   openssl rand -hex 32
   ```

2. Generate a separate dashboard password:

   ```bash
   openssl rand -base64 24
   ```

3. In the `studybuddy-ai-server` Render service, set:

   - `SECURITY_INGEST_SECRET` to the first value.
   - `SECURITY_DASHBOARD_PASSWORD` to the second value.
   - Keep `SECURITY_DASHBOARD_USERNAME=sentinel`, or choose a different username in both Render and your password manager.
   - Keep `SECURITY_AI_ENABLED=true` only if authenticated, on-demand AI summaries are wanted. AI review uses the existing OpenAI key and is never automatic.

4. Keep both secrets out of GitHub, screenshots, support messages, and shell history.

When the updated service is deployed, open:

```text
https://studybuddy-ai-server-m5zi.onrender.com/security
```

The browser will request the dashboard username and password. Save them in a password manager if desired.

## Configure a Mac Agent

Node.js 18 or newer is required. The following files are templates; review their paths before installing anything as root.

1. Copy the agent and private configuration into a root-controlled directory:

   ```bash
   sudo mkdir -p "/Library/Application Support/DaybreakSentinel"
   sudo install -o root -g wheel -m 755 agent/macos/daybreak-sentinel-agent.mjs "/Library/Application Support/DaybreakSentinel/daybreak-sentinel-agent.mjs"
   sudo install -o root -g wheel -m 600 agent/macos/agent.conf.example "/Library/Application Support/DaybreakSentinel/agent.conf"
   ```

2. Edit `agent.conf` as root. Use the same ingestion secret configured on Render and choose a non-identifying agent ID such as `personal-mac`. Do not use a serial number, email address, or full name.

3. Verify the report locally without sending it:

   ```bash
   sudo /opt/homebrew/bin/node "/Library/Application Support/DaybreakSentinel/daybreak-sentinel-agent.mjs" --dry-run
   ```

4. Send one signed report:

   ```bash
   sudo /opt/homebrew/bin/node "/Library/Application Support/DaybreakSentinel/daybreak-sentinel-agent.mjs"
   ```

5. Only after both commands work, review `agent/macos/com.daybreak.sentinel.plist.example`. Replace the Node path if `command -v node` reports a different location, validate with `plutil -lint`, then install it as a root-owned LaunchDaemon. The template polls every five minutes for the single allowlisted `scan_now` action and sends a routine posture report no more than once per hour.

True system sleep suspends the agent. A scheduled run may be coalesced after wake; Sentinel does not claim to observe the Mac while it is asleep. Router- or firewall-level monitoring is still required for sleep-time network visibility.

## Dashboard Controls

- **Request fresh scan:** queues only the fixed `scan_now` action. The agent retrieves it during outbound polling and reports completion.
- **Acknowledge:** marks a finding as reviewed; it does not change the Mac.
- **AI review:** sends only the selected report's allowlisted check names, statuses, short generic details, platform, time, and risk score to the configured model. The device ID is excluded. Recommendations are escaped, stored as advisory text, and never executed.

Dashboard actions require the dashboard credentials plus a short-lived signed anti-CSRF token. Agent messages bind the HTTP method, API path, timestamp, nonce, and exact JSON body into the HMAC signature.

## Secret Rotation

If the ingestion secret might be exposed:

1. Generate a new value.
2. Change `SECURITY_INGEST_SECRET` on Render.
3. Update each root-owned agent configuration.
4. Restart or manually run each agent.

If the dashboard password might be exposed, change only `SECURITY_DASHBOARD_PASSWORD` on Render. These credentials are intentionally separate.

## Deliberate Boundaries

- No arbitrary command execution or remote shell; the only device action is `scan_now`.
- No automated firewall changes, process termination, VPN changes, DNS flushing, or file deletion.
- AI analysis is explicit and receives only allowlisted, sanitized posture fields—never raw host telemetry.
- No browser history, cookies, sessions, or profiles are inspected.
- The server retains at most the configured number of sanitized reports, with a default of 500.

Future controls must be individually allowlisted, authenticated, auditable, reversible, and tested before deployment.
