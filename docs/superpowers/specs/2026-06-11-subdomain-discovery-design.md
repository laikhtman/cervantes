# Subdomain discovery for targets — design

## Goal
Let operators connect MerkleMap and SecurityTrails API keys and discover subdomains
for domain-style targets, creating the discovered subdomains as new targets. Surfaced
from the global `/targets` management page.

## Decisions (agreed)
- **Key storage:** `appsettings.json`, matching every existing integration (Jira/LDAP/CVE).
  Plaintext, set at deploy time, no in-app editing UI.
- **Trigger:** both a manual button (on `/targets`) and an opt-in scheduled Hangfire job.
- **Discovered subdomains:** auto-created as `Hostname` targets, deduped against existing
  target names in the same project.

## Configuration (`SubdomainConfiguration` in appsettings.json)
```jsonc
"SubdomainConfiguration": {
  "Enabled": false,
  "MerkleMapApiKey": "",
  "SecurityTrailsApiKey": "",
  "MerkleMapBaseUrl": "https://api.merklemap.com",
  "SecurityTrailsBaseUrl": "https://api.securitytrails.com/v1",
  "ScheduledEnabled": false,
  "Schedule": "0 3 * * *",
  "MaxMerkleMapPages": 20
}
```
`ISubdomainConfiguration` + POCO in `Cervantes.IFR/Subdomain/`, registered as a singleton in
`ExternalServiceExtensions.AddSubdomainServices`.

## Provider APIs (verified against live docs)
- **MerkleMap:** `GET {base}/v1/search?query={domain}&page={n}&type=wildcard`,
  header `Authorization: Bearer {key}`. Response `{ "count": N, "results": [ { "hostname": "..." } ] }`.
  Paginated (0-based); cap at `MaxMerkleMapPages`.
- **SecurityTrails:** `GET {base}/domain/{domain}/subdomains?children_only=false`,
  header `apikey: {key}`. Response `{ "subdomains": ["www","mail", ...] }` — **bare prefixes**;
  hostname = `prefix + "." + domain`. Parser treats a value as a prefix unless it already
  ends with the domain.

## Service (`Cervantes.IFR/Subdomain/SubdomainService.cs`, typed `HttpClient`)
- `EnumerateAsync(domain)` — query both providers that have a key; merge + dedupe (lowercased,
  must end in the domain). A provider failure is logged and skipped; the other still returns.
- `DiscoverAndImportAsync(targetId, userId)` — resolve the target's domain (URL → host, Hostname →
  name), enumerate, create each new subdomain as a `Hostname` target in the same project, deduped.
  Returns `{ Status, Domain, Found, Created, Skipped }`. Uses `ITargetManager`, exactly like
  `NmapParser` creates targets today.
- `RunScheduledAsync()` — Hangfire body: snapshot eligible targets (URL/Hostname) at start, run
  the same import for each, attributing created targets to the source target's owner.

Only `URL` and `Hostname` targets are eligible. IP/CIDR/Binary are skipped.

## Web
- `TargetController`: `POST /api/Target/{targetId}/subdomains/discover`, `[HasPermission(TargetsAdd)]`,
  returns the result counts. Inject `ISubdomainConfiguration` to expose an `Enabled` flag.

## UI (`/targets`)
- A **"Discover subdomains"** toolbar button, visible only when `Enabled` and ≥1 eligible target is
  selected. Runs discovery on the selection, refreshes the grid, shows a result snackbar.

## Scheduled job (`Program.cs`)
- When `Enabled && ScheduledEnabled`, register a `RecurringJob` on the configured cron calling
  `RunScheduledAsync`, beside the existing CVE/log jobs.

## Out of scope (YAGNI)
No in-app key editing, no new permission, no DB schema change, no per-provider toggles, no retry/
backoff beyond skipping a failed provider. `ScheduledEnabled` defaults to `false` (nightly job opt-in).
