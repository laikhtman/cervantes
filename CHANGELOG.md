# Changelog

All notable changes to this project (this fork) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- CVE subscriptions now support a **maximum EPSS score** filter, completing the EPSS range
  (previously only a minimum existed, so CVEs above the intended EPSS range still matched
  and generated notifications). Adds a `MaxEpssScore` column (EF migration
  `AddMaxEpssScoreToCveSubscription`), viewmodel/validation, controller mapping, a dialog
  field, localization (en/es), and the matching filter in `CveSubscriptionManager`.
  Requires applying the new migration to the database. ([#14](https://github.com/laikhtman/cervantes/issues/14))

### Security

- Fixed missing authorization and IDOR in `ChatController` (AI chat): the controller now
  carries `[ApiController]`, `[Route("api/[controller]")]`, `[Authorize]` and per-action
  `[HasPermission(Permissions.AIChatUsage)]` attributes like its siblings, and every
  per-chat action (`GetMessages`, `EditChat`, `DeleteChat`, and `AddMessage`) verifies the
  chat belongs to the requesting user before acting — previously any authenticated user could
  read, rename, delete, or post into another user's AI chat by id. The constructor's user-claim
  lookup is also null-guarded so unauthenticated requests no longer throw
  `NullReferenceException`. ([#3](https://github.com/laikhtman/cervantes/issues/3))
- Fixed LDAP filter injection on the authentication path: the username from the login form
  (and the user DN used for group lookups) were interpolated into LDAP search filters via
  `string.Format` without escaping. `LdapService` now escapes `\ * ( )` and NUL per RFC 4515
  before building `UserSearchFilter`/`GroupSearchFilter`, preventing filter metacharacters from
  altering query semantics (user enumeration / auth-logic bypass). This also fixes group
  lookups for legitimate DNs containing parentheses. ([#4](https://github.com/laikhtman/cervantes/issues/4))

### Changed

- Destructive actions now ask for confirmation before executing: **Delete All Logs**
  (Admin → Logs), **Delete Personal Data** (account self-deletion), and **Delete Avatar**
  in the profile page previously fired immediately on click. Each now shows a localized
  confirmation dialog (new `confirmDelete*Message` resource keys in en/es; other languages
  fall back to English).

### Changed

- Accessibility improvements in the app chrome: the drawer toggle, global search button,
  language selector, and the five social/documentation icon buttons in both layouts now have
  `aria-label`/`title` attributes (they were icon-only with no accessible name), and the
  logo images in the layouts and login pages now carry alt text.

### Fixed

- Two-factor authentication snackbars in the profile page showed raw resource key names
  (e.g. literally "twoFactorSetError") instead of the translated messages — the existing
  keys are now resolved through the localizer. The Stack Trace and Logger column headers
  in the admin Logs grid are now localized as well (new `stackTrace`/`logger` keys, en/es).
- Client contact e-mails in the Clients grid now link with `mailto:` — previously the raw
  address was used as the href, producing a broken relative link.
- Hardened the global search dialog (app bar) in `MainLayout`/`WorkspaceLayout`: the
  "no results" empty state now actually shows after a search with no hits (previously any
  completed search rendered an empty results list forever, because the visibility check
  only tested lists for `null`); `SearchViewModel` collections are initialized so the dialog
  can never crash on a null list; `SearchController.Search` returns an empty model instead
  of `null`; and a search failure now shows a localized error snackbar instead of crashing
  the whole Blazor circuit.
- Fixed `NullReferenceException` crashes when typing in the search/quick-filter box of the
  **Logs**, **Clients**, **Projects**, and **Users** data grids: the filter lambdas called
  `.Contains` on optional fields that are frequently null (log `Exception`/`StackTrace`/`Url`,
  client contact details, project `Client` navigation property). The Logs row-color function
  had the same issue with `Level`. All accesses are now null-conditional.
- The uploaded **Organization logo** is now actually displayed by the application. The
  navigation drawer headers in `MainLayout` and `WorkspaceLayout` and the `Login`/`LdapLogin`
  pages were hardcoded to the bundled `img/logo*.png` assets and never bound to
  `Organization.ImagePath`, so uploading a logo in Admin → Organization only changed the
  admin-page preview. These views now use the configured logo when one is set and fall back
  to the bundled images (including the dark/light horizontal variants) when not.
  ([#15](https://github.com/laikhtman/cervantes/issues/15))
- Audit records for inserted rows now record the acting user's id. The `EntityState.Added`
  branch in `ApplicationDbContext.BeforeSaveChanges` gated the assignment on
  `auditEntry.UserId != null`, which is always false at that point, so inserts were always
  logged with a null `UserId`. The user id is now read from the HTTP context claims, the same
  way the `Deleted` and `Modified` branches do (this also avoids a crash for entities without
  a `CreatedBy` property). ([#9](https://github.com/laikhtman/cervantes/issues/9))
- Fixed `ChecklistExecutionManager.BulkUpdateStatus` firing `SaveChangesAsync()` without
  awaiting it once per affected checklist: `UpdateChecklistCompletion` is now `async Task`,
  every call (and the save inside it) is awaited, eliminating concurrent operations on the
  same `DbContext` (*"A second operation was started on this context instance…"*) and
  silently lost completion/status updates. ([#13](https://github.com/laikhtman/cervantes/issues/13))
- Hardened the Nmap parser (`NmapParser`) against `NullReferenceException` on valid scan
  output: hosts missing a `status` element, hosts with no usable `address` (now preferring a
  non-MAC address), and ports missing `portid` are skipped gracefully instead of aborting the
  import, and the port number is parsed with `int.TryParse`. ([#11](https://github.com/laikhtman/cervantes/issues/11))
- Hardened the Nessus parser (`NessusParser`) against import-aborting crashes and wrong host
  data: it no longer throws when a `ReportHost` has no `HostProperties`; CVSS scores are parsed
  with `float.TryParse` (a non-numeric `cvss3_base_score` no longer throws `FormatException`);
  and OS / host-IP are now read correctly from `<tag name="…">value</tag>` elements instead of
  non-existent attributes (previously these fields were always blank). ([#10](https://github.com/laikhtman/cervantes/issues/10))
- Fixed WSTG report generation appending footer components into the body builder
  (`sbBody`) instead of the footer builder (`sbFooter`). Footer content was duplicated
  into the body and the `{{FooterComponents}}` placeholder was left empty. ([#12](https://github.com/laikhtman/cervantes/issues/12))
- Fixed a `NullReferenceException` in the EF Core audit interceptor
  (`ApplicationDbContext.BeforeSaveChanges`) when `Connection.RemoteIpAddress` is null.
  The NRE ran inside `SaveChangesAsync` and aborted the entire audited write; the IP is
  now read with a null-conditional operator. ([#8](https://github.com/laikhtman/cervantes/issues/8))
- Fixed a `NullReferenceException` in `KnowledgeBaseController.DeleteCategory` when deleting
  a non-existent category id. The code null-checked `category.Name` instead of `category`,
  so a missing id threw instead of returning a clean error. ([#7](https://github.com/laikhtman/cervantes/issues/7))
- Fixed a `NullReferenceException` (HTTP 500) in `JiraController.GetCommentsByVuln` when a
  vuln has no linked Jira issue. `FirstOrDefault` could return null and `jira.Id` was then
  dereferenced; the endpoint now returns an empty list for vulns without a Jira issue. ([#6](https://github.com/laikhtman/cervantes/issues/6))
- Fixed a `NullReferenceException` that made valid logins return HTTP 500.
  `AccountController` declared an `IHttpContextAccessor` field but never received or
  assigned it in the constructor, so it was always null; `Login` then dereferenced it
  while writing the audit record (after sign-in had already succeeded). The accessor is
  now injected via the constructor, matching the other controllers. ([#5](https://github.com/laikhtman/cervantes/issues/5))

### Security

- Fixed broken access control in `ReportController.GetByProject`: the project-membership
  check (`projectUserManager.VerifyUser`) was computed but its deny branch was commented
  out, allowing any user with `ReportsRead` to read reports of any project (IDOR). The
  check is now enforced and returns an empty result for non-members. ([#1](https://github.com/laikhtman/cervantes/issues/1))
- Restricted `ApiKeysController.GetByUser` to the `Admin` permission. It was guarded only
  by `[Authorize]`, letting any authenticated user enumerate another user's API-key
  records (prefix, name, expiry, last-used, revocation state) by supplying an arbitrary
  `userId`. ([#2](https://github.com/laikhtman/cervantes/issues/2))
