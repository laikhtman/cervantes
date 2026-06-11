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

### Fixed

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
