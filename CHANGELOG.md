# Changelog

All notable changes to this project (this fork) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed

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
