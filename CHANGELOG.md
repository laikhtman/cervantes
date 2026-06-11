# Changelog

All notable changes to this project (this fork) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Security

- Fixed broken access control in `ReportController.GetByProject`: the project-membership
  check (`projectUserManager.VerifyUser`) was computed but its deny branch was commented
  out, allowing any user with `ReportsRead` to read reports of any project (IDOR). The
  check is now enforced and returns an empty result for non-members. ([#1](https://github.com/laikhtman/cervantes/issues/1))
