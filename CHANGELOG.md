# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-12

### Added
- **Production Hardening (C1–C9):**
  - Fully configured `pyproject.toml` with setuptools package directory discovery for `vaishnavi_av`.
  - Console script entrypoint `vaishnavi-av = vaishnavi_av.main:run` supporting CLI arguments (`--max-files`, `--version`, `-v`).
  - Multi-version GitHub Actions CI matrix across Python 3.10, 3.11, 3.12, and 3.13.
  - Multi-stage unprivileged Alpine `Dockerfile` with non-root UID 10001 (`vaishnavi`).
  - GitHub CodeQL static analysis workflow and Dependabot dependency automation.
  - Automated release packaging workflow with SHA256 checksum generation.
  - Formal `SECURITY.md` establishing threat model and disclosure protocols.
  - Expanded test suite to 19 tests with **97%** measured code coverage (exceeding 90% threshold).
  - Clean Ruff linting and Mypy strict type checking.
