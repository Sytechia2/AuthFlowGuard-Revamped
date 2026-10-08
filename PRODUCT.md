# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Developers testing websites they own or control, especially local and staging
websites, and security testers or auditors performing repeatable authentication
assessments. Both audiences need to understand what was tested, what was
observed, and where the evidence is incomplete.

## Product Purpose

AuthFlowGuard helps users test how websites implement authentication. It
discovers and verifies authentication flows, runs controlled authentication
security checks, and presents findings with the evidence and limitations needed
to judge the result. Success means a user can run an authorized scan and
understand the resulting security coverage without relying on unsupported
claims.

## Positioning

AuthFlowGuard is an evidence-backed authentication testing tool. It combines
browser-based discovery and guided flow identification with explicit,
OWASP-based checks. AI may assist with navigation and discovery, but the
security verdicts come from deterministic analysers evaluating recorded
evidence.

## Operating Context

Users run the interface and backend on their own computer, define a permitted
website scope, and start a scan. The application may automatically discover
the target's authentication flow or pause for the user to identify controls and
protected account information. Playwright operates isolated browser contexts,
records relevant observations, and supports controlled replay experiments.
Users then review scan progress, results, supporting evidence, coverage, and
limitations in the React interface or generated reports.

## Capabilities and Constraints

- The first release covers traditional forms and JavaScript applications,
  including separate username and password steps and cookie or bearer-token
  sessions.
- The first release includes six controlled checks: login enumeration,
  registration enumeration, reset-request enumeration, login throttling and
  lockout, session fixation, and logout invalidation.
- Scans run locally on the developer's machine.
- Users must explicitly define the website and frontend/API origins that may be
  tested.
- Raw passwords, tokens, and other secrets must not be exposed in the UI or
  persisted as evidence; credential values are represented by local
  references.
- Findings must be supported by recorded browser evidence. If the required
  evidence is missing or ambiguous, the result must be inconclusive or
  unsupported rather than an invented pass/fail verdict.
- AI assists discovery and navigation but does not generate executable browser
  code or independently decide security verdicts.
- MFA, CAPTCHA, external identity providers, password-reset completion, and
  applications without a browser interface are outside the first release.

## Evidence on Hand

The repository contains the React/TypeScript/Vite interface in `frontend/`,
the FastAPI and Playwright implementation in `backend/`, controlled evaluation
applications and browser tests, and the agreed scope and acceptance criteria in
`Documentation/PROJECT_PLAN_AI.md` and `Documentation/EXECUTION_PLAN_AI.md`.
No external customer testimonials, deployment claims, or third-party brand
assets are established; future work must not fabricate them.

## Product Principles

- Test only explicitly authorized targets.
- Make observed evidence and coverage visible enough to support review.
- Keep discovery assistance separate from deterministic security analysis.
- Treat missing evidence as a meaningful limitation, not a positive result.
- Support both practical developer testing and repeatable professional
  assessment workflows.

## Brand Commitments

- The interface follows the familiar conventions of established vulnerability
  scanners such as Tenable Nessus and Qualys: a scan list, severity-coded
  findings, and drill-down from a scan to its checks and evidence. Security
  professionals should recognise the tool category at a glance. (Chosen
  2026-10-08 for the revamp shown at AWS AI Fest 2026.)
- The theme is light.
- The conventions are borrowed, never the brands: no third-party names, logos,
  or trade dress appear in the product.

## Accessibility & Inclusion

The interface must remain usable for both developers and security testers with
different levels of security expertise. Future UI work should preserve clear
plain-language explanations, visible progress and limitations, keyboard
accessibility, and distinguishable status and result states.
