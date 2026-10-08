// The six controlled checks and what a confirmed finding means for each.
// Codes, severities and recommendations mirror CHECK_REPORT_INFO in
// backend/authflowguard/reports.py so the interface and the HTML report agree;
// change both together. The analysers decide outcomes; this table only
// describes them.

export type Severity = "critical" | "high" | "medium" | "low";

export type CheckInfo = {
  /** Backend check id, e.g. "login_enumeration". */
  id: string;
  /** Setup form id, e.g. "login-enumeration". */
  formId: string;
  code: string;
  label: string;
  reference: string;
  failureSeverity: Severity;
  recommendation: string;
};

export const checkCatalog: CheckInfo[] = [
  {
    id: "login_enumeration",
    formId: "login-enumeration",
    code: "CHK-001",
    label: "Login account enumeration",
    reference: "WSTG-IDNT-04",
    failureSeverity: "medium",
    recommendation:
      "Return indistinguishable login failure responses (status, message, body size, headers and timing) for valid and invalid accounts.",
  },
  {
    id: "registration_enumeration",
    formId: "registration-enumeration",
    code: "CHK-002",
    label: "Registration account enumeration",
    reference: "WSTG-IDNT-04",
    failureSeverity: "medium",
    recommendation:
      "Prevent account enumeration during registration by returning generic responses and avoiding account-exists disclosure.",
  },
  {
    id: "reset_request_enumeration",
    formId: "reset-request-enumeration",
    code: "CHK-003",
    label: "Reset-request account enumeration",
    reference: "WSTG-IDNT-04",
    failureSeverity: "medium",
    recommendation:
      "Use generic password reset responses and identical behaviour whether or not an account exists.",
  },
  {
    id: "login_throttling",
    formId: "login-throttling",
    code: "CHK-004",
    label: "Login throttling and lockout",
    reference: "WSTG-ATHN-03",
    failureSeverity: "high",
    recommendation:
      "Implement rate limiting, lockout and abuse monitoring for authentication endpoints.",
  },
  {
    id: "session_fixation",
    formId: "session-fixation",
    code: "CHK-005",
    label: "Session fixation",
    reference: "WSTG-SESS-03",
    failureSeverity: "high",
    recommendation:
      "Regenerate session identifiers after authentication and prevent fixation of pre-authenticated sessions.",
  },
  {
    id: "logout_invalidation",
    formId: "logout-invalidation",
    code: "CHK-006",
    label: "Logout invalidation",
    reference: "WSTG-SESS-06",
    failureSeverity: "critical",
    recommendation:
      "Invalidate server-side session state on logout and ensure replayed tokens or cookies no longer grant authenticated access.",
  },
];

export function checkInfo(checkId: string): CheckInfo | undefined {
  return checkCatalog.find((check) => check.id === checkId);
}

/** What a result row shows: a severity for findings, otherwise its status. */
export type Rating = Severity | "passed" | "inconclusive" | "other";

export const ratingLabels: Record<Rating, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  passed: "Passed",
  inconclusive: "Inconclusive",
  other: "Not rated",
};

const outcomeLabels: Record<string, string> = {
  finding_confirmed: "Fail",
  no_issue_observed: "Passed",
  inconclusive: "Inconclusive",
  not_applicable: "Not applicable",
  unsupported: "Unsupported",
  execution_error: "Error",
};

export function outcomeLabel(outcome: string): string {
  return outcomeLabels[outcome] ?? outcome.replaceAll("_", " ");
}

// The status words of the HTML report (STATUS_LABELS in reports.py), in
// sentence case. A selected check without a result was not run.
const reportStatusLabels: Record<string, string> = {
  finding_confirmed: "Fail",
  no_issue_observed: "Pass",
  inconclusive: "Inconclusive",
  not_applicable: "N/A",
  unsupported: "Unsupported",
  execution_error: "Error",
};

export function reportStatus(outcome?: string | null): string {
  if (!outcome) return "Not run";
  return reportStatusLabels[outcome] ?? outcome.replaceAll("_", " ");
}

/** The report's severity: the failure severity for a finding, Info for a
 *  pass, and N/A when there is no verdict. */
export function reportSeverity(
  checkId: string,
  outcome?: string | null,
): Severity | "info" | "n/a" | "unrated" {
  if (outcome === "finding_confirmed") {
    return checkInfo(checkId)?.failureSeverity ?? "unrated";
  }
  if (outcome === "no_issue_observed") return "info";
  return "n/a";
}

export function ratingFor(checkId: string, outcome: string): Rating {
  if (outcome === "finding_confirmed") {
    return checkInfo(checkId)?.failureSeverity ?? "other";
  }
  if (outcome === "no_issue_observed") return "passed";
  if (outcome === "inconclusive") return "inconclusive";
  return "other";
}

const ratingOrder: Rating[] = [
  "critical",
  "high",
  "medium",
  "low",
  "inconclusive",
  "other",
  "passed",
];

export function compareRatings(a: Rating, b: Rating): number {
  return ratingOrder.indexOf(a) - ratingOrder.indexOf(b);
}

export type RatingCounts = Record<Rating, number>;

export function countRatings(
  results: { check_id: string; outcome: string }[],
): RatingCounts {
  const counts: RatingCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    passed: 0,
    inconclusive: 0,
    other: 0,
  };
  for (const result of results) {
    counts[ratingFor(result.check_id, result.outcome)] += 1;
  }
  return counts;
}
