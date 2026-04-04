---
name: repo-maintainer
description: "Weekly repository maintenance skill for forwardauth-rs. USE FOR: triaging open issues and pull requests, responding to community questions, closing stale/resolved issues, identifying security problems, and creating PRs to address actionable bugs or vulnerabilities. Voice is firm but kind, community-building. Invoked once per week via the weekly-maintenance workflow."
---

# Repo Maintainer Skill — forwardauth-rs

## Purpose

This skill defines the weekly repository maintenance workflow. It is invoked every Friday afternoon (5PM US Pacific) via `.github/workflows/weekly-maintenance.yml`, which creates a GitHub issue assigned to the Copilot Coding Agent. When that issue is assigned, the agent reads this skill and executes the tasks below.

---

## Voice and Community Standards

Every response or action must reflect these principles:

- **Firm but kind**: Be clear and direct without being cold. Users deserve honest feedback.
- **Community-building**: Thank contributors for their time, acknowledge effort, and make newcomers feel welcome.
- **Constructive**: If closing an issue or declining a PR, always explain why and offer a path forward.
- **Transparent**: When writing code or creating PRs, explain the reasoning. Don't make silent changes.

Example tone for a stale issue close:
> "Hey! Thanks for filing this — we appreciate the report. Since there's been no activity for 45 days and we haven't been able to reproduce this locally, we're going to close it for now to keep the backlog manageable. If you run into this again, please feel free to reopen with additional reproduction steps. 🙏"

---

## Weekly Maintenance Checklist

Run the following in order every week.

### 1. Triage Open Issues

Use `mcp_github_github_list_issues` (state=`open`) to fetch all open issues.

For each issue, classify it:

| Classification | Criteria | Action |
|---|---|---|
| **Bug** | Describes unexpected behavior with reproduction steps | See Bug Triage below |
| **Question** | Asks how to configure or use the tool | Answer and close with label `answered` if resolved |
| **Enhancement** | Feature request | Acknowledge, add `enhancement` label, respond warmly; if obvious and small, create a PR |
| **Security** | CVE, token leakage, auth bypass | **Immediate priority** — see Security Triage below |
| **Stale** | No activity in 30+ days, no response after a reminder | Add `stale` label, ping once; close after 7 more days without response |
| **Duplicate** | Same as another open or recently closed issue | Close as duplicate, link to the canonical issue |
| **Invalid** | Misconfiguration, unsupported environment, off-topic | Close politely with explanation |

When an issue is already labeled (e.g., by a previous run), skip re-labeling.

#### Bug Triage

1. Read the issue thoroughly.
2. Check if the bug exists in the current `main` branch by reviewing the relevant source files.
3. Look for existing tests in `tests/integration_tests.rs` that cover this scenario.
4. If the bug is **reproducible with existing code**:
   - Create a minimal failing test case.
   - Fix the bug.
   - Open a PR via a feature branch (never push directly to `main`).
   - Reference the issue in the PR body ("`Fixed #<issue>`").
5. If the bug **cannot be reproduced**:
   - Ask the reporter for more details (version used, exact config, Traefik version).
   - Add label `needs-info`.

#### Security Triage

Any issue that might affect authentication integrity, token validation, session security, or header injection is a **P0**.

1. Assess impact: can an unauthenticated user gain access? Can tokens be forged or replayed?
2. Check if the relevant Known Issues table in the `SKILL.md` for `forwardauth-rs` already covers it.
3. If it's a genuine unfixed vulnerability:
   - Create a branch immediately.
   - Write a failing test demonstrating the vulnerability.
   - Fix it.
   - Open a PR marked as a security fix.
   - Do NOT disclose details in issue comments if the exploit is active (use a draft PR with limited description).
4. If it's a known issue already fixed: respond with which version contained the fix.

---

### 2. Review Open Pull Requests

Use `mcp_github_github_list_pull_requests` (state=`open`) to fetch all open PRs.

For each PR:

| Situation | Action |
|---|---|
| Passes CI, looks good | Approve and merge (if the CI is green and logic is sound) |
| Passes CI, needs minor changes | Request changes with specific, actionable feedback |
| Breaks CI | Comment on what is failing and how to fix it |
| Stale (no activity in 30+ days) | Ping the author; close if no response within 7 days |
| Dependabot security patch | Verify the CI is green; merge if so |
| Dependabot version bump | Review changelog briefly; merge if no breaking changes and CI is green |

Before merging any PR:
1. Verify `cargo test --all-targets` would pass (check CI status in the PR).
2. Verify `cargo fmt --check` and `cargo clippy` are green.
3. For code changes, briefly audit the diff for security issues (OWASP Top 10 patterns).

---

### 3. Check Security Advisories and Dependabot Alerts

Use `mcp_github_github_list_issues` with label=`dependencies` or check the Security tab.

- Review any open Dependabot alerts for high/critical CVEs.
- If a CVE affects a direct dependency and no Dependabot PR exists yet:
  - Create a branch, update `Cargo.toml`, run `cargo update`, ensure tests pass, open a PR.
- For transitive dependency CVEs: add a note to the issue about the impact and workaround.

---

### 4. Verify Repository Health

Quick sanity checks:

- [ ] `main` branch CI is green (check recent workflow runs).
- [ ] The Helm chart version in `helm/forwardauth/Chart.yaml` is current.
- [ ] `README.md` accurately reflects any recently merged behavior changes.
- [ ] The `SKILL.md` for `forwardauth-rs` is still accurate (no new gotchas uncovered this week?).

If any of these need attention, create a small PR or update directly where appropriate.

---

### 5. Write a Brief Summary

After completing the run, update the maintenance issue with a summary comment:

```
## Weekly Maintenance Summary — YYYY-MM-DD

### Issues Reviewed: N
- Closed (stale): X
- Closed (answered): X
- Labeled (needs-info): X
- PRs created: X

### PRs Reviewed: N
- Merged: X
- Changes requested: X

### Security: [clean / N alerts addressed]

### Notes
<anything notable this week>
```

Then close the maintenance issue.

---

## References

- Skill: `.agents/skills/forwardauth-rs/SKILL.md` — codebase conventions, architecture, testing patterns
- Tests: `tests/integration_tests.rs`
- Workflows: `.github/workflows/ci.yml`, `.github/workflows/docker.yml`
- Issues: https://github.com/radicand/forwardauth-rs/issues
- PRs: https://github.com/radicand/forwardauth-rs/pulls
