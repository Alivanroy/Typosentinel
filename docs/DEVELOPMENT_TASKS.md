Typosentinel – Enterprise Remediation & Testing Plan
====================================================

Real‑World Context
------------------
* **Enterprise integration team** – wires IntegrationHub into CI/CD, consumes REST APIs,
  and expects connector filtering plus persistent audit trails.
* **Security expert** – demands authenticated policy actions, provable supply‑chain
  tokens, and stored policy violations.
* **DevOps** – requires rate‑limited supply‑chain endpoints, validated tokens, and
  functional schedulers/CLI for automated scans.
* **CISO** – needs persistent audit logs, accurate dashboards, and compliance metrics
  for reporting risk posture.

Findings & Remediation Tasks
----------------------------

1. Policy handlers lack authenticated user context
   :::task-stub{title="Populate policy metadata from auth context"}
   - Path: `internal/api/rest/enterprise_handlers.go`
   - Fetch acting user ID from `AuthorizationMiddleware` in `CreatePolicy`,
     `ApproveViolation`, and `RejectViolation`.
   - Populate `CreatedBy`, `approved_by`, and `rejected_by` fields.
   - Unit tests confirming metadata is recorded.
   :::

2. Policy violation storage is stubbed
   :::task-stub{title="Persist and retrieve policy violations"}
   - Path: `internal/api/rest/enterprise_handlers.go`
   - Add datastore for `PolicyViolation`.
   - Implement Create/List/Get/Approve/Reject using the store.
   - Integration tests for approval lifecycle.
   :::

3. Supply chain token validation is insecure
   :::task-stub{title="Implement real token validation in supply chain middleware"}
   - Path: `internal/api/rest/middleware/sc_middleware.go`
   - Verify JWTs or API keys against a token store.
   - Return detailed errors for invalid/expired tokens.
   - Unit tests for valid, invalid, and expired tokens.
   :::

4. Rate limiting middleware is a no‑op
   :::task-stub{title="Enable rate limiting for supply chain endpoints"}
   - Path: `internal/api/rest/middleware/sc_middleware.go`
   - Integrate Redis or in‑memory counters keyed by IP/endpoint.
   - Separate quotas for high‑cost vs. standard routes.
   - Tests simulating throttled and non‑throttled clients.
   :::

5. Audit logs are not persisted
   :::task-stub{title="Persist audit logs in DatabaseAuditWriter"}
   - Path: `internal/enterprise/audit/writers.go`
   - Implement DB insertion in `flushBuffer` with batching and retries.
   - Tests verifying logs survive flush operations.
   :::

6. Dashboard metrics rely on placeholder data
   :::task-stub{title="Collect real metrics for enterprise dashboard"}
   - Path: `internal/enterprise/dashboard/dashboard.go`
   - Populate recent scans, trends, compliance scores, and resource usage
     from live services.
   - Tests confirming dynamic metric population.
   :::

7. Scheduler initialization is stubbed
   :::task-stub{title="Initialize scheduler and queue"}
   - Path: `cmd/enterprise/main.go`
   - Instantiate job queue and `ScanScheduler` when enabled.
   - Hook scheduler metrics into dashboard/repo manager.
   - Integration tests ensuring scheduled scans run.
   :::

8. Enterprise CLI subcommands are placeholders
   :::task-stub{title="Implement enterprise CLI subcommands"}
   - Path: `cmd/enterprise/main.go`
   - Provide real logic for reports, schedules, audits, compliance,
     config management, health/metrics, exports, user/policy management,
     and integrations.
   - End‑to‑end CLI tests for each subcommand.
   :::

9. Integration hub lacks connector‑specific filtering
   :::task-stub{title="Apply connector-specific filters in IntegrationHub"}
   - Path: `internal/integrations/hub/hub.go`
   - Extend connector config with filter settings; evaluate in `routeToConnector`.
   - Tests for allowed vs. blocked events per filter.
   :::

10. Hardcoded basic authentication credentials
    :::task-stub{title="Validate basic auth against user store"}
    - Path: `internal/api/rest/middleware.go`
    - Replace static map with lookup against user DB or directory service.
    - Support password hashing and account status checks.
    - Tests for valid, invalid, and disabled users.
    :::

11. Vulnerability scanning endpoints return static results
    :::task-stub{title="Integrate real vulnerability scanning"}
    - Path: `internal/api/rest/server.go`
    - Wire endpoints to scanner engine; persist scan status/results.
    - Tests covering single and batch scans.
    :::

12. Checksum validation stub in Go analyzer
    :::task-stub{title="Implement checksum validation in Go analyzer"}
    - Path: `internal/scanner/go_analyzer_enhanced.go`
    - Compute and compare checksums with `go.sum` or registry data.
    - Report mismatches as tampering.
    - Unit tests with valid/invalid checksums.
    :::

13. Provenance analyzer lacks real signature verification
    :::task-stub{title="Implement provenance signature verification"}
    - Path: `internal/provenance/integrity.go`
    - Integrate Sigstore/SLSA verification for signatures and provenance.
    - Replace placeholder returns with actual trust assessments.
    - Tests validating trusted and untrusted signatures.
    :::

14. Dashboard formatter omits trend/compliance details
    :::task-stub{title="Generate real trend and compliance data in dashboard output"}
    - Path: `internal/output/dashboard.go`
    - Pull historical scan results for trend metrics.
    - Produce compliance assessments with risk/threat scores.
    - Tests for dashboard generation with sample historical data.
    :::

End‑to‑End Testing Expectations
-------------------------------
* **Dev** – full CLI workflow: scheduling scans, generating reports, viewing
  audit/compliance data, exporting results.
* **Security expert** – authenticated policy lifecycle with violation approval,
  secure token validation, and rate‑limited supply‑chain endpoints.
* **DevOps** – queue‑driven scheduled scans and verified rate limits under load.
* **CISO** – persistent audit trail, dynamic dashboard metrics, and compliance
  summaries exported in multiple formats.

