# Test Coverage Targets for v1.1.0

Current focus packages and minimum targets:

| Package | Target |
|---------|--------|
| internal/detector | ≥70% |
| internal/analyzer | ≥60% |
| internal/scanner  | ≥60% |
| api/              | ≥80% |
| pkg/types         | 100% |

Strategy:
- Add edge‑case tests
- Fix failing tests before adding new ones
- Track baseline via CI artifacts (coverage.txt, coverage.html)
