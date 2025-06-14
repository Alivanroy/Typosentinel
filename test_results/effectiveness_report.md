# Typosentinel Detection Effectiveness Report

Generated: 2025-06-14 15:08:34

## Executive Summary

**Overall Grade:** F  
**Effectiveness Score:** 50.0%  
**Compliance Status:** NON_COMPLIANT

### Key Metrics
- **Total Tests Executed:** 2
- **Tests Passed:** 1 (50.0%)
- **Tests Failed:** 1 (50.0%)
- **Overall Accuracy:** 50.0%
- **Average Response Time:** 0s

## Detection Performance by Component

| Detector | Accuracy | Precision | Recall | F1 Score | Avg Response Time | False Positives | False Negatives |
|----------|----------|-----------|--------|----------|-------------------|-----------------|-----------------|
| behavioral | 0.0% | 0.0% | 0.0% | 0.0% | 2.000478708s | 1 | 0 |
| ml | 100.0% | 100.0% | 100.0% | 100.0% | 4.541µs | 0 | 0 |
| yara | 50.0% | 100.0% | 50.0% | 66.7% | 0s | 0 | 1 |
| typo | 50.0% | 100.0% | 50.0% | 66.7% | 27.187µs | 0 | 1 |
| anomaly | 100.0% | 100.0% | 100.0% | 100.0% | 2.291µs | 0 | 0 |
| static | 50.0% | 100.0% | 50.0% | 66.7% | 0s | 0 | 1 |

## Key Findings

- ml detector performing excellently (100.0% accuracy)
- yara detector underperforming (50.0% accuracy)
- typo detector underperforming (50.0% accuracy)
- anomaly detector performing excellently (100.0% accuracy)
- static detector underperforming (50.0% accuracy)
- behavioral detector underperforming (0.0% accuracy)

## Critical Issues

- ⚠️ Overall detection accuracy critically low
- ⚠️ yara detector missing threats (1 false negatives)
- ⚠️ typo detector missing threats (1 false negatives)
- ⚠️ static detector missing threats (1 false negatives)

## Recommendations

- Overall accuracy below 99% target - review failed test cases
- static detector accuracy below 95% - requires tuning
- behavioral detector accuracy below 95% - requires tuning
- behavioral detector has high false positive rate
- yara detector accuracy below 95% - requires tuning
- typo detector accuracy below 95% - requires tuning

## Next Steps

1. Analyze failed test cases and improve detection rules
1. Retrain ML models with additional data
1. Implement ensemble voting for better accuracy

## Performance Metrics

- **Total Execution Time:** 2.000672167s
- **Average Test Time:** 1.000336083s
- **Throughput:** 1.0 tests/second
- **Memory Usage:** 0.0 MB
- **CPU Usage:** 0.0%

## Test Case Details

| Test Case | Status | Detected | Threat Type | Confidence | Response Time | IOCs Found |
|-----------|--------|----------|-------------|------------|---------------|------------|
| Malicious lodahs package | ❌ FAIL | No | unknown | 0.0% | 58.209µs | 0 |
| Clean lodash package | ✅ PASS | No | unknown | 0.0% | 2.000587208s | 0 |

## Conclusion

⚠️ **IMPROVEMENT NEEDED**: The current effectiveness score of 50.0% is below the 99% target. Review the recommendations above and implement the suggested improvements before production deployment.

### Compliance Assessment

❌ **NON-COMPLIANT**: The system does not meet minimum detection effectiveness requirements.
