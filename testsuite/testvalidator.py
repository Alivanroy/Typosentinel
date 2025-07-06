#!/usr/bin/env python3
"""
Comprehensive Test Validator for Typosentinel
This script orchestrates and validates all real-world tests for the Typosentinel project.
"""

import json
import subprocess
import time
import os
import sys
import argparse
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import logging
import statistics
import requests
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class TestResult:
    """Represents the result of a single test."""
    test_name: str
    category: str
    passed: bool
    score: float
    expected_score: float
    processing_time_ms: int
    error_message: str = ""
    confidence: float = 0.0
    detection_flags: List[str] = None
    
    def __post_init__(self):
        if self.detection_flags is None:
            self.detection_flags = []

@dataclass
class PerformanceMetrics:
    """Performance metrics for the test run."""
    total_packages_tested: int
    total_processing_time_ms: int
    packages_per_second: float
    average_processing_time_ms: float
    p95_processing_time_ms: float
    p99_processing_time_ms: float
    peak_memory_mb: float
    
@dataclass 
class AccuracyMetrics:
    """Accuracy metrics for threat detection."""
    total_threats: int
    detected_threats: int
    total_legitimate: int
    false_positives: int
    true_positive_rate: float
    false_positive_rate: float
    precision: float
    recall: float
    f1_score: float

@dataclass
class TestSuiteResults:
    """Complete test suite results."""
    test_results: List[TestResult]
    performance_metrics: PerformanceMetrics
    accuracy_metrics: AccuracyMetrics
    overall_success: bool
    start_time: datetime
    end_time: datetime
    
class TyposentinelTestValidator:
    """Main test validator class."""
    
    def __init__(self, config_path: str = "test_config.yaml", binary_path: str = "./typosentinel"):
        self.config_path = config_path
        self.binary_path = binary_path
        self.test_results: List[TestResult] = []
        self.threat_database = self._load_threat_database()
        self.start_time = datetime.now()
        
    def _load_threat_database(self) -> Dict[str, Any]:
        """Load the threat validation database."""
        try:
            with open("threat_validation_data.json", "r") as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning("Threat database not found, using minimal test data")
            return self._get_minimal_test_data()
    
    def _get_minimal_test_data(self) -> Dict[str, Any]:
        """Provide minimal test data if database file is missing."""
        return {
            "threat_database": {
                "categories": {
                    "typosquatting": {
                        "threats": [
                            {
                                "malicious_package": "lodahs",
                                "target_package": "lodash", 
                                "registry": "npm",
                                "risk_level": "HIGH"
                            }
                        ]
                    }
                }
            },
            "legitimate_packages": {
                "packages": [
                    {
                        "name": "lodash",
                        "registry": "npm",
                        "weekly_downloads": 30000000
                    }
                ]
            }
        }
    
    def run_command(self, cmd: List[str], timeout: int = 30) -> Tuple[bool, str, int]:
        """Execute a command and return success, output, and processing time."""
        start_time = time.time()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            processing_time = int((time.time() - start_time) * 1000)
            return result.returncode == 0, result.stdout + result.stderr, processing_time
        except subprocess.TimeoutExpired:
            processing_time = timeout * 1000
            return False, f"Command timed out after {timeout}s", processing_time
        except Exception as e:
            processing_time = int((time.time() - start_time) * 1000)
            return False, str(e), processing_time
    
    def test_single_package(self, package_name: str, registry: str, expected_risk: str) -> TestResult:
        """Test a single package and return results."""
        logger.info(f"Testing {package_name} ({registry}) - expected: {expected_risk}")
        
        cmd = [
            self.binary_path,
            "scan",
            "--package", package_name,
            "--registry", registry,
            "--config", self.config_path,
            "--output", "json"
        ]
        
        success, output, processing_time = self.run_command(cmd)
        
        if not success:
            return TestResult(
                test_name=f"{registry}_{package_name}",
                category="package_scan",
                passed=False,
                score=0.0,
                expected_score=self._get_expected_score(expected_risk),
                processing_time_ms=processing_time,
                error_message=output
            )
        
        # Parse JSON output
        try:
            result_data = json.loads(output)
            actual_score = result_data.get("threat_score", 0.0)
            actual_risk = result_data.get("risk_level", "UNKNOWN")
            confidence = result_data.get("confidence", 0.0)
            detection_flags = result_data.get("detection_flags", [])
            
            # Determine if test passed based on expected vs actual
            passed = self._evaluate_detection_result(expected_risk, actual_risk, actual_score)
            
            return TestResult(
                test_name=f"{registry}_{package_name}",
                category="package_scan",
                passed=passed,
                score=actual_score,
                expected_score=self._get_expected_score(expected_risk),
                processing_time_ms=processing_time,
                confidence=confidence,
                detection_flags=detection_flags
            )
            
        except json.JSONDecodeError:
            return TestResult(
                test_name=f"{registry}_{package_name}",
                category="package_scan", 
                passed=False,
                score=0.0,
                expected_score=self._get_expected_score(expected_risk),
                processing_time_ms=processing_time,
                error_message="Failed to parse JSON output"
            )
    
    def _get_expected_score(self, risk_level: str) -> float:
        """Get expected score for a risk level."""
        score_map = {
            "HIGH": 0.8,
            "CRITICAL": 0.9,
            "MEDIUM": 0.6,
            "LOW": 0.3,
            "MINIMAL": 0.1
        }
        return score_map.get(risk_level, 0.5)
    
    def _evaluate_detection_result(self, expected: str, actual: str, score: float) -> bool:
        """Evaluate if detection result matches expectations."""
        if expected == "HIGH" or expected == "CRITICAL":
            return score >= 0.7 and actual in ["HIGH", "CRITICAL"]
        elif expected == "MEDIUM":
            return 0.4 <= score < 0.8 and actual in ["MEDIUM", "HIGH"]
        elif expected == "LOW" or expected == "MINIMAL":
            return score < 0.4 and actual in ["LOW", "MINIMAL"]
        return True  # Unknown expected result
    
    def test_known_threats(self) -> List[TestResult]:
        """Test against known threats from the database."""
        logger.info("Testing known threat detection...")
        results = []
        
        threat_db = self.threat_database.get("threat_database", {})
        categories = threat_db.get("categories", {})
        
        for category_name, category_data in categories.items():
            threats = category_data.get("threats", [])
            for threat in threats:
                package_name = threat.get("malicious_package")
                registry = threat.get("registry")
                risk_level = threat.get("risk_level", "HIGH")
                
                if package_name and registry:
                    result = self.test_single_package(package_name, registry, risk_level)
                    result.category = f"threat_{category_name}"
                    results.append(result)
        
        self.test_results.extend(results)
        return results
    
    def test_legitimate_packages(self) -> List[TestResult]:
        """Test legitimate packages for false positives."""
        logger.info("Testing legitimate packages for false positives...")
        results = []
        
        legitimate_packages = self.threat_database.get("legitimate_packages", {}).get("packages", [])
        
        for package in legitimate_packages:
            package_name = package.get("name")
            registry = package.get("registry")
            
            if package_name and registry:
                result = self.test_single_package(package_name, registry, "LOW")
                result.category = "legitimate_package"
                results.append(result)
        
        self.test_results.extend(results)
        return results
    
    def test_typosquatting_patterns(self) -> List[TestResult]:
        """Test specific typosquatting patterns."""
        logger.info("Testing typosquatting patterns...")
        results = []
        
        # Test common typosquatting patterns
        patterns = [
            ("lodahs", "lodash", "npm"),
            ("recat", "react", "npm"),
            ("reqeusts", "requests", "pypi"),
            ("expresss", "express", "npm"),
            ("nmupy", "numpy", "pypi")
        ]
        
        for malicious, target, registry in patterns:
            result = self.test_single_package(malicious, registry, "HIGH")
            result.category = "typosquatting_pattern"
            result.test_name = f"typosquat_{malicious}_vs_{target}"
            results.append(result)
        
        self.test_results.extend(results)
        return results
    
    def test_performance_benchmarks(self) -> List[TestResult]:
        """Test performance benchmarks."""
        logger.info("Testing performance benchmarks...")
        results = []
        
        # Test batch processing performance
        test_packages = [
            ("lodash", "npm"), ("react", "npm"), ("express", "npm"),
            ("requests", "pypi"), ("numpy", "pypi"), ("flask", "pypi")
        ]
        
        batch_start = time.time()
        batch_results = []
        
        for package_name, registry in test_packages:
            result = self.test_single_package(package_name, registry, "LOW")
            batch_results.append(result)
        
        batch_time = time.time() - batch_start
        packages_per_second = len(test_packages) / batch_time
        
        # Create performance test result
        perf_result = TestResult(
            test_name="batch_performance",
            category="performance",
            passed=packages_per_second >= 1.0,  # Minimum 1 package per second
            score=packages_per_second,
            expected_score=5.0,  # Target 5 packages per second
            processing_time_ms=int(batch_time * 1000)
        )
        
        results.extend(batch_results)
        results.append(perf_result)
        self.test_results.extend(results)
        return results
    
    def test_project_scanning(self) -> List[TestResult]:
        """Test project dependency file scanning."""
        logger.info("Testing project scanning...")
        results = []
        
        # Create temporary test projects
        test_dir = Path("temp_test_projects")
        test_dir.mkdir(exist_ok=True)
        
        # NPM project
        npm_project = test_dir / "npm_test"
        npm_project.mkdir(exist_ok=True)
        
        package_json = {
            "name": "test-project",
            "dependencies": {
                "lodash": "^4.17.21",
                "react": "^18.0.0",
                "express": "^4.18.0"
            }
        }
        
        with open(npm_project / "package.json", "w") as f:
            json.dump(package_json, f, indent=2)
        
        # Test NPM project scanning
        cmd = [
            self.binary_path,
            "scan",
            "--project-path", str(npm_project),
            "--config", self.config_path,
            "--output", "json"
        ]
        
        success, output, processing_time = self.run_command(cmd)
        
        project_result = TestResult(
            test_name="npm_project_scan",
            category="project_scanning",
            passed=success,
            score=1.0 if success else 0.0,
            expected_score=1.0,
            processing_time_ms=processing_time,
            error_message="" if success else output
        )
        
        results.append(project_result)
        
        # Cleanup
        import shutil
        shutil.rmtree(test_dir, ignore_errors=True)
        
        self.test_results.extend(results)
        return results
    
    def calculate_accuracy_metrics(self) -> AccuracyMetrics:
        """Calculate accuracy metrics from test results."""
        threat_results = [r for r in self.test_results if r.category.startswith("threat") or r.category == "typosquatting_pattern"]
        legitimate_results = [r for r in self.test_results if r.category == "legitimate_package"]
        
        # Threat detection metrics
        total_threats = len(threat_results)
        detected_threats = len([r for r in threat_results if r.passed])
        
        # False positive metrics
        total_legitimate = len(legitimate_results)
        false_positives = len([r for r in legitimate_results if not r.passed])
        
        # Calculate rates
        true_positive_rate = detected_threats / total_threats if total_threats > 0 else 0.0
        false_positive_rate = false_positives / total_legitimate if total_legitimate > 0 else 0.0
        
        # Precision and recall
        true_positives = detected_threats
        false_negatives = total_threats - detected_threats
        
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0.0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        return AccuracyMetrics(
            total_threats=total_threats,
            detected_threats=detected_threats,
            total_legitimate=total_legitimate,
            false_positives=false_positives,
            true_positive_rate=true_positive_rate,
            false_positive_rate=false_positive_rate,
            precision=precision,
            recall=recall,
            f1_score=f1_score
        )
    
    def calculate_performance_metrics(self) -> PerformanceMetrics:
        """Calculate performance metrics from test results."""
        all_times = [r.processing_time_ms for r in self.test_results if r.processing_time_ms > 0]
        
        if not all_times:
            return PerformanceMetrics(0, 0, 0.0, 0.0, 0.0, 0.0, 0.0)
        
        total_time = sum(all_times)
        avg_time = statistics.mean(all_times)
        
        # Calculate percentiles
        sorted_times = sorted(all_times)
        p95_index = int(0.95 * len(sorted_times))
        p99_index = int(0.99 * len(sorted_times))
        
        p95_time = sorted_times[min(p95_index, len(sorted_times) - 1)]
        p99_time = sorted_times[min(p99_index, len(sorted_times) - 1)]
        
        packages_per_second = len(all_times) / (total_time / 1000) if total_time > 0 else 0.0
        
        return PerformanceMetrics(
            total_packages_tested=len(all_times),
            total_processing_time_ms=total_time,
            packages_per_second=packages_per_second,
            average_processing_time_ms=avg_time,
            p95_processing_time_ms=p95_time,
            p99_processing_time_ms=p99_time,
            peak_memory_mb=0.0  # Would need additional monitoring
        )
    
    def run_all_tests(self) -> TestSuiteResults:
        """Run the complete test suite."""
        logger.info("Starting comprehensive test suite...")
        
        # Run all test categories
        self.test_known_threats()
        self.test_legitimate_packages()
        self.test_typosquatting_patterns()
        self.test_performance_benchmarks()
        self.test_project_scanning()
        
        # Calculate metrics
        accuracy_metrics = self.calculate_accuracy_metrics()
        performance_metrics = self.calculate_performance_metrics()
        
        # Determine overall success
        passed_tests = len([r for r in self.test_results if r.passed])
        total_tests = len(self.test_results)
        pass_rate = passed_tests / total_tests if total_tests > 0 else 0.0
        
        overall_success = (
            pass_rate >= 0.8 and  # 80% pass rate
            accuracy_metrics.true_positive_rate >= 0.85 and  # 85% threat detection
            accuracy_metrics.false_positive_rate <= 0.15 and  # 15% max false positives
            performance_metrics.packages_per_second >= 1.0  # 1 package/second minimum
        )
        
        end_time = datetime.now()
        
        return TestSuiteResults(
            test_results=self.test_results,
            performance_metrics=performance_metrics,
            accuracy_metrics=accuracy_metrics,
            overall_success=overall_success,
            start_time=self.start_time,
            end_time=end_time
        )
    
    def generate_report(self, results: TestSuiteResults, output_file: str = "test_report.md"):
        """Generate a comprehensive test report."""
        logger.info(f"Generating test report: {output_file}")
        
        duration = results.end_time - results.start_time
        
        report = f"""# Typosentinel Real-World Test Report

**Generated:** {results.end_time.strftime('%Y-%m-%d %H:%M:%S')}
**Test Duration:** {duration}
**Overall Result:** {'✅ PASS' if results.overall_success else '❌ FAIL'}

## Executive Summary

- **Total Tests:** {len(results.test_results)}
- **Passed:** {len([r for r in results.test_results if r.passed])}
- **Failed:** {len([r for r in results.test_results if not r.passed])}
- **Pass Rate:** {len([r for r in results.test_results if r.passed]) / len(results.test_results) * 100:.1f}%

## Accuracy Metrics

- **Threat Detection Rate:** {results.accuracy_metrics.true_positive_rate:.1%}
- **False Positive Rate:** {results.accuracy_metrics.false_positive_rate:.1%}
- **Precision:** {results.accuracy_metrics.precision:.3f}
- **Recall:** {results.accuracy_metrics.recall:.3f}
- **F1 Score:** {results.accuracy_metrics.f1_score:.3f}

## Performance Metrics

- **Total Packages Tested:** {results.performance_metrics.total_packages_tested}
- **Packages per Second:** {results.performance_metrics.packages_per_second:.2f}
- **Average Processing Time:** {results.performance_metrics.average_processing_time_ms:.0f}ms
- **95th Percentile Time:** {results.performance_metrics.p95_processing_time_ms:.0f}ms
- **99th Percentile Time:** {results.performance_metrics.p99_processing_time_ms:.0f}ms

## Test Categories

"""
        
        # Group results by category
        categories = {}
        for result in results.test_results:
            if result.category not in categories:
                categories[result.category] = []
            categories[result.category].append(result)
        
        for category, tests in categories.items():
            passed = len([t for t in tests if t.passed])
            total = len(tests)
            
            report += f"""### {category.replace('_', ' ').title()}

- **Tests:** {total}
- **Passed:** {passed}
- **Pass Rate:** {passed/total*100:.1f}%

"""
            
            for test in tests:
                status = "✅" if test.passed else "❌"
                report += f"- {status} `{test.test_name}` - Score: {test.score:.3f} (Expected: {test.expected_score:.3f})\n"
            
            report += "\n"
        
        # Detailed failures
        failures = [r for r in results.test_results if not r.passed]
        if failures:
            report += "## Failed Tests\n\n"
            for failure in failures:
                report += f"""### {failure.test_name}

- **Category:** {failure.category}
- **Score:** {failure.score:.3f} (Expected: {failure.expected_score:.3f})
- **Processing Time:** {failure.processing_time_ms}ms
- **Error:** {failure.error_message}

"""
        
        # Recommendations
        report += "## Recommendations\n\n"
        
        if results.accuracy_metrics.true_positive_rate < 0.9:
            report += "- ⚠️ Improve threat detection accuracy - consider tuning detection thresholds\n"
        
        if results.accuracy_metrics.false_positive_rate > 0.1:
            report += "- ⚠️ Reduce false positive rate - review legitimate package scoring\n"
        
        if results.performance_metrics.packages_per_second < 5.0:
            report += "- ⚠️ Improve performance - consider optimization or parallel processing\n"
        
        if results.overall_success:
            report += "- ✅ System is ready for production deployment\n"
        else:
            report += "- ❌ Address issues before production deployment\n"
        
        # Write report
        with open(output_file, "w") as f:
            f.write(report)
        
        logger.info(f"Report generated: {output_file}")

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Comprehensive Typosentinel Test Validator")
    parser.add_argument("--config", default="test_config.yaml", help="Test configuration file")
    parser.add_argument("--binary", default="./typosentinel", help="Path to Typosentinel binary")
    parser.add_argument("--output", default="test_report.md", help="Output report file")
    parser.add_argument("--json", action="store_true", help="Also output JSON results")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Check if binary exists
    if not os.path.exists(args.binary):
        logger.error(f"Typosentinel binary not found: {args.binary}")
        logger.error("Please build the binary first: make build")
        sys.exit(1)
    
    # Run tests
    validator = TyposentinelTestValidator(args.config, args.binary)
    results = validator.run_all_tests()
    
    # Generate reports
    validator.generate_report(results, args.output)
    
    if args.json:
        json_output = args.output.replace('.md', '.json')
        with open(json_output, 'w') as f:
            json.dump(asdict(results), f, indent=2, default=str)
        logger.info(f"JSON results saved: {json_output}")
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"TEST SUITE SUMMARY")
    print(f"{'='*60}")
    print(f"Overall Result: {'PASS' if results.overall_success else 'FAIL'}")
    print(f"Tests Passed: {len([r for r in results.test_results if r.passed])}/{len(results.test_results)}")
    print(f"Threat Detection: {results.accuracy_metrics.true_positive_rate:.1%}")
    print(f"False Positive Rate: {results.accuracy_metrics.false_positive_rate:.1%}")
    print(f"Performance: {results.performance_metrics.packages_per_second:.2f} packages/sec")
    print(f"Report: {args.output}")
    print(f"{'='*60}")
    
    # Exit with appropriate code
    sys.exit(0 if results.overall_success else 1)

if __name__ == "__main__":
    main()