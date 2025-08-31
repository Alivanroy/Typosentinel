#!/usr/bin/env python3
"""
CI/CD Pipeline Validation Script for TypoSentinel Enterprise Environment

This script validates CI/CD pipeline configurations, test results, and security gates
to ensure proper integration and compliance with enterprise security standards.
"""

import json
import yaml
import os
import sys
import argparse
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('pipeline-validation.log')
    ]
)
logger = logging.getLogger(__name__)

class CICDValidator:
    """Main validator class for CI/CD pipeline testing"""
    
    def __init__(self, project_root: str, config_file: str = None):
        self.project_root = Path(project_root)
        self.config_file = config_file or self.project_root / "tests" / "cicd-test-config.yaml"
        self.results_dir = self.project_root / "tests" / "results"
        self.validation_results = {
            "timestamp": datetime.utcnow().isoformat(),
            "project_root": str(self.project_root),
            "validations": {},
            "summary": {
                "total_checks": 0,
                "passed_checks": 0,
                "failed_checks": 0,
                "warnings": 0
            }
        }
        
        # Load configuration
        self.config = self._load_config()
        
    def _load_config(self) -> Dict:
        """Load test configuration from YAML file"""
        try:
            with open(self.config_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config from {self.config_file}: {e}")
            return {}
    
    def _record_check(self, category: str, check_name: str, passed: bool, 
                     message: str = "", warning: bool = False) -> None:
        """Record validation check result"""
        if category not in self.validation_results["validations"]:
            self.validation_results["validations"][category] = []
        
        self.validation_results["validations"][category].append({
            "check": check_name,
            "passed": passed,
            "message": message,
            "warning": warning,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        self.validation_results["summary"]["total_checks"] += 1
        if passed:
            self.validation_results["summary"]["passed_checks"] += 1
        else:
            self.validation_results["summary"]["failed_checks"] += 1
        
        if warning:
            self.validation_results["summary"]["warnings"] += 1
        
        # Log the result
        level = logging.WARNING if warning else (logging.INFO if passed else logging.ERROR)
        logger.log(level, f"{category}.{check_name}: {'PASS' if passed else 'FAIL'} - {message}")
    
    def validate_project_structure(self) -> bool:
        """Validate enterprise project structure"""
        logger.info("Validating project structure...")
        
        required_dirs = [
            "frontend",
            "backend",
            "microservices",
            "infrastructure",
            "tests",
            ".github/workflows"
        ]
        
        all_passed = True
        
        for dir_name in required_dirs:
            dir_path = self.project_root / dir_name
            passed = dir_path.exists() and dir_path.is_dir()
            self._record_check(
                "project_structure", 
                f"directory_{dir_name.replace('/', '_')}",
                passed,
                f"Directory {dir_name} {'exists' if passed else 'missing'}"
            )
            if not passed:
                all_passed = False
        
        # Check for microservices
        microservices_dir = self.project_root / "microservices"
        if microservices_dir.exists():
            services = [d for d in microservices_dir.iterdir() if d.is_dir()]
            passed = len(services) >= 4
            self._record_check(
                "project_structure",
                "microservices_count",
                passed,
                f"Found {len(services)} microservices (expected >= 4)"
            )
            if not passed:
                all_passed = False
        
        return all_passed
    
    def validate_cicd_workflows(self) -> bool:
        """Validate CI/CD workflow configurations"""
        logger.info("Validating CI/CD workflows...")
        
        workflows_dir = self.project_root / ".github" / "workflows"
        all_passed = True
        
        # Check for required workflow files
        required_workflows = [
            "security-scan.yml",
            "test-security-pipeline.yml"
        ]
        
        for workflow in required_workflows:
            workflow_path = workflows_dir / workflow
            passed = workflow_path.exists()
            self._record_check(
                "cicd_workflows",
                f"workflow_{workflow.replace('.yml', '').replace('-', '_')}",
                passed,
                f"Workflow {workflow} {'exists' if passed else 'missing'}"
            )
            
            if passed:
                # Validate workflow content
                try:
                    with open(workflow_path, 'r') as f:
                        workflow_content = yaml.safe_load(f)
                    
                    # Check for required jobs
                    jobs = workflow_content.get('jobs', {})
                    if 'security-scan' in jobs or 'test-security' in jobs:
                        self._record_check(
                            "cicd_workflows",
                            f"workflow_{workflow.replace('.yml', '')}_has_security_job",
                            True,
                            f"Workflow {workflow} has security job"
                        )
                    else:
                        self._record_check(
                            "cicd_workflows",
                            f"workflow_{workflow.replace('.yml', '')}_has_security_job",
                            False,
                            f"Workflow {workflow} missing security job"
                        )
                        all_passed = False
                    
                except Exception as e:
                    self._record_check(
                        "cicd_workflows",
                        f"workflow_{workflow.replace('.yml', '')}_valid_yaml",
                        False,
                        f"Invalid YAML in {workflow}: {e}"
                    )
                    all_passed = False
            else:
                all_passed = False
        
        return all_passed
    
    def validate_security_configuration(self) -> bool:
        """Validate security configuration files"""
        logger.info("Validating security configuration...")
        
        config_files = [
            "infrastructure/security/enterprise-security-config.yaml",
            "tests/cicd-test-config.yaml"
        ]
        
        all_passed = True
        
        for config_file in config_files:
            config_path = self.project_root / config_file
            passed = config_path.exists()
            
            config_name = config_file.split('/')[-1].replace('.yaml', '').replace('-', '_')
            self._record_check(
                "security_config",
                f"config_{config_name}",
                passed,
                f"Config file {config_file} {'exists' if passed else 'missing'}"
            )
            
            if passed:
                try:
                    with open(config_path, 'r') as f:
                        config_data = yaml.safe_load(f)
                    
                    # Validate config structure
                    if 'enterprise-security-config.yaml' in config_file:
                        required_sections = ['threat_thresholds', 'vulnerability_scanning', 'supply_chain']
                        for section in required_sections:
                            section_exists = section in config_data
                            self._record_check(
                                "security_config",
                                f"enterprise_config_{section}",
                                section_exists,
                                f"Enterprise config section {section} {'exists' if section_exists else 'missing'}"
                            )
                            if not section_exists:
                                all_passed = False
                    
                except Exception as e:
                    self._record_check(
                        "security_config",
                        f"config_{config_name}_valid",
                        False,
                        f"Invalid config {config_file}: {e}"
                    )
                    all_passed = False
            else:
                all_passed = False
        
        return all_passed
    
    def validate_test_scripts(self) -> bool:
        """Validate test execution scripts"""
        logger.info("Validating test scripts...")
        
        test_scripts = [
            "tests/run-cicd-tests.sh",
            "tests/run-cicd-tests.ps1",
            "tests/validate-cicd-pipeline.py"
        ]
        
        all_passed = True
        
        for script in test_scripts:
            script_path = self.project_root / script
            passed = script_path.exists()
            
            script_name = script.split('/')[-1].replace('.', '_')
            self._record_check(
                "test_scripts",
                f"script_{script_name}",
                passed,
                f"Test script {script} {'exists' if passed else 'missing'}"
            )
            
            if not passed:
                all_passed = False
        
        return all_passed
    
    def validate_dependency_manifests(self) -> bool:
        """Validate dependency manifest files across services"""
        logger.info("Validating dependency manifests...")
        
        services = [
            "frontend",
            "backend",
            "microservices/auth-service",
            "microservices/payment-service",
            "microservices/notification-service",
            "microservices/analytics-service"
        ]
        
        all_passed = True
        
        for service in services:
            service_path = self.project_root / service
            
            # Check for package.json or go.mod
            package_json = service_path / "package.json"
            go_mod = service_path / "go.mod"
            
            has_manifest = package_json.exists() or go_mod.exists()
            
            service_name = service.replace('/', '_').replace('-', '_')
            self._record_check(
                "dependency_manifests",
                f"service_{service_name}_manifest",
                has_manifest,
                f"Service {service} {'has' if has_manifest else 'missing'} dependency manifest"
            )
            
            if has_manifest:
                # Validate manifest content
                if package_json.exists():
                    try:
                        with open(package_json, 'r') as f:
                            package_data = json.load(f)
                        
                        has_deps = 'dependencies' in package_data or 'devDependencies' in package_data
                        self._record_check(
                            "dependency_manifests",
                            f"service_{service_name}_has_dependencies",
                            has_deps,
                            f"Service {service} package.json {'has' if has_deps else 'missing'} dependencies"
                        )
                        
                    except Exception as e:
                        self._record_check(
                            "dependency_manifests",
                            f"service_{service_name}_valid_package_json",
                            False,
                            f"Invalid package.json in {service}: {e}"
                        )
                        all_passed = False
            else:
                all_passed = False
        
        return all_passed
    
    def validate_test_results(self) -> bool:
        """Validate existing test results if available"""
        logger.info("Validating test results...")
        
        if not self.results_dir.exists():
            self._record_check(
                "test_results",
                "results_directory",
                False,
                "Test results directory does not exist - run tests first",
                warning=True
            )
            return True  # Not a failure, just a warning
        
        all_passed = True
        
        # Check for test result categories
        result_categories = [
            "basic_security",
            "performance",
            "multi_service",
            "failure_scenarios",
            "security_gates"
        ]
        
        for category in result_categories:
            category_dir = self.results_dir / category
            passed = category_dir.exists()
            
            self._record_check(
                "test_results",
                f"category_{category}",
                passed,
                f"Test results for {category} {'exist' if passed else 'missing'}",
                warning=not passed
            )
        
        # Check for test reports
        reports_dir = self.results_dir / "reports"
        if reports_dir.exists():
            report_files = list(reports_dir.glob("*.md")) + list(reports_dir.glob("*.json"))
            has_reports = len(report_files) > 0
            
            self._record_check(
                "test_results",
                "test_reports",
                has_reports,
                f"Found {len(report_files)} test report files",
                warning=not has_reports
            )
        
        return all_passed
    
    def validate_security_gates(self) -> bool:
        """Validate security gate configurations and thresholds"""
        logger.info("Validating security gates...")
        
        all_passed = True
        
        # Check security gate configuration
        if self.config:
            test_scenarios = self.config.get('test_scenarios', {})
            security_gates = test_scenarios.get('security_gates', {})
            
            if security_gates:
                # Validate critical threat threshold
                critical_threshold = security_gates.get('critical_threshold', 0)
                passed = critical_threshold == 0
                self._record_check(
                    "security_gates",
                    "critical_threshold",
                    passed,
                    f"Critical threat threshold is {critical_threshold} (should be 0)"
                )
                
                # Validate high threat threshold
                high_threshold = security_gates.get('high_threshold', 10)
                passed = high_threshold <= 10
                self._record_check(
                    "security_gates",
                    "high_threshold",
                    passed,
                    f"High threat threshold is {high_threshold} (should be <= 10)"
                )
                
                if not passed:
                    all_passed = False
            else:
                self._record_check(
                    "security_gates",
                    "configuration_exists",
                    False,
                    "Security gates configuration missing"
                )
                all_passed = False
        
        return all_passed
    
    def run_integration_test(self) -> bool:
        """Run a quick integration test to verify TypoSentinel functionality"""
        logger.info("Running integration test...")
        
        # Find TypoSentinel binary
        typosentinel_paths = [
            self.project_root.parent / "typosentinel.exe",
            self.project_root.parent / "typosentinel",
            "typosentinel.exe",
            "typosentinel"
        ]
        
        typosentinel_binary = None
        for path in typosentinel_paths:
            if isinstance(path, Path) and path.exists():
                typosentinel_binary = str(path)
                break
            elif isinstance(path, str):
                try:
                    subprocess.run([path, "--version"], capture_output=True, check=True, timeout=10)
                    typosentinel_binary = path
                    break
                except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                    continue
        
        if not typosentinel_binary:
            self._record_check(
                "integration_test",
                "typosentinel_binary",
                False,
                "TypoSentinel binary not found"
            )
            return False
        
        self._record_check(
            "integration_test",
            "typosentinel_binary",
            True,
            f"TypoSentinel binary found: {typosentinel_binary}"
        )
        
        # Test basic scan functionality
        try:
            result = subprocess.run(
                [typosentinel_binary, "scan", str(self.project_root / "frontend"), "--output", "json"],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            passed = result.returncode == 0
            self._record_check(
                "integration_test",
                "basic_scan",
                passed,
                f"Basic scan {'succeeded' if passed else 'failed'}: {result.stderr if not passed else 'OK'}"
            )
            
            if passed and result.stdout:
                try:
                    scan_results = json.loads(result.stdout)
                    has_summary = 'summary' in scan_results
                    self._record_check(
                        "integration_test",
                        "scan_output_format",
                        has_summary,
                        f"Scan output {'has valid format' if has_summary else 'invalid format'}"
                    )
                except json.JSONDecodeError:
                    self._record_check(
                        "integration_test",
                        "scan_output_format",
                        False,
                        "Scan output is not valid JSON"
                    )
                    passed = False
            
            return passed
            
        except subprocess.TimeoutExpired:
            self._record_check(
                "integration_test",
                "basic_scan",
                False,
                "Basic scan timed out"
            )
            return False
        except Exception as e:
            self._record_check(
                "integration_test",
                "basic_scan",
                False,
                f"Basic scan failed with error: {e}"
            )
            return False
    
    def generate_validation_report(self) -> str:
        """Generate comprehensive validation report"""
        logger.info("Generating validation report...")
        
        report_file = self.results_dir / "reports" / "pipeline_validation_report.json"
        report_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Calculate overall status
        total_checks = self.validation_results["summary"]["total_checks"]
        passed_checks = self.validation_results["summary"]["passed_checks"]
        failed_checks = self.validation_results["summary"]["failed_checks"]
        
        success_rate = (passed_checks / total_checks * 100) if total_checks > 0 else 0
        
        overall_status = "PASS" if failed_checks == 0 else "FAIL"
        if self.validation_results["summary"]["warnings"] > 0 and failed_checks == 0:
            overall_status = "PASS_WITH_WARNINGS"
        
        self.validation_results["summary"]["success_rate"] = round(success_rate, 2)
        self.validation_results["summary"]["overall_status"] = overall_status
        
        # Save JSON report
        with open(report_file, 'w') as f:
            json.dump(self.validation_results, f, indent=2)
        
        # Generate Markdown report
        md_report_file = self.results_dir / "reports" / "pipeline_validation_report.md"
        
        md_content = f"""# 🔍 CI/CD Pipeline Validation Report

**Validation Date**: {self.validation_results['timestamp']}  
**Project Root**: {self.validation_results['project_root']}  
**Overall Status**: {overall_status}  

## 📊 Validation Summary

| Metric | Value |
|--------|-------|
| Total Checks | {total_checks} |
| Passed | {passed_checks} |
| Failed | {failed_checks} |
| Warnings | {self.validation_results['summary']['warnings']} |
| Success Rate | {success_rate:.1f}% |

## 📋 Validation Results by Category

"""
        
        for category, checks in self.validation_results["validations"].items():
            md_content += f"\n### {category.replace('_', ' ').title()}\n\n"
            
            for check in checks:
                status_icon = "✅" if check["passed"] else ("⚠️" if check["warning"] else "❌")
                md_content += f"- {status_icon} **{check['check']}**: {check['message']}\n"
        
        md_content += f"\n## 🎯 Recommendations\n\n"
        
        if overall_status == "PASS":
            md_content += "- ✅ **CI/CD pipeline validation passed successfully**\n"
            md_content += "- Continue with regular pipeline monitoring\n"
            md_content += "- Consider running integration tests regularly\n"
        elif overall_status == "PASS_WITH_WARNINGS":
            md_content += "- ⚠️ **CI/CD pipeline validation passed with warnings**\n"
            md_content += "- Address warning items when possible\n"
            md_content += "- Monitor for potential issues\n"
        else:
            md_content += "- ❌ **CI/CD pipeline validation failed**\n"
            md_content += "- Address all failed checks before proceeding\n"
            md_content += "- Re-run validation after fixes\n"
        
        md_content += f"\n---\n\n**Generated by**: TypoSentinel CI/CD Pipeline Validator  \n"
        md_content += f"**Report Version**: 1.0  \n"
        md_content += f"**Validation Tool**: validate-cicd-pipeline.py\n"
        
        with open(md_report_file, 'w', encoding='utf-8') as f:
            f.write(md_content)
        
        logger.info(f"Validation report saved to: {report_file}")
        logger.info(f"Markdown report saved to: {md_report_file}")
        
        return str(report_file)
    
    def run_all_validations(self) -> bool:
        """Run all validation checks"""
        logger.info("Starting comprehensive CI/CD pipeline validation...")
        
        validations = [
            ("Project Structure", self.validate_project_structure),
            ("CI/CD Workflows", self.validate_cicd_workflows),
            ("Security Configuration", self.validate_security_configuration),
            ("Test Scripts", self.validate_test_scripts),
            ("Dependency Manifests", self.validate_dependency_manifests),
            ("Test Results", self.validate_test_results),
            ("Security Gates", self.validate_security_gates),
            ("Integration Test", self.run_integration_test)
        ]
        
        overall_success = True
        
        for validation_name, validation_func in validations:
            logger.info(f"Running {validation_name} validation...")
            try:
                success = validation_func()
                if not success:
                    overall_success = False
                logger.info(f"{validation_name} validation: {'PASS' if success else 'FAIL'}")
            except Exception as e:
                logger.error(f"{validation_name} validation failed with exception: {e}")
                overall_success = False
        
        # Generate report
        report_file = self.generate_validation_report()
        
        logger.info(f"Validation completed. Overall result: {'PASS' if overall_success else 'FAIL'}")
        logger.info(f"Detailed report available at: {report_file}")
        
        return overall_success

def main():
    parser = argparse.ArgumentParser(
        description="Validate CI/CD pipeline configuration and test setup"
    )
    parser.add_argument(
        "--project-root",
        default=".",
        help="Path to project root directory (default: current directory)"
    )
    parser.add_argument(
        "--config",
        help="Path to test configuration file"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "--category",
        choices=[
            "structure", "workflows", "security", "scripts", 
            "manifests", "results", "gates", "integration", "all"
        ],
        default="all",
        help="Run specific validation category (default: all)"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize validator
    validator = CICDValidator(args.project_root, args.config)
    
    # Run validations based on category
    if args.category == "all":
        success = validator.run_all_validations()
    else:
        validation_map = {
            "structure": validator.validate_project_structure,
            "workflows": validator.validate_cicd_workflows,
            "security": validator.validate_security_configuration,
            "scripts": validator.validate_test_scripts,
            "manifests": validator.validate_dependency_manifests,
            "results": validator.validate_test_results,
            "gates": validator.validate_security_gates,
            "integration": validator.run_integration_test
        }
        
        success = validation_map[args.category]()
        validator.generate_validation_report()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()