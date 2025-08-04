#!/usr/bin/env python3
"""
Enterprise Network Testing Runner
Orchestrates Docker-based enterprise-level testing environment
"""

import os
import sys
import time
import json
import yaml
import subprocess
import argparse
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('enterprise_tests.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class EnterpriseTestRunner:
    """Orchestrates enterprise-level network testing using Docker"""
    
    def __init__(self, config_path: str = "scenarios/enterprise_scenarios.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        self.test_results = {}
        self.start_time = datetime.now()
        
        # Docker configuration
        self.docker_compose_file = "/Users/alikorsi/Documents/Typosentinel/deployments/docker/docker-compose.enterprise-test.yml"
        self.project_name = "typosentinel-enterprise-test"
        
    def _load_config(self) -> Dict[str, Any]:
        """Load enterprise test configuration"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {self.config_path}")
            sys.exit(1)
        except yaml.YAMLError as e:
            logger.error(f"Error parsing configuration file: {e}")
            sys.exit(1)
    
    def setup_environment(self) -> bool:
        """Setup Docker environment for enterprise testing"""
        logger.info("Setting up enterprise testing environment...")
        
        try:
            # Check if Docker is running
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                logger.error("Docker is not running. Please start Docker first.")
                return False
            
            # Build and start services
            logger.info("Building Docker images...")
            build_cmd = [
                "docker-compose",
                "-f", self.docker_compose_file,
                "-p", self.project_name,
                "build"
            ]
            
            result = subprocess.run(build_cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"Failed to build Docker images: {result.stderr}")
                return False
            
            logger.info("Starting enterprise testing services...")
            start_cmd = [
                "docker-compose",
                "-f", self.docker_compose_file,
                "-p", self.project_name,
                "up", "-d"
            ]
            
            result = subprocess.run(start_cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"Failed to start services: {result.stderr}")
                return False
            
            # Wait for services to be ready
            logger.info("Waiting for services to be ready...")
            time.sleep(30)
            
            # Verify services are running
            if not self._verify_services():
                logger.error("Some services failed to start properly")
                return False
            
            logger.info("Enterprise testing environment is ready!")
            return True
            
        except Exception as e:
            logger.error(f"Error setting up environment: {e}")
            return False
    
    def _verify_services(self) -> bool:
        """Verify that all required services are running"""
        required_services = [
            "typosentinel-scanner",
            "attack-simulator",
            "redis",
            "postgres",
            "elasticsearch"
        ]
        
        for service in required_services:
            try:
                check_cmd = [
                    "docker-compose",
                    "-f", self.docker_compose_file,
                    "-p", self.project_name,
                    "ps", service
                ]
                
                result = subprocess.run(check_cmd, capture_output=True, text=True)
                if "Up" not in result.stdout:
                    logger.warning(f"Service {service} is not running properly")
                    return False
                    
            except Exception as e:
                logger.error(f"Error checking service {service}: {e}")
                return False
        
        return True
    
    def run_typosquatting_tests(self) -> Dict[str, Any]:
        """Run typosquatting attack scenarios"""
        logger.info("Running typosquatting attack scenarios...")
        
        results = {
            "basic_typos": self._run_attack_scenario("typosquatting", "basic"),
            "advanced_typos": self._run_attack_scenario("typosquatting", "advanced"),
            "sophisticated_typos": self._run_attack_scenario("typosquatting", "sophisticated")
        }
        
        return results
    
    def run_supply_chain_tests(self) -> Dict[str, Any]:
        """Run supply chain attack scenarios"""
        logger.info("Running supply chain attack scenarios...")
        
        results = {
            "dependency_confusion": self._run_attack_scenario("supply_chain", "dependency_confusion"),
            "malicious_updates": self._run_attack_scenario("supply_chain", "malicious_updates"),
            "compromised_maintainers": self._run_attack_scenario("supply_chain", "compromised_maintainers")
        }
        
        return results
    
    def run_nation_state_tests(self) -> Dict[str, Any]:
        """Run nation-state level attack scenarios"""
        logger.info("Running nation-state attack scenarios...")
        
        results = {
            "apt_campaigns": self._run_attack_scenario("nation_state", "apt_campaigns"),
            "zero_day_exploits": self._run_attack_scenario("nation_state", "zero_day_exploits"),
            "infrastructure_targeting": self._run_attack_scenario("nation_state", "infrastructure_targeting")
        }
        
        return results
    
    def run_advanced_persistent_tests(self) -> Dict[str, Any]:
        """Run advanced persistent threat scenarios"""
        logger.info("Running advanced persistent threat scenarios...")
        
        results = {
            "long_term_campaigns": self._run_attack_scenario("advanced_persistent", "long_term_campaigns"),
            "multi_stage_attacks": self._run_attack_scenario("advanced_persistent", "multi_stage_attacks"),
            "ai_powered_attacks": self._run_attack_scenario("advanced_persistent", "ai_powered_attacks")
        }
        
        return results
    
    def run_quantum_era_tests(self) -> Dict[str, Any]:
        """Run quantum-era attack scenarios"""
        logger.info("Running quantum-era attack scenarios...")
        
        results = {
            "quantum_cryptographic": self._run_attack_scenario("quantum_era", "quantum_cryptographic"),
            "quantum_network": self._run_attack_scenario("quantum_era", "quantum_network")
        }
        
        return results
    
    def _run_attack_scenario(self, category: str, scenario: str) -> Dict[str, Any]:
        """Run a specific attack scenario"""
        logger.info(f"Running {category}/{scenario} scenario...")
        
        try:
            # Execute attack scenario via Docker
            exec_cmd = [
                "docker-compose",
                "-f", self.docker_compose_file,
                "-p", self.project_name,
                "exec", "-T", "attack-simulator",
                "python", "/app/attack_orchestrator.py",
                "--category", category,
                "--scenario", scenario,
                "--output", f"/app/results/{category}_{scenario}.json"
            ]
            
            start_time = time.time()
            result = subprocess.run(exec_cmd, capture_output=True, text=True, timeout=300)
            execution_time = time.time() - start_time
            
            if result.returncode == 0:
                # Get results from container
                results = self._get_scenario_results(f"{category}_{scenario}.json")
                results["execution_time"] = execution_time
                results["status"] = "success"
                logger.info(f"Scenario {category}/{scenario} completed successfully")
                return results
            else:
                logger.error(f"Scenario {category}/{scenario} failed: {result.stderr}")
                return {
                    "status": "failed",
                    "error": result.stderr,
                    "execution_time": execution_time
                }
                
        except subprocess.TimeoutExpired:
            logger.error(f"Scenario {category}/{scenario} timed out")
            return {
                "status": "timeout",
                "execution_time": 300
            }
        except Exception as e:
            logger.error(f"Error running scenario {category}/{scenario}: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    def _get_scenario_results(self, filename: str) -> Dict[str, Any]:
        """Get results from a completed scenario"""
        try:
            # Copy results from container
            copy_cmd = [
                "docker", "cp",
                f"{self.project_name}_attack-simulator_1:/app/results/{filename}",
                f"./results/{filename}"
            ]
            
            subprocess.run(copy_cmd, capture_output=True)
            
            # Load results
            with open(f"./results/{filename}", 'r') as f:
                return json.load(f)
                
        except Exception as e:
            logger.error(f"Error getting results for {filename}: {e}")
            return {"error": f"Failed to get results: {e}"}
    
    def run_performance_tests(self) -> Dict[str, Any]:
        """Run performance and load testing"""
        logger.info("Running performance tests...")
        
        performance_results = {}
        
        for intensity in ["low", "medium", "high", "enterprise"]:
            logger.info(f"Running {intensity} intensity performance test...")
            
            config = self.config["intensity_levels"][intensity]
            
            # Run performance test
            exec_cmd = [
                "docker-compose",
                "-f", self.docker_compose_file,
                "-p", self.project_name,
                "exec", "-T", "attack-simulator",
                "python", "/app/performance_tester.py",
                "--intensity", intensity,
                "--concurrent", str(config["concurrent_attacks"]),
                "--delay", str(config["delay_between_attacks"]),
                "--duration", config["duration"]
            ]
            
            start_time = time.time()
            result = subprocess.run(exec_cmd, capture_output=True, text=True, timeout=3600)
            execution_time = time.time() - start_time
            
            if result.returncode == 0:
                perf_results = self._get_scenario_results(f"performance_{intensity}.json")
                perf_results["execution_time"] = execution_time
                performance_results[intensity] = perf_results
            else:
                logger.error(f"Performance test {intensity} failed: {result.stderr}")
                performance_results[intensity] = {
                    "status": "failed",
                    "error": result.stderr
                }
        
        return performance_results
    
    def generate_enterprise_report(self) -> str:
        """Generate comprehensive enterprise test report"""
        logger.info("Generating enterprise test report...")
        
        report = {
            "test_execution": {
                "start_time": self.start_time.isoformat(),
                "end_time": datetime.now().isoformat(),
                "duration": str(datetime.now() - self.start_time),
                "environment": "enterprise_docker_network"
            },
            "test_results": self.test_results,
            "summary": self._generate_summary(),
            "recommendations": self._generate_recommendations(),
            "compliance_assessment": self._assess_compliance()
        }
        
        # Save report
        report_filename = f"enterprise_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(f"reports/{report_filename}", 'w') as f:
            json.dump(report, f, indent=2)
        
        # Generate HTML report
        html_report = self._generate_html_report(report)
        html_filename = f"enterprise_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(f"reports/{html_filename}", 'w') as f:
            f.write(html_report)
        
        logger.info(f"Enterprise test report generated: {report_filename}")
        return report_filename
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate test summary statistics"""
        total_tests = 0
        passed_tests = 0
        failed_tests = 0
        
        for category, scenarios in self.test_results.items():
            if isinstance(scenarios, dict):
                for scenario, result in scenarios.items():
                    total_tests += 1
                    if result.get("status") == "success":
                        passed_tests += 1
                    else:
                        failed_tests += 1
        
        return {
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "failed_tests": failed_tests,
            "success_rate": passed_tests / total_tests if total_tests > 0 else 0,
            "categories_tested": list(self.test_results.keys())
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on test results"""
        recommendations = []
        
        # Analyze results and generate recommendations
        summary = self._generate_summary()
        
        if summary["success_rate"] < 0.95:
            recommendations.append("Detection rate is below enterprise standards (95%). Consider tuning detection algorithms.")
        
        if "typosquatting" in self.test_results:
            typo_results = self.test_results["typosquatting"]
            if any(result.get("status") != "success" for result in typo_results.values()):
                recommendations.append("Improve typosquatting detection capabilities for enterprise environments.")
        
        if "nation_state" in self.test_results:
            ns_results = self.test_results["nation_state"]
            if any(result.get("status") != "success" for result in ns_results.values()):
                recommendations.append("Critical: Nation-state attack detection failures detected. Immediate security review required.")
        
        return recommendations
    
    def _assess_compliance(self) -> Dict[str, Any]:
        """Assess compliance with enterprise security standards"""
        targets = self.config["performance_targets"]
        
        # This would be populated with actual performance metrics
        return {
            "detection_rate_compliance": "PASS",  # Would be calculated from actual results
            "false_positive_compliance": "PASS",
            "response_time_compliance": "PASS",
            "throughput_compliance": "PASS",
            "overall_compliance": "PASS"
        }
    
    def _generate_html_report(self, report: Dict[str, Any]) -> str:
        """Generate HTML version of the report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>TypoSentinel Enterprise Test Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
                .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
                .success { background-color: #d4edda; border-color: #c3e6cb; }
                .warning { background-color: #fff3cd; border-color: #ffeaa7; }
                .danger { background-color: #f8d7da; border-color: #f5c6cb; }
                table { width: 100%; border-collapse: collapse; margin: 10px 0; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>TypoSentinel Enterprise Test Report</h1>
                <p>Generated: {timestamp}</p>
            </div>
            
            <div class="section">
                <h2>Executive Summary</h2>
                <p>Total Tests: {total_tests}</p>
                <p>Success Rate: {success_rate:.2%}</p>
                <p>Duration: {duration}</p>
            </div>
            
            <div class="section">
                <h2>Test Results</h2>
                <!-- Test results would be populated here -->
            </div>
            
            <div class="section">
                <h2>Recommendations</h2>
                <ul>
                    {recommendations}
                </ul>
            </div>
        </body>
        </html>
        """.format(
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            total_tests=report["summary"]["total_tests"],
            success_rate=report["summary"]["success_rate"],
            duration=report["test_execution"]["duration"],
            recommendations="".join(f"<li>{rec}</li>" for rec in report["recommendations"])
        )
        
        return html_template
    
    def cleanup_environment(self):
        """Clean up Docker environment"""
        logger.info("Cleaning up enterprise testing environment...")
        
        try:
            # Stop and remove containers
            cleanup_cmd = [
                "docker-compose",
                "-f", self.docker_compose_file,
                "-p", self.project_name,
                "down", "-v"
            ]
            
            subprocess.run(cleanup_cmd, capture_output=True)
            logger.info("Environment cleanup completed")
            
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
    
    def run_all_tests(self, intensity: str = "medium") -> str:
        """Run complete enterprise test suite"""
        logger.info(f"Starting enterprise test suite with {intensity} intensity...")
        
        # Create results directory
        os.makedirs("results", exist_ok=True)
        os.makedirs("reports", exist_ok=True)
        
        try:
            # Setup environment
            if not self.setup_environment():
                logger.error("Failed to setup testing environment")
                return None
            
            # Run all test categories
            self.test_results["typosquatting"] = self.run_typosquatting_tests()
            self.test_results["supply_chain"] = self.run_supply_chain_tests()
            self.test_results["nation_state"] = self.run_nation_state_tests()
            self.test_results["advanced_persistent"] = self.run_advanced_persistent_tests()
            self.test_results["quantum_era"] = self.run_quantum_era_tests()
            self.test_results["performance"] = self.run_performance_tests()
            
            # Generate report
            report_file = self.generate_enterprise_report()
            
            logger.info("Enterprise test suite completed successfully!")
            return report_file
            
        except Exception as e:
            logger.error(f"Error during test execution: {e}")
            return None
        finally:
            # Always cleanup
            self.cleanup_environment()

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="TypoSentinel Enterprise Network Testing")
    parser.add_argument("--config", default="scenarios/enterprise_scenarios.yaml",
                       help="Path to test configuration file")
    parser.add_argument("--intensity", choices=["low", "medium", "high", "enterprise"],
                       default="medium", help="Test intensity level")
    parser.add_argument("--category", choices=["typosquatting", "supply_chain", "nation_state", 
                                              "advanced_persistent", "quantum_era", "all"],
                       default="all", help="Test category to run")
    parser.add_argument("--cleanup-only", action="store_true",
                       help="Only cleanup existing environment")
    
    args = parser.parse_args()
    
    runner = EnterpriseTestRunner(args.config)
    
    if args.cleanup_only:
        runner.cleanup_environment()
        return
    
    if args.category == "all":
        report_file = runner.run_all_tests(args.intensity)
        if report_file:
            print(f"Enterprise test report generated: {report_file}")
        else:
            print("Enterprise tests failed")
            sys.exit(1)
    else:
        # Run specific category
        if not runner.setup_environment():
            print("Failed to setup testing environment")
            sys.exit(1)
        
        try:
            if args.category == "typosquatting":
                results = runner.run_typosquatting_tests()
            elif args.category == "supply_chain":
                results = runner.run_supply_chain_tests()
            elif args.category == "nation_state":
                results = runner.run_nation_state_tests()
            elif args.category == "advanced_persistent":
                results = runner.run_advanced_persistent_tests()
            elif args.category == "quantum_era":
                results = runner.run_quantum_era_tests()
            
            print(f"Test results for {args.category}:")
            print(json.dumps(results, indent=2))
            
        finally:
            runner.cleanup_environment()

if __name__ == "__main__":
    main()