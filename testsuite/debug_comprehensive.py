#!/usr/bin/env python3
import json
import subprocess
import time

def run_command(cmd):
    """Run a command and return success, output, and processing time."""
    start_time = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True)
    processing_time = int((time.time() - start_time) * 1000)
    
    success = result.returncode == 0
    output = result.stdout + result.stderr
    
    return success, output, processing_time

def test_single_package(package_name, registry, expected_risk):
    """Test a single package and return the result."""
    cmd = [
        "./typosentinel",
        "scan",
        package_name,
        "--registry", registry,
        "--config", "test_config.yaml",
        "--format", "json"
    ]
    
    success, output, processing_time = run_command(cmd)
    
    if not success:
        print(f"Command failed for {package_name}")
        print(f"Output: {output}")
        return None
    
    print(f"\n=== Testing {package_name} ===")
    print(f"Raw output length: {len(output)}")
    
    # Parse JSON output
    try:
        # Extract JSON from output (it might contain logs before the JSON)
        json_start = output.find('{')
        if json_start != -1:
            json_output = output[json_start:]
            # Find the end of the JSON object
            brace_count = 0
            json_end = json_start
            for i, char in enumerate(json_output):
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        json_end = json_start + i + 1
                        break
            json_output = output[json_start:json_end]
        else:
            json_output = output
            
        print(f"JSON output length: {len(json_output)}")
        print(f"JSON starts with: {json_output[:100]}...")
        
        result_data = json.loads(json_output)
        # Try multiple field names for compatibility - check package object first
        package_data = result_data.get("package", {})
        
        print(f"Package data keys: {list(package_data.keys())}")
        print(f"Root data keys: {list(result_data.keys())}")
        
        # Get risk score with explicit None checking
        actual_score = package_data.get("risk_score")
        print(f"Risk score from package: {actual_score} (type: {type(actual_score)})")
        if actual_score is None:
            actual_score = result_data.get("threat_score")
            print(f"Risk score from threat_score: {actual_score}")
        if actual_score is None:
            actual_score = result_data.get("risk_score", 0.0)
            print(f"Risk score from root: {actual_score}")
        
        # Check for risk level in package object or root level
        actual_risk = package_data.get("risk_level")
        print(f"Risk level from package: {actual_risk} (type: {type(actual_risk)})")
        if actual_risk is None:
            actual_risk = result_data.get("risk_level")
            print(f"Risk level from root: {actual_risk}")
        if actual_risk is None:
            actual_risk = result_data.get("overall_risk", "UNKNOWN")
            print(f"Overall risk from root: {actual_risk}")
        
        print(f"\nFinal actual_score: {actual_score} (type: {type(actual_score)})")
        print(f"Final actual_risk: {actual_risk} (type: {type(actual_risk)})")
        
        # Convert risk level to uppercase for consistency
        if isinstance(actual_risk, str):
            actual_risk = actual_risk.upper()
        elif isinstance(actual_risk, int):
            # Convert numeric risk level to string
            risk_level_map = {0: "MINIMAL", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
            actual_risk = risk_level_map.get(actual_risk, "UNKNOWN")
        
        print(f"Converted actual_risk: {actual_risk}")
        
        return {
            'package': package_name,
            'score': actual_score,
            'risk': actual_risk,
            'expected_risk': expected_risk
        }
        
    except json.JSONDecodeError as e:
        print(f"JSON parsing error: {e}")
        return None

if __name__ == "__main__":
    # Test the problematic package
    result = test_single_package("lodahs", "npm", "HIGH")
    if result:
        print(f"\n=== FINAL RESULT ===")
        print(f"Package: {result['package']}")
        print(f"Score: {result['score']}")
        print(f"Risk: {result['risk']}")
        print(f"Expected: {result['expected_risk']}")