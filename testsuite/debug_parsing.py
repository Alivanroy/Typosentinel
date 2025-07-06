#!/usr/bin/env python3
import json
import subprocess

# Test the actual command output
cmd = [
    "./typosentinel",
    "scan",
    "lodahs",
    "--registry", "npm",
    "--config", "test_config.yaml",
    "--format", "json"
]

result = subprocess.run(cmd, capture_output=True, text=True)
output = result.stdout + result.stderr

print("=== RAW OUTPUT ===")
print(repr(output))

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
    
    print("\n=== EXTRACTED JSON ===")
    print(json_output)
    
    try:
        result_data = json.loads(json_output)
        # Try multiple field names for compatibility - check package object first
        package_data = result_data.get("package", {})
        actual_score = (
            package_data.get("risk_score") or 
            result_data.get("threat_score") or 
            result_data.get("risk_score", 0.0)
        )
        
        # Check for risk level in package object or root level
        actual_risk = (
            package_data.get("risk_level") or
            result_data.get("risk_level") or 
            result_data.get("overall_risk", "UNKNOWN")
        )
        
        print("\n=== PARSED DATA ===")
        print(f"Package data: {package_data}")
        print(f"Risk score from package: {package_data.get('risk_score')}")
        print(f"Risk level from package: {package_data.get('risk_level')}")
        print(f"Risk score from root: {result_data.get('risk_score')}")
        print(f"Risk level from root: {result_data.get('risk_level')}")
        print(f"Overall risk from root: {result_data.get('overall_risk')}")
        
        print(f"\nFinal actual_score: {actual_score}")
        print(f"Final actual_risk: {actual_risk}")
        print(f"Type of actual_score: {type(actual_score)}")
        print(f"Type of actual_risk: {type(actual_risk)}")
        
        # Convert risk level to uppercase for consistency
        if isinstance(actual_risk, str):
            actual_risk = actual_risk.upper()
        elif isinstance(actual_risk, int):
            # Convert numeric risk level to string
            risk_level_map = {0: "MINIMAL", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
            actual_risk = risk_level_map.get(actual_risk, "UNKNOWN")
        
        print(f"\nConverted actual_risk: {actual_risk}")
        
    except json.JSONDecodeError as e:
        print(f"\nJSON parsing error: {e}")
else:
    print("\nNo JSON found in output")