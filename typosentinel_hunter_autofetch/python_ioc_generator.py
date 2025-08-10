#!/usr/bin/env python3
"""
Python IOC (Indicators of Compromise) Generator
Generates IOCs for detected Python malware for security monitoring
"""

import json
import hashlib
import sys
import os
from datetime import datetime
from pathlib import Path

def generate_python_iocs():
    """Generate IOCs for Python malware detection"""
    
    # Load enhanced malware analysis results
    results_file = Path("enhanced_python_malware_results/enhanced_malware_analysis.json")
    if not results_file.exists():
        print("❌ Enhanced malware analysis results not found!")
        return
    
    with open(results_file, 'r') as f:
        results = json.load(f)
    
    iocs = {
        'metadata': {
            'generated': datetime.now().isoformat(),
            'version': '1.0',
            'source': 'Typosentinel Python Malware Analysis',
            'description': 'IOCs for detected Python malware packages'
        },
        'package_iocs': [],
        'pattern_iocs': [],
        'network_iocs': [],
        'file_iocs': []
    }
    
    # Generate package-based IOCs
    for package in results:
        if package['success'] and (package.get('critical_findings', 0) > 0 or package.get('high_findings', 0) > 0):
            
            # Package IOC
            package_ioc = {
                'type': 'malicious_package',
                'package_name': package['package_name'],
                'ecosystem': 'pypi',
                'threat_level': 'critical' if package.get('critical_findings', 0) > 0 else 'high',
                'description': f"Malicious Python package: {package['package_name']}",
                'indicators': [
                    f"pip install {package['package_name']}",
                    f"import {package['package_name']}",
                    f"from {package['package_name']} import",
                    package['package_name']
                ],
                'detection_rules': [
                    f"process_name contains 'pip' AND command_line contains '{package['package_name']}'",
                    f"file_path contains '{package['package_name']}' AND file_extension = '.py'",
                    f"network_request contains 'pypi.org/simple/{package['package_name']}'"
                ]
            }
            iocs['package_iocs'].append(package_ioc)
            
            # Extract pattern-based IOCs from findings
            if 'findings' in package:
                for finding in package['findings']:
                    if finding['severity'] in ['CRITICAL', 'HIGH']:
                        
                        # Code pattern IOC
                        pattern_ioc = {
                            'type': 'malicious_code_pattern',
                            'pattern': finding['pattern'],
                            'match': finding['match'],
                            'category': finding['category'],
                            'severity': finding['severity'],
                            'description': f"Malicious code pattern in {package['package_name']}",
                            'regex': finding['pattern'],
                            'detection_rule': f"file_content matches '{finding['pattern']}' AND file_extension = '.py'"
                        }
                        iocs['pattern_iocs'].append(pattern_ioc)
                        
                        # Network IOCs for network activity
                        if finding['category'] == 'network_activity':
                            network_ioc = {
                                'type': 'suspicious_network_activity',
                                'pattern': finding['match'],
                                'source_package': package['package_name'],
                                'description': f"Suspicious network activity from {package['package_name']}",
                                'detection_rule': f"process_name contains 'python' AND network_activity contains '{finding['match']}'"
                            }
                            iocs['network_iocs'].append(network_ioc)
    
    # Generate specific IOCs for known malicious packages
    specific_iocs = generate_specific_iocs()
    iocs.update(specific_iocs)
    
    # Save IOCs
    output_dir = Path("python_iocs")
    output_dir.mkdir(exist_ok=True)
    
    iocs_file = output_dir / "python_malware_iocs.json"
    with open(iocs_file, 'w') as f:
        json.dump(iocs, f, indent=2)
    
    # Generate YARA rules
    generate_yara_rules(iocs, output_dir)
    
    # Generate STIX format
    generate_stix_format(iocs, output_dir)
    
    # Generate summary
    generate_ioc_summary(iocs, output_dir)
    
    print(f"🔍 PYTHON IOCs GENERATED!")
    print("=" * 50)
    print(f"📁 IOCs saved to: {output_dir}")
    print(f"📦 Package IOCs: {len(iocs['package_iocs'])}")
    print(f"🔍 Pattern IOCs: {len(iocs['pattern_iocs'])}")
    print(f"🌐 Network IOCs: {len(iocs['network_iocs'])}")
    print(f"📄 File IOCs: {len(iocs['file_iocs'])}")

def generate_specific_iocs():
    """Generate specific IOCs for known malicious packages"""
    
    return {
        'beautifulsoup_iocs': {
            'package_hashes': [
                # These would be actual file hashes in a real scenario
                'sha256:beautifulsoup_malware_hash_placeholder'
            ],
            'file_patterns': [
                'BeautifulSoup.py',
                'BeautifulSoup-3.2.2'
            ],
            'code_signatures': [
                'compile(\'[a-zA-Z][-_.:a-zA-Z0-9]*\'',
                'compile("([<>]|"',
                '\\x80-\\x9f'
            ]
        },
        'pandas3_iocs': {
            'credential_patterns': [
                '.aws',
                'secret',
                'requests.post'
            ],
            'file_patterns': [
                'pandas3/__init__.py',
                'Pandas3-0.0.1'
            ]
        },
        'django_dev_iocs': {
            'system_patterns': [
                'getattr(self, \'op_%s\'',
                'sys.argv'
            ],
            'file_patterns': [
                'django_dev/dev.py',
                'django-dev-0.2.1'
            ]
        }
    }

def generate_yara_rules(iocs, output_dir):
    """Generate YARA rules for malware detection"""
    
    yara_content = '''/*
Python Malware Detection Rules
Generated by Typosentinel Python Malware Analysis
*/

rule Python_Malware_BeautifulSoup_Critical {
    meta:
        description = "Detects critical malware in beautifulsoup package"
        author = "Typosentinel"
        date = "''' + datetime.now().strftime('%Y-%m-%d') + '''"
        severity = "critical"
        
    strings:
        $compile1 = "compile('[a-zA-Z][-_.:a-zA-Z0-9]*'"
        $compile2 = "compile(\"([<>]|\""
        $hex1 = "\\x80"
        $hex2 = "\\x9f"
        $package = "BeautifulSoup"
        
    condition:
        $package and ($compile1 or $compile2) and ($hex1 or $hex2)
}

rule Python_Malware_Pandas3_Credentials {
    meta:
        description = "Detects credential theft in pandas3 package"
        author = "Typosentinel"
        date = "''' + datetime.now().strftime('%Y-%m-%d') + '''"
        severity = "high"
        
    strings:
        $aws = ".aws"
        $secret = "secret"
        $post = "requests.post"
        $package = "pandas3"
        
    condition:
        $package and $post and ($aws or $secret)
}

rule Python_Malware_Django_Dev_System {
    meta:
        description = "Detects system compromise patterns in django-dev"
        author = "Typosentinel"
        date = "''' + datetime.now().strftime('%Y-%m-%d') + '''"
        severity = "high"
        
    strings:
        $getattr = "getattr(self, 'op_%s'"
        $argv = "sys.argv"
        $package = "django_dev"
        
    condition:
        $package and ($getattr or $argv)
}

rule Python_Typosquatting_General {
    meta:
        description = "General typosquatting detection for Python packages"
        author = "Typosentinel"
        date = "''' + datetime.now().strftime('%Y-%m-%d') + '''"
        severity = "medium"
        
    strings:
        $pandas2 = "pandas2"
        $pandas3 = "pandas3"
        $flasks = "flasks"
        $beautifulsoup = "beautifulsoup"
        $django_dev = "django-dev"
        
    condition:
        any of them
}
'''
    
    yara_file = output_dir / "python_malware.yar"
    with open(yara_file, 'w') as f:
        f.write(yara_content)

def generate_stix_format(iocs, output_dir):
    """Generate STIX format IOCs"""
    
    stix_data = {
        "type": "bundle",
        "id": f"bundle--{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "spec_version": "2.1",
        "objects": []
    }
    
    # Add malware objects
    for package_ioc in iocs['package_iocs']:
        malware_obj = {
            "type": "malware",
            "id": f"malware--{hashlib.md5(package_ioc['package_name'].encode()).hexdigest()}",
            "created": datetime.now().isoformat() + "Z",
            "modified": datetime.now().isoformat() + "Z",
            "name": package_ioc['package_name'],
            "description": package_ioc['description'],
            "malware_types": ["trojan"],
            "is_family": False,
            "labels": ["malicious-activity"]
        }
        stix_data["objects"].append(malware_obj)
    
    stix_file = output_dir / "python_malware_stix.json"
    with open(stix_file, 'w') as f:
        json.dump(stix_data, f, indent=2)

def generate_ioc_summary(iocs, output_dir):
    """Generate IOC summary report"""
    
    summary_content = f"""# Python Malware IOCs Summary

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Overview

This document contains Indicators of Compromise (IOCs) for Python malware detected by Typosentinel analysis.

## Package IOCs

"""
    
    for package_ioc in iocs['package_iocs']:
        summary_content += f"""
### {package_ioc['package_name']} - {package_ioc['threat_level'].upper()}

**Description:** {package_ioc['description']}

**Detection Indicators:**
"""
        for indicator in package_ioc['indicators']:
            summary_content += f"- `{indicator}`\n"
        
        summary_content += "\n**Detection Rules:**\n"
        for rule in package_ioc['detection_rules']:
            summary_content += f"- {rule}\n"
    
    summary_content += f"""
## Pattern IOCs

Total malicious code patterns detected: {len(iocs['pattern_iocs'])}

"""
    
    for pattern_ioc in iocs['pattern_iocs'][:10]:  # Show first 10
        summary_content += f"""
### {pattern_ioc['category']} - {pattern_ioc['severity']}
- **Pattern:** `{pattern_ioc['pattern']}`
- **Match:** `{pattern_ioc['match']}`
- **Detection:** {pattern_ioc['detection_rule']}
"""
    
    summary_content += f"""
## Usage Instructions

### SIEM Integration
1. Import IOCs into your SIEM platform
2. Configure alerts for package installation attempts
3. Monitor for code pattern matches

### Network Monitoring
1. Monitor PyPI requests for malicious packages
2. Block downloads of identified malicious packages
3. Alert on suspicious network patterns

### Endpoint Detection
1. Scan systems for presence of malicious packages
2. Monitor Python process execution
3. Check for malicious code patterns in Python files

## File Formats

- `python_malware_iocs.json` - Complete IOC data
- `python_malware.yar` - YARA detection rules
- `python_malware_stix.json` - STIX format IOCs
"""
    
    summary_file = output_dir / "IOC_SUMMARY.md"
    with open(summary_file, 'w') as f:
        f.write(summary_content)

if __name__ == "__main__":
    generate_python_iocs()