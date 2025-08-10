# Python Malware IOCs Summary

**Generated:** 2025-08-10 01:26:17

## Overview

This document contains Indicators of Compromise (IOCs) for Python malware detected by Typosentinel analysis.

## Package IOCs


### django-dev - HIGH

**Description:** Malicious Python package: django-dev

**Detection Indicators:**
- `pip install django-dev`
- `import django-dev`
- `from django-dev import`
- `django-dev`

**Detection Rules:**
- process_name contains 'pip' AND command_line contains 'django-dev'
- file_path contains 'django-dev' AND file_extension = '.py'
- network_request contains 'pypi.org/simple/django-dev'

### beautifulsoup - CRITICAL

**Description:** Malicious Python package: beautifulsoup

**Detection Indicators:**
- `pip install beautifulsoup`
- `import beautifulsoup`
- `from beautifulsoup import`
- `beautifulsoup`

**Detection Rules:**
- process_name contains 'pip' AND command_line contains 'beautifulsoup'
- file_path contains 'beautifulsoup' AND file_extension = '.py'
- network_request contains 'pypi.org/simple/beautifulsoup'

### py-test - HIGH

**Description:** Malicious Python package: py-test

**Detection Indicators:**
- `pip install py-test`
- `import py-test`
- `from py-test import`
- `py-test`

**Detection Rules:**
- process_name contains 'pip' AND command_line contains 'py-test'
- file_path contains 'py-test' AND file_extension = '.py'
- network_request contains 'pypi.org/simple/py-test'

## Pattern IOCs

Total malicious code patterns detected: 441


### obfuscation - HIGH
- **Pattern:** `getattr\s*\(\s*.*,\s*["\'].*["\']`
- **Match:** `getattr(self, 'op_%s'`
- **Detection:** file_content matches 'getattr\s*\(\s*.*,\s*["\'].*["\']' AND file_extension = '.py'

### system_access - HIGH
- **Pattern:** `sys\.argv`
- **Match:** `sys.argv`
- **Detection:** file_content matches 'sys\.argv' AND file_extension = '.py'

### obfuscation - CRITICAL
- **Pattern:** `compile\s*\(\s*["\'].*["\']`
- **Match:** `compile('[a-zA-Z][-_.:a-zA-Z0-9]*'`
- **Detection:** file_content matches 'compile\s*\(\s*["\'].*["\']' AND file_extension = '.py'

### obfuscation - CRITICAL
- **Pattern:** `compile\s*\(\s*["\'].*["\']`
- **Match:** `compile("([<>]|"`
- **Detection:** file_content matches 'compile\s*\(\s*["\'].*["\']' AND file_extension = '.py'

### obfuscation - CRITICAL
- **Pattern:** `compile\s*\(\s*["\'].*["\']`
- **Match:** `compile('(<[^<>]*)/>'`
- **Detection:** file_content matches 'compile\s*\(\s*["\'].*["\']' AND file_extension = '.py'

### obfuscation - CRITICAL
- **Pattern:** `compile\s*\(\s*["\'].*["\']`
- **Match:** `compile('<!\s+([^<>]*)>'`
- **Detection:** file_content matches 'compile\s*\(\s*["\'].*["\']' AND file_extension = '.py'

### obfuscation - CRITICAL
- **Pattern:** `compile\s*\(\s*["\'].*["\']`
- **Match:** `compile("((^|;)\s*charset=)([^;]*)"`
- **Detection:** file_content matches 'compile\s*\(\s*["\'].*["\']' AND file_extension = '.py'

### obfuscation - CRITICAL
- **Pattern:** `compile\s*\(\s*["\'].*["\']`
- **Match:** `compile("([\x80-\x9f])"`
- **Detection:** file_content matches 'compile\s*\(\s*["\'].*["\']' AND file_extension = '.py'

### obfuscation - CRITICAL
- **Pattern:** `compile\s*\(\s*["\'].*["\']`
- **Match:** `compile(
            '^<\?.*encoding=[\'"](.*?)[\'"].*\?>'`
- **Detection:** file_content matches 'compile\s*\(\s*["\'].*["\']' AND file_extension = '.py'

### obfuscation - CRITICAL
- **Pattern:** `compile\s*\(\s*["\'].*["\']`
- **Match:** `compile('<\s*meta[^>]+charset=([^>]*?)[;\'">]'`
- **Detection:** file_content matches 'compile\s*\(\s*["\'].*["\']' AND file_extension = '.py'

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
