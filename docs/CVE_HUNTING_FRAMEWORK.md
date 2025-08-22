# CVE Hunting Framework - Typosentinel Security Research

## 🎯 CVE-Worthiness Criteria

### Core Definition
A finding is **CVE-worthy** when it meets ALL of the following criteria:

1. **Specific Flaw in Vendor-Controlled Product**
   - Code vulnerability
   - Default configuration issue
   - Design flaw
   - Must be in vendor-controlled components

2. **Security Property Violation**
   - Breaks confidentiality
   - Breaks integrity
   - Breaks authentication/authorization
   - Breaks availability
   - Under plausible attack conditions

3. **Reproducible with Minimal PoC**
   - Product-only proof of concept
   - No external dependencies
   - Clear reproduction steps
   - Minimal attack surface

4. **Root Cause Identification**
   - Exact file/line location
   - Clear config path
   - Pinpointed vulnerability source

5. **Version Scope Definition**
   - Affected version ranges
   - Clear version matrix
   - Precise impact boundaries

### ❌ Non-CVE-Worthy Findings

- **Misconfiguration Issues**: User error, not product flaw
- **Expected Behavior**: Working as designed
- **Non-Default Insecure Settings**: Vendor doesn't claim to protect
- **Performance Quirks**: No security impact
- **Input-Dependent Timing**: Without secret leakage
- **Duplicate CVEs**: Already reported vulnerabilities

### 🔍 Side-Channel Special Criteria

Side-channel vulnerabilities qualify ONLY when demonstrating:
- **Secret-dependent leakage**: Timing varies with secret data
- **Practical exploit**: Real-world attack scenario
- **Boundary bypass**: Circumvents security controls
- **NOT** just input-dependent timing variance

## 🛠️ CVE Hunting Methodology

### Phase 1: Target Identification

#### 1.1 Package Selection Criteria
```yaml
selection_criteria:
  popularity:
    weekly_downloads: ">= 100,000"
    github_stars: ">= 1,000"
    dependent_packages: ">= 100"
  
  attack_surface:
    native_code: "high_priority"
    network_facing: "high_priority"
    file_processing: "medium_priority"
    crypto_operations: "high_priority"
  
  maintenance_status:
    last_update: "< 2_years"
    active_maintainer: "preferred"
    security_history: "check_advisories"
```

#### 1.2 Ecosystem Prioritization
1. **npm** (Node.js) - High attack surface
2. **PyPI** (Python) - Wide adoption
3. **Cargo** (Rust) - Memory safety focus
4. **Maven** (Java) - Enterprise usage
5. **Go Modules** - Growing ecosystem

### Phase 2: Vulnerability Discovery

#### 2.1 Static Analysis Techniques

**Code Pattern Detection:**
```javascript
// High-risk patterns to search for
const HIGH_RISK_PATTERNS = {
  buffer_operations: [
    /Buffer\.alloc\([^)]*\)/g,
    /Buffer\.from\([^)]*\)/g,
    /\.length\s*[+\-*\/]/g
  ],
  
  unsafe_eval: [
    /eval\s*\(/g,
    /Function\s*\(/g,
    /new\s+Function/g
  ],
  
  prototype_pollution: [
    /__proto__/g,
    /constructor\.prototype/g,
    /Object\.keys\([^)]*\)\.forEach/g
  ],
  
  path_traversal: [
    /path\.join\([^)]*\.\./g,
    /fs\.readFile\([^)]*\+/g,
    /require\([^)]*\+/g
  ]
};
```

**AST Analysis Focus Areas:**
- Function parameter validation
- Buffer boundary checks
- Input sanitization
- Error handling paths
- Privilege escalation points

#### 2.2 Dynamic Analysis Techniques

**Fuzzing Strategies:**
```python
# Fuzzing input categories
FUZZ_CATEGORIES = {
    'buffer_overflow': {
        'oversized_inputs': [b'A' * (2**i) for i in range(10, 20)],
        'negative_sizes': [-1, -2**31, -2**63],
        'zero_sizes': [0, None, undefined]
    },
    
    'injection': {
        'code_injection': ['eval("malicious")', '__proto__.polluted = true'],
        'path_traversal': ['../../../etc/passwd', '..\\..\\windows\\system32'],
        'prototype_pollution': ['{"__proto__": {"polluted": true}}']
    },
    
    'memory_corruption': {
        'format_strings': ['%s%s%s%s', '%x%x%x%x'],
        'integer_overflow': [2**32, 2**64, -2**31],
        'null_bytes': ['\x00', '\x00\x00\x00\x00']
    }
}
```

#### 2.3 Side-Channel Analysis

**Timing Analysis Framework:**
```python
class SideChannelDetector:
    def __init__(self, target_function, secret_data):
        self.target = target_function
        self.secrets = secret_data
        self.timing_threshold = 0.05  # 50ms variance
    
    def detect_secret_dependent_timing(self):
        """Detect if timing varies with secret data"""
        results = []
        
        for secret in self.secrets:
            timings = []
            for _ in range(100):  # Multiple samples
                start = time.perf_counter()
                self.target(secret)
                end = time.perf_counter()
                timings.append(end - start)
            
            results.append({
                'secret': secret,
                'mean_time': statistics.mean(timings),
                'std_dev': statistics.stdev(timings),
                'timings': timings
            })
        
        return self.analyze_correlation(results)
    
    def analyze_correlation(self, results):
        """Check for secret-dependent correlation"""
        # Statistical analysis for secret leakage
        pass
```

### Phase 3: CVE Validation

#### 3.1 Evidence Collection Checklist

```yaml
evidence_requirements:
  technical_proof:
    - exact_file_line: "path/to/file.js:123"
    - vulnerable_function: "function_name()"
    - root_cause: "missing input validation"
    - attack_vector: "crafted input payload"
  
  reproduction:
    - minimal_poc: "standalone script"
    - clear_steps: "numbered instructions"
    - expected_output: "vulnerability demonstration"
    - environment: "Node.js v18+, package v1.2.3"
  
  impact_assessment:
    - security_property: "confidentiality/integrity/availability"
    - attack_scenario: "realistic exploitation"
    - affected_systems: "web apps using package"
    - severity_justification: "CVSS calculation"
  
  version_analysis:
    - affected_versions: "1.0.0 - 2.1.5"
    - first_vulnerable: "1.0.0"
    - fix_available: "2.1.6+"
    - version_matrix: "tested across versions"
```

#### 3.2 CVE-Worthiness Validation Gates

**Gate 1: Product Flaw Verification**
- [ ] Vulnerability exists in vendor code
- [ ] Not user misconfiguration
- [ ] Not expected behavior
- [ ] Affects default configuration

**Gate 2: Security Impact Confirmation**
- [ ] Breaks confidentiality/integrity/availability
- [ ] Realistic attack scenario
- [ ] Plausible attacker capabilities
- [ ] Measurable security impact

**Gate 3: Reproducibility Validation**
- [ ] Minimal PoC created
- [ ] Independent reproduction
- [ ] Clear pass/fail criteria
- [ ] No external dependencies

**Gate 4: Root Cause Analysis**
- [ ] Exact location identified
- [ ] Root cause pinpointed
- [ ] Fix strategy proposed
- [ ] Affected code paths mapped

**Gate 5: Scope Definition**
- [ ] Version ranges identified
- [ ] Impact boundaries defined
- [ ] Affected configurations listed
- [ ] Mitigation strategies documented

### Phase 4: CVE Submission Process

#### 4.1 Documentation Requirements

**CVE Submission Package:**
```
cve_submission/
├── CVE_REQUEST.md           # Main submission document
├── TECHNICAL_ANALYSIS.md    # Detailed technical analysis
├── PROOF_OF_CONCEPT.js      # Minimal reproduction script
├── VERSION_MATRIX.md        # Affected versions analysis
├── IMPACT_ASSESSMENT.md     # Security impact evaluation
├── MITIGATION_GUIDE.md      # Fix recommendations
└── EVIDENCE/
    ├── screenshots/
    ├── logs/
    └── test_results/
```

**CVE Request Template:**
```markdown
# CVE Request: [Package Name] [Vulnerability Type]

## Summary
- **Package:** package-name
- **Version:** x.y.z
- **Vulnerability:** Brief description
- **CVSS:** X.X (SEVERITY)
- **CWE:** CWE-XXX

## Technical Details
### Root Cause
[Exact file:line and explanation]

### Attack Vector
[How the vulnerability is exploited]

### Impact
[Security properties affected]

## Proof of Concept
[Minimal reproduction steps]

## Affected Versions
[Version range analysis]

## Mitigation
[Fix recommendations]
```

#### 4.2 Vendor Communication

**Responsible Disclosure Timeline:**
1. **Day 0:** Initial discovery and validation
2. **Day 1-3:** CVE-worthiness verification
3. **Day 4-7:** PoC development and testing
4. **Day 8-14:** Documentation preparation
5. **Day 15:** Vendor notification (private)
6. **Day 45:** Follow-up if no response
7. **Day 90:** Public disclosure (if unpatched)

**Vendor Contact Methods:**
1. Security email (security@vendor.com)
2. GitHub Security Advisory
3. HackerOne/Bugcrowd program
4. Direct maintainer contact
5. CVE coordination (MITRE/NVD)

### Phase 5: Quality Assurance

#### 5.1 Peer Review Process

**Review Checklist:**
- [ ] CVE-worthiness criteria met
- [ ] Technical accuracy verified
- [ ] PoC independently reproduced
- [ ] Documentation completeness
- [ ] Ethical considerations addressed

#### 5.2 False Positive Prevention

**Common False Positives:**
- Configuration issues
- Expected behavior
- Theoretical vulnerabilities
- Duplicate findings
- Non-security impacts

**Validation Questions:**
1. Is this a product flaw or user error?
2. Does this break a security property?
3. Can this be exploited realistically?
4. Is the PoC minimal and standalone?
5. Is the root cause clearly identified?

## 🔧 Tools and Automation

### Static Analysis Tools
```bash
# Code scanning
semgrep --config=cve-patterns .
CodeQL analyze --language=javascript
bandit -r . -f json

# Dependency analysis
npm audit --audit-level=moderate
safety check --json
cargo audit
```

### Dynamic Analysis Tools
```bash
# Fuzzing
AFL++ -i input_dir -o output_dir target_binary
libFuzzer target_function

# Memory analysis
valgrind --tool=memcheck target_app
AddressSanitizer compilation flags
```

### Side-Channel Analysis
```python
# Timing analysis
import time, statistics
from scipy import stats

# Statistical correlation testing
from sklearn.metrics import mutual_info_score
```

## 📊 Success Metrics

### CVE Quality Indicators
- **Acceptance Rate:** >90% of submissions accepted
- **Reproduction Rate:** 100% independent reproduction
- **Fix Rate:** >80% of vendors provide fixes
- **False Positive Rate:** <5% invalid submissions

### Impact Metrics
- **CVSS Distribution:** Focus on 7.0+ severity
- **Ecosystem Coverage:** Multiple package managers
- **Vendor Response:** <30 days average response time
- **Community Benefit:** Measurable security improvements

## 🚨 Ethical Guidelines

### Research Ethics
1. **No Harm Principle:** Never cause damage
2. **Responsible Disclosure:** Follow disclosure timelines
3. **Vendor Cooperation:** Work with maintainers
4. **Community Benefit:** Improve overall security

### Legal Considerations
1. **Authorization:** Only test owned/permitted systems
2. **Compliance:** Follow applicable laws
3. **Documentation:** Maintain research records
4. **Attribution:** Credit collaborative work

---

**Framework Version:** 1.0  
**Last Updated:** January 15, 2025  
**Maintainer:** Typosentinel Security Research Team