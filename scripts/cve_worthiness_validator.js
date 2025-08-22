#!/usr/bin/env node
/**
 * CVE Worthiness Validator
 * 
 * Implements the CVE hunting framework to automatically assess whether
 * security findings meet CVE-worthiness criteria.
 * 
 * Usage: node cve_worthiness_validator.js <finding_file.json>
 */

const fs = require('fs');
const path = require('path');

class CVEWorthinessValidator {
    constructor() {
        this.criteria = {
            vendor_controlled_flaw: {
                weight: 0.25,
                gates: ['code_flaw', 'config_flaw', 'design_flaw', 'vendor_controlled']
            },
            security_property_violation: {
                weight: 0.25,
                gates: ['confidentiality', 'integrity', 'authentication', 'availability']
            },
            reproducible_poc: {
                weight: 0.20,
                gates: ['minimal_poc', 'standalone', 'clear_steps', 'reproducible']
            },
            root_cause_identified: {
                weight: 0.15,
                gates: ['exact_location', 'root_cause', 'fix_strategy']
            },
            version_scope_defined: {
                weight: 0.15,
                gates: ['affected_versions', 'version_matrix', 'impact_boundaries']
            }
        };
        
        this.disqualifiers = [
            'misconfiguration_only',
            'expected_behavior',
            'non_default_insecure',
            'performance_only',
            'input_timing_only',
            'duplicate_cve'
        ];
        
        this.side_channel_requirements = [
            'secret_dependent_leakage',
            'practical_exploit',
            'boundary_bypass'
        ];
    }

    /**
     * Validate a security finding against CVE-worthiness criteria
     */
    validateFinding(finding) {
        console.log('🔍 CVE Worthiness Validation');
        console.log('=' .repeat(50));
        console.log(`Package: ${finding.package_name} v${finding.version}`);
        console.log(`Vulnerability: ${finding.description}`);
        console.log('');

        const validation = {
            finding_id: finding.id || 'unknown',
            package_name: finding.package_name,
            version: finding.version,
            vulnerability_type: finding.vulnerability_type,
            timestamp: new Date().toISOString(),
            gates: {},
            disqualifiers_check: {},
            side_channel_check: {},
            overall_assessment: {},
            recommendations: []
        };

        // Step 1: Check disqualifiers
        console.log('📋 Step 1: Disqualifier Check');
        const disqualified = this.checkDisqualifiers(finding, validation);
        
        if (disqualified) {
            validation.overall_assessment = {
                cve_worthy: false,
                reason: 'Failed disqualifier check',
                confidence: 0.0,
                recommendation: 'NOT_CVE_WORTHY'
            };
            return validation;
        }

        // Step 2: Side-channel special validation
        if (finding.vulnerability_type === 'side_channel') {
            console.log('\n🔬 Step 2: Side-Channel Validation');
            const sideChannelValid = this.validateSideChannel(finding, validation);
            if (!sideChannelValid) {
                validation.overall_assessment = {
                    cve_worthy: false,
                    reason: 'Failed side-channel requirements',
                    confidence: 0.0,
                    recommendation: 'NOT_CVE_WORTHY'
                };
                return validation;
            }
        }

        // Step 3: Core CVE criteria validation
        console.log('\n✅ Step 3: Core CVE Criteria Validation');
        const gateResults = this.validateCoreGates(finding, validation);
        
        // Step 4: Calculate overall score
        const overallScore = this.calculateOverallScore(gateResults);
        
        // Step 5: Generate assessment
        validation.overall_assessment = this.generateAssessment(overallScore, gateResults);
        validation.recommendations = this.generateRecommendations(gateResults, finding);

        return validation;
    }

    /**
     * Check for disqualifying factors
     */
    checkDisqualifiers(finding, validation) {
        let disqualified = false;
        
        this.disqualifiers.forEach(disqualifier => {
            const result = this.checkDisqualifier(finding, disqualifier);
            validation.disqualifiers_check[disqualifier] = result;
            
            if (result.failed) {
                console.log(`   ❌ ${disqualifier}: ${result.reason}`);
                disqualified = true;
            } else {
                console.log(`   ✅ ${disqualifier}: Passed`);
            }
        });
        
        return disqualified;
    }

    /**
     * Helper function to get nested property
     */
    getNestedProp(obj, path) {
        return path.split('.').reduce((current, key) => current && current[key], obj);
    }

    /**
     * Check individual disqualifier
     */
    checkDisqualifier(finding, disqualifier) {
        switch (disqualifier) {
            case 'misconfiguration_only':
                if (finding.category === 'misconfiguration' || 
                    finding.description.toLowerCase().includes('configuration')) {
                    return { failed: true, reason: 'Issue is user misconfiguration, not product flaw' };
                }
                break;
                
            case 'expected_behavior':
                if (finding.category === 'expected_behavior' ||
                    finding.description.toLowerCase().includes('working as designed')) {
                    return { failed: true, reason: 'Behavior is expected and documented' };
                }
                break;
                
            case 'non_default_insecure':
                if (finding.requires_insecure_config === true) {
                    return { failed: true, reason: 'Requires non-default insecure configuration' };
                }
                break;
                
            case 'performance_only':
                const performanceOnly = finding.impact_type === 'performance' || this.getNestedProp(finding, 'additional_evidence.impact_type') === 'performance';
                const noSecurityImpact = !finding.security_impact && !this.getNestedProp(finding, 'additional_evidence.security_impact');
                if (performanceOnly && noSecurityImpact) {
                    return { failed: true, reason: 'Performance issue without security impact' };
                }
                break;
                
            case 'input_timing_only':
                if (finding.vulnerability_type === 'timing' && 
                    !finding.secret_dependent && 
                    finding.input_dependent) {
                    return { failed: true, reason: 'Input-dependent timing without secret leakage' };
                }
                break;
                
            case 'duplicate_cve':
                if (finding.existing_cve || finding.duplicate_of) {
                    return { failed: true, reason: `Duplicate of ${finding.existing_cve || finding.duplicate_of}` };
                }
                break;
        }
        
        return { failed: false, reason: 'Passed disqualifier check' };
    }

    /**
     * Validate side-channel specific requirements
     */
    validateSideChannel(finding, validation) {
        let allPassed = true;
        
        this.side_channel_requirements.forEach(requirement => {
            const result = this.checkSideChannelRequirement(finding, requirement);
            validation.side_channel_check[requirement] = result;
            
            if (!result.passed) {
                console.log(`   ❌ ${requirement}: ${result.reason}`);
                allPassed = false;
            } else {
                console.log(`   ✅ ${requirement}: ${result.reason}`);
            }
        });
        
        return allPassed;
    }

    /**
     * Check side-channel requirement
     */
    checkSideChannelRequirement(finding, requirement) {
        switch (requirement) {
            case 'secret_dependent_leakage':
                if (finding.secret_dependent === true && finding.leakage_demonstrated === true) {
                    return { passed: true, reason: 'Secret-dependent timing leakage demonstrated' };
                }
                return { passed: false, reason: 'No secret-dependent leakage shown' };
                
            case 'practical_exploit':
                if (finding.practical_exploit === true || finding.exploit_scenario) {
                    return { passed: true, reason: 'Practical exploitation scenario provided' };
                }
                return { passed: false, reason: 'No practical exploit demonstrated' };
                
            case 'boundary_bypass':
                if (finding.boundary_bypass === true || finding.security_control_bypass) {
                    return { passed: true, reason: 'Security boundary bypass demonstrated' };
                }
                return { passed: false, reason: 'No security boundary bypass shown' };
        }
        
        return { passed: false, reason: 'Unknown requirement' };
    }

    /**
     * Validate core CVE gates
     */
    validateCoreGates(finding, validation) {
        const gateResults = {};
        
        Object.keys(this.criteria).forEach(criteriaName => {
            const criteria = this.criteria[criteriaName];
            const gateResult = this.validateGate(finding, criteriaName, criteria.gates);
            gateResults[criteriaName] = gateResult;
            validation.gates[criteriaName] = gateResult;
            
            const status = gateResult.passed ? '✅' : '❌';
            const score = (gateResult.score * 100).toFixed(1);
            console.log(`   ${status} ${criteriaName}: ${score}% (${gateResult.passed_gates}/${gateResult.total_gates})`);
            
            if (!gateResult.passed) {
                console.log(`      Missing: ${gateResult.failed_gates.join(', ')}`);
            }
        });
        
        return gateResults;
    }

    /**
     * Validate individual gate
     */
    validateGate(finding, criteriaName, gates) {
        const results = gates.map(gate => this.checkGate(finding, gate));
        const passedGates = results.filter(r => r.passed);
        const failedGates = results.filter(r => !r.passed).map(r => r.gate);
        
        return {
            passed: passedGates.length === gates.length,
            score: passedGates.length / gates.length,
            total_gates: gates.length,
            passed_gates: passedGates.length,
            failed_gates: failedGates,
            details: results
        };
    }

    /**
     * Check individual gate requirement
     */
    checkGate(finding, gate) {
        switch (gate) {
            // Vendor-controlled flaw gates
            case 'code_flaw':
                const codeLocation = finding.code_location || this.getNestedProp(finding, 'vendor_controlled_flaw.code_location') || this.getNestedProp(finding, 'vendor_controlled_flaw.vulnerable_function');
                return {
                    gate,
                    passed: !!codeLocation,
                    reason: codeLocation ? 'Code location identified' : 'No code location provided'
                };
                
            case 'config_flaw':
                const configFlaw = finding.config_path || finding.default_config_issue || this.getNestedProp(finding, 'additional_evidence.default_config_issue') || this.getNestedProp(finding, 'vendor_controlled_flaw.code_location');
                return {
                    gate,
                    passed: !!configFlaw,
                    reason: 'Configuration or code flaw identified'
                };
                
            case 'design_flaw':
                const designFlaw = finding.design_issue || finding.architectural_flaw || this.getNestedProp(finding, 'vendor_controlled_flaw.code_location');
                return {
                    gate,
                    passed: !!designFlaw,
                    reason: 'Design or implementation flaw identified'
                };
                
            case 'vendor_controlled':
                const vendorControlled = this.getNestedProp(finding, 'vendor_controlled_flaw.vendor_controlled') !== false && !this.getNestedProp(finding, 'vendor_controlled_flaw.user_controlled') && !this.getNestedProp(finding, 'vendor_controlled_flaw.third_party_dependency');
                return {
                    gate,
                    passed: vendorControlled,
                    reason: vendorControlled ? 'Vendor-controlled component' : 'User-controlled or third-party issue'
                };

            // Security property violation gates
            case 'confidentiality':
                const confidentialityImpact = finding.confidentiality_impact === true || finding.data_disclosure === true || this.getNestedProp(finding, 'security_property_violation.confidentiality_impact') === true;
                return {
                    gate,
                    passed: confidentialityImpact,
                    reason: confidentialityImpact ? 'Confidentiality impact confirmed' : 'No confidentiality impact'
                };
                
            case 'integrity':
                const integrityImpact = finding.integrity_impact === true || finding.data_modification === true || this.getNestedProp(finding, 'security_property_violation.integrity_impact') === true || this.getNestedProp(finding, 'security_property_violation.data_modification') === true;
                return {
                    gate,
                    passed: integrityImpact,
                    reason: integrityImpact ? 'Integrity impact confirmed' : 'No integrity impact'
                };
                
            case 'authentication':
                const authImpact = finding.auth_bypass === true || finding.privilege_escalation === true || this.getNestedProp(finding, 'security_property_violation.auth_bypass') === true || this.getNestedProp(finding, 'security_property_violation.privilege_escalation') === true;
                return {
                    gate,
                    passed: authImpact,
                    reason: authImpact ? 'Authentication bypass confirmed' : 'No auth impact'
                };
                
            case 'availability':
                const availabilityImpact = finding.availability_impact === true || finding.denial_of_service === true || this.getNestedProp(finding, 'security_property_violation.availability_impact') === true;
                return {
                    gate,
                    passed: availabilityImpact,
                    reason: availabilityImpact ? 'Availability impact confirmed' : 'No availability impact'
                };

            // Reproducible PoC gates
            case 'minimal_poc':
                const pocProvided = finding.poc_provided === true || this.getNestedProp(finding, 'reproducible_poc.poc_provided') === true;
                const pocMinimal = finding.poc_minimal === true || this.getNestedProp(finding, 'reproducible_poc.poc_minimal') === true;
                return {
                    gate,
                    passed: pocProvided && pocMinimal,
                    reason: pocProvided ? 'PoC provided' : 'No PoC provided'
                };
                
            case 'standalone':
                const pocStandalone = finding.poc_standalone === true || this.getNestedProp(finding, 'reproducible_poc.poc_standalone') === true;
                const noExternalDeps = !finding.external_dependencies && !this.getNestedProp(finding, 'reproducible_poc.external_dependencies');
                return {
                    gate,
                    passed: pocStandalone || noExternalDeps,
                    reason: pocStandalone ? 'Standalone PoC' : 'PoC has external dependencies'
                };
                
            case 'clear_steps':
                const reproSteps = finding.reproduction_steps || this.getNestedProp(finding, 'reproducible_poc.reproduction_steps');
                const pocInstructions = finding.poc_instructions || this.getNestedProp(finding, 'reproducible_poc.poc_instructions');
                return {
                    gate,
                    passed: !!(reproSteps || pocInstructions),
                    reason: (reproSteps || pocInstructions) ? 'Clear reproduction steps provided' : 'No reproduction steps'
                };
                
            case 'reproducible':
                const independentlyReproduced = finding.independently_reproduced === true || this.getNestedProp(finding, 'reproducible_poc.independently_reproduced') === true;
                const reproConfirmed = finding.reproduction_confirmed === true || this.getNestedProp(finding, 'reproducible_poc.reproduction_confirmed') === true;
                return {
                    gate,
                    passed: independentlyReproduced || reproConfirmed,
                    reason: independentlyReproduced ? 'Independent reproduction confirmed' : 'No independent reproduction'
                };

            // Root cause identification gates
            case 'exact_location':
                const fileLine = finding.file_line || this.getNestedProp(finding, 'vendor_controlled_flaw.file_line');
                const codeLocationExact = finding.code_location || this.getNestedProp(finding, 'vendor_controlled_flaw.code_location');
                const configPath = finding.config_path;
                const exactLocation = fileLine || codeLocationExact || configPath;
                return {
                    gate,
                    passed: !!exactLocation,
                    reason: exactLocation ? `Location: ${exactLocation}` : 'No exact location provided'
                };
                
            case 'root_cause':
                const rootCause = finding.root_cause || this.getNestedProp(finding, 'root_cause_identification.root_cause');
                const vulnCause = finding.vulnerability_cause || this.getNestedProp(finding, 'root_cause_identification.vulnerability_cause');
                return {
                    gate,
                    passed: !!(rootCause || vulnCause),
                    reason: (rootCause || vulnCause) ? 'Root cause identified' : 'Root cause not identified'
                };
                
            case 'fix_strategy':
                const fixRec = finding.fix_recommendation || this.getNestedProp(finding, 'root_cause_identification.fix_recommendation');
                const mitigationStrategy = finding.mitigation_strategy || this.getNestedProp(finding, 'root_cause_identification.mitigation_strategy');
                return {
                    gate,
                    passed: !!(fixRec || mitigationStrategy),
                    reason: (fixRec || mitigationStrategy) ? 'Fix strategy provided' : 'No fix strategy'
                };

            // Version scope gates
            case 'affected_versions':
                const affectedVersions = finding.affected_versions || this.getNestedProp(finding, 'version_scope.affected_versions');
                const versionRange = finding.version_range || this.getNestedProp(finding, 'version_scope.version_range');
                return {
                    gate,
                    passed: !!(affectedVersions || versionRange),
                    reason: (affectedVersions || versionRange) ? `Versions: ${affectedVersions || versionRange}` : 'No version range provided'
                };
                
            case 'version_matrix':
                const versionMatrix = finding.version_matrix || this.getNestedProp(finding, 'version_scope.version_matrix');
                const testedVersions = finding.tested_versions || this.getNestedProp(finding, 'version_scope.tested_versions');
                return {
                    gate,
                    passed: !!(versionMatrix || testedVersions),
                    reason: (versionMatrix || testedVersions) ? 'Version matrix provided' : 'No version testing matrix'
                };
                
            case 'impact_boundaries':
                const impactScope = finding.impact_scope || this.getNestedProp(finding, 'version_scope.impact_scope');
                const affectedConfigs = finding.affected_configurations || this.getNestedProp(finding, 'version_scope.affected_configurations');
                return {
                    gate,
                    passed: !!(impactScope || affectedConfigs),
                    reason: (impactScope || affectedConfigs) ? 'Impact boundaries defined' : 'Impact scope not defined'
                };

            default:
                return {
                    gate,
                    passed: false,
                    reason: 'Unknown gate'
                };
        }
    }

    /**
     * Calculate overall CVE-worthiness score
     */
    calculateOverallScore(gateResults) {
        let totalScore = 0;
        let totalWeight = 0;
        
        Object.keys(this.criteria).forEach(criteriaName => {
            const criteria = this.criteria[criteriaName];
            const gateResult = gateResults[criteriaName];
            
            totalScore += gateResult.score * criteria.weight;
            totalWeight += criteria.weight;
        });
        
        return totalScore / totalWeight;
    }

    /**
     * Generate overall assessment
     */
    generateAssessment(overallScore, gateResults) {
        const passedGates = Object.values(gateResults).filter(g => g.passed).length;
        const totalGates = Object.keys(gateResults).length;
        
        let recommendation, confidence, reason;
        
        if (overallScore >= 0.9 && passedGates === totalGates) {
            recommendation = 'IMMEDIATE_CVE_ASSIGNMENT';
            confidence = overallScore;
            reason = 'All criteria met with high confidence';
        } else if (overallScore >= 0.8 && passedGates >= totalGates * 0.8) {
            recommendation = 'CVE_WORTHY_WITH_IMPROVEMENTS';
            confidence = overallScore;
            reason = 'Most criteria met, minor improvements needed';
        } else if (overallScore >= 0.6) {
            recommendation = 'NEEDS_MORE_EVIDENCE';
            confidence = overallScore;
            reason = 'Significant gaps in evidence';
        } else {
            recommendation = 'NOT_CVE_WORTHY';
            confidence = overallScore;
            reason = 'Insufficient evidence for CVE assignment';
        }
        
        return {
            cve_worthy: overallScore >= 0.8,
            overall_score: overallScore,
            confidence: confidence,
            passed_gates: passedGates,
            total_gates: totalGates,
            recommendation: recommendation,
            reason: reason
        };
    }

    /**
     * Generate improvement recommendations
     */
    generateRecommendations(gateResults, finding) {
        const recommendations = [];
        
        Object.keys(gateResults).forEach(criteriaName => {
            const gateResult = gateResults[criteriaName];
            
            if (!gateResult.passed) {
                gateResult.failed_gates.forEach(failedGate => {
                    recommendations.push(this.getGateRecommendation(failedGate, finding));
                });
            }
        });
        
        return recommendations.filter(r => r !== null);
    }

    /**
     * Get specific recommendation for failed gate
     */
    getGateRecommendation(gate, finding) {
        const recommendations = {
            'code_flaw': 'Identify exact file and line number of vulnerable code',
            'exact_location': 'Provide precise file:line location (e.g., src/utils.js:123)',
            'root_cause': 'Explain the underlying cause of the vulnerability',
            'minimal_poc': 'Create a minimal, standalone proof of concept',
            'reproduction_steps': 'Provide clear, numbered reproduction steps',
            'affected_versions': 'Test and document affected version ranges',
            'fix_strategy': 'Propose concrete fix recommendations',
            'confidentiality': 'Demonstrate data disclosure or information leakage',
            'integrity': 'Show data modification or corruption capabilities',
            'availability': 'Prove denial of service or system unavailability',
            'authentication': 'Demonstrate authentication bypass or privilege escalation'
        };
        
        return recommendations[gate] ? {
            gate: gate,
            action: recommendations[gate],
            priority: gate.includes('exact_location') || gate.includes('minimal_poc') ? 'HIGH' : 'MEDIUM'
        } : null;
    }

    /**
     * Generate detailed report
     */
    generateReport(validation) {
        console.log('\n📊 CVE WORTHINESS ASSESSMENT REPORT');
        console.log('=' .repeat(60));
        
        const assessment = validation.overall_assessment;
        const statusIcon = assessment.cve_worthy ? '✅' : '❌';
        const scorePercent = (assessment.overall_score * 100).toFixed(1);
        
        console.log(`\n${statusIcon} Overall Assessment: ${assessment.recommendation}`);
        console.log(`📊 CVE-Worthiness Score: ${scorePercent}%`);
        console.log(`🎯 Confidence: ${(assessment.confidence * 100).toFixed(1)}%`);
        console.log(`✅ Gates Passed: ${assessment.passed_gates}/${assessment.total_gates}`);
        console.log(`💡 Reason: ${assessment.reason}`);
        
        if (validation.recommendations.length > 0) {
            console.log('\n🔧 Recommendations for Improvement:');
            validation.recommendations.forEach((rec, index) => {
                const priority = rec.priority === 'HIGH' ? '🔴' : '🟡';
                console.log(`   ${priority} ${index + 1}. ${rec.action}`);
            });
        }
        
        console.log('\n📋 Gate Details:');
        Object.keys(validation.gates).forEach(gateName => {
            const gate = validation.gates[gateName];
            const status = gate.passed ? '✅' : '❌';
            const score = (gate.score * 100).toFixed(1);
            console.log(`   ${status} ${gateName}: ${score}% (${gate.passed_gates}/${gate.total_gates})`);
        });
        
        return validation;
    }

    /**
     * Save validation report to file
     */
    saveReport(validation, outputPath) {
        const reportData = {
            ...validation,
            framework_version: '1.0',
            validation_tool: 'CVE Worthiness Validator',
            generated_at: new Date().toISOString()
        };
        
        fs.writeFileSync(outputPath, JSON.stringify(reportData, null, 2));
        console.log(`\n💾 Report saved to: ${outputPath}`);
    }
}

// CLI interface
if (require.main === module) {
    const args = process.argv.slice(2);
    
    if (args.length === 0) {
        console.log('Usage: node cve_worthiness_validator.js <finding_file.json>');
        console.log('\nExample finding file format:');
        console.log(JSON.stringify({
            "id": "example_001",
            "package_name": "example-package",
            "version": "1.2.3",
            "vulnerability_type": "buffer_overflow",
            "description": "Buffer overflow in parse function",
            "code_location": "src/parser.js:45",
            "poc_provided": true,
            "poc_minimal": true,
            "confidentiality_impact": true,
            "affected_versions": "1.0.0 - 1.2.3",
            "root_cause": "Missing bounds checking",
            "fix_recommendation": "Add input validation"
        }, null, 2));
        process.exit(1);
    }
    
    const findingFile = args[0];
    
    if (!fs.existsSync(findingFile)) {
        console.error(`❌ Finding file not found: ${findingFile}`);
        process.exit(1);
    }
    
    try {
        const finding = JSON.parse(fs.readFileSync(findingFile, 'utf8'));
        const validator = new CVEWorthinessValidator();
        const validation = validator.validateFinding(finding);
        const report = validator.generateReport(validation);
        
        // Save report
        const outputPath = findingFile.replace('.json', '_validation_report.json');
        validator.saveReport(validation, outputPath);
        
    } catch (error) {
        console.error(`❌ Error processing finding: ${error.message}`);
        process.exit(1);
    }
}

module.exports = CVEWorthinessValidator;