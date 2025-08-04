/**
 * TypoSentinel Enhanced Dashboard Test Suite
 * 
 * This test suite provides comprehensive testing for the enhanced web dashboard
 * including authentication, preferences, configuration management, and widgets.
 * 
 * Usage:
 * 1. Start TypoSentinel server: typosentinel server --port 3456 --auth --username admin --password test123
 * 2. Run tests: node dashboard-tests.js
 * 3. Or use with testing framework: npm test
 */

const assert = require('assert');
const fetch = require('node-fetch'); // npm install node-fetch
const fs = require('fs');

class DashboardTester {
    constructor(baseUrl = 'http://localhost:3456', credentials = { username: 'admin', password: 'test123' }) {
        this.baseUrl = baseUrl;
        this.credentials = credentials;
        this.sessionId = null;
        this.testResults = [];
    }

    async runAllTests() {
        console.log('🚀 Starting TypoSentinel Dashboard Test Suite...\n');

        try {
            // Authentication Tests
            await this.testAuthentication();
            
            // Preferences Tests
            await this.testUserPreferences();
            
            // Configuration Tests
            await this.testConfigurationManagement();
            
            // Widget Tests
            await this.testWidgetManagement();
            
            // Notification Tests
            await this.testNotifications();
            
            // Session Tests
            await this.testSessionManagement();

            this.printResults();
        } catch (error) {
            console.error('❌ Test suite failed:', error.message);
            process.exit(1);
        }
    }

    async testAuthentication() {
        console.log('🔐 Testing Authentication...');

        // Test 1: Valid login
        await this.test('Valid Login', async () => {
            const response = await fetch(`${this.baseUrl}/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(this.credentials)
            });

            assert.strictEqual(response.status, 200);
            const data = await response.json();
            assert.strictEqual(data.success, true);
            assert.ok(data.session_id);
            
            this.sessionId = data.session_id;
            return 'Login successful';
        });

        // Test 2: Invalid login
        await this.test('Invalid Login', async () => {
            const response = await fetch(`${this.baseUrl}/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: 'wrong', password: 'wrong' })
            });

            assert.strictEqual(response.status, 401);
            return 'Invalid login correctly rejected';
        });

        // Test 3: Session info
        await this.test('Session Info', async () => {
            const response = await fetch(`${this.baseUrl}/auth/session`, {
                headers: { 'Cookie': `session_id=${this.sessionId}` }
            });

            assert.strictEqual(response.status, 200);
            const session = await response.json();
            assert.strictEqual(session.username, this.credentials.username);
            return 'Session info retrieved';
        });
    }

    async testUserPreferences() {
        console.log('⚙️ Testing User Preferences...');

        // Test 1: Get default preferences
        await this.test('Get Default Preferences', async () => {
            const response = await fetch(`${this.baseUrl}/api/preferences`, {
                headers: { 'Cookie': `session_id=${this.sessionId}` }
            });

            assert.strictEqual(response.status, 200);
            const prefs = await response.json();
            assert.ok(prefs.username);
            assert.ok(prefs.theme);
            return 'Default preferences loaded';
        });

        // Test 2: Update preferences
        await this.test('Update Preferences', async () => {
            const newPrefs = {
                theme: 'dark',
                refresh_rate: 60,
                default_view: 'scans',
                notifications: {
                    browser: true,
                    on_high_threats: true,
                    on_system_error: false
                }
            };

            const response = await fetch(`${this.baseUrl}/api/preferences`, {
                method: 'POST',
                headers: { 
                    'Cookie': `session_id=${this.sessionId}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(newPrefs)
            });

            assert.strictEqual(response.status, 200);
            const result = await response.json();
            assert.strictEqual(result.success, true);
            return 'Preferences updated successfully';
        });

        // Test 3: Update theme preference
        await this.test('Update Theme Preference', async () => {
            const response = await fetch(`${this.baseUrl}/api/preferences/theme`, {
                method: 'POST',
                headers: { 
                    'Cookie': `session_id=${this.sessionId}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ theme: 'light' })
            });

            assert.strictEqual(response.status, 200);
            const result = await response.json();
            assert.strictEqual(result.success, true);
            return 'Theme preference updated';
        });
    }

    async testConfigurationManagement() {
        console.log('📋 Testing Configuration Management...');

        // Test 1: Get configuration templates
        await this.test('Get Configuration Templates', async () => {
            const response = await fetch(`${this.baseUrl}/api/config/templates`, {
                headers: { 'Cookie': `session_id=${this.sessionId}` }
            });

            assert.strictEqual(response.status, 200);
            const data = await response.json();
            assert.ok(Array.isArray(data.templates));
            assert.ok(data.templates.length > 0);
            return `Found ${data.templates.length} templates`;
        });

        // Test 2: Validate configuration
        await this.test('Validate Configuration', async () => {
            const testConfig = {
                scanner: {
                    timeout: 30,
                    concurrency: 5,
                    scan_depth: 3
                },
                detector: {
                    threshold: 0.7,
                    algorithms: ['levenshtein', 'jaro_winkler']
                }
            };

            const response = await fetch(`${this.baseUrl}/api/config/validate`, {
                method: 'POST',
                headers: { 
                    'Cookie': `session_id=${this.sessionId}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(testConfig)
            });

            assert.strictEqual(response.status, 200);
            const result = await response.json();
            assert.strictEqual(result.valid, true);
            return 'Configuration validation passed';
        });

        // Test 3: Export configuration
        await this.test('Export Configuration', async () => {
            const response = await fetch(`${this.baseUrl}/api/config/export?type=preferences`, {
                headers: { 'Cookie': `session_id=${this.sessionId}` }
            });

            assert.strictEqual(response.status, 200);
            const config = await response.json();
            assert.ok(config.exported_at);
            assert.ok(config.version);
            return 'Configuration exported successfully';
        });

        // Test 4: Import configuration
        await this.test('Import Configuration', async () => {
            const importData = {
                version: '1.0',
                preferences: {
                    theme: 'auto',
                    refresh_rate: 45
                }
            };

            const response = await fetch(`${this.baseUrl}/api/config/import`, {
                method: 'POST',
                headers: { 
                    'Cookie': `session_id=${this.sessionId}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(importData)
            });

            assert.strictEqual(response.status, 200);
            const result = await response.json();
            assert.strictEqual(result.success, true);
            return 'Configuration imported successfully';
        });

        // Test 5: Get configuration history
        await this.test('Get Configuration History', async () => {
            const response = await fetch(`${this.baseUrl}/api/config/history?limit=10`, {
                headers: { 'Cookie': `session_id=${this.sessionId}` }
            });

            assert.strictEqual(response.status, 200);
            const data = await response.json();
            assert.ok(Array.isArray(data.history));
            assert.ok(typeof data.total === 'number');
            return `Found ${data.history.length} history entries`;
        });
    }

    async testWidgetManagement() {
        console.log('🧩 Testing Widget Management...');

        // Test 1: Get widget layout
        await this.test('Get Widget Layout', async () => {
            const response = await fetch(`${this.baseUrl}/api/widgets`, {
                headers: { 'Cookie': `session_id=${this.sessionId}` }
            });

            assert.strictEqual(response.status, 200);
            const data = await response.json();
            assert.ok(Array.isArray(data.widgets));
            return `Found ${data.widgets.length} widgets`;
        });

        // Test 2: Update widget layout
        await this.test('Update Widget Layout', async () => {
            const newLayout = {
                widgets: [
                    {
                        id: 'metrics',
                        type: 'metrics',
                        position: 1,
                        size: 'large',
                        visible: true
                    },
                    {
                        id: 'scans',
                        type: 'table',
                        position: 2,
                        size: 'medium',
                        visible: true
                    },
                    {
                        id: 'threats',
                        type: 'chart',
                        position: 3,
                        size: 'medium',
                        visible: false
                    }
                ]
            };

            const response = await fetch(`${this.baseUrl}/api/widgets`, {
                method: 'POST',
                headers: { 
                    'Cookie': `session_id=${this.sessionId}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(newLayout)
            });

            assert.strictEqual(response.status, 200);
            const result = await response.json();
            assert.strictEqual(result.success, true);
            return 'Widget layout updated successfully';
        });
    }

    async testNotifications() {
        console.log('🔔 Testing Notifications...');

        // Test 1: Get notifications
        await this.test('Get Notifications', async () => {
            const response = await fetch(`${this.baseUrl}/api/notifications`, {
                headers: { 'Cookie': `session_id=${this.sessionId}` }
            });

            assert.strictEqual(response.status, 200);
            const data = await response.json();
            assert.ok(Array.isArray(data.notifications));
            return `Found ${data.notifications.length} notifications`;
        });

        // Test 2: Send notification
        await this.test('Send Notification', async () => {
            const notification = {
                type: 'info',
                message: 'Test notification from automated test suite'
            };

            const response = await fetch(`${this.baseUrl}/api/notifications`, {
                method: 'POST',
                headers: { 
                    'Cookie': `session_id=${this.sessionId}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(notification)
            });

            assert.strictEqual(response.status, 200);
            const result = await response.json();
            assert.strictEqual(result.success, true);
            return 'Notification sent successfully';
        });
    }

    async testSessionManagement() {
        console.log('🔑 Testing Session Management...');

        // Test 1: Access protected endpoint without session
        await this.test('Protected Endpoint Without Session', async () => {
            const response = await fetch(`${this.baseUrl}/api/preferences`);
            assert.strictEqual(response.status, 401);
            return 'Protected endpoint correctly rejected unauthorized access';
        });

        // Test 2: Logout
        await this.test('Logout', async () => {
            const response = await fetch(`${this.baseUrl}/auth/logout`, {
                method: 'POST',
                headers: { 'Cookie': `session_id=${this.sessionId}` }
            });

            assert.strictEqual(response.status, 200);
            const result = await response.json();
            assert.strictEqual(result.success, true);
            return 'Logout successful';
        });

        // Test 3: Access after logout
        await this.test('Access After Logout', async () => {
            const response = await fetch(`${this.baseUrl}/api/preferences`, {
                headers: { 'Cookie': `session_id=${this.sessionId}` }
            });
            assert.strictEqual(response.status, 401);
            return 'Access correctly denied after logout';
        });
    }

    async test(name, testFunction) {
        try {
            const result = await testFunction();
            this.testResults.push({ name, status: 'PASS', message: result });
            console.log(`  ✅ ${name}: ${result}`);
        } catch (error) {
            this.testResults.push({ name, status: 'FAIL', message: error.message });
            console.log(`  ❌ ${name}: ${error.message}`);
            throw error; // Re-throw to stop test suite on failure
        }
    }

    printResults() {
        console.log('\n📊 Test Results Summary:');
        console.log('========================');
        
        const passed = this.testResults.filter(r => r.status === 'PASS').length;
        const failed = this.testResults.filter(r => r.status === 'FAIL').length;
        const total = this.testResults.length;

        console.log(`Total Tests: ${total}`);
        console.log(`Passed: ${passed}`);
        console.log(`Failed: ${failed}`);
        console.log(`Success Rate: ${((passed / total) * 100).toFixed(1)}%`);

        if (failed === 0) {
            console.log('\n🎉 All tests passed! Dashboard is working correctly.');
        } else {
            console.log('\n⚠️ Some tests failed. Please check the dashboard configuration.');
        }

        // Save results to file
        const reportPath = './dashboard-test-report.json';
        fs.writeFileSync(reportPath, JSON.stringify({
            timestamp: new Date().toISOString(),
            summary: { total, passed, failed },
            results: this.testResults
        }, null, 2));
        
        console.log(`\n📄 Detailed report saved to: ${reportPath}`);
    }
}

// Performance Testing
class PerformanceTester {
    constructor(baseUrl = 'http://localhost:3456') {
        this.baseUrl = baseUrl;
    }

    async runPerformanceTests() {
        console.log('\n⚡ Running Performance Tests...');

        // Test dashboard load time
        await this.testLoadTime('Dashboard Load Time', `${this.baseUrl}/`);
        
        // Test API response times
        await this.testApiPerformance();
    }

    async testLoadTime(name, url) {
        const start = Date.now();
        try {
            const response = await fetch(url);
            const end = Date.now();
            const loadTime = end - start;
            
            console.log(`  ⏱️ ${name}: ${loadTime}ms`);
            
            if (loadTime < 1000) {
                console.log(`    ✅ Excellent performance (< 1s)`);
            } else if (loadTime < 3000) {
                console.log(`    ⚠️ Acceptable performance (< 3s)`);
            } else {
                console.log(`    ❌ Poor performance (> 3s)`);
            }
        } catch (error) {
            console.log(`  ❌ ${name}: Failed to load - ${error.message}`);
        }
    }

    async testApiPerformance() {
        const endpoints = [
            '/api/metrics',
            '/api/config/templates',
            '/api/notifications'
        ];

        for (const endpoint of endpoints) {
            await this.testLoadTime(`API ${endpoint}`, `${this.baseUrl}${endpoint}`);
        }
    }
}

// Load Testing
class LoadTester {
    constructor(baseUrl = 'http://localhost:3456', credentials = { username: 'admin', password: 'test123' }) {
        this.baseUrl = baseUrl;
        this.credentials = credentials;
    }

    async runLoadTests() {
        console.log('\n🔥 Running Load Tests...');

        // Test concurrent requests
        await this.testConcurrentRequests(10);
        await this.testConcurrentRequests(50);
    }

    async testConcurrentRequests(concurrency) {
        console.log(`  🔄 Testing ${concurrency} concurrent requests...`);
        
        const start = Date.now();
        const promises = [];

        for (let i = 0; i < concurrency; i++) {
            promises.push(fetch(`${this.baseUrl}/api/config/templates`));
        }

        try {
            const responses = await Promise.all(promises);
            const end = Date.now();
            const duration = end - start;
            
            const successful = responses.filter(r => r.status === 200).length;
            const failed = responses.length - successful;
            
            console.log(`    ✅ ${successful} successful, ${failed} failed in ${duration}ms`);
            console.log(`    📊 Average response time: ${(duration / concurrency).toFixed(1)}ms`);
        } catch (error) {
            console.log(`    ❌ Load test failed: ${error.message}`);
        }
    }
}

// Main execution
async function main() {
    const args = process.argv.slice(2);
    const baseUrl = args[0] || 'http://localhost:3456';
    
    console.log(`🎯 Testing dashboard at: ${baseUrl}`);
    console.log('Make sure the server is running with: typosentinel server --port 3456 --auth --username admin --password test123\n');

    try {
        // Functional tests
        const tester = new DashboardTester(baseUrl);
        await tester.runAllTests();

        // Performance tests
        const perfTester = new PerformanceTester(baseUrl);
        await perfTester.runPerformanceTests();

        // Load tests
        const loadTester = new LoadTester(baseUrl);
        await loadTester.runLoadTests();

        console.log('\n🏁 All tests completed successfully!');
    } catch (error) {
        console.error('\n💥 Test suite failed:', error.message);
        process.exit(1);
    }
}

// Run tests if this file is executed directly
if (require.main === module) {
    main().catch(console.error);
}

module.exports = { DashboardTester, PerformanceTester, LoadTester };